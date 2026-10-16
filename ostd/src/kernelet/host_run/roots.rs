// SPDX-License-Identifier: MPL-2.0

//! Image page-table root services: register, unregister, activate, and TLB
//! shootdown.
//!
//! Registration validates a Guest-provided root against the Host-built boot
//! page before that root may be activated on any CPU.

use core::sync::atomic::Ordering;

use super::{RETURNING, current_carrier_state, resources::RootRegistration};
#[cfg(all(kernelet_rq1_diagnostics, not(feature = "kernelet")))]
use crate::cpu::CpuId;
use crate::{
    kernelet::abi::{BootArgs, INVALID, KERNEL_HALF_START, STATE},
    mm::{MAX_USERSPACE_VADDR, PAGE_SIZE, tlb::TlbFlushOp},
};

// SAFETY: Every entry below is reached only through a stack-switching service
// stub, with the carrier authenticated and physical interrupts masked.
#[unsafe(no_mangle)]
extern "C" fn kernelet_host_pt_root_register_impl(root: u64) -> i64 {
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return -STATE;
    };
    let Some(_admission) = state.admit_service() else {
        return -STATE;
    };
    state.enter_schedulable_service();
    crate::arch::irq::enable_local();
    let result = if root == 0 || !root.is_multiple_of(PAGE_SIZE as u64) {
        -INVALID
    } else {
        let boot = unsafe { &*(state.boot_args as *const BootArgs) };
        // One scoped pin retains the complete root page through validation.
        // Release it before allocating the registration or locking `roots`.
        // SAFETY: Only the immutable kernel-half words of the trusted
        // vOSTD page-table root are read; this does not authorize Host writes
        // to typed page-table memory or expose this capability to kernel code.
        let valid = unsafe {
            state
                .guest_memory
                .with_raw_reader(root, PAGE_SIZE, |reader| {
                    reader.skip(KERNEL_HALF_START * size_of::<u64>());
                    for expected in &boot.kernel_half_entries {
                        let Ok(actual) = reader.read_val::<u64>() else {
                            return false;
                        };
                        if u64::from_le(actual) != *expected {
                            return false;
                        }
                    }
                    true
                })
        }
        .unwrap_or(false);
        let registration = valid.then(|| RootRegistration::new(root)).flatten();
        let mut roots = state.execution.roots.lock();
        match roots.binary_search_by_key(&root, |entry| entry.paddr) {
            Ok(_) if valid => 0,
            Ok(_) => -INVALID,
            Err(_) if !valid || roots.len() >= roots.capacity() => -INVALID,
            Err(index) => {
                if let Some(registration) = registration {
                    roots.insert(index, registration);
                    0
                } else {
                    -STATE
                }
            }
        }
    };
    crate::arch::irq::disable_local();
    state.set_phase(RETURNING);
    result
}

#[unsafe(no_mangle)]
extern "C" fn kernelet_host_pt_root_unregister_impl(root: u64) -> i64 {
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return -STATE;
    };
    let Some(_admission) = state.admit_service() else {
        return -STATE;
    };
    state.enter_schedulable_service();
    crate::arch::irq::enable_local();
    let mut roots = state.execution.roots.lock();
    let mut retired_root = None;
    let result = match roots.binary_search_by_key(&root, |entry| entry.paddr) {
        Err(_) => -INVALID,
        Ok(index)
            if roots[index].table.is_active()
                || state
                    .control
                    .carriers
                    .iter()
                    .any(|carrier| carrier.active_root.load(Ordering::Acquire) == root) =>
        {
            -STATE
        }
        Ok(index) => {
            retired_root = Some(roots.remove(index));
            0
        }
    };
    drop(roots);
    drop(retired_root);
    crate::arch::irq::disable_local();
    state.set_phase(RETURNING);
    result
}

#[unsafe(no_mangle)]
extern "C" fn kernelet_host_pt_activate_impl(root: u64) -> i64 {
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return -STATE;
    };
    let Some(_admission) = state.admit_service() else {
        return -STATE;
    };
    let roots = state.execution.roots.lock();
    let table = if root == 0 {
        Some(None)
    } else {
        roots
            .binary_search_by_key(&root, |entry| entry.paddr)
            .ok()
            .map(|index| Some(roots[index].table.clone()))
    };
    let result = if let Some(table) = table {
        let activated = if let Some(table) = table {
            // The registry lock pins both registrations through the synchronous
            // CR3 commit. The carrier keeps its old active reservation until the
            // new root has been installed; no intermediate Host root is needed.
            let irq_guard = crate::irq::disable_local();
            state.vm_space.activate_registered_root(table, &irq_guard)
        } else {
            // Explicit deactivation still leaves the old root through HostRoot.
            state.install_host_root();
            state.vm_space.set_registered_root(None);
            true
        };
        if activated {
            state.active_root.set(root as usize);
            state.control.carriers[state.vcpu as usize]
                .active_root
                .store(root, Ordering::Release);
            0
        } else {
            -STATE
        }
    } else {
        -INVALID
    };
    drop(roots);
    state.set_phase(RETURNING);
    result
}

#[unsafe(no_mangle)]
extern "C" fn kernelet_host_tlb_shootdown_impl(root: u64, start: u64, len: u64) -> i64 {
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return -STATE;
    };
    let Some(_admission) = state.admit_service() else {
        return -STATE;
    };
    state.enter_schedulable_service();
    let result = if root == 0 {
        // A local invalidation has no root registry or remote wait. Keep IRQs
        // masked so this physical CPU performs it before the fixed epilogue
        // restores the carrier's unchanged desired root.
        flush_local_carrier_tlb(start, len)
    } else if let Some(op) = shootdown_op(start, len) {
        // The service has installed the Host root and left the active set.
        // Keep physical IRQs enabled during the snapshot and IPI acknowledgement.
        crate::arch::irq::enable_local();
        let shootdown = {
            let roots = state.execution.roots.lock();
            match roots.binary_search_by_key(&root, |entry| entry.paddr) {
                Err(_) => Err(-INVALID),
                Ok(index) => roots[index].table.begin_shootdown().ok_or(-STATE),
            }
        };
        let result = match shootdown {
            Err(error) => error,
            Ok(shootdown) => {
                let targets = shootdown.active;
                #[cfg(all(kernelet_rq1_diagnostics, not(feature = "kernelet")))]
                let request = state.control.tlb_profile.begin(
                    crate::kernelet::tlb_profile::RequestDescriptor {
                        root_id: shootdown.root_id,
                        root_paddr: root,
                        root_generation: shootdown.generation,
                        source_vcpu: state.vcpu,
                        source_cpu: u32::from(CpuId::current_racy()),
                        start,
                        len,
                    },
                    &targets,
                );
                // The callback only flushes the local hardware TLB. It never
                // acquires `roots`, so simultaneous reciprocal waits can progress.
                crate::mm::tlb::dispatch_tlb_flush_on_cpus(
                    &targets,
                    op,
                    #[cfg(all(kernelet_rq1_diagnostics, not(feature = "kernelet")))]
                    request.as_ref(),
                )
                .wait();
                #[cfg(all(kernelet_rq1_diagnostics, not(feature = "kernelet")))]
                if let Some(request) = request {
                    request.wait_returned();
                }
                0
            }
        };
        crate::arch::irq::disable_local();
        result
    } else {
        -INVALID
    };
    state.set_phase(RETURNING);
    result
}

fn flush_local_carrier_tlb(start: u64, len: u64) -> i64 {
    if start != 0 || len != u64::MAX {
        return -INVALID;
    }
    crate::arch::mm::tlb_flush_all_including_global();
    0
}

fn shootdown_op(start: u64, len: u64) -> Option<TlbFlushOp> {
    if len == u64::MAX {
        return Some(TlbFlushOp::for_all());
    }
    let end = start.checked_add(len)?;
    if len == 0
        || len > 128 * 1024
        || !start.is_multiple_of(PAGE_SIZE as u64)
        || !len.is_multiple_of(PAGE_SIZE as u64)
        || end > MAX_USERSPACE_VADDR as u64
    {
        return None;
    }
    Some(TlbFlushOp::for_range(start as usize..end as usize))
}

#[cfg(ktest)]
mod test {
    use super::{
        INVALID, MAX_USERSPACE_VADDR, PAGE_SIZE, TlbFlushOp, flush_local_carrier_tlb, shootdown_op,
    };
    use crate::prelude::ktest;

    #[ktest]
    fn local_carrier_flush_rejects_partial_or_offset_ranges() {
        for (start, len) in [(0, 0), (0, PAGE_SIZE as u64), (1, u64::MAX)] {
            assert_eq!(flush_local_carrier_tlb(start, len), -INVALID);
        }
    }

    #[ktest]
    fn shootdown_accepts_user_ranges_and_full_flush() {
        assert_eq!(
            shootdown_op(0, PAGE_SIZE as u64),
            Some(TlbFlushOp::for_single(0))
        );
        let start = MAX_USERSPACE_VADDR - PAGE_SIZE;
        assert_eq!(
            shootdown_op(start as u64, PAGE_SIZE as u64),
            Some(TlbFlushOp::for_single(start))
        );
        assert_eq!(shootdown_op(0, u64::MAX), Some(TlbFlushOp::for_all()));
    }

    #[ktest]
    fn shootdown_rejects_invalid_ranges() {
        for (start, len) in [
            (0, 0),
            (1, PAGE_SIZE as u64),
            (0, PAGE_SIZE as u64 - 1),
            (MAX_USERSPACE_VADDR as u64, PAGE_SIZE as u64),
            (0, 128 * 1024 + PAGE_SIZE as u64),
            (u64::MAX - PAGE_SIZE as u64 + 1, PAGE_SIZE as u64),
        ] {
            assert_eq!(shootdown_op(start, len), None);
        }
    }
}
