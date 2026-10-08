// SPDX-License-Identifier: MPL-2.0

//! Image page-table root services: register, unregister, activate, and TLB
//! shootdown.
//!
//! Registration validates a Guest-provided root against the Host-built boot
//! page before that root may be activated on any CPU.

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::{RETURNING, current_carrier_state, resources::RootRegistration};
use crate::{
    cpu::{CpuId, CpuSet},
    kernelet::abi::{BootArgs, INVALID, STATE},
    mm::PAGE_SIZE,
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
    let result = if root == 0
        || !root.is_multiple_of(PAGE_SIZE as u64)
        || !state.guest_memory.contains(root, PAGE_SIZE)
    {
        -INVALID
    } else {
        let boot = unsafe { &*(state.boot_args as *const BootArgs) };
        let mut valid = true;
        for (index, expected) in boot.kernel_half_entries.iter().enumerate() {
            let mut bytes = [0u8; 8];
            let addr = root + ((256 + index) * size_of::<u64>()) as u64;
            if state.guest_memory.read(addr, &mut bytes).is_err()
                || u64::from_le_bytes(bytes) != *expected
            {
                valid = false;
                break;
            }
        }
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
            if !roots[index].active.is_empty()
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
    state.install_host_root();
    let roots = state.execution.roots.lock();
    let result = if root == 0
        || roots
            .binary_search_by_key(&root, |entry| entry.paddr)
            .is_ok()
    {
        // Keep the Host root through the service epilogue. The final assembly
        // transition installs this registered root immediately before entry.
        state.active_root.set(root as usize);
        state.control.carriers[state.vcpu as usize]
            .active_root
            .store(root, Ordering::Release);
        0
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
    let result = if len != u64::MAX
        && start
            .checked_add(len)
            .is_none_or(|end| end > usize::MAX as u64 || len > 128 * 1024)
    {
        -INVALID
    } else {
        // The service has installed the Host root and left the active set.
        // Keep physical IRQs enabled during allocation and IPI acknowledgement.
        crate::arch::irq::enable_local();
        let mut target_cpus = Vec::<CpuId>::new();
        let result = if target_cpus
            .try_reserve_exact(crate::cpu::num_cpus())
            .is_err()
        {
            -STATE
        } else {
            let mut roots = state.execution.roots.lock();
            match roots.binary_search_by_key(&root, |entry| entry.paddr) {
                Err(_) => -INVALID,
                Ok(index) => match roots[index].generation.checked_add(1) {
                    None => -STATE,
                    Some(generation) => {
                        roots[index].generation = generation;
                        target_cpus.extend(roots[index].active.iter());
                        0
                    }
                },
            }
        };
        if result == 0 {
            let mut targets = CpuSet::new_empty();
            for cpu in target_cpus {
                targets.add(cpu);
            }
            // The callback only flushes the local hardware TLB. It never
            // acquires `roots`, so simultaneous reciprocal waits can progress.
            crate::smp::inter_processor_call(
                &targets,
                crate::arch::mm::tlb_flush_all_excluding_global,
            )
            .wait();
        }
        crate::arch::irq::disable_local();
        result
    };
    state.set_phase(RETURNING);
    result
}
