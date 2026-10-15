// SPDX-License-Identifier: MPL-2.0

//! Runs Host hooks on permanent per-CPU Host stacks, with no unwind across
//! the assembly stack switch. The caller keeps native preemption disabled.

use alloc::vec::Vec;
use core::{
    mem::MaybeUninit,
    sync::atomic::{AtomicBool, Ordering},
};

use spin::Once;

use crate::{
    cpu::{CpuId, CpuSet, PinCurrentCpu, num_cpus},
    mm::{
        CachePolicy, FrameAllocOptions, PAGE_SIZE, PageFlags, PageProperty, PrivilegedPageFlags,
        kspace::kvirt_area::KVirtArea,
    },
    task::DisabledPreemptGuard,
    util::id_set::Id,
};

const STACK_BYTES: usize = 64 * 1024;
const STACK_PAGES: usize = STACK_BYTES / PAGE_SIZE;
const STACK_STRIDE: usize = STACK_BYTES + 2 * PAGE_SIZE;
const STACK_PROP: PageProperty = PageProperty {
    flags: PageFlags::RW,
    cache: CachePolicy::Writeback,
    priv_flags: PrivilegedPageFlags::GLOBAL,
};

// Host CPU IDs are fixed before any instance is prepared. Once published,
// these mappings and their frame ownership remain alive for the Host lifetime.
static STACKS: Once<HookStacks> = Once::new();

struct HookStacks {
    area: KVirtArea,
    active: Vec<AtomicBool>,
}

impl HookStacks {
    fn new() -> crate::Result<Self> {
        let cpus = num_cpus() as usize;
        if cpus == 0 {
            return Err(crate::Error::InvalidArgs);
        }
        let bytes = cpus
            .checked_mul(STACK_STRIDE)
            .ok_or(crate::Error::Overflow)?;
        let mut active = Vec::new();
        active
            .try_reserve_exact(cpus)
            .map_err(|_| crate::Error::NoMemory)?;
        active.resize_with(cpus, || AtomicBool::new(false));
        let mut mappings = Vec::new();
        mappings
            .try_reserve_exact(cpus)
            .map_err(|_| crate::Error::NoMemory)?;
        for cpu in 0..cpus {
            let mut frames = Vec::new();
            frames
                .try_reserve_exact(STACK_PAGES)
                .map_err(|_| crate::Error::NoMemory)?;
            for _ in 0..STACK_PAGES {
                frames.push(FrameAllocOptions::new().alloc_frame()?);
            }
            mappings.push((cpu * STACK_STRIDE + PAGE_SIZE, frames.into_iter()));
        }
        let area = KVirtArea::try_reserve(bytes)?.with_synchronous_reclaim();
        area.map_additional_frames_batch(mappings.into_iter(), STACK_PROP)?;
        // The arena may reuse virtual addresses. Invalidate even Global
        // translations on every Host CPU before publishing any stack top.
        crate::smp::inter_processor_call(
            &CpuSet::new_full(),
            crate::arch::mm::tlb_flush_all_including_global,
        )
        .wait();
        Ok(Self { area, active })
    }

    fn stack_range(&self, cpu: CpuId) -> core::ops::Range<usize> {
        let start = self.area.start() + cpu.as_usize() * STACK_STRIDE + PAGE_SIZE;
        start..start + STACK_BYTES
    }
}

/// Preallocates all Host hook stacks before the first carrier may enter.
///
/// The initial call runs in task context with physical IRQs enabled, because
/// mapping publication and failure cleanup wait for remote TLB invalidation.
/// Allocation failure leaves the Once unpublished, so preparation can retry.
pub(super) fn prepare() -> crate::Result<()> {
    if STACKS.get().is_some() {
        return Ok(());
    }
    if !crate::arch::irq::is_local_enabled() {
        return Err(crate::Error::AccessDenied);
    }
    STACKS.try_call_once(HookStacks::new).map(|_| ())
}

struct ActiveStack<'a>(&'a AtomicBool);

impl Drop for ActiveStack<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

struct Call<F, R> {
    function: Option<F>,
    result: MaybeUninit<R>,
}

unsafe extern "C" {
    fn kernelet_host_on_hook_stack(
        function: unsafe extern "C" fn(*mut ()),
        context: *mut (),
        stack_top: usize,
    );
}

/// # Safety
///
/// `function` must catch any unwind before returning through the assembly.
/// The caller must have successfully prepared the Host hook stacks.
///
/// # Panics
///
/// Panics before switching stacks if this CPU is already running a hook.
pub(super) unsafe fn call<F: FnOnce() -> R, R>(guard: &DisabledPreemptGuard, function: F) -> R {
    unsafe extern "C" fn invoke<F: FnOnce() -> R, R>(context: *mut ()) {
        // SAFETY: `call` keeps this exclusive local live on the shared stack
        // while the synchronous callback runs on the private hook stack.
        let call = unsafe { &mut *context.cast::<Call<F, R>>() };
        call.result.write(call.function.take().unwrap()());
    }

    let mut context = Call {
        function: Some(function),
        result: MaybeUninit::uninit(),
    };
    let stacks = STACKS
        .get()
        .expect("Host hook stacks have not been prepared");
    let cpu = guard.current_cpu();
    let active = &stacks.active[cpu.as_usize()];
    assert!(
        active
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok(),
        "nested Host hooks cannot share a CPU's hook stack"
    );
    let _active = ActiveStack(active);
    // SAFETY: The native guard pins this CPU and excludes another Task's hook.
    // The active bit rejects recursive use of the same private stack. The
    // caller catches unwinds before returning to the assembly, and permanent
    // mappings retain the stack throughout this synchronous call.
    // The callback initializes result before the fixed synchronous return.
    unsafe {
        kernelet_host_on_hook_stack(
            invoke::<F, R>,
            (&mut context as *mut Call<F, R>).cast(),
            stacks.stack_range(cpu).end,
        );
        context.result.assume_init()
    }
}

#[cfg(ktest)]
mod test {
    use alloc::boxed::Box;
    use core::{cell::Cell, sync::atomic::AtomicUsize};

    use super::*;
    use crate::prelude::*;

    fn stack_pointer() -> usize {
        let rsp: usize;
        // SAFETY: Reading RSP leaves the stack and execution state unchanged.
        unsafe {
            core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags));
        }
        rsp
    }

    #[ktest]
    fn hooks_use_each_host_cpus_own_guarded_64k_stack() {
        static OBSERVED: Once<Vec<AtomicUsize>> = Once::new();
        prepare().unwrap();
        let observed = OBSERVED.call_once(|| {
            (0..num_cpus())
                .map(|_| AtomicUsize::new(0))
                .collect::<Vec<_>>()
        });
        crate::smp::inter_processor_call(&CpuSet::new_full(), || {
            let guard = crate::task::disable_preempt();
            let cpu = guard.current_cpu();
            // SAFETY: Preparation published permanent stacks; this callback
            // cannot unwind and the native guard spans the entire switch.
            let rsp = unsafe { call(&guard, stack_pointer) };
            OBSERVED.get().unwrap()[cpu.as_usize()].store(rsp, Ordering::Release);
        })
        .wait();
        let stacks = STACKS.get().unwrap();
        let guard = crate::task::disable_preempt();
        for cpu in crate::cpu::all_cpus() {
            let range = stacks.stack_range(cpu);
            assert_eq!(range.len(), STACK_BYTES);
            assert!(range.contains(&observed[cpu.as_usize()].load(Ordering::Acquire)));
            assert!(stacks.area.query(&guard, range.start).is_some());
            assert!(stacks.area.query(&guard, range.start - PAGE_SIZE).is_none());
            assert!(stacks.area.query(&guard, range.end).is_none());
            assert!(!stacks.active[cpu.as_usize()].load(Ordering::Acquire));
        }
    }

    #[ktest]
    fn hook_unwind_stays_on_private_stack_and_returns_before_reuse() {
        struct ObserveDrop<'a>(&'a Cell<usize>);
        impl Drop for ObserveDrop<'_> {
            fn drop(&mut self) {
                self.0.set(stack_pointer());
            }
        }

        prepare().unwrap();
        let dropped_rsp = Cell::new(0);
        let payload: Box<dyn core::any::Any + Send> = Box::new(0x64_u32);
        let guard = crate::task::disable_preempt();
        let stacks = STACKS.get().unwrap();
        let range = stacks.stack_range(guard.current_cpu());
        assert!(!range.contains(&stack_pointer()));
        // SAFETY: The unwind is caught on the private stack, before `invoke`
        // or the assembly switch returns. The guard pins the selected CPU.
        let result = unsafe {
            call(&guard, || {
                crate::panic::catch_unwind(|| {
                    let _observe = ObserveDrop(&dropped_rsp);
                    crate::panic::begin_panic(payload)
                })
            })
        };
        assert!(result.is_err());
        assert!(range.contains(&dropped_rsp.get()));
        assert!(!range.contains(&stack_pointer()));
        assert!(!stacks.active[guard.current_cpu().as_usize()].load(Ordering::Acquire));
        // SAFETY: The preceding invocation fully returned and released this
        // CPU's stack; the callback does not unwind.
        let reused_rsp = unsafe { call(&guard, stack_pointer) };
        assert!(range.contains(&reused_rsp));
    }
}
