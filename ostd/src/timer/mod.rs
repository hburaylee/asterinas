// SPDX-License-Identifier: MPL-2.0

//! The timer support.

mod jiffies;

use alloc::{boxed::Box, vec::Vec};
use core::{cell::RefCell, sync::atomic::Ordering};

pub use jiffies::Jiffies;
use spin::Once;

#[cfg(feature = "kernelet")]
use crate::cpu_local_cell;
use crate::{
    arch::trap::TrapFrame,
    cpu::{CpuId, PinCurrentCpu},
    cpu_local, irq,
};

/// The timer frequency in Hz.
///
/// Here we choose 1000Hz since 1000Hz is easier for unit conversion and convenient for timer.
/// What's more, the frequency cannot be set too high or too low, 1000Hz is a modest choice.
///
/// For system performance reasons, this rate cannot be set too high, otherwise most of the time is
/// spent in executing timer code.
pub const TIMER_FREQ: u64 = 1000;

#[cfg(feature = "kernelet")]
const TICK_NS: u64 = 1_000_000_000 / TIMER_FREQ;

type InterruptCallback = Box<dyn Fn() + Sync + Send>;

#[cfg(any(feature = "kernelet", ktest))]
type SampledTaskCallback =
    Box<dyn Fn(&crate::task::Task, crate::cpu::PrivilegeLevel, u64) + Sync + Send>;

static NEXT_EXPIRY: Once<fn(CpuId) -> Option<u64>> = Once::new();
static DEADLINE_CALLBACK: Once<fn()> = Once::new();
static IDLE_ELAPSED_CALLBACK: Once<fn(u64)> = Once::new();

#[cfg(feature = "kernelet")]
cpu_local_cell! {
    static LAST_IDLE_JIFFIES: u64 = 0;
}

cpu_local! {
    static INTERRUPT_CALLBACKS: RefCell<Vec<InterruptCallback>> = RefCell::new(Vec::new());
}

#[cfg(any(feature = "kernelet", ktest))]
cpu_local! {
    static SAMPLED_TASK_CALLBACKS: RefCell<Vec<SampledTaskCallback>> = RefCell::new(Vec::new());
}

/// Registers a function that will be executed during the timer interrupt on the current CPU.
pub fn register_callback_on_cpu<F>(func: F)
where
    F: Fn() + Sync + Send + 'static,
{
    let irq_guard = irq::disable_local();
    INTERRUPT_CALLBACKS
        .get_with(&irq_guard)
        .borrow_mut()
        .push(Box::new(func));
}

/// Registers accounting for physical samples of an explicitly identified Task.
///
/// In a kernelet, ordinary timer callbacks can run after the sampled Task has
/// switched out. These callbacks instead receive its retained execution owner
/// and sampled privilege, once per nonempty count. They run at L1 with virtual
/// IRQs disabled, on the sampling vCPU, before an outgoing Task can migrate or
/// free its stack. They must not sleep or infer the sample owner from the
/// current Task, current Thread, or its local data. Timer actions must retain
/// their own targets. The count is not a new global timer advance.
#[cfg(any(feature = "kernelet", ktest))]
pub fn register_sampled_task_callback_on_cpu<F>(func: F)
where
    F: Fn(&crate::task::Task, crate::cpu::PrivilegeLevel, u64) + Sync + Send + 'static,
{
    let irq_guard = irq::disable_local();
    SAMPLED_TASK_CALLBACKS
        .get_with(&irq_guard)
        .borrow_mut()
        .push(Box::new(func));
}

#[cfg(any(feature = "kernelet", ktest))]
pub(crate) fn call_sampled_task_callbacks(
    task: &crate::task::Task,
    privilege: crate::cpu::PrivilegeLevel,
    ticks: u64,
) {
    let irq_guard = irq::disable_local();
    let callbacks = SAMPLED_TASK_CALLBACKS.get_with(&irq_guard);
    for callback in callbacks.borrow().iter() {
        callback(task, privilege, ticks);
    }
}

/// Registers the next timer expiry, as an absolute elapsed jiffy, for an idle CPU.
///
/// In a kernelet the callback runs with virtual IRQs off after the vCPU has
/// entered an RCU extended quiescent state. It must not start an RCU reader or
/// sleep. The callback may retire objects; the idle path rechecks for ready
/// RCU callbacks before entering the Host wait.
pub fn register_next_expiry_callback(func: fn(CpuId) -> Option<u64>) {
    NEXT_EXPIRY.call_once(|| func);
}

/// Registers the timer-wheel callback used after an idle deadline expires.
pub fn register_deadline_callback(func: fn()) {
    DEADLINE_CALLBACK.call_once(|| func);
}

/// Registers a bulk idle-time accounting callback.
pub fn register_idle_elapsed_callback(func: fn(u64)) {
    IDLE_ELAPSED_CALLBACK.call_once(|| func);
}

/// Enables local interrupts and halts until work or the next timer deadline.
///
/// The caller has disabled local interrupts and forgotten its guard.
pub(crate) fn enable_local_and_halt() {
    #[cfg(not(feature = "kernelet"))]
    crate::arch::irq::enable_local_and_halt();

    #[cfg(feature = "kernelet")]
    {
        use crate::kernelet::entry;

        // The caller is the inner idle Task and has left virtual IRQs off.
        // Keep them off until after the Host service returns and the idle RCU
        // state is cleared. Otherwise an upcall could start a new reader while
        // this vCPU still counts as quiescent.
        // SAFETY: `halt_cpu` checked that its idle Task can sleep, so there is
        // no preemption guard or RCU reader, and it left virtual IRQs disabled.
        if !unsafe { crate::sync::enter_idle() } {
            crate::arch::irq::enable_local();
            // SAFETY: This idle Task has no RCU read-side guard, and virtual
            // IRQs are enabled before completed callbacks may run.
            unsafe { crate::sync::finish_grace_period() };
            return;
        }

        let now_ns = entry::clock_now_ns();
        let deadline_ns = NEXT_EXPIRY
            .get()
            .map(|next| {
                next(CpuId::current_racy())
                    .map(|jiffies| jiffies.saturating_mul(TICK_NS).max(1))
                    .unwrap_or(u64::MAX)
            })
            .unwrap_or(0);
        let fallback_deadline = now_ns.saturating_add(TICK_NS);

        // Deadline discovery may discard canceled timers and queue their RCU
        // drops. Do not park when this vCPU must execute those callbacks.
        // SAFETY: This idle Task has kept virtual IRQs off since `enter_idle`.
        if !unsafe { crate::sync::can_park_idle() } {
            crate::arch::irq::enable_local();
            // SAFETY: The idle RCU state was retracted and no reader is held.
            unsafe { crate::sync::finish_grace_period() };
            return;
        }

        let result = (entry::services().vcpu_idle)(deadline_ns);
        // SAFETY: The Host service returns without an upcall while virtual
        // IRQs are off, so no reader ran during this idle interval.
        unsafe { crate::sync::leave_idle() };
        assert!(
            result >= 0,
            "Host refused to idle the virtual CPU: {result}"
        );

        let parked_ns = entry::vcpu_record().parked_ns.load(Ordering::Acquire);
        let completed_idle_jiffies = parked_ns / TICK_NS;
        let elapsed_idle_jiffies = completed_idle_jiffies.saturating_sub(LAST_IDLE_JIFFIES.load());
        LAST_IDLE_JIFFIES.store(completed_idle_jiffies);
        if elapsed_idle_jiffies != 0 {
            if let Some(callback) = IDLE_ELAPSED_CALLBACK.get() {
                callback(elapsed_idle_jiffies);
            }
        }

        let deadline = if deadline_ns == 0 {
            fallback_deadline
        } else {
            deadline_ns
        };
        crate::arch::irq::enable_local();
        // SAFETY: The idle Task has left its extended quiescent state and
        // holds no RCU read-side guard. This is ordinary kernelet context.
        unsafe { crate::sync::finish_grace_period() };
        if entry::clock_now_ns() >= deadline {
            if let Some(callback) = DEADLINE_CALLBACK.get() {
                callback();
            }
        }
    }
}

pub(crate) fn call_timer_callback_functions(_: &TrapFrame) {
    #[cfg(any(feature = "kernelet-host", feature = "kernelet", kernelet_rq1, ktest))]
    crate::task::scheduler::runtime_ticks();
    #[cfg(feature = "kernelet-host")]
    crate::kernelet::host_run::on_host_tick();
    let irq_guard = irq::disable_local();

    if irq_guard.current_cpu() == CpuId::bsp() {
        #[cfg(not(feature = "kernelet"))]
        jiffies::ELAPSED.fetch_add(1, Ordering::Relaxed);
        #[cfg(feature = "kernelet-host")]
        crate::kernelet::account::on_timer_tick();
        #[cfg(feature = "kernelet-host")]
        crate::kernelet::clock::publish();
    }

    let callbacks_guard = INTERRUPT_CALLBACKS.get_with(&irq_guard);
    for callback in callbacks_guard.borrow().iter() {
        (callback)();
    }
    drop(callbacks_guard);
}

#[cfg(ktest)]
mod sampled_task_tests {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};

    use crate::{
        cpu::PrivilegeLevel,
        prelude::*,
        task::{Task, TaskOptions},
    };

    struct SampleCounts {
        user: AtomicU64,
        kernel: AtomicU64,
    }

    #[ktest]
    fn accounting_uses_explicit_task_without_changing_current() {
        let counts = || {
            Arc::new(SampleCounts {
                user: AtomicU64::new(0),
                kernel: AtomicU64::new(0),
            })
        };
        let first_counts = counts();
        let second_counts = counts();
        let first = TaskOptions::new(|| {})
            .data(first_counts.clone())
            .build()
            .unwrap();
        let second = TaskOptions::new(|| {})
            .data(second_counts.clone())
            .build()
            .unwrap();
        let current = Task::current().map(|task| task.cloned());
        let expected_current = current.as_ref().map(Arc::downgrade);
        super::register_sampled_task_callback_on_cpu(move |task, privilege, ticks| {
            let Some(counts) = task.data().downcast_ref::<Arc<SampleCounts>>() else {
                return;
            };
            let current = Task::current();
            if let Some(expected) = expected_current.as_ref() {
                let expected = expected.upgrade().unwrap();
                assert!(core::ptr::eq(&**current.as_ref().unwrap(), &*expected));
            } else {
                assert!(current.is_none());
            }
            assert!(current.is_none_or(|current| !core::ptr::eq(&*current, task)));
            let counter = match privilege {
                PrivilegeLevel::User => &counts.user,
                PrivilegeLevel::Kernel => &counts.kernel,
            };
            counter.fetch_add(ticks, Ordering::Relaxed);
        });
        crate::irq::call_sampled_task_tick_callback_functions(&first, PrivilegeLevel::User, 3);
        crate::irq::call_sampled_task_tick_callback_functions(&first, PrivilegeLevel::Kernel, 2);
        crate::irq::call_sampled_task_tick_callback_functions(&second, PrivilegeLevel::User, 1);
        assert_eq!(first_counts.user.load(Ordering::Relaxed), 3);
        assert_eq!(first_counts.kernel.load(Ordering::Relaxed), 2);
        assert_eq!(second_counts.user.load(Ordering::Relaxed), 1);
        assert_eq!(second_counts.kernel.load(Ordering::Relaxed), 0);
        match current {
            Some(current) => assert!(Arc::ptr_eq(&Task::current().unwrap().cloned(), &current)),
            None => assert!(Task::current().is_none()),
        }
    }
}
