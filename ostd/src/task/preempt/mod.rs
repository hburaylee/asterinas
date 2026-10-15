// SPDX-License-Identifier: MPL-2.0

pub(super) mod cpu_local;
mod guard;

pub use self::guard::{DisabledPreemptGuard, disable_preempt};

/// Checks for preemption after leaving an atomic section.
#[cfg(all(target_arch = "x86_64", not(feature = "kernelet")))]
#[inline]
pub(crate) fn check_preempt() {
    if !cpu_local::should_preempt() {
        return;
    }

    // A bottom half may release its final guard with IRQs still off. Bootstrap
    // must also finish installing its idle Task before the first switch.
    if !crate::irq::InterruptLevel::current().is_task_context()
        || !crate::arch::irq::is_local_enabled()
        || super::Task::current().is_none()
    {
        return;
    }

    super::scheduler::might_preempt();
}

/// Halts the CPU until interrupts if no preemption is required.
///
/// This function will return if:
///  - preemption is required when calling this function,
///  - preemption is required during halting the CPU, or
///  - interrupts occur during halting the CPU.
///
/// This function will perform preemption before returning if
/// preemption is required.
///
/// # Panics
///
/// This function will panic if it is called in the atomic mode
/// ([`crate::task::atomic_mode`]) or from a kernelet's one-shot boot Task.
#[track_caller]
pub fn halt_cpu() {
    #[cfg(feature = "kernelet")]
    assert!(
        !super::Task::current().is_some_and(|task| task.is_boot_task()),
        "a boot Task cannot halt"
    );
    crate::task::atomic_mode::might_sleep();

    let irq_guard = crate::irq::disable_local();

    if cpu_local::need_preempt() {
        drop(irq_guard);
    } else {
        core::mem::forget(irq_guard);
        // IRQs were previously enabled (checked by `might_sleep`). So we can re-enable them now.
        crate::timer::enable_local_and_halt();
    }

    super::scheduler::might_preempt();
}
