// SPDX-License-Identifier: MPL-2.0

//! Virtual local-interrupt state for a kernelet vCPU.

use core::sync::atomic::Ordering;

use crate::kernelet::{
    abi::{STATE, STOP_PANIC},
    entry,
};

pub(crate) fn enable_local() {
    entry::vcpu_record().irq_off.store(0, Ordering::Release);
    entry::deliver_pending();
    entry::release_host_preemption();
    if entry::vcpu_record().guards.load(Ordering::Acquire) == 0
        && crate::irq::InterruptLevel::current().is_task_context()
        && !crate::task::virq_delivery_deferred()
        && crate::task::Task::current().is_some()
    {
        // The first context switch never returns. Let bootstrap finish
        // initializing this CPU and enqueue its idle Task before switching.
        crate::task::scheduler::might_preempt();
    }
}

pub(crate) fn disable_local() {
    entry::disable_virtual_irqs();
}

pub(crate) fn is_local_enabled() -> bool {
    entry::vcpu_record().irq_off.load(Ordering::Acquire) == 0
}

pub(crate) fn disable_local_and_halt() -> ! {
    disable_local();
    const MESSAGE: &[u8] = b"virtual CPU halted";
    (entry::services().stop)(
        STOP_PANIC,
        STATE as u32,
        MESSAGE.as_ptr(),
        MESSAGE.len() as u32,
    )
}
