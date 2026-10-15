// SPDX-License-Identifier: MPL-2.0

//! Virtual local-interrupt state for a kernelet vCPU.

use core::sync::atomic::Ordering;

use crate::kernelet::{
    abi::{STATE, STOP_PANIC},
    entry,
};

pub(crate) fn enable_local() {
    set_local_mask(false);
    // A local wake can request preemption without publishing a pending IRQ.
    // When neither action is needed, avoid all Task/context gate lookups.
    if entry::vcpu_record().pending.load(Ordering::Acquire) == 0
        && !crate::task::scheduler::should_preempt()
    {
        return;
    }
    if !can_receive_virtual_interrupts() {
        // Bootstrap must finish installing its idle Task. A scheduling
        // transition or upcall epilogue must finish before another upcall.
        return;
    }
    crate::task::scheduler::might_preempt();
    if entry::vcpu_record().pending.load(Ordering::Acquire) == 0 {
        return;
    }
    // Only the pending slow path reads Task-local progress. This borrowed
    // current Task remains this continuation's owner if an upcall migrates it.
    let Some(task) = crate::task::Task::current() else {
        return;
    };
    let completed = task.completed_virq_batches();
    let mut kicked_vcpu = None;
    #[cfg(kernelet_getpid_profile)]
    let mut window_started = false;
    #[cfg(kernelet_getpid_profile)]
    let mut _window_span = None;
    while task.completed_virq_batches() == completed {
        // One completed batch is enough even if producers keep pending
        // nonzero. An upcall can migrate this Task: reload every CPU gate.
        if entry::vcpu_record().pending.load(Ordering::Acquire) == 0
            || !can_receive_virtual_interrupts()
            || entry::copy_fault_record().pending.load(Ordering::Acquire) != 0
        {
            // A user-copy fault must be consumed by its recovery path before
            // the Host can redirect another virtual interrupt.
            return;
        }
        #[cfg(kernelet_getpid_profile)]
        if !window_started {
            use crate::kernelet::getpid_profile as profile;
            window_started = true;
            profile::event(profile::event_id::VIRQ_WINDOW);
            _window_span = profile::span(profile::stage::GUEST_VIRQ_WINDOW);
        }
        let vcpu = entry::vcpu_record().vcpu;
        if kicked_vcpu != Some(vcpu) {
            // Request one physical doorbell through the existing service.
            // Its common STI; RET enables physical IRQ delivery only after
            // returning to Guest code; the trap-return hook is the consumer.
            // If this Task resumed on another vCPU, kick that carrier once.
            kicked_vcpu = Some(vcpu);
            let result = (entry::services().vcpu_kick)(vcpu);
            assert_eq!(result, 0, "failed to kick a pending virtual interrupt");
        } else {
            core::hint::spin_loop();
        }
    }
}

#[inline]
fn can_receive_virtual_interrupts() -> bool {
    entry::vcpu_record().guards.load(Ordering::Acquire) == 0
        && entry::vcpu_record().irq_off.load(Ordering::Acquire) == 0
        && crate::irq::InterruptLevel::current().is_task_context()
        && !crate::task::virq_delivery_deferred()
        && crate::task::Task::current().is_some()
}

pub(crate) fn disable_local() {
    set_local_mask(true);
}

pub(crate) fn is_local_enabled() -> bool {
    let mask: u32;
    // SAFETY: The record selection and state read cannot be separated by a
    // virtual upcall. The Host pins this validated cooperation mapping.
    unsafe {
        crate::arch::cpu::local::record_asm!(
            "mov {mask:e}, dword ptr [{record_base} + {irq_offset}]";
            mask = out(reg) mask,
            irq_offset = const core::mem::offset_of!(crate::kernelet::abi::VcpuRecord, irq_off),
            options(nostack, readonly),
        );
    }
    mask == 0
}

#[inline]
fn set_local_mask(disabled: bool) {
    // SAFETY: The complete selection and store are nonredirectable. The
    // memory-clobbering asm plus x86 store ordering implements Release.
    unsafe {
        crate::arch::cpu::local::record_asm!(
            "mov dword ptr [{record_base} + {irq_offset}], {mask:e}";
            mask = in(reg) u32::from(disabled),
            irq_offset = const core::mem::offset_of!(crate::kernelet::abi::VcpuRecord, irq_off),
            options(nostack),
        );
    }
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
