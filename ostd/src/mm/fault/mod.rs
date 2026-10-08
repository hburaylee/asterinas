// SPDX-License-Identifier: MPL-2.0

//! Page fault handling.
//!
//! This module manages a handler that can address page faults occurring in the kernel due to
//! user-space addresses. For example, this occurs during [`FallibleVmRead::read_fallible`] and
//! [`FallibleVmWrite::write_fallible`].
//!
//! If the page fault is handled successfully, the read/write process continues and the fault
//! address is retried. Otherwise, those methods will return an error to indicate that the
//! read/write process cannot be completed.
//!
//! [`FallibleVmRead::read_fallible`]: super::FallibleVmRead::read_fallible
//! [`FallibleVmWrite::write_fallible`]: super::FallibleVmWrite::write_fallible

mod ex_table;

#[cfg(feature = "kernelet")]
use core::sync::atomic::Ordering;

use spin::Once;

#[cfg(not(target_arch = "loongarch64"))]
use crate::arch::cpu::context::CpuException;
#[cfg(target_arch = "loongarch64")]
use crate::arch::cpu::context::CpuExceptionInfo as CpuException;
#[cfg(feature = "kernelet")]
use crate::arch::cpu::context::{PageFaultErrorCode, RawPageFaultInfo};
use crate::{
    arch::trap::TrapFrame,
    mm::{MAX_USERSPACE_VADDR, Vaddr, fault::ex_table::ExTable},
};

/// A handler that handles page faults caused by user-space addresses.
///
/// The page fault is described in [`CpuException`]. If it can be resolved successfully,
/// this method will return `Ok(())`. Otherwise, it should return `Err(())`.
pub type UserPageFaultHandler = fn(&CpuException) -> Result<(), ()>;

static USER_PAGE_FAULT_HANDLER: Once<UserPageFaultHandler> = Once::new();

/// Injects a custom handler for page faults that occur in the kernel and
/// are caused by user-space addresses.
///
/// The function may be called only once; subsequent calls take no effect.
pub fn inject_user_page_fault_handler(handler: UserPageFaultHandler) {
    USER_PAGE_FAULT_HANDLER.call_once(|| handler);
}

/// Clears stale result state before an image-side fallible access.
/// A Host upcall is deferred while the marker is set by a fixup.
#[cfg(feature = "kernelet")]
pub(crate) fn clear_image_copy_fault() {
    crate::kernelet::entry::copy_fault_record()
        .pending
        .store(0, Ordering::Release);
}

/// Takes the hardware fault published by the Host's validated image fixup.
/// Keep the pending marker set until both fields are in local values, so a
/// physical IRQ cannot deliver an upcall that overwrites them mid-read.
#[cfg(feature = "kernelet")]
pub(crate) fn take_image_copy_fault() -> Option<CpuException> {
    let record = crate::kernelet::entry::copy_fault_record();
    if record.pending.load(Ordering::Acquire) == 0 {
        return None;
    }
    let addr = record.addr.load(Ordering::Relaxed) as usize;
    let error = record.error.load(Ordering::Relaxed) as usize;
    record.pending.store(0, Ordering::Release);
    if !(0..MAX_USERSPACE_VADDR).contains(&addr) {
        return None;
    }
    let error_code = PageFaultErrorCode::from_bits(error)?;
    Some(CpuException::PageFault(RawPageFaultInfo {
        error_code,
        addr,
    }))
}

/// Lets the kernel proper resolve an image-side user-copy page fault.
#[cfg(feature = "kernelet")]
pub(crate) fn resolve_image_copy_fault(exception: &CpuException) -> bool {
    USER_PAGE_FAULT_HANDLER
        .get()
        .expect("a page fault handler is missing")(exception)
    .is_ok()
}

/// The common interface that every CPU architecture-specific [`TrapFrame`] implements.
pub(crate) trait TrapFrameApi {
    /// Sets the instruction pointer.
    fn set_instruction_pointer(&mut self, ip: usize);

    /// Gets the instruction pointer.
    fn instruction_pointer(&self) -> usize;
}

/// Handles page fault from user space.
pub(crate) fn handle_user_page_fault(
    f: &mut TrapFrame,
    exception: &CpuException,
    fault_addr: Vaddr,
) {
    // The actual user space implementation should be responsible
    // for providing mechanism to treat the 0 virtual address.
    if !(0..MAX_USERSPACE_VADDR).contains(&fault_addr) {
        panic!(
            "Cannot handle kernel page fault: {:#x?}; trapframe: {:#x?}",
            exception, f
        );
    }

    let handler = USER_PAGE_FAULT_HANDLER
        .get()
        .expect("a page fault handler is missing");

    let res = handler(exception);
    // Copying bytes by bytes can recover directly
    // if handling the page fault successfully.
    if res.is_ok() {
        return;
    }

    // Use the exception table to recover to normal execution.
    let inst_addr = f.instruction_pointer();
    if let Some(new_addr) = ExTable::find_recovery_inst_addr(inst_addr) {
        f.set_instruction_pointer(new_addr);
    } else {
        panic!("Cannot handle user page fault; trapframe: {:#x?}", f);
    }
}
