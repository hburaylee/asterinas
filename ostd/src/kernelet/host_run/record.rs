// SPDX-License-Identifier: MPL-2.0

//! Bounded service record copying with scoped Host fault recovery.

use core::ops::Range;

use super::CarrierState;
use crate::{
    arch::{cpu::context::PageFaultErrorCode, mm as arch_mm, trap::TrapFrame},
    irq,
    kernelet::abi,
};

crate::cpu_local_cell! {
    static COPY_SOURCE_START: usize = 0;
    static COPY_SOURCE_END: usize = 0;
}

struct CopyGuard;

impl Drop for CopyGuard {
    fn drop(&mut self) {
        COPY_SOURCE_START.store(0);
        COPY_SOURCE_END.store(0);
    }
}

/// Copies an owned Image range, returning a borrow of the Host buffer only.
///
/// # Safety
///
/// The authenticated carrier must pin the Image, stacks and grants for this
/// synchronous call.
/// Mapped typed source bytes must have an existing shared byte borrow; ownership alone does not authorize reading arbitrary objects.
/// Unmapped source bytes are allowed and cause `-abi::INVALID` without a Rust borrow.
pub(super) unsafe fn read<'a>(
    state: &CarrierState,
    ptr: *const u8,
    len: u32,
    buffer: &'a mut [u8],
) -> Result<&'a [u8], i64> {
    let bytes = buffer.get_mut(..len as usize).ok_or(-abi::INVALID)?;
    if bytes.is_empty() {
        return Ok(bytes);
    }
    let start = ptr.addr();
    let end = start.checked_add(bytes.len()).ok_or(-abi::INVALID)?;
    let owned = (start >= state.image_start && end <= state.image_end)
        || state.execution.contains_stack_range(start, end)
        || start
            .checked_sub(crate::mm::kspace::LINEAR_MAPPING_BASE_VADDR)
            .is_some_and(|paddr| state.guest_memory.owns_range(paddr as u64, bytes.len()));
    if !owned {
        return Err(-abi::INVALID);
    }
    // SAFETY: Ownership is pinned above; the caller supplies the shared-byte
    // authorization for mapped bytes. `copy_into` rejects virtual overlap.
    unsafe { copy_into(ptr, bytes)? };
    Ok(bytes)
}

/// Copies bytes without constructing a reference to the source.
///
/// # Safety
///
/// On nonoverlapping ranges, mapped source bytes must be authorized for reads
/// for the call, and must not physically alias the Host destination borrow.
/// Unmapped source bytes are permitted.
/// Virtual overlap is rejected before any copy; an empty destination requires
/// no source access.
unsafe fn copy_into(source: *const u8, destination: &mut [u8]) -> Result<(), i64> {
    if destination.is_empty() {
        return Ok(());
    }
    let start = source.addr();
    let end = start.checked_add(destination.len()).ok_or(-abi::INVALID)?;
    let destination_start = destination.as_ptr().addr();
    let destination_end = destination_start
        .checked_add(destination.len())
        .ok_or(-abi::INVALID)?;
    if start == 0 || (start < destination_end && destination_start < end) {
        return Err(-abi::INVALID);
    }

    // Keep this private recovery marker on the same physical CPU. Only this
    // routine publishes it, and it makes no callback while the marker is live.
    let _irq = irq::disable_local();
    if COPY_SOURCE_START.load() != 0 {
        return Err(-abi::STATE);
    }
    COPY_SOURCE_END.store(end);
    COPY_SOURCE_START.store(start);
    let _copy = CopyGuard;
    // SAFETY: The caller authorizes mapped reads and owns the destination.
    // Virtual overlap is rejected above. The scoped exception fixup handles
    // unmapped source bytes and leaves destination faults fatal.
    let remaining =
        unsafe { arch_mm::__memcpy_fallible(destination.as_mut_ptr(), source, destination.len()) };
    if remaining != 0 {
        return Err(-abi::INVALID);
    }
    Ok(())
}

fn recoverable_read(error: usize, address: usize, range: Range<usize>) -> bool {
    let allowed = (PageFaultErrorCode::PRESENT | PageFaultErrorCode::PROTECTION).bits();
    error & !allowed == 0 && range.start != 0 && range.contains(&address)
}

/// Recovers only a scoped source-read fault in the native copy instructions.
pub(crate) fn recover_host_copy_fault(frame: &mut TrapFrame) -> bool {
    if frame.trap_num != 14 {
        return false;
    }
    let start = COPY_SOURCE_START.load();
    if start == 0 {
        return false;
    }
    let copy_start = arch_mm::__memcpy_fallible as *const () as usize;
    let copy_end = core::ptr::addr_of!(arch_mm::__memcpy_fallible_end) as usize;
    if !(copy_start..copy_end).contains(&frame.rip) {
        return false;
    }
    let address = x86_64::registers::control::Cr2::read_raw() as usize;
    if !recoverable_read(frame.error_code, address, start..COPY_SOURCE_END.load()) {
        return false;
    }
    crate::mm::fault::recover_kernel_copy_fault(frame)
}

#[cfg(ktest)]
mod tests {
    use super::*;
    use crate::{
        mm::{
            FrameAllocOptions, PAGE_SIZE, VmIo,
            kspace::kvirt_area::KVirtArea,
            page_prop::{CachePolicy, PageFlags, PageProperty, PrivilegedPageFlags},
        },
        prelude::*,
    };

    #[ktest]
    fn bounded_record_copy_preserves_bytes_and_rejects_overlap() {
        let source = [0x5a; crate::kernelet::abi::MAX_LOG_TEXT_BYTES as usize];
        let mut destination = [0; crate::kernelet::abi::MAX_LOG_TEXT_BYTES as usize];
        // SAFETY: Source and destination are disjoint, initialized arrays.
        unsafe { copy_into(source.as_ptr(), &mut destination) }.unwrap();
        assert_eq!(source, destination);
        let same = destination.as_ptr();
        // SAFETY: Virtual overlap is rejected before source access.
        assert_eq!(
            unsafe { copy_into(same, &mut destination) },
            Err(-abi::INVALID)
        );
        // SAFETY: An empty destination does not access the null source.
        unsafe { copy_into(core::ptr::null(), &mut []) }.unwrap();
    }

    #[ktest]
    fn unmapped_kernel_source_returns_invalid_and_clears_scope() {
        let source = KVirtArea::try_reserve(PAGE_SIZE).unwrap();
        let _irq = irq::disable_local();
        crate::arch::mm::tlb_flush_addr_range(&source.range());
        let mut destination = [0x6b; 16];
        // SAFETY: This reserved source is unmapped. No source reference is
        // formed; the real Host fault path fixes up the bounded raw copy.
        assert_eq!(
            unsafe { copy_into(source.start() as *const u8, &mut destination) },
            Err(-abi::INVALID)
        );
        assert_eq!(destination, [0x6b; 16]);
        assert_eq!(COPY_SOURCE_START.load(), 0);
        assert_eq!(COPY_SOURCE_END.load(), 0);
    }

    #[ktest]
    fn partial_kernel_source_returns_invalid_then_allows_valid_copy() {
        let frame = FrameAllocOptions::default().alloc_frame().unwrap();
        frame.write_bytes(PAGE_SIZE - 16, &[0x5a; 16]).unwrap();
        let source = KVirtArea::map_frames(
            2 * PAGE_SIZE,
            0,
            core::iter::once(frame),
            PageProperty {
                flags: PageFlags::RW,
                cache: CachePolicy::Writeback,
                priv_flags: PrivilegedPageFlags::empty(),
            },
        );
        let _irq = irq::disable_local();
        crate::arch::mm::tlb_flush_addr_range(&source.range());
        let mut destination = [0x6b; 32];
        let partial = (source.start() + PAGE_SIZE - 16) as *const u8;
        // SAFETY: The first half is initialized, owned byte storage. The second
        // half is reserved but unmapped. Neither aliases the Host destination.
        assert_eq!(
            unsafe { copy_into(partial, &mut destination) },
            Err(-abi::INVALID)
        );
        assert_eq!(destination[..16], [0x5a; 16]);
        assert_eq!(destination[16..], [0x6b; 16]);
        assert_eq!(COPY_SOURCE_START.load(), 0);
        assert_eq!(COPY_SOURCE_END.load(), 0);
        let valid = [0x7c; 32];
        // SAFETY: Both initialized arrays are disjoint; the prior recovery
        // scope has been cleared before this independent copy.
        unsafe { copy_into(valid.as_ptr(), &mut destination) }.unwrap();
        assert_eq!(destination, valid);
    }

    #[ktest]
    fn recovery_excludes_writes_execution_and_unrelated_addresses() {
        assert!(recoverable_read(0, 0x1010, 0x1000..0x1020));
        assert!(recoverable_read(
            PageFaultErrorCode::PRESENT.bits(),
            0x1010,
            0x1000..0x1020
        ));
        for error in [
            PageFaultErrorCode::WRITE,
            PageFaultErrorCode::USER,
            PageFaultErrorCode::RESERVED,
            PageFaultErrorCode::INSTRUCTION,
            PageFaultErrorCode::SHADOW_STACK,
            PageFaultErrorCode::SGX,
        ] {
            assert!(!recoverable_read(error.bits(), 0x1010, 0x1000..0x1020));
        }
        assert!(!recoverable_read(0, 0x1020, 0x1000..0x1020));
        assert!(!recoverable_read(0, 0x1010, 0..0));
        assert!(!recoverable_read(usize::MAX, 0x1010, 0x1000..0x1020));
    }
}
