// SPDX-License-Identifier: MPL-2.0

//! The image-side view of Host-published frame grants and metadata.

use core::sync::atomic::{AtomicU32, Ordering};

use super::{
    abi::{GRAIN_SIZE, InfoPage, META_SECTION_BYTES, NO_META_BLOCK, RunDesc},
    entry,
};
use crate::{
    boot::memory_region::{MemoryRegion, MemoryRegionArray, MemoryRegionType},
    mm::PAGE_SIZE,
};

const META_SLOT_BYTES: usize = 64;

// The frame allocator temporarily masks virtual IRQs and can deliver a grant
// notification when it restores them. Keep IRQs masked until the import count
// is committed and this lock is released, so delivery cannot reenter import.
static IMPORTED_RUNS: crate::sync::SpinLock<u32, crate::sync::LocalIrqDisabled> =
    crate::sync::SpinLock::new(0);

fn shared_at<T>(offset: u32) -> &'static T {
    let addr = (entry::boot_args() as *const _ as usize) + offset as usize;
    // SAFETY: The Host maps and pins the shared pages for the instance
    // lifetime. The offset names a page-aligned object validated at entry.
    unsafe { &*(addr as *const T) }
}

fn info() -> &'static InfoPage {
    shared_at(entry::boot_args().info_page)
}

/// Observes the Host's sticky lifecycle notice before virtual callbacks.
pub(crate) fn is_dying() -> bool {
    info().dying.load(Ordering::Acquire) != 0
}

/// Publishes the initial grant and returns its boot-visible memory regions.
pub(crate) fn init_initial_grant() -> MemoryRegionArray {
    let boot = entry::boot_args();
    let info = info();
    let runs = info.runs.load(Ordering::Acquire) as usize;
    assert!(runs <= boot.max_meta_sections as usize * META_SECTION_BYTES / GRAIN_SIZE);
    let ceiling = info.max_paddr.load(Ordering::Acquire) as usize;
    crate::mm::frame::init_kernelet_max_paddr(ceiling);
    let mut regions = MemoryRegionArray::new();

    for index in 0..runs {
        let addr =
            boot as *const _ as usize + boot.grant_table as usize + index * size_of::<RunDesc>();
        // SAFETY: `runs` is bounded by the one mapped run-table page, and
        // the Host publishes each initialized descriptor before its count.
        let run = unsafe { &*(addr as *const RunDesc) };
        let paddr = run.paddr as usize;
        let bytes = run.grains as usize * GRAIN_SIZE;
        assert!(paddr.is_multiple_of(GRAIN_SIZE) && bytes != 0);
        assert!(paddr.checked_add(bytes).is_some_and(|end| end <= ceiling));
        crate::mm::frame::allocator::add_kernelet_grant(paddr, bytes);
        regions
            .push(MemoryRegion::new(paddr, bytes, MemoryRegionType::Usable))
            .expect("the grant table exceeds boot memory-region capacity");
    }
    *IMPORTED_RUNS.lock() = runs as u32;
    regions
}

/// Imports newly published runs once, before exposing them to allocation.
pub(crate) fn rescan_grants() {
    let mut imported = IMPORTED_RUNS.lock();
    let published = info().runs.load(Ordering::Acquire);
    let boot = entry::boot_args();
    assert!(
        published as usize <= boot.max_meta_sections as usize * META_SECTION_BYTES / GRAIN_SIZE
    );
    crate::mm::frame::extend_kernelet_max_paddr(info().max_paddr.load(Ordering::Acquire) as usize);
    while *imported < published {
        let address = boot as *const _ as usize
            + boot.grant_table as usize
            + *imported as usize * size_of::<RunDesc>();
        // SAFETY: The acquire count covers this immutable published descriptor.
        let run = unsafe { &*(address as *const RunDesc) };
        crate::mm::frame::allocator::add_kernelet_grant(
            run.paddr as usize,
            run.grains as usize * GRAIN_SIZE,
        );
        *imported += 1;
    }
}

/// Requests one bounded refill after the image allocator releases its lock.
pub(crate) fn request_grains(bytes: usize) -> bool {
    let grains = bytes.div_ceil(GRAIN_SIZE).max(1);
    if grains > super::abi::MAX_GRAINS_PER_REQUEST as usize || is_dying() {
        return false;
    }
    let result = (entry::services().grains_request)(grains as u32, grains as u32);
    if result > 0 {
        rescan_grants();
        true
    } else {
        false
    }
}

/// Translates a granted frame through the Host's compact section index.
pub(crate) fn frame_to_meta(paddr: usize) -> usize {
    let boot = entry::boot_args();
    let ceiling = info().max_paddr.load(Ordering::Acquire) as usize;
    assert!(paddr < ceiling);
    let section = paddr / META_SECTION_BYTES;
    let index = shared_at::<AtomicU32>(boot.meta_section_index + (section * 4) as u32);
    let block = index.load(Ordering::Acquire);
    assert!(
        block != NO_META_BLOCK && block < boot.max_meta_sections,
        "frame metadata missing: paddr={paddr:#x}, section={section}, block={block}, index_offset={:#x}",
        boot.meta_section_index,
    );
    let frame = (paddr % META_SECTION_BYTES) / PAGE_SIZE;
    boot.meta_base as usize + block as usize * GRAIN_SIZE + frame * META_SLOT_BYTES
}

/// Returns whether the Host has published a metadata block for this frame.
/// Buddy lookups can probe an adjacent, ungranted section while coalescing.
pub(crate) fn has_meta(paddr: usize) -> bool {
    let boot = entry::boot_args();
    if paddr >= info().max_paddr.load(Ordering::Acquire) as usize {
        return false;
    }
    let mut granted = false;
    for run_index in 0..info().runs.load(Ordering::Acquire) as usize {
        let addr = boot as *const _ as usize
            + boot.grant_table as usize
            + run_index * size_of::<RunDesc>();
        // SAFETY: `runs` is published only after the Host initialized the
        // pinned descriptor page; entry validation bounds that shared page.
        let run = unsafe { &*(addr as *const RunDesc) };
        let start = run.paddr as usize;
        let end = start + run.grains as usize * GRAIN_SIZE;
        if (start..end).contains(&paddr) {
            granted = true;
            break;
        }
    }
    if !granted {
        return false;
    }
    let section = paddr / META_SECTION_BYTES;
    let index = shared_at::<AtomicU32>(boot.meta_section_index + (section * 4) as u32);
    let block = index.load(Ordering::Acquire);
    block != NO_META_BLOCK && block < info().meta_blocks.load(Ordering::Acquire)
}

/// Recovers a frame address from a slot in the compact metadata window.
pub(crate) fn meta_to_frame(vaddr: usize) -> usize {
    let boot = entry::boot_args();
    let offset = vaddr
        .checked_sub(boot.meta_base as usize)
        .expect("invalid metadata address");
    let block = offset / GRAIN_SIZE;
    assert!(block < info().meta_blocks.load(Ordering::Acquire) as usize);
    let section = shared_at::<AtomicU32>(boot.meta_block_sections + (block * 4) as u32)
        .load(Ordering::Acquire) as usize;
    let frame = (offset % GRAIN_SIZE) / META_SLOT_BYTES;
    section * META_SECTION_BYTES + frame * PAGE_SIZE
}
