// SPDX-License-Identifier: MPL-2.0

//! Kernel virtual memory allocation

use alloc::vec::Vec;
use core::ops::Range;

use self::allocator::kvirt_area_allocator;
use super::{KERNEL_PAGE_TABLE, KernelPtConfig, MappedItem};
use crate::{
    irq,
    mm::{
        HasSize, PAGE_SIZE, Paddr, Split, Vaddr,
        frame::{Frame, meta::AnyFrameMeta},
        page_prop::PageProperty,
        page_table::{largest_pages, max_page_level},
    },
};

mod allocator {
    use crate::{
        irq::DisabledLocalIrqGuard, mm::kspace::VMALLOC_VADDR_RANGE,
        util::range_alloc::RangeAllocator,
    };

    static KVIRT_AREA_ALLOCATOR: RangeAllocator = RangeAllocator::new(VMALLOC_VADDR_RANGE);

    /// Returns a reference to the kernel virtual memory allocator.
    ///
    /// [`DisabledLocalIrqGuard`] is required because DMA objects may be
    /// dropped in IRQ handlers. So the guard is necessary to prevent
    /// deadlocks. For more details, see [`crate::mm::dma`].
    ///
    /// Meanwhile, note that deadlocks may occur if the page table nodes locked
    /// in this file are also locked in other files where only preemption is
    /// disabled. This requires extra care.
    pub(super) fn kvirt_area_allocator(_guard: &DisabledLocalIrqGuard) -> &RangeAllocator {
        &KVIRT_AREA_ALLOCATOR
    }
}

/// Kernel virtual area.
///
/// A kernel virtual area manages a range of memory in [`VMALLOC_VADDR_RANGE`].
/// It can map a portion or the entirety of its virtual memory pages to
/// physical memory, whether tracked with metadata or not.
///
/// It is the caller's responsibility to ensure TLB coherence before using the
/// mapped virtual address on a certain CPU.
//
// FIXME: This caller-ensured design is very error-prone. A good option is to
// use a guard the pins the CPU and ensures TLB coherence while accessing the
// `KVirtArea`. However, `IoMem` need some non trivial refactoring to support
// being implemented on a `!Send` and `!Sync` guard.
#[derive(Debug)]
pub(crate) struct KVirtArea {
    range: Range<Vaddr>,
    synchronous_reclaim: bool,
}

impl HasSize for KVirtArea {
    fn size(&self) -> usize {
        self.range.len()
    }
}

impl Split for KVirtArea {
    fn split(self, offset: usize) -> (Self, Self) {
        assert!(offset.is_multiple_of(PAGE_SIZE));
        assert!(0 < offset && offset < self.size());

        let old = core::mem::ManuallyDrop::new(self);

        let left_range = old.start()..old.start() + offset;
        let right_range = old.start() + offset..old.end();
        (
            KVirtArea {
                range: left_range,
                synchronous_reclaim: old.synchronous_reclaim,
            },
            KVirtArea {
                range: right_range,
                synchronous_reclaim: old.synchronous_reclaim,
            },
        )
    }
}

impl KVirtArea {
    /// Keeps unmapped frames and the virtual reservation alive until every
    /// online CPU has invalidated its translations, including Global entries.
    ///
    /// Such an area must be dropped in task context with local IRQs enabled.
    /// This is needed for mappings shared by roots on multiple CPUs.
    pub(crate) fn with_synchronous_reclaim(mut self) -> Self {
        self.synchronous_reclaim = true;
        self
    }

    pub(crate) fn start(&self) -> Vaddr {
        self.range.start
    }

    pub(crate) fn end(&self) -> Vaddr {
        self.range.end
    }

    pub(crate) fn range(&self) -> Range<Vaddr> {
        self.range.start..self.range.end
    }

    #[cfg(ktest)]
    pub(crate) fn query<'a, G: crate::task::atomic_mode::AsAtomicModeGuard>(
        &'a self,
        guard: &'a G,
        addr: Vaddr,
    ) -> Option<super::MappedItemRef<'a>> {
        use align_ext::AlignExt;

        assert!(self.start() <= addr && self.end() >= addr);

        let start = addr.align_down(PAGE_SIZE);
        let vaddr = start..start + PAGE_SIZE;

        let page_table = KERNEL_PAGE_TABLE.get().unwrap();
        let mut cursor = page_table.cursor(guard, &vaddr).unwrap();

        cursor.query().unwrap().1
    }

    /// Create a kernel virtual area and map tracked pages into it.
    ///
    /// The created virtual area will have a size of `area_size`, and the pages
    /// will be mapped starting from `map_offset` in the area.
    ///
    /// # Panics
    ///
    /// This function panics if
    ///  - the area size is not a multiple of [`PAGE_SIZE`];
    ///  - the map offset is not aligned to [`PAGE_SIZE`];
    ///  - the map offset plus the size of the pages exceeds the area size.
    pub(crate) fn map_frames<T: AnyFrameMeta + ?Sized>(
        area_size: usize,
        map_offset: usize,
        frames: impl Iterator<Item = Frame<T>>,
        prop: PageProperty,
    ) -> Self {
        assert!(area_size.is_multiple_of(PAGE_SIZE));
        assert!(map_offset.is_multiple_of(PAGE_SIZE));

        let irq_guard = irq::disable_local();

        let range = kvirt_area_allocator(&irq_guard).alloc(area_size).unwrap();
        let cursor_range = range.start + map_offset..range.end;

        let page_table = KERNEL_PAGE_TABLE.get().unwrap();
        let mut cursor = page_table.cursor_mut(&irq_guard, &cursor_range).unwrap();

        for frame in frames.into_iter() {
            // SAFETY: The constructor of the `KVirtArea` has already ensured
            // that this mapping does not affect kernel's memory safety.
            unsafe { cursor.map(MappedItem::Tracked(Frame::from_unsized(frame), prop)) };
        }

        Self {
            range,
            synchronous_reclaim: false,
        }
    }

    /// Maps new tracked pages into an unmapped part of this reservation.
    ///
    /// Existing mappings are never replaced. The owner serializes growth and
    /// retains the area until all users of the new mapping have detached.
    pub(crate) fn map_additional_frames<T: AnyFrameMeta + ?Sized>(
        &self,
        offset: usize,
        frames: impl ExactSizeIterator<Item = Frame<T>>,
        prop: PageProperty,
    ) -> crate::Result<()> {
        let bytes = frames
            .len()
            .checked_mul(PAGE_SIZE)
            .ok_or(crate::Error::Overflow)?;
        let end = offset.checked_add(bytes).ok_or(crate::Error::Overflow)?;
        if !offset.is_multiple_of(PAGE_SIZE) || bytes == 0 || end > self.size() {
            return Err(crate::Error::InvalidArgs);
        }
        let range = self.start() + offset..self.start() + end;
        let guard = irq::disable_local();
        let table = KERNEL_PAGE_TABLE.get().unwrap();
        let mut cursor = table.cursor_mut(&guard, &range).unwrap();
        // Metadata growth supplies only never-mapped grain slots. Checking the
        // complete range before modifying it keeps rejection transactional.
        for addr in range.clone().step_by(PAGE_SIZE) {
            cursor.jump(addr).unwrap();
            if cursor.query().unwrap().1.is_some() {
                return Err(crate::Error::InvalidArgs);
            }
        }
        cursor.jump(range.start).unwrap();
        for frame in frames {
            // SAFETY: This reservation owns the previously unmapped range.
            unsafe { cursor.map(MappedItem::Tracked(Frame::from_unsized(frame), prop)) };
        }
        Ok(())
    }

    /// Creates a kernel virtual area and maps untracked frames into it.
    ///
    /// The created virtual area will have a size of `area_size`, and the
    /// physical addresses will be mapped starting from `map_offset` in
    /// the area.
    ///
    /// You can provide a `0..0` physical range to create a virtual area without
    /// mapping any physical memory.
    ///
    /// # Panics
    ///
    /// This function panics if
    ///  - the area size is not a multiple of [`PAGE_SIZE`];
    ///  - the map offset is not aligned to [`PAGE_SIZE`];
    ///  - the provided physical range is not aligned to [`PAGE_SIZE`];
    ///  - the map offset plus the length of the physical range exceeds the
    ///    area size;
    ///  - the provided physical range contains tracked physical addresses.
    pub(crate) unsafe fn map_untracked_frames(
        area_size: usize,
        map_offset: usize,
        pa_range: Range<Paddr>,
        prop: PageProperty,
    ) -> Self {
        assert!(pa_range.start.is_multiple_of(PAGE_SIZE));
        assert!(pa_range.end.is_multiple_of(PAGE_SIZE));
        assert!(area_size.is_multiple_of(PAGE_SIZE));
        assert!(map_offset.is_multiple_of(PAGE_SIZE));
        assert!(map_offset + pa_range.len() <= area_size);

        let irq_guard = irq::disable_local();

        let range = kvirt_area_allocator(&irq_guard).alloc(area_size).unwrap();

        if !pa_range.is_empty() {
            let len = pa_range.len();
            let va_range = range.start + map_offset..range.start + map_offset + len;

            let page_table = KERNEL_PAGE_TABLE.get().unwrap();
            let min_level = max_page_level::<KernelPtConfig>(len);
            let mut cursor = page_table
                .cursor_mut_with_min_level(&irq_guard, &va_range, min_level)
                .unwrap();

            for (pa, level) in largest_pages::<KernelPtConfig>(va_range.start, pa_range.start, len)
            {
                // SAFETY: The caller of `map_untracked_frames` has ensured the safety of this mapping.
                unsafe { cursor.map(MappedItem::Untracked(pa, level, prop)) };
            }
        }

        Self {
            range,
            synchronous_reclaim: false,
        }
    }
}

impl Drop for KVirtArea {
    fn drop(&mut self) {
        if self.synchronous_reclaim {
            assert!(crate::arch::irq::is_local_enabled());
        }
        let mut retired = Vec::new();
        let irq_guard = irq::disable_local();

        // 1. Unmap all mapped pages.
        let page_table = KERNEL_PAGE_TABLE.get().unwrap();
        let range = self.start()..self.end();
        let mut cursor = page_table.cursor_mut(&irq_guard, &range).unwrap();
        loop {
            // SAFETY:
            // 1. The range is under `KVirtArea`, so it is safe to unmap.
            // 2. Synchronous areas retain each removed fragment until the
            //    acknowledged shootdown below. Other callers retain the
            //    existing responsibility to ensure TLB coherence before reuse.
            let Some(frag) = (unsafe { cursor.take_next(self.end() - cursor.virt_addr()) }) else {
                break;
            };
            if self.synchronous_reclaim {
                retired.push(frag);
            } else {
                drop(frag);
            }
        }
        drop(cursor);
        drop(irq_guard);

        if self.synchronous_reclaim {
            // All roots share these kernel-half PTEs. Retain both the removed
            // page-table fragments and the reservation until every CPU has
            // acknowledged the invalidation. No allocator lock spans the IPI.
            crate::smp::inter_processor_call(
                &crate::cpu::CpuSet::new_full(),
                crate::arch::mm::tlb_flush_all_including_global,
            )
            .wait();
        }
        drop(retired);
        // 2. Free the virtual block only after stale translations are gone.
        let irq_guard = irq::disable_local();
        kvirt_area_allocator(&irq_guard).free(range);
    }
}

#[cfg(ktest)]
mod test {
    use core::iter;

    use super::{super::MappedItemRef, *};
    use crate::{
        mm::{
            FrameAllocOptions,
            page_prop::{CachePolicy, PageFlags, PrivilegedPageFlags},
        },
        prelude::*,
        task::disable_preempt,
    };

    #[ktest]
    fn tracked_base_pages_unmap_after_shootdown() {
        let frame = FrameAllocOptions::new().alloc_frame().unwrap();
        let paddr = frame.paddr();
        let initial_refs = frame.reference_count();
        let prop = PageProperty {
            flags: PageFlags::R,
            cache: CachePolicy::Writeback,
            priv_flags: PrivilegedPageFlags::GLOBAL,
        };
        let area = KVirtArea::map_frames(2 * PAGE_SIZE, 0, iter::once(frame.clone()), prop)
            .with_synchronous_reclaim();
        let start = area.start();
        assert_eq!(frame.reference_count(), initial_refs + 1);

        // An additional tracked page can be mapped into the unmapped slot.
        area.map_additional_frames(PAGE_SIZE, iter::once(frame.clone()), prop)
            .unwrap();
        assert_eq!(frame.reference_count(), initial_refs + 2);
        // Already-mapped slots are never replaced; rejection is transactional.
        assert!(matches!(
            area.map_additional_frames(0, iter::once(frame.clone()), prop),
            Err(crate::Error::InvalidArgs)
        ));
        assert_eq!(frame.reference_count(), initial_refs + 2);

        let guard = disable_preempt();
        match area.query(&guard, start) {
            Some(MappedItemRef::Tracked(mapped, mapped_prop)) => {
                assert_eq!(mapped.paddr(), paddr);
                assert_eq!(mapped_prop.flags, PageFlags::R);
            }
            _ => panic!("the mapped frame must be tracked"),
        }
        drop(guard);

        // Releasing the area waits for the acknowledged shootdown before
        // retiring the fragments. Their references also wait for RCU readers.
        drop(area);

        let guard = disable_preempt();
        let range = start..start + 2 * PAGE_SIZE;
        let mut cursor = KERNEL_PAGE_TABLE
            .get()
            .unwrap()
            .cursor(&guard, &range)
            .unwrap();
        assert!(cursor.query().unwrap().1.is_none());
        cursor.jump(start + PAGE_SIZE).unwrap();
        assert!(cursor.query().unwrap().1.is_none());
    }
}
