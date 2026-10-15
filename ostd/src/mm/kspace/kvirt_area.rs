// SPDX-License-Identifier: MPL-2.0

//! Kernel virtual memory allocation

use alloc::vec::Vec;
use core::ops::Range;

use self::allocator::kvirt_area_allocator;
use super::{KERNEL_PAGE_TABLE, KernelPtConfig, MappedItem};
#[cfg(feature = "kernelet-host")]
use crate::mm::{HasPaddr, frame::Segment};
use crate::{
    irq,
    mm::{
        HasSize, PAGE_SIZE, Paddr, Split, Vaddr,
        frame::{Frame, meta::AnyFrameMeta},
        page_prop::PageProperty,
        page_table::{CursorMut, PageTableFrag, largest_pages},
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
    #[cfg(feature = "kernelet-host")]
    synchronous_reclaim: bool,
    // Huge PTEs cannot hold the reference counts of their constituent frames.
    // These owners outlive Drop's acknowledged shootdown instead.
    #[cfg(feature = "kernelet-host")]
    mapped_segments: Vec<Segment<()>>,
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

        #[cfg(feature = "kernelet-host")]
        let mut area = self;
        #[cfg(not(feature = "kernelet-host"))]
        let area = self;
        // Either half can still map part of any segment, including when the
        // split cuts through a huge page. Both retain the physical owners.
        #[cfg(feature = "kernelet-host")]
        let left_segments = area.mapped_segments.clone();
        #[cfg(feature = "kernelet-host")]
        let right_segments = core::mem::take(&mut area.mapped_segments);
        let old = core::mem::ManuallyDrop::new(area);

        let left_range = old.start()..old.start() + offset;
        let right_range = old.start() + offset..old.end();
        (
            KVirtArea {
                range: left_range,
                #[cfg(feature = "kernelet-host")]
                synchronous_reclaim: old.synchronous_reclaim,
                #[cfg(feature = "kernelet-host")]
                mapped_segments: left_segments,
            },
            KVirtArea {
                range: right_range,
                #[cfg(feature = "kernelet-host")]
                synchronous_reclaim: old.synchronous_reclaim,
                #[cfg(feature = "kernelet-host")]
                mapped_segments: right_segments,
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
    #[cfg(feature = "kernelet-host")]
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

    /// Reserves an unmapped kernel range, returning an error on exhaustion.
    pub(crate) fn try_reserve(area_size: usize) -> crate::Result<Self> {
        Self::try_reserve_aligned(area_size, PAGE_SIZE)
    }

    /// Reserves an unmapped range with a power-of-two virtual alignment.
    pub(crate) fn try_reserve_aligned(area_size: usize, alignment: usize) -> crate::Result<Self> {
        if area_size == 0
            || !area_size.is_multiple_of(PAGE_SIZE)
            || alignment < PAGE_SIZE
            || !alignment.is_power_of_two()
        {
            return Err(crate::Error::InvalidArgs);
        }
        let reserved_size = area_size
            .checked_add(alignment - PAGE_SIZE)
            .ok_or(crate::Error::Overflow)?;
        let irq_guard = irq::disable_local();
        let allocator = kvirt_area_allocator(&irq_guard);
        let reserved = allocator
            .alloc(reserved_size)
            .map_err(|_| crate::Error::NoMemory)?;
        // The allocator returns page-aligned bounds. The extra reservation
        // therefore covers every possible padding up to alignment - PAGE_SIZE.
        let padding = (alignment - reserved.start % alignment) % alignment;
        let range = reserved.start + padding..reserved.start + padding + area_size;
        if reserved.start < range.start {
            allocator.free(reserved.start..range.start);
        }
        if range.end < reserved.end {
            allocator.free(range.end..reserved.end);
        }
        Ok(Self {
            range,
            #[cfg(feature = "kernelet-host")]
            synchronous_reclaim: false,
            #[cfg(feature = "kernelet-host")]
            mapped_segments: Vec::new(),
        })
    }

    /// Creates a kernel virtual area and maps tracked pages into it.
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
            #[cfg(feature = "kernelet-host")]
            synchronous_reclaim: false,
            #[cfg(feature = "kernelet-host")]
            mapped_segments: Vec::new(),
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
        self.map_additional_frames_batch(core::iter::once((offset, frames)), prop)
    }

    /// Maps owned segments using the largest pages allowed by their alignment.
    ///
    /// The PTEs carry physical addresses; this area retains the frame owners
    /// until unmapping and an acknowledged shootdown complete. Consequently,
    /// this requires [`Self::with_synchronous_reclaim`]. Existing mappings are
    /// never replaced, and every returned error leaves all mappings unchanged.
    #[cfg(feature = "kernelet-host")]
    pub(crate) fn map_additional_segments(
        &mut self,
        offset: usize,
        segments: impl ExactSizeIterator<Item = Segment<()>>,
        prop: PageProperty,
    ) -> crate::Result<()> {
        if !self.synchronous_reclaim || !offset.is_multiple_of(PAGE_SIZE) {
            return Err(crate::Error::InvalidArgs);
        }
        let mut incoming = Vec::new();
        incoming
            .try_reserve_exact(segments.len())
            .map_err(|_| crate::Error::NoMemory)?;
        let mut bytes = 0usize;
        for segment in segments {
            bytes = bytes
                .checked_add(segment.size())
                .ok_or(crate::Error::Overflow)?;
            incoming.push(segment);
        }
        let end = offset.checked_add(bytes).ok_or(crate::Error::Overflow)?;
        if bytes == 0 || end > self.size() {
            return Err(crate::Error::InvalidArgs);
        }
        self.mapped_segments
            .try_reserve(incoming.len())
            .map_err(|_| crate::Error::NoMemory)?;

        let range = self.start() + offset..self.start() + end;
        let guard = irq::disable_local();
        let table = KERNEL_PAGE_TABLE.get().unwrap();
        let mut max_map_level = 1;
        let mut addr = range.start;
        for segment in &incoming {
            for (_, level) in largest_pages::<KernelPtConfig>(addr, segment.paddr(), segment.size())
            {
                max_map_level = max_map_level.max(level);
            }
            addr += segment.size();
        }
        let mut cursor = table
            .cursor_mut_for_mapping(&guard, &range, max_map_level)
            .unwrap();
        prepare_unmapped_range(&mut cursor, &range)?;

        let mut addr = range.start;
        for segment in &incoming {
            for (pa, level) in
                largest_pages::<KernelPtConfig>(addr, segment.paddr(), segment.size())
            {
                let va = addr + pa - segment.paddr();
                cursor.prepare_mapping(va, level)?;
            }
            addr += segment.size();
        }

        // Publish all owners before any PTE, including on panic/unwind paths.
        let first_segment = self.mapped_segments.len();
        self.mapped_segments.extend(incoming);
        let mut addr = range.start;
        for segment in &self.mapped_segments[first_segment..] {
            cursor.jump(addr).unwrap();
            for (pa, level) in
                largest_pages::<KernelPtConfig>(addr, segment.paddr(), segment.size())
            {
                // SAFETY: This reservation owns the unmapped virtual range,
                // and mapped_segments retains every physical frame until all
                // CPUs acknowledge invalidation after its PTEs are removed.
                unsafe { cursor.map(MappedItem::Untracked(pa, level, prop)) };
            }
            addr += segment.size();
        }
        Ok(())
    }

    /// Maps disjoint, previously unmapped ranges without sleeping.
    /// Every returned error leaves all mappings unchanged.
    pub(crate) fn map_additional_frames_batch<
        T: AnyFrameMeta + ?Sized,
        I: ExactSizeIterator<Item = Frame<T>>,
    >(
        &self,
        mappings: impl ExactSizeIterator<Item = (usize, I)>,
        prop: PageProperty,
    ) -> crate::Result<()> {
        let mut batches = Vec::new();
        batches
            .try_reserve_exact(mappings.len())
            .map_err(|_| crate::Error::NoMemory)?;
        for (offset, frames) in mappings {
            let bytes = frames
                .len()
                .checked_mul(PAGE_SIZE)
                .ok_or(crate::Error::Overflow)?;
            let end = offset.checked_add(bytes).ok_or(crate::Error::Overflow)?;
            if !offset.is_multiple_of(PAGE_SIZE) || bytes == 0 || end > self.size() {
                return Err(crate::Error::InvalidArgs);
            }
            batches.push((self.start() + offset..self.start() + end, frames));
        }
        if batches.is_empty() {
            return Err(crate::Error::InvalidArgs);
        }
        batches.sort_unstable_by_key(|(range, _)| range.start);
        if batches
            .windows(2)
            .any(|pair| pair[0].0.end > pair[1].0.start)
        {
            return Err(crate::Error::InvalidArgs);
        }
        let range = batches.first().unwrap().0.start..batches.last().unwrap().0.end;
        let guard = irq::disable_local();
        let table = KERNEL_PAGE_TABLE.get().unwrap();
        let mut cursor = table.cursor_mut(&guard, &range).unwrap();
        // One cursor retains exclusive access across every precheck and map.
        // A rejection in a later range cannot leave earlier ranges installed.
        for (range, _) in &batches {
            for addr in range.clone().step_by(PAGE_SIZE) {
                cursor.jump(addr).unwrap();
                if cursor.query().unwrap().1.is_some() {
                    return Err(crate::Error::InvalidArgs);
                }
            }
        }
        // Allocate every intermediate node before transferring any frame into
        // a leaf. An OOM in a later range leaves earlier ranges unmapped.
        for (range, _) in &batches {
            for addr in range.clone().step_by(PAGE_SIZE) {
                cursor.prepare_mapping(addr, 1)?;
            }
        }
        for (range, frames) in batches {
            cursor.jump(range.start).unwrap();
            for frame in frames {
                // SAFETY: This reservation owns the previously unmapped range.
                unsafe { cursor.map(MappedItem::Tracked(Frame::from_unsized(frame), prop)) };
            }
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
            let max_map_level =
                largest_pages::<KernelPtConfig>(va_range.start, pa_range.start, len)
                    .map(|(_, level)| level)
                    .max()
                    .unwrap();
            let mut cursor = page_table
                .cursor_mut_for_mapping(&irq_guard, &va_range, max_map_level)
                .unwrap();
            if max_map_level > 1 {
                // A former base-page reservation may have left empty tables.
                prepare_unmapped_range(&mut cursor, &va_range).unwrap();
            }

            for (pa, level) in largest_pages::<KernelPtConfig>(va_range.start, pa_range.start, len)
            {
                // SAFETY: The caller of `map_untracked_frames` has ensured the safety of this mapping.
                unsafe { cursor.map(MappedItem::Untracked(pa, level, prop)) };
            }
        }

        Self {
            range,
            #[cfg(feature = "kernelet-host")]
            synchronous_reclaim: false,
            #[cfg(feature = "kernelet-host")]
            mapped_segments: Vec::new(),
        }
    }
}

/// Checks the whole range before removing any empty page-table structure.
/// The cursor keeps the same exclusive range lock through checking and removal.
fn prepare_unmapped_range(
    cursor: &mut CursorMut<'_, KernelPtConfig>,
    range: &Range<Vaddr>,
) -> crate::Result<()> {
    if cursor.find_next(range.len()).is_some() {
        return Err(crate::Error::InvalidArgs);
    }
    // find_next reached the barrier end. This jump resets the traversal to
    // the locked root, so take_next can see and retire empty child tables.
    cursor.jump(range.start).unwrap();
    while let Some(fragment) =
        // SAFETY: The same exclusive cursor just proved the entire range has
        // no mapped items. Only empty child tables can be removed. take_next
        // marks them stray and their RcuDrop owners defer reclamation until
        // software walkers have left their RCU read-side critical sections.
        unsafe { cursor.take_next(range.end - cursor.virt_addr()) }
    {
        debug_assert!(matches!(
            &fragment,
            PageTableFrag::StrayPageTable { num_frames: 0, .. }
        ));
        drop(fragment);
    }
    cursor.jump(range.start).unwrap();
    Ok(())
}

impl Drop for KVirtArea {
    fn drop(&mut self) {
        #[cfg(feature = "kernelet-host")]
        if self.synchronous_reclaim {
            assert!(crate::arch::irq::is_local_enabled());
        }
        #[cfg(feature = "kernelet-host")]
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
            #[cfg(feature = "kernelet-host")]
            if self.synchronous_reclaim {
                retired.push(frag);
            } else {
                drop(frag);
            }
            #[cfg(not(feature = "kernelet-host"))]
            drop(frag);
        }
        drop(cursor);

        #[cfg(feature = "kernelet-host")]
        {
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
            // Free the virtual block only after stale translations are gone.
            let irq_guard = irq::disable_local();
            kvirt_area_allocator(&irq_guard).free(range);
            // mapped_segments is dropped after this body, following the shootdown.
        }
        #[cfg(not(feature = "kernelet-host"))]
        kvirt_area_allocator(&irq_guard).free(range);
    }
}

#[cfg(all(ktest, feature = "kernelet-host"))]
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
    fn batch_mapping_oom_does_not_publish_earlier_frames() {
        const HUGE_SIZE: usize = 2 * 1024 * 1024;
        let area = KVirtArea::try_reserve_aligned(2 * HUGE_SIZE, HUGE_SIZE)
            .unwrap()
            .with_synchronous_reclaim();
        let range = area.range();
        {
            let guard = irq::disable_local();
            let mut cursor = KERNEL_PAGE_TABLE
                .get()
                .unwrap()
                .cursor_mut_for_mapping(&guard, &range, 2)
                .unwrap();
            prepare_unmapped_range(&mut cursor, &range).unwrap();
            cursor.prepare_mapping(range.start, 2).unwrap();
        }
        let frame = FrameAllocOptions::new().alloc_frame().unwrap();
        let refs = frame.reference_count();
        let prop = PageProperty {
            flags: PageFlags::R,
            cache: CachePolicy::Writeback,
            priv_flags: PrivilegedPageFlags::GLOBAL,
        };
        {
            let _failure = crate::mm::page_table::test::NodeAllocationFailure::after(1);
            let result = area.map_additional_frames_batch(
                [
                    (0, iter::once(frame.clone())),
                    (HUGE_SIZE, iter::once(frame.clone())),
                ]
                .into_iter(),
                prop,
            );
            assert_eq!(result, Err(crate::Error::NoMemory));
            assert_eq!(frame.reference_count(), refs);
            let guard = disable_preempt();
            assert!(area.query(&guard, range.start).is_none());
            assert!(area.query(&guard, range.start + HUGE_SIZE).is_none());
        }
        area.map_additional_frames_batch(
            [
                (0, iter::once(frame.clone())),
                (HUGE_SIZE, iter::once(frame.clone())),
            ]
            .into_iter(),
            prop,
        )
        .unwrap();
        assert_eq!(frame.reference_count(), refs + 2);
    }

    #[ktest]
    fn exact_huge_segment_replaces_empty_base_page_table() {
        const HUGE_SIZE: usize = 2 * 1024 * 1024;
        let prop = PageProperty {
            flags: PageFlags::RW,
            cache: CachePolicy::Writeback,
            priv_flags: PrivilegedPageFlags::GLOBAL,
        };
        for prepare_base_table in [false, true] {
            let segment = FrameAllocOptions::new()
                .alloc_segment_aligned(HUGE_SIZE / PAGE_SIZE, HUGE_SIZE)
                .unwrap();
            let frame = segment.slice(&(0..PAGE_SIZE)).next().unwrap();
            let paddr = segment.paddr();
            let mut area = KVirtArea::try_reserve_aligned(HUGE_SIZE, HUGE_SIZE)
                .unwrap()
                .with_synchronous_reclaim();
            let start = area.start();
            if prepare_base_table {
                // A prior mapping preparation may leave an empty level-1
                // table. The huge mapping must retire it before placing the
                // level-2 leaf. Queries themselves no longer allocate nodes.
                let guard = irq::disable_local();
                let mut cursor = KERNEL_PAGE_TABLE
                    .get()
                    .unwrap()
                    .cursor_mut(&guard, &(start..start + PAGE_SIZE))
                    .unwrap();
                cursor.prepare_mapping(start, 1).unwrap();
                assert!(cursor.query().unwrap().1.is_none());
            }
            area.map_additional_segments(0, iter::once(segment), prop)
                .unwrap();
            assert_eq!(frame.reference_count(), 2);
            {
                let guard = disable_preempt();
                for addr in [start, start + HUGE_SIZE - PAGE_SIZE] {
                    match area.query(&guard, addr) {
                        Some(MappedItemRef::Untracked(mapped, 2, mapped_prop)) => {
                            assert_eq!(mapped, paddr);
                            assert_eq!(mapped_prop, prop);
                        }
                        _ => panic!("an exact 2 MiB range must use a level-2 leaf"),
                    }
                }
            }
            drop(area);
            assert_eq!(frame.reference_count(), 1);
        }
    }

    #[ktest]
    fn huge_segment_rejection_preserves_mappings_and_owners() {
        const HUGE_SIZE: usize = 2 * 1024 * 1024;
        let prop = PageProperty {
            flags: PageFlags::RW,
            cache: CachePolicy::Writeback,
            priv_flags: PrivilegedPageFlags::GLOBAL,
        };
        let segment = FrameAllocOptions::new()
            .alloc_segment_aligned(HUGE_SIZE / PAGE_SIZE, HUGE_SIZE)
            .unwrap();
        let segment_frame = segment.slice(&(0..PAGE_SIZE)).next().unwrap();
        let existing = FrameAllocOptions::new().alloc_frame().unwrap();
        let mut area = KVirtArea::try_reserve_aligned(HUGE_SIZE, HUGE_SIZE)
            .unwrap()
            .with_synchronous_reclaim();
        area.map_additional_frames(PAGE_SIZE, iter::once(existing.clone()), prop)
            .unwrap();
        assert!(matches!(
            area.map_additional_segments(0, iter::once(segment.clone()), prop),
            Err(crate::Error::InvalidArgs)
        ));
        assert!(area.mapped_segments.is_empty());
        assert_eq!(segment_frame.reference_count(), 2);
        assert_eq!(existing.reference_count(), 2);
        {
            let guard = disable_preempt();
            assert!(area.query(&guard, area.start()).is_none());
            assert!(
                area.query(&guard, area.start() + HUGE_SIZE - PAGE_SIZE)
                    .is_none()
            );
            match area.query(&guard, area.start() + PAGE_SIZE) {
                Some(MappedItemRef::Tracked(frame, mapped_prop)) => {
                    assert_eq!(frame.paddr(), existing.paddr());
                    // KernelPtConfig preserves its tracked-frame marker in
                    // queried properties; all supplied permissions remain.
                    assert_eq!(
                        mapped_prop,
                        PageProperty {
                            priv_flags: PrivilegedPageFlags::GLOBAL | PrivilegedPageFlags::AVAIL1,
                            ..prop
                        }
                    );
                }
                _ => panic!("a rejected huge mapping must preserve the existing base page"),
            }
        }
        let range = area.start()..area.end();
        drop(area);
        // The acknowledged shootdown removes the mapping. Its retired
        // page-table subtree can still own the tracked frame until every
        // CPU reports an RCU quiescent state.
        {
            let guard = disable_preempt();
            let mut cursor = KERNEL_PAGE_TABLE
                .get()
                .unwrap()
                .cursor(&guard, &range)
                .unwrap();
            assert!(cursor.find_next(range.len()).is_none());
        }

        let mut small = KVirtArea::try_reserve_aligned(PAGE_SIZE, HUGE_SIZE)
            .unwrap()
            .with_synchronous_reclaim();
        assert!(matches!(
            small.map_additional_segments(0, iter::once(segment), prop),
            Err(crate::Error::InvalidArgs)
        ));
        assert!(small.mapped_segments.is_empty());
        assert_eq!(segment_frame.reference_count(), 1);
        let guard = disable_preempt();
        assert!(small.query(&guard, small.start()).is_none());
    }

    #[ktest]
    fn huge_segments_keep_ownership_across_split_and_reclaim() {
        const HUGE_SIZE: usize = 2 * 1024 * 1024;
        assert!(matches!(
            KVirtArea::try_reserve_aligned(PAGE_SIZE, 3 * PAGE_SIZE),
            Err(crate::Error::InvalidArgs)
        ));
        assert!(matches!(
            KVirtArea::try_reserve_aligned(usize::MAX & !(PAGE_SIZE - 1), HUGE_SIZE),
            Err(crate::Error::Overflow)
        ));

        let segment = FrameAllocOptions::new()
            .alloc_segment_aligned(HUGE_SIZE / PAGE_SIZE, HUGE_SIZE)
            .unwrap();
        let frame = segment.slice(&(0..PAGE_SIZE)).next().unwrap();
        let paddr = segment.paddr();
        let initial_refs = frame.reference_count();
        assert_eq!(initial_refs, 2);
        let prop = PageProperty {
            flags: PageFlags::RW,
            cache: CachePolicy::Writeback,
            priv_flags: PrivilegedPageFlags::GLOBAL,
        };
        let mut area = KVirtArea::try_reserve_aligned(HUGE_SIZE + PAGE_SIZE, HUGE_SIZE)
            .unwrap()
            .with_synchronous_reclaim();
        let start = area.start();
        assert!(start.is_multiple_of(HUGE_SIZE));
        area.map_additional_segments(0, iter::once(segment), prop)
            .unwrap();
        // The PTE has no frame handle; the area now owns the moved segment.
        assert_eq!(frame.reference_count(), initial_refs);
        {
            let guard = disable_preempt();
            for addr in [start, start + HUGE_SIZE - PAGE_SIZE] {
                match area.query(&guard, addr) {
                    Some(MappedItemRef::Untracked(mapped, 2, mapped_prop)) => {
                        assert_eq!(mapped, paddr);
                        assert_eq!(mapped_prop, prop);
                    }
                    _ => panic!("the entire segment must use a 2 MiB leaf"),
                }
            }
        }
        let duplicate = area.mapped_segments[0].clone();
        assert!(matches!(
            area.map_additional_segments(0, iter::once(duplicate), prop),
            Err(crate::Error::InvalidArgs)
        ));
        assert_eq!(frame.reference_count(), initial_refs);

        // Cutting through a huge leaf must keep the segment alive for either
        // half. Unmapping the first base page splits the surviving huge PTE.
        let (left, right) = area.split(PAGE_SIZE);
        assert_eq!(frame.reference_count(), initial_refs + 1);
        drop(left);
        assert_eq!(frame.reference_count(), initial_refs);
        {
            let guard = disable_preempt();
            match right.query(&guard, start + PAGE_SIZE) {
                Some(MappedItemRef::Untracked(mapped, 1, mapped_prop)) => {
                    assert_eq!(mapped, paddr + PAGE_SIZE);
                    assert_eq!(mapped_prop, prop);
                }
                _ => panic!("the other half must remain mapped after splitting"),
            }
        }
        drop(right);
        assert_eq!(frame.reference_count(), 1);
        let guard = disable_preempt();
        let range = start..start + HUGE_SIZE + PAGE_SIZE;
        let mut cursor = KERNEL_PAGE_TABLE
            .get()
            .unwrap()
            .cursor(&guard, &range)
            .unwrap();
        assert!(cursor.query().unwrap().1.is_none());
        cursor.jump(start + HUGE_SIZE - PAGE_SIZE).unwrap();
        assert!(cursor.query().unwrap().1.is_none());
    }

    #[ktest]
    fn batch_rejection_leaves_earlier_ranges_unmapped() {
        let frame = FrameAllocOptions::new().alloc_frame().unwrap();
        let initial_refs = frame.reference_count();
        let prop = PageProperty {
            flags: PageFlags::R,
            cache: CachePolicy::Writeback,
            priv_flags: PrivilegedPageFlags::GLOBAL,
        };
        let area = KVirtArea::map_frames(
            3 * PAGE_SIZE,
            2 * PAGE_SIZE,
            iter::once(frame.clone()),
            prop,
        )
        .with_synchronous_reclaim();
        assert!(matches!(
            area.map_additional_frames_batch(
                [
                    (0, iter::once(frame.clone())),
                    (2 * PAGE_SIZE, iter::once(frame.clone())),
                ]
                .into_iter(),
                prop,
            ),
            Err(crate::Error::InvalidArgs)
        ));
        assert_eq!(frame.reference_count(), initial_refs + 1);
        {
            let guard = disable_preempt();
            assert!(area.query(&guard, area.start()).is_none());
            assert!(area.query(&guard, area.start() + 2 * PAGE_SIZE).is_some());
            // A rejected batch leaves its earlier slots available for retry.
            area.map_additional_frames_batch(
                [
                    (0, iter::once(frame.clone())),
                    (PAGE_SIZE, iter::once(frame.clone())),
                ]
                .into_iter(),
                prop,
            )
            .unwrap();
            assert_eq!(frame.reference_count(), initial_refs + 3);
        }
    }

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
