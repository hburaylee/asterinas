// SPDX-License-Identifier: MPL-2.0

//! Host-owned growing grain grants and compact frame metadata.

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};

use super::{
    abi::{GRAIN_SIZE, InfoPage, MAX_GRAINS_PER_REQUEST, META_SECTION_BYTES, RunDesc},
    guest_memory::{GrantMemory, GuestMemory},
    owner::KerneletId,
};
use crate::{
    Error, Result,
    mm::{
        CachePolicy, Frame, FrameAllocOptions, HasPaddr, PAGE_SIZE, PageFlags, PageProperty,
        PrivilegedPageFlags, VmIo, frame::meta::META_REF_COUNT_OFFSET,
        kspace::kvirt_area::KVirtArea,
    },
    sync::{SpinLock, WaitQueue},
};

const META_SLOT_BYTES: usize = 64;
const META_PAGES_PER_GRAIN: usize = GRAIN_SIZE / PAGE_SIZE * META_SLOT_BYTES / PAGE_SIZE;
const GRAINS_PER_SECTION: usize = META_SECTION_BYTES / GRAIN_SIZE;
const _: () = assert!(GRAINS_PER_SECTION <= u64::BITS as usize);

const META_PAGE_PROP: PageProperty = PageProperty {
    flags: PageFlags::RW,
    cache: CachePolicy::Writeback,
    priv_flags: PrivilegedPageFlags::GLOBAL,
};

#[derive(Default)]
struct Growth {
    sections: BTreeMap<usize, u32>,
    grains: u32,
    ceiling: u32,
    runs: u32,
}

enum RunAllocation {
    Initial,
    Growth,
}

/// Growth is serialized without sleeping, including under an image guard.
/// The growth lock precedes the metadata page-table and grant-registry locks;
/// Host policy hooks run after it has been released.
pub(crate) struct Grant {
    meta_area: Option<KVirtArea>,
    memory: Arc<GrantMemory>,
    growth: SpinLock<Growth>,
    info_frame: Frame<()>,
    run_frames: Vec<Frame<()>>,
    index_frames: Vec<Frame<()>>,
    reverse_frames: Vec<Frame<()>>,
    bitmap_frames: Vec<Frame<()>>,
    max_sections: u32,
}

impl Grant {
    /// Fixed shared pages plus the authorized high-water mark of metadata.
    /// The physical-address index is sized from the Host span, just as in new.
    pub(crate) fn reservation_bytes(max_sections: u32, lifetime_grains: u32) -> Result<usize> {
        let sections = max_sections as usize;
        if sections == 0 || max_sections > lifetime_grains {
            return Err(Error::InvalidArgs);
        }
        let capacity = sections
            .checked_mul(GRAINS_PER_SECTION)
            .ok_or(Error::Overflow)?;
        let physical_sections = crate::mm::frame::max_paddr().div_ceil(META_SECTION_BYTES);
        let table_pages = capacity
            .checked_mul(size_of::<RunDesc>())
            .ok_or(Error::Overflow)?
            .div_ceil(PAGE_SIZE);
        let index_pages = physical_sections
            .checked_mul(size_of::<u32>())
            .ok_or(Error::Overflow)?
            .div_ceil(PAGE_SIZE);
        let reverse_pages = sections
            .checked_mul(size_of::<u32>())
            .ok_or(Error::Overflow)?
            .div_ceil(PAGE_SIZE);
        let bitmap_pages = sections
            .checked_mul(size_of::<u64>())
            .ok_or(Error::Overflow)?
            .div_ceil(PAGE_SIZE);
        let shared_pages = 1usize
            .checked_add(table_pages)
            .and_then(|n| n.checked_add(index_pages))
            .and_then(|n| n.checked_add(reverse_pages))
            .and_then(|n| n.checked_add(bitmap_pages))
            .ok_or(Error::Overflow)?;
        let grains = (lifetime_grains as usize).min(capacity);
        // One page per grain conservatively covers registry/tree nodes, pin
        // vectors and retained Frame handles (including transient growth
        // copies). Four PT pages per section cover sparse metadata mappings.
        let metadata_pages = grains
            .checked_mul(META_PAGES_PER_GRAIN + 1)
            .ok_or(Error::Overflow)?;
        let pt_pages = sections
            .checked_mul(4)
            .and_then(|n| n.checked_add(shared_pages.div_ceil(512) + 4))
            .ok_or(Error::Overflow)?;
        // The first instance may initialize the Host-wide authoritative owner
        // table. Charge its full span conservatively even when already shared.
        let owner_pages = crate::mm::frame::max_paddr()
            .div_ceil(GRAIN_SIZE)
            .checked_mul(size_of::<u64>())
            .ok_or(Error::Overflow)?
            .div_ceil(PAGE_SIZE);
        shared_pages
            .checked_add(metadata_pages)
            .and_then(|n| n.checked_add(pt_pages))
            .and_then(|n| n.checked_add(owner_pages))
            .and_then(|n| n.checked_mul(PAGE_SIZE))
            .ok_or(Error::Overflow)
    }

    pub(super) fn new(
        owner: KerneletId,
        initial: u32,
        ceiling: u32,
        max_sections: u32,
    ) -> Result<Self> {
        let physical_sections = crate::mm::frame::max_paddr().div_ceil(META_SECTION_BYTES);
        if initial == 0
            || initial > ceiling
            || max_sections == 0
            || max_sections as usize > physical_sections
            || ceiling as u64 > max_sections as u64 * GRAINS_PER_SECTION as u64
        {
            return Err(Error::InvalidArgs);
        }
        let capacity = max_sections as usize * GRAINS_PER_SECTION;
        let area =
            KVirtArea::try_reserve(max_sections as usize * GRAIN_SIZE)?.with_synchronous_reclaim();
        let mut grant = Self {
            meta_area: Some(area),
            memory: GrantMemory::new(owner)?,
            growth: SpinLock::new(Growth {
                sections: BTreeMap::new(),
                grains: 0,
                ceiling,
                runs: 0,
            }),
            info_frame: FrameAllocOptions::new().alloc_frame()?,
            run_frames: allocate_pages(capacity * size_of::<RunDesc>(), None)?,
            index_frames: allocate_pages(physical_sections * size_of::<u32>(), Some(0xff))?,
            reverse_frames: allocate_pages(max_sections as usize * size_of::<u32>(), Some(0xff))?,
            bitmap_frames: allocate_pages(max_sections as usize * size_of::<u64>(), None)?,
            max_sections,
        };
        // Construction owns the unpublished grant exclusively. Avoid holding
        // a preemption guard across its potentially much larger initial grant.
        let mut growth = core::mem::take(grant.growth.get_mut());
        let mut remaining = initial;
        while remaining != 0 {
            // Creation may publish a complete physical section at once;
            // later control and image requests have the 16-grain bound.
            let count = remaining.min(GRAINS_PER_SECTION as u32);
            grant.add_run(&mut growth, count, RunAllocation::Initial)?;
            remaining -= count;
        }
        *grant.growth.get_mut() = growth;
        Ok(grant)
    }

    /// Adds bounded memory using the available live ceiling.
    pub(crate) fn grow_within_ceiling(&self, count: u32, contiguous: u32) -> Result<u32> {
        self.grow(count, contiguous, false)
    }

    /// Adds bounded memory and raises the ceiling by the amount published.
    pub(crate) fn grow_and_raise_ceiling(&self, count: u32, contiguous: u32) -> Result<u32> {
        self.grow(count, contiguous, true)
    }

    fn grow(&self, count: u32, contiguous: u32, raise_ceiling: bool) -> Result<u32> {
        if count == 0 || count > MAX_GRAINS_PER_REQUEST {
            return Err(Error::InvalidArgs);
        }
        let mut growth = self.growth.lock();
        let capacity = self.max_sections * GRAINS_PER_SECTION as u32;
        let available = if raise_ceiling {
            capacity - growth.ceiling
        } else {
            growth.ceiling - growth.grains
        };
        if available == 0 || (contiguous != 0 && count > available) {
            return Err(Error::AccessDenied);
        }
        self.allocate_growth(&mut growth, count.min(available), contiguous, raise_ceiling)
    }

    /// Commits a policy authorization before allocation; an allocation failure
    /// leaves this ceiling available to a later request without another debit.
    pub(crate) fn grow_authorized(
        &self,
        count: u32,
        contiguous: u32,
        authorized: u32,
    ) -> (Result<u32>, u32) {
        if count == 0 || count > MAX_GRAINS_PER_REQUEST {
            return (Err(Error::InvalidArgs), 0);
        }
        let mut growth = self.growth.lock();
        let available = growth.ceiling - growth.grains;
        let needs_ceiling = available == 0 || (contiguous != 0 && available < count);
        let committed = if needs_ceiling {
            authorized
                .min(count)
                .min(self.max_sections * GRAINS_PER_SECTION as u32 - growth.ceiling)
        } else {
            0
        };
        growth.ceiling += committed;
        let available = growth.ceiling - growth.grains;
        let result = if available == 0 || (contiguous != 0 && available < count) {
            Err(Error::AccessDenied)
        } else {
            self.allocate_growth(&mut growth, count.min(available), contiguous, false)
        };
        (result, committed)
    }

    fn allocate_growth(
        &self,
        growth: &mut Growth,
        wanted: u32,
        contiguous: u32,
        raise_ceiling: bool,
    ) -> Result<u32> {
        let mut candidate = wanted;
        loop {
            match self.add_run(growth, candidate, RunAllocation::Growth) {
                Ok(()) => {
                    if raise_ceiling {
                        growth.ceiling += candidate;
                    }
                    return Ok(candidate);
                }
                Err(Error::NoMemory) if contiguous == 0 && candidate > 1 => candidate /= 2,
                Err(error) => return Err(error),
            }
        }
    }

    fn add_run(&self, growth: &mut Growth, count: u32, allocation: RunAllocation) -> Result<()> {
        let bytes = count as usize * GRAIN_SIZE;
        let align = if matches!(allocation, RunAllocation::Initial)
            && count as usize == GRAINS_PER_SECTION
        {
            META_SECTION_BYTES
        } else {
            GRAIN_SIZE
        };
        let run = FrameAllocOptions::new().alloc_segment_aligned(bytes / PAGE_SIZE, align)?;
        let base = run.paddr();
        // Allocate registry/pin storage before installing metadata. Its guard
        // removes the unpublished run on any subsequent allocation error.
        let mut pending = self.memory.prepare(run)?;
        let first_section = base / META_SECTION_BYTES;
        let last_section = (base + bytes - 1) / META_SECTION_BYTES;
        let missing = (first_section..=last_section)
            .filter(|section| !growth.sections.contains_key(section))
            .count();
        if growth.sections.len() + missing > self.max_sections as usize {
            return Err(Error::Overflow);
        }
        let mut sections = growth.sections.clone();
        for section in first_section..=last_section {
            if !sections.contains_key(&section) {
                sections.insert(section, sections.len() as u32);
            }
        }
        let mut metadata = Vec::with_capacity(count as usize);
        let mut meta_page = [0u8; PAGE_SIZE];
        for slot in meta_page.chunks_exact_mut(META_SLOT_BYTES) {
            slot[META_REF_COUNT_OFFSET..META_REF_COUNT_OFFSET + size_of::<u64>()]
                .copy_from_slice(&u64::MAX.to_le_bytes());
        }
        for grain in 0..count as usize {
            let paddr = base + grain * GRAIN_SIZE;
            let block = sections[&(paddr / META_SECTION_BYTES)] as usize;
            let offset =
                block * GRAIN_SIZE + (paddr % META_SECTION_BYTES) / PAGE_SIZE * META_SLOT_BYTES;
            let mut frames = Vec::with_capacity(META_PAGES_PER_GRAIN);
            for _ in 0..META_PAGES_PER_GRAIN {
                let frame = FrameAllocOptions::new().alloc_frame()?;
                frame.write_bytes(0, &meta_page)?;
                frames.push(frame);
            }
            metadata.push((offset, frames));
        }
        // The pin registry owns the same authoritative metadata backing. A
        // retained Host pin must survive virtual mapping/construction teardown.
        let mut retained_metadata = Vec::new();
        retained_metadata
            .try_reserve_exact(count as usize * META_PAGES_PER_GRAIN)
            .map_err(|_| Error::NoMemory)?;
        retained_metadata.extend(
            metadata
                .iter()
                .flat_map(|(_, frames)| frames.iter().cloned()),
        );
        pending.set_metadata(retained_metadata)?;
        // No grant descriptor is visible until zeroed frames, all metadata
        // pages, and both section indexes have been installed.
        self.meta_area
            .as_ref()
            .unwrap()
            .map_additional_frames_batch(
                metadata
                    .into_iter()
                    .map(|(offset, frames)| (offset, frames.into_iter())),
                META_PAGE_PROP,
            )?;
        for (&section, &block) in &sections {
            if !growth.sections.contains_key(&section) {
                write_u32(&self.reverse_frames, block as usize, section as u32);
                publish_u32(&self.index_frames, section, block);
            }
        }
        pending.publish();
        for grain in 0..count as usize {
            let paddr = base + grain * GRAIN_SIZE;
            let block = sections[&(paddr / META_SECTION_BYTES)] as usize;
            let bit = (paddr % META_SECTION_BYTES) / GRAIN_SIZE;
            // Metadata mappings and the authoritative grant owner are ready
            // before a buddy lookup may probe this grain. Descriptors are
            // published afterward, before the allocator imports the run.
            self.grain_bitmap(block)
                .fetch_or(1u64 << bit, Ordering::Release);
        }
        let descriptor = RunDesc {
            paddr: base as u64,
            grains: count,
            reserved: 0,
        };
        let descriptor_offset = growth.runs as usize * size_of::<RunDesc>();
        let page = &self.run_frames[descriptor_offset / PAGE_SIZE];
        let offset = descriptor_offset % PAGE_SIZE;
        page.write_bytes(offset, &descriptor.paddr.to_le_bytes())
            .unwrap();
        page.write_bytes(offset + 8, &count.to_le_bytes()).unwrap();
        let end = base + bytes;
        growth.sections = sections;
        growth.grains += count;
        growth.runs += 1;
        let info = self.info();
        info.max_paddr.fetch_max(end as u64, Ordering::Release);
        info.meta_blocks
            .store(growth.sections.len() as u32, Ordering::Release);
        info.runs.store(growth.runs, Ordering::Release);
        Ok(())
    }

    fn info(&self) -> &InfoPage {
        // SAFETY: The zeroed info frame is page-aligned and remains pinned by
        // self. Every published field uses atomic access in Host and image.
        unsafe { &*(crate::mm::kspace::paddr_to_vaddr(self.info_frame.paddr()) as *const InfoPage) }
    }

    fn grain_bitmap(&self, block: usize) -> &AtomicU64 {
        let offset = block * size_of::<u64>();
        let addr =
            crate::mm::kspace::paddr_to_vaddr(self.bitmap_frames[offset / PAGE_SIZE].paddr())
                + offset % PAGE_SIZE;
        // SAFETY: Pinned zeroed pages hold aligned atomic words; all accesses
        // use atomics and blocks are bounded by the fixed section capacity.
        unsafe { &*(addr as *const AtomicU64) }
    }

    pub(crate) fn overhead_bytes(&self) -> usize {
        self.shared_pages() * PAGE_SIZE + self.grains() as usize * META_PAGES_PER_GRAIN * PAGE_SIZE
    }

    pub(crate) fn dying_address(&self) -> usize {
        core::ptr::addr_of!(self.info().dying) as usize
    }
    pub(crate) fn drain_queue(&self) -> Arc<WaitQueue> {
        self.memory.drain_queue()
    }
    pub(crate) fn close(&self) -> usize {
        self.memory.close()
    }
    pub(crate) fn grains(&self) -> u32 {
        self.growth.lock().grains
    }
    pub(crate) fn ceiling(&self) -> u32 {
        self.growth.lock().ceiling
    }
    pub(crate) fn meta_base(&self) -> u64 {
        self.meta_area.as_ref().unwrap().start() as u64
    }
    pub(crate) fn guest_memory(&self) -> GuestMemory {
        GuestMemory::new(&self.memory)
    }
    pub(crate) fn bind_lifecycle(&self, lifecycle: Arc<AtomicU8>) {
        self.memory.bind_lifecycle(lifecycle);
    }
    pub(crate) fn bind_identity(&self, identity: Arc<super::control::identity::Registration>) {
        self.memory.bind_identity(identity);
    }
    pub(crate) fn run_pages(&self) -> usize {
        self.run_frames.len()
    }
    pub(crate) fn index_pages(&self) -> usize {
        self.index_frames.len()
    }
    pub(crate) fn reverse_pages(&self) -> usize {
        self.reverse_frames.len()
    }
    pub(crate) fn shared_pages(&self) -> usize {
        1 + self.run_frames.len()
            + self.index_frames.len()
            + self.reverse_frames.len()
            + self.bitmap_frames.len()
    }
    pub(crate) fn shared_frames(&self) -> impl Iterator<Item = Frame<()>> + '_ {
        core::iter::once(self.info_frame.clone())
            .chain(self.run_frames.iter().cloned())
            .chain(self.index_frames.iter().cloned())
            .chain(self.reverse_frames.iter().cloned())
            .chain(self.bitmap_frames.iter().cloned())
    }
}

impl Drop for Grant {
    fn drop(&mut self) {
        self.memory.close();
        drop(self.meta_area.take());
        self.memory.reclaim();
    }
}

fn allocate_pages(bytes: usize, fill: Option<u8>) -> Result<Vec<Frame<()>>> {
    let mut pages = Vec::with_capacity(bytes.div_ceil(PAGE_SIZE));
    for _ in 0..bytes.div_ceil(PAGE_SIZE) {
        let frame = FrameAllocOptions::new().alloc_frame()?;
        if let Some(byte) = fill {
            frame.write_bytes(0, &[byte; PAGE_SIZE])?;
        }
        pages.push(frame);
    }
    Ok(pages)
}

fn write_u32(frames: &[Frame<()>], index: usize, value: u32) {
    let offset = index * size_of::<u32>();
    frames[offset / PAGE_SIZE]
        .write_bytes(offset % PAGE_SIZE, &value.to_le_bytes())
        .unwrap();
}

fn publish_u32(frames: &[Frame<()>], index: usize, value: u32) {
    let offset = index * size_of::<u32>();
    let address =
        crate::mm::kspace::paddr_to_vaddr(frames[offset / PAGE_SIZE].paddr()) + offset % PAGE_SIZE;
    // SAFETY: The pinned index pages hold aligned atomic u32 slots. A slot is
    // initialized before its release publication and never changes afterward.
    unsafe { &*(address as *const AtomicU32) }.store(value, Ordering::Release);
}

#[cfg(ktest)]
mod test {
    use super::*;
    use crate::prelude::ktest;

    #[ktest]
    fn published_bitmap_preserves_holes_and_tracks_growth() {
        let identity = super::super::control::identity::Registration::new().unwrap();
        let grant = Grant::new(identity.owner(), 1, 4, 4).unwrap();
        for count in [1, 3] {
            if count == 3 {
                assert_eq!(grant.grow_within_ceiling(2, 0).unwrap(), 2);
            }
            let growth = grant.growth.lock();
            let present: u32 = growth
                .sections
                .values()
                .map(|block| {
                    grant
                        .grain_bitmap(*block as usize)
                        .load(Ordering::Acquire)
                        .count_ones()
                })
                .sum();
            assert_eq!(present, count);
            for run_index in 0..growth.runs as usize {
                let offset = run_index * size_of::<RunDesc>();
                let mut raw = [0u8; size_of::<RunDesc>()];
                grant.run_frames[offset / PAGE_SIZE]
                    .read_bytes(offset % PAGE_SIZE, &mut raw)
                    .unwrap();
                let base = u64::from_le_bytes(raw[..8].try_into().unwrap()) as usize;
                let grains = u32::from_le_bytes(raw[8..12].try_into().unwrap()) as usize;
                for grain in 0..grains {
                    let paddr = base + grain * GRAIN_SIZE;
                    let block = growth.sections[&(paddr / META_SECTION_BYTES)];
                    let bit = paddr % META_SECTION_BYTES / GRAIN_SIZE;
                    assert_ne!(
                        grant.grain_bitmap(block as usize).load(Ordering::Acquire) & (1u64 << bit),
                        0
                    );
                }
            }
        }
    }

    #[ktest]
    fn metadata_reservation_covers_actual_fixed_pages_and_lifetime_growth() {
        let identity = super::super::control::identity::Registration::new().unwrap();
        let grant = Grant::new(identity.owner(), 1, 4, 4).unwrap();
        let reserved = Grant::reservation_bytes(4, 4).unwrap();
        assert!(reserved >= grant.overhead_bytes() + 3 * META_PAGES_PER_GRAIN * PAGE_SIZE);
        assert_eq!(Grant::reservation_bytes(5, 4), Err(Error::InvalidArgs));
        assert_eq!(Grant::reservation_bytes(0, 4), Err(Error::InvalidArgs));
    }

    #[ktest]
    fn growth_publishes_zeroed_memory_under_preempt_guard() {
        let identity = super::super::control::identity::Registration::new().unwrap();
        let grant = Grant::new(identity.owner(), 1, 4, 4).unwrap();
        let initial_runs = grant.info().runs.load(Ordering::Acquire);
        let baseline = crate::task::preempt_guard_count();
        {
            let _guard = crate::task::disable_preempt();
            assert_eq!(grant.grow_within_ceiling(2, 0).unwrap(), 2);
            assert_eq!(crate::task::preempt_guard_count(), baseline + 1);
            assert_eq!(grant.info().runs.load(Ordering::Acquire), initial_runs + 1);

            let descriptor_offset = initial_runs as usize * size_of::<RunDesc>();
            let mut descriptor = [0u8; size_of::<RunDesc>()];
            grant.run_frames[descriptor_offset / PAGE_SIZE]
                .read_bytes(descriptor_offset % PAGE_SIZE, &mut descriptor)
                .unwrap();
            let paddr = u64::from_le_bytes(descriptor[..8].try_into().unwrap());
            let grains = u32::from_le_bytes(descriptor[8..12].try_into().unwrap());
            assert_eq!(grains, 2);
            let memory = grant.guest_memory();
            assert!(memory.contains(paddr, grains as usize * GRAIN_SIZE));
            let mut byte = [1];
            memory.read(paddr, &mut byte).unwrap();
            assert_eq!(byte, [0]);
            memory
                .read(paddr + grains as u64 * GRAIN_SIZE as u64 - 1, &mut byte)
                .unwrap();
            assert_eq!(byte, [0]);
        }
        assert_eq!(crate::task::preempt_guard_count(), baseline);
    }

    #[ktest]
    fn authorized_ceiling_survives_unsatisfied_contiguous_request() {
        let identity = super::super::control::identity::Registration::new().unwrap();
        let grant = Grant::new(identity.owner(), 1, 1, 4).unwrap();
        let (result, committed) = grant.grow_authorized(2, 1, 1);
        assert!(matches!(result, Err(Error::AccessDenied)));
        assert_eq!(committed, 1);
        assert_eq!(grant.ceiling(), 2);
        assert_eq!(grant.grains(), 1);
        assert_eq!(grant.grow_within_ceiling(1, 0).unwrap(), 1);
        assert_eq!(grant.grains(), 2);
    }

    #[ktest]
    fn available_ceiling_refunds_unneeded_authorization() {
        let identity = super::super::control::identity::Registration::new().unwrap();
        let grant = Grant::new(identity.owner(), 1, 3, 4).unwrap();
        let (result, committed) = grant.grow_authorized(2, 0, 2);
        assert_eq!(result.unwrap(), 2);
        assert_eq!(committed, 0);
        assert_eq!(grant.ceiling(), 3);
    }

    #[ktest]
    fn nonzero_contiguous_flag_refuses_partial_grant() {
        let identity = super::super::control::identity::Registration::new().unwrap();
        let grant = Grant::new(identity.owner(), 1, 2, 4).unwrap();
        for contiguous in [1, u32::MAX] {
            assert!(matches!(
                grant.grow_within_ceiling(2, contiguous),
                Err(Error::AccessDenied)
            ));
            assert_eq!(grant.grains(), 1);
        }
        assert_eq!(grant.grow_within_ceiling(1, u32::MAX).unwrap(), 1);
    }
}
