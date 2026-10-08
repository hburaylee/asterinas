// SPDX-License-Identifier: MPL-2.0

//! Host-owned growing grain grants and compact frame metadata.

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};

use super::{
    abi::{GRAIN_SIZE, InfoPage, MAX_GRAINS_PER_REQUEST, META_SECTION_BYTES, RunDesc},
    guest_memory::{GrantMemory, GuestMemory},
};
use crate::{
    Error, Result,
    mm::{
        CachePolicy, Frame, FrameAllocOptions, HasPaddr, PAGE_SIZE, PageFlags, PageProperty,
        PrivilegedPageFlags, VmIo, frame::meta::META_REF_COUNT_OFFSET,
        kspace::kvirt_area::KVirtArea,
    },
    sync::{Mutex, WaitQueue},
};

const META_SLOT_BYTES: usize = 64;
const META_PAGES_PER_GRAIN: usize = GRAIN_SIZE / PAGE_SIZE * META_SLOT_BYTES / PAGE_SIZE;
const GRAINS_PER_SECTION: usize = META_SECTION_BYTES / GRAIN_SIZE;

const META_PAGE_PROP: PageProperty = PageProperty {
    flags: PageFlags::RW,
    cache: CachePolicy::Writeback,
    priv_flags: PrivilegedPageFlags::GLOBAL,
};

struct Growth {
    sections: BTreeMap<usize, u32>,
    grains: u32,
    ceiling: u32,
    runs: u32,
}

/// The sleeping growth mutex is outside every short registry lock.
/// Publication is allocation-free after metadata mapping has started.
pub(crate) struct Grant {
    meta_area: Option<KVirtArea>,
    memory: Arc<GrantMemory>,
    growth: Mutex<Growth>,
    info_frame: Frame<()>,
    run_frames: Vec<Frame<()>>,
    index_frames: Vec<Frame<()>>,
    reverse_frames: Vec<Frame<()>>,
    max_sections: u32,
}

impl Grant {
    pub(crate) fn new(initial: u32, ceiling: u32, max_sections: u32) -> Result<Self> {
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
        let area = KVirtArea::map_frames(
            max_sections as usize * GRAIN_SIZE,
            0,
            core::iter::empty::<Frame<()>>(),
            META_PAGE_PROP,
        )
        .with_synchronous_reclaim();
        let grant = Self {
            meta_area: Some(area),
            memory: GrantMemory::new(),
            growth: Mutex::new(Growth {
                sections: BTreeMap::new(),
                grains: 0,
                ceiling,
                runs: 0,
            }),
            info_frame: FrameAllocOptions::new().alloc_frame()?,
            run_frames: allocate_pages(capacity * size_of::<RunDesc>(), false)?,
            index_frames: allocate_pages(physical_sections * size_of::<u32>(), true)?,
            reverse_frames: allocate_pages(max_sections as usize * size_of::<u32>(), true)?,
            max_sections,
        };
        {
            let mut growth = grant.growth.lock();
            let mut remaining = initial;
            while remaining != 0 {
                // Creation may publish a complete physical section at once;
                // later control and image requests have the 16-grain bound.
                let count = remaining.min(GRAINS_PER_SECTION as u32);
                grant.add_run(&mut growth, count, true)?;
                remaining -= count;
            }
        }
        Ok(grant)
    }

    /// Adds bounded memory, optionally increasing the live ceiling by exactly
    /// the amount successfully published by a Host control request.
    pub(crate) fn grow(&self, count: u32, contiguous: u32, raise_ceiling: bool) -> Result<u32> {
        if count == 0 || count > MAX_GRAINS_PER_REQUEST || contiguous > count {
            return Err(Error::InvalidArgs);
        }
        let mut growth = self.growth.lock();
        let capacity = self.max_sections * GRAINS_PER_SECTION as u32;
        let available = if raise_ceiling {
            capacity - growth.ceiling
        } else {
            growth.ceiling - growth.grains
        };
        if available == 0 || (contiguous > 1 && count > available) {
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
        if count == 0 || count > MAX_GRAINS_PER_REQUEST || contiguous > count {
            return (Err(Error::InvalidArgs), 0);
        }
        let mut growth = self.growth.lock();
        let available = growth.ceiling - growth.grains;
        let needs_ceiling = available == 0 || (contiguous > 1 && available < count);
        let committed = if needs_ceiling {
            authorized
                .min(count)
                .min(self.max_sections * GRAINS_PER_SECTION as u32 - growth.ceiling)
        } else {
            0
        };
        growth.ceiling += committed;
        let available = growth.ceiling - growth.grains;
        let result = if available == 0 || (contiguous > 1 && available < count) {
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
            match self.add_run(growth, candidate, false) {
                Ok(()) => {
                    if raise_ceiling {
                        growth.ceiling += candidate;
                    }
                    return Ok(candidate);
                }
                Err(Error::NoMemory) if contiguous <= 1 && candidate > 1 => candidate /= 2,
                Err(error) => return Err(error),
            }
        }
    }

    fn add_run(&self, growth: &mut Growth, count: u32, initial: bool) -> Result<()> {
        let bytes = count as usize * GRAIN_SIZE;
        let align = if initial && count as usize == GRAINS_PER_SECTION {
            META_SECTION_BYTES
        } else {
            GRAIN_SIZE
        };
        let run = FrameAllocOptions::new().alloc_segment_aligned(bytes / PAGE_SIZE, align)?;
        let first_section = run.paddr() / META_SECTION_BYTES;
        let last_section = (run.paddr() + bytes - 1) / META_SECTION_BYTES;
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
            let paddr = run.paddr() + grain * GRAIN_SIZE;
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
        // No grant descriptor is visible until zeroed frames, all metadata
        // pages, and both section indexes have been installed.
        for (offset, frames) in metadata {
            self.meta_area.as_ref().unwrap().map_additional_frames(
                offset,
                frames.into_iter(),
                META_PAGE_PROP,
            )?;
        }
        for (&section, &block) in &sections {
            if !growth.sections.contains_key(&section) {
                write_u32(&self.reverse_frames, block as usize, section as u32);
                publish_u32(&self.index_frames, section, block);
            }
        }
        let descriptor = RunDesc {
            paddr: run.paddr() as u64,
            grains: count,
            reserved: 0,
        };
        let descriptor_offset = growth.runs as usize * size_of::<RunDesc>();
        let page = &self.run_frames[descriptor_offset / PAGE_SIZE];
        let offset = descriptor_offset % PAGE_SIZE;
        page.write_bytes(offset, &descriptor.paddr.to_le_bytes())
            .unwrap();
        page.write_bytes(offset + 8, &count.to_le_bytes()).unwrap();
        let end = run.paddr() + bytes;
        self.memory.publish(run);
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
    pub(crate) fn run_pages(&self) -> usize {
        self.run_frames.len()
    }
    pub(crate) fn index_pages(&self) -> usize {
        self.index_frames.len()
    }
    pub(crate) fn shared_pages(&self) -> usize {
        1 + self.run_frames.len() + self.index_frames.len() + self.reverse_frames.len()
    }
    pub(crate) fn shared_frames(&self) -> impl Iterator<Item = Frame<()>> + '_ {
        core::iter::once(self.info_frame.clone())
            .chain(self.run_frames.iter().cloned())
            .chain(self.index_frames.iter().cloned())
            .chain(self.reverse_frames.iter().cloned())
    }
}

impl Drop for Grant {
    fn drop(&mut self) {
        self.memory.close();
        drop(self.meta_area.take());
        self.memory.reclaim();
    }
}

fn allocate_pages(bytes: usize, invalid: bool) -> Result<Vec<Frame<()>>> {
    let mut pages = Vec::with_capacity(bytes.div_ceil(PAGE_SIZE));
    for _ in 0..bytes.div_ceil(PAGE_SIZE) {
        let frame = FrameAllocOptions::new().alloc_frame()?;
        if invalid {
            frame.write_bytes(0, &[0xff; PAGE_SIZE])?;
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
    fn authorized_ceiling_survives_unsatisfied_contiguous_request() {
        let grant = Grant::new(1, 1, 4).unwrap();
        let (result, committed) = grant.grow_authorized(2, 2, 1);
        assert!(matches!(result, Err(Error::AccessDenied)));
        assert_eq!(committed, 1);
        assert_eq!(grant.ceiling(), 2);
        assert_eq!(grant.grains(), 1);
        assert_eq!(grant.grow(1, 0, false).unwrap(), 1);
        assert_eq!(grant.grains(), 2);
    }

    #[ktest]
    fn available_ceiling_refunds_unneeded_authorization() {
        let grant = Grant::new(1, 3, 4).unwrap();
        let (result, committed) = grant.grow_authorized(2, 0, 2);
        assert_eq!(result.unwrap(), 2);
        assert_eq!(committed, 0);
        assert_eq!(grant.ceiling(), 3);
    }
}
