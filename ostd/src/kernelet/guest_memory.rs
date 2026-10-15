// SPDX-License-Identifier: MPL-2.0

//! Revocable Host access to a kernelet's physical-memory grant.

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::{
    ops::Range,
    sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
};

use smallvec::SmallVec;

use super::{
    abi::GRAIN_SIZE,
    control::{KerneletState, identity::Registration},
    dma,
    owner::{KerneletId, OwnerTable},
};
use crate::{
    Error, Result,
    mm::{
        Frame, HasPaddr, HasSize, PAGE_SIZE, VmReader, VmWriter,
        frame::{
            Segment,
            meta::{META_IO_STATE_OFFSET, META_SLOT_SIZE},
        },
        kspace::paddr_to_vaddr,
    },
    sync::{LocalIrqDisabled, SpinLock, WaitQueue},
};

struct GrantRun {
    frames: Segment<()>,
    pins: Vec<usize>,
    // Retain authoritative metadata backing even if Grant construction fails
    // or its virtual metadata mapping is retired while a Host pin is alive.
    metadata: Vec<Frame<()>>,
    owners: &'static OwnerTable,
    owner: KerneletId,
    published: bool,
}

impl GrantRun {
    fn io_state(&self, paddr: usize) -> Option<&AtomicU64> {
        let page = paddr.checked_sub(self.frames.paddr())? / PAGE_SIZE;
        if page >= self.frames.size() / PAGE_SIZE {
            return None;
        }
        let offset = page * META_SLOT_SIZE + META_IO_STATE_OFFSET;
        let frame = self.metadata.get(offset / PAGE_SIZE)?;
        let address = paddr_to_vaddr(frame.paddr()) + offset % PAGE_SIZE;
        // SAFETY: Host-owned backing frames contain initialized 64-byte image
        // metadata slots. This aligned atomic field is accessed atomically by
        // both halves; the registry retains its backing through the last pin.
        Some(unsafe { &*(address as *const AtomicU64) })
    }
}

impl Drop for GrantRun {
    fn drop(&mut self) {
        if self.published {
            // Clear ownership before Segment drops its physical frame handles.
            self.owners.release(
                &(self.frames.paddr()..self.frames.paddr() + self.frames.size()),
                self.owner,
            );
        }
    }
}

/// An unpublished registry entry. Errors retire it without publishing an owner.
pub(super) struct PendingRun {
    memory: Arc<GrantMemory>,
    base: usize,
    published: bool,
}

impl PendingRun {
    pub(super) fn set_metadata(&mut self, frames: Vec<Frame<()>>) -> Result<()> {
        let mut state = self.memory.state.lock();
        let run = state.runs.get_mut(&self.base).ok_or(Error::InvalidArgs)?;
        let expected = run.frames.size() / PAGE_SIZE * META_SLOT_SIZE / PAGE_SIZE;
        if frames.len() != expected || !run.metadata.is_empty() {
            return Err(Error::InvalidArgs);
        }
        run.metadata = frames;
        Ok(())
    }

    pub(super) fn publish(mut self) {
        let mut state = self.memory.state.lock();
        debug_assert!(state.accepting);
        let run = state.runs.get_mut(&self.base).unwrap();
        run.owners.publish(
            &(run.frames.paddr()..run.frames.paddr() + run.frames.size()),
            run.owner,
        );
        run.published = true;
        self.published = true;
    }
}

impl Drop for PendingRun {
    fn drop(&mut self) {
        if !self.published {
            let run = self.memory.state.lock().runs.remove(&self.base);
            drop(run);
        }
    }
}

struct MemoryState {
    accepting: bool,
    runs: BTreeMap<usize, GrantRun>,
    pins: usize,
    // Only the lifecycle word is shared. A retained memory capability must
    // neither retain RunControl's stacks nor read a freed state pointer.
    lifecycle: Option<Arc<AtomicU8>>,
    // A failed construction can drop its control while a Host pin is active.
    // Keep only the reservation until owners and physical frames are returned.
    identity: Option<Arc<Registration>>,
    // Before first entry all grant frames are untyped Host-owned storage.
    // Afterwards only live DMA mappings authorize safe Host byte access.
    dma_only: bool,
}

impl MemoryState {
    fn io_state(&self, page: usize) -> Option<&AtomicU64> {
        self.run_covering(page)?.0.io_state(page)
    }

    fn dma_covers(&self, range: &Range<usize>) -> bool {
        if range.is_empty() {
            return true;
        }
        let start = range.start / PAGE_SIZE * PAGE_SIZE;
        let end = range.end.div_ceil(PAGE_SIZE) * PAGE_SIZE;
        (start..end)
            .step_by(PAGE_SIZE)
            .all(|page| self.io_state(page).is_some_and(dma::has_owner))
    }

    fn accepts_access(&self) -> bool {
        self.accepting
            && !self.lifecycle.as_ref().is_some_and(|lifecycle| {
                matches!(lifecycle.load(Ordering::Acquire), value if
                value == KerneletState::Destroying as u8 || value == KerneletState::Destroyed as u8)
            })
    }

    fn run_covering(&self, paddr: usize) -> Option<(&GrantRun, usize)> {
        let (_, run) = self.runs.range(..=paddr).next_back()?;
        let end = run.frames.paddr() + run.frames.size();
        (paddr < end).then_some((run, end))
    }
}

/// The pin registry's lock serializes admission with the destroy drain check.
/// No device callback or file operation executes under this lock.
pub(crate) struct GrantMemory {
    state: SpinLock<MemoryState, LocalIrqDisabled>,
    drained: Arc<WaitQueue>,
    mappings_retired: AtomicBool,
    owners: &'static OwnerTable,
    owner: KerneletId,
}

impl GrantMemory {
    pub(super) fn new(owner: KerneletId) -> Result<Arc<Self>> {
        let owners = OwnerTable::shared()?;
        Ok(Arc::new(Self {
            state: SpinLock::new(MemoryState {
                accepting: true,
                runs: BTreeMap::new(),
                pins: 0,
                lifecycle: None,
                identity: None,
                dma_only: false,
            }),
            drained: Arc::new(WaitQueue::new()),
            mappings_retired: AtomicBool::new(false),
            owners,
            owner,
        }))
    }

    pub(crate) fn bind_lifecycle(&self, lifecycle: Arc<AtomicU8>) {
        let mut state = self.state.lock();
        debug_assert!(state.lifecycle.is_none());
        state.lifecycle = Some(lifecycle);
    }

    pub(crate) fn bind_identity(&self, identity: Arc<Registration>) {
        let mut state = self.state.lock();
        debug_assert!(state.identity.is_none());
        state.identity = Some(identity);
    }

    pub(super) fn prepare(self: &Arc<Self>, frames: Segment<()>) -> Result<PendingRun> {
        let base = frames.paddr();
        let end = base.checked_add(frames.size()).ok_or(Error::InvalidArgs)?;
        self.owners.prepare(&(base..end))?;
        let mut pins = Vec::new();
        let grains = frames.size() / GRAIN_SIZE;
        pins.try_reserve_exact(grains)
            .map_err(|_| Error::NoMemory)?;
        pins.resize(grains, 0);
        let mut state = self.state.lock();
        if !state.accepts_access()
            || state
                .runs
                .range(..end)
                .next_back()
                .is_some_and(|(_, run)| run.frames.paddr() + run.frames.size() > base)
        {
            return Err(Error::AccessDenied);
        }
        state.runs.insert(
            base,
            GrantRun {
                frames,
                pins,
                metadata: Vec::new(),
                owners: self.owners,
                owner: self.owner,
                published: false,
            },
        );
        Ok(PendingRun {
            memory: self.clone(),
            base,
            published: false,
        })
    }

    pub(crate) fn drain_queue(&self) -> Arc<WaitQueue> {
        self.drained.clone()
    }

    /// Closes new pin admission and reports distinct pinned grains.
    pub(crate) fn close(&self) -> usize {
        let mut state = self.state.lock();
        state.accepting = false;
        state.pins
    }

    /// Drops physical ownership after the caller has removed every mapping.
    pub(crate) fn reclaim(&self) {
        let (runs, identity) = {
            let mut state = self.state.lock();
            debug_assert!(!state.accepting);
            self.mappings_retired.store(true, Ordering::Release);
            if state.pins == 0 {
                (core::mem::take(&mut state.runs), state.identity.take())
            } else {
                (BTreeMap::new(), None)
            }
        };
        drop(runs);
        drop(identity);
    }

    fn checked_range(paddr: u64, len: usize) -> Result<Range<usize>> {
        let start = usize::try_from(paddr).map_err(|_| Error::InvalidArgs)?;
        let end = start.checked_add(len).ok_or(Error::InvalidArgs)?;
        if end > crate::mm::frame::max_paddr() {
            return Err(Error::AccessDenied);
        }
        Ok(start..end)
    }

    fn owns_range(&self, paddr: u64, len: usize) -> bool {
        let Ok(range) = Self::checked_range(paddr, len) else {
            return false;
        };
        let state = self.state.lock();
        state.accepts_access() && self.owners.contains(&range, self.owner)
    }

    fn contains(&self, paddr: u64, len: usize) -> bool {
        let Ok(range) = Self::checked_range(paddr, len) else {
            return false;
        };
        let state = self.state.lock();
        if !state.accepts_access() {
            return false;
        }
        self.owners.contains(&range, self.owner) && (!state.dma_only || state.dma_covers(&range))
    }

    /// Closes construction-time access before any Guest allocator can run.
    pub(crate) fn restrict_to_dma(&self) -> Result<()> {
        let mut state = self.state.lock();
        // A scoped construction accessor may itself call start. Never wait
        // for that callback's own pin; leave Created retryable instead.
        if state.pins != 0 {
            return Err(Error::NotEnoughResources);
        }
        state.dma_only = true;
        Ok(())
    }

    fn pin(self: &Arc<Self>, paddr: u64, len: usize) -> Result<MemoryPin> {
        self.pin_impl(paddr, len, true)
    }

    fn pin_impl(self: &Arc<Self>, paddr: u64, len: usize, dma: bool) -> Result<MemoryPin> {
        let Range { start, end } = Self::checked_range(paddr, len)?;
        let mut state = self.state.lock();
        if !state.accepts_access() || !self.owners.contains(&(start..end), self.owner) {
            return Err(Error::AccessDenied);
        }
        // This state read linearizes admission before or after the destroy
        // flip. A pin admitted before the flip increments under this lock;
        // close() takes the same lock before checking the remaining pins.
        let mut cursor = start;
        let mut held: SmallVec<[(usize, Range<usize>); 4]> = SmallVec::new();
        while cursor < end {
            let (run, run_end) = state.run_covering(cursor).ok_or(Error::AccessDenied)?;
            let run_base = run.frames.paddr();
            let next = run_end.min(end);
            let range = (cursor - run_base) / GRAIN_SIZE..(next - run_base).div_ceil(GRAIN_SIZE);
            if run.pins[range.clone()]
                .iter()
                .any(|count| *count == usize::MAX)
            {
                return Err(Error::Overflow);
            }
            held.push((run_base, range));
            cursor = next;
        }
        let dma_pages = if dma && state.dma_only && start != end {
            let first = start / PAGE_SIZE * PAGE_SIZE;
            let last = end.div_ceil(PAGE_SIZE) * PAGE_SIZE;
            let mut page = first;
            while page < last {
                let result = state
                    .io_state(page)
                    .ok_or(Error::AccessDenied)
                    .and_then(dma::try_pin);
                if let Err(error) = result {
                    // Grain counters have not changed yet. Every preceding
                    // page was pinned under this same registry lock.
                    for previous in (first..page).step_by(PAGE_SIZE).rev() {
                        dma::unpin(state.io_state(previous).unwrap());
                    }
                    return Err(error);
                }
                page += PAGE_SIZE;
            }
            first..last
        } else {
            0..0
        };
        let mut added = 0;
        for (base, range) in &held {
            let run = state.runs.get_mut(base).unwrap();
            for count in &mut run.pins[range.clone()] {
                added += usize::from(*count == 0);
                *count += 1;
            }
        }
        state.pins += added;
        Ok(MemoryPin {
            memory: self.clone(),
            held,
            dma_pages,
        })
    }
}

struct MemoryPin {
    memory: Arc<GrantMemory>,
    held: SmallVec<[(usize, Range<usize>); 4]>,
    dma_pages: Range<usize>,
}

impl Drop for MemoryPin {
    fn drop(&mut self) {
        let (reclaimed, notify) = {
            let mut state = self.memory.state.lock();
            for page in self.dma_pages.clone().step_by(PAGE_SIZE) {
                dma::unpin(state.io_state(page).unwrap());
            }
            let mut removed = 0;
            for (base, range) in &self.held {
                let run = state.runs.get_mut(base).unwrap();
                for count in &mut run.pins[range.clone()] {
                    *count -= 1;
                    removed += usize::from(*count == 0);
                }
            }
            state.pins -= removed;
            let notify = !state.accepting;
            let reclaimed = if notify
                && state.pins == 0
                && self.memory.mappings_retired.load(Ordering::Acquire)
            {
                Some((core::mem::take(&mut state.runs), state.identity.take()))
            } else {
                None
            };
            (reclaimed, notify)
        };
        if let Some((runs, identity)) = reclaimed {
            drop(runs);
            drop(identity);
        }
        if notify {
            self.memory.drained.wake_all();
        }
    }
}

/// A revocable capability to access one instance's granted frames.
///
/// Cloning a capability retains only its registry. Every actual access pins
/// the checked range until that operation ends; destroy can revoke idle handles.
#[derive(Clone)]
pub struct GuestMemory {
    memory: Arc<GrantMemory>,
}

impl GuestMemory {
    pub(crate) fn restrict_to_dma(&self) -> Result<()> {
        self.memory.restrict_to_dma()
    }

    pub(crate) fn new(memory: &Arc<GrantMemory>) -> Self {
        Self {
            memory: memory.clone(),
        }
    }

    /// Checks physical ownership for a trusted caller's existing borrow.
    /// This does not authorize byte access or bypass the public DMA boundary.
    pub(crate) fn owns_range(&self, paddr: u64, len: usize) -> bool {
        self.memory.owns_range(paddr, len)
    }

    /// Checks that every byte belongs to a currently accessible grant.
    ///
    /// This query does not pin frames or authorize later access: destroy may
    /// revoke the range after it returns. Actual access must acquire its own pin.
    /// An empty range needs no grant, but still checks admission and address bounds.
    pub fn contains(&self, paddr: u64, len: usize) -> bool {
        self.memory.contains(paddr, len)
    }

    /// Copies bytes from granted memory into a Host-owned buffer.
    pub fn read(&self, paddr: u64, dst: &mut [u8]) -> Result<()> {
        let len = dst.len();
        let _pin = self.memory.pin(paddr, len)?;
        // SAFETY: The pin keeps the entire grant range alive until the copy
        // finishes. Host accesses use VM I/O, as required for untyped memory;
        // the Host-owned destination cannot overlap the grant.
        let mut reader = unsafe {
            VmReader::from_kernel_space(paddr_to_vaddr(paddr as usize) as *const u8, len)
        };
        let copied = reader.read(&mut VmWriter::from(dst));
        debug_assert_eq!(copied, len);
        Ok(())
    }

    /// Copies a Host-owned buffer into granted memory.
    pub fn write(&self, paddr: u64, src: &[u8]) -> Result<()> {
        let len = src.len();
        let _pin = self.memory.pin(paddr, len)?;
        // SAFETY: The pin keeps the entire grant range alive until the copy
        // finishes. Host accesses use VM I/O, as required for untyped memory;
        // the Host-owned source cannot overlap the grant.
        let mut writer =
            unsafe { VmWriter::from_kernel_space(paddr_to_vaddr(paddr as usize) as *mut u8, len) };
        let copied = writer.write(&mut VmReader::from(src));
        debug_assert_eq!(copied, len);
        Ok(())
    }

    /// Runs a closure with bounded accessors that cannot escape their pin.
    pub fn with_range<R>(
        &self,
        paddr: u64,
        len: usize,
        f: impl for<'a> FnOnce(VmReader<'a>, VmWriter<'a>) -> R,
    ) -> Result<R> {
        let _pin = self.memory.pin(paddr, len)?;
        let addr = paddr_to_vaddr(paddr as usize);
        // SAFETY: The range is pinned for this entire call. The higher-ranked
        // callback cannot return either borrowed accessor in R.
        let reader = unsafe { VmReader::from_kernel_space(addr as *const u8, len) }.to_fallible();
        // SAFETY: Same scoped pin and nonescaping lifetime as the reader.
        let writer = unsafe { VmWriter::from_kernel_space(addr as *mut u8, len) }.to_fallible();
        Ok(f(reader, writer))
    }

    /// Runs Host I/O with a writable accessor pinned for the whole call.
    pub fn with_writer<R>(
        &self,
        paddr: u64,
        len: usize,
        f: impl for<'a> FnOnce(&mut VmWriter<'a>) -> R,
    ) -> Result<R> {
        self.with_range(paddr, len, |_, mut writer| f(&mut writer))
    }

    /// Runs Host I/O with a readable accessor pinned for the whole call.
    pub fn with_reader<R>(
        &self,
        paddr: u64,
        len: usize,
        f: impl for<'a> FnOnce(&mut VmReader<'a>) -> R,
    ) -> Result<R> {
        self.with_range(paddr, len, |mut reader, _| f(&mut reader))
    }

    /// Reads one aligned shared ring index without tearing.
    pub fn read_u16_once(&self, paddr: u64) -> Result<u16> {
        if !paddr.is_multiple_of(align_of::<u16>() as u64) {
            return Err(Error::InvalidArgs);
        }
        let _pin = self.memory.pin(paddr, size_of::<u16>())?;
        // SAFETY: The range is aligned, untyped DMA storage (or pre-entry
        // construction storage) and remains pinned through the single load.
        unsafe {
            VmReader::from_kernel_space(
                paddr_to_vaddr(paddr as usize) as *const u8,
                size_of::<u16>(),
            )
        }
        .read_once::<u16>()
    }

    /// Publishes one aligned shared ring index without tearing.
    pub fn write_u16_once(&self, paddr: u64, value: u16) -> Result<()> {
        if !paddr.is_multiple_of(align_of::<u16>() as u64) {
            return Err(Error::InvalidArgs);
        }
        let _pin = self.memory.pin(paddr, size_of::<u16>())?;
        // SAFETY: Same aligned, live untyped DMA range as read_u16_once.
        unsafe {
            VmWriter::from_kernel_space(paddr_to_vaddr(paddr as usize) as *mut u8, size_of::<u16>())
        }
        .write_once(&value)
    }

    /// Reads a Host-validated page-table snapshot without authorizing writes.
    ///
    /// # Safety
    /// The trusted caller must establish that these bytes permit VM reads
    /// while pinned (e.g. atomic page-table words), despite not being DMA data.
    pub(crate) unsafe fn with_raw_reader<R>(
        &self,
        paddr: u64,
        len: usize,
        f: impl for<'a> FnOnce(&mut VmReader<'a>) -> R,
    ) -> Result<R> {
        let _pin = self.memory.pin_impl(paddr, len, false)?;
        // SAFETY: The caller establishes byte-read validity; the grant pin
        // keeps the mapping alive, and the callback cannot retain the reader.
        let mut reader = unsafe {
            VmReader::from_kernel_space(paddr_to_vaddr(paddr as usize) as *const u8, len)
        }
        .to_fallible();
        Ok(f(&mut reader))
    }
}

#[cfg(ktest)]
mod test {
    use super::*;
    use crate::{
        mm::{FrameAllocOptions, PAGE_SIZE, Split},
        prelude::*,
    };

    #[ktest]
    fn copies_unaligned_bytes_across_adjacent_grants() {
        let identity = super::super::control::identity::Registration::new().unwrap();
        let memory = GrantMemory::new(identity.owner()).unwrap();
        let frames = FrameAllocOptions::new()
            .alloc_segment_aligned(2 * GRAIN_SIZE / PAGE_SIZE, GRAIN_SIZE)
            .unwrap();
        let base = frames.paddr() as u64;
        let (first, second) = frames.split(GRAIN_SIZE);
        memory.prepare(first).unwrap().publish();
        memory.prepare(second).unwrap().publish();
        let capability = GuestMemory::new(&memory);
        let start = base + GRAIN_SIZE as u64 - 7;
        let src: Vec<u8> = (0..PAGE_SIZE + 17).map(|index| index as u8).collect();
        let guard = alloc::vec![0xa5; src.len() + 2];
        capability.write(start - 1, &guard).unwrap();
        capability.write(start, &src).unwrap();
        let mut dst = alloc::vec![0x5a; src.len() + 4];
        capability
            .read(start - 1, &mut dst[1..src.len() + 3])
            .unwrap();
        assert_eq!(dst[0], 0x5a);
        assert_eq!(dst[1], 0xa5);
        assert_eq!(&dst[2..src.len() + 2], src.as_slice());
        assert_eq!(dst[src.len() + 2], 0xa5);
        assert_eq!(dst[src.len() + 3], 0x5a);
        assert_eq!(memory.close(), 0);
        memory.reclaim();
    }

    #[ktest]
    fn copies_reject_invalid_ranges_before_touching_buffers() {
        let identity = super::super::control::identity::Registration::new().unwrap();
        let memory = GrantMemory::new(identity.owner()).unwrap();
        let frames = FrameAllocOptions::new()
            .alloc_segment_aligned(GRAIN_SIZE / PAGE_SIZE, GRAIN_SIZE)
            .unwrap();
        let base = frames.paddr() as u64;
        memory.prepare(frames).unwrap().publish();
        let capability = GuestMemory::new(&memory);
        let last = base + GRAIN_SIZE as u64 - 1;
        capability.write(last, &[0xa5]).unwrap();
        let mut dst = [0x5a; 2];
        assert!(matches!(
            capability.read(last, &mut dst),
            Err(Error::AccessDenied)
        ));
        assert_eq!(dst, [0x5a; 2]);
        assert!(matches!(
            capability.write(last, &[1, 2]),
            Err(Error::AccessDenied)
        ));
        let mut byte = [0];
        capability.read(last, &mut byte).unwrap();
        assert_eq!(byte, [0xa5]);
        assert!(matches!(
            capability.read(u64::MAX, &mut byte),
            Err(Error::InvalidArgs)
        ));
        assert_eq!(byte, [0xa5]);
        capability.read(0, &mut []).unwrap();
        capability.write(0, &[]).unwrap();
        assert_eq!(memory.close(), 0);
        assert!(matches!(
            capability.read(base, &mut byte),
            Err(Error::AccessDenied)
        ));
        assert_eq!(byte, [0xa5]);
        assert!(matches!(
            capability.write(base, &[1]),
            Err(Error::AccessDenied)
        ));
        assert!(matches!(
            capability.read(0, &mut []),
            Err(Error::AccessDenied)
        ));
        assert!(matches!(capability.write(0, &[]), Err(Error::AccessDenied)));
        memory.reclaim();
    }

    #[ktest]
    fn owner_array_rejects_other_instances_and_unpublished_runs() {
        let first = super::super::control::identity::Registration::new().unwrap();
        let second = super::super::control::identity::Registration::new().unwrap();
        let memory = GrantMemory::new(first.owner()).unwrap();
        let other = GrantMemory::new(second.owner()).unwrap();
        let frames = FrameAllocOptions::new()
            .alloc_segment_aligned(GRAIN_SIZE / PAGE_SIZE, GRAIN_SIZE)
            .unwrap();
        let base = frames.paddr() as u64;
        let pending = memory.prepare(frames).unwrap();
        assert!(!GuestMemory::new(&memory).contains(base, 1));
        assert!(memory.pin(base, 1).is_err());
        pending.publish();
        assert!(GuestMemory::new(&memory).contains(base, 1));
        assert!(!GuestMemory::new(&other).contains(base, 1));
        assert!(other.pin(base, 1).is_err());
        memory.close();
        memory.reclaim();
        assert!(
            !memory
                .owners
                .contains(&(base as usize..base as usize + GRAIN_SIZE), first.owner())
        );
    }

    #[ktest]
    fn abandoned_run_never_publishes_an_owner() {
        let identity = super::super::control::identity::Registration::new().unwrap();
        let memory = GrantMemory::new(identity.owner()).unwrap();
        let frames = FrameAllocOptions::new()
            .alloc_segment_aligned(GRAIN_SIZE / PAGE_SIZE, GRAIN_SIZE)
            .unwrap();
        let base = frames.paddr();
        let pending = memory.prepare(frames).unwrap();
        drop(pending);
        assert!(memory.state.lock().runs.is_empty());
        assert!(
            !memory
                .owners
                .contains(&(base..base + GRAIN_SIZE), identity.owner())
        );
        assert!(!GuestMemory::new(&memory).contains(base as u64, 1));
    }

    #[ktest]
    fn contains_checks_adjacent_runs_without_acquiring_pins() {
        let identity = super::super::control::identity::Registration::new().unwrap();
        let memory = GrantMemory::new(identity.owner()).unwrap();
        let frames = FrameAllocOptions::new()
            .alloc_segment_aligned(2 * GRAIN_SIZE / PAGE_SIZE, GRAIN_SIZE)
            .unwrap();
        let base = frames.paddr();
        let (first, second) = frames.split(GRAIN_SIZE);
        memory.prepare(first).unwrap().publish();
        memory.prepare(second).unwrap().publish();
        let capability = GuestMemory::new(&memory);
        let pin = memory.pin(base as u64, 1).unwrap();
        {
            let mut state = memory.state.lock();
            // A range query remains valid even when no additional pin can fit.
            state.runs.get_mut(&base).unwrap().pins[0] = usize::MAX;
        }
        assert!(capability.contains(base as u64, 2 * GRAIN_SIZE));
        assert!(capability.contains((base + GRAIN_SIZE - 1) as u64, 2));
        assert!(!capability.contains((base + 2 * GRAIN_SIZE) as u64, 1));
        {
            let mut state = memory.state.lock();
            assert_eq!(state.pins, 1);
            assert_eq!(state.runs[&base].pins, [usize::MAX]);
            assert_eq!(state.runs[&(base + GRAIN_SIZE)].pins, [0]);
            state.runs.get_mut(&base).unwrap().pins[0] = 1;
        }
        drop(pin);
        assert_eq!(memory.close(), 0);
        memory.reclaim();
    }

    #[ktest]
    fn contains_rejects_grant_gaps() {
        let identity = super::super::control::identity::Registration::new().unwrap();
        let memory = GrantMemory::new(identity.owner()).unwrap();
        let frames = FrameAllocOptions::new()
            .alloc_segment_aligned(3 * GRAIN_SIZE / PAGE_SIZE, GRAIN_SIZE)
            .unwrap();
        let base = frames.paddr();
        let (first, rest) = frames.split(GRAIN_SIZE);
        let (gap, last) = rest.split(GRAIN_SIZE);
        memory.prepare(first).unwrap().publish();
        memory.prepare(last).unwrap().publish();
        drop(gap);
        let capability = GuestMemory::new(&memory);
        assert!(capability.contains(base as u64, GRAIN_SIZE));
        assert!(!capability.contains(base as u64, GRAIN_SIZE + 1));
        assert!(!capability.contains((base + GRAIN_SIZE) as u64, 1));
        assert!(!capability.contains(base as u64, 3 * GRAIN_SIZE));
        assert!(capability.contains((base + 2 * GRAIN_SIZE) as u64, GRAIN_SIZE));
        assert_eq!(memory.close(), 0);
        memory.reclaim();
    }

    #[ktest]
    fn contains_checks_empty_ranges_bounds_and_revocation() {
        let identity = super::super::control::identity::Registration::new().unwrap();
        let memory = GrantMemory::new(identity.owner()).unwrap();
        let capability = GuestMemory::new(&memory);
        let lifecycle = Arc::new(AtomicU8::new(KerneletState::Created as u8));
        memory.bind_lifecycle(lifecycle.clone());
        let max = crate::mm::frame::max_paddr();
        assert!(capability.contains(0, 0));
        assert!(capability.contains(max as u64, 0));
        assert!(!capability.contains(max as u64, 1));
        assert!(!capability.contains(1, usize::MAX));
        assert!(!capability.contains(u64::MAX, 1));
        assert!(!capability.contains(0, 1));
        if let Some(outside) = max.checked_add(1) {
            assert!(!capability.contains(outside as u64, 0));
        }
        let frames = FrameAllocOptions::new()
            .alloc_segment_aligned(GRAIN_SIZE / PAGE_SIZE, GRAIN_SIZE)
            .unwrap();
        let base = frames.paddr() as u64;
        memory.prepare(frames).unwrap().publish();
        assert!(capability.contains(base, 1));
        lifecycle.store(KerneletState::Destroying as u8, Ordering::Release);
        assert!(!capability.contains(0, 0));
        assert!(!capability.contains(base, 1));
        lifecycle.store(KerneletState::Destroyed as u8, Ordering::Release);
        assert!(!capability.contains(0, 0));
        assert!(!capability.contains(base, 1));
        lifecycle.store(KerneletState::Created as u8, Ordering::Release);
        assert!(capability.contains(0, 0));
        assert_eq!(memory.close(), 0);
        assert!(!capability.contains(0, 0));
        memory.reclaim();
    }

    #[ktest]
    fn overlapping_accesses_count_distinct_grains() {
        let identity = super::super::control::identity::Registration::new().unwrap();
        let memory = GrantMemory::new(identity.owner()).unwrap();
        let frames = FrameAllocOptions::new()
            .alloc_segment_aligned(2 * GRAIN_SIZE / PAGE_SIZE, GRAIN_SIZE)
            .unwrap();
        let base = frames.paddr() as u64;
        memory.prepare(frames).unwrap().publish();
        let first = memory.pin(base, GRAIN_SIZE + 1).unwrap();
        let overlap = memory.pin(base + GRAIN_SIZE as u64, 1).unwrap();
        assert_eq!(memory.close(), 2);
        assert!(memory.pin(base, 1).is_err());
        drop(first);
        assert_eq!(memory.close(), 1);
        memory.reclaim();
        assert!(!memory.state.lock().runs.is_empty());
        assert!(memory.owners.contains(
            &(base as usize..base as usize + 2 * GRAIN_SIZE),
            identity.owner()
        ));
        drop(overlap);
        assert_eq!(memory.close(), 0);
        assert!(memory.state.lock().runs.is_empty());
        assert!(!memory.owners.contains(
            &(base as usize..base as usize + 2 * GRAIN_SIZE),
            identity.owner()
        ));
    }

    #[ktest]
    fn revoked_idle_capability_does_not_retain_frames() {
        let identity = super::super::control::identity::Registration::new().unwrap();
        let memory = GrantMemory::new(identity.owner()).unwrap();
        let frames = FrameAllocOptions::new()
            .alloc_segment_aligned(GRAIN_SIZE / PAGE_SIZE, GRAIN_SIZE)
            .unwrap();
        let base = frames.paddr() as u64;
        memory.prepare(frames).unwrap().publish();
        let capability = GuestMemory::new(&memory);
        assert!(capability.contains(base, 1));
        assert_eq!(memory.close(), 0);
        memory.reclaim();
        assert!(!capability.contains(base, 1));
        assert!(memory.state.lock().runs.is_empty());
    }

    #[ktest]
    fn close_reports_held_pins_and_release_wakes_retry() {
        let identity = super::super::control::identity::Registration::new().unwrap();
        let memory = GrantMemory::new(identity.owner()).unwrap();
        let frames = FrameAllocOptions::new()
            .alloc_segment_aligned(GRAIN_SIZE / PAGE_SIZE, GRAIN_SIZE)
            .unwrap();
        let base = frames.paddr() as u64;
        memory.prepare(frames).unwrap().publish();
        let pin = memory.pin(base, GRAIN_SIZE).unwrap();

        // Closing admission reports the genuinely held pin and refuses new
        // pins instead of claiming an empty registry.
        assert_eq!(memory.close(), 1);
        assert!(memory.pin(base, 1).is_err());

        // The retry side registers on the drain queue first, then waits for
        // the last release, mirroring the Host reaper.
        let drained = memory.drain_queue();
        let (waiter, waker) = crate::sync::Waiter::new_pair();
        drained.enqueue_once(waker);
        assert_eq!(memory.close(), 1);
        // This release precedes wait(), exercising its sticky wake contract.
        drop(pin);
        waiter.wait();
        assert_eq!(memory.close(), 0);
        memory.reclaim();
        assert!(memory.state.lock().runs.is_empty());
    }
    fn dma_fixture() -> (Arc<GrantMemory>, u64, Frame<()>) {
        let identity = super::super::control::identity::Registration::new().unwrap();
        let memory = GrantMemory::new(identity.owner()).unwrap();
        memory.bind_identity(Arc::new(identity));
        let frames = FrameAllocOptions::new()
            .alloc_segment_aligned(GRAIN_SIZE / PAGE_SIZE, GRAIN_SIZE)
            .unwrap();
        let base = frames.paddr() as u64;
        let metadata: Vec<_> = (0..GRAIN_SIZE / PAGE_SIZE * META_SLOT_SIZE / PAGE_SIZE)
            .map(|_| FrameAllocOptions::new().alloc_frame().unwrap())
            .collect();
        let witness = metadata[0].clone();
        let mut pending = memory.prepare(frames).unwrap();
        pending.set_metadata(metadata).unwrap();
        pending.publish();
        (memory, base, witness)
    }

    #[ktest]
    fn dma_only_access_rejects_unregistered_and_metadata_pages() {
        let (memory, base, witness) = dma_fixture();
        let capability = GuestMemory::new(&memory);
        capability.write(base, &[1]).unwrap();
        capability.restrict_to_dma().unwrap();
        assert!(!capability.contains(base, 1));
        assert_eq!(capability.write(base, &[2]), Err(Error::AccessDenied));
        {
            let state = memory.state.lock();
            dma::register_owner(state.io_state(base as usize).unwrap()).unwrap();
        }
        assert!(capability.contains(base, PAGE_SIZE));
        assert!(!capability.contains(base + PAGE_SIZE as u64, 1));
        assert!(!capability.contains(witness.paddr() as u64, 1));
        capability.write_u16_once(base + 2, 0x1234).unwrap();
        assert_eq!(capability.read_u16_once(base + 2).unwrap(), 0x1234);
        assert_eq!(
            capability.write_u16_once(base + 1, 1),
            Err(Error::InvalidArgs)
        );
        memory.close();
        memory.reclaim();
    }

    #[ktest]
    fn partial_dma_pin_failure_rolls_back_pages_without_holding_a_grain() {
        let (memory, base, _) = dma_fixture();
        memory.restrict_to_dma().unwrap();
        {
            let state = memory.state.lock();
            dma::register_owner(state.io_state(base as usize).unwrap()).unwrap();
        }
        assert!(matches!(
            memory.pin(base, PAGE_SIZE + 1),
            Err(Error::AccessDenied)
        ));
        {
            let state = memory.state.lock();
            assert_eq!(
                state
                    .io_state(base as usize)
                    .unwrap()
                    .load(Ordering::Acquire)
                    >> 48,
                0
            );
            assert_eq!(state.pins, 0);
        }
        let pin = memory.pin(base, PAGE_SIZE).unwrap();
        assert_eq!(memory.close(), 1);
        drop(pin);
        assert_eq!(memory.close(), 0);
        memory.reclaim();
    }

    #[ktest]
    fn packed_metadata_backing_survives_reclaim_until_last_host_pin() {
        let (memory, base, witness) = dma_fixture();
        memory.restrict_to_dma().unwrap();
        {
            let state = memory.state.lock();
            dma::register_owner(state.io_state(base as usize).unwrap()).unwrap();
        }
        let pin = memory.pin(base, 1).unwrap();
        assert_eq!(witness.reference_count(), 2);
        memory.close();
        memory.reclaim();
        assert_eq!(witness.reference_count(), 2);
        drop(pin);
        assert_eq!(witness.reference_count(), 1);
        assert!(memory.state.lock().runs.is_empty());
    }

    #[ktest]
    fn construction_pin_keeps_dma_restriction_retryable() {
        let (memory, base, _) = dma_fixture();
        let pin = memory.pin(base, 1).unwrap();
        assert_eq!(memory.restrict_to_dma(), Err(Error::NotEnoughResources));
        assert!(!memory.state.lock().dma_only);
        drop(pin);
        memory.restrict_to_dma().unwrap();
        assert!(memory.state.lock().dma_only);
        memory.close();
        memory.reclaim();
    }
}
