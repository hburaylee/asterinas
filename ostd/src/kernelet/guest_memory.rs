// SPDX-License-Identifier: MPL-2.0

//! Revocable Host access to a kernelet's physical-memory grant.

use alloc::{collections::BTreeMap, sync::Arc, vec, vec::Vec};
use core::{
    ops::Range,
    sync::atomic::{AtomicBool, AtomicU8, Ordering},
};

use smallvec::SmallVec;

use super::{abi::GRAIN_SIZE, control::KerneletState};
use crate::{
    Error, Result,
    mm::{HasPaddr, HasSize, VmReader, VmWriter, frame::Segment, kspace::paddr_to_vaddr},
    sync::{LocalIrqDisabled, SpinLock, WaitQueue},
};

struct GrantRun {
    frames: Segment<()>,
    pins: Vec<usize>,
}

struct MemoryState {
    accepting: bool,
    runs: BTreeMap<usize, GrantRun>,
    pins: usize,
    // Only the lifecycle word is shared. A retained memory capability must
    // neither retain RunControl's stacks nor read a freed state pointer.
    lifecycle: Option<Arc<AtomicU8>>,
}

/// The pin registry's lock serializes admission with the destroy drain check.
/// No device callback or file operation executes under this lock.
pub(crate) struct GrantMemory {
    state: SpinLock<MemoryState, LocalIrqDisabled>,
    drained: Arc<WaitQueue>,
    mappings_retired: AtomicBool,
}

impl GrantMemory {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: SpinLock::new(MemoryState {
                accepting: true,
                runs: BTreeMap::new(),
                pins: 0,
                lifecycle: None,
            }),
            drained: Arc::new(WaitQueue::new()),
            mappings_retired: AtomicBool::new(false),
        })
    }

    pub(crate) fn bind_lifecycle(&self, lifecycle: Arc<AtomicU8>) {
        let mut state = self.state.lock();
        debug_assert!(state.lifecycle.is_none());
        state.lifecycle = Some(lifecycle);
    }

    pub(crate) fn publish(&self, run: Segment<()>) {
        let mut state = self.state.lock();
        debug_assert!(state.accepting);
        debug_assert!(run.size().is_multiple_of(GRAIN_SIZE));
        let pins = vec![0; run.size() / GRAIN_SIZE];
        let old = state
            .runs
            .insert(run.paddr(), GrantRun { frames: run, pins });
        debug_assert!(old.is_none());
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
        let runs = {
            let mut state = self.state.lock();
            debug_assert!(!state.accepting);
            self.mappings_retired.store(true, Ordering::Release);
            if state.pins == 0 {
                core::mem::take(&mut state.runs)
            } else {
                BTreeMap::new()
            }
        };
        drop(runs);
    }

    fn pin(self: &Arc<Self>, paddr: u64, len: usize) -> Result<MemoryPin> {
        let start = usize::try_from(paddr).map_err(|_| Error::InvalidArgs)?;
        let end = start.checked_add(len).ok_or(Error::InvalidArgs)?;
        if end > crate::mm::frame::max_paddr() {
            return Err(Error::AccessDenied);
        }
        let mut state = self.state.lock();
        if !state.accepting
            || state.lifecycle.as_ref().is_some_and(|lifecycle| {
                matches!(lifecycle.load(Ordering::Acquire), value if
                value == KerneletState::Destroying as u8 || value == KerneletState::Destroyed as u8)
            })
        {
            return Err(Error::AccessDenied);
        }
        // This state read linearizes admission before or after the destroy
        // flip. A pin admitted before the flip increments under this lock;
        // close() takes the same lock before checking the remaining pins.
        let mut cursor = start;
        let mut held: SmallVec<[(usize, Range<usize>); 4]> = SmallVec::new();
        while cursor < end {
            let (_, run) = state
                .runs
                .range(..=cursor)
                .next_back()
                .ok_or(Error::AccessDenied)?;
            let run_end = run.frames.paddr() + run.frames.size();
            if cursor >= run_end {
                return Err(Error::AccessDenied);
            }
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
        })
    }
}

struct MemoryPin {
    memory: Arc<GrantMemory>,
    held: SmallVec<[(usize, Range<usize>); 4]>,
}

impl Drop for MemoryPin {
    fn drop(&mut self) {
        let (reclaimed, notify) = {
            let mut state = self.memory.state.lock();
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
                Some(core::mem::take(&mut state.runs))
            } else {
                None
            };
            (reclaimed, notify)
        };
        drop(reclaimed);
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
    pub(crate) fn new(memory: &Arc<GrantMemory>) -> Self {
        Self {
            memory: memory.clone(),
        }
    }

    /// Checks that every byte belongs to a currently accessible grant.
    pub fn contains(&self, paddr: u64, len: usize) -> bool {
        self.memory.pin(paddr, len).is_ok()
    }

    /// Copies bytes from granted memory into a Host-owned buffer.
    pub fn read(&self, paddr: u64, dst: &mut [u8]) -> Result<()> {
        let _pin = self.memory.pin(paddr, dst.len())?;
        // SAFETY: The scoped pin covers every byte and retains the frames;
        // the Host destination is distinct from all guest-owned frames.
        unsafe {
            core::ptr::copy_nonoverlapping(
                paddr_to_vaddr(paddr as usize) as *const u8,
                dst.as_mut_ptr(),
                dst.len(),
            )
        };
        Ok(())
    }

    /// Copies a Host-owned buffer into granted memory.
    pub fn write(&self, paddr: u64, src: &[u8]) -> Result<()> {
        let _pin = self.memory.pin(paddr, src.len())?;
        // SAFETY: The scoped pin covers every byte and retains the frames;
        // the Host source is distinct from all guest-owned frames.
        unsafe {
            core::ptr::copy_nonoverlapping(
                src.as_ptr(),
                paddr_to_vaddr(paddr as usize) as *mut u8,
                src.len(),
            )
        };
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
}

#[cfg(ktest)]
mod test {
    use super::*;
    use crate::{
        mm::{FrameAllocOptions, PAGE_SIZE},
        prelude::*,
    };

    #[ktest]
    fn overlapping_accesses_count_distinct_grains() {
        let memory = GrantMemory::new();
        let frames = FrameAllocOptions::new()
            .alloc_segment_aligned(2 * GRAIN_SIZE / PAGE_SIZE, GRAIN_SIZE)
            .unwrap();
        let base = frames.paddr() as u64;
        memory.publish(frames);
        let first = memory.pin(base, GRAIN_SIZE + 1).unwrap();
        let overlap = memory.pin(base + GRAIN_SIZE as u64, 1).unwrap();
        assert_eq!(memory.close(), 2);
        assert!(memory.pin(base, 1).is_err());
        drop(first);
        assert_eq!(memory.close(), 1);
        memory.reclaim();
        assert!(!memory.state.lock().runs.is_empty());
        drop(overlap);
        assert_eq!(memory.close(), 0);
        assert!(memory.state.lock().runs.is_empty());
    }

    #[ktest]
    fn revoked_idle_capability_does_not_retain_frames() {
        let memory = GrantMemory::new();
        let frames = FrameAllocOptions::new()
            .alloc_segment_aligned(GRAIN_SIZE / PAGE_SIZE, GRAIN_SIZE)
            .unwrap();
        let base = frames.paddr() as u64;
        memory.publish(frames);
        let capability = GuestMemory::new(&memory);
        assert!(capability.contains(base, 1));
        assert_eq!(memory.close(), 0);
        memory.reclaim();
        assert!(!capability.contains(base, 1));
        assert!(memory.state.lock().runs.is_empty());
    }

    #[ktest]
    fn close_reports_held_pins_and_release_wakes_retry() {
        let memory = GrantMemory::new();
        let frames = FrameAllocOptions::new()
            .alloc_segment_aligned(GRAIN_SIZE / PAGE_SIZE, GRAIN_SIZE)
            .unwrap();
        let base = frames.paddr() as u64;
        memory.publish(frames);
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
}
