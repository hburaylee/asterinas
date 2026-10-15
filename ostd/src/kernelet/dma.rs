// SPDX-License-Identifier: MPL-2.0

//! DMA visibility in the existing shared frame-metadata word.
//!
//! The low 31 bits retain the image's linked-list identity. Retirement closes
//! admission before the last owner waits for Host accesses to finish. A new
//! owner cannot reuse that word until retirement clears its gate.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::{Error, Result};

#[cfg(any(feature = "kernelet", ktest))]
pub(crate) const LIST_ID_MASK: u64 = (1 << 31) - 1;
const RETIRING: u64 = 1 << 31;
#[cfg(any(feature = "kernelet", ktest))]
const OWNER_ONE: u64 = 1 << 32;
const OWNER_MASK: u64 = 0xffff << 32;
#[cfg(any(not(feature = "kernelet"), ktest))]
const PIN_ONE: u64 = 1 << 48;
const PIN_MASK: u64 = 0xffff << 48;

#[cfg(any(not(feature = "kernelet"), ktest))]
pub(crate) fn has_owner(state: &AtomicU64) -> bool {
    let value = state.load(Ordering::Acquire);
    value & RETIRING == 0 && value & OWNER_MASK != 0
}

#[cfg(any(feature = "kernelet", ktest))]
pub(crate) fn register_owner(state: &AtomicU64) -> Result<()> {
    let mut old = state.load(Ordering::Acquire);
    loop {
        if old & RETIRING != 0 {
            return Err(Error::NotEnoughResources);
        }
        if old & OWNER_MASK == OWNER_MASK {
            return Err(Error::Overflow);
        }
        match state.compare_exchange_weak(old, old + OWNER_ONE, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => return Ok(()),
            Err(value) => old = value,
        }
    }
}

/// Removes an owner and returns whether this caller owns the retirement gate.
#[cfg(any(feature = "kernelet", ktest))]
fn begin_retire(state: &AtomicU64) -> Result<bool> {
    let mut old = state.load(Ordering::Acquire);
    loop {
        if old & RETIRING != 0 || old & OWNER_MASK == 0 {
            return Err(Error::InvalidArgs);
        }
        let last = old & OWNER_MASK == OWNER_ONE;
        let new = (old - OWNER_ONE) | if last { RETIRING } else { 0 };
        match state.compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Ok(last),
            Err(value) => old = value,
        }
    }
}

#[cfg(any(feature = "kernelet", ktest))]
fn finish_retire(state: &AtomicU64) -> bool {
    let mut old = state.load(Ordering::Acquire);
    loop {
        debug_assert_ne!(old & RETIRING, 0);
        debug_assert_eq!(old & OWNER_MASK, 0);
        if old & PIN_MASK != 0 {
            return false;
        }
        match state.compare_exchange_weak(old, old & !RETIRING, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => return true,
            Err(value) => old = value,
        }
    }
}

#[cfg(any(not(feature = "kernelet"), ktest))]
pub(crate) fn try_pin(state: &AtomicU64) -> Result<()> {
    let mut old = state.load(Ordering::Acquire);
    loop {
        if old & RETIRING != 0 || old & OWNER_MASK == 0 {
            return Err(Error::AccessDenied);
        }
        if old & PIN_MASK == PIN_MASK {
            return Err(Error::Overflow);
        }
        match state.compare_exchange_weak(old, old + PIN_ONE, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Ok(()),
            Err(value) => old = value,
        }
    }
}

#[cfg(any(not(feature = "kernelet"), ktest))]
pub(crate) fn unpin(state: &AtomicU64) {
    let old = state.fetch_sub(PIN_ONE, Ordering::Release);
    debug_assert_ne!(old & PIN_MASK, 0);
}

#[cfg(any(feature = "kernelet", ktest))]
fn retire_owner(state: &AtomicU64) {
    let last = begin_retire(state).unwrap_or_else(|_| crate::panic::abort());
    if !last {
        return;
    }
    while !finish_retire(state) {
        core::hint::spin_loop();
        // Match the existing image spin-lock slow path. Native Host work may
        // run even while this image holds a virtual IRQ/preemption guard.
        #[cfg(feature = "kernelet")]
        super::entry::on_spin();
        #[cfg(not(feature = "kernelet"))]
        crate::task::Task::yield_now();
    }
}

/// Publishes pages held by one OSTD DMA object. A failed page rolls back the
/// preceding pages before the constructor can release its storage.
///
/// # Safety
/// The complete aligned range must be owned untyped DMA storage until the
/// matching unregister returns. Only OSTD's DMA owners may publish it.
#[cfg(feature = "kernelet")]
pub(crate) unsafe fn register(range: &core::ops::Range<usize>) -> Result<()> {
    use crate::mm::{PAGE_SIZE, frame::meta::dma_state};
    if range.is_empty()
        || !range.start.is_multiple_of(PAGE_SIZE)
        || !range.end.is_multiple_of(PAGE_SIZE)
    {
        return Err(Error::InvalidArgs);
    }
    register_pages(range, |page| {
        dma_state(page).map_err(|_| Error::AccessDenied)
    })
}

#[cfg(any(feature = "kernelet", ktest))]
fn register_pages<'a>(
    range: &core::ops::Range<usize>,
    state_for: impl Fn(usize) -> Result<&'a AtomicU64>,
) -> Result<()> {
    use crate::mm::PAGE_SIZE;
    let mut page = range.start;
    while page < range.end {
        let result = state_for(page).and_then(register_owner);
        if let Err(error) = result {
            for previous in (range.start..page).step_by(PAGE_SIZE).rev() {
                retire_owner(state_for(previous).unwrap());
            }
            return Err(error);
        }
        page += PAGE_SIZE;
    }
    Ok(())
}

/// Revokes one owner's pages while its Segment/KVirtArea fields remain alive.
///
/// # Safety
/// The range must match pages published by register (including a valid DMA
/// split), and remain untyped and owned until this operation returns.
#[cfg(feature = "kernelet")]
pub(crate) unsafe fn unregister(range: &core::ops::Range<usize>) {
    use crate::mm::{PAGE_SIZE, frame::meta::dma_state};
    for page in range.clone().step_by(PAGE_SIZE) {
        retire_owner(dma_state(page).unwrap_or_else(|_| crate::panic::abort()));
    }
}

#[cfg(ktest)]
mod test {
    use super::*;
    use crate::prelude::*;

    #[ktest]
    fn retirement_excludes_new_owners_and_pins_without_erasing_list_id() {
        let state = AtomicU64::new(23);
        assert_eq!(try_pin(&state), Err(Error::AccessDenied));
        register_owner(&state).unwrap();
        try_pin(&state).unwrap();
        assert!(begin_retire(&state).unwrap());
        assert!(!finish_retire(&state));
        assert_eq!(register_owner(&state), Err(Error::NotEnoughResources));
        assert_eq!(try_pin(&state), Err(Error::AccessDenied));
        unpin(&state);
        assert!(finish_retire(&state));
        assert_eq!(state.load(Ordering::Acquire), 23);
        register_owner(&state).unwrap();
        assert_eq!(state.load(Ordering::Acquire) & LIST_ID_MASK, 23);
    }

    #[ktest]
    fn packed_counters_reject_overflow_without_carrying_into_neighbors() {
        let owners = AtomicU64::new(OWNER_MASK | 17);
        assert_eq!(register_owner(&owners), Err(Error::Overflow));
        assert_eq!(owners.load(Ordering::Acquire), OWNER_MASK | 17);
        let pins = AtomicU64::new(OWNER_ONE | PIN_MASK | 19);
        assert_eq!(try_pin(&pins), Err(Error::Overflow));
        assert_eq!(pins.load(Ordering::Acquire), OWNER_ONE | PIN_MASK | 19);
        assert!(!begin_retire(&AtomicU64::new(2 * OWNER_ONE)).unwrap());
    }
    #[ktest]
    fn failed_multi_page_registration_rolls_back_only_its_acquired_owners() {
        use crate::mm::PAGE_SIZE;
        let states = [
            AtomicU64::new(31),
            AtomicU64::new(OWNER_MASK | 7),
            AtomicU64::new(11),
        ];
        assert_eq!(
            register_pages(&(0..3 * PAGE_SIZE), |page| Ok(&states[page / PAGE_SIZE])),
            Err(Error::Overflow)
        );
        assert_eq!(states[0].load(Ordering::Acquire), 31);
        assert_eq!(states[1].load(Ordering::Acquire), OWNER_MASK | 7);
        assert_eq!(states[2].load(Ordering::Acquire), 11);
        states[0].store(OWNER_ONE | 31, Ordering::Relaxed);
        assert_eq!(
            register_pages(&(0..3 * PAGE_SIZE), |page| Ok(&states[page / PAGE_SIZE])),
            Err(Error::Overflow)
        );
        assert_eq!(states[0].load(Ordering::Acquire), OWNER_ONE | 31);
    }
}
