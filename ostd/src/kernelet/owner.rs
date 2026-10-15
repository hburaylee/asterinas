// SPDX-License-Identifier: MPL-2.0

//! Host-wide ownership of aligned physical grant grains.

use alloc::{boxed::Box, vec::Vec};
use core::{
    num::NonZeroU64,
    ops::Range,
    sync::atomic::{AtomicU64, Ordering},
};

use spin::Once;

use super::abi::{self, CpuSlot};
use crate::{Error, Result};

/// A complete instance identity, including its nonzero generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct KerneletId(NonZeroU64);

impl KerneletId {
    pub(super) fn from_slot(slot: CpuSlot) -> Self {
        debug_assert_ne!(slot.kernelet, u16::MAX);
        debug_assert_ne!(slot.generation, 0);
        Self(
            NonZeroU64::new((u64::from(slot.generation) << 16) | u64::from(slot.kernelet)).unwrap(),
        )
    }
}

const _: () = assert!(size_of::<Option<KerneletId>>() == 8);
const _: () = assert!(size_of::<AtomicU64>() == 8);

/// Zero represents `None`; each other word encodes a complete `KerneletId`.
pub(super) struct OwnerTable {
    entries: Box<[AtomicU64]>,
}

static OWNERS: Once<OwnerTable> = Once::new();

impl OwnerTable {
    pub(super) fn shared() -> Result<&'static Self> {
        OWNERS.try_call_once(|| {
            // Use the address span tracked by Host frame metadata, including
            // holes. A usable-byte sum would misindex high physical addresses.
            let count = crate::mm::frame::max_paddr().div_ceil(abi::GRAIN_SIZE);
            let mut entries = Vec::new();
            entries
                .try_reserve_exact(count)
                .map_err(|_| Error::NoMemory)?;
            entries.resize_with(count, || AtomicU64::new(0));
            Ok(Self {
                entries: entries.into_boxed_slice(),
            })
        })
    }

    pub(super) fn prepare(&self, range: &Range<usize>) -> Result<()> {
        if range.is_empty()
            || !range.start.is_multiple_of(abi::GRAIN_SIZE)
            || !range.end.is_multiple_of(abi::GRAIN_SIZE)
            || range.end > crate::mm::frame::max_paddr()
        {
            return Err(Error::InvalidArgs);
        }
        let entries = self
            .entries
            .get(range.start / abi::GRAIN_SIZE..range.end / abi::GRAIN_SIZE)
            .ok_or(Error::InvalidArgs)?;
        if entries
            .iter()
            .any(|entry| entry.load(Ordering::Acquire) != 0)
        {
            return Err(Error::AccessDenied);
        }
        Ok(())
    }

    /// Commits ownership after metadata installation, before run publication.
    /// The caller holds the exclusively allocated Segment and its registry lock.
    pub(super) fn publish(&self, range: &Range<usize>, owner: KerneletId) {
        let entries = &self.entries[range.start / abi::GRAIN_SIZE..range.end / abi::GRAIN_SIZE];
        debug_assert!(
            entries
                .iter()
                .all(|entry| entry.load(Ordering::Relaxed) == 0)
        );
        for entry in entries {
            entry.store(owner.0.get(), Ordering::Release);
        }
    }

    pub(super) fn contains(&self, range: &Range<usize>, owner: KerneletId) -> bool {
        if range.is_empty() {
            return true;
        }
        let Some(entries) = self
            .entries
            .get(range.start / abi::GRAIN_SIZE..range.end.div_ceil(abi::GRAIN_SIZE))
        else {
            return false;
        };
        entries
            .iter()
            .all(|entry| entry.load(Ordering::Acquire) == owner.0.get())
    }

    /// Called only after pin admission closes, pins drain, and mappings retire.
    pub(super) fn release(&self, range: &Range<usize>, owner: KerneletId) {
        for entry in &self.entries[range.start / abi::GRAIN_SIZE..range.end / abi::GRAIN_SIZE] {
            let cleared =
                entry.compare_exchange(owner.0.get(), 0, Ordering::Release, Ordering::Relaxed);
            debug_assert!(cleared.is_ok());
        }
    }
}

#[cfg(ktest)]
mod test {
    use super::*;
    use crate::prelude::*;

    fn owner(generation: u32) -> KerneletId {
        KerneletId::from_slot(CpuSlot {
            kernelet: 1,
            vcpu: 0,
            generation,
            _reserved: 0,
        })
    }

    fn table() -> OwnerTable {
        OwnerTable {
            entries: alloc::vec![AtomicU64::new(0), AtomicU64::new(0)].into_boxed_slice(),
        }
    }

    #[ktest]
    fn owner_lookup_checks_every_grain_and_full_generation() {
        let table = table();
        let old = owner(1);
        let new = owner(2);
        table.prepare(&(0..abi::GRAIN_SIZE)).unwrap();
        table.publish(&(0..abi::GRAIN_SIZE), old);
        assert!(table.contains(&(1..abi::GRAIN_SIZE), old));
        assert!(!table.contains(&(0..1), new));
        assert!(!table.contains(&(abi::GRAIN_SIZE - 1..abi::GRAIN_SIZE + 1), old));
        table.publish(&(abi::GRAIN_SIZE..2 * abi::GRAIN_SIZE), new);
        assert!(!table.contains(&(abi::GRAIN_SIZE - 1..abi::GRAIN_SIZE + 1), new));
        table.release(&(0..abi::GRAIN_SIZE), old);
        table.publish(&(0..abi::GRAIN_SIZE), new);
        assert!(!table.contains(&(0..1), old));
        assert!(table.contains(&(0..2 * abi::GRAIN_SIZE), new));
        table.release(&(0..2 * abi::GRAIN_SIZE), new);
    }

    #[ktest]
    fn owner_preflight_rejects_invalid_and_already_owned_ranges() {
        let table = table();
        for range in [
            0..0,
            1..abi::GRAIN_SIZE,
            0..abi::GRAIN_SIZE + 1,
            0..3 * abi::GRAIN_SIZE,
        ] {
            assert!(table.prepare(&range).is_err());
        }
        table.publish(&(0..abi::GRAIN_SIZE), owner(1));
        assert!(matches!(
            table.prepare(&(0..abi::GRAIN_SIZE)),
            Err(Error::AccessDenied)
        ));
        assert!(
            table
                .prepare(&(abi::GRAIN_SIZE..2 * abi::GRAIN_SIZE))
                .is_ok()
        );
        table.release(&(0..abi::GRAIN_SIZE), owner(1));
        assert!(table.prepare(&(0..abi::GRAIN_SIZE)).is_ok());
    }
}
