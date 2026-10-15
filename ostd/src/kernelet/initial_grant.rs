// SPDX-License-Identifier: MPL-2.0

//! Imports the bootstrap grant before allocating its complete boot memory map.

use alloc::vec::Vec;

use super::abi::{GRAIN_SIZE, RunDesc};
use crate::boot::memory_region::{MemoryRegion, MemoryRegionType};

pub(super) fn import(
    runs: &[RunDesc],
    ceiling: usize,
    mut add_run_fn: impl FnMut(usize, usize),
    publish_count_fn: impl FnOnce(u32),
) -> Vec<MemoryRegion> {
    for run in runs {
        let paddr = run.paddr as usize;
        let bytes = run.grains as usize * GRAIN_SIZE;
        assert!(paddr.is_multiple_of(GRAIN_SIZE) && bytes != 0);
        assert!(paddr.checked_add(bytes).is_some_and(|end| end <= ceiling));
        add_run_fn(paddr, bytes);
    }
    // Import before allocating from the heap. Publishing the count also keeps
    // a refill during the Vec allocation from importing any initial run twice.
    publish_count_fn(runs.len() as u32);
    runs.iter()
        .map(|run| {
            MemoryRegion::new(
                run.paddr as usize,
                run.grains as usize * GRAIN_SIZE,
                MemoryRegionType::Usable,
            )
        })
        .collect()
}

#[cfg(ktest)]
mod test {
    use core::cell::Cell;

    use super::*;
    use crate::prelude::ktest;

    #[ktest]
    fn bootstrap_imports_more_than_bootloader_region_capacity() {
        const RUNS: usize = 513;
        let runs: Vec<_> = (0..RUNS)
            .map(|index| RunDesc {
                paddr: ((index + 1) * GRAIN_SIZE) as u64,
                grains: 1,
                reserved: 0,
            })
            .collect();
        let imported = Cell::new(0);
        let published = Cell::new(false);
        let regions = import(
            &runs,
            (RUNS + 1) * GRAIN_SIZE,
            |paddr, bytes| {
                assert!(!published.get());
                assert_eq!(paddr, (imported.get() + 1) * GRAIN_SIZE);
                assert_eq!(bytes, GRAIN_SIZE);
                imported.set(imported.get() + 1);
            },
            |count| {
                assert_eq!(imported.get(), RUNS);
                assert_eq!(count as usize, RUNS);
                published.set(true);
            },
        );
        assert!(published.get());
        assert_eq!(regions.len(), RUNS);
        assert_eq!(
            regions.iter().map(MemoryRegion::len).sum::<usize>(),
            RUNS * GRAIN_SIZE
        );
        for (run, region) in runs.iter().zip(&regions) {
            assert_eq!(region.base(), run.paddr as usize);
            assert_eq!(region.typ(), MemoryRegionType::Usable);
        }
    }
}
