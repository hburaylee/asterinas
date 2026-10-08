// SPDX-License-Identifier: MPL-2.0

//! Execution resources shared by every fixed carrier: image stacks, landing
//! stacks, and registered image page-table roots.
//!
//! These resources are created before the first carrier enters and dropped
//! only after the last carrier detaches. The carrier state and the service
//! implementations borrow them through [`ExecutionResources`].

use alloc::vec::Vec;

#[cfg(ktest)]
use crate::cpu::CpuId;
use crate::{
    arch::mm::tlb_flush_addr_range,
    cpu::CpuSet,
    kernelet::abi::INVALID,
    mm::{
        CachePolicy, FrameAllocOptions, PAGE_SIZE, PageFlags, PageProperty, PrivilegedPageFlags,
        kspace::kvirt_area::KVirtArea,
    },
    sync::{LocalIrqDisabled, SpinLock},
};

const STACK_PAGES: usize = 64;
const STACK_GUARD_PAGES: usize = 2;
pub(super) const STACK_BYTES: usize = STACK_PAGES * PAGE_SIZE;

/// A registered image page-table root and its physical TLB users.
///
/// The active set describes CPUs that either run this root or have committed
/// to installing it with physical IRQs masked. Each activation writes CR3,
/// which flushes non-global translations and observes the latest generation.
pub(super) struct RootRegistration {
    pub(super) paddr: u64,
    pub(super) active: CpuSet,
    pub(super) generation: u64,
    pub(super) seen_generation: Vec<u64>,
}

impl RootRegistration {
    pub(super) fn new(paddr: u64) -> Option<Self> {
        let mut seen_generation = Vec::new();
        seen_generation
            .try_reserve_exact(crate::cpu::num_cpus())
            .ok()?;
        seen_generation.resize(crate::cpu::num_cpus(), 0);
        Some(Self {
            paddr,
            active: CpuSet::new_empty(),
            generation: 0,
            seen_generation,
        })
    }
}

/// Shared Task stacks and page-table registration outlive all fixed carriers.
pub(crate) struct ExecutionResources {
    pub(super) stacks: SpinLock<StackPool, LocalIrqDisabled>,
    // Sorted by physical root address. Service and trap paths locate a root
    // without a scan proportional to the number of image processes.
    pub(super) roots: SpinLock<Vec<RootRegistration>, LocalIrqDisabled>,
    pub(super) landings: Vec<LandingStacks>,
}

impl ExecutionResources {
    pub(crate) fn new(max_tasks: usize, vcpus: usize) -> crate::Result<Self> {
        let mut roots = Vec::new();
        roots
            .try_reserve_exact(max_tasks)
            .map_err(|_| crate::Error::NoMemory)?;
        let mut landings = Vec::new();
        landings
            .try_reserve_exact(vcpus)
            .map_err(|_| crate::Error::NoMemory)?;
        Ok(Self {
            stacks: SpinLock::new(StackPool::new(max_tasks, vcpus)?),
            roots: SpinLock::new(roots),
            landings,
        })
    }

    pub(crate) fn prepare(&mut self) -> crate::Result<usize> {
        let stacks = self.stacks.get_mut();
        self.landings
            .try_reserve_exact(stacks.boot_slots.saturating_sub(self.landings.len()))
            .map_err(|_| crate::Error::NoMemory)?;
        stacks.allocate_boot(0)?;
        for _ in 0..stacks.boot_slots {
            self.landings.push(LandingStacks::new()?);
        }
        Ok(stacks.boot_slots * (STACK_BYTES + LANDING_BYTES * 5))
    }
    #[cfg(ktest)]
    pub(crate) fn boot_stack_base(&self) -> usize {
        self.stacks.lock().slots[0].base()
    }

    #[cfg(ktest)]
    pub(crate) fn register_test_root(&self, root: u64) {
        self.roots.lock().push(RootRegistration::new(root).unwrap());
    }

    #[cfg(ktest)]
    pub(crate) fn test_root_is_active(&self, root: u64, cpu: CpuId) -> bool {
        let roots = self.roots.lock();
        roots
            .binary_search_by_key(&root, |entry| entry.paddr)
            .is_ok_and(|index| roots[index].active.contains(cpu))
    }

    pub(crate) fn counts(&self) -> (u32, u32) {
        (
            self.stacks.lock().slots.len() as u32,
            self.roots.lock().len() as u32,
        )
    }

    /// Reserves the pool slot under its lock, then maps a new stack without
    /// holding the lock or disabling physical interrupts.
    pub(super) fn allocate_stack(&self) -> crate::Result<(u64, bool)> {
        {
            let mut stacks = self.stacks.lock();
            let boot_slots = stacks.boot_slots;
            if let Some(slot) = stacks
                .slots
                .iter_mut()
                .skip(boot_slots)
                .find(|slot| !slot.allocated)
            {
                slot.allocated = true;
                let base = slot.base() as u64;
                let range = slot.area.range();
                drop(stacks);
                tlb_flush_addr_range(&range);
                return Ok((base, false));
            }
            if stacks.slots.len() + stacks.allocating >= stacks.max_tasks + stacks.boot_slots {
                return Err(crate::Error::NoMemory);
            }
            stacks.allocating += 1;
        }

        let slot = StackSlot::new();
        let mut stacks = self.stacks.lock();
        stacks.allocating -= 1;
        let slot = slot?;
        let base = slot.base() as u64;
        // StackPool reserved the complete capacity before any carrier ran.
        stacks.slots.push(slot);
        Ok((base, true))
    }
}
const LANDING_BYTES: usize = 8 * PAGE_SIZE;
const LANDING_STRIDE: usize = LANDING_BYTES + 2 * PAGE_SIZE;

/// Image traps always land here first, regardless of the interrupted RSP.
pub(super) struct LandingStacks {
    pub(super) area: KVirtArea,
}
impl LandingStacks {
    fn new() -> crate::Result<Self> {
        let prop = PageProperty {
            flags: PageFlags::RW,
            cache: CachePolicy::Writeback,
            priv_flags: PrivilegedPageFlags::GLOBAL,
        };
        let area = KVirtArea::map_frames(
            5 * LANDING_STRIDE,
            0,
            core::iter::empty::<crate::mm::Frame<()>>(),
            prop,
        )
        .with_synchronous_reclaim();
        for index in 0..5 {
            let frames: Vec<_> = FrameAllocOptions::new()
                .alloc_segment(LANDING_BYTES / PAGE_SIZE)?
                .collect();
            area.map_additional_frames(
                index * LANDING_STRIDE + PAGE_SIZE,
                frames.into_iter(),
                prop,
            )?;
        }
        tlb_flush_addr_range(&area.range());
        Ok(Self { area })
    }
    pub(super) fn tops(&self) -> [usize; 5] {
        core::array::from_fn(|index| {
            self.area.start() + index * LANDING_STRIDE + PAGE_SIZE + LANDING_BYTES
        })
    }
}

pub(super) struct StackSlot {
    pub(super) area: KVirtArea,
    allocated: bool,
}

impl StackSlot {
    fn new() -> crate::Result<Self> {
        let pages = FrameAllocOptions::new().alloc_segment(STACK_PAGES)?;
        let prop = PageProperty {
            flags: PageFlags::RW,
            cache: CachePolicy::Writeback,
            priv_flags: PrivilegedPageFlags::empty(),
        };
        let area = KVirtArea::map_frames(
            STACK_BYTES + 2 * STACK_GUARD_PAGES * PAGE_SIZE,
            STACK_GUARD_PAGES * PAGE_SIZE,
            pages.into_iter(),
            prop,
        )
        .with_synchronous_reclaim();
        tlb_flush_addr_range(&area.range());
        Ok(Self {
            area,
            allocated: true,
        })
    }

    pub(super) fn base(&self) -> usize {
        self.area.start() + STACK_GUARD_PAGES * PAGE_SIZE
    }

    pub(super) fn contains(&self, rsp: usize) -> bool {
        (self.base()..self.base() + STACK_BYTES).contains(&rsp)
    }

    fn contains_range(&self, start: usize, end: usize) -> bool {
        self.allocated && start >= self.base() && end <= self.base() + STACK_BYTES
    }
}

pub(super) struct StackPool {
    pub(super) slots: Vec<StackSlot>,
    max_tasks: usize,
    boot_slots: usize,
    allocating: usize,
}

impl StackPool {
    fn new(max_tasks: usize, boot_slots: usize) -> crate::Result<Self> {
        let capacity = max_tasks
            .checked_add(boot_slots)
            .ok_or(crate::Error::Overflow)?;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity)
            .map_err(|_| crate::Error::NoMemory)?;
        Ok(Self {
            slots,
            max_tasks,
            boot_slots,
            allocating: 0,
        })
    }

    fn allocate_boot(&mut self, vcpu: usize) -> crate::Result<u64> {
        while self.slots.len() < self.boot_slots {
            self.allocate_slot()?;
        }
        Ok(self.slots[vcpu].base() as u64)
    }

    fn allocate_slot(&mut self) -> crate::Result<u64> {
        let slot = StackSlot::new()?;
        let base = slot.base() as u64;
        self.slots.push(slot);
        Ok(base)
    }

    pub(super) fn free(&mut self, base: usize, saved_rsp: usize) -> i64 {
        let Some(slot) = self
            .slots
            .iter_mut()
            .skip(self.boot_slots)
            .find(|slot| slot.base() == base)
        else {
            return -INVALID;
        };
        if !slot.allocated || slot.contains(saved_rsp) {
            return -INVALID;
        }
        slot.allocated = false;
        0
    }

    pub(super) fn contains_range(&self, start: usize, end: usize) -> bool {
        self.slots
            .iter()
            .any(|slot| slot.contains_range(start, end))
    }

    pub(super) fn contains_current_range(&self, start: usize, end: usize, rsp: usize) -> bool {
        self.slots
            .iter()
            .any(|slot| slot.contains(rsp) && slot.contains_range(start, end))
    }
}
