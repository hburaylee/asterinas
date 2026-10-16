// SPDX-License-Identifier: MPL-2.0

//! Generation-checked instance identities. Only creation and retirement take
//! the allocator lock; service, trap and hook lookups only read atomic cells.

use core::{
    ptr,
    sync::atomic::{AtomicBool, AtomicPtr, AtomicU16, AtomicU32, Ordering},
};

use super::RunControl;
use crate::{
    Error,
    kernelet::abi::CpuSlot,
    sync::{LocalIrqDisabled, SpinLock},
};

const NONE: u16 = u16::MAX;
const CAPACITY: usize = NONE as usize;

struct Slot {
    control: AtomicPtr<RunControl>,
    generation: AtomicU32,
    next_free: AtomicU16,
}

impl Slot {
    const fn new() -> Self {
        Self {
            control: AtomicPtr::new(ptr::null_mut()),
            generation: AtomicU32::new(0),
            // Unused until retirement links this slot into the free list.
            next_free: AtomicU16::new(0),
        }
    }
}

struct Allocator {
    next: usize,
    free: u16,
}

struct Registry {
    slots: &'static [Slot],
    allocator: SpinLock<Allocator, LocalIrqDisabled>,
}

impl Registry {
    const fn new(slots: &'static [Slot]) -> Self {
        assert!(slots.len() <= CAPACITY);
        Self {
            slots,
            allocator: SpinLock::new(Allocator {
                next: 0,
                free: NONE,
            }),
        }
    }

    fn reserve(&'static self) -> crate::Result<Registration> {
        let mut allocator = self.allocator.lock();
        let index = if allocator.free != NONE {
            let index = allocator.free;
            allocator.free = self.slots[index as usize].next_free.load(Ordering::Relaxed);
            index
        } else {
            if allocator.next == self.slots.len() {
                return Err(Error::NoMemory);
            }
            let index = allocator.next as u16;
            allocator.next += 1;
            index
        };
        let slot = &self.slots[index as usize];
        // A slot at the last generation is never returned to the free list.
        let generation = slot
            .generation
            .load(Ordering::Relaxed)
            .checked_add(1)
            .unwrap();
        debug_assert!(slot.control.load(Ordering::Relaxed).is_null());
        slot.generation.store(generation, Ordering::Release);
        Ok(Registration {
            registry: self,
            index,
            generation,
            live: AtomicBool::new(true),
        })
    }

    fn lookup<'a>(&self, identity: CpuSlot, owner: &'a RunControl) -> Option<&'a RunControl> {
        let slot = self.slots.get(identity.kernelet as usize)?;
        if slot.generation.load(Ordering::Acquire) != identity.generation
            || slot.control.load(Ordering::Acquire) != ptr::from_ref(owner).cast_mut()
            || slot.generation.load(Ordering::Acquire) != identity.generation
        {
            return None;
        }
        // The caller already pins this owner through its current native Task.
        // Never dereference a table pointer: retirement can clear and reuse a
        // slot concurrently. Rechecking the generation rejects an old first
        // sample combined with a newly published pointer. Acquiring that new
        // pointer publishes the preceding generation increment, so the second
        // sample cannot still observe the old generation. This owner's live
        // borrow also prevents its address from being reused during lookup.
        Some(owner)
    }
}

static SLOTS: [Slot; CAPACITY] = [const { Slot::new() }; CAPACITY];
static REGISTRY: Registry = Registry::new(&SLOTS);

/// Retires its index on every construction-error path and at final teardown.
pub(in crate::kernelet) struct Registration {
    registry: &'static Registry,
    index: u16,
    generation: u32,
    live: AtomicBool,
}

impl Registration {
    pub(in crate::kernelet) fn new() -> crate::Result<Self> {
        REGISTRY.reserve()
    }

    pub(in crate::kernelet) fn owner(&self) -> crate::kernelet::owner::KerneletId {
        crate::kernelet::owner::KerneletId::from_slot(self.cpu_slot(0))
    }

    pub(super) fn publish(&self, control: &RunControl) {
        assert!(self.live.load(Ordering::Relaxed));
        let slot = &self.registry.slots[self.index as usize];
        assert!(
            slot.control
                .compare_exchange(
                    ptr::null_mut(),
                    ptr::from_ref(control).cast_mut(),
                    Ordering::Release,
                    Ordering::Relaxed,
                )
                .is_ok()
        );
    }

    pub(super) fn cpu_slot(&self, vcpu: u16) -> CpuSlot {
        CpuSlot {
            kernelet: self.index,
            vcpu,
            generation: self.generation,
            _reserved: 0,
        }
    }

    /// Withdraws a dying control without releasing its outstanding grant's slot.
    pub(super) fn unpublish(&self, control: &RunControl) {
        let slot = &self.registry.slots[self.index as usize];
        // Explicit destroy may already have retired and recycled this slot.
        // A late control drop must leave a different owner's address intact.
        let _ = slot.control.compare_exchange(
            ptr::from_ref(control).cast_mut(),
            ptr::null_mut(),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    pub(super) fn retire(&self) {
        if !self.live.swap(false, Ordering::AcqRel) {
            return;
        }
        let slot = &self.registry.slots[self.index as usize];
        // Clear the owner before allowing reserve to increment the generation
        // and publish another owner. Lookup needs no allocator lock or Arc.
        slot.control.store(ptr::null_mut(), Ordering::Release);
        if self.generation != u32::MAX {
            let mut allocator = self.registry.allocator.lock();
            slot.next_free.store(allocator.free, Ordering::Relaxed);
            allocator.free = self.index;
        }
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.retire();
    }
}

pub(super) fn lookup(identity: CpuSlot, owner: &RunControl) -> Option<&RunControl> {
    REGISTRY.lookup(identity, owner)
}

#[cfg(ktest)]
mod test {
    use alloc::sync::Arc;

    use super::*;
    use crate::{
        cpu::CpuId,
        kernelet::{account::Account, control::KerneletPolicy, host_run},
        prelude::*,
        sync::WaitQueue,
    };

    fn owner() -> Arc<RunControl> {
        RunControl::new(
            Registration::new().unwrap(),
            0,
            Account::new(Arc::new(WaitQueue::new()), KerneletPolicy::default()),
            alloc::vec![CpuId::bsp()],
            host_run::ExecutionResources::new(1, 1).unwrap(),
        )
    }

    #[ktest]
    fn recycled_instance_slot_rejects_stale_generation_and_other_owner() {
        static ENTRIES: [Slot; 1] = [Slot::new()];
        static TABLE: Registry = Registry::new(&ENTRIES);
        let old_owner = owner();
        let new_owner = owner();
        let old = TABLE.reserve().unwrap();
        old.publish(&old_owner);
        let stale = old.cpu_slot(0);
        assert!(TABLE.lookup(stale, &old_owner).is_some());
        assert!(TABLE.lookup(stale, &new_owner).is_none());
        old.retire();
        assert!(TABLE.lookup(stale, &old_owner).is_none());
        let new = TABLE.reserve().unwrap();
        new.publish(&new_owner);
        let current = new.cpu_slot(0);
        assert_eq!(current.kernelet, stale.kernelet);
        assert_eq!(current.generation, stale.generation + 1);
        assert!(TABLE.lookup(stale, &new_owner).is_none());
        assert!(TABLE.lookup(current, &new_owner).is_some());
        old.unpublish(&old_owner);
        assert!(TABLE.lookup(current, &new_owner).is_some());
        assert!(TABLE.lookup(CpuSlot::NONE, &new_owner).is_none());
    }

    #[ktest]
    fn control_drop_withdraws_address_before_deferred_slot_retirement() {
        let control = owner();
        let held = control.identity.clone();
        let old = held.cpu_slot(0);
        let slot = &REGISTRY.slots[old.kernelet as usize];
        assert!(!slot.control.load(Ordering::Acquire).is_null());
        drop(control);
        assert!(slot.control.load(Ordering::Acquire).is_null());
        let during = Registration::new().unwrap();
        assert_ne!(during.cpu_slot(0).kernelet, old.kernelet);
        drop(held);
        let next = Registration::new().unwrap();
        assert_eq!(next.cpu_slot(0).kernelet, old.kernelet);
        assert_eq!(next.cpu_slot(0).generation, old.generation + 1);
    }

    #[ktest]
    fn unpublished_reservation_recycles_and_last_generation_is_retired() {
        static ENTRIES: [Slot; 1] = [Slot::new()];
        static TABLE: Registry = Registry::new(&ENTRIES);
        let reservation = TABLE.reserve().unwrap();
        let old = reservation.cpu_slot(0);
        drop(reservation);
        let next = TABLE.reserve().unwrap();
        assert_eq!(next.cpu_slot(0).generation, old.generation + 1);
        // This isolated registry has no concurrent users. Exercise the actual
        // last-generation allocation/retirement path without billions of runs.
        drop(next);
        ENTRIES[0].generation.store(u32::MAX - 1, Ordering::Relaxed);
        let last = TABLE.reserve().unwrap();
        assert_eq!(last.cpu_slot(0).generation, u32::MAX);
        drop(last);
        assert!(matches!(TABLE.reserve(), Err(Error::NoMemory)));
    }
}
