// SPDX-License-Identifier: MPL-2.0

//! Execution resources shared by every fixed carrier: Task stacks and
//! registered image page-table roots.
//!
//! These resources are created before the first carrier enters and dropped
//! only after the last carrier detaches. The carrier state and the service
//! implementations borrow them through [`ExecutionResources`].

use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

#[cfg(ktest)]
use crate::cpu::CpuId;
use crate::{
    arch::mm::tlb_flush_addr_range,
    kernelet::abi::{INVALID, KSTACK_MAPPING_BYTES, KSTACK_USABLE_BYTES, STATE, StackTickRecord},
    mm::{
        CachePolicy, FrameAllocOptions, PAGE_SIZE, PageFlags, PageProperty, PrivilegedPageFlags,
        VmSpace, kspace::kvirt_area::KVirtArea, vm_space::RegisteredPageTable,
    },
    sync::{LocalIrqDisabled, SpinLock},
};

const STACK_PAGES: usize = 64;

#[cfg(not(ktest))]
use crate::arch::mm::tlb_flush_all_excluding_global as flush_stack_mapping;

#[cfg(ktest)]
static STACK_MAPPING_FLUSHES: AtomicU64 = AtomicU64::new(0);

#[cfg(ktest)]
fn flush_stack_mapping() {
    crate::arch::mm::tlb_flush_all_excluding_global();
    STACK_MAPPING_FLUSHES.fetch_add(1, Ordering::Relaxed);
}
pub(super) const STACK_BYTES: usize = STACK_PAGES * PAGE_SIZE;
pub(super) const STACK_STRIDE: usize = 2 * STACK_BYTES;

const _: () = assert!(STACK_STRIDE.is_power_of_two());
const _: () = assert!(STACK_BYTES == KSTACK_MAPPING_BYTES);

#[derive(Debug, Eq, PartialEq)]
pub(super) enum TickSampleError {
    InvalidStack,
    Overflow,
}

fn allocate_stack_frames() -> crate::Result<alloc::vec::IntoIter<crate::mm::Frame<()>>> {
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(STACK_PAGES)
        .map_err(|_| crate::Error::NoMemory)?;
    frames.extend(FrameAllocOptions::new().alloc_segment(STACK_PAGES)?);
    Ok(frames.into_iter())
}

/// A registered image page-table root and its physical TLB users.
///
/// The active set describes CPUs that either run this root or have committed
/// to installing it with physical IRQs masked. Each activation writes CR3,
/// which flushes non-global translations and observes the latest generation.
pub(super) struct RootRegistration {
    pub(super) paddr: u64,
    pub(super) table: Arc<RegisteredPageTable>,
}

impl RootRegistration {
    pub(super) fn new(paddr: u64) -> Option<Self> {
        Some(Self {
            paddr,
            table: RegisteredPageTable::new(paddr as usize)?,
        })
    }
}

impl Drop for RootRegistration {
    fn drop(&mut self) {
        self.table.invalidate();
    }
}

/// Shared Task stacks and page-table registration outlive all fixed carriers.
pub(crate) struct ExecutionResources {
    pub(super) stacks: SpinLock<StackPool, LocalIrqDisabled>,
    // Sorted by physical root address. Service and trap paths locate a root
    // without a scan proportional to the number of image processes.
    pub(super) roots: SpinLock<Vec<RootRegistration>, LocalIrqDisabled>,
    carrier_spaces: Vec<Arc<VmSpace>>,
}

impl ExecutionResources {
    pub(crate) fn reservation_bytes(max_tasks: u32, vcpus: usize) -> crate::Result<usize> {
        if max_tasks == 0
            || max_tasks > super::super::control::MAX_TASKS
            || vcpus == 0
            || vcpus > super::super::abi::MAX_VCPUS
        {
            return Err(crate::Error::InvalidArgs);
        }
        // Ordinary and bootstrap stacks can all remain mapped at their
        // high-water mark. Boot slots are additional to max_tasks; native
        // carrier stacks exist only for configured vCPUs.
        let per_task = STACK_BYTES
            + 4 * PAGE_SIZE
            + size_of::<StackSlot>()
            + size_of::<RootRegistration>()
            + size_of::<RegisteredPageTable>()
            + 4 * size_of::<usize>();
        let per_carrier = crate::task::native_stack_reservation_bytes()
            + size_of::<VmSpace>()
            + 4 * PAGE_SIZE
            + 2 * size_of::<usize>();
        (max_tasks as usize)
            .checked_add(vcpus)
            .and_then(|slots| slots.checked_mul(per_task))
            .and_then(|bytes| bytes.checked_add(vcpus.checked_mul(per_carrier)?))
            .ok_or(crate::Error::Overflow)
    }

    pub(crate) fn new(max_tasks: usize, vcpus: usize) -> crate::Result<Self> {
        Self::reservation_bytes(
            max_tasks.try_into().map_err(|_| crate::Error::Overflow)?,
            vcpus,
        )?;
        let mut roots = Vec::new();
        roots
            .try_reserve_exact(max_tasks)
            .map_err(|_| crate::Error::NoMemory)?;
        let mut carrier_spaces = Vec::new();
        carrier_spaces
            .try_reserve_exact(vcpus)
            .map_err(|_| crate::Error::NoMemory)?;
        carrier_spaces.extend((0..vcpus).map(|_| Arc::new(VmSpace::new_activation_only())));
        Ok(Self {
            stacks: SpinLock::new(StackPool::new(max_tasks, vcpus)?),
            roots: SpinLock::new(roots),
            carrier_spaces,
        })
    }

    pub(crate) fn carrier_vm_space(&self, vcpu: u16) -> crate::Result<Arc<VmSpace>> {
        self.carrier_spaces
            .get(vcpu as usize)
            .cloned()
            .ok_or(crate::Error::InvalidArgs)
    }

    pub(crate) fn prepare(&mut self) -> crate::Result<usize> {
        super::hook_stack::prepare()?;
        let stacks = self.stacks.get_mut();
        stacks.allocate_boot(0)?;
        Ok(stacks.boot_slots * STACK_BYTES)
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
            .is_ok_and(|index| roots[index].table.is_active_on(cpu))
    }

    pub(crate) fn counts(&self) -> (u32, u32) {
        (
            self.stacks.lock().mapped_slots as u32,
            self.roots.lock().len() as u32,
        )
    }

    /// Returns the aligned pool bounds and the stable live-bitmap address.
    /// The resources pin the arena and bitmap until every carrier detaches.
    pub(super) fn stack_pool_layout(&self) -> (usize, usize, usize) {
        let stacks = self.stacks.lock();
        (
            stacks.start,
            stacks.end,
            stacks.live_bitmap.as_ptr() as usize,
        )
    }

    /// Returns an authenticated stack slot and releases its allocation charge.
    ///
    /// Boot slots were charged by create, ordinary slots by kstack_alloc.
    /// Rejected and repeated releases leave both the pool and charge unchanged.
    pub(super) fn release_stack(
        &self,
        base: usize,
        saved_rsp: usize,
        vcpu: usize,
        stacks_allocated: &AtomicU32,
    ) -> Result<(), i64> {
        self.stacks.lock().free(base, saved_rsp, vcpu)?;
        stacks_allocated.fetch_sub(1, Ordering::Relaxed);
        Ok(())
    }

    /// Reserves the pool slot under its lock, then maps a new stack without
    /// holding the lock or disabling physical interrupts.
    pub(super) fn allocate_stack(&self) -> crate::Result<(u64, bool)> {
        let (index, base, mapped, arena) = {
            let mut stacks = self.stacks.lock();
            if stacks.active_tasks >= stacks.max_tasks {
                return Err(crate::Error::NoMemory);
            }
            let Some(index) = stacks.slots.iter().enumerate().find_map(|(index, slot)| {
                (!slot.boot_reserved && !slot.allocated && !slot.allocating).then_some(index)
            }) else {
                return Err(crate::Error::NoMemory);
            };
            // Include in-flight allocations before releasing the lock, so
            // concurrent mapping cannot exceed the configured Task limit.
            stacks.active_tasks += 1;
            let slot = &mut stacks.slots[index];
            slot.allocating = true;
            (index, slot.base(), slot.mapped, stacks.arena.clone())
        };

        // Mapping and remote acknowledgements must not hold the pool lock.
        // The live bit stays clear until every CPU can use this mapping.
        let result: crate::Result<()> = (|| {
            if !mapped {
                arena.map_additional_frames(
                    base - arena.start(),
                    allocate_stack_frames()?,
                    STACK_PROP,
                )?;
                crate::smp::inter_processor_call(
                    &crate::cpu::CpuSet::new_full(),
                    flush_stack_mapping,
                )
                .wait();
            }
            Ok(())
        })();
        let mut stacks = self.stacks.lock();
        stacks.slots[index].allocating = false;
        if let Err(error) = result {
            stacks.active_tasks -= 1;
            return Err(error);
        }
        stacks.slots[index].mapped = true;
        // The slot has no live execution owner until publish_live below.
        // Initialize both new and reused storage before the Guest can run.
        // SAFETY: Mapping completed, but this slot has not been published live.
        unsafe { stacks.slots[index].initialize_ticks() };
        stacks.slots[index].allocated = true;
        if !mapped {
            stacks.mapped_slots += 1;
        }
        stacks.publish_live(index);
        Ok((base as u64, !mapped))
    }
}
pub(super) struct StackSlot {
    base: usize,
    mapped: bool,
    allocated: bool,
    allocating: bool,
    // A carrier may retire its bootstrap slot once after its first switch.
    // Thereafter the slot can serve ordinary, possibly migrating Tasks.
    boot_reserved: bool,
}

/// Distinguishes initial bootstrap storage from a counted Task allocation.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum StackRelease {
    Boot,
    Task,
}

impl StackSlot {
    pub(super) fn base(&self) -> usize {
        self.base
    }

    pub(super) fn contains(&self, rsp: usize) -> bool {
        (self.base()..self.base() + STACK_BYTES).contains(&rsp)
    }

    fn contains_range(&self, start: usize, end: usize) -> bool {
        self.allocated
            && start <= end
            && start >= self.base()
            && end <= self.base() + KSTACK_USABLE_BYTES
    }

    fn ticks(&self) -> &StackTickRecord {
        // SAFETY: A mapped pool slot retains these frames until every carrier
        // detaches. Initialization precedes its first live publication.
        unsafe { &*((self.base() + KSTACK_USABLE_BYTES) as *const StackTickRecord) }
    }

    /// # Safety
    /// The mapped slot must have no live producer or Guest execution owner.
    unsafe fn initialize_ticks(&self) {
        unsafe {
            core::ptr::write(
                (self.base() + KSTACK_USABLE_BYTES) as *mut StackTickRecord,
                StackTickRecord::default(),
            )
        };
    }
}

const STACK_PROP: PageProperty = PageProperty {
    flags: PageFlags::RW,
    cache: CachePolicy::Writeback,
    priv_flags: PrivilegedPageFlags::empty(),
};

pub(super) struct StackPool {
    arena: Arc<KVirtArea>,
    start: usize,
    end: usize,
    // Neither vector grows after creation. Assembly may read these atomic
    // words through the address copied into each pinned carrier context.
    live_bitmap: Vec<AtomicU64>,
    pub(super) slots: Vec<StackSlot>,
    boot_slots: usize,
    mapped_slots: usize,
    max_tasks: usize,
    active_tasks: usize,
}

impl StackPool {
    fn new(max_tasks: usize, boot_slots: usize) -> crate::Result<Self> {
        let capacity = max_tasks
            .checked_add(boot_slots)
            .ok_or(crate::Error::Overflow)?;
        let pool_bytes = capacity
            .checked_mul(STACK_STRIDE)
            .ok_or(crate::Error::Overflow)?;
        let arena_bytes = pool_bytes
            .checked_add(STACK_STRIDE)
            .ok_or(crate::Error::Overflow)?;
        if capacity == 0 || arena_bytes > crate::mm::kspace::VMALLOC_VADDR_RANGE.len() {
            return Err(crate::Error::NoMemory);
        }
        // Reserve the address space before the slot metadata so exhaustion
        // returns NoMemory without first allocating a potentially large Vec.
        let arena = Arc::new(KVirtArea::try_reserve(arena_bytes)?.with_synchronous_reclaim());
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity)
            .map_err(|_| crate::Error::NoMemory)?;
        let mut live_bitmap = Vec::new();
        live_bitmap
            .try_reserve_exact(capacity.div_ceil(64))
            .map_err(|_| crate::Error::NoMemory)?;
        live_bitmap.resize_with(capacity.div_ceil(64), || AtomicU64::new(0));
        // An extra stride leaves room to align the interior without mapping
        // unused stack frames.
        let start = (arena.start() + STACK_STRIDE - 1) & !(STACK_STRIDE - 1);
        let end = start + pool_bytes;
        debug_assert!(end <= arena.end());
        slots.extend((0..capacity).map(|index| StackSlot {
            base: start + index * STACK_STRIDE + STACK_BYTES,
            mapped: false,
            allocated: false,
            allocating: false,
            boot_reserved: index < boot_slots,
        }));
        Ok(Self {
            arena,
            start,
            end,
            live_bitmap,
            slots,
            boot_slots,
            mapped_slots: 0,
            max_tasks,
            active_tasks: 0,
        })
    }

    fn allocate_boot(&mut self, vcpu: usize) -> crate::Result<u64> {
        for index in 0..self.boot_slots {
            if self.slots[index].mapped {
                continue;
            }
            let base = self.slots[index].base();
            self.arena.map_additional_frames(
                base - self.arena.start(),
                allocate_stack_frames()?,
                STACK_PROP,
            )?;
            // No carrier has entered this unpublished instance yet. Reused
            // arena addresses were synchronously retired by their old owner.
            tlb_flush_addr_range(&(base..base + STACK_BYTES));
            self.slots[index].mapped = true;
            // SAFETY: No carrier has entered this unpublished instance.
            unsafe { self.slots[index].initialize_ticks() };
            self.slots[index].allocated = true;
            self.mapped_slots += 1;
            self.publish_live(index);
        }
        Ok(self.slots[vcpu].base() as u64)
    }

    fn publish_live(&self, index: usize) {
        self.live_bitmap[index / 64].fetch_or(1 << (index % 64), Ordering::Release);
    }

    fn slot_index(&self, address: usize) -> Option<usize> {
        (self.start..self.end)
            .contains(&address)
            .then(|| (address - self.start) / STACK_STRIDE)
    }

    pub(super) fn free(
        &mut self,
        base: usize,
        saved_rsp: usize,
        vcpu: usize,
    ) -> Result<StackRelease, i64> {
        let Some(index) = self.slot_index(base) else {
            return Err(-INVALID);
        };
        let slot = &mut self.slots[index];
        if slot.base() != base
            || !slot.allocated
            || slot.contains(saved_rsp)
            || (slot.boot_reserved && index != vcpu)
        {
            return Err(-INVALID);
        }
        // The Guest must settle the old owner's samples before this slot can
        // acquire another identity. Reject rather than erase deferred credit.
        if !slot.ticks().is_empty() {
            return Err(-STATE);
        }
        let released = if slot.boot_reserved {
            slot.boot_reserved = false;
            StackRelease::Boot
        } else {
            self.active_tasks -= 1;
            StackRelease::Task
        };
        slot.allocated = false;
        self.live_bitmap[index / 64].fetch_and(!(1 << (index % 64)), Ordering::Release);
        Ok(released)
    }

    pub(super) fn contains_range(&self, start: usize, end: usize) -> bool {
        self.slot_index(start)
            .is_some_and(|index| self.slots[index].contains_range(start, end))
    }

    pub(super) fn contains_current_range(&self, start: usize, end: usize, rsp: usize) -> bool {
        self.slot_index(rsp).is_some_and(|index| {
            let slot = &self.slots[index];
            slot.contains(rsp) && slot.contains_range(start, end)
        })
    }

    /// Samples only a live Host-owned slot, using the interrupted kernel RSP.
    /// Neither CURRENT_TASK nor a Guest-published stack limit identifies it.
    pub(super) fn record_tick(&self, rsp: usize, user: bool) -> Result<(), TickSampleError> {
        let Some(index) = self.slot_index(rsp) else {
            return Err(TickSampleError::InvalidStack);
        };
        let slot = &self.slots[index];
        // An empty stack may point exactly at its usable end: the next push
        // writes below it. No frame may use the sample record above that end.
        if !slot.allocated || !slot.contains(rsp) || rsp > slot.base() + KSTACK_USABLE_BYTES {
            return Err(TickSampleError::InvalidStack);
        }
        if slot.ticks().record(user) {
            Ok(())
        } else {
            Err(TickSampleError::Overflow)
        }
    }

    #[cfg(ktest)]
    fn is_guard_address(&self, address: usize) -> bool {
        self.slot_index(address).is_some_and(|index| {
            let slot = &self.slots[index];
            slot.mapped && address < slot.base()
        })
    }
}

#[cfg(ktest)]
mod stack_pool_tests {
    use super::*;
    use crate::prelude::*;

    #[ktest]
    fn reservation_covers_boot_stacks_in_addition_to_ordinary_tasks() {
        let one = ExecutionResources::reservation_bytes(32, 1).unwrap();
        let all = ExecutionResources::reservation_bytes(32, 32).unwrap();
        assert!(all - one >= 31 * (STACK_BYTES + crate::task::native_stack_reservation_bytes()));
    }

    #[ktest]
    fn stack_creation_reports_virtual_address_exhaustion() {
        // Keep the slot metadata small while exhausting only unmapped virtual
        // reservations. Stack creation must return an error rather than panic.
        let mut reservations = Vec::new();
        let mut bytes = crate::mm::kspace::VMALLOC_VADDR_RANGE.len() / 2;
        while bytes >= 64 * STACK_STRIDE {
            while let Ok(area) = KVirtArea::try_reserve(bytes) {
                reservations.push(area.with_synchronous_reclaim());
            }
            bytes /= 2;
        }
        assert!(matches!(StackPool::new(64, 1), Err(crate::Error::NoMemory)));

        drop(reservations);
        assert!(StackPool::new(64, 1).is_ok());
    }

    #[ktest]
    fn physical_ticks_follow_stack_rsp_and_settle_before_reuse() {
        let mut resources = ExecutionResources::new(2, 1).unwrap();
        resources.prepare().unwrap();
        let (first, _) = resources.allocate_stack().unwrap();
        let (second, _) = resources.allocate_stack().unwrap();
        let first = first as usize;
        let second = second as usize;
        let charged = AtomicU32::new(3);
        {
            let stacks = resources.stacks.lock();
            // Publishing a different Guest current Task cannot affect these
            // samples: only the physical/saved kernel RSP selects the slot.
            stacks.record_tick(first + 128, true).unwrap();
            stacks.record_tick(first + 64, false).unwrap();
            // An initial/empty stack's next push is below this valid end.
            stacks
                .record_tick(first + KSTACK_USABLE_BYTES, false)
                .unwrap();
            stacks.record_tick(second + 64, false).unwrap();
            assert_eq!(
                stacks.record_tick(first + KSTACK_USABLE_BYTES + 1, true),
                Err(TickSampleError::InvalidStack)
            );
            assert_eq!(
                stacks.record_tick(first - 8, true),
                Err(TickSampleError::InvalidStack)
            );
        }
        assert_eq!(
            resources.release_stack(first, second + 64, 0, &charged),
            Err(-STATE)
        );
        assert_eq!(charged.load(Ordering::Relaxed), 3);
        {
            let stacks = resources.stacks.lock();
            assert_eq!(stacks.active_tasks, 2);
            let first_slot = &stacks.slots[stacks.slot_index(first).unwrap()];
            let second_slot = &stacks.slots[stacks.slot_index(second).unwrap()];
            assert_eq!(first_slot.ticks().take(), (1, 2));
            assert_eq!(second_slot.ticks().take(), (0, 1));
            assert_eq!(first_slot.ticks().take(), (0, 0));
        }
        resources
            .release_stack(first, second + 64, 0, &charged)
            .unwrap();
        assert_eq!(charged.load(Ordering::Relaxed), 2);
        assert_eq!(
            resources.stacks.lock().record_tick(first + 64, true),
            Err(TickSampleError::InvalidStack)
        );
        let (reused, mapped) = resources.allocate_stack().unwrap();
        assert_eq!(reused as usize, first);
        assert!(!mapped);
        let stacks = resources.stacks.lock();
        let reused = &stacks.slots[stacks.slot_index(first).unwrap()];
        assert_eq!(reused.ticks().take(), (0, 0));
        stacks.record_tick(first + 64, true).unwrap();
        assert_eq!(reused.ticks().take(), (1, 0));
    }

    #[ktest]
    fn aligned_stack_pool_maps_on_demand_and_retains_freed_mappings() {
        let mut resources = ExecutionResources::new(2, 1).unwrap();
        resources.prepare().unwrap();
        let layout = resources.stack_pool_layout();
        let (start, end, bitmap) = layout;
        assert!(start.is_multiple_of(STACK_STRIDE));
        assert_eq!(end - start, 3 * STACK_STRIDE);
        assert_eq!(resources.counts(), (1, 0));
        let boot = resources.boot_stack_base();
        assert_eq!(boot, start + STACK_BYTES);
        // SAFETY: The fixed bitmap belongs to these resources and remains
        // allocated until this test drops them after every access below.
        let live = unsafe { &*(bitmap as *const AtomicU64) };
        assert_eq!(live.load(Ordering::Acquire), 1);
        {
            let guard = crate::irq::disable_local();
            let stacks = resources.stacks.lock();
            assert!(stacks.arena.query(&guard, boot).is_some());
            assert!(stacks.arena.query(&guard, boot - PAGE_SIZE).is_none());
            assert!(
                stacks
                    .arena
                    .query(&guard, start + STACK_STRIDE + STACK_BYTES)
                    .is_none()
            );
            assert!(stacks.is_guard_address(boot - PAGE_SIZE));
            assert!(!stacks.is_guard_address(boot));
        }

        let before = STACK_MAPPING_FLUSHES.load(Ordering::Relaxed);
        let (first, new_first) = resources.allocate_stack().unwrap();
        let (second, new_second) = resources.allocate_stack().unwrap();
        assert_eq!(
            STACK_MAPPING_FLUSHES.load(Ordering::Relaxed) - before,
            2 * crate::cpu::num_cpus() as u64
        );
        assert!(new_first && new_second);
        assert_eq!(first as usize, start + STACK_STRIDE + STACK_BYTES);
        assert_eq!(second as usize, start + 2 * STACK_STRIDE + STACK_BYTES);
        assert_eq!(resources.counts(), (3, 0));
        assert_eq!(live.load(Ordering::Acquire), 7);
        assert!(matches!(
            resources.allocate_stack(),
            Err(crate::Error::NoMemory)
        ));
        {
            let mut stacks = resources.stacks.lock();
            assert!(stacks.contains_current_range(
                first as usize + 16,
                first as usize + KSTACK_USABLE_BYTES,
                first as usize + 8,
            ));
            assert!(!stacks.contains_current_range(
                second as usize + 16,
                second as usize + 24,
                first as usize + 8,
            ));
            assert_eq!(stacks.free(boot, first as usize, 1), Err(-INVALID));
            assert_eq!(stacks.free(first as usize + 8, boot, 0), Err(-INVALID));
            assert_eq!(
                stacks.free(first as usize, first as usize + 8, 0),
                Err(-INVALID)
            );
            assert_eq!(stacks.free(first as usize, boot, 0), Ok(StackRelease::Task));
            assert_eq!(stacks.free(first as usize, boot, 0), Err(-INVALID));
            assert!(!stacks.contains_range(first as usize, first as usize + 8));
        }
        assert_eq!(live.load(Ordering::Acquire), 5);
        {
            let guard = crate::irq::disable_local();
            let stacks = resources.stacks.lock();
            assert!(stacks.arena.query(&guard, first as usize).is_some());
        }
        let before_reuse = STACK_MAPPING_FLUSHES.load(Ordering::Relaxed);
        let (reused, new_mapping) = resources.allocate_stack().unwrap();
        assert_eq!(STACK_MAPPING_FLUSHES.load(Ordering::Relaxed), before_reuse);
        assert_eq!(reused, first);
        assert!(!new_mapping);
        assert_eq!(live.load(Ordering::Acquire), 7);
        assert_eq!(resources.counts(), (3, 0));
        assert_eq!(resources.stack_pool_layout(), layout);
    }

    #[ktest]
    fn bootstrap_retirement_reuses_storage_without_expanding_task_limit() {
        let mut resources = ExecutionResources::new(1, 2).unwrap();
        resources.prepare().unwrap();
        let boot = resources.boot_stack_base();
        let second_boot = boot + STACK_STRIDE;
        let (first, new_mapping) = resources.allocate_stack().unwrap();
        assert!(new_mapping);
        {
            let mut stacks = resources.stacks.lock();
            assert_eq!(stacks.active_tasks, 1);
            assert_eq!(stacks.live_bitmap[0].load(Ordering::Acquire), 7);
            assert_eq!(stacks.free(boot, first as usize, 1), Err(-INVALID));
            assert_eq!(stacks.free(boot, boot + 8, 0), Err(-INVALID));
            // Boot storage is independent of the ordinary active_tasks
            // limit. Its total stack charge was reserved by create.
            assert_eq!(stacks.free(boot, first as usize, 0), Ok(StackRelease::Boot));
            assert_eq!(stacks.active_tasks, 1);
            assert_eq!(stacks.live_bitmap[0].load(Ordering::Acquire), 6);
            assert_eq!(stacks.free(boot, first as usize, 0), Err(-INVALID));
            assert!(stacks.slots[0].mapped);
            assert!(!stacks.slots[0].allocated);
            assert!(!stacks.slots[0].boot_reserved);
        }
        // A free, retired bootstrap slot cannot bypass the max_tasks limit.
        assert!(matches!(
            resources.allocate_stack(),
            Err(crate::Error::NoMemory)
        ));
        {
            let mut stacks = resources.stacks.lock();
            assert_eq!(
                stacks.free(first as usize, second_boot, 1),
                Ok(StackRelease::Task)
            );
            assert_eq!(stacks.active_tasks, 0);
            assert_eq!(stacks.live_bitmap[0].load(Ordering::Acquire), 2);
        }

        let (reused, new_mapping) = resources.allocate_stack().unwrap();
        assert_eq!(reused as usize, boot);
        assert!(!new_mapping);
        assert_eq!(resources.counts(), (3, 0));
        assert!(matches!(
            resources.allocate_stack(),
            Err(crate::Error::NoMemory)
        ));
        let mut stacks = resources.stacks.lock();
        assert_eq!(stacks.active_tasks, 1);
        assert_eq!(stacks.live_bitmap[0].load(Ordering::Acquire), 3);
        // Once reused, this is a normal Task stack and may be released by
        // another vCPU after its Task migrates.
        assert_eq!(stacks.free(boot, second_boot, 1), Ok(StackRelease::Task));
        assert_eq!(stacks.active_tasks, 0);
        assert_eq!(stacks.live_bitmap[0].load(Ordering::Acquire), 2);
        assert_eq!(stacks.free(boot, second_boot, 1), Err(-INVALID));
    }

    #[ktest]
    fn boot_and_reused_stack_release_charges_once() {
        let mut resources = ExecutionResources::new(1, 2).unwrap();
        resources.prepare().unwrap();
        let boot = resources.boot_stack_base();
        let second_boot = boot + STACK_STRIDE;
        // create charges both reserved Boot slots before any carrier runs.
        let stacks_allocated = AtomicU32::new(2);
        assert_eq!(
            resources.release_stack(boot, second_boot, 1, &stacks_allocated),
            Err(-INVALID)
        );
        assert_eq!(
            resources.release_stack(boot, boot + 8, 0, &stacks_allocated),
            Err(-INVALID)
        );
        assert_eq!(stacks_allocated.load(Ordering::Relaxed), 2);
        resources
            .release_stack(boot, second_boot, 0, &stacks_allocated)
            .unwrap();
        assert_eq!(stacks_allocated.load(Ordering::Relaxed), 1);
        assert_eq!(
            resources.release_stack(boot, second_boot, 0, &stacks_allocated),
            Err(-INVALID)
        );
        assert_eq!(stacks_allocated.load(Ordering::Relaxed), 1);

        let (reused, new_mapping) = resources.allocate_stack().unwrap();
        assert_eq!(reused as usize, boot);
        assert!(!new_mapping);
        // This is the same ordinary allocation charge made by kstack_alloc.
        stacks_allocated.fetch_add(1, Ordering::Relaxed);
        assert_eq!(stacks_allocated.load(Ordering::Relaxed), 2);
        assert!(matches!(
            resources.allocate_stack(),
            Err(crate::Error::NoMemory)
        ));
        resources
            .release_stack(boot, second_boot, 1, &stacks_allocated)
            .unwrap();
        assert_eq!(stacks_allocated.load(Ordering::Relaxed), 1);
        resources
            .release_stack(second_boot, boot, 1, &stacks_allocated)
            .unwrap();
        assert_eq!(stacks_allocated.load(Ordering::Relaxed), 0);
        assert_eq!(
            resources.release_stack(second_boot, boot, 1, &stacks_allocated),
            Err(-INVALID)
        );
        assert_eq!(stacks_allocated.load(Ordering::Relaxed), 0);
        let stacks = resources.stacks.lock();
        assert_eq!(stacks.active_tasks, 0);
        assert_eq!(stacks.live_bitmap[0].load(Ordering::Acquire), 0);
    }
}
