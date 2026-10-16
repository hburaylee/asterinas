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
    kernelet::abi::{INVALID, KSTACK_MAPPING_BYTES, KSTACK_USABLE_BYTES},
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
    stacks: SpinLock<StackPool, LocalIrqDisabled>,
    stack_layout: Arc<StackPoolLayout>,
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
            // Reserve the separately shared layout, its Arc counters and the
            // additional handle independently of per-slot allocation charges.
            .and_then(|bytes| {
                bytes.checked_add(size_of::<StackPoolLayout>() + 3 * size_of::<usize>())
            })
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
        let stacks = StackPool::new(max_tasks, vcpus)?;
        let stack_layout = stacks.layout.clone();
        Ok(Self {
            stacks: SpinLock::new(stacks),
            stack_layout,
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
        self.initial_stack_base(0).unwrap()
    }

    /// Returns the fixed initial stack assigned to one carrier by creation.
    /// The START protocol, rather than this address getter, admits initial use.
    pub(super) fn initial_stack_base(&self, vcpu: usize) -> Option<usize> {
        (vcpu < self.carrier_spaces.len()).then(|| self.stack_layout.stack_base(vcpu))
    }

    #[cfg(ktest)]
    pub(crate) fn register_test_root(&self, root: u64) {
        let mut roots = self.roots.lock();
        let index = roots
            .binary_search_by_key(&root, |entry| entry.paddr)
            .unwrap_err();
        roots.insert(index, RootRegistration::new(root).unwrap());
    }

    #[cfg(ktest)]
    pub(crate) fn test_root_is_active(&self, root: u64, cpu: CpuId) -> bool {
        let roots = self.roots.lock();
        roots
            .binary_search_by_key(&root, |entry| entry.paddr)
            .is_ok_and(|index| roots[index].table.is_active_on(cpu))
    }

    #[cfg(ktest)]
    pub(crate) fn test_root_last_direct_activation_from(&self, root: u64) -> Option<usize> {
        let roots = self.roots.lock();
        roots
            .binary_search_by_key(&root, |entry| entry.paddr)
            .ok()
            .map(|index| roots[index].table.last_direct_activation_from())
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
        (
            self.stack_layout.start,
            self.stack_layout.end,
            self.stack_layout.live_bitmap.as_ptr() as usize,
        )
    }

    /// Checks a range against fixed stack bounds and its allocation's live bit.
    /// This does not acquire the allocator lock or pin a Task's stack owner.
    pub(super) fn contains_stack_range(&self, start: usize, end: usize) -> bool {
        self.stack_layout.contains_range(start, end)
    }

    /// Checks a range on the stack selected by the interrupted RSP.
    /// Task execution ownership must keep that allocation live through use.
    pub(super) fn contains_current_stack_range(
        &self,
        start: usize,
        end: usize,
        rsp: usize,
    ) -> bool {
        self.stack_layout.contains_current_range(start, end, rsp)
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
            (index, slot.base(), slot.mapped, stacks.layout.arena.clone())
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
        stacks.slots[index].allocated = true;
        if !mapped {
            stacks.mapped_slots += 1;
        }
        stacks.publish_live(index);
        Ok((base as u64, !mapped))
    }
}
struct StackSlot {
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
enum StackRelease {
    Boot,
    Task,
}

impl StackSlot {
    fn base(&self) -> usize {
        self.base
    }

    fn contains(&self, rsp: usize) -> bool {
        // An empty descending stack has RSP at its exclusive mapping end.
        // Retain the lower boundary too when rejecting release of a live stack.
        (self.base()..=self.base() + KSTACK_USABLE_BYTES).contains(&rsp)
    }

    #[cfg(ktest)]
    fn contains_range(&self, start: usize, end: usize) -> bool {
        self.allocated
            && start <= end
            && start >= self.base()
            && end <= self.base() + KSTACK_USABLE_BYTES
    }
}

const STACK_PROP: PageProperty = PageProperty {
    flags: PageFlags::RW,
    cache: CachePolicy::Writeback,
    priv_flags: PrivilegedPageFlags::empty(),
};

/// Fixed stack geometry and publication state, shared without an allocator lock.
/// The arena and bitmap remain owned together, and the bitmap never grows.
struct StackPoolLayout {
    arena: Arc<KVirtArea>,
    start: usize,
    end: usize,
    live_bitmap: Vec<AtomicU64>,
}

impl StackPoolLayout {
    fn slot_index(&self, address: usize) -> Option<usize> {
        (self.start..self.end)
            .contains(&address)
            .then(|| (address - self.start) / STACK_STRIDE)
    }

    fn stack_base(&self, index: usize) -> usize {
        // new() validates the entire fixed geometry before publishing it.
        self.start + index * STACK_STRIDE + STACK_BYTES
    }

    fn is_live(&self, index: usize) -> bool {
        self.live_bitmap
            .get(index / 64)
            .is_some_and(|word| word.load(Ordering::Acquire) & (1 << (index % 64)) != 0)
    }

    fn publish_live(&self, index: usize) {
        self.live_bitmap[index / 64].fetch_or(1 << (index % 64), Ordering::Release);
    }

    fn clear_live(&self, index: usize) {
        self.live_bitmap[index / 64].fetch_and(!(1 << (index % 64)), Ordering::Release);
    }

    fn contains_range(&self, start: usize, end: usize) -> bool {
        let Some(index) = self.slot_index(start) else {
            return false;
        };
        let base = self.stack_base(index);
        start <= end && start >= base && end <= base + KSTACK_USABLE_BYTES && self.is_live(index)
    }

    fn contains_current_range(&self, start: usize, end: usize, rsp: usize) -> bool {
        let Some(index) = rsp
            .checked_sub(1)
            .and_then(|address| self.slot_index(address))
        else {
            return false;
        };
        let base = self.stack_base(index);
        rsp > base
            && rsp <= base + KSTACK_USABLE_BYTES
            && start <= end
            && start >= base
            && end <= base + KSTACK_USABLE_BYTES
            && self.is_live(index)
    }
}

struct StackPool {
    layout: Arc<StackPoolLayout>,
    slots: Vec<StackSlot>,
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
        let layout = Arc::new(StackPoolLayout {
            arena,
            start,
            end,
            live_bitmap,
        });
        Ok(Self {
            layout,
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
            self.layout.arena.map_additional_frames(
                base - self.layout.arena.start(),
                allocate_stack_frames()?,
                STACK_PROP,
            )?;
            // No carrier has entered this unpublished instance yet. Reused
            // arena addresses were synchronously retired by their old owner.
            tlb_flush_addr_range(&(base..base + STACK_BYTES));
            self.slots[index].mapped = true;
            self.slots[index].allocated = true;
            self.mapped_slots += 1;
            self.publish_live(index);
        }
        Ok(self.slots[vcpu].base() as u64)
    }

    fn publish_live(&self, index: usize) {
        self.layout.publish_live(index);
    }

    fn slot_index(&self, address: usize) -> Option<usize> {
        (self.layout.start..self.layout.end)
            .contains(&address)
            .then(|| (address - self.layout.start) / STACK_STRIDE)
    }

    fn free(&mut self, base: usize, saved_rsp: usize, vcpu: usize) -> Result<StackRelease, i64> {
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
        let released = if slot.boot_reserved {
            slot.boot_reserved = false;
            StackRelease::Boot
        } else {
            self.active_tasks -= 1;
            StackRelease::Task
        };
        slot.allocated = false;
        self.layout.clear_live(index);
        Ok(released)
    }

    #[cfg(ktest)]
    fn contains_range(&self, start: usize, end: usize) -> bool {
        self.slot_index(start)
            .is_some_and(|index| self.slots[index].contains_range(start, end))
    }

    #[cfg(ktest)]
    fn contains_current_range(&self, start: usize, end: usize, rsp: usize) -> bool {
        // Locate the byte below RSP so an empty stack still selects its own
        // slot, including the last slot whose top equals the pool's end.
        rsp.checked_sub(1)
            .and_then(|address| self.slot_index(address))
            .is_some_and(|index| {
                let slot = &self.slots[index];
                rsp > slot.base() && slot.contains(rsp) && slot.contains_range(start, end)
            })
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
    use core::sync::atomic::AtomicBool;

    use super::*;
    use crate::{cpu::PinCurrentCpu, prelude::*};

    struct StackPublicationProbe {
        resources: Arc<ExecutionResources>,
        remote: CpuId,
        first: usize,
        second: usize,
        first_live: AtomicBool,
        ready: AtomicBool,
        go: AtomicBool,
    }

    static STACK_PUBLICATION_PROBE: SpinLock<Option<Arc<StackPublicationProbe>>, LocalIrqDisabled> =
        SpinLock::new(None);

    fn observe_stack_publication() {
        let probe = STACK_PUBLICATION_PROBE.lock().as_ref().unwrap().clone();
        assert_eq!(crate::cpu::CpuId::current_racy(), probe.remote);
        assert_eq!(
            probe
                .resources
                .contains_stack_range(probe.first, probe.first + 8),
            probe.first_live.load(Ordering::Acquire)
        );
        assert!(probe.resources.contains_current_stack_range(
            probe.second + STACK_BYTES - 64,
            probe.second + STACK_BYTES,
            probe.second + STACK_BYTES,
        ));
    }

    fn update_remote_stack_bits() {
        let probe = STACK_PUBLICATION_PROBE.lock().as_ref().unwrap().clone();
        assert_eq!(crate::cpu::CpuId::current_racy(), probe.remote);
        probe.ready.store(true, Ordering::Release);
        while !probe.go.load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
        for _ in 0..4096 {
            probe.resources.stack_layout.clear_live(1);
            probe.resources.stack_layout.publish_live(1);
        }
    }

    fn compare_stack_validation_with_locked_slots(resources: &ExecutionResources) {
        // Keeping this guard while calling production readers also verifies
        // that neither reader nor fixed-layout getter acquires the pool lock.
        let stacks = resources.stacks.lock();
        let (start, end, bitmap) = resources.stack_pool_layout();
        assert_eq!(start, stacks.layout.start);
        assert_eq!(end, stacks.layout.end);
        assert_eq!(bitmap, stacks.layout.live_bitmap.as_ptr() as usize);
        assert_eq!(
            resources.initial_stack_base(0),
            Some(stacks.slots[0].base())
        );
        assert_eq!(
            resources.initial_stack_base(resources.carrier_spaces.len()),
            None
        );
        let mut boundaries = alloc::vec![0, 1, usize::MAX, start - 1, start, end - 1, end, end + 1];
        for slot in &stacks.slots {
            let base = slot.base();
            let top = base + KSTACK_USABLE_BYTES;
            boundaries.extend([base - 1, base, base + 1, top - 1, top, top + 1]);
        }
        for &range_start in &boundaries {
            for &range_end in &boundaries {
                assert_eq!(
                    resources.contains_stack_range(range_start, range_end),
                    stacks.contains_range(range_start, range_end),
                    "range={:#x?}",
                    (range_start, range_end)
                );
                for &rsp in &boundaries {
                    assert_eq!(
                        resources.contains_current_stack_range(range_start, range_end, rsp),
                        stacks.contains_current_range(range_start, range_end, rsp),
                        "range and RSP={:#x?}",
                        (range_start, range_end, rsp)
                    );
                }
            }
        }
    }

    #[ktest]
    fn lock_free_stack_validation_matches_allocator_boundaries_and_reuse() {
        let mut resources = ExecutionResources::new(2, 1).unwrap();
        let layout = resources.stack_pool_layout();
        compare_stack_validation_with_locked_slots(&resources);
        resources.prepare().unwrap();
        compare_stack_validation_with_locked_slots(&resources);
        let boot = resources.boot_stack_base();
        assert!(resources.contains_stack_range(boot, boot));
        assert!(!resources.contains_stack_range(boot + STACK_BYTES, boot + STACK_BYTES));
        assert!(resources.contains_current_stack_range(
            boot + STACK_BYTES,
            boot + STACK_BYTES,
            boot + STACK_BYTES,
        ));
        let (first, _) = resources.allocate_stack().unwrap();
        compare_stack_validation_with_locked_slots(&resources);
        let (_last, _) = resources.allocate_stack().unwrap();
        compare_stack_validation_with_locked_slots(&resources);
        let charged = AtomicU32::new(3);
        resources
            .release_stack(first as usize, boot, 0, &charged)
            .unwrap();
        compare_stack_validation_with_locked_slots(&resources);
        assert!(!resources.contains_stack_range(first as usize, first as usize));
        let (reused, mapped) = resources.allocate_stack().unwrap();
        assert_eq!(reused, first);
        assert!(!mapped);
        compare_stack_validation_with_locked_slots(&resources);
        assert_eq!(resources.stack_pool_layout(), layout);
    }

    #[ktest]
    fn stack_live_publication_is_visible_on_another_cpu_without_lost_bits() {
        let guard = crate::task::disable_preempt();
        let current = guard.current_cpu();
        let Some(remote) = crate::cpu::all_cpus().find(|cpu| *cpu != current) else {
            crate::early_println!("[skipped: stack publication requires two physical CPUs]");
            return;
        };
        let mut resources = ExecutionResources::new(1, 2).unwrap();
        resources.prepare().unwrap();
        let resources = Arc::new(resources);
        let first = resources.initial_stack_base(0).unwrap();
        let second = resources.initial_stack_base(1).unwrap();
        let layout = resources.stack_pool_layout();
        let probe = Arc::new(StackPublicationProbe {
            resources: resources.clone(),
            remote,
            first,
            second,
            first_live: AtomicBool::new(true),
            ready: AtomicBool::new(false),
            go: AtomicBool::new(false),
        });
        *STACK_PUBLICATION_PROBE.lock() = Some(probe.clone());
        let observe_fn = |first_live| {
            probe.first_live.store(first_live, Ordering::Release);
            crate::smp::inter_processor_call(&remote.into(), observe_stack_publication).wait();
        };
        observe_fn(true);
        let charged = AtomicU32::new(2);
        resources.release_stack(first, second, 0, &charged).unwrap();
        observe_fn(false);
        let (reused, mapped) = resources.allocate_stack().unwrap();
        assert_eq!(reused as usize, first);
        assert!(!mapped);
        observe_fn(true);

        // Both mappings remain owned and unused by Tasks. Exercise concurrent
        // publication of different bits in the same word on two real CPUs;
        // this checks the atomic protocol, not Task identity or stack pinning.
        let pending = crate::smp::inter_processor_call(&remote.into(), update_remote_stack_bits);
        while !probe.ready.load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
        probe.go.store(true, Ordering::Release);
        for _ in 0..4096 {
            resources.stack_layout.clear_live(0);
            resources.stack_layout.publish_live(0);
        }
        pending.wait();
        assert_eq!(
            resources.stack_layout.live_bitmap[0].load(Ordering::Acquire),
            3
        );
        observe_fn(true);
        assert_eq!(resources.stack_pool_layout(), layout);
        STACK_PUBLICATION_PROBE.lock().take();
    }

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
            assert!(stacks.layout.arena.query(&guard, boot).is_some());
            assert!(
                stacks
                    .layout
                    .arena
                    .query(&guard, boot - PAGE_SIZE)
                    .is_none()
            );
            assert!(
                stacks
                    .layout
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
            for base in [boot, first as usize, second as usize] {
                let top = base + STACK_BYTES;
                assert!(stacks.contains_current_range(top - 64, top, top));
                assert!(!stacks.contains_current_range(top - 64, top, top + 1));
                assert!(!stacks.contains_current_range(top - 64, top + 1, top));
                assert!(!stacks.contains_current_range(base, base + 8, base));
                assert!(!stacks.contains_current_range(base, base + 8, base - 1));
                assert!(!stacks.contains_current_range(base, base + 8, 0));
            }
            assert!(stacks.contains_current_range(
                first as usize + 16,
                first as usize + KSTACK_USABLE_BYTES,
                first as usize + 8,
            ));
            // The entire mapping is usable stack storage, while the first
            // byte beyond its upper bound must remain inaccessible to a frame.
            assert!(stacks.contains_current_range(
                first as usize + STACK_BYTES - 8,
                first as usize + STACK_BYTES,
                first as usize + 8,
            ));
            assert!(!stacks.contains_current_range(
                first as usize + STACK_BYTES - 8,
                first as usize + STACK_BYTES + 1,
                first as usize + 8,
            ));
            assert!(!stacks.contains_current_range(
                first as usize - 8,
                first as usize + 8,
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
            assert_eq!(
                stacks.free(first as usize, first as usize + STACK_BYTES, 0),
                Err(-INVALID)
            );
            assert_eq!(stacks.free(first as usize, boot, 0), Ok(StackRelease::Task));
            assert_eq!(stacks.free(first as usize, boot, 0), Err(-INVALID));
            assert!(!stacks.contains_range(first as usize, first as usize + 8));
            assert!(!stacks.contains_current_range(
                first as usize + STACK_BYTES - 64,
                first as usize + STACK_BYTES,
                first as usize + STACK_BYTES,
            ));
        }
        assert_eq!(live.load(Ordering::Acquire), 5);
        {
            let guard = crate::irq::disable_local();
            let stacks = resources.stacks.lock();
            assert!(stacks.layout.arena.query(&guard, first as usize).is_some());
        }
        let before_reuse = STACK_MAPPING_FLUSHES.load(Ordering::Relaxed);
        let (reused, new_mapping) = resources.allocate_stack().unwrap();
        assert_eq!(STACK_MAPPING_FLUSHES.load(Ordering::Relaxed), before_reuse);
        assert_eq!(reused, first);
        assert!(!new_mapping);
        assert_eq!(live.load(Ordering::Acquire), 7);
        assert_eq!(resources.counts(), (3, 0));
        assert_eq!(resources.stack_pool_layout(), layout);
        assert!(resources.stacks.lock().contains_current_range(
            first as usize + STACK_BYTES - 64,
            first as usize + STACK_BYTES,
            first as usize + STACK_BYTES,
        ));
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
            assert_eq!(stacks.layout.live_bitmap[0].load(Ordering::Acquire), 7);
            assert_eq!(stacks.free(boot, first as usize, 1), Err(-INVALID));
            assert_eq!(stacks.free(boot, boot + 8, 0), Err(-INVALID));
            assert_eq!(stacks.free(boot, boot + STACK_BYTES, 0), Err(-INVALID));
            // Boot storage is independent of the ordinary active_tasks
            // limit. Its total stack charge was reserved by create.
            assert_eq!(stacks.free(boot, first as usize, 0), Ok(StackRelease::Boot));
            assert_eq!(stacks.active_tasks, 1);
            assert_eq!(stacks.layout.live_bitmap[0].load(Ordering::Acquire), 6);
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
            assert_eq!(stacks.layout.live_bitmap[0].load(Ordering::Acquire), 2);
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
        assert_eq!(stacks.layout.live_bitmap[0].load(Ordering::Acquire), 3);
        // Once reused, this is a normal Task stack and may be released by
        // another vCPU after its Task migrates.
        assert_eq!(stacks.free(boot, second_boot, 1), Ok(StackRelease::Task));
        assert_eq!(stacks.active_tasks, 0);
        assert_eq!(stacks.layout.live_bitmap[0].load(Ordering::Acquire), 2);
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
        assert_eq!(stacks.layout.live_bitmap[0].load(Ordering::Acquire), 0);
    }
}
