// SPDX-License-Identifier: MPL-2.0

//! Virtual memory space management.
//!
//! The [`VmSpace`] struct is provided to manage the virtual memory space of a
//! user. Cursors are used to traverse and modify over the virtual memory space
//! concurrently. The VM space cursor [`self::Cursor`] is just a wrapper over
//! the page table cursor, providing efficient, powerful concurrent accesses
//! to the page table.

#[cfg(any(feature = "kernelet", feature = "kernelet-host"))]
use core::sync::atomic::AtomicBool;
use core::{ops::Range, sync::atomic::Ordering};

use super::{AnyUFrameMeta, PagingLevel, page_table::PageTableConfig};
#[cfg(not(feature = "kernelet"))]
use crate::mm::kspace::KERNEL_PAGE_TABLE;
use crate::{
    Error,
    arch::mm::{PageTableEntry, PagingConsts, current_page_table_paddr},
    cpu::{AtomicCpuSet, CpuSet, PinCurrentCpu},
    cpu_local_cell,
    io::IoMem,
    mm::{
        Frame, HasPaddrRange, PAGE_SIZE, PageProperty, PrivilegedPageFlags, UFrame, VmReader,
        VmWriter,
        frame::FrameRef,
        io::Fallible,
        page_prop::{CachePolicy, PageFlags},
        page_table::{self, PageTable, PageTableFrag},
        tlb::{TlbFlushOp, TlbFlusher},
    },
    prelude::*,
    sync::{RcuDrop, SpinLock},
    task::{DisabledPreemptGuard, atomic_mode::AsAtomicModeGuard, disable_preempt},
};

/// A virtual address space for user-mode tasks, enabling safe manipulation of user-space memory.
///
/// The `VmSpace` type provides memory isolation guarantees between user-space and
/// kernel-space. For example, given an arbitrary user-space pointer, one can read and
/// write the memory location referred to by the user-space pointer without the risk of
/// breaking the memory safety of the kernel space.
///
/// # Task Association Semantics
///
/// As far as OSTD is concerned, a `VmSpace` is not necessarily associated with a task. Once a
/// `VmSpace` is activated (see [`VmSpace::activate`]), it remains activated until another
/// `VmSpace` is activated **possibly by another task running on the same CPU**.
///
/// This means that it's up to the kernel to ensure that a task's `VmSpace` is always activated
/// while the task is running. This can be done by using the injected post schedule handler
/// (see [`inject_post_schedule_handler`]) to always activate the correct `VmSpace` after each
/// context switch.
///
/// If the kernel otherwise decides not to ensure that the running task's `VmSpace` is always
/// activated, the kernel must deal with race conditions when calling methods that require the
/// `VmSpace` to be activated, e.g., [`UserMode::execute`], [`VmSpace::reader`],
/// [`VmSpace::writer`]. Otherwise, the behavior is unspecified, though it's guaranteed _not_ to
/// compromise the kernel's memory safety.
///
/// # Memory Backing
///
/// A newly-created `VmSpace` is not backed by any physical memory pages. To
/// provide memory pages for a `VmSpace`, one can allocate and map physical
/// memory ([`UFrame`]s) to the `VmSpace` using the cursor.
///
/// A `VmSpace` can also attach a page fault handler, which will be invoked to
/// handle page faults generated from user space.
///
/// [`inject_post_schedule_handler`]: crate::task::inject_post_schedule_handler
/// [`UserMode::execute`]: crate::user::UserMode::execute
#[derive(Debug)]
pub struct VmSpace {
    #[cfg(feature = "kernelet-host")]
    pt: Option<PageTable<UserPtConfig>>,
    #[cfg(not(feature = "kernelet-host"))]
    pt: PageTable<UserPtConfig>,
    #[cfg(feature = "kernelet-host")]
    activation: Option<RootActivation>,
    cpus: AtomicCpuSet,
    iomems: SpinLock<Vec<IoMem>>,
    #[cfg(feature = "kernelet")]
    registered: AtomicBool,
}

#[cfg(feature = "kernelet-host")]
#[derive(Debug)]
struct RootActivation {
    root: SpinLock<Option<Arc<RegisteredPageTable>>, crate::sync::LocalIrqDisabled>,
    restore: AtomicBool,
}

/// A validated root. No Host page-table walker may inspect its tenant frames.
#[cfg(feature = "kernelet-host")]
#[derive(Debug)]
pub(crate) struct RegisteredPageTable {
    paddr: Paddr,
    state: SpinLock<RegisteredRootState, crate::sync::LocalIrqDisabled>,
    #[cfg(ktest)]
    last_direct_activation_from: core::sync::atomic::AtomicUsize,
    #[cfg(all(kernelet_rq1_diagnostics, feature = "kernelet-host"))]
    diagnostic_id: Option<u64>,
}

/// One root generation and its active physical CPU snapshot.
#[cfg(feature = "kernelet-host")]
pub(crate) struct RootShootdown {
    pub(crate) active: CpuSet,
    #[cfg(all(kernelet_rq1_diagnostics, feature = "kernelet-host"))]
    pub(crate) root_id: Option<u64>,
    #[cfg(all(kernelet_rq1_diagnostics, feature = "kernelet-host"))]
    pub(crate) generation: u64,
}

#[cfg(feature = "kernelet-host")]
#[derive(Debug)]
struct RegisteredRootState {
    valid: bool,
    active: CpuSet,
    generation: u64,
    seen_generation: Vec<u64>,
}

#[cfg(feature = "kernelet-host")]
impl RegisteredPageTable {
    /// The caller must retain the validated root's grant until invalidation.
    pub(crate) fn new(paddr: Paddr) -> Option<Arc<Self>> {
        let mut seen_generation = Vec::new();
        seen_generation
            .try_reserve_exact(crate::cpu::num_cpus())
            .ok()?;
        seen_generation.resize(crate::cpu::num_cpus(), 0);
        Some(Arc::new(Self {
            paddr,
            #[cfg(ktest)]
            last_direct_activation_from: core::sync::atomic::AtomicUsize::new(0),
            #[cfg(all(kernelet_rq1_diagnostics, feature = "kernelet-host"))]
            diagnostic_id: crate::kernelet::tlb_profile::next_root_id(),
            state: SpinLock::new(RegisteredRootState {
                valid: true,
                active: CpuSet::new_empty(),
                generation: 0,
                seen_generation,
            }),
        }))
    }

    fn reserve(&self, cpu: crate::cpu::CpuId) -> bool {
        let mut state = self.state.lock();
        if !state.valid {
            return false;
        }
        let generation = state.generation;
        if state.seen_generation[u32::from(cpu) as usize] != generation {
            #[cfg(all(kernelet_getpid_profile, target_arch = "x86_64"))]
            crate::kernelet::getpid_profile::event(
                crate::kernelet::getpid_profile::event_id::ROOT_GENERATION_FLUSH,
            );
            crate::arch::mm::tlb_flush_all_excluding_global();
        }
        state.seen_generation[u32::from(cpu) as usize] = generation;
        state.active.add(cpu);
        true
    }

    fn activate(&self, cpu: crate::cpu::CpuId) -> bool {
        let mut state = self.state.lock();
        if !state.valid {
            return false;
        }
        // Holding this lock through CR3 excludes a missed shootdown snapshot.
        // Every restoration flushes non-global entries, including generations
        // published while this CPU was absent from the active set.
        // SAFETY: The registry validated the shared kernel half and retains
        // the grant until this token is invalidated with no active CPUs.
        unsafe { crate::arch::mm::activate_page_table(self.paddr) };
        #[cfg(all(kernelet_getpid_profile, target_arch = "x86_64"))]
        crate::kernelet::getpid_profile::event(
            crate::kernelet::getpid_profile::event_id::CR3_WRITE,
        );
        let generation = state.generation;
        state.seen_generation[u32::from(cpu) as usize] = generation;
        state.active.add(cpu);
        true
    }

    fn leave(&self, cpu: crate::cpu::CpuId) {
        self.state.lock().active.remove(cpu);
    }

    pub(crate) fn is_active(&self) -> bool {
        !self.state.lock().active.is_empty()
    }

    #[cfg(ktest)]
    pub(crate) fn is_active_on(&self, cpu: crate::cpu::CpuId) -> bool {
        self.state.lock().active.contains(cpu)
    }

    #[cfg(ktest)]
    pub(crate) fn last_direct_activation_from(&self) -> Paddr {
        self.last_direct_activation_from.load(Ordering::Relaxed)
    }

    pub(crate) fn begin_shootdown(&self) -> Option<RootShootdown> {
        let mut state = self.state.lock();
        state.generation = state.generation.checked_add(1)?;
        Some(RootShootdown {
            active: state.active.clone(),
            #[cfg(all(kernelet_rq1_diagnostics, feature = "kernelet-host"))]
            root_id: self.diagnostic_id,
            #[cfg(all(kernelet_rq1_diagnostics, feature = "kernelet-host"))]
            generation: state.generation,
        })
    }

    pub(crate) fn invalidate(&self) {
        let mut state = self.state.lock();
        assert!(
            state.active.is_empty(),
            "retiring an active registered root"
        );
        state.valid = false;
    }
}

#[cfg(feature = "kernelet")]
impl Drop for VmSpace {
    fn drop(&mut self) {
        if self.registered.load(Ordering::Acquire) {
            let result = (crate::kernelet::entry::services().pt_root_unregister)(
                self.page_table().unwrap().root_paddr() as u64,
            );
            assert_eq!(
                result, 0,
                "Host refused to unregister a user page-table root"
            );
        }
    }
}

impl VmSpace {
    /// Creates a new VM address space.
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "kernelet-host")]
            pt: Some(KERNEL_PAGE_TABLE.get().unwrap().create_user_page_table()),
            #[cfg(not(any(feature = "kernelet", feature = "kernelet-host")))]
            pt: KERNEL_PAGE_TABLE.get().unwrap().create_user_page_table(),
            #[cfg(feature = "kernelet")]
            pt: PageTable::new_kernelet_user_page_table(),
            #[cfg(feature = "kernelet-host")]
            activation: None,
            cpus: AtomicCpuSet::new(CpuSet::new_empty()),
            iomems: SpinLock::new(Vec::new()),
            #[cfg(feature = "kernelet")]
            registered: AtomicBool::new(false),
        }
    }

    fn page_table(&self) -> Result<&PageTable<UserPtConfig>> {
        #[cfg(feature = "kernelet-host")]
        {
            self.pt.as_ref().ok_or(Error::AccessDenied)
        }
        #[cfg(not(feature = "kernelet-host"))]
        {
            Ok(&self.pt)
        }
    }

    /// Creates a carrier address space that can only activate validated roots.
    #[cfg(feature = "kernelet-host")]
    pub(crate) fn new_activation_only() -> Self {
        Self {
            pt: None,
            activation: Some(RootActivation {
                root: SpinLock::new(None),
                restore: AtomicBool::new(false),
            }),
            cpus: AtomicCpuSet::new(CpuSet::new_empty()),
            iomems: SpinLock::new(Vec::new()),
        }
    }

    #[cfg(feature = "kernelet-host")]
    pub(crate) fn set_registered_root(&self, root: Option<Arc<RegisteredPageTable>>) {
        let activation = self.activation.as_ref().unwrap();
        debug_assert!(self.cpus.load(Ordering::Relaxed).is_empty());
        *activation.root.lock() = root;
    }

    /// Commits a carrier's new root before releasing its old active reservation.
    ///
    /// The caller retains the registry lock and the roots' grants throughout
    /// this synchronous operation. Its IRQ guard excludes native scheduling
    /// until the carrier's desired-root identity has also been updated.
    #[cfg(feature = "kernelet-host")]
    pub(crate) fn activate_registered_root(
        self: &Arc<Self>,
        root: Arc<RegisteredPageTable>,
        irq_guard: &crate::irq::DisabledLocalIrqGuard,
    ) -> bool {
        let Some(activation) = self.activation.as_ref() else {
            return false;
        };
        let current = ACTIVATED_VM_SPACE.load();
        if !current.is_null() && current != Arc::as_ptr(self) {
            // Carrier entry and pause must release any native address space.
            // Reject an unexpected owner without changing its root or references.
            return false;
        }
        let cpu = irq_guard.current_cpu();
        let was_active = current == Arc::as_ptr(self);
        let mut selected = activation.root.lock();
        // Keep the old token and active CPU bit until the new CR3 is installed.
        // activate() serializes validation, CR3 and the new active bit against
        // shootdown. Failure leaves all old hardware and software state intact.
        #[cfg(ktest)]
        let from = current_page_table_paddr();
        if !root.activate(cpu) {
            return false;
        }
        #[cfg(ktest)]
        root.last_direct_activation_from
            .store(from, Ordering::Relaxed);
        let previous = selected.replace(root);
        self.record_activation(cpu);
        activation.restore.store(true, Ordering::Release);
        if was_active {
            if let Some(previous) = previous {
                // Re-selecting the same token must retain its new reservation.
                if !Arc::ptr_eq(&previous, selected.as_ref().unwrap()) {
                    previous.leave(cpu);
                }
            }
        }
        true
    }

    #[cfg(feature = "kernelet-host")]
    pub(crate) fn set_root_restore(&self, restore: bool) {
        self.activation
            .as_ref()
            .unwrap()
            .restore
            .store(restore, Ordering::Release);
    }

    /// Reserves the root and its CPU reference before the fixed CR3 commit.
    ///
    /// The caller's physical IRQ guard pins this CPU throughout preparation.
    #[cfg(feature = "kernelet-host")]
    pub(crate) fn prepare_registered_root(
        self: &Arc<Self>,
        expected_root: Paddr,
        irq_guard: &crate::irq::DisabledLocalIrqGuard,
    ) -> bool {
        debug_assert!(!crate::arch::irq::is_local_enabled());
        let cpu = irq_guard.current_cpu();
        let activation = self.activation.as_ref().unwrap();
        if ACTIVATED_VM_SPACE.load() == Arc::as_ptr(self)
            && activation.restore.load(Ordering::Acquire)
            && self.cpus.contains(cpu, Ordering::Relaxed)
            && expected_root != 0
        {
            // A CPU reference is published only after a valid root is reserved,
            // and cleared before leaving its active set. Root replacement and
            // invalidation require that set to be empty. With IRQs masked, this
            // reservation remains valid until the caller's fixed CR3 commit,
            // including when that commit has not installed the root yet.
            // A concurrent shootdown still waits for the actual IPI; this path
            // must not update the root's observed generation.
            #[cfg(all(kernelet_getpid_profile, target_arch = "x86_64"))]
            crate::kernelet::getpid_profile::event(
                crate::kernelet::getpid_profile::event_id::ROOT_FAST,
            );
            return true;
        }
        #[cfg(all(kernelet_getpid_profile, target_arch = "x86_64"))]
        crate::kernelet::getpid_profile::event(
            crate::kernelet::getpid_profile::event_id::ROOT_SLOW,
        );
        Self::deactivate();
        let root = activation.root.lock();
        let Some(root) = root.as_ref() else {
            return true;
        };
        if !root.reserve(cpu) {
            return false;
        }
        self.record_activation(cpu);
        activation.restore.store(true, Ordering::Release);
        true
    }

    /// Installs the kernel root and releases this CPU's active-space reference.
    pub fn deactivate() {
        let irq_guard = crate::irq::disable_local();
        #[cfg(not(feature = "kernelet"))]
        {
            KERNEL_PAGE_TABLE.get().unwrap().activate(
                #[cfg(feature = "kernelet-host")]
                &irq_guard,
            );
        }
        #[cfg(feature = "kernelet")]
        {
            let status = (crate::kernelet::entry::services().pt_activate)(0);
            assert_eq!(
                status, 0,
                "Host refused to deactivate a user page-table root"
            );
        }
        let last_ptr = ACTIVATED_VM_SPACE.load();
        ACTIVATED_VM_SPACE.store(core::ptr::null());
        if !last_ptr.is_null() {
            // SAFETY: The CPU cell owns exactly one reference from `into_raw`.
            let last = unsafe { Arc::from_raw(last_ptr) };
            last.cpus.remove(irq_guard.current_cpu(), Ordering::Relaxed);
            #[cfg(feature = "kernelet-host")]
            if let Some(activation) = last.activation.as_ref() {
                if let Some(root) = activation.root.lock().as_ref() {
                    root.leave(irq_guard.current_cpu());
                }
            }
        }
        #[cfg(feature = "kernelet")]
        if let Some(task) = crate::task::Task::current() {
            // Release the Task's cache only after the Host installed its kernel
            // root and this CPU released its active-space reference.
            drop(task.replace_active_vm_space(None, &irq_guard));
        }
    }

    #[cfg(feature = "kernelet-host")]
    pub(crate) fn kernel_root_paddr() -> Paddr {
        KERNEL_PAGE_TABLE.get().unwrap().root_paddr()
    }

    fn record_activation(self: &Arc<Self>, cpu: crate::cpu::CpuId) {
        let last_ptr = ACTIVATED_VM_SPACE.load();
        if last_ptr == Arc::as_ptr(self) {
            return;
        }
        self.cpus.add(cpu, Ordering::Acquire);
        ACTIVATED_VM_SPACE.store(Arc::into_raw(self.clone()));
        if !last_ptr.is_null() {
            // SAFETY: Replacing the CPU cell transfers its unique raw reference.
            let last = unsafe { Arc::from_raw(last_ptr) };
            last.cpus.remove(cpu, Ordering::Relaxed);
            #[cfg(feature = "kernelet-host")]
            if let Some(activation) = last.activation.as_ref() {
                if let Some(root) = activation.root.lock().as_ref() {
                    root.leave(cpu);
                }
            }
        }
    }

    /// Gets an immutable cursor in the virtual address range.
    ///
    /// The cursor behaves like a lock guard, exclusively owning a sub-tree of
    /// the page table, preventing others from creating a cursor in it. So be
    /// sure to drop the cursor as soon as possible.
    ///
    /// The creation of the cursor may block if another cursor having an
    /// overlapping range is alive.
    pub fn cursor<'a, G: AsAtomicModeGuard>(
        &'a self,
        guard: &'a G,
        va: &Range<Vaddr>,
    ) -> Result<Cursor<'a>> {
        Ok(Cursor(self.page_table()?.cursor(guard, va)?))
    }

    /// Gets an mutable cursor in the virtual address range.
    ///
    /// The same as [`Self::cursor`], the cursor behaves like a lock guard,
    /// exclusively owning a sub-tree of the page table, preventing others
    /// from creating a cursor in it. So be sure to drop the cursor as soon as
    /// possible.
    ///
    /// The creation of the cursor may block if another cursor having an
    /// overlapping range is alive. The modification to the mapping by the
    /// cursor may also block or be overridden the mapping of another cursor.
    pub fn cursor_mut<'a, G: AsAtomicModeGuard>(
        &'a self,
        guard: &'a G,
        va: &Range<Vaddr>,
    ) -> Result<CursorMut<'a>> {
        Ok(CursorMut {
            pt_cursor: self.page_table()?.cursor_mut(guard, va)?,
            #[cfg(not(feature = "kernelet"))]
            flusher: TlbFlusher::new(&self.cpus, disable_preempt()),
            #[cfg(feature = "kernelet")]
            flusher: TlbFlusher::for_user_root(&self.cpus, disable_preempt(), self),
            vmspace: self,
        })
    }

    /// Activates the page table on the current CPU.
    pub fn activate(self: &Arc<Self>) {
        #[cfg(feature = "kernelet")]
        let _irq_guard = crate::irq::disable_local();
        let preempt_guard = disable_preempt();
        let cpu = preempt_guard.current_cpu();

        #[cfg(feature = "kernelet-host")]
        if let Some(activation) = self.activation.as_ref() {
            let _irq_guard = crate::irq::disable_local();
            if !activation.restore.load(Ordering::Acquire) {
                Self::deactivate();
                return;
            }
            let root = activation.root.lock().clone();
            let Some(root) = root else {
                Self::deactivate();
                return;
            };
            // Transfer any ordinary native root reference to the permanent
            // kernel root before borrowing CR3 for a tenant page table.
            Self::deactivate();
            if !root.activate(cpu) {
                Self::deactivate();
                return;
            }
            self.record_activation(cpu);
            return;
        }

        let last_ptr = ACTIVATED_VM_SPACE.load();

        #[cfg(feature = "kernelet")]
        let current_task = crate::task::Task::current();
        #[cfg(feature = "kernelet")]
        let cached = current_task.as_ref().map_or_else(
            // Bootstrap execution has no Task-owned cache yet.
            || last_ptr == Arc::as_ptr(self),
            |task| task.active_vm_space_matches(self, &_irq_guard),
        );
        #[cfg(not(feature = "kernelet"))]
        let cached = last_ptr == Arc::as_ptr(self);

        // Image Tasks can borrow another root while their Task-owned cache
        // remains unchanged. Host carrier boundaries release the native
        // VmSpace before borrowing CR3, so native cache hits need no CR3 read.
        #[cfg(feature = "kernelet")]
        let already_active =
            cached && current_page_table_paddr() == self.page_table().unwrap().root_paddr();
        #[cfg(not(feature = "kernelet"))]
        let already_active = cached;
        if already_active {
            #[cfg(feature = "kernelet")]
            self.record_activation(cpu);
            return;
        }

        // Native cache hits only need CPU pinning. Protect an actual root
        // change and its active-space publication with physical IRQs masked.
        #[cfg(feature = "kernelet-host")]
        let _irq_guard = crate::irq::disable_local();

        #[cfg(feature = "kernelet")]
        {
            let root = self.register_kernelet_root();
            let status = (crate::kernelet::entry::services().pt_activate)(root);
            assert_eq!(status, 0, "Host refused to activate a user page-table root");
        }

        #[cfg(not(feature = "kernelet"))]
        self.page_table().unwrap().activate(
            #[cfg(feature = "kernelet-host")]
            &_irq_guard,
        );
        self.record_activation(cpu);
        #[cfg(feature = "kernelet")]
        if let Some(task) = current_task {
            drop(task.replace_active_vm_space(Some(self.clone()), &_irq_guard));
        }
    }

    /// Registers this root before activation or an image-side shootdown.
    #[cfg(feature = "kernelet")]
    pub(super) fn register_kernelet_root(&self) -> u64 {
        let root = self.page_table().unwrap().root_paddr() as u64;
        if !self.registered.load(Ordering::Acquire) {
            // Host registration is idempotent. Concurrent first activations
            // and flushes may both register, but neither may publish completion
            // or use the root before its registration has returned.
            let status = (crate::kernelet::entry::services().pt_root_register)(root);
            if status != 0 {
                crate::kernelet::entry::stop_panic(format_args!(
                    "Host refused to register a user page-table root: {status}"
                ));
            }
            self.registered.store(true, Ordering::Release);
        }
        root
    }

    /// Creates a reader to read data from the user space of the current task.
    ///
    /// Returns `Err` if this `VmSpace` doesn't belong to the user space of the current task
    /// or the `vaddr` and `len` do not represent a user space memory range.
    ///
    /// Users must ensure that no other page table is activated in the current task during the
    /// lifetime of the created `VmReader`. This guarantees that the `VmReader` can operate correctly.
    pub fn reader(&self, vaddr: Vaddr, len: usize) -> Result<VmReader<'_, Fallible>> {
        if current_page_table_paddr() != self.page_table()?.root_paddr()
            || !super::is_in_user_space(vaddr, len)
        {
            return Err(Error::AccessDenied);
        }

        // SAFETY: The memory range is in user space, as checked above.
        Ok(unsafe { VmReader::<Fallible>::from_user_space(vaddr as *const u8, len) })
    }

    /// Creates a writer to write data into the user space.
    ///
    /// Returns `Err` if this `VmSpace` doesn't belong to the user space of the current task
    /// or the `vaddr` and `len` do not represent a user space memory range.
    ///
    /// Users must ensure that no other page table is activated in the current task during the
    /// lifetime of the created `VmWriter`. This guarantees that the `VmWriter` can operate correctly.
    pub fn writer(&self, vaddr: Vaddr, len: usize) -> Result<VmWriter<'_, Fallible>> {
        if current_page_table_paddr() != self.page_table()?.root_paddr()
            || !super::is_in_user_space(vaddr, len)
        {
            return Err(Error::AccessDenied);
        }

        // `VmWriter` is neither `Sync` nor `Send`, so it will not live longer than the current
        // task. This ensures that the correct page table is activated during the usage period of
        // the `VmWriter`.
        //
        // SAFETY: The memory range is in user space, as checked above.
        Ok(unsafe { VmWriter::<Fallible>::from_user_space(vaddr as *mut u8, len) })
    }

    /// Creates a reader/writer pair to read data from and write data into the user space.
    ///
    /// Returns `Err` if this `VmSpace` doesn't belong to the user space of the current task
    /// or the `vaddr` and `len` do not represent a user space memory range.
    ///
    /// Users must ensure that no other page table is activated in the current task during the
    /// lifetime of the created `VmReader` and `VmWriter`. This guarantees that the `VmReader`
    /// and the `VmWriter` can operate correctly.
    ///
    /// This method is semantically equivalent to calling [`Self::reader`] and [`Self::writer`]
    /// separately, but it avoids double checking the validity of the memory region.
    pub fn reader_writer(
        &self,
        vaddr: Vaddr,
        len: usize,
    ) -> Result<(VmReader<'_, Fallible>, VmWriter<'_, Fallible>)> {
        if current_page_table_paddr() != self.page_table()?.root_paddr()
            || !super::is_in_user_space(vaddr, len)
        {
            return Err(Error::AccessDenied);
        }

        // SAFETY: The memory range is in user space, as checked above.
        let reader = unsafe { VmReader::<Fallible>::from_user_space(vaddr as *const u8, len) };

        // `VmWriter` is neither `Sync` nor `Send`, so it will not live longer than the current
        // task. This ensures that the correct page table is activated during the usage period of
        // the `VmWriter`.
        //
        // SAFETY: The memory range is in user space, as checked above.
        let writer = unsafe { VmWriter::<Fallible>::from_user_space(vaddr as *mut u8, len) };

        Ok((reader, writer))
    }
}

impl Default for VmSpace {
    fn default() -> Self {
        Self::new()
    }
}

impl VmSpace {
    /// Finds the [`IoMem`] that contains the given physical address.
    ///
    /// It is a private method for internal use only. Please refer to
    /// [`CursorMut::find_iomem_by_paddr`] for more details.
    fn find_iomem_by_paddr(&self, paddr: Paddr) -> Option<(IoMem, usize)> {
        let iomems = self.iomems.lock();
        for iomem in iomems.iter() {
            let start = iomem.paddr();
            let end = start + iomem.size();
            if paddr >= start && paddr < end {
                let offset = paddr - start;
                return Some((iomem.clone(), offset));
            }
        }
        None
    }
}

/// The cursor for querying over the VM space without modifying it.
///
/// It exclusively owns a sub-tree of the page table, preventing others from
/// reading or modifying the same sub-tree. Two read-only cursors can not be
/// created from the same virtual address range either.
pub struct Cursor<'a>(page_table::Cursor<'a, UserPtConfig>);

impl Cursor<'_> {
    /// Queries the mapping at the current virtual address.
    ///
    /// If the cursor is pointing to a valid virtual address that is locked,
    /// it will return the virtual address range and the mapped item.
    pub fn query(&mut self) -> Result<(Range<Vaddr>, Option<VmQueriedItem<'_>>)> {
        let (range, item) = self.0.query()?;
        Ok((range, item.map(VmQueriedItem::from)))
    }

    /// Moves the cursor forward to the next mapped virtual address.
    ///
    /// If there is mapped virtual address following the current address within
    /// next `len` bytes, it will return that mapped address. In this case,
    /// the cursor will stop at the mapped address.
    ///
    /// Otherwise, it will return `None`. And the cursor may stop at any
    /// address after `len` bytes.
    ///
    /// # Panics
    ///
    /// Panics if:
    ///  - the length is longer than the remaining range of the cursor;
    ///  - the length is not page-aligned.
    pub fn find_next(&mut self, len: usize) -> Option<Vaddr> {
        self.0.find_next(len)
    }

    /// Jumps to the virtual address.
    ///
    /// If the target address is out of the range, this method will return `Err`.
    ///
    /// # Panics
    ///
    /// This method panics if the address has bad alignment.
    pub fn jump(&mut self, va: Vaddr) -> Result<()> {
        self.0.jump(va)?;
        Ok(())
    }

    /// Gets the virtual address of the current slot.
    pub fn virt_addr(&self) -> Vaddr {
        self.0.virt_addr()
    }
}

/// The cursor for modifying the mappings in VM space.
///
/// It exclusively owns a sub-tree of the page table, preventing others from
/// reading or modifying the same sub-tree.
pub struct CursorMut<'a> {
    pt_cursor: page_table::CursorMut<'a, UserPtConfig>,
    // We have a read lock so the CPU set in the flusher is always a superset
    // of actual activated CPUs.
    flusher: TlbFlusher<'a, DisabledPreemptGuard>,
    // References to the `VmSpace`
    vmspace: &'a VmSpace,
}

impl<'a> CursorMut<'a> {
    /// Queries the mapping at the current virtual address.
    ///
    /// This is the same as [`Cursor::query`].
    ///
    /// If the cursor is pointing to a valid virtual address that is locked,
    /// it will return the virtual address range and the mapped item.
    pub fn query(&mut self) -> Result<(Range<Vaddr>, Option<VmQueriedItem<'_>>)> {
        let (range, item) = self.pt_cursor.query()?;
        Ok((range, item.map(VmQueriedItem::from)))
    }

    /// Moves the cursor forward to the next mapped virtual address.
    ///
    /// This is the same as [`Cursor::find_next`].
    pub fn find_next(&mut self, len: usize) -> Option<Vaddr> {
        self.pt_cursor.find_next(len)
    }

    /// Jumps to the virtual address.
    ///
    /// This is the same as [`Cursor::jump`].
    ///
    /// # Panics
    ///
    /// This method panics if the address has bad alignment.
    pub fn jump(&mut self, va: Vaddr) -> Result<()> {
        self.pt_cursor.jump(va)?;
        Ok(())
    }

    /// Gets the virtual address of the current slot.
    pub fn virt_addr(&self) -> Vaddr {
        self.pt_cursor.virt_addr()
    }

    /// Gets the dedicated TLB flusher for this cursor.
    pub fn flusher(&mut self) -> &mut TlbFlusher<'a, DisabledPreemptGuard> {
        &mut self.flusher
    }

    /// Maps a frame into the current slot.
    ///
    /// This method will bring the cursor to the next slot after the modification.
    ///
    /// # Panics
    ///
    /// Panics if:
    ///  - the current virtual address is already mapped;
    ///  - the current virtual address is outside the cursor's range.
    pub fn map(&mut self, frame: UFrame, prop: PageProperty) {
        let item = VmItem::new_tracked(frame, prop);

        // SAFETY: It is safe to map untyped memory into the userspace.
        unsafe { self.pt_cursor.map(item) };
    }

    /// Maps a range of [`IoMem`] into the current slot.
    ///
    /// The memory region to be mapped is the [`IoMem`] range starting at
    /// `offset` and extending to `offset + len`, or to the end of [`IoMem`],
    /// whichever comes first. This method will bring the cursor to the next
    /// slot after the modification.
    ///
    /// # Limitations
    ///
    /// Once an instance of `IoMem` is mapped to a `VmSpace`,
    /// then the `IoMem` instance will only be dropped when the `VmSpace` is
    /// dropped, not when all the mappings backed by the `IoMem` are destroyed
    /// with the `unmap` method.
    ///
    /// # Panics
    ///
    /// Panics if
    ///  - `len`, `offset`, or the address range of the `IoMem` instance is
    ///    not aligned to the page size;
    ///  - the current virtual address is already mapped.
    pub fn map_iomem(&mut self, io_mem: IoMem, prop: PageProperty, len: usize, offset: usize) {
        assert_eq!(len % PAGE_SIZE, 0);
        assert_eq!(offset % PAGE_SIZE, 0);

        let io_mem_paddr = io_mem.paddr();
        let io_mem_size = io_mem.size();
        assert_eq!(io_mem_paddr % PAGE_SIZE, 0);
        assert_eq!(io_mem_size % PAGE_SIZE, 0);

        if offset >= io_mem_size {
            return;
        }

        let paddr_begin = io_mem_paddr + offset;
        let paddr_end = if io_mem_size - offset < len {
            io_mem_paddr + io_mem_size
        } else {
            io_mem_paddr + len + offset
        };

        for current_paddr in (paddr_begin..paddr_end).step_by(PAGE_SIZE) {
            // SAFETY: It is safe to map I/O memory into the userspace.
            unsafe {
                self.pt_cursor
                    .map(VmItem::new_untracked_io(current_paddr, prop))
            };
        }

        fn io_mem_contains(parent: &IoMem, child: &IoMem) -> bool {
            parent.paddr() <= child.paddr() && child.end_paddr() <= parent.end_paddr()
        }

        // If the `iomems` list in `VmSpace` does not contain the current I/O
        // memory, push it to maintain the correct reference count.
        let mut iomems = self.vmspace.iomems.lock();
        if !iomems.iter().any(|iomem| io_mem_contains(iomem, &io_mem)) {
            iomems.retain(|iomem| !io_mem_contains(&io_mem, iomem));
            iomems.push(io_mem);
        }
    }

    /// Finds an [`IoMem`] that was previously mapped to by [`Self::map_iomem`] and contains the
    /// physical address.
    ///
    /// This method can recover the originally mapped `IoMem` from the physical address returned by
    /// [`Self::query`]. If the query returns a [`VmQueriedItem::MappedIoMem`], this method is
    /// guaranteed to succeed with the specific physical address. However, if the corresponding
    /// mapping is subsequently unmapped, it is unspecified whether this method will still succeed
    /// or not.
    ///
    /// On success, this method returns the `IoMem` and the offset from the `IoMem` start to the
    /// given physical address. Otherwise, this method returns `None`.
    pub fn find_iomem_by_paddr(&self, paddr: Paddr) -> Option<(IoMem, usize)> {
        self.vmspace.find_iomem_by_paddr(paddr)
    }

    /// Clears the mapping starting from the current slot,
    /// and returns the number of unmapped pages.
    ///
    /// This method will bring the cursor forward by at least `len` bytes
    /// in the virtual address space, but not past the end of the cursor's range.
    ///
    /// Already-absent mappings encountered by the cursor will be skipped. It
    /// is valid to unmap a range that is not mapped.
    ///
    /// It must issue and dispatch a TLB flush after the operation. Otherwise,
    /// the memory safety will be compromised. Please call this function less
    /// to avoid the overhead of TLB flush. Using a large `len` is wiser than
    /// splitting the operation into multiple small ones.
    ///
    /// # Panics
    ///
    /// Panics if:
    ///  - the length is longer than the remaining range of the cursor;
    ///  - the length is not page-aligned.
    pub fn unmap(&mut self, len: usize) -> usize {
        let end_va = self.virt_addr() + len;
        let mut num_unmapped: usize = 0;
        loop {
            // SAFETY:
            // 1. It is safe to unmap memory in the userspace.
            // 2. We drop the unmapped items only after flushing TLB entries, which is safe.
            let Some(frag) = (unsafe { self.pt_cursor.take_next(end_va - self.virt_addr()) })
            else {
                break; // No more mappings in the range.
            };

            match frag {
                PageTableFrag::Mapped { va, item, .. } => {
                    // SAFETY: If the item is not a scalar (e.g., a frame
                    // pointer), we will drop it after the RCU grace period
                    // (see `issue_tlb_flush_with`).
                    let (item, panic_guard) = unsafe { RcuDrop::into_inner(item) };

                    match item {
                        VmItem {
                            mapped_item: MappedItem::TrackedFrame(old_frame),
                            ..
                        } => {
                            num_unmapped += 1;

                            let rcu_frame = RcuDrop::new(old_frame);
                            panic_guard.forget();
                            let rcu_frame = Frame::rcu_from_unsized(rcu_frame);
                            self.flusher
                                .issue_tlb_flush_with(TlbFlushOp::for_single(va), rcu_frame);
                        }
                        VmItem {
                            mapped_item: MappedItem::UntrackedIoMem { .. },
                            ..
                        } => {
                            panic_guard.forget();

                            // Flush the TLB entry for the current address, but
                            // in the current design, we cannot drop the
                            // corresponding `IoMem`. This is because we manage
                            // the range of I/O as a whole, but the frames
                            // handled here might be one segment of it.
                            self.flusher.issue_tlb_flush(TlbFlushOp::for_single(va));
                        }
                    }
                }
                PageTableFrag::StrayPageTable {
                    pt,
                    va,
                    len,
                    num_frames,
                } => {
                    num_unmapped += num_frames;

                    self.flusher.issue_tlb_flush_with(
                        TlbFlushOp::for_range(va..va + len),
                        Frame::rcu_from_unsized(pt),
                    );
                }
            }
        }

        self.flusher.dispatch_tlb_flush();

        num_unmapped
    }

    /// Applies the operation to the next slot of mapping within the range.
    ///
    /// The range to be found in is the current virtual address with the
    /// provided length.
    ///
    /// The function stops and yields the actually protected range if it has
    /// actually protected a page, no matter if the following pages are also
    /// required to be protected.
    ///
    /// It also makes the cursor moves forward to the next page after the
    /// protected one. If no mapped pages exist in the following range, the
    /// cursor will stop at the end of the range and return [`None`].
    ///
    /// Note that it will **NOT** flush the TLB after the operation. Please
    /// make the decision yourself on when and how to flush the TLB using
    /// [`Self::flusher`].
    ///
    /// # Panics
    ///
    /// Panics if:
    ///  - the length is longer than the remaining range of the cursor;
    ///  - the length is not page-aligned.
    pub fn protect_next(
        &mut self,
        len: usize,
        mut op: impl FnMut(&mut PageFlags, &mut CachePolicy),
    ) -> Option<Range<Vaddr>> {
        // SAFETY: It is safe to set `PageFlags` and `CachePolicy` of memory
        // in the userspace.
        unsafe {
            self.pt_cursor.protect_next(len, &mut |prop| {
                op(&mut prop.flags, &mut prop.cache);
            })
        }
    }
}

cpu_local_cell! {
    /// The `Arc` pointer to the activated VM space on this CPU. If the pointer
    /// is NULL, it means that the activated page table is merely the kernel
    /// page table.
    // TODO: If we are enabling ASID, we need to maintain the TLB state of each
    // CPU, rather than merely the activated `VmSpace`. When ASID is enabled,
    // the non-active `VmSpace`s can still have their TLB entries in the CPU!
    static ACTIVATED_VM_SPACE: *const VmSpace = core::ptr::null();
}

#[cfg(ktest)]
pub(super) fn get_activated_vm_space() -> *const VmSpace {
    ACTIVATED_VM_SPACE.load()
}

#[cfg(all(ktest, not(feature = "kernelet")))]
mod native_activation_test {
    use super::{VmSpace, get_activated_vm_space};
    use crate::{arch::mm::current_page_table_paddr, prelude::*, task::disable_preempt};

    #[ktest]
    fn native_roots_release_cpu_references_after_switch_and_deactivate() {
        let first = Arc::new(VmSpace::new());
        let second = Arc::new(VmSpace::new());
        let first_table = first.page_table().unwrap();
        let second_table = second.page_table().unwrap();
        let _guard = disable_preempt();
        VmSpace::deactivate();
        let first_refs = first_table.root_reference_count();
        let second_refs = second_table.root_reference_count();
        for _ in 0..3 {
            first.activate();
            first.activate();
            assert_eq!(current_page_table_paddr(), first_table.root_paddr());
            assert_eq!(first_table.root_reference_count(), first_refs + 1);
            second.activate();
            assert_eq!(current_page_table_paddr(), second_table.root_paddr());
            assert_eq!(first_table.root_reference_count(), first_refs);
            assert_eq!(second_table.root_reference_count(), second_refs + 1);
            VmSpace::deactivate();
            VmSpace::deactivate();
            assert!(get_activated_vm_space().is_null());
            assert_eq!(first_table.root_reference_count(), first_refs);
            assert_eq!(second_table.root_reference_count(), second_refs);
            assert_eq!(Arc::strong_count(&first), 1);
            assert_eq!(Arc::strong_count(&second), 1);
        }
    }
}

#[cfg(all(ktest, feature = "kernelet-host"))]
mod activation_test {
    use core::sync::atomic::Ordering;

    use super::{RegisteredPageTable, RootShootdown, VmSpace, get_activated_vm_space};
    use crate::{
        arch::mm::current_page_table_paddr,
        cpu::PinCurrentCpu,
        mm::PAGE_SIZE,
        prelude::*,
        sync::{LocalIrqDisabled, SpinLock},
        task::disable_preempt,
    };

    #[ktest]
    fn direct_root_switch_preserves_reservations_and_failure_state() {
        let owners = [Arc::new(VmSpace::new()), Arc::new(VmSpace::new())];
        let first = RegisteredPageTable::new(owners[0].page_table().unwrap().root_paddr()).unwrap();
        let second =
            RegisteredPageTable::new(owners[1].page_table().unwrap().root_paddr()).unwrap();
        let retired_owner = Arc::new(VmSpace::new());
        let retired =
            RegisteredPageTable::new(retired_owner.page_table().unwrap().root_paddr()).unwrap();
        retired.invalidate();
        let carrier = Arc::new(VmSpace::new_activation_only());
        let _pin = disable_preempt();
        let guard = crate::irq::disable_local();
        let cpu = guard.current_cpu();
        VmSpace::deactivate();
        let host_root = current_page_table_paddr();
        let references = Arc::strong_count(&carrier);
        assert!(carrier.activate_registered_root(first.clone(), &guard));
        assert_eq!(first.last_direct_activation_from(), host_root);
        assert_eq!(current_page_table_paddr(), first.paddr);
        assert!(first.is_active_on(cpu));
        assert_eq!(Arc::strong_count(&carrier), references + 1);

        // A shootdown published while B is absent must be observed by the
        // single direct CR3 commit, without first switching to HostRoot.
        let generation = second.begin_shootdown().unwrap();
        assert!(generation.active.is_empty());
        assert!(carrier.activate_registered_root(second.clone(), &guard));
        assert_eq!(second.last_direct_activation_from(), first.paddr);
        assert_eq!(current_page_table_paddr(), second.paddr);
        assert!(!first.is_active_on(cpu));
        assert!(second.is_active_on(cpu));
        assert_eq!(get_activated_vm_space(), Arc::as_ptr(&carrier));
        assert_eq!(Arc::strong_count(&carrier), references + 1);
        {
            let state = second.state.lock();
            assert_eq!(
                state.seen_generation[u32::from(cpu) as usize],
                state.generation
            );
        }
        assert_eq!(Arc::strong_count(&first), 1);
        assert_eq!(Arc::strong_count(&second), 2);

        // Same-token activation must not clear the newly installed active bit.
        assert!(carrier.activate_registered_root(second.clone(), &guard));
        assert_eq!(second.last_direct_activation_from(), second.paddr);
        assert!(second.is_active_on(cpu));
        assert_eq!(Arc::strong_count(&carrier), references + 1);
        assert!(!carrier.activate_registered_root(retired, &guard));
        assert_eq!(current_page_table_paddr(), second.paddr);
        assert!(second.is_active_on(cpu));
        assert_eq!(Arc::strong_count(&carrier), references + 1);
        assert!(Arc::ptr_eq(
            carrier
                .activation
                .as_ref()
                .unwrap()
                .root
                .lock()
                .as_ref()
                .unwrap(),
            &second,
        ));
        VmSpace::deactivate();
        assert_eq!(current_page_table_paddr(), host_root);
        assert!(!second.is_active_on(cpu));
        assert_eq!(Arc::strong_count(&carrier), references);
        carrier.set_registered_root(None);
        first.invalidate();
        second.invalidate();
    }

    static REMOTE_ROOT: SpinLock<Option<Arc<RegisteredPageTable>>, LocalIrqDisabled> =
        SpinLock::new(None);
    static REMOTE_SHOOTDOWN: SpinLock<Option<RootShootdown>, LocalIrqDisabled> =
        SpinLock::new(None);
    static REMOTE_CPU: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(u32::MAX);

    fn publish_remote_shootdown() {
        let root = REMOTE_ROOT.lock().as_ref().unwrap().clone();
        let shootdown = root.begin_shootdown().unwrap();
        REMOTE_CPU.store(
            u32::from(crate::cpu::CpuId::current_racy()),
            Ordering::Relaxed,
        );
        *REMOTE_SHOOTDOWN.lock() = Some(shootdown);
    }

    #[ktest]
    fn direct_root_switch_serializes_with_remote_shootdown_publication() {
        let pin = disable_preempt();
        let cpu = pin.current_cpu();
        let Some(remote) = crate::cpu::all_cpus().find(|other| *other != cpu) else {
            crate::early_println!("[skipped: remote root switch requires two CPUs]");
            return;
        };
        let owners = [Arc::new(VmSpace::new()), Arc::new(VmSpace::new())];
        let roots = [
            RegisteredPageTable::new(owners[0].page_table().unwrap().root_paddr()).unwrap(),
            RegisteredPageTable::new(owners[1].page_table().unwrap().root_paddr()).unwrap(),
        ];
        let carrier = Arc::new(VmSpace::new_activation_only());
        {
            let guard = crate::irq::disable_local();
            VmSpace::deactivate();
            assert!(carrier.activate_registered_root(roots[0].clone(), &guard));
        }
        for iteration in 0..32 {
            let next = &roots[(iteration + 1) % 2];
            let old = &roots[iteration % 2];
            *REMOTE_ROOT.lock() = Some(next.clone());
            let pending =
                crate::smp::inter_processor_call(&remote.into(), publish_remote_shootdown);
            {
                let guard = crate::irq::disable_local();
                assert!(carrier.activate_registered_root(next.clone(), &guard));
                assert_eq!(next.last_direct_activation_from(), old.paddr);
                assert_eq!(current_page_table_paddr(), next.paddr);
                assert!(!old.is_active_on(cpu));
                assert!(next.is_active_on(cpu));
            }
            pending.wait();
            assert_eq!(REMOTE_CPU.load(Ordering::Relaxed), u32::from(remote));
            let shootdown = REMOTE_SHOOTDOWN.lock().take().unwrap();
            {
                let state = next.state.lock();
                if !shootdown.active.contains(cpu) {
                    // Publication preceded activation: the CR3 write must
                    // already have observed that generation.
                    assert_eq!(
                        state.seen_generation[u32::from(cpu) as usize],
                        state.generation
                    );
                }
            }
            // If publication followed activation, the snapshot contains this
            // CPU and a real flush/ack is required before old frames retire.
            crate::mm::tlb::dispatch_tlb_flush_on_cpus(
                &shootdown.active,
                crate::mm::tlb::TlbFlushOp::for_all(),
                #[cfg(kernelet_rq1_diagnostics)]
                None,
            )
            .wait();
            assert!(next.is_active_on(cpu));
        }
        VmSpace::deactivate();
        carrier.set_registered_root(None);
        *REMOTE_ROOT.lock() = None;
        assert!(REMOTE_SHOOTDOWN.lock().is_none());
        for root in roots {
            assert!(!root.is_active());
            root.invalidate();
        }
    }

    #[ktest]
    fn native_reactivation_after_kernel_boundary_releases_cpu_references() {
        let space = Arc::new(VmSpace::new());
        let table = space.page_table().unwrap();
        let _guard = disable_preempt();
        VmSpace::deactivate();
        let references = table.root_reference_count();
        for _ in 0..3 {
            space.activate();
            assert_eq!(table.root_reference_count(), references + 1);
            {
                let _irq_guard = crate::irq::disable_local();
                // The carrier boundary installs the permanent root and clears
                // the software identity before any fixed stub borrows CR3.
                VmSpace::deactivate();
                assert!(get_activated_vm_space().is_null());
                assert_eq!(Arc::strong_count(&space), 1);
                assert_eq!(table.root_reference_count(), references);
                assert_eq!(current_page_table_paddr(), VmSpace::kernel_root_paddr());
                space.activate();
                assert_eq!(current_page_table_paddr(), table.root_paddr());
                assert_eq!(table.root_reference_count(), references + 1);
            }
            VmSpace::deactivate();
            assert_eq!(table.root_reference_count(), references);
        }
    }

    #[ktest]
    fn native_activation_does_not_drop_a_borrowed_tenant_root() {
        let owner = Arc::new(VmSpace::new());
        let owner_table = owner.page_table().unwrap();
        let root = RegisteredPageTable::new(owner_table.root_paddr()).unwrap();
        let carrier = Arc::new(VmSpace::new_activation_only());
        carrier.set_registered_root(Some(root.clone()));
        let native = Arc::new(VmSpace::new());
        let _guard = disable_preempt();
        let _irq_guard = crate::irq::disable_local();
        let references = owner_table.root_reference_count();
        assert!(carrier.prepare_registered_root(root.paddr, &_irq_guard));
        carrier.activate();
        assert_eq!(owner_table.root_reference_count(), references);

        native.activate();
        assert_eq!(owner_table.root_reference_count(), references);
        assert!(!root.is_active());
        VmSpace::deactivate();
        assert_eq!(owner_table.root_reference_count(), references);
        carrier.set_registered_root(None);
        root.invalidate();
    }

    #[ktest]
    fn registered_root_restores_and_releases_cpu_reference() {
        let owner = Arc::new(VmSpace::new());
        let root = owner.page_table().unwrap().root_paddr();
        let table = RegisteredPageTable::new(root).unwrap();
        let carrier = Arc::new(VmSpace::new_activation_only());
        carrier.set_registered_root(Some(table.clone()));
        let guard = disable_preempt();
        let cpu = guard.current_cpu();
        let _irq_guard = crate::irq::disable_local();
        VmSpace::deactivate();
        let host_root = current_page_table_paddr();
        let references = Arc::strong_count(&carrier);

        assert!(carrier.prepare_registered_root(root, &_irq_guard));
        assert_eq!(current_page_table_paddr(), host_root);
        assert!(table.is_active_on(cpu));
        assert_eq!(Arc::strong_count(&carrier), references + 1);
        assert!(table.begin_shootdown().unwrap().active.contains(cpu));
        // Preparing again before the fixed CR3 commit retains the reservation
        // without acknowledging a shootdown that has not dispatched its IPI.
        let reserved_generation = table.state.lock().seen_generation[u32::from(cpu) as usize];
        assert!(carrier.prepare_registered_root(root, &_irq_guard));
        assert_eq!(current_page_table_paddr(), host_root);
        assert_eq!(Arc::strong_count(&carrier), references + 1);
        assert!(table.is_active_on(cpu));
        {
            let state = table.state.lock();
            assert_eq!(
                state.seen_generation[u32::from(cpu) as usize],
                reserved_generation
            );
            assert_ne!(reserved_generation, state.generation);
        }

        carrier.activate();
        assert_eq!(current_page_table_paddr(), root);
        assert_eq!(get_activated_vm_space(), Arc::as_ptr(&carrier));
        assert_eq!(Arc::strong_count(&carrier), references + 1);

        assert!(carrier.prepare_registered_root(root, &_irq_guard));
        assert_eq!(current_page_table_paddr(), root);

        // Repeated preparation must retain the tenant root and CPU reference,
        // including when a shootdown published a new generation meanwhile.
        let installed_generation = table.state.lock().seen_generation[u32::from(cpu) as usize];
        assert!(table.begin_shootdown().unwrap().active.contains(cpu));
        assert!(carrier.prepare_registered_root(root, &_irq_guard));
        {
            let state = table.state.lock();
            assert_eq!(
                state.seen_generation[u32::from(cpu) as usize],
                installed_generation
            );
            assert_ne!(installed_generation, state.generation);
        }
        assert_eq!(current_page_table_paddr(), root);
        assert!(table.is_active_on(cpu));
        assert_eq!(get_activated_vm_space(), Arc::as_ptr(&carrier));
        assert_eq!(Arc::strong_count(&carrier), references + 1);
        // Execute the real flush callback and wait for its acknowledgement.
        // The active reservation must survive both dispatch and preparation;
        // only a fresh reservation records a newly observed generation.
        let shootdown = table.begin_shootdown().unwrap();
        assert!(shootdown.active.contains(cpu));
        // The outer preemption guard retains this CPU; waiting for remote
        // acknowledgements requires restoring physical IRQ delivery.
        drop(_irq_guard);
        crate::mm::tlb::dispatch_tlb_flush_on_cpus(
            &shootdown.active,
            crate::mm::tlb::TlbFlushOp::for_all(),
            #[cfg(kernelet_rq1_diagnostics)]
            None,
        )
        .wait();
        let _irq_guard = crate::irq::disable_local();
        assert!(carrier.prepare_registered_root(root, &_irq_guard));
        assert_eq!(current_page_table_paddr(), root);
        assert!(table.is_active_on(cpu));
        {
            let state = table.state.lock();
            assert_eq!(
                state.seen_generation[u32::from(cpu) as usize],
                installed_generation
            );
            assert_ne!(installed_generation, state.generation);
        }
        VmSpace::deactivate();
        assert_eq!(current_page_table_paddr(), host_root);
        assert!(!table.is_active_on(cpu));
        assert!(get_activated_vm_space().is_null());
        assert_eq!(Arc::strong_count(&carrier), references);

        // The active CPU's generation publication above did not dispatch an
        // IPI. After leaving, a new reservation must observe that generation
        // before the fixed entry installs the root again.
        assert!(carrier.prepare_registered_root(root, &_irq_guard));
        assert_eq!(current_page_table_paddr(), host_root);
        assert!(table.is_active_on(cpu));
        assert_eq!(get_activated_vm_space(), Arc::as_ptr(&carrier));
        assert_eq!(Arc::strong_count(&carrier), references + 1);
        {
            let state = table.state.lock();
            assert_eq!(
                state.seen_generation[u32::from(cpu) as usize],
                state.generation
            );
        }
        VmSpace::deactivate();
        assert_eq!(current_page_table_paddr(), host_root);
        assert!(!table.is_active_on(cpu));
        assert!(get_activated_vm_space().is_null());
        assert_eq!(Arc::strong_count(&carrier), references);
        carrier.set_registered_root(None);
        table.invalidate();
    }

    #[ktest]
    fn activation_only_space_rejects_walks_and_retired_roots() {
        let owner = Arc::new(VmSpace::new());
        let table = RegisteredPageTable::new(owner.page_table().unwrap().root_paddr()).unwrap();
        let carrier = Arc::new(VmSpace::new_activation_only());
        carrier.set_registered_root(Some(table.clone()));
        let guard = disable_preempt();
        assert!(carrier.cursor(&guard, &(0..PAGE_SIZE)).is_err());
        assert!(carrier.cursor_mut(&guard, &(0..PAGE_SIZE)).is_err());
        assert!(carrier.reader(0, 1).is_err());
        assert!(carrier.writer(0, 1).is_err());

        let _irq_guard = crate::irq::disable_local();
        VmSpace::deactivate();
        let host_root = current_page_table_paddr();
        table.invalidate();
        // SAFETY: The native owner retains this page table and its Host kernel
        // mappings. Matching its hardware address must not revive the retired
        // registration token or establish a carrier CPU reference.
        unsafe { crate::arch::mm::activate_page_table(table.paddr) };
        assert!(!carrier.prepare_registered_root(table.paddr, &_irq_guard));
        assert_eq!(current_page_table_paddr(), host_root);
        assert!(get_activated_vm_space().is_null());
        carrier.set_root_restore(true);
        carrier.activate();
        assert_eq!(current_page_table_paddr(), host_root);
        assert!(get_activated_vm_space().is_null());
        carrier.set_registered_root(None);
    }
}

/// The result of a query over the VM space.
pub enum VmQueriedItem<'a> {
    /// The current slot is mapped, the frame within is allocated from the
    /// physical memory.
    MappedRam {
        /// The mapped frame.
        frame: FrameRef<'a, dyn AnyUFrameMeta>,
        /// The property of the slot.
        prop: PageProperty,
    },
    /// The current slot is mapped, the frame within is allocated from the
    /// MMIO memory.
    MappedIoMem {
        /// The physical address of the corresponding I/O memory.
        paddr: Paddr,
        /// The property of the slot.
        prop: PageProperty,
    },
}

impl VmQueriedItem<'_> {
    /// Returns the page property of the mapped item.
    pub fn prop(&self) -> &PageProperty {
        match self {
            Self::MappedRam { prop, .. } => prop,
            Self::MappedIoMem { prop, .. } => prop,
        }
    }
}

/// Internal representation of a VM item.
///
/// This is kept private to ensure memory safety. The public interface
/// should use `VmQueriedItem` for querying mapping information.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct VmItem {
    prop: PageProperty,
    mapped_item: MappedItem,
}

/// A reference to a VM item.
#[derive(Debug)]
pub(crate) struct VmItemRef<'a> {
    prop: PageProperty,
    mapped_item: MappedItemRef<'a>,
}

#[derive(Clone, Debug, PartialEq)]
enum MappedItem {
    TrackedFrame(UFrame),
    UntrackedIoMem { paddr: Paddr, level: PagingLevel },
}

#[derive(Debug)]
enum MappedItemRef<'a> {
    TrackedFrame(FrameRef<'a, dyn AnyUFrameMeta>),
    UntrackedIoMem { paddr: Paddr, level: PagingLevel },
}

impl VmItem {
    /// Creates a new `VmItem` that maps a tracked frame.
    pub(super) fn new_tracked(frame: UFrame, prop: PageProperty) -> Self {
        Self {
            prop,
            mapped_item: MappedItem::TrackedFrame(frame),
        }
    }

    /// Creates a new `VmItem` that maps an untracked I/O memory.
    fn new_untracked_io(paddr: Paddr, prop: PageProperty) -> Self {
        Self {
            prop,
            mapped_item: MappedItem::UntrackedIoMem { paddr, level: 1 },
        }
    }
}

impl<'a> From<VmItemRef<'a>> for VmQueriedItem<'a> {
    fn from(item: VmItemRef<'a>) -> Self {
        match item.mapped_item {
            MappedItemRef::TrackedFrame(frame) => VmQueriedItem::MappedRam {
                frame,
                prop: item.prop,
            },
            MappedItemRef::UntrackedIoMem { paddr, level } => {
                debug_assert_eq!(level, 1);
                VmQueriedItem::MappedIoMem {
                    paddr,
                    prop: item.prop,
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct UserPtConfig {}

// SAFETY: `item_raw_info`, `item_into_raw`, `item_from_raw`, and
// `item_ref_from_raw` are correctly implemented with respect to the `Item` and
// `ItemRef` types.
unsafe impl PageTableConfig for UserPtConfig {
    const TOP_LEVEL_INDEX_RANGE: Range<usize> = 0..256;

    type E = PageTableEntry;
    type C = PagingConsts;

    type Item = VmItem;
    type ItemRef<'a> = VmItemRef<'a>;

    fn item_raw_info(item: &Self::Item) -> (Paddr, PagingLevel, PageProperty) {
        match &item.mapped_item {
            MappedItem::TrackedFrame(frame) => {
                let mut prop = item.prop;
                prop.priv_flags -= PrivilegedPageFlags::AVAIL1; // Clear AVAIL1 for tracked frames
                let level = frame.map_level();
                let paddr = frame.paddr();
                (paddr, level, prop)
            }
            MappedItem::UntrackedIoMem { paddr, level } => {
                let mut prop = item.prop;
                prop.priv_flags |= PrivilegedPageFlags::AVAIL1; // Set AVAIL1 for I/O memory
                (*paddr, *level, prop)
            }
        }
    }

    unsafe fn item_from_raw(paddr: Paddr, level: PagingLevel, prop: PageProperty) -> Self::Item {
        debug_assert_eq!(level, 1);
        if prop.priv_flags.contains(PrivilegedPageFlags::AVAIL1) {
            // `AVAIL1` is set, this is I/O memory.
            VmItem::new_untracked_io(paddr, prop)
        } else {
            // `AVAIL1` is clear, this is tracked memory.
            // SAFETY: The caller ensures safety.
            let frame = unsafe { Frame::<dyn AnyUFrameMeta>::from_raw(paddr) };
            VmItem::new_tracked(frame, prop)
        }
    }

    unsafe fn item_ref_from_raw<'a>(
        paddr: Paddr,
        level: PagingLevel,
        prop: PageProperty,
    ) -> Self::ItemRef<'a> {
        debug_assert_eq!(level, 1);
        if prop.priv_flags.contains(PrivilegedPageFlags::AVAIL1) {
            // `AVAIL1` is set, this is I/O memory.
            VmItemRef {
                prop,
                mapped_item: MappedItemRef::UntrackedIoMem { paddr, level },
            }
        } else {
            // `AVAIL1` is clear, this is tracked memory.
            // SAFETY: The caller ensures that the frame outlives `'a` and that
            // the type matches the frame.
            let frame_ref = unsafe { FrameRef::<dyn AnyUFrameMeta>::borrow_paddr(paddr) };
            VmItemRef {
                prop,
                mapped_item: MappedItemRef::TrackedFrame(frame_ref),
            }
        }
    }
}
