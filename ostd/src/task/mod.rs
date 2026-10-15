// SPDX-License-Identifier: MPL-2.0

//! Tasks are the unit of code execution.

#[cfg(any(feature = "kernelet-host", feature = "kernelet", kernelet_rq1, ktest))]
pub(crate) mod accounting;
pub mod atomic_mode;
#[cfg_attr(feature = "kernelet", path = "kernelet_stack.rs")]
pub(crate) mod kernel_stack;
mod preempt;

mod processor;
pub mod scheduler;
mod utils;

use core::{
    any::Any,
    borrow::Borrow,
    cell::{Cell, SyncUnsafeCell},
    ops::Deref,
    ptr::NonNull,
    sync::atomic::{AtomicBool, Ordering},
};
#[cfg(feature = "kernelet")]
use core::{
    cell::RefCell,
    sync::atomic::{AtomicU32, AtomicU64},
};

use kernel_stack::KernelStack;
#[cfg(all(target_arch = "x86_64", not(feature = "kernelet")))]
pub(crate) use preempt::check_preempt;
use processor::current_task;
use spin::Once;
use utils::ForceSync;

#[cfg(any(feature = "kernelet-host", feature = "kernelet", kernelet_rq1, ktest))]
pub use self::accounting::CpuTimeMeasurement;
pub use self::{
    preempt::{DisabledPreemptGuard, disable_preempt, halt_cpu},
    scheduler::info::{AtomicCpuId, TaskScheduleInfo},
};
use crate::{
    arch::task::TaskContext,
    irq::{DisabledLocalIrqGuard, InterruptLevel},
    prelude::*,
};

static PRE_SCHEDULE_HANDLER: Once<fn(&DisabledLocalIrqGuard)> = Once::new();

static POST_SCHEDULE_HANDLER: Once<fn()> = Once::new();

#[cfg(all(ktest, target_arch = "x86_64"))]
pub(crate) fn preempt_guard_count() -> u32 {
    preempt::cpu_local::get_guard_count()
}

/// Injects a handler to be executed before scheduling.
pub fn inject_pre_schedule_handler(handler: fn(&DisabledLocalIrqGuard)) {
    PRE_SCHEDULE_HANDLER.call_once(|| handler);
}

/// Injects a handler to be executed after scheduling.
pub fn inject_post_schedule_handler(handler: fn()) {
    POST_SCHEDULE_HANDLER.call_once(|| handler);
}

/// Ends the current Task using the normal return-path cleanup.
///
/// This never returns. The caller must release any owned resources on its
/// stack before calling it, because the stack will be discarded after switching.
pub(crate) fn exit_current_task() -> ! {
    #[cfg(feature = "kernelet")]
    crate::mm::VmSpace::deactivate();

    #[cfg(any(feature = "kernelet-host", ktest))]
    {
        let current_task = Task::current().expect("task exit requires a current Task");
        let _ = current_task.accounting.detach(None);
    }
    scheduler::exit_current();
}

/// Adopts this vCPU's live bootstrap stack as a one-shot current Task.
///
/// This Task never enters a runqueue: it runs initialization to completion,
/// then exits. It cannot yield, park, halt, run again, or be woken. IRQs remain
/// deliverable; only inner scheduling and RCU callback dispatch are deferred.
/// The caller must have initialized the allocator, CPU-local storage, and RCU,
/// and must still hold virtual IRQs disabled with no guard or deferral active.
#[cfg(feature = "kernelet")]
pub(crate) fn adopt_boot_task() {
    assert!(!crate::arch::irq::is_local_enabled());
    assert!(InterruptLevel::current().is_task_context());
    assert_eq!(preempt::cpu_local::get_guard_count(), 0);
    assert!(!virq_delivery_deferred());
    assert!(Task::current().is_none());

    let base = crate::kernelet::entry::vcpu_record()
        .stack_limit
        .load(Ordering::Acquire) as usize;
    assert!(base.is_multiple_of(crate::mm::PAGE_SIZE));
    let rsp: usize;
    // SAFETY: Reading RSP does not access memory or change execution state.
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags))
    };
    // SAFETY: Entry is executing on the Host-provided live boot slot. The
    // bounds below are checked before publishing its one-shot Task owner.
    let kstack = unsafe { KernelStack::adopt_boot(base) };
    assert!((base..kstack.end_vaddr()).contains(&rsp));

    let task = Arc::new(Task {
        func: ForceSync::new(Cell::new(None)),
        data: Box::new(()),
        local_data: ForceSync::new(Box::new(())),
        // The first ordinary context_switch writes this context. It is
        // never restored because a boot Task cannot be scheduled again.
        ctx: SyncUnsafeCell::new(TaskContext::new()),
        kstack,
        switched_to_cpu: AtomicBool::new(true),
        scheduling_in_progress: AtomicBool::new(false),
        virq_deferral_depth: AtomicU32::new(0),
        completed_virq_batches: AtomicU64::new(0),
        active_vm_space: ForceSync::new(RefCell::new(None)),
        schedule_info: TaskScheduleInfo {
            cpu: AtomicCpuId::default(),
        },
        accounting: accounting::TaskAccounting::new(),
        #[cfg(kernelet_rq1_diagnostics)]
        rq1_fpu_counters: crate::kernelet::fpu_profile::Counters::new(),
    });
    processor::adopt_current_boot_task(task);
}

/// Whether this vCPU is still executing its non-enqueued boot Task.
#[cfg(feature = "kernelet")]
pub(crate) fn in_boot_task() -> bool {
    preempt::cpu_local::in_boot_task()
}

/// A task that executes a function to the end.
///
/// Each task is associated with per-task data and an optional user space.
/// If having a user space, the task can switch to the user space to
/// execute user code. Multiple tasks can share a single user space.
#[derive(Debug)]
pub struct Task {
    #[expect(clippy::type_complexity)]
    func: ForceSync<Cell<Option<Box<dyn FnOnce() + Send>>>>,

    data: Box<dyn Any + Send + Sync>,
    local_data: ForceSync<Box<dyn Any + Send>>,

    ctx: SyncUnsafeCell<TaskContext>,
    /// kernel stack, note that the top is SyscallFrame/TrapFrame
    kstack: KernelStack,

    /// If we have switched this task to a CPU.
    ///
    /// This is to enforce not context switching to an already running task.
    /// See [`processor::switch_to_task`] for more details.
    switched_to_cpu: AtomicBool,

    /// Defers preemption from a scheduler decision until its context switch.
    scheduling_in_progress: AtomicBool,

    /// Defers virtual interrupt delivery while this Task finishes an upcall.
    #[cfg(feature = "kernelet")]
    virq_deferral_depth: AtomicU32,

    /// Counts nonempty virtual-interrupt batches completed on this Task.
    ///
    /// This is Guest-local progress state, never shared with the Host. The
    /// upcall advances it before its epilogue can switch Tasks. A pending
    /// IRQ-on window can therefore finish after one batch, even if producers
    /// leave more pending events. Only this Task accesses its counter.
    #[cfg(feature = "kernelet")]
    completed_virq_batches: AtomicU64,

    /// Retains the user space last activated by this Guest Task.
    #[cfg(feature = "kernelet")]
    active_vm_space: ForceSync<RefCell<Option<Arc<crate::mm::VmSpace>>>>,

    schedule_info: TaskScheduleInfo,
    #[cfg(any(feature = "kernelet-host", feature = "kernelet", kernelet_rq1, ktest))]
    accounting: accounting::TaskAccounting,
    #[cfg(kernelet_rq1_diagnostics)]
    rq1_fpu_counters:
        crate::kernelet::fpu_profile::Counters<{ crate::kernelet::fpu_profile::EVENT_COUNT }>,
}

impl Task {
    /// Diagnostic events owned by this Task; absent from ordinary builds.
    #[cfg(kernelet_rq1_diagnostics)]
    pub fn rq1_fpu_counters(
        &self,
    ) -> &crate::kernelet::fpu_profile::Counters<{ crate::kernelet::fpu_profile::EVENT_COUNT }>
    {
        &self.rq1_fpu_counters
    }

    /// Settles samples while this stack's execution ownership is exclusive.
    /// IRQs must be off, and an outgoing Task must still be switched_to_cpu.
    #[cfg(feature = "kernelet")]
    fn drain_sampled_ticks(&self) {
        debug_assert!(!crate::arch::irq::is_local_enabled());
        debug_assert!(self.switched_to_cpu.load(Ordering::Acquire));
        let (user, kernel) = self.kstack.take_ticks();
        if user != 0 {
            crate::irq::call_sampled_task_tick_callback_functions(
                self,
                crate::cpu::PrivilegeLevel::User,
                user,
            );
        }
        if kernel != 0 {
            crate::irq::call_sampled_task_tick_callback_functions(
                self,
                crate::cpu::PrivilegeLevel::Kernel,
                kernel,
            );
        }
    }

    /// Attaches an account to this currently executing native Task.
    #[cfg(any(feature = "kernelet-host", ktest))]
    pub(crate) fn attach_cpu_account(
        &self,
        account: Arc<dyn accounting::CpuTimeAccount>,
    ) -> Result<()> {
        if !Task::current().is_some_and(|task| core::ptr::eq(&*task, self)) {
            return Err(crate::Error::InvalidArgs);
        }
        self.accounting.attach(account)
    }

    #[cfg(any(feature = "kernelet-host", ktest))]
    pub(crate) fn sample_cpu_account(&self, owner: usize) -> Result<()> {
        if !Task::current().is_some_and(|task| core::ptr::eq(&*task, self)) {
            return Err(crate::Error::InvalidArgs);
        }
        self.accounting.sample_owned(owner)
    }

    #[cfg(any(feature = "kernelet-host", ktest))]
    pub(crate) fn detach_cpu_account(&self, owner: usize) -> Result<()> {
        debug_assert!(Task::current().is_some_and(|task| core::ptr::eq(&*task, self)));
        self.accounting.detach(Some(owner))
    }

    /// Installs the calling Task's pinned carrier context, or clears it with zero.
    ///
    /// # Safety
    /// The nonzero address must remain a live carrier context until this Task
    /// clears it. The caller must hold physical IRQs disabled and own this Task.
    #[cfg(feature = "kernelet-host")]
    pub(crate) unsafe fn set_carrier_context(&self, address: usize) {
        // SAFETY: The caller supplies the Task-owned lifetime and IRQ exclusion.
        unsafe { self.accounting.set_carrier_context(address) };
    }

    /// Gets the current task.
    ///
    /// It returns `None` in Native bootstrap or before Guest boot adopts its Task.
    pub fn current() -> Option<CurrentTask> {
        let current_task = current_task()?;

        // SAFETY: `current_task` is the current task.
        Some(unsafe { CurrentTask::new(current_task) })
    }

    pub(super) fn ctx(&self) -> &SyncUnsafeCell<TaskContext> {
        &self.ctx
    }

    #[cfg(feature = "kernelet")]
    pub(super) fn is_boot_task(&self) -> bool {
        self.kstack.is_boot()
    }

    /// Returns whether we need to yield execution to another task.
    ///
    /// If the scheduler decides to preempt the current task in favor of
    /// another (for example, if the current task has exhausted its runtime
    /// budget or if the new task has a higher priority), this method will
    /// return `true`.
    pub fn need_yield() -> bool {
        preempt::cpu_local::need_preempt()
    }

    /// Yields execution so that another task may be scheduled.
    ///
    /// Note that this method cannot be simply named "yield" as the name is
    /// a Rust keyword.
    ///
    /// # Panics
    ///
    /// Panics if the current Task is a kernelet's one-shot boot Task.
    #[track_caller]
    pub fn yield_now() {
        scheduler::yield_now()
    }

    /// Kicks the task scheduler to run the task.
    ///
    /// BUG: This method highly depends on the current scheduling policy.
    ///
    /// # Panics
    ///
    /// Panics if this is a kernelet's one-shot boot Task.
    #[track_caller]
    pub fn run(self: &Arc<Self>) {
        #[cfg(feature = "kernelet")]
        assert!(!self.kstack.is_boot(), "a boot Task cannot be run again");
        scheduler::run_new_task(self.clone());
    }

    /// Returns the task data.
    pub fn data(&self) -> &Box<dyn Any + Send + Sync> {
        &self.data
    }

    /// Get the attached scheduling information.
    pub fn schedule_info(&self) -> &TaskScheduleInfo {
        &self.schedule_info
    }
}

crate::cpu_local_cell! {
    static BOOT_SCHEDULING_IN_PROGRESS: bool = false;
}

pub(crate) fn scheduling_in_progress() -> bool {
    Task::current().map_or_else(
        || BOOT_SCHEDULING_IN_PROGRESS.load(),
        |task| task.scheduling_in_progress.load(Ordering::Relaxed),
    )
}

/// Keeps IRQ preemption from reentering a Task's unfinished scheduler decision.
///
/// The mark follows the Task across a context switch. It does not mask IRQs or
/// add a preemption guard, so the scheduler can still switch to another Task.
pub(crate) struct SchedulingGuard;

impl !Send for SchedulingGuard {}

impl SchedulingGuard {
    pub(crate) fn new() -> Self {
        debug_assert!(!scheduling_in_progress());
        if let Some(task) = Task::current() {
            task.scheduling_in_progress.store(true, Ordering::Relaxed);
        } else {
            BOOT_SCHEDULING_IN_PROGRESS.store(true);
        }
        Self
    }
}

impl Drop for SchedulingGuard {
    fn drop(&mut self) {
        if let Some(task) = Task::current() {
            task.scheduling_in_progress.store(false, Ordering::Relaxed);
        } else {
            BOOT_SCHEDULING_IN_PROGRESS.store(false);
        }
    }
}

#[cfg(feature = "kernelet")]
crate::cpu_local_cell! {
    static BOOT_VIRQ_DEFERRAL_DEPTH: u32 = 0;
}

/// Returns whether the current Task is in a virtual-interrupt deferral region.
#[cfg(feature = "kernelet")]
pub(crate) fn virq_delivery_deferred() -> bool {
    scheduling_in_progress()
        || Task::current().map_or_else(
            || BOOT_VIRQ_DEFERRAL_DEPTH.load() != 0,
            |task| task.virq_deferral_depth.load(Ordering::Relaxed) != 0,
        )
}

/// Holds off nested virtual interrupts until this Task has finished its
/// upcall epilogue. The mark follows the Task across a context switch;
/// another Task can still receive pending notices on the same vCPU.
#[cfg(feature = "kernelet")]
pub(crate) struct VirtualIrqDeferral;

#[cfg(feature = "kernelet")]
impl VirtualIrqDeferral {
    pub(crate) fn new() -> Self {
        if let Some(task) = Task::current() {
            task.virq_deferral_depth.fetch_add(1, Ordering::Relaxed);
        } else {
            BOOT_VIRQ_DEFERRAL_DEPTH.add_assign(1);
        }
        Self
    }
}

#[cfg(feature = "kernelet")]
impl Drop for VirtualIrqDeferral {
    fn drop(&mut self) {
        if let Some(task) = Task::current() {
            let previous = task.virq_deferral_depth.fetch_sub(1, Ordering::Relaxed);
            debug_assert!(previous > 0);
        } else {
            debug_assert!(BOOT_VIRQ_DEFERRAL_DEPTH.load() > 0);
            BOOT_VIRQ_DEFERRAL_DEPTH.sub_assign(1);
        }
    }
}

/// Options to create or spawn a new task.
pub struct TaskOptions {
    func: Option<Box<dyn FnOnce() + Send>>,
    data: Option<Box<dyn Any + Send + Sync>>,
    local_data: Option<Box<dyn Any + Send>>,
}

/// A fallibly reserved Task stack, owned until task construction or Drop.
///
/// Reserve this before entering an infallible cyclic-owner constructor.
pub struct PreparedTaskStack(KernelStack);

#[cfg(feature = "kernelet-host")]
pub(crate) const fn native_stack_reservation_bytes() -> usize {
    kernel_stack::RESERVATION_BYTES
}

impl TaskOptions {
    /// Creates a set of options for a task.
    pub fn new<F>(func: F) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        Self {
            func: Some(Box::new(func)),
            data: None,
            local_data: None,
        }
    }

    /// Sets the function that represents the entry point of the task.
    pub fn func<F>(mut self, func: F) -> Self
    where
        F: Fn() + Send + 'static,
    {
        self.func = Some(Box::new(func));
        self
    }

    /// Sets the data associated with the task.
    pub fn data<T>(mut self, data: T) -> Self
    where
        T: Any + Send + Sync,
    {
        self.data = Some(Box::new(data));
        self
    }

    /// Sets the local data associated with the task.
    pub fn local_data<T>(mut self, data: T) -> Self
    where
        T: Any + Send,
    {
        self.local_data = Some(Box::new(data));
        self
    }

    /// Builds a new task without running it immediately.
    pub fn build(self) -> Result<Task> {
        Ok(self.build_with_stack(Self::prepare_stack()?))
    }

    /// Reserves the stack before publishing cyclic Task/Thread ownership.
    pub fn prepare_stack() -> Result<PreparedTaskStack> {
        KernelStack::new_with_guard_page().map(PreparedTaskStack)
    }

    /// Builds a dormant task using an already reserved stack.
    pub fn build_with_stack(self, stack: PreparedTaskStack) -> Task {
        // All tasks will enter this function. It is meant to execute the `task_fn` in `Task`.
        //
        // We provide an assembly wrapper for this function as the end of call stack so we
        // have to disable name mangling for it.
        //
        // # Safety
        //
        // This function must be called from `switch.S` when the context is prepared correctly.
        // SAFETY: The name does not collide with other symbols.
        #[unsafe(no_mangle)]
        unsafe extern "C" fn kernel_task_entry() -> ! {
            // SAFETY: The new task is switched on a CPU for the first time, `after_switching_to`
            // hasn't been called yet.
            unsafe { processor::after_switching_to() };

            let current_task = Task::current()
                .expect("no current task, it should have current task in kernel task entry");

            // SAFETY: The `func` field will only be accessed by the current task in the task
            // context, so the data won't be accessed concurrently.
            let task_func = unsafe { current_task.func.get() };
            let task_func = task_func
                .take()
                .expect("task function is `None` when trying to run");
            task_func();

            // Manually drop all the on-stack variables to prevent memory leakage!
            // This is needed because `scheduler::exit_current()` will never return.
            //
            // However, `current_task` _borrows_ the current task without holding
            // an extra reference count. So we do nothing here.

            exit_current_task();
        }

        let kstack = stack.0;

        let mut ctx = TaskContext::new();
        ctx.set_instruction_pointer(
            crate::arch::task::kernel_task_entry_wrapper as *const () as usize,
        );
        // We should reserve space for the return address in the stack, otherwise
        // we will write across the page boundary due to the implementation of
        // the context switch.
        //
        // According to the System V AMD64 ABI, the stack pointer should be aligned
        // to at least 16 bytes. A larger alignment is needed if larger arguments
        // are passed to the function, which is not the case for the
        // `kernel_task_entry` function because it does not have any arguments. So
        // we only need to align the stack pointer to 16 bytes.
        ctx.set_stack_pointer(kstack.end_vaddr() - 16);

        let new_task = Task {
            #[cfg(any(feature = "kernelet-host", feature = "kernelet", kernelet_rq1, ktest))]
            accounting: accounting::TaskAccounting::new(),
            #[cfg(kernelet_rq1_diagnostics)]
            rq1_fpu_counters: crate::kernelet::fpu_profile::Counters::new(),
            func: ForceSync::new(Cell::new(self.func)),
            data: self.data.unwrap_or_else(|| Box::new(())),
            local_data: ForceSync::new(self.local_data.unwrap_or_else(|| Box::new(()))),
            ctx: SyncUnsafeCell::new(ctx),
            kstack,
            switched_to_cpu: AtomicBool::new(false),
            scheduling_in_progress: AtomicBool::new(false),
            #[cfg(feature = "kernelet")]
            virq_deferral_depth: AtomicU32::new(0),
            #[cfg(feature = "kernelet")]
            completed_virq_batches: AtomicU64::new(0),
            #[cfg(feature = "kernelet")]
            active_vm_space: ForceSync::new(RefCell::new(None)),
            schedule_info: TaskScheduleInfo {
                cpu: AtomicCpuId::default(),
            },
        };

        new_task
    }

    /// Builds a new task and runs it immediately.
    #[track_caller]
    pub fn spawn(self) -> Result<Arc<Task>> {
        let task = Arc::new(self.build()?);
        task.run();
        Ok(task)
    }
}

/// The current task.
///
/// This type is not `Send`, so it cannot outlive the current task.
///
/// This type is also not `Sync`, so it can provide access to the local data of the current task.
#[derive(Debug)]
pub struct CurrentTask(NonNull<Task>);

// The intern `NonNull<Task>` contained by `CurrentTask` implies that `CurrentTask` is `!Send` and
// `!Sync`. But it is still good to do this explicitly because these properties are key for
// soundness.
impl !Send for CurrentTask {}
impl !Sync for CurrentTask {}

impl CurrentTask {
    /// Settles this Task's physical tick samples before publishing an exit.
    ///
    /// Only explicit-owner accounting callbacks run. No global timer callback
    /// is replayed, and this method does not change the running Task identity.
    #[cfg(feature = "kernelet")]
    pub fn flush_sampled_ticks(&self) {
        assert!(InterruptLevel::current().is_task_context());
        let _irq_guard = crate::irq::disable_local();
        self.drain_sampled_ticks();
    }

    /// Returns this Task's local virtual-interrupt progress epoch.
    #[cfg(feature = "kernelet")]
    pub(crate) fn completed_virq_batches(&self) -> u64 {
        self.completed_virq_batches.load(Ordering::Relaxed)
    }

    /// Records a nonempty batch after its callbacks and before its epilogue.
    ///
    /// The original Task owns this continuation across any context switch;
    /// another Task cannot advance this counter on its behalf. Relaxed order
    /// suffices because the same Task reads and updates its own progress.
    #[cfg(feature = "kernelet")]
    pub(crate) fn complete_virq_batch(&self) {
        self.completed_virq_batches.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(feature = "kernelet")]
    pub(crate) fn active_vm_space_matches(
        &self,
        space: &Arc<crate::mm::VmSpace>,
        _irq_guard: &DisabledLocalIrqGuard,
    ) -> bool {
        // SAFETY: Only the current Task accesses this cache. Masking virtual
        // IRQs excludes Guest upcalls, and a Task executes on only one CPU.
        unsafe { self.active_vm_space.get() }
            .borrow()
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, space))
    }

    #[cfg(feature = "kernelet")]
    pub(crate) fn replace_active_vm_space(
        &self,
        space: Option<Arc<crate::mm::VmSpace>>,
        _irq_guard: &DisabledLocalIrqGuard,
    ) -> Option<Arc<crate::mm::VmSpace>> {
        // SAFETY: The current Task owns this cache, and the IRQ guard excludes
        // Guest upcalls that could access it before this replacement finishes.
        unsafe { self.active_vm_space.get() }.replace(space)
    }

    /// Begins measuring execution accounted by this Task's scheduler,
    /// excluding time spent asleep or running other Tasks.
    #[cfg(any(feature = "kernelet-host", feature = "kernelet", kernelet_rq1, ktest))]
    pub fn measure_cpu_time(&self) -> CpuTimeMeasurement {
        CpuTimeMeasurement::start(self.cloned())
    }

    /// # Safety
    ///
    /// The caller must ensure that `task` is the current task.
    unsafe fn new(task: NonNull<Task>) -> Self {
        Self(task)
    }

    /// Returns the local data of the current task.
    ///
    /// Note that the local data is only accessible in the task context. Although there is a
    /// current task in the non-task context (e.g. IRQ handlers), access to the local data is
    /// forbidden as it may cause soundness problems.
    ///
    /// # Panics
    ///
    /// This method will panic if called in a non-task context.
    pub fn local_data(&self) -> &(dyn Any + Send) {
        assert!(InterruptLevel::current().is_task_context());

        let local_data = &self.local_data;

        // SAFETY: The `local_data` field will only be accessed by the current task in the task
        // context, so the data won't be accessed concurrently.
        &**unsafe { local_data.get() }
    }

    /// Returns a cloned `Arc<Task>`.
    pub fn cloned(&self) -> Arc<Task> {
        let ptr = self.0.as_ptr();

        // SAFETY: The current task is always a valid task and it is always contained in an `Arc`.
        unsafe { Arc::increment_strong_count(ptr) };

        // SAFETY: We've increased the reference count in the current `Arc<Task>` above.
        unsafe { Arc::from_raw(ptr) }
    }
}

impl Deref for CurrentTask {
    type Target = Task;

    fn deref(&self) -> &Self::Target {
        // SAFETY: The current task is always a valid task.
        unsafe { self.0.as_ref() }
    }
}

impl AsRef<Task> for CurrentTask {
    fn as_ref(&self) -> &Task {
        self
    }
}

impl Borrow<Task> for CurrentTask {
    fn borrow(&self) -> &Task {
        self
    }
}

/// A trait that provides methods to manipulate the task context.
pub(crate) trait TaskContextApi {
    /// Sets the instruction pointer.
    fn set_instruction_pointer(&mut self, ip: usize);

    /// Sets the stack pointer.
    fn set_stack_pointer(&mut self, sp: usize);
}

#[cfg(ktest)]
mod test {
    use crate::prelude::*;

    #[ktest]
    fn create_task() {
        #[expect(clippy::eq_op)]
        let task = || {
            assert_eq!(1, 1);
        };
        let task = Arc::new(
            crate::task::TaskOptions::new(task)
                .data(())
                .build()
                .unwrap(),
        );
        task.run();
    }

    #[ktest]
    fn spawn_task() {
        #[expect(clippy::eq_op)]
        let task = || {
            assert_eq!(1, 1);
        };
        let _ = crate::task::TaskOptions::new(task).data(()).spawn();
    }
}
