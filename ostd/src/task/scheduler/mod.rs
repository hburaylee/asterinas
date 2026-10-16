// SPDX-License-Identifier: MPL-2.0

//! Task scheduling.
//!
//! # Scheduler Injection
//!
//! The task scheduler of an OS is a complex beast,
//! and the most suitable scheduling algorithm often depends on the target usage scenario.
//! To avoid code bloat and offer flexibility,
//! OSTD does not include a gigantic, one-size-fits-all task scheduler.
//! Instead, it allows the client to implement a custom scheduler (in safe Rust, of course)
//! and register it with OSTD.
//! This feature is known as **scheduler injection**.
//!
//! The client kernel performs scheduler injection via the [`inject_scheduler`] API.
//! This API should be called as early as possible during kernel initialization,
//! before any [`Task`]-related APIs are used.
//! This requirement is reasonable since `Task`s depend on the scheduler.
//!
//! # Scheduler Abstraction
//!
//! The `inject_scheduler` API accepts an object implementing the [`Scheduler`] trait,
//! which abstracts over any SMP-aware task scheduler.
//! Whenever an OSTD client spawns a new task (via [`crate::task::TaskOptions`])
//! or wakes a sleeping task (e.g., via [`crate::sync::Waker`]),
//! OSTD internally forwards the corresponding `Arc<Task>`
//! to the scheduler by invoking the [`Scheduler::enqueue`] method.
//! This allows the injected scheduler to manage all runnable tasks.
//!
//! Each enqueued task is dispatched to one of the per-CPU local runqueues,
//! which manage all runnable tasks on a specific CPU.
//! A local runqueue is abstracted by the [`LocalRunQueue`] trait.
//! OSTD accesses the local runqueue of the current CPU
//! via [`Scheduler::local_rq_with`] or [`Scheduler::mut_local_rq_with`],
//! which return immutable and mutable references to `dyn LocalRunQueue`, respectively.
//!
//! The [`LocalRunQueue`] trait enables OSTD to inspect and manipulate local runqueues.
//! For instance, OSTD invokes the [`LocalRunQueue::pick_next`] method
//! to let the scheduler select the next task to run.
//! OSTD then performs a context switch to that task,
//! which becomes the _current_ running task, accessible via [`LocalRunQueue::current`].
//! When the current task is about to sleep (e.g., via [`crate::sync::Waiter`]),
//! OSTD removes it from the local runqueue using [`LocalRunQueue::dequeue_current`].
//!
//! The interfaces of `Scheduler` and `LocalRunQueue` are simple
//! yet (perhaps surprisingly) powerful enough to support
//! even complex and advanced task scheduler implementations.
//! Scheduler implementations are free to employ any load-balancing strategy
//! to dispatch enqueued tasks across local runqueues,
//! and each local runqueue is free to choose any prioritization strategy
//! for selecting the next task to run.
//! Based on OSTD's scheduling abstractions,
//! the Asterinas kernel has successfully supported multiple Linux scheduling classes,
//! including both real-time and normal policies.
//!
//! # Safety Impact
//!
//! While OSTD delegates scheduling decisions to the injected task scheduler,
//! it verifies these decisions to avoid undefined behavior.
//! In particular, it enforces the following safety invariant:
//!
//! > A task must not be scheduled to run on more than one CPU at a time.
//!
//! Violating this invariant—e.g., running the same task on two CPUs concurrently—
//! can have catastrophic consequences,
//! as the task's stack and internal state may be corrupted by concurrent modifications.

mod fifo_scheduler;
pub mod info;

#[cfg(feature = "kernelet")]
use core::sync::atomic::Ordering;

use spin::Once;

use super::{Task, preempt::cpu_local, processor};
use crate::{
    cpu::{CpuId, PinCurrentCpu},
    prelude::*,
    task::disable_preempt,
    timer,
};

/// Returns the execution clock used to charge the current Task's runtime.
///
/// Explicit Image, experiment, or test measurements share this clock reading.
/// Ordinary Host builds return the native scheduler clock directly.
///
/// On a kernelet vCPU, complete Host off-CPU intervals are removed from this
/// clock. The offset is local to the current vCPU; a scheduler must retain a
/// starting value only while the Task runs on that vCPU.
pub fn runtime_ticks() -> u64 {
    #[cfg(any(feature = "kernelet", kernelet_rq1, kernelet_rq1_diagnostics, ktest))]
    {
        Task::current()
            .and_then(|task| task.accounting.sample(true))
            .unwrap_or_else(super::accounting::runtime_ticks)
    }
    #[cfg(not(any(feature = "kernelet", kernelet_rq1, kernelet_rq1_diagnostics, ktest)))]
    {
        crate::arch::read_tsc()
    }
}

/// Injects a custom implementation of task scheduler into OSTD.
///
/// This function can only be called once and must be called
/// during the initialization phase of kernel,
/// before any [`Task`]-related APIs are invoked.
///
/// # Panics
///
/// This function panics if a scheduler has already been injected,
/// either explicitly via a previous call to this function
/// or implicitly via the lazy default FIFO scheduler.
pub fn inject_scheduler(scheduler: &'static dyn Scheduler<Task>) {
    let mut is_new = false;
    SCHEDULER.call_once(|| {
        is_new = true;
        scheduler
    });
    assert!(is_new, "a scheduler has already been initialized");
}

/// Enables preemptive scheduling on the current CPU.
///
/// After calling this function on a CPU,
/// a task that is executing in the user mode may get preempted
/// if another runnable task on the same CPU is deemed more urgent by the scheduler.
///
/// OSTD achieves task preemption by registering a per-CPU timer callback
/// to invoke the scheduler periodically.
/// Thus, this function should be called _once_ on every CPU
/// by an OSTD-based kernel during its initialization phase,
/// after it has injected its scheduler via [`inject_scheduler`].
pub fn enable_preemption_on_cpu() {
    timer::register_callback_on_cpu(|| update_current_on_tick(scheduler_singleton()));
}

fn update_current_on_tick(scheduler: &dyn Scheduler) {
    scheduler.mut_local_rq_with(&mut |local_rq| {
        if local_rq.update_current(UpdateFlags::Tick) {
            cpu_local::set_need_preempt();
        }
    });
}

/// The global scheduler singleton.
///
/// Do not access this directly; it may not yet be initialized.
/// Use [`scheduler_singleton`] instead, which returns the current scheduler
/// and falls back to a default FIFO scheduler if none has been injected.
static SCHEDULER: Once<&'static dyn Scheduler<Task>> = Once::new();

/// Returns the global scheduler.
///
/// If a scheduler has already been injected (e.g., by a custom scheduler),
/// it is returned directly. Otherwise, a default FIFO scheduler
/// is lazily initialized and used.
///
/// Initialization is atomic: [`Once::call_once`] guarantees that even if
/// multiple CPUs call this concurrently, only one will execute the
/// initialization closure while the others block until it completes.
fn scheduler_singleton() -> &'static dyn Scheduler<Task> {
    *SCHEDULER.call_once(|| fifo_scheduler::new_instance())
}

/// A SMP-aware task scheduler.
pub trait Scheduler<T = Task>: Sync + Send {
    /// Enqueues a runnable task.
    ///
    /// The scheduler implementer can perform load-balancing or some time accounting work here.
    ///
    /// The newly-enqueued task may have a higher priority than the currently running one on a CPU
    /// and thus should preempt the latter.
    /// In this case, this method returns the ID of that CPU.
    fn enqueue(&self, runnable: Arc<T>, flags: EnqueueFlags) -> Option<CpuId>;

    /// Gets an immutable access to the local runqueue of the current CPU.
    fn local_rq_with(&self, f: &mut dyn FnMut(&dyn LocalRunQueue<T>));

    /// Gets a mutable access to the local runqueue of the current CPU.
    fn mut_local_rq_with(&self, f: &mut dyn FnMut(&mut dyn LocalRunQueue<T>));
}

/// A per-CPU, local runqueue.
///
/// This abstraction allows OSTD to inspect and manipulate local runqueues.
///
/// Conceptually, a local runqueue maintains:
/// 1. A priority queue of runnable tasks.
///    The definition of "priority" is left to the concrete implementation.
/// 2. The current running task.
///
/// # Interactions with OSTD
///
/// ## Overview
///
/// It is crucial for implementers of `LocalRunQueue`
/// to understand how OSTD interacts with local runqueues.
///
/// A local runqueue is consulted by OSTD in response to one of four scheduling events:
/// - **Yielding**, triggered by [`Task::yield_now`], where the current task voluntarily gives up CPU time.
/// - **Sleeping**, triggered by [`crate::sync::Waiter::wait`]
///   or any synchronization primitive built upon it (e.g., [`crate::sync::WaitQueue`], [`crate::sync::Mutex`]),
///   which blocks the current task until a wake-up event occurs.
/// - **Ticking**, triggered periodically by the system timer
///   (see [`crate::timer::TIMER_FREQ`]),
///   which provides an opportunity to do time accounting and consider preemption.
/// - **Exiting**, triggered when the execution logic of a task has come to an end,
///   which informs the scheduler that the task is exiting and will never be enqueued again.
///
/// The general workflow for OSTD to handle a scheduling event is as follows:
/// 1. Acquire exclusive access to the local runqueue using [`Scheduler::mut_local_rq_with`].
/// 2. Call [`LocalRunQueue::update_current`] to update the current task's state,
///    returning a boolean value that indicates
///    whether the current task should and can be replaced with another runnable task.
/// 3. If the task is about to sleep or exit, call [`LocalRunQueue::dequeue_current`]
///    to remove it from the runqueue.
/// 4. If the return value of `update_current` in Step 2 is true,
///    then select the next task to run with [`LocalRunQueue::pick_next`].
///
/// ## When to Pick the Next Task?
///
/// As shown above,
/// OSTD guarantees that `pick_next` is only called
/// when the current task should and can be replaced.
/// This avoids unnecessary invocations and improves efficiency.
///
/// But under what conditions should the current task be replaced?
/// Two criteria must be met:
/// 1. There exists at least one other runnable task in the runqueue.
/// 2. That task should preempt the current one, if present.
///
/// Some implications of these rules:
/// - If the runqueue is empty, `update_current` must return `false`—there's nothing to run.
/// - If the runqueue is non-empty but the current task is absent,
///   `update_current` should return `true`—anything is better than nothing.
/// - If the runqueue is non-empty and the flag is `UpdateFlags::WAIT`,
///   `update_current` should also return `true`,
///   because the current task is about to block.
/// - In other cases, the return value depends on the scheduler's prioritization policy.
///   For instance, a real-time task may only be preempted by a higher-priority task
///   or if it explicitly yields.
///   A normal task under Linux's CFS may be preempted by a task with smaller vruntime,
///   but never by the idle task.
///
/// When OSTD is unsure about whether the current task should or can be replaced,
/// it will invoke [`LocalRunQueue::try_pick_next`], the fallible version of `pick_next`.
///
/// ## Internal Working
///
/// To guide scheduler implementers,
/// we provide a simplified view of how OSTD interacts with local runqueues _internally_
/// in order to handle the four scheduling events.
///
/// ### Yielding
///
/// ```
/// # use ostd::prelude::*;
/// # use ostd::task::{*, scheduler::*};
/// #
/// # fn switch_to(next: Arc<Task>) {}
/// #
/// /// Yields the current task.
/// fn yield(scheduler: &'static dyn Scheduler) {
///     let next_task_opt: Option<Arc<Task>> = scheduler.mut_local_rq_with(|local_rq| {
///         let should_pick_next = local_rq.update_current(UpdateFlags::Yield);
///         should_pick_next.then(|| local_rq.pick_next().clone())
///     });
///     let Some(next_task) = next_task_opt {
///         switch_to(next_task);
///     }
/// }
/// ```
///
/// ### Sleeping
///
/// ```
/// # use ostd::prelude::*;
/// # use ostd::task::{*, scheduler::*};
/// #
/// # fn switch_to(next: Arc<Task>) {}
/// #
/// /// Puts the current task to sleep.
/// ///
/// /// The function takes a closure to check if the task is woken.
/// /// This function is used internally to guard against race conditions,
/// /// where the task is woken just before it goes to sleep.
/// fn sleep<F: Fn() -> bool>(scheduler: &'static dyn Scheduler, is_woken: F) {
///     let mut next_task_opt: Option<Arc<Task>> = None;
///     let mut is_first_try = true;
///     while scheduler.mut_local_rq_with(|local_rq| {
///         if is_first_try {
///             if is_woken() {
///                 return false; // exit loop
///             }
///             is_first_try = false;
///
///             let should_pick_next = local_rq.update_current(UpdateFlags::Wait);
///             let _current = local_rq.dequeue_current();
///             if !should_pick_next {
///                 return true; // continue loop
///             }
///             next_task_opt = Some(local_rq.pick_next().clone());
///             false // exit loop
///         } else {
///             next_task_opt = local_rq.try_pick_next().cloned();
///             next_task_opt.is_none()
///         }
///     }) {}
///     let Some(next_task) = next_task_opt {
///         switch_to(next_task);
///     }
/// }
/// ```
///
/// ### Ticking
///
/// ```
/// # use ostd::prelude::*;
/// # use ostd::task::{*, scheduler::*};
/// #
/// # fn switch_to(next: Arc<Task>) {}
/// # mod cpu_local {
/// #     fn set_need_preempt();
/// #     fn should_preempt() -> bool;
/// # }
/// #
/// /// A callback to be invoked periodically by the timer interrupt.
/// fn on_tick(scheduler: &'static dyn Scheduler) {
///     scheduler.mut_local_rq_with(|local_rq| {
///         let should_pick_next = local_rq.update_current(UpdateFlags::Tick);
///         if should_pick_next {
///             cpu_local::set_need_preempt();
///         }
///     });
/// }
///
/// /// A preemption point, called at an earliest convenient timing
/// /// when OSTD can safely preempt the current running task.
/// fn might_preempt(scheduler: &'static dyn Scheduler) {
///     if !cpu_local::should_preempt() {
///         return;
///     }
///     let next_task_opt: Option<Arc<Task>> = scheduler
///         .mut_local_rq_with(|local_rq| local_rq.try_pick_next().cloned())
///     let Some(next_task) = next_task_opt {
///         switch_to(next_task);
///     }
/// }
/// ```
///
/// ### Exiting
///
/// ```
/// # use ostd::prelude::*;
/// # use ostd::task::{*, scheduler::*};
/// #
/// # fn switch_to(next: Arc<Task>) {}
/// #
/// /// Exits the current task.
/// fn exit(scheduler: &'static dyn Scheduler) {
///     let mut next_task_opt: Option<Arc<Task>> = None;
///     let mut is_first_try = true;
///     while scheduler.mut_local_rq_with(|local_rq| {
///         if is_first_try {
///             is_first_try = false;
///             let should_pick_next = local_rq.update_current(UpdateFlags::Exit);
///             let _current = local_rq.dequeue_current();
///             if !should_pick_next {
///                 return true; // continue loop
///             }
///             next_task_opt = Some(local_rq.pick_next().clone());
///             false // exit loop
///         } else {
///             next_task_opt = local_rq.try_pick_next().cloned();
///             next_task_opt.is_none()
///         }
///     }) {}
///     let next_task = next_task_opt.unwrap();
///     switch_to(next_task);
/// }
/// ```
pub trait LocalRunQueue<T = Task> {
    /// Gets the current runnable task.
    fn current(&self) -> Option<&Arc<T>>;

    /// Updates the current runnable task's scheduling statistics and
    /// potentially its position in the runqueue.
    ///
    /// The return value of this method indicates whether an invocation of `pick_next` should be followed
    /// to find another task to replace the current one.
    #[must_use]
    fn update_current(&mut self, flags: UpdateFlags) -> bool;

    /// Picks the next runnable task.
    ///
    /// This method instructs the local runqueue to pick the next runnable task and replace the current one.
    /// A reference to the new "current" task will be returned by this method.
    /// If the "old" current task presents, then it is still runnable and thus remains in the runqueue.
    ///
    /// # Panics
    ///
    /// As explained in the type-level Rust doc,
    /// this method will only be invoked by OSTD after a call to `update_current` returns true.
    /// In case that this contract is broken by the caller,
    /// the implementer is free to exhibit any undesirable or incorrect behaviors, include panicking.
    fn pick_next(&mut self) -> &Arc<T> {
        self.try_pick_next().unwrap()
    }

    /// Tries to pick the next runnable task.
    ///
    /// This method instructs the local runqueue to pick the next runnable task on a best-effort basis.
    /// If such a task can be picked, then this task supersedes the current task and
    /// the new the method returns a reference to the new "current" task.
    /// If the "old" current task presents, then it is still runnable and thus remains in the runqueue.
    fn try_pick_next(&mut self) -> Option<&Arc<T>>;

    /// Removes the current runnable task from runqueue.
    ///
    /// This method returns the current runnable task.
    /// If there is no current runnable task, this method returns `None`.
    fn dequeue_current(&mut self) -> Option<Arc<T>>;
}

/// Possible triggers of an `enqueue` action.
#[derive(Clone, Copy, PartialEq)]
pub enum EnqueueFlags {
    /// Spawn a new task.
    Spawn,
    /// Wake a sleeping task.
    Wake,
}

/// Possible triggers of an `update_current` action.
#[derive(Clone, Copy, PartialEq)]
pub enum UpdateFlags {
    /// Timer interrupt.
    Tick,
    /// Task waiting.
    Wait,
    /// Task yielding.
    Yield,
    /// Task exiting.
    Exit,
}

/// Returns whether the current CPU has an unblocked inner preemption request.
///
/// The caller must still check its IRQ and Task-context gates before scheduling.
#[cfg(feature = "kernelet")]
#[inline]
pub(crate) fn should_preempt() -> bool {
    cpu_local::should_preempt()
}

/// Preempts the current task.
#[track_caller]
pub(crate) fn might_preempt() {
    if !cpu_local::should_preempt() {
        return;
    }
    #[cfg(feature = "kernelet")]
    if super::scheduling_in_progress() {
        return;
    }
    reschedule(|local_rq| {
        let next_task_opt = local_rq.try_pick_next();
        if let Some(next_task) = next_task_opt {
            ReschedAction::SwitchTo(next_task.clone())
        } else {
            ReschedAction::DoNothing
        }
    })
}

/// Blocks the current task unless `has_unparked()` returns `true`.
///
/// Note that this method may return due to spurious wake events. It's the caller's responsibility
/// to detect them (if necessary).
#[track_caller]
pub(crate) fn park_current<F>(has_unparked: F)
where
    F: Fn() -> bool,
{
    #[cfg(feature = "kernelet")]
    assert!(
        !Task::current().is_some_and(|task| task.is_boot_task()),
        "a boot Task cannot park"
    );
    let mut current = None;
    let mut is_first_try = true;

    reschedule(|local_rq: &mut dyn LocalRunQueue| {
        let next_task_opt = if is_first_try {
            if has_unparked() {
                return ReschedAction::DoNothing;
            }
            is_first_try = false;

            // Note the race conditions: the current task may be woken after the above `has_unparked`
            // check, but before the below `dequeue_current` action, we need to make sure that the
            // wakeup event isn't lost.
            //
            // Currently, for the FIFO and CFS scheduler, `Scheduler::enqueue` will try to lock `local_rq`
            // when the above race condition occurs, so it will wait until we finish calling the
            // `dequeue_current` method and nothing bad will happen. This may need to be revisited
            // after more complex schedulers are introduced.

            let should_pick_next = local_rq.update_current(UpdateFlags::Wait);
            current = local_rq.dequeue_current();
            should_pick_next.then(|| local_rq.pick_next())
        } else {
            local_rq.try_pick_next()
        };

        if let Some(next_task) = next_task_opt {
            if Arc::ptr_eq(current.as_ref().unwrap(), next_task) {
                // The current task has been woken and picked as the next runnable task.
                return ReschedAction::DoNothing;
            }
            return ReschedAction::SwitchTo(next_task.clone());
        }

        ReschedAction::Retry
    });
}

/// Unblocks a target task.
pub(crate) fn unpark_target(runnable: Arc<Task>) {
    #[cfg(feature = "kernelet")]
    assert!(!runnable.is_boot_task(), "a boot Task cannot be woken");
    let preempt_cpu = scheduler_singleton().enqueue(runnable, EnqueueFlags::Wake);
    if let Some(preempt_cpu_id) = preempt_cpu {
        set_need_preempt(preempt_cpu_id);
    }
}

/// Enqueues a newly built task.
///
/// Note that the new task is not guaranteed to run at once.
#[track_caller]
pub(super) fn run_new_task(runnable: Arc<Task>) {
    #[cfg(feature = "kernelet")]
    assert!(!runnable.is_boot_task(), "a boot Task cannot be enqueued");
    let preempt_cpu = scheduler_singleton().enqueue(runnable, EnqueueFlags::Spawn);
    if let Some(preempt_cpu_id) = preempt_cpu {
        set_need_preempt(preempt_cpu_id);
    }

    might_preempt();
}

fn set_need_preempt(cpu_id: CpuId) {
    let preempt_guard = disable_preempt();

    if preempt_guard.current_cpu() == cpu_id {
        cpu_local::set_need_preempt();
    } else {
        #[cfg(feature = "kernelet")]
        {
            // KICK publishes the runnable work and wakes an idle carrier. The
            // target sets its own CPU-local preemption flag on delivery.
            let result = (crate::kernelet::entry::services().vcpu_kick)(u32::from(cpu_id));
            // A failed kick would leave the remote runnable task stranded.
            assert_eq!(result, 0, "failed to kick a virtual CPU");
        }

        #[cfg(not(feature = "kernelet"))]
        crate::smp::inter_processor_call(&crate::cpu::CpuSet::from(cpu_id), || {
            cpu_local::set_need_preempt();
        });
    }
}

/// Rechecks scheduling policy after a virtual KICK publishes work.
///
/// A KICK can also be a pure delivery doorbell. It does not itself authorize
/// picking another Task. Reuse the timer's policy/runtime update without
/// replaying a timer or charging a CPU-clock tick, and preserve any existing
/// preemption request if the policy does not request another one.
#[cfg(feature = "kernelet")]
pub(crate) fn check_preempt_after_virtual_kick() {
    if super::in_boot_task() {
        return;
    }
    // A bootstrap grant notification must not install the default FIFO
    // scheduler before the kernel injects its own scheduler.
    let Some(scheduler) = SCHEDULER.get() else {
        return;
    };
    update_current_on_tick(*scheduler);
}

/// Dequeues the current task from its runqueue.
///
/// This should only be called if the current is to exit.
#[track_caller]
pub(super) fn exit_current() -> ! {
    let mut is_first_try = true;

    let action = |local_rq: &mut dyn LocalRunQueue| {
        let next_task_opt = if is_first_try {
            is_first_try = false;
            let should_pick_next = local_rq.update_current(UpdateFlags::Exit);
            let _current = local_rq.dequeue_current();
            should_pick_next.then(|| local_rq.pick_next())
        } else {
            local_rq.try_pick_next()
        };

        if let Some(next_task) = next_task_opt {
            ReschedAction::SwitchTo(next_task.clone())
        } else {
            ReschedAction::Retry
        }
    };

    #[cfg(feature = "kernelet")]
    if super::in_boot_task() {
        super::atomic_mode::might_sleep();
        // A finite main that spawned nothing has no successor stack. Stop
        // through the protected Host stack; instance teardown owns its slot.
        // Do not initialize the default FIFO merely to inspect this case.
        if SCHEDULER.get().is_none() {
            crate::power::poweroff(crate::power::ExitCode::Success);
        }
        // Boot is not enqueued. Keep scheduling excluded continuously until
        // its Exit decision: this mark takes over before clearing BOOT.
        // RCU callbacks may sleep, so leave their dispatch to the next Task.
        let scheduling_guard = super::SchedulingGuard::new();
        cpu_local::leave_boot_task();
        reschedule_with_guard(action, scheduling_guard);
    } else {
        reschedule(action);
    }
    #[cfg(not(feature = "kernelet"))]
    reschedule(action);

    unreachable!()
}

/// Yields execution.
#[track_caller]
pub(super) fn yield_now() {
    #[cfg(feature = "kernelet")]
    assert!(
        !Task::current().is_some_and(|task| task.is_boot_task()),
        "a boot Task cannot yield"
    );
    reschedule(|local_rq| {
        let should_pick_next = local_rq.update_current(UpdateFlags::Yield);
        let next_task_opt = should_pick_next.then(|| local_rq.pick_next());
        if let Some(next_task) = next_task_opt {
            ReschedAction::SwitchTo(next_task.clone())
        } else {
            ReschedAction::DoNothing
        }
    })
}

/// Do rescheduling by acting on the scheduling decision (`ReschedAction`) made by a
/// user-given closure.
///
/// The closure makes the scheduling decision by taking the local runqueue has its input.
#[track_caller]
fn reschedule<F>(f: F)
where
    F: FnMut(&mut dyn LocalRunQueue) -> ReschedAction,
{
    super::atomic_mode::might_sleep();

    // RCU callbacks may sleep or yield. Run them before marking this Task's
    // scheduling transition and before committing a runqueue decision.
    // SAFETY: `might_sleep` checked that no preemption guard or RCU reader
    // is held and that local IRQs are enabled outside bootstrap context.
    unsafe { crate::sync::finish_grace_period() };

    // IRQs may run after the runqueue decision and before the context switch.
    // Keep their preemption checks from replacing this Task's unfinished
    // decision. The next Task has its own mark and can still be preempted.
    #[cfg(feature = "kernelet")]
    let scheduling_guard = super::SchedulingGuard::new();

    reschedule_with_guard(
        f,
        #[cfg(feature = "kernelet")]
        scheduling_guard,
    );
}

fn reschedule_with_guard<F>(
    mut f: F,
    #[cfg(feature = "kernelet")] _scheduling_guard: super::SchedulingGuard,
) where
    F: FnMut(&mut dyn LocalRunQueue) -> ReschedAction,
{
    // Even if the decision below is `DoNothing`, we should clear this flag. Meanwhile, to avoid
    // race conditions, we should do this before making the decision.
    cpu_local::clear_need_preempt();

    let next_task = loop {
        let mut action = ReschedAction::DoNothing;
        scheduler_singleton().mut_local_rq_with(&mut |rq| {
            action = f(rq);
        });

        match action {
            ReschedAction::DoNothing => {
                return;
            }
            ReschedAction::Retry => {
                continue;
            }
            ReschedAction::SwitchTo(next_task) => {
                break next_task;
            }
        };
    };

    // `switch_to_task` will spin if it finds that the next task is still running on some CPU core,
    // which guarantees soundness regardless of the scheduler implementation.
    //
    // FIXME: The scheduler decision and context switching are not atomic, which can lead to some
    // strange behavior even if the scheduler is implemented correctly. See "Problem 2" at
    // <https://github.com/asterinas/asterinas/issues/1633> for details.
    processor::switch_to_task(next_task);
}

/// Possible actions of a rescheduling.
enum ReschedAction {
    /// Keep running current task and do nothing.
    DoNothing,
    /// Loop until finding a task to swap out the current.
    Retry,
    /// Switch to target task.
    SwitchTo(Arc<Task>),
}

#[cfg(ktest)]
mod test {
    #[cfg(not(feature = "kernelet"))]
    use core::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    #[cfg(feature = "kernelet")]
    #[ktest]
    fn preemption_waits_for_scheduler_decision() {
        assert!(!super::super::scheduling_in_progress());

        reschedule(|_| {
            assert!(super::super::scheduling_in_progress());
            ReschedAction::DoNothing
        });

        assert!(!super::super::scheduling_in_progress());

        // The runqueue closure itself holds a preemption guard. Exercise the
        // later decision-to-switch window separately, without that guard.
        let scheduling_guard = super::super::SchedulingGuard::new();
        let irq_guard = crate::irq::disable_local();
        cpu_local::set_need_preempt();
        assert!(cpu_local::should_preempt());
        might_preempt();
        assert!(cpu_local::need_preempt());
        drop(irq_guard);
        assert!(cpu_local::need_preempt());
        cpu_local::clear_need_preempt();
        drop(scheduling_guard);
        assert!(!super::super::scheduling_in_progress());
    }

    #[cfg(feature = "kernelet-host")]
    #[ktest]
    fn host_preempt_guard_drop_keeps_pending_request() {
        // FIFO workers run on the BSP. One CPU excludes remote progress.
        if crate::cpu::num_cpus() != 1 {
            crate::early_println!("skipping Host guard-drop test: requires one CPU");
            return;
        }
        assert!(Task::current().is_some());
        assert!(crate::arch::irq::is_local_enabled());
        assert_eq!(cpu_local::get_guard_count(), 0);

        for _ in 0..8 {
            let ran = Arc::new(AtomicBool::new(false));
            let worker_ran = ran.clone();
            let preempt_guard = disable_preempt();
            let worker = crate::task::TaskOptions::new(move || {
                worker_ran.store(true, Ordering::Release);
            })
            .spawn()
            .unwrap();

            let irq_enabled_at_drop = crate::arch::irq::is_local_enabled();
            let before = crate::timer::Jiffies::elapsed().as_u64();
            cpu_local::set_need_preempt();
            drop(preempt_guard);
            let irq_guard = crate::irq::disable_local();
            let after = crate::timer::Jiffies::elapsed().as_u64();
            let ran_at_drop = ran.load(Ordering::Acquire);
            let pending_at_drop = cpu_local::need_preempt();
            // IRQ enable remains a scheduling point. Remove only this test's
            // request before restoring IRQs so explicit yield cleans up below.
            cpu_local::clear_need_preempt();
            drop(irq_guard);

            for _ in 0..16 {
                Task::yield_now();
                if ran.load(Ordering::Acquire) {
                    break;
                }
            }
            let completed = ran.load(Ordering::Acquire);
            drop(worker);
            assert!(
                completed,
                "Host worker did not complete after explicit yields"
            );
            assert!(
                irq_enabled_at_drop,
                "Host guard drop did not run with IRQs enabled"
            );

            // A timer IRQ may independently schedule after Drop. Retry such
            // windows after cleanup rather than attributing that switch to Drop.
            if before != after {
                continue;
            }
            assert!(
                !ran_at_drop,
                "Host preemption guard drop ran a worker before explicit yield"
            );
            assert!(
                pending_at_drop,
                "Host preemption guard drop consumed pending request"
            );
            return;
        }
        panic!("Host guard-drop test could not observe a window without a timer IRQ");
    }

    #[cfg(feature = "kernelet-host")]
    #[ktest]
    fn host_timer_irq_keeps_native_pending_request() {
        if crate::cpu::num_cpus() != 1 {
            crate::early_println!("skipping Host IRQ-return test: requires one CPU");
            return;
        }
        assert!(crate::arch::irq::is_local_enabled());
        let ran = Arc::new(AtomicBool::new(false));
        let worker_ran = ran.clone();
        let preempt_guard = disable_preempt();
        let worker = crate::task::TaskOptions::new(move || {
            worker_ran.store(true, Ordering::Release);
        })
        .spawn()
        .unwrap();
        cpu_local::set_need_preempt();
        drop(preempt_guard);

        // Exercise physical timer IRQ returns, without yielding or toggling
        // IRQs in this ordinary Host Task. The FIFO worker must stay queued.
        let start = crate::timer::Jiffies::elapsed().as_u64();
        while crate::timer::Jiffies::elapsed()
            .as_u64()
            .saturating_sub(start)
            < 3
        {
            core::hint::spin_loop();
        }
        let irq_guard = crate::irq::disable_local();
        let ran_on_irq_return = ran.load(Ordering::Acquire);
        let pending_on_irq_return = cpu_local::need_preempt();
        cpu_local::clear_need_preempt();
        drop(irq_guard);

        // Clean up real queued work before asserting either boundary.
        for _ in 0..16 {
            Task::yield_now();
            if ran.load(Ordering::Acquire) {
                break;
            }
        }
        assert!(ran.load(Ordering::Acquire), "Host worker did not complete");
        drop(worker);
        assert!(
            !ran_on_irq_return,
            "ordinary Host timer IRQ return ran a queued worker"
        );
        assert!(
            pending_on_irq_return,
            "ordinary Host timer IRQ return consumed pending preemption"
        );
    }

    #[cfg(not(any(feature = "kernelet-host", feature = "kernelet")))]
    #[ktest]
    fn native_pending_preempt_waits_for_explicit_yield() {
        // The standalone OSTD test kernel uses the default FIFO scheduler.
        // Its workers are queued on the BSP, so one CPU excludes remote progress.
        if crate::cpu::num_cpus() != 1 {
            crate::early_println!(
                "skipping native pending-preempt progress test: requires one CPU"
            );
            return;
        }
        assert!(Task::current().is_some());
        assert!(crate::arch::irq::is_local_enabled());

        fn observe_boundary(reenable_irqs: bool) -> bool {
            let ran = Arc::new(AtomicBool::new(false));
            let worker_ran = ran.clone();
            let preempt_guard = disable_preempt();
            let worker = crate::task::TaskOptions::new(move || {
                worker_ran.store(true, Ordering::Release);
            })
            .spawn()
            .unwrap();
            assert!(!ran.load(Ordering::Acquire));

            // First phase drops the final preemption guard with IRQs masked,
            // then restores IRQs. Second phase drops it with IRQs enabled.
            let irq_guard = reenable_irqs.then(crate::irq::disable_local);
            cpu_local::set_need_preempt();
            drop(preempt_guard);
            drop(irq_guard);
            let ran_before_yield = ran.load(Ordering::Acquire);

            // Always finish the real worker before asserting the boundary,
            // including when the old automatic-preemption path already ran it.
            // FIFO's explicit yield selects queued work, and this worker exits
            // immediately after publishing progress, before we resume.
            for _ in 0..16 {
                Task::yield_now();
                if ran.load(Ordering::Acquire) {
                    break;
                }
            }
            let completed = ran.load(Ordering::Acquire);
            drop(worker);
            assert!(
                completed,
                "Native worker did not complete after 16 explicit yields"
            );
            ran_before_yield
        }

        let ran_on_irq_enable = observe_boundary(true);
        let ran_on_guard_drop = observe_boundary(false);
        // Both workers have completed even when either assertion must fail.
        assert!(
            !ran_on_irq_enable,
            "Native pending preemption ran a worker at IRQ enable"
        );
        assert!(
            !ran_on_guard_drop,
            "Native pending preemption ran a worker at guard drop"
        );
    }

    #[cfg(not(feature = "kernelet"))]
    #[ktest]
    fn rcu_destructor_can_yield_before_scheduler_decision() {
        // Other CPUs must report their own quiescent states. This regression
        // uses one CPU so the real global grace period completes synchronously.
        if crate::cpu::num_cpus() != 1 {
            return;
        }

        struct YieldOnDrop(Arc<AtomicBool>);

        impl Drop for YieldOnDrop {
            fn drop(&mut self) {
                assert!(crate::arch::irq::is_local_enabled());
                Task::yield_now();
                self.0.store(true, Ordering::Release);
            }
        }

        let worker_ran = Arc::new(AtomicBool::new(false));
        let worker_observed = worker_ran.clone();
        let worker = crate::task::TaskOptions::new(move || {
            worker_observed.store(true, Ordering::Release);
        })
        .spawn()
        .unwrap();
        let dropped = Arc::new(AtomicBool::new(false));
        drop(crate::sync::RcuDrop::new(YieldOnDrop(dropped.clone())));

        // A prior grace period may precede the one containing this destructor.
        // Yield through the public API so the destructor itself can switch Tasks.
        for _ in 0..3 {
            Task::yield_now();
            if dropped.load(Ordering::Acquire) {
                break;
            }
        }

        assert!(dropped.load(Ordering::Acquire));
        assert!(worker_ran.load(Ordering::Acquire));
        drop(worker);
    }
}
