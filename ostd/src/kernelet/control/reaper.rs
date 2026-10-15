// SPDX-License-Identifier: MPL-2.0

//! The single Host worker for lifecycle callbacks and deferred reclamation.
//!
//! OSTD owns the worker and its queues. The Host supplies only the factory
//! that wraps its body in a native scheduler-compatible thread.

use alloc::{
    boxed::Box,
    sync::{Arc, Weak},
    vec::Vec,
};

use spin::Once;

use super::{DestroyError, ExitStatus, Kernelet, KerneletHooks, KerneletState};
use crate::{
    Error,
    sync::{SpinLock, Waiter, Waker},
    task::Task,
};

/// Host-specific prerequisites and notifications for deferred reclamation.
///
/// All callbacks run on the reaper without subsystem locks. `prepare` runs
/// once after exit. `ready` subscribes to Host-specific release queues before
/// checking whether those references have drained. `complete` runs once after
/// reclamation. Callbacks must not retain their own instance or wait for I/O.
pub struct ReclaimCallbacks {
    pub prepare: Option<Box<dyn FnOnce() + Send>>,
    pub ready: Box<dyn FnMut(&Arc<Waker>) -> bool + Send>,
    pub complete: Option<Box<dyn FnOnce() + Send>>,
}

struct Lifecycle {
    kernelet: Weak<Kernelet>,
    running: Option<Arc<Kernelet>>,
    hooks: Option<Arc<dyn KerneletHooks>>,
    notified_dying: bool,
}

struct Observer {
    kernelet: Arc<Kernelet>,
    action: Action,
}

enum Action {
    WatchExit(Box<dyn FnOnce(ExitStatus) + Send>),
    Reclaim(ReclaimCallbacks),
}

enum Incoming {
    Lifecycle(Lifecycle),
    Started(Arc<Kernelet>),
    Observer(Observer),
}

struct Reaper {
    incoming: SpinLock<Vec<Incoming>>,
    waker: Once<Arc<Waker>>,
}

static REAPER: Once<Arc<Reaper>> = Once::new();

/// Initializes the machine's single kernelet reaper.
///
/// The factory builds a dormant native Task for the supplied body. OSTD queues
/// it after initialization is published. The Host must call this after its
/// allocator and scheduler are ready, before creating an instance. Repeated
/// successful initialization does not build another Task; a failed factory
/// leaves initialization retryable.
pub fn init_reaper(
    build_fn: impl FnOnce(Box<dyn FnOnce() + Send>) -> crate::Result<Arc<Task>>,
) -> crate::Result<()> {
    let mut task = None;
    let reaper = REAPER.try_call_once(|| {
        let reaper = Arc::new(Reaper {
            incoming: SpinLock::new(Vec::new()),
            waker: Once::new(),
        });
        let worker = reaper.clone();
        task = Some(build_fn(Box::new(move || worker.run()))?);
        Ok::<_, Error>(reaper)
    })?;
    if let Some(task) = task {
        let timer_reaper = reaper.clone();
        crate::timer::register_callback_on_cpu(move || {
            if let Some(waker) = timer_reaper.waker.get()
                && super::take_reaper_notification()
            {
                waker.wake_up();
            }
        });
        task.run();
    }
    Ok(())
}

pub(super) fn require_initialized() -> crate::Result<()> {
    REAPER.get().map(|_| ()).ok_or(Error::AccessDenied)
}

pub(super) fn track(kernelet: &Arc<Kernelet>) {
    submit(Incoming::Lifecycle(Lifecycle {
        kernelet: Arc::downgrade(kernelet),
        running: None,
        hooks: None,
        notified_dying: false,
    }));
}

pub(super) fn retain_started(kernelet: Arc<Kernelet>) {
    submit(Incoming::Started(kernelet));
}

pub(super) fn notify() {
    if let Some(reaper) = REAPER.get()
        && let Some(waker) = reaper.waker.get()
    {
        waker.wake_up();
    }
}

/// Queues a once-only exit observer on the kernelet reaper.
pub fn watch_exit(
    kernelet: Arc<Kernelet>,
    on_exit: Box<dyn FnOnce(ExitStatus) + Send>,
) -> crate::Result<()> {
    require_initialized()?;
    submit(Incoming::Observer(Observer {
        kernelet,
        action: Action::WatchExit(on_exit),
    }));
    Ok(())
}

/// Hands deferred reclamation to the same worker that delivers lifecycle hooks.
pub fn enqueue_reclaim(kernelet: Arc<Kernelet>, callbacks: ReclaimCallbacks) -> crate::Result<()> {
    require_initialized()?;
    submit(Incoming::Observer(Observer {
        kernelet,
        action: Action::Reclaim(callbacks),
    }));
    Ok(())
}

fn submit(incoming: Incoming) {
    let reaper = REAPER.get().expect("kernelet reaper is not initialized");
    reaper.incoming.lock().push(incoming);
    // The worker scans its inbox after publishing its own Task's waker. Once
    // published, a direct wake is sticky until the worker's next wait.
    if let Some(waker) = reaper.waker.get() {
        waker.wake_up();
    }
}

impl Reaper {
    fn run(&self) {
        let (waiter, waker) = Waiter::new_pair();
        self.waker.call_once(|| waker.clone());
        let mut lifecycles = Vec::new();
        let mut observers = Vec::new();
        loop {
            let incoming = core::mem::take(&mut *self.incoming.lock());
            for incoming in incoming {
                match incoming {
                    Incoming::Lifecycle(entry) => lifecycles.push(entry),
                    Incoming::Started(kernelet) => {
                        let weak = Arc::downgrade(&kernelet);
                        let entry = lifecycles
                            .iter_mut()
                            .find(|entry| entry.kernelet.ptr_eq(&weak))
                            .expect("started kernelet has no lifecycle registration");
                        entry.running = Some(kernelet);
                    }
                    Incoming::Observer(entry) => observers.push(entry),
                }
            }
            // Publish and deliver lifecycle events before descriptor observers,
            // regardless of their order of registration in the inbox.
            let mut index = 0;
            while index < lifecycles.len() {
                let entry = &mut lifecycles[index];
                let Some(kernelet) = entry.kernelet.upgrade() else {
                    lifecycles.swap_remove(index);
                    continue;
                };
                if entry.running.is_none() {
                    // start queues the strong owner before publishing Running.
                    // That inbox item may arrive after this pass drained the
                    // inbox, so leave started instances for the next pass. An
                    // acquired Dying observation followed by active then
                    // started distinguishes inline Created teardown from a
                    // start whose reservation is still being handed off.
                    let state = kernelet.state();
                    if matches!(state, KerneletState::Created | KerneletState::Running)
                        || (state == KerneletState::Dying
                            && (kernelet
                                .control
                                .active
                                .load(core::sync::atomic::Ordering::Acquire)
                                & !super::host_run::STOP_REQUESTED
                                != 0
                                || kernelet
                                    .control
                                    .started
                                    .load(core::sync::atomic::Ordering::Acquire)))
                    {
                        index += 1;
                        continue;
                    }
                }
                kernelet.exit_wait_queue().enqueue_once(waker.clone());
                if kernelet.begin_reap() {
                    if !entry.notified_dying {
                        entry.notified_dying = true;
                        if kernelet
                            .control
                            .started
                            .load(core::sync::atomic::Ordering::Acquire)
                        {
                            entry.hooks = kernelet.control.hooks.lock().clone();
                            let reason = kernelet.stop_reason();
                            entry
                                .hooks
                                .as_ref()
                                .expect("started kernelet lost its hooks")
                                .on_dying(&kernelet, &reason);
                        }
                    }
                    if let Some(status) = kernelet.finish_reap() {
                        if let Some(hooks) = &entry.hooks {
                            hooks.on_exited(&kernelet, &status);
                        }
                        lifecycles.swap_remove(index);
                        continue;
                    }
                } else if kernelet.exit_status().is_some() {
                    // Created instances can exit inline without any carrier
                    // having run. The book skips their lifecycle callbacks.
                    lifecycles.swap_remove(index);
                    continue;
                }
                index += 1;
            }

            let mut index = 0;
            while index < observers.len() {
                let entry = &mut observers[index];
                entry.kernelet.exit_wait_queue().enqueue_once(waker.clone());
                let Some(status) = entry.kernelet.exit_status() else {
                    index += 1;
                    continue;
                };
                match &mut entry.action {
                    Action::WatchExit(_) => {
                        let Observer {
                            action: Action::WatchExit(on_exit),
                            ..
                        } = observers.swap_remove(index)
                        else {
                            unreachable!();
                        };
                        on_exit(status);
                    }
                    Action::Reclaim(callbacks) => {
                        if let Some(prepare) = callbacks.prepare.take() {
                            prepare();
                        }
                        if !(callbacks.ready)(&waker) {
                            index += 1;
                            continue;
                        }
                        if let Some(queue) = entry.kernelet.reclaim_wait_queue() {
                            queue.enqueue_once(waker.clone());
                        }
                        match entry.kernelet.destroy() {
                            Ok(_) | Err(DestroyError::NotExited(KerneletState::Destroyed)) => {
                                if let Some(complete) = callbacks.complete.take() {
                                    complete();
                                }
                                observers.swap_remove(index);
                            }
                            Err(DestroyError::Zombie { .. }) => index += 1,
                            Err(DestroyError::NotExited(state)) => {
                                crate::error!(
                                    "kernelet teardown found unexpected state {:?}",
                                    state
                                );
                                index += 1;
                            }
                        }
                    }
                }
            }
            waiter.wait();
        }
    }
}
