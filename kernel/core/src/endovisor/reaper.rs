// SPDX-License-Identifier: MPL-2.0

//! One Host task retries kernelet teardown after exit and reclaim notifications.
//!
//! A descriptor's last close only enqueues work. The reaper subscribes to each
//! instance's exit and reclaim queues before checking its state, so a release
//! racing the check cannot strand a zombie. All callbacks run outside locks.

use alloc::{boxed::Box, sync::Arc, vec::Vec};

use ostd::{
    kernelet::control::{DestroyError, ExitStatus, Kernelet, KerneletState},
    sync::{SpinLock, Waiter, Waker},
};
use spin::Once;

use crate::thread::kernel_thread::ThreadOptions;

struct Entry {
    cid: u32,
    kernelet: Arc<Kernelet>,
    action: Action,
}

enum Action {
    WatchExit {
        on_dying: Option<Box<dyn FnOnce() + Send>>,
        on_exit: Option<Box<dyn FnOnce(ExitStatus) + Send>>,
    },
    Destroy {
        cleanup: Option<Box<dyn FnOnce() + Send>>,
        on_destroy: Option<Box<dyn FnOnce() + Send>>,
    },
}

struct Reaper {
    incoming: SpinLock<Vec<Entry>>,
    waker: Once<Arc<Waker>>,
}

static REAPER: Once<Arc<Reaper>> = Once::new();

/// Starts the single Host retry task when the endovisor is registered.
pub(super) fn init() {
    REAPER.call_once(|| {
        let reaper = Arc::new(Reaper {
            incoming: SpinLock::new(Vec::new()),
            waker: Once::new(),
        });
        let worker = reaper.clone();
        ThreadOptions::new(move || worker.run()).spawn();
        reaper
    });
}

/// Hands ownership of teardown to the reaper without waiting on the caller.
///
/// The sandbox state machine enqueues each instance once. `cleanup` cancels
/// device models and revokes endpoints after exit. `on_destroy` publishes the
/// descriptor's final state after OSTD has reclaimed the instance. Neither
/// callback may retain an `Arc<Kernelet>` or wait for host I/O to finish.
pub(super) fn enqueue(
    cid: u32,
    kernelet: Arc<Kernelet>,
    cleanup: Option<Box<dyn FnOnce() + Send>>,
    on_destroy: Option<Box<dyn FnOnce() + Send>>,
) {
    submit(Entry {
        cid,
        kernelet,
        action: Action::Destroy {
            cleanup,
            on_destroy,
        },
    });
}

/// Observes a live descriptor until the reaper publishes its exit status.
/// The descriptor retains ownership of the instance until explicit destroy
/// or last close separately enqueues reclamation.
pub(super) fn watch_exit(
    cid: u32,
    kernelet: Arc<Kernelet>,
    on_dying: Box<dyn FnOnce() + Send>,
    on_exit: Box<dyn FnOnce(ExitStatus) + Send>,
) {
    submit(Entry {
        cid,
        kernelet,
        action: Action::WatchExit {
            on_dying: Some(on_dying),
            on_exit: Some(on_exit),
        },
    });
}

fn submit(entry: Entry) {
    let reaper = REAPER.get().expect("endovisor reaper is not initialized");
    reaper.incoming.lock().push(entry);
    // A worker starting concurrently checks the inbox after publishing its
    // waker. Once published, a direct wake is sticky until it next waits.
    if let Some(waker) = reaper.waker.get() {
        waker.wake_up();
    }
}

impl Reaper {
    fn run(&self) {
        let (waiter, waker) = Waiter::new_pair();
        self.waker.call_once(|| waker.clone());
        let mut pending = Vec::new();

        loop {
            let incoming = core::mem::take(&mut *self.incoming.lock());
            pending.extend(incoming);

            let mut index = 0;
            while index < pending.len() {
                let entry: &mut Entry = &mut pending[index];

                entry.kernelet.exit_wait_queue().enqueue_once(waker.clone());
                if matches!(
                    entry.kernelet.state(),
                    KerneletState::Dying
                        | KerneletState::Exited
                        | KerneletState::Destroying
                        | KerneletState::Destroyed
                ) && let Action::WatchExit { on_dying, .. } = &mut entry.action
                    && let Some(on_dying) = on_dying.take()
                {
                    on_dying();
                }
                let Some(exit) = entry.kernelet.reap() else {
                    index += 1;
                    continue;
                };
                match &mut entry.action {
                    Action::WatchExit { on_exit, .. } => {
                        if let Some(on_exit) = on_exit.take() {
                            on_exit(exit);
                        }
                        pending.swap_remove(index);
                        continue;
                    }
                    Action::Destroy { cleanup, .. } => {
                        if let Some(cleanup) = cleanup.take() {
                            cleanup();
                        }
                    }
                }

                if let Some(queue) = super::vsock_switch::retire_wait_queue(entry.cid) {
                    queue.enqueue_once(waker.clone());
                }
                if !super::vsock_switch::retired_drained(entry.cid) {
                    index += 1;
                    continue;
                }

                // Register before trying destroy. If a final pin drains during
                // the call, its wake remains pending even when destroy reports
                // Zombie after that release.
                if let Some(queue) = entry.kernelet.reclaim_wait_queue() {
                    queue.enqueue_once(waker.clone());
                }
                match entry.kernelet.destroy() {
                    Ok(_) | Err(DestroyError::NotExited(KerneletState::Destroyed)) => {
                        if let Action::Destroy { on_destroy, .. } = &mut entry.action
                            && let Some(on_destroy) = on_destroy.take()
                        {
                            on_destroy();
                        }
                        pending.swap_remove(index);
                    }
                    Err(DestroyError::Zombie { .. }) => index += 1,
                    Err(DestroyError::NotExited(state)) => {
                        // The sandbox serializes explicit destroy and retry.
                        // If that invariant is violated, retain the instance
                        // instead of publishing a false successful teardown.
                        ostd::error!(
                            "kernelet {} teardown found unexpected state {:?}",
                            entry.cid,
                            state
                        );
                        index += 1;
                    }
                }
            }

            waiter.wait();
        }
    }
}
