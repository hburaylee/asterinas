// SPDX-License-Identifier: MPL-2.0

//! Cancellable wakeups delegated to the kernel's existing timer manager.

use alloc::{boxed::Box, sync::Arc};
use core::time::Duration;

use spin::Once;

use crate::sync::WaitQueue;

/// A one-shot timer supplied by the Host kernel.
///
/// Dropping the handle must cancel the timer without waiting for a callback.
/// An already running callback may still wake the queue; callers recheck their
/// wait condition. The timer must retain no image or carrier state, and may
/// retain only a weak reference to its wake queue.
pub trait HostTimer: Send + Sync {
    /// Checks expiry in the same clock domain used to arm the timer.
    fn is_expired(&self) -> bool;
}

type TimerFactory = fn(Duration, &Arc<WaitQueue>) -> Box<dyn HostTimer>;
static TIMER_FACTORY: Once<TimerFactory> = Once::new();

/// Connects kernelet waits to the Host kernel's existing timer implementation.
///
/// Register during kernel initialization, before constructing instances. The
/// factory must be nonblocking, including with physical IRQs disabled. It must
/// arm a one-shot timer for the requested relative duration and wake the queue
/// on expiry. Later registrations leave the original factory in place.
pub fn register_host_timer(factory: TimerFactory) {
    TIMER_FACTORY.call_once(|| factory);
}

pub(crate) struct Deadline {
    timer: Box<dyn HostTimer>,
}

impl Deadline {
    pub(crate) fn after(duration: Duration, queue: &Arc<WaitQueue>) -> Self {
        let factory = TIMER_FACTORY
            .get()
            .expect("Host timer factory must be registered before kernelet waits");
        Self {
            timer: factory(duration, queue),
        }
    }

    pub(crate) fn is_expired(&self) -> bool {
        self.timer.is_expired()
    }
}

#[cfg(ktest)]
pub(crate) mod test {
    use core::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use crate::task::Task;

    // Standalone OSTD tests have no kernel TimerManager. This explicit test
    // backend uses ordinary FIFO Tasks; production has no fallback backend.
    struct TestState {
        cancelled: AtomicBool,
        expired: AtomicBool,
    }
    struct TestTimer(Arc<TestState>);
    impl HostTimer for TestTimer {
        fn is_expired(&self) -> bool {
            self.0.expired.load(Ordering::Acquire)
        }
    }
    impl Drop for TestTimer {
        fn drop(&mut self) {
            self.0.cancelled.store(true, Ordering::Release);
        }
    }
    pub(crate) fn init() {
        register_host_timer(|duration, queue| {
            let state = Arc::new(TestState {
                cancelled: AtomicBool::new(false),
                expired: AtomicBool::new(false),
            });
            let worker_state = state.clone();
            let queue = Arc::downgrade(queue);
            let at = crate::task::accounting::now_ns()
                .saturating_add(duration.as_nanos().min(u64::MAX as u128) as u64);
            crate::task::TaskOptions::new(move || {
                while !worker_state.cancelled.load(Ordering::Acquire) {
                    if crate::task::accounting::now_ns() >= at {
                        worker_state.expired.store(true, Ordering::Release);
                        if let Some(queue) = queue.upgrade() {
                            queue.wake_all();
                        }
                        return;
                    }
                    Task::yield_now();
                }
            })
            .spawn()
            .unwrap();
            Box::new(TestTimer(state))
        });
    }
}
