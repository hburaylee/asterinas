// SPDX-License-Identifier: MPL-2.0

//! Connects OSTD carrier waits to the ordinary Host monotonic timers.

use core::time::Duration;

use ostd::{
    kernelet::control::{HostTimer, register_host_timer},
    sync::WaitQueue,
};

use super::{Timer, TimerManager, clocks::MonotonicClock, timer::Timeout};
use crate::prelude::*;

struct CarrierTimer(Arc<Timer>);

impl HostTimer for CarrierTimer {
    fn is_expired(&self) -> bool {
        self.0.lock().remain() == Duration::ZERO
    }
}

impl Drop for CarrierTimer {
    fn drop(&mut self) {
        self.0.lock().cancel();
    }
}

pub(super) fn init() {
    register_host_timer(|duration, queue: &Arc<WaitQueue>| {
        arm(MonotonicClock::timer_manager(), duration, queue)
    });
}

fn arm(
    manager: &Arc<TimerManager>,
    duration: Duration,
    queue: &Arc<WaitQueue>,
) -> Box<dyn HostTimer> {
    let queue = Arc::downgrade(queue);
    let timer = manager.create_timer(move |_| {
        if let Some(queue) = queue.upgrade() {
            queue.wake_all();
        }
    });
    timer.lock().set_timeout(Timeout::After(duration));
    Box::new(CarrierTimer(timer))
}

#[cfg(ktest)]
mod test {
    use core::sync::atomic::{AtomicU64, Ordering};

    use ostd::{prelude::ktest, sync::Waiter};

    use super::*;

    // Advance time explicitly while exercising the real Host TimerManager,
    // callback, expiry query and cancellation implementation.
    struct TestClock(AtomicU64);
    impl crate::time::Clock for TestClock {
        fn read_time(&self) -> Duration {
            Duration::from_nanos(self.0.load(Ordering::Relaxed))
        }
    }

    #[ktest]
    fn deadline_wakes_at_expiry_and_can_be_rearmed() {
        let clock = Arc::new(TestClock(AtomicU64::new(100)));
        let manager = TimerManager::new(clock.clone());
        let queue = Arc::new(WaitQueue::new());
        for start in [100, 110] {
            let (_waiter, waker) = Waiter::new_pair();
            queue.enqueue(waker.clone());
            let timer = arm(&manager, Duration::from_nanos(10), &queue);
            assert!(!timer.is_expired());
            clock.0.store(start + 9, Ordering::Relaxed);
            manager.process_expired_timers();
            assert!(!timer.is_expired());
            clock.0.store(start + 10, Ordering::Relaxed);
            manager.process_expired_timers();
            assert!(timer.is_expired());
            assert!(!waker.wake_up(), "expired timer did not wake the queue");
        }
    }

    #[ktest]
    fn timer_cancellation_rearm_and_periodic_expiry_preserve_order() {
        let clock = Arc::new(TestClock(AtomicU64::new(0)));
        let manager = TimerManager::new(clock.clone());
        let calls = Arc::new(
            ostd::sync::SpinLock::<Vec<u64>, ostd::sync::LocalIrqDisabled>::new(Vec::new()),
        );
        let mut timers = Vec::new();
        let mut expected = Vec::new();
        for index in 0..97u64 {
            let calls = calls.clone();
            let timer = manager.create_timer(move |_| calls.lock().push(index));
            let mut expiry = (index * 37) % 97 + 1;
            timer
                .lock()
                .set_timeout(Timeout::After(Duration::from_nanos(expiry)));
            if index % 3 == 0 {
                timer.lock().cancel();
            }
            if index % 7 == 0 {
                expiry = 200 + index;
                timer
                    .lock()
                    .set_timeout(Timeout::After(Duration::from_nanos(expiry)));
            }
            if index % 3 != 0 || index % 7 == 0 {
                expected.push((expiry, index));
            }
            timers.push(timer);
        }
        assert_eq!(manager.pending_count(), expected.len());
        expected.sort();
        clock.0.store(300, Ordering::Relaxed);
        manager.process_expired_timers();
        assert_eq!(
            *calls.lock(),
            expected.iter().map(|(_, index)| *index).collect::<Vec<_>>()
        );
        assert_eq!(manager.pending_count(), 0);
        drop(timers);
        let periodic = manager.create_timer(|_| {});
        periodic.lock().set_interval(Duration::from_nanos(2));
        periodic
            .lock()
            .set_timeout(Timeout::After(Duration::from_nanos(1)));
        for now in [301, 303, 305] {
            clock.0.store(now, Ordering::Relaxed);
            manager.process_expired_timers();
            assert_eq!(periodic.lock().remain(), Duration::from_nanos(2));
            assert_eq!(manager.pending_count(), 1);
        }
        drop(periodic);
        assert_eq!(manager.pending_count(), 0);
    }

    #[ktest]
    fn early_wake_does_not_retain_later_cancelled_deadlines() {
        let manager = TimerManager::new(Arc::new(TestClock(AtomicU64::new(0))));
        let queue = Arc::new(WaitQueue::new());
        let live = arm(&manager, Duration::from_secs(1), &queue);
        for _ in 0..1024 {
            drop(arm(&manager, Duration::from_secs(3600), &queue));
            assert_eq!(manager.pending_count(), 1);
        }
        manager.process_expired_timers();
        assert_eq!(manager.pending_count(), 1);
        drop(live);
        assert_eq!(manager.pending_count(), 0);
    }

    #[ktest]
    fn cancellation_preserves_other_timers_and_does_not_retain_queue() {
        let clock = Arc::new(TestClock(AtomicU64::new(0)));
        let manager = TimerManager::new(clock.clone());
        let cancelled_queue = Arc::new(WaitQueue::new());
        let live_queue = Arc::new(WaitQueue::new());
        let (_cancelled_waiter, cancelled_waker) = Waiter::new_pair();
        let (_live_waiter, live_waker) = Waiter::new_pair();
        cancelled_queue.enqueue(cancelled_waker.clone());
        live_queue.enqueue(live_waker.clone());
        let cancelled = arm(&manager, Duration::from_nanos(10), &cancelled_queue);
        let live = arm(&manager, Duration::from_nanos(10), &live_queue);
        assert_eq!(Arc::strong_count(&cancelled_queue), 1);
        drop(cancelled);
        clock.0.store(10, Ordering::Relaxed);
        manager.process_expired_timers();
        assert!(
            cancelled_waker.wake_up(),
            "cancelled timer still woke its queue"
        );
        assert!(
            !live_waker.wake_up(),
            "cancelling another timer lost this wakeup"
        );
        assert!(live.is_expired());

        let queue = Arc::new(WaitQueue::new());
        let weak = Arc::downgrade(&queue);
        let timer = arm(&manager, Duration::from_nanos(10), &queue);
        drop(queue);
        assert!(weak.upgrade().is_none());
        clock.0.store(20, Ordering::Relaxed);
        manager.process_expired_timers();
        assert!(timer.is_expired());
    }
}
