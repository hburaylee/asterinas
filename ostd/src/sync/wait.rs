// SPDX-License-Identifier: MPL-2.0

use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use super::{LocalIrqDisabled, SpinLock};
use crate::task::{Task, scheduler};

// # Explanation on the memory orders
//
// ```
// [CPU 1 (the waker)]     [CPU 2 (the waiter)]
// cond = true;
// wake_up();
//                         wait();
//                         if cond { /* .. */ }
// ```
//
// As soon as the waiter is woken up by the waker, it must see the true condition. This is
// trivially satisfied if `wake_up()` and `wait()` synchronize with a lock. But if they synchronize
// with an atomic variable, `wake_up()` must access the variable with `Ordering::Release` and
// `wait()` must access the variable with `Ordering::Acquire`.
//
// Examples of `wake_up()`:
//  - `WaitQueue::wake_one()`
//  - `WaitQueue::wake_all()`
//  - `Waker::wake_up()`
//
// Examples of `wait()`:
//  - `WaitQueue::wait_until()`
//  - `Waiter::wait()`
//  - `Waiter::drop()`
//
// Note that dropping a waiter must be treated as a `wait()` with zero timeout, because we need to
// make sure that the wake event isn't lost in this case.

/// A wait queue.
///
/// One may wait on a wait queue to put its executing thread to sleep.
/// Multiple threads may be the waiters of a wait queue.
/// Other threads may invoke the `wake`-family methods of a wait queue to
/// wake up one or many waiting threads.
pub struct WaitQueue {
    // A copy of `wakers.len()`, used for the lock-free fast path in `wake_one` and `wake_all`.
    num_wakers: AtomicU32,
    wakers: SpinLock<QueuedWakers, LocalIrqDisabled>,
}

impl WaitQueue {
    /// Creates a new, empty wait queue.
    pub const fn new() -> Self {
        WaitQueue {
            num_wakers: AtomicU32::new(0),
            wakers: SpinLock::new(QueuedWakers::new()),
        }
    }

    /// Waits until some condition is met.
    ///
    /// This method takes a closure that tests a user-given condition.
    /// The method only returns if the condition returns `Some(_)`.
    /// A waker thread should first make the condition `Some(_)`, then invoke the
    /// `wake`-family method. This ordering is important to ensure that waiter
    /// threads do not lose any wakeup notifications.
    ///
    /// By taking a condition closure, this wait-wakeup mechanism becomes
    /// more efficient and robust.
    #[track_caller]
    pub fn wait_until<F, R>(&self, mut cond: F) -> R
    where
        F: FnMut() -> Option<R>,
    {
        if let Some(res) = cond() {
            return res;
        }

        let (waiter, waker) = Waiter::new_pair();
        loop {
            // A normal wake removed the old registration. Check the condition
            // before inserting again, then recheck after insertion to close the
            // condition-change-before-registration window.
            if let Some(result) = cond() {
                return result;
            }
            let registration = {
                let mut wakers = self.wakers.lock();
                let index = wakers.push_back(waker.clone());
                self.num_wakers.fetch_add(1, Ordering::Acquire);
                index
            };
            if let Some(result) = cond() {
                // Close before unlinking so later wakes from a detached
                // batch observe the closed waiter.
                drop(waiter);
                self.remove_registration(registration, &waker);
                return result;
            }
            waiter.wait();
            // Only a queue wake can notify this private waker, and it removes
            // the registration first. Discard the old token before inserting
            // again; normal wakes require no cleanup lock or slot lookup.
        }
    }

    /// Wakes up one waiting thread, if there is one at the point of time when this method is
    /// called, returning whether such a thread was woken up.
    pub fn wake_one(&self) -> bool {
        // Fast path
        if self.is_empty() {
            return false;
        }

        loop {
            let mut wakers = self.wakers.lock();
            let Some(waker) = wakers.pop_front() else {
                return false;
            };
            self.num_wakers.fetch_sub(1, Ordering::Release);
            // Avoid holding lock when calling `wake_up`
            drop(wakers);

            if waker.wake_up() {
                return true;
            }
        }
    }

    /// Wakes up all currently waiting threads, returning the number of threads that were woken up.
    ///
    /// Waiters that register again during this call wait for a subsequent wake.
    pub fn wake_all(&self) -> usize {
        // Fast path
        if self.is_empty() {
            return 0;
        }

        let mut batch = self.take_batch();

        let mut num_woken = 0;
        while let Some(waker) = batch.pop_front() {
            if waker.wake_up() {
                num_woken += 1;
            }
        }

        // Keep the detached allocation for the next batch if no registration
        // needs the current allocation. Never discard concurrently added items.
        {
            let mut wakers = self.wakers.lock();
            if wakers.is_empty() && wakers.capacity() < batch.capacity() {
                core::mem::swap(&mut *wakers, &mut batch);
            }
        }
        // Any replaced empty allocation is freed after restoring IRQs.
        drop(batch);
        num_woken
    }

    fn take_batch(&self) -> QueuedWakers {
        let mut wakers = self.wakers.lock();
        // A woken Task may run and register again before wake_all returns.
        // Detach this batch so re-registration cannot extend its wake loop.
        self.num_wakers
            .fetch_sub(wakers.len() as u32, Ordering::Release);
        core::mem::take(&mut *wakers)
    }

    fn is_empty(&self) -> bool {
        // On x86-64, this generates `mfence; mov`, which is exactly the right way to implement
        // atomic loading with `Ordering::Release`. It performs much better than naively
        // translating `fetch_add(0)` to `lock; xadd`.
        self.num_wakers.fetch_add(0, Ordering::Release) == 0
    }

    /// Registers a waker unless this same waker is already queued.
    ///
    /// This supports an event loop that checks several queues after any one
    /// source wakes it. A repeated scan does not accumulate stale registrations.
    pub fn enqueue_once(&self, waker: Arc<Waker>) {
        let mut wakers = self.wakers.lock();
        if wakers.contains(&waker) {
            return;
        }
        wakers.push_back(waker);
        self.num_wakers.fetch_add(1, Ordering::Acquire);
    }

    /// Removes a token belonging to `wait_until`'s private, singly registered
    /// waker. The token must be retired before inserting that waker again.
    fn remove_registration(&self, index: usize, waker: &Arc<Waker>) {
        let removed = {
            let mut wakers = self.wakers.lock();
            let removed = wakers.remove_registration(index, waker);
            if removed.is_some() {
                self.num_wakers.fetch_sub(1, Ordering::Release);
            }
            removed
        };
        // The last Task reference can free its stack. Release it outside the
        // queue's IRQ-disabling lock, including when registration lost a race.
        drop(removed);
    }

    /// Enqueues the input [`Waker`] to the wait queue.
    #[doc(hidden)]
    pub fn enqueue(&self, waker: Arc<Waker>) {
        let mut wakers = self.wakers.lock();
        wakers.push_back(waker);
        self.num_wakers.fetch_add(1, Ordering::Acquire);
    }
}

/// A FIFO with reusable indexed slots. Tokens let a private waiter unlink its
/// own registration in constant time, without scanning unrelated waiters.
/// Public enqueue operations can still register one waker in multiple queues.
struct QueuedWakers {
    slots: Vec<WakerSlot>,
    head: usize,
    tail: usize,
    free: usize,
    len: usize,
}

// No Vec can allocate usize::MAX slots, so this index can never name a slot.
// Using a sentinel keeps each link to one word without unsafe pointers.
const NO_SLOT: usize = usize::MAX;

struct WakerSlot {
    waker: Option<Arc<Waker>>,
    previous: usize,
    // The next occupied slot, or the next free slot when waker is None.
    next: usize,
}

impl QueuedWakers {
    const fn new() -> Self {
        Self {
            slots: Vec::new(),
            head: NO_SLOT,
            tail: NO_SLOT,
            free: NO_SLOT,
            len: 0,
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn capacity(&self) -> usize {
        self.slots.capacity()
    }

    fn push_back(&mut self, waker: Arc<Waker>) -> usize {
        let slot = WakerSlot {
            waker: Some(waker),
            previous: self.tail,
            next: NO_SLOT,
        };
        let index = if self.free != NO_SLOT {
            let index = self.free;
            self.free = self.slots[index].next;
            self.slots[index] = slot;
            index
        } else {
            let index = self.slots.len();
            self.slots.push(slot);
            index
        };
        if self.tail != NO_SLOT {
            self.slots[self.tail].next = index;
        } else {
            self.head = index;
        }
        self.tail = index;
        self.len += 1;
        index
    }

    fn pop_front(&mut self) -> Option<Arc<Waker>> {
        (self.head != NO_SLOT).then(|| self.remove(self.head))
    }

    fn contains(&self, waker: &Arc<Waker>) -> bool {
        let mut next = self.head;
        while next != NO_SLOT {
            let slot = &self.slots[next];
            if Arc::ptr_eq(slot.waker.as_ref().unwrap(), waker) {
                return true;
            }
            next = slot.next;
        }
        false
    }

    fn remove_registration(&mut self, index: usize, waker: &Arc<Waker>) -> Option<Arc<Waker>> {
        // A wake may already have unlinked the slot, or wake_all may have
        // detached its entire allocation. A reused slot can belong to another
        // waiter; pointer equality prevents removing that registration.
        // No generation is needed: this private waker is never exposed and
        // wait_until retires its old token before its next insertion. Other
        // public enqueues never obtain tokens and can contain duplicates.
        let registered = self.slots.get(index)?.waker.as_ref()?;
        Arc::ptr_eq(registered, waker).then(|| self.remove(index))
    }

    fn remove(&mut self, index: usize) -> Arc<Waker> {
        let slot = &mut self.slots[index];
        let waker = slot.waker.take().unwrap();
        let previous = core::mem::replace(&mut slot.previous, NO_SLOT);
        let next = slot.next;
        slot.next = self.free;
        self.free = index;
        if previous != NO_SLOT {
            self.slots[previous].next = next;
        } else {
            self.head = next;
        }
        if next != NO_SLOT {
            self.slots[next].previous = previous;
        } else {
            self.tail = previous;
        }
        self.len -= 1;
        waker
    }
}

impl Default for QueuedWakers {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// A waiter that can put the current thread to sleep until it is woken up by the associated
/// [`Waker`].
///
/// By definition, a waiter belongs to the current thread, so it cannot be sent to another thread
/// and its reference cannot be shared between threads.
pub struct Waiter {
    waker: Arc<Waker>,
}

impl !Send for Waiter {}
impl !Sync for Waiter {}

/// A waker that can wake up the associated [`Waiter`].
///
/// A waker can be created by calling [`Waiter::new_pair`]. This method creates an `Arc<Waker>` that can
/// be used across different threads.
pub struct Waker {
    has_woken: AtomicBool,
    task: Arc<Task>,
}

impl Waiter {
    /// Creates a waiter and its associated [`Waker`].
    pub fn new_pair() -> (Self, Arc<Waker>) {
        let waker = Arc::new(Waker {
            has_woken: AtomicBool::new(false),
            task: Task::current().unwrap().cloned(),
        });
        let waiter = Self {
            waker: waker.clone(),
        };
        (waiter, waker)
    }

    /// Waits until the waiter is woken up by calling [`Waker::wake_up`] on the associated
    /// [`Waker`].
    ///
    /// This method returns immediately if the waiter has been woken since the end of the last call
    /// to this method (or since the waiter was created, if this method has not been called
    /// before). Otherwise, it puts the current thread to sleep until the waiter is woken up.
    #[track_caller]
    pub fn wait(&self) {
        self.waker.do_wait();
    }

    /// Waits until some condition is met or the cancel condition becomes true.
    ///
    /// This method will return `Ok(_)` if the condition returns `Some(_)`, and will stop waiting
    /// if the cancel condition returns `Err(_)`. In this situation, this method will return the `Err(_)`
    /// generated by the cancel condition.
    #[track_caller]
    pub fn wait_until_or_cancelled<F, R, FCancel, E>(
        &self,
        mut cond: F,
        cancel_cond: FCancel,
    ) -> Result<R, E>
    where
        F: FnMut() -> Option<R>,
        FCancel: Fn() -> Result<(), E>,
    {
        loop {
            if let Some(res) = cond() {
                return Ok(res);
            };

            if let Err(e) = cancel_cond() {
                // Close the waker and check again to avoid missing a wake event.
                self.waker.close();
                return cond().ok_or(e);
            }

            self.wait();
        }
    }

    /// Gets the associated [`Waker`] of the current waiter.
    pub fn waker(&self) -> Arc<Waker> {
        self.waker.clone()
    }

    /// Returns the task that the associated waker will attempt to wake up.
    pub fn task(&self) -> &Arc<Task> {
        &self.waker.task
    }
}

impl Drop for Waiter {
    fn drop(&mut self) {
        // When dropping the waiter, we need to close the waker to ensure that if someone wants to
        // wake up the waiter afterwards, they will perform a no-op.
        self.waker.close();
    }
}

impl Waker {
    /// Wakes up the associated [`Waiter`].
    ///
    /// This method returns `true` if the waiter is woken by this call. It returns `false` if the
    /// waiter has already been woken by a previous call to the method, or if the waiter has been
    /// dropped.
    ///
    /// Note that if this method returns `true`, it implies that the wake event will be properly
    /// delivered, _or_ that the waiter will be dropped after being woken. It's up to the caller to
    /// handle the latter case properly to avoid missing the wake event.
    pub fn wake_up(&self) -> bool {
        if self.has_woken.swap(true, Ordering::Release) {
            return false;
        }
        scheduler::unpark_target(self.task.clone());

        true
    }

    #[track_caller]
    fn do_wait(&self) {
        while !self.has_woken.swap(false, Ordering::Acquire) {
            scheduler::park_current(|| self.has_woken.load(Ordering::Acquire));
        }
    }

    fn close(&self) {
        // This must use `Ordering::Acquire`, although we do not care about the return value. See
        // the memory order explanation at the top of the file for details.
        let _ = self.has_woken.swap(true, Ordering::Acquire);
    }
}

#[cfg(ktest)]
mod test {
    use super::*;
    use crate::{prelude::*, task::TaskOptions};

    fn queue_wake<F>(wake: F)
    where
        F: Fn(&WaitQueue) + Sync + Send + 'static,
    {
        let queue = Arc::new(WaitQueue::new());
        let queue_cloned = queue.clone();

        let cond = Arc::new(AtomicBool::new(false));
        let cond_cloned = cond.clone();

        TaskOptions::new(move || {
            Task::yield_now();

            cond_cloned.store(true, Ordering::Relaxed);
            wake(&queue_cloned);
        })
        .data(())
        .spawn()
        .unwrap();

        queue.wait_until(|| cond.load(Ordering::Relaxed).then_some(()));

        assert!(cond.load(Ordering::Relaxed));
    }

    #[ktest]
    fn queue_wake_one() {
        queue_wake(|queue| {
            queue.wake_one();
        });
    }

    #[ktest]
    fn queue_wake_all() {
        queue_wake(|queue| {
            queue.wake_all();
        });
    }

    #[ktest]
    fn wake_all_counts_live_waiters() {
        let queue = WaitQueue::new();
        let (closed_waiter, closed_waker) = Waiter::new_pair();
        let (waiter, waker) = Waiter::new_pair();
        queue.enqueue(closed_waker);
        queue.enqueue(waker.clone());
        queue.enqueue(waker.clone());
        drop(closed_waiter);

        assert_eq!(queue.wake_all(), 1);
        assert!(queue.is_empty());
        assert_eq!(queue.wake_all(), 0);
        waiter.wait();

        // A fresh registration after the notification must remain wakeable.
        queue.enqueue(waker);
        assert!(!queue.is_empty());
        assert_eq!(queue.wake_all(), 1);
        waiter.wait();
        assert!(queue.is_empty());
    }

    #[ktest]
    fn completed_wait_releases_its_task_reference() {
        let queue = WaitQueue::new();
        let task = Task::current().unwrap().cloned();
        let references = Arc::strong_count(&task);
        let mut probes = 0;

        queue.wait_until(|| {
            probes += 1;
            (probes == 3).then_some(())
        });

        assert!(queue.is_empty());
        assert_eq!(Arc::strong_count(&task), references);
    }

    #[ktest]
    fn condition_can_wake_its_own_registration_before_returning() {
        let queue = WaitQueue::new();
        let task = Task::current().unwrap().cloned();
        let references = Arc::strong_count(&task);
        let mut probes = 0;
        queue.wait_until(|| {
            probes += 1;
            if probes != 3 {
                return None;
            }
            // The condition runs outside the queue lock. A synchronous wake
            // can retire its token before successful-condition cleanup.
            assert_eq!(queue.wake_all(), 1);
            Some(())
        });
        assert!(queue.is_empty());
        assert_eq!(Arc::strong_count(&task), references);
    }

    #[ktest]
    fn cancelled_registration_preserves_fifo_and_reuses_slots() {
        let (_first_waiter, first) = Waiter::new_pair();
        let (_second_waiter, second) = Waiter::new_pair();
        let (_third_waiter, third) = Waiter::new_pair();
        let mut queued = QueuedWakers::new();
        queued.push_back(first.clone());
        let cancelled = queued.push_back(second.clone());
        queued.push_back(third.clone());
        assert!(Arc::ptr_eq(
            &queued.remove_registration(cancelled, &second).unwrap(),
            &second
        ));
        let (_replacement_waiter, replacement) = Waiter::new_pair();
        assert_eq!(queued.push_back(replacement.clone()), cancelled);
        // A retired token must not unlink a different waiter using its slot.
        assert!(queued.remove_registration(cancelled, &second).is_none());
        assert!(Arc::ptr_eq(&queued.pop_front().unwrap(), &first));
        assert!(Arc::ptr_eq(&queued.pop_front().unwrap(), &third));
        assert!(Arc::ptr_eq(&queued.pop_front().unwrap(), &replacement));
        assert!(queued.is_empty());
    }

    #[ktest]
    fn mixed_registration_cancellation_keeps_fifo_order() {
        let pairs: Vec<_> = (0..16).map(|_| Waiter::new_pair()).collect();
        let mut queued = QueuedWakers::new();
        let mut expected = alloc::collections::VecDeque::new();
        let mut registrations = [None; 16];
        let mut random = 0x1234_5678u32;
        for _ in 0..512 {
            random = random.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let item = (random as usize >> 8) % pairs.len();
            match random % 3 {
                0 if registrations[item].is_none() => {
                    registrations[item] = Some(queued.push_back(pairs[item].1.clone()));
                    expected.push_back(item);
                }
                1 => {
                    if let Some(index) = registrations[item].take() {
                        let removed = queued.remove_registration(index, &pairs[item].1).unwrap();
                        assert!(Arc::ptr_eq(&removed, &pairs[item].1));
                        expected.retain(|&entry| entry != item);
                    }
                }
                _ => {
                    let actual = queued.pop_front();
                    if let Some(item) = expected.pop_front() {
                        assert!(Arc::ptr_eq(&actual.unwrap(), &pairs[item].1));
                        registrations[item] = None;
                    } else {
                        assert!(actual.is_none());
                    }
                }
            }
            assert_eq!(queued.len(), expected.len());
        }
        while let Some(item) = expected.pop_front() {
            assert!(Arc::ptr_eq(&queued.pop_front().unwrap(), &pairs[item].1));
        }
        assert!(queued.is_empty());
    }

    #[ktest]
    fn detached_batch_does_not_consume_a_reregistered_waiter() {
        let queue = WaitQueue::new();
        let (waiter, waker) = Waiter::new_pair();
        queue.enqueue(waker.clone());
        let mut batch = queue.take_batch();
        assert!(batch.pop_front().unwrap().wake_up());
        waiter.wait();
        // Model a resumed waiter registering while the detached batch is
        // still being processed. That registration needs the next wake.
        queue.enqueue(waker);
        assert!(batch.pop_front().is_none());
        assert!(!queue.is_empty());
        assert_eq!(queue.wake_all(), 1);
        waiter.wait();
        assert!(queue.is_empty());
    }

    #[ktest]
    fn repeated_wake_batches_reuse_capacity_and_multi_queue_wakers() {
        let queue = WaitQueue::new();
        let other = WaitQueue::new();
        let (waiter, waker) = Waiter::new_pair();
        queue.enqueue_once(waker.clone());
        queue.enqueue_once(waker.clone());
        other.enqueue_once(waker.clone());
        assert_eq!(queue.wake_all(), 1);
        let capacity = queue.wakers.lock().capacity();
        assert!(capacity > 0);
        assert_eq!(other.wake_all(), 0);
        waiter.wait();
        for _ in 0..16 {
            queue.enqueue(waker.clone());
            assert_eq!(queue.wake_all(), 1);
            waiter.wait();
            assert_eq!(queue.wakers.lock().capacity(), capacity);
        }
    }

    #[ktest]
    fn waiter_wake_twice() {
        let (_waiter, waker) = Waiter::new_pair();

        assert!(waker.wake_up());
        assert!(!waker.wake_up());
    }

    #[ktest]
    fn waiter_wake_drop() {
        let (waiter, waker) = Waiter::new_pair();

        drop(waiter);
        assert!(!waker.wake_up());
    }

    #[ktest]
    fn waiter_wake_async() {
        let (waiter, waker) = Waiter::new_pair();

        let cond = Arc::new(AtomicBool::new(false));
        let cond_cloned = cond.clone();

        TaskOptions::new(move || {
            Task::yield_now();

            cond_cloned.store(true, Ordering::Relaxed);
            assert!(waker.wake_up());
        })
        .data(())
        .spawn()
        .unwrap();

        waiter.wait();

        assert!(cond.load(Ordering::Relaxed));
    }

    #[ktest]
    fn waiter_wake_reorder() {
        let (waiter, waker) = Waiter::new_pair();

        let cond = Arc::new(AtomicBool::new(false));
        let cond_cloned = cond.clone();

        let (waiter2, waker2) = Waiter::new_pair();

        let cond2 = Arc::new(AtomicBool::new(false));
        let cond2_cloned = cond2.clone();

        TaskOptions::new(move || {
            Task::yield_now();

            cond2_cloned.store(true, Ordering::Relaxed);
            assert!(waker2.wake_up());

            Task::yield_now();

            cond_cloned.store(true, Ordering::Relaxed);
            assert!(waker.wake_up());
        })
        .data(())
        .spawn()
        .unwrap();

        waiter.wait();
        assert!(cond.load(Ordering::Relaxed));

        waiter2.wait();
        assert!(cond2.load(Ordering::Relaxed));
    }
}
