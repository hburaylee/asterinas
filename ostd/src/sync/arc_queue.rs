// SPDX-License-Identifier: MPL-2.0

//! A FIFO queue of `Arc`-owned objects with links allocated at object creation.

use alloc::sync::Arc;
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};

use intrusive_collections::{LinkedList, LinkedListAtomicLink, intrusive_adapter};

/// An object's reusable queue link.
///
/// An object can be pending in only one queue at a time. Removing it releases
/// the link for reuse, including when the queue itself is dropped.
pub struct ArcQueueLink<T> {
    pending: AtomicBool,
    link: LinkedListAtomicLink,
    item: UnsafeCell<Option<Arc<T>>>,
}

// SAFETY: Only the queue that claimed `pending` may access `item`. Its
// operations are serialized by exclusive access to the queue; readers borrow
// that queue. Removal clears `item` before releasing `pending`, so another
// queue cannot access it concurrently. Sharing the stored object requires Sync.
unsafe impl<T: Send + Sync> Sync for ArcQueueLink<T> {}

intrusive_adapter!(QueueAdapter<T> = Arc<ArcQueueLink<T>>: ArcQueueLink<T> {
    link: LinkedListAtomicLink
});

impl<T> ArcQueueLink<T> {
    /// Creates a reusable link when its owner is constructed.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            pending: AtomicBool::new(false),
            link: LinkedListAtomicLink::new(),
            item: UnsafeCell::new(None),
        })
    }
}

/// Supplies a queueable object's reusable link.
pub trait ArcQueueItem: Send + Sync + Sized {
    /// Returns this object's link.
    ///
    /// Objects that share a link cannot be queued at the same time.
    fn queue_link(&self) -> &Arc<ArcQueueLink<Self>>;
}

/// A FIFO queue whose insertion requires no allocation.
///
/// Callers serialize access to the queue, for example with a `SpinLock` or a
/// CPU-local value and disabled local IRQs. A link can be pending in only one
/// queue at a time, including when an entire queue is moved for processing.
pub struct ArcQueue<T: ArcQueueItem> {
    list: LinkedList<QueueAdapter<T>>,
}

impl<T: ArcQueueItem> ArcQueue<T> {
    /// Creates an empty queue.
    pub const fn new() -> Self {
        Self {
            list: LinkedList::new(QueueAdapter::NEW),
        }
    }

    /// Appends an object, returning false if its link is already pending.
    pub fn push_back(&mut self, item: Arc<T>) -> bool {
        let link = Arc::clone(item.queue_link());
        if link
            .pending
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return false;
        }

        // SAFETY: We exclusively claimed this link. The previous owner cleared
        // `item` before releasing `pending`, and no queue can acquire it yet.
        let slot = unsafe { &mut *link.item.get() };
        debug_assert!(slot.is_none());
        *slot = Some(item);
        self.list.push_back(link);
        true
    }

    /// Removes the oldest object.
    pub fn pop_front(&mut self) -> Option<Arc<T>> {
        self.list.pop_front().map(Self::release_link)
    }

    /// Removes the oldest object matching a predicate.
    pub fn remove_first_matching(
        &mut self,
        mut predicate: impl FnMut(&T) -> bool,
    ) -> Option<Arc<T>> {
        let mut cursor = self.list.front_mut();
        while let Some(link) = cursor.get() {
            if predicate(Self::queued_item(link)) {
                return cursor.remove().map(Self::release_link);
            }
            cursor.move_next();
        }
        None
    }

    /// Returns whether any queued object matches a predicate.
    pub fn any(&self, mut predicate: impl FnMut(&T) -> bool) -> bool {
        self.list
            .iter()
            .any(|link| predicate(Self::queued_item(link)))
    }

    /// Returns whether the queue has no objects.
    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// Moves every pending object into a separate queue without relinking it.
    pub fn take(&mut self) -> Self {
        core::mem::take(self)
    }

    fn queued_item(link: &ArcQueueLink<T>) -> &T {
        // SAFETY: Called only for links borrowed from this queue. Queue access
        // is serialized, and another queue cannot claim a pending link.
        unsafe { &*link.item.get() }
            .as_deref()
            .expect("queued link has no object")
    }

    fn release_link(link: Arc<ArcQueueLink<T>>) -> Arc<T> {
        // SAFETY: Called only after this queue unlinks the node. `pending`
        // still excludes other queues until we have cleared the stored object.
        let item = unsafe { &mut *link.item.get() }
            .take()
            .expect("queued link has no object");
        link.pending.store(false, Ordering::Release);
        item
    }
}

impl<T: ArcQueueItem> Default for ArcQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: ArcQueueItem> Drop for ArcQueue<T> {
    fn drop(&mut self) {
        while self.pop_front().is_some() {}
    }
}

#[cfg(ktest)]
mod test {
    use super::*;
    use crate::prelude::ktest;

    struct Item {
        id: usize,
        link: Arc<ArcQueueLink<Self>>,
    }

    impl Item {
        fn new(id: usize) -> Arc<Self> {
            Arc::new(Self {
                id,
                link: ArcQueueLink::new(),
            })
        }
    }

    impl ArcQueueItem for Item {
        fn queue_link(&self) -> &Arc<ArcQueueLink<Self>> {
            &self.link
        }
    }

    #[ktest]
    fn fifo_and_unique_pending_membership() {
        let mut queue = ArcQueue::new();
        let first = Item::new(1);
        let second = Item::new(2);

        assert!(queue.push_back(Arc::clone(&first)));
        assert!(!queue.push_back(Arc::clone(&first)));
        assert!(queue.push_back(Arc::clone(&second)));
        assert_eq!(queue.pop_front().unwrap().id, 1);
        assert!(queue.push_back(Arc::clone(&first)));
        assert_eq!(queue.pop_front().unwrap().id, 2);
        assert_eq!(queue.pop_front().unwrap().id, 1);
        assert!(queue.is_empty());
    }

    #[ktest]
    fn moving_a_queue_preserves_exclusive_membership() {
        let mut queue = ArcQueue::new();
        let mut other = ArcQueue::new();
        let item = Item::new(1);

        assert!(queue.push_back(item.clone()));
        let mut processing = queue.take();
        assert!(queue.is_empty());
        assert!(!other.push_back(item.clone()));
        assert_eq!(processing.pop_front().unwrap().id, 1);
        assert!(other.push_back(item));
        assert_eq!(other.pop_front().unwrap().id, 1);
    }

    #[ktest]
    fn predicate_removal_and_queue_drop_release_items() {
        let mut queue = ArcQueue::new();
        let first = Item::new(1);
        let second = Item::new(2);
        let third = Item::new(3);
        let second_weak = Arc::downgrade(&second);
        let third_weak = Arc::downgrade(&third);

        assert!(queue.push_back(first));
        assert!(queue.push_back(Arc::clone(&second)));
        assert!(queue.push_back(Arc::clone(&third)));
        assert!(queue.any(|item| item.id == 2));
        assert_eq!(
            queue.remove_first_matching(|item| item.id == 2).unwrap().id,
            2
        );
        drop(second);
        assert!(second_weak.upgrade().is_none());
        assert_eq!(queue.pop_front().unwrap().id, 1);

        drop(third);
        drop(queue);
        assert!(third_weak.upgrade().is_none());
    }
}
