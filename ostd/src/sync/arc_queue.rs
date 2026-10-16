// SPDX-License-Identifier: MPL-2.0

//! An allocation-free FIFO queue with links embedded in `Arc`-owned objects.

use alloc::sync::Arc;
use core::{
    cell::UnsafeCell,
    ptr::NonNull,
    sync::atomic::{AtomicBool, Ordering},
};

/// An object's reusable queue link.
///
/// A link can be pending in only one queue at a time. Removing it releases
/// it for reuse, including when the queue itself is dropped.
pub struct ArcQueueLink<T> {
    pending: AtomicBool,
    state: UnsafeCell<LinkState<T>>,
}

struct LinkState<T> {
    item: Option<Arc<T>>,
    next: Option<NonNull<ArcQueueLink<T>>>,
}

// SAFETY: Only the queue that claimed pending accesses state, under exclusive
// queue access. Removal clears state before releasing pending. The retained
// Arc pins the object and its borrowed link until removal. Other queues must
// acquire pending before accessing state; shared queued items require Sync.
unsafe impl<T: Send + Sync> Sync for ArcQueueLink<T> {}
// SAFETY: An unqueued link has no raw references. A pending link is borrowed
// through its retained Arc owner and cannot be moved through safe access.
unsafe impl<T: Send + Sync> Send for ArcQueueLink<T> {}

impl<T> ArcQueueLink<T> {
    /// Creates a reusable link without allocating memory.
    pub const fn new() -> Self {
        Self {
            pending: AtomicBool::new(false),
            state: UnsafeCell::new(LinkState {
                item: None,
                next: None,
            }),
        }
    }
}

impl<T> Default for ArcQueueLink<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Supplies a queueable object's reusable link.
pub trait ArcQueueItem: Send + Sync + Sized {
    /// Returns a link whose lifetime is tied to this object.
    ///
    /// Objects that share a link cannot use that link in queues simultaneously.
    /// The queue captures the returned link once, without assuming that later
    /// calls return the same link.
    fn queue_link(&self) -> &ArcQueueLink<Self>;
}

/// A FIFO queue whose insertion requires no allocation or reference cloning.
///
/// Callers serialize access to the queue, for example with a spin lock or a
/// CPU-local value and disabled local IRQs. Each queued link retains the supplied
/// Arc owner, keeping the link alive until it is removed or the queue is dropped.
pub struct ArcQueue<T: ArcQueueItem> {
    head: Option<NonNull<ArcQueueLink<T>>>,
    tail: Option<NonNull<ArcQueueLink<T>>>,
}

// SAFETY: Links remain pinned by their retained Arc owners. Moving the queue
// moves only its end pointers; mutation requires exclusive access. T is Send.
unsafe impl<T: ArcQueueItem> Send for ArcQueue<T> {}
// SAFETY: Shared queue access only reads links owned by this queue, and T is
// Sync. No other queue can mutate those links while their pending bit is set.
unsafe impl<T: ArcQueueItem> Sync for ArcQueue<T> {}

impl<T: ArcQueueItem> ArcQueue<T> {
    /// Creates an empty queue.
    pub const fn new() -> Self {
        Self {
            head: None,
            tail: None,
        }
    }

    /// Appends an object, returning false if its link is already pending.
    pub fn push_back(&mut self, item: Arc<T>) -> bool {
        let link = item.queue_link();
        if link
            .pending
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return false;
        }
        let address = NonNull::from(link);
        let state = link.state.get();
        // SAFETY: We claimed this exact link. The preceding owner cleared its
        // state before releasing pending. Retaining item pins the borrowed link;
        // only this queue can access it until unlink releases pending again.
        unsafe {
            debug_assert!((*state).item.is_none());
            *state = LinkState {
                item: Some(item),
                next: None,
            };
            if let Some(tail) = self.tail {
                (*tail.as_ref().state.get()).next = Some(address);
            } else {
                self.head = Some(address);
            }
        }
        self.tail = Some(address);
        true
    }

    /// Removes the oldest object.
    pub fn pop_front(&mut self) -> Option<Arc<T>> {
        let head = self.head?;
        // SAFETY: head is a live link belonging to this exclusively borrowed queue.
        Some(unsafe { self.unlink(None, head) })
    }

    /// Removes the oldest object matching a predicate.
    pub fn remove_first_matching(
        &mut self,
        mut predicate: impl FnMut(&T) -> bool,
    ) -> Option<Arc<T>> {
        let mut previous = None;
        let mut current = self.head;
        while let Some(link) = current {
            // SAFETY: Traversal follows this queue's retained, exclusively owned
            // links. Predicates borrow T and cannot mutate these pending links.
            let state = unsafe { &*link.as_ref().state.get() };
            if predicate(state.item.as_deref().expect("queued link has no object")) {
                // SAFETY: previous and link are adjacent live nodes in this queue.
                return Some(unsafe { self.unlink(previous, link) });
            }
            previous = Some(link);
            current = state.next;
        }
        None
    }

    /// Returns whether any queued object matches a predicate.
    pub fn any(&self, mut predicate: impl FnMut(&T) -> bool) -> bool {
        let mut current = self.head;
        while let Some(link) = current {
            // SAFETY: Shared access cannot coexist with mutation of this queue,
            // and pending excludes mutation through any other queue.
            let state = unsafe { &*link.as_ref().state.get() };
            if predicate(state.item.as_deref().expect("queued link has no object")) {
                return true;
            }
            current = state.next;
        }
        false
    }

    /// Returns whether the queue has no objects.
    pub fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    /// Moves every pending object into a separate queue without relinking it.
    pub fn take(&mut self) -> Self {
        core::mem::take(self)
    }

    /// # Safety
    /// link must belong to this queue, with previous naming its predecessor
    /// or None exactly when link is the head. Exclusive queue access is required.
    unsafe fn unlink(
        &mut self,
        previous: Option<NonNull<ArcQueueLink<T>>>,
        link: NonNull<ArcQueueLink<T>>,
    ) -> Arc<T> {
        // SAFETY: The caller proves membership and exclusive access. The local
        // item retains the borrowed link through its final pending publication;
        // no pointer into that link is used after another queue may claim it.
        unsafe {
            let state = &mut *link.as_ref().state.get();
            let next = state.next.take();
            let item = state.item.take().expect("queued link has no object");
            if let Some(previous) = previous {
                (*previous.as_ref().state.get()).next = next;
            } else {
                self.head = next;
            }
            if self.tail == Some(link) {
                self.tail = previous;
            }
            link.as_ref().pending.store(false, Ordering::Release);
            item
        }
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
        link: ArcQueueLink<Self>,
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
        fn queue_link(&self) -> &ArcQueueLink<Self> {
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
    #[ktest]
    fn shared_link_preserves_owner_and_can_be_reused_by_another_object() {
        struct SharedItem {
            id: usize,
            link: Arc<ArcQueueLink<Self>>,
        }
        impl ArcQueueItem for SharedItem {
            fn queue_link(&self) -> &ArcQueueLink<Self> {
                &self.link
            }
        }
        let link = Arc::new(ArcQueueLink::new());
        let first = Arc::new(SharedItem {
            id: 1,
            link: link.clone(),
        });
        let second = Arc::new(SharedItem { id: 2, link });
        let mut a = ArcQueue::new();
        let mut b = ArcQueue::new();
        assert!(a.push_back(first));
        assert!(!b.push_back(second.clone()));
        assert_eq!(a.pop_front().unwrap().id, 1);
        assert!(b.push_back(second));
        assert_eq!(b.pop_front().unwrap().id, 2);
    }

    #[ktest]
    fn removal_uses_the_captured_link_when_the_getter_changes() {
        struct SwitchingItem {
            selected: core::sync::atomic::AtomicUsize,
            links: [ArcQueueLink<Self>; 2],
        }
        impl ArcQueueItem for SwitchingItem {
            fn queue_link(&self) -> &ArcQueueLink<Self> {
                &self.links[self.selected.load(Ordering::Relaxed)]
            }
        }
        let item = Arc::new(SwitchingItem {
            selected: core::sync::atomic::AtomicUsize::new(0),
            links: [ArcQueueLink::new(), ArcQueueLink::new()],
        });
        let mut a = ArcQueue::new();
        let mut b = ArcQueue::new();
        assert!(a.push_back(item.clone()));
        item.selected.store(1, Ordering::Relaxed);
        assert!(b.push_back(item.clone()));
        assert!(Arc::ptr_eq(&a.pop_front().unwrap(), &item));
        // The second link remains owned by b when a releases the first one.
        assert!(!a.push_back(item.clone()));
        assert!(Arc::ptr_eq(&b.pop_front().unwrap(), &item));
        assert!(a.push_back(item));
    }

    #[ktest]
    fn removing_tail_allows_append_and_queue_retains_the_only_owner() {
        let mut queue = ArcQueue::new();
        let first = Item::new(1);
        let weak = Arc::downgrade(&first);
        assert!(queue.push_back(first));
        assert!(weak.upgrade().is_some());
        assert!(queue.push_back(Item::new(2)));
        assert_eq!(queue.remove_first_matching(|x| x.id == 2).unwrap().id, 2);
        assert!(queue.push_back(Item::new(3)));
        assert_eq!(queue.pop_front().unwrap().id, 1);
        assert!(weak.upgrade().is_none());
        assert_eq!(queue.pop_front().unwrap().id, 3);
        assert!(queue.is_empty());
    }
}
