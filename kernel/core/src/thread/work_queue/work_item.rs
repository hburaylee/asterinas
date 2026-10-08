// SPDX-License-Identifier: MPL-2.0

#![expect(dead_code)]

use core::sync::atomic::{AtomicBool, Ordering};

use ostd::{
    cpu::{CpuId, CpuSet},
    sync::{ArcQueueItem, ArcQueueLink},
};

use crate::prelude::*;

/// A task to be executed by a worker thread.
pub(crate) struct WorkItem {
    work_func: Box<dyn Fn() + Send + Sync>,
    cpu_affinity: CpuSet,
    // This stays set after dequeue until a worker starts the callback. The
    // queue link tracks only membership, so it cannot replace this flag.
    was_pending: AtomicBool,
    link: Arc<ArcQueueLink<Self>>,
}

impl ArcQueueItem for WorkItem {
    fn queue_link(&self) -> &Arc<ArcQueueLink<Self>> {
        &self.link
    }
}

impl WorkItem {
    pub(crate) fn new(work_func: Box<dyn Fn() + Send + Sync>) -> Arc<WorkItem> {
        let cpu_affinity = CpuSet::new_full();
        Arc::new(WorkItem {
            work_func,
            cpu_affinity,
            was_pending: AtomicBool::new(false),
            link: ArcQueueLink::new(),
        })
    }

    pub(crate) fn cpu_affinity(&self) -> &CpuSet {
        &self.cpu_affinity
    }

    pub(crate) fn cpu_affinity_mut(&mut self) -> &mut CpuSet {
        &mut self.cpu_affinity
    }

    pub(super) fn is_valid_cpu(&self, cpu_id: CpuId) -> bool {
        self.cpu_affinity.contains(cpu_id)
    }

    pub(super) fn set_processing(&self) {
        self.was_pending.store(false, Ordering::Release);
    }

    pub(super) fn set_pending(&self) {
        self.was_pending.store(true, Ordering::Release);
    }

    pub(super) fn is_pending(&self) -> bool {
        self.was_pending.load(Ordering::Acquire)
    }

    pub(super) fn try_pending(&self) -> bool {
        self.was_pending
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    pub(super) fn call_work_func(&self) {
        (self.work_func)()
    }
}
