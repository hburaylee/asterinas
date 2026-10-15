// SPDX-License-Identifier: MPL-2.0

//! Host thread construction and device-specific gates for the OSTD reaper.

use alloc::{boxed::Box, sync::Arc};

use ostd::kernelet::control::{self, ExitStatus, Kernelet, ReclaimCallbacks};

use crate::thread::kernel_thread::ThreadOptions;

/// Supplies the native Thread wrapper for OSTD's single lifecycle worker.
pub(super) fn init() -> ostd::Result<()> {
    control::init_reaper(|body| Ok(ThreadOptions::new(body).build()))
}

/// Transfers reclamation while retaining the device models' release gate.
pub(super) fn enqueue(
    cid: u32,
    kernelet: Arc<Kernelet>,
    cleanup: Option<Box<dyn FnOnce() + Send>>,
    on_destroy: Option<Box<dyn FnOnce() + Send>>,
) {
    control::enqueue_reclaim(
        kernelet,
        ReclaimCallbacks {
            prepare: cleanup,
            ready: Box::new(move |waker| {
                if let Some(queue) = super::vsock_switch::retire_wait_queue(cid) {
                    queue.enqueue_once(waker.clone());
                }
                super::vsock_switch::retired_drained(cid)
            }),
            complete: on_destroy,
        },
    )
    .expect("kernelet reaper is not initialized");
}

/// Observes exit without taking ownership away from the live descriptor.
pub(super) fn watch_exit(kernelet: Arc<Kernelet>, on_exit: Box<dyn FnOnce(ExitStatus) + Send>) {
    control::watch_exit(kernelet, on_exit).expect("kernelet reaper is not initialized");
}
