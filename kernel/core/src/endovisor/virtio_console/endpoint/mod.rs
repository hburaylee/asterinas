// SPDX-License-Identifier: MPL-2.0

//! The console endpoint of a kernelet sandbox: a bounded two-way byte stream
//! between host user space and a console device model.
//!
//! A [`ConsoleEndpoint`] owns two fixed-capacity byte queues. The user-side
//! [`EndpointFile`] appends user bytes to the *input* queue and drains the
//! *output* queue; the device model drains input with
//! [`ConsoleEndpoint::pop_input`] and appends output with
//! [`ConsoleEndpoint::push_output`]. Both model operations are non-blocking
//! and never allocate: each queue holds at most [`QUEUE_CAPACITY`] bytes and
//! is allocated once in [`ConsoleEndpoint::new`]. An operation larger than
//! the free space is a partial transfer, as with any stream.
//!
//! The two sides wake each other through separate channels:
//!
//! * The user side blocks on the file's [`Pollee`]: the model notifies `IN`
//!   after pushing output, `OUT` after popping input, and revocation
//!   notifies everything.
//! * The device model waits on [`ConsoleEndpoint::changes`]: woken whenever
//!   the user writes input or reads output, so that it can wait for input or
//!   output space, and also on revocation.
//!
//! [`ConsoleEndpoint::revoke`] runs before a sandbox is destroyed.
//! Afterwards reads report end-of-file (`Ok(0)`) and writes report `EPIPE`,
//! without raising `SIGPIPE`; blocked and polling waiters on both sides are
//! woken. A surviving descriptor needs no further access to the sandbox.
//!
//! The queues are charged to the kernelet's Host-byte account before START.
//! Revocation drops their buffers and removes that charge, even if a user
//! descriptor remains open.

mod file;
mod queue;

use core::sync::atomic::{AtomicBool, Ordering};

pub(in crate::endovisor) use file::EndpointFile;
use ostd::{kernelet::control::Kernelet, sync::WaitQueue};
use queue::{QUEUE_CAPACITY, Queue};

use crate::{events::IoEvents, prelude::*, process::signal::Pollee};

/// One console stream of a kernelet sandbox.
///
/// The sandbox descriptor hands [`ConsoleEndpoint::file`] to user space and
/// keeps the endpoint itself; the console device model also keeps the
/// endpoint to move bytes through it. See the module documentation for the
/// queue layout, the wakeup protocol and the revocation rules.
pub(in crate::endovisor) struct ConsoleEndpoint {
    /// Bytes written by the user and drained by the device model.
    input: Queue,
    /// Bytes pushed by the device model and drained by the user.
    output: Queue,
    /// Wakes the device model when the user side makes progress.
    changes: Arc<WaitQueue>,
    /// Reports readiness to the user side.
    pollee: Pollee,
    /// Set by `revoke`; afterwards reads report EOF and writes report `EPIPE`.
    revoked: AtomicBool,
    account: SpinLock<Option<(Arc<Kernelet>, usize)>>,
}

impl ConsoleEndpoint {
    /// Creates a console endpoint with both queues empty.
    ///
    /// This is the only allocation point: both [`QUEUE_CAPACITY`] queues and
    /// their wait channels are set up here, so that later operations,
    /// including the device-model hooks, never allocate.
    pub(in crate::endovisor) fn new() -> Arc<Self> {
        Arc::new(Self {
            input: Queue::new(),
            output: Queue::new(),
            changes: Arc::new(WaitQueue::new()),
            pollee: Pollee::new(),
            revoked: AtomicBool::new(false),
            account: SpinLock::new(None),
        })
    }

    /// Returns the user-space end of the endpoint as a file description.
    pub(in crate::endovisor) fn file(self: &Arc<Self>) -> Arc<EndpointFile> {
        EndpointFile::new(self.clone())
    }

    /// Returns the wait queue on which the device model waits for progress.
    ///
    /// The queue wakes when the user writes input (input is available) or
    /// reads output (output space is available), and when the endpoint is
    /// revoked.
    pub(super) fn changes(&self) -> Arc<WaitQueue> {
        self.changes.clone()
    }

    pub(in crate::endovisor) fn reservation_bytes(&self) -> usize {
        QUEUE_CAPACITY * 2 + size_of::<Self>()
    }

    pub(in crate::endovisor) fn bind_account(&self, kernelet: Arc<Kernelet>) -> ostd::Result<()> {
        let mut account = self.account.lock();
        if self.revoked.load(Ordering::Acquire) || account.is_some() {
            return Err(ostd::Error::InvalidArgs);
        }
        let bytes = self.reservation_bytes();
        kernelet.charge_host_bytes(bytes)?;
        *account = Some((kernelet, bytes));
        Ok(())
    }

    pub(in crate::endovisor) fn unbind_account(&self) {
        if let Some((kernelet, bytes)) = self.account.lock().take() {
            kernelet.uncharge_host_bytes(bytes);
        }
    }

    /// Drains queued user-to-image bytes into `dst`, returning the number of
    /// bytes moved. Never blocks and never allocates.
    pub(super) fn pop_input(&self, dst: &mut [u8]) -> usize {
        let popped = self.input.pop(dst);
        if popped > 0 {
            // The user can write again.
            self.pollee.notify(IoEvents::OUT);
        }
        popped
    }

    /// Appends image-to-user bytes from `src`, returning the number of bytes
    /// queued; the rest exceeds the bound and is left to the caller. Never
    /// blocks and never allocates.
    pub(super) fn push_output(&self, src: &[u8]) -> usize {
        let pushed = self.output.push(src);
        if pushed > 0 {
            // The user can read again.
            self.pollee.notify(IoEvents::IN);
        }
        pushed
    }

    /// Revokes the endpoint, waking all waiters. Idempotent.
    ///
    /// Afterwards reads report EOF and writes report `EPIPE`, on both the
    /// user-side file and, through [`Self::changes`], a device model that
    /// rechecks the queues. The queued bytes are simply dropped.
    pub(in crate::endovisor) fn revoke(&self) {
        if self.revoked.swap(true, Ordering::AcqRel) {
            return;
        }
        self.input.revoke();
        self.output.revoke();
        self.unbind_account();
        // Wake user readers (EOF), writers (`EPIPE`) and pollers.
        self.pollee
            .notify(IoEvents::IN | IoEvents::OUT | IoEvents::RDHUP | IoEvents::ERR);
        // Wake a device model that may be waiting for input or output space.
        self.changes.wake_all();
    }
}

impl Drop for ConsoleEndpoint {
    fn drop(&mut self) {
        self.unbind_account();
    }
}
