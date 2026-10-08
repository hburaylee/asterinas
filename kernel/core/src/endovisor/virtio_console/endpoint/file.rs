// SPDX-License-Identifier: MPL-2.0

//! The user-space descriptor of a console endpoint, exposed as a stream file
//! backed by the anon-inode filesystem.

use core::{fmt::Display, sync::atomic::Ordering};

use super::ConsoleEndpoint;
use crate::{
    events::IoEvents,
    fs::{
        file::{AccessMode, FileCommon, FileLike, StatusFlags, file_table::FdFlags},
        pseudofs::AnonInodeFs,
    },
    prelude::*,
    process::signal::{PollHandle, Pollable},
    util::ring_buffer::{ConsumerU8Ext, ProducerU8Ext},
};

/// The user-space end of a [`ConsoleEndpoint`], exposed as a stream file.
///
/// Reading consumes the endpoint's output queue and writing fills its input
/// queue. Unless the descriptor is non-blocking, both operations block with
/// [`Pollable::wait_events`] until the queues change. Once the endpoint is
/// revoked, reads report EOF and writes report `EPIPE`.
pub(in crate::endovisor) struct EndpointFile {
    common: FileCommon,
    endpoint: Arc<ConsoleEndpoint>,
}

impl EndpointFile {
    pub(super) fn new(endpoint: Arc<ConsoleEndpoint>) -> Arc<Self> {
        Arc::new(Self {
            common: FileCommon::new(
                AnonInodeFs::new_path(|_| "anon_inode:[kernelet-console]".into()),
                AccessMode::O_RDWR,
                StatusFlags::empty(),
            ),
            endpoint,
        })
    }

    /// Returns the console endpoint this file operates on.
    pub(in crate::endovisor) fn endpoint(&self) -> &Arc<ConsoleEndpoint> {
        &self.endpoint
    }

    /// Reads from the output queue; an empty queue fails with `EAGAIN` and a
    /// revoked endpoint reports EOF as `Ok(0)`.
    fn try_read(&self, writer: &mut VmWriter) -> Result<usize> {
        if self.endpoint.revoked.load(Ordering::Acquire) {
            return Ok(0);
        }
        let read_len = {
            let mut consumer = self.endpoint.output.consumer.lock();
            let Some(consumer) = consumer.as_mut() else {
                return Ok(0);
            };
            consumer.read_fallible(writer)?
        };
        if read_len > 0 {
            // Space for the device model to push output again.
            self.endpoint.changes.wake_all();
            // Readability may have disappeared.
            self.endpoint.pollee.invalidate();
            return Ok(read_len);
        }
        return_errno_with_message!(Errno::EAGAIN, "the console endpoint is empty");
    }

    /// Writes to the input queue; a full queue fails with `EAGAIN` and a
    /// revoked endpoint fails with `EPIPE`.
    fn try_write(&self, reader: &mut VmReader) -> Result<usize> {
        if self.endpoint.revoked.load(Ordering::Acquire) {
            return_errno_with_message!(Errno::EPIPE, "the console endpoint is revoked");
        }
        let written_len = {
            let mut producer = self.endpoint.input.producer.lock();
            let Some(producer) = producer.as_mut() else {
                return_errno_with_message!(Errno::EPIPE, "the console endpoint is revoked");
            };
            producer.write_fallible(reader)?
        };
        if written_len > 0 {
            // Input for the device model to drain.
            self.endpoint.changes.wake_all();
            // Writability may have disappeared.
            self.endpoint.pollee.invalidate();
            return Ok(written_len);
        }
        return_errno_with_message!(Errno::EAGAIN, "the console endpoint is full");
    }

    /// Returns the readiness events of the endpoint for the user side.
    fn check_io_events(&self) -> IoEvents {
        let endpoint = &self.endpoint;
        if endpoint.revoked.load(Ordering::Acquire) {
            // Reads report EOF and writes report `EPIPE`.
            return IoEvents::IN | IoEvents::OUT | IoEvents::RDHUP | IoEvents::ERR;
        }
        let mut events = IoEvents::empty();
        if !endpoint.output.is_empty() {
            events |= IoEvents::IN;
        }
        if endpoint.input.has_space() {
            events |= IoEvents::OUT;
        }
        events
    }
}

impl Pollable for EndpointFile {
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.endpoint
            .pollee
            .poll_with(mask, poller, || self.check_io_events())
    }
}

impl FileLike for EndpointFile {
    fn read(&self, writer: &mut VmWriter) -> Result<usize> {
        if !self.common().access_mode().is_readable() {
            return_errno_with_message!(Errno::EBADF, "the file is not opened for reading");
        }
        if !writer.has_avail() {
            return Ok(0);
        }
        if self.common().is_nonblocking() {
            self.try_read(writer)
        } else {
            self.wait_events(IoEvents::IN, None, || self.try_read(writer))
        }
    }

    fn write(&self, reader: &mut VmReader) -> Result<usize> {
        if !self.common().access_mode().is_writable() {
            return_errno_with_message!(Errno::EBADF, "the file is not opened for writing");
        }
        if !reader.has_remain() {
            return Ok(0);
        }
        if self.common().is_nonblocking() {
            self.try_write(reader)
        } else {
            self.wait_events(IoEvents::OUT, None, || self.try_write(reader))
        }
    }

    fn common(&self) -> &FileCommon {
        &self.common
    }

    fn dump_proc_fdinfo(self: Arc<Self>, _fd_flags: FdFlags) -> Box<dyn Display> {
        // Queue lengths would need the queue mutexes, which must not be taken
        // here because the file table's lock may be held.
        Box::new("kernelet-console:\tendpoint\n".to_string())
    }
}
