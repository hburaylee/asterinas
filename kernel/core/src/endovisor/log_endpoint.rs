// SPDX-License-Identifier: MPL-2.0

//! Bounded, nonblocking kernelet log ingress and a readable operator stream.

use core::fmt::Display;

use ostd::kernelet::control::Kernelet;

use crate::{
    events::IoEvents,
    fs::{
        file::{AccessMode, FileCommon, FileLike, StatusFlags, file_table::FdFlags},
        pseudofs::AnonInodeFs,
    },
    prelude::*,
    process::signal::{PollHandle, Pollable, Pollee},
};

const RECORD_BYTES: usize = 256;
const RECORD_COUNT: usize = 32;
const CHARGED_BYTES: usize = size_of::<Ring>();

#[derive(Clone, Copy)]
struct Record {
    len: usize,
    bytes: [u8; RECORD_BYTES],
}

impl Record {
    const EMPTY: Self = Self {
        len: 0,
        bytes: [0; RECORD_BYTES],
    };

    fn append(&mut self, input: &str) {
        let room = RECORD_BYTES.saturating_sub(self.len + 1);
        let mut len = input.len().min(room);
        while !input.is_char_boundary(len) {
            len -= 1;
        }
        self.bytes[self.len..self.len + len].copy_from_slice(&input.as_bytes()[..len]);
        self.len += len;
    }

    fn append_level(&mut self, mut level: u32) {
        let mut digits = [0; 10];
        let mut start = digits.len();
        loop {
            start -= 1;
            digits[start] = b'0' + (level % 10) as u8;
            level /= 10;
            if level == 0 {
                break;
            }
        }
        self.bytes[0] = b'[';
        self.len = 1;
        let count = digits.len() - start;
        self.bytes[self.len..self.len + count].copy_from_slice(&digits[start..]);
        self.len += count;
        self.bytes[self.len] = b']';
        self.bytes[self.len + 1] = b' ';
        self.len += 2;
    }

    fn new(level: u32, module: &str, text: &str) -> Self {
        let mut record = Self::EMPTY;
        record.append_level(level);
        record.append(module);
        record.append(": ");
        record.append(text);
        record.bytes[record.len] = b'\n';
        record.len += 1;
        record
    }
}

struct Ring {
    records: [Record; RECORD_COUNT],
    head: usize,
    len: usize,
    offset: usize,
}

impl Ring {
    fn new() -> Self {
        Self {
            records: [Record::EMPTY; RECORD_COUNT],
            head: 0,
            len: 0,
            offset: 0,
        }
    }

    fn push(&mut self, record: Record) -> bool {
        if self.len == RECORD_COUNT {
            return false;
        }
        let tail = (self.head + self.len) % RECORD_COUNT;
        self.records[tail] = record;
        self.len += 1;
        true
    }

    fn consumed(&mut self, bytes: usize) {
        self.offset += bytes;
        if self.offset == self.records[self.head].len {
            self.head = (self.head + 1) % RECORD_COUNT;
            self.len -= 1;
            self.offset = 0;
        }
    }
}

/// The Host hook copies one bounded record without sleeping or allocating.
pub(super) struct LogEndpoint {
    ring: SpinLock<Option<Box<Ring>>>,
    reader: Mutex<()>,
    pollee: Pollee,
    account: SpinLock<Option<Arc<Kernelet>>>,
}

impl LogEndpoint {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            ring: SpinLock::new(Some(Box::new(Ring::new()))),
            reader: Mutex::new(()),
            pollee: Pollee::new(),
            account: SpinLock::new(None),
        })
    }

    pub(super) fn file(self: &Arc<Self>) -> Arc<LogEndpointFile> {
        Arc::new(LogEndpointFile {
            common: FileCommon::new(
                AnonInodeFs::new_path(|_| "anon_inode:[kernelet-log]".into()),
                AccessMode::O_RDONLY,
                StatusFlags::empty(),
            ),
            endpoint: self.clone(),
        })
    }

    pub(super) fn reservation_bytes(&self) -> usize {
        CHARGED_BYTES
    }

    pub(super) fn bind_account(&self, kernelet: Arc<Kernelet>) -> ostd::Result<()> {
        kernelet.charge_host_bytes(CHARGED_BYTES)?;
        *self.account.lock() = Some(kernelet);
        Ok(())
    }

    pub(super) fn unbind_account(&self) {
        if let Some(kernelet) = self.account.lock().take() {
            kernelet.uncharge_host_bytes(CHARGED_BYTES);
        }
    }

    pub(super) fn push(&self, level: u32, module: &str, text: &str) -> bool {
        let pushed = self
            .ring
            .lock()
            .as_mut()
            .is_some_and(|ring| ring.push(Record::new(level, module, text)));
        if pushed {
            self.pollee.notify(IoEvents::IN);
        }
        pushed
    }

    pub(super) fn revoke(&self) {
        // Serialize readers and concurrent revokers until the payload is freed.
        // A retained fd only keeps the small, permanently closed endpoint alive.
        let _reader = self.reader.lock();
        let ring = self.ring.lock().take();
        drop(ring);
        self.unbind_account();
        self.pollee
            .notify(IoEvents::IN | IoEvents::RDHUP | IoEvents::ERR);
    }
}

impl Drop for LogEndpoint {
    fn drop(&mut self) {
        let ring = self.ring.lock().take();
        drop(ring);
        if let Some(kernelet) = self.account.lock().take() {
            kernelet.uncharge_host_bytes(CHARGED_BYTES);
        }
    }
}

pub(super) struct LogEndpointFile {
    common: FileCommon,
    endpoint: Arc<LogEndpoint>,
}

impl LogEndpointFile {
    fn try_read(&self, writer: &mut VmWriter) -> Result<usize> {
        let _reader = self.endpoint.reader.lock();
        let mut buffer = [0; RECORD_BYTES];
        let length = {
            let ring = self.endpoint.ring.lock();
            let Some(ring) = ring.as_ref() else {
                return Ok(0);
            };
            if ring.len == 0 {
                return_errno_with_message!(Errno::EAGAIN, "log endpoint is empty");
            }
            let record = &ring.records[ring.head];
            let length = (record.len - ring.offset).min(writer.avail());
            buffer[..length].copy_from_slice(&record.bytes[ring.offset..ring.offset + length]);
            length
        };
        let mut reader = VmReader::from(&buffer[..length]).to_fallible();
        writer.write_fallible(&mut reader)?;
        let mut ring = self.endpoint.ring.lock();
        if let Some(ring) = ring.as_mut() {
            ring.consumed(length);
        }
        drop(ring);
        self.endpoint.pollee.invalidate();
        Ok(length)
    }

    fn events(&self) -> IoEvents {
        match self.endpoint.ring.lock().as_ref() {
            None => IoEvents::IN | IoEvents::RDHUP | IoEvents::ERR,
            Some(ring) if ring.len != 0 => IoEvents::IN,
            Some(_) => IoEvents::empty(),
        }
    }
}

impl Pollable for LogEndpointFile {
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.endpoint
            .pollee
            .poll_with(mask, poller, || self.events())
    }
}

impl FileLike for LogEndpointFile {
    fn read(&self, writer: &mut VmWriter) -> Result<usize> {
        if !writer.has_avail() {
            return Ok(0);
        }
        if self.common.is_nonblocking() {
            self.try_read(writer)
        } else {
            self.wait_events(IoEvents::IN, None, || self.try_read(writer))
        }
    }

    fn common(&self) -> &FileCommon {
        &self.common
    }

    fn dump_proc_fdinfo(self: Arc<Self>, _flags: FdFlags) -> Box<dyn Display> {
        Box::new("kernelet-log:\tendpoint\n".to_string())
    }
}

#[cfg(ktest)]
mod tests {
    use ostd::prelude::*;

    use super::*;

    #[ktest]
    fn retained_log_fd_is_empty_and_rejects_writes_after_revoke() {
        crate::time::clocks::init_for_ktest();
        let endpoint = LogEndpoint::new();
        let file = endpoint.file();
        assert!(endpoint.push(1, "test", "before revoke"));
        endpoint.revoke();
        endpoint.revoke();
        drop(endpoint);
        let mut buffer = [0; RECORD_BYTES];
        let mut writer = VmWriter::from(buffer.as_mut_slice()).to_fallible();
        assert_eq!(file.read(&mut writer).unwrap(), 0);
        assert!(!file.endpoint.push(1, "test", "after revoke"));
        assert!(file.events().contains(IoEvents::RDHUP));
        assert!(file.endpoint.ring.lock().is_none());
    }
}
