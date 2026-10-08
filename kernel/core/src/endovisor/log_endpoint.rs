// SPDX-License-Identifier: MPL-2.0

//! Bounded, nonblocking kernelet log ingress and a readable operator stream.

use core::{
    fmt::Display,
    sync::atomic::{AtomicBool, Ordering},
};

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
const CHARGED_BYTES: usize = RECORD_BYTES * RECORD_COUNT;

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
    ring: SpinLock<Ring>,
    reader: Mutex<()>,
    pollee: Pollee,
    revoked: AtomicBool,
    account: SpinLock<Option<Arc<Kernelet>>>,
}

impl LogEndpoint {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            ring: SpinLock::new(Ring::new()),
            reader: Mutex::new(()),
            pollee: Pollee::new(),
            revoked: AtomicBool::new(false),
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
        if self.revoked.load(Ordering::Acquire) {
            return false;
        }
        let pushed = self.ring.lock().push(Record::new(level, module, text));
        if pushed {
            self.pollee.notify(IoEvents::IN);
        }
        pushed
    }

    pub(super) fn revoke(&self) {
        if self.revoked.swap(true, Ordering::AcqRel) {
            return;
        }
        let account = self.account.lock().take();
        self.ring.lock().len = 0;
        if let Some(kernelet) = account {
            kernelet.uncharge_host_bytes(CHARGED_BYTES);
        }
        self.pollee
            .notify(IoEvents::IN | IoEvents::RDHUP | IoEvents::ERR);
    }
}

impl Drop for LogEndpoint {
    fn drop(&mut self) {
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
            if self.endpoint.revoked.load(Ordering::Acquire) {
                return Ok(0);
            }
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
        if !self.endpoint.revoked.load(Ordering::Acquire) {
            let mut ring = self.endpoint.ring.lock();
            if ring.len != 0 {
                ring.consumed(length);
            }
        }
        self.endpoint.pollee.invalidate();
        Ok(length)
    }

    fn events(&self) -> IoEvents {
        if self.endpoint.revoked.load(Ordering::Acquire) {
            IoEvents::IN | IoEvents::RDHUP | IoEvents::ERR
        } else if self.endpoint.ring.lock().len != 0 {
            IoEvents::IN
        } else {
            IoEvents::empty()
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
