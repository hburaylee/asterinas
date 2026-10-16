// SPDX-License-Identifier: MPL-2.0

//! A bounded virtio MMIO block register file and file-backed request worker.
//!
//! The device implements the block device of VirtIO 1.3 §5.2 (device ID 2)
//! over the common MMIO register file of §4.2.2: the read-only, block-size
//! and flush feature bits (§5.2.3) plus `VIRTIO_F_VERSION_1` (§6), and the
//! capacity and block-size fields of the configuration space (§5.2.4).
//! See <https://docs.oasis-open.org/virtio/virtio/v1.3/virtio-v1.3.html>.

use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering, fence};

use ostd::{
    kernelet::{
        abi::{INVALID, MmioResult},
        control::Kernelet,
        guest_memory::GuestMemory,
    },
    mm::PAGE_SIZE,
    sync::{SpinLock, WaitQueue},
};

use super::{
    io_accounting::{ChargedSpan, WorkCategory},
    policy::Admission,
    virtio_mmio::{
        CONFIG_OFFSET, feature_word, invalid_read, set_high, set_low, write_driver_feature_word,
    },
};
use crate::{
    fs::file::{FileLike, SyncMode},
    prelude::{Errno, Result, VmReader, VmWriter, return_errno_with_message},
};

mod backing;
use backing::{BlockIo, IO_DEPTH, STAGING_BYTES};

const QUEUE_SIZE: usize = 64;
const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;
const HEADER_BYTES: usize = 16;
const STATUS_BYTES: usize = 1;
const MAX_CHAIN_BYTES: usize = MAX_REQUEST_BYTES + HEADER_BYTES + STATUS_BYTES;
const SECTOR_BYTES: u64 = 512;
const MAGIC: u32 = 0x7472_6976;
const VERSION: u32 = 2;
const DEVICE_ID_BLOCK: u32 = 2;
const FEATURE_VERSION_1: u64 = 1 << 32;
const FEATURE_READ_ONLY: u64 = 1 << 5;
const FEATURE_BLOCK_SIZE: u64 = 1 << 6;
const FEATURE_FLUSH: u64 = 1 << 9;
const REQUEST_READ: u32 = 0;
const REQUEST_WRITE: u32 = 1;
const REQUEST_FLUSH: u32 = 4;
const STATUS_IO_ERROR: u8 = 1;
const STATUS_UNSUPPORTED: u8 = 2;
const DEVICE_NEEDS_RESET: u32 = 1 << 6;

type Buffer = super::virtio_mmio::Descriptor;

struct Request {
    head: u16,
    generation: u64,
    buffers: [Buffer; QUEUE_SIZE],
    len: usize,
}

enum BlockWork {
    Cancel,
    Progress,
    Request(Request),
}

enum BlockCommand {
    Flush,
    Transfer {
        offset: usize,
        len: usize,
        operation: u32,
    },
}

struct Registers {
    status: u32,
    device_features_select: u32,
    driver_features_select: u32,
    driver_features: u64,
    queue_select: u32,
    queue_num: u32,
    queue_ready: bool,
    desc: u64,
    avail: u64,
    used: u64,
    last_avail: u16,
    next_used: u16,
    collect_pending: bool,
    generation: u64,
    active: usize,
    pending_heads: [bool; QUEUE_SIZE],
    resetting: bool,
    inbox: VecDeque<Request>,
}

impl Registers {
    fn new() -> Self {
        Self {
            status: 0,
            device_features_select: 0,
            driver_features_select: 0,
            driver_features: 0,
            queue_select: 0,
            queue_num: 0,
            queue_ready: false,
            desc: 0,
            avail: 0,
            used: 0,
            last_avail: 0,
            next_used: 0,
            collect_pending: false,
            generation: 1,
            active: 0,
            pending_heads: [false; QUEUE_SIZE],
            resetting: false,
            inbox: VecDeque::with_capacity(QUEUE_SIZE),
        }
    }

    fn reset(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.inbox.clear();
        self.pending_heads.fill(false);
        self.queue_ready = false;
        self.last_avail = 0;
        self.next_used = 0;
        self.collect_pending = false;
        self.resetting = self.active != 0;
        if !self.resetting {
            self.status = 0;
        }
    }
}

/// One attached virtio block device. Its hook never performs file I/O.
pub(super) struct VirtioBlock {
    kernelet: Arc<Kernelet>,
    admission: Arc<Admission>,
    memory: GuestMemory,
    backing: Arc<dyn FileLike>,
    capacity_sectors: u64,
    read_only: bool,
    irq: u8,
    registers: SpinLock<Registers>,
    interrupt_status: AtomicU32,
    requests: WaitQueue,
    cancelled: AtomicBool,
    charged_bytes: usize,
}

impl VirtioBlock {
    pub(super) fn new(
        kernelet: Arc<Kernelet>,
        admission: Arc<Admission>,
        backing: Arc<dyn FileLike>,
        capacity_sectors: u64,
        read_only: bool,
        irq: u8,
    ) -> ostd::Result<Arc<Self>> {
        let registers = Registers::new();
        let charged_bytes = registers
            .inbox
            .capacity()
            .checked_mul(size_of::<Request>())
            .and_then(|bytes| bytes.checked_add(size_of::<Self>()))
            // Fixed request/slot/BIO metadata for the raw worker. Payload DMA
            // is charged separately when a slot actually allocates it.
            .and_then(|bytes| bytes.checked_add(IO_DEPTH * PAGE_SIZE))
            .ok_or(ostd::Error::Overflow)?;
        kernelet.charge_host_bytes(charged_bytes)?;
        Ok(Arc::new(Self {
            memory: kernelet.guest_memory(),
            kernelet,
            admission,
            backing,
            capacity_sectors,
            read_only,
            irq,
            registers: SpinLock::new(registers),
            interrupt_status: AtomicU32::new(0),
            requests: WaitQueue::new(),
            cancelled: AtomicBool::new(false),
            charged_bytes,
        }))
    }

    pub(super) fn start_worker(self: &Arc<Self>, execution: &super::scheduling::ExecutionThreads) {
        let device = self.clone();
        execution.spawn_worker(move || device.worker());
    }

    pub(super) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.requests.wake_all();
    }

    pub(super) fn read(&self, offset: u32, width: u32) -> MmioResult {
        if offset == 0x60 && width == 4 {
            return MmioResult {
                status: 0,
                value: self.interrupt_status.load(Ordering::Acquire) as u64,
            };
        }
        let registers = self.registers.lock();
        let value = if offset >= CONFIG_OFFSET {
            self.read_config(offset - CONFIG_OFFSET, width)
        } else if width == 4 {
            let value = match offset {
                0x00 => MAGIC,
                0x04 => VERSION,
                0x08 => DEVICE_ID_BLOCK,
                0x0c => 0x1af4,
                0x10 => feature_word(
                    FEATURE_VERSION_1
                        | FEATURE_BLOCK_SIZE
                        | FEATURE_FLUSH
                        | if self.read_only { FEATURE_READ_ONLY } else { 0 },
                    registers.device_features_select,
                ),
                0x34 => (registers.queue_select == 0) as u32 * QUEUE_SIZE as u32,
                0x38 => registers.queue_num,
                0x44 => registers.queue_ready as u32,
                0x70 => registers.status,
                0xfc => 0,
                _ => return invalid_read(),
            };
            Some(value as u64)
        } else {
            None
        };
        match value {
            Some(value) => MmioResult { status: 0, value },
            None => invalid_read(),
        }
    }

    pub(super) fn write(&self, offset: u32, width: u32, value: u64) -> i64 {
        if width != 4 || offset >= CONFIG_OFFSET || value > u32::MAX as u64 {
            return -INVALID;
        }
        let value = value as u32;
        let mut registers = self.registers.lock();
        let mut wake_worker = false;
        match offset {
            0x14 => registers.device_features_select = value,
            0x20 => {
                let selector = registers.driver_features_select;
                write_driver_feature_word(&mut registers.driver_features, selector, value);
            }
            0x24 => registers.driver_features_select = value,
            0x30 => registers.queue_select = value,
            0x38 if !registers.queue_ready => registers.queue_num = value,
            0x44 => {
                if value > 1 || registers.resetting || (value == 0 && registers.queue_ready) {
                    registers.status |= DEVICE_NEEDS_RESET;
                    return -INVALID;
                }
                if value == 1 && !self.queue_valid(&registers) {
                    registers.status |= DEVICE_NEEDS_RESET;
                    return -INVALID;
                }
                registers.queue_ready = value == 1;
            }
            0x50 => {
                if value != 0
                    || !registers.queue_ready
                    || registers.resetting
                    || registers.status & DEVICE_NEEDS_RESET != 0
                {
                    return -INVALID;
                }
                registers.collect_pending = true;
                wake_worker = true;
            }
            0x64 => {
                self.interrupt_status.fetch_and(!value, Ordering::AcqRel);
            }
            0x70 => {
                if value == 0 {
                    registers.reset();
                    self.interrupt_status.store(0, Ordering::Release);
                } else {
                    registers.status = value | (registers.status & DEVICE_NEEDS_RESET);
                }
            }
            0x80 if !registers.queue_ready => set_low(&mut registers.desc, value),
            0x84 if !registers.queue_ready => set_high(&mut registers.desc, value),
            0x90 if !registers.queue_ready => set_low(&mut registers.avail, value),
            0x94 if !registers.queue_ready => set_high(&mut registers.avail, value),
            0xa0 if !registers.queue_ready => set_low(&mut registers.used, value),
            0xa4 if !registers.queue_ready => set_high(&mut registers.used, value),
            _ => return -INVALID,
        }
        drop(registers);
        if wake_worker {
            self.requests.wake_all();
        }
        0
    }

    fn read_config(&self, offset: u32, width: u32) -> Option<u64> {
        let mut bytes = [0u8; CONFIG_OFFSET as usize];
        bytes[0..8].copy_from_slice(&self.capacity_sectors.to_le_bytes());
        bytes[20..24].copy_from_slice(&512u32.to_le_bytes());
        let start = offset as usize;
        let end = start.checked_add(width as usize)?;
        let slice = bytes.get(start..end)?;
        let mut word = [0u8; 8];
        word.get_mut(..slice.len())?.copy_from_slice(slice);
        Some(u64::from_le_bytes(word))
    }

    fn queue_valid(&self, r: &Registers) -> bool {
        r.queue_select == 0
            && super::virtio_mmio::layout_valid(
                &self.memory,
                r.queue_num,
                QUEUE_SIZE,
                r.desc,
                r.avail,
                r.used,
            )
    }

    fn collect_requests(&self, r: &mut Registers) -> bool {
        r.collect_pending = false;
        let Some(avail_index_addr) = r.avail.checked_add(2) else {
            r.status |= DEVICE_NEEDS_RESET;
            return false;
        };
        let Ok(avail_idx) = self.read_u16(avail_index_addr) else {
            r.status |= DEVICE_NEEDS_RESET;
            return false;
        };
        if avail_idx.wrapping_sub(r.last_avail) as u32 > r.queue_num {
            r.status |= DEVICE_NEEDS_RESET;
            return false;
        }
        let mut has_failed_completion = false;
        let mut budget = 1;
        while budget != 0
            && r.last_avail != avail_idx
            && r.inbox.len() + r.active < r.queue_num as usize
            && r.status & DEVICE_NEEDS_RESET == 0
        {
            budget -= 1;
            let slot = r.last_avail as u32 % r.queue_num;
            let Some(head_addr) = r.avail.checked_add(4 + slot as u64 * 2) else {
                r.status |= DEVICE_NEEDS_RESET;
                break;
            };
            let Ok(head) = self.read_u16(head_addr) else {
                r.status |= DEVICE_NEEDS_RESET;
                break;
            };
            match self.collect_chain(r, head) {
                Ok(request) if !r.pending_heads[head as usize] => {
                    r.pending_heads[head as usize] = true;
                    r.inbox.push_back(request);
                }
                Ok(request) => {
                    let status_tail = request.buffers[request.len - 1];
                    has_failed_completion |= self.complete_failed_chain(r, head, Some(status_tail));
                }
                Err(status_tail) => {
                    has_failed_completion |= self.complete_failed_chain(r, head, status_tail);
                }
            }
            r.last_avail = r.last_avail.wrapping_add(1);
        }
        // At most one chain per worker turn; a full inbox preserves the doorbell.
        r.collect_pending = r.last_avail != avail_idx && r.status & DEVICE_NEEDS_RESET == 0;
        has_failed_completion
    }

    // An invalid chain can still have a valid final status buffer.
    fn collect_chain(&self, r: &Registers, head: u16) -> Result<Request, Option<Buffer>> {
        if head as u32 >= r.queue_num {
            return Err(None);
        }
        let mut request = Request {
            head,
            generation: r.generation,
            buffers: [Buffer::default(); QUEUE_SIZE],
            len: 0,
        };
        let mut index = head;
        let mut total_bytes = 0usize;
        let mut is_valid = true;
        let mut visited = [false; QUEUE_SIZE];
        loop {
            if request.len >= r.queue_num as usize || visited[index as usize] {
                return Err(None);
            }
            visited[index as usize] = true;
            let mut bytes = [0u8; 16];
            let Some(desc_addr) = r.desc.checked_add(index as u64 * 16) else {
                return Err(None);
            };
            if self.memory.read(desc_addr, &mut bytes).is_err() {
                return Err(None);
            }
            let buffer = Buffer::decode(bytes);
            let buffer_len = buffer.len as usize;
            let is_bounded = buffer_len <= MAX_CHAIN_BYTES;
            if !buffer.supported() || !is_bounded || !self.memory.contains(buffer.paddr, buffer_len)
            {
                is_valid = false;
            }
            if let Some(bytes) = total_bytes.checked_add(buffer_len) {
                total_bytes = bytes;
                is_valid &= total_bytes <= MAX_CHAIN_BYTES;
            } else {
                is_valid = false;
            }
            request.buffers[request.len] = buffer;
            request.len += 1;
            if !buffer.has_next() {
                return if is_valid {
                    Ok(request)
                } else {
                    Err(self.status_tail(buffer))
                };
            }
            if buffer.next as u32 >= r.queue_num {
                return Err(None);
            }
            index = buffer.next;
        }
    }

    fn status_tail(&self, buffer: Buffer) -> Option<Buffer> {
        (buffer.writable()
            && buffer.len >= 1
            && buffer.len as usize <= MAX_CHAIN_BYTES
            && self.memory.contains(buffer.paddr, buffer.len as usize))
        .then_some(buffer)
    }

    fn complete_failed_chain(&self, r: &mut Registers, head: u16, tail: Option<Buffer>) -> bool {
        let used_len = if tail
            .and_then(|buffer| self.status_tail(buffer))
            .is_some_and(|buffer| self.memory.write(buffer.paddr, &[STATUS_IO_ERROR]).is_ok())
        {
            1
        } else {
            r.status |= DEVICE_NEEDS_RESET;
            0
        };
        self.publish_used(r, head, used_len)
    }

    fn take_request(&self) -> Option<BlockWork> {
        if self.cancelled.load(Ordering::Acquire) {
            return Some(BlockWork::Cancel);
        }
        let mut registers = self.registers.lock();
        if registers.collect_pending && registers.queue_ready && !registers.resetting {
            let before = registers.last_avail;
            let failed = self.collect_requests(&mut registers);
            let progressed = registers.last_avail != before;
            if failed {
                drop(registers);
                let _ = self.kernelet.raise_irq(self.irq);
                return Some(BlockWork::Progress);
            }
            if progressed && registers.inbox.is_empty() {
                return Some(BlockWork::Progress);
            }
        }
        let request = registers.inbox.pop_front()?;
        registers.active += 1;
        Some(BlockWork::Request(request))
    }

    fn worker(&self) {
        if self.kernelet.adopt_current_task().is_err() {
            return;
        }
        // Resolve the retained open-file capability once, never a pathname.
        if let Some(device) = crate::device::block_device_from_file(self.backing.as_ref()) {
            self.raw_worker(&mut BlockIo::new(
                device,
                self.kernelet.clone(),
                self.admission.clone(),
            ));
        } else {
            loop {
                match self.requests.wait_until(|| self.take_request()) {
                    BlockWork::Cancel => break,
                    BlockWork::Progress => {}
                    BlockWork::Request(request) => {
                        let result = self.execute(&request);
                        self.complete(request, result);
                    }
                }
                if ostd::task::Task::need_yield() {
                    ostd::task::Task::yield_now();
                }
            }
        }
        self.kernelet.disown_current_task();
    }

    fn raw_worker(&self, io: &mut BlockIo) {
        let mut deferred = None;
        let mut pending = Vec::with_capacity(IO_DEPTH);
        loop {
            if self.cancelled.load(Ordering::Acquire) {
                if let Some((request, _)) = deferred.take() {
                    self.complete(request, (STATUS_IO_ERROR, 0));
                }
                break;
            }
            let mut staged_bytes = 0;
            for _ in 0..IO_DEPTH {
                let (request, command) = if let Some(command) = deferred.take() {
                    command
                } else {
                    let work = if pending.is_empty() {
                        self.requests.wait_until(|| self.take_request())
                    } else {
                        let Some(work) = self.take_request() else {
                            break;
                        };
                        work
                    };
                    let request = match work {
                        BlockWork::Cancel => break,
                        BlockWork::Progress => continue,
                        BlockWork::Request(request) => request,
                    };
                    match self.prepare(&request) {
                        Ok(command) => (request, command),
                        Err(result) => {
                            self.complete(request, result);
                            continue;
                        }
                    }
                };
                match command {
                    BlockCommand::Flush if !pending.is_empty() => {
                        deferred = Some((request, command));
                        break;
                    }
                    BlockCommand::Flush => {
                        let result = self.flush();
                        self.complete(request, result);
                    }
                    BlockCommand::Transfer {
                        offset,
                        len,
                        operation,
                    } => {
                        if len == 0 {
                            self.complete(request, (0, 0));
                            continue;
                        }
                        let bytes = len.div_ceil(PAGE_SIZE) * PAGE_SIZE;
                        if !pending.is_empty() && staged_bytes + bytes > STAGING_BYTES {
                            deferred = Some((request, command));
                            break;
                        }
                        match io.submit(
                            pending.len(),
                            &self.memory,
                            &request.buffers[1..request.len - 1],
                            offset,
                            len,
                            operation,
                        ) {
                            Ok(transfer) => {
                                staged_bytes += bytes;
                                pending.push((request, transfer));
                            }
                            // Drain this batch before retrying admission or device
                            // backpressure once with no earlier BIO in flight.
                            Err(_) if !pending.is_empty() => {
                                deferred = Some((request, command));
                                break;
                            }
                            Err(_) => self.complete(request, (STATUS_IO_ERROR, 0)),
                        }
                    }
                }
            }
            // Every submitted request drains, including after reset/cancel. A
            // stale generations skip read copyback and used publication. Reset stays
            // pending until all active references drain, so a concurrent reset
            // cannot enable reuse of buffers during a copy already in progress.
            for (request, transfer) in pending.drain(..) {
                let result =
                    transfer.finish(&self.memory, &request.buffers[1..request.len - 1], || {
                        request.generation == self.registers.lock().generation
                            && !self.cancelled.load(Ordering::Acquire)
                    });
                let result = match result {
                    Ok(len) => (0, len),
                    Err((_, len)) => (STATUS_IO_ERROR, len),
                };
                self.complete(request, result);
            }
            if ostd::task::Task::need_yield() {
                ostd::task::Task::yield_now();
            }
        }
    }

    fn flush(&self) -> (u8, u32) {
        match self.backing.sync(SyncMode::Full) {
            Ok(()) => (0, 0),
            Err(_) => (STATUS_IO_ERROR, 0),
        }
    }

    fn prepare(&self, request: &Request) -> Result<BlockCommand, (u8, u32)> {
        if request.len < 2 || request.buffers[0].writable() {
            return Err((STATUS_IO_ERROR, 0));
        }
        let status = request.buffers[request.len - 1];
        if !status.writable() || status.len < 1 {
            return Err((STATUS_IO_ERROR, 0));
        }
        let mut header = [0u8; HEADER_BYTES];
        if request.buffers[0].len < HEADER_BYTES as u32
            || self
                .memory
                .read(request.buffers[0].paddr, &mut header)
                .is_err()
        {
            return Err((STATUS_IO_ERROR, 0));
        }
        let operation = u32::from_le_bytes(header[0..4].try_into().unwrap());
        if operation == REQUEST_FLUSH {
            if request.len != 2 {
                return Err((STATUS_IO_ERROR, 0));
            }
            return Ok(BlockCommand::Flush);
        }
        if operation == REQUEST_WRITE && self.read_only {
            return Err((STATUS_IO_ERROR, 0));
        }
        if operation != REQUEST_READ && operation != REQUEST_WRITE {
            return Err((STATUS_UNSUPPORTED, 0));
        }
        let sector = u64::from_le_bytes(header[8..16].try_into().unwrap());
        let Some(offset) = sector
            .checked_mul(SECTOR_BYTES)
            .and_then(|v| usize::try_from(v).ok())
        else {
            return Err((STATUS_IO_ERROR, 0));
        };
        let Some(capacity_bytes) = self.capacity_sectors.checked_mul(SECTOR_BYTES) else {
            return Err((STATUS_IO_ERROR, 0));
        };
        let mut end_offset = offset;
        for buffer in &request.buffers[1..request.len - 1] {
            if buffer.writable() != (operation == REQUEST_READ) {
                return Err((STATUS_IO_ERROR, 0));
            }
            let Some(next_offset) = end_offset.checked_add(buffer.len as usize) else {
                return Err((STATUS_IO_ERROR, 0));
            };
            if next_offset as u64 > capacity_bytes {
                return Err((STATUS_IO_ERROR, 0));
            }
            end_offset = next_offset;
        }
        if !(end_offset - offset).is_multiple_of(SECTOR_BYTES as usize) {
            return Err((STATUS_IO_ERROR, 0));
        }

        Ok(BlockCommand::Transfer {
            offset,
            len: end_offset - offset,
            operation,
        })
    }

    fn execute(&self, request: &Request) -> (u8, u32) {
        let (mut offset, operation) = match self.prepare(request) {
            Ok(BlockCommand::Flush) => return self.flush(),
            Ok(BlockCommand::Transfer {
                offset, operation, ..
            }) => (offset, operation),
            Err(result) => return result,
        };
        let mut used_len = 0u32;
        let result = with_buffers(
            &self.memory,
            &request.buffers[1..request.len - 1],
            |buffer, reader, writer| {
                let len = buffer.len as usize;
                let n = if operation == REQUEST_READ {
                    self.backing.read_at(offset, writer)?
                } else {
                    self.backing.write_at(offset, reader)?
                };
                if operation == REQUEST_READ {
                    used_len = used_len.saturating_add(n.min(len) as u32);
                }
                if n != len {
                    return_errno_with_message!(Errno::EIO, "short block backing transfer");
                }
                offset += len;
                Ok(())
            },
        );
        match result {
            Ok(()) => (0, used_len),
            Err(_) => (STATUS_IO_ERROR, used_len),
        }
    }

    fn complete(&self, request: Request, (status, data_len): (u8, u32)) {
        let mut registers = self.registers.lock();
        registers.active -= 1;
        if request.generation != registers.generation || self.cancelled.load(Ordering::Acquire) {
            if registers.resetting && registers.active == 0 {
                registers.resetting = false;
                registers.status = 0;
            }
            return;
        }
        registers.pending_heads[request.head as usize] = false;
        let status_buffer = request.buffers[request.len - 1];
        let used_len = if self.status_tail(status_buffer).is_some()
            && self.memory.write(status_buffer.paddr, &[status]).is_ok()
        {
            data_len + 1
        } else {
            registers.status |= DEVICE_NEEDS_RESET;
            0
        };
        let has_completion = self.publish_used(&mut registers, request.head, used_len);
        drop(registers);
        // This is the only inbox consumer. It checks the queue again on the
        // next iteration; producers and cancellation perform the needed wake.
        if has_completion {
            // Completion category: reporting the completions published
            // above, charged to this device's owning instance.
            let _ = ChargedSpan::measure(&self.kernelet, WorkCategory::Completion, || {
                self.kernelet.raise_irq(self.irq)
            });
        }
    }

    fn publish_used(&self, r: &mut Registers, head: u16, used_len: u32) -> bool {
        // Completion category: writing the used-ring entry and publishing
        // the used index, charged to this device's owning instance. Every
        // exit of this bounded region is charged, including a failed
        // publication that marks the device for reset.
        let _span = ChargedSpan::new(&self.kernelet, WorkCategory::Completion);
        if r.queue_num == 0 || r.queue_num as usize > QUEUE_SIZE {
            r.status |= DEVICE_NEEDS_RESET;
            return false;
        }
        let slot = r.next_used as u32 % r.queue_num;
        let Some(used_entry) = r.used.checked_add(4 + slot as u64 * 8) else {
            r.status |= DEVICE_NEEDS_RESET;
            return false;
        };
        let Some(used_index) = r.used.checked_add(2) else {
            r.status |= DEVICE_NEEDS_RESET;
            return false;
        };
        let next_used = r.next_used.wrapping_add(1);
        let mut entry = [0u8; 8];
        entry[..4].copy_from_slice(&u32::from(head).to_le_bytes());
        entry[4..].copy_from_slice(&used_len.to_le_bytes());
        if self.memory.write(used_entry, &entry).is_err() {
            r.status |= DEVICE_NEEDS_RESET;
            return false;
        }
        fence(Ordering::Release);
        if self
            .memory
            .write_u16_once(used_index, next_used.to_le())
            .is_err()
        {
            r.status |= DEVICE_NEEDS_RESET;
            return false;
        }
        r.next_used = next_used;
        self.interrupt_status.fetch_or(1, Ordering::Release);
        true
    }

    fn read_u16(&self, paddr: u64) -> ostd::Result<u16> {
        let value = self.memory.read_u16_once(paddr)?;
        fence(Ordering::Acquire);
        Ok(u16::from_le(value))
    }
}

/// Visits each descriptor with its original access bounds and call boundary.
/// Adjacent nonempty descriptors share a pin, but admission is rechecked before
/// each subsequent call so destroy cannot turn one in-progress I/O into several.
fn with_buffers(
    memory: &GuestMemory,
    mut buffers: &[Buffer],
    mut transfer_fn: impl FnMut(&Buffer, &mut VmReader, &mut VmWriter) -> Result<()>,
) -> Result<()> {
    while !buffers.is_empty() {
        let (run, len) = contiguous_run(buffers);
        if run.len() == 1 {
            memory.with_range(run[0].paddr, len, |mut reader, mut writer| {
                transfer_fn(&run[0], &mut reader, &mut writer)
            })??;
            buffers = &buffers[1..];
            continue;
        }
        let result = memory.with_range(run[0].paddr, len, |mut reader, mut writer| -> Result<()> {
            for (index, buffer) in run.iter().enumerate() {
                if index != 0 && !memory.contains(buffer.paddr, buffer.len as usize) {
                    return Err(ostd::Error::AccessDenied.into());
                }
                transfer_buffer(buffer, &mut reader, &mut writer, &mut transfer_fn)?;
            }
            Ok(())
        });
        match result {
            Ok(result) => result?,
            // No callback ran when the aggregate pin failed. Preserve the
            // original admission and completed-prefix behavior one descriptor
            // at a time; never retry a transfer that ran and then failed.
            Err(_) => {
                for buffer in run {
                    memory.with_range(
                        buffer.paddr,
                        buffer.len as usize,
                        |mut reader, mut writer| transfer_fn(buffer, &mut reader, &mut writer),
                    )??;
                }
            }
        }
        buffers = &buffers[run.len()..];
    }
    Ok(())
}

/// Returns the first physically contiguous, nonempty run. An empty descriptor
/// keeps its own call, including the backing file's zero-length error behavior.
fn contiguous_run(buffers: &[Buffer]) -> (&[Buffer], usize) {
    let first = &buffers[0];
    let mut len = first.len as usize;
    let mut count = 1;
    if len != 0 {
        while let Some(next) = buffers.get(count) {
            if next.len == 0 || first.paddr.checked_add(len as u64) != Some(next.paddr) {
                break;
            }
            let Some(next_len) = len.checked_add(next.len as usize) else {
                break;
            };
            if next_len > MAX_REQUEST_BYTES {
                break;
            }
            len = next_len;
            count += 1;
        }
    }
    (&buffers[..count], len)
}

fn transfer_buffer(
    buffer: &Buffer,
    reader: &mut VmReader,
    writer: &mut VmWriter,
    transfer_fn: &mut impl FnMut(&Buffer, &mut VmReader, &mut VmWriter) -> Result<()>,
) -> Result<()> {
    let len = buffer.len as usize;
    {
        let mut chunk_reader = reader.clone();
        chunk_reader.limit(len);
        let mut chunk_writer = writer.clone_exclusive();
        chunk_writer.limit(len);
        transfer_fn(buffer, &mut chunk_reader, &mut chunk_writer)?;
    }
    // The clones do not advance the enclosing accessors. Move to the next
    // descriptor only after this one completed successfully.
    reader.skip(len);
    writer.skip(len);
    Ok(())
}

impl Drop for VirtioBlock {
    fn drop(&mut self) {
        self.kernelet.uncharge_host_bytes(self.charged_bytes);
    }
}

#[cfg(ktest)]
mod tests {
    use ostd::{
        mm::{FallibleVmRead, FrameAllocOptions, io::util::HasVmReaderWriter},
        prelude::*,
    };

    use super::*;
    use crate::prelude::Error;

    fn buffer(paddr: u64, len: u32) -> Buffer {
        Buffer {
            paddr,
            len,
            ..Buffer::default()
        }
    }

    #[ktest]
    fn block_contiguous_runs_keep_empty_and_disjoint_buffers_separate() {
        let buffers = [
            buffer(4096, 512),
            buffer(4608, 1024),
            buffer(5632, 0),
            buffer(5632, 512),
            buffer(8192, 512),
        ];
        let (run, len) = contiguous_run(&buffers);
        assert_eq!((run.len(), len), (2, 1536));
        let (run, len) = contiguous_run(&buffers[2..]);
        assert_eq!((run.len(), len), (1, 0));
        let (run, len) = contiguous_run(&buffers[3..]);
        assert_eq!((run.len(), len), (1, 512));

        let buffers = [buffer(u64::MAX - 255, 512), buffer(256, 512)];
        assert_eq!(contiguous_run(&buffers).0.len(), 1);
        let buffers = [
            buffer(4096, MAX_REQUEST_BYTES as u32),
            buffer(4096 + MAX_REQUEST_BYTES as u64, 512),
        ];
        assert_eq!(contiguous_run(&buffers).0.len(), 1);
    }

    #[ktest]
    fn block_transfer_buffer_limits_each_accessor_and_advances_the_run() {
        let source = FrameAllocOptions::new().alloc_frame_with(()).unwrap();
        let destination = FrameAllocOptions::new().alloc_frame_with(()).unwrap();
        let data = [1u8, 2, 3, 4, 5, 6, 7, 8];
        source.writer().write(&mut VmReader::from(data.as_slice()));
        let mut reader = source.reader().to_fallible();
        reader.limit(data.len());
        let mut writer = destination.writer().to_fallible();
        writer.limit(data.len());
        let mut calls = 0;
        let mut transfer_fn = |buffer: &Buffer, reader: &mut VmReader, writer: &mut VmWriter| {
            let len = buffer.len as usize;
            assert_eq!(reader.remain(), len);
            assert_eq!(writer.avail(), len);
            assert_eq!(reader.read_fallible(writer).unwrap(), len);
            calls += 1;
            Ok(())
        };
        for buffer in [buffer(0, 3), buffer(3, 5)] {
            transfer_buffer(&buffer, &mut reader, &mut writer, &mut transfer_fn).unwrap();
        }
        assert_eq!(calls, 2);
        assert_eq!(reader.remain(), 0);
        assert_eq!(writer.avail(), 0);
        let mut actual = [0u8; 8];
        destination
            .reader()
            .read(&mut VmWriter::from(actual.as_mut_slice()));
        assert_eq!(actual, data);
    }

    #[ktest]
    fn block_transfer_buffer_preserves_error_and_does_not_advance_the_run() {
        let source = FrameAllocOptions::new().alloc_frame_with(()).unwrap();
        let destination = FrameAllocOptions::new().alloc_frame_with(()).unwrap();
        let mut reader = source.reader().to_fallible();
        reader.limit(8);
        let mut writer = destination.writer().to_fallible();
        writer.limit(8);
        let mut calls = 0;
        let result = transfer_buffer(
            &buffer(0, 4),
            &mut reader,
            &mut writer,
            &mut |_, reader, writer| {
                calls += 1;
                reader.skip(2);
                writer.skip(2);
                Err(Error::with_message(
                    Errno::ENOSPC,
                    "injected backing failure",
                ))
            },
        );
        assert!(matches!(result, Err(error) if error.error() == Errno::ENOSPC));
        assert_eq!(calls, 1);
        assert_eq!(reader.remain(), 8);
        assert_eq!(writer.avail(), 8);
    }
}
