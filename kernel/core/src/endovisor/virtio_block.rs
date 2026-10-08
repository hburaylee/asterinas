// SPDX-License-Identifier: MPL-2.0

//! A bounded virtio MMIO block register file and file-backed request worker.
//!
//! The device implements the block device of VirtIO 1.3 §5.2 (device ID 2)
//! over the common MMIO register file of §4.2.2: the read-only, block-size
//! and flush feature bits (§5.2.3) plus `VIRTIO_F_VERSION_1` (§6), and the
//! capacity and block-size fields of the configuration space (§5.2.4).
//! See <https://docs.oasis-open.org/virtio/virtio/v1.3/virtio-v1.3.html>.

use alloc::{collections::VecDeque, sync::Arc};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering, fence};

use ostd::{
    kernelet::{
        abi::{INVALID, MmioResult},
        control::Kernelet,
        guest_memory::GuestMemory,
    },
    sync::{SpinLock, WaitQueue},
};

use super::{
    io_accounting::{ChargedSpan, WorkCategory},
    virtio_mmio::{
        CONFIG_OFFSET, feature_word, invalid_read, set_high, set_low, write_driver_feature_word,
    },
};
use crate::{
    fs::file::{FileLike, SyncMode},
    thread::kernel_thread::ThreadOptions,
};

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

#[derive(Clone, Copy, Default)]
struct Buffer {
    paddr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

impl Buffer {
    fn writable(self) -> bool {
        self.flags & 2 != 0
    }

    fn has_next(self) -> bool {
        self.flags & 1 != 0
    }
}

struct Request {
    head: u16,
    generation: u64,
    buffers: [Buffer; QUEUE_SIZE],
    len: usize,
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
        self.resetting = self.active != 0;
        if !self.resetting {
            self.status = 0;
        }
    }
}

/// One attached virtio block device. Its hook never performs file I/O.
pub(super) struct VirtioBlock {
    kernelet: Arc<Kernelet>,
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
            .ok_or(ostd::Error::Overflow)?;
        kernelet.charge_host_bytes(charged_bytes)?;
        Ok(Arc::new(Self {
            memory: kernelet.guest_memory(),
            kernelet,
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

    pub(super) fn start_worker(self: &Arc<Self>) {
        let device = self.clone();
        ThreadOptions::new(move || device.worker()).spawn();
    }

    pub(super) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.requests.wake_all();
    }

    pub(super) fn read(&self, offset: u32, width: u32) -> MmioResult {
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
                0x60 => self.interrupt_status.load(Ordering::Acquire),
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
        let mut has_failed_completion = false;
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
                has_failed_completion = self.collect_requests(&mut registers);
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
        if has_failed_completion {
            // Completion category: reporting the failed chains completed
            // above, charged to this device's owning instance.
            let _ = ChargedSpan::measure(&self.kernelet, WorkCategory::Completion, || {
                self.kernelet.raise_irq(self.irq)
            });
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
            && r.queue_num > 0
            && r.queue_num as usize <= QUEUE_SIZE
            && r.queue_num.is_power_of_two()
            && r.desc.is_multiple_of(16)
            && r.avail.is_multiple_of(2)
            && r.used.is_multiple_of(4)
            && self.memory.contains(r.desc, r.queue_num as usize * 16)
            && self.memory.contains(r.avail, 6 + r.queue_num as usize * 2)
            && self.memory.contains(r.used, 6 + r.queue_num as usize * 8)
    }

    fn collect_requests(&self, r: &mut Registers) -> bool {
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
        while r.last_avail != avail_idx
            && r.inbox.len() + r.active < r.queue_num as usize
            && r.status & DEVICE_NEEDS_RESET == 0
        {
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
            let buffer = Buffer {
                paddr: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
                len: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
                flags: u16::from_le_bytes(bytes[12..14].try_into().unwrap()),
                next: u16::from_le_bytes(bytes[14..16].try_into().unwrap()),
            };
            let buffer_len = buffer.len as usize;
            let is_bounded = buffer_len <= MAX_CHAIN_BYTES;
            if buffer.flags & !3 != 0
                || !is_bounded
                || !self.memory.contains(buffer.paddr, buffer_len)
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

    fn worker(&self) {
        if self.kernelet.adopt_current_task().is_err() {
            return;
        }
        loop {
            let request = self.requests.wait_until(|| {
                if self.cancelled.load(Ordering::Acquire) {
                    return Some(None);
                }
                let mut registers = self.registers.lock();
                let request = registers.inbox.pop_front()?;
                registers.active += 1;
                Some(Some(request))
            });
            let Some(request) = request else {
                break;
            };
            let result = self.execute(&request);
            self.complete(request, result);
        }
        self.kernelet.disown_current_task();
    }

    fn execute(&self, request: &Request) -> (u8, u32) {
        if request.len < 2 || request.buffers[0].writable() {
            return (STATUS_IO_ERROR, 0);
        }
        let status = request.buffers[request.len - 1];
        if !status.writable() || status.len < 1 {
            return (STATUS_IO_ERROR, 0);
        }
        let mut header = [0u8; HEADER_BYTES];
        if request.buffers[0].len < HEADER_BYTES as u32
            || self
                .memory
                .read(request.buffers[0].paddr, &mut header)
                .is_err()
        {
            return (STATUS_IO_ERROR, 0);
        }
        let operation = u32::from_le_bytes(header[0..4].try_into().unwrap());
        if operation == REQUEST_FLUSH {
            if request.len != 2 {
                return (STATUS_IO_ERROR, 0);
            }
            return match self.backing.sync(SyncMode::Full) {
                Ok(()) => (0, 0),
                Err(_) => (STATUS_IO_ERROR, 0),
            };
        }
        if operation == REQUEST_WRITE && self.read_only {
            return (STATUS_IO_ERROR, 0);
        }
        if operation != REQUEST_READ && operation != REQUEST_WRITE {
            return (STATUS_UNSUPPORTED, 0);
        }
        let sector = u64::from_le_bytes(header[8..16].try_into().unwrap());
        let Some(mut offset) = sector
            .checked_mul(SECTOR_BYTES)
            .and_then(|v| usize::try_from(v).ok())
        else {
            return (STATUS_IO_ERROR, 0);
        };
        let Some(capacity_bytes) = self.capacity_sectors.checked_mul(SECTOR_BYTES) else {
            return (STATUS_IO_ERROR, 0);
        };
        let mut end_offset = offset;
        for buffer in &request.buffers[1..request.len - 1] {
            if buffer.writable() != (operation == REQUEST_READ) {
                return (STATUS_IO_ERROR, 0);
            }
            let Some(next_offset) = end_offset.checked_add(buffer.len as usize) else {
                return (STATUS_IO_ERROR, 0);
            };
            if next_offset as u64 > capacity_bytes {
                return (STATUS_IO_ERROR, 0);
            }
            end_offset = next_offset;
        }
        if !(end_offset - offset).is_multiple_of(SECTOR_BYTES as usize) {
            return (STATUS_IO_ERROR, 0);
        }

        let mut used_len = 0u32;
        for buffer in &request.buffers[1..request.len - 1] {
            let len = buffer.len as usize;
            let result = if operation == REQUEST_READ {
                self.memory
                    .with_writer(buffer.paddr, len, |writer| {
                        self.backing.read_at(offset, writer)
                    })
                    .map_err(|_| ())
                    .and_then(|result| result.map_err(|_| ()))
            } else {
                self.memory
                    .with_reader(buffer.paddr, len, |reader| {
                        self.backing.write_at(offset, reader)
                    })
                    .map_err(|_| ())
                    .and_then(|result| result.map_err(|_| ()))
            };
            match result {
                Ok(n) if n == len => {}
                Ok(n) => {
                    if operation == REQUEST_READ {
                        used_len = used_len.saturating_add(n.min(len) as u32);
                    }
                    return (STATUS_IO_ERROR, used_len);
                }
                Err(_) => return (STATUS_IO_ERROR, used_len),
            }
            if operation == REQUEST_READ {
                used_len = used_len.saturating_add(buffer.len);
            }
            offset += len;
        }
        (0, used_len)
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
        let has_failed_completion =
            if !self.cancelled.load(Ordering::Acquire) && registers.queue_ready {
                self.collect_requests(&mut registers)
            } else {
                false
            };
        drop(registers);
        self.requests.wake_all();
        if has_completion || has_failed_completion {
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
        let Some(used_len_addr) = used_entry.checked_add(4) else {
            r.status |= DEVICE_NEEDS_RESET;
            return false;
        };
        let Some(used_index) = r.used.checked_add(2) else {
            r.status |= DEVICE_NEEDS_RESET;
            return false;
        };
        let next_used = r.next_used.wrapping_add(1);
        if self
            .memory
            .write(used_entry, &u32::from(head).to_le_bytes())
            .and_then(|_| self.memory.write(used_len_addr, &used_len.to_le_bytes()))
            .is_err()
        {
            r.status |= DEVICE_NEEDS_RESET;
            return false;
        }
        fence(Ordering::Release);
        if self
            .memory
            .write(used_index, &next_used.to_le_bytes())
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
        let mut bytes = [0u8; 2];
        self.memory.read(paddr, &mut bytes)?;
        Ok(u16::from_le_bytes(bytes))
    }
}

impl Drop for VirtioBlock {
    fn drop(&mut self) {
        self.kernelet.uncharge_host_bytes(self.charged_bytes);
    }
}
