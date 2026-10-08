// SPDX-License-Identifier: MPL-2.0

//! A bounded virtio MMIO entropy device backed by the Host random source.
//!
//! The device implements the entropy device of VirtIO 1.3 §5.4 (device ID
//! 4), which has no device-specific feature bits or configuration space,
//! over the common MMIO register file of §4.2.2, offering only
//! `VIRTIO_F_VERSION_1` (§6).
//! See <https://docs.oasis-open.org/virtio/virtio/v1.3/virtio-v1.3.html>.
//!
//! The MMIO hook only snapshots validated descriptor chains. A Host kernel
//! thread fills their writable buffers and publishes used-ring completions.

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

use super::virtio_mmio::{
    feature_word, invalid_read, set_high, set_low, write_driver_feature_word,
};
use crate::{thread::kernel_thread::ThreadOptions, util::random::getrandom};

const QUEUE_SIZE: usize = 64;
const MAX_REQUEST_BYTES: usize = 4096;
const MAGIC: u32 = 0x7472_6976;
const VERSION: u32 = 2;
const DEVICE_ID_RNG: u32 = 4;
const VENDOR: u32 = 0x1af4;
const FEATURE_VERSION_1: u64 = 1 << 32;
const DEVICE_NEEDS_RESET: u32 = 1 << 6;

#[derive(Clone, Copy, Default)]
struct Buffer {
    paddr: u64,
    len: u32,
}

struct Request {
    head: u16,
    generation: u64,
    buffers: [Buffer; QUEUE_SIZE],
    num_buffers: usize,
    total_bytes: usize,
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
    resetting: bool,
    pending: [bool; QUEUE_SIZE],
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
            resetting: false,
            pending: [false; QUEUE_SIZE],
            inbox: VecDeque::with_capacity(QUEUE_SIZE),
        }
    }

    fn reset(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.inbox.clear();
        self.pending.fill(false);
        self.queue_ready = false;
        self.last_avail = 0;
        self.next_used = 0;
        self.resetting = self.active != 0;
        if !self.resetting {
            self.status = 0;
        }
    }
}

/// One Host-owned entropy source exposed to a single kernelet.
pub(super) struct VirtioRng {
    kernelet: Arc<Kernelet>,
    memory: GuestMemory,
    irq: u8,
    registers: SpinLock<Registers>,
    interrupt_status: AtomicU32,
    requests: WaitQueue,
    cancelled: AtomicBool,
}

impl VirtioRng {
    pub(super) fn new(kernelet: Arc<Kernelet>, irq: u8) -> Arc<Self> {
        Arc::new(Self {
            memory: kernelet.guest_memory(),
            kernelet,
            irq,
            registers: SpinLock::new(Registers::new()),
            interrupt_status: AtomicU32::new(0),
            requests: WaitQueue::new(),
            cancelled: AtomicBool::new(false),
        })
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
        if width != 4 {
            return invalid_read();
        }
        let registers = self.registers.lock();
        let value = match offset {
            0x00 => MAGIC,
            0x04 => VERSION,
            0x08 => DEVICE_ID_RNG,
            0x0c => VENDOR,
            0x10 => feature_word(FEATURE_VERSION_1, registers.device_features_select),
            0x34 => (registers.queue_select == 0) as u32 * QUEUE_SIZE as u32,
            0x38 => registers.queue_num,
            0x44 => registers.queue_ready as u32,
            0x60 => self.interrupt_status.load(Ordering::Acquire),
            0x70 => registers.status,
            0xfc => 0,
            _ => return invalid_read(),
        };
        MmioResult {
            status: 0,
            value: value as u64,
        }
    }

    pub(super) fn write(&self, offset: u32, width: u32, value: u64) -> i64 {
        if width != 4 || value > u32::MAX as u64 {
            return -INVALID;
        }
        let value = value as u32;
        let mut registers = self.registers.lock();
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
                if value > 1 || (value == 1 && !self.queue_valid(&registers)) {
                    registers.status |= DEVICE_NEEDS_RESET;
                    return -INVALID;
                }
                if registers.resetting {
                    return -INVALID;
                }
                if value == 0 && registers.pending.iter().any(|pending| *pending) {
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
                self.collect_requests(&mut registers);
                self.requests.wake_all();
            }
            0x64 => {
                self.interrupt_status.fetch_and(!value, Ordering::AcqRel);
            }
            0x70 => {
                if value == 0 {
                    registers.reset();
                    self.interrupt_status.store(0, Ordering::Release);
                } else if registers.resetting {
                    return -INVALID;
                } else {
                    registers.status = value;
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
        0
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

    fn collect_requests(&self, r: &mut Registers) {
        let Ok(avail_idx) = self.read_u16(r.avail + 2) else {
            r.status |= DEVICE_NEEDS_RESET;
            return;
        };
        if avail_idx.wrapping_sub(r.last_avail) as u32 > r.queue_num {
            r.status |= DEVICE_NEEDS_RESET;
            return;
        }
        while r.last_avail != avail_idx && r.inbox.len() + r.active < QUEUE_SIZE {
            let slot = r.last_avail as u32 % r.queue_num;
            let Some(head_addr) = r.avail.checked_add(4 + slot as u64 * 2) else {
                r.status |= DEVICE_NEEDS_RESET;
                return;
            };
            let Ok(head) = self.read_u16(head_addr) else {
                r.status |= DEVICE_NEEDS_RESET;
                return;
            };
            if r.pending.get(head as usize) != Some(&false) {
                r.status |= DEVICE_NEEDS_RESET;
                return;
            }
            let Some(request) = self.collect_chain(r, head) else {
                r.status |= DEVICE_NEEDS_RESET;
                return;
            };
            r.pending[head as usize] = true;
            r.inbox.push_back(request);
            r.last_avail = r.last_avail.wrapping_add(1);
        }
    }

    fn collect_chain(&self, r: &Registers, head: u16) -> Option<Request> {
        if head as u32 >= r.queue_num {
            return None;
        }
        let mut request = Request {
            head,
            generation: r.generation,
            buffers: [Buffer::default(); QUEUE_SIZE],
            num_buffers: 0,
            total_bytes: 0,
        };
        let mut visited = 0u64;
        let mut index = head;
        loop {
            let bit = 1u64.checked_shl(index as u32)?;
            if visited & bit != 0 {
                return None;
            }
            visited |= bit;
            let mut bytes = [0u8; 16];
            self.memory
                .read(r.desc.checked_add(index as u64 * 16)?, &mut bytes)
                .ok()?;
            let paddr = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
            let len = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
            let flags = u16::from_le_bytes(bytes[12..14].try_into().ok()?);
            let next = u16::from_le_bytes(bytes[14..16].try_into().ok()?);
            if flags & 2 == 0 || flags & !3 != 0 || !self.memory.contains(paddr, len as usize) {
                return None;
            }
            request.total_bytes = request.total_bytes.checked_add(len as usize)?;
            if request.total_bytes > MAX_REQUEST_BYTES {
                return None;
            }
            request.buffers[request.num_buffers] = Buffer { paddr, len };
            request.num_buffers += 1;
            if flags & 1 == 0 {
                break;
            }
            if next as u32 >= r.queue_num || request.num_buffers == QUEUE_SIZE {
                return None;
            }
            index = next;
        }
        Some(request)
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
                let mut r = self.registers.lock();
                let request = r.inbox.pop_front()?;
                r.active += 1;
                Some(Some(request))
            });
            let Some(request) = request else {
                break;
            };
            let mut entropy = [0u8; MAX_REQUEST_BYTES];
            getrandom(&mut entropy[..request.total_bytes]);
            self.complete(request, &entropy);
        }
        self.kernelet.disown_current_task();
    }

    fn complete(&self, request: Request, entropy: &[u8]) {
        let mut r = self.registers.lock();
        r.active -= 1;
        if request.generation != r.generation || self.cancelled.load(Ordering::Acquire) {
            if r.resetting && r.active == 0 {
                r.resetting = false;
                r.status = 0;
            }
            return;
        }
        let mut copied = 0;
        for buffer in &request.buffers[..request.num_buffers] {
            let end = copied + buffer.len as usize;
            if self
                .memory
                .write(buffer.paddr, &entropy[copied..end])
                .is_err()
            {
                r.status |= DEVICE_NEEDS_RESET;
                return;
            }
            copied = end;
        }
        let slot = r.next_used as u32 % r.queue_num;
        let used_entry = r.used + 4 + slot as u64 * 8;
        if self
            .memory
            .write(used_entry, &(request.head as u32).to_le_bytes())
            .is_err()
            || self
                .memory
                .write(used_entry + 4, &(copied as u32).to_le_bytes())
                .is_err()
        {
            r.status |= DEVICE_NEEDS_RESET;
            return;
        }
        r.next_used = r.next_used.wrapping_add(1);
        fence(Ordering::Release);
        if self
            .memory
            .write(r.used + 2, &r.next_used.to_le_bytes())
            .is_err()
        {
            r.status |= DEVICE_NEEDS_RESET;
            return;
        }
        r.pending[request.head as usize] = false;
        self.interrupt_status.fetch_or(1, Ordering::Release);
        drop(r);
        let _ = self.kernelet.raise_irq(self.irq);
    }

    fn read_u16(&self, paddr: u64) -> ostd::Result<u16> {
        let mut bytes = [0u8; 2];
        self.memory.read(paddr, &mut bytes)?;
        Ok(u16::from_le_bytes(bytes))
    }
}
