// SPDX-License-Identifier: MPL-2.0

//! A bounded virtio MMIO network device with a Host kernel network backend.
//!
//! The device implements the network device of VirtIO 1.3 §5.1 (device ID
//! 1) over the common MMIO register file of §4.2.2: one receiveq and one
//! transmitq (§5.1.2), the `VIRTIO_NET_F_MAC` and `VIRTIO_NET_F_STATUS`
//! feature bits (§5.1.3) plus `VIRTIO_F_VERSION_1` (§6), and the MAC and
//! link-status fields of the configuration space (§5.1.4).
//! See <https://docs.oasis-open.org/virtio/virtio/v1.3/virtio-v1.3.html>.
//!
//! Device queues, Ethernet forwarding, and native sockets run on one adopted
//! Host task. The endpoint descriptor is used only to configure the backend.

use core::sync::atomic::{AtomicU32, Ordering, fence};

use ostd::kernelet::{
    abi::{INVALID, MmioResult},
    control::Kernelet,
    guest_memory::GuestMemory,
};

use super::{
    io_accounting::{ChargedSpan, WorkCategory},
    virtio_mmio::{
        CONFIG_OFFSET, Queue, ReadyWrite, feature_word, invalid_read, write_driver_feature_word,
    },
};
use crate::{prelude::*, thread::kernel_thread::ThreadOptions};

mod endpoint;
mod nat;
mod sockets;

pub(super) use endpoint::{NetEndpoint, NetEndpointFile};

const QUEUE_SIZE: usize = 64;
const NUM_QUEUES: usize = 2;
const QUEUE_RX: usize = 0;
const QUEUE_TX: usize = 1;
const INBOX_SLOTS: usize = QUEUE_SIZE * NUM_QUEUES;
const ENDPOINT_SLOTS: usize = QUEUE_SIZE;
const NET_HEADER_BYTES: usize = 12;
const MIN_FRAME_BYTES: usize = 14;
const MAX_FRAME_BYTES: usize = 1514;
const MAX_CHAIN_BYTES: usize = 64 * 1024;
const MAGIC: u32 = 0x7472_6976;
const VERSION: u32 = 2;
const DEVICE_ID_NET: u32 = 1;
const VENDOR: u32 = 0x1af4;
const FEATURE_MAC: u64 = 1 << 5;
const FEATURE_STATUS: u64 = 1 << 16;
const FEATURE_VERSION_1: u64 = 1 << 32;
const DEVICE_NEEDS_RESET: u32 = 1 << 6;

#[derive(Clone)]
struct Frame {
    len: usize,
    bytes: [u8; MAX_FRAME_BYTES],
}

impl Frame {
    fn empty() -> Self {
        Self {
            len: 0,
            bytes: [0; MAX_FRAME_BYTES],
        }
    }
}

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
    queue: usize,
    head: u16,
    generation: u64,
    buffers: [Buffer; QUEUE_SIZE],
    len: usize,
    bytes: usize,
}

struct Registers {
    status: u32,
    device_features_select: u32,
    driver_features_select: u32,
    driver_features: u64,
    queue_select: u32,
    queues: [Queue<QUEUE_SIZE>; NUM_QUEUES],
    generation: u64,
    active: usize,
    resetting: bool,
    cancelled: bool,
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
            queues: [Queue::<QUEUE_SIZE>::default(); NUM_QUEUES],
            generation: 1,
            active: 0,
            resetting: false,
            cancelled: false,
            inbox: VecDeque::with_capacity(INBOX_SLOTS),
        }
    }

    fn reset(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.inbox.clear();
        for queue in &mut self.queues {
            queue.ready = false;
            queue.last_avail = 0;
            queue.next_used = 0;
            queue.pending.fill(false);
        }
        self.resetting = self.active != 0;
        if !self.resetting {
            self.status = 0;
        }
    }

    fn selected_queue_mut(&mut self) -> Option<&mut Queue<QUEUE_SIZE>> {
        self.queues.get_mut(self.queue_select as usize)
    }
}

/// One virtio-net device. MMIO hooks validate and enqueue; the worker moves frames.
pub(super) struct VirtioNet {
    kernelet: Arc<Kernelet>,
    memory: GuestMemory,
    endpoint: Arc<NetEndpoint>,
    mac: [u8; 6],
    irq: u8,
    registers: SpinLock<Registers>,
    interrupt_status: AtomicU32,
}

impl VirtioNet {
    pub(super) fn new(
        kernelet: Arc<Kernelet>,
        endpoint: Arc<NetEndpoint>,
        mac: [u8; 6],
        irq: u8,
    ) -> Arc<Self> {
        Arc::new(Self {
            memory: kernelet.guest_memory(),
            kernelet,
            endpoint,
            mac,
            irq,
            registers: SpinLock::new(Registers::new()),
            interrupt_status: AtomicU32::new(0),
        })
    }

    pub(super) fn start_worker(self: &Arc<Self>) {
        let device = self.clone();
        ThreadOptions::new(move || device.worker()).spawn();
    }

    pub(super) fn cancel(&self) {
        self.registers.lock().cancelled = true;
        self.endpoint.wake_backend();
    }

    pub(super) fn read(&self, offset: u32, width: u32) -> MmioResult {
        let registers = self.registers.lock();
        let value = if offset >= CONFIG_OFFSET {
            self.read_config(offset - CONFIG_OFFSET, width)
        } else if width == 4 {
            let value = match offset {
                0x00 => MAGIC,
                0x04 => VERSION,
                0x08 => DEVICE_ID_NET,
                0x0c => VENDOR,
                0x10 => feature_word(
                    FEATURE_VERSION_1 | FEATURE_MAC | FEATURE_STATUS,
                    registers.device_features_select,
                ),
                0x34 => ((registers.queue_select as usize) < NUM_QUEUES) as u32 * QUEUE_SIZE as u32,
                0x38 => registers
                    .queues
                    .get(registers.queue_select as usize)
                    .map_or(0, |queue| queue.num),
                0x44 => registers
                    .queues
                    .get(registers.queue_select as usize)
                    .map_or(0, |queue| queue.ready as u32),
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
        match offset {
            0x14 => registers.device_features_select = value,
            0x20 => {
                let selector = registers.driver_features_select;
                write_driver_feature_word(&mut registers.driver_features, selector, value);
            }
            0x24 => registers.driver_features_select = value,
            0x30 => registers.queue_select = value,
            0x38 => match registers.selected_queue_mut() {
                Some(queue) => {
                    if !queue.set_num(value) {
                        return -INVALID;
                    }
                }
                None => return -INVALID,
            },
            0x44 => {
                let valid = self.queue_valid(&registers);
                let outcome = match registers.selected_queue_mut() {
                    Some(queue) => queue.set_ready(value, valid),
                    None => return -INVALID,
                };
                match outcome {
                    ReadyWrite::Applied => {}
                    ReadyWrite::Refused => return -INVALID,
                    ReadyWrite::NeedsReset => {
                        registers.status |= DEVICE_NEEDS_RESET;
                        return -INVALID;
                    }
                }
            }
            0x50 => {
                let index = value as usize;
                if index >= NUM_QUEUES || !registers.queues[index].ready || registers.resetting {
                    return -INVALID;
                }
                self.collect_requests(&mut registers, index);
                self.endpoint.wake_backend();
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
            0x80 | 0x84 | 0x90 | 0x94 | 0xa0 | 0xa4 => match registers.selected_queue_mut() {
                Some(queue) => {
                    if !queue.set_address_register(offset, value) {
                        return -INVALID;
                    }
                }
                None => return -INVALID,
            },
            _ => return -INVALID,
        }
        let irq = offset == 0x50 && self.interrupt_status.load(Ordering::Acquire) != 0;
        drop(registers);
        if irq {
            // Completion category: reporting the invalid chains completed
            // during the notify above, charged to the owning instance.
            let _ = ChargedSpan::measure(&self.kernelet, WorkCategory::Completion, || {
                self.kernelet.raise_irq(self.irq)
            });
        }
        0
    }

    fn read_config(&self, offset: u32, width: u32) -> Option<u64> {
        // Keep the full modern virtio-net configuration space addressable.
        // Fields whose features are not offered by this model read as zero.
        let mut bytes = [0u8; 24];
        bytes[..6].copy_from_slice(&self.mac);
        bytes[6..8].copy_from_slice(&1u16.to_le_bytes());
        let start = offset as usize;
        let end = start.checked_add(width as usize)?;
        let slice = bytes.get(start..end)?;
        let mut word = [0u8; 8];
        word.get_mut(..slice.len())?.copy_from_slice(slice);
        Some(u64::from_le_bytes(word))
    }

    fn queue_valid(&self, r: &Registers) -> bool {
        let Some(queue) = r.queues.get(r.queue_select as usize) else {
            return false;
        };
        queue.num > 0
            && queue.num as usize <= QUEUE_SIZE
            && queue.num.is_power_of_two()
            && queue.desc.is_multiple_of(16)
            && queue.avail.is_multiple_of(2)
            && queue.used.is_multiple_of(4)
            && self.memory.contains(queue.desc, queue.num as usize * 16)
            && self
                .memory
                .contains(queue.avail, 6 + queue.num as usize * 2)
            && self.memory.contains(queue.used, 6 + queue.num as usize * 8)
    }

    fn collect_requests(&self, r: &mut Registers, index: usize) {
        let (avail, num) = {
            let queue = &r.queues[index];
            (queue.avail, queue.num)
        };
        let Ok(avail_idx) = self.read_u16(avail + 2) else {
            r.status |= DEVICE_NEEDS_RESET;
            return;
        };
        if avail_idx.wrapping_sub(r.queues[index].last_avail) as u32 > num {
            r.status |= DEVICE_NEEDS_RESET;
            return;
        }
        while r.queues[index].last_avail != avail_idx && r.inbox.len() < INBOX_SLOTS {
            let slot = r.queues[index].last_avail as u32 % num;
            let Some(head_addr) = avail.checked_add(4 + slot as u64 * 2) else {
                r.status |= DEVICE_NEEDS_RESET;
                return;
            };
            let Ok(head) = self.read_u16(head_addr) else {
                r.status |= DEVICE_NEEDS_RESET;
                return;
            };
            if !r.queues[index].head_acceptable(head) {
                r.status |= DEVICE_NEEDS_RESET;
                self.complete_invalid(r, index, head);
            } else if let Some(request) = self.collect_chain(r, index, head) {
                r.queues[index].mark_accepted(head);
                r.inbox.push_back(request);
            } else {
                r.status |= DEVICE_NEEDS_RESET;
                self.complete_invalid(r, index, head);
            }
            r.queues[index].last_avail = r.queues[index].last_avail.wrapping_add(1);
        }
    }

    fn collect_chain(&self, r: &Registers, queue_index: usize, head: u16) -> Option<Request> {
        let queue = &r.queues[queue_index];
        if head as u32 >= queue.num {
            return None;
        }
        let mut request = Request {
            queue: queue_index,
            head,
            generation: r.generation,
            buffers: [Buffer::default(); QUEUE_SIZE],
            len: 0,
            bytes: 0,
        };
        let mut index = head;
        loop {
            if request.len >= queue.num as usize {
                return None;
            }
            let mut bytes = [0u8; 16];
            self.memory
                .read(queue.desc.checked_add(index as u64 * 16)?, &mut bytes)
                .ok()?;
            let buffer = Buffer {
                paddr: u64::from_le_bytes(bytes[0..8].try_into().ok()?),
                len: u32::from_le_bytes(bytes[8..12].try_into().ok()?),
                flags: u16::from_le_bytes(bytes[12..14].try_into().ok()?),
                next: u16::from_le_bytes(bytes[14..16].try_into().ok()?),
            };
            if buffer.flags & 4 != 0
                || buffer.writable() != (queue_index == QUEUE_RX)
                || !self.memory.contains(buffer.paddr, buffer.len as usize)
            {
                return None;
            }
            request.bytes = request.bytes.checked_add(buffer.len as usize)?;
            if request.bytes > MAX_CHAIN_BYTES {
                return None;
            }
            request.buffers[request.len] = buffer;
            request.len += 1;
            if !buffer.has_next() {
                break;
            }
            if buffer.next as u32 >= queue.num {
                return None;
            }
            index = buffer.next;
        }
        Some(request)
    }

    fn complete_invalid(&self, r: &mut Registers, index: usize, head: u16) {
        // Completion category: a refused chain still publishes its used
        // entry so the driver can recycle it; charged to the owning
        // instance.
        let _span = ChargedSpan::new(&self.kernelet, WorkCategory::Completion);
        let queue = &mut r.queues[index];
        let slot = queue.next_used as u32 % queue.num;
        let used_entry = queue.used + 4 + slot as u64 * 8;
        let _ = self.memory.write(used_entry, &(head as u32).to_le_bytes());
        let _ = self.memory.write(used_entry + 4, &0u32.to_le_bytes());
        queue.next_used = queue.next_used.wrapping_add(1);
        let _ = self
            .memory
            .write(queue.used + 2, &queue.next_used.to_le_bytes());
        fence(Ordering::Release);
        self.interrupt_status.fetch_or(1, Ordering::Release);
    }

    fn worker(&self) {
        if self.kernelet.adopt_current_task().is_err() {
            return;
        }
        if let Some((backend, reservation)) = self.endpoint.take_backend() {
            // Backend resources are released before their UID reservation.
            let result = backend.run(self);
            drop(reservation);
            if let Err(error) = result {
                error!("kernelet network backend failed: {:?}", error);
                let _ = self
                    .kernelet
                    .kill(ostd::kernelet::control::KillReason::HostPolicy(u32::MAX));
            }
        }
        self.kernelet.disown_current_task();
    }

    fn take_work(&self) -> Option<Work> {
        let has_input = self.endpoint.input_available();
        let has_output_room = self.endpoint.output_has_space();
        let mut r = self.registers.lock();
        if r.cancelled || self.endpoint.revoked.load(Ordering::Acquire) {
            return Some(Work::Cancel);
        }
        let slot = r.inbox.iter().position(|request| {
            (request.queue == QUEUE_RX && has_input)
                || (request.queue == QUEUE_TX && has_output_room)
        })?;
        let request = r.inbox.remove(slot).unwrap();
        r.active += 1;
        drop(r);
        if request.queue == QUEUE_RX {
            self.receive(request);
        } else {
            self.transmit(request);
        }
        Some(Work::Progress)
    }

    fn transmit(&self, request: Request) {
        if !(NET_HEADER_BYTES + MIN_FRAME_BYTES..=NET_HEADER_BYTES + MAX_FRAME_BYTES)
            .contains(&request.bytes)
        {
            self.complete(request, 0);
            return;
        }
        let mut bytes = [0u8; NET_HEADER_BYTES + MAX_FRAME_BYTES];
        let mut offset = 0usize;
        for buffer in &request.buffers[..request.len] {
            let count = buffer.len as usize;
            if self
                .memory
                .read(buffer.paddr, &mut bytes[offset..offset + count])
                .is_err()
            {
                self.registers.lock().status |= DEVICE_NEEDS_RESET;
                self.complete(request, 0);
                return;
            }
            offset += count;
        }
        // Offloads are not advertised. An unoffloaded packet has a zeroed
        // virtio-net header; silently drop a driver request that violates it.
        if bytes[..NET_HEADER_BYTES].iter().any(|byte| *byte != 0) {
            self.complete(request, 0);
            return;
        }
        if self.registers.lock().generation != request.generation {
            self.complete(request, 0);
            return;
        }
        let mut frame = Frame::empty();
        frame.len = request.bytes - NET_HEADER_BYTES;
        frame.bytes[..frame.len].copy_from_slice(&bytes[NET_HEADER_BYTES..request.bytes]);
        if !self.endpoint.push_output(frame) {
            let mut r = self.registers.lock();
            r.active -= 1;
            if r.generation == request.generation && !r.cancelled {
                r.inbox.push_front(request);
            }
            if r.resetting && r.active == 0 {
                r.resetting = false;
                r.status = 0;
            }
            return;
        }
        self.complete(request, 0);
    }

    fn receive(&self, request: Request) {
        let Some(frame) = self.endpoint.pop_input() else {
            let mut r = self.registers.lock();
            r.active -= 1;
            if r.generation == request.generation && !r.cancelled {
                r.inbox.push_front(request);
            }
            if r.resetting && r.active == 0 {
                r.resetting = false;
                r.status = 0;
            }
            return;
        };
        let mut r = self.registers.lock();
        if r.generation != request.generation {
            r.active -= 1;
            if r.resetting && r.active == 0 {
                r.resetting = false;
                r.status = 0;
            }
            return;
        }
        let used_len = NET_HEADER_BYTES + frame.len;
        if request.bytes < used_len {
            r.status |= DEVICE_NEEDS_RESET;
            self.complete_locked(&mut r, request, 0);
        } else {
            let mut bytes = [0u8; NET_HEADER_BYTES + MAX_FRAME_BYTES];
            bytes[NET_HEADER_BYTES..used_len].copy_from_slice(&frame.bytes[..frame.len]);
            let mut done = 0usize;
            let mut failed = false;
            // Ingress category: the receiving instance pays for copying
            // the received frame into its guest buffers.
            let span = ChargedSpan::new(&self.kernelet, WorkCategory::Ingress);
            for buffer in &request.buffers[..request.len] {
                if done == used_len {
                    break;
                }
                let count = (buffer.len as usize).min(used_len - done);
                if self
                    .memory
                    .write(buffer.paddr, &bytes[done..done + count])
                    .is_err()
                {
                    failed = true;
                    break;
                }
                done += count;
            }
            drop(span);
            if failed {
                r.status |= DEVICE_NEEDS_RESET;
            }
            self.complete_locked(&mut r, request, if failed { 0 } else { used_len as u32 });
        }
        drop(r);
        // Completion category: reporting the receive completion published
        // by `complete_locked`, charged to the owning instance.
        let _ = ChargedSpan::measure(&self.kernelet, WorkCategory::Completion, || {
            self.kernelet.raise_irq(self.irq)
        });
    }

    fn complete(&self, request: Request, used_len: u32) {
        let mut r = self.registers.lock();
        let live = r.generation == request.generation;
        self.complete_locked(&mut r, request, used_len);
        drop(r);
        if live {
            // Completion category: reporting the completion published by
            // `complete_locked`, charged to the owning instance.
            let _ = ChargedSpan::measure(&self.kernelet, WorkCategory::Completion, || {
                self.kernelet.raise_irq(self.irq)
            });
        }
    }

    fn complete_locked(&self, r: &mut Registers, request: Request, used_len: u32) {
        r.active -= 1;
        if r.generation != request.generation {
            if r.resetting && r.active == 0 {
                r.resetting = false;
                r.status = 0;
            }
            return;
        }
        // Completion category: publishing the used-ring entry, charged to
        // this device's owning instance.
        let _span = ChargedSpan::new(&self.kernelet, WorkCategory::Completion);
        let queue = &mut r.queues[request.queue];
        queue.retire(request.head);
        let slot = queue.next_used as u32 % queue.num;
        let used_entry = queue.used + 4 + slot as u64 * 8;
        let _ = self
            .memory
            .write(used_entry, &(request.head as u32).to_le_bytes());
        let _ = self.memory.write(used_entry + 4, &used_len.to_le_bytes());
        queue.next_used = queue.next_used.wrapping_add(1);
        let _ = self
            .memory
            .write(queue.used + 2, &queue.next_used.to_le_bytes());
        fence(Ordering::Release);
        self.interrupt_status.fetch_or(1, Ordering::Release);
    }

    fn read_u16(&self, paddr: u64) -> ostd::Result<u16> {
        let mut bytes = [0u8; 2];
        self.memory.read(paddr, &mut bytes)?;
        Ok(u16::from_le_bytes(bytes))
    }
}

enum Work {
    Cancel,
    Progress,
}
