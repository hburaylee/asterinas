// SPDX-License-Identifier: MPL-2.0

//! Virtio MMIO vsock device for a kernelet.
//!
//! The device implements the socket device of VirtIO 1.3 §5.10 (device ID
//! 19) over the common MMIO register file of §4.2.2: a receiveq, a transmitq
//! and an eventq (§5.10.2), the stream feature `VIRTIO_VSOCK_F_STREAM`
//! (§5.10.3) plus `VIRTIO_F_VERSION_1` (§6), and the guest CID at offset
//! zero of the configuration space (§5.10.4).
//! See <https://docs.oasis-open.org/virtio/virtio/v1.3/virtio-v1.3.html>.
//!
//! The MMIO notify path validates descriptor chains and queues fixed-size
//! records. A device thread copies packets through `GuestMemory`, routes them
//! through the Host switch, and publishes used-ring completions. It never
//! exposes a guest address to the switch.

use alloc::{collections::VecDeque, sync::Arc};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering, fence};

use ostd::{
    kernelet::{
        abi::{INVALID, MmioResult},
        control::Kernelet,
        guest_memory::GuestMemory,
    },
    mm::{FallibleVmRead, VmReader, VmWriter},
    sync::{SpinLock, WaitQueue},
};

use super::{
    io_accounting::{ChargedSpan, WorkCategory},
    policy::{Admission, EndpointReservation},
    virtio_mmio::{
        CONFIG_OFFSET, Queue, ReadyWrite, feature_word, invalid_read, write_driver_feature_word,
    },
    vsock_switch::{Packet, SwitchRef, VsockSwitch},
};
use crate::{
    prelude::{Errno, Error},
    thread::kernel_thread::ThreadOptions,
};

const QUEUE_SIZE: usize = 64;
const NUM_QUEUES: usize = 3;
const RX: usize = 0;
const TX: usize = 1;
const EVENT: usize = 2;
const MAX_PACKET_BYTES: usize = 4096;
const MAX_INBOUND: usize = 64;
const MAGIC: u32 = 0x7472_6976;
const VERSION: u32 = 2;
const DEVICE_ID_VSOCK: u32 = 19;
const VENDOR: u32 = 0x1af4;
const FEATURE_STREAM: u64 = 1;
const FEATURE_VERSION_1: u64 = 1 << 32;
const DEVICE_NEEDS_RESET: u32 = 1 << 6;
const DEVICE_CHARGE: usize = size_of::<VirtioVsock>()
    + size_of::<Request>() * (QUEUE_SIZE * 2 + 1)
    + size_of::<QueuedPacket>() * MAX_INBOUND;

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
    capacity: usize,
}

struct Registers {
    status: u32,
    feature_select: u32,
    driver_feature_select: u32,
    driver_features: u64,
    queue_select: u32,
    queues: [Queue<QUEUE_SIZE>; NUM_QUEUES],
    generation: u64,
    active: usize,
    resetting: bool,
    cancelled: bool,
    rx: VecDeque<Request>,
    tx: VecDeque<Request>,
    events: VecDeque<Request>,
    inbound: VecDeque<QueuedPacket>,
    next_rx: bool,
}

pub(super) struct PacketCharge {
    owner: Arc<Kernelet>,
    bytes: usize,
    _admission: EndpointReservation,
}

impl PacketCharge {
    pub(super) fn reserve(
        owner: Arc<Kernelet>,
        admission: Arc<Admission>,
        bytes: usize,
    ) -> Option<Arc<Self>> {
        let reservation = admission.reserve_endpoint_bytes(bytes).ok()?;
        owner.charge_host_bytes(bytes).ok()?;
        Some(Arc::new(Self {
            owner,
            bytes,
            _admission: reservation,
        }))
    }
}

impl Drop for PacketCharge {
    fn drop(&mut self) {
        self.owner.uncharge_host_bytes(self.bytes);
    }
}

pub(super) struct QueuedPacket {
    pub(super) packet: Packet,
    pub(super) charge: Arc<PacketCharge>,
    pub(super) switch_ref: Option<SwitchRef>,
}

impl Registers {
    fn new() -> Self {
        Self {
            status: 0,
            feature_select: 0,
            driver_feature_select: 0,
            driver_features: 0,
            queue_select: 0,
            queues: [Queue::<QUEUE_SIZE>::default(); NUM_QUEUES],
            generation: 1,
            active: 0,
            resetting: false,
            cancelled: false,
            rx: VecDeque::with_capacity(QUEUE_SIZE),
            tx: VecDeque::with_capacity(QUEUE_SIZE),
            events: VecDeque::with_capacity(1),
            inbound: VecDeque::with_capacity(MAX_INBOUND),
            next_rx: false,
        }
    }

    fn reset(&mut self) -> VecDeque<QueuedPacket> {
        self.generation = self.generation.wrapping_add(1);
        self.rx.clear();
        self.tx.clear();
        self.events.clear();
        let pending = core::mem::take(&mut self.inbound);
        self.next_rx = false;
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
        pending
    }

    fn finish_reset(&mut self) {
        if self.resetting && self.active == 0 {
            self.resetting = false;
            self.status = 0;
        }
    }

    fn selected_queue_mut(&mut self) -> Option<&mut Queue<QUEUE_SIZE>> {
        self.queues.get_mut(self.queue_select as usize)
    }
}

/// A device instance is bound to one immutable, Host-assigned CID.
pub(super) struct VirtioVsock {
    kernelet: Arc<Kernelet>,
    admission: Arc<Admission>,
    _reservation: EndpointReservation,
    memory: GuestMemory,
    cid: u32,
    irq: u8,
    switch: Arc<VsockSwitch>,
    registers: SpinLock<Registers>,
    interrupt_status: AtomicU32,
    changes: WaitQueue,
    worker_started: AtomicBool,
}

impl VirtioVsock {
    pub(super) fn new(
        kernelet: Arc<Kernelet>,
        cid: u32,
        irq: u8,
        admission: Arc<Admission>,
    ) -> crate::prelude::Result<Arc<Self>> {
        let switch = VsockSwitch::global();
        let reservation = admission.reserve_endpoint_bytes(DEVICE_CHARGE)?;
        if kernelet.charge_host_bytes(DEVICE_CHARGE).is_err() {
            return Err(Error::with_message(
                Errno::ENOMEM,
                "cannot reserve vsock device queues",
            ));
        }
        let memory = kernelet.guest_memory();
        let device = Arc::new(Self {
            kernelet,
            admission,
            _reservation: reservation,
            memory,
            cid,
            irq,
            switch: switch.clone(),
            registers: SpinLock::new(Registers::new()),
            interrupt_status: AtomicU32::new(0),
            changes: WaitQueue::new(),
            worker_started: AtomicBool::new(false),
        });
        // CIDs are allocated monotonically by CREATE and must be unique.
        switch.register(cid, &device)?;
        Ok(device)
    }

    pub(super) fn start_worker(self: &Arc<Self>) {
        if self.worker_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let device = self.clone();
        ThreadOptions::new(move || device.worker()).spawn();
    }

    pub(super) fn cancel(&self) {
        let pending = {
            let mut registers = self.registers.lock();
            registers.cancelled = true;
            core::mem::take(&mut registers.inbound)
        };
        drop(pending);
        self.changes.wake_all();
    }

    /// Called by the switch without holding its routing lock.
    pub(super) fn enqueue(&self, packet: Packet) -> bool {
        self.enqueue_with_ref(packet, None)
    }

    pub(super) fn enqueue_with_ref(&self, packet: Packet, switch_ref: Option<SwitchRef>) -> bool {
        let (owner, admission) = self.switch.charge_account(packet.src_cid, self);
        let bytes = size_of::<Packet>() + packet.payload.len();
        let Some(charge) = PacketCharge::reserve(owner, admission, bytes) else {
            return false;
        };
        let mut registers = self.registers.lock();
        if registers.cancelled || registers.inbound.len() == MAX_INBOUND {
            return false;
        }
        registers.inbound.push_back(QueuedPacket {
            packet,
            charge,
            switch_ref,
        });
        drop(registers);
        self.changes.wake_all();
        true
    }

    pub(super) fn account_owner(&self) -> Arc<Kernelet> {
        self.kernelet.clone()
    }

    pub(super) fn account_admission(&self) -> Arc<Admission> {
        self.admission.clone()
    }

    pub(super) fn wake_notice(&self) {
        self.changes.wake_all();
    }

    pub(super) fn read(&self, offset: u32, width: u32) -> MmioResult {
        let registers = self.registers.lock();
        let value = if offset >= CONFIG_OFFSET {
            let mut config = [0u8; 8];
            config[..4].copy_from_slice(&self.cid.to_le_bytes());
            let start = (offset - CONFIG_OFFSET) as usize;
            let end = start.saturating_add(width as usize);
            let Some(bytes) = config.get(start..end) else {
                return invalid_read();
            };
            let mut word = [0u8; 8];
            let Some(dst) = word.get_mut(..bytes.len()) else {
                return invalid_read();
            };
            dst.copy_from_slice(bytes);
            Some(u64::from_le_bytes(word))
        } else if width == 4 {
            let value = match offset {
                0x00 => MAGIC,
                0x04 => VERSION,
                0x08 => DEVICE_ID_VSOCK,
                0x0c => VENDOR,
                0x10 => feature_word(FEATURE_STREAM | FEATURE_VERSION_1, registers.feature_select),
                0x34 => match registers.queue_select as usize {
                    RX | TX => QUEUE_SIZE as u32,
                    EVENT => 1,
                    _ => 0,
                },
                0x38 => registers
                    .queues
                    .get(registers.queue_select as usize)
                    .map_or(0, |q| q.num),
                0x44 => registers
                    .queues
                    .get(registers.queue_select as usize)
                    .map_or(0, |q| q.ready as u32),
                0x60 => self.interrupt_status.load(Ordering::Acquire),
                0x70 => registers.status,
                0xfc => 0,
                _ => return invalid_read(),
            };
            Some(u64::from(value))
        } else {
            None
        };
        value.map_or_else(invalid_read, |value| MmioResult { status: 0, value })
    }

    pub(super) fn write(&self, offset: u32, width: u32, value: u64) -> i64 {
        if width != 4 || offset >= CONFIG_OFFSET || value > u32::MAX as u64 {
            return -INVALID;
        }
        let value = value as u32;
        let mut registers = self.registers.lock();
        match offset {
            0x14 => registers.feature_select = value,
            0x20 => {
                let selector = registers.driver_feature_select;
                write_driver_feature_word(&mut registers.driver_features, selector, value);
            }
            0x24 => registers.driver_feature_select = value,
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
                self.changes.wake_all();
            }
            0x64 => {
                self.interrupt_status.fetch_and(!value, Ordering::AcqRel);
            }
            0x70 => {
                if value == 0 {
                    let pending = registers.reset();
                    self.interrupt_status.store(0, Ordering::Release);
                    drop(registers);
                    drop(pending);
                    return 0;
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
        0
    }

    fn queue_valid(&self, registers: &Registers) -> bool {
        let Some(queue) = registers.queues.get(registers.queue_select as usize) else {
            return false;
        };
        let max = if registers.queue_select as usize == EVENT {
            1
        } else {
            QUEUE_SIZE
        };
        queue.num > 0
            && queue.num as usize <= max
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

    fn collect_requests(&self, registers: &mut Registers, index: usize) {
        let queue = registers.queues[index];
        let Ok(avail_idx) = self.read_u16(queue.avail + 2) else {
            registers.status |= DEVICE_NEEDS_RESET;
            return;
        };
        if avail_idx.wrapping_sub(queue.last_avail) as u32 > queue.num {
            registers.status |= DEVICE_NEEDS_RESET;
            return;
        }
        let capacity = if index == EVENT { 1 } else { QUEUE_SIZE };
        while registers.queues[index].last_avail != avail_idx {
            let pending = match index {
                RX => registers.rx.len(),
                TX => registers.tx.len(),
                _ => registers.events.len(),
            };
            if pending >= capacity {
                break;
            }
            let last = registers.queues[index].last_avail;
            let slot = last as u32 % queue.num;
            let Some(addr) = queue.avail.checked_add(4 + slot as u64 * 2) else {
                registers.status |= DEVICE_NEEDS_RESET;
                return;
            };
            let Ok(head) = self.read_u16(addr) else {
                registers.status |= DEVICE_NEEDS_RESET;
                return;
            };
            let acceptable = registers.queues[index].head_acceptable(head);
            if acceptable && let Some(request) = self.collect_chain(registers, index, head) {
                registers.queues[index].mark_accepted(head);
                match index {
                    RX => registers.rx.push_back(request),
                    TX => registers.tx.push_back(request),
                    _ => registers.events.push_back(request),
                }
            } else {
                registers.status |= DEVICE_NEEDS_RESET;
            }
            registers.queues[index].last_avail = last.wrapping_add(1);
        }
    }

    fn collect_chain(&self, registers: &Registers, index: usize, head: u16) -> Option<Request> {
        let queue = &registers.queues[index];
        if head as u32 >= queue.num {
            return None;
        }
        let mut request = Request {
            head,
            generation: registers.generation,
            buffers: [Buffer::default(); QUEUE_SIZE],
            len: 0,
            capacity: 0,
        };
        let mut slot = head;
        loop {
            if request.len >= queue.num as usize {
                return None;
            }
            let mut bytes = [0u8; 16];
            self.read_guest(queue.desc.checked_add(slot as u64 * 16)?, &mut bytes)
                .ok()?;
            let buffer = Buffer {
                paddr: u64::from_le_bytes(bytes[0..8].try_into().ok()?),
                len: u32::from_le_bytes(bytes[8..12].try_into().ok()?),
                flags: u16::from_le_bytes(bytes[12..14].try_into().ok()?),
                next: u16::from_le_bytes(bytes[14..16].try_into().ok()?),
            };
            let next_capacity = request.capacity.checked_add(buffer.len as usize)?;
            if buffer.flags & 4 != 0
                || buffer.writable() != (index != TX)
                || next_capacity > MAX_PACKET_BYTES
                || !self.memory.contains(buffer.paddr, buffer.len as usize)
            {
                return None;
            }
            request.capacity = next_capacity;
            request.buffers[request.len] = buffer;
            request.len += 1;
            if !buffer.has_next() {
                break;
            }
            if buffer.next as u32 >= queue.num {
                return None;
            }
            slot = buffer.next;
        }
        if index == TX && request.capacity < Packet::HEADER_LEN {
            return None;
        }
        Some(request)
    }

    fn worker(&self) {
        if self.kernelet.adopt_current_task().is_err() {
            return;
        }
        loop {
            if self.changes.wait_until(|| self.take_work()) {
                break;
            }
        }
        self.kernelet.disown_current_task();
    }

    /// Returns `None` to block, `Some(false)` for progress, `Some(true)` to exit.
    fn take_work(&self) -> Option<bool> {
        let mut registers = self.registers.lock();
        if registers.cancelled {
            return Some(true);
        }
        if !registers.rx.is_empty()
            && let Some(notice) = self.switch.take_notice(self.cid)
        {
            let request = registers.rx.pop_front().unwrap();
            registers.active += 1;
            drop(registers);
            self.receive(request, notice);
            return Some(false);
        }
        if let Some(index) = registers.inbound.iter().position(|queued| {
            !self
                .switch
                .delivery_live(&queued.packet, queued.switch_ref.as_ref())
        }) {
            let retired = registers.inbound.remove(index);
            drop(registers);
            drop(retired);
            return Some(false);
        }
        let can_rx = !registers.rx.is_empty() && !registers.inbound.is_empty();
        if can_rx && (registers.next_rx || registers.tx.is_empty()) {
            let request = registers.rx.pop_front().unwrap();
            let packet = registers.inbound.pop_front().unwrap();
            registers.active += 1;
            registers.next_rx = false;
            drop(registers);
            self.receive(request, packet);
            return Some(false);
        }
        if let Some(request) = registers.tx.pop_front() {
            registers.active += 1;
            registers.next_rx = true;
            drop(registers);
            self.transmit(request);
            return Some(false);
        }
        None
    }

    fn transmit(&self, request: Request) {
        let mut bytes = [0u8; MAX_PACKET_BYTES];
        let mut offset = 0;
        for buffer in request.buffers[..request.len].iter() {
            let len = buffer.len as usize;
            if self
                .read_guest(buffer.paddr, &mut bytes[offset..offset + len])
                .is_err()
            {
                self.registers.lock().status |= DEVICE_NEEDS_RESET;
                self.complete(TX, request, 0);
                return;
            }
            offset += len;
        }
        if let Some(packet) = Packet::from_bytes(&bytes[..offset]) {
            self.switch.route(self.cid, packet);
        } else {
            self.registers.lock().status |= DEVICE_NEEDS_RESET;
        }
        self.complete(TX, request, 0);
    }

    fn receive(&self, request: Request, mut queued: QueuedPacket) {
        let packet = &mut queued.packet;
        if !self
            .switch
            .delivery_live(packet, queued.switch_ref.as_ref())
        {
            self.repark_receive(request);
            return;
        }
        if request.capacity < Packet::HEADER_LEN + packet.payload.len() {
            if packet.op != Packet::RW || request.capacity <= Packet::HEADER_LEN {
                self.registers.lock().status |= DEVICE_NEEDS_RESET;
                self.complete(RX, request, 0);
                return;
            }
            let deferred = Packet {
                src_cid: packet.src_cid,
                dst_cid: packet.dst_cid,
                src_port: packet.src_port,
                dst_port: packet.dst_port,
                op: packet.op,
                flags: packet.flags,
                buf_alloc: packet.buf_alloc,
                fwd_cnt: packet.fwd_cnt,
                payload: packet
                    .payload
                    .split_off(request.capacity - Packet::HEADER_LEN),
            };
            let mut registers = self.registers.lock();
            if registers.generation == request.generation {
                registers.inbound.push_front(QueuedPacket {
                    packet: deferred,
                    charge: queued.charge.clone(),
                    switch_ref: queued.switch_ref.clone(),
                });
            }
        }
        let mut bytes = [0u8; MAX_PACKET_BYTES];
        let Some(len) = packet.to_bytes(&mut bytes) else {
            self.registers.lock().status |= DEVICE_NEEDS_RESET;
            self.complete(RX, request, 0);
            return;
        };
        // Ingress category: the receiving instance pays for copying the
        // received packet into its guest buffers. Only the copy is charged:
        // the parked-wait and liveness rechecks around it are not execution.
        let span = ChargedSpan::new(&self.kernelet, WorkCategory::Ingress);
        let mut offset = 0;
        let mut copy_failed = false;
        for buffer in request.buffers[..request.len].iter() {
            let count = (len - offset).min(buffer.len as usize);
            if count == 0 {
                break;
            }
            if self
                .write_guest(buffer.paddr, &bytes[offset..offset + count])
                .is_err()
            {
                copy_failed = true;
                break;
            }
            offset += count;
        }
        drop(span);
        if copy_failed {
            self.registers.lock().status |= DEVICE_NEEDS_RESET;
            self.complete(RX, request, 0);
            return;
        }
        if !self
            .switch
            .delivery_live(packet, queued.switch_ref.as_ref())
        {
            self.repark_receive(request);
            return;
        }
        self.complete(RX, request, len as u32);
    }

    fn repark_receive(&self, request: Request) {
        let mut registers = self.registers.lock();
        registers.active -= 1;
        if registers.generation == request.generation {
            registers.rx.push_front(request);
        } else {
            registers.finish_reset();
        }
    }

    fn complete(&self, index: usize, request: Request, used_len: u32) {
        let mut registers = self.registers.lock();
        registers.active -= 1;
        if registers.generation != request.generation {
            registers.finish_reset();
            return;
        }
        // Completion category: publishing the used-ring entry and its IRQ,
        // charged to this device's owning instance.
        let span = ChargedSpan::new(&self.kernelet, WorkCategory::Completion);
        let queue = &mut registers.queues[index];
        queue.retire(request.head);
        let slot = queue.next_used as u32 % queue.num;
        let used_entry = queue.used + 4 + slot as u64 * 8;
        let _ = self.write_guest(used_entry, &(request.head as u32).to_le_bytes());
        let _ = self.write_guest(used_entry + 4, &used_len.to_le_bytes());
        queue.next_used = queue.next_used.wrapping_add(1);
        let _ = self.write_guest(queue.used + 2, &queue.next_used.to_le_bytes());
        fence(Ordering::Release);
        self.interrupt_status.fetch_or(1, Ordering::Release);
        drop(registers);
        let _ = self.kernelet.raise_irq(self.irq);
        drop(span);
    }

    fn read_u16(&self, paddr: u64) -> ostd::Result<u16> {
        let mut bytes = [0u8; 2];
        self.read_guest(paddr, &mut bytes)?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn read_guest(&self, paddr: u64, dst: &mut [u8]) -> ostd::Result<()> {
        self.memory.with_reader(paddr, dst.len(), |reader| {
            let mut writer = VmWriter::from(dst).to_fallible();
            reader
                .read_fallible(&mut writer)
                .map_err(|(error, _)| error)
        })??;
        Ok(())
    }

    fn write_guest(&self, paddr: u64, src: &[u8]) -> ostd::Result<()> {
        self.memory.with_writer(paddr, src.len(), |writer| {
            let mut reader = VmReader::from(src).to_fallible();
            reader.read_fallible(writer).map_err(|(error, _)| error)
        })??;
        Ok(())
    }
}

impl Drop for VirtioVsock {
    fn drop(&mut self) {
        self.kernelet.uncharge_host_bytes(DEVICE_CHARGE);
    }
}

#[cfg(ktest)]
mod reset_tests {
    use ostd::prelude::*;

    use super::{DEVICE_NEEDS_RESET, QUEUE_SIZE, Registers};

    #[ktest]
    fn virtio_vsock_reset_waits_for_active_requests() {
        let mut registers = Registers::new();
        registers.status = DEVICE_NEEDS_RESET;
        registers.queues[0].set_num(QUEUE_SIZE as u32);
        registers.queues[0].set_ready(1, true);
        registers.queues[0].mark_accepted(0);
        registers.active = 1;
        let generation = registers.generation;
        drop(registers.reset());
        assert_ne!(registers.generation, generation);
        assert!(registers.resetting);
        assert_eq!(registers.status, DEVICE_NEEDS_RESET);
        assert!(!registers.queues[0].ready);
        assert!(registers.queues[0].pending.iter().all(|pending| !pending));
        registers.finish_reset();
        assert!(registers.resetting);
        registers.active -= 1;
        registers.finish_reset();
        assert!(!registers.resetting);
        assert_eq!(registers.status, 0);
    }
}
