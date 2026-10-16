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
//! The MMIO notify path records a doorbell. A device thread validates bounded
//! descriptor chains, copies packets through `GuestMemory`, routes them
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
    events::IoEvents,
    prelude::{Errno, Error, Result},
    process::signal::{PollHandle, Pollee},
};

const QUEUE_SIZE: usize = 64;
const NUM_QUEUES: usize = 3;
const RX: usize = 0;
const TX: usize = 1;
const EVENT: usize = 2;
const MAX_PACKET_BYTES: usize = 4096;
const MAX_INBOUND: usize = 64;

#[cfg(kernelet_host_connect_gate)]
struct ConnectGate {
    identity: super::vsock_switch::DiagConnectIdentity,
    generation: u64,
    host_port: u32,
    peer_port: u32,
    delay_ms: u64,
}

#[cfg(kernelet_host_connect_gate)]
struct ConnectGateWake(Arc<WaitQueue>);

#[cfg(kernelet_host_connect_gate)]
impl crate::events::Observer<IoEvents> for ConnectGateWake {
    fn on_events(&self, _: &IoEvents) {
        self.0.wake_all();
    }
}
const MAGIC: u32 = 0x7472_6976;
const VERSION: u32 = 2;
const DEVICE_ID_VSOCK: u32 = 19;
const VENDOR: u32 = 0x1af4;
const FEATURE_STREAM: u64 = 1;
const FEATURE_VERSION_1: u64 = 1 << 32;
const DEVICE_NEEDS_RESET: u32 = 1 << 6;
const DEVICE_CHARGE: usize = size_of::<VirtioVsock>()
    + size_of::<Request>() * (QUEUE_SIZE * 2 + 1)
    + size_of::<QueuedPacket>() * MAX_INBOUND
    + CONNECT_GATE_CHARGE;

#[cfg(kernelet_host_connect_gate)]
const CONNECT_GATE_CHARGE: usize = size_of::<WaitQueue>() + size_of::<ConnectGateWake>();
#[cfg(not(kernelet_host_connect_gate))]
const CONNECT_GATE_CHARGE: usize = 0;

type Buffer = super::virtio_mmio::Descriptor;

struct Request {
    head: u16,
    generation: u64,
    buffers: [Buffer; QUEUE_SIZE],
    len: usize,
    capacity: usize,
}

/// Walks an already validated descriptor chain across header/payload calls.
struct BufferCursor<'a> {
    buffers: &'a [Buffer],
    offset: usize,
}

impl<'a> BufferCursor<'a> {
    fn new(buffers: &'a [Buffer]) -> Self {
        Self { buffers, offset: 0 }
    }

    fn copy(
        &mut self,
        len: usize,
        mut copy: impl FnMut(u64, core::ops::Range<usize>) -> ostd::Result<()>,
    ) -> ostd::Result<()> {
        let mut copied = 0;
        while copied < len {
            let Some(buffer) = self.buffers.first() else {
                return Err(ostd::Error::InvalidArgs);
            };
            if self.offset == buffer.len as usize {
                self.buffers = &self.buffers[1..];
                self.offset = 0;
                continue;
            }
            let count = (len - copied).min(buffer.len as usize - self.offset);
            let paddr = buffer
                .paddr
                .checked_add(self.offset as u64)
                .ok_or(ostd::Error::InvalidArgs)?;
            copy(paddr, copied..copied + count)?;
            copied += count;
            self.offset += count;
        }
        Ok(())
    }
}

struct Registers {
    status: u32,
    feature_select: u32,
    driver_feature_select: u32,
    driver_features: u64,
    queue_select: u32,
    queues: [Queue<QUEUE_SIZE>; NUM_QUEUES],
    notified: [bool; NUM_QUEUES],
    generation: u64,
    active: usize,
    resetting: bool,
    cancelled: bool,
    rx: VecDeque<Request>,
    tx: VecDeque<Request>,
    events: VecDeque<Request>,
    inbound: InboundQueue<QueuedPacket>,
    rx_is_next: bool,
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
    ) -> Option<Self> {
        Self::try_reserve(owner, admission, bytes).ok()
    }

    pub(super) fn try_reserve(
        owner: Arc<Kernelet>,
        admission: Arc<Admission>,
        bytes: usize,
    ) -> Result<Self> {
        let reservation = admission.reserve_endpoint_bytes(bytes)?;
        owner.charge_host_bytes(bytes)?;
        Ok(Self {
            owner,
            bytes,
            _admission: reservation,
        })
    }
}

impl Drop for PacketCharge {
    fn drop(&mut self) {
        self.owner.uncharge_host_bytes(self.bytes);
    }
}

pub(super) struct QueuedPacket {
    pub(super) packet: Packet,
    // Retain the full payload allocation and its single charge while receiving
    // successive prefixes. The slot stays active until the remainder is back.
    pub(super) payload_offset: usize,
    pub(super) charge: PacketCharge,
    pub(super) switch_ref: Option<SwitchRef>,
}

pub(super) enum EnqueueError {
    Full(Packet),
    Failed(Error),
}

/// The bounded receive queue keeps an in-flight packet's slot until any
/// remaining payload has been put back. All methods run under the device
/// register lock; the pollee reports space in this queue, not peer credit.
struct InboundQueue<T> {
    pending: VecDeque<T>,
    active: usize,
    space: Pollee,
}

impl<T> InboundQueue<T> {
    fn new() -> Self {
        Self {
            pending: VecDeque::with_capacity(MAX_INBOUND),
            active: 0,
            space: Pollee::new(),
        }
    }

    fn has_space(&self) -> bool {
        self.pending.len() + self.active < MAX_INBOUND
    }

    fn push(&mut self, packet: T) -> Result<(), T> {
        if !self.has_space() {
            return Err(packet);
        }
        self.pending.push_back(packet);
        if !self.has_space() {
            self.space.invalidate();
        }
        Ok(())
    }

    fn take(&mut self) -> Option<T> {
        let packet = self.pending.pop_front()?;
        self.active += 1;
        Some(packet)
    }

    fn finish(&mut self, remaining: Option<T>) {
        let was_full = !self.has_space();
        self.active -= 1;
        if let Some(remaining) = remaining {
            self.pending.push_front(remaining);
        }
        self.notify_space(was_full);
    }

    fn remove(&mut self, index: usize) -> Option<T> {
        let was_full = !self.has_space();
        let packet = self.pending.remove(index);
        self.notify_space(was_full);
        packet
    }

    fn clear(&mut self) -> VecDeque<T> {
        let was_full = !self.has_space();
        let pending = core::mem::take(&mut self.pending);
        self.notify_space(was_full);
        pending
    }

    fn notify_space(&self, was_full: bool) {
        if was_full && self.has_space() {
            self.space.notify(IoEvents::OUT);
        }
    }
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
            notified: [false; NUM_QUEUES],
            generation: 1,
            active: 0,
            resetting: false,
            cancelled: false,
            rx: VecDeque::with_capacity(QUEUE_SIZE),
            tx: VecDeque::with_capacity(QUEUE_SIZE),
            events: VecDeque::with_capacity(1),
            inbound: InboundQueue::new(),
            rx_is_next: false,
        }
    }

    fn reset(&mut self) -> VecDeque<QueuedPacket> {
        self.notified.fill(false);
        self.generation = self.generation.wrapping_add(1);
        self.rx.clear();
        self.tx.clear();
        self.events.clear();
        let pending = self.inbound.clear();
        self.rx_is_next = false;
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
    #[cfg(kernelet_host_connect_gate)]
    connect_gate_used: AtomicU32,
    #[cfg(kernelet_host_connect_gate)]
    connect_gate: SpinLock<Option<ConnectGate>>,
    #[cfg(kernelet_host_connect_gate)]
    connect_gate_changes: Arc<WaitQueue>,
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
    inbound_space: Pollee,
    worker_started: AtomicBool,
}

/// Retains the inbound slot while the worker copies a packet. A partial
/// packet replaces that slot; reset discards any remainder from the old
/// generation. Drop also releases the slot if the copy unwinds.
struct InboundReceive<'a> {
    device: &'a VirtioVsock,
    generation: u64,
    remaining: Option<QueuedPacket>,
}

impl Drop for InboundReceive<'_> {
    fn drop(&mut self) {
        let mut registers = self.device.registers.lock();
        let remaining = if registers.generation == self.generation && !registers.cancelled {
            self.remaining.take()
        } else {
            None
        };
        registers.inbound.finish(remaining);
        // Any rejected remainder's charges and peer references drop only
        // after this guard releases the device register lock.
    }
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
        let registers = Registers::new();
        let inbound_space = registers.inbound.space.clone();
        let device = Arc::new(Self {
            #[cfg(kernelet_host_connect_gate)]
            connect_gate_used: AtomicU32::new(0),
            #[cfg(kernelet_host_connect_gate)]
            connect_gate: SpinLock::new(None),
            #[cfg(kernelet_host_connect_gate)]
            connect_gate_changes: Arc::new(WaitQueue::new()),
            kernelet,
            admission,
            _reservation: reservation,
            memory,
            cid,
            irq,
            switch: switch.clone(),
            registers: SpinLock::new(registers),
            interrupt_status: AtomicU32::new(0),
            changes: WaitQueue::new(),
            inbound_space,
            worker_started: AtomicBool::new(false),
        });
        // CIDs are allocated monotonically by CREATE and must be unique.
        switch.register(cid, &device)?;
        Ok(device)
    }

    pub(super) fn start_worker(self: &Arc<Self>, execution: &super::scheduling::ExecutionThreads) {
        if self.worker_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let device = self.clone();
        execution.spawn_worker(move || device.worker());
    }

    pub(super) fn cancel(&self) {
        let pending = {
            let mut registers = self.registers.lock();
            registers.cancelled = true;
            registers.inbound.clear()
        };
        drop(pending);
        self.inbound_space.notify(IoEvents::ERR);
        self.changes.wake_all();
        #[cfg(kernelet_host_connect_gate)]
        self.connect_gate_changes.wake_all();
    }

    /// Called by the switch without holding its routing lock.
    pub(super) fn enqueue(&self, packet: Packet) -> bool {
        self.try_enqueue(packet).is_ok()
    }

    pub(super) fn try_enqueue(&self, packet: Packet) -> core::result::Result<(), EnqueueError> {
        self.try_enqueue_with_ref(packet, None)
            .map_err(|(error, _)| error)
    }

    /// Returns the original connection lease on failure, without cloning it.
    pub(super) fn enqueue_with_ref(
        &self,
        packet: Packet,
        switch_ref: Option<SwitchRef>,
    ) -> core::result::Result<(), (EnqueueError, Option<SwitchRef>)> {
        self.try_enqueue_with_ref(packet, switch_ref)
    }

    fn try_enqueue_with_ref(
        &self,
        packet: Packet,
        mut switch_ref: Option<SwitchRef>,
    ) -> core::result::Result<(), (EnqueueError, Option<SwitchRef>)> {
        let mut packet = packet;
        let charge = if let Some(charge) = packet.payload_charge.take() {
            // Guest TX charged its authenticated sender; Host TX charged the
            // endpoint's instance before creating this payload. Do not look up
            // a possibly retired sender or charge these bytes a second time.
            charge
        } else {
            if packet.payload.capacity() != 0 {
                return Err((
                    EnqueueError::Failed(Error::with_message(
                        Errno::EINVAL,
                        "vsock payload has no reservation",
                    )),
                    switch_ref,
                ));
            }
            let (owner, admission) = self.switch.charge_account(packet.src_cid, self);
            PacketCharge::try_reserve(owner, admission, size_of::<Packet>())
                .map_err(|error| (EnqueueError::Failed(error), switch_ref.take()))?
        };
        let mut queued = QueuedPacket {
            packet,
            payload_offset: 0,
            charge,
            switch_ref,
        };
        let mut registers = self.registers.lock();
        if registers.cancelled {
            drop(registers);
            let reference = queued.switch_ref.take();
            drop(queued);
            return Err((
                EnqueueError::Failed(Error::with_message(
                    Errno::ENODEV,
                    "kernelet vsock device cancelled",
                )),
                reference,
            ));
        }
        let queued = registers.inbound.push(queued);
        drop(registers);
        if let Err(mut queued) = queued {
            // Full returns a packet for retry. Payload memory must remain
            // charged for as long as that caller holds it. Empty control
            // packets retain the existing no-reservation-on-Full behavior.
            if queued.packet.payload.capacity() != 0 {
                queued.packet.payload_charge = Some(queued.charge);
            }
            return Err((EnqueueError::Full(queued.packet), queued.switch_ref));
        }
        self.changes.wake_all();
        #[cfg(kernelet_host_connect_gate)]
        self.connect_gate_changes.wake_all();
        Ok(())
    }

    /// Pollers subscribe directly to the destination queue's space changes;
    /// freeing a slot does not scan or broadcast to unrelated endpoints.
    pub(super) fn poll_inbound_space(&self, poller: Option<&mut PollHandle>) -> IoEvents {
        self.inbound_space.poll_with(IoEvents::OUT, poller, || {
            let registers = self.registers.lock();
            if registers.cancelled {
                IoEvents::ERR
            } else if registers.inbound.has_space() {
                IoEvents::OUT
            } else {
                IoEvents::empty()
            }
        })
    }

    pub(super) fn poll_cancelled(&self, poller: Option<&mut PollHandle>) -> IoEvents {
        if let Some(poller) = poller {
            self.inbound_space.register_poller(poller, IoEvents::ERR);
        }
        if self.registers.lock().cancelled {
            IoEvents::ERR
        } else {
            IoEvents::empty()
        }
    }

    #[cfg(ktest)]
    pub(super) fn take_inbound_for_ktest(&self) -> Option<Packet> {
        let queued = {
            let mut registers = self.registers.lock();
            let queued = registers.inbound.take()?;
            registers.inbound.finish(None);
            queued
        };
        // Use the production slot-release notification and dispose the
        // packet's charge after the register lock has been released.
        Some(queued.packet)
    }

    #[cfg(ktest)]
    pub(super) fn take_control_for_ktest(&self) -> Option<Packet> {
        self.take_control(&self.registers.lock())
    }

    fn take_control(&self, registers: &Registers) -> Option<Packet> {
        self.switch
            .take_host_control(self.cid, |host_port, peer_port| {
                // Do not publish newer credit ahead of an older header on the
                // same stream. Other streams cannot consume its reserved state.
                registers.inbound.pending.iter().any(|queued| {
                    queued.packet.src_cid == 2
                        && queued.packet.src_port == host_port
                        && queued.packet.dst_port == peer_port
                })
            })
    }

    pub(super) fn account_owner(&self) -> Arc<Kernelet> {
        self.kernelet.clone()
    }

    pub(super) fn account_admission(&self) -> Arc<Admission> {
        self.admission.clone()
    }

    pub(super) fn wake_notice(&self) {
        self.changes.wake_all();
        #[cfg(kernelet_host_connect_gate)]
        self.connect_gate_changes.wake_all();
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
                registers.notified[index] = true;
                self.changes.wake_all();
                #[cfg(kernelet_host_connect_gate)]
                self.connect_gate_changes.wake_all();
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
                    #[cfg(kernelet_host_connect_gate)]
                    self.connect_gate_changes.wake_all();
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
        super::virtio_mmio::layout_valid(
            &self.memory,
            queue.num,
            max,
            queue.desc,
            queue.avail,
            queue.used,
        )
    }

    fn collect_requests(&self, registers: &mut Registers, index: usize) {
        registers.notified[index] = false;
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
        let mut budget = 1;
        while budget != 0 && registers.queues[index].last_avail != avail_idx {
            budget -= 1;
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
        registers.notified[index] = registers.queues[index].last_avail != avail_idx
            && registers.status & DEVICE_NEEDS_RESET == 0;
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
            let buffer = Buffer::decode(bytes);
            let next_capacity = request.capacity.checked_add(buffer.len as usize)?;
            if !buffer.supported()
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
            // This adopted worker processes one bounded packet/header per
            // iteration. Throttle before claiming a request or taking locks.
            #[cfg(kernelet_host_connect_gate)]
            self.hold_connect_request();
            if self.changes.wait_until(|| self.take_work()) {
                break;
            }
        }
        self.kernelet.disown_current_task();
    }

    /// Returns `None` to block, `Some(false)` for progress, `Some(true)` to exit.
    fn collect_notified(&self) -> bool {
        let mut registers = self.registers.lock();
        if registers.cancelled || registers.resetting || registers.status & DEVICE_NEEDS_RESET != 0
        {
            return false;
        }
        let mut progressed = false;
        for index in 0..NUM_QUEUES {
            if !registers.notified[index] {
                continue;
            }
            let before = registers.queues[index].last_avail;
            self.collect_requests(&mut registers, index);
            progressed = registers.queues[index].last_avail != before;
            if progressed || registers.status & DEVICE_NEEDS_RESET != 0 {
                break;
            }
        }
        drop(registers);
        if progressed && ostd::task::Task::need_yield() {
            ostd::task::Task::yield_now();
        }
        progressed
    }

    fn take_work(&self) -> Option<bool> {
        if self.collect_notified() {
            return Some(false);
        }
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
            let remaining = self.receive(request, notice);
            // Switch notices are header-only reset packets.
            debug_assert!(remaining.is_none());
            return Some(false);
        }
        if !registers.rx.is_empty()
            && let Some(control) = self.take_control(&registers)
        {
            let request = registers.rx.pop_front().unwrap();
            registers.active += 1;
            drop(registers);
            self.publish_packet(request, &control, 0..0, None);
            return Some(false);
        }
        if let Some(index) = registers.inbound.pending.iter().position(|queued| {
            !self
                .switch
                .delivery_live(&queued.packet, queued.switch_ref.as_ref())
        }) {
            let retired = registers.inbound.remove(index);
            drop(registers);
            drop(retired);
            return Some(false);
        }
        let can_rx = !registers.rx.is_empty() && !registers.inbound.pending.is_empty();
        if can_rx && (registers.rx_is_next || registers.tx.is_empty()) {
            #[cfg(kernelet_host_connect_gate)]
            if self.prepare_connect_gate(&registers) {
                return Some(false);
            }
            let request = registers.rx.pop_front().unwrap();
            let packet = registers.inbound.take().unwrap();
            let generation = request.generation;
            registers.active += 1;
            registers.rx_is_next = false;
            drop(registers);
            let mut inbound = InboundReceive {
                device: self,
                generation,
                remaining: None,
            };
            inbound.remaining = self.receive(request, packet);
            return Some(false);
        }
        if let Some(request) = registers.tx.pop_front() {
            registers.active += 1;
            registers.rx_is_next = true;
            drop(registers);
            self.transmit(request);
            return Some(false);
        }
        None
    }

    #[cfg(kernelet_host_connect_gate)]
    fn prepare_connect_gate(&self, registers: &Registers) -> bool {
        let packet = &registers.inbound.pending.front().unwrap().packet;
        if packet.src_cid != 2 || packet.dst_cid != self.cid || packet.op != Packet::REQUEST {
            return false;
        }
        let (bit, delay_ms) = match packet.dst_port {
            19003 => (1, 3000),
            19004 => (2, 5000),
            _ => return false,
        };
        let Some(identity) = self
            .switch
            .connect_gate_identity(self.cid, packet.src_port, self)
        else {
            return false;
        };
        if self.connect_gate_used.fetch_or(bit, Ordering::AcqRel) & bit != 0 {
            return false;
        }
        *self.connect_gate.lock() = Some(ConnectGate {
            identity,
            generation: registers.generation,
            host_port: packet.src_port,
            peer_port: packet.dst_port,
            delay_ms,
        });
        // The worker returns to its outer loop before parking: neither the
        // Guest RX descriptor nor inbound packet has been taken or copied.
        true
    }

    #[cfg(kernelet_host_connect_gate)]
    fn hold_connect_request(&self) {
        use core::time::Duration;

        use crate::{process::signal::PollAdaptor, time::wait::WaitTimeout};
        let gate = self.connect_gate.lock().take();
        let Some(gate) = gate else { return };
        let changes = self.connect_gate_changes.clone();
        let mut observer = PollAdaptor::with_observer(ConnectGateWake(changes.clone()));
        let subscribed = self
            .switch
            .poll_connect_gate_cancelled(&gate.identity, Some(observer.as_handle_mut()));
        let start = aster_time::read_monotonic_time();
        ostd::early_println!(
            "HOST_CONNECT_GATE_BEGIN cid={} host_port={} peer_port={} generation={} delay_ms={} rx_ready_at_arm=true before_take=true",
            self.cid,
            gate.host_port,
            gate.peer_port,
            gate.generation,
            gate.delay_ms
        );
        let result = changes.wait_until_or_timeout(
            || {
                let local_live = {
                    let registers = self.registers.lock();
                    !registers.cancelled
                        && registers.generation == gate.generation
                        && registers.inbound.pending.front().is_some_and(|queued| {
                            queued.packet.src_cid == 2
                                && queued.packet.src_port == gate.host_port
                                && queued.packet.dst_cid == self.cid
                                && queued.packet.dst_port == gate.peer_port
                                && queued.packet.op == Packet::REQUEST
                        })
                };
                let cancelled = subscribed.contains(IoEvents::ERR)
                    || self
                        .switch
                        .poll_connect_gate_cancelled(&gate.identity, None)
                        .contains(IoEvents::ERR);
                (!local_live || cancelled).then_some(())
            },
            &Duration::from_millis(gate.delay_ms),
        );
        let elapsed = aster_time::read_monotonic_time().saturating_sub(start);
        let reason = match &result {
            Ok(()) => "cancel_or_identity_change",
            Err(error) if error.error() == Errno::ETIME => "hold_timeout",
            Err(_) => "hold_error",
        };
        ostd::early_println!(
            "HOST_CONNECT_GATE_END cid={} host_port={} peer_port={} generation={} elapsed_ns={} reason={} result={:?}",
            self.cid,
            gate.host_port,
            gate.peer_port,
            gate.generation,
            elapsed.as_nanos(),
            reason,
            result
        );
    }

    fn transmit(&self, request: Request) {
        let mut cursor = BufferCursor::new(&request.buffers[..request.len]);
        let header = Packet::read_header_from(request.capacity, |bytes| {
            cursor.copy(bytes.len(), |paddr, range| {
                self.read_packet_guest(paddr, &mut bytes[range])
            })
        });
        let Ok(Some((mut packet, payload_len))) = header else {
            self.registers.lock().status |= DEVICE_NEEDS_RESET;
            self.complete(TX, request, 0);
            return;
        };
        if packet
            .prepare_payload(payload_len, self.kernelet.clone(), self.admission.clone())
            .is_err()
        {
            // Resource rejection is a stream reset, not a malformed virtqueue.
            // Use the authenticated CID even though the header is untrusted.
            self.switch.reject_packet(self.cid, &packet);
            drop(packet);
            self.complete(TX, request, 0);
            return;
        }
        if cursor
            .copy(payload_len, |paddr, range| {
                self.read_packet_guest(paddr, &mut packet.payload[range])
            })
            .is_err()
        {
            self.registers.lock().status |= DEVICE_NEEDS_RESET;
            drop(packet);
            self.complete(TX, request, 0);
            return;
        }
        self.switch.route(self.cid, packet);
        self.complete(TX, request, 0);
    }

    fn receive(&self, request: Request, mut queued: QueuedPacket) -> Option<QueuedPacket> {
        let packet = &queued.packet;
        if !self
            .switch
            .delivery_live(packet, queued.switch_ref.as_ref())
        {
            self.repark_receive(request);
            return None;
        }
        let remaining = packet.payload.len() - queued.payload_offset;
        let count = remaining.min(request.capacity.saturating_sub(Packet::HEADER_LEN));
        if request.capacity < Packet::HEADER_LEN + remaining
            && (packet.op != Packet::RW || request.capacity <= Packet::HEADER_LEN)
        {
            self.registers.lock().status |= DEVICE_NEEDS_RESET;
            self.complete(RX, request, 0);
            return None;
        }
        let end = queued.payload_offset + count;
        if self.publish_packet(
            request,
            packet,
            queued.payload_offset..end,
            queued.switch_ref.as_ref(),
        ) && end < packet.payload.len()
        {
            queued.payload_offset = end;
            Some(queued)
        } else {
            None
        }
    }

    fn publish_packet(
        &self,
        request: Request,
        packet: &Packet,
        range: core::ops::Range<usize>,
        reference: Option<&SwitchRef>,
    ) -> bool {
        if !self.switch.delivery_live(packet, reference) {
            self.repark_receive(request);
            return false;
        }
        if request.capacity < Packet::HEADER_LEN + range.len() {
            self.registers.lock().status |= DEVICE_NEEDS_RESET;
            self.complete(RX, request, 0);
            return false;
        }
        // Ingress category: only the actual copy, not waits or liveness checks.
        let span = ChargedSpan::new(&self.kernelet, WorkCategory::Ingress);
        let mut cursor = BufferCursor::new(&request.buffers[..request.len]);
        let copied = packet.write_range_to(range, |bytes| {
            cursor.copy(bytes.len(), |paddr, range| {
                self.write_packet_guest(paddr, &bytes[range])
            })
        });
        drop(span);
        let Ok(Some(len)) = copied else {
            self.registers.lock().status |= DEVICE_NEEDS_RESET;
            self.complete(RX, request, 0);
            return false;
        };
        if !self.switch.delivery_live(packet, reference) {
            self.repark_receive(request);
            return false;
        }
        self.complete(RX, request, len as u32);
        true
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
        let mut entry = [0u8; 8];
        entry[..4].copy_from_slice(&(request.head as u32).to_le_bytes());
        entry[4..].copy_from_slice(&used_len.to_le_bytes());
        let _ = self.write_guest(used_entry, &entry);
        queue.next_used = queue.next_used.wrapping_add(1);
        fence(Ordering::Release);
        let _ = self
            .memory
            .write_u16_once(queue.used + 2, queue.next_used.to_le());
        self.interrupt_status.fetch_or(1, Ordering::Release);
        drop(registers);
        let _ = self.kernelet.raise_irq(self.irq);
        drop(span);
    }

    fn read_u16(&self, paddr: u64) -> ostd::Result<u16> {
        let value = self.memory.read_u16_once(paddr)?;
        fence(Ordering::Acquire);
        Ok(u16::from_le(value))
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

    fn read_packet_guest(&self, paddr: u64, dst: &mut [u8]) -> ostd::Result<()> {
        self.memory.with_reader(paddr, dst.len(), |reader| {
            let mut writer = VmWriter::from(dst).to_fallible();
            #[cfg(all(kernelet_rq1_diagnostics, not(feature = "kernelet")))]
            let copied = super::io_copy_profile::measure_fallible(
                super::io_copy_profile::Category::VsockTx,
                writer.avail(),
                || reader.read_fallible(&mut writer),
            );
            #[cfg(not(all(kernelet_rq1_diagnostics, not(feature = "kernelet"))))]
            let copied = reader.read_fallible(&mut writer);
            copied.map_err(|(error, _)| error)
        })??;
        Ok(())
    }

    fn write_packet_guest(&self, paddr: u64, src: &[u8]) -> ostd::Result<()> {
        self.memory.with_writer(paddr, src.len(), |writer| {
            let mut reader = VmReader::from(src).to_fallible();
            #[cfg(all(kernelet_rq1_diagnostics, not(feature = "kernelet")))]
            let copied = super::io_copy_profile::measure_fallible(
                super::io_copy_profile::Category::VsockRx,
                reader.remain(),
                || reader.read_fallible(writer),
            );
            #[cfg(not(all(kernelet_rq1_diagnostics, not(feature = "kernelet"))))]
            let copied = reader.read_fallible(writer);
            copied.map_err(|(error, _)| error)
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
mod tests {
    use core::sync::atomic::AtomicUsize;

    use ostd::prelude::*;

    use super::*;
    use crate::{events::Observer, process::signal::PollAdaptor};

    struct WriteNotifications(Arc<AtomicUsize>);

    impl Observer<IoEvents> for WriteNotifications {
        fn on_events(&self, events: &IoEvents) {
            assert!(events.contains(IoEvents::OUT));
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn writer_observer() -> (Arc<AtomicUsize>, PollAdaptor<WriteNotifications>) {
        let notifications = Arc::new(AtomicUsize::new(0));
        let writer = PollAdaptor::with_observer(WriteNotifications(notifications.clone()));
        (notifications, writer)
    }

    fn poll_space(
        queue: &SpinLock<InboundQueue<usize>>,
        poller: Option<&mut PollHandle>,
    ) -> IoEvents {
        let space = queue.lock().space.clone();
        space.poll_with(IoEvents::OUT, poller, || {
            if queue.lock().has_space() {
                IoEvents::OUT
            } else {
                IoEvents::empty()
            }
        })
    }

    fn fill(queue: &SpinLock<InboundQueue<usize>>) {
        let mut queue = queue.lock();
        for packet in 0..MAX_INBOUND {
            queue.push(packet).unwrap();
        }
    }

    #[ktest]
    fn vsock_writer_wakes_when_full_queue_gains_space() {
        // Regression: freeing inbound space never notified Host OUT waiters.
        let queue = SpinLock::new(InboundQueue::new());
        // Cache the initial writable state before filling the queue.
        assert_eq!(poll_space(&queue, None), IoEvents::OUT);
        fill(&queue);
        let (notifications, mut writer) = writer_observer();
        assert!(poll_space(&queue, Some(writer.as_handle_mut())).is_empty());
        assert_eq!(queue.lock().take(), Some(0));
        // The worker can still split this packet, so its slot is retained.
        assert!(queue.lock().push(MAX_INBOUND).is_err());
        assert!(poll_space(&queue, None).is_empty());
        queue.lock().finish(None);
        assert_eq!(notifications.load(Ordering::Relaxed), 1);
        assert_eq!(poll_space(&queue, None), IoEvents::OUT);
        queue.lock().push(MAX_INBOUND).unwrap();
        assert!(poll_space(&queue, None).is_empty());
    }

    #[ktest]
    fn vsock_partial_receive_keeps_its_queue_slot() {
        let queue = SpinLock::new(InboundQueue::new());
        fill(&queue);
        let (notifications, mut writer) = writer_observer();
        assert!(poll_space(&queue, Some(writer.as_handle_mut())).is_empty());
        let packet = queue.lock().take();
        queue.lock().finish(packet);
        assert!(poll_space(&queue, None).is_empty());
        assert_eq!(notifications.load(Ordering::Relaxed), 0);
        assert_eq!(queue.lock().take(), Some(0));
        queue.lock().finish(None);
        assert_eq!(notifications.load(Ordering::Relaxed), 1);
        assert_eq!(poll_space(&queue, None), IoEvents::OUT);
    }

    #[ktest]
    fn vsock_space_recovered_before_poll_is_observed() {
        let queue = SpinLock::new(InboundQueue::new());
        fill(&queue);
        assert!(poll_space(&queue, None).is_empty());
        queue.lock().take().unwrap();
        queue.lock().finish(None);
        let (_, mut writer) = writer_observer();
        assert_eq!(
            poll_space(&queue, Some(writer.as_handle_mut())),
            IoEvents::OUT
        );
    }

    #[ktest]
    fn vsock_space_recovery_during_poll_is_not_lost() {
        let queue = SpinLock::new(InboundQueue::new());
        fill(&queue);
        let space = queue.lock().space.clone();
        let (notifications, mut writer) = writer_observer();
        // Force recovery after readiness was read but before poll caches it.
        let events = space.poll_with(IoEvents::OUT, Some(writer.as_handle_mut()), || {
            assert!(!queue.lock().has_space());
            queue.lock().take().unwrap();
            queue.lock().finish(None);
            IoEvents::empty()
        });
        assert!(events.is_empty());
        assert_eq!(notifications.load(Ordering::Relaxed), 1);
        assert_eq!(poll_space(&queue, None), IoEvents::OUT);
    }

    #[ktest]
    fn vsock_discarded_packets_release_queue_space() {
        let queue = SpinLock::new(InboundQueue::new());
        fill(&queue);
        let (notifications, mut writer) = writer_observer();
        assert!(poll_space(&queue, Some(writer.as_handle_mut())).is_empty());
        assert_eq!(queue.lock().remove(0), Some(0));
        assert_eq!(notifications.load(Ordering::Relaxed), 1);
        queue.lock().push(MAX_INBOUND).unwrap();
        queue.lock().take().unwrap();
        // Reset drops queued packets but the old in-flight slot is live.
        assert_eq!(queue.lock().clear().len(), MAX_INBOUND - 1);
        for packet in 0..MAX_INBOUND - 1 {
            queue.lock().push(packet).unwrap();
        }
        assert!(queue.lock().push(MAX_INBOUND).is_err());
        assert!(poll_space(&queue, None).is_empty());
        queue.lock().finish(None);
        assert_eq!(notifications.load(Ordering::Relaxed), 3);
        assert_eq!(poll_space(&queue, None), IoEvents::OUT);
    }

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
