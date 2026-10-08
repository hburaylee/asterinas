// SPDX-License-Identifier: MPL-2.0

//! A bounded virtio MMIO console register file and endpoint-backed worker.
//!
//! The device implements the console device of VirtIO 1.3 §5.3 (device ID
//! 3) over the common MMIO register file of §4.2.2: one receiveq0 and one
//! transmitq0 (§5.3.2), no feature bits beyond `VIRTIO_F_VERSION_1` (§5.3.3,
//! §6). The configuration layout follows §5.3.4; size, multiport and
//! emergency-write features are not offered.
//! See <https://docs.oasis-open.org/virtio/virtio/v1.3/virtio-v1.3.html>.
//!
//! The guest drives this device with the kernel proper's own virtio console
//! driver: queue 0 parks one device-writable receive buffer, and queue 1
//! offers device-readable transmit buffers. The notify hook validates
//! descriptor chains into a preallocated inbox only; the worker thread moves
//! the bytes between guest memory and the [`ConsoleEndpoint`] and publishes
//! completions through the used ring.

use alloc::{collections::VecDeque, sync::Arc};
use core::sync::atomic::{AtomicU32, Ordering, fence};

use ostd::{
    kernelet::{
        abi::{INVALID, MmioResult},
        control::Kernelet,
        guest_memory::GuestMemory,
    },
    sync::SpinLock,
};

use super::{
    io_accounting::{ChargedSpan, WorkCategory},
    virtio_mmio::{
        CONFIG_OFFSET, Queue, ReadyWrite, feature_word, invalid_read, write_driver_feature_word,
    },
};
use crate::thread::kernel_thread::ThreadOptions;

mod endpoint;

pub(super) use endpoint::{ConsoleEndpoint, EndpointFile};

/// Maximum descriptors per queue, as the tree's console driver requests.
const QUEUE_SIZE: usize = 2;
/// Receiveq0 plus transmitq0; a larger `queue_select` reads `queue_num_max` 0.
const NUM_QUEUES: usize = 2;
const QUEUE_RX: usize = 0;
const QUEUE_TX: usize = 1;
/// Inbox slots, preallocated at attach so the notify hook never allocates.
const INBOX_SLOTS: usize = QUEUE_SIZE * NUM_QUEUES;
/// Bound on the bytes one descriptor chain may describe.
const MAX_CHAIN_BYTES: usize = 64 * 1024;
/// Host bounce buffer for one endpoint move.
const CHUNK_BYTES: usize = 128;
const MAGIC: u32 = 0x7472_6976;
const VERSION: u32 = 2;
const DEVICE_ID_CONSOLE: u32 = 3;
const VENDOR: u32 = 0x1af4;
const FEATURE_VERSION_1: u64 = 1 << 32;
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

    fn readable(self) -> bool {
        self.flags & 2 == 0
    }

    fn has_next(self) -> bool {
        self.flags & 1 != 0
    }
}

/// One validated descriptor chain waiting in the inbox.
struct Request {
    queue: usize,
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
    queues: [Queue<QUEUE_SIZE>; NUM_QUEUES],
    /// Bumps on every reset; a request only touches its own generation.
    generation: u64,
    /// Requests held by the worker, each through one reset drain reference.
    active: usize,
    /// A reset that waits for the active requests to drain.
    resetting: bool,
    /// Set by `cancel`; the worker abandons everything and exits.
    cancelled: bool,
    /// A transmit chain stalled on endpoint output room, held by the worker
    /// as `(request, buffer index, buffer offset)`. It keeps its active
    /// reference across reset, so reset must not clear it.
    suspended: Option<(Request, usize, usize)>,
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
            suspended: None,
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

    /// Ends a pending reset once the last active request has retired.
    fn finish_reset_if_last(&mut self) {
        if self.resetting && self.active == 0 {
            self.resetting = false;
            self.status = 0;
        }
    }
}

/// One unit of worker progress.
enum Work {
    /// The device is cancelled: the worker must exit.
    Cancel,
    /// Bounded work was done; look for more before blocking again.
    Progress,
}

/// One attached virtio console device. Its hook never touches the endpoint.
pub(super) struct VirtioConsole {
    kernelet: Arc<Kernelet>,
    memory: GuestMemory,
    endpoint: Arc<ConsoleEndpoint>,
    irq: u8,
    registers: SpinLock<Registers>,
    interrupt_status: AtomicU32,
}

impl VirtioConsole {
    pub(super) fn new(
        kernelet: Arc<Kernelet>,
        endpoint: Arc<ConsoleEndpoint>,
        irq: u8,
    ) -> Arc<Self> {
        Arc::new(Self {
            memory: kernelet.guest_memory(),
            kernelet,
            endpoint,
            irq,
            registers: SpinLock::new(Registers::new()),
            interrupt_status: AtomicU32::new(0),
        })
    }

    pub(super) fn start_worker(self: &Arc<Self>) {
        let device = self.clone();
        ThreadOptions::new(move || device.worker()).spawn();
    }

    /// Asks the worker to abandon its work and exit, waking it if parked.
    pub(super) fn cancel(&self) {
        self.registers.lock().cancelled = true;
        self.endpoint.changes().wake_all();
    }

    pub(super) fn read(&self, offset: u32, width: u32) -> MmioResult {
        let registers = self.registers.lock();
        let value = if offset >= CONFIG_OFFSET {
            self.read_config(offset - CONFIG_OFFSET, width)
        } else if width == 4 {
            let value = match offset {
                0x00 => MAGIC,
                0x04 => VERSION,
                0x08 => DEVICE_ID_CONSOLE,
                0x0c => VENDOR,
                0x10 => feature_word(FEATURE_VERSION_1, registers.device_features_select),
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
                // The worker blocks on the endpoint's change queue alone; the
                // hook wakes it for the inbox work recorded above, so one
                // wait covers every wakeup source.
                self.endpoint.changes().wake_all();
            }
            0x64 => {
                self.interrupt_status.fetch_and(!value, Ordering::AcqRel);
            }
            0x70 => {
                if value == 0 {
                    registers.reset();
                    self.interrupt_status.store(0, Ordering::Release);
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

    fn read_config(&self, offset: u32, width: u32) -> Option<u64> {
        let mut bytes = [0u8; CONFIG_OFFSET as usize];
        // `VIRTIO_CONSOLE_F_SIZE` is not offered, so cols and rows are zero.
        // One port; emerg_wr is not offered and stays zero.
        bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
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
            let last_avail = r.queues[index].last_avail;
            let slot = last_avail as u32 % num;
            let Some(head_addr) = avail.checked_add(4 + slot as u64 * 2) else {
                r.status |= DEVICE_NEEDS_RESET;
                return;
            };
            let Ok(head) = self.read_u16(head_addr) else {
                r.status |= DEVICE_NEEDS_RESET;
                return;
            };
            let acceptable = r.queues[index].head_acceptable(head);
            if acceptable && let Some(request) = self.collect_chain(r, index, head) {
                r.queues[index].mark_accepted(head);
                r.inbox.push_back(request);
            } else {
                r.status |= DEVICE_NEEDS_RESET;
            }
            r.queues[index].last_avail = last_avail.wrapping_add(1);
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
        };
        let mut index = head;
        let mut total_bytes = 0usize;
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
            if buffer.flags & 4 != 0 || !self.memory.contains(buffer.paddr, buffer.len as usize) {
                return None;
            }
            total_bytes = total_bytes.checked_add(buffer.len as usize)?;
            if total_bytes > MAX_CHAIN_BYTES {
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

    fn worker(&self) {
        if self.kernelet.adopt_current_task().is_err() {
            return;
        }
        // The endpoint's change queue is the single blocking point: it
        // signals endpoint input and output room, and the hook wakes it for
        // inbox work and cancellation, so one wait covers every wakeup
        // source without busy spinning.
        let changes = self.endpoint.changes();
        loop {
            match changes.wait_until(|| self.take_work()) {
                Work::Cancel => break,
                Work::Progress => {}
            }
        }
        self.kernelet.disown_current_task();
    }

    /// Performs one bounded unit of work, or `None` when the device must
    /// block. Endpoint moves happen without the device lock held.
    fn take_work(&self) -> Option<Work> {
        let mut registers = self.registers.lock();
        if registers.cancelled {
            return Some(Work::Cancel);
        }
        if let Some((request, index, offset)) = registers.suspended.take() {
            drop(registers);
            return self
                .transmit(request, index, offset)
                .then_some(Work::Progress);
        }
        if let Some(slot) = registers
            .inbox
            .iter()
            .position(|request| request.queue == QUEUE_TX)
        {
            let request = registers.inbox.remove(slot).unwrap();
            registers.active += 1;
            drop(registers);
            return self.transmit(request, 0, 0).then_some(Work::Progress);
        }
        if let Some(slot) = registers
            .inbox
            .iter()
            .position(|request| request.queue == QUEUE_RX)
        {
            let request = registers.inbox.remove(slot).unwrap();
            registers.active += 1;
            drop(registers);
            return self.receive(request).then_some(Work::Progress);
        }
        None
    }

    /// Pushes a transmit chain's readable bytes into the endpoint until the
    /// chain is consumed or the endpoint runs out of room. A stalled chain
    /// is parked in the registers for a later pass. Returns whether any byte
    /// moved.
    fn transmit(&self, request: Request, mut index: usize, mut offset: usize) -> bool {
        let mut chunk = [0u8; CHUNK_BYTES];
        let mut progressed = false;
        while index < request.len {
            let buffer = request.buffers[index];
            if !buffer.readable() {
                index += 1;
                offset = 0;
                continue;
            }
            let len = buffer.len as usize;
            let count = (len - offset).min(chunk.len());
            if self
                .memory
                .read(buffer.paddr + offset as u64, &mut chunk[..count])
                .is_err()
            {
                // Cannot happen for a chain the hook validated; fail safely.
                self.registers.lock().status |= DEVICE_NEEDS_RESET;
                self.complete(request, 0);
                return progressed;
            }
            let pushed = self.endpoint.push_output(&chunk[..count]);
            progressed |= pushed > 0;
            offset += pushed;
            if pushed < count {
                self.registers.lock().suspended = Some((request, index, offset));
                return progressed;
            }
            if offset == len {
                index += 1;
                offset = 0;
            }
        }
        // The used length counts bytes written into device-writable buffers.
        // A transmit chain only contains bytes read by the device.
        self.complete(request, 0);
        true
    }

    /// Writes pending endpoint input into a parked receive chain's writable
    /// buffers and completes it. Returns false when the endpoint had no
    /// input, re-parking the chain for a later pass.
    fn receive(&self, request: Request) -> bool {
        let mut chunk = [0u8; CHUNK_BYTES];
        let mut total = 0usize;
        // Ingress category: the receiving instance pays for moving the
        // endpoint's input into its guest receive buffers.
        let span = ChargedSpan::new(&self.kernelet, WorkCategory::Ingress);
        for slot in 0..request.len {
            let buffer = request.buffers[slot];
            if !buffer.writable() {
                continue;
            }
            let len = buffer.len as usize;
            let mut done = 0usize;
            while done < len {
                let count = (len - done).min(chunk.len());
                let popped = self.endpoint.pop_input(&mut chunk[..count]);
                if popped == 0 {
                    break;
                }
                if self
                    .memory
                    .write(buffer.paddr + done as u64, &chunk[..popped])
                    .is_err()
                {
                    break;
                }
                done += popped;
                total += popped;
            }
            if done < len {
                break;
            }
        }
        drop(span);
        if total == 0 {
            let mut registers = self.registers.lock();
            registers.active -= 1;
            if request.generation != registers.generation {
                registers.finish_reset_if_last();
                return false;
            }
            registers.inbox.push_front(request);
            return false;
        }
        self.complete(request, total as u32);
        true
    }

    fn complete(&self, request: Request, used_len: u32) {
        let mut registers = self.registers.lock();
        registers.active -= 1;
        if request.generation != registers.generation {
            registers.finish_reset_if_last();
            return;
        }
        // Completion category: publishing the used-ring entry and its IRQ,
        // charged to this device's owning instance.
        let span = ChargedSpan::new(&self.kernelet, WorkCategory::Completion);
        let queue = &mut registers.queues[request.queue];
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
        drop(registers);
        let _ = self.kernelet.raise_irq(self.irq);
        drop(span);
    }

    fn read_u16(&self, paddr: u64) -> ostd::Result<u16> {
        let mut bytes = [0u8; 2];
        self.memory.read(paddr, &mut bytes)?;
        Ok(u16::from_le_bytes(bytes))
    }
}

#[cfg(ktest)]
mod reset_tests {
    use ostd::prelude::*;

    use super::{DEVICE_NEEDS_RESET, QUEUE_SIZE, Registers};

    #[ktest]
    fn virtio_console_reset_waits_for_active_requests() {
        let mut registers = Registers::new();
        registers.status = DEVICE_NEEDS_RESET;
        registers.queues[0].set_num(QUEUE_SIZE as u32);
        registers.queues[0].set_ready(1, true);
        registers.queues[0].mark_accepted(0);
        registers.active = 1;
        let generation = registers.generation;
        registers.reset();
        assert_ne!(registers.generation, generation);
        assert!(registers.resetting);
        assert_eq!(registers.status, DEVICE_NEEDS_RESET);
        assert!(!registers.queues[0].ready);
        assert!(registers.queues[0].pending.iter().all(|pending| !pending));
        registers.finish_reset_if_last();
        assert!(registers.resetting);
        registers.active -= 1;
        registers.finish_reset_if_last();
        assert!(!registers.resetting);
        assert_eq!(registers.status, 0);
    }
}
