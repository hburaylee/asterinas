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
//! offers device-readable transmit buffers. The notify hook records a doorbell;
//! the worker validates chains into a preallocated inbox and moves
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

type Buffer = super::virtio_mmio::Descriptor;

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
    notified: [bool; NUM_QUEUES],
    /// Bumps on every reset; a request only touches its own generation.
    generation: u64,
    /// Requests held by the worker, each through one reset drain reference.
    active: usize,
    /// A reset that waits for the active requests to drain.
    resetting: bool,
    /// Set by `cancel`; the worker abandons everything and exits.
    cancelled: bool,
    /// A transmit chain stalled on endpoint output room, held by the worker
    /// as `(request, buffer index, buffer offset)`. Reset retires its active
    /// reference without waiting for endpoint output room.
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
            notified: [false; NUM_QUEUES],
            generation: 1,
            active: 0,
            resetting: false,
            cancelled: false,
            suspended: None,
            inbox: VecDeque::with_capacity(INBOX_SLOTS),
        }
    }

    fn reset(&mut self) {
        self.notified.fill(false);
        self.generation = self.generation.wrapping_add(1);
        self.inbox.clear();
        if self.suspended.take().is_some() {
            self.active -= 1;
        }
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

    fn take_transmit(&mut self) -> Option<(Request, usize, usize)> {
        if let Some(suspended) = self.suspended.take() {
            return Some(suspended);
        }
        let slot = self
            .inbox
            .iter()
            .position(|request| request.queue == QUEUE_TX)?;
        let request = self.inbox.remove(slot).unwrap();
        self.active += 1;
        Some((request, 0, 0))
    }

    fn take_receive(&mut self) -> Option<Request> {
        let slot = self
            .inbox
            .iter()
            .position(|request| request.queue == QUEUE_RX)?;
        let request = self.inbox.remove(slot).unwrap();
        self.active += 1;
        Some(request)
    }

    /// Retires stale work instead of parking it across reset or cancellation.
    fn suspend_transmit(&mut self, request: Request, index: usize, offset: usize) -> bool {
        if request.generation != self.generation || self.cancelled {
            self.active -= 1;
            self.finish_reset_if_last();
            return false;
        }
        self.suspended = Some((request, index, offset));
        true
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

/// Dispatches both queues before blocking. The byte movers run without the
/// register lock and report whether they made progress or retired a request.
fn poll_queues(
    registers: &SpinLock<Registers>,
    transmit: impl FnOnce(Request, usize, usize) -> bool,
    receive: impl FnOnce(Request) -> bool,
) -> Option<Work> {
    let mut registers = registers.lock();
    if registers.cancelled {
        return Some(Work::Cancel);
    }
    // Both directions get a turn, including when transmit parks again
    // without moving a byte. Neither endpoint queue depends on the other.
    let tx = registers.take_transmit();
    let rx = registers.take_receive();
    drop(registers);
    let mut progressed = false;
    if let Some((request, index, offset)) = tx {
        progressed |= transmit(request, index, offset);
    }
    if let Some(request) = rx {
        progressed |= receive(request);
    }
    progressed.then_some(Work::Progress)
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

    pub(super) fn start_worker(self: &Arc<Self>, execution: &super::scheduling::ExecutionThreads) {
        let device = self.clone();
        execution.spawn_worker(move || device.worker());
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
                registers.notified[index] = true;
                // The worker blocks on the endpoint's change queue alone; the
                // hook wakes it for the doorbell recorded above, so one
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
                    self.endpoint.changes().wake_all();
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
        super::virtio_mmio::layout_valid(
            &self.memory,
            queue.num,
            QUEUE_SIZE,
            queue.desc,
            queue.avail,
            queue.used,
        )
    }

    fn collect_requests(&self, r: &mut Registers, index: usize) {
        r.notified[index] = false;
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
        let mut budget = 1;
        while budget != 0 && r.queues[index].last_avail != avail_idx && r.inbox.len() < INBOX_SLOTS
        {
            budget -= 1;
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
        r.notified[index] =
            r.queues[index].last_avail != avail_idx && r.status & DEVICE_NEEDS_RESET == 0;
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
            let buffer = Buffer::decode(bytes);
            if !buffer.supported() || !self.memory.contains(buffer.paddr, buffer.len as usize) {
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

    fn take_work(&self) -> Option<Work> {
        if self.collect_notified() {
            return Some(Work::Progress);
        }
        poll_queues(
            &self.registers,
            |request, index, offset| self.transmit(request, index, offset),
            |request| self.receive(request),
        )
    }

    /// Pushes a transmit chain's readable bytes into the endpoint until the
    /// chain is consumed or the endpoint runs out of room. A stalled chain
    /// is parked in the registers for a later pass. Returns whether any byte
    /// moved or a request retired.
    fn transmit(&self, request: Request, mut index: usize, mut offset: usize) -> bool {
        let mut chunk = [0u8; CHUNK_BYTES];
        let mut progressed = false;
        while index < request.len {
            let registers = self.registers.lock();
            if request.generation != registers.generation || registers.cancelled {
                drop(registers);
                self.complete(request, 0);
                return true;
            }
            drop(registers);
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
                // Cannot happen for a chain the worker validated; fail safely.
                self.registers.lock().status |= DEVICE_NEEDS_RESET;
                self.complete(request, 0);
                return progressed;
            }
            let pushed = self.endpoint.push_output(&chunk[..count]);
            progressed |= pushed > 0;
            offset += pushed;
            if pushed < count {
                let suspended = self
                    .registers
                    .lock()
                    .suspend_transmit(request, index, offset);
                return progressed || !suspended;
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
        if request.generation != registers.generation || registers.cancelled {
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
}

#[cfg(ktest)]
mod tests {
    use ostd::prelude::*;

    use super::*;
    use crate::{fs::file::FileLike, prelude::VmReader};

    fn request(queue: usize, generation: u64) -> Request {
        Request {
            queue,
            head: 0,
            generation,
            buffers: [Buffer::default(); QUEUE_SIZE],
            len: 0,
        }
    }

    fn full_output() -> Arc<ConsoleEndpoint> {
        let endpoint = ConsoleEndpoint::new();
        while endpoint.push_output(&[0; CHUNK_BYTES]) != 0 {}
        endpoint
    }

    #[ktest]
    fn console_input_progresses_while_output_is_full() {
        // Regression: a parked transmit used to return before dispatching RX.
        crate::time::clocks::init_for_ktest();
        let endpoint = full_output();
        let file = endpoint.file();
        let registers = SpinLock::new(Registers::new());
        let generation = registers.lock().generation;
        registers
            .lock()
            .inbox
            .push_back(request(QUEUE_TX, generation));
        // Exercise both the first stall and retrying the same parked TX.
        for byte in [b'a', b'b'] {
            assert_eq!(
                file.write(&mut VmReader::from(&[byte][..]).to_fallible())
                    .unwrap(),
                1
            );
            registers
                .lock()
                .inbox
                .push_back(request(QUEUE_RX, generation));
            let work = poll_queues(
                &registers,
                |request, index, offset| {
                    assert_eq!(endpoint.push_output(b"blocked"), 0);
                    assert!(registers.lock().suspend_transmit(request, index, offset));
                    false
                },
                |request| {
                    assert_eq!(request.queue, QUEUE_RX);
                    let mut received = [0];
                    assert_eq!(endpoint.pop_input(&mut received), 1);
                    assert_eq!(received, [byte]);
                    registers.lock().active -= 1;
                    true
                },
            );
            assert!(matches!(work, Some(Work::Progress)));
            assert_eq!(registers.lock().active, 1);
        }
        registers.lock().reset();
    }

    #[ktest]
    fn console_reset_completes_without_draining_output() {
        // Regression: reset retained a parked TX's active reference forever.
        let endpoint = full_output();
        let registers = SpinLock::new(Registers::new());
        let generation = registers.lock().generation;
        registers.lock().status = DEVICE_NEEDS_RESET;
        registers
            .lock()
            .inbox
            .push_back(request(QUEUE_TX, generation));
        assert!(
            poll_queues(
                &registers,
                |request, index, offset| {
                    assert_eq!(endpoint.push_output(b"blocked"), 0);
                    assert!(registers.lock().suspend_transmit(request, index, offset));
                    false
                },
                |_| panic!("no receive request was queued"),
            )
            .is_none()
        );
        let mut registers = registers.lock();
        registers.reset();
        assert_eq!(registers.status, 0);
        assert_eq!(registers.active, 0);
        assert!(!registers.resetting);
        assert!(registers.suspended.is_none());
        drop(registers);
        assert_eq!(endpoint.push_output(b"still full"), 0);
    }

    #[ktest]
    fn console_reset_retires_transmit_before_it_can_park_again() {
        // Reset can race a byte move that has already left the register lock.
        let registers = SpinLock::new(Registers::new());
        let generation = registers.lock().generation;
        registers.lock().status = DEVICE_NEEDS_RESET;
        registers
            .lock()
            .inbox
            .push_back(request(QUEUE_TX, generation));
        let work = poll_queues(
            &registers,
            |request, index, offset| {
                let mut registers = registers.lock();
                registers.reset();
                assert!(registers.resetting);
                assert!(!registers.suspend_transmit(request, index, offset));
                true
            },
            |_| panic!("no receive request was queued"),
        );
        assert!(matches!(work, Some(Work::Progress)));
        let registers = registers.lock();
        assert_eq!(registers.status, 0);
        assert_eq!(registers.active, 0);
        assert!(!registers.resetting);
        assert!(registers.suspended.is_none());
    }

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
