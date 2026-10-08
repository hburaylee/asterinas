// SPDX-License-Identifier: MPL-2.0

//! One CID-scoped Host stream endpoint and its user-space descriptor.

use alloc::format;
use core::{
    fmt::Display,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::Duration,
};

use aster_time::read_monotonic_time;
use ostd::{kernelet::control::Kernelet, sync::WaitQueue};
use spin::Once;

use super::{HOST_CID, MAX_PAYLOAD, Packet, VsockSwitch, WINDOW};
use crate::{
    endovisor::{
        io_accounting::{ChargedSpan, WorkCategory},
        policy::{Admission, EndpointReservation, PrestartEndpointReservation},
    },
    events::IoEvents,
    fs::{
        file::{AccessMode, FileCommon, FileLike, StatusFlags, file_table::FdFlags},
        pseudofs::AnonInodeFs,
    },
    prelude::*,
    process::{
        Uid,
        signal::{PollHandle, Pollable, Pollee},
    },
    thread::kernel_thread::ThreadOptions,
    util::ioctl::{RawIoctl, dispatch_ioctl},
};

const CLOSE_TIMEOUT: Duration = Duration::from_secs(8);
const CLOSE_CHARGE: usize = size_of::<Closing>() + 32;
const HOST_ENDPOINT_CHARGE: usize = size_of::<HostEndpoint>() + size_of::<HostEndpointFile>() + 128;

mod ioctl_defs {
    use crate::util::ioctl::{NoData, ioc};

    pub(super) type Shutdown = ioc!(KERNELET_VSOCK_SHUTDOWN, 0xc7, 0x32, NoData);
}

struct EndpointState {
    owner: Option<Arc<Kernelet>>,
    admission: Option<Arc<Admission>>,
    window_reservation: Option<EndpointReservation>,
    peer_port: Option<u32>,
    connected: bool,
    closing: bool,
    peer_buf_alloc: u32,
    peer_fwd_cnt: u32,
    tx_cnt: u32,
    rx_cnt: u32,
    fwd_cnt: u32,
    output: VecDeque<u8>,
    peer_write_closed: bool,
    local_write_closed: bool,
    reset: bool,
}

enum EndpointBaseReservation {
    Prestart(PrestartEndpointReservation),
    Running(EndpointReservation),
}

impl EndpointBaseReservation {
    fn release(self) {
        match self {
            Self::Prestart(reservation) => drop(reservation),
            Self::Running(reservation) => drop(reservation),
        }
    }
}

pub(super) struct HostEndpoint {
    cid: u32,
    port: u32,
    switch: Weak<VsockSwitch>,
    state: Mutex<EndpointState>,
    pollee: Pollee,
    revoked: AtomicBool,
    base_reservation: Option<EndpointBaseReservation>,
}

impl HostEndpoint {
    fn new(
        cid: u32,
        port: u32,
        switch: Weak<VsockSwitch>,
        reservation: EndpointBaseReservation,
    ) -> Arc<Self> {
        Arc::new(Self {
            cid,
            port,
            switch,
            state: Mutex::new(EndpointState {
                owner: None,
                admission: None,
                window_reservation: None,
                peer_port: None,
                connected: false,
                closing: false,
                peer_buf_alloc: 0,
                peer_fwd_cnt: 0,
                tx_cnt: 0,
                rx_cnt: 0,
                fwd_cnt: 0,
                output: VecDeque::new(),
                peer_write_closed: false,
                local_write_closed: false,
                reset: false,
            }),
            pollee: Pollee::new(),
            revoked: AtomicBool::new(false),
            base_reservation: Some(reservation),
        })
    }

    /// A listener is installed before the device exists, so its fixed Host
    /// allocation is reserved against the owning user before START.
    pub(super) fn new_listener(
        cid: u32,
        port: u32,
        switch: Weak<VsockSwitch>,
        owner: Uid,
    ) -> Result<Arc<Self>> {
        let reservation = PrestartEndpointReservation::reserve(owner, HOST_ENDPOINT_CHARGE)?;
        Ok(Self::new(
            cid,
            port,
            switch,
            EndpointBaseReservation::Prestart(reservation),
        ))
    }

    pub(super) fn new_connect(
        cid: u32,
        host_port: u32,
        peer_port: u32,
        switch: Weak<VsockSwitch>,
        admission: Arc<Admission>,
    ) -> Result<Arc<Self>> {
        let reservation = admission.reserve_endpoint_bytes(HOST_ENDPOINT_CHARGE)?;
        let endpoint = Self::new(
            cid,
            host_port,
            switch,
            EndpointBaseReservation::Running(reservation),
        );
        {
            let mut state = endpoint.state.lock();
            if !endpoint.activate(&mut state) {
                return_errno_with_message!(Errno::ENOMEM, "cannot reserve vsock endpoint");
            }
            state.peer_port = Some(peer_port);
        }
        Ok(endpoint)
    }

    fn activate(&self, state: &mut EndpointState) -> bool {
        let Some(device) = self
            .switch
            .upgrade()
            .and_then(|switch| switch.device(self.cid))
        else {
            return false;
        };
        let owner = device.account_owner();
        let admission = device.account_admission();
        let Ok(reservation) = admission.reserve_endpoint_bytes(WINDOW) else {
            return false;
        };
        let bytes = WINDOW + HOST_ENDPOINT_CHARGE;
        if owner.charge_host_bytes(bytes).is_err() {
            return false;
        }
        if state.output.try_reserve_exact(WINDOW).is_err() {
            owner.uncharge_host_bytes(bytes);
            return false;
        }
        state.owner = Some(owner);
        state.admission = Some(admission);
        state.window_reservation = Some(reservation);
        true
    }

    pub(super) fn receive(&self, packet: Packet) -> Option<Packet> {
        let mut state = self.state.lock();
        if self.revoked.load(Ordering::Acquire) || state.reset {
            return (packet.op != Packet::RST).then(|| packet.reply(Packet::RST, 0, 0));
        }
        if packet.op == Packet::REQUEST {
            if state.peer_port.is_some() {
                return Some(packet.reply(Packet::RST, 0, 0));
            }
            if !self.activate(&mut state) {
                return Some(packet.reply(Packet::RST, 0, 0));
            }
            state.peer_port = Some(packet.src_port);
            state.connected = true;
            state.peer_buf_alloc = packet.buf_alloc;
            state.peer_fwd_cnt = packet.fwd_cnt;
            self.pollee.notify(IoEvents::OUT);
            return Some(packet.reply(Packet::RESPONSE, WINDOW as u32, 0));
        }
        if state.peer_port != Some(packet.src_port) {
            return (packet.op != Packet::RST).then(|| packet.reply(Packet::RST, 0, 0));
        }
        if !state.connected && packet.op != Packet::RESPONSE && packet.op != Packet::RST {
            return Some(packet.reply(Packet::RST, 0, 0));
        }
        state.peer_buf_alloc = packet.buf_alloc;
        state.peer_fwd_cnt = packet.fwd_cnt;
        match packet.op {
            Packet::RESPONSE if !state.connected => {
                state.connected = true;
                self.pollee.notify(IoEvents::OUT);
            }
            Packet::RW => {
                if state.closing {
                    return None;
                }
                let used = state.rx_cnt.wrapping_sub(state.fwd_cnt) as usize;
                if packet.payload.len() > WINDOW.saturating_sub(used) {
                    let reset = packet.reply(Packet::RST, 0, 0);
                    drop(state);
                    self.revoke();
                    return Some(reset);
                }
                state.rx_cnt = state.rx_cnt.wrapping_add(packet.payload.len() as u32);
                // Ingress category: this endpoint's instance pays for
                // copying the received payload into its Host byte queue.
                let owner = state.owner.clone();
                let ingress = owner
                    .as_deref()
                    .map(|owner| ChargedSpan::new(owner, WorkCategory::Ingress));
                state.output.extend(packet.payload);
                drop(ingress);
                self.pollee.notify(IoEvents::IN);
            }
            Packet::CREDIT_REQUEST => {
                return Some(packet.reply(Packet::CREDIT_UPDATE, WINDOW as u32, state.fwd_cnt));
            }
            Packet::CREDIT_UPDATE => self.pollee.notify(IoEvents::OUT),
            Packet::SHUTDOWN => {
                if packet.flags & 2 != 0 {
                    state.peer_write_closed = true;
                    self.pollee.notify(IoEvents::IN | IoEvents::RDHUP);
                }
                if packet.flags & 1 != 0 {
                    state.local_write_closed = true;
                    self.pollee.notify(IoEvents::OUT);
                }
            }
            Packet::RST => {
                drop(state);
                self.revoke();
                return None;
            }
            _ => return Some(packet.reply(Packet::RST, 0, 0)),
        }
        None
    }

    fn make_packet(&self, state: &EndpointState, op: u16, payload: Vec<u8>) -> Packet {
        Packet {
            src_cid: HOST_CID,
            dst_cid: self.cid,
            src_port: self.port,
            dst_port: state.peer_port.unwrap(),
            op,
            flags: 0,
            buf_alloc: WINDOW as u32,
            fwd_cnt: state.fwd_cnt,
            payload,
        }
    }

    pub(super) fn revoke(&self) {
        let mut state = self.state.lock();
        state.reset = true;
        state.output = VecDeque::new();
        let owner = state.owner.take();
        let reservation = state.window_reservation.take();
        state.admission.take();
        drop(state);
        drop(reservation);
        if let Some(owner) = owner {
            owner.uncharge_host_bytes(WINDOW + HOST_ENDPOINT_CHARGE);
        }
        self.revoked.store(true, Ordering::Release);
        self.pollee
            .notify(IoEvents::IN | IoEvents::OUT | IoEvents::RDHUP | IoEvents::ERR);
        if let Some(worker) = CLOSE_WORKER.get() {
            worker.wake();
        }
    }

    fn check_events(&self) -> IoEvents {
        let state = self.state.lock();
        if self.revoked.load(Ordering::Acquire) || state.reset {
            return IoEvents::IN | IoEvents::OUT | IoEvents::ERR | IoEvents::RDHUP;
        }
        let mut events = IoEvents::empty();
        if !state.output.is_empty() || state.peer_write_closed {
            events |= IoEvents::IN;
        }
        if state.connected
            && !state.local_write_closed
            && state.peer_buf_alloc > state.tx_cnt.wrapping_sub(state.peer_fwd_cnt)
        {
            events |= IoEvents::OUT;
        }
        events
    }
}

impl Drop for HostEndpoint {
    fn drop(&mut self) {
        let (owner, reservation) = {
            let mut state = self.state.lock();
            (state.owner.take(), state.window_reservation.take())
        };
        drop(reservation);
        if let Some(owner) = owner {
            owner.uncharge_host_bytes(WINDOW + HOST_ENDPOINT_CHARGE);
        }
        if let Some(reservation) = self.base_reservation.take() {
            reservation.release();
        }
    }
}

pub(super) struct HostEndpointFile {
    common: FileCommon,
    endpoint: Arc<HostEndpoint>,
}

impl HostEndpointFile {
    pub(super) fn new(endpoint: Arc<HostEndpoint>) -> Self {
        Self {
            common: FileCommon::new(
                AnonInodeFs::new_path(|_| "anon_inode:[kernelet-vsock]".into()),
                AccessMode::O_RDWR,
                StatusFlags::empty(),
            ),
            endpoint,
        }
    }

    pub(super) fn wait_connected(&self) -> Result<()> {
        self.wait_events(
            IoEvents::OUT | IoEvents::ERR,
            Some(&Duration::from_secs(2)),
            || {
                let state = self.endpoint.state.lock();
                if state.reset {
                    return_errno_with_message!(Errno::ECONNRESET, "vsock connection refused");
                }
                if state.connected {
                    Ok(())
                } else {
                    return_errno_with_message!(Errno::EAGAIN, "vsock connection pending");
                }
            },
        )
    }

    fn try_read(&self, writer: &mut VmWriter) -> Result<usize> {
        let mut state = self.endpoint.state.lock();
        if state.reset {
            return_errno_with_message!(Errno::ECONNRESET, "vsock connection reset");
        }
        if state.output.is_empty() {
            if state.peer_write_closed || self.endpoint.revoked.load(Ordering::Acquire) {
                return Ok(0);
            }
            return_errno_with_message!(Errno::EAGAIN, "vsock stream has no data");
        }
        let count = state.output.len().min(writer.avail()).min(4096);
        let bytes: Vec<u8> = state.output.iter().take(count).copied().collect();
        let mut reader = VmReader::from(bytes.as_slice()).to_fallible();
        let copied = writer.write_fallible(&mut reader)?;
        for _ in 0..copied {
            state.output.pop_front();
        }
        state.fwd_cnt = state.fwd_cnt.wrapping_add(copied as u32);
        // Interactive reads may never reach a quarter window, so each read
        // reports its progress to a possibly credit-starved sender.
        let credit = self
            .endpoint
            .make_packet(&state, Packet::CREDIT_UPDATE, Vec::new());
        drop(state);
        self.endpoint.pollee.invalidate();
        if let Some(switch) = self.endpoint.switch.upgrade() {
            let _ = switch.deliver(credit);
        }
        Ok(copied)
    }

    fn try_write(&self, reader: &mut VmReader) -> Result<usize> {
        let mut state = self.endpoint.state.lock();
        if state.reset {
            return_errno_with_message!(Errno::ECONNRESET, "vsock connection reset");
        }
        if self.endpoint.revoked.load(Ordering::Acquire) || state.local_write_closed {
            return_errno_with_message!(Errno::EPIPE, "vsock connection closed");
        }
        if !state.connected {
            return_errno_with_message!(Errno::EAGAIN, "vsock listener has no peer");
        }
        let credit = state
            .peer_buf_alloc
            .saturating_sub(state.tx_cnt.wrapping_sub(state.peer_fwd_cnt))
            as usize;
        if credit == 0 {
            return_errno_with_message!(Errno::EAGAIN, "vsock peer has no receive credit");
        }
        let count = reader.remain().min(MAX_PAYLOAD).min(credit);
        let mut bytes = vec![0u8; count];
        // Do not advance the caller's cursor until the device accepts the
        // packet. A full bounded queue can return EAGAIN for a retry.
        let mut preview = reader.clone();
        let copied = preview.read_fallible(&mut VmWriter::from(bytes.as_mut_slice()))?;
        bytes.truncate(copied);
        let packet = self.endpoint.make_packet(&state, Packet::RW, bytes);
        let Some(switch) = self.endpoint.switch.upgrade() else {
            return_errno_with_message!(Errno::EPIPE, "vsock switch unavailable");
        };
        if !switch.deliver(packet) {
            return_errno_with_message!(Errno::EAGAIN, "vsock receive queue full");
        }
        reader.skip(copied);
        state.tx_cnt = state.tx_cnt.wrapping_add(copied as u32);
        drop(state);
        self.endpoint.pollee.invalidate();
        Ok(copied)
    }

    fn shutdown_write(&self) -> Result<()> {
        let mut state = self.endpoint.state.lock();
        if !state.connected {
            return_errno_with_message!(Errno::ENOTCONN, "vsock endpoint is not connected");
        }
        if state.local_write_closed {
            return Ok(());
        }
        if state.reset || self.endpoint.revoked.load(Ordering::Acquire) {
            return_errno_with_message!(Errno::ECONNRESET, "vsock connection reset");
        }
        let mut packet = self
            .endpoint
            .make_packet(&state, Packet::SHUTDOWN, Vec::new());
        packet.flags = 2;
        let Some(switch) = self.endpoint.switch.upgrade() else {
            return_errno_with_message!(Errno::EPIPE, "vsock switch unavailable");
        };
        if !switch.deliver(packet) {
            return_errno_with_message!(Errno::EAGAIN, "vsock receive queue full");
        }
        state.local_write_closed = true;
        drop(state);
        self.endpoint.pollee.invalidate();
        Ok(())
    }
}

impl Pollable for HostEndpointFile {
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.endpoint
            .pollee
            .poll_with(mask, poller, || self.endpoint.check_events())
    }
}

impl FileLike for HostEndpointFile {
    fn ioctl(&self, raw_ioctl: RawIoctl) -> Result<i32> {
        use ioctl_defs::*;
        dispatch_ioctl!(match raw_ioctl {
            _cmd @ Shutdown => {
                self.shutdown_write()?;
                Ok(0)
            }
            _ => return_errno_with_message!(Errno::ENOTTY, "unknown vsock endpoint ioctl"),
        })
    }

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

    fn write(&self, reader: &mut VmReader) -> Result<usize> {
        if !reader.has_remain() {
            return Ok(0);
        }
        if self.common.is_nonblocking() {
            self.try_write(reader)
        } else {
            self.wait_events(IoEvents::OUT, None, || self.try_write(reader))
        }
    }

    fn common(&self) -> &FileCommon {
        &self.common
    }

    fn dump_proc_fdinfo(self: Arc<Self>, _fd_flags: FdFlags) -> Box<dyn Display> {
        Box::new(format!(
            "kernelet-vsock:\t{}:{}\n",
            self.endpoint.cid, self.endpoint.port
        ))
    }
}

impl Drop for HostEndpointFile {
    fn drop(&mut self) {
        if let Some(switch) = self.endpoint.switch.upgrade() {
            let shutdown = {
                let mut state = self.endpoint.state.lock();
                if state.connected && !state.reset {
                    state.closing = true;
                    let mut packet =
                        self.endpoint
                            .make_packet(&state, Packet::SHUTDOWN, Vec::new());
                    packet.flags = 3;
                    Some(packet)
                } else {
                    None
                }
            };
            if let Some(packet) = shutdown {
                let _ = switch.deliver(packet);
                if CloseWorker::global().enqueue(self.endpoint.clone()) {
                    return;
                }
                // A dying sandbox cannot own a pending timer. Complete the
                // close immediately so the endpoint cannot pin its resources.
                let reset = {
                    let state = self.endpoint.state.lock();
                    self.endpoint.make_packet(&state, Packet::RST, Vec::new())
                };
                let _ = switch.deliver(reset);
            }
            switch.remove_listener(self.endpoint.cid, self.endpoint.port);
        }
        self.endpoint.revoke();
    }
}

struct Closing {
    endpoint: Arc<HostEndpoint>,
    owner: Arc<Kernelet>,
    _reservation: EndpointReservation,
    deadline: Duration,
}

impl Drop for Closing {
    fn drop(&mut self) {
        self.owner.uncharge_host_bytes(CLOSE_CHARGE);
    }
}

struct CloseWorker {
    pending: Mutex<VecDeque<Closing>>,
    changes: WaitQueue,
    generation: AtomicU64,
}

static CLOSE_WORKER: Once<Arc<CloseWorker>> = Once::new();

impl CloseWorker {
    fn global() -> Arc<Self> {
        CLOSE_WORKER
            .call_once(|| {
                let worker = Arc::new(Self {
                    pending: Mutex::new(VecDeque::new()),
                    changes: WaitQueue::new(),
                    generation: AtomicU64::new(0),
                });
                let running = worker.clone();
                ThreadOptions::new(move || running.run()).spawn();
                worker
            })
            .clone()
    }

    fn wake(&self) {
        self.generation.fetch_add(1, Ordering::Release);
        self.changes.wake_all();
    }

    fn enqueue(&self, endpoint: Arc<HostEndpoint>) -> bool {
        let (owner, admission) = {
            let state = endpoint.state.lock();
            (state.owner.clone(), state.admission.clone())
        };
        let (Some(owner), Some(admission)) = (owner, admission) else {
            return false;
        };
        let Ok(reservation) = admission.reserve_endpoint_bytes(CLOSE_CHARGE) else {
            return false;
        };
        if owner.charge_host_bytes(CLOSE_CHARGE).is_err() {
            return false;
        }
        self.pending.lock().push_back(Closing {
            endpoint,
            owner,
            _reservation: reservation,
            deadline: read_monotonic_time() + CLOSE_TIMEOUT,
        });
        self.wake();
        true
    }

    fn run(&self) {
        loop {
            let generation = self.generation.load(Ordering::Acquire);
            let now = read_monotonic_time();
            let (ready, next) = {
                let mut pending = self.pending.lock();
                let index = pending.iter().position(|closing| {
                    closing.deadline <= now || closing.endpoint.revoked.load(Ordering::Acquire)
                });
                let ready = index.and_then(|index| pending.remove(index));
                let next = pending.iter().map(|closing| closing.deadline).min();
                (ready, next)
            };
            if let Some(closing) = ready {
                self.finish(closing);
                continue;
            }
            let changed = || (self.generation.load(Ordering::Acquire) != generation).then_some(());
            if let Some(deadline) = next {
                let remaining = deadline.saturating_sub(now);
                let _ = self.changes.wait_until_or_timeout(changed, &remaining);
            } else {
                self.changes.wait_until(changed);
            }
        }
    }

    fn finish(&self, closing: Closing) {
        let endpoint = &closing.endpoint;
        if let Some(switch) = endpoint.switch.upgrade() {
            let reset = {
                let state = endpoint.state.lock();
                (!state.reset && state.connected)
                    .then(|| endpoint.make_packet(&state, Packet::RST, Vec::new()))
            };
            if let Some(reset) = reset {
                let _ = switch.deliver(reset);
            }
            switch.remove_listener_if(endpoint.cid, endpoint.port, endpoint);
        }
        endpoint.revoke();
    }
}
