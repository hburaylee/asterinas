// SPDX-License-Identifier: MPL-2.0

//! One CID-scoped Host stream endpoint and its user-space descriptor.

use alloc::format;
use core::{
    fmt::Display,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::Duration,
};

use aster_time::read_monotonic_time;
use ostd::{kernelet::control::Kernelet, sync::WaitQueue};
use spin::Once;

use super::{
    HOST_CID, HostCleanupLease, HostEndpointAccount, MAX_PAYLOAD, Packet, VsockSwitch, WINDOW,
};
#[cfg(kernelet_nat_failure_diag_host)]
use crate::endovisor::policy::{QuotaClass, QuotaTag};
use crate::{
    endovisor::{
        io_accounting::{ChargedSpan, WorkCategory},
        policy::{Admission, EndpointReservation, PrestartEndpointReservation},
        virtio_vsock::{EnqueueError, VirtioVsock},
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
    cleanup: Option<HostCleanupLease>,
    peer_port: Option<u32>,
    connected: bool,
    closing: bool,
    peer_buf_alloc: u32,
    peer_fwd_cnt: u32,
    tx_cnt: u32,
    rx_cnt: u32,
    fwd_cnt: u32,
    // Fixed, prepaid endpoint state: coalesce credit instead of queueing packets.
    response_pending: bool,
    credit_pending: bool,
    output: VecDeque<u8>,
    peer_write_closed: bool,
    local_write_closed: bool,
    reset: bool,
}

/// Owns resources moved out of state; releases the destruction gate last.
struct EndpointCleanup {
    output: VecDeque<u8>,
    owner: Option<Arc<Kernelet>>,
    admission: Option<Arc<Admission>>,
    reservation: Option<EndpointReservation>,
    lease: Option<HostCleanupLease>,
}

impl EndpointCleanup {
    fn take(state: &mut EndpointState) -> Self {
        state.reset = true;
        Self {
            output: core::mem::take(&mut state.output),
            owner: state.owner.take(),
            admission: state.admission.take(),
            reservation: state.window_reservation.take(),
            lease: state.cleanup.take(),
        }
    }
}

impl Drop for EndpointCleanup {
    fn drop(&mut self) {
        drop(core::mem::take(&mut self.output));
        drop(self.reservation.take());
        drop(self.admission.take());
        if let Some(owner) = self.owner.take() {
            owner.uncharge_host_bytes(WINDOW + HOST_ENDPOINT_CHARGE);
            drop(owner);
        }
        drop(self.lease.take());
    }
}

/// Every ordinary state holder hands pending revocation on after unlocking.
struct EndpointStateGuard<'a> {
    endpoint: &'a HostEndpoint,
    guard: Option<MutexGuard<'a, EndpointState>>,
}

impl Deref for EndpointStateGuard<'_> {
    type Target = EndpointState;

    fn deref(&self) -> &Self::Target {
        self.guard.as_ref().unwrap()
    }
}

impl DerefMut for EndpointStateGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.guard.as_mut().unwrap()
    }
}

impl Drop for EndpointStateGuard<'_> {
    fn drop(&mut self) {
        let control_pending = self
            .guard
            .as_ref()
            .is_some_and(|state| state.response_pending || state.credit_pending);
        // MutexGuard's wake path must finish without a handoff spin lock.
        drop(self.guard.take());
        // This RMW pairs with revoke's swap. If revoke comes first, this
        // holder retries cleanup; if it comes second, it observes our unlock.
        if self.endpoint.revoked.fetch_or(false, Ordering::AcqRel) {
            self.endpoint.try_cleanup();
        } else if control_pending && let Some(switch) = self.endpoint.switch.upgrade() {
            // A worker that skipped our busy mutex must retry after unlock.
            switch.wake_notice(self.endpoint.cid);
        }
    }
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
    #[cfg(kernelet_host_connect_gate)]
    pub(super) fn gate_poll_cancelled(&self, poller: Option<&mut PollHandle>) -> IoEvents {
        if let Some(poller) = poller {
            self.pollee.register_poller(poller, IoEvents::ERR);
        }
        if self.revoked.load(Ordering::Acquire) {
            IoEvents::ERR
        } else {
            IoEvents::empty()
        }
    }

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
                cleanup: None,
                peer_port: None,
                connected: false,
                closing: false,
                peer_buf_alloc: 0,
                peer_fwd_cnt: 0,
                tx_cnt: 0,
                rx_cnt: 0,
                fwd_cnt: 0,
                response_pending: false,
                credit_pending: false,
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
        let reservation = PrestartEndpointReservation::reserve(
            owner,
            HOST_ENDPOINT_CHARGE,
            #[cfg(kernelet_nat_failure_diag_host)]
            QuotaTag::new(QuotaClass::HostVsockFixed, Some(cid)),
        )?;
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
        account: HostEndpointAccount,
    ) -> Result<Arc<Self>> {
        let reservation = account
            .admission
            .reserve_endpoint_bytes(HOST_ENDPOINT_CHARGE)?;
        let endpoint = Self::new(
            cid,
            host_port,
            switch,
            EndpointBaseReservation::Running(reservation),
        );
        let activated = {
            let mut state = endpoint.lock_state();
            let activated = endpoint.activate_account(&mut state, account);
            if activated.is_ok() {
                state.peer_port = Some(peer_port);
            }
            activated
        };
        if let Err(account) = activated {
            // The failed endpoint owns its fixed reservation. Refund it
            // before activation's last lease permits account destruction.
            drop(endpoint);
            drop(account);
            return_errno_with_message!(Errno::ENOMEM, "cannot reserve vsock endpoint");
        }
        Ok(endpoint)
    }

    fn lock_state(&self) -> EndpointStateGuard<'_> {
        EndpointStateGuard {
            endpoint: self,
            guard: Some(self.state.lock()),
        }
    }

    fn activate(&self, state: &mut EndpointState) -> bool {
        let Some(account) = self
            .switch
            .upgrade()
            .and_then(|switch| switch.host_endpoint_account(self.cid).ok())
        else {
            return false;
        };
        self.activate_account(state, account).is_ok()
    }

    fn activate_account(
        &self,
        state: &mut EndpointState,
        account: HostEndpointAccount,
    ) -> core::result::Result<(), HostEndpointAccount> {
        let Ok(reservation) = account.admission.reserve_endpoint_bytes(WINDOW) else {
            return Err(account);
        };
        let bytes = WINDOW + HOST_ENDPOINT_CHARGE;
        if account.owner.charge_host_bytes(bytes).is_err() {
            return Err(account);
        }
        if state.output.try_reserve_exact(WINDOW).is_err() {
            account.owner.uncharge_host_bytes(bytes);
            return Err(account);
        }
        state.owner = Some(account.owner);
        state.admission = Some(account.admission);
        state.window_reservation = Some(reservation);
        state.cleanup = Some(account.cleanup);
        Ok(())
    }

    pub(super) fn receive(&self, packet: Packet) -> Option<Packet> {
        if self.revoked.load(Ordering::Acquire) {
            return (packet.op != Packet::RST).then(|| packet.reply(Packet::RST, 0, 0));
        }
        let mut state = self.lock_state();
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
            state.response_pending = true;
            self.pollee.notify(IoEvents::OUT);
            return None;
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
                let state = &mut *state;
                let ingress = state
                    .owner
                    .as_deref()
                    .map(|owner| ChargedSpan::new(owner, WorkCategory::Ingress));
                state.output.extend(packet.payload);
                drop(ingress);
                self.pollee.notify(IoEvents::IN);
            }
            Packet::CREDIT_REQUEST => {
                state.credit_pending = true;
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

    /// Called under device/switch spin locks, so never wait for endpoint state.
    /// The ordinary state guard wakes the device after a skipped busy mutex.
    pub(super) fn take_control(&self, credit_blocked: impl Fn(u32, u32) -> bool) -> Option<Packet> {
        let mut state = self.state.try_lock()?;
        if self.revoked.load(Ordering::Acquire) || state.reset || !state.connected {
            return None;
        }
        let op = if state.response_pending {
            state.response_pending = false;
            Packet::RESPONSE
        } else if state.credit_pending && !credit_blocked(self.port, state.peer_port.unwrap()) {
            state.credit_pending = false;
            Packet::CREDIT_UPDATE
        } else {
            return None;
        };
        let mut packet = self.make_packet(&state, op, Vec::new());
        if op == Packet::RESPONSE {
            // Handshake precedes queued RW headers. Those headers may carry
            // older credit, so publish any newer progress only after them.
            packet.fwd_cnt = 0;
        }
        Some(packet)
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
            payload_charge: None,
        }
    }

    fn try_cleanup(&self) {
        // This bare guard must not call the ordinary guard's Drop again.
        let Some(mut state) = self.state.try_lock() else {
            return;
        };
        let cleanup = EndpointCleanup::take(&mut state);
        drop(state);
        drop(cleanup);
    }

    pub(super) fn revoke(&self) {
        self.revoked.swap(true, Ordering::AcqRel);
        self.try_cleanup();
        self.pollee
            .notify(IoEvents::IN | IoEvents::OUT | IoEvents::RDHUP | IoEvents::ERR);
        if let Some(worker) = CLOSE_WORKER.get() {
            worker.wake();
        }
    }

    fn connect_events(&self) -> IoEvents {
        let state = self.lock_state();
        if state.reset || self.revoked.load(Ordering::Acquire) {
            IoEvents::ERR
        } else if state.connected {
            IoEvents::OUT
        } else {
            IoEvents::empty()
        }
    }

    fn check_events(&self) -> IoEvents {
        if self.revoked.load(Ordering::Acquire) {
            return IoEvents::IN | IoEvents::OUT | IoEvents::ERR | IoEvents::RDHUP;
        }
        let state = self.lock_state();
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
        let cleanup = EndpointCleanup::take(self.state.get_mut());
        if let Some(reservation) = self.base_reservation.take() {
            reservation.release();
        }
        drop(cleanup);
    }
}

pub(super) struct HostEndpointFile {
    common: FileCommon,
    endpoint: Arc<HostEndpoint>,
}

struct ConnectSubmission<'a> {
    file: &'a HostEndpointFile,
    identity: &'a Weak<VirtioVsock>,
}

impl Pollable for ConnectSubmission<'_> {
    fn poll(&self, mask: IoEvents, mut poller: Option<&mut PollHandle>) -> IoEvents {
        #[cfg(ktest)]
        let registered = poller.is_some();
        // Before a RESPONSE, endpoint OUT is false regardless of queue space.
        let events =
            self.file
                .endpoint
                .pollee
                .poll_with(IoEvents::ERR, poller.as_deref_mut(), || {
                    self.file.endpoint.check_events()
                });
        if events.contains(IoEvents::ERR) {
            return events;
        }
        let (device, account) = match self.file.connect_device(self.identity) {
            Ok(device) => device,
            Err(_) => return IoEvents::ERR,
        };
        let space = device.poll_inbound_space(poller);
        drop(device);
        drop(account);
        #[cfg(ktest)]
        if registered {
            tests::after_connect_registered(self.file.endpoint.cid, self.file.endpoint.port, false);
        }
        (events | space) & (mask | IoEvents::ALWAYS_POLL)
    }
}

struct ConnectHandshake<'a> {
    file: &'a HostEndpointFile,
    identity: &'a Weak<VirtioVsock>,
}

impl Pollable for ConnectHandshake<'_> {
    fn poll(&self, mask: IoEvents, mut poller: Option<&mut PollHandle>) -> IoEvents {
        #[cfg(ktest)]
        let registered = poller.is_some();
        if let Some(poller) = poller.as_deref_mut() {
            // Connected readiness differs from write-credit readiness. Do
            // not read or replace the ordinary stream Pollee's cached state.
            self.file
                .endpoint
                .pollee
                .register_poller(poller, IoEvents::OUT | IoEvents::ERR);
        }
        let (device, account) = match self.file.connect_device(self.identity) {
            Ok(device) => device,
            Err(_) => return IoEvents::ERR,
        };
        let cancelled = device.poll_cancelled(poller);
        drop(device);
        drop(account);
        #[cfg(ktest)]
        if registered {
            tests::after_connect_registered(self.file.endpoint.cid, self.file.endpoint.port, true);
        }
        (cancelled | self.file.endpoint.connect_events()) & (mask | IoEvents::ALWAYS_POLL)
    }
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

    fn connect_device(
        &self,
        identity: &Weak<VirtioVsock>,
    ) -> Result<(Arc<VirtioVsock>, HostEndpointAccount)> {
        if self.endpoint.revoked.load(Ordering::Acquire) {
            return_errno_with_message!(Errno::ECONNRESET, "vsock connection refused");
        }
        let switch = self.endpoint.switch.upgrade().ok_or_else(|| {
            Error::with_message(Errno::ENODEV, "kernelet vsock switch unavailable")
        })?;
        let account = switch.host_endpoint_account(self.endpoint.cid)?;
        if !Weak::ptr_eq(&account.device, identity) {
            return_errno_with_message!(Errno::ENODEV, "kernelet vsock device changed");
        }
        let device = account.device.upgrade().ok_or_else(|| {
            Error::with_message(Errno::ENODEV, "kernelet vsock device unavailable")
        })?;
        let live = {
            let state = switch.state.lock();
            state
                .devices
                .get(&self.endpoint.cid)
                .is_some_and(|current| Weak::ptr_eq(current, identity))
                && state
                    .listeners
                    .get(&(self.endpoint.cid, self.endpoint.port))
                    .is_some_and(|current| Arc::ptr_eq(current, &self.endpoint))
        };
        if !live {
            return_errno_with_message!(Errno::ENODEV, "kernelet vsock connection unavailable");
        }
        Ok((device, account))
    }

    pub(super) fn submit_request(
        &self,
        request: Packet,
        identity: &Weak<VirtioVsock>,
    ) -> Result<()> {
        let submission = ConnectSubmission {
            file: self,
            identity,
        };
        let mut request = Some(request);
        submission.wait_events(IoEvents::OUT | IoEvents::ERR, None, || {
            let (device, account) = self.connect_device(identity)?;
            let result = device.try_enqueue(request.take().unwrap());
            // Temporary device references must leave the destruction gate
            // before this Native caller parks.
            drop(device);
            drop(account);
            match result {
                Ok(()) => Ok(()),
                Err(EnqueueError::Full(packet)) => {
                    request = Some(packet);
                    return_errno_with_message!(Errno::EAGAIN, "kernelet vsock receive queue full");
                }
                Err(EnqueueError::Failed(error)) => Err(error),
            }
        })
    }

    pub(super) fn wait_connected(&self, identity: &Weak<VirtioVsock>) -> Result<()> {
        let handshake = ConnectHandshake {
            file: self,
            identity,
        };
        handshake.wait_events(IoEvents::OUT | IoEvents::ERR, None, || {
            let (device, account) = self.connect_device(identity)?;
            let cancelled = device.poll_cancelled(None);
            drop(device);
            drop(account);
            if cancelled.contains(IoEvents::ERR) {
                return_errno_with_message!(Errno::ENODEV, "kernelet vsock device cancelled");
            }
            let events = self.endpoint.connect_events();
            if events.contains(IoEvents::ERR) {
                return_errno_with_message!(Errno::ECONNRESET, "vsock connection refused");
            }
            if events.contains(IoEvents::OUT) {
                Ok(())
            } else {
                return_errno_with_message!(Errno::EAGAIN, "vsock connection pending");
            }
        })
    }

    fn try_read(&self, writer: &mut VmWriter) -> Result<usize> {
        if self.endpoint.revoked.load(Ordering::Acquire) {
            return_errno_with_message!(Errno::ECONNRESET, "vsock connection reset");
        }
        let mut state = self.endpoint.lock_state();
        if state.reset || self.endpoint.revoked.load(Ordering::Acquire) {
            return_errno_with_message!(Errno::ECONNRESET, "vsock connection reset");
        }
        if state.output.is_empty() {
            if state.peer_write_closed || self.endpoint.revoked.load(Ordering::Acquire) {
                return Ok(0);
            }
            return_errno_with_message!(Errno::EAGAIN, "vsock stream has no data");
        }
        let count = state.output.len().min(writer.avail()).min(4096);
        let copied = {
            let (first, second) = state.output.as_slices();
            let first_len = count.min(first.len());
            let mut reader = VmReader::from(&first[..first_len]).to_fallible();
            let mut copied = writer.write_fallible(&mut reader)?;
            if copied == first_len && copied < count {
                let mut reader = VmReader::from(&second[..count - copied]).to_fallible();
                copied += writer.write_fallible(&mut reader)?;
            }
            copied
        };
        // Keep the complete queue and credit unchanged if either copy faults,
        // including when the first slice has already advanced the writer.
        for _ in 0..copied {
            state.output.pop_front();
        }
        state.fwd_cnt = state.fwd_cnt.wrapping_add(copied as u32);
        // Interactive reads may never reach a quarter window, so each read
        // reports its progress to a possibly credit-starved sender.
        state.credit_pending = true;
        drop(state);
        self.endpoint.pollee.invalidate();
        Ok(copied)
    }

    fn try_write(&self, reader: &mut VmReader) -> Result<usize> {
        if self.endpoint.revoked.load(Ordering::Acquire) {
            return_errno_with_message!(Errno::ECONNRESET, "vsock connection reset");
        }
        let mut state = self.endpoint.lock_state();
        if state.reset || self.endpoint.revoked.load(Ordering::Acquire) {
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
        let (Some(owner), Some(admission)) = (&state.owner, &state.admission) else {
            return_errno_with_message!(Errno::EPIPE, "vsock endpoint has no live account");
        };
        let mut packet = self.endpoint.make_packet(&state, Packet::RW, Vec::new());
        // Host-originated payloads belong to this endpoint's instance in both
        // directions. Charge before allocating, then transfer with the packet.
        packet.prepare_payload(count, owner.clone(), admission.clone())?;
        // Do not advance the caller's cursor until the device accepts the
        // packet. A full bounded queue can return EAGAIN for a retry.
        let mut preview = reader.clone();
        let copied = preview.read_fallible(&mut VmWriter::from(packet.payload.as_mut_slice()))?;
        packet.payload.truncate(copied);
        let Some(switch) = self.endpoint.switch.upgrade() else {
            return_errno_with_message!(Errno::EPIPE, "vsock switch unavailable");
        };
        if !switch.deliver_host(packet) {
            return_errno_with_message!(Errno::EAGAIN, "vsock receive queue full");
        }
        reader.skip(copied);
        state.tx_cnt = state.tx_cnt.wrapping_add(copied as u32);
        drop(state);
        self.endpoint.pollee.invalidate();
        Ok(copied)
    }

    fn shutdown_write(&self) -> Result<()> {
        if self.endpoint.revoked.load(Ordering::Acquire) {
            return_errno_with_message!(Errno::ECONNRESET, "vsock connection reset");
        }
        let mut state = self.endpoint.lock_state();
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
        if !switch.deliver_host(packet) {
            return_errno_with_message!(Errno::EAGAIN, "vsock receive queue full");
        }
        state.local_write_closed = true;
        drop(state);
        self.endpoint.pollee.invalidate();
        Ok(())
    }
}

impl Pollable for HostEndpointFile {
    fn poll(&self, mask: IoEvents, mut poller: Option<&mut PollHandle>) -> IoEvents {
        let mut events = self
            .endpoint
            .pollee
            .poll_with(mask, poller.as_deref_mut(), || self.endpoint.check_events());
        if mask.contains(IoEvents::OUT) && !events.intersects(IoEvents::ERR) {
            let space = self
                .endpoint
                .switch
                .upgrade()
                .map_or(IoEvents::empty(), |switch| {
                    let account = match switch.host_endpoint_account(self.endpoint.cid) {
                        Ok(account) => account,
                        Err(error) if error.error() == Errno::ENODEV => return IoEvents::empty(),
                        Err(_) => return IoEvents::ERR,
                    };
                    let Some(device) = account.device.upgrade() else {
                        return IoEvents::empty();
                    };
                    let events = device.poll_inbound_space(poller);
                    drop(device);
                    drop(account);
                    events
                });
            if !space.contains(IoEvents::OUT) {
                events.remove(IoEvents::OUT);
            }
            events |= space & IoEvents::ALWAYS_POLL;
        }
        events
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
            let shutdown = if self.endpoint.revoked.load(Ordering::Acquire) {
                None
            } else {
                let mut state = self.endpoint.lock_state();
                if state.connected && !state.reset && !self.endpoint.revoked.load(Ordering::Acquire)
                {
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
                let _ = switch.deliver_host(packet);
                if CloseWorker::global().enqueue(self.endpoint.clone()) {
                    return;
                }
                // A dying sandbox cannot own a pending timer. Complete the
                // close immediately so the endpoint cannot pin its resources.
                let reset = if self.endpoint.revoked.load(Ordering::Acquire) {
                    None
                } else {
                    let state = self.endpoint.lock_state();
                    (!state.reset && !self.endpoint.revoked.load(Ordering::Acquire))
                        .then(|| self.endpoint.make_packet(&state, Packet::RST, Vec::new()))
                };
                if let Some(reset) = reset {
                    let _ = switch.deliver_host(reset);
                }
            }
            switch.remove_listener_if(self.endpoint.cid, self.endpoint.port, &self.endpoint);
        }
        self.endpoint.revoke();
    }
}

struct Closing {
    // Fields drop in declaration order after Drop: endpoint and accounting
    // references must disappear before the final cleanup lease.
    endpoint: Arc<HostEndpoint>,
    owner: Arc<Kernelet>,
    admission: Arc<Admission>,
    reservation: Option<EndpointReservation>,
    charged: bool,
    deadline: Duration,
    _cleanup: HostCleanupLease,
}

impl Drop for Closing {
    fn drop(&mut self) {
        if self.charged {
            self.owner.uncharge_host_bytes(CLOSE_CHARGE);
        }
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
        if endpoint.revoked.load(Ordering::Acquire) {
            return false;
        }
        let mut closing = {
            let state = endpoint.lock_state();
            if state.reset || endpoint.revoked.load(Ordering::Acquire) {
                return false;
            }
            let (Some(owner), Some(admission), Some(cleanup)) =
                (&state.owner, &state.admission, &state.cleanup)
            else {
                return false;
            };
            let Some(cleanup) = cleanup.try_clone() else {
                return false;
            };
            // Count this continuation before it releases endpoint state.
            // All rollback paths dispose its references before the lease.
            Closing {
                endpoint: endpoint.clone(),
                owner: owner.clone(),
                admission: admission.clone(),
                reservation: None,
                charged: false,
                deadline: read_monotonic_time() + CLOSE_TIMEOUT,
                _cleanup: cleanup,
            }
        };
        #[cfg(ktest)]
        tests::after_closing_prepared(endpoint.cid);
        let Ok(reservation) = closing.admission.reserve_endpoint_bytes(CLOSE_CHARGE) else {
            return false;
        };
        closing.reservation = Some(reservation);
        if closing.owner.charge_host_bytes(CLOSE_CHARGE).is_err() {
            return false;
        }
        closing.charged = true;
        self.pending.lock().push_back(closing);
        #[cfg(ktest)]
        tests::after_closing_enqueued(endpoint.cid);
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
            let reset = if endpoint.revoked.load(Ordering::Acquire) {
                None
            } else {
                let state = endpoint.lock_state();
                (!state.reset && state.connected && !endpoint.revoked.load(Ordering::Acquire))
                    .then(|| endpoint.make_packet(&state, Packet::RST, Vec::new()))
            };
            if let Some(reset) = reset {
                let _ = switch.deliver_host(reset);
            }
            switch.remove_listener_if(endpoint.cid, endpoint.port, endpoint);
        }
        endpoint.revoke();
        #[cfg(ktest)]
        tests::after_closing_finished(endpoint.cid);
    }
}

#[cfg(ktest)]
pub(super) mod tests {
    use core::sync::atomic::{AtomicU32, AtomicUsize};

    use ostd::{
        cpu::{CpuId, CpuSet, PinCurrentCpu},
        kernelet::{
            abi::MmioResult,
            control::{
                CpuBudget, KerneletConfig, KerneletHooks, KerneletKind, KerneletPolicy,
                KerneletState, KillReason,
            },
        },
        prelude::ktest,
        sync::Waiter,
        task::{Task, TaskOptions},
    };

    use super::*;
    use crate::{
        endovisor::virtio_vsock::VirtioVsock, events::Observer, process::signal::PollAdaptor,
    };

    static NEXT_FIXTURE_CID: AtomicU32 = AtomicU32::new(0x6f00_0000);
    static FIXTURE_KIND: Once<KerneletKind> = Once::new();

    struct DormantHooks;

    impl KerneletHooks for DormantHooks {
        fn create_vcpu_thread(
            &self,
            _: &Arc<Kernelet>,
            _: u16,
            _: CpuId,
            _: i8,
        ) -> ostd::Result<Arc<Task>> {
            TaskOptions::new(|| panic!("vsock fixture carrier must stay dormant"))
                .data(())
                .build()
                .map(Arc::new)
        }

        fn realtime_now(&self) -> Duration {
            Duration::ZERO
        }

        fn mmio_read(&self, _: u16, _: u32, _: u32) -> MmioResult {
            panic!("vsock fixture must not execute Image MMIO")
        }

        fn mmio_write(&self, _: u16, _: u32, _: u32, _: u64) -> i64 {
            panic!("vsock fixture must not execute Image MMIO")
        }

        fn log(&self, _: u32, _: &str, _: &str) -> bool {
            panic!("vsock fixture must not execute Image logging")
        }

        fn set_vcpu_nice(&self, _: i8) -> ostd::Result<()> {
            panic!("vsock fixture must not change a dormant carrier's budget")
        }
    }

    struct Fixture {
        cid: u32,
        uid: Uid,
        switch: Arc<VsockSwitch>,
        owner: Arc<Kernelet>,
        admission: Arc<Admission>,
        device: Option<Arc<VirtioVsock>>,
        device_refs: Weak<VirtioVsock>,
        finished: bool,
    }

    impl Fixture {
        fn new() -> Self {
            aster_time::init_for_ktest();
            crate::time::clocks::init_for_ktest();
            crate::endovisor::reaper::init().unwrap();
            let kind = FIXTURE_KIND.call_once(|| KerneletKind::register_dormant_fixture().unwrap());
            let cid = NEXT_FIXTURE_CID
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                    next.checked_add(1)
                })
                .unwrap();
            let uid = Uid::new(cid);
            let admission = Admission::reserve(uid, 1, 1, 0).unwrap();
            let cpu = ostd::irq::disable_local().current_cpu();
            let mut cpus = CpuSet::new_empty();
            cpus.add(cpu);
            let owner = kind
                .create(
                    &KerneletConfig {
                        cmdline: "",
                        initial_grains: 1,
                        max_grains: 1,
                        max_meta_sections: 1,
                        budget: CpuBudget::default(),
                        policy: KerneletPolicy::default(),
                        max_tasks: 1,
                        devices: &[],
                        cpus,
                    },
                    Arc::new(DormantHooks),
                )
                .unwrap();
            admission.mark_created();
            let device = VirtioVsock::new(owner.clone(), cid, 64, admission.clone()).unwrap();
            // new() registers the device; this Host-only fixture never calls start_worker().
            let device_refs = Arc::downgrade(&device);
            Self {
                cid,
                uid,
                switch: VsockSwitch::global(),
                owner,
                admission,
                device: Some(device),
                device_refs,
                finished: false,
            }
        }

        fn cleanup(&self) -> Arc<super::super::HostCleanup> {
            self.switch.state.lock().retired[&self.cid]
                .host_cleanup
                .clone()
        }

        fn endpoint(&self) -> (Arc<dyn FileLike>, Arc<HostEndpoint>) {
            let file = self.switch.listen(self.cid, 12345, self.uid).unwrap();
            let endpoint = file
                .downcast_ref::<HostEndpointFile>()
                .unwrap()
                .endpoint
                .clone();
            assert!(
                endpoint
                    .receive(Packet {
                        src_cid: self.cid,
                        dst_cid: HOST_CID,
                        src_port: 23456,
                        dst_port: 12345,
                        op: Packet::REQUEST,
                        flags: 0,
                        buf_alloc: WINDOW as u32,
                        fwd_cnt: 0,
                        payload: Vec::new(),
                        payload_charge: None,
                    })
                    .is_none()
            );
            assert_eq!(
                endpoint.take_control(|_, _| false).unwrap().op,
                Packet::RESPONSE
            );
            (file, endpoint)
        }

        fn detach_device(&mut self) {
            if let Some(device) = self.device.take() {
                device.cancel();
                drop(device);
            }
        }

        fn finish(mut self) {
            self.switch.on_dying(self.cid);
            self.detach_device();
            // cancel() requests stop; it is not a join. Observe actual strong
            // references and charges separately from the Host cleanup gate.
            let device_refs_gone = wait_for(|| self.device_refs.strong_count() == 0);
            let host_gate_drained = wait_for(|| self.switch.retired_drained(self.cid));
            let host_charges_refunded = wait_for(|| self.owner.stats().host_bytes_charged == 0);
            assert!(device_refs_gone && host_gate_drained && host_charges_refunded);
            assert!(self.switch.retired_drained(self.cid));
            assert_eq!(self.owner.stats().host_bytes_charged, 0);
            if self.owner.state() == KerneletState::Created {
                self.owner.kill(KillReason::Requested).unwrap();
            }
            assert!(wait_for(|| self.owner.state() == KerneletState::Exited));
            self.owner.destroy().unwrap();
            self.admission.release_after_destroy();
            self.finished = true;
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            if self.finished {
                return;
            }
            // Preserve admission on an unproven drain; never fake teardown
            // success merely to let a failing regression continue.
            self.switch.on_dying(self.cid);
            self.detach_device();
            if !self.switch.retired_drained(self.cid) {
                error!(
                    "vsock test cleanup retained CID {} with live leases",
                    self.cid
                );
                return;
            }
            if self.owner.state() == KerneletState::Created
                && let Err(error) = self.owner.kill(KillReason::Requested)
            {
                error!("vsock test cleanup kill failed: {:?}", error);
                return;
            }
            if self.owner.state() == KerneletState::Exited {
                match self.owner.destroy() {
                    Ok(_) => self.admission.release_after_destroy(),
                    Err(error) => error!("vsock test cleanup destroy failed: {:?}", error),
                }
            } else {
                error!(
                    "vsock test cleanup retained CID {} in {:?}",
                    self.cid,
                    self.owner.state()
                );
            }
        }
    }

    fn wait_for(mut condition: impl FnMut() -> bool) -> bool {
        for _ in 0..100_000 {
            if condition() {
                return true;
            }
            Task::yield_now();
        }
        false
    }

    struct Checkpoint {
        cid: u32,
        entered: AtomicBool,
        proceed: AtomicBool,
        changes: WaitQueue,
    }

    impl Checkpoint {
        fn new(cid: u32) -> Arc<Self> {
            Arc::new(Self {
                cid,
                entered: AtomicBool::new(false),
                proceed: AtomicBool::new(false),
                changes: WaitQueue::new(),
            })
        }

        fn pause(&self) {
            self.entered.store(true, Ordering::Release);
            self.changes
                .wait_until(|| self.proceed.load(Ordering::Acquire).then_some(()));
        }

        fn release(&self) {
            self.proceed.store(true, Ordering::Release);
            self.changes.wake_all();
        }
    }

    struct ReleaseCheckpoint(Arc<Checkpoint>);

    impl Drop for ReleaseCheckpoint {
        fn drop(&mut self) {
            self.0.release();
        }
    }

    static PEER_REVOKE_CHECKPOINT: SpinLock<Option<Arc<Checkpoint>>> = SpinLock::new(None);

    struct PeerRevokeRegistration(Arc<Checkpoint>);

    impl Drop for PeerRevokeRegistration {
        fn drop(&mut self) {
            self.0.release();
            drop(PEER_REVOKE_CHECKPOINT.lock().take());
        }
    }

    pub(in crate::endovisor::vsock_switch) fn after_peer_revoke_boundary(cid: u32) {
        let checkpoint = PEER_REVOKE_CHECKPOINT.lock().clone();
        if let Some(checkpoint) = checkpoint.filter(|checkpoint| checkpoint.cid == cid) {
            checkpoint.pause();
        }
    }

    struct ClosingCheckpoint {
        barrier: Arc<Checkpoint>,
        enqueued: AtomicBool,
        finished: AtomicBool,
    }

    static CLOSING_CHECKPOINT: SpinLock<Option<Arc<ClosingCheckpoint>>> = SpinLock::new(None);

    struct ClosingRegistration(Arc<ClosingCheckpoint>);

    impl ClosingRegistration {
        fn new(cid: u32) -> Self {
            let checkpoint = Arc::new(ClosingCheckpoint {
                barrier: Checkpoint::new(cid),
                enqueued: AtomicBool::new(false),
                finished: AtomicBool::new(false),
            });
            {
                let mut current = CLOSING_CHECKPOINT.lock();
                assert!(current.is_none());
                *current = Some(checkpoint.clone());
            }
            Self(checkpoint)
        }
    }

    impl Drop for ClosingRegistration {
        fn drop(&mut self) {
            self.0.barrier.release();
            let checkpoint = CLOSING_CHECKPOINT.lock().take();
            drop(checkpoint);
        }
    }

    fn closing_checkpoint(cid: u32) -> Option<Arc<ClosingCheckpoint>> {
        let checkpoint = CLOSING_CHECKPOINT.lock().clone();
        checkpoint.filter(|checkpoint| checkpoint.barrier.cid == cid)
    }

    pub(super) fn after_closing_prepared(cid: u32) {
        if let Some(checkpoint) = closing_checkpoint(cid) {
            checkpoint.barrier.pause();
        }
    }

    pub(super) fn after_closing_enqueued(cid: u32) {
        if let Some(checkpoint) = closing_checkpoint(cid) {
            checkpoint.enqueued.store(true, Ordering::Release);
        }
    }

    pub(super) fn after_closing_finished(cid: u32) {
        if let Some(checkpoint) = closing_checkpoint(cid) {
            checkpoint.finished.store(true, Ordering::Release);
        }
    }

    struct ZeroProbe {
        cleanup: Arc<super::super::HostCleanup>,
        owner: Arc<Kernelet>,
        admission: Arc<Admission>,
        expected_host_bytes: usize,
        expected_capacity: usize,
        observed: AtomicBool,
        host_refunded: AtomicBool,
        capacity_refunded: AtomicBool,
    }

    static ZERO_PROBE: SpinLock<Option<Arc<ZeroProbe>>> = SpinLock::new(None);

    struct ProbeRegistration;

    impl Drop for ProbeRegistration {
        fn drop(&mut self) {
            let probe = ZERO_PROBE.lock().take();
            drop(probe);
        }
    }

    pub(in crate::endovisor::vsock_switch) fn after_cleanup_zero(
        cleanup: &Arc<super::super::HostCleanup>,
    ) {
        let probe = ZERO_PROBE.lock().clone();
        let Some(probe) = probe.filter(|probe| Arc::ptr_eq(&probe.cleanup, cleanup)) else {
            return;
        };
        probe.host_refunded.store(
            probe.owner.stats().host_bytes_charged == probe.expected_host_bytes,
            Ordering::Relaxed,
        );
        let reservation = probe
            .admission
            .reserve_endpoint_bytes(probe.expected_capacity);
        probe
            .capacity_refunded
            .store(reservation.is_ok(), Ordering::Relaxed);
        drop(reservation);
        probe.observed.store(true, Ordering::Release);
    }

    fn available_capacity(admission: &Arc<Admission>) -> usize {
        // Query the actual ledger without exposing or duplicating its limit.
        let mut low = 0usize;
        let mut high = usize::MAX;
        while low < high {
            let distance = high - low;
            let middle = low + distance / 2 + distance % 2;
            match admission.reserve_endpoint_bytes(middle) {
                Ok(reservation) => {
                    drop(reservation);
                    low = middle;
                }
                Err(error) if error.error() == Errno::ENOSPC => high = middle - 1,
                Err(error) => panic!("live vsock fixture admission failed: {:?}", error),
            }
        }
        low
    }

    #[ktest]
    fn revoke_returns_with_state_held_and_unlock_cleans_and_wakes() {
        let mut first = Fixture::new();
        let mut second = Fixture::new();
        let (file, endpoint) = first.endpoint();
        let (second_file, second_endpoint) = second.endpoint();
        let cleanup = first.cleanup();
        let drained = cleanup.drained.clone();
        let (waiter, waker) = Waiter::new_pair();
        drained.enqueue_once(waker.clone());
        let checkpoint = Checkpoint::new(first.cid);
        let release = ReleaseCheckpoint(checkpoint.clone());
        let holder_done = Arc::new(AtomicBool::new(false));
        let holder = {
            let endpoint = endpoint.clone();
            let checkpoint = checkpoint.clone();
            let done = holder_done.clone();
            TaskOptions::new(move || {
                let state = endpoint.lock_state();
                checkpoint.pause();
                drop(state);
                done.store(true, Ordering::Release);
            })
            .data(())
            .spawn()
            .unwrap()
        };
        let held = wait_for(|| checkpoint.entered.load(Ordering::Acquire));
        let reaper_done = Arc::new(AtomicBool::new(false));
        let lifecycle = {
            let switch = first.switch.clone();
            let first_cid = first.cid;
            let second_cid = second.cid;
            let done = reaper_done.clone();
            TaskOptions::new(move || {
                switch.on_dying(first_cid);
                switch.on_dying(second_cid);
                done.store(true, Ordering::Release);
            })
            .data(())
            .spawn()
            .unwrap()
        };
        let returned_before_unlock = wait_for(|| reaper_done.load(Ordering::Acquire));
        let first_still_pending = !first.switch.retired_drained(first.cid);
        let second_revoked_before_unlock = second_endpoint.revoked.load(Ordering::Acquire);
        first.detach_device();
        second.detach_device();
        checkpoint.release();
        let holder_returned = wait_for(|| holder_done.load(Ordering::Acquire));
        let lifecycle_returned = wait_for(|| reaper_done.load(Ordering::Acquire));
        let clean = {
            let state = endpoint.lock_state();
            state.reset
                && state.owner.is_none()
                && state.cleanup.is_none()
                && state.output.capacity() == 0
        };
        let actual_drain_wakeup = !waker.wake_up();
        waiter.wait(); // Consume production wake, or the explicit failing fallback above.
        let count_zero = cleanup.active.load(Ordering::Acquire) == 0;
        let ready = first.switch.retired_drained(first.cid);
        drop((
            file,
            endpoint,
            second_file,
            second_endpoint,
            holder,
            lifecycle,
            release,
        ));
        first.finish();
        second.finish();
        assert!(held && returned_before_unlock && second_revoked_before_unlock);
        assert!(first_still_pending && holder_returned && lifecycle_returned);
        assert!(clean && count_zero && actual_drain_wakeup && ready);
    }

    #[ktest]
    fn last_cleanup_lease_gates_retirement_and_wakes_the_registered_waiter() {
        let mut fixture = Fixture::new();
        let account = fixture.switch.host_endpoint_account(fixture.cid).unwrap();
        let last = account.cleanup.try_clone().unwrap();
        let cleanup = fixture.cleanup();
        drop(account);
        fixture.switch.on_dying(fixture.cid);
        fixture.detach_device();
        let count_one = cleanup.active.load(Ordering::Acquire) == 1;
        let pending = !fixture.switch.retired_drained(fixture.cid);
        let (waiter, waker) = Waiter::new_pair();
        cleanup.drained.enqueue_once(waker.clone());
        drop(last);
        let actual_wakeup = !waker.wake_up();
        waiter.wait();
        let ready = fixture.switch.retired_drained(fixture.cid);
        fixture.finish();
        assert!(count_one && pending && actual_wakeup && ready);
    }

    #[ktest]
    fn failed_connect_refunds_fixed_and_window_resources_before_zero() {
        for reject_host_charge in [false, true] {
            let fixture = Fixture::new();
            let capacity = available_capacity(&fixture.admission);
            let blocker = if reject_host_charge {
                fixture.owner.kill(KillReason::Requested).unwrap();
                None
            } else {
                Some(
                    fixture
                        .admission
                        .reserve_endpoint_bytes(capacity - HOST_ENDPOINT_CHARGE)
                        .unwrap(),
                )
            };
            let expected_capacity = if reject_host_charge {
                capacity
            } else {
                HOST_ENDPOINT_CHARGE
            };
            let cleanup = fixture.cleanup();
            let probe = Arc::new(ZeroProbe {
                cleanup: cleanup.clone(),
                owner: fixture.owner.clone(),
                admission: fixture.admission.clone(),
                expected_host_bytes: fixture.owner.stats().host_bytes_charged,
                expected_capacity,
                observed: AtomicBool::new(false),
                host_refunded: AtomicBool::new(false),
                capacity_refunded: AtomicBool::new(false),
            });
            {
                let mut active = ZERO_PROBE.lock();
                assert!(active.is_none());
                *active = Some(probe.clone());
            }
            let registration = ProbeRegistration;
            let account = fixture.switch.host_endpoint_account(fixture.cid).unwrap();
            let result = HostEndpoint::new_connect(
                fixture.cid,
                49152,
                23456,
                Arc::downgrade(&fixture.switch),
                account,
            );
            let failed = match result {
                Err(error) => error.error() == Errno::ENOMEM,
                Ok(endpoint) => {
                    drop(endpoint);
                    false
                }
            };
            let observed = probe.observed.load(Ordering::Acquire);
            let host_refunded = probe.host_refunded.load(Ordering::Relaxed);
            let capacity_refunded = probe.capacity_refunded.load(Ordering::Relaxed);
            let count_zero = cleanup.active.load(Ordering::Acquire) == 0;
            drop(registration);
            drop(probe);
            drop(blocker);
            fixture.finish();
            assert!(failed && observed && host_refunded && capacity_refunded && count_zero);
        }
    }

    #[ktest]
    fn closing_preparation_holds_a_lease_until_actual_charge_failure_rolls_back() {
        let mut fixture = Fixture::new();
        let (file, endpoint) = fixture.endpoint();
        let cleanup = fixture.cleanup();
        let registration = ClosingRegistration::new(fixture.cid);
        let close_done = Arc::new(AtomicBool::new(false));
        let closer = {
            let done = close_done.clone();
            TaskOptions::new(move || {
                drop(file); // The real last HostEndpointFile Drop enters enqueue.
                done.store(true, Ordering::Release);
            })
            .data(())
            .spawn()
            .unwrap()
        };
        let prepared = wait_for(|| registration.0.barrier.entered.load(Ordering::Acquire));
        let counted_before_reserve = cleanup.active.load(Ordering::Acquire) == 2;
        fixture.switch.on_dying(fixture.cid);
        fixture.detach_device();
        let continuation_counted = cleanup.active.load(Ordering::Acquire) == 1;
        let pending = !fixture.switch.retired_drained(fixture.cid);
        let (waiter, waker) = Waiter::new_pair();
        cleanup.drained.enqueue_once(waker.clone());
        // Use the real Created->Exited transition to reject charge_host_bytes.
        fixture.owner.kill(KillReason::Requested).unwrap();
        registration.0.barrier.release();
        let closed = wait_for(|| close_done.load(Ordering::Acquire));
        let actual_wakeup = !waker.wake_up();
        waiter.wait();
        let ready = fixture.switch.retired_drained(fixture.cid);
        drop((registration, closer, endpoint));
        fixture.finish();
        assert!(prepared && counted_before_reserve && continuation_counted && pending);
        assert!(closed && actual_wakeup && ready);
    }

    #[ktest]
    fn prepared_closing_can_enqueue_after_retirement_and_releases_its_lease() {
        let mut fixture = Fixture::new();
        let (file, endpoint) = fixture.endpoint();
        let cleanup = fixture.cleanup();
        let registration = ClosingRegistration::new(fixture.cid);
        let closed = Arc::new(AtomicBool::new(false));
        let closer = {
            let closed = closed.clone();
            TaskOptions::new(move || {
                drop(file);
                closed.store(true, Ordering::Release);
            })
            .data(())
            .spawn()
            .unwrap()
        };
        let prepared = wait_for(|| registration.0.barrier.entered.load(Ordering::Acquire));
        let prepared_lease = cleanup.active.load(Ordering::Acquire) == 2;
        fixture.switch.on_dying(fixture.cid);
        fixture.detach_device();
        let continuation_counted = cleanup.active.load(Ordering::Acquire) == 1;
        let pending = !fixture.switch.retired_drained(fixture.cid);
        let (waiter, waker) = Waiter::new_pair();
        cleanup.drained.enqueue_once(waker.clone());
        // The owner remains Created: real reservation and Host charge succeed.
        // enqueue() must wake the real CloseWorker even though on_dying's wake
        // happened before this continuation entered its pending queue.
        registration.0.barrier.release();
        let file_drop_returned = wait_for(|| closed.load(Ordering::Acquire));
        let enqueued = wait_for(|| registration.0.enqueued.load(Ordering::Acquire));
        let finished = wait_for(|| registration.0.finished.load(Ordering::Acquire));
        let drained = wait_for(|| cleanup.active.load(Ordering::Acquire) == 0);
        let actual_wakeup = !waker.wake_up();
        waiter.wait();
        let ready = fixture.switch.retired_drained(fixture.cid);
        drop((registration, endpoint, closer));
        fixture.finish();
        assert!(prepared && prepared_lease && continuation_counted && pending);
        assert!(file_drop_returned && enqueued && finished && drained && actual_wakeup && ready);
    }

    fn connect_request(cid: u32, host_port: u32) -> Packet {
        Packet {
            src_cid: HOST_CID,
            dst_cid: cid,
            src_port: host_port,
            dst_port: 23456,
            op: Packet::REQUEST,
            flags: 0,
            buf_alloc: WINDOW as u32,
            fwd_cnt: 0,
            payload: Vec::new(),
            payload_charge: None,
        }
    }

    #[ktest]
    fn reauthorization_does_not_let_an_old_revoke_close_new_connections() {
        // R2-04: pause the old revoke exactly after releasing authorization.
        let a = Fixture::new();
        let b = Fixture::new();
        a.switch.set_peer_allowed(a.cid, b.cid, true).unwrap();
        let request = |port| Packet {
            src_cid: a.cid,
            dst_cid: b.cid,
            src_port: port,
            dst_port: 30002,
            op: Packet::REQUEST,
            flags: 0,
            buf_alloc: WINDOW as u32,
            fwd_cnt: 0,
            payload: Vec::new(),
            payload_charge: None,
        };
        a.switch.route(a.cid, request(30001));
        drop(b.device.as_ref().unwrap().take_inbound_for_ktest().unwrap());
        let checkpoint = Checkpoint::new(a.cid);
        assert!(
            PEER_REVOKE_CHECKPOINT
                .lock()
                .replace(checkpoint.clone())
                .is_none()
        );
        let registration = PeerRevokeRegistration(checkpoint.clone());
        let done = Arc::new(AtomicBool::new(false));
        let task = {
            let switch = a.switch.clone();
            let (a_cid, b_cid) = (a.cid, b.cid);
            let done = done.clone();
            TaskOptions::new(move || {
                switch.set_peer_allowed(a_cid, b_cid, false).unwrap();
                done.store(true, Ordering::Release);
            })
            .data(())
            .spawn()
            .unwrap()
        };
        let paused = wait_for(|| checkpoint.entered.load(Ordering::Acquire));
        a.switch.set_peer_allowed(a.cid, b.cid, true).unwrap();
        a.switch.route(a.cid, request(40001));
        let new_request = b.device.as_ref().unwrap().take_inbound_for_ktest().unwrap();
        checkpoint.release();
        let completed = wait_for(|| done.load(Ordering::Acquire));
        let (old_removed, new_live) = {
            let state = a.switch.state.lock();
            (
                !state.peers.contains_key(&(a.cid, 30001, b.cid, 30002)),
                state
                    .peers
                    .get(&(a.cid, 40001, b.cid, 30002))
                    .is_some_and(|peer| !peer.reference.dead.load(Ordering::Acquire)),
            )
        };
        for cid in [a.cid, b.cid] {
            drop(a.switch.take_notice(cid));
        }
        drop((registration, task));
        a.finish();
        b.finish();
        assert!(paused && completed && old_removed && new_live);
        assert_eq!(new_request.src_port, 40001);
    }

    #[ktest]
    fn full_data_queue_preserves_latest_credit_and_handshake_response() {
        // R2-05: the last read and CREDIT_REQUEST occur while all 64 data
        // slots are occupied; neither may strand the Guest after RX resumes.
        let fixture = Fixture::new();
        let device = fixture.device.as_ref().unwrap().clone();
        let (file, endpoint) = fixture.endpoint();
        for index in 0..64 {
            assert!(
                device
                    .try_enqueue(connect_request(fixture.cid, 49152 + index))
                    .is_ok()
            );
        }
        fill_wrapped_output(&endpoint, &[1, 2, 3, 4]);
        let before = fixture.owner.stats().host_bytes_charged;
        let mut bytes = [0; 4];
        assert_eq!(
            file.read(&mut VmWriter::from(bytes.as_mut_slice()).to_fallible())
                .unwrap(),
            4
        );
        let mut credit_request =
            connect_request(fixture.cid, 12345).reply(Packet::CREDIT_REQUEST, 0, 0);
        credit_request.src_port = 23456;
        fixture.switch.route(fixture.cid, credit_request);
        assert_eq!(fixture.owner.stats().host_bytes_charged, before);
        let listener = fixture
            .switch
            .listen(fixture.cid, 40000, fixture.uid)
            .unwrap();
        let mut request =
            connect_request(fixture.cid, 40000).reply(Packet::REQUEST, WINDOW as u32, 0);
        request.src_port = 23457;
        fixture.switch.route(fixture.cid, request);
        // Even a busy endpoint mutex cannot block the device worker.
        let held = endpoint.lock_state();
        assert_eq!(
            device.take_control_for_ktest().unwrap().op,
            Packet::RESPONSE
        );
        assert!(device.take_control_for_ktest().is_none());
        drop(held);
        drop(device.take_inbound_for_ktest().unwrap());
        let credit = device.take_control_for_ktest().unwrap();
        assert_eq!(credit.op, Packet::CREDIT_UPDATE);
        assert_eq!(credit.fwd_cnt, 4);
        assert_eq!(credit.buf_alloc, WINDOW as u32);
        assert!(device.take_control_for_ktest().is_none());
        while device.take_inbound_for_ktest().is_some() {}
        drop((listener, file, endpoint, device));
        fixture.finish();
        assert_eq!(bytes, [1, 2, 3, 4]);
    }

    #[ktest]
    fn credit_update_follows_older_headers_on_the_same_stream() {
        let fixture = Fixture::new();
        let device = fixture.device.as_ref().unwrap().clone();
        let (file, endpoint) = fixture.endpoint();
        assert_eq!(
            file.write(&mut VmReader::from([9u8].as_slice()).to_fallible())
                .unwrap(),
            1
        );
        fill_wrapped_output(&endpoint, &[1, 2, 3, 4]);
        let mut bytes = [0; 4];
        file.read(&mut VmWriter::from(bytes.as_mut_slice()).to_fallible())
            .unwrap();
        // The fixed pending slot must not reorder fwd_cnt=4 before the
        // already queued RW header with fwd_cnt=0 (R2-05).
        assert!(device.take_control_for_ktest().is_none());
        let data = device.take_inbound_for_ktest().unwrap();
        assert_eq!(data.op, Packet::RW);
        assert_eq!(data.fwd_cnt, 0);
        assert_eq!(data.payload, [9]);
        let credit = device.take_control_for_ktest().unwrap();
        assert_eq!(credit.op, Packet::CREDIT_UPDATE);
        assert_eq!(credit.fwd_cnt, 4);
        drop((data, file, endpoint, device));
        fixture.finish();
    }

    #[ktest]
    fn established_peer_delivery_failure_retires_both_sides_and_refunds_credit() {
        let a = Fixture::new();
        let b = Fixture::new();
        let a_device = a.device.as_ref().unwrap().clone();
        let b_device = b.device.as_ref().unwrap().clone();
        let a_bytes = a.owner.stats().host_bytes_charged;
        let b_bytes = b.owner.stats().host_bytes_charged;
        let a_capacity = available_capacity(&a.admission);
        let b_capacity = available_capacity(&b.admission);
        a.switch.set_peer_allowed(a.cid, b.cid, true).unwrap();
        let make_packet = |src, dst, src_port, dst_port, op| Packet {
            src_cid: src,
            dst_cid: dst,
            src_port,
            dst_port,
            op,
            flags: 0,
            buf_alloc: WINDOW as u32,
            fwd_cnt: 0,
            payload: Vec::new(),
            payload_charge: None,
        };
        a.switch.route(
            a.cid,
            make_packet(a.cid, b.cid, 30001, 30002, Packet::REQUEST),
        );
        assert_eq!(
            b_device.take_inbound_for_ktest().unwrap().op,
            Packet::REQUEST
        );
        a.switch.route(
            b.cid,
            make_packet(b.cid, a.cid, 30002, 30001, Packet::RESPONSE),
        );
        assert_eq!(
            a_device.take_inbound_for_ktest().unwrap().op,
            Packet::RESPONSE
        );
        let key = (a.cid, 30001, b.cid, 30002);
        assert!(a.switch.state.lock().peers[&key].established);
        let stale = a.switch.state.lock().peers[&key].reference.borrow();
        for index in 0..64 {
            assert!(
                b_device
                    .try_enqueue(connect_request(b.cid, 49152 + index))
                    .is_ok()
            );
        }
        let mut data = make_packet(a.cid, b.cid, 30001, 30002, Packet::RW);
        data.prepare_payload(1, a.owner.clone(), a.admission.clone())
            .unwrap();
        a.switch.route(a.cid, data);
        assert!(!a.switch.state.lock().peers.contains_key(&key));
        // Reserved notices bypass the saturated data queue and notify both ends.
        for cid in [a.cid, b.cid] {
            let notice = a.switch.take_notice(cid).unwrap();
            assert_eq!(notice.packet.op, Packet::RST);
            assert_eq!(notice.packet.dst_cid, cid);
            drop(notice);
        }
        while b_device.take_inbound_for_ktest().is_some() {}
        // Deterministically recreate the delivery/reset/reconnect race: the
        // old failed lease must not retire a fresh connection with this tuple.
        a.switch.route(
            a.cid,
            make_packet(a.cid, b.cid, 30001, 30002, Packet::REQUEST),
        );
        assert_eq!(
            b_device.take_inbound_for_ktest().unwrap().op,
            Packet::REQUEST
        );
        a.switch.route(
            b.cid,
            make_packet(b.cid, a.cid, 30002, 30001, Packet::RESPONSE),
        );
        assert_eq!(
            a_device.take_inbound_for_ktest().unwrap().op,
            Packet::RESPONSE
        );
        a.switch.reset_peer(key, &stale);
        assert!(a.switch.state.lock().peers[&key].established);
        a.switch
            .route(a.cid, make_packet(a.cid, b.cid, 30001, 30002, Packet::RST));
        assert_eq!(a.switch.take_notice(b.cid).unwrap().packet.op, Packet::RST);
        drop(stale);
        a.switch.state.lock().prune_retired(a.cid);
        assert_eq!(a.owner.stats().host_bytes_charged, a_bytes);
        assert_eq!(b.owner.stats().host_bytes_charged, b_bytes);
        assert_eq!(available_capacity(&a.admission), a_capacity);
        assert_eq!(available_capacity(&b.admission), b_capacity);
        drop((a_device, b_device));
        a.finish();
        b.finish();
    }

    #[ktest]
    fn connect_enqueue_returns_the_unaccepted_packet_when_capacity_is_full() {
        let fixture = Fixture::new();
        let device = fixture.device.as_ref().unwrap().clone();
        for index in 0..64 {
            assert!(
                device
                    .try_enqueue(connect_request(fixture.cid, 49152 + index))
                    .is_ok()
            );
        }
        let charged = fixture.owner.stats().host_bytes_charged;
        let packet = match device.try_enqueue(connect_request(fixture.cid, 50000)) {
            Err(EnqueueError::Full(packet)) => packet,
            _ => panic!("full receive queue must return the unaccepted request"),
        };
        assert_eq!(packet.src_port, 50000);
        assert_eq!(packet.dst_cid, fixture.cid);
        assert_eq!(packet.op, Packet::REQUEST);
        assert!(packet.payload.is_empty());
        assert_eq!(fixture.owner.stats().host_bytes_charged, charged);
        drop(packet);

        device.cancel();
        match device.try_enqueue(connect_request(fixture.cid, 50001)) {
            Err(EnqueueError::Failed(error)) => assert_eq!(error.error(), Errno::ENODEV),
            _ => panic!("cancelled device must fail rather than wait for capacity"),
        }
        drop(device);
        fixture.finish();
    }

    #[ktest]
    fn connect_enqueue_preserves_endpoint_quota_failure() {
        let fixture = Fixture::new();
        let device = fixture.device.as_ref().unwrap().clone();
        let available = available_capacity(&fixture.admission);
        let reservation = fixture.admission.reserve_endpoint_bytes(available).unwrap();
        let charged = fixture.owner.stats().host_bytes_charged;
        match device.try_enqueue(connect_request(fixture.cid, 50000)) {
            Err(EnqueueError::Failed(error)) => assert_eq!(error.error(), Errno::ENOSPC),
            _ => panic!("quota rejection must not become a queue-space wait"),
        }
        assert_eq!(fixture.owner.stats().host_bytes_charged, charged);
        drop(reservation);
        drop(device);
        fixture.finish();
    }

    #[ktest]
    fn payload_quota_failure_precedes_the_real_allocation() {
        let fixture = Fixture::new();
        let available = available_capacity(&fixture.admission);
        let blocker = fixture.admission.reserve_endpoint_bytes(available).unwrap();
        let before = fixture.owner.stats().host_bytes_charged;
        let mut packet = connect_request(fixture.cid, 50000);
        packet.op = Packet::RW;
        let error = packet
            .prepare_payload(64, fixture.owner.clone(), fixture.admission.clone())
            .unwrap_err();
        assert_eq!(error.error(), Errno::ENOSPC);
        assert_eq!(packet.payload.capacity(), 0);
        assert!(packet.payload_charge.is_none());
        assert_eq!(fixture.owner.stats().host_bytes_charged, before);
        drop((packet, blocker));
        fixture.finish();
    }

    #[ktest]
    fn full_data_packet_keeps_its_real_charge_until_dropped() {
        let fixture = Fixture::new();
        let device = fixture.device.as_ref().unwrap().clone();
        for index in 0..64 {
            assert!(
                device
                    .try_enqueue(connect_request(fixture.cid, 49152 + index))
                    .is_ok()
            );
        }
        let before = fixture.owner.stats().host_bytes_charged;
        let mut packet = connect_request(fixture.cid, 50000);
        packet.op = Packet::RW;
        packet
            .prepare_payload(64, fixture.owner.clone(), fixture.admission.clone())
            .unwrap();
        let charged = fixture.owner.stats().host_bytes_charged;
        assert!(charged > before);
        let packet = match device.try_enqueue(packet) {
            Err(EnqueueError::Full(packet)) => packet,
            _ => panic!("full receive queue must return the owned data packet"),
        };
        assert!(packet.payload_charge.is_some());
        assert_eq!(fixture.owner.stats().host_bytes_charged, charged);
        drop(packet);
        assert_eq!(fixture.owner.stats().host_bytes_charged, before);
        drop(device);
        fixture.finish();
    }

    #[ktest]
    fn full_data_packet_retry_moves_its_charge_without_charging_twice() {
        let fixture = Fixture::new();
        let device = fixture.device.as_ref().unwrap().clone();
        let before = fixture.owner.stats().host_bytes_charged;
        for index in 0..64 {
            assert!(
                device
                    .try_enqueue(connect_request(fixture.cid, 49152 + index))
                    .is_ok()
            );
        }
        let mut packet = connect_request(fixture.cid, 50000);
        packet.op = Packet::RW;
        packet
            .prepare_payload(64, fixture.owner.clone(), fixture.admission.clone())
            .unwrap();
        packet.payload.fill(0x5a);
        let packet = match device.try_enqueue(packet) {
            Err(EnqueueError::Full(packet)) => packet,
            _ => panic!("full receive queue must return the owned data packet"),
        };
        assert!(packet.payload_charge.is_some());
        assert!(packet.payload.iter().all(|byte| *byte == 0x5a));
        drop(device.take_inbound_for_ktest().unwrap());
        let before_retry = fixture.owner.stats().host_bytes_charged;
        assert!(device.try_enqueue(packet).is_ok());
        assert_eq!(fixture.owner.stats().host_bytes_charged, before_retry);
        device.cancel();
        assert_eq!(fixture.owner.stats().host_bytes_charged, before);
        drop(device);
        fixture.finish();
    }

    #[ktest]
    fn cancelled_queue_refunds_a_precharged_data_packet() {
        let fixture = Fixture::new();
        let device = fixture.device.as_ref().unwrap().clone();
        device.cancel();
        let before = fixture.owner.stats().host_bytes_charged;
        let mut packet = connect_request(fixture.cid, 50000);
        packet.op = Packet::RW;
        packet
            .prepare_payload(64, fixture.owner.clone(), fixture.admission.clone())
            .unwrap();
        match device.try_enqueue(packet) {
            Err(EnqueueError::Failed(error)) => assert_eq!(error.error(), Errno::ENODEV),
            _ => panic!("cancelled receive queue must reject data"),
        }
        assert_eq!(fixture.owner.stats().host_bytes_charged, before);
        drop(device);
        fixture.finish();
    }

    fn fill_wrapped_output(endpoint: &HostEndpoint, bytes: &[u8]) {
        assert!(bytes.len() >= 2);
        let mut state = endpoint.lock_state();
        assert!(state.output.is_empty());
        let capacity = state.output.capacity();
        assert!(capacity > bytes.len());
        state.output.extend(core::iter::repeat_n(0, capacity));
        for _ in 0..capacity - 2 {
            state.output.pop_front();
        }
        state.output[0] = bytes[0];
        state.output[1] = bytes[1];
        state.output.extend(bytes[2..].iter().copied());
        state.rx_cnt = bytes.len() as u32;
        let (first, second) = state.output.as_slices();
        assert_eq!(first.len(), 2);
        assert_eq!(second.len(), bytes.len() - 2);
        drop(state);
        endpoint.pollee.notify(IoEvents::IN);
    }

    #[ktest]
    fn endpoint_read_wrapped_output_preserves_order_and_advances_credit() {
        let fixture = Fixture::new();
        let (file, endpoint) = fixture.endpoint();
        let expected = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15];
        fill_wrapped_output(&endpoint, &expected);
        let mut observed = [0u8; 6];
        let copied = file
            .read(&mut VmWriter::from(observed.as_mut_slice()).to_fallible())
            .unwrap();
        assert_eq!(copied, expected.len());
        assert_eq!(observed, expected);
        {
            let state = endpoint.lock_state();
            assert!(state.output.is_empty());
            assert_eq!(state.fwd_cnt, expected.len() as u32);
        }
        drop((file, endpoint));
        fixture.finish();
    }

    #[ktest]
    fn endpoint_read_preserves_zero_writer_and_four_kib_limit() {
        let fixture = Fixture::new();
        let (file, endpoint) = fixture.endpoint();
        let expected: Vec<u8> = (0..4112).map(|at| at as u8).collect();
        fill_wrapped_output(&endpoint, &expected);
        let before = fixture.owner.stats().host_bytes_charged;
        assert_eq!(
            file.read(&mut VmWriter::from([].as_mut_slice()).to_fallible())
                .unwrap(),
            0
        );
        {
            let state = endpoint.lock_state();
            assert_eq!(state.output.len(), expected.len());
            assert_eq!(state.fwd_cnt, 0);
        }
        assert_eq!(fixture.owner.stats().host_bytes_charged, before);
        let mut observed = vec![0u8; 5000];
        let copied = file
            .read(&mut VmWriter::from(observed.as_mut_slice()).to_fallible())
            .unwrap();
        assert_eq!(copied, 4096);
        assert_eq!(&observed[..copied], &expected[..copied]);
        let mut tail = [0u8; 3];
        assert_eq!(
            file.read(&mut VmWriter::from(tail.as_mut_slice()).to_fallible())
                .unwrap(),
            3
        );
        assert_eq!(&tail, &expected[4096..4099]);
        {
            let state = endpoint.lock_state();
            assert_eq!(
                state.output.iter().copied().collect::<Vec<_>>(),
                expected[4099..]
            );
            assert_eq!(state.fwd_cnt, 4099);
        }
        drop((file, endpoint));
        fixture.finish();
    }

    #[ktest]
    fn endpoint_read_second_slice_page_fault_keeps_queue_and_credit() {
        use ostd::mm::{
            CachePolicy, FrameAllocOptions, PAGE_SIZE, PageFlags, PageProperty, VmSpace,
            io::util::HasVmReaderWriter,
        };

        // The core ktest runner has no process fault resolver. An unmapped
        // second page uses OSTD's real fallible-copy fixup, as the existing
        // batch_user_fault_retains_cached_report test does.
        let _ = crate::thread::exception::fault_test::count();
        let fixture = Fixture::new();
        let (file, endpoint) = fixture.endpoint();
        let expected = [0x20, 0x21, 0x22, 0x23, 0x24, 0x25];
        fill_wrapped_output(&endpoint, &expected);
        let before = fixture.owner.stats().host_bytes_charged;
        let frame = FrameAllocOptions::new().alloc_frame_with(()).unwrap();
        let space = Arc::new(VmSpace::new());
        let guard = ostd::task::disable_preempt();
        let base = PAGE_SIZE;
        space
            .cursor_mut(&guard, &(base..base + PAGE_SIZE))
            .unwrap()
            .map(
                frame.clone().into(),
                PageProperty::new_user(PageFlags::RW, CachePolicy::Writeback),
            );
        struct RestoreKernelRoot;
        impl Drop for RestoreKernelRoot {
            fn drop(&mut self) {
                VmSpace::deactivate();
            }
        }
        VmSpace::deactivate();
        let restore = RestoreKernelRoot;
        space.activate();
        // The first deque slice is exactly two bytes at the mapped page's
        // end. The second copy starts at the next, unmapped user page.
        // Fixture has no worker and no competing holder of this mutex.
        let mut writer = space.writer(base + PAGE_SIZE - 2, expected.len()).unwrap();
        let error = file.read(&mut writer).unwrap_err();
        let remaining = writer.avail();
        drop(writer);
        drop(restore);
        drop(guard);
        assert_eq!(error.error(), Errno::EFAULT);
        assert_eq!(remaining, expected.len() - 2);
        let mut observed = [0u8; 2];
        let mut reader = frame.reader();
        reader.skip(PAGE_SIZE - 2);
        assert_eq!(reader.read(&mut VmWriter::from(observed.as_mut_slice())), 2);
        assert_eq!(&observed, &expected[..2]);
        {
            let state = endpoint.lock_state();
            assert_eq!(state.output.iter().copied().collect::<Vec<_>>(), expected);
            assert_eq!(state.fwd_cnt, 0);
        }
        assert_eq!(fixture.owner.stats().host_bytes_charged, before);
        drop(reader);
        drop((frame, space, file, endpoint));
        fixture.finish();
    }

    struct ConnectNotifications(Arc<AtomicUsize>);

    impl Observer<IoEvents> for ConnectNotifications {
        fn on_events(&self, _: &IoEvents) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn pending_connect(
        fixture: &Fixture,
    ) -> (Arc<HostEndpointFile>, Arc<HostEndpoint>, Weak<VirtioVsock>) {
        let account = fixture.switch.host_endpoint_account(fixture.cid).unwrap();
        let identity = account.device.clone();
        let endpoint = HostEndpoint::new_connect(
            fixture.cid,
            50000,
            23456,
            Arc::downgrade(&fixture.switch),
            account,
        )
        .unwrap();
        fixture
            .switch
            .state
            .lock()
            .listeners
            .insert((fixture.cid, 50000), endpoint.clone());
        let file = Arc::new(HostEndpointFile::new(endpoint.clone()));
        file.submit_request(connect_request(fixture.cid, 50000), &identity)
            .unwrap();
        (file, endpoint, identity)
    }

    #[ktest]
    fn zero_credit_response_before_poll_registration_is_connected() {
        let fixture = Fixture::new();
        let (file, endpoint, identity) = pending_connect(&fixture);
        // Force the fast-try/register boundary: pending, then RESPONSE, then poll.
        assert!(endpoint.connect_events().is_empty());
        endpoint.receive(connect_request(fixture.cid, 50000).reply(Packet::RESPONSE, 0, 0));
        let handshake = ConnectHandshake {
            file: &file,
            identity: &identity,
        };
        assert!(
            handshake
                .poll(IoEvents::OUT | IoEvents::ERR, None)
                .contains(IoEvents::OUT)
        );
        assert!(file.wait_connected(&identity).is_ok());
        // Connect readiness must not make ordinary zero-credit writes writable.
        assert!(!file.poll(IoEvents::OUT, None).contains(IoEvents::OUT));
        endpoint.receive(connect_request(fixture.cid, 50000).reply(Packet::RST, 0, 0));
        drop((file, endpoint));
        fixture.finish();
    }

    #[ktest]
    fn zero_credit_response_after_poll_registration_notifies_the_waiter() {
        let fixture = Fixture::new();
        let (file, endpoint, identity) = pending_connect(&fixture);
        let notifications = Arc::new(AtomicUsize::new(0));
        let mut observer = PollAdaptor::with_observer(ConnectNotifications(notifications.clone()));
        let handshake = ConnectHandshake {
            file: &file,
            identity: &identity,
        };
        // Queue capacity alone must not indicate a completed handshake.
        assert!(
            handshake
                .poll(
                    IoEvents::OUT | IoEvents::ERR,
                    Some(observer.as_handle_mut())
                )
                .is_empty()
        );
        endpoint.receive(connect_request(fixture.cid, 50000).reply(Packet::RESPONSE, 0, 0));
        assert_eq!(notifications.load(Ordering::Relaxed), 1);
        assert!(file.wait_connected(&identity).is_ok());
        assert!(!file.poll(IoEvents::OUT, None).contains(IoEvents::OUT));
        endpoint.receive(connect_request(fixture.cid, 50000).reply(Packet::RST, 0, 0));
        drop((observer, file, endpoint));
        fixture.finish();
    }

    #[ktest]
    fn independent_device_cancel_notifies_a_pending_handshake() {
        let fixture = Fixture::new();
        let (file, endpoint, identity) = pending_connect(&fixture);
        let notifications = Arc::new(AtomicUsize::new(0));
        let mut observer = PollAdaptor::with_observer(ConnectNotifications(notifications.clone()));
        let handshake = ConnectHandshake {
            file: &file,
            identity: &identity,
        };
        assert!(
            handshake
                .poll(
                    IoEvents::OUT | IoEvents::ERR,
                    Some(observer.as_handle_mut())
                )
                .is_empty()
        );
        fixture.device.as_ref().unwrap().cancel();
        assert!(!endpoint.revoked.load(Ordering::Acquire));
        assert_eq!(notifications.load(Ordering::Relaxed), 1);
        assert_eq!(
            file.wait_connected(&identity).unwrap_err().error(),
            Errno::ENODEV
        );
        drop((observer, file, endpoint));
        fixture.finish();
    }

    struct ConnectWatch {
        cid: u32,
        port: AtomicU32,
        submission: AtomicBool,
        handshake: AtomicBool,
    }

    static CONNECT_WATCH: SpinLock<Option<Arc<ConnectWatch>>> = SpinLock::new(None);

    struct ConnectRegistration(Arc<ConnectWatch>);

    impl ConnectRegistration {
        fn new(cid: u32) -> Self {
            let watch = Arc::new(ConnectWatch {
                cid,
                port: AtomicU32::new(0),
                submission: AtomicBool::new(false),
                handshake: AtomicBool::new(false),
            });
            let mut current = CONNECT_WATCH.lock();
            assert!(current.is_none());
            *current = Some(watch.clone());
            Self(watch)
        }
    }

    impl Drop for ConnectRegistration {
        fn drop(&mut self) {
            let previous = CONNECT_WATCH.lock().take();
            drop(previous);
        }
    }

    pub(super) fn after_connect_registered(cid: u32, port: u32, handshake: bool) {
        let watch = CONNECT_WATCH.lock().clone();
        if let Some(watch) = watch.filter(|watch| watch.cid == cid) {
            watch.port.store(port, Ordering::Relaxed);
            if handshake {
                watch.handshake.store(true, Ordering::Release);
            } else {
                watch.submission.store(true, Ordering::Release);
            }
        }
    }

    type ConnectResult = Arc<Mutex<Option<Result<Arc<dyn FileLike>>>>>;

    fn spawn_connect(fixture: &Fixture) -> (Arc<Task>, ConnectResult) {
        let result = Arc::new(Mutex::new(None));
        let task = {
            let switch = fixture.switch.clone();
            let cid = fixture.cid;
            let result = result.clone();
            TaskOptions::new(move || {
                let connected = switch.connect(cid, 23456);
                *result.lock() = Some(connected);
            })
            .data(())
            .spawn()
            .unwrap()
        };
        (task, result)
    }

    fn collect_connect(
        fixture: &Fixture,
        result: &ConnectResult,
    ) -> (bool, Result<Arc<dyn FileLike>>) {
        let completed_before_cleanup = wait_for(|| result.lock().is_some());
        if !completed_before_cleanup {
            // Release the failed attempt, retaining the failed causal oracle
            // for the caller to assert after complete fixture teardown.
            fixture.switch.on_dying(fixture.cid);
            fixture.device.as_ref().unwrap().cancel();
            assert!(wait_for(|| result.lock().is_some()));
        }
        let connected = result.lock().take().unwrap();
        (completed_before_cleanup, connected)
    }

    fn watch_endpoint(fixture: &Fixture, watch: &ConnectWatch) -> Option<Arc<HostEndpoint>> {
        let port = watch.port.load(Ordering::Acquire);
        fixture
            .switch
            .state
            .lock()
            .listeners
            .get(&(fixture.cid, port))
            .cloned()
    }

    fn fill_inbound(fixture: &Fixture) {
        for port in 1..=64 {
            assert!(
                fixture
                    .device
                    .as_ref()
                    .unwrap()
                    .try_enqueue(connect_request(fixture.cid, port))
                    .is_ok()
            );
        }
    }

    #[ktest]
    fn full_queue_one_slot_release_wakes_connect_and_enqueues_exactly_one_request() {
        let fixture = Fixture::new();
        fill_inbound(&fixture);
        let registration = ConnectRegistration::new(fixture.cid);
        let (task, result) = spawn_connect(&fixture);
        let registered = wait_for(|| registration.0.submission.load(Ordering::Acquire));
        let pending_before_slot_release = result.lock().is_none();
        let temporary_device_refs_released = wait_for(|| fixture.device_refs.strong_count() == 1);
        let only_endpoint_lease =
            wait_for(|| fixture.cleanup().active.load(Ordering::Acquire) == 1);
        let released = fixture.device.as_ref().unwrap().take_inbound_for_ktest();
        let entered_handshake = wait_for(|| registration.0.handshake.load(Ordering::Acquire));
        let endpoint = watch_endpoint(&fixture, &registration.0);
        let host_port = registration.0.port.load(Ordering::Acquire);
        let mut requests = 0;
        let mut packets = 0;
        while let Some(packet) = fixture.device.as_ref().unwrap().take_inbound_for_ktest() {
            packets += 1;
            if packet.src_cid == HOST_CID
                && packet.src_port == host_port
                && packet.dst_cid == fixture.cid
                && packet.dst_port == 23456
                && packet.op == Packet::REQUEST
            {
                requests += 1;
            }
        }
        if let Some(endpoint) = &endpoint {
            endpoint.receive(connect_request(fixture.cid, host_port).reply(Packet::RESPONSE, 0, 0));
        }
        let (completed_before_cleanup, connected) = collect_connect(&fixture, &result);
        let success = connected.is_ok();
        if let Some(endpoint) = &endpoint {
            endpoint.receive(connect_request(fixture.cid, host_port).reply(Packet::RST, 0, 0));
        }
        drop((connected, endpoint, task, result, registration));
        fixture.finish();
        assert!(
            completed_before_cleanup,
            "connect required cleanup to complete"
        );
        assert!(
            registered
                && pending_before_slot_release
                && temporary_device_refs_released
                && only_endpoint_lease
        );
        assert_eq!(released.unwrap().src_port, 1);
        assert!(entered_handshake && success);
        assert_eq!(packets, 64);
        assert_eq!(requests, 1);
    }

    #[ktest]
    fn queued_request_waits_beyond_two_seconds_for_a_zero_credit_response() {
        let fixture = Fixture::new();
        let registration = ConnectRegistration::new(fixture.cid);
        let (task, result) = spawn_connect(&fixture);
        let registered = wait_for(|| registration.0.handshake.load(Ordering::Acquire));
        let temporary_device_refs_released = wait_for(|| fixture.device_refs.strong_count() == 1);
        let only_endpoint_lease =
            wait_for(|| fixture.cleanup().active.load(Ordering::Acquire) == 1);
        let start = read_monotonic_time();
        let timer = WaitQueue::new();
        let delay = Duration::from_millis(2200);
        let waited = timer.wait_until_or_timeout(|| None::<()>, &delay);
        let elapsed = read_monotonic_time().saturating_sub(start);
        let still_pending = result.lock().is_none();
        let endpoint = watch_endpoint(&fixture, &registration.0);
        let host_port = registration.0.port.load(Ordering::Acquire);
        if let Some(endpoint) = &endpoint {
            endpoint.receive(connect_request(fixture.cid, host_port).reply(Packet::RESPONSE, 0, 0));
        }
        let (completed_before_cleanup, connected) = collect_connect(&fixture, &result);
        let success = connected.is_ok();
        if let Some(endpoint) = &endpoint {
            endpoint.receive(connect_request(fixture.cid, host_port).reply(Packet::RST, 0, 0));
        }
        drop((connected, endpoint, task, result, registration));
        fixture.finish();
        assert!(
            completed_before_cleanup,
            "connect required cleanup to complete"
        );
        assert!(registered && temporary_device_refs_released && only_endpoint_lease);
        assert_eq!(waited.unwrap_err().error(), Errno::ETIME);
        assert!(elapsed > Duration::from_secs(2));
        assert!(still_pending && success);
    }

    fn blocked_connect_is_woken(full: bool, revoke_endpoint: bool) {
        let fixture = Fixture::new();
        if full {
            fill_inbound(&fixture);
        }
        let registration = ConnectRegistration::new(fixture.cid);
        let (task, result) = spawn_connect(&fixture);
        let registered = wait_for(|| {
            if full {
                registration.0.submission.load(Ordering::Acquire)
            } else {
                registration.0.handshake.load(Ordering::Acquire)
            }
        });
        let was_pending = result.lock().is_none();
        let temporary_device_refs_released = wait_for(|| fixture.device_refs.strong_count() == 1);
        let endpoint = watch_endpoint(&fixture, &registration.0);
        let independent = revoke_endpoint
            || endpoint
                .as_ref()
                .is_some_and(|endpoint| !endpoint.revoked.load(Ordering::Acquire));
        if revoke_endpoint {
            if let Some(endpoint) = &endpoint {
                endpoint.revoke();
            }
        } else {
            // No switch on_dying or endpoint revoke: exercise independent cancel.
            fixture.device.as_ref().unwrap().cancel();
        }
        let (completed_before_cleanup, connected) = collect_connect(&fixture, &result);
        let error = match connected {
            Err(error) => Some(error.error()),
            Ok(file) => {
                drop(file);
                None
            }
        };
        drop((endpoint, task, result, registration));
        fixture.finish();
        assert!(
            completed_before_cleanup,
            "connect required cleanup to complete"
        );
        assert!(registered && was_pending && temporary_device_refs_released && independent);
        assert_eq!(
            error,
            Some(if revoke_endpoint {
                Errno::ECONNRESET
            } else {
                Errno::ENODEV
            })
        );
    }

    #[ktest]
    fn independent_device_cancel_wakes_a_full_queue_connect() {
        blocked_connect_is_woken(true, false);
    }

    #[ktest]
    fn independent_device_cancel_wakes_a_response_wait() {
        blocked_connect_is_woken(false, false);
    }

    #[ktest]
    fn endpoint_revoke_wakes_a_full_queue_connect() {
        blocked_connect_is_woken(true, true);
    }

    #[ktest]
    fn endpoint_revoke_wakes_a_response_wait() {
        blocked_connect_is_woken(false, true);
    }

    #[ktest]
    fn connect_packet_quota_failure_returns_enospc_and_refunds_endpoint() {
        let fixture = Fixture::new();
        let capacity = available_capacity(&fixture.admission);
        let baseline_host_bytes = fixture.owner.stats().host_bytes_charged;
        let endpoint_bytes = HOST_ENDPOINT_CHARGE + WINDOW;
        assert!(capacity >= endpoint_bytes);
        let reservation = fixture
            .admission
            .reserve_endpoint_bytes(capacity - endpoint_bytes)
            .unwrap();
        // Leave exactly enough for endpoint activation, but no REQUEST charge.
        let connected = fixture.switch.connect(fixture.cid, 23456);
        let error = match connected {
            Err(error) => error.error(),
            Ok(file) => {
                drop(file);
                panic!("connect without packet quota succeeded");
            }
        };
        let charges_refunded = fixture.owner.stats().host_bytes_charged == baseline_host_bytes;
        let endpoint_capacity_refunded = available_capacity(&fixture.admission) == endpoint_bytes;
        let no_listener = !fixture
            .switch
            .state
            .lock()
            .listeners
            .keys()
            .any(|(cid, _)| *cid == fixture.cid);
        let no_temporary_lease = fixture.cleanup().active.load(Ordering::Acquire) == 0;
        drop(reservation);
        let all_capacity_refunded = available_capacity(&fixture.admission) == capacity;
        fixture.finish();
        assert_eq!(error, Errno::ENOSPC);
        assert!(
            charges_refunded
                && endpoint_capacity_refunded
                && no_listener
                && no_temporary_lease
                && all_capacity_refunded
        );
    }
}
