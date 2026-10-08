// SPDX-License-Identifier: MPL-2.0

//! CID-scoped virtio-vsock switch and Host stream endpoints.
//!
//! Device threads route copied packets here. The switch owns CID policy,
//! connection credit, and endpoint lookup; no guest memory address is stored.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use ostd::{kernelet::control::Kernelet, sync::WaitQueue};
use spin::Once;

use super::{
    policy::{Admission, EndpointReservation},
    virtio_vsock::{PacketCharge, QueuedPacket, VirtioVsock},
};
use crate::{fs::file::FileLike, prelude::*, process::Uid};

mod endpoint;
mod packet;

use endpoint::{HostEndpoint, HostEndpointFile};
pub(super) use packet::Packet;

const HOST_CID: u32 = 2;
const WINDOW: usize = 64 * 1024;
const MAX_PAYLOAD: usize = 4096 - Packet::HEADER_LEN;
const MAX_CONNECTIONS_PER_CID: usize = 256;
const CONNECTION_CHARGE: usize = size_of::<PeerConnection>() + 128;
const NOTICE_CHARGE: usize = size_of::<QueuedPacket>() + 32;
const NOTICE_QUEUE_CHARGE: usize = size_of::<QueuedPacket>() * MAX_CONNECTIONS_PER_CID;
const RETIRE_QUEUE_CHARGE: usize = size_of::<Arc<PeerRef>>() * MAX_CONNECTIONS_PER_CID;
const PEER_REF_CHARGE: usize = size_of::<PeerRef>() + 32;

struct SwitchState {
    devices: BTreeMap<u32, Weak<VirtioVsock>>,
    notices: BTreeMap<u32, NoticeQueue>,
    retired: BTreeMap<u32, RetireQueue>,
    listeners: BTreeMap<(u32, u32), Arc<HostEndpoint>>,
    /// CID pairs are denied unless the owner of both sandbox descriptors
    /// explicitly opens the pair through policy.
    allowed_pairs: BTreeSet<(u32, u32)>,
    /// Guest-to-guest connections, keyed in the direction of the request.
    peers: BTreeMap<(u32, u32, u32, u32), PeerConnection>,
}

impl SwitchState {
    fn enqueue_notice(
        &mut self,
        packet: Packet,
        charge: Arc<PacketCharge>,
    ) -> core::result::Result<(), QueuedPacket> {
        let queued = QueuedPacket {
            packet,
            charge,
            switch_ref: None,
        };
        let Some(queue) = self.notices.get_mut(&queued.packet.dst_cid) else {
            return Err(queued);
        };
        if queue.pending.len() == MAX_CONNECTIONS_PER_CID {
            return Err(queued);
        }
        queue.pending.push_back(queued);
        Ok(())
    }

    fn retire(&mut self, connection: &PeerConnection) {
        for cid in [connection.reference.a, connection.reference.b] {
            let queue = self.retired.get_mut(&cid).unwrap();
            debug_assert!(queue.pending.len() < MAX_CONNECTIONS_PER_CID);
            queue.pending.push_back(connection.reference.clone());
        }
    }

    fn prune_retired(&mut self, cid: u32) {
        let mut index = 0;
        while let Some(reference) = self
            .retired
            .get(&cid)
            .and_then(|queue| queue.pending.get(index))
        {
            if reference.borrowed.load(Ordering::Acquire) != 0 {
                index += 1;
                continue;
            }
            let reference = self
                .retired
                .get_mut(&cid)
                .unwrap()
                .pending
                .remove(index)
                .unwrap();
            if let Some(peer) = self.retired.get_mut(&reference.other(cid)) {
                peer.pending.retain(|other| !Arc::ptr_eq(other, &reference));
            }
            drop(reference);
        }
    }
}

struct PeerConnection {
    a_owner: Arc<Kernelet>,
    b_owner: Arc<Kernelet>,
    _a_reservation: EndpointReservation,
    _b_reservation: EndpointReservation,
    a_notice: Option<Arc<PacketCharge>>,
    b_notice: Option<Arc<PacketCharge>>,
    reference: Arc<PeerRef>,
    established: bool,
    a_alloc: u32,
    b_alloc: u32,
    a_fwd: u32,
    b_fwd: u32,
    a_sent: u32,
    b_sent: u32,
}

struct PeerRef {
    a: u32,
    b: u32,
    a_owner: Arc<Kernelet>,
    b_owner: Arc<Kernelet>,
    _a_reservation: EndpointReservation,
    _b_reservation: EndpointReservation,
    a_drained: Arc<WaitQueue>,
    b_drained: Arc<WaitQueue>,
    dead: AtomicBool,
    borrowed: AtomicUsize,
}

impl PeerRef {
    fn new(
        a: u32,
        b: u32,
        source: &VirtioVsock,
        destination: &VirtioVsock,
        a_drained: Arc<WaitQueue>,
        b_drained: Arc<WaitQueue>,
    ) -> Option<Arc<Self>> {
        let a_owner = source.account_owner();
        let b_owner = destination.account_owner();
        let a_admission = source.account_admission();
        let b_admission = destination.account_admission();
        let a_reservation = a_admission.reserve_endpoint_bytes(PEER_REF_CHARGE).ok()?;
        let b_reservation = b_admission.reserve_endpoint_bytes(PEER_REF_CHARGE).ok()?;
        a_owner.charge_host_bytes(PEER_REF_CHARGE).ok()?;
        if b_owner.charge_host_bytes(PEER_REF_CHARGE).is_err() {
            a_owner.uncharge_host_bytes(PEER_REF_CHARGE);
            return None;
        }
        Some(Arc::new(Self {
            a,
            b,
            a_owner,
            b_owner,
            _a_reservation: a_reservation,
            _b_reservation: b_reservation,
            a_drained,
            b_drained,
            dead: AtomicBool::new(false),
            borrowed: AtomicUsize::new(0),
        }))
    }

    fn borrow(self: &Arc<Self>) -> SwitchRef {
        self.borrowed.fetch_add(1, Ordering::AcqRel);
        SwitchRef(self.clone())
    }

    fn other(&self, cid: u32) -> u32 {
        if self.a == cid { self.b } else { self.a }
    }
}

impl Drop for PeerRef {
    fn drop(&mut self) {
        self.a_owner.uncharge_host_bytes(PEER_REF_CHARGE);
        self.b_owner.uncharge_host_bytes(PEER_REF_CHARGE);
    }
}

pub(super) struct SwitchRef(Arc<PeerRef>);

impl Clone for SwitchRef {
    fn clone(&self) -> Self {
        self.0.borrowed.fetch_add(1, Ordering::AcqRel);
        Self(self.0.clone())
    }
}

impl Drop for SwitchRef {
    fn drop(&mut self) {
        if self.0.borrowed.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.a_drained.wake_all();
            self.0.b_drained.wake_all();
        }
    }
}

struct RetireQueue {
    owner: Arc<Kernelet>,
    _reservation: EndpointReservation,
    pending: VecDeque<Arc<PeerRef>>,
    drained: Arc<WaitQueue>,
}

impl RetireQueue {
    fn new(owner: Arc<Kernelet>, admission: Arc<Admission>) -> Option<Self> {
        let reservation = admission.reserve_endpoint_bytes(RETIRE_QUEUE_CHARGE).ok()?;
        owner.charge_host_bytes(RETIRE_QUEUE_CHARGE).ok()?;
        Some(Self {
            owner,
            _reservation: reservation,
            pending: VecDeque::with_capacity(MAX_CONNECTIONS_PER_CID),
            drained: Arc::new(WaitQueue::new()),
        })
    }
}

impl Drop for RetireQueue {
    fn drop(&mut self) {
        self.owner.uncharge_host_bytes(RETIRE_QUEUE_CHARGE);
    }
}

struct NoticeQueue {
    owner: Arc<Kernelet>,
    _reservation: EndpointReservation,
    pending: VecDeque<QueuedPacket>,
}

impl NoticeQueue {
    fn new(owner: Arc<Kernelet>, admission: Arc<Admission>) -> Option<Self> {
        let reservation = admission.reserve_endpoint_bytes(NOTICE_QUEUE_CHARGE).ok()?;
        owner.charge_host_bytes(NOTICE_QUEUE_CHARGE).ok()?;
        Some(Self {
            owner,
            _reservation: reservation,
            pending: VecDeque::with_capacity(MAX_CONNECTIONS_PER_CID),
        })
    }
}

impl Drop for NoticeQueue {
    fn drop(&mut self) {
        self.owner.uncharge_host_bytes(NOTICE_QUEUE_CHARGE);
    }
}

impl Drop for PeerConnection {
    fn drop(&mut self) {
        self.a_owner.uncharge_host_bytes(CONNECTION_CHARGE);
        self.b_owner.uncharge_host_bytes(CONNECTION_CHARGE);
    }
}

impl PeerConnection {
    fn accept(&mut self, packet: &Packet, from_a: bool) -> bool {
        if from_a {
            self.a_alloc = packet.buf_alloc;
            self.a_fwd = packet.fwd_cnt;
        } else {
            self.b_alloc = packet.buf_alloc;
            self.b_fwd = packet.fwd_cnt;
        }
        match packet.op {
            Packet::RESPONSE if !from_a && !self.established => {
                self.established = true;
                true
            }
            Packet::RW if self.established => {
                let (sent, receiver_fwd, receiver_alloc) = if from_a {
                    (&mut self.a_sent, self.b_fwd, self.b_alloc)
                } else {
                    (&mut self.b_sent, self.a_fwd, self.a_alloc)
                };
                let pending = sent.wrapping_sub(receiver_fwd);
                let Some(next) = pending.checked_add(packet.payload.len() as u32) else {
                    return false;
                };
                if next > receiver_alloc {
                    return false;
                }
                *sent = sent.wrapping_add(packet.payload.len() as u32);
                true
            }
            Packet::RST | Packet::SHUTDOWN | Packet::CREDIT_UPDATE | Packet::CREDIT_REQUEST => true,
            _ => false,
        }
    }
}

/// The Host owns routing identities and never retains a guest pointer.
pub(super) struct VsockSwitch {
    state: SpinLock<SwitchState>,
}

static SWITCH: Once<Arc<VsockSwitch>> = Once::new();
static NEXT_HOST_PORT: AtomicU32 = AtomicU32::new(49152);

impl VsockSwitch {
    pub(super) fn global() -> Arc<Self> {
        SWITCH
            .call_once(|| {
                Arc::new(Self {
                    state: SpinLock::new(SwitchState {
                        devices: BTreeMap::new(),
                        notices: BTreeMap::new(),
                        retired: BTreeMap::new(),
                        listeners: BTreeMap::new(),
                        allowed_pairs: BTreeSet::new(),
                        peers: BTreeMap::new(),
                    }),
                })
            })
            .clone()
    }

    pub(super) fn register(&self, cid: u32, device: &Arc<VirtioVsock>) -> Result<()> {
        let Some(notices) = NoticeQueue::new(device.account_owner(), device.account_admission())
        else {
            return_errno_with_message!(Errno::ENOMEM, "cannot reserve vsock notice queue");
        };
        let Some(retired) = RetireQueue::new(device.account_owner(), device.account_admission())
        else {
            return_errno_with_message!(Errno::ENOMEM, "cannot reserve vsock retire queue");
        };
        let mut state = self.state.lock();
        if state.devices.contains_key(&cid) {
            return_errno_with_message!(Errno::EEXIST, "vsock CID already registered");
        }
        state.devices.insert(cid, Arc::downgrade(device));
        state.notices.insert(cid, notices);
        state.retired.insert(cid, retired);
        Ok(())
    }

    pub(super) fn take_notice(&self, cid: u32) -> Option<QueuedPacket> {
        self.state.lock().notices.get_mut(&cid)?.pending.pop_front()
    }

    pub(super) fn retire_wait_queue(&self, cid: u32) -> Option<Arc<WaitQueue>> {
        self.state
            .lock()
            .retired
            .get(&cid)
            .map(|queue| queue.drained.clone())
    }

    fn wake_notice(&self, cid: u32) {
        if let Some(device) = self.device(cid) {
            device.wake_notice();
        }
    }

    fn device(&self, cid: u32) -> Option<Arc<VirtioVsock>> {
        self.state.lock().devices.get(&cid)?.upgrade()
    }

    pub(super) fn charge_account(
        &self,
        source: u32,
        receiver: &VirtioVsock,
    ) -> (Arc<Kernelet>, Arc<Admission>) {
        if source == HOST_CID {
            return (receiver.account_owner(), receiver.account_admission());
        }
        self.device(source).map_or_else(
            || (receiver.account_owner(), receiver.account_admission()),
            |device| (device.account_owner(), device.account_admission()),
        )
    }

    pub(super) fn set_peer_allowed(&self, a: u32, b: u32, allowed: bool) -> Result<()> {
        if a < 3 || b < 3 || a == b {
            return_errno_with_message!(Errno::EINVAL, "invalid vsock peer pair");
        }
        let pair = ordered_pair(a, b);
        let mut state = self.state.lock();
        if !state.devices.contains_key(&a) || !state.devices.contains_key(&b) {
            return_errno_with_message!(Errno::ENODEV, "vsock peer is not live");
        }
        if allowed {
            state.allowed_pairs.insert(pair);
            return Ok(());
        }
        state.allowed_pairs.remove(&pair);
        drop(state);
        loop {
            let reset_pair = {
                let mut state = self.state.lock();
                let key = state
                    .peers
                    .keys()
                    .find(|(src, _, dst, _)| ordered_pair(*src, *dst) == pair)
                    .copied();
                key.map(|(src, src_port, dst, dst_port)| {
                    let mut retired = state.peers.remove(&(src, src_port, dst, dst_port)).unwrap();
                    retired.reference.dead.store(true, Ordering::Release);
                    state.retire(&retired);
                    let forward = Packet {
                        src_cid: src,
                        dst_cid: dst,
                        src_port,
                        dst_port,
                        op: Packet::RST,
                        flags: 0,
                        buf_alloc: 0,
                        fwd_cnt: 0,
                        payload: Vec::new(),
                    };
                    let reverse = forward.reply(Packet::RST, 0, 0);
                    let failed_forward = state
                        .enqueue_notice(forward, retired.b_notice.take().unwrap())
                        .err();
                    let failed_reverse = state
                        .enqueue_notice(reverse, retired.a_notice.take().unwrap())
                        .err();
                    (src, dst, failed_forward, failed_reverse, retired)
                })
            };
            let Some((src, dst, failed_forward, failed_reverse, retired)) = reset_pair else {
                break;
            };
            drop(failed_forward);
            drop(failed_reverse);
            drop(retired);
            self.wake_notice(src);
            self.wake_notice(dst);
        }
        Ok(())
    }

    pub(super) fn listen(
        self: &Arc<Self>,
        cid: u32,
        port: u32,
        owner: Uid,
    ) -> Result<Arc<dyn FileLike>> {
        if cid < 3 || port == 0 {
            return_errno_with_message!(Errno::EINVAL, "invalid vsock listener");
        }
        // The runtime must install its agent listener before START. The
        // sandbox ioctl has already verified that this CID owns an attached
        // vsock device; the device enters this switch when START constructs
        // the model. No packet can reach this listener until then.
        let endpoint = HostEndpoint::new_listener(cid, port, Arc::downgrade(self), owner)?;
        let mut state = self.state.lock();
        state.prune_retired(cid);
        if state.listeners.contains_key(&(cid, port)) {
            return_errno_with_message!(Errno::EADDRINUSE, "vsock port already listening");
        }
        if state
            .listeners
            .keys()
            .filter(|(owner, _)| *owner == cid)
            .count()
            + state
                .peers
                .keys()
                .filter(|(src, _, dst, _)| *src == cid || *dst == cid)
                .count()
            + state
                .notices
                .get(&cid)
                .map_or(0, |queue| queue.pending.len())
            + state
                .retired
                .get(&cid)
                .map_or(0, |queue| queue.pending.len())
            >= MAX_CONNECTIONS_PER_CID
        {
            return_errno_with_message!(Errno::ENOSPC, "vsock connection limit reached");
        }
        state.listeners.insert((cid, port), endpoint.clone());
        Ok(Arc::new(HostEndpointFile::new(endpoint)))
    }

    pub(super) fn connect(self: &Arc<Self>, cid: u32, port: u32) -> Result<Arc<dyn FileLike>> {
        if cid < 3 || port == 0 {
            return_errno_with_message!(Errno::EINVAL, "invalid vsock destination");
        }
        let device = self.device(cid).ok_or_else(|| {
            Error::with_message(Errno::ENODEV, "kernelet vsock device unavailable")
        })?;
        let host_port = NEXT_HOST_PORT
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                (next < u32::MAX).then_some(next + 1)
            })
            .map_err(|_| Error::with_message(Errno::ENOSPC, "Host vsock port space exhausted"))?;
        let endpoint = HostEndpoint::new_connect(
            cid,
            host_port,
            port,
            Arc::downgrade(self),
            device.account_admission(),
        )?;
        {
            let mut state = self.state.lock();
            state.prune_retired(cid);
            if state.listeners.contains_key(&(cid, host_port)) {
                return_errno_with_message!(Errno::EADDRINUSE, "Host vsock port already used");
            }
            if state
                .listeners
                .keys()
                .filter(|(owner, _)| *owner == cid)
                .count()
                + state
                    .peers
                    .keys()
                    .filter(|(src, _, dst, _)| *src == cid || *dst == cid)
                    .count()
                + state
                    .notices
                    .get(&cid)
                    .map_or(0, |queue| queue.pending.len())
                + state
                    .retired
                    .get(&cid)
                    .map_or(0, |queue| queue.pending.len())
                >= MAX_CONNECTIONS_PER_CID
            {
                return_errno_with_message!(Errno::ENOSPC, "vsock connection limit reached");
            }
            state.listeners.insert((cid, host_port), endpoint.clone());
        }
        let file = Arc::new(HostEndpointFile::new(endpoint));
        let request = Packet {
            src_cid: HOST_CID,
            dst_cid: cid,
            src_port: host_port,
            dst_port: port,
            op: Packet::REQUEST,
            flags: 0,
            buf_alloc: WINDOW as u32,
            fwd_cnt: 0,
            payload: Vec::new(),
        };
        if !self.deliver(request) {
            return_errno_with_message!(Errno::EAGAIN, "kernelet vsock receive queue full");
        }
        let connected = file.wait_connected();
        if let Err(error) = connected {
            if error.error() == Errno::ETIME {
                return_errno_with_message!(Errno::ETIMEDOUT, "vsock connection timed out");
            }
            return Err(error);
        }
        Ok(file)
    }

    /// Routes one guest packet. The sender CID is authoritative even if its
    /// guest wrote a forged source CID in the header.
    pub(super) fn route(&self, sender: u32, mut packet: Packet) {
        packet.src_cid = sender;
        packet.buf_alloc = packet.buf_alloc.min(WINDOW as u32);
        if packet.dst_cid == HOST_CID {
            self.route_host(packet);
            return;
        }
        if packet.dst_cid < 3 || packet.dst_cid == sender {
            self.reset_sender(&packet);
            return;
        }
        let pair = ordered_pair(sender, packet.dst_cid);
        let allowed = self.state.lock().allowed_pairs.contains(&pair);
        if !allowed {
            self.reset_sender(&packet);
            return;
        }
        if packet.op == Packet::RST {
            self.route_reset(packet);
            return;
        }
        let destination = self.device(packet.dst_cid);
        if let Some(device) = destination {
            let mut prepared = if packet.op == Packet::REQUEST {
                let Some(source) = self.device(sender) else {
                    self.reset_sender(&packet);
                    return;
                };
                let a_owner = source.account_owner();
                let b_owner = device.account_owner();
                let a_admission = source.account_admission();
                let b_admission = device.account_admission();
                let (Some(a_drained), Some(b_drained)) = (
                    self.retire_wait_queue(sender),
                    self.retire_wait_queue(packet.dst_cid),
                ) else {
                    self.reset_sender(&packet);
                    return;
                };
                let Ok(a_reservation) = a_admission.reserve_endpoint_bytes(CONNECTION_CHARGE)
                else {
                    self.reset_sender(&packet);
                    return;
                };
                let Ok(b_reservation) = b_admission.reserve_endpoint_bytes(CONNECTION_CHARGE)
                else {
                    self.reset_sender(&packet);
                    return;
                };
                if a_owner.charge_host_bytes(CONNECTION_CHARGE).is_err() {
                    self.reset_sender(&packet);
                    return;
                }
                if b_owner.charge_host_bytes(CONNECTION_CHARGE).is_err() {
                    a_owner.uncharge_host_bytes(CONNECTION_CHARGE);
                    self.reset_sender(&packet);
                    return;
                }
                let Some(a_notice) =
                    PacketCharge::reserve(a_owner.clone(), a_admission.clone(), NOTICE_CHARGE)
                else {
                    a_owner.uncharge_host_bytes(CONNECTION_CHARGE);
                    b_owner.uncharge_host_bytes(CONNECTION_CHARGE);
                    self.reset_sender(&packet);
                    return;
                };
                let Some(b_notice) =
                    PacketCharge::reserve(b_owner.clone(), b_admission.clone(), NOTICE_CHARGE)
                else {
                    drop(a_notice);
                    a_owner.uncharge_host_bytes(CONNECTION_CHARGE);
                    b_owner.uncharge_host_bytes(CONNECTION_CHARGE);
                    self.reset_sender(&packet);
                    return;
                };
                let Some(reference) = PeerRef::new(
                    sender,
                    packet.dst_cid,
                    &source,
                    &device,
                    a_drained,
                    b_drained,
                ) else {
                    drop(a_notice);
                    drop(b_notice);
                    a_owner.uncharge_host_bytes(CONNECTION_CHARGE);
                    b_owner.uncharge_host_bytes(CONNECTION_CHARGE);
                    self.reset_sender(&packet);
                    return;
                };
                Some(PeerConnection {
                    a_owner,
                    b_owner,
                    _a_reservation: a_reservation,
                    _b_reservation: b_reservation,
                    a_notice: Some(a_notice),
                    b_notice: Some(b_notice),
                    reference,
                    established: false,
                    a_alloc: packet.buf_alloc,
                    b_alloc: 0,
                    a_fwd: packet.fwd_cnt,
                    b_fwd: 0,
                    a_sent: 0,
                    b_sent: 0,
                })
            } else {
                None
            };
            let key = (sender, packet.src_port, packet.dst_cid, packet.dst_port);
            let reverse = (packet.dst_cid, packet.dst_port, sender, packet.src_port);
            let (admitted, retired, reference) = {
                let mut state = self.state.lock();
                if !state.allowed_pairs.contains(&pair)
                    || !state.devices.contains_key(&sender)
                    || !state.devices.contains_key(&packet.dst_cid)
                {
                    (false, None, None)
                } else if packet.op == Packet::REQUEST {
                    state.prune_retired(sender);
                    state.prune_retired(packet.dst_cid);
                    let count_for = |cid| {
                        state
                            .listeners
                            .keys()
                            .filter(|(owner, _)| *owner == cid)
                            .count()
                            + state
                                .peers
                                .keys()
                                .filter(|(src, _, dst, _)| *src == cid || *dst == cid)
                                .count()
                            + state
                                .notices
                                .get(&cid)
                                .map_or(0, |queue| queue.pending.len())
                            + state
                                .retired
                                .get(&cid)
                                .map_or(0, |queue| queue.pending.len())
                    };
                    if state.peers.contains_key(&key)
                        || state.peers.contains_key(&reverse)
                        || count_for(sender) >= MAX_CONNECTIONS_PER_CID
                        || count_for(packet.dst_cid) >= MAX_CONNECTIONS_PER_CID
                    {
                        (false, None, None)
                    } else {
                        state.peers.insert(key, prepared.take().unwrap());
                        let reference = state.peers.get(&key).unwrap().reference.borrow();
                        (true, None, Some(reference))
                    }
                } else {
                    let (connection_key, from_a) = if state.peers.contains_key(&key) {
                        (key, true)
                    } else {
                        (reverse, false)
                    };
                    let accepted = state
                        .peers
                        .get_mut(&connection_key)
                        .is_some_and(|connection| connection.accept(&packet, from_a));
                    let reference = accepted
                        .then(|| state.peers.get(&connection_key).unwrap().reference.borrow());
                    let retired = if !accepted {
                        let retired = state.peers.remove(&connection_key);
                        if let Some(connection) = &retired {
                            if !accepted {
                                connection.reference.dead.store(true, Ordering::Release);
                            }
                            state.retire(connection);
                        }
                        retired
                    } else {
                        None
                    };
                    (accepted, retired, reference)
                }
            };
            drop(retired);
            drop(prepared);
            if !admitted {
                self.reset_sender(&packet);
                return;
            }
            let reset = (packet.op != Packet::RST).then(|| packet.reply(Packet::RST, 0, 0));
            let op = packet.op;
            if !device.enqueue_with_ref(packet, reference) {
                if op == Packet::REQUEST {
                    let retired = {
                        let mut state = self.state.lock();
                        let retired = state.peers.remove(&key);
                        if let Some(connection) = &retired {
                            connection.reference.dead.store(true, Ordering::Release);
                            state.retire(connection);
                        }
                        retired
                    };
                    drop(retired);
                }
                if let Some(reset) = reset {
                    let _ = self.deliver(reset);
                }
            }
        } else {
            self.reset_sender(&packet);
        }
    }

    fn route_host(&self, packet: Packet) {
        let endpoint = self
            .state
            .lock()
            .listeners
            .get(&(packet.src_cid, packet.dst_port))
            .cloned();
        let Some(endpoint) = endpoint else {
            self.reset_sender(&packet);
            return;
        };
        if let Some(response) = endpoint.receive(packet) {
            let _ = self.deliver(response);
        }
    }

    fn route_reset(&self, packet: Packet) {
        let destination = packet.dst_cid;
        let key = (
            packet.src_cid,
            packet.src_port,
            packet.dst_cid,
            packet.dst_port,
        );
        let reverse = (
            packet.dst_cid,
            packet.dst_port,
            packet.src_cid,
            packet.src_port,
        );
        let (queued, retired) = {
            let mut state = self.state.lock();
            if !state.devices.contains_key(&packet.src_cid)
                || !state.devices.contains_key(&packet.dst_cid)
                || !state
                    .allowed_pairs
                    .contains(&ordered_pair(packet.src_cid, packet.dst_cid))
            {
                return;
            }
            let (connection_key, from_a) = if state.peers.contains_key(&key) {
                (key, true)
            } else {
                (reverse, false)
            };
            let Some(mut retired) = state.peers.remove(&connection_key) else {
                return;
            };
            let charge = if from_a {
                retired.b_notice.take().unwrap()
            } else {
                retired.a_notice.take().unwrap()
            };
            retired.reference.dead.store(true, Ordering::Release);
            state.retire(&retired);
            let queued = state.enqueue_notice(packet, charge);
            (queued, retired)
        };
        // Reset admission exchanged one live connection slot for one
        // pre-reserved notice slot, so a full queue violates the bound.
        debug_assert!(queued.is_ok());
        drop(queued);
        drop(retired);
        self.wake_notice(destination);
    }

    pub(super) fn deliver(&self, packet: Packet) -> bool {
        self.device(packet.dst_cid)
            .is_some_and(|device| device.enqueue(packet))
    }

    /// Rechecks a queued peer packet when a receiver is about to publish it.
    /// Host-originated packets and reset notices are independent of the
    /// sender's liveness; other peer data needs a live, permitted connection.
    pub(super) fn delivery_live(&self, packet: &Packet, reference: Option<&SwitchRef>) -> bool {
        if packet.src_cid == HOST_CID || packet.op == Packet::RST {
            return true;
        }
        if reference.is_some_and(|reference| reference.0.dead.load(Ordering::Acquire)) {
            return false;
        }
        let state = self.state.lock();
        if !state.devices.contains_key(&packet.src_cid)
            || !state
                .allowed_pairs
                .contains(&ordered_pair(packet.src_cid, packet.dst_cid))
        {
            return false;
        }
        let key = (
            packet.src_cid,
            packet.src_port,
            packet.dst_cid,
            packet.dst_port,
        );
        let reverse = (
            packet.dst_cid,
            packet.dst_port,
            packet.src_cid,
            packet.src_port,
        );
        state.peers.contains_key(&key)
            || state.peers.contains_key(&reverse)
            || reference.is_some_and(|reference| {
                reference.0.a == packet.src_cid && reference.0.b == packet.dst_cid
                    || reference.0.a == packet.dst_cid && reference.0.b == packet.src_cid
            })
    }

    fn reset_sender(&self, packet: &Packet) {
        if packet.op != Packet::RST {
            let _ = self.deliver(packet.reply(Packet::RST, 0, 0));
        }
    }

    pub(super) fn remove_listener(&self, cid: u32, port: u32) {
        self.state.lock().listeners.remove(&(cid, port));
    }

    fn remove_listener_if(&self, cid: u32, port: u32, endpoint: &Arc<HostEndpoint>) {
        let retired = {
            let mut state = self.state.lock();
            state
                .listeners
                .get(&(cid, port))
                .is_some_and(|current| Arc::ptr_eq(current, endpoint))
                .then(|| state.listeners.remove(&(cid, port)))
                .flatten()
        };
        drop(retired);
    }

    pub(super) fn on_dying(&self, cid: u32) {
        let discarded = {
            let mut state = self.state.lock();
            state.devices.remove(&cid);
            state.allowed_pairs.retain(|(a, b)| *a != cid && *b != cid);
            if let Some(queue) = state.retired.get(&cid) {
                for reference in &queue.pending {
                    reference.dead.store(true, Ordering::Release);
                }
            }
            state.notices.remove(&cid)
        };
        drop(discarded);
        let mut retired_index = 0;
        loop {
            let peer = {
                let state = self.state.lock();
                state
                    .retired
                    .get(&cid)
                    .and_then(|queue| queue.pending.get(retired_index))
                    .map(|reference| reference.other(cid))
            };
            let Some(peer) = peer else { break };
            self.wake_notice(peer);
            retired_index += 1;
        }
        // Detach one entry per lock acquisition. Neither peer-device locks
        // nor allocations are needed while the switch lock is held.
        loop {
            let notice = {
                let mut state = self.state.lock();
                let key = state
                    .peers
                    .keys()
                    .find(|(a, _, b, _)| *a == cid || *b == cid)
                    .copied();
                key.map(|(a, a_port, b, b_port)| {
                    let mut retired = state.peers.remove(&(a, a_port, b, b_port)).unwrap();
                    retired.reference.dead.store(true, Ordering::Release);
                    state.retire(&retired);
                    let (dst_cid, src_port, dst_port, charge) = if a == cid {
                        (b, a_port, b_port, retired.b_notice.take().unwrap())
                    } else {
                        (a, b_port, a_port, retired.a_notice.take().unwrap())
                    };
                    let notice = Packet {
                        src_cid: cid,
                        dst_cid,
                        src_port,
                        dst_port,
                        op: Packet::RST,
                        flags: 0,
                        buf_alloc: 0,
                        fwd_cnt: 0,
                        payload: Vec::new(),
                    };
                    let failed_notice = state.enqueue_notice(notice, charge).err();
                    (dst_cid, failed_notice, retired)
                })
            };
            let Some((dst_cid, failed_notice, retired)) = notice else {
                break;
            };
            drop(failed_notice);
            drop(retired);
            self.wake_notice(dst_cid);
        }
        loop {
            let endpoint = {
                let mut state = self.state.lock();
                let key = state
                    .listeners
                    .keys()
                    .find(|(owner, _)| *owner == cid)
                    .copied();
                key.and_then(|key| state.listeners.remove(&key))
            };
            let Some(endpoint) = endpoint else { break };
            endpoint.revoke();
        }
    }

    pub(super) fn retired_drained(&self, cid: u32) -> bool {
        let retired = {
            let mut state = self.state.lock();
            if state.devices.contains_key(&cid)
                || state
                    .peers
                    .keys()
                    .any(|(a, _, b, _)| *a == cid || *b == cid)
            {
                return false;
            }
            state.prune_retired(cid);
            if state
                .retired
                .get(&cid)
                .is_some_and(|queue| !queue.pending.is_empty())
            {
                return false;
            }
            state.retired.remove(&cid)
        };
        drop(retired);
        true
    }
}

pub(super) fn listen(cid: u32, port: u32, owner: Uid) -> Result<Arc<dyn FileLike>> {
    VsockSwitch::global().listen(cid, port, owner)
}

pub(super) fn connect(cid: u32, port: u32) -> Result<Arc<dyn FileLike>> {
    VsockSwitch::global().connect(cid, port)
}

pub(super) fn on_dying(cid: u32) {
    VsockSwitch::global().on_dying(cid);
}

pub(super) fn retired_drained(cid: u32) -> bool {
    VsockSwitch::global().retired_drained(cid)
}

pub(super) fn retire_wait_queue(cid: u32) -> Option<Arc<WaitQueue>> {
    VsockSwitch::global().retire_wait_queue(cid)
}

pub(super) fn set_peer_allowed(a: u32, b: u32, allowed: bool) -> Result<()> {
    VsockSwitch::global().set_peer_allowed(a, b, allowed)
}

fn ordered_pair(a: u32, b: u32) -> (u32, u32) {
    if a < b { (a, b) } else { (b, a) }
}
