// SPDX-License-Identifier: MPL-2.0

//! Ethernet NAT frontend forwarded through native Host TCP and UDP sockets.
//!
//! One adopted device Task drives virtqueues and the protocol frontend. It
//! sleeps on native socket events, device notifications and protocol deadlines.

use core::{
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration,
};

use kernelet_abi::{MAX_NET_PORTS, NET_PROTOCOL_TCP, NET_PROTOCOL_UDP, NetConfigArgs};
use ostd::kernelet::control::Kernelet;
use smoltcp::{
    iface::{Config as InterfaceConfig, Interface, PollResult, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::{Socket, tcp, udp},
    time::Instant as NetworkInstant,
    wire::{
        EthernetAddress, EthernetFrame, EthernetProtocol, HardwareAddress, IpAddress, IpCidr,
        IpEndpoint, IpProtocol, Ipv4Address, Ipv4Packet, TcpPacket, UdpPacket,
    },
};

use super::{
    super::policy::PrestartEndpointReservation,
    Frame, MAX_FRAME_BYTES, NetEndpoint, VirtioNet, Work,
    sockets::{TcpListener, TcpStream, UdpSocket},
};
use crate::{events::IoEvents, prelude::*, process::signal::Poller};

const MAX_FRAME: usize = MAX_FRAME_BYTES;
const MAX_FLOWS: usize = 256;
const BUFFER_BYTES: usize = 64 * 1024;
const FLOW_RESERVATION_BYTES: usize = 512 * 1024;
const GATEWAY_MAC: [u8; 6] = [2, 0xc7, 0, 0, 0, 1];
const GATEWAY: Ipv4Address = Ipv4Addr::new(10, 0, 2, 2);
const GUEST: Ipv4Address = Ipv4Addr::new(10, 0, 2, 15);
/// Guest-facing source ports handed out to Host-initiated NAT flows.
const FIRST_SOURCE_PORT: u16 = 40000;
const LAST_SOURCE_PORT: u16 = 60000;
/// The bounded allocator is scanned at most one full cycle per flow.
const SOURCE_PORT_CYCLE: usize = (LAST_SOURCE_PORT - FIRST_SOURCE_PORT) as usize + 1;

pub(super) struct NatBackend {
    config: NetConfigArgs,
    listeners: Vec<(TcpListener, u16)>,
    datagram_listeners: Vec<(UdpSocket, u16)>,
}

impl NatBackend {
    pub(super) fn new(config: NetConfigArgs) -> Result<Self> {
        let count = usize::from(config.num_ports);
        if count > MAX_NET_PORTS || config.reserved0 != 0 {
            return_errno_with_message!(Errno::EINVAL, "invalid network configuration");
        }
        let mut listeners = Vec::new();
        let mut datagram_listeners = Vec::new();
        for (index, port) in config.ports.iter().enumerate() {
            if port.reserved0 != 0
                || (index >= count
                    && (port.host_address != [0; 4]
                        || port.host_port != 0
                        || port.guest_port != 0
                        || port.protocol != 0))
            {
                return_errno_with_message!(Errno::EINVAL, "invalid network port mapping");
            }
            if index >= count {
                continue;
            }
            if port.host_port == 0 || port.guest_port == 0 {
                return_errno_with_message!(Errno::EINVAL, "empty network port mapping");
            }
            let local = SocketAddrV4::new(Ipv4Addr::from(port.host_address), port.host_port);
            match port.protocol {
                NET_PROTOCOL_TCP => listeners.push((TcpListener::bind(local)?, port.guest_port)),
                NET_PROTOCOL_UDP => {
                    datagram_listeners.push((UdpSocket::bind(local)?, port.guest_port))
                }
                _ => return_errno_with_message!(Errno::EINVAL, "unsupported network protocol"),
            }
        }
        Ok(Self {
            config,
            listeners,
            datagram_listeners,
        })
    }

    pub(super) fn run(self, model: &VirtioNet) -> Result<()> {
        let Self {
            config,
            listeners,
            datagram_listeners,
        } = self;
        run(model, config, listeners, datagram_listeners)
    }
}

fn now() -> Duration {
    aster_time::read_monotonic_time()
}
fn elapsed(since: Duration) -> Duration {
    now().saturating_sub(since)
}
fn guest_socket_error(error: impl Debug) -> Error {
    error!("kernelet network frontend socket failed: {:?}", error);
    Error::with_message(Errno::EINVAL, "invalid guest network socket endpoint")
}

/// Returns the next guest-facing source port that no live socket holds,
/// advancing the bounded allocator at most one full cycle; `None` when
/// every port is taken.
///
/// smoltcp hands a received packet to the first socket whose endpoints
/// match, so once the allocator wraps around while earlier flows are still
/// alive, a reused port would let a new flow collide with an existing
/// tuple and steal its traffic. The existing socket state is the source of
/// truth; no separate port set is kept.
fn next_source_port(next_port: &mut u16, in_use: impl Fn(u16) -> bool) -> Option<u16> {
    (0..SOURCE_PORT_CYCLE).find_map(|_| {
        let port = *next_port;
        *next_port = if port == LAST_SOURCE_PORT {
            FIRST_SOURCE_PORT
        } else {
            port + 1
        };
        (!in_use(port)).then_some(port)
    })
}

/// Covers active socket buffers and pending stream data conservatively.
struct FlowCharge {
    kernelet: Arc<Kernelet>,
    _reservation: PrestartEndpointReservation,
}
impl FlowCharge {
    fn new(model: &VirtioNet) -> Result<Self> {
        let reservation = model
            .endpoint
            .reserve_backend_bytes(FLOW_RESERVATION_BYTES)?;
        model
            .kernelet
            .charge_host_bytes(FLOW_RESERVATION_BYTES)
            .map_err(|_| Error::with_message(Errno::ENOMEM, "cannot charge network flow"))?;
        Ok(Self {
            kernelet: model.kernelet.clone(),
            _reservation: reservation,
        })
    }
}
impl Drop for FlowCharge {
    fn drop(&mut self) {
        self.kernelet.uncharge_host_bytes(FLOW_RESERVATION_BYTES);
    }
}
struct UdpFrontend {
    handle: SocketHandle,
    _charge: FlowCharge,
}
fn run(
    model: &VirtioNet,
    config: NetConfigArgs,
    listeners: Vec<(TcpListener, u16)>,
    datagram_listeners: Vec<(UdpSocket, u16)>,
) -> Result<()> {
    let mut device = FrameDevice {
        endpoint: &model.endpoint,
        received: None,
    };
    let mut interface_config =
        InterfaceConfig::new(HardwareAddress::Ethernet(EthernetAddress(GATEWAY_MAC)));
    let mac = model.mac;
    interface_config.random_seed =
        u64::from_be_bytes([mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], 0, 1]);
    let mut interface = Interface::new(
        interface_config,
        &mut device,
        NetworkInstant::from_millis(0),
    );
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(GATEWAY), 24))
            .unwrap();
    });
    interface
        .routes_mut()
        .add_default_ipv4_route(GATEWAY)
        .unwrap();
    interface.set_any_ip(true);
    let mut sockets = SocketSet::new(Vec::new());
    let mut tcp_flows = Vec::<TcpFlow>::new();
    let mut udp_sockets = BTreeMap::<SocketAddrV4, UdpFrontend>::new();
    let mut udp_flows = BTreeMap::<(SocketAddrV4, SocketAddrV4), UdpFlow>::new();
    let mut inbound_datagrams = Vec::<UdpPortFlow>::new();
    let mut next_port = FIRST_SOURCE_PORT;
    let result = (|| {
        loop {
            let generation = model.endpoint.generation();
            let timestamp =
                NetworkInstant::from_millis(now().as_millis().min(i64::MAX as u128) as i64);
            let mut progressed = false;
            for _ in 0..128 {
                match model.take_work() {
                    Some(Work::Cancel) => return Ok(()),
                    Some(Work::Progress) => progressed = true,
                    None => break,
                }
            }
            for _ in 0..32 {
                if device.received.is_some() || !device.endpoint.input_has_space() {
                    break;
                }
                let Some(frame) = model.endpoint.pop_output() else {
                    break;
                };
                prepare_incoming(
                    &frame.bytes[..frame.len],
                    &config,
                    model,
                    &mut sockets,
                    &mut tcp_flows,
                    &mut udp_sockets,
                )?;
                device.received = Some(frame);
                progressed |=
                    interface.poll(timestamp, &mut device, &mut sockets) != PollResult::None;
            }
            for (listener, destination_port) in &listeners {
                if tcp_flows.len() + udp_flows.len() + inbound_datagrams.len() >= MAX_FLOWS {
                    break;
                }
                if let Ok(stream) = listener.accept() {
                    progressed = true;
                    // Skip ports still held by live TCP sockets, including
                    // sockets listening on a mapped guest port, so the new
                    // flow gets a unique guest-facing tuple.
                    let Some(source_port) = next_source_port(&mut next_port, |port| {
                        sockets.iter().any(|(_, socket)| {
                            matches!(socket, Socket::Tcp(socket)
                            if socket.local_endpoint().is_some_and(|endpoint| endpoint.port == port)
                                || socket.listen_endpoint().port == port)
                        })
                    }) else {
                        // Every source port is taken: refuse this connection.
                        continue;
                    };
                    let Ok(charge) = FlowCharge::new(model) else {
                        continue;
                    };
                    let mut socket = tcp_socket();
                    socket
                        .connect(
                            interface.context(),
                            (GUEST, *destination_port),
                            (GATEWAY, source_port),
                        )
                        .map_err(guest_socket_error)?;
                    let handle = sockets.add(socket);
                    tcp_flows.push(TcpFlow::new(handle, stream, charge));
                }
            }
            for (index, (host, guest_port)) in datagram_listeners.iter().enumerate() {
                let mut packet = [0; 1472];
                if let Ok((length, peer)) = host.recv_from(&mut packet) {
                    let existing = inbound_datagrams
                        .iter()
                        .position(|flow| flow.listener == index && flow.peer == peer);
                    let flow_index = if let Some(index) = existing {
                        index
                    } else {
                        if tcp_flows.len() + udp_flows.len() + inbound_datagrams.len() >= MAX_FLOWS
                        {
                            continue;
                        }
                        let Ok(charge) = FlowCharge::new(model) else {
                            continue;
                        };
                        let mut socket = udp_socket();
                        // A mapping gives each Host peer its own guest-facing tuple.
                        // Do not reuse a live port when the bounded allocator wraps.
                        let Some(port) = next_source_port(&mut next_port, |port| {
                            sockets.iter().any(|(_, socket)| matches!(socket, Socket::Udp(socket) if socket.endpoint().port == port))
                        }) else {
                            continue;
                        };
                        socket.bind((GATEWAY, port)).map_err(guest_socket_error)?;
                        inbound_datagrams.push(UdpPortFlow {
                            listener: index,
                            peer,
                            handle: sockets.add(socket),
                            last_active: now(),
                            _charge: charge,
                        });
                        inbound_datagrams.len() - 1
                    };
                    let flow = &mut inbound_datagrams[flow_index];
                    let _ = sockets
                        .get_mut::<udp::Socket>(flow.handle)
                        .send_slice(&packet[..length], (GUEST, *guest_port));
                    flow.last_active = now();
                }
            }
            progressed |= interface.poll(timestamp, &mut device, &mut sockets) != PollResult::None;
            for flow in &mut tcp_flows {
                let previous = flow.last_active;
                flow.forward(sockets.get_mut::<tcp::Socket>(flow.handle));
                progressed |= flow.last_active != previous;
            }
            tcp_flows.retain(|flow| {
                if !flow.alive || elapsed(flow.last_active) > Duration::from_secs(300) {
                    sockets.remove(flow.handle);
                    false
                } else {
                    true
                }
            });
            for (destination, frontend) in &udp_sockets {
                let socket = sockets.get_mut::<udp::Socket>(frontend.handle);
                while let Ok((payload, metadata)) = socket.recv() {
                    let IpAddress::Ipv4(source_ip) = metadata.endpoint.addr else {
                        continue;
                    };
                    let source = SocketAddrV4::new(source_ip, metadata.endpoint.port);
                    let key = (source, *destination);
                    if !udp_flows.contains_key(&key) {
                        if udp_flows.len() + tcp_flows.len() + inbound_datagrams.len() >= MAX_FLOWS
                        {
                            continue;
                        }
                        let Ok(charge) = FlowCharge::new(model) else {
                            continue;
                        };
                        let host_destination = translate_destination(*destination, &config);
                        let host = match UdpSocket::connect(host_destination) {
                            Ok(host) => host,
                            Err(error) => {
                                debug!("kernelet UDP connect failed: {:?}", error);
                                continue;
                            }
                        };
                        udp_flows.insert(
                            key,
                            UdpFlow {
                                host,
                                last_active: now(),
                                handle: frontend.handle,
                                _charge: charge,
                            },
                        );
                    }
                    let flow = udp_flows.get_mut(&key).unwrap();
                    if let Err(error) = flow.host.send(payload)
                        && error.error() != Errno::EAGAIN
                    {
                        debug!("kernelet UDP send failed: {:?}", error);
                    }
                    progressed = true;
                    flow.last_active = now();
                }
            }
            udp_flows.retain(|(source, _), flow| {
                if elapsed(flow.last_active) > Duration::from_secs(60) {
                    return false;
                }
                let mut packet = [0; 1472];
                if let Ok(length) = flow.host.recv(&mut packet) {
                    let socket = sockets.get_mut::<udp::Socket>(flow.handle);
                    let _ = socket.send_slice(
                        &packet[..length],
                        IpEndpoint::new(IpAddress::Ipv4(*source.ip()), source.port()),
                    );
                    flow.last_active = now();
                }
                true
            });
            inbound_datagrams.retain_mut(|flow| {
                if elapsed(flow.last_active) > Duration::from_secs(60) {
                    sockets.remove(flow.handle);
                    return false;
                }
                let (host, port) = &datagram_listeners[flow.listener];
                let socket = sockets.get_mut::<udp::Socket>(flow.handle);
                while let Ok((payload, metadata)) = socket.recv() {
                    if metadata.endpoint == IpEndpoint::new(IpAddress::Ipv4(GUEST), *port) {
                        let _ = host.send_to(payload, flow.peer);
                        flow.last_active = now();
                    }
                }
                true
            });
            let unused: Vec<_> = udp_sockets
                .iter()
                .filter(|(_, frontend)| {
                    !udp_flows
                        .values()
                        .any(|flow| flow.handle == frontend.handle)
                })
                .map(|(destination, frontend)| (*destination, frontend.handle))
                .collect();
            for (destination, handle) in unused {
                sockets.remove(handle);
                udp_sockets.remove(&destination);
            }
            progressed |= interface.poll(timestamp, &mut device, &mut sockets) != PollResult::None;
            if progressed {
                continue;
            }
            let current = now();
            let mut timeout = tcp_flows
                .iter()
                .map(|flow| (flow.last_active + Duration::from_secs(300)).saturating_sub(current))
                .chain(udp_flows.values().map(|flow| {
                    (flow.last_active + Duration::from_secs(60)).saturating_sub(current)
                }))
                .chain(inbound_datagrams.iter().map(|flow| {
                    (flow.last_active + Duration::from_secs(60)).saturating_sub(current)
                }))
                .min();
            if let Some(delay) = interface.poll_delay(timestamp, &sockets) {
                let delay = Duration::from_millis(delay.total_millis());
                if !delay.is_zero() || device.endpoint.input_has_space() {
                    timeout = Some(timeout.map_or(delay, |previous| previous.min(delay)));
                }
            }
            if timeout.is_some_and(|duration| duration.is_zero()) {
                continue;
            }
            let mut poller = Poller::new(timeout.as_ref());
            let mut ready = !model
                .endpoint
                .poll_change(generation, poller.as_handle_mut())
                .is_empty();
            if tcp_flows.len() + udp_flows.len() + inbound_datagrams.len() < MAX_FLOWS {
                for (listener, _) in &listeners {
                    ready |= !listener.poll(poller.as_handle_mut()).is_empty();
                }
                for (listener, _) in &datagram_listeners {
                    ready |= !listener
                        .poll(IoEvents::IN, poller.as_handle_mut())
                        .is_empty();
                }
            }
            for flow in &tcp_flows {
                let guest = sockets.get::<tcp::Socket>(flow.handle);
                let mut events = IoEvents::empty();
                if flow.host.is_connecting() || !flow.to_host.is_empty() {
                    events |= IoEvents::OUT;
                }
                if !flow.host_eof && guest.can_send() {
                    events |= IoEvents::IN;
                }
                if !events.is_empty() {
                    ready |= !flow.host.poll(events, poller.as_handle_mut()).is_empty();
                }
            }
            for flow in udp_flows.values() {
                if sockets.get::<udp::Socket>(flow.handle).can_send() {
                    ready |= !flow
                        .host
                        .poll(IoEvents::IN, poller.as_handle_mut())
                        .is_empty();
                }
            }
            if !ready {
                match poller.wait() {
                    Ok(()) => {}
                    Err(error) if error.error() == Errno::ETIME => {}
                    Err(error) => return Err(error),
                }
            }
        }
    })();
    drop(sockets);
    drop(tcp_flows);
    drop(udp_flows);
    drop(inbound_datagrams);
    drop(udp_sockets);
    result
}
struct TcpFlow {
    handle: SocketHandle,
    host: TcpStream,
    to_host: VecDeque<u8>,
    last_active: Duration,
    alive: bool,
    host_eof: bool,
    requested: Option<(IpEndpoint, IpEndpoint)>,
    write_closed: bool,
    _charge: FlowCharge,
}
impl TcpFlow {
    fn new(handle: SocketHandle, host: TcpStream, charge: FlowCharge) -> Self {
        Self {
            handle,
            host,
            to_host: VecDeque::with_capacity(BUFFER_BYTES),
            last_active: now(),
            alive: true,
            host_eof: false,
            requested: None,
            write_closed: false,
            _charge: charge,
        }
    }
    fn forward(&mut self, guest: &mut tcp::Socket) {
        match self.host.finish_connect() {
            Ok(true) => {}
            Ok(false) => return,
            Err(error) => {
                debug!("kernelet TCP connect failed: {:?}", error);
                guest.abort();
                self.alive = false;
                return;
            }
        }
        match self.host.take_error() {
            Ok(None) => {}
            Ok(Some(error)) | Err(error) => {
                debug!("kernelet TCP socket failed: {:?}", error);
                guest.abort();
                self.alive = false;
                return;
            }
        }
        let mut bytes = [0; 16 * 1024];
        while !self.to_host.is_empty() {
            let (first, _) = self.to_host.as_slices();
            match self.host.write(first) {
                Ok(0) => {
                    guest.abort();
                    self.alive = false;
                    return;
                }
                Ok(length) => {
                    self.to_host.drain(..length);
                    self.last_active = now();
                }
                Err(error) if error.error() == Errno::EAGAIN => break,
                Err(error) => {
                    debug!("kernelet TCP send failed: {:?}", error);
                    guest.abort();
                    self.alive = false;
                    return;
                }
            }
        }
        if guest.can_recv() && self.to_host.len() < BUFFER_BYTES {
            let capacity = bytes.len().min(BUFFER_BYTES - self.to_host.len());
            if let Ok(length) = guest.recv_slice(&mut bytes[..capacity]) {
                self.to_host.extend(&bytes[..length]);
                self.last_active = now();
            }
        }
        if guest.can_send() && !self.host_eof {
            let capacity = bytes.len().min(guest.send_capacity() - guest.send_queue());
            match self.host.read(&mut bytes[..capacity]) {
                Ok(0) if capacity != 0 => {
                    self.host_eof = true;
                    guest.close();
                }
                Ok(length) => {
                    let _ = guest.send_slice(&bytes[..length]);
                    if length != 0 {
                        self.last_active = now();
                    }
                }
                Err(error) if error.error() == Errno::EAGAIN => {}
                Err(error) => {
                    debug!("kernelet TCP receive failed: {:?}", error);
                    guest.abort();
                    self.alive = false;
                }
            }
        }
        if matches!(
            guest.state(),
            tcp::State::CloseWait | tcp::State::LastAck | tcp::State::TimeWait
        ) && self.to_host.is_empty()
            && !self.write_closed
        {
            if let Err(error) = self.host.shutdown_write() {
                debug!("kernelet TCP half-close failed: {:?}", error);
            }
            self.write_closed = true;
        }
        if !guest.is_open() {
            self.alive = false;
        }
    }
}
struct UdpPortFlow {
    listener: usize,
    peer: SocketAddrV4,
    handle: SocketHandle,
    last_active: Duration,
    _charge: FlowCharge,
}

fn udp_socket() -> udp::Socket<'static> {
    udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; BUFFER_BYTES]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; BUFFER_BYTES]),
    )
}

struct UdpFlow {
    host: UdpSocket,
    last_active: Duration,
    handle: SocketHandle,
    _charge: FlowCharge,
}

fn prepare_incoming(
    frame: &[u8],
    config: &NetConfigArgs,
    model: &VirtioNet,
    sockets: &mut SocketSet<'static>,
    tcp_flows: &mut Vec<TcpFlow>,
    udp_sockets: &mut BTreeMap<SocketAddrV4, UdpFrontend>,
) -> Result<()> {
    let ethernet = match EthernetFrame::new_checked(frame) {
        Ok(packet) if packet.ethertype() == EthernetProtocol::Ipv4 => packet,
        _ => return Ok(()),
    };
    let ipv4 = match Ipv4Packet::new_checked(ethernet.payload()) {
        Ok(packet) => packet,
        Err(_) => return Ok(()),
    };
    if ipv4.src_addr() != GUEST
        || !ipv4.verify_checksum()
        || ipv4.frag_offset() != 0
        || ipv4.more_frags()
    {
        return Ok(());
    }
    match ipv4.next_header() {
        IpProtocol::Tcp => {
            let packet = match TcpPacket::new_checked(ipv4.payload()) {
                Ok(packet)
                    if packet.syn()
                        && !packet.ack()
                        && packet.src_port() != 0
                        && packet.dst_port() != 0
                        && packet.verify_checksum(
                            &IpAddress::Ipv4(ipv4.src_addr()),
                            &IpAddress::Ipv4(ipv4.dst_addr()),
                        ) =>
                {
                    packet
                }
                _ => return Ok(()),
            };
            let source = IpEndpoint::new(IpAddress::Ipv4(ipv4.src_addr()), packet.src_port());
            let destination = IpEndpoint::new(IpAddress::Ipv4(ipv4.dst_addr()), packet.dst_port());
            if sockets.iter().count() >= MAX_FLOWS
                || tcp_flows.iter().any(|flow| {
                    let socket = sockets.get::<tcp::Socket>(flow.handle);
                    flow.requested == Some((source, destination))
                        || socket.remote_endpoint() == Some(source)
                            && socket.local_endpoint() == Some(destination)
                })
            {
                return Ok(());
            }
            let Ok(charge) = FlowCharge::new(model) else {
                return Ok(());
            };
            let Ok(host) = TcpStream::connect(translate_destination(
                SocketAddrV4::new(ipv4.dst_addr(), packet.dst_port()),
                config,
            )) else {
                return Ok(());
            };
            let mut socket = tcp_socket();
            socket.listen(destination).map_err(guest_socket_error)?;
            let handle = sockets.add(socket);
            let mut flow = TcpFlow::new(handle, host, charge);
            flow.requested = Some((source, destination));
            tcp_flows.push(flow);
        }
        IpProtocol::Udp => {
            let packet = match UdpPacket::new_checked(ipv4.payload()) {
                Ok(packet)
                    if packet.src_port() != 0
                        && packet.dst_port() != 0
                        && packet.verify_checksum(
                            &IpAddress::Ipv4(ipv4.src_addr()),
                            &IpAddress::Ipv4(ipv4.dst_addr()),
                        ) =>
                {
                    packet
                }
                _ => return Ok(()),
            };
            let destination = SocketAddrV4::new(ipv4.dst_addr(), packet.dst_port());
            if sockets.iter().count() >= MAX_FLOWS
                || sockets.iter().any(|(_, socket)| {
                    matches!(socket, Socket::Udp(socket)
                    if socket.endpoint().port == destination.port()
                    && socket.endpoint().addr == Some(IpAddress::Ipv4(*destination.ip())))
                })
            {
                return Ok(());
            }
            let Ok(charge) = FlowCharge::new(model) else {
                return Ok(());
            };
            let mut socket = udp_socket();
            socket
                .bind((ipv4.dst_addr(), packet.dst_port()))
                .map_err(guest_socket_error)?;
            udp_sockets.insert(
                destination,
                UdpFrontend {
                    handle: sockets.add(socket),
                    _charge: charge,
                },
            );
        }
        _ => {}
    }
    Ok(())
}
fn translate_destination(destination: SocketAddrV4, config: &NetConfigArgs) -> SocketAddrV4 {
    if *destination.ip() == Ipv4Addr::new(10, 0, 2, 3) && destination.port() == 53 {
        SocketAddrV4::new(Ipv4Addr::from(config.host_resolver), 53)
    } else {
        destination
    }
}

fn tcp_socket() -> tcp::Socket<'static> {
    tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; BUFFER_BYTES]),
        tcp::SocketBuffer::new(vec![0; BUFFER_BYTES]),
    )
}

struct FrameDevice<'a> {
    endpoint: &'a NetEndpoint,
    received: Option<Frame>,
}
struct Receive(Frame);
struct Transmit<'a>(&'a NetEndpoint);
impl RxToken for Receive {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0.bytes[..self.0.len])
    }
}
impl TxToken for Transmit<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        assert!(len <= MAX_FRAME);
        let mut frame = Frame::empty();
        frame.len = len;
        let result = f(&mut frame.bytes[..len]);
        // Only this Task produces input frames; failure during revocation discards the frame.
        let _ = self.0.push_input(frame);
        result
    }
}
impl Device for FrameDevice<'_> {
    type RxToken<'a>
        = Receive
    where
        Self: 'a;
    type TxToken<'a>
        = Transmit<'a>
    where
        Self: 'a;
    fn receive(&mut self, _: NetworkInstant) -> Option<(Receive, Transmit<'_>)> {
        if !self.endpoint.input_has_space() {
            return None;
        }
        Some((Receive(self.received.take()?), Transmit(self.endpoint)))
    }
    fn transmit(&mut self, _: NetworkInstant) -> Option<Transmit<'_>> {
        self.endpoint
            .input_has_space()
            .then_some(Transmit(self.endpoint))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut result = DeviceCapabilities::default();
        result.medium = Medium::Ethernet;
        result.max_transmission_unit = MAX_FRAME;
        result.max_burst_size = Some(32);
        result
    }
}

#[cfg(ktest)]
mod source_port_tests {
    use core::cell::Cell;

    use ostd::prelude::*;

    use super::{FIRST_SOURCE_PORT, LAST_SOURCE_PORT, SOURCE_PORT_CYCLE, next_source_port};

    #[ktest]
    fn source_port_wrap_skips_live_ports() {
        let mut next = LAST_SOURCE_PORT;
        let occupied = [LAST_SOURCE_PORT, FIRST_SOURCE_PORT, FIRST_SOURCE_PORT + 1];
        assert_eq!(
            next_source_port(&mut next, |port| occupied.contains(&port)),
            Some(FIRST_SOURCE_PORT + 2)
        );
        assert_eq!(next, FIRST_SOURCE_PORT + 3);
        // Reclaimed ports are eligible on the next visit; no stale ledger persists.
        next = LAST_SOURCE_PORT;
        assert_eq!(
            next_source_port(&mut next, |port| port == FIRST_SOURCE_PORT),
            Some(LAST_SOURCE_PORT)
        );
        assert_eq!(next, FIRST_SOURCE_PORT);
    }

    #[ktest]
    fn source_port_exhaustion_is_bounded() {
        let mut next = FIRST_SOURCE_PORT + 10;
        let initial = next;
        let checks = Cell::new(0);
        assert_eq!(
            next_source_port(&mut next, |_| {
                checks.set(checks.get() + 1);
                true
            }),
            None
        );
        assert_eq!(checks.get(), SOURCE_PORT_CYCLE);
        assert_eq!(next, initial);
    }
}
