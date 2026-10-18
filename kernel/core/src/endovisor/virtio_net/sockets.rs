// SPDX-License-Identifier: MPL-2.0

//! Nonblocking native sockets used by the network backend, without file descriptors.

use core::net::SocketAddrV4;

use aster_bigtcp::socket::{TCP_RECV_BUF_LEN, TCP_SEND_BUF_LEN};

#[cfg(kernelet_nat_failure_diag_host)]
use super::{
    VirtioNet,
    endpoint::{NatContext, NatEvent},
};
use crate::{
    endovisor::NativeTcpBufferCharge,
    events::IoEvents,
    fs::file::FileLike,
    net::socket::{
        Socket,
        ip::{DatagramSocket, IpAddressFamily, StreamSocket, stream_options::NoDelay},
        options::{Error as SocketError, Linger},
        util::{LingerOption, MessageHeader, RecvFlags, SendFlags, SockShutdownCmd, SocketAddr},
    },
    prelude::*,
    process::signal::{PollHandle, Pollable},
};

const TCP_LISTENER_BACKLOG: usize = 8;
const TCP_LISTENER_METADATA_BYTES: usize = 128 * 1024;
// Reserve the listener socket and the entire pending queue before binding.
pub(super) const TCP_LISTENER_RESERVATION_BYTES: usize = (TCP_LISTENER_BACKLOG + 1)
    * (TCP_RECV_BUF_LEN + TCP_SEND_BUF_LEN)
    + TCP_LISTENER_METADATA_BYTES;

fn address(value: SocketAddrV4) -> SocketAddr {
    SocketAddr::IPv4(*value.ip(), value.port())
}

fn configure_tcp_stream(socket: &dyn Socket) -> Result<()> {
    // Fatal errors and cancellation abort native sockets. An orderly bridge
    // handoff explicitly disables this policy after data and EOF are transferred.
    let mut linger = Linger::new();
    linger.set(LingerOption::new(true, core::time::Duration::ZERO));
    socket.set_option(&linger)?;

    // Application TCP_NODELAY does not propagate across the bridge's connections.
    let mut no_delay = NoDelay::new();
    no_delay.set(true);
    socket.set_option(&no_delay)
}

pub(super) struct TcpStream {
    file: Arc<dyn FileLike>,
    connecting: Option<SocketAddrV4>,
}

// The private NAT stream is IPv4. Preserve IP results and real errors in a
// Copy snapshot; an unexpected non-IP family remains explicit and unknown.
#[cfg(kernelet_nat_failure_diag_host)]
#[derive(Clone, Copy, Debug)]
pub(super) enum TcpDiagnosticAddress {
    IPv4(SocketAddrV4),
    IPv6(aster_bigtcp::wire::Ipv6Address, u16),
    UnexpectedFamily(&'static str),
}

#[cfg(kernelet_nat_failure_diag_host)]
impl From<SocketAddr> for TcpDiagnosticAddress {
    fn from(address: SocketAddr) -> Self {
        match address {
            SocketAddr::IPv4(ip, port) => Self::IPv4(SocketAddrV4::new(ip, port)),
            SocketAddr::IPv6(ip, port) => Self::IPv6(ip, port),
            SocketAddr::Unix(_) => Self::UnexpectedFamily("Unix"),
            SocketAddr::Netlink(_) => Self::UnexpectedFamily("Netlink"),
            SocketAddr::Vsock(_) => Self::UnexpectedFamily("Vsock"),
        }
    }
}

#[cfg(kernelet_nat_failure_diag_host)]
#[derive(Clone, Copy, Debug)]
pub(super) struct TcpErrorDiagnostic {
    native_local: Result<TcpDiagnosticAddress>,
    native_peer: Result<TcpDiagnosticAddress>,
    native_reset:
        core::result::Result<Option<aster_bigtcp::socket::TcpResetDiagnostic>, &'static str>,
}

impl TcpStream {
    pub(super) fn connect(remote: SocketAddrV4, charge: NativeTcpBufferCharge) -> Result<Self> {
        let socket = StreamSocket::new_nat(true, IpAddressFamily::IPv4, charge);
        configure_tcp_stream(socket.as_ref())?;
        let connecting = match socket.connect(address(remote)) {
            Ok(()) => None,
            Err(error) if error.error() == Errno::EINPROGRESS => Some(remote),
            Err(error) => return Err(error),
        };
        Ok(Self {
            file: socket,
            connecting,
        })
    }

    pub(super) fn finish_connect(&mut self) -> Result<bool> {
        let Some(remote) = self.connecting else {
            return Ok(true);
        };
        match self.file.as_socket().unwrap().connect(address(remote)) {
            Ok(()) => {
                self.connecting = None;
                Ok(true)
            }
            Err(error) if matches!(error.error(), Errno::EINPROGRESS | Errno::EALREADY) => {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    pub(super) fn is_connecting(&self) -> bool {
        self.connecting.is_some()
    }

    pub(super) fn take_error(
        &self,
        #[cfg(kernelet_nat_failure_diag_host)] model: &VirtioNet,
        #[cfg(kernelet_nat_failure_diag_host)] handle: smoltcp::iface::SocketHandle,
        #[cfg(kernelet_nat_failure_diag_host)] requested: Option<(
            smoltcp::wire::IpEndpoint,
            smoltcp::wire::IpEndpoint,
        )>,
        #[cfg(kernelet_nat_failure_diag_host)] guest: &smoltcp::socket::tcp::Socket,
    ) -> Result<Option<Error>> {
        let mut error = SocketError::new();
        let result = self.file.as_socket().unwrap().get_option(&mut error);
        #[cfg(kernelet_nat_failure_diag_host)]
        {
            let failure = match &result {
                Ok(()) => error
                    .get()
                    .and_then(|error| error.as_ref())
                    .map(|error| ("socket_error_OkSome", error)),
                Err(error) => Some(("socket_error_Err", error)),
            };
            if let Some((branch, error)) = failure {
                let context = self.failure_context(handle, requested, guest, branch, error);
                model.record_diagnostic(NatEvent::NativeError, context, Some(error.error()));
            }
        }
        result?;
        Ok(error.get().cloned().flatten())
    }

    #[cfg(kernelet_nat_failure_diag_host)]
    pub(super) fn error_diagnostic(&self) -> TcpErrorDiagnostic {
        let socket = self.file.as_socket().unwrap();
        let native_local = socket.addr().map(TcpDiagnosticAddress::from);
        let native_peer = socket.peer_addr().map(TcpDiagnosticAddress::from);
        let native_reset = self
            .file
            .downcast_ref::<StreamSocket>()
            .map(StreamSocket::reset_diagnostic)
            .ok_or("not a native TCP stream");
        TcpErrorDiagnostic {
            native_local,
            native_peer,
            native_reset,
        }
    }

    #[cfg(kernelet_nat_failure_diag_host)]
    pub(super) fn failure_context(
        &self,
        handle: smoltcp::iface::SocketHandle,
        requested: Option<(smoltcp::wire::IpEndpoint, smoltcp::wire::IpEndpoint)>,
        guest: &smoltcp::socket::tcp::Socket,
        stage: &'static str,
        error: &Error,
    ) -> NatContext {
        let ipv4 = |endpoint: smoltcp::wire::IpEndpoint| match endpoint.addr {
            smoltcp::wire::IpAddress::Ipv4(ip) => Some(SocketAddrV4::new(ip, endpoint.port)),
            _ => None,
        };
        let mut context = NatContext::new(stage);
        context.flow_handle = Some(handle);
        context.requested =
            requested.and_then(|(source, destination)| Some((ipv4(source)?, ipv4(destination)?)));
        context.guest_local = guest.local_endpoint().and_then(ipv4);
        context.guest_remote = guest.remote_endpoint().and_then(ipv4);
        context.guest_state = Some(guest.state());
        context.error = Some(*error);
        // Each getter has returned its owned result before publication. No
        // second SO_ERROR read or reset-error consumption occurs.
        context.native_diagnostic = Some(self.error_diagnostic());
        context
    }

    pub(super) fn read(&self, bytes: &mut [u8]) -> Result<usize> {
        self.file.read(&mut VmWriter::from(bytes).to_fallible())
    }

    pub(super) fn write(&self, bytes: &[u8]) -> Result<usize> {
        self.file.write(&mut VmReader::from(bytes).to_fallible())
    }

    pub(super) fn shutdown_write(&self) -> Result<()> {
        self.file
            .as_socket()
            .unwrap()
            .shutdown(SockShutdownCmd::SHUT_WR)
    }

    pub(super) fn allow_graceful_drop(&self) -> Result<()> {
        let mut linger = Linger::new();
        linger.set(LingerOption::new(false, core::time::Duration::ZERO));
        self.file.as_socket().unwrap().set_option(&linger)
    }

    pub(super) fn poll(&self, mask: IoEvents, handle: &mut PollHandle) -> IoEvents {
        self.file.poll(mask, Some(handle))
    }
}

pub(super) struct TcpListener(
    Arc<StreamSocket>,
    #[cfg(kernelet_nat_failure_diag_host)] SocketAddrV4,
);

impl TcpListener {
    pub(super) fn bind(
        local: SocketAddrV4,
        reservation: super::endpoint::BackendReservation,
    ) -> Result<Self> {
        // Install before listen exposes a native backlog. Its observer is
        // retained by unaccepted connections even after this file closes.
        let socket = StreamSocket::new_nat_shared(true, IpAddressFamily::IPv4, reservation);
        socket.bind(address(local))?;
        // Retain a bounded connection burst until the backend can accept it.
        // The endpoint reserves buffers for this entire pending queue.
        socket.listen(TCP_LISTENER_BACKLOG)?;
        Ok(Self(
            socket,
            #[cfg(kernelet_nat_failure_diag_host)]
            local,
        ))
    }

    #[cfg(kernelet_nat_failure_diag_host)]
    pub(super) fn diagnostic_context(&self, stage: &'static str, guest_port: u16) -> NatContext {
        let mut context = NatContext::new(stage);
        context.listener = Some(self.1);
        context.guest_port = Some(guest_port);
        context
    }

    #[cfg(kernelet_nat_failure_diag_host)]
    fn record_accept_failure(
        &self,
        model: &VirtioNet,
        event: NatEvent,
        mut context: NatContext,
        peer: Option<&SocketAddr>,
        error: &Error,
    ) {
        // All socket calls have returned; no socket guard reaches publication.
        context.error = Some(*error);
        match self.0.addr() {
            Ok(SocketAddr::IPv4(ip, port)) => {
                context.native_local = Some(SocketAddrV4::new(ip, port))
            }
            Ok(_) => {}
            Err(error) => context.native_local_errno = Some(error.error()),
        }
        if let Some(SocketAddr::IPv4(ip, port)) = peer {
            context.native_peer = Some(SocketAddrV4::new(*ip, *port));
        }
        model.record_diagnostic(event, context, Some(error.error()));
    }

    pub(super) fn accept(
        &self,
        charge: NativeTcpBufferCharge,
        #[cfg(kernelet_nat_failure_diag_host)] model: &VirtioNet,
        #[cfg(kernelet_nat_failure_diag_host)] context: NatContext,
    ) -> Result<TcpStream> {
        let accepted = self.0.accept_nat(true, charge);
        #[cfg(kernelet_nat_failure_diag_host)]
        if let Err(error) = &accepted
            && error.error() != Errno::EAGAIN
        {
            let mut context = context;
            context.stage = "native_accept";
            self.record_accept_failure(model, NatEvent::Accept, context, None, error);
        }
        let (file, _peer) = accepted?;
        let configured = configure_tcp_stream(file.as_socket().unwrap());
        #[cfg(kernelet_nat_failure_diag_host)]
        if let Err(error) = &configured {
            let mut context = context;
            context.stage = "accepted_stream_options";
            self.record_accept_failure(model, NatEvent::AcceptLinger, context, Some(&_peer), error);
        }
        configured?;
        Ok(TcpStream {
            file,
            connecting: None,
        })
    }

    pub(super) fn poll(&self, handle: Option<&mut PollHandle>) -> IoEvents {
        self.0.poll(IoEvents::IN, handle)
    }
}

pub(super) struct UdpSocket(Arc<DatagramSocket>);

impl UdpSocket {
    pub(super) fn bind(local: SocketAddrV4) -> Result<Self> {
        let socket = DatagramSocket::new(true);
        socket.bind(address(local))?;
        Ok(Self(socket))
    }

    pub(super) fn connect(remote: SocketAddrV4) -> Result<Self> {
        let socket = DatagramSocket::new(true);
        socket.connect(address(remote))?;
        Ok(Self(socket))
    }

    pub(super) fn send(&self, bytes: &[u8]) -> Result<usize> {
        self.send_message(bytes, None)
    }

    pub(super) fn send_to(&self, bytes: &[u8], peer: SocketAddrV4) -> Result<usize> {
        self.send_message(bytes, Some(address(peer)))
    }

    fn send_message(&self, bytes: &[u8], peer: Option<SocketAddr>) -> Result<usize> {
        self.0.sendmsg(
            &mut VmReader::from(bytes).to_fallible(),
            MessageHeader::new(peer, Vec::new()),
            SendFlags::empty(),
        )
    }

    pub(super) fn recv_from(&self, bytes: &mut [u8]) -> Result<(usize, SocketAddrV4)> {
        let (output, header) = self
            .0
            .recvmsg(&mut VmWriter::from(bytes).to_fallible(), RecvFlags::empty())?;
        let Some(SocketAddr::IPv4(ip, port)) = header.addr() else {
            return_errno_with_message!(Errno::EAFNOSUPPORT, "non-IPv4 network peer");
        };
        if output.flags().contains(RecvFlags::MSG_TRUNC) {
            return_errno_with_message!(Errno::EMSGSIZE, "network datagram exceeds the MTU");
        }
        Ok((output.len(), SocketAddrV4::new(*ip, *port)))
    }

    pub(super) fn recv(&self, bytes: &mut [u8]) -> Result<usize> {
        self.recv_from(bytes).map(|(length, _)| length)
    }

    pub(super) fn poll(&self, mask: IoEvents, handle: &mut PollHandle) -> IoEvents {
        self.0.poll(mask, Some(handle))
    }
}
