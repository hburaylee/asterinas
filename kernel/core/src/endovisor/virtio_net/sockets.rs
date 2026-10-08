// SPDX-License-Identifier: MPL-2.0

//! Nonblocking native sockets used by the network backend, without file descriptors.

use core::net::SocketAddrV4;

use crate::{
    events::IoEvents,
    fs::file::FileLike,
    net::socket::{
        Socket,
        ip::{DatagramSocket, IpAddressFamily, StreamSocket},
        options::{Error as SocketError, Linger},
        util::{LingerOption, MessageHeader, RecvFlags, SendFlags, SockShutdownCmd, SocketAddr},
    },
    prelude::*,
    process::signal::{PollHandle, Pollable},
};

fn address(value: SocketAddrV4) -> SocketAddr {
    SocketAddr::IPv4(*value.ip(), value.port())
}

// Flow retirement and instance cancellation release native buffers promptly.
// Half-close during forwarding still uses SHUT_WR and preserves queued data.
fn reset_on_drop(socket: &dyn Socket) -> Result<()> {
    let mut linger = Linger::new();
    linger.set(LingerOption::new(true, core::time::Duration::ZERO));
    socket.set_option(&linger)
}

pub(super) struct TcpStream {
    file: Arc<dyn FileLike>,
    connecting: Option<SocketAddrV4>,
}

impl TcpStream {
    pub(super) fn connect(remote: SocketAddrV4) -> Result<Self> {
        let socket = StreamSocket::new(true, IpAddressFamily::IPv4);
        reset_on_drop(socket.as_ref())?;
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

    pub(super) fn take_error(&self) -> Result<Option<Error>> {
        let mut error = SocketError::new();
        self.file.as_socket().unwrap().get_option(&mut error)?;
        Ok(error.get().cloned().flatten())
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

    pub(super) fn poll(&self, mask: IoEvents, handle: &mut PollHandle) -> IoEvents {
        self.file.poll(mask, Some(handle))
    }
}

pub(super) struct TcpListener(Arc<StreamSocket>);

impl TcpListener {
    pub(super) fn bind(local: SocketAddrV4) -> Result<Self> {
        let socket = StreamSocket::new(true, IpAddressFamily::IPv4);
        socket.bind(address(local))?;
        // A bounded pending connection is covered by the mapping reservation.
        socket.listen(1)?;
        Ok(Self(socket))
    }

    pub(super) fn accept(&self) -> Result<TcpStream> {
        let (file, _) = self.0.accept(true)?;
        reset_on_drop(file.as_socket().unwrap())?;
        Ok(TcpStream {
            file,
            connecting: None,
        })
    }

    pub(super) fn poll(&self, handle: &mut PollHandle) -> IoEvents {
        self.0.poll(IoEvents::IN, Some(handle))
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
