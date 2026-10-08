// SPDX-License-Identifier: MPL-2.0

//! Explicit ownership transfer of close-on-exec descriptors to the holder.

use std::{
    io::{self, IoSlice, IoSliceMut},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::net::UnixStream,
    },
};

use nix::sys::socket::{self, ControlMessage, ControlMessageOwned, MsgFlags};

const MAX_DESCRIPTORS: usize = 8;

pub fn send(stream: &UnixStream, descriptors: &[RawFd]) -> io::Result<()> {
    if descriptors.is_empty() || descriptors.len() > MAX_DESCRIPTORS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid descriptor count",
        ));
    }
    let marker = [descriptors.len() as u8];
    let written = socket::sendmsg::<()>(
        stream.as_raw_fd(),
        &[IoSlice::new(&marker)],
        &[ControlMessage::ScmRights(descriptors)],
        MsgFlags::MSG_NOSIGNAL,
        None,
    )?;
    if written != 1 {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "descriptor transfer failed",
        ));
    }
    Ok(())
}

pub fn receive(stream: &UnixStream) -> io::Result<Vec<OwnedFd>> {
    let mut marker = [0u8];
    let mut control = nix::cmsg_space!([RawFd; MAX_DESCRIPTORS]);
    let mut buffers = [IoSliceMut::new(&mut marker)];
    let message = socket::recvmsg::<()>(
        stream.as_raw_fd(),
        &mut buffers,
        Some(&mut control),
        MsgFlags::MSG_CMSG_CLOEXEC,
    )?;
    let mut descriptors = Vec::new();
    for control in message.cmsgs()? {
        if let ControlMessageOwned::ScmRights(received) = control {
            for fd in received {
                // SAFETY: recvmsg installs new descriptors; ownership is transferred exactly once.
                descriptors.push(unsafe { OwnedFd::from_raw_fd(fd) });
            }
        }
    }
    if message.flags.contains(MsgFlags::MSG_CTRUNC)
        || message.bytes != 1
        || descriptors.is_empty()
        || descriptors.len() > MAX_DESCRIPTORS
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid descriptor transfer",
        ));
    }
    if descriptors.len() != marker[0] as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "descriptor count mismatch",
        ));
    }
    Ok(descriptors)
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use super::*;
    #[test]
    fn descriptors_survive_sender_close_and_are_cloexec() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let file = File::open("/dev/null").unwrap();
        send(&sender, &[file.as_raw_fd()]).unwrap();
        drop(file);
        let received = receive(&receiver).unwrap();
        assert_eq!(received.len(), 1);
        let flags =
            nix::fcntl::fcntl(received[0].as_raw_fd(), nix::fcntl::FcntlArg::F_GETFD).unwrap();
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
    }
}
