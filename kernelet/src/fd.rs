// SPDX-License-Identifier: MPL-2.0

//! Explicit ownership transfer of close-on-exec descriptors to the holder.

use std::{
    io::{self, IoSlice},
    mem,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::net::UnixStream,
    },
    ptr,
};

use nix::{
    fcntl::{FcntlArg, FdFlag, fcntl},
    sys::socket::{self, ControlMessage, MsgFlags},
};

const MAX_DESCRIPTORS: usize = 8;
// Linux's SCM_MAX_FD. The protocol still accepts at most MAX_DESCRIPTORS.
const MAX_RIGHTS_DESCRIPTORS: usize = 253;

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
    // SAFETY: CMSG_SPACE only computes the ABI's padded buffer size.
    let control_bytes =
        unsafe { libc::CMSG_SPACE((MAX_RIGHTS_DESCRIPTORS * size_of::<RawFd>()) as u32) as usize };
    // Linux CMSG alignment uses usize on both GNU and musl. Their cmsghdr
    // field layouts differ, so allocate aligned words rather than a literal.
    const { assert!(mem::align_of::<usize>() >= mem::align_of::<libc::cmsghdr>()) };
    let mut control = vec![0usize; control_bytes.div_ceil(size_of::<usize>())];
    let mut buffer = libc::iovec {
        iov_base: marker.as_mut_ptr().cast(),
        iov_len: marker.len(),
    };
    // SAFETY: msghdr has only integer and pointer fields, all valid when zero.
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut buffer;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control_bytes.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "control buffer exceeds ABI limit",
        )
    })?;
    // SAFETY: The live iovec and aligned control buffer are writable for their
    // declared lengths. recvmsg cannot retain their pointers after returning.
    let bytes = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
    if bytes < 0 {
        return Err(io::Error::last_os_error());
    }
    let actual_control_bytes = message.msg_controllen as usize;
    if actual_control_bytes > control_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid control message length",
        ));
    }
    let mut descriptors = Vec::new();
    // SAFETY: message points at the live control buffer with the actual length
    // returned by recvmsg. CMSG_FIRSTHDR checks whether a header fits.
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    // SAFETY: CMSG_LEN only computes the ABI's header and payload offset.
    let header_bytes = unsafe { libc::CMSG_LEN(0) as usize };
    while !header.is_null() {
        let offset = (header as usize)
            .checked_sub(message.msg_control as usize)
            .filter(|offset| *offset <= actual_control_bytes)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid control message offset")
            })?;
        let remaining = actual_control_bytes - offset;
        if remaining < size_of::<libc::cmsghdr>() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "incomplete control message header",
            ));
        }
        // SAFETY: The header is aligned by CMSG iteration and the complete
        // header lies inside the kernel's actual returned control length.
        let current = unsafe { &*header };
        let length = current.cmsg_len as usize;
        if length < header_bytes || length > remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid control message header",
            ));
        }
        if current.cmsg_level == libc::SOL_SOCKET && current.cmsg_type == libc::SCM_RIGHTS {
            let payload_bytes = length - header_bytes;
            // SAFETY: The checked header length bounds this payload. Each
            // complete RawFd was installed by recvmsg and is owned once here.
            let payload = unsafe { libc::CMSG_DATA(header) };
            for index in 0..payload_bytes / size_of::<RawFd>() {
                let raw = unsafe {
                    ptr::read_unaligned(payload.add(index * size_of::<RawFd>()).cast::<RawFd>())
                };
                descriptors.push(unsafe { OwnedFd::from_raw_fd(raw) });
            }
            if !payload_bytes.is_multiple_of(size_of::<RawFd>()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid rights payload",
                ));
            }
        }
        // SAFETY: The validated current length is bounded by actual controllen;
        // CMSG_NXTHDR checks the aligned next header against that same length.
        header = unsafe { libc::CMSG_NXTHDR(&message, header) };
    }
    // RLIMIT_NOFILE can cause partial installation even with a full-size
    // control buffer. Own those descriptors before preserving nix's ENOBUFS.
    if message.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::from_raw_os_error(libc::ENOBUFS));
    }
    if bytes != 1 || descriptors.is_empty() || descriptors.len() > MAX_DESCRIPTORS {
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
    set_cloexec(&descriptors)?;
    Ok(descriptors)
}

fn set_cloexec(descriptors: &[OwnedFd]) -> io::Result<()> {
    // Asterinas currently ignores MSG_CMSG_CLOEXEC. Both production receivers
    // run before starting threads or execs; this fallback is not atomic with
    // a concurrent fork. Linux retains the atomic recvmsg flag above.
    for descriptor in descriptors {
        let flags = FdFlag::from_bits_retain(fcntl(descriptor.as_raw_fd(), FcntlArg::F_GETFD)?);
        fcntl(
            descriptor.as_raw_fd(),
            FcntlArg::F_SETFD(flags | FdFlag::FD_CLOEXEC),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, File, OpenOptions},
        process::Command,
        time::{SystemTime, UNIX_EPOCH},
    };

    use nix::sys::resource::{Resource, getrlimit, setrlimit};

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

    #[test]
    fn cloexec_fallback_sets_the_flag_on_an_owned_descriptor() {
        let file = File::open("/dev/null").unwrap();
        let raw = nix::unistd::dup(file.as_raw_fd()).unwrap();
        // SAFETY: dup creates this new descriptor, which is owned exactly once.
        let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
        let before = fcntl(raw, FcntlArg::F_GETFD).unwrap();
        assert_eq!(before & libc::FD_CLOEXEC, 0);
        let descriptors = [descriptor];
        set_cloexec(&descriptors).unwrap();
        assert_eq!(
            fcntl(raw, FcntlArg::F_GETFD).unwrap(),
            before | libc::FD_CLOEXEC
        );
    }

    #[test]
    fn excessive_rights_are_rejected_after_all_received_descriptors_are_owned() {
        for count in [MAX_DESCRIPTORS + 1, MAX_RIGHTS_DESCRIPTORS] {
            let (sender, receiver) = UnixStream::pair().unwrap();
            let path = std::env::temp_dir().join(format!(
                "kernelet-fd-overflow-{}-{}-{count}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            let descriptors = vec![file.as_raw_fd(); count];
            // Bypass send's protocol bound to exercise a malformed peer.
            let marker = [count as u8];
            assert_eq!(
                socket::sendmsg::<()>(
                    sender.as_raw_fd(),
                    &[IoSlice::new(&marker)],
                    &[ControlMessage::ScmRights(&descriptors)],
                    MsgFlags::MSG_NOSIGNAL,
                    None,
                )
                .unwrap(),
                1
            );
            drop(file);
            assert_eq!(
                receive(&receiver).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            for entry in fs::read_dir("/proc/self/fd").unwrap() {
                assert!(!fs::read_link(entry.unwrap().path()).is_ok_and(|target| target == path));
            }
            fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn truncated_rights_are_closed_when_fd_limit_allows_only_a_partial_transfer() {
        const CHILD: &str = "KERNELET_FD_RLIMIT_CHILD";
        const MARKER: &str = "KERNELET_FD_RLIMIT_CHILD_OK";
        if std::env::var_os(CHILD).as_deref() != Some(std::ffi::OsStr::new("1")) {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "fd::tests::truncated_rights_are_closed_when_fd_limit_allows_only_a_partial_transfer",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            assert!(String::from_utf8(output.stdout).unwrap().contains(MARKER));
            return;
        }

        let (sender, receiver) = UnixStream::pair().unwrap();
        let file = File::open("/dev/null").unwrap();
        let maximum = fs::read_dir("/proc/self/fd")
            .unwrap()
            .map(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_str()
                    .unwrap()
                    .parse::<RawFd>()
                    .unwrap()
            })
            .max()
            .unwrap();
        let mut gaps = Vec::new();
        for descriptor in 0..=maximum {
            if fcntl(descriptor, FcntlArg::F_GETFD).is_err() {
                let raw = nix::unistd::dup(file.as_raw_fd()).unwrap();
                // SAFETY: dup returned this new descriptor, owned once here.
                gaps.push(unsafe { OwnedFd::from_raw_fd(raw) });
            }
        }
        let limit = maximum as u64 + 5;
        let open_fds = || {
            (0..limit as RawFd)
                .filter(|descriptor| fcntl(*descriptor, FcntlArg::F_GETFD).is_ok())
                .collect::<Vec<_>>()
        };
        let before = open_fds();
        assert_eq!(before.len(), maximum as usize + 1);
        let marker = [9u8];
        socket::sendmsg::<()>(
            sender.as_raw_fd(),
            &[IoSlice::new(&marker)],
            &[ControlMessage::ScmRights(&[file.as_raw_fd(); 9])],
            MsgFlags::MSG_NOSIGNAL,
            None,
        )
        .unwrap();
        let (soft, hard) = getrlimit(Resource::RLIMIT_NOFILE).unwrap();
        assert!(limit <= soft);
        setrlimit(Resource::RLIMIT_NOFILE, limit, hard).unwrap();
        let result = receive(&receiver);
        let after = open_fds();
        setrlimit(Resource::RLIMIT_NOFILE, soft, hard).unwrap();
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::ENOBUFS));
        assert_eq!(
            before, after,
            "partial SCM_RIGHTS installation leaked descriptors"
        );
        println!("{MARKER}");
    }
}
