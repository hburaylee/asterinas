// SPDX-License-Identifier: MPL-2.0

//! CID queries and explicit route authorization through holder capabilities.

use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::net::UnixStream,
    },
    path::Path,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use clap::Subcommand;
use nix::{
    errno::Errno,
    poll::{PollFd, PollFlags, PollTimeout, poll},
    sys::socket::{self, AddressFamily, SockFlag, SockType, UnixAddr},
};
use serde::{Deserialize, Serialize};

use super::{CONTROL_TIMEOUT, Control, Reply};
use crate::{fd, protocol, uapi};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Subcommand)]
pub(crate) enum PairAction {
    Allow,
    Revoke,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Identity {
    id: String,
    cid: u32,
}

impl Identity {
    pub(super) fn new(id: &str, cid: Option<u32>) -> Result<Self> {
        super::validate_id(id)?;
        let cid = cid.context("sandbox record has no CREATE CID; recreate the sandbox")?;
        ensure!((3..u32::MAX).contains(&cid), "invalid sandbox CID");
        Ok(Self { id: id.into(), cid })
    }

    pub(super) fn cid(&self) -> u32 {
        self.cid
    }

    fn validate_for(&self, id: &str) -> Result<()> {
        Self::new(&self.id, Some(self.cid))?;
        ensure!(self.id == id, "holder sandbox identity differs");
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub(super) struct Pair {
    id: String,
    cid: u32,
    peer_id: String,
    peer_cid: u32,
    allowed: bool,
}

pub(super) fn query(directory: &Path, id: &str) -> Result<Identity> {
    let (reply, _) = request(directory, &Control::VsockCid)?;
    identity(reply, id)
}

pub(super) fn set_pair(root: &Path, id: &str, peer_id: &str, action: PairAction) -> Result<Pair> {
    super::validate_id(id)?;
    super::validate_id(peer_id)?;
    ensure!(id != peer_id, "a sandbox cannot authorize itself");

    // Both connections use the caller's access to the private holder sockets.
    // Copies live only through this ioctl; each holder retains its own reference.
    let (local, sandbox) = capability(&root.join(id), id)?;
    let (peer, peer_sandbox) = capability(&root.join(peer_id), peer_id)?;
    ensure!(local.cid != peer.cid, "sandbox CIDs are not distinct");
    let allowed = matches!(action, PairAction::Allow);
    let args = uapi::VsockPolicyArgs {
        peer_fd: peer_sandbox.as_raw_fd(),
        allow: u32::from(allowed),
    };
    uapi::Sandbox::from_file(sandbox).vsock_policy(&args)?;

    Ok(Pair {
        id: local.id,
        cid: local.cid,
        peer_id: peer.id,
        peer_cid: peer.cid,
        allowed,
    })
}

fn capability(directory: &Path, id: &str) -> Result<(Identity, File)> {
    let (reply, mut stream) = request(directory, &Control::VsockCapability)?;
    let identity = identity(reply, id)?;
    stream.set_read_timeout(Some(CONTROL_TIMEOUT))?;
    protocol::send_value(&mut stream, &())?;
    let mut descriptors = fd::receive(&stream)?;
    ensure!(descriptors.len() == 1, "expected one sandbox descriptor");
    let descriptor = descriptors.pop().context("missing sandbox descriptor")?;
    Ok((identity, File::from(descriptor)))
}

fn identity(reply: Reply, id: &str) -> Result<Identity> {
    let Reply::VsockIdentity(identity) = reply else {
        bail!("invalid holder vsock identity response");
    };
    identity.validate_for(id)?;
    Ok(identity)
}

fn request(directory: &Path, operation: &Control) -> Result<(Reply, UnixStream)> {
    let mut stream = connect_control(directory)?;
    stream.set_read_timeout(Some(CONTROL_TIMEOUT))?;
    stream.set_write_timeout(Some(CONTROL_TIMEOUT))?;
    protocol::send_value(&mut stream, operation)?;
    let reply = super::receive_reply(&mut stream)?;
    Ok((reply, stream))
}

fn connect_control(directory: &Path) -> Result<UnixStream> {
    let descriptor = socket::socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )?;
    let path = directory.join("control.sock");
    let address = UnixAddr::new(path.as_path())?;
    let deadline = Instant::now() + CONTROL_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::from_raw_os_error(libc::ETIMEDOUT).into());
        }
        match socket::connect(descriptor.as_raw_fd(), &address) {
            Ok(()) | Err(Errno::EISCONN) => break,
            // A full Unix listener backlog does not start a pending connect.
            // Retry this nonblocking socket under the same fixed deadline.
            Err(Errno::EAGAIN) => thread::sleep(remaining.min(Duration::from_millis(10))),
            Err(Errno::EINTR) => continue,
            Err(Errno::EINPROGRESS | Errno::EALREADY) => {
                let mut descriptors = [PollFd::new(descriptor.as_fd(), PollFlags::POLLOUT)];
                let ready = match poll(&mut descriptors, PollTimeout::try_from(remaining)?) {
                    Ok(ready) => ready,
                    Err(Errno::EINTR) => continue,
                    Err(error) => return Err(error.into()),
                };
                if ready == 0 {
                    return Err(std::io::Error::from_raw_os_error(libc::ETIMEDOUT).into());
                }
                let error = socket::getsockopt(&descriptor, socket::sockopt::SocketError)?;
                if error != 0 {
                    return Err(std::io::Error::from_raw_os_error(error).into());
                }
                ensure!(
                    descriptors[0]
                        .revents()
                        .is_some_and(|events| events.contains(PollFlags::POLLOUT)),
                    "holder control socket did not become writable"
                );
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }
    let stream = UnixStream::from(descriptor);
    stream.set_nonblocking(false)?;
    Ok(stream)
}

pub(super) fn send_capability(
    stream: &mut UnixStream,
    identity: Identity,
    sandbox: &File,
) -> Result<()> {
    stream.set_write_timeout(Some(CONTROL_TIMEOUT))?;
    protocol::send_value(stream, &Reply::VsockIdentity(identity))?;
    // Asterinas ordinary reads may consume adjacent auxiliary data. Wait until
    // the client has read and validated the identity before queueing any FDs.
    stream.set_read_timeout(Some(CONTROL_TIMEOUT))?;
    protocol::receive_value::<()>(stream)?;
    fd::send(stream, &[sandbox.as_raw_fd()])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::{fd::AsRawFd, unix::net::UnixListener},
        path::PathBuf,
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };

    use clap::Parser;

    use super::*;
    use crate::runtime::{Cli, Operation, Record};

    struct Directory(PathBuf);

    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "kernelet-vsock-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn serve(
            &self,
            id: &str,
            handler: impl FnOnce(UnixStream) + Send + 'static,
        ) -> thread::JoinHandle<()> {
            let directory = self.0.join(id);
            fs::create_dir(&directory).unwrap();
            let listener = UnixListener::bind(directory.join("control.sock")).unwrap();
            thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                handler(stream);
            })
        }
    }

    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn assert_files_closed(paths: &[PathBuf]) {
        for entry in fs::read_dir("/proc/self/fd").unwrap() {
            let target = fs::read_link(entry.unwrap().path());
            assert!(!target.is_ok_and(|target| paths.contains(&target)));
        }
    }

    #[test]
    fn missing_cid_preserves_legacy_records_without_inventing_an_address() {
        let record: Record = serde_json::from_value(serde_json::json!({
            "state": {"ociVersion":"1.0.2", "id":"old", "status":"running",
                "pid":1, "bundle":"/bundle", "annotations":{}},
            "config": {"ociVersion":"1.0.2", "root":{"path":"rootfs"},
                "process":{"args":["/bin/sh"], "cwd":"/"}}
        }))
        .unwrap();
        assert_eq!(record.vsock_cid, None);
        assert!(
            Identity::new("old", record.vsock_cid)
                .unwrap_err()
                .to_string()
                .contains("no CREATE CID")
        );
        assert!(
            serde_json::to_value(record)
                .unwrap()
                .get("vsock_cid")
                .is_none()
        );
        for cid in [0, 1, 2, u32::MAX] {
            assert!(Identity::new("bad", Some(cid)).is_err());
        }
        for cid in [3, u32::MAX - 1] {
            assert_eq!(Identity::new("valid", Some(cid)).unwrap().cid(), cid);
        }
    }

    #[test]
    fn cli_commands_keep_value_output_explicit_and_pair_actions_distinct() {
        for (arguments, value) in [
            (vec!["kernelet-runtime", "vsock-cid", "local"], false),
            (
                vec!["kernelet-runtime", "vsock-cid", "local", "--value"],
                true,
            ),
        ] {
            let cli = Cli::try_parse_from(arguments).unwrap();
            assert!(
                matches!(cli.command, Operation::VsockCid { id, value: actual } if id == "local" && actual == value)
            );
        }
        for (verb, allowed) in [("allow", true), ("revoke", false)] {
            let cli =
                Cli::try_parse_from(["kernelet-runtime", "vsock-pair", "local", "peer", verb])
                    .unwrap();
            assert!(
                matches!(cli.command, Operation::VsockPair { id, peer_id, action }
                if id == "local" && peer_id == "peer" && matches!(action, PairAction::Allow) == allowed)
            );
        }
        assert!(Cli::try_parse_from(["kernelet-runtime", "vsock-pair", "local", "peer"]).is_err());
    }

    #[test]
    fn cid_query_uses_the_holder_identity_and_rejects_a_different_instance() {
        let directory = Directory::new();
        let server = directory.serve("actual", |mut stream| {
            assert!(matches!(
                protocol::receive_value(&mut stream).unwrap(),
                Control::VsockCid
            ));
            protocol::send_value(
                &mut stream,
                &Reply::VsockIdentity(Identity::new("actual", Some(27)).unwrap()),
            )
            .unwrap();
        });
        let identity = query(&directory.0.join("actual"), "actual").unwrap();
        assert_eq!(
            serde_json::to_value(identity).unwrap(),
            serde_json::json!({"id":"actual", "cid":27})
        );
        server.join().unwrap();

        let server = directory.serve("wrong", |mut stream| {
            let _: Control = protocol::receive_value(&mut stream).unwrap();
            protocol::send_value(
                &mut stream,
                &Reply::VsockIdentity(Identity::new("replacement", Some(28)).unwrap()),
            )
            .unwrap();
        });
        assert!(
            query(&directory.0.join("wrong"), "wrong")
                .unwrap_err()
                .to_string()
                .contains("identity differs")
        );
        server.join().unwrap();
    }

    #[test]
    fn capability_transfer_preserves_the_file_and_cloexec() {
        let directory = Directory::new();
        let path = directory.0.join("sandbox-file");
        fs::write(&path, b"owned capability").unwrap();
        let server = directory.serve("local", move |mut stream| {
            assert!(matches!(
                protocol::receive_value(&mut stream).unwrap(),
                Control::VsockCapability
            ));
            let file = File::open(path).unwrap();
            send_capability(&mut stream, Identity::new("local", Some(3)).unwrap(), &file).unwrap();
        });
        let (_, mut file) = capability(&directory.0.join("local"), "local").unwrap();
        server.join().unwrap();
        let flags = nix::fcntl::fcntl(file.as_raw_fd(), nix::fcntl::FcntlArg::F_GETFD).unwrap();
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut bytes).unwrap();
        assert_eq!(bytes, b"owned capability");
    }

    #[test]
    fn capability_does_not_queue_rights_until_the_identity_is_acknowledged() {
        let directory = Directory::new();
        let server = directory.serve("local", |mut stream| {
            let _: Control = protocol::receive_value(&mut stream).unwrap();
            let file = File::open("/dev/null").unwrap();
            send_capability(&mut stream, Identity::new("local", Some(3)).unwrap(), &file).unwrap();
        });
        let (reply, mut stream) =
            request(&directory.0.join("local"), &Control::VsockCapability).unwrap();
        identity(reply, "local").unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let error = fd::receive(&stream).unwrap_err();
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
        protocol::send_value(&mut stream, &()).unwrap();
        stream.set_read_timeout(Some(CONTROL_TIMEOUT)).unwrap();
        assert_eq!(fd::receive(&stream).unwrap().len(), 1);
        server.join().unwrap();
    }

    #[test]
    fn capability_rejects_missing_and_invalid_acknowledgements() {
        for invalid_ack in [false, true] {
            let directory = Directory::new();
            let server = directory.serve("local", move |mut stream| {
                let _: Control = protocol::receive_value(&mut stream).unwrap();
                let file = File::open("/dev/null").unwrap();
                let error =
                    send_capability(&mut stream, Identity::new("local", Some(3)).unwrap(), &file)
                        .unwrap_err();
                if invalid_ack {
                    assert_eq!(
                        error.downcast_ref::<std::io::Error>().unwrap().kind(),
                        std::io::ErrorKind::InvalidData
                    );
                } else {
                    assert_eq!(
                        error.downcast_ref::<std::io::Error>().unwrap().kind(),
                        std::io::ErrorKind::UnexpectedEof
                    );
                }
            });
            let (reply, mut stream) =
                request(&directory.0.join("local"), &Control::VsockCapability).unwrap();
            identity(reply, "local").unwrap();
            if invalid_ack {
                protocol::send_value(&mut stream, &true).unwrap();
            }
            drop(stream);
            server.join().unwrap();
        }
    }

    #[test]
    fn pair_failure_preserves_real_ioctl_errno_and_releases_received_capabilities() {
        for action in [PairAction::Allow, PairAction::Revoke] {
            let directory = Directory::new();
            let mut servers = Vec::new();
            let mut paths = Vec::new();
            for (id, cid) in [("local", 3), ("peer", 4)] {
                let path = directory.0.join(format!("{id}-file"));
                fs::write(&path, b"not a sandbox").unwrap();
                paths.push(path.clone());
                servers.push(directory.serve(id, move |mut stream| {
                    assert!(matches!(
                        protocol::receive_value(&mut stream).unwrap(),
                        Control::VsockCapability
                    ));
                    let file = File::open(path).unwrap();
                    send_capability(&mut stream, Identity::new(id, Some(cid)).unwrap(), &file)
                        .unwrap();
                }));
            }
            let error = set_pair(&directory.0, "local", "peer", action).unwrap_err();
            assert_eq!(
                error
                    .downcast_ref::<std::io::Error>()
                    .unwrap()
                    .raw_os_error(),
                Some(libc::ENOTTY)
            );
            for server in servers {
                server.join().unwrap();
            }
            assert_files_closed(&paths);
        }
    }

    #[test]
    fn capability_rejects_multiple_descriptors_and_drops_them() {
        let directory = Directory::new();
        let path = directory.0.join("extra-capabilities");
        fs::write(&path, b"not a sandbox").unwrap();
        let server_path = path.clone();
        let server = directory.serve("local", move |mut stream| {
            let _: Control = protocol::receive_value(&mut stream).unwrap();
            protocol::send_value(
                &mut stream,
                &Reply::VsockIdentity(Identity::new("local", Some(3)).unwrap()),
            )
            .unwrap();
            protocol::receive_value::<()>(&mut stream).unwrap();
            let file = File::open(server_path).unwrap();
            fd::send(&stream, &[file.as_raw_fd(), file.as_raw_fd()]).unwrap();
        });
        assert!(
            capability(&directory.0.join("local"), "local")
                .unwrap_err()
                .to_string()
                .contains("expected one")
        );
        server.join().unwrap();
        assert_files_closed(&[path]);
        assert!(set_pair(&directory.0, "same", "same", PairAction::Allow).is_err());
        assert!(set_pair(&directory.0, "../outside", "peer", PairAction::Allow).is_err());
    }
}
