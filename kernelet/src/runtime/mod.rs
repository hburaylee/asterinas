// SPDX-License-Identifier: MPL-2.0

//! OCI command lifecycle and its descriptor-owning holder process.

mod create;
mod crossing_capture;
mod holder;
mod hooks;
mod rootfs;
mod status;
mod terminal;
mod tlb_capture;
mod vsock;

use std::{
    fs::{self, File},
    io::{IsTerminal, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};
pub(crate) use create::create_for_shim;
use serde::{Deserialize, Serialize};
use status::InstanceStatus;
use vsock::PairAction;

use crate::{config::Process, protocol};

// Leave headroom for Host execution storage within the default per-user
// admission budget of 512 grains, which includes both Guest and Host memory.
const DEFAULT_MAX_GRAINS: u32 = 256;
const DEFAULT_VCPUS: u16 = 2;
const DEFAULT_ROOT: &str = "/run/kernelet";
const DEFAULT_CACHE: &str = "/var/cache/kernelet";
const DEFAULT_AGENT: &str = "/usr/libexec/kernelet-agent";
const DEFAULT_MKE2FS: &str = "/usr/libexec/kernelet-mke2fs";
const CONTROL_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Parser)]
#[command(name = "kernelet-runtime", version)]
pub struct Cli {
    #[arg(long, default_value = DEFAULT_ROOT)]
    root: PathBuf,
    #[arg(long, default_value = DEFAULT_CACHE)]
    cache: PathBuf,
    #[arg(long, default_value = DEFAULT_AGENT)]
    agent: PathBuf,
    #[arg(long, default_value = DEFAULT_MKE2FS)]
    mke2fs: PathBuf,
    #[arg(long, default_value_t = DEFAULT_VCPUS)]
    vcpus: u16,
    #[arg(long, default_value_t = DEFAULT_MAX_GRAINS)]
    max_grains: u32,
    #[command(subcommand)]
    command: Operation,
}

#[derive(Subcommand)]
enum Operation {
    Create {
        id: String,
        #[arg(short, long)]
        bundle: PathBuf,
        #[arg(long)]
        console_socket: Option<PathBuf>,
        #[arg(long)]
        pid_file: Option<PathBuf>,
    },
    Start {
        id: String,
        #[arg(long)]
        attach: bool,
    },
    State {
        id: String,
    },
    Stats {
        id: String,
    },
    /// Read the kernel instance state and exit reason without changing lifecycle.
    InspectStatus {
        id: String,
    },
    /// Control a Host-only RQ1 TLB capture in the sandbox FD owner.
    Rq1Tlb {
        id: String,
        #[command(subcommand)]
        action: TlbAction,
    },
    /// Capture one bounded crossing window in the sandbox FD owner.
    Rq1Crossing {
        id: String,
        #[command(subcommand)]
        action: CrossingAction,
    },
    /// Query the CID returned by sandbox creation.
    VsockCid {
        id: String,
        #[arg(long)]
        value: bool,
    },
    /// Explicitly authorize or revoke one pair of live sandboxes.
    VsockPair {
        id: String,
        peer_id: String,
        #[command(subcommand)]
        action: PairAction,
    },
    Kill {
        id: String,
        #[arg(default_value = "TERM")]
        signal: String,
    },
    Delete {
        id: String,
        #[arg(short, long)]
        force: bool,
    },
    Resize {
        id: String,
        columns: u16,
        rows: u16,
    },
    Exec {
        id: String,
        #[arg(long)]
        process: PathBuf,
    },
    #[command(hide = true)]
    Holder {
        directory: PathBuf,
    },
    Pause {
        id: String,
    },
    Resume {
        id: String,
    },
    Update {
        id: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Subcommand)]
pub(crate) enum TlbAction {
    /// Arm a new per-open capture; the instance must be running.
    Arm,
    /// Close admission and read a snapshot; EBUSY permits a later retry.
    Finish,
    /// Release the capture, including an unfinished capture.
    Close,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Subcommand)]
pub(crate) enum CrossingAction {
    /// Arm a window with a nonzero evidence nonce; the instance must be running.
    Arm { nonce: u64 },
    /// Close admission and read the snapshot; EBUSY permits a later retry.
    Finish,
    /// Release or cancel the holder's capture lease.
    Close,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct State {
    oci_version: String,
    id: String,
    pub(crate) status: String,
    pub(crate) pid: u32,
    pub(crate) bundle: PathBuf,
    annotations: std::collections::BTreeMap<String, String>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct Record {
    pub(crate) state: State,
    pub(crate) config: crate::config::Config,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) vsock_cid: Option<u32>,
}

#[derive(Deserialize, Serialize)]
pub(crate) enum Control {
    CloseInput { id: u64 },
    Resize { id: u64, columns: u16, rows: u16 },
    State,
    Stats,
    InspectStatus,
    Rq1Tlb { action: TlbAction },
    Rq1Crossing { action: CrossingAction },
    VsockCid,
    VsockCapability,
    Processes,
    ExitStatus { id: u64 },
    ForgetExited { id: u64 },
    Start { attach: bool },
    Exec { process: Process },
    ReserveProcess,
    Launch { id: u64, process: Option<Process> },
    Signal { id: u64, signal: i32 },
    SignalAll { signal: i32 },
    Delete { force: bool },
}

#[derive(Deserialize, Serialize)]
pub(crate) enum Reply {
    Ready,
    State(State),
    Stats(Stats),
    InspectStatus(InstanceStatus),
    Rq1TlbSnapshot(String),
    Rq1CrossingSnapshot(String),
    VsockIdentity(vsock::Identity),
    Processes(Vec<u32>),
    ExitStatus { code: Option<i32> },
    Reserved { id: u64 },
    StartRejected(String),
    Started { id: u64 },
    Done,
    Error(String),
}

#[derive(Deserialize, Serialize)]
pub(crate) struct Stats {
    pub cpu_time_ns: u64,
    pub throttled_ns: u64,
    pub completion_cpu_ns: Option<u64>,
    pub ingress_copy_cpu_ns: Option<u64>,
    pub host_bytes_charged: u64,
    pub host_overhead_bytes: u64,
    pub stacks_allocated: u32,
    pub memory_bytes: u64,
    pub memory_limit: u64,
}

pub fn run(cli: Cli) -> Result<i32> {
    if let Operation::Holder { directory } = &cli.command {
        return holder::run(directory).map(|()| 0);
    }
    let id = match &cli.command {
        Operation::Create { id, .. }
        | Operation::Start { id, .. }
        | Operation::State { id }
        | Operation::Stats { id }
        | Operation::InspectStatus { id }
        | Operation::Rq1Tlb { id, .. }
        | Operation::Rq1Crossing { id, .. }
        | Operation::VsockCid { id, .. }
        | Operation::VsockPair { id, .. }
        | Operation::Kill { id, .. }
        | Operation::Delete { id, .. }
        | Operation::Resize { id, .. }
        | Operation::Exec { id, .. }
        | Operation::Pause { id }
        | Operation::Resume { id }
        | Operation::Update { id } => id,
        _ => unreachable!(),
    };
    validate_id(id)?;
    let directory = cli.root.join(id);
    match &cli.command {
        Operation::Create {
            bundle,
            console_socket,
            pid_file,
            ..
        } => create::create(
            &cli,
            id,
            bundle,
            &directory,
            console_socket.as_deref(),
            pid_file.as_deref(),
        )?,
        Operation::State { .. } => {
            let state = state(&directory)?;
            println!("{}", serde_json::to_string(&state)?);
        }
        Operation::InspectStatus { .. } => {
            println!("{}", serde_json::to_string(&inspect_status(&directory)?)?);
        }
        Operation::VsockCid { value, .. } => {
            let identity = vsock::query(&directory, id)?;
            if *value {
                println!("{}", identity.cid());
            } else {
                println!("{}", serde_json::to_string(&identity)?);
            }
        }
        Operation::VsockPair {
            peer_id, action, ..
        } => {
            let pair = vsock::set_pair(&cli.root, id, peer_id, *action)?;
            println!("{}", serde_json::to_string(&pair)?);
        }
        Operation::Rq1Tlb { action, .. } => {
            let (reply, _) = request(&directory, &Control::Rq1Tlb { action: *action })?;
            match (action, reply) {
                (TlbAction::Finish, Reply::Rq1TlbSnapshot(snapshot)) => {
                    println!("{snapshot}");
                }
                (TlbAction::Arm | TlbAction::Close, Reply::Done) => {}
                _ => bail!("invalid holder TLB capture response"),
            }
        }
        Operation::Rq1Crossing { action, .. } => {
            let (reply, _) = request(&directory, &Control::Rq1Crossing { action: *action })?;
            match (action, reply) {
                (CrossingAction::Finish, Reply::Rq1CrossingSnapshot(snapshot)) => {
                    println!("{snapshot}")
                }
                (CrossingAction::Arm { .. } | CrossingAction::Close, Reply::Done) => {}
                _ => bail!("invalid holder crossing capture response"),
            }
        }
        Operation::Stats { .. } => {
            let (reply, _) = request(&directory, &Control::Stats)?;
            let Reply::Stats(stats) = reply else {
                bail!("invalid holder stats response");
            };
            println!("{}", serde_json::to_string(&stats)?);
        }
        Operation::Start { attach, .. } => {
            let terminal = if *attach {
                let record: Record =
                    serde_json::from_reader(File::open(directory.join("config.json"))?)?;
                record.config.process.terminal
            } else {
                false
            };
            let (reply, stream) = request(&directory, &Control::Start { attach: *attach })?;
            let Reply::Started { id } = reply else {
                bail!("invalid holder start response");
            };
            run_hooks(&directory, "poststart")?;
            if *attach {
                if terminal && std::io::stdout().is_terminal() {
                    let mut stdout = std::io::stdout().lock();
                    writeln!(
                        stdout,
                        "\n{}",
                        logo_ascii_art::get_kernelet_gradient_color_version()
                    )?;
                    stdout.flush()?;
                }
                return forward_process(&directory, stream, id, terminal);
            }
        }
        Operation::Exec { process, .. } => {
            let process: Process = serde_json::from_reader(File::open(process)?)?;
            process.validate()?;
            let terminal = process.terminal;
            let (reply, stream) = request(&directory, &Control::Exec { process })?;
            let Reply::Started { id } = reply else {
                bail!("invalid holder exec response");
            };
            return forward_process(&directory, stream, id, terminal);
        }
        Operation::Resize { columns, rows, .. } => {
            request(
                &directory,
                &Control::Resize {
                    id: 1,
                    columns: *columns,
                    rows: *rows,
                },
            )?;
        }
        Operation::Kill { signal, .. } => {
            request(
                &directory,
                &Control::Signal {
                    id: 1,
                    signal: parse_signal(signal)?,
                },
            )?;
        }
        Operation::Delete { force, .. } => {
            delete(&directory, *force)?;
        }
        Operation::Pause { .. } | Operation::Resume { .. } | Operation::Update { .. } => bail!(
            "operation unsupported: {}",
            std::io::Error::from_raw_os_error(libc::ENOTSUP)
        ),
        _ => unreachable!(),
    }
    Ok(0)
}

fn forward_process(directory: &Path, stream: UnixStream, id: u64, terminal: bool) -> Result<i32> {
    let code = terminal::forward(directory, stream, id, terminal)?;
    // The consumer owns this status after forwarding returned the actual exit.
    // An interrupted attachment keeps its status available for later observation.
    request(directory, &Control::ForgetExited { id })?;
    Ok(code)
}

/// A missing listener after successful creation means the capability owner died.
fn holder_disconnected(error: &anyhow::Error) -> bool {
    error.downcast_ref::<std::io::Error>().is_some_and(|error| {
        matches!(
            error.raw_os_error(),
            Some(libc::ENOENT | libc::ECONNREFUSED)
        )
    })
}

/// Query the retained sandbox capability; never substitute OCI or agent state.
fn inspect_status(directory: &Path) -> Result<InstanceStatus> {
    let (reply, _) = request(directory, &Control::InspectStatus)?;
    let Reply::InspectStatus(status) = reply else {
        bail!("invalid holder instance status response");
    };
    status.validate()?;
    Ok(status)
}

pub(crate) fn state(directory: &Path) -> Result<State> {
    match request(directory, &Control::State) {
        Ok((Reply::State(state), _)) => Ok(state),
        Ok(_) => bail!("invalid holder state response"),
        Err(error) if holder_disconnected(&error) => {
            let record: Record =
                serde_json::from_reader(File::open(directory.join("config.json"))?)?;
            let mut state = record.state;
            state.status = "stopped".into();
            Ok(state)
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn delete(directory: &Path, force: bool) -> Result<()> {
    match request(directory, &Control::Delete { force }) {
        Ok(_) => {}
        Err(error) if holder_disconnected(&error) => {
            // Closing the owner's last capability already revokes the sandbox.
            ensure!(
                state(directory)?.status == "stopped",
                "sandbox is not stopped"
            );
        }
        Err(error) => return Err(error),
    }
    run_hooks(directory, "poststop")?;
    fs::remove_dir_all(directory)?;
    Ok(())
}

pub(crate) fn request(directory: &Path, operation: &Control) -> Result<(Reply, UnixStream)> {
    let mut stream = begin_request(directory, operation)?;
    let reply = receive_reply(&mut stream)?;
    if let Reply::StartRejected(detail) = &reply {
        bail!("{detail}");
    }
    Ok((reply, stream))
}

fn begin_request(directory: &Path, operation: &Control) -> Result<UnixStream> {
    let mut stream =
        UnixStream::connect(directory.join("control.sock")).context("connect to sandbox holder")?;
    stream.set_read_timeout(Some(CONTROL_TIMEOUT))?;
    protocol::send_value(&mut stream, operation)?;
    Ok(stream)
}

fn receive_reply(stream: &mut UnixStream) -> Result<Reply> {
    let reply: Reply = protocol::receive_value(stream)?;
    if let Reply::Error(message) = &reply {
        bail!("{message}");
    }
    stream.set_read_timeout(None)?;
    Ok(reply)
}

/// Runs every hook of one OCI phase against the sandbox state. The per-hook
/// subprocess lifecycle lives in [`hooks`] and is bounded end to end.
pub(crate) fn run_hooks(directory: &Path, kind: &str) -> Result<()> {
    let record: Record = serde_json::from_reader(File::open(directory.join("config.json"))?)?;
    let mut state = request(directory, &Control::State)
        .ok()
        .and_then(|(reply, _)| {
            if let Reply::State(state) = reply {
                Some(state)
            } else {
                None
            }
        })
        .unwrap_or(record.state);
    if kind == "poststop" {
        state.status = "stopped".into();
    }
    for hook in record.config.hooks.get(kind).into_iter().flatten() {
        hooks::run_hook(kind, hook, &state)?;
    }
    Ok(())
}

fn validate_id(id: &str) -> Result<()> {
    ensure!(
        !id.is_empty()
            && id.len() <= 128
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
            && id != "."
            && id != "..",
        "invalid container ID"
    );
    Ok(())
}
fn parse_signal(value: &str) -> Result<i32> {
    if let Ok(signal) = value.parse::<i32>() {
        ensure!((0..=64).contains(&signal), "invalid signal number");
        return Ok(signal);
    }
    let name = if value.starts_with("SIG") {
        value.to_owned()
    } else {
        format!("SIG{value}")
    };
    Ok(name.parse::<nix::sys::signal::Signal>()? as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StatusDirectory(PathBuf);

    impl StatusDirectory {
        fn new() -> Self {
            let directory = std::env::temp_dir().join(format!(
                "kernelet-inspect-status-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&directory).unwrap();
            Self(directory)
        }
    }

    impl Drop for StatusDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    // A real local IPC exchange verifies the holder protocol, not a kernel ioctl.
    fn status_reply(reply: serde_json::Value) -> Result<InstanceStatus> {
        let directory = StatusDirectory::new();
        let listener =
            std::os::unix::net::UnixListener::bind(directory.0.join("control.sock")).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            assert!(matches!(
                protocol::receive_value::<Control>(&mut stream).unwrap(),
                Control::InspectStatus
            ));
            protocol::send_value(&mut stream, &reply).unwrap();
        });
        let result = inspect_status(&directory.0);
        server.join().unwrap();
        result
    }

    fn status_json(state: &str, reason: &str) -> serde_json::Value {
        serde_json::json!({"InspectStatus": {
            "version": 1, "state": state, "reason": reason, "code": 0,
            "uptime_ns": 12, "cpu_time_ns": 7,
            "fault_addr": "0x0000000000000000", "fault_ip": "0x0000000000000000",
            "message": "", "message_truncated": false
        }})
    }

    #[test]
    fn tlb_capture_commands_select_explicit_holder_actions() {
        for (name, expected) in [("arm", "Arm"), ("finish", "Finish"), ("close", "Close")] {
            let cli =
                Cli::try_parse_from(["kernelet-runtime", "rq1-tlb", "subject", name]).unwrap();
            let Operation::Rq1Tlb { id, action } = cli.command else {
                panic!("wrong diagnostic command");
            };
            assert_eq!(id, "subject");
            assert_eq!(serde_json::to_value(action).unwrap(), expected);
        }
        assert!(Cli::try_parse_from(["kernelet-runtime", "rq1-tlb", "subject"]).is_err());
        assert!(
            Cli::try_parse_from(["kernelet-runtime", "rq1-tlb", "subject", "unknown"]).is_err()
        );
    }

    #[test]
    fn inspect_status_reads_running_and_exited_diagnostics_without_agent_state() {
        let cli = Cli::try_parse_from(["kernelet-runtime", "inspect-status", "subject"]).unwrap();
        assert!(matches!(cli.command, Operation::InspectStatus { id } if id == "subject"));
        for state in ["running", "exited"] {
            let reply = status_reply(status_json(state, "none")).unwrap();
            assert_eq!(serde_json::to_value(reply).unwrap()["state"], state);
        }
        let mut reply = status_json("exited", "panicked");
        reply["InspectStatus"]["message"] = "panic: original message\n中文".into();
        assert_eq!(
            serde_json::to_value(status_reply(reply).unwrap()).unwrap()["message"],
            "panic: original message\n中文"
        );
    }

    #[test]
    fn inspect_status_rejects_wrong_malformed_and_failed_holder_replies() {
        assert!(
            status_reply(serde_json::json!("Done"))
                .unwrap_err()
                .to_string()
                .contains("invalid holder instance status")
        );
        let error =
            status_reply(serde_json::json!({"Error":"STATUS ioctl denied: original diagnostic"}))
                .unwrap_err();
        assert_eq!(
            error.to_string(),
            "STATUS ioctl denied: original diagnostic"
        );
        for invalid in ["version", "state", "message", "extra"] {
            let mut reply = status_json("running", "none");
            reply["InspectStatus"][invalid] = match invalid {
                "version" => 2.into(),
                "state" => "unrecognized".into(),
                "message" => 7.into(),
                _ => true.into(),
            };
            assert!(status_reply(reply).is_err(), "accepted malformed {invalid}");
        }
        let directory = StatusDirectory::new();
        let listener =
            std::os::unix::net::UnixListener::bind(directory.0.join("control.sock")).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _: Control = protocol::receive_value(&mut stream).unwrap();
            // A truncated response is an IPC failure, never a synthetic exit.
            stream.write_all(&10u32.to_le_bytes()).unwrap();
            stream.write_all(b"{").unwrap();
        });
        assert!(inspect_status(&directory.0).is_err());
        server.join().unwrap();
    }

    #[test]
    fn inspect_status_has_no_oci_fallback_after_holder_loss_or_delete() {
        let directory = StatusDirectory::new();
        fs::write(
            directory.0.join("config.json"),
            b"{\"state\":{\"status\":\"stopped\"}}",
        )
        .unwrap();
        let error = inspect_status(&directory.0).unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::NotFound
        );
        fs::remove_dir_all(&directory.0).unwrap();
        let error = inspect_status(&directory.0).unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::NotFound
        );
    }

    #[test]
    fn lost_holder_state_is_stopped_and_can_be_deleted() {
        let directory =
            std::env::temp_dir().join(format!("kernelet-holder-recovery-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let record = serde_json::json!({
            "state": {"ociVersion":"1.0.2", "id":"recover", "status":"running", "pid":42, "bundle":"/bundle", "annotations":{}},
            "config": {"ociVersion":"1.0.2", "root":{"path":"rootfs"}, "process":{"args":["/bin/sh"],"cwd":"/"}}
        });
        fs::write(
            directory.join("config.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        // A listener left in the filesystem but no longer held by a process.
        let listener =
            std::os::unix::net::UnixListener::bind(directory.join("control.sock")).unwrap();
        drop(listener);
        let recovered = state(&directory).unwrap();
        assert_eq!(recovered.status, "stopped");
        assert_eq!(recovered.pid, 42);
        delete(&directory, false).unwrap();
        assert!(!directory.exists());
        assert!(!holder_disconnected(
            &std::io::Error::from_raw_os_error(libc::EACCES).into()
        ));
    }
    #[test]
    fn crossing_commands_preserve_full_width_nonce_and_holder_action() {
        for nonce in [1, u64::MAX] {
            let nonce_text = nonce.to_string();
            let cli = Cli::try_parse_from([
                "kernelet-runtime",
                "rq1-crossing",
                "subject",
                "arm",
                &nonce_text,
            ])
            .unwrap();
            let Operation::Rq1Crossing { id, action } = cli.command else {
                panic!("wrong crossing command");
            };
            assert_eq!(id, "subject");
            assert!(matches!(action, CrossingAction::Arm { nonce: actual } if actual == nonce));
            let raw = serde_json::to_vec(&Control::Rq1Crossing { action }).unwrap();
            let request: Control = serde_json::from_slice(&raw).unwrap();
            assert!(
                matches!(request, Control::Rq1Crossing { action: CrossingAction::Arm { nonce: actual } } if actual == nonce)
            );
        }
        for (command, expected) in [("finish", "Finish"), ("close", "Close")] {
            let cli = Cli::try_parse_from(["kernelet-runtime", "rq1-crossing", "subject", command])
                .unwrap();
            let Operation::Rq1Crossing { action, .. } = cli.command else {
                panic!("wrong crossing command")
            };
            assert_eq!(serde_json::to_value(action).unwrap(), expected);
        }
    }
}

/// Linux signal zero probes existence; real signal numbers are 1 through 64.
pub(crate) fn validate_signal(signal: i32) -> Result<()> {
    ensure!((0..=64).contains(&signal), "invalid signal number {signal}");
    Ok(())
}

/// A launch observation outlives its caller's RPC deadline. Only a confirmed
/// rejection permits reuse; transport failure leaves the operation uncertain.
pub(crate) fn request_launch(directory: &Path, operation: &Control) -> Result<(Reply, UnixStream)> {
    let mut stream = begin_request(directory, operation)?;
    stream.set_read_timeout(None)?;
    let reply = receive_reply(&mut stream)?;
    Ok((reply, stream))
}
