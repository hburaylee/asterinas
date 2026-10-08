// SPDX-License-Identifier: MPL-2.0

//! OCI command lifecycle and its descriptor-owning holder process.

mod create;
mod holder;
mod hooks;
mod rootfs;
mod terminal;

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

use crate::{config::Process, protocol};

// The first-version Host admits up to 512 grains per user by default.
const DEFAULT_MAX_GRAINS: u32 = 512;
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
}

#[derive(Deserialize, Serialize)]
pub(crate) enum Control {
    CloseInput { id: u64 },
    Resize { id: u64, columns: u16, rows: u16 },
    State,
    Stats,
    Processes,
    Start { attach: bool },
    Exec { process: Process },
    Signal { id: u64, signal: i32 },
    Delete { force: bool },
}

#[derive(Deserialize, Serialize)]
pub(crate) enum Reply {
    Ready,
    State(State),
    Stats(Stats),
    Processes(Vec<u32>),
    Started { id: u64 },
    Done,
    Error(String),
}

#[derive(Deserialize, Serialize)]
pub(crate) struct Stats {
    pub cpu_time_ns: u64,
    pub throttled_ns: u64,
    pub completion_cpu_ns: u64,
    pub ingress_copy_cpu_ns: u64,
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
                return terminal::forward(&directory, stream, id, terminal);
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
            return terminal::forward(&directory, stream, id, terminal);
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

/// A missing listener after successful creation means the capability owner died.
fn holder_disconnected(error: &anyhow::Error) -> bool {
    error.downcast_ref::<std::io::Error>().is_some_and(|error| {
        matches!(
            error.raw_os_error(),
            Some(libc::ENOENT | libc::ECONNREFUSED)
        )
    })
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
}
