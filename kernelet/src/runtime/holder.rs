// SPDX-License-Identifier: MPL-2.0

//! One process retains each sandbox capability and multiplexes agent messages.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::{
            fs::OpenOptionsExt,
            net::{UnixListener, UnixStream},
        },
    },
    path::Path,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
/// One grain of guest memory, shared with the Host through the ioctl ABI.
use kernelet_abi::GRAIN_SIZE_BYTES;
use nix::fcntl::{FcntlArg, OFlag, fcntl};

use super::{
    Control, CrossingAction, Record, Reply, State, Stats, TlbAction,
    crossing_capture::CrossingCapture, tlb_capture::TlbCapture, vsock,
};
use crate::{
    fd,
    protocol::{self, Message, Request, Stream},
    uapi::{self, Sandbox},
};

struct Shared {
    state: State,
    next_process: u64,
    next_request: u64,
    processes: BTreeMap<u64, ProcessStatus>,
    input_ready: BTreeSet<u64>,
    input_errors: BTreeMap<u64, String>,
    pending_requests: BTreeMap<u64, Option<RequestResult>>,
    outputs: BTreeMap<u64, Arc<mpsc::SyncSender<Message>>>,
    terminal: Option<File>,
    failure: Option<String>,
}

#[derive(Debug, PartialEq)]
enum ProcessStatus {
    StartPending,
    Running { pid: u32 },
    Exited { code: i32 },
    Rejected { detail: String },
}

impl ProcessStatus {
    fn active(&self) -> bool {
        matches!(self, Self::StartPending) || self.pid().is_some()
    }
    fn pid(&self) -> Option<u32> {
        match self {
            Self::Running { pid } => Some(*pid),
            _ => None,
        }
    }
    fn code(&self) -> Option<i32> {
        match self {
            Self::Exited { code } => Some(*code),
            _ => None,
        }
    }
}

enum RequestResult {
    Done,
    Processes(Vec<u32>),
    Failed(String),
}

struct Holder {
    sandbox: Sandbox,
    vsock_cid: Option<u32>,
    tlb_capture: Mutex<TlbCapture>,
    crossing_capture: Mutex<CrossingCapture>,
    writer: Mutex<File>,
    shared: Mutex<Shared>,
    changed: Condvar,
    destroy_accepted: Mutex<bool>,
    stopping: AtomicBool,
    socket_path: std::path::PathBuf,
    stdout: File,
    stderr: File,
}

// Two credited output chunks, Started, one stdin credit or failure, two stream
// failures, two Close messages, and Exited never make the control reader wait.
const OUTPUT_QUEUE_CAPACITY: usize = 10;
const ATTACH_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
// Refuse further execs when their statuses have not been consumed. Never evict
// an exit code that a disconnected observer may still need.
const MAX_PROCESS_RECORDS: usize = 1024;
const DELETE_TIMEOUT: Duration = Duration::from_secs(10);
const DELETE_POLL_INTERVAL: Duration = Duration::from_millis(10);

struct AttachmentWriter<'a> {
    connection: &'a UnixStream,
    deadline: Instant,
}

struct OutputRegistration {
    holder: Arc<Holder>,
    id: u64,
    sender: Arc<mpsc::SyncSender<Message>>,
    armed: bool,
}

struct AttachmentInput {
    credit: AtomicBool,
    closed: AtomicBool,
    cancelled: AtomicBool,
}

impl Drop for OutputRegistration {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut shared = self.holder.shared.lock().unwrap();
        if !shared
            .outputs
            .get(&self.id)
            .is_some_and(|sender| Arc::ptr_eq(sender, &self.sender))
        {
            return;
        }
        shared.outputs.remove(&self.id);
        drop(shared);
        for stream in [Stream::Stdout, Stream::Stderr] {
            let _ = self.holder.send(&Message::OutputFailed {
                id: self.id,
                stream,
                detail: "output attachment initialization failed".into(),
            });
        }
    }
}

impl Write for AttachmentWriter<'_> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        loop {
            if Instant::now() >= self.deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "attachment stalled for two seconds",
                ));
            }
            // SAFETY: send borrows the live socket and the caller's byte slice.
            let sent = unsafe {
                libc::send(
                    self.connection.as_raw_fd(),
                    data.as_ptr().cast(),
                    data.len(),
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            };
            if sent >= 0 {
                return Ok(sent as usize);
            }
            let error = std::io::Error::last_os_error();
            match error.kind() {
                std::io::ErrorKind::Interrupted => continue,
                std::io::ErrorKind::WouldBlock => {
                    let mut descriptor = libc::pollfd {
                        fd: self.connection.as_raw_fd(),
                        events: libc::POLLOUT,
                        revents: 0,
                    };
                    // SAFETY: poll borrows this live socket and valid pollfd.
                    let ready = unsafe { libc::poll(&mut descriptor, 1, 20) };
                    if ready < 0 {
                        let error = std::io::Error::last_os_error();
                        if error.kind() != std::io::ErrorKind::Interrupted {
                            return Err(error);
                        }
                    }
                }
                _ => return Err(error),
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(super) fn run(directory: &Path) -> Result<()> {
    let listener = UnixListener::bind(directory.join("control.sock"))?;
    let (mut creator, _) = listener.accept()?;
    creator.set_read_timeout(Some(Duration::from_secs(10)))?;
    let descriptors = fd::receive(&creator)?;
    let holder = initialize(directory, descriptors)?;
    protocol::send_value(&mut creator, &Reply::Ready)?;
    drop(creator);
    serve(listener, holder)
}

pub(super) fn start_in_process(directory: &Path, files: Vec<File>) -> Result<()> {
    let listener = UnixListener::bind(directory.join("control.sock"))?;
    let descriptors = files.into_iter().map(OwnedFd::from).collect();
    let holder = initialize(directory, descriptors)?;
    thread::spawn(move || {
        if let Err(error) = serve(listener, holder) {
            eprintln!("kernelet holder: {error:#}");
        }
    });
    Ok(())
}

fn initialize(directory: &Path, descriptors: Vec<OwnedFd>) -> Result<Arc<Holder>> {
    let mut record: Record = serde_json::from_reader(File::open(directory.join("config.json"))?)?;
    let mut descriptors = descriptors.into_iter();
    let sandbox = Sandbox::from_file(File::from(
        descriptors.next().context("missing sandbox descriptor")?,
    ));
    let agent = File::from(descriptors.next().context("missing agent descriptor")?);
    let console = File::from(descriptors.next().context("missing console descriptor")?);
    let log = File::from(descriptors.next().context("missing log descriptor")?);
    let terminal = descriptors.next().map(File::from);
    ensure!(descriptors.next().is_none(), "unexpected holder descriptor");
    let mut state = record.state.clone();
    state.status = "created".into();
    state.pid = std::process::id();
    record.state = state.clone();
    let mut record_file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(directory.join("config.json"))?;
    serde_json::to_writer(&mut record_file, &record)?;
    record_file.sync_all()?;
    let stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(directory.join("stdout"))?;
    let stderr = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(directory.join("stderr"))?;
    let holder = Arc::new(Holder {
        sandbox,
        vsock_cid: record.vsock_cid,
        tlb_capture: Mutex::new(TlbCapture::default()),
        crossing_capture: Mutex::new(CrossingCapture::default()),
        writer: Mutex::new(agent.try_clone()?),
        shared: Mutex::new(Shared {
            state,
            next_process: 2,
            next_request: 1,
            processes: BTreeMap::new(),
            input_ready: BTreeSet::new(),
            input_errors: BTreeMap::new(),
            pending_requests: BTreeMap::new(),
            outputs: BTreeMap::new(),
            terminal,
            failure: None,
        }),
        changed: Condvar::new(),
        destroy_accepted: Mutex::new(false),
        stopping: AtomicBool::new(false),
        socket_path: directory.join("control.sock"),
        stdout,
        stderr,
    });
    drain_endpoint(log, directory.join("kernel.log"))?;
    drain_endpoint(console, directory.join("console.log"))?;
    let reader_holder = holder.clone();
    thread::spawn(move || read_agent(reader_holder, agent));
    Ok(holder)
}

fn serve(listener: UnixListener, holder: Arc<Holder>) -> Result<()> {
    for connection in listener.incoming() {
        let connection = connection?;
        if holder.stopping.load(Ordering::Acquire) {
            break;
        }
        let holder = holder.clone();
        thread::spawn(move || {
            if let Err(error) = handle(&holder, connection.try_clone().unwrap()) {
                let _ = protocol::send_value(&mut &connection, &Reply::Error(format!("{error:#}")));
            }
        });
    }
    Ok(())
}

fn handle(holder: &Arc<Holder>, mut connection: UnixStream) -> Result<()> {
    connection.set_read_timeout(Some(Duration::from_secs(30)))?;
    let operation: Control = protocol::receive_value(&mut connection)?;
    connection.set_read_timeout(None)?;
    match operation {
        Control::VsockCid | Control::VsockCapability => {
            let identity = {
                let shared = holder.shared.lock().unwrap();
                vsock::Identity::new(&shared.state.id, holder.vsock_cid)?
            };
            if matches!(operation, Control::VsockCapability) {
                ensure!(
                    holder.sandbox.status()?.state == uapi::STATE_RUNNING,
                    "kernelet is not running"
                );
                vsock::send_capability(&mut connection, identity, holder.sandbox.file())?;
            } else {
                protocol::send_value(&mut connection, &Reply::VsockIdentity(identity))?;
            }
        }
        Control::ExitStatus { id } => {
            let shared = holder.shared.lock().unwrap();
            let code = shared.processes.get(&id).and_then(ProcessStatus::code);
            if code.is_none()
                && let Some(detail) = &shared.failure
            {
                bail!("{detail}");
            }
            ensure!(
                code.is_some() || shared.processes.get(&id).is_some_and(ProcessStatus::active),
                "unknown process"
            );
            drop(shared);
            protocol::send_value(&mut connection, &Reply::ExitStatus { code })?;
        }
        Control::ForgetExited { id } => {
            let mut shared = holder.shared.lock().unwrap();
            ensure!(
                !shared.processes.get(&id).is_some_and(ProcessStatus::active),
                "process has not exited"
            );
            shared.processes.remove(&id);
            drop(shared);
            protocol::send_value(&mut connection, &Reply::Done)?;
        }
        Control::InspectStatus => {
            let status = super::status::InstanceStatus::from_raw(holder.sandbox.status()?)?;
            protocol::send_value(&mut connection, &Reply::InspectStatus(status))?;
        }
        Control::Rq1Tlb { action } => {
            let reply = {
                let mut capture = holder.tlb_capture.lock().unwrap();
                match action {
                    TlbAction::Arm => {
                        capture.arm(&holder.sandbox)?;
                        Reply::Done
                    }
                    TlbAction::Finish => Reply::Rq1TlbSnapshot(capture.finish()?),
                    TlbAction::Close => {
                        capture.close()?;
                        Reply::Done
                    }
                }
            };
            protocol::send_value(&mut connection, &reply)?;
        }
        Control::Rq1Crossing { action } => {
            let reply = {
                let mut capture = holder.crossing_capture.lock().unwrap();
                match action {
                    CrossingAction::Arm { nonce } => {
                        capture.arm(&holder.sandbox, nonce)?;
                        Reply::Done
                    }
                    CrossingAction::Finish => Reply::Rq1CrossingSnapshot(capture.finish()?),
                    CrossingAction::Close => {
                        capture.close()?;
                        Reply::Done
                    }
                }
            };
            protocol::send_value(&mut connection, &reply)?;
        }
        Control::Stats => {
            let stats = holder.sandbox.stats()?;
            protocol::send_value(
                &mut connection,
                &Reply::Stats(Stats {
                    cpu_time_ns: (stats.cpu_time_ns != kernelet_abi::STATS_UNAVAILABLE)
                        .then_some(stats.cpu_time_ns),
                    throttled_ns: stats.throttled_ns,
                    completion_cpu_ns: (stats.completion_cpu_ns != kernelet_abi::STATS_UNAVAILABLE)
                        .then_some(stats.completion_cpu_ns),
                    ingress_copy_cpu_ns: (stats.ingress_copy_cpu_ns
                        != kernelet_abi::STATS_UNAVAILABLE)
                        .then_some(stats.ingress_copy_cpu_ns),
                    host_bytes_charged: stats.host_bytes_charged,
                    host_overhead_bytes: stats.host_overhead_bytes,
                    stacks_allocated: stats.stacks_allocated,
                    memory_bytes: u64::from(stats.grains_granted) * GRAIN_SIZE_BYTES,
                    memory_limit: u64::from(stats.max_grains) * GRAIN_SIZE_BYTES,
                }),
            )?;
        }
        Control::Processes => {
            let result = holder
                .request(
                    |request_id| Message::ListProcesses { request_id },
                    Duration::from_secs(10),
                )?
                .context("agent process query timed out")?;
            let RequestResult::Processes(pids) = result else {
                bail!("unexpected agent process query response");
            };
            protocol::send_value(&mut connection, &Reply::Processes(pids))?;
        }
        Control::State => {
            let mut shared = holder.shared.lock().unwrap();
            if holder.sandbox.status()?.state == uapi::STATE_EXITED {
                shared.state.status = "stopped".into();
            }
            let state = shared.state.clone();
            drop(shared);
            protocol::send_value(&mut connection, &Reply::State(state))?;
        }
        Control::Start { attach } => {
            {
                let shared = holder.shared.lock().unwrap();
                ensure!(shared.state.status == "created", "container is not created");
                ensure!(
                    !shared.processes.get(&1).is_some_and(ProcessStatus::active),
                    "container already started"
                );
            }
            start(holder, connection, 1, None, attach)?;
        }
        Control::ReserveProcess => {
            let mut shared = holder.shared.lock().unwrap();
            ensure!(shared.state.status == "running", "container is not running");
            let id = shared.next_process;
            shared.next_process = id.checked_add(1).context("process ID exhausted")?;
            drop(shared);
            protocol::send_value(&mut connection, &Reply::Reserved { id })?;
        }
        Control::Launch { id, process } => {
            if let Some(process) = &process {
                process.validate()?;
            }
            let shared = holder.shared.lock().unwrap();
            ensure!(
                id == 1 || (id >= 2 && id < shared.next_process),
                "unreserved process ID"
            );
            ensure!(
                shared.state.status == if id == 1 { "created" } else { "running" },
                "container cannot start process"
            );
            drop(shared);
            start(holder, connection, id, process, true)?;
        }
        Control::Exec { process } => {
            process.validate()?;
            let id = {
                let mut shared = holder.shared.lock().unwrap();
                ensure!(shared.state.status == "running", "container is not running");
                let id = shared.next_process;
                shared.next_process = id.checked_add(1).context("process ID exhausted")?;
                id
            };
            start(holder, connection, id, Some(process), true)?;
        }
        Control::Resize { id, columns, rows } => {
            ensure!(
                columns != 0 && rows != 0,
                "terminal dimensions must be nonzero"
            );
            let result = holder
                .request(
                    |request_id| Message::Resize {
                        request_id,
                        id,
                        columns,
                        rows,
                    },
                    Duration::from_secs(10),
                )?
                .context("agent terminal resize timed out")?;
            ensure!(
                matches!(result, RequestResult::Done),
                "unexpected agent resize response"
            );
            protocol::send_value(&mut connection, &Reply::Done)?;
        }
        Control::CloseInput { id } => {
            let result = holder
                .request(
                    |request_id| Message::CloseInput { request_id, id },
                    Duration::from_secs(10),
                )?
                .context("agent close-input timed out")?;
            ensure!(
                matches!(result, RequestResult::Done),
                "unexpected agent close-input response"
            );
            protocol::send_value(&mut connection, &Reply::Done)?;
        }
        Control::SignalAll { signal } => {
            super::validate_signal(signal)?;
            let result = holder
                .request(
                    |request_id| Message::SignalAll { request_id, signal },
                    Duration::from_secs(2),
                )?
                .context("agent signal-all timed out")?;
            ensure!(
                matches!(result, RequestResult::Done),
                "unexpected signal-all reply"
            );
            protocol::send_value(&mut connection, &Reply::Done)?;
        }
        Control::Signal { id, signal } => {
            super::validate_signal(signal)?;
            let status = holder.shared.lock().unwrap().state.status.clone();
            if id == 1 && status == "created" {
                if signal == 0 {
                    protocol::send_value(&mut connection, &Reply::Done)?;
                    return Ok(());
                }
                holder.sandbox.kill(signal as u32)?;
                holder.shared.lock().unwrap().state.status = "stopped".into();
            } else {
                ensure!(
                    holder
                        .shared
                        .lock()
                        .unwrap()
                        .processes
                        .get(&id)
                        .is_some_and(ProcessStatus::active),
                    "process is not running"
                );
                let result = holder.request(
                    |request_id| Message::Signal {
                        request_id,
                        id,
                        signal,
                    },
                    Duration::from_secs(2),
                )?;
                match result {
                    Some(RequestResult::Done) => {}
                    None if id == 1 && signal != 0 => holder.sandbox.kill(signal as u32)?,
                    None => bail!("agent signal timed out"),
                    Some(_) => bail!("unexpected agent signal response"),
                }
            }
            protocol::send_value(&mut connection, &Reply::Done)?;
        }
        Control::Delete { force } => {
            let status = holder.shared.lock().unwrap().state.status.clone();
            ensure!(
                force || status == "stopped",
                "container must be stopped before delete"
            );
            let mut destroy_accepted = match holder.destroy_accepted.try_lock() {
                Ok(accepted) => accepted,
                Err(std::sync::TryLockError::WouldBlock) => {
                    return Err(std::io::Error::from_raw_os_error(libc::EBUSY))
                        .context("another kernelet delete request is in progress");
                }
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    bail!("kernelet delete state lock is poisoned");
                }
            };
            let deadline = Instant::now() + DELETE_TIMEOUT;
            if !*destroy_accepted {
                // OCI `stopped` means the init process exited; the kernelet may
                // still be running until its Host carriers have been stopped.
                holder.sandbox.kill(libc::SIGKILL as u32)?;
                loop {
                    match holder.sandbox.destroy() {
                        Ok(()) => {
                            // The Host may have queued a reaper. Preserve this
                            // acceptance even if STATUS or this request fails.
                            *destroy_accepted = true;
                            break;
                        }
                        Err(error)
                            if error
                                .downcast_ref::<std::io::Error>()
                                .and_then(std::io::Error::raw_os_error)
                                == Some(libc::EBUSY)
                                && Instant::now() < deadline =>
                        {
                            holder.sandbox.kill(libc::SIGKILL as u32)?;
                            thread::sleep(
                                DELETE_POLL_INTERVAL
                                    .min(deadline.saturating_duration_since(Instant::now())),
                            );
                        }
                        Err(error)
                            if error
                                .downcast_ref::<std::io::Error>()
                                .and_then(std::io::Error::raw_os_error)
                                == Some(libc::EBUSY) =>
                        {
                            let detail = match holder.sandbox.status() {
                                Ok(status) => {
                                    format!(
                                        "kernelet did not finish teardown (Host state {})",
                                        status.state
                                    )
                                }
                                Err(status_error) => format!(
                                    "kernelet did not finish teardown (Host status unavailable: {status_error})"
                                ),
                            };
                            return Err(error).context(detail);
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
            wait_destroyed(deadline, || {
                holder.sandbox.status().map(|status| status.state)
            })?;
            drop(destroy_accepted);
            protocol::send_value(&mut connection, &Reply::Done)?;
            holder.stopping.store(true, Ordering::Release);
            let _ = UnixStream::connect(&holder.socket_path);
        }
    }
    Ok(())
}

fn wait_destroyed(deadline: Instant, mut status_fn: impl FnMut() -> Result<u32>) -> Result<()> {
    let mut last_state = None;
    loop {
        if Instant::now() >= deadline {
            return Err(std::io::Error::from_raw_os_error(libc::ETIMEDOUT)).with_context(|| {
                format!(
                    "kernelet did not finish accepted teardown (last Host state {last_state:?})"
                )
            });
        }
        let state = status_fn().context("query kernelet status after destroy was accepted")?;
        last_state = Some(state);
        match state {
            uapi::STATE_DESTROYED if Instant::now() < deadline => return Ok(()),
            uapi::STATE_EXITED | uapi::STATE_DESTROYING | uapi::STATE_DESTROYED => {}
            other => bail!("unexpected Host state {other} after destroy was accepted"),
        }
        // Exited and poll(IN) can precede the reaper's completion. Only a new
        // STATUS observation of Destroyed completes Delete.
        thread::sleep(DELETE_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
    }
}

fn start(
    holder: &Arc<Holder>,
    connection: UnixStream,
    id: u64,
    process: Option<crate::config::Process>,
    attach: bool,
) -> Result<()> {
    let (sender, receiver) = mpsc::sync_channel(OUTPUT_QUEUE_CAPACITY);
    let sender = Arc::new(sender);
    {
        let mut shared = holder.shared.lock().unwrap();
        ensure!(
            !shared.processes.get(&id).is_some_and(ProcessStatus::active),
            "process already started"
        );
        ensure!(
            shared.processes.len() < MAX_PROCESS_RECORDS,
            "too many process statuses await observation; consume and forget exited processes"
        );
        // Reserve the ID before sending, so concurrent start commands cannot race.
        shared.processes.insert(id, ProcessStatus::StartPending);
        shared.outputs.insert(id, sender.clone());
    }
    let mut registration = OutputRegistration {
        holder: holder.clone(),
        id,
        sender: sender.clone(),
        armed: true,
    };
    if let Err(error) = holder.send(&Message::Start { id, process }) {
        let mut shared = holder.shared.lock().unwrap();
        // A failed transport write may have sent part of Start. Its identity
        // cannot safely be reused until the sandbox is destroyed.
        shared.failure = Some(format!("agent start send failed: {error:#}"));
        shared.state.status = "stopped".into();
        shared.processes.remove(&id);
        shared.outputs.remove(&id);
        registration.armed = false;
        holder.changed.notify_all();
        return Err(error);
    }
    let mut shared = holder.shared.lock().unwrap();
    while matches!(shared.processes.get(&id), Some(ProcessStatus::StartPending))
        && shared.failure.is_none()
    {
        shared = holder.changed.wait(shared).unwrap();
    }
    if let Some(ProcessStatus::Rejected { detail }) = shared.processes.get(&id) {
        let detail = detail.clone();
        registration.armed = false;
        shared.processes.remove(&id);
        shared.outputs.remove(&id);
        drop(shared);
        protocol::send_value(&mut &connection, &Reply::StartRejected(detail))?;
        return Ok(());
    }
    if let Some(failure) = shared.failure.clone() {
        bail!("{failure}");
    }
    drop(shared);
    protocol::send_value(
        &mut AttachmentWriter {
            connection: &connection,
            deadline: Instant::now() + ATTACH_WRITE_TIMEOUT,
        },
        &Reply::Started { id },
    )?;
    if attach {
        attach_input(holder, id, connection.try_clone()?, sender)?;
        registration.armed = false;
        return forward_output(holder, id, receiver, Some(connection));
    } else if id == 1 {
        let terminal = holder
            .shared
            .lock()
            .unwrap()
            .terminal
            .as_ref()
            .map(File::try_clone)
            .transpose()?;
        if let Some(mut input) = terminal {
            let holder = holder.clone();
            thread::spawn(move || {
                let mut data = vec![0; protocol::STREAM_CHUNK_BYTES];
                loop {
                    let length = match input.read(&mut data) {
                        Ok(0) => break,
                        Ok(length) => length,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            if !holder
                                .shared
                                .lock()
                                .unwrap()
                                .processes
                                .get(&id)
                                .is_some_and(ProcessStatus::active)
                            {
                                break;
                            }
                            thread::sleep(Duration::from_millis(20));
                            continue;
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    };
                    if holder
                        .send_input(&Message::Data {
                            id,
                            stream: Stream::Stdin,
                            data: data[..length].to_vec(),
                        })
                        .is_err()
                    {
                        break;
                    }
                }
                let _ = holder.send(&Message::Close {
                    id,
                    stream: Stream::Stdin,
                });
            });
        }
    }
    registration.armed = false;
    let holder = holder.clone();
    thread::spawn(move || {
        if let Err(error) = forward_output(&holder, id, receiver, None) {
            eprintln!("kernelet process {id} output: {error:#}");
        }
    });
    Ok(())
}

fn attach_input(
    holder: &Arc<Holder>,
    id: u64,
    mut connection: UnixStream,
    responses: Arc<mpsc::SyncSender<Message>>,
) -> Result<()> {
    let input = Arc::new(AttachmentInput {
        credit: AtomicBool::new(true),
        closed: AtomicBool::new(false),
        cancelled: AtomicBool::new(false),
    });
    // Credit admits one data chunk. The extra slot preserves a following EOF
    // without making the attachment reader wait behind a full guest pipe.
    let (sender, receiver) = mpsc::sync_channel(2);
    let worker_holder = holder.clone();
    let worker_input = input.clone();
    let worker_connection = connection.try_clone()?;
    let worker_responses = responses.clone();
    thread::spawn(move || {
        for message in receiver {
            if worker_input.cancelled.load(Ordering::Acquire) {
                break;
            }
            let response =
                match worker_holder.send_input_until(&message, Some(&worker_input.cancelled)) {
                    Ok(()) if matches!(message, Message::Data { .. }) => {
                        if worker_input.closed.load(Ordering::Acquire) {
                            continue;
                        }
                        worker_input.credit.store(true, Ordering::Release);
                        Message::InputReady { id }
                    }
                    Ok(()) => break,
                    Err(error) => {
                        worker_input.closed.store(true, Ordering::Release);
                        if worker_input.cancelled.load(Ordering::Acquire) {
                            break;
                        }
                        Message::RequestFailed {
                            request: Request::Data { id },
                            detail: format!("stdin delivery failed: {error:#}"),
                        }
                    }
                };
            let failed = matches!(response, Message::RequestFailed { .. });
            if let Err(error) = worker_responses.try_send(response) {
                // A credited peer cannot fill this queue. Do not hide a
                // protocol violation or leave its observer waiting for credit.
                eprintln!("kernelet process {id} stdin response failed: {error}");
                let _ = worker_connection.shutdown(std::net::Shutdown::Both);
                break;
            }
            if failed {
                break;
            }
        }
    });
    let holder = holder.clone();
    thread::spawn(move || {
        let result = (|| -> Result<()> {
            loop {
                let message = match protocol::receive(&mut connection) {
                    Ok(message) => message,
                    Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(error) => return Err(error.into()),
                };
                match &message {
                    Message::Data {
                        id: target,
                        stream: Stream::Stdin,
                        data,
                    } if *target == id => {
                        ensure!(
                            data.len() <= protocol::STREAM_CHUNK_BYTES,
                            "stdin chunk too large"
                        );
                        ensure!(
                            !input.closed.load(Ordering::Acquire)
                                && input.credit.swap(false, Ordering::AcqRel),
                            "attachment exceeded stdin credit or wrote after EOF"
                        );
                        sender.try_send(message).context("stdin credit exceeded")?;
                    }
                    Message::Close {
                        id: target,
                        stream: Stream::Stdin,
                    } if *target == id => {
                        if !input.closed.swap(true, Ordering::AcqRel) {
                            sender.try_send(message).context("stdin close queue full")?;
                        }
                    }
                    Message::OutputFailed {
                        id: target,
                        stream: Stream::Stdout | Stream::Stderr,
                        ..
                    } if *target == id => holder.send(&message)?,
                    _ => bail!("unexpected attachment input message"),
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            eprintln!("kernelet process {id} attachment input failed: {error:#}");
            if let Err(error) = responses.try_send(Message::RequestFailed {
                request: Request::Data { id },
                detail: format!("attachment input failed: {error:#}"),
            }) {
                eprintln!("kernelet process {id} stdin response failed: {error}");
                let _ = connection.shutdown(std::net::Shutdown::Both);
            }
        }
        {
            // Take the ACK predicate's mutex before notifying, so a worker
            // cannot miss cancellation between checking and sleeping.
            let _shared = holder.shared.lock().unwrap();
            input.cancelled.store(true, Ordering::Release);
            holder.changed.notify_all();
        }
        let _ = holder.send(&Message::Close {
            id,
            stream: Stream::Stdin,
        });
    });
    Ok(())
}

fn forward_output(
    holder: &Arc<Holder>,
    id: u64,
    receiver: mpsc::Receiver<Message>,
    attachment: Option<UnixStream>,
) -> Result<()> {
    let result = (|| -> Result<()> {
        let terminal = if id == 1 {
            holder
                .shared
                .lock()
                .unwrap()
                .terminal
                .as_ref()
                .map(File::try_clone)
                .transpose()?
        } else {
            None
        };
        let mut terminal = terminal;
        let mut stdout = holder.stdout.try_clone()?;
        let mut stderr = holder.stderr.try_clone()?;
        for sink in [&stdout, &stderr].into_iter().chain(terminal.as_ref()) {
            let flags = OFlag::from_bits_truncate(fcntl(sink.as_raw_fd(), FcntlArg::F_GETFL)?);
            fcntl(
                sink.as_raw_fd(),
                FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK),
            )?;
        }
        // A separate worker holds each process's output credit while its sinks
        // are slow. The only agent reader never performs these writes.
        if let Some(connection) = &attachment {
            protocol::send(
                &mut AttachmentWriter {
                    connection,
                    deadline: Instant::now() + ATTACH_WRITE_TIMEOUT,
                },
                &Message::InputReady { id },
            )?;
        }
        for stream in [Stream::Stdout, Stream::Stderr] {
            holder.send(&Message::OutputReady { id, stream })?;
        }
        for message in receiver {
            if let Message::Data { stream, data, .. } = &message {
                if let Some(terminal) = &mut terminal {
                    write_output(terminal, data)?;
                } else if *stream == Stream::Stderr {
                    write_output(&mut stderr, data)?;
                } else {
                    write_output(&mut stdout, data)?;
                }
            }
            if let Some(connection) = &attachment {
                protocol::send(
                    &mut AttachmentWriter {
                        connection,
                        deadline: Instant::now() + ATTACH_WRITE_TIMEOUT,
                    },
                    &message,
                )?;
            }
            if let Message::Data { stream, .. } = &message {
                holder.send(&Message::OutputReady {
                    id,
                    stream: *stream,
                })?;
            }
            if let Message::OutputFailed { stream, detail, .. } = &message {
                eprintln!("kernelet process {id} {stream:?} output: {detail}");
            }
            if matches!(message, Message::Exited { .. } | Message::Error { .. }) {
                break;
            }
        }
        Ok(())
    })();
    holder.shared.lock().unwrap().outputs.remove(&id);
    if let Some(connection) = attachment {
        // Wake the dedicated stdin reader even when the peer stopped reading.
        let _ = connection.shutdown(std::net::Shutdown::Both);
    }
    if let Err(error) = &result {
        // This cancellation is scoped to the process's streams. Closing an
        // attachment never turns an unrelated process or the agent into failed.
        for stream in [Stream::Stdout, Stream::Stderr] {
            let _ = holder.send(&Message::OutputFailed {
                id,
                stream,
                detail: format!("output sink failed: {error:#}"),
            });
        }
    }
    result
}

fn write_output(sink: &mut File, mut data: &[u8]) -> Result<()> {
    let deadline = Instant::now() + ATTACH_WRITE_TIMEOUT;
    while !data.is_empty() {
        ensure!(
            Instant::now() < deadline,
            "output sink stalled for two seconds"
        );
        match sink.write(data) {
            Ok(0) => bail!("output sink write made no progress"),
            Ok(length) => data = &data[length..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                let mut descriptor = libc::pollfd {
                    fd: sink.as_raw_fd(),
                    events: libc::POLLOUT,
                    revents: 0,
                };
                // SAFETY: poll borrows one live file and its valid pollfd buffer.
                let ready = unsafe { libc::poll(&mut descriptor, 1, 20) };
                if ready < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.kind() != std::io::ErrorKind::Interrupted {
                        return Err(error.into());
                    }
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

impl Holder {
    fn request(
        &self,
        message: impl FnOnce(u64) -> Message,
        timeout: Duration,
    ) -> Result<Option<RequestResult>> {
        let request_id = {
            let mut shared = self.shared.lock().unwrap();
            ensure!(shared.failure.is_none(), "agent is unavailable");
            let request_id = shared.next_request;
            shared.next_request = request_id.checked_add(1).context("request ID exhausted")?;
            shared.pending_requests.insert(request_id, None);
            request_id
        };
        if let Err(error) = self.send(&message(request_id)) {
            self.shared
                .lock()
                .unwrap()
                .pending_requests
                .remove(&request_id);
            return Err(error);
        }
        let deadline = Instant::now() + timeout;
        let mut shared = self.shared.lock().unwrap();
        loop {
            if let Some(result) = shared
                .pending_requests
                .get_mut(&request_id)
                .and_then(Option::take)
            {
                shared.pending_requests.remove(&request_id);
                return match result {
                    RequestResult::Failed(detail) => bail!("{detail}"),
                    result => Ok(Some(result)),
                };
            }
            if let Some(detail) = shared.failure.clone() {
                shared.pending_requests.remove(&request_id);
                bail!("{detail}");
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                shared.pending_requests.remove(&request_id);
                return Ok(None);
            }
            shared = self.changed.wait_timeout(shared, remaining).unwrap().0;
        }
    }

    fn send_input(&self, message: &Message) -> Result<()> {
        self.send_input_until(message, None)
    }

    fn send_input_until(&self, message: &Message, cancelled: Option<&AtomicBool>) -> Result<()> {
        let Message::Data { id, .. } = message else {
            return self.send(message);
        };
        {
            let mut shared = self.shared.lock().unwrap();
            shared.input_ready.remove(id);
            shared.input_errors.remove(id);
        }
        self.send(message)?;
        let mut shared = self.shared.lock().unwrap();
        while !shared.input_ready.contains(id)
            && !shared.input_errors.contains_key(id)
            && shared.failure.is_none()
            && shared.processes.get(id).is_some_and(ProcessStatus::active)
            && !cancelled.is_some_and(|cancelled| cancelled.load(Ordering::Acquire))
        {
            shared = self.changed.wait(shared).unwrap();
        }
        ensure!(
            !cancelled.is_some_and(|cancelled| cancelled.load(Ordering::Acquire)),
            "attachment closed before stdin acknowledgement"
        );
        if let Some(detail) = &shared.failure {
            bail!("{detail}");
        }
        if let Some(detail) = shared.input_errors.remove(id) {
            bail!("{detail}");
        }
        ensure!(
            shared.input_ready.contains(id),
            "process exited before stdin acknowledgement"
        );
        Ok(())
    }

    fn send(&self, message: &Message) -> Result<()> {
        Ok(protocol::send(&mut *self.writer.lock().unwrap(), message)?)
    }
}

fn read_agent(holder: Arc<Holder>, mut agent: File) {
    let result = (|| -> Result<()> {
        loop {
            let message = protocol::receive(&mut agent)?;
            let mut shared = holder.shared.lock().unwrap();
            let id = match &message {
                Message::Processes { request_id, pids } => {
                    shared.resolve_request(*request_id, RequestResult::Processes(pids.clone()));
                    holder.changed.notify_all();
                    continue;
                }
                Message::RequestCompleted { request_id } => {
                    shared.resolve_request(*request_id, RequestResult::Done);
                    holder.changed.notify_all();
                    continue;
                }
                Message::RequestFailed { request, detail } => {
                    shared.reject_request(*request, detail.clone());
                    holder.changed.notify_all();
                    continue;
                }
                Message::InputReady { id } => {
                    if shared.processes.get(id).is_some_and(ProcessStatus::active) {
                        shared.input_ready.insert(*id);
                    }
                    holder.changed.notify_all();
                    continue;
                }
                Message::Started { id, pid } => {
                    ensure!(*pid != 0, "agent returned an invalid process ID");
                    shared
                        .processes
                        .insert(*id, ProcessStatus::Running { pid: *pid });
                    if *id == 1 {
                        shared.state.status = "running".into();
                    }
                    holder.changed.notify_all();
                    *id
                }
                Message::Exited { id, code } => {
                    shared
                        .processes
                        .insert(*id, ProcessStatus::Exited { code: *code });
                    shared.input_ready.remove(id);
                    shared.input_errors.remove(id);
                    if *id == 1 {
                        shared.state.status = "stopped".into();
                    }
                    holder.changed.notify_all();
                    *id
                }
                Message::Data { id, stream, data } => {
                    ensure!(*stream != Stream::Stdin, "unexpected agent stdin output");
                    ensure!(
                        data.len() <= protocol::STREAM_CHUNK_BYTES,
                        "output chunk too large"
                    );
                    *id
                }
                Message::Close { id, .. } | Message::OutputFailed { id, .. } => *id,
                Message::Error { detail } => {
                    shared.failure = Some(detail.clone());
                    holder.changed.notify_all();
                    for sender in shared.outputs.values() {
                        let _ = sender.try_send(message.clone());
                    }
                    continue;
                }
                _ => bail!("unexpected agent response"),
            };
            if let Some(sender) = shared.outputs.get(&id) {
                match sender.try_send(message) {
                    Ok(()) => {}
                    Err(mpsc::TrySendError::Full(_)) => bail!("agent exceeded output credit"),
                    Err(mpsc::TrySendError::Disconnected(_)) => {
                        // The output worker already failed and cancelled its streams.
                        shared.outputs.remove(&id);
                    }
                }
            }
        }
    })();
    if let Err(error) = result {
        let mut shared = holder.shared.lock().unwrap();
        shared.state.status = "stopped".into();
        let detail = format!("agent connection closed: {error:#}");
        shared.failure = Some(detail.clone());
        for sender in shared.outputs.values() {
            let _ = sender.try_send(Message::Error {
                detail: detail.clone(),
            });
        }
        shared.outputs.clear();
        holder.changed.notify_all();
    }
}

impl Shared {
    fn resolve_request(&mut self, request_id: u64, result: RequestResult) {
        if let Some(pending) = self.pending_requests.get_mut(&request_id) {
            *pending = Some(result);
        }
    }

    fn reject_request(&mut self, request: Request, detail: String) {
        if let Some(request_id) = request.request_id() {
            self.resolve_request(request_id, RequestResult::Failed(detail));
            return;
        }
        match request {
            Request::Start { id }
                if matches!(self.processes.get(&id), Some(ProcessStatus::StartPending)) =>
            {
                self.processes
                    .insert(id, ProcessStatus::Rejected { detail });
            }
            Request::Data { id } if self.processes.get(&id).is_some_and(ProcessStatus::active) => {
                self.input_errors.insert(id, detail);
            }
            Request::Close { id } => {
                eprintln!("kernelet process {id} stdin close failed: {detail}");
            }
            Request::Start { .. } | Request::Data { .. } => {}
            _ => {}
        }
    }
}

fn drain_endpoint(mut endpoint: File, path: std::path::PathBuf) -> Result<()> {
    let mut output = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    thread::spawn(move || {
        let _ = std::io::copy(&mut endpoint, &mut output);
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        process::{Command, Stdio},
        time::SystemTime,
    };

    use super::*;

    // Regression: an accepted DESTROY can still retain an Exited sandbox while
    // its Host reaper waits for references. These tests cover the private STATUS
    // completion boundary, not a real Host or its reaper.
    #[test]
    fn delete_completion_waits_for_destroyed_after_acceptance() {
        use std::sync::atomic::AtomicU32;

        let state = Arc::new(AtomicU32::new(uapi::STATE_EXITED));
        let worker_state = state.clone();
        let (observed_tx, observed_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let result = wait_destroyed(Instant::now() + Duration::from_secs(3), || {
                let state = worker_state.load(Ordering::Acquire);
                observed_tx.send(state).unwrap();
                Ok(state)
            });
            done_tx.send(()).unwrap();
            result
        });
        let first = observed_rx.recv_timeout(Duration::from_secs(1));
        let pending_while_exited = matches!(
            done_rx.recv_timeout(Duration::from_millis(30)),
            Err(mpsc::RecvTimeoutError::Timeout)
        );
        state.store(uapi::STATE_DESTROYING, Ordering::Release);
        let deadline = Instant::now() + Duration::from_secs(1);
        let saw_destroying = loop {
            match observed_rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(uapi::STATE_DESTROYING) => break true,
                Ok(_) if Instant::now() < deadline => {}
                _ => break false,
            }
        };
        let pending_while_destroying = matches!(
            done_rx.recv_timeout(Duration::from_millis(30)),
            Err(mpsc::RecvTimeoutError::Timeout)
        );
        // Release and join before assertions. Cleanup must not hide an early
        // completion: both pending observations above remain required.
        state.store(uapi::STATE_DESTROYED, Ordering::Release);
        let result = worker.join().unwrap();
        assert!(matches!(first, Ok(uapi::STATE_EXITED)));
        assert!(
            pending_while_exited,
            "Delete completed while Host was Exited"
        );
        assert!(saw_destroying, "Host Destroying was not observed");
        assert!(
            pending_while_destroying,
            "Delete completed while Host was Destroying"
        );
        result.unwrap();
    }

    #[test]
    fn delete_completion_rejects_exhausted_deadline_without_query() {
        let error = wait_destroyed(Instant::now(), || {
            panic!("an exhausted Delete deadline must not issue another STATUS query")
        })
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(libc::ETIMEDOUT)
        );
        assert!(error.to_string().contains("last Host state None"));
    }

    #[test]
    fn delete_completion_rejects_destroyed_after_deadline() {
        let error = wait_destroyed(Instant::now() + Duration::from_millis(10), || {
            thread::sleep(Duration::from_millis(20));
            Ok(uapi::STATE_DESTROYED)
        })
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(libc::ETIMEDOUT)
        );
    }

    #[test]
    fn delete_completion_preserves_status_ioctl_error() {
        let sandbox = Sandbox::from_file(File::open("/dev/null").unwrap());
        let error = wait_destroyed(Instant::now() + Duration::from_secs(1), || {
            sandbox.status().map(|status| status.state)
        })
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(libc::ENOTTY)
        );
        assert!(
            error
                .to_string()
                .contains("status after destroy was accepted")
        );
    }

    #[test]
    fn delete_completion_rejects_unknown_and_unexpected_host_states() {
        for state in [
            uapi::STATE_CONFIGURING,
            uapi::STATE_CREATED,
            uapi::STATE_STARTING,
            uapi::STATE_RUNNING,
            uapi::STATE_DYING,
            u32::MAX,
        ] {
            let error =
                wait_destroyed(Instant::now() + Duration::from_secs(1), || Ok(state)).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains(&format!("unexpected Host state {state}")),
                "{error}"
            );
        }
    }

    struct FixtureDirectory(std::path::PathBuf);

    impl FixtureDirectory {
        fn kill_children(&self) {
            for name in ["input.pid", "probe.pid", "retry.pid", "cached.pid"] {
                if let Ok(text) = std::fs::read_to_string(self.0.join(name))
                    && let Ok(pid) = text.trim().parse::<i32>()
                {
                    let pid = nix::unistd::Pid::from_raw(pid);
                    let _ = nix::sys::signal::killpg(pid, nix::sys::signal::Signal::SIGKILL);
                    let _ = nix::sys::wait::waitpid(pid, None);
                }
            }
        }
    }

    impl Drop for FixtureDirectory {
        fn drop(&mut self) {
            self.kill_children();
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct LifecycleFixture {
        holder: Arc<Holder>,
        directory: FixtureDirectory,
        agent: Option<thread::JoinHandle<Result<()>>>,
        reader: Option<thread::JoinHandle<()>>,
    }

    impl LifecycleFixture {
        fn new(directory: FixtureDirectory) -> Self {
            let (agent_peer, runtime_peer) = UnixStream::pair().unwrap();
            let agent = thread::spawn(move || {
                crate::agent::serve_connection(File::from(OwnedFd::from(agent_peer)))
            });
            let mut runtime_peer = File::from(OwnedFd::from(runtime_peer));
            assert!(matches!(
                protocol::receive(&mut runtime_peer).unwrap(),
                Message::Hello { .. }
            ));
            let holder = Arc::new(Holder {
                sandbox: Sandbox::from_file(File::open("/dev/null").unwrap()),
                vsock_cid: None,
                tlb_capture: Mutex::new(TlbCapture::default()),
                crossing_capture: Mutex::new(CrossingCapture::default()),
                writer: Mutex::new(runtime_peer.try_clone().unwrap()),
                shared: Mutex::new(Shared {
                    state: State {
                        oci_version: "1.0.2".into(),
                        id: "test".into(),
                        status: "created".into(),
                        pid: std::process::id(),
                        bundle: directory.0.clone(),
                        annotations: BTreeMap::new(),
                    },
                    next_process: 2,
                    next_request: 1,
                    processes: BTreeMap::new(),
                    input_ready: BTreeSet::new(),
                    input_errors: BTreeMap::new(),
                    pending_requests: BTreeMap::new(),
                    outputs: BTreeMap::new(),
                    terminal: None,
                    failure: None,
                }),
                changed: Condvar::new(),
                destroy_accepted: Mutex::new(false),
                stopping: AtomicBool::new(false),
                socket_path: directory.0.join("unused.sock"),
                stdout: File::options().write(true).open("/dev/null").unwrap(),
                stderr: File::options().write(true).open("/dev/null").unwrap(),
            });
            let reader_holder = holder.clone();
            let reader = thread::spawn(move || read_agent(reader_holder, runtime_peer));
            Self {
                holder,
                directory,
                agent: Some(agent),
                reader: Some(reader),
            }
        }

        fn process(&self, name: &str, command: &str) -> crate::config::Process {
            serde_json::from_value(serde_json::json!({
                "args": ["/bin/sh", "-c", format!("printf %s $$ > {}; {command}", self.directory.0.join(name).display())],
                "cwd": "/",
                "user": {"uid": nix::unistd::geteuid().as_raw(), "gid": nix::unistd::getegid().as_raw()}
            })).unwrap()
        }

        fn attach(
            &self,
            id: u64,
            process: crate::config::Process,
        ) -> (UnixStream, thread::JoinHandle<Result<()>>) {
            let (peer, mut client) = UnixStream::pair().unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let holder = self.holder.clone();
            let worker = thread::spawn(move || start(&holder, peer, id, Some(process), true));
            assert!(matches!(
                protocol::receive_value::<Reply>(&mut client).unwrap(),
                Reply::Started { id: process_id } if process_id == id
            ));
            (client, worker)
        }

        fn query(&self, operation: &Control) -> Reply {
            let (peer, mut client) = UnixStream::pair().unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            protocol::send_value(&mut client, operation).unwrap();
            let mut reply = peer.try_clone().unwrap();
            if let Err(error) = handle(&self.holder, peer) {
                protocol::send_value(&mut reply, &Reply::Error(format!("{error:#}"))).unwrap();
            }
            protocol::receive_value(&mut client).unwrap()
        }

        fn disconnect(&mut self) {
            // SAFETY: this live Unix socket belongs to the fixture's agent link.
            unsafe {
                libc::shutdown(
                    self.holder.writer.lock().unwrap().as_raw_fd(),
                    libc::SHUT_RDWR,
                )
            };
            if let Some(reader) = self.reader.take() {
                reader.join().unwrap();
            }
            if let Some(agent) = self.agent.take() {
                assert!(agent.join().unwrap().is_err());
            }
        }
    }

    impl Drop for LifecycleFixture {
        fn drop(&mut self) {
            // Started is published before the child can create its pid file.
            // Also clean up a fixture that fails in that interval.
            let pids: Vec<_> = self
                .holder
                .shared
                .lock()
                .unwrap()
                .processes
                .values()
                .filter_map(ProcessStatus::pid)
                .collect();
            for pid in pids {
                let pid = nix::unistd::Pid::from_raw(pid as i32);
                let _ = nix::sys::signal::killpg(pid, nix::sys::signal::Signal::SIGKILL);
                let _ = nix::sys::wait::waitpid(pid, None);
            }
            self.directory.kill_children();
            self.disconnect();
        }
    }

    #[test]
    fn inspect_status_preserves_ioctl_failure_even_after_agent_failure() {
        let directory = FixtureDirectory(std::env::temp_dir().join(format!(
            "kernelet-status-ioctl-{}-{}", std::process::id(),
            SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        )));
        std::fs::create_dir(&directory.0).unwrap();
        let mut fixture = LifecycleFixture::new(directory);
        fixture.disconnect();
        assert!(fixture.holder.shared.lock().unwrap().failure.is_some());
        {
            let mut shared = fixture.holder.shared.lock().unwrap();
            shared.state.status = "stopped".into();
            shared
                .processes
                .insert(1, ProcessStatus::Exited { code: 137 });
        }
        // /dev/null is deliberately not a sandbox: this exercises real ENOTTY
        // through the holder IPC error path, without substituting agent state.
        let Reply::Error(error) = fixture.query(&Control::InspectStatus) else {
            panic!("non-sandbox fd produced a successful instance diagnosis");
        };
        assert!(
            error.contains(&format!("os error {}", libc::ENOTTY)),
            "{error}"
        );
        assert!(!error.contains("agent disconnected"));
    }

    fn run_lifecycle_fixture(case: &str) {
        let directory = FixtureDirectory(std::env::temp_dir().join(format!(
            "kernelet-lifecycle-fixture-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos()
        )));
        std::fs::create_dir(&directory.0).unwrap();
        let mut fixture = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "runtime::holder::tests::lifecycle_fixture",
                "--nocapture",
            ])
            .env("KERNELET_LIFECYCLE_FIXTURE", case)
            .env("KERNELET_LIFECYCLE_DIRECTORY", &directory.0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(8);
        while fixture.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                fixture.kill().unwrap();
                let output = fixture.wait_with_output().unwrap();
                panic!("{case} fixture timed out: {output:?}");
            }
            thread::sleep(Duration::from_millis(20));
        }
        let output = fixture.wait_with_output().unwrap();
        assert!(output.status.success(), "{case} fixture failed: {output:?}");
    }

    #[test]
    fn created_signal_zero_preserves_the_capability_and_state() {
        run_lifecycle_fixture("signal-zero");
    }

    #[test]
    fn signal_all_reaches_independent_agent_sessions() {
        run_lifecycle_fixture("signal-all");
    }

    #[test]
    fn last_managed_exit_reaps_adopted_children() {
        run_lifecycle_fixture("adopted-reap");
    }

    #[test]
    fn blocked_stdin_does_not_delay_output_cancellation_or_another_process_control() {
        run_lifecycle_fixture("blocked-stdin");
    }

    #[test]
    fn agent_disconnect_reports_unknown_exit_without_overriding_cached_exit() {
        run_lifecycle_fixture("disconnect");
    }

    #[test]
    fn rejected_init_start_preserves_retry_output_and_large_stdin() {
        run_lifecycle_fixture("retry");
    }

    #[test]
    fn closed_stdin_reports_local_failure_and_preserves_real_exit() {
        run_lifecycle_fixture("closed-stdin");
    }

    #[test]
    #[ignore = "isolated fixture with real agent execs, pipes and transport disconnect"]
    fn lifecycle_fixture() {
        let Ok(case) = std::env::var("KERNELET_LIFECYCLE_FIXTURE") else {
            return;
        };
        let directory = FixtureDirectory(
            std::env::var_os("KERNELET_LIFECYCLE_DIRECTORY")
                .unwrap()
                .into(),
        );
        let mut fixture = LifecycleFixture::new(directory);
        match case.as_str() {
            "signal-zero" => {
                assert!(matches!(
                    fixture.query(&Control::Signal { id: 1, signal: 0 }),
                    Reply::Done
                ));
                assert_eq!(
                    fixture.holder.shared.lock().unwrap().state.status,
                    "created"
                );
                assert!(matches!(
                    fixture.query(&Control::Signal { id: 1, signal: 65 }),
                    Reply::Error(_)
                ));
                assert_eq!(
                    fixture.holder.shared.lock().unwrap().state.status,
                    "created"
                );
            }
            "signal-all" => {
                fixture.holder.shared.lock().unwrap().state.status = "running".into();
                let (mut init, init_worker) =
                    fixture.attach(1, fixture.process("init.pid", "exec /bin/sleep 5"));
                let (mut exec, exec_worker) =
                    fixture.attach(2, fixture.process("exec.pid", "exec /bin/sleep 5"));
                assert!(matches!(
                    fixture.query(&Control::SignalAll {
                        signal: libc::SIGKILL
                    }),
                    Reply::Done
                ));
                for (id, connection) in [(1, &mut init), (2, &mut exec)] {
                    loop {
                        if let Message::Exited { id: actual, code } =
                            protocol::receive(connection).unwrap()
                        {
                            assert_eq!((actual, code), (id, 128 + libc::SIGKILL));
                            break;
                        }
                    }
                }
                init_worker.join().unwrap().unwrap();
                exec_worker.join().unwrap().unwrap();
            }
            "adopted-reap" => {
                // Isolated fixture process acts as PID 1's subreaper on Linux.
                // SAFETY: scalar prctl changes only this dedicated subprocess.
                assert_eq!(
                    unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
                    0
                );
                fixture.holder.shared.lock().unwrap().state.status = "running".into();
                let (mut connection, worker) = fixture.attach(
                    2,
                    fixture.process(
                        "parent.pid",
                        &format!(
                            "sleep 30 & printf %s $! > {}; exit 0",
                            fixture.directory.0.join("child.pid").display()
                        ),
                    ),
                );
                loop {
                    if matches!(
                        protocol::receive(&mut connection).unwrap(),
                        Message::Exited { .. }
                    ) {
                        break;
                    }
                }
                worker.join().unwrap().unwrap();
                let child: u32 = std::fs::read_to_string(fixture.directory.0.join("child.pid"))
                    .unwrap()
                    .parse()
                    .unwrap();
                let deadline = Instant::now() + Duration::from_secs(2);
                while Path::new(&format!("/proc/{child}")).exists() {
                    assert!(
                        Instant::now() < deadline,
                        "last process's adopted child was not reaped"
                    );
                    thread::sleep(Duration::from_millis(10));
                }
            }
            "blocked-stdin" => {
                fixture.holder.shared.lock().unwrap().state.status = "running".into();
                let (mut input, input_worker) = fixture.attach(
                    2,
                    fixture.process("input.pid", "printf ready; exec /bin/sleep 5"),
                );
                let mut credit = false;
                let mut output = Vec::new();
                while !credit || output != b"ready" {
                    match protocol::receive(&mut input).unwrap() {
                        Message::InputReady { id: 2 } => credit = true,
                        Message::Data {
                            id: 2,
                            stream: Stream::Stdout,
                            data,
                        } => output.extend(data),
                        _ => {}
                    }
                }
                let pid = fixture.holder.shared.lock().unwrap().processes[&2]
                    .pid()
                    .unwrap();
                let guest_stdin = File::open(format!("/proc/{pid}/fd/0")).unwrap();
                // SAFETY: this fixture owns the pipe. Shrinking it makes a 16KiB
                // write block on every host, independent of its default capacity.
                assert!(
                    unsafe { libc::fcntl(guest_stdin.as_raw_fd(), libc::F_SETPIPE_SZ, 4096) } > 0
                );
                drop(guest_stdin);
                protocol::send(
                    &mut input,
                    &Message::Data {
                        id: 2,
                        stream: Stream::Stdin,
                        data: vec![7; protocol::STREAM_CHUNK_BYTES],
                    },
                )
                .unwrap();
                input
                    .set_read_timeout(Some(Duration::from_millis(100)))
                    .unwrap();
                let error = protocol::receive(&mut input).unwrap_err();
                assert!(matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ));
                input
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                protocol::send(
                    &mut input,
                    &Message::OutputFailed {
                        id: 2,
                        stream: Stream::Stdout,
                        detail: "cancel while stdin is blocked".into(),
                    },
                )
                .unwrap();
                let mut failed = false;
                loop {
                    match protocol::receive(&mut input).unwrap() {
                        Message::OutputFailed {
                            id: 2,
                            stream: Stream::Stdout,
                            detail,
                        } => {
                            assert!(detail.contains("cancel while stdin is blocked"));
                            failed = true;
                        }
                        Message::Close {
                            id: 2,
                            stream: Stream::Stdout,
                        } => {
                            assert!(failed, "stream close preceded its cancellation report");
                            break;
                        }
                        Message::InputReady { .. } => {
                            panic!("blocked stdin unexpectedly acknowledged")
                        }
                        _ => {}
                    }
                }
                let (mut probe, probe_worker) =
                    fixture.attach(3, fixture.process("probe.pid", "exec /bin/sleep 5"));
                assert!(matches!(
                    fixture.query(&Control::Signal {
                        id: 3,
                        signal: libc::SIGTERM
                    }),
                    Reply::Done
                ));
                loop {
                    if let Message::Exited { id, code } = protocol::receive(&mut probe).unwrap() {
                        assert_eq!((id, code), (3, 128 + libc::SIGTERM));
                        break;
                    }
                }
                probe_worker.join().unwrap().unwrap();
                assert!(fixture.holder.shared.lock().unwrap().failure.is_none());
                assert!(
                    !fixture
                        .holder
                        .shared
                        .lock()
                        .unwrap()
                        .input_ready
                        .contains(&2)
                );
                assert!(matches!(
                    fixture.query(&Control::Signal {
                        id: 2,
                        signal: libc::SIGTERM
                    }),
                    Reply::Done
                ));
                loop {
                    if let Message::Exited { id, code } = protocol::receive(&mut input).unwrap() {
                        assert_eq!((id, code), (2, 128 + libc::SIGTERM));
                        break;
                    }
                }
                input_worker.join().unwrap().unwrap();
            }
            "closed-stdin" => {
                fixture.holder.shared.lock().unwrap().state.status = "running".into();
                let (mut input, worker) = fixture.attach(
                    2,
                    fixture.process("input.pid", "exec 0<&-; printf ready; exec /bin/sleep 5"),
                );
                let mut credit = false;
                let mut output = Vec::new();
                while !credit || output != b"ready" {
                    match protocol::receive(&mut input).unwrap() {
                        Message::InputReady { id: 2 } => credit = true,
                        Message::Data {
                            id: 2,
                            stream: Stream::Stdout,
                            data,
                        } => output.extend(data),
                        _ => {}
                    }
                }
                protocol::send(
                    &mut input,
                    &Message::Data {
                        id: 2,
                        stream: Stream::Stdin,
                        data: vec![1],
                    },
                )
                .unwrap();
                loop {
                    match protocol::receive(&mut input).unwrap() {
                        Message::RequestFailed {
                            request: Request::Data { id: 2 },
                            detail,
                        } => {
                            assert!(detail.contains("stdin write failed"), "{detail}");
                            break;
                        }
                        Message::InputReady { .. } => panic!("closed stdin acknowledged delivery"),
                        _ => {}
                    }
                }
                assert!(fixture.holder.shared.lock().unwrap().failure.is_none());
                assert!(matches!(
                    fixture.query(&Control::Signal {
                        id: 2,
                        signal: libc::SIGTERM
                    }),
                    Reply::Done
                ));
                loop {
                    if let Message::Exited { id, code } = protocol::receive(&mut input).unwrap() {
                        assert_eq!((id, code), (2, 128 + libc::SIGTERM));
                        break;
                    }
                }
                worker.join().unwrap().unwrap();
            }
            "disconnect" => {
                fixture.holder.shared.lock().unwrap().state.status = "running".into();
                let (mut cached, cached_worker) =
                    fixture.attach(2, fixture.process("cached.pid", "exit 29"));
                loop {
                    if let Message::Exited { id, code } = protocol::receive(&mut cached).unwrap() {
                        assert_eq!((id, code), (2, 29));
                        break;
                    }
                }
                cached_worker.join().unwrap().unwrap();
                let (mut pending, pending_worker) =
                    fixture.attach(3, fixture.process("probe.pid", "exec /bin/sleep 5"));
                while !matches!(
                    protocol::receive(&mut pending).unwrap(),
                    Message::Started { id: 3, .. }
                ) {}
                assert!(matches!(
                    fixture.query(&Control::ExitStatus { id: 3 }),
                    Reply::ExitStatus { code: None }
                ));
                fixture.disconnect();
                assert!(matches!(
                    fixture.query(&Control::ExitStatus { id: 2 }),
                    Reply::ExitStatus { code: Some(29) }
                ));
                let Reply::Error(detail) = fixture.query(&Control::ExitStatus { id: 3 }) else {
                    panic!("lost agent was reported as an indefinitely pending exit");
                };
                assert!(detail.contains("agent connection closed"), "{detail}");
                pending_worker.join().unwrap().unwrap();
            }
            "retry" => {
                let mut bad = fixture.process("retry.pid", "exec /bin/cat");
                bad.args = vec!["/kernelet-fixture-does-not-exist".into()];
                let (peer, mut client) = UnixStream::pair().unwrap();
                start(&fixture.holder, peer, 1, Some(bad), true).unwrap();
                assert!(matches!(
                    protocol::receive_value::<Reply>(&mut client).unwrap(),
                    Reply::StartRejected(_)
                ));
                assert!(fixture.holder.shared.lock().unwrap().outputs.is_empty());
                let (mut connection, worker) =
                    fixture.attach(1, fixture.process("retry.pid", "exec /bin/cat"));
                let current = fixture.holder.shared.lock().unwrap().outputs[&1].clone();
                let (obsolete, _) = mpsc::sync_channel(OUTPUT_QUEUE_CAPACITY);
                // Deterministically run stale cleanup after the retry owns ID 1.
                // Its route and the real agent's streams must remain usable.
                drop(OutputRegistration {
                    holder: fixture.holder.clone(),
                    id: 1,
                    sender: Arc::new(obsolete),
                    armed: true,
                });
                assert!(Arc::ptr_eq(
                    fixture
                        .holder
                        .shared
                        .lock()
                        .unwrap()
                        .outputs
                        .get(&1)
                        .unwrap(),
                    &current,
                ));
                let expected: Vec<_> = (0..4 * protocol::STREAM_CHUNK_BYTES)
                    .map(|index| (index % 251) as u8)
                    .collect();
                let mut output = Vec::new();
                for chunk in expected.chunks(protocol::STREAM_CHUNK_BYTES) {
                    loop {
                        match protocol::receive(&mut connection).unwrap() {
                            Message::InputReady { id: 1 } => break,
                            Message::Data {
                                id: 1,
                                stream: Stream::Stdout,
                                data,
                            } => output.extend(data),
                            Message::OutputFailed { detail, .. }
                            | Message::RequestFailed { detail, .. } => panic!("{detail}"),
                            _ => {}
                        }
                    }
                    protocol::send(
                        &mut connection,
                        &Message::Data {
                            id: 1,
                            stream: Stream::Stdin,
                            data: chunk.to_vec(),
                        },
                    )
                    .unwrap();
                }
                // EOF is ordered after the last chunk and needs no extra credit.
                protocol::send(
                    &mut connection,
                    &Message::Close {
                        id: 1,
                        stream: Stream::Stdin,
                    },
                )
                .unwrap();
                loop {
                    match protocol::receive(&mut connection).unwrap() {
                        Message::Data {
                            id: 1,
                            stream: Stream::Stdout,
                            data,
                        } => output.extend(data),
                        Message::Exited { id, code } => {
                            assert_eq!((id, code), (1, 0));
                            break;
                        }
                        Message::OutputFailed { detail, .. }
                        | Message::RequestFailed { detail, .. } => panic!("{detail}"),
                        _ => {}
                    }
                }
                assert_eq!(output, expected);
                worker.join().unwrap().unwrap();
            }
            _ => panic!("unknown fixture {case}"),
        }
    }

    #[test]
    fn stalled_output_does_not_delay_another_process_start_signal_or_exit() {
        for sink in ["attachment", "log", "terminal"] {
            let mut fixture = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "runtime::holder::tests::stalled_output_fixture",
                    "--nocapture",
                ])
                .env("KERNELET_STALLED_OUTPUT_FIXTURE", sink)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(8);
            loop {
                if fixture.try_wait().unwrap().is_some() {
                    break;
                }
                if Instant::now() >= deadline {
                    fixture.kill().unwrap();
                    let output = fixture.wait_with_output().unwrap();
                    panic!("{sink} fixture timed out: {output:?}");
                }
                thread::sleep(Duration::from_millis(20));
            }
            let output = fixture.wait_with_output().unwrap();
            assert!(output.status.success(), "{sink} fixture failed: {output:?}");
        }
    }

    // Regression: review 35d423a96, one synchronous subscriber/log write froze
    // all Started/Exited/request ACKs. The isolated agent runs real child execs.
    #[test]
    #[ignore = "subprocess fixture with actual process ownership and stalled sinks"]
    fn stalled_output_fixture() {
        let Some(sink) = std::env::var_os("KERNELET_STALLED_OUTPUT_FIXTURE") else {
            return;
        };
        struct FixtureDirectory(std::path::PathBuf);
        impl Drop for FixtureDirectory {
            fn drop(&mut self) {
                for name in ["producer.pid", "probe.pid", "failed-attach.pid"] {
                    if let Ok(text) = std::fs::read_to_string(self.0.join(name))
                        && let Ok(pid) = text.trim().parse::<i32>()
                    {
                        let pid = nix::unistd::Pid::from_raw(pid);
                        let _ = nix::sys::signal::killpg(pid, nix::sys::signal::Signal::SIGKILL);
                        let _ = nix::sys::wait::waitpid(pid, None);
                    }
                }
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let directory = FixtureDirectory(std::env::temp_dir().join(format!(
            "kernelet-output-fixture-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos()
        )));
        std::fs::create_dir(&directory.0).unwrap();
        let process = |name: &str, command: &str| -> crate::config::Process {
            serde_json::from_value(serde_json::json!({
                "args": ["/bin/sh", "-c", format!("printf %s $$ > {}; exec {command}", directory.0.join(name).display())],
                "cwd": "/",
                "user": {"uid": nix::unistd::geteuid().as_raw(), "gid": nix::unistd::getegid().as_raw()}
            })).unwrap()
        };
        let producer = process("producer.pid", "/bin/dd if=/dev/zero bs=16384 count=1024");
        let probe = process("probe.pid", "/bin/sleep 5");
        let failed_attach = process(
            "failed-attach.pid",
            "/bin/dd if=/dev/zero bs=16384 count=1024",
        );
        let (agent_peer, runtime_peer) = UnixStream::pair().unwrap();
        let agent_thread = thread::spawn(move || {
            crate::agent::serve_connection(File::from(OwnedFd::from(agent_peer)))
        });
        let mut agent = File::from(OwnedFd::from(runtime_peer));
        assert!(matches!(
            protocol::receive(&mut agent).unwrap(),
            Message::Hello { .. }
        ));
        let (pipe_read, pipe_write) = nix::unistd::pipe().unwrap();
        let stalled = File::from(pipe_write);
        let stdout = if sink == "log" {
            stalled.try_clone().unwrap()
        } else {
            File::options().write(true).open("/dev/null").unwrap()
        };
        let terminal = (sink == "terminal").then_some(stalled);
        let holder = Arc::new(Holder {
            sandbox: Sandbox::from_file(File::open("/dev/null").unwrap()),
            vsock_cid: None,
            tlb_capture: Mutex::new(TlbCapture::default()),
            crossing_capture: Mutex::new(CrossingCapture::default()),
            writer: Mutex::new(agent.try_clone().unwrap()),
            shared: Mutex::new(Shared {
                state: State {
                    oci_version: "1.0.2".into(),
                    id: "test".into(),
                    status: "running".into(),
                    pid: std::process::id(),
                    bundle: directory.0.clone(),
                    annotations: BTreeMap::new(),
                },
                next_process: if sink == "terminal" { 2 } else { 3 },
                next_request: 1,
                processes: BTreeMap::new(),
                input_ready: BTreeSet::new(),
                input_errors: BTreeMap::new(),
                pending_requests: BTreeMap::new(),
                outputs: BTreeMap::new(),
                terminal,
                failure: None,
            }),
            changed: Condvar::new(),
            destroy_accepted: Mutex::new(false),
            stopping: AtomicBool::new(false),
            socket_path: directory.0.join("unused.sock"),
            stdout,
            stderr: File::options().write(true).open("/dev/null").unwrap(),
        });
        let reader_holder = holder.clone();
        let reader = thread::spawn(move || read_agent(reader_holder, agent));
        let (producer_peer, mut producer_client) = UnixStream::pair().unwrap();
        producer_client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        nix::sys::socket::setsockopt(&producer_peer, nix::sys::socket::sockopt::SndBuf, &4096)
            .unwrap();
        let producer_holder = holder.clone();
        let producer_id = if sink == "terminal" { 1 } else { 2 };
        let producer_thread = thread::spawn(move || {
            start(
                &producer_holder,
                producer_peer,
                producer_id,
                Some(producer),
                true,
            )
        });
        assert!(matches!(
            protocol::receive_value::<Reply>(&mut producer_client).unwrap(),
            Reply::Started { .. }
        ));
        // Verify that the sink really has bytes queued without consuming them.
        let stalled_fd = if sink == "attachment" {
            producer_client.as_raw_fd()
        } else {
            pipe_read.as_raw_fd()
        };
        let stall_deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let mut queued: libc::c_int = 0;
            // SAFETY: FIONREAD writes one c_int into a valid live object.
            assert_eq!(
                unsafe { libc::ioctl(stalled_fd, libc::FIONREAD, &mut queued) },
                0
            );
            if queued >= 4096 {
                break;
            }
            assert!(
                Instant::now() < stall_deadline,
                "producer never reached the stalled sink"
            );
            thread::sleep(Duration::from_millis(10));
        }
        let (probe_peer, mut probe_client) = UnixStream::pair().unwrap();
        probe_client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        protocol::send_value(&mut probe_client, &Control::Exec { process: probe }).unwrap();
        let probe_holder = holder.clone();
        let probe_thread = thread::spawn(move || handle(&probe_holder, probe_peer));
        let Reply::Started { id: probe_id } = protocol::receive_value(&mut probe_client).unwrap()
        else {
            panic!("probe did not start");
        };
        protocol::send(
            &mut probe_client,
            &Message::OutputFailed {
                id: probe_id,
                stream: Stream::Stderr,
                detail: "probe consumer cancelled stderr".into(),
            },
        )
        .unwrap();
        protocol::send(
            &mut probe_client,
            &Message::Data {
                id: probe_id,
                stream: Stream::Stdin,
                data: vec![1],
            },
        )
        .unwrap();
        let input_deadline = Instant::now() + Duration::from_secs(1);
        let mut shared = holder.shared.lock().unwrap();
        while !shared.input_ready.contains(&probe_id) {
            assert!(
                Instant::now() < input_deadline,
                "output cancellation also closed stdin"
            );
            shared = holder
                .changed
                .wait_timeout(shared, Duration::from_millis(20))
                .unwrap()
                .0;
        }
        drop(shared);
        let (signal_peer, mut signal_client) = UnixStream::pair().unwrap();
        signal_client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        protocol::send_value(
            &mut signal_client,
            &Control::Signal {
                id: probe_id,
                signal: libc::SIGTERM,
            },
        )
        .unwrap();
        let signal_holder = holder.clone();
        let signal_thread = thread::spawn(move || handle(&signal_holder, signal_peer));
        assert!(matches!(
            protocol::receive_value::<Reply>(&mut signal_client).unwrap(),
            Reply::Done
        ));
        loop {
            if let Message::Exited { id, code } = protocol::receive(&mut probe_client).unwrap() {
                assert_eq!((id, code), (probe_id, 128 + libc::SIGTERM));
                break;
            }
        }
        signal_thread.join().unwrap().unwrap();
        probe_thread.join().unwrap().unwrap();
        assert!(holder.shared.lock().unwrap().failure.is_none());
        assert_eq!(
            holder
                .shared
                .lock()
                .unwrap()
                .processes
                .get(&probe_id)
                .and_then(ProcessStatus::code),
            Some(128 + libc::SIGTERM)
        );
        // The slow process is cancelled independently; its consumer observes
        // disconnection while the real exit status remains queryable.
        assert!(producer_thread.join().unwrap().is_err());
        let query = |operation: &Control| -> Reply {
            let (peer, mut client) = UnixStream::pair().unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            protocol::send_value(&mut client, operation).unwrap();
            handle(&holder, peer).unwrap();
            protocol::receive_value(&mut client).unwrap()
        };
        let exit_deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Reply::ExitStatus { code: Some(_) } =
                query(&Control::ExitStatus { id: producer_id })
            {
                break;
            }
            assert!(
                Instant::now() < exit_deadline,
                "disconnected process exit was not retained"
            );
            thread::sleep(Duration::from_millis(20));
        }
        assert!(
            matches!(query(&Control::ExitStatus { id: probe_id }), Reply::ExitStatus { code: Some(code) } if code == 128 + libc::SIGTERM)
        );
        assert!(matches!(
            query(&Control::ForgetExited { id: probe_id }),
            Reply::Done
        ));
        assert!(
            !holder
                .shared
                .lock()
                .unwrap()
                .processes
                .get(&probe_id)
                .is_some_and(|p| p.code().is_some())
        );
        let (broken_peer, broken_client) = UnixStream::pair().unwrap();
        drop(broken_client);
        assert!(start(&holder, broken_peer, 100, Some(failed_attach), true).is_err());
        assert!(!holder.shared.lock().unwrap().outputs.contains_key(&100));
        let cancelled_deadline = Instant::now() + Duration::from_secs(2);
        let mut shared = holder.shared.lock().unwrap();
        while !shared
            .processes
            .get(&100)
            .is_some_and(|p| p.code().is_some())
        {
            assert!(
                Instant::now() < cancelled_deadline,
                "failed attachment left output waiting for its first credit"
            );
            shared = holder
                .changed
                .wait_timeout(shared, Duration::from_millis(20))
                .unwrap()
                .0;
        }
        drop(shared);
        // SAFETY: this descriptor is a live Unix socket owned by the fixture.
        unsafe { libc::shutdown(holder.writer.lock().unwrap().as_raw_fd(), libc::SHUT_RDWR) };
        assert!(agent_thread.join().unwrap().is_err());
        reader.join().unwrap();
    }

    #[test]
    fn request_failure_is_confined_to_its_process_or_query() {
        let mut shared = Shared {
            state: State {
                oci_version: "1.0.2".into(),
                id: "test".into(),
                status: "running".into(),
                pid: 1,
                bundle: std::path::PathBuf::new(),
                annotations: BTreeMap::new(),
            },
            next_process: 4,
            next_request: 12,
            processes: BTreeMap::from([
                (2, ProcessStatus::StartPending),
                (3, ProcessStatus::StartPending),
            ]),
            input_ready: BTreeSet::new(),
            input_errors: BTreeMap::new(),
            pending_requests: BTreeMap::from([(10, None), (11, None)]),
            outputs: BTreeMap::new(),
            terminal: None,
            failure: None,
        };

        shared.reject_request(Request::Start { id: 2 }, "bad process".into());
        shared.reject_request(
            Request::ListProcesses { request_id: 10 },
            "query failed".into(),
        );
        shared.resolve_request(11, RequestResult::Done);

        assert_eq!(
            match shared.processes.get(&2) {
                Some(ProcessStatus::Rejected { detail }) => Some(detail.as_str()),
                _ => None,
            },
            Some("bad process")
        );
        assert_eq!(shared.processes.get(&3), Some(&ProcessStatus::StartPending));
        assert!(matches!(
            shared.pending_requests.get(&10),
            Some(Some(RequestResult::Failed(detail))) if detail == "query failed"
        ));
        assert!(matches!(
            shared.pending_requests.get(&11),
            Some(Some(RequestResult::Done))
        ));
        assert!(shared.failure.is_none());
    }
}
