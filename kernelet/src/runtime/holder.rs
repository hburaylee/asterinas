// SPDX-License-Identifier: MPL-2.0

//! One process retains each sandbox capability and multiplexes agent messages.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::OwnedFd,
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

use super::{Control, Record, Reply, State, Stats};
use crate::{
    fd,
    protocol::{self, Message, Request, Stream},
    uapi::{self, Sandbox},
};

struct Shared {
    state: State,
    next_process: u64,
    next_request: u64,
    started: BTreeMap<u64, u32>,
    start_errors: BTreeMap<u64, String>,
    input_ready: BTreeSet<u64>,
    input_errors: BTreeMap<u64, String>,
    pending_requests: BTreeMap<u64, Option<RequestResult>>,
    subscribers: BTreeMap<u64, mpsc::SyncSender<Message>>,
    terminal: Option<File>,
    failure: Option<String>,
}

enum RequestResult {
    Done,
    Processes(Vec<u32>),
    Failed(String),
}

struct Holder {
    sandbox: Sandbox,
    writer: Mutex<File>,
    shared: Mutex<Shared>,
    changed: Condvar,
    stopping: AtomicBool,
    socket_path: std::path::PathBuf,
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
    let holder = Arc::new(Holder {
        sandbox,
        writer: Mutex::new(agent.try_clone()?),
        shared: Mutex::new(Shared {
            state,
            next_process: 2,
            next_request: 1,
            started: BTreeMap::new(),
            start_errors: BTreeMap::new(),
            input_ready: BTreeSet::new(),
            input_errors: BTreeMap::new(),
            pending_requests: BTreeMap::new(),
            subscribers: BTreeMap::new(),
            terminal,
            failure: None,
        }),
        changed: Condvar::new(),
        stopping: AtomicBool::new(false),
        socket_path: directory.join("control.sock"),
    });
    drain_endpoint(log, directory.join("kernel.log"))?;
    drain_endpoint(console, directory.join("console.log"))?;
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
    let reader_holder = holder.clone();
    thread::spawn(move || read_agent(reader_holder, agent, stdout, stderr));
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
        Control::Stats => {
            let stats = holder.sandbox.stats()?;
            protocol::send_value(
                &mut connection,
                &Reply::Stats(Stats {
                    cpu_time_ns: stats.cpu_time_ns,
                    throttled_ns: stats.throttled_ns,
                    completion_cpu_ns: stats.completion_cpu_ns,
                    ingress_copy_cpu_ns: stats.ingress_copy_cpu_ns,
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
            protocol::send_value(&mut connection, &Reply::State(shared.state.clone()))?;
        }
        Control::Start { attach } => {
            {
                let shared = holder.shared.lock().unwrap();
                ensure!(shared.state.status == "created", "container is not created");
                ensure!(
                    !shared.started.contains_key(&1),
                    "container already started"
                );
            }
            start(holder, connection, 1, None, attach)?;
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
        Control::Signal { id, signal } => {
            let status = holder.shared.lock().unwrap().state.status.clone();
            if id == 1 && status == "created" {
                holder.sandbox.kill(signal as u32)?;
                holder.shared.lock().unwrap().state.status = "stopped".into();
            } else {
                ensure!(status == "running", "container is not running");
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
                    None if id == 1 => holder.sandbox.kill(signal as u32)?,
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
            // OCI `stopped` means the init process exited; the kernelet may
            // still be running until its Host carriers have been stopped.
            holder.sandbox.kill(libc::SIGKILL as u32)?;
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                match holder.sandbox.destroy() {
                    Ok(()) => break,
                    Err(error)
                        if error
                            .downcast_ref::<std::io::Error>()
                            .and_then(std::io::Error::raw_os_error)
                            == Some(libc::EBUSY)
                            && Instant::now() < deadline =>
                    {
                        holder.sandbox.kill(libc::SIGKILL as u32)?;
                        thread::sleep(Duration::from_millis(10));
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
            protocol::send_value(&mut connection, &Reply::Done)?;
            holder.stopping.store(true, Ordering::Release);
            let _ = UnixStream::connect(&holder.socket_path);
        }
    }
    Ok(())
}

fn start(
    holder: &Arc<Holder>,
    mut connection: UnixStream,
    id: u64,
    process: Option<crate::config::Process>,
    attach: bool,
) -> Result<()> {
    let (sender, receiver) = mpsc::sync_channel(16);
    {
        let mut shared = holder.shared.lock().unwrap();
        ensure!(!shared.started.contains_key(&id), "process already started");
        // Reserve the ID before sending, so concurrent start commands cannot race.
        shared.started.insert(id, 0);
        if attach {
            shared.subscribers.insert(id, sender);
        }
    }
    if let Err(error) = holder.send(&Message::Start { id, process }) {
        let mut shared = holder.shared.lock().unwrap();
        shared.started.remove(&id);
        shared.subscribers.remove(&id);
        return Err(error);
    }
    let shared = holder.shared.lock().unwrap();
    let (mut shared, _) = holder
        .changed
        .wait_timeout_while(shared, Duration::from_secs(30), |shared| {
            shared.started.get(&id) == Some(&0)
                && !shared.start_errors.contains_key(&id)
                && shared.failure.is_none()
        })
        .unwrap();
    if let Some(detail) = shared.start_errors.remove(&id) {
        shared.started.remove(&id);
        shared.subscribers.remove(&id);
        bail!("{detail}");
    }
    if let Some(failure) = shared.failure.clone() {
        shared.subscribers.remove(&id);
        bail!("{failure}");
    }
    if shared.started.get(&id) == Some(&0) {
        shared.subscribers.remove(&id);
        bail!("agent start timed out");
    }
    drop(shared);
    protocol::send_value(&mut connection, &Reply::Started { id })?;
    if attach {
        let mut input = connection.try_clone()?;
        let input_holder = holder.clone();
        thread::spawn(move || {
            while let Ok(message) = protocol::receive(&mut input) {
                if matches!(&message, Message::Data { id: target, stream: Stream::Stdin, .. } | Message::Close { id: target, stream: Stream::Stdin } if *target == id)
                {
                    if input_holder.send_input(&message).is_err() {
                        break;
                    }
                } else {
                    break;
                }
            }
            let _ = input_holder.send(&Message::Close {
                id,
                stream: Stream::Stdin,
            });
        });
        for message in receiver {
            protocol::send(&mut connection, &message)?;
            if matches!(message, Message::Exited { .. } | Message::Error { .. }) {
                break;
            }
        }
        holder.shared.lock().unwrap().subscribers.remove(&id);
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
                while let Ok(length) = input.read(&mut data) {
                    if length == 0 {
                        break;
                    }
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
            && shared.started.contains_key(id)
            && shared.state.status == "running"
        {
            shared = self.changed.wait(shared).unwrap();
        }
        if let Some(detail) = &shared.failure {
            bail!("{detail}");
        }
        if let Some(detail) = shared.input_errors.remove(id) {
            bail!("{detail}");
        }
        Ok(())
    }

    fn send(&self, message: &Message) -> Result<()> {
        Ok(protocol::send(&mut *self.writer.lock().unwrap(), message)?)
    }
}

fn read_agent(holder: Arc<Holder>, mut agent: File, mut stdout: File, mut stderr: File) {
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
                    if shared.started.contains_key(id) {
                        shared.input_ready.insert(*id);
                    }
                    holder.changed.notify_all();
                    continue;
                }
                Message::Started { id, pid } => {
                    shared.started.insert(*id, *pid);
                    if *id == 1 {
                        shared.state.status = "running".into();
                    }
                    holder.changed.notify_all();
                    *id
                }
                Message::Exited { id, .. } => {
                    shared.started.remove(id);
                    shared.input_ready.remove(id);
                    shared.input_errors.remove(id);
                    if *id == 1 {
                        shared.state.status = "stopped".into();
                    }
                    holder.changed.notify_all();
                    *id
                }
                Message::Data { id, .. } | Message::Close { id, .. } => *id,
                Message::Error { detail } => {
                    shared.failure = Some(detail.clone());
                    holder.changed.notify_all();
                    for sender in shared.subscribers.values() {
                        let _ = sender.try_send(message.clone());
                    }
                    continue;
                }
                _ => bail!("unexpected agent response"),
            };
            let subscriber = shared.subscribers.get(&id).cloned();
            let terminal = if id == 1 {
                shared.terminal.as_ref().map(File::try_clone).transpose()?
            } else {
                None
            };
            drop(shared);
            if let Some(sender) = subscriber {
                let _ = sender.send(message.clone());
            }
            if let Message::Data { stream, data, .. } = &message {
                if let Some(mut terminal) = terminal {
                    terminal.write_all(data)?;
                } else if *stream == Stream::Stderr {
                    stderr.write_all(data)?;
                } else {
                    stdout.write_all(data)?;
                }
            }
        }
    })();
    if let Err(error) = result {
        let mut shared = holder.shared.lock().unwrap();
        shared.state.status = "stopped".into();
        let detail = format!("agent connection closed: {error:#}");
        shared.failure = Some(detail.clone());
        for sender in shared.subscribers.values() {
            let _ = sender.try_send(Message::Error {
                detail: detail.clone(),
            });
        }
        shared.subscribers.clear();
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
            Request::Start { id } if self.started.get(&id) == Some(&0) => {
                self.start_errors.insert(id, detail);
            }
            Request::Data { id } if self.started.contains_key(&id) => {
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
    use super::*;

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
            started: BTreeMap::from([(2, 0), (3, 0)]),
            start_errors: BTreeMap::new(),
            input_ready: BTreeSet::new(),
            input_errors: BTreeMap::new(),
            pending_requests: BTreeMap::from([(10, None), (11, None)]),
            subscribers: BTreeMap::new(),
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
            shared.start_errors.get(&2).map(String::as_str),
            Some("bad process")
        );
        assert_eq!(shared.started.get(&3), Some(&0));
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
