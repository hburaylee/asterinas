// SPDX-License-Identifier: MPL-2.0

//! Containerd shim v2 using the same in-process holder as the OCI CLI.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    sync::{Arc, Condvar, Mutex},
    thread,
};

use anyhow::{Context, Result, bail, ensure};
use containerd_shim::{
    self as shim, Config, DeleteResponse, ExitSignal, Flags, TtrpcContext, TtrpcResult, api,
    protos::{
        events::task,
        protobuf::{MessageDyn, well_known_types::timestamp::Timestamp},
        ttrpc::{self, Code},
    },
    synchronous::publisher::RemotePublisher,
};

use crate::{
    config::Process,
    protocol::{self, Message, Stream},
    runtime::{self, Control, Reply},
};

pub fn run() {
    shim::run::<Service>("io.containerd.kernelet.v2", None);
}

#[derive(Clone)]
struct Service {
    root: PathBuf,
    id: String,
    namespace: String,
    exit: Arc<ExitSignal>,
    publisher: Arc<Mutex<Option<RemotePublisher>>>,
    task: Arc<Mutex<Option<Task>>>,
    changed: Arc<Condvar>,
}
struct Task {
    id: String,
    bundle: String,
    processes: BTreeMap<String, ProcessRecord>,
}
#[derive(Clone)]
struct ProcessRecord {
    spec: Option<Process>,
    stdin: String,
    stdout: String,
    stderr: String,
    terminal: bool,
    agent_id: Option<u64>,
    state: ProcessState,
    exited_at: Option<Timestamp>,
}
#[derive(Clone, Copy)]
enum ProcessState {
    Created,
    Starting,
    Running,
    Exited(u32),
}

impl shim::Shim for Service {
    type T = Self;
    fn new(_: &str, args: &Flags, config: &mut Config) -> Self {
        config.no_reaper = true;
        config.no_sub_reaper = true;
        Self::new_at(
            Path::new("/run/kernelet/containerd").join(&args.namespace),
            args,
        )
    }
    fn start_shim(&mut self, opts: shim::StartOpts) -> shim::Result<String> {
        let grouping = opts.id.clone();
        let (_, address) = shim::spawn(opts, &grouping, Vec::new())?;
        Ok(address)
    }
    fn delete_shim(&mut self) -> shim::Result<DeleteResponse> {
        self.cleanup()
            .map_err(|error| shim::Error::Other(format!("{error:#}")))
    }
    fn wait(&mut self) {
        self.exit.wait();
    }
    fn create_task_service(&self, publisher: RemotePublisher) -> Self {
        *self.publisher.lock().unwrap() = Some(publisher);
        self.clone()
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ExitRecord {
    code: u32,
    seconds: i64,
    nanos: i32,
}

impl Service {
    /// Builds the service with an explicit state root; `Shim::new` supplies
    /// the containerd layout, tests supply a temporary directory.
    fn new_at(root: PathBuf, args: &Flags) -> Self {
        Self {
            root,
            id: args.id.clone(),
            namespace: args.namespace.clone(),
            exit: Arc::new(ExitSignal::default()),
            publisher: Arc::new(Mutex::new(None)),
            task: Arc::new(Mutex::new(None)),
            changed: Arc::new(Condvar::new()),
        }
    }

    fn cleanup(&self) -> Result<DeleteResponse> {
        let directory = self.root.join(&self.id);
        let state = runtime::state(&directory)?;
        let exit = match File::open(directory.join("exit.json")) {
            Ok(file) => Some(serde_json::from_reader::<_, ExitRecord>(file)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        runtime::delete(&directory, true)?;
        let mut response = DeleteResponse::new();
        response.set_pid(state.pid);
        if let Some(exit) = exit {
            response.set_exit_status(exit.code);
            response.set_exited_at(Timestamp {
                seconds: exit.seconds,
                nanos: exit.nanos,
                ..Default::default()
            });
        } else {
            // The capability owner's death revokes all guest execution. No
            // normal process exit was observed; report forced termination.
            response.set_exit_status(128 + libc::SIGKILL as u32);
            response.set_exited_at(shim::util::timestamp()?);
        }
        Ok(response)
    }

    fn directory(&self, id: &str) -> Result<PathBuf> {
        let task = self.task.lock().unwrap();
        let task = task.as_ref().context("sandbox has not been created")?;
        ensure!(task.id == id, "unknown sandbox");
        Ok(self.root.join(id))
    }
    fn process(&self, id: &str, exec_id: &str) -> Result<ProcessRecord> {
        let task = self.task.lock().unwrap();
        let task = task.as_ref().context("sandbox has not been created")?;
        ensure!(task.id == id, "unknown sandbox");
        task.processes
            .get(exec_id)
            .cloned()
            .context("unknown process")
    }
    /// Restores the created state after a start attempt failed before the
    /// holder acknowledged any guest process.
    fn reset(&self, exec_id: &str) {
        if let Some(task) = self.task.lock().unwrap().as_mut()
            && let Some(process) = task.processes.get_mut(exec_id)
        {
            process.state = ProcessState::Created;
        }
    }
    fn publish(&self, topic: &str, event: impl MessageDyn + 'static) -> Result<()> {
        if let Some(publisher) = self.publisher.lock().unwrap().as_ref() {
            publisher.publish(
                shim::Context::default(),
                topic,
                &self.namespace,
                Box::new(event),
            )?;
        }
        Ok(())
    }
    fn exited(&self, id: &str, exec_id: &str, code: u32) {
        let exited_at = shim::util::timestamp().ok();
        if let Some(task) = self.task.lock().unwrap().as_mut()
            && let Some(process) = task.processes.get_mut(exec_id)
        {
            process.state = ProcessState::Exited(code);
            process.exited_at = exited_at.clone();
        }
        if exec_id.is_empty()
            && let Some(time) = &exited_at
        {
            let directory = self.root.join(id);
            let persist = (|| -> Result<()> {
                let mut file = File::create(directory.join("exit.json.pending"))?;
                serde_json::to_writer(
                    &mut file,
                    &ExitRecord {
                        code,
                        seconds: time.seconds,
                        nanos: time.nanos,
                    },
                )?;
                file.sync_all()?;
                fs::rename(
                    directory.join("exit.json.pending"),
                    directory.join("exit.json"),
                )?;
                File::open(directory)?.sync_all()?;
                Ok(())
            })();
            if let Err(error) = persist {
                eprintln!("persist kernelet exit: {error:#}");
            }
        }
        self.changed.notify_all();
        let mut event = task::TaskExit::new();
        event.set_container_id(id.into());
        event.set_id(exec_id.into());
        event.set_pid(std::process::id());
        event.set_exit_status(code);
        if let Some(time) = exited_at {
            event.set_exited_at(time);
        }
        let _ = self.publish("/tasks/exit", event);
    }

    /// Spawns the detached thread that turns a completed relay into exit
    /// bookkeeping. The thread's lifetime is independent of Start: once
    /// spawned, no later failure can prevent the exit notification.
    fn observe_exit(
        &self,
        connection: UnixStream,
        agent_id: u64,
        process: ProcessRecord,
        id: String,
        exec_id: String,
    ) {
        let service = self.clone();
        thread::spawn(move || {
            let code = relay(connection, agent_id, &process).unwrap_or(255);
            service.exited(&id, &exec_id, code);
        });
    }

    /// Commits an acknowledged start and owns its exit observation before
    /// attempting hooks or event publication.
    fn finish_start(
        &self,
        connection: UnixStream,
        agent_id: u64,
        process: ProcessRecord,
        id: &str,
        exec_id: &str,
        directory: &Path,
    ) -> Result<()> {
        {
            let mut task = self.task.lock().unwrap();
            let process = task.as_mut().unwrap().processes.get_mut(exec_id).unwrap();
            process.agent_id = Some(agent_id);
            process.state = ProcessState::Running;
        }
        self.observe_exit(connection, agent_id, process, id.into(), exec_id.into());
        self.announce_start(id, exec_id, directory)
    }

    /// Runs the post-start announcements: the poststart hook for the
    /// container process and the task events. Failures are returned to the
    /// caller; they never affect the already-installed exit observation.
    fn announce_start(&self, id: &str, exec_id: &str, directory: &Path) -> Result<()> {
        if exec_id.is_empty() {
            runtime::run_hooks(directory, "poststart")?;
            let mut event = task::TaskStart::new();
            event.set_container_id(id.into());
            event.set_pid(std::process::id());
            self.publish("/tasks/start", event)
        } else {
            let mut event = task::TaskExecStarted::new();
            event.set_container_id(id.into());
            event.set_exec_id(exec_id.into());
            event.set_pid(std::process::id());
            self.publish("/tasks/exec-started", event)
        }
    }

    /// Blocks until the given process records an exit; shared by the ttrpc
    /// `wait` handler and the lifecycle tests.
    fn wait_for_exit(&self, exec_id: &str) -> Result<(u32, Option<Timestamp>)> {
        let mut task = self.task.lock().unwrap();
        loop {
            let process = task
                .as_ref()
                .context("sandbox deleted")?
                .processes
                .get(exec_id)
                .context("unknown process")?;
            if let ProcessState::Exited(code) = process.state {
                return Ok((code, process.exited_at.clone()));
            }
            task = self.changed.wait(task).unwrap();
        }
    }
}

impl shim::Task for Service {
    fn create(
        &self,
        _: &TtrpcContext,
        req: api::CreateTaskRequest,
    ) -> TtrpcResult<api::CreateTaskResponse> {
        convert((|| {
            ensure!(
                req.checkpoint.is_empty() && req.parent_checkpoint.is_empty(),
                "checkpoint restore is unsupported"
            );
            let mut slot = self.task.lock().unwrap();
            ensure!(slot.is_none(), "shim already owns a sandbox");
            let snapshot = SnapshotMount::prepare(&req)?;
            runtime::create_for_shim(&self.root, &req.id, Path::new(&req.bundle))?;
            if let Err(error) = snapshot.unmount() {
                let _ =
                    runtime::request(&self.root.join(&req.id), &Control::Delete { force: true });
                return Err(error);
            }
            let process = ProcessRecord {
                spec: None,
                stdin: req.stdin.clone(),
                stdout: req.stdout.clone(),
                stderr: req.stderr.clone(),
                terminal: req.terminal,
                agent_id: None,
                state: ProcessState::Created,
                exited_at: None,
            };
            *slot = Some(Task {
                id: req.id.clone(),
                bundle: req.bundle.clone(),
                processes: BTreeMap::from([(String::new(), process)]),
            });
            drop(slot);
            let mut event = task::TaskCreate::new();
            event.set_container_id(req.id);
            event.set_bundle(req.bundle);
            event.set_pid(std::process::id());
            self.publish("/tasks/create", event)?;
            Ok(api::CreateTaskResponse {
                pid: std::process::id(),
                ..Default::default()
            })
        })())
    }
    fn start(&self, _: &TtrpcContext, req: api::StartRequest) -> TtrpcResult<api::StartResponse> {
        convert((|| {
            let directory = self.directory(&req.id)?;
            let process = {
                let mut task = self.task.lock().unwrap();
                let process = task
                    .as_mut()
                    .unwrap()
                    .processes
                    .get_mut(&req.exec_id)
                    .context("unknown process")?;
                ensure!(
                    matches!(process.state, ProcessState::Created),
                    "process has already started"
                );
                process.state = ProcessState::Starting;
                process.clone()
            };
            let operation = if let Some(spec) = &process.spec {
                Control::Exec {
                    process: spec.clone(),
                }
            } else {
                Control::Start { attach: true }
            };
            let (reply, connection) = match runtime::request(&directory, &operation) {
                Ok(response) => response,
                Err(error) => {
                    self.reset(&req.exec_id);
                    return Err(error);
                }
            };
            let Reply::Started { id: agent_id } = reply else {
                self.reset(&req.exec_id);
                bail!("invalid holder start reply");
            };
            // The holder acknowledged the start, so the guest process exists.
            // Exit observation is installed before any fallible bookkeeping:
            // a failing poststart hook or event publication below must never
            // strand Wait or Delete on a process that is already running.
            if let Err(error) = self.finish_start(
                connection,
                agent_id,
                process,
                &req.id,
                &req.exec_id,
                &directory,
            ) {
                // The process keeps running and its exit stays observed; the
                // failure only concerns the announcement, so report it to the
                // caller without rolling the running process back.
                eprintln!(
                    "kernelet start announcement for {}/{}: {error:#}",
                    req.id, req.exec_id
                );
                return Err(error);
            }
            Ok(api::StartResponse {
                pid: std::process::id(),
                ..Default::default()
            })
        })())
    }
    fn exec(&self, _: &TtrpcContext, req: api::ExecProcessRequest) -> TtrpcResult<api::Empty> {
        convert((|| {
            self.directory(&req.id)?;
            ensure!(!req.exec_id.is_empty(), "exec ID is empty");
            let spec: Process = serde_json::from_slice(
                &req.spec
                    .as_ref()
                    .context("missing process specification")?
                    .value,
            )?;
            spec.validate()?;
            ensure!(
                spec.terminal == req.terminal,
                "terminal setting differs from process specification"
            );
            let mut slot = self.task.lock().unwrap();
            let processes = &mut slot.as_mut().unwrap().processes;
            ensure!(processes.len() < 256, "too many live exec records");
            ensure!(
                !processes.contains_key(&req.exec_id),
                "exec ID already exists"
            );
            processes.insert(
                req.exec_id.clone(),
                ProcessRecord {
                    spec: Some(spec),
                    stdin: req.stdin,
                    stdout: req.stdout,
                    stderr: req.stderr,
                    terminal: req.terminal,
                    agent_id: None,
                    state: ProcessState::Created,
                    exited_at: None,
                },
            );
            drop(slot);
            let mut event = task::TaskExecAdded::new();
            event.set_container_id(req.id);
            event.set_exec_id(req.exec_id);
            self.publish("/tasks/exec-added", event)?;
            Ok(api::Empty::default())
        })())
    }
    fn state(&self, _: &TtrpcContext, req: api::StateRequest) -> TtrpcResult<api::StateResponse> {
        convert((|| {
            let process = self.process(&req.id, &req.exec_id)?;
            let (status, code) = match process.state {
                ProcessState::Created | ProcessState::Starting => (api::Status::CREATED, 0),
                ProcessState::Running => (api::Status::RUNNING, 0),
                ProcessState::Exited(code) => (api::Status::STOPPED, code),
            };
            let task = self.task.lock().unwrap();
            let task = task.as_ref().unwrap();
            Ok(api::StateResponse {
                id: req.id,
                bundle: task.bundle.clone(),
                pid: std::process::id(),
                status: status.into(),
                stdin: process.stdin,
                stdout: process.stdout,
                stderr: process.stderr,
                terminal: process.terminal,
                exit_status: code,
                exited_at: process.exited_at.into(),
                exec_id: req.exec_id,
                ..Default::default()
            })
        })())
    }
    fn pause(&self, _: &TtrpcContext, _: api::PauseRequest) -> TtrpcResult<api::Empty> {
        Err(unsupported("pause"))
    }
    fn resume(&self, _: &TtrpcContext, _: api::ResumeRequest) -> TtrpcResult<api::Empty> {
        Err(unsupported("resume"))
    }
    fn update(&self, _: &TtrpcContext, _: api::UpdateTaskRequest) -> TtrpcResult<api::Empty> {
        Err(unsupported("update"))
    }
    fn kill(&self, _: &TtrpcContext, req: api::KillRequest) -> TtrpcResult<api::Empty> {
        convert((|| {
            let process = self.process(&req.id, &req.exec_id)?;
            let directory = self.directory(&req.id)?;
            if matches!(process.state, ProcessState::Created) && !req.exec_id.is_empty() {
                self.exited(&req.id, &req.exec_id, 128 + req.signal);
                return Ok(api::Empty::default());
            }
            let id = process.agent_id.unwrap_or(1);
            runtime::request(
                &directory,
                &Control::Signal {
                    id,
                    signal: req.signal.try_into()?,
                },
            )?;
            if matches!(process.state, ProcessState::Created) {
                self.exited(&req.id, &req.exec_id, 128 + req.signal);
            }
            Ok(api::Empty::default())
        })())
    }
    fn resize_pty(&self, _: &TtrpcContext, req: api::ResizePtyRequest) -> TtrpcResult<api::Empty> {
        convert((|| {
            let process = self.process(&req.id, &req.exec_id)?;
            let id = process.agent_id.context("process has not started")?;
            runtime::request(
                &self.directory(&req.id)?,
                &Control::Resize {
                    id,
                    columns: req.width.try_into()?,
                    rows: req.height.try_into()?,
                },
            )?;
            Ok(api::Empty::default())
        })())
    }
    fn close_io(&self, _: &TtrpcContext, req: api::CloseIORequest) -> TtrpcResult<api::Empty> {
        convert((|| {
            if req.stdin {
                let process = self.process(&req.id, &req.exec_id)?;
                let id = process.agent_id.context("process has not started")?;
                runtime::request(&self.directory(&req.id)?, &Control::CloseInput { id })?;
            }
            Ok(api::Empty::default())
        })())
    }
    fn wait(&self, _: &TtrpcContext, req: api::WaitRequest) -> TtrpcResult<api::WaitResponse> {
        convert((|| {
            self.directory(&req.id)?;
            let (code, exited_at) = self.wait_for_exit(&req.exec_id)?;
            let mut response = api::WaitResponse::new();
            response.set_exit_status(code);
            if let Some(time) = exited_at {
                response.set_exited_at(time);
            }
            Ok(response)
        })())
    }
    fn delete(&self, _: &TtrpcContext, req: api::DeleteRequest) -> TtrpcResult<DeleteResponse> {
        convert((|| {
            let directory = self.directory(&req.id)?;
            let process = self.process(&req.id, &req.exec_id)?;
            let ProcessState::Exited(code) = process.state else {
                bail!("process must be stopped before deletion");
            };
            if req.exec_id.is_empty() {
                runtime::request(&directory, &Control::Delete { force: false })?;
                runtime::run_hooks(&directory, "poststop")?;
                fs::remove_dir_all(directory)?;
                *self.task.lock().unwrap() = None;
            } else {
                self.task
                    .lock()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .processes
                    .remove(&req.exec_id);
            }
            self.changed.notify_all();
            let mut response = DeleteResponse::new();
            response.set_pid(std::process::id());
            response.set_exit_status(code);
            if let Some(time) = process.exited_at {
                response.set_exited_at(time);
            }
            let mut event = task::TaskDelete::new();
            event.set_container_id(req.id);
            event.set_id(req.exec_id);
            event.set_pid(response.pid);
            event.set_exit_status(response.exit_status);
            if let Some(time) = response.exited_at.as_ref() {
                event.set_exited_at(time.clone());
            }
            self.publish("/tasks/delete", event)?;
            Ok(response)
        })())
    }
    fn pids(&self, _: &TtrpcContext, req: api::PidsRequest) -> TtrpcResult<api::PidsResponse> {
        convert((|| {
            let (Reply::Processes(pids), _) =
                runtime::request(&self.directory(&req.id)?, &Control::Processes)?
            else {
                bail!("invalid process list reply");
            };
            Ok(api::PidsResponse {
                processes: pids
                    .into_iter()
                    .map(|pid| shim::protos::api::ProcessInfo {
                        pid,
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            })
        })())
    }
    fn stats(&self, _: &TtrpcContext, req: api::StatsRequest) -> TtrpcResult<api::StatsResponse> {
        convert((|| {
            use shim::protos::{
                cgroups::metrics,
                protobuf::{Message, MessageField, well_known_types::any::Any},
            };
            let (Reply::Stats(stats), _) =
                runtime::request(&self.directory(&req.id)?, &Control::Stats)?
            else {
                bail!("invalid statistics reply");
            };
            let metrics = metrics::Metrics {
                cpu: MessageField::some(metrics::CPUStat {
                    usage: MessageField::some(metrics::CPUUsage {
                        total: stats.cpu_time_ns,
                        ..Default::default()
                    }),
                    throttling: MessageField::some(metrics::Throttle {
                        throttled_time: stats.throttled_ns,
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                memory: MessageField::some(metrics::MemoryStat {
                    usage: MessageField::some(metrics::MemoryEntry {
                        usage: stats.memory_bytes,
                        limit: stats.memory_limit,
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            };
            Ok(api::StatsResponse {
                stats: MessageField::some(Any {
                    type_url: "types.containerd.io/io.containerd.cgroups.v1.Metrics".into(),
                    value: metrics.write_to_bytes()?,
                    ..Default::default()
                }),
                ..Default::default()
            })
        })())
    }
    fn connect(
        &self,
        _: &TtrpcContext,
        _: api::ConnectRequest,
    ) -> TtrpcResult<api::ConnectResponse> {
        Ok(api::ConnectResponse {
            shim_pid: std::process::id(),
            task_pid: std::process::id(),
            version: env!("CARGO_PKG_VERSION").into(),
            ..Default::default()
        })
    }
    fn shutdown(&self, _: &TtrpcContext, req: api::ShutdownRequest) -> TtrpcResult<api::Empty> {
        if self.task.lock().unwrap().is_some() && !req.now {
            return Err(error("sandbox still exists"));
        }
        self.exit.signal();
        Ok(api::Empty::default())
    }
}

struct SnapshotMount {
    target: Option<PathBuf>,
}
impl SnapshotMount {
    fn prepare(request: &api::CreateTaskRequest) -> Result<Self> {
        use nix::mount::{self, MsFlags};
        if request.rootfs.is_empty() {
            return Ok(Self { target: None });
        }
        ensure!(
            request.rootfs.len() == 1,
            "multiple snapshot root mounts are unsupported"
        );
        let config: crate::config::Config =
            serde_json::from_reader(File::open(Path::new(&request.bundle).join("config.json"))?)?;
        let target = Path::new(&request.bundle).join(&config.root.path);
        fs::create_dir_all(&target)?;
        let snapshot = &request.rootfs[0];
        let mut flags = MsFlags::empty();
        let mut options = Vec::new();
        for option in &snapshot.options {
            match option.as_str() {
                "bind" => flags |= MsFlags::MS_BIND,
                "rbind" => flags |= MsFlags::MS_BIND | MsFlags::MS_REC,
                "ro" => flags |= MsFlags::MS_RDONLY,
                "rw" => flags.remove(MsFlags::MS_RDONLY),
                "nosuid" => flags |= MsFlags::MS_NOSUID,
                "nodev" => flags |= MsFlags::MS_NODEV,
                "noexec" => flags |= MsFlags::MS_NOEXEC,
                other => options.push(other),
            }
        }
        if snapshot.type_ == "bind" {
            flags |= MsFlags::MS_BIND;
        }
        mount::mount(
            Some(snapshot.source.as_str()),
            &target,
            Some(snapshot.type_.as_str()),
            flags,
            Some(options.join(",").as_str()),
        )?;
        Ok(Self {
            target: Some(target),
        })
    }
    fn unmount(mut self) -> Result<()> {
        if let Some(target) = self.target.take() {
            nix::mount::umount(&target)?;
        }
        Ok(())
    }
}
impl Drop for SnapshotMount {
    fn drop(&mut self) {
        if let Some(target) = &self.target {
            let _ = nix::mount::umount2(target, nix::mount::MntFlags::MNT_DETACH);
        }
    }
}

fn relay(mut connection: UnixStream, id: u64, process: &ProcessRecord) -> Result<u32> {
    let mut input = connection.try_clone()?;
    let path = process.stdin.clone();
    thread::spawn(move || {
        if !path.is_empty()
            && let Ok(mut source) = File::open(path)
        {
            let mut bytes = vec![0; protocol::STREAM_CHUNK_BYTES];
            while let Ok(length) = source.read(&mut bytes) {
                if length == 0 {
                    break;
                }
                if protocol::send(
                    &mut input,
                    &Message::Data {
                        id,
                        stream: Stream::Stdin,
                        data: bytes[..length].to_vec(),
                    },
                )
                .is_err()
                {
                    break;
                }
            }
        }
        let _ = protocol::send(
            &mut input,
            &Message::Close {
                id,
                stream: Stream::Stdin,
            },
        );
    });
    let mut stdout = output(&process.stdout)?;
    let mut stderr = output(&process.stderr)?;
    loop {
        match protocol::receive(&mut connection)? {
            Message::Data {
                stream: Stream::Stdout,
                data,
                ..
            } => stdout.write_all(&data)?,
            Message::Data {
                stream: Stream::Stderr,
                data,
                ..
            } => stderr.write_all(&data)?,
            Message::Exited { code, .. } => return Ok(code as u32),
            Message::Error { detail } => bail!("{detail}"),
            _ => {}
        }
    }
}
fn output(path: &str) -> Result<File> {
    Ok(OpenOptions::new()
        .write(true)
        .open(if path.is_empty() { "/dev/null" } else { path })?)
}
fn error(detail: &str) -> ttrpc::Error {
    ttrpc::Error::RpcStatus(ttrpc::get_status(Code::FAILED_PRECONDITION, detail))
}
fn unsupported(operation: &str) -> ttrpc::Error {
    ttrpc::Error::RpcStatus(ttrpc::get_status(
        Code::UNIMPLEMENTED,
        format!("{operation}: ENOTSUP"),
    ))
}
fn convert<T>(result: Result<T>) -> TtrpcResult<T> {
    result.map_err(|failure| error(&format!("{failure:#}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECOVERY_RECORD: &str = r#"{"state":{"ociVersion":"1.0.2","id":"c1","status":"running","pid":4242,"bundle":"/bundle","annotations":{}},"config":{"ociVersion":"1.0.2","root":{"path":"rootfs"},"process":{"args":["/bin/sh"],"cwd":"/"}}}"#;

    fn temp_root(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("kernelet-shim-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn service(root: &Path, id: &str) -> Service {
        Service::new_at(
            root.to_path_buf(),
            &Flags {
                id: id.into(),
                namespace: "test".into(),
                ..Default::default()
            },
        )
    }

    fn running_process() -> ProcessRecord {
        ProcessRecord {
            spec: None,
            stdin: String::new(),
            stdout: String::new(),
            stderr: String::new(),
            terminal: false,
            agent_id: Some(1),
            state: ProcessState::Running,
            exited_at: None,
        }
    }

    #[test]
    fn cleanup_without_observed_exit_reports_forced_termination() {
        let root = temp_root("delete");
        let directory = root.join("c1");
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("config.json"), RECOVERY_RECORD).unwrap();
        let shim_service = service(&root, "c1");
        let response = shim_service.cleanup().unwrap();
        assert_eq!(response.pid, 4242);
        assert_eq!(response.exit_status, 128 + libc::SIGKILL as u32);
        assert!(response.exited_at.as_ref().is_some());
        assert!(!directory.exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn cleanup_reports_the_persisted_exit() {
        let root = temp_root("delete-exit");
        let directory = root.join("c1");
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("config.json"), RECOVERY_RECORD).unwrap();
        let mut file = File::create(directory.join("exit.json")).unwrap();
        serde_json::to_writer(
            &mut file,
            &ExitRecord {
                code: 3,
                seconds: 5,
                nanos: 6,
            },
        )
        .unwrap();
        let shim_service = service(&root, "c1");
        let response = shim_service.cleanup().unwrap();
        assert_eq!(response.exit_status, 3);
        let time = response.exited_at.as_ref().unwrap();
        assert_eq!((time.seconds, time.nanos), (5, 6));
        assert!(!directory.exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn failing_poststart_hook_does_not_strand_exit_observation() {
        let root = temp_root("hook");
        let directory = root.join("c1");
        fs::create_dir_all(&directory).unwrap();
        let record = serde_json::json!({
            "state": {"ociVersion":"1.0.2","id":"c1","status":"running","pid":7,"bundle":"/bundle","annotations":{}},
            "config": {"ociVersion":"1.0.2","root":{"path":"rootfs"},"process":{"args":["/bin/sh"],"cwd":"/"},
                       "hooks":{"poststart":[{"path":"/bin/sh","args":["sh","-c","exit 3"]}]}}
        });
        fs::write(
            directory.join("config.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        let shim_service = service(&root, "c1");
        *shim_service.task.lock().unwrap() = Some(Task {
            id: "c1".into(),
            bundle: "/bundle".into(),
            processes: BTreeMap::from([(String::new(), running_process())]),
        });
        // The agent side of the relay reports an immediate guest exit.
        let (connection, mut peer) = UnixStream::pair().unwrap();
        thread::spawn(move || {
            protocol::send(&mut peer, &Message::Exited { id: 1, code: 9 }).unwrap();
        });
        // Start installs the observation before announcing; the announcement
        // then fails through the poststart hook.
        let failure = shim_service
            .finish_start(connection, 1, running_process(), "c1", "", &directory)
            .unwrap_err();
        assert!(
            format!("{failure:#}").contains("poststart hook failed"),
            "unexpected error: {failure:#}"
        );
        assert_exit_observed(&shim_service, &directory, 9);
        let _ = fs::remove_dir_all(&root);
    }

    fn assert_exit_observed(service: &Service, directory: &Path, expected: u32) {
        let service = service.clone();
        let (sender, receiver) = std::sync::mpsc::channel();
        thread::spawn(move || sender.send(service.wait_for_exit("")).unwrap());
        let (code, _) = receiver
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap()
            .unwrap();
        assert_eq!(code, expected);
        // Exit status becomes visible before the persistent record is written.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while !directory.join("exit.json").exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "exit record was not written"
            );
            thread::sleep(std::time::Duration::from_millis(10));
        }
        let exit: ExitRecord =
            serde_json::from_reader(File::open(directory.join("exit.json")).unwrap()).unwrap();
        assert_eq!(exit.code, expected);
    }

    #[test]
    fn failed_event_publication_does_not_strand_exit_observation() {
        let root = temp_root("event-failure");
        let directory = root.join("c1");
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("config.json"), RECOVERY_RECORD).unwrap();
        let shim_service = service(&root, "c1");
        *shim_service.task.lock().unwrap() = Some(Task {
            id: "c1".into(),
            bundle: "/bundle".into(),
            processes: BTreeMap::from([(String::new(), running_process())]),
        });
        // Exercise the actual publisher on a transport whose peer has closed.
        let socket_path = root.join("events.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        let publisher = RemotePublisher::new(socket_path.to_str().unwrap()).unwrap();
        let (peer, _) = listener.accept().unwrap();
        drop(peer);
        drop(listener);
        *shim_service.publisher.lock().unwrap() = Some(publisher);
        let (connection, mut peer) = UnixStream::pair().unwrap();
        thread::spawn(move || {
            protocol::send(&mut peer, &Message::Exited { id: 1, code: 7 }).unwrap();
        });
        shim_service
            .finish_start(connection, 1, running_process(), "c1", "", &directory)
            .unwrap_err();
        assert_exit_observed(&shim_service, &directory, 7);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn relay_streams_output_and_returns_the_exit_code() {
        let root = temp_root("relay");
        let stdout_path = root.join("out");
        // The shim only opens the consumer containerd created (a fifo or
        // file), so the test materializes it first.
        File::create(&stdout_path).unwrap();
        let process = ProcessRecord {
            stdout: stdout_path.to_str().unwrap().into(),
            ..running_process()
        };
        let (connection, mut peer) = UnixStream::pair().unwrap();
        thread::spawn(move || {
            protocol::send(
                &mut peer,
                &Message::Data {
                    id: 1,
                    stream: Stream::Stdout,
                    data: b"hello".to_vec(),
                },
            )
            .unwrap();
            protocol::send(&mut peer, &Message::Exited { id: 1, code: 7 }).unwrap();
        });
        let code = relay(connection, 1, &process).unwrap();
        assert_eq!(code, 7);
        assert_eq!(fs::read(&stdout_path).unwrap(), b"hello");
        let _ = fs::remove_dir_all(&root);
    }
}
