// SPDX-License-Identifier: MPL-2.0

//! Containerd shim v2 using the same in-process holder as the OCI CLI.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    net::Shutdown,
    os::{
        fd::{AsFd, AsRawFd},
        unix::{fs::OpenOptionsExt, net::UnixStream},
    },
    path::{Path, PathBuf},
    sync::{Arc, Condvar, Mutex, TryLockError},
    thread,
    time::{Duration, Instant},
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
use nix::poll::{PollFd, PollFlags, poll};

use crate::{
    config::Process,
    protocol::{self, Message, Request, Stream},
    runtime::{self, Control, Reply},
};

pub fn run() {
    shim::run::<Service>("io.containerd.kernelet.v2", None);
}

#[cfg(test)]
type SnapshotCallback = Box<dyn FnOnce() + Send>;

#[derive(Clone)]
struct Service {
    root: PathBuf,
    id: String,
    namespace: String,
    exit: Arc<ExitSignal>,
    publisher: Arc<Mutex<Option<RemotePublisher>>>,
    task: Arc<Mutex<Option<Task>>>,
    changed: Arc<Condvar>,
    #[cfg(test)]
    snapshot_hook: Arc<Mutex<Option<SnapshotCallback>>>,
}
struct Task {
    id: String,
    bundle: String,
    // Keep records and the state directory owned while cleanup runs without
    // the task mutex. State and Wait remain callable by external hooks.
    deleting: BTreeSet<String>,
    processes: BTreeMap<String, ProcessRecord>,
}
#[derive(Clone)]
struct ProcessRecord {
    // Cloned snapshots retain this identity even if an exec ID is reused.
    identity: Arc<()>,
    // Distinguish confirmed-rejection retries within the same OCI record.
    start_generation: u64,
    spec: Option<Process>,
    stdin: String,
    stdout: String,
    stderr: String,
    terminal: bool,
    agent_id: Option<u64>,
    state: ProcessState,
    exited_at: Option<Timestamp>,
    // Prevent Delete/exec-ID reuse until the old exit event is acknowledged.
    exit_pending: bool,
    exit_error: Option<String>,
}
#[derive(Clone, Copy)]
enum ProcessState {
    Created,
    Starting,
    Stopping,
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
            #[cfg(test)]
            snapshot_hook: Arc::new(Mutex::new(None)),
        }
    }

    fn cleanup(&self) -> Result<DeleteResponse> {
        let directory = self.root.join(&self.id);
        let state = runtime::state(&directory)?;
        let exit = match File::open(directory.join("exit.json")) {
            Ok(file) => Some(serde_json::from_reader::<_, ExitRecord>(file)?),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
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
    fn process(&self, id: &str, exec_id: &str) -> Result<(PathBuf, ProcessRecord)> {
        let task = self.task.lock().unwrap();
        let task = task.as_ref().context("sandbox has not been created")?;
        ensure!(task.id == id, "unknown sandbox");
        let process = task
            .processes
            .get(exec_id)
            .cloned()
            .context("unknown process")?;
        Ok((self.root.join(id), process))
    }
    /// Restores the created state after a start attempt failed before the
    /// holder acknowledged any guest process.
    fn reset(&self, id: &str, exec_id: &str, expected: &ProcessRecord) {
        if let Some(task) = self.task.lock().unwrap().as_mut()
            && task.id == id
            && let Some(process) = task.processes.get_mut(exec_id)
            && Arc::ptr_eq(&process.identity, &expected.identity)
            && process.start_generation == expected.start_generation
            && matches!(process.state, ProcessState::Starting)
        {
            process.state = ProcessState::Created;
            process.agent_id = None;
            process.exit_error = None;
            self.changed.notify_all();
        }
    }
    fn launch_process(
        &self,
        req: &api::StartRequest,
        acknowledgement_timeout: Duration,
    ) -> Result<()> {
        let (directory, process) = {
            let mut task = self.task.lock().unwrap();
            let task = task.as_mut().context("sandbox has not been created")?;
            ensure!(task.id == req.id, "unknown sandbox");
            ensure!(!task.deleting.contains(""), "sandbox deletion in progress");
            let process = task
                .processes
                .get_mut(&req.exec_id)
                .context("unknown process")?;
            ensure!(
                matches!(process.state, ProcessState::Created),
                "process has already started"
            );
            process.start_generation = process
                .start_generation
                .checked_add(1)
                .context("start generation exhausted")?;
            process.state = ProcessState::Starting;
            (self.root.join(&req.id), process.clone())
        };
        // Reserve the identity before issuing Start. An uncertain transport
        // result never permits a second guest process to reuse this record.
        let agent_id = if process.spec.is_some() {
            match runtime::request(&directory, &Control::ReserveProcess) {
                Ok((Reply::Reserved { id }, _)) => id,
                Ok(_) => {
                    self.reset(&req.id, &req.exec_id, &process);
                    bail!("invalid reservation reply");
                }
                Err(error) => {
                    self.reset(&req.id, &req.exec_id, &process);
                    return Err(error);
                }
            }
        } else {
            1
        };
        {
            let mut slot = self.task.lock().unwrap();
            let current = slot
                .as_mut()
                .context("sandbox deleted during reservation")?
                .processes
                .get_mut(&req.exec_id)
                .context("process deleted during reservation")?;
            ensure!(
                Arc::ptr_eq(&current.identity, &process.identity)
                    && current.start_generation == process.start_generation,
                "process changed during reservation"
            );
            current.agent_id = Some(agent_id);
        }
        let service = self.clone();
        let id = req.id.clone();
        let exec_id = req.exec_id.clone();
        let (completion, result) = std::sync::mpsc::sync_channel(1);
        thread::spawn(move || {
            let outcome = (|| -> Result<()> {
                let operation = Control::Launch {
                    id: agent_id,
                    process: process.spec.clone(),
                };
                let (reply, connection) = runtime::request_launch(&directory, &operation)?;
                match reply {
                    Reply::StartRejected(detail) => {
                        service.reset(&id, &exec_id, &process);
                        service.changed.notify_all();
                        bail!("{detail}");
                    }
                    Reply::Started { id: acknowledged } if acknowledged == agent_id => {}
                    _ => bail!("invalid holder start reply"),
                }
                service.finish_start(
                    connection,
                    agent_id,
                    process.clone(),
                    &id,
                    &exec_id,
                    &directory,
                )
            })();
            if let Err(error) = &outcome {
                let mut slot = service.task.lock().unwrap();
                if let Some(current) = slot
                    .as_mut()
                    .filter(|task| task.id == id)
                    .and_then(|task| task.processes.get_mut(&exec_id))
                    && Arc::ptr_eq(&current.identity, &process.identity)
                    && current.start_generation == process.start_generation
                    && matches!(current.state, ProcessState::Starting)
                {
                    current.exit_error = Some(format!("start outcome is uncertain: {error:#}"));
                }
                service.changed.notify_all();
            }
            let _ = completion.send(outcome);
        });
        // The observer retains the operation and attachment after this RPC
        // times out; a late acknowledgement still installs relay and Wait.
        result
            .recv_timeout(acknowledgement_timeout)
            .context("start acknowledgement pending; operation remains Starting")??;
        Ok(())
    }

    fn signal_process(&self, id: &str, exec_id: &str, signal: i32, deliver: bool) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let (process, local_exit) = {
            let mut slot = self.task.lock().unwrap();
            let start_generation = slot
                .as_ref()
                .context("sandbox deleted")?
                .processes
                .get(exec_id)
                .context("unknown process")?
                .start_generation;
            let identity = slot
                .as_ref()
                .context("sandbox deleted")?
                .processes
                .get(exec_id)
                .context("unknown process")?
                .identity
                .clone();
            loop {
                let task = slot.as_mut().context("sandbox deleted")?;
                ensure!(task.id == id, "unknown sandbox");
                let process = task.processes.get_mut(exec_id).context("unknown process")?;
                ensure!(
                    Arc::ptr_eq(&process.identity, &identity)
                        && process.start_generation == start_generation,
                    "process changed while waiting for start"
                );
                if !matches!(
                    process.state,
                    ProcessState::Starting | ProcessState::Stopping
                ) {
                    if matches!(process.state, ProcessState::Created)
                        && !exec_id.is_empty()
                        && signal != 0
                    {
                        let exited_at = shim::util::timestamp().ok();
                        process.state = ProcessState::Exited((128 + signal) as u32);
                        process.exited_at = exited_at.clone();
                        process.exit_pending = true;
                        break (process.clone(), Some(exited_at));
                    }
                    if matches!(process.state, ProcessState::Created)
                        && exec_id.is_empty()
                        && signal != 0
                    {
                        let before = process.clone();
                        // Own created-init cancellation before dropping the lock,
                        // so Start cannot begin while Host revocation is pending.
                        process.state = ProcessState::Stopping;
                        break (before, None);
                    }
                    break (process.clone(), None);
                }
                if let Some(detail) = &process.exit_error {
                    bail!("{detail}");
                }
                ensure!(Instant::now() < deadline, "process start is still pending");
                slot = self
                    .changed
                    .wait_timeout(slot, deadline.saturating_duration_since(Instant::now()))
                    .unwrap()
                    .0;
            }
        };
        if let Some(exited_at) = local_exit {
            self.report_exit(id, exec_id, &process, (128 + signal) as u32, exited_at);
            return Ok(());
        }
        match process.state {
            ProcessState::Exited(_) => {
                if signal == 0 {
                    bail!("process has exited");
                }
                return Ok(());
            }
            ProcessState::Created if signal == 0 => return Ok(()),
            _ => {}
        }
        if matches!(process.state, ProcessState::Running) && !deliver {
            return Ok(());
        }
        let agent_id = if exec_id.is_empty() {
            1
        } else {
            process
                .agent_id
                .context("exec has no acknowledged process identity")?
        };
        if let Err(error) = runtime::request(
            &self.root.join(id),
            &Control::Signal {
                id: agent_id,
                signal,
            },
        ) {
            if matches!(process.state, ProcessState::Created) {
                let mut slot = self.task.lock().unwrap();
                if let Some(current) = slot
                    .as_mut()
                    .filter(|task| task.id == id)
                    .and_then(|task| task.processes.get_mut(exec_id))
                    && Arc::ptr_eq(&current.identity, &process.identity)
                {
                    current.exit_error =
                        Some(format!("created init termination is uncertain: {error:#}"));
                    self.changed.notify_all();
                }
            }
            return Err(error);
        }
        if matches!(process.state, ProcessState::Created) && signal != 0 {
            self.exited(id, exec_id, &process, (128 + signal) as u32);
        }
        Ok(())
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
    fn exited(&self, id: &str, exec_id: &str, expected: &ProcessRecord, code: u32) {
        let exited_at = shim::util::timestamp().ok();
        {
            let mut slot = self.task.lock().unwrap();
            let Some(task) = slot.as_mut().filter(|task| task.id == id) else {
                return;
            };
            let Some(process) = task.processes.get_mut(exec_id) else {
                return;
            };
            if !Arc::ptr_eq(&process.identity, &expected.identity)
                || process.start_generation != expected.start_generation
            {
                return;
            }
            if matches!(process.state, ProcessState::Exited(_)) {
                return;
            }
            process.state = ProcessState::Exited(code);
            process.exited_at = exited_at.clone();
            process.exit_pending = true;
        }
        self.report_exit(id, exec_id, expected, code, exited_at);
    }

    fn report_exit(
        &self,
        id: &str,
        exec_id: &str,
        expected: &ProcessRecord,
        code: u32,
        exited_at: Option<Timestamp>,
    ) {
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
        // Publishing can block or call another RPC. Keep the task mutex free,
        // while the record itself retains ownership of this event identity.
        let result = self.publish("/tasks/exit", event);
        let mut slot = self.task.lock().unwrap();
        if let Some(process) = slot
            .as_mut()
            .filter(|task| task.id == id)
            .and_then(|task| task.processes.get_mut(exec_id))
            .filter(|process| {
                Arc::ptr_eq(&process.identity, &expected.identity)
                    && process.start_generation == expected.start_generation
            })
        {
            match result {
                Ok(()) => process.exit_pending = false,
                Err(error) => {
                    process.exit_error = Some(format!("exit event publication failed: {error:#}"))
                }
            }
        }
        drop(slot);
        self.changed.notify_all();
    }

    /// Spawns the detached thread that turns a completed relay into exit
    /// bookkeeping. The thread's lifetime is independent of Start: once
    /// spawned, no later failure can prevent the exit notification.
    #[cfg(test)]
    fn observe_exit(
        &self,
        connection: UnixStream,
        agent_id: u64,
        process: ProcessRecord,
        id: String,
        exec_id: String,
    ) {
        self.observe_exit_after(connection, agent_id, process, id, exec_id, None);
    }

    fn observe_exit_after(
        &self,
        connection: UnixStream,
        agent_id: u64,
        process: ProcessRecord,
        id: String,
        exec_id: String,
        announcement: Option<Arc<(Mutex<bool>, Condvar)>>,
    ) {
        let service = self.clone();
        thread::spawn(move || {
            let code = match relay(connection, agent_id, &process) {
                Ok(code) => Some(code),
                Err(relay_error) => {
                    eprintln!("kernelet relay for {id}/{exec_id}: {relay_error:#}");
                    match service.query_exit(&id, &exec_id, &process, agent_id) {
                        Ok(code) => code,
                        Err(error) => {
                            let detail = format!(
                                "relay failed: {relay_error:#}; query exit status: {error:#}"
                            );
                            let mut task = service.task.lock().unwrap();
                            if let Some(task) = task.as_mut().filter(|task| task.id == id)
                                && let Some(current) = task.processes.get_mut(&exec_id)
                                && Arc::ptr_eq(&current.identity, &process.identity)
                                && !matches!(current.state, ProcessState::Exited(_))
                            {
                                current.exit_error = Some(detail);
                            }
                            service.changed.notify_all();
                            None
                        }
                    }
                }
            };
            if let Some(gate) = announcement {
                let (lock, changed) = &*gate;
                let mut announced = lock.lock().unwrap();
                while !*announced {
                    announced = changed.wait(announced).unwrap();
                }
            }
            if let Some(code) = code {
                service.exited(&id, &exec_id, &process, code);
            }
        });
    }

    fn query_exit(
        &self,
        id: &str,
        exec_id: &str,
        expected: &ProcessRecord,
        agent_id: u64,
    ) -> Result<Option<u32>> {
        let directory = self.root.join(id);
        loop {
            {
                let task = self.task.lock().unwrap();
                let Some(task) = task.as_ref().filter(|task| task.id == id) else {
                    return Ok(None);
                };
                let Some(current) = task.processes.get(exec_id) else {
                    return Ok(None);
                };
                if !Arc::ptr_eq(&current.identity, &expected.identity)
                    || current.start_generation != expected.start_generation
                {
                    return Ok(None);
                }
            }
            let (reply, _) = runtime::request(&directory, &Control::ExitStatus { id: agent_id })?;
            match reply {
                Reply::ExitStatus { code: Some(code) } => return Ok(Some(code as u32)),
                Reply::ExitStatus { code: None } => thread::sleep(Duration::from_millis(25)),
                _ => bail!("invalid holder exit-status reply"),
            }
        }
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
            let task = task.as_mut().context("sandbox deleted during start")?;
            ensure!(task.id == id, "sandbox changed during start");
            let current = task
                .processes
                .get_mut(exec_id)
                .context("process deleted during start")?;
            ensure!(
                Arc::ptr_eq(&current.identity, &process.identity)
                    && current.start_generation == process.start_generation
                    && matches!(current.state, ProcessState::Starting),
                "process changed during start"
            );
            current.agent_id = Some(agent_id);
            current.state = ProcessState::Running;
        }
        self.changed.notify_all();
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        self.observe_exit_after(
            connection,
            agent_id,
            process,
            id.into(),
            exec_id.into(),
            Some(gate.clone()),
        );
        let result = self.announce_start(id, exec_id, directory);
        // Failed hooks/publication must release an already observed exit too.
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        result
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
    fn wait_for_exit(&self, id: &str, exec_id: &str) -> Result<(u32, Option<Timestamp>)> {
        let mut task = self.task.lock().unwrap();
        let identity = {
            let task = task.as_ref().context("sandbox deleted")?;
            ensure!(task.id == id, "unknown sandbox");
            task.processes
                .get(exec_id)
                .context("unknown process")?
                .identity
                .clone()
        };
        loop {
            let current = task.as_ref().context("sandbox deleted")?;
            ensure!(current.id == id, "sandbox changed while waiting");
            let process = current.processes.get(exec_id).context("unknown process")?;
            ensure!(
                Arc::ptr_eq(&process.identity, &identity),
                "process changed while waiting"
            );
            if let ProcessState::Exited(code) = process.state {
                return Ok((code, process.exited_at.clone()));
            }
            if let Some(error) = &process.exit_error {
                bail!("observe process exit: {error}");
            }
            task = self.changed.wait(task).unwrap();
        }
    }

    #[cfg(test)]
    fn after_snapshot(&self) {
        let hook = self.snapshot_hook.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
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
                identity: Arc::new(()),
                start_generation: 0,
                spec: None,
                stdin: req.stdin.clone(),
                stdout: req.stdout.clone(),
                stderr: req.stderr.clone(),
                terminal: req.terminal,
                agent_id: None,
                state: ProcessState::Created,
                exited_at: None,
                exit_pending: false,
                exit_error: None,
            };
            *slot = Some(Task {
                id: req.id.clone(),
                bundle: req.bundle.clone(),
                deleting: BTreeSet::new(),
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
        convert(
            self.launch_process(&req, Duration::from_secs(30))
                .map(|()| api::StartResponse {
                    pid: std::process::id(),
                    ..Default::default()
                }),
        )
    }
    fn exec(&self, _: &TtrpcContext, req: api::ExecProcessRequest) -> TtrpcResult<api::Empty> {
        convert((|| {
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
            #[cfg(test)]
            self.after_snapshot();
            let mut slot = self.task.lock().unwrap();
            let task = slot.as_mut().context("sandbox has not been created")?;
            ensure!(task.id == req.id, "unknown sandbox");
            ensure!(!task.deleting.contains(""), "sandbox deletion in progress");
            let processes = &mut task.processes;
            ensure!(processes.len() < 256, "too many live exec records");
            ensure!(
                !processes.contains_key(&req.exec_id),
                "exec ID already exists"
            );
            processes.insert(
                req.exec_id.clone(),
                ProcessRecord {
                    identity: Arc::new(()),
                    start_generation: 0,
                    spec: Some(spec),
                    stdin: req.stdin,
                    stdout: req.stdout,
                    stderr: req.stderr,
                    terminal: req.terminal,
                    agent_id: None,
                    state: ProcessState::Created,
                    exited_at: None,
                    exit_pending: false,
                    exit_error: None,
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
            let response = {
                let task = self.task.lock().unwrap();
                let task = task.as_ref().context("sandbox has not been created")?;
                ensure!(task.id == req.id, "unknown sandbox");
                let process = task
                    .processes
                    .get(&req.exec_id)
                    .context("unknown process")?;
                let (status, code) = match process.state {
                    ProcessState::Created | ProcessState::Starting | ProcessState::Stopping => {
                        (api::Status::CREATED, 0)
                    }
                    ProcessState::Running => (api::Status::RUNNING, 0),
                    ProcessState::Exited(code) => (api::Status::STOPPED, code),
                };
                api::StateResponse {
                    id: req.id,
                    bundle: task.bundle.clone(),
                    pid: std::process::id(),
                    status: status.into(),
                    stdin: process.stdin.clone(),
                    stdout: process.stdout.clone(),
                    stderr: process.stderr.clone(),
                    terminal: process.terminal,
                    exit_status: code,
                    exited_at: process.exited_at.clone().into(),
                    exec_id: req.exec_id,
                    ..Default::default()
                }
            };
            #[cfg(test)]
            self.after_snapshot();
            Ok(response)
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
            let signal: i32 = req.signal.try_into()?;
            runtime::validate_signal(signal)?;
            let targets = {
                let slot = self.task.lock().unwrap();
                let task = slot.as_ref().context("sandbox has not been created")?;
                ensure!(task.id == req.id, "unknown sandbox");
                ensure!(task.processes.contains_key(&req.exec_id), "unknown process");
                if req.all {
                    task.processes.keys().cloned().collect::<Vec<_>>()
                } else {
                    vec![req.exec_id.clone()]
                }
            };
            let mut errors = Vec::new();
            for exec_id in targets {
                if let Err(error) = self.signal_process(&req.id, &exec_id, signal, !req.all) {
                    errors.push(format!("{exec_id}: {error:#}"));
                }
            }
            if req.all {
                // Detached descendants can outlive every managed process.
                // Once any launch was acknowledged, broadcast in the Guest even
                // when all recorded launchers have already exited.
                let any_started = self.task.lock().unwrap().as_ref().is_some_and(|task| {
                    task.processes
                        .values()
                        .any(|process| process.agent_id.is_some())
                });
                if any_started
                    && let Err(error) =
                        runtime::request(&self.root.join(&req.id), &Control::SignalAll { signal })
                {
                    errors.push(format!("all Guest processes: {error:#}"));
                }
            }
            ensure!(
                errors.is_empty(),
                "signal delivery failed: {}",
                errors.join("; ")
            );
            Ok(api::Empty::default())
        })())
    }
    fn resize_pty(&self, _: &TtrpcContext, req: api::ResizePtyRequest) -> TtrpcResult<api::Empty> {
        convert((|| {
            let (directory, process) = self.process(&req.id, &req.exec_id)?;
            let id = process.agent_id.context("process has not started")?;
            runtime::request(
                &directory,
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
                let (directory, process) = self.process(&req.id, &req.exec_id)?;
                let id = process.agent_id.context("process has not started")?;
                runtime::request(&directory, &Control::CloseInput { id })?;
            }
            Ok(api::Empty::default())
        })())
    }
    fn wait(&self, _: &TtrpcContext, req: api::WaitRequest) -> TtrpcResult<api::WaitResponse> {
        convert((|| {
            let (code, exited_at) = self.wait_for_exit(&req.id, &req.exec_id)?;
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
            let (process, code) = {
                let mut slot = self.task.lock().unwrap();
                let current = slot.as_mut().context("sandbox has not been created")?;
                ensure!(current.id == req.id, "unknown sandbox");
                ensure!(
                    !current.deleting.contains("")
                        && !current.deleting.contains(&req.exec_id)
                        && (!req.exec_id.is_empty() || current.deleting.is_empty()),
                    "process deletion in progress"
                );
                let process = current
                    .processes
                    .get(&req.exec_id)
                    .cloned()
                    .context("unknown process")?;
                let ProcessState::Exited(code) = process.state else {
                    bail!("process must be stopped before deletion");
                };
                ensure!(
                    !process.exit_pending
                        && (!req.exec_id.is_empty()
                            || current
                                .processes
                                .values()
                                .all(|record| !record.exit_pending)),
                    "exit event publication is pending; process ID cannot be reused"
                );
                current.deleting.insert(req.exec_id.clone());
                (process, code)
            };
            let directory = self.root.join(&req.id);
            // The marked record prevents reuse; no task mutex is held during
            // holder I/O or hooks that may call back through State and Wait.
            let cleanup = (|| -> Result<()> {
                if req.exec_id.is_empty() {
                    runtime::request(&directory, &Control::Delete { force: false })?;
                    runtime::run_hooks(&directory, "poststop")?;
                    fs::remove_dir_all(directory)?;
                } else if let Some(id) = process.agent_id {
                    let (reply, _) = runtime::request(&directory, &Control::ForgetExited { id })?;
                    ensure!(matches!(reply, Reply::Done), "invalid holder forget reply");
                }
                Ok(())
            })();
            if let Err(failure) = cleanup {
                let mut slot = self.task.lock().unwrap();
                if let Some(current) = slot.as_mut().filter(|task| task.id == req.id) {
                    current.deleting.remove(&req.exec_id);
                }
                self.changed.notify_all();
                return Err(failure);
            }
            // Cleanup succeeded, but this identity remains reserved until its
            // TaskDelete event is acknowledged. No task lock crosses the RPC.
            let mut response = DeleteResponse::new();
            response.set_pid(std::process::id());
            response.set_exit_status(code);
            if let Some(time) = process.exited_at {
                response.set_exited_at(time);
            }
            let mut event = task::TaskDelete::new();
            event.set_container_id(req.id.clone());
            event.set_id(req.exec_id.clone());
            event.set_pid(response.pid);
            event.set_exit_status(response.exit_status);
            if let Some(time) = response.exited_at.as_ref() {
                event.set_exited_at(time.clone());
            }
            let published = self.publish("/tasks/delete", event);
            let mut slot = self.task.lock().unwrap();
            let current = slot.as_mut().context("sandbox changed during deletion")?;
            ensure!(
                current.id == req.id
                    && current
                        .processes
                        .get(&req.exec_id)
                        .is_some_and(|record| { Arc::ptr_eq(&record.identity, &process.identity) }),
                "process changed during deletion"
            );
            match published {
                Ok(()) => {
                    current.deleting.remove(&req.exec_id);
                    if req.exec_id.is_empty() {
                        *slot = None;
                    } else {
                        current.processes.remove(&req.exec_id);
                    }
                }
                Err(failure) => {
                    current.processes.get_mut(&req.exec_id).unwrap().exit_error =
                        Some(format!("delete event publication failed: {failure:#}"));
                    return Err(failure);
                }
            }
            drop(slot);
            self.changed.notify_all();
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
    let writer = Arc::new(RelayWriter {
        connection: connection.try_clone()?,
        serial: Mutex::new(()),
        failure: Mutex::new(None),
    });
    let input_credit = Arc::new(RelayInput::default());
    let input = writer.clone();
    let credit = input_credit.clone();
    let path = process.stdin.clone();
    let input_worker = thread::spawn(move || {
        if !path.is_empty()
            && let Ok(mut source) = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(path)
        {
            let mut bytes = vec![0; protocol::STREAM_CHUNK_BYTES];
            while credit.wait_credit() {
                let length = loop {
                    if credit.stopped() {
                        return;
                    }
                    let mut descriptors = [PollFd::new(
                        source.as_fd(),
                        PollFlags::POLLIN | PollFlags::POLLHUP,
                    )];
                    match poll(&mut descriptors, OUTPUT_POLL_INTERVAL) {
                        Ok(0) | Err(nix::errno::Errno::EINTR) => continue,
                        Ok(_) => {}
                        Err(error) => {
                            eprintln!("kernelet {id} stdin poll: {error}");
                            return;
                        }
                    }
                    match source.read(&mut bytes) {
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                            ) =>
                        {
                            continue;
                        }
                        result => break result,
                    }
                };
                let length = match length {
                    Ok(length) => length,
                    Err(error) => {
                        eprintln!("kernelet {id} stdin: {error}");
                        break;
                    }
                };
                if length == 0 {
                    break;
                }
                if let Err(error) = send_relay(
                    &input,
                    &Message::Data {
                        id,
                        stream: Stream::Stdin,
                        data: bytes[..length].to_vec(),
                    },
                ) {
                    eprintln!("kernelet {id} stdin forwarding: {error}");
                    break;
                }
            }
        }
        if !credit.stopped() {
            let _ = send_relay(
                &input,
                &Message::Close {
                    id,
                    stream: Stream::Stdin,
                },
            );
        }
    });
    let mut stdout = RelayOutput::new(process.stdout.clone(), id, Stream::Stdout, writer.clone());
    let mut stderr = RelayOutput::new(process.stderr.clone(), id, Stream::Stderr, writer.clone());
    let result = (|| loop {
        match protocol::receive(&mut connection)? {
            Message::InputReady { id: process_id } if process_id == id => input_credit.ready(),
            Message::RequestFailed {
                request:
                    Request::Data { id: process_id }
                    | Request::Close { id: process_id }
                    | Request::CloseInput { id: process_id, .. },
                detail,
            } if process_id == id => {
                eprintln!("kernelet {id} stdin: {detail}");
                input_credit.stop();
            }
            Message::Data {
                id: process_id,
                stream: Stream::Stdout,
                data,
            } if process_id == id => {
                ensure!(
                    data.len() <= protocol::STREAM_CHUNK_BYTES,
                    "oversized output chunk"
                );
                stdout.push(data);
            }
            Message::Data {
                id: process_id,
                stream: Stream::Stderr,
                data,
            } if process_id == id => {
                ensure!(
                    data.len() <= protocol::STREAM_CHUNK_BYTES,
                    "oversized output chunk"
                );
                stderr.push(data);
            }
            Message::OutputFailed {
                id: process_id,
                stream,
                detail,
            } if process_id == id => {
                eprintln!("kernelet {id} {stream:?}: {detail}");
                match stream {
                    Stream::Stdout => stdout.cancel(&detail, false),
                    Stream::Stderr => stderr.cancel(&detail, false),
                    Stream::Stdin => bail!("invalid output stream"),
                }
            }
            Message::Close {
                id: process_id,
                stream,
            } if process_id == id => match stream {
                Stream::Stdout => stdout.close(),
                Stream::Stderr => stderr.close(),
                Stream::Stdin => (),
            },
            Message::Exited {
                id: process_id,
                code,
            } if process_id == id => {
                return Ok(code as u32);
            }
            Message::Error { detail } => bail!("{detail}"),
            _ => {}
        }
    })();
    // Shutdown does not need the writer mutex. Wake a blocked frame or credit
    // wait before joining output workers that might report cancellation.
    input_credit.stop();
    let _ = writer.connection.shutdown(Shutdown::Both);
    let _ = input_worker.join();
    let deadline = if result.is_ok() {
        Instant::now() + OUTPUT_DRAIN_TIMEOUT
    } else {
        stdout.cancel("attachment closed before output drained", false);
        stderr.cancel("attachment closed before output drained", false);
        Instant::now()
    };
    stdout.finish(deadline);
    stderr.finish(deadline);
    result.map_err(|error: anyhow::Error| {
        if let Some(detail) = writer.failure.lock().unwrap().as_ref() {
            error.context(format!("attachment write failed: {detail}"))
        } else {
            error
        }
    })
}

const MAX_RELAY_OUTPUT_CHUNKS: usize = 8;
const OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
const OUTPUT_POLL_INTERVAL: u16 = 25;
const ATTACH_WRITE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Default)]
struct RelayInput {
    state: Mutex<RelayInputState>,
    changed: Condvar,
}

#[derive(Default)]
struct RelayInputState {
    credit: bool,
    stopped: bool,
}

impl RelayInput {
    fn ready(&self) {
        self.state.lock().unwrap().credit = true;
        self.changed.notify_all();
    }

    fn wait_credit(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        while !state.credit && !state.stopped {
            state = self.changed.wait(state).unwrap();
        }
        if state.stopped {
            return false;
        }
        state.credit = false;
        true
    }

    fn stop(&self) {
        self.state.lock().unwrap().stopped = true;
        self.changed.notify_all();
    }

    fn stopped(&self) -> bool {
        self.state.lock().unwrap().stopped
    }
}

#[derive(Default)]
struct RelayOutputState {
    queue: VecDeque<Vec<u8>>,
    closed: bool,
    cancelled: bool,
    deadline: Option<Instant>,
    error: Option<String>,
    report_failure: bool,
}

struct RelayOutput {
    state: Arc<(Mutex<RelayOutputState>, Condvar)>,
    worker: Option<thread::JoinHandle<()>>,
}

impl RelayOutput {
    fn new(path: String, id: u64, stream: Stream, writer: Arc<RelayWriter>) -> Self {
        let state = Arc::new((
            Mutex::new(RelayOutputState {
                report_failure: true,
                ..Default::default()
            }),
            Condvar::new(),
        ));
        let worker_state = state.clone();
        let worker = thread::spawn(move || {
            if let Err(error) = drain_output(&path, &worker_state) {
                let (lock, changed) = &*worker_state;
                let (detail, report) = {
                    let mut state = lock.lock().unwrap();
                    let detail = state
                        .error
                        .get_or_insert_with(|| format!("{error:#}"))
                        .clone();
                    state.cancelled = true;
                    state.queue.clear();
                    (detail, state.report_failure)
                };
                changed.notify_all();
                if report {
                    eprintln!("kernelet {id} {stream:?}: {detail}");
                    if let Err(error) =
                        send_relay(&writer, &Message::OutputFailed { id, stream, detail })
                    {
                        eprintln!("kernelet {id} {stream:?} output cancellation: {error}");
                    }
                }
            }
        });
        Self {
            state,
            worker: Some(worker),
        }
    }

    fn push(&self, data: Vec<u8>) {
        let (lock, changed) = &*self.state;
        let mut state = lock.lock().unwrap();
        // Give a healthy writer time to catch up with a burst. A stopped sink
        // cannot hold message reception indefinitely through a full queue.
        let deadline = Instant::now() + OUTPUT_DRAIN_TIMEOUT;
        while state.queue.len() >= MAX_RELAY_OUTPUT_CHUNKS && !state.cancelled {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                state.cancelled = true;
                state.error = Some("output queue remained full for one second".into());
                state.queue.clear();
                changed.notify_all();
                return;
            }
            state = changed.wait_timeout(state, remaining).unwrap().0;
        }
        if !state.cancelled && !state.closed {
            state.queue.push_back(data);
            changed.notify_all();
        }
    }

    fn close(&self) {
        let (lock, changed) = &*self.state;
        lock.lock().unwrap().closed = true;
        changed.notify_all();
    }

    fn cancel(&self, detail: &str, report: bool) {
        let (lock, changed) = &*self.state;
        let mut state = lock.lock().unwrap();
        state.cancelled = true;
        state.error.get_or_insert_with(|| detail.into());
        state.report_failure = report;
        state.queue.clear();
        changed.notify_all();
    }

    fn finish(&mut self, deadline: Instant) {
        let (lock, changed) = &*self.state;
        {
            let mut state = lock.lock().unwrap();
            state.closed = true;
            state.deadline = Some(deadline);
        }
        changed.notify_all();
        if let Some(worker) = self.worker.take()
            && worker.join().is_err()
        {
            eprintln!("kernelet output worker panicked");
        }
    }
}

impl Drop for RelayOutput {
    fn drop(&mut self) {
        if self.worker.is_some() {
            self.cancel("attachment closed before output drained", true);
            self.finish(Instant::now());
        }
    }
}

fn output_deadline(state: &RelayOutputState, idle_deadline: Instant) -> Result<Instant> {
    ensure!(!state.cancelled, "output cancelled");
    let deadline = state
        .deadline
        .map_or(idle_deadline, |deadline| deadline.min(idle_deadline));
    ensure!(
        Instant::now() < deadline,
        "output sink did not drain before its deadline"
    );
    Ok(deadline)
}

fn drain_output(path: &str, shared: &(Mutex<RelayOutputState>, Condvar)) -> Result<()> {
    let (lock, changed) = shared;
    let open_deadline = Instant::now() + OUTPUT_DRAIN_TIMEOUT;
    let mut sink = loop {
        output_deadline(&lock.lock().unwrap(), open_deadline)?;
        match output(path) {
            Ok(sink) => break sink,
            Err(error) if error.raw_os_error() == Some(libc::ENXIO) => {
                let state = lock.lock().unwrap();
                drop(
                    changed
                        .wait_timeout(
                            state,
                            Duration::from_millis(u64::from(OUTPUT_POLL_INTERVAL)),
                        )
                        .unwrap(),
                );
            }
            Err(error) => return Err(error.into()),
        }
    };
    loop {
        let data = {
            let mut state = lock.lock().unwrap();
            while state.queue.is_empty() && !state.closed && !state.cancelled {
                state = changed.wait(state).unwrap();
            }
            ensure!(!state.cancelled, "output cancelled");
            let Some(data) = state.queue.pop_front() else {
                return Ok(());
            };
            changed.notify_all();
            data
        };
        let mut offset = 0;
        let mut idle_deadline = Instant::now() + OUTPUT_DRAIN_TIMEOUT;
        while offset < data.len() {
            let deadline = output_deadline(&lock.lock().unwrap(), idle_deadline)?;
            match sink.write(&data[offset..]) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
                Ok(length) => {
                    offset += length;
                    idle_deadline = Instant::now() + OUTPUT_DRAIN_TIMEOUT;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let mut descriptors = [PollFd::new(sink.as_fd(), PollFlags::POLLOUT)];
                    let timeout = deadline
                        .saturating_duration_since(Instant::now())
                        .as_millis()
                        .min(u128::from(OUTPUT_POLL_INTERVAL))
                        as u16;
                    match poll(&mut descriptors, timeout) {
                        Ok(_) | Err(nix::errno::Errno::EINTR) => (),
                        Err(error) => return Err(error.into()),
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}

fn output(path: &str) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(if path.is_empty() { "/dev/null" } else { path })
}

struct RelayWriter {
    connection: UnixStream,
    serial: Mutex<()>,
    failure: Mutex<Option<String>>,
}

impl RelayWriter {
    fn failed(&self, error: &io::Error) {
        self.failure
            .lock()
            .unwrap()
            .get_or_insert_with(|| error.to_string());
        // Stop a partial frame before another sender appends to it. This also
        // wakes the reader so it can query the independently cached exit.
        let _ = self.connection.shutdown(Shutdown::Both);
    }
}

struct RelayFrame<'a> {
    connection: &'a UnixStream,
    deadline: Instant,
}

impl Write for RelayFrame<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        loop {
            if Instant::now() >= self.deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "attachment frame stalled for two seconds",
                ));
            }
            // SAFETY: send borrows this live socket and the caller's byte slice.
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
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => {
                    let mut descriptors =
                        [PollFd::new(self.connection.as_fd(), PollFlags::POLLOUT)];
                    match poll(&mut descriptors, OUTPUT_POLL_INTERVAL) {
                        Ok(_) | Err(nix::errno::Errno::EINTR) => (),
                        Err(error) => return Err(error.into()),
                    }
                }
                _ => return Err(error),
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn send_relay(writer: &RelayWriter, message: &Message) -> io::Result<()> {
    let deadline = Instant::now() + ATTACH_WRITE_TIMEOUT;
    let serial = loop {
        match writer.serial.try_lock() {
            Ok(serial) => break serial,
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(u64::from(OUTPUT_POLL_INTERVAL)));
            }
            Err(error) => {
                let error = match error {
                    TryLockError::WouldBlock => io::Error::new(
                        io::ErrorKind::TimedOut,
                        "attachment writer busy for two seconds",
                    ),
                    TryLockError::Poisoned(_) => io::Error::other("attachment writer panicked"),
                };
                writer.failed(&error);
                return Err(error);
            }
        }
    };
    let result = protocol::send(
        &mut RelayFrame {
            connection: &writer.connection,
            deadline,
        },
        message,
    );
    if let Err(error) = &result {
        writer.failed(error);
    }
    drop(serial);
    result
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
    use shim::protos::shim_sync::{TaskClient, create_task};

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
            identity: Arc::new(()),
            start_generation: 0,
            spec: None,
            stdin: String::new(),
            stdout: String::new(),
            stderr: String::new(),
            terminal: false,
            agent_id: Some(1),
            state: ProcessState::Running,
            exited_at: None,
            exit_pending: false,
            exit_error: None,
        }
    }

    #[test]
    fn pending_exit_publication_blocks_delete_and_exec_id_reuse() {
        let root = temp_root("pending-exit-event");
        let service = service(&root, "c1");
        let process = ProcessRecord {
            agent_id: None,
            ..running_process()
        };
        *service.task.lock().unwrap() = Some(Task {
            id: "c1".into(),
            bundle: "/bundle".into(),
            deleting: BTreeSet::new(),
            processes: BTreeMap::from([
                (
                    String::new(),
                    ProcessRecord {
                        state: ProcessState::Exited(0),
                        agent_id: None,
                        ..running_process()
                    },
                ),
                ("e1".into(), process.clone()),
            ]),
        });
        let address = format!("unix://{}", root.join("shim.sock").display());
        let mut server = ttrpc::Server::new()
            .bind(&address)
            .unwrap()
            .register_service(create_task(Arc::new(service.clone())));
        server.start().unwrap();
        let client = TaskClient::new(ttrpc::Client::connect(&address).unwrap());
        let publisher = service.publisher.lock().unwrap();
        let observer = service.clone();
        let exited = thread::spawn(move || observer.exited("c1", "e1", &process, 17));
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if service.process("c1", "e1").unwrap().1.exit_pending {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "exit observer did not reach publisher"
            );
            thread::yield_now();
        }
        assert_eq!(
            client
                .wait(
                    ttrpc::context::with_timeout(3_000_000_000),
                    &api::WaitRequest {
                        id: "c1".into(),
                        exec_id: "e1".into(),
                        ..Default::default()
                    }
                )
                .unwrap()
                .exit_status,
            17
        );
        for exec_id in ["e1", ""] {
            assert!(
                client
                    .delete(
                        ttrpc::context::with_timeout(3_000_000_000),
                        &api::DeleteRequest {
                            id: "c1".into(),
                            exec_id: exec_id.into(),
                            ..Default::default()
                        }
                    )
                    .is_err()
            );
        }
        let request = api::ExecProcessRequest {
            id: "c1".into(),
            exec_id: "e1".into(),
            spec: Some(shim::protos::protobuf::well_known_types::any::Any {
                value: br#"{"args":["/bin/sh"],"cwd":"/"}"#.to_vec(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        assert!(
            client
                .exec(ttrpc::context::with_timeout(3_000_000_000), &request)
                .is_err()
        );
        drop(publisher);
        exited.join().unwrap();
        assert!(!service.process("c1", "e1").unwrap().1.exit_pending);
        let publisher = service.publisher.lock().unwrap();
        let deleting_client = TaskClient::new(ttrpc::Client::connect(&address).unwrap());
        let deleting = thread::spawn(move || {
            deleting_client.delete(
                ttrpc::context::with_timeout(3_000_000_000),
                &api::DeleteRequest {
                    id: "c1".into(),
                    exec_id: "e1".into(),
                    ..Default::default()
                },
            )
        });
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if service
                .task
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .deleting
                .contains("e1")
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "Delete did not reserve event identity"
            );
            thread::yield_now();
        }
        assert!(
            client
                .exec(ttrpc::context::with_timeout(3_000_000_000), &request)
                .is_err()
        );
        for exec_id in ["e1", ""] {
            assert!(
                client
                    .delete(
                        ttrpc::context::with_timeout(3_000_000_000),
                        &api::DeleteRequest {
                            id: "c1".into(),
                            exec_id: exec_id.into(),
                            ..Default::default()
                        },
                    )
                    .is_err()
            );
        }
        drop(publisher);
        deleting.join().unwrap().unwrap();
        client
            .exec(ttrpc::context::with_timeout(3_000_000_000), &request)
            .unwrap();
        server.shutdown();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_delete_publication_retains_the_identity_and_failure() {
        let root = temp_root("delete-event-failure");
        let service = service(&root, "c1");
        *service.task.lock().unwrap() = Some(Task {
            id: "c1".into(),
            bundle: "/bundle".into(),
            deleting: BTreeSet::new(),
            processes: BTreeMap::from([(
                "e1".into(),
                ProcessRecord {
                    state: ProcessState::Exited(17),
                    agent_id: None,
                    ..running_process()
                },
            )]),
        });
        let events = root.join("events.sock");
        let listener = std::os::unix::net::UnixListener::bind(&events).unwrap();
        let publisher = RemotePublisher::new(events.to_str().unwrap()).unwrap();
        let (peer, _) = listener.accept().unwrap();
        drop(peer);
        drop(listener);
        *service.publisher.lock().unwrap() = Some(publisher);
        let address = format!("unix://{}", root.join("shim.sock").display());
        let mut server = ttrpc::Server::new()
            .bind(&address)
            .unwrap()
            .register_service(create_task(Arc::new(service.clone())));
        server.start().unwrap();
        let client = TaskClient::new(ttrpc::Client::connect(&address).unwrap());
        let request = api::DeleteRequest {
            id: "c1".into(),
            exec_id: "e1".into(),
            ..Default::default()
        };
        assert!(
            client
                .delete(ttrpc::context::with_timeout(3_000_000_000), &request)
                .is_err()
        );
        let slot = service.task.lock().unwrap();
        let task = slot.as_ref().unwrap();
        assert!(task.deleting.contains("e1"));
        assert!(
            task.processes["e1"]
                .exit_error
                .as_ref()
                .unwrap()
                .contains("delete event publication failed")
        );
        drop(slot);
        assert!(
            client
                .delete(ttrpc::context::with_timeout(3_000_000_000), &request)
                .is_err()
        );
        server.shutdown();
        fs::remove_dir_all(root).unwrap();
    }

    // The test hook pauses the actual RPC at the former split-lock boundary.
    // Delete runs on another ttrpc worker and removes the sandbox first.
    fn delete_during_rpc<T: Send + 'static>(
        name: &str,
        invoke: impl FnOnce(TaskClient) -> TtrpcResult<T> + Send + 'static,
    ) -> TtrpcResult<T> {
        let root = temp_root(name);
        let directory = root.join("c1");
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("config.json"), RECOVERY_RECORD).unwrap();
        let shim_service = service(&root, "c1");
        *shim_service.task.lock().unwrap() = Some(Task {
            id: "c1".into(),
            bundle: "/bundle".into(),
            deleting: BTreeSet::new(),
            processes: BTreeMap::from([(
                String::new(),
                ProcessRecord {
                    state: ProcessState::Exited(17),
                    ..running_process()
                },
            )]),
        });
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        *shim_service.snapshot_hook.lock().unwrap() = Some(Box::new(move || {
            ready_tx.send(()).unwrap();
            resume_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        }));
        // Only the Host control boundary is replaced; State, Exec, and Delete
        // execute through the real Service and synchronous ttrpc worker pool.
        let listener =
            std::os::unix::net::UnixListener::bind(directory.join("control.sock")).unwrap();
        let holder = thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            drop(listener);
            assert!(matches!(
                protocol::receive_value::<Control>(&mut connection).unwrap(),
                Control::Delete { force: false }
            ));
            protocol::send_value(&mut connection, &Reply::Done).unwrap();
        });
        let address = format!("unix://{}", root.join("shim.sock").display());
        let mut server = ttrpc::Server::new()
            .bind(&address)
            .unwrap()
            .register_service(create_task(Arc::new(shim_service.clone())));
        server.start().unwrap();
        let client = TaskClient::new(ttrpc::Client::connect(&address).unwrap());
        let in_flight = thread::spawn(move || invoke(client));
        ready_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        let client = TaskClient::new(ttrpc::Client::connect(&address).unwrap());
        let deleted = client.delete(
            ttrpc::context::with_timeout(3_000_000_000),
            &api::DeleteRequest {
                id: "c1".into(),
                ..Default::default()
            },
        );
        resume_tx.send(()).unwrap();
        let result = in_flight.join().unwrap();
        server.shutdown();
        holder.join().unwrap();
        assert!(shim_service.task.lock().unwrap().is_none());
        fs::remove_dir_all(root).unwrap();
        assert_eq!(deleted.unwrap().exit_status, 17);
        result
    }

    #[test]
    fn state_returns_a_complete_snapshot_during_delete() {
        let response = delete_during_rpc("state-delete", |client| {
            client.state(
                ttrpc::context::with_timeout(3_000_000_000),
                &api::StateRequest {
                    id: "c1".into(),
                    ..Default::default()
                },
            )
        })
        .unwrap();
        assert_eq!(response.bundle, "/bundle");
        assert_eq!(response.status.enum_value().unwrap(), api::Status::STOPPED);
        assert_eq!(response.exit_status, 17);
    }

    #[test]
    fn exec_returns_an_error_when_the_sandbox_is_deleted() {
        let result = delete_during_rpc("exec-delete", |client| {
            client.exec(
                ttrpc::context::with_timeout(3_000_000_000),
                &api::ExecProcessRequest {
                    id: "c1".into(),
                    exec_id: "e1".into(),
                    spec: Some(shim::protos::protobuf::well_known_types::any::Any {
                        value: br#"{"args":["/bin/sh"],"cwd":"/"}"#.to_vec(),
                        ..Default::default()
                    })
                    .into(),
                    ..Default::default()
                },
            )
        });
        assert!(
            matches!(result, Err(ttrpc::Error::RpcStatus(status)) if status.code() == Code::FAILED_PRECONDITION && status.message.contains("sandbox has not been created"))
        );
    }

    #[test]
    fn delete_allows_a_poststop_hook_to_query_state_and_wait() {
        // Regression: Delete held the task mutex while a real poststop hook
        // called State through another synchronous ttrpc worker.
        let root = temp_root("poststop-callback");
        let directory = root.join("c1");
        fs::create_dir_all(&directory).unwrap();
        let address = format!("unix://{}", root.join("shim.sock").display());
        let marker = root.join("hook-observed");
        let executable = std::env::current_exe().unwrap();
        let mut record: serde_json::Value = serde_json::from_str(RECOVERY_RECORD).unwrap();
        record["config"]["hooks"] = serde_json::json!({
            "poststop": [{
                "path": executable,
                "args": [executable, "--ignored", "--exact",
                         "shim::tests::poststop_state_hook_fixture", "--nocapture"],
                "env": [format!("KERNELET_POSTSTOP_ADDRESS={address}"),
                        format!("KERNELET_POSTSTOP_MARKER={}", marker.display())],
                "timeout": 3
            }]
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
            deleting: BTreeSet::new(),
            processes: BTreeMap::from([(
                String::new(),
                ProcessRecord {
                    state: ProcessState::Exited(17),
                    ..running_process()
                },
            )]),
        });
        let listener =
            std::os::unix::net::UnixListener::bind(directory.join("control.sock")).unwrap();
        let holder = thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            drop(listener);
            assert!(matches!(
                protocol::receive_value::<Control>(&mut connection).unwrap(),
                Control::Delete { force: false }
            ));
            protocol::send_value(&mut connection, &Reply::Done).unwrap();
        });
        let mut server = ttrpc::Server::new()
            .bind(&address)
            .unwrap()
            .register_service(create_task(Arc::new(shim_service.clone())));
        server.start().unwrap();
        let client = TaskClient::new(ttrpc::Client::connect(&address).unwrap());
        let deleted = client.delete(
            ttrpc::context::with_timeout(5_000_000_000),
            &api::DeleteRequest {
                id: "c1".into(),
                ..Default::default()
            },
        );
        server.shutdown();
        holder.join().unwrap();
        let observed = fs::read(&marker);
        let removed = shim_service.task.lock().unwrap().is_none();
        fs::remove_dir_all(root).unwrap();
        assert_eq!(deleted.unwrap().exit_status, 17);
        assert_eq!(observed.unwrap(), b"state and wait observed");
        assert!(removed);
    }

    #[test]
    #[ignore = "subprocess fixture invoked by the real poststop hook runner"]
    fn poststop_state_hook_fixture() {
        let Some(address) = std::env::var_os("KERNELET_POSTSTOP_ADDRESS") else {
            return;
        };
        let state: serde_json::Value = serde_json::from_reader(io::stdin()).unwrap();
        assert_eq!(state["id"], "c1");
        assert_eq!(state["status"], "stopped");
        let client = TaskClient::new(ttrpc::Client::connect(address.to_str().unwrap()).unwrap());
        let request = api::StateRequest {
            id: "c1".into(),
            ..Default::default()
        };
        let state = client
            .state(ttrpc::context::with_timeout(500_000_000), &request)
            .unwrap();
        assert_eq!(state.status.enum_value().unwrap(), api::Status::STOPPED);
        assert_eq!(state.exit_status, 17);
        let waited = client
            .wait(
                ttrpc::context::with_timeout(500_000_000),
                &api::WaitRequest {
                    id: "c1".into(),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(waited.exit_status, 17);
        assert!(
            client
                .create(
                    ttrpc::context::with_timeout(500_000_000),
                    &api::CreateTaskRequest {
                        id: "c1".into(),
                        bundle: "/bundle".into(),
                        ..Default::default()
                    },
                )
                .is_err(),
            "the directory must stay owned throughout the poststop hook"
        );
        assert!(
            client
                .delete(
                    ttrpc::context::with_timeout(500_000_000),
                    &api::DeleteRequest {
                        id: "c1".into(),
                        ..Default::default()
                    },
                )
                .is_err(),
            "concurrent deletion must be rejected while the hook is running"
        );
        assert!(
            client
                .exec(
                    ttrpc::context::with_timeout(500_000_000),
                    &api::ExecProcessRequest {
                        id: "c1".into(),
                        exec_id: "during-delete".into(),
                        spec: Some(shim::protos::protobuf::well_known_types::any::Any {
                            value: br#"{"args":["/bin/sh"],"cwd":"/"}"#.to_vec(),
                            ..Default::default()
                        })
                        .into(),
                        ..Default::default()
                    },
                )
                .is_err(),
            "deletion must retain the task without accepting a new exec"
        );
        fs::write(
            std::env::var_os("KERNELET_POSTSTOP_MARKER").unwrap(),
            b"state and wait observed",
        )
        .unwrap();
    }

    #[test]
    fn old_callbacks_do_not_change_a_reused_exec_record() {
        let root = temp_root("reused-exec");
        let shim_service = service(&root, "c1");
        let old = ProcessRecord {
            state: ProcessState::Starting,
            ..running_process()
        };
        let current = running_process();
        *shim_service.task.lock().unwrap() = Some(Task {
            id: "c1".into(),
            bundle: "/bundle".into(),
            deleting: BTreeSet::new(),
            processes: BTreeMap::from([("e1".into(), current.clone())]),
        });
        let (connection, _) = UnixStream::pair().unwrap();
        assert!(
            shim_service
                .finish_start(connection, 7, old.clone(), "c1", "e1", &root.join("c1"))
                .is_err()
        );
        shim_service.reset("c1", "e1", &old);
        shim_service.exited("c1", "e1", &old, 9);
        let (_, observed) = shim_service.process("c1", "e1").unwrap();
        assert!(Arc::ptr_eq(&observed.identity, &current.identity));
        assert!(matches!(observed.state, ProcessState::Running));
        assert_eq!(observed.agent_id, Some(1));
        fs::remove_dir_all(root).unwrap();
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
                       "hooks":{"poststart":[{"path":"/bin/sh","args":["sh","-c","cat > /dev/null; exit 3"]}]}}
        });
        fs::write(
            directory.join("config.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        let shim_service = service(&root, "c1");
        let process = ProcessRecord {
            state: ProcessState::Starting,
            ..running_process()
        };
        *shim_service.task.lock().unwrap() = Some(Task {
            id: "c1".into(),
            bundle: "/bundle".into(),
            deleting: BTreeSet::new(),
            processes: BTreeMap::from([(String::new(), process.clone())]),
        });
        // The agent side of the relay reports an immediate guest exit.
        let (connection, mut peer) = UnixStream::pair().unwrap();
        thread::spawn(move || {
            protocol::send(&mut peer, &Message::Exited { id: 1, code: 9 }).unwrap();
        });
        // Start installs the observation before announcing; the announcement
        // then fails through the poststart hook.
        let failure = shim_service
            .finish_start(connection, 1, process, "c1", "", &directory)
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
        thread::spawn(move || sender.send(service.wait_for_exit("c1", "")).unwrap());
        let (code, _) = receiver
            .recv_timeout(Duration::from_secs(3))
            .unwrap()
            .unwrap();
        assert_eq!(code, expected);
        // Exit status becomes visible before the persistent record is written.
        let deadline = Instant::now() + Duration::from_secs(3);
        while !directory.join("exit.json").exists() {
            assert!(Instant::now() < deadline, "exit record was not written");
            thread::sleep(Duration::from_millis(10));
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
        let process = ProcessRecord {
            state: ProcessState::Starting,
            ..running_process()
        };
        *shim_service.task.lock().unwrap() = Some(Task {
            id: "c1".into(),
            bundle: "/bundle".into(),
            deleting: BTreeSet::new(),
            processes: BTreeMap::from([(String::new(), process.clone())]),
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
            .finish_start(connection, 1, process, "c1", "", &directory)
            .unwrap_err();
        assert_exit_observed(&shim_service, &directory, 7);
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let process = shim_service.process("c1", "").unwrap().1;
            if process
                .exit_error
                .as_ref()
                .is_some_and(|error| error.contains("exit event publication failed"))
            {
                assert!(process.exit_pending);
                break;
            }
            assert!(
                Instant::now() < deadline,
                "failed exit publication was not retained"
            );
            thread::yield_now();
        }

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

    #[test]
    fn relay_preserves_stdin_and_waits_for_each_input_credit() {
        let root = temp_root("stdin-credit");
        let stdin = root.join("in");
        let expected = vec![b'i'; protocol::STREAM_CHUNK_BYTES + 7];
        fs::write(&stdin, &expected).unwrap();
        let process = ProcessRecord {
            stdin: stdin.to_str().unwrap().into(),
            ..running_process()
        };
        let (connection, mut peer) = UnixStream::pair().unwrap();
        let relay_thread = thread::spawn(move || relay(connection, 1, &process));
        let mut received = Vec::new();
        for expected_length in [protocol::STREAM_CHUNK_BYTES, 7] {
            peer.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let waiting = protocol::receive(&mut peer).unwrap_err();
            assert!(matches!(
                waiting.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ));
            protocol::send(&mut peer, &Message::InputReady { id: 1 }).unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let Message::Data { id, stream, data } = protocol::receive(&mut peer).unwrap() else {
                panic!("expected stdin data after credit");
            };
            assert_eq!(id, 1);
            assert_eq!(stream, Stream::Stdin);
            assert_eq!(data.len(), expected_length);
            received.extend(data);
        }
        protocol::send(&mut peer, &Message::InputReady { id: 1 }).unwrap();
        assert!(matches!(
            protocol::receive(&mut peer).unwrap(),
            Message::Close {
                id: 1,
                stream: Stream::Stdin
            }
        ));
        protocol::send(&mut peer, &Message::Exited { id: 1, code: 0 }).unwrap();
        let result = relay_thread.join().unwrap();
        fs::remove_dir_all(root).unwrap();
        assert_eq!(result.unwrap(), 0);
        assert_eq!(received, expected);
    }

    #[test]
    fn slow_output_does_not_hide_the_process_exit() {
        let root = temp_root("slow-output");
        let directory = root.join("c1");
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("config.json"), RECOVERY_RECORD).unwrap();
        let fifo = root.join("out");
        nix::unistd::mkfifo(
            &fifo,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        // Keep a consumer attached without draining it, so the real FIFO fills.
        let _consumer = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo)
            .unwrap();
        let process = ProcessRecord {
            stdout: fifo.to_str().unwrap().into(),
            ..running_process()
        };
        let shim_service = service(&root, "c1");
        *shim_service.task.lock().unwrap() = Some(Task {
            id: "c1".into(),
            bundle: "/bundle".into(),
            deleting: BTreeSet::new(),
            processes: BTreeMap::from([(String::new(), process.clone())]),
        });
        let (connection, mut peer) = UnixStream::pair().unwrap();
        shim_service.observe_exit(connection, 1, process, "c1".into(), String::new());
        let sender = thread::spawn(move || {
            for _ in 0..16 {
                protocol::send(
                    &mut peer,
                    &Message::Data {
                        id: 1,
                        stream: Stream::Stdout,
                        data: vec![b'x'; protocol::STREAM_CHUNK_BYTES],
                    },
                )
                .unwrap();
            }
            protocol::send(&mut peer, &Message::Exited { id: 1, code: 17 }).unwrap();
        });
        assert_exit_observed(&shim_service, &directory, 17);
        sender.join().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejected_start_callbacks_do_not_change_a_new_attempt() {
        let root = temp_root("start-generations");
        let shim_service = service(&root, "c1");
        let old = ProcessRecord {
            start_generation: 1,
            state: ProcessState::Starting,
            ..running_process()
        };
        let current = ProcessRecord {
            start_generation: 2,
            ..old.clone()
        };
        *shim_service.task.lock().unwrap() = Some(Task {
            id: "c1".into(),
            bundle: "/bundle".into(),
            deleting: BTreeSet::new(),
            processes: BTreeMap::from([("e1".into(), current)]),
        });
        shim_service.reset("c1", "e1", &old);
        shim_service.exited("c1", "e1", &old, 99);
        let (connection, _) = UnixStream::pair().unwrap();
        assert!(
            shim_service
                .finish_start(connection, 1, old, "c1", "e1", &root.join("c1"))
                .is_err()
        );
        let observed = shim_service.process("c1", "e1").unwrap().1;
        assert!(matches!(observed.state, ProcessState::Starting));
        assert_eq!(observed.start_generation, 2);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn created_init_cancellation_owns_the_transition_before_host_reply() {
        let root = temp_root("created-init-stop");
        let directory = root.join("c1");
        fs::create_dir(&directory).unwrap();
        let listener =
            std::os::unix::net::UnixListener::bind(directory.join("control.sock")).unwrap();
        let (observed, wait_observed) = std::sync::mpsc::channel();
        let (release, wait_release) = std::sync::mpsc::channel();
        let holder = thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            let operation: Control = protocol::receive_value(&mut connection).unwrap();
            assert!(matches!(
                operation,
                Control::Signal {
                    id: 1,
                    signal: libc::SIGTERM
                }
            ));
            observed.send(()).unwrap();
            wait_release.recv().unwrap();
            protocol::send_value(&mut connection, &Reply::Done).unwrap();
        });
        let shim_service = service(&root, "c1");
        *shim_service.task.lock().unwrap() = Some(Task {
            id: "c1".into(),
            bundle: "/bundle".into(),
            deleting: BTreeSet::new(),
            processes: BTreeMap::from([(
                String::new(),
                ProcessRecord {
                    agent_id: None,
                    state: ProcessState::Created,
                    ..running_process()
                },
            )]),
        });
        let sender = shim_service.clone();
        let kill = thread::spawn(move || sender.signal_process("c1", "", libc::SIGTERM, true));
        wait_observed.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(
            shim_service.process("c1", "").unwrap().1.state,
            ProcessState::Stopping
        ));
        let request = api::StartRequest {
            id: "c1".into(),
            ..Default::default()
        };
        assert!(
            shim_service
                .launch_process(&request, Duration::from_millis(20))
                .is_err()
        );
        release.send(()).unwrap();
        kill.join().unwrap().unwrap();
        holder.join().unwrap();
        assert_exit_observed(&shim_service, &directory, (128 + libc::SIGTERM) as u32);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn late_start_acknowledgement_retains_one_operation_and_observes_exit() {
        let root = temp_root("late-start");
        let directory = root.join("c1");
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("config.json"), RECOVERY_RECORD).unwrap();
        let listener =
            std::os::unix::net::UnixListener::bind(directory.join("control.sock")).unwrap();
        let holder = thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            let operation: Control = protocol::receive_value(&mut connection).unwrap();
            assert!(matches!(
                operation,
                Control::Launch {
                    id: 1,
                    process: None
                }
            ));
            thread::sleep(Duration::from_millis(100));
            protocol::send_value(&mut connection, &Reply::Started { id: 1 }).unwrap();
            protocol::send(&mut connection, &Message::Exited { id: 1, code: 27 }).unwrap();
        });
        let shim_service = service(&root, "c1");
        *shim_service.task.lock().unwrap() = Some(Task {
            id: "c1".into(),
            bundle: "/bundle".into(),
            deleting: BTreeSet::new(),
            processes: BTreeMap::from([(
                String::new(),
                ProcessRecord {
                    agent_id: None,
                    state: ProcessState::Created,
                    ..running_process()
                },
            )]),
        });
        let request = api::StartRequest {
            id: "c1".into(),
            ..Default::default()
        };
        let error = shim_service
            .launch_process(&request, Duration::from_millis(20))
            .unwrap_err();
        assert!(format!("{error:#}").contains("operation remains Starting"));
        let pending = shim_service.process("c1", "").unwrap().1;
        assert!(matches!(pending.state, ProcessState::Starting));
        assert_eq!(pending.agent_id, Some(1));
        assert!(
            shim_service
                .launch_process(&request, Duration::from_millis(20))
                .is_err()
        );
        assert_exit_observed(&shim_service, &directory, 27);
        holder.join().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn starting_exec_signal_uses_its_acknowledged_identity() {
        let root = temp_root("starting-exec-kill");
        let directory = root.join("c1");
        fs::create_dir(&directory).unwrap();
        let listener =
            std::os::unix::net::UnixListener::bind(directory.join("control.sock")).unwrap();
        let holder = thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            let operation: Control = protocol::receive_value(&mut connection).unwrap();
            assert!(matches!(
                operation,
                Control::Signal {
                    id: 7,
                    signal: libc::SIGTERM
                }
            ));
            protocol::send_value(&mut connection, &Reply::Done).unwrap();
        });
        let shim_service = service(&root, "c1");
        *shim_service.task.lock().unwrap() = Some(Task {
            id: "c1".into(),
            bundle: "/bundle".into(),
            deleting: BTreeSet::new(),
            processes: BTreeMap::from([(
                "e1".into(),
                ProcessRecord {
                    agent_id: None,
                    state: ProcessState::Starting,
                    ..running_process()
                },
            )]),
        });
        let sender = shim_service.clone();
        let kill = thread::spawn(move || sender.signal_process("c1", "e1", libc::SIGTERM, true));
        thread::sleep(Duration::from_millis(50));
        {
            let mut slot = shim_service.task.lock().unwrap();
            let process = slot.as_mut().unwrap().processes.get_mut("e1").unwrap();
            process.agent_id = Some(7);
            process.state = ProcessState::Running;
        }
        shim_service.changed.notify_all();
        kill.join().unwrap().unwrap();
        holder.join().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn early_exit_bookkeeping_waits_for_the_start_announcement() {
        let root = temp_root("early-exit-order");
        let directory = root.join("c1");
        fs::create_dir(&directory).unwrap();
        let entered = directory.join("entered");
        let release = directory.join("release");
        let record = serde_json::json!({
            "state": {"ociVersion":"1.0.2","id":"c1","status":"running","pid":7,"bundle":"/bundle","annotations":{}},
            "config": {"ociVersion":"1.0.2","root":{"path":"rootfs"},"process":{"args":["/bin/sh"],"cwd":"/"},
            "hooks":{"poststart":[{"path":"/bin/sh","args":["sh","-c",format!("cat > /dev/null; touch {}; while [ ! -f {} ]; do sleep 0.01; done", entered.display(), release.display())]}]}}
        });
        fs::write(
            directory.join("config.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        let shim_service = service(&root, "c1");
        let process = ProcessRecord {
            state: ProcessState::Starting,
            ..running_process()
        };
        *shim_service.task.lock().unwrap() = Some(Task {
            id: "c1".into(),
            bundle: "/bundle".into(),
            deleting: BTreeSet::new(),
            processes: BTreeMap::from([(String::new(), process.clone())]),
        });
        let (connection, mut peer) = UnixStream::pair().unwrap();
        protocol::send(&mut peer, &Message::Exited { id: 1, code: 13 }).unwrap();
        let service = shim_service.clone();
        let path = directory.clone();
        let start =
            thread::spawn(move || service.finish_start(connection, 1, process, "c1", "", &path));
        let deadline = Instant::now() + Duration::from_secs(2);
        while !entered.exists() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(10));
        }
        thread::sleep(Duration::from_millis(50));
        assert!(matches!(
            shim_service.process("c1", "").unwrap().1.state,
            ProcessState::Running
        ));
        assert!(!directory.join("exit.json").exists());
        fs::write(release, b"release").unwrap();
        start.join().unwrap().unwrap();
        assert_exit_observed(&shim_service, &directory, 13);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn created_exec_signal_zero_preserves_created_state() {
        let root = temp_root("exec-signal-zero");
        let shim_service = service(&root, "c1");
        let process = ProcessRecord {
            agent_id: None,
            state: ProcessState::Created,
            ..running_process()
        };
        *shim_service.task.lock().unwrap() = Some(Task {
            id: "c1".into(),
            bundle: "/bundle".into(),
            deleting: BTreeSet::new(),
            processes: BTreeMap::from([("e1".into(), process)]),
        });
        shim_service.signal_process("c1", "e1", 0, true).unwrap();
        assert!(matches!(
            shim_service.process("c1", "e1").unwrap().1.state,
            ProcessState::Created
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fifo_stdin_workers_are_joined_after_exit() {
        for idle_writer in [false, true] {
            let root = temp_root(if idle_writer {
                "stdin-idle-writer"
            } else {
                "stdin-no-writer"
            });
            let path = root.join("stdin");
            nix::unistd::mkfifo(
                &path,
                nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
            )
            .unwrap();
            // O_RDWR keeps a FIFO writer idle without blocking this test's open.
            let writer = if idle_writer {
                Some(
                    OpenOptions::new()
                        .read(true)
                        .write(true)
                        .custom_flags(libc::O_NONBLOCK)
                        .open(&path)
                        .unwrap(),
                )
            } else {
                None
            };
            let process = ProcessRecord {
                stdin: path.to_str().unwrap().into(),
                ..running_process()
            };
            let (connection, mut peer) = UnixStream::pair().unwrap();
            let (done, result) = std::sync::mpsc::channel();
            let worker = thread::spawn(move || done.send(relay(connection, 1, &process)).unwrap());
            protocol::send(&mut peer, &Message::InputReady { id: 1 }).unwrap();
            thread::sleep(Duration::from_millis(50));
            protocol::send(&mut peer, &Message::Exited { id: 1, code: 19 }).unwrap();
            assert_eq!(
                result
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap()
                    .unwrap(),
                19
            );
            worker.join().unwrap();
            // relay returns only after joining stdin. No fd for this FIFO may
            // remain except the writer explicitly owned by this test.
            let references = fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter(|entry| {
                    fs::read_link(entry.as_ref().unwrap().path()).ok().as_ref() == Some(&path)
                })
                .count();
            assert_eq!(references, usize::from(idle_writer));
            drop(writer);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn blocked_stdin_does_not_delay_the_observed_exit() {
        use std::os::fd::AsRawFd;

        // Regression: output cancellation joined a worker waiting for the
        // stdin writer's mutex after Exited had already reached the reader.
        let root = temp_root("blocked-stdin-exit");
        let stdin = root.join("in");
        fs::write(&stdin, vec![b'i'; 8 * protocol::STREAM_CHUNK_BYTES]).unwrap();
        let stdout = root.join("out");
        nix::unistd::mkfifo(
            &stdout,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        let _consumer = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&stdout)
            .unwrap();
        nix::fcntl::fcntl(
            _consumer.as_raw_fd(),
            nix::fcntl::FcntlArg::F_SETPIPE_SZ(4096),
        )
        .unwrap();
        let process = ProcessRecord {
            stdin: stdin.to_str().unwrap().into(),
            stdout: stdout.to_str().unwrap().into(),
            ..running_process()
        };
        let (connection, mut peer) = UnixStream::pair().unwrap();
        nix::sys::socket::setsockopt(&connection, nix::sys::socket::sockopt::SndBuf, &4096)
            .unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let relay_thread = thread::spawn(move || {
            sender.send(relay(connection, 1, &process)).unwrap();
        });
        protocol::send(&mut peer, &Message::InputReady { id: 1 }).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let mut queued: libc::c_int = 0;
            // SAFETY: FIONREAD writes one c_int into a valid live object.
            assert_eq!(
                unsafe { libc::ioctl(peer.as_raw_fd(), libc::FIONREAD, &mut queued) },
                0
            );
            if queued >= 4096 {
                break;
            }
            assert!(Instant::now() < deadline, "stdin never filled the socket");
            thread::sleep(Duration::from_millis(10));
        }
        protocol::send(
            &mut peer,
            &Message::Data {
                id: 1,
                stream: Stream::Stdout,
                data: vec![b'o'; protocol::STREAM_CHUNK_BYTES],
            },
        )
        .unwrap();
        protocol::send(&mut peer, &Message::Exited { id: 1, code: 23 }).unwrap();
        let result = receiver.recv_timeout(Duration::from_millis(1500));
        // Also unblock the legacy failure path, so a failed assertion leaves
        // no relay or stdin writer behind in the test process.
        let _ = peer.shutdown(Shutdown::Both);
        relay_thread.join().unwrap();
        fs::remove_dir_all(root).unwrap();
        assert_eq!(result.unwrap().unwrap(), 23);
    }

    #[test]
    fn relay_drains_burst_output_before_reporting_exit() {
        let root = temp_root("burst-output");
        let stdout = root.join("out");
        let stderr = root.join("err");
        File::create(&stdout).unwrap();
        File::create(&stderr).unwrap();
        let process = ProcessRecord {
            stdout: stdout.to_str().unwrap().into(),
            stderr: stderr.to_str().unwrap().into(),
            ..running_process()
        };
        let expected = vec![b'x'; 24 * protocol::STREAM_CHUNK_BYTES];
        let (connection, mut peer) = UnixStream::pair().unwrap();
        let sender = thread::spawn(move || {
            for _ in 0..24 {
                protocol::send(
                    &mut peer,
                    &Message::Data {
                        id: 1,
                        stream: Stream::Stdout,
                        data: vec![b'x'; protocol::STREAM_CHUNK_BYTES],
                    },
                )
                .unwrap();
            }
            protocol::send(
                &mut peer,
                &Message::Data {
                    id: 1,
                    stream: Stream::Stderr,
                    data: b"diagnostic".to_vec(),
                },
            )
            .unwrap();
            protocol::send(&mut peer, &Message::Exited { id: 1, code: 3 }).unwrap();
        });
        assert_eq!(relay(connection, 1, &process).unwrap(), 3);
        sender.join().unwrap();
        assert_eq!(fs::read(stdout).unwrap(), expected);
        assert_eq!(fs::read(stderr).unwrap(), b"diagnostic");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn output_failure_keeps_the_actual_exit_code() {
        let (connection, mut peer) = UnixStream::pair().unwrap();
        let sender = thread::spawn(move || {
            protocol::send(
                &mut peer,
                &Message::OutputFailed {
                    id: 1,
                    stream: Stream::Stdout,
                    detail: "output drain timed out".into(),
                },
            )
            .unwrap();
            protocol::send(
                &mut peer,
                &Message::Close {
                    id: 1,
                    stream: Stream::Stdout,
                },
            )
            .unwrap();
            protocol::send(&mut peer, &Message::Exited { id: 1, code: 7 }).unwrap();
        });
        assert_eq!(relay(connection, 1, &running_process()).unwrap(), 7);
        sender.join().unwrap();
    }

    #[test]
    fn disconnected_attachment_queries_the_actual_exit_code() {
        let root = temp_root("query-exit");
        let directory = root.join("c1");
        fs::create_dir_all(&directory).unwrap();
        let listener =
            std::os::unix::net::UnixListener::bind(directory.join("control.sock")).unwrap();
        let holder = thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            assert!(matches!(
                protocol::receive_value::<Control>(&mut connection).unwrap(),
                Control::ExitStatus { id: 1 }
            ));
            protocol::send_value(&mut connection, &Reply::ExitStatus { code: Some(11) }).unwrap();
        });
        let shim_service = service(&root, "c1");
        let process = running_process();
        *shim_service.task.lock().unwrap() = Some(Task {
            id: "c1".into(),
            bundle: "/bundle".into(),
            deleting: BTreeSet::new(),
            processes: BTreeMap::from([(String::new(), process.clone())]),
        });
        let (connection, peer) = UnixStream::pair().unwrap();
        drop(peer);
        shim_service.observe_exit(connection, 1, process, "c1".into(), String::new());
        assert_exit_observed(&shim_service, &directory, 11);
        holder.join().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unavailable_exit_status_returns_an_error_without_an_exit_code() {
        let root = temp_root("unknown-exit");
        let directory = root.join("c1");
        fs::create_dir_all(&directory).unwrap();
        let listener =
            std::os::unix::net::UnixListener::bind(directory.join("control.sock")).unwrap();
        let holder = thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            assert!(matches!(
                protocol::receive_value::<Control>(&mut connection).unwrap(),
                Control::ExitStatus { id: 1 }
            ));
            protocol::send_value(
                &mut connection,
                &Reply::Error("exit status unavailable".into()),
            )
            .unwrap();
        });
        let shim_service = service(&root, "c1");
        let process = running_process();
        *shim_service.task.lock().unwrap() = Some(Task {
            id: "c1".into(),
            bundle: "/bundle".into(),
            deleting: BTreeSet::new(),
            processes: BTreeMap::from([(String::new(), process.clone())]),
        });
        let (connection, peer) = UnixStream::pair().unwrap();
        drop(peer);
        shim_service.observe_exit(connection, 1, process, "c1".into(), String::new());
        let observer = shim_service.clone();
        let (sender, receiver) = std::sync::mpsc::channel();
        let waiter = thread::spawn(move || sender.send(observer.wait_for_exit("c1", "")).unwrap());
        let error = receiver
            .recv_timeout(Duration::from_secs(3))
            .unwrap()
            .unwrap_err();
        assert!(format!("{error:#}").contains("exit status unavailable"));
        let (_, process) = shim_service.process("c1", "").unwrap();
        assert!(matches!(process.state, ProcessState::Running));
        assert!(process.exited_at.is_none());
        waiter.join().unwrap();
        holder.join().unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
