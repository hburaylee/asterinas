// SPDX-License-Identifier: MPL-2.0

//! Guest PID 1: prepares the container and manages processes over vsock.

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Read, Write},
    os::{fd::AsRawFd, unix::process::CommandExt},
    process::{Command, Stdio},
    sync::{Arc, Condvar, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use nix::{
    errno::Errno,
    mount::{self, MntFlags, MsFlags},
    sys::{
        signal::{self, Signal},
        wait::{self, WaitStatus},
    },
    unistd::{self, Gid, Pid, Uid},
};

use crate::{
    config::{Config, Process},
    protocol::{self, Message, Request, Stream},
    uapi,
};

type Writer = Arc<Mutex<File>>;
type ProcessTable = Arc<Processes>;

// A child exit must not depend on EOF from descendants that escaped its group.
const OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
const OUTPUT_POLL_INTERVAL: Duration = Duration::from_millis(20);

struct Processes {
    state: Mutex<ProcessState>,
    started: Condvar,
}

struct ProcessState {
    running: BTreeMap<u64, Running>,
    outputs: BTreeMap<u64, Arc<Outputs>>,
    starts: u64,
}

struct Running {
    pid: Pid,
    input: Option<mpsc::SyncSender<Option<Vec<u8>>>>,
    output_threads: Vec<thread::JoinHandle<()>>,
    outputs: Arc<Outputs>,
    terminal: Option<File>,
}

struct ProcessIo {
    input: Box<dyn Write + Send>,
    outputs: Vec<(Stream, File)>,
    terminal_control: Option<File>,
}

struct Outputs {
    state: Mutex<OutputState>,
    changed: Condvar,
}

struct OutputState {
    credit: [bool; 2],
    cancelled: [Option<String>; 2],
    deadline: Option<Instant>,
}

impl Outputs {
    fn new() -> Self {
        Self {
            state: Mutex::new(OutputState {
                credit: [false; 2],
                cancelled: [None, None],
                deadline: None,
            }),
            changed: Condvar::new(),
        }
    }

    fn ready(&self, stream: Stream) {
        let Some(index) = output_index(stream) else {
            return;
        };
        self.state.lock().unwrap().credit[index] = true;
        self.changed.notify_all();
    }

    fn cancel(&self, stream: Stream, detail: String) {
        let Some(index) = output_index(stream) else {
            return;
        };
        self.state.lock().unwrap().cancelled[index].get_or_insert(detail);
        self.changed.notify_all();
    }

    fn finish(&self) {
        self.state.lock().unwrap().deadline = Some(Instant::now() + OUTPUT_DRAIN_TIMEOUT);
        self.changed.notify_all();
    }

    fn check(state: &OutputState, index: usize) -> Result<()> {
        if let Some(detail) = &state.cancelled[index] {
            bail!("{detail}");
        }
        if state
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            bail!("output did not drain within one second after process exit");
        }
        Ok(())
    }

    fn wait_credit(&self, stream: Stream) -> Result<()> {
        let index = output_index(stream).unwrap();
        let mut state = self.state.lock().unwrap();
        loop {
            Self::check(&state, index)?;
            if state.credit[index] {
                state.credit[index] = false;
                return Ok(());
            }
            state = self
                .changed
                .wait_timeout(state, OUTPUT_POLL_INTERVAL)
                .unwrap()
                .0;
        }
    }

    fn check_stream(&self, stream: Stream) -> Result<()> {
        Self::check(&self.state.lock().unwrap(), output_index(stream).unwrap())
    }
}

fn signal_all(signal: i32) -> Result<()> {
    ensure!(
        std::process::id() == 1,
        "signal-all requires the Guest PID 1 agent"
    );
    ensure!((0..=64).contains(&signal), "invalid signal number");
    // SAFETY: the agent is PID 1 in its dedicated Guest. The kernel broadcasts
    // atomically over its process table, excluding PID 1 and the sender. This
    // includes descendants that changed their session or process group.
    if unsafe { libc::kill(-1, signal) } < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error.into());
        }
    }
    Ok(())
}

#[cfg(test)]
fn signal_managed_fixture(processes: &ProcessTable, signal: i32) -> Result<()> {
    let state = processes.state.lock().unwrap();
    for process in state.running.values() {
        // SAFETY: only unreaped fixture-owned process groups are addressed.
        if unsafe { libc::kill(-process.pid.as_raw(), signal) } < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error.into());
            }
        }
    }
    Ok(())
}

fn output_index(stream: Stream) -> Option<usize> {
    match stream {
        Stream::Stdout => Some(0),
        Stream::Stderr => Some(1),
        Stream::Stdin => None,
    }
}

pub fn run() -> Result<()> {
    ensure!(std::process::id() == 1, "agent must run as PID 1");
    prepare_overlay().context("prepare writable guest root")?;
    let connection =
        uapi::connect_agent(protocol::AGENT_PORT).context("connect to host runtime")?;
    serve_connection(connection)
}

pub(crate) fn serve_connection(mut connection: File) -> Result<()> {
    let writer = Arc::new(Mutex::new(connection.try_clone()?));
    transmit(
        &writer,
        Message::Hello {
            version: protocol::VERSION,
        },
    )?;
    let mut prepared = None;
    let processes = Arc::new(Processes {
        state: Mutex::new(ProcessState {
            running: BTreeMap::new(),
            outputs: BTreeMap::new(),
            starts: 0,
        }),
        started: Condvar::new(),
    });
    reap_children(processes.clone(), writer.clone());
    loop {
        let message = protocol::receive(&mut connection)?;
        let request = Request::from_message(&message);
        let result = (|| -> Result<()> {
            match message {
                Message::OutputReady { id, stream } => {
                    if let Some(outputs) = processes.state.lock().unwrap().outputs.get(&id) {
                        outputs.ready(stream);
                    }
                    Ok(())
                }
                Message::OutputFailed { id, stream, detail } => {
                    if let Some(outputs) = processes.state.lock().unwrap().outputs.get(&id) {
                        outputs.cancel(stream, detail);
                    }
                    Ok(())
                }
                Message::ListProcesses { request_id } => {
                    let mut pids = Vec::new();
                    for entry in fs::read_dir("/proc")? {
                        let entry = entry?;
                        if let Some(pid) = entry
                            .file_name()
                            .to_str()
                            .and_then(|name| name.parse::<u32>().ok())
                            && pid > 1
                        {
                            ensure!(pids.len() < 65536, "process list exceeds protocol bound");
                            pids.push(pid);
                        }
                    }
                    pids.sort_unstable();
                    transmit(&writer, Message::Processes { request_id, pids })
                }
                Message::Prepare { config } => {
                    if prepared.is_some() {
                        bail!("container already prepared");
                    }
                    config.validate()?;
                    prepare(&config)?;
                    prepared = Some(*config);
                    transmit(&writer, Message::Prepared)
                }
                Message::Start { id, process } => {
                    let process = process.or_else(|| {
                        prepared
                            .as_ref()
                            .map(|config: &Config| config.process.clone())
                    });
                    match process {
                        Some(process) => start(id, process, &writer, &processes),
                        None => Err(anyhow::anyhow!("container has not been prepared")),
                    }
                }
                Message::Resize {
                    request_id,
                    id,
                    rows,
                    columns,
                } => {
                    let processes = processes.state.lock().unwrap();
                    let terminal = processes
                        .running
                        .get(&id)
                        .and_then(|process| process.terminal.as_ref())
                        .context("process has no terminal")?;
                    let size = libc::winsize {
                        ws_row: rows,
                        ws_col: columns,
                        ws_xpixel: 0,
                        ws_ypixel: 0,
                    };
                    // SAFETY: the terminal descriptor and winsize buffer are valid through ioctl.
                    if unsafe { libc::ioctl(terminal.as_raw_fd(), libc::TIOCSWINSZ, &size) } < 0 {
                        return Err(std::io::Error::last_os_error().into());
                    }
                    transmit(&writer, Message::RequestCompleted { request_id })
                }
                Message::SignalAll { request_id, signal } => {
                    ensure!((0..=64).contains(&signal), "invalid signal number");
                    #[cfg(test)]
                    if std::process::id() != 1 {
                        // Host lifecycle fixtures substitute only delivery;
                        // broadcasting from an ordinary Linux process is unsafe.
                        signal_managed_fixture(&processes, signal)?;
                        transmit(&writer, Message::RequestCompleted { request_id })?;
                        return Ok(());
                    }
                    signal_all(signal)?;
                    transmit(&writer, Message::RequestCompleted { request_id })
                }
                Message::Signal {
                    request_id,
                    id,
                    signal,
                } => {
                    ensure!((0..=64).contains(&signal), "invalid signal number");
                    let processes = processes.state.lock().unwrap();
                    let process = processes.running.get(&id).context("unknown process")?;
                    // SAFETY: kill receives scalar process-group and signal numbers.
                    if unsafe { libc::kill(-process.pid.as_raw(), signal) } < 0 {
                        return Err(std::io::Error::last_os_error().into());
                    }
                    transmit(&writer, Message::RequestCompleted { request_id })
                }
                Message::Data {
                    id,
                    stream: Stream::Stdin,
                    data,
                } => {
                    ensure!(
                        data.len() <= protocol::STREAM_CHUNK_BYTES,
                        "stdin chunk too large"
                    );
                    let processes = processes.state.lock().unwrap();
                    let input = processes
                        .running
                        .get(&id)
                        .and_then(|process| process.input.as_ref())
                        .context("stdin is closed")?;
                    input
                        .try_send(Some(data))
                        .context("stdin credit exceeded")?;
                    Ok(())
                }
                Message::Close {
                    id,
                    stream: Stream::Stdin,
                } => close_input(id, &processes),
                Message::CloseInput { request_id, id } => {
                    close_input(id, &processes)?;
                    transmit(&writer, Message::RequestCompleted { request_id })
                }
                _ => Err(anyhow::anyhow!("unexpected host message")),
            }
        })();
        if let Err(error) = result {
            let detail = format!("{error:#}");
            let failure = match request {
                Some(request) => Message::RequestFailed { request, detail },
                None => Message::Error { detail },
            };
            transmit(&writer, failure)?;
        }
    }
}

fn close_input(id: u64, processes: &Processes) -> Result<()> {
    let mut state = processes.state.lock().unwrap();
    if let Some(process) = state.running.get_mut(&id)
        && let Some(input) = &process.input
    {
        input.try_send(None).context("stdin credit exceeded")?;
        process.input = None;
    }
    Ok(())
}

fn prepare_overlay() -> Result<()> {
    mount::mount(
        Some("tmpfs"),
        "/run",
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("mode=0755"),
    )
    .context("mount /run tmpfs")?;
    for path in [
        "/run/kernelet/upper",
        "/run/kernelet/work",
        "/run/kernelet/root",
    ] {
        fs::create_dir_all(path).with_context(|| format!("create {path}"))?;
    }
    mount::mount(
        Some("overlay"),
        "/run/kernelet/root",
        Some("overlay"),
        MsFlags::empty(),
        Some("lowerdir=/,upperdir=/run/kernelet/upper,workdir=/run/kernelet/work"),
    )
    .context("mount overlay root")?;
    fs::create_dir_all("/run/kernelet/root/.kernelet-old-root")
        .context("create old-root mount point")?;
    unistd::pivot_root(
        "/run/kernelet/root",
        "/run/kernelet/root/.kernelet-old-root",
    )
    .context("pivot to overlay root")?;
    std::env::set_current_dir("/").context("enter overlay root")?;
    mount::umount2("/.kernelet-old-root", MntFlags::MNT_DETACH).context("detach old root")?;
    fs::remove_dir("/.kernelet-old-root").context("remove old-root mount point")?;
    mount::mount(
        Some("devtmpfs"),
        "/dev",
        Some("devtmpfs"),
        MsFlags::MS_NOSUID,
        None::<&str>,
    )
    .context("mount devtmpfs")?;
    fs::create_dir_all("/dev/pts").context("create /dev/pts")?;
    mount::mount(
        Some("devpts"),
        "/dev/pts",
        Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("mode=0620,ptmxmode=0666"),
    )
    .context("mount devpts")?;
    std::os::unix::fs::symlink("pts/ptmx", "/dev/ptmx").context("create /dev/ptmx")?;
    Ok(())
}

fn prepare(config: &Config) -> Result<()> {
    if !config.hostname.is_empty() {
        unistd::sethostname(&config.hostname)?;
    }
    // Install the default before explicit mounts can replace /etc or its
    // resolver file, including read-only binds supplied by the container manager.
    if let Some(network) = &config.network {
        crate::network::configure_guest(network)?;
    }
    for entry in &config.mounts {
        if let Some(content) = &entry.content {
            if let Some(parent) = entry.destination.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&entry.destination, content)?;
            if let Some((mode, uid, gid)) = entry.content_metadata {
                use std::os::unix::fs::PermissionsExt;
                std::os::unix::fs::chown(&entry.destination, Some(uid), Some(gid))?;
                fs::set_permissions(&entry.destination, fs::Permissions::from_mode(mode))?;
            }
            if entry.options.iter().any(|option| option == "ro") {
                mount::mount(
                    Some(&entry.destination),
                    &entry.destination,
                    None::<&str>,
                    MsFlags::MS_BIND,
                    None::<&str>,
                )?;
                mount::mount::<str, _, str, str>(
                    None,
                    &entry.destination,
                    None,
                    MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                    None,
                )?;
            }
            continue;
        }
        fs::create_dir_all(&entry.destination)?;
        let mut flags = MsFlags::empty();
        let mut options = Vec::new();
        for option in &entry.options {
            match option.as_str() {
                "ro" => flags |= MsFlags::MS_RDONLY,
                "rw" | "defaults" => {}
                "nosuid" => flags |= MsFlags::MS_NOSUID,
                "nodev" => flags |= MsFlags::MS_NODEV,
                "noexec" => flags |= MsFlags::MS_NOEXEC,
                "noatime" => flags |= MsFlags::MS_NOATIME,
                "nodiratime" => flags |= MsFlags::MS_NODIRATIME,
                "relatime" => flags |= MsFlags::MS_RELATIME,
                "strictatime" => flags |= MsFlags::MS_STRICTATIME,
                _ => options.push(option.as_str()),
            }
        }
        let data = options.join(",");
        mount::mount(
            Some(entry.source.as_str()),
            &entry.destination,
            Some(entry.kind.as_str()),
            flags,
            Some(data.as_str()),
        )
        .with_context(|| format!("mount {}", entry.destination.display()))?;
        if entry.destination == std::path::Path::new("/dev") {
            populate_devices()?;
        }
    }
    if config.root.readonly {
        mount::mount::<str, str, str, str>(
            None,
            "/",
            None,
            MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
            None,
        )?;
    }
    Ok(())
}

fn populate_devices() -> Result<()> {
    use nix::sys::stat::{self, Mode, SFlag};
    for (name, major, minor) in [
        ("null", 1, 3),
        ("zero", 1, 5),
        ("full", 1, 7),
        ("random", 1, 8),
        ("urandom", 1, 9),
        ("tty", 5, 0),
        ("console", 5, 1),
    ] {
        let path = std::path::Path::new("/dev").join(name);
        stat::mknod(
            &path,
            SFlag::S_IFCHR,
            Mode::from_bits_truncate(0o666),
            stat::makedev(major, minor),
        )?;
    }
    for (name, target) in [
        ("ptmx", "pts/ptmx"),
        ("fd", "/proc/self/fd"),
        ("stdin", "/proc/self/fd/0"),
        ("stdout", "/proc/self/fd/1"),
        ("stderr", "/proc/self/fd/2"),
    ] {
        std::os::unix::fs::symlink(target, std::path::Path::new("/dev").join(name))?;
    }
    Ok(())
}

fn start(id: u64, process: Process, writer: &Writer, processes: &ProcessTable) -> Result<()> {
    process.validate()?;
    let mut state = processes.state.lock().unwrap();
    ensure!(
        !state.running.contains_key(&id),
        "duplicate process identifier"
    );
    let next_start = state
        .starts
        .checked_add(1)
        .context("process generation exhausted")?;
    let mut command = Command::new(&process.args[0]);
    command
        .args(&process.args[1..])
        .env_clear()
        .current_dir(&process.cwd);
    for entry in &process.env {
        let (key, value) = entry.split_once('=').unwrap();
        command.env(key, value);
    }
    let mut terminal = None;
    if process.terminal {
        let pty = nix::pty::openpty(None, None).context("open guest pseudo terminal")?;
        let slave = File::from(pty.slave);
        command
            .stdin(slave.try_clone()?)
            .stdout(slave.try_clone()?)
            .stderr(slave);
        terminal = Some(File::from(pty.master));
    } else {
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
    }
    let capabilities = crate::capabilities::Capabilities::parse(&process.capabilities)?;
    let groups: Vec<_> = process
        .user
        .additional_gids
        .iter()
        .copied()
        .map(Gid::from_raw)
        .collect();
    let uid = Uid::from_raw(process.user.uid);
    let gid = Gid::from_raw(process.user.gid);
    let limits = process
        .rlimits
        .iter()
        .map(|limit| Ok((rlimit_resource(&limit.kind)?, (limit.soft, limit.hard))))
        .collect::<Result<Vec<_>>>()?;
    // SAFETY: the child callback performs only async-signal-safe system calls and allocates nothing.
    unsafe {
        command.pre_exec(move || {
            unistd::setsid()?;
            if let Some(mask) = process.user.umask {
                libc::umask(mask);
            }
            if process.terminal && libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            for (resource, (soft, hard)) in &limits {
                nix::sys::resource::setrlimit(*resource, *soft, *hard)?;
            }
            if process.no_new_privileges && libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if let Some(capabilities) = capabilities {
                capabilities.before_uid_change()?;
            }
            unistd::setgroups(&groups)?;
            unistd::setgid(gid)?;
            unistd::setuid(uid)?;
            if let Some(capabilities) = capabilities {
                capabilities.after_uid_change()?;
            }
            Ok(())
        });
    }
    let terminal = terminal
        .map(|master| -> std::io::Result<_> {
            Ok((master.try_clone()?, master.try_clone()?, master))
        })
        .transpose()?;
    let mut child = command.spawn().context("start container process")?;
    let pid = child.id();
    let io = if let Some((input_master, control_master, master)) = terminal {
        ProcessIo {
            input: Box::new(input_master),
            outputs: vec![(Stream::Stdout, master)],
            terminal_control: Some(control_master),
        }
    } else {
        ProcessIo {
            input: Box::new(child.stdin.take().unwrap()),
            outputs: vec![
                (
                    Stream::Stdout,
                    File::from(std::os::fd::OwnedFd::from(child.stdout.take().unwrap())),
                ),
                (
                    Stream::Stderr,
                    File::from(std::os::fd::OwnedFd::from(child.stderr.take().unwrap())),
                ),
            ],
            terminal_control: None,
        }
    };
    let ProcessIo {
        input,
        outputs,
        terminal_control,
    } = io;
    // One data chunk may be in flight when a close request arrives.
    let (input_sender, input_receiver) = mpsc::sync_channel(2);
    let output_state = Arc::new(Outputs::new());
    state.outputs.insert(id, output_state.clone());
    state.running.insert(
        id,
        Running {
            pid: Pid::from_raw(pid as i32),
            input: Some(input_sender),
            output_threads: Vec::new(),
            outputs: output_state.clone(),
            terminal: terminal_control,
        },
    );
    state.starts = next_start;
    // Publish Started before output forwarding can fill the host's subscriber
    // queue. The process lock prevents the reaper from publishing Exited first.
    transmit(writer, Message::Started { id, pid })?;
    let input_writer = writer.clone();
    thread::spawn(move || {
        let mut input = input;
        for data in input_receiver {
            let Some(data): Option<Vec<u8>> = data else {
                if process.terminal {
                    let _ = input.write_all(&[4]);
                }
                break;
            };
            if let Err(error) = input.write_all(&data) {
                let _ = transmit(
                    &input_writer,
                    Message::RequestFailed {
                        request: Request::Data { id },
                        detail: format!("stdin write failed: {error}"),
                    },
                );
                break;
            }
            if transmit(&input_writer, Message::InputReady { id }).is_err() {
                break;
            }
        }
    });
    state.running.get_mut(&id).unwrap().output_threads = outputs
        .into_iter()
        .map(|(stream, output)| {
            copy_output(id, stream, output, writer.clone(), output_state.clone())
        })
        .collect();
    processes.started.notify_one();
    Ok(())
}

fn copy_output(
    id: u64,
    stream: Stream,
    mut output: File,
    writer: Writer,
    outputs: Arc<Outputs>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut bytes = vec![0; protocol::STREAM_CHUNK_BYTES];
        let result = (|| -> Result<()> {
            loop {
                outputs.check_stream(stream)?;
                let mut descriptor = libc::pollfd {
                    fd: output.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: poll borrows one live descriptor and its valid pollfd buffer.
                let ready = unsafe {
                    libc::poll(&mut descriptor, 1, OUTPUT_POLL_INTERVAL.as_millis() as i32)
                };
                if ready < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(error.into());
                }
                if ready == 0 {
                    continue;
                }
                match output.read(&mut bytes) {
                    Ok(0) => return Ok(()),
                    Ok(length) => {
                        outputs.wait_credit(stream)?;
                        transmit(
                            &writer,
                            Message::Data {
                                id,
                                stream,
                                data: bytes[..length].to_vec(),
                            },
                        )?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    // The PTY master reports EIO after the last slave closes.
                    Err(error) if error.raw_os_error() == Some(libc::EIO) => return Ok(()),
                    Err(error) => return Err(error.into()),
                }
            }
        })();
        if let Err(error) = result {
            let _ = transmit(
                &writer,
                Message::OutputFailed {
                    id,
                    stream,
                    detail: format!("{error:#}"),
                },
            );
        }
        let _ = transmit(&writer, Message::Close { id, stream });
    })
}

fn transmit(writer: &Writer, message: Message) -> Result<()> {
    Ok(protocol::send(&mut *writer.lock().unwrap(), &message)?)
}

fn rlimit_resource(name: &str) -> Result<nix::sys::resource::Resource> {
    Ok(match name {
        "RLIMIT_AS" => nix::sys::resource::Resource::RLIMIT_AS,
        "RLIMIT_CORE" => nix::sys::resource::Resource::RLIMIT_CORE,
        "RLIMIT_CPU" => nix::sys::resource::Resource::RLIMIT_CPU,
        "RLIMIT_DATA" => nix::sys::resource::Resource::RLIMIT_DATA,
        "RLIMIT_FSIZE" => nix::sys::resource::Resource::RLIMIT_FSIZE,
        "RLIMIT_NOFILE" => nix::sys::resource::Resource::RLIMIT_NOFILE,
        "RLIMIT_NPROC" => nix::sys::resource::Resource::RLIMIT_NPROC,
        "RLIMIT_STACK" => nix::sys::resource::Resource::RLIMIT_STACK,
        "RLIMIT_MEMLOCK" => nix::sys::resource::Resource::RLIMIT_MEMLOCK,
        "RLIMIT_LOCKS" => nix::sys::resource::Resource::RLIMIT_LOCKS,
        "RLIMIT_SIGPENDING" => nix::sys::resource::Resource::RLIMIT_SIGPENDING,
        "RLIMIT_MSGQUEUE" => nix::sys::resource::Resource::RLIMIT_MSGQUEUE,
        "RLIMIT_NICE" => nix::sys::resource::Resource::RLIMIT_NICE,
        "RLIMIT_RTPRIO" => nix::sys::resource::Resource::RLIMIT_RTPRIO,
        "RLIMIT_RTTIME" => nix::sys::resource::Resource::RLIMIT_RTTIME,
        "RLIMIT_RSS" => nix::sys::resource::Resource::RLIMIT_RSS,
        _ => bail!("unsupported rlimit {name}"),
    })
}

fn reap_children(processes: ProcessTable, writer: Writer) {
    thread::spawn(move || {
        loop {
            let mut state = processes.state.lock().unwrap();
            // Before the first managed spawn, Prepare owns and waits for its
            // setup commands. Do not steal those command exit statuses.
            while state.starts == 0 {
                state = processes.started.wait(state).unwrap();
            }
            let starts = state.starts;
            drop(state);

            // start() holds the process lock from spawn through insertion. A child
            // can exit before insertion, but the reaper cannot observe it without
            // subsequently finding its process record.
            match wait::waitpid(Pid::from_raw(-1), None) {
                Ok(WaitStatus::Exited(pid, code)) => {
                    finish_child(&processes, &writer, pid, code);
                }
                Ok(WaitStatus::Signaled(pid, signal, _)) => {
                    finish_child(&processes, &writer, pid, 128 + signal as i32);
                }
                Err(Errno::EINTR) => continue,
                Err(Errno::ECHILD) => {
                    // A new child may have been inserted after waitpid returned.
                    let mut state = processes.state.lock().unwrap();
                    if state.starts != starts {
                        continue;
                    }
                    // No kernel children remain, so any tracked process has lost
                    // its exit status. Close it as failed instead of spinning or
                    // leaving the host waiting for Exited indefinitely.
                    let missing = std::mem::take(&mut state.running);
                    drop(state);
                    for (id, process) in missing {
                        report_exit(&processes, &writer, id, 255, process);
                    }
                    // ECHILD proves there are no adopted children either. Only
                    // then wait for a new spawn; an empty managed map alone
                    // never prevents waitpid from reaping an orphan.
                    let mut state = processes.state.lock().unwrap();
                    while state.starts == starts {
                        state = processes.started.wait(state).unwrap();
                    }
                }
                Ok(_) => {}
                Err(error) => {
                    let mut state = processes.state.lock().unwrap();
                    if state.starts != starts {
                        continue;
                    }
                    eprintln!("agent waitpid failed: {error}");
                    let failed = std::mem::take(&mut state.running);
                    drop(state);
                    for (id, process) in failed {
                        report_exit(&processes, &writer, id, 255, process);
                    }
                }
            }
        }
    });
}

fn finish_child(processes: &ProcessTable, writer: &Writer, pid: Pid, code: i32) {
    let mut state = processes.state.lock().unwrap();
    let id = state
        .running
        .iter()
        .find_map(|(id, process)| (process.pid == pid).then_some(*id));
    if let Some(id) = id {
        let process = state.running.remove(&id).unwrap();
        drop(state);
        report_exit(processes, writer, id, code, process);
    }
    // PID 1 also adopts orphaned descendants. Reap them without reporting an
    // exit for a process the agent did not start through this protocol.
}

fn report_exit(processes: &ProcessTable, writer: &Writer, id: u64, code: i32, process: Running) {
    let _ = signal::killpg(process.pid, Signal::SIGKILL);
    process.outputs.finish();
    let writer = writer.clone();
    let processes = processes.clone();
    thread::spawn(move || {
        for handle in process.output_threads {
            let _ = handle.join();
        }
        let _ = transmit(&writer, Message::Exited { id, code });
        processes.state.lock().unwrap().outputs.remove(&id);
    });
}

#[cfg(test)]
mod tests {
    use std::os::{fd::OwnedFd, unix::net::UnixStream};

    use super::*;

    #[test]
    fn signal_all_refuses_to_broadcast_from_a_host_fixture() {
        assert_ne!(std::process::id(), 1);
        assert!(
            signal_all(libc::SIGKILL)
                .unwrap_err()
                .to_string()
                .contains("Guest PID 1")
        );
    }

    #[test]
    fn escaped_descendant_does_not_delay_exit_or_kill_another_exec() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "agent::tests::owned_exit_fixture_supervisor",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("KERNELET_OUTPUT_EXIT_SUPERVISOR", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "owned exit fixture failed: {output:?}"
        );
    }

    #[test]
    fn timed_out_exit_fixture_cleans_escaped_descendants() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "agent::tests::owned_exit_fixture_supervisor",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("KERNELET_OUTPUT_EXIT_SUPERVISOR", "1")
            .env("KERNELET_OUTPUT_EXIT_FORCE_TIMEOUT", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "timeout cleanup failed: {output:?}"
        );
    }

    // The isolated supervisor owns all descendants through subreaper adoption.
    // Capture to regular files: a descendant retaining stdout cannot block EOF.
    #[test]
    #[ignore = "isolated owner for descendant fixture"]
    fn owned_exit_fixture_supervisor() {
        if std::env::var_os("KERNELET_OUTPUT_EXIT_SUPERVISOR").is_none() {
            return;
        }
        // SAFETY: scalar prctl affects only this dedicated supervisor process.
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
            0
        );
        let path =
            std::env::temp_dir().join(format!("kernelet-exit-fixture-{}.log", std::process::id()));
        let capture = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        // Unlink immediately; the supervisor and fixture retain bounded ownership.
        std::fs::remove_file(path).unwrap();
        let mut fixture = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "agent::tests::escaped_descendant_holds_output_fixture",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("KERNELET_OUTPUT_EXIT_FIXTURE", "1")
            .stdout(capture.try_clone().unwrap())
            .stderr(capture.try_clone().unwrap())
            .spawn()
            .unwrap();
        let force_timeout = std::env::var_os("KERNELET_OUTPUT_EXIT_FORCE_TIMEOUT").is_some();
        let deadline = Instant::now()
            + if force_timeout {
                Duration::from_millis(250)
            } else {
                Duration::from_secs(8)
            };
        let status = loop {
            if let Some(status) = fixture.try_wait().unwrap() {
                break Some(status);
            }
            if Instant::now() >= deadline {
                fixture.kill().unwrap();
                fixture.wait().unwrap();
                break None;
            }
            thread::sleep(Duration::from_millis(20));
        };
        // No other work runs in this process. Unreaped children retain their PID
        // identity until waitpid, including adopted setsid descendants.
        let cleanup_deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let mut children = Vec::new();
            for entry in fs::read_dir("/proc/self/task").unwrap() {
                if let Ok(text) = fs::read_to_string(entry.unwrap().path().join("children")) {
                    children.extend(
                        text.split_whitespace()
                            .map(|pid| pid.parse::<i32>().unwrap()),
                    );
                }
            }
            for pid in children {
                let _ = signal::kill(Pid::from_raw(pid), Signal::SIGKILL);
            }
            match wait::waitpid(Pid::from_raw(-1), Some(wait::WaitPidFlag::WNOHANG)) {
                Err(Errno::ECHILD) => break,
                Ok(WaitStatus::StillAlive) | Err(Errno::EINTR) => {}
                Ok(_) => continue,
                Err(error) => panic!("fixture descendant reap failed: {error}"),
            }
            assert!(
                Instant::now() < cleanup_deadline,
                "fixture descendants did not terminate"
            );
            thread::sleep(Duration::from_millis(10));
        }
        let mut text = String::new();
        use std::io::Seek;
        let mut capture = capture;
        capture.rewind().unwrap();
        // Bound failure diagnostics independently from inherited descriptors.
        capture.take(1024 * 1024).read_to_string(&mut text).unwrap();
        if force_timeout {
            assert!(
                status.is_none(),
                "fixture unexpectedly finished before its forced timeout: {text}"
            );
        } else {
            assert!(
                status.is_some_and(|status| status.success()),
                "exit fixture failed or timed out: {text}"
            );
        }
    }

    // Run the fork fixture in its own process so subreaper adoption cannot
    // interfere with other tests. Regression: review 35d423a96, exit/EOF wait.
    #[test]
    #[ignore = "subprocess fixture for escaped descendant lifecycle"]
    fn escaped_descendant_holds_output_fixture() {
        if std::env::var_os("KERNELET_OUTPUT_EXIT_FIXTURE").is_none() {
            return;
        }
        // SAFETY: prctl receives scalar arguments and enables adoption only in
        // this isolated fixture process, whose descendants are explicitly reaped.
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
            0
        );
        let (stdout_read, stdout_write) = unistd::pipe().unwrap();
        let (stderr_read, stderr_write) = unistd::pipe().unwrap();
        let (pid_read, pid_write) = unistd::pipe().unwrap();
        // SAFETY: child branches use only async-signal-safe scalar syscalls;
        // all allocation, locking and Rust cleanup remain in the parent.
        let leader = unsafe {
            let leader = libc::fork();
            if leader == 0 {
                libc::close(stdout_read.as_raw_fd());
                libc::close(stderr_read.as_raw_fd());
                libc::close(pid_read.as_raw_fd());
                if libc::setsid() < 0 {
                    libc::_exit(120);
                }
                let descendant = libc::fork();
                if descendant == 0 {
                    if libc::setsid() < 0 {
                        libc::_exit(121);
                    }
                    let pid = libc::getpid().to_ne_bytes();
                    if libc::write(pid_write.as_raw_fd(), pid.as_ptr().cast(), pid.len()) != 4 {
                        libc::_exit(122);
                    }
                    libc::close(pid_write.as_raw_fd());
                    loop {
                        libc::pause();
                    }
                }
                if descendant < 0 {
                    libc::_exit(123);
                }
                let bytes = b"before exit\n";
                libc::write(stdout_write.as_raw_fd(), bytes.as_ptr().cast(), bytes.len());
                libc::_exit(23);
            }
            leader
        };
        assert!(leader > 0);
        drop(stdout_write);
        drop(stderr_write);
        drop(pid_write);
        let mut descendant_bytes = [0; 4];
        File::from(pid_read)
            .read_exact(&mut descendant_bytes)
            .unwrap();
        let descendant = Pid::from_raw(i32::from_ne_bytes(descendant_bytes));
        struct Descendant(Pid);
        impl Drop for Descendant {
            fn drop(&mut self) {
                let _ = signal::kill(self.0, Signal::SIGKILL);
                let _ = wait::waitpid(self.0, None);
            }
        }
        let _descendant = Descendant(descendant);
        if std::env::var_os("KERNELET_OUTPUT_EXIT_FORCE_TIMEOUT").is_some() {
            loop {
                thread::park();
            }
        }
        assert_eq!(
            wait::waitpid(Pid::from_raw(leader), None).unwrap(),
            WaitStatus::Exited(Pid::from_raw(leader), 23)
        );
        struct Sibling(std::process::Child);
        impl Drop for Sibling {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut sibling = Sibling(Command::new("/bin/sleep").arg("30").spawn().unwrap());
        let (server, mut client) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(4)))
            .unwrap();
        let writer = Arc::new(Mutex::new(File::from(OwnedFd::from(server))));
        let outputs = Arc::new(Outputs::new());
        outputs.ready(Stream::Stdout);
        outputs.ready(Stream::Stderr);
        let process = Running {
            pid: Pid::from_raw(leader),
            input: None,
            output_threads: vec![
                copy_output(
                    7,
                    Stream::Stdout,
                    File::from(stdout_read),
                    writer.clone(),
                    outputs.clone(),
                ),
                copy_output(
                    7,
                    Stream::Stderr,
                    File::from(stderr_read),
                    writer.clone(),
                    outputs.clone(),
                ),
            ],
            outputs: outputs.clone(),
            terminal: None,
        };
        let processes = Arc::new(Processes {
            state: Mutex::new(ProcessState {
                running: BTreeMap::new(),
                outputs: BTreeMap::from([(7, outputs)]),
                starts: 0,
            }),
            started: Condvar::new(),
        });
        let started = Instant::now();
        report_exit(&processes, &writer, 7, 23, process);
        let mut closed = [false; 2];
        let mut failed = [false; 2];
        let mut received = Vec::new();
        loop {
            match protocol::receive(&mut client).unwrap() {
                Message::Data {
                    stream: Stream::Stdout,
                    data,
                    ..
                } => received.extend(data),
                Message::OutputFailed { stream, .. } => {
                    failed[output_index(stream).unwrap()] = true
                }
                Message::Close { stream, .. } => {
                    let index = output_index(stream).unwrap();
                    assert!(
                        failed[index],
                        "truncated output must report its failure before Close"
                    );
                    closed[index] = true;
                }
                Message::Exited { id, code } => {
                    assert_eq!((id, code), (7, 23));
                    assert_eq!(closed, [true; 2]);
                    break;
                }
                message => panic!("unexpected lifecycle message: {message:?}"),
            }
        }
        assert_eq!(received, b"before exit\n");
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(
            sibling.0.try_wait().unwrap().is_none(),
            "another exec must remain alive"
        );
    }
}
