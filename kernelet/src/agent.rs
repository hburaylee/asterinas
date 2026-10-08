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

struct Processes {
    state: Mutex<ProcessState>,
    started: Condvar,
}

struct ProcessState {
    running: BTreeMap<u64, Running>,
    starts: u64,
}

struct Running {
    pid: Pid,
    input: Option<mpsc::SyncSender<Option<Vec<u8>>>>,
    output_threads: Vec<thread::JoinHandle<()>>,
    terminal: Option<File>,
}

struct ProcessIo {
    input: Box<dyn Write + Send>,
    outputs: Vec<(Stream, Box<dyn Read + Send>)>,
    terminal_control: Option<File>,
}

pub fn run() -> Result<()> {
    ensure!(std::process::id() == 1, "agent must run as PID 1");
    prepare_overlay().context("prepare writable guest root")?;
    let mut connection =
        uapi::connect_agent(protocol::AGENT_PORT).context("connect to host runtime")?;
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
    if let Some(network) = &config.network {
        crate::network::configure_guest(network)?;
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
            outputs: vec![(Stream::Stdout, Box::new(master))],
            terminal_control: Some(control_master),
        }
    } else {
        ProcessIo {
            input: Box::new(child.stdin.take().unwrap()),
            outputs: vec![
                (Stream::Stdout, Box::new(child.stdout.take().unwrap())),
                (Stream::Stderr, Box::new(child.stderr.take().unwrap())),
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
    state.running.insert(
        id,
        Running {
            pid: Pid::from_raw(pid as i32),
            input: Some(input_sender),
            output_threads: Vec::new(),
            terminal: terminal_control,
        },
    );
    state.starts = state.starts.wrapping_add(1);
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
            if input.write_all(&data).is_err() {
                break;
            }
            if transmit(&input_writer, Message::InputReady { id }).is_err() {
                break;
            }
        }
    });
    state.running.get_mut(&id).unwrap().output_threads = outputs
        .into_iter()
        .map(|(stream, output)| copy_output(id, stream, output, writer.clone()))
        .collect();
    processes.started.notify_one();
    Ok(())
}

fn copy_output(
    id: u64,
    stream: Stream,
    mut output: impl Read + Send + 'static,
    writer: Writer,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut bytes = vec![0; protocol::STREAM_CHUNK_BYTES];
        loop {
            match output.read(&mut bytes) {
                Ok(0) => break,
                Ok(length) => {
                    if transmit(
                        &writer,
                        Message::Data {
                            id,
                            stream,
                            data: bytes[..length].to_vec(),
                        },
                    )
                    .is_err()
                    {
                        break;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
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
            while state.running.is_empty() {
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
                        report_exit(&writer, id, 255, process);
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
                        report_exit(&writer, id, 255, process);
                    }
                }
            }
        }
    });
}

fn finish_child(processes: &Processes, writer: &Writer, pid: Pid, code: i32) {
    let mut state = processes.state.lock().unwrap();
    let id = state
        .running
        .iter()
        .find_map(|(id, process)| (process.pid == pid).then_some(*id));
    if let Some(id) = id {
        let process = state.running.remove(&id).unwrap();
        drop(state);
        report_exit(writer, id, code, process);
    }
    // PID 1 also adopts orphaned descendants. Reap them without reporting an
    // exit for a process the agent did not start through this protocol.
}

fn report_exit(writer: &Writer, id: u64, code: i32, process: Running) {
    let _ = signal::killpg(process.pid, Signal::SIGKILL);
    let writer = writer.clone();
    thread::spawn(move || {
        for handle in process.output_threads {
            let _ = handle.join();
        }
        let _ = transmit(&writer, Message::Exited { id, code });
    });
}
