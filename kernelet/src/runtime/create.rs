// SPDX-License-Identifier: MPL-2.0

//! The create pipeline: filesystem artifacts, sandbox boot, and the handoff
//! of every descriptor to the holder that will serve the sandbox.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{DirBuilderExt, FileTypeExt, OpenOptionsExt},
            net::UnixStream,
        },
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};

use super::{Cli, Record, State, rootfs, run_hooks, validate_id};
use crate::{
    config::Config,
    fd,
    protocol::{self, Message},
    uapi::{self, CreateArgs, Sandbox},
};

/// Locations and resource limits shared by the CLI parser and the shim's
/// in-process create path, so the two entry points cannot drift apart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CreateSettings {
    cache: PathBuf,
    agent: PathBuf,
    mke2fs: PathBuf,
    vcpus: u16,
    max_grains: u32,
}

impl Default for CreateSettings {
    fn default() -> Self {
        Self {
            cache: super::DEFAULT_CACHE.into(),
            agent: super::DEFAULT_AGENT.into(),
            mke2fs: super::DEFAULT_MKE2FS.into(),
            vcpus: super::DEFAULT_VCPUS,
            max_grains: super::DEFAULT_MAX_GRAINS,
        }
    }
}

impl From<&Cli> for CreateSettings {
    fn from(cli: &Cli) -> Self {
        Self {
            cache: cli.cache.clone(),
            agent: cli.agent.clone(),
            mke2fs: cli.mke2fs.clone(),
            vcpus: cli.vcpus,
            max_grains: cli.max_grains,
        }
    }
}

pub(crate) struct CreateOutput<'a> {
    console_socket: Option<&'a Path>,
    pid_file: Option<&'a Path>,
    placement: HolderPlacement,
}

enum HolderPlacement {
    SeparateProcess,
    CurrentProcess,
}

/// Bounded wait for the freshly spawned holder to acknowledge ownership.
const HOLDER_HANDOFF_TIMEOUT_SECS: u64 = 10;

const LOG_LEVEL_ANNOTATION: &str = "org.asterinas.kernelet.log-level";
const IMAGE_CMDLINE: &str = "root=/dev/vda rootfstype=ext2 ro init=/sbin/kernelet-agent";

/// Carries one validated early-parser value through the existing boot command line.
fn image_cmdline(config: &Config) -> Result<String> {
    let Some(value) = config.annotations.get(LOG_LEVEL_ANNOTATION) else {
        return Ok(IMAGE_CMDLINE.to_owned());
    };
    // The kernel's early parser interprets the level. Restrict this unquoted
    // value to its accepted single tokens so it cannot add boot parameters.
    ensure!(
        matches!(
            value.as_str(),
            "0" | "1"
                | "2"
                | "3"
                | "4"
                | "5"
                | "6"
                | "7"
                | "8"
                | "off"
                | "emerg"
                | "alert"
                | "crit"
                | "error"
                | "err"
                | "warning"
                | "warn"
                | "notice"
                | "info"
                | "debug"
        ),
        "{LOG_LEVEL_ANNOTATION} must be a loglevel from 0 to 8 or a lowercase level name"
    );
    Ok(format!("{IMAGE_CMDLINE} loglevel={value}"))
}

const RQ1_IO_ANNOTATION: &str = "org.asterinas.kernelet.rq1-io";
const RQ1_RAM_BYTES: u64 = 4 * 1024 * 1024;
const RQ1_RAM_MAGIC: &[u8] = b"KerneletRQ1RAMv1";

/// Selects the opt-in diagnostic device. One rootfs guarantees that the
/// additional backing is vdb, as required by the in-kernel probe.
fn rq1_io_requested(config: &Config, root_images: usize) -> Result<bool> {
    let Some(value) = config.annotations.get(RQ1_IO_ANNOTATION) else {
        return Ok(false);
    };
    ensure!(value == "ram", "{RQ1_IO_ANNOTATION} only accepts 'ram'");
    ensure!(
        root_images == 1,
        "RQ1 RAM I/O requires exactly one rootfs image so the fixture is vdb"
    );
    Ok(true)
}

fn validate_rq1_ram(backing: &mut (impl Read + Seek)) -> Result<()> {
    ensure!(
        backing.seek(SeekFrom::End(0))? == RQ1_RAM_BYTES,
        "RQ1 RAM fixture must be exactly 4 MiB"
    );
    backing.seek(SeekFrom::Start(0))?;
    let mut magic = [0u8; RQ1_RAM_MAGIC.len()];
    backing
        .read_exact(&mut magic)
        .context("read RQ1 RAM fixture magic")?;
    ensure!(magic == RQ1_RAM_MAGIC, "RQ1 RAM fixture magic differs");
    backing.seek(SeekFrom::Start(0))?;
    Ok(())
}

/// Only the Host diagnostic device is accepted, never an annotation-supplied
/// pathname. Normal kernels do not register this device.
fn open_rq1_ram() -> Result<File> {
    let mut backing = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/dev/rq1ram")
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                std::io::Error::from_raw_os_error(libc::ENODEV)
            } else {
                error
            }
        })
        .context("open diagnostic Host /dev/rq1ram")?;
    ensure!(
        backing.metadata()?.file_type().is_block_device(),
        "RQ1 RAM fixture must be a block device"
    );
    validate_rq1_ram(&mut backing)?;
    Ok(backing)
}

pub(crate) fn create_for_shim(root: &Path, id: &str, bundle: &Path) -> Result<()> {
    validate_id(id)?;
    let bundle = bundle.canonicalize()?;
    let directory = root.join(id);
    let mut config: Config = serde_json::from_reader(File::open(bundle.join("config.json"))?)?;
    config.validate()?;
    fs::create_dir_all(root)?;
    fs::DirBuilder::new().mode(0o700).create(&directory)?;
    let result = create_inner(
        &CreateSettings::default(),
        id,
        &bundle,
        &directory,
        &mut config,
        CreateOutput {
            console_socket: None,
            pid_file: None,
            placement: HolderPlacement::CurrentProcess,
        },
    );
    if result.is_err() {
        let _ = fs::remove_dir_all(directory);
    }
    result
}

pub(super) fn create(
    cli: &Cli,
    id: &str,
    bundle: &Path,
    directory: &Path,
    console_socket: Option<&Path>,
    pid_file: Option<&Path>,
) -> Result<()> {
    let bundle = bundle.canonicalize()?;
    let mut config: Config = serde_json::from_reader(File::open(bundle.join("config.json"))?)?;
    config.validate()?;
    ensure!(
        console_socket.is_none() || config.process.terminal,
        "--console-socket requires terminal=true"
    );
    fs::create_dir_all(&cli.root)?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(directory)
        .context("create state directory (container ID must be unused)")?;
    let result = create_inner(
        &CreateSettings::from(cli),
        id,
        &bundle,
        directory,
        &mut config,
        CreateOutput {
            console_socket,
            pid_file,
            placement: HolderPlacement::SeparateProcess,
        },
    );
    if result.is_err() {
        let _ = fs::remove_dir_all(directory);
    }
    result
}

fn create_inner(
    settings: &CreateSettings,
    id: &str,
    bundle: &Path,
    directory: &Path,
    config: &mut Config,
    output: CreateOutput<'_>,
) -> Result<()> {
    let CreateOutput {
        console_socket,
        pid_file,
        placement,
    } = output;
    // Phase 1 — filesystem artifacts: immutable rootfs images, the initial
    // on-disk record, and the OCI setup hooks. Failures here leave only the
    // state directory, which the entry points above remove.
    let (images, record) = stage_state(settings, id, bundle, directory, config)?;
    // Phase 2 — one sandbox capability: create it, attach every device, and
    // finish the agent handshake. The value owns the cleanup transaction for
    // everything after creation; dropping it while armed tears the sandbox down.
    let mut boot =
        BootedSandbox::boot(settings, config, &images, record, directory, console_socket)?;
    // Phase 3 — transfer descriptor ownership to the serving holder.
    let result = boot.handoff(directory, placement, pid_file);
    if result.is_ok() {
        boot.capability.armed = false;
    }
    result
}

/// Phase 1: build the rootfs images, write the initial record, and run the
/// OCI setup hooks.
fn stage_state(
    settings: &CreateSettings,
    id: &str,
    bundle: &Path,
    directory: &Path,
    config: &mut Config,
) -> Result<(Vec<PathBuf>, RecordFile)> {
    let images = rootfs::build(
        config,
        bundle,
        &settings.cache,
        &settings.agent,
        &settings.mke2fs,
    )?;
    let record = RecordFile::create(directory, id, bundle, config)?;
    run_hooks(directory, "prestart")?;
    run_hooks(directory, "createRuntime")?;
    Ok((images, record))
}

/// The durable `config.json` record: the OCI state plus the resolved config.
/// It is written once up front and rewritten when creation resolves more of
/// the configuration (guest networking and the CREATE-assigned CID).
struct RecordFile {
    record: Record,
    file: File,
}

impl RecordFile {
    fn create(directory: &Path, id: &str, bundle: &Path, config: &Config) -> Result<Self> {
        let record = Record {
            state: State {
                oci_version: config.oci_version.clone(),
                id: id.into(),
                status: "creating".into(),
                pid: 0,
                bundle: bundle.into(),
                annotations: config.annotations.clone(),
            },
            config: config.clone(),
            vsock_cid: None,
        };
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join("config.json"))
            .context("write sandbox state record")?;
        serde_json::to_writer(&mut file, &record)?;
        file.sync_all()?;
        Ok(Self { record, file })
    }

    /// Rewrites the record in place with the further-resolved configuration.
    fn persist(&mut self, config: &Config, cid: u32) -> Result<()> {
        super::vsock::Identity::new(&self.record.state.id, Some(cid))?;
        self.record.config = config.clone();
        self.record.vsock_cid = Some(cid);
        self.file.set_len(0)?;
        self.file.seek(SeekFrom::Start(0))?;
        serde_json::to_writer(&mut self.file, &self.record)?;
        self.file.sync_all()?;
        Ok(())
    }
}

/// Owns sandbox cleanup from creation until the holder accepts the descriptors.
struct SandboxCleanup {
    sandbox: Sandbox,
    armed: bool,
}

impl Drop for SandboxCleanup {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.sandbox.kill(0);
            let _ = self.sandbox.destroy();
        }
    }
}

/// Endpoints and the capability handed to the serving holder.
struct BootedSandbox {
    capability: SandboxCleanup,
    agent: File,
    console: File,
    log: File,
    terminal: Option<File>,
}

impl BootedSandbox {
    /// Phase 2: create the sandbox capability, attach all devices, resolve
    /// guest networking, and complete the agent handshake.
    fn boot(
        settings: &CreateSettings,
        config: &mut Config,
        images: &[PathBuf],
        mut record: RecordFile,
        directory: &Path,
        console_socket: Option<&Path>,
    ) -> Result<Self> {
        let mut args = create_args(settings, config)?;
        let rq1_ram = if rq1_io_requested(config, images.len())? {
            Some(open_rq1_ram()?)
        } else {
            None
        };
        // The content-addressed base image is immutable. The guest overlays it
        // with a writable upper layer before applying OCI's root.readonly flag.
        let cmdline = image_cmdline(config)?;
        let capability = SandboxCleanup {
            sandbox: Sandbox::create(&mut args, &cmdline).context("create kernelet sandbox")?,
            armed: true,
        };
        let sandbox = &capability.sandbox;
        config.network = crate::network::configure(&config.annotations, args.out_cid)?;
        record.persist(config, args.out_cid)?;
        // The image's VirtIO MMIO driver pops transports in reverse attachment
        // order. With exactly one root image, attaching RAM first keeps the
        // root at /dev/vda and the diagnostic backing at /dev/vdb.
        if let Some(backing) = rq1_ram {
            sandbox
                .attach(uapi::BLOCK, Some(&backing), 0)
                .context("attach diagnostic RQ1 RAM backing as vdb")?;
        }
        // Reverse discovery must preserve root=vda and bind1=vdb, bind2=vdc.
        for image in images.iter().rev() {
            let block = uapi::open_image(image)?;
            sandbox
                .attach(uapi::BLOCK, Some(&block), uapi::BLOCK_READ_ONLY)
                .with_context(|| format!("attach rootfs image {}", image.display()))?;
        }
        let log = sandbox.endpoint(uapi::LOG).context("open log endpoint")?;
        let console = sandbox
            .endpoint(uapi::CONSOLE)
            .context("open console endpoint")?;
        sandbox
            .attach(uapi::CONSOLE, Some(&console), 0)
            .context("attach console")?;
        sandbox.attach(uapi::RNG, None, 0).context("attach RNG")?;
        sandbox
            .attach(uapi::VSOCK, None, 0)
            .context("attach vsock")?;
        if let Some(network) = &config.network {
            let endpoint = sandbox
                .endpoint(uapi::NET)
                .context("open network endpoint")?;
            // The Host binds mapped ports synchronously, so occupied ports
            // fail creation before the container is acknowledged.
            crate::network::configure_host(&endpoint, network)
                .context("configure Host network forwarding")?;
            let mut mac = [0; 8];
            mac[..6].copy_from_slice(&network.mac);
            sandbox
                .attach_with_arg(uapi::NET, Some(&endpoint), 0, u64::from_le_bytes(mac))
                .context("attach network")?;
            // Forwarding belongs to the Host kernel: the endpoint descriptor
            // is dropped here instead of being handed off, and the runtime
            // performs no payload I/O on it.
        }
        let mut agent = sandbox
            .listen(protocol::AGENT_PORT)
            .context("listen for the guest agent")?;
        sandbox.start().context("start kernelet")?;
        let mut output = BootOutput::new(&log, &console, directory)?;
        ensure!(
            matches!(
                wait_for_agent_message(&mut agent, sandbox, &mut output, "Hello")?,
                Message::Hello {
                    version: protocol::VERSION
                }
            ),
            "agent protocol version mismatch: {}",
            boot_diagnostics(sandbox, &output)
        );
        protocol::send(
            &mut agent,
            &Message::Prepare {
                config: Box::new(config.clone()),
            },
        )?;
        match wait_for_agent_message(&mut agent, sandbox, &mut output, "preparation")? {
            Message::Prepared => {}
            Message::Error { detail } => bail!("agent preparation failed: {detail}"),
            _ => bail!(
                "unexpected agent preparation response: {}",
                boot_diagnostics(sandbox, &output)
            ),
        }
        let terminal = open_terminal(console_socket)?;
        Ok(Self {
            capability,
            agent,
            console,
            log,
            terminal,
        })
    }

    /// Phase 3: transfer descriptor ownership to the serving holder.
    fn handoff(
        &mut self,
        directory: &Path,
        placement: HolderPlacement,
        pid_file: Option<&Path>,
    ) -> Result<()> {
        match placement {
            HolderPlacement::CurrentProcess => {
                let mut files = vec![
                    self.capability.sandbox.file().try_clone()?,
                    self.agent.try_clone()?,
                    self.console.try_clone()?,
                    self.log.try_clone()?,
                ];
                if let Some(terminal) = &self.terminal {
                    files.push(terminal.try_clone()?);
                }
                super::holder::start_in_process(directory, files)
            }
            HolderPlacement::SeparateProcess => self.spawn_holder(directory, pid_file),
        }
    }

    /// Spawns the holder process and waits, bounded, until it acknowledges
    /// descriptor ownership; a failed handoff kills and reaps the holder.
    fn spawn_holder(&mut self, directory: &Path, pid_file: Option<&Path>) -> Result<()> {
        let holder_log = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(directory.join("holder.log"))?;
        let mut child = Command::new(std::env::current_exe()?)
            .arg("holder")
            .arg(directory)
            .stdin(Stdio::null())
            .stdout(holder_log.try_clone()?)
            .stderr(holder_log)
            .spawn()?;
        let result = (|| {
            let deadline = Instant::now() + Duration::from_secs(HOLDER_HANDOFF_TIMEOUT_SECS);
            let mut connection = loop {
                match UnixStream::connect(directory.join("control.sock")) {
                    Ok(stream) => break stream,
                    Err(error) if Instant::now() < deadline => {
                        if let Some(status) = child.try_wait()? {
                            bail!("holder exited before handoff: {status}: {error}");
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => return Err(error.into()),
                }
            };
            connection.set_read_timeout(Some(Duration::from_secs(10)))?;
            let mut descriptors = vec![
                self.capability.sandbox.file().as_raw_fd(),
                self.agent.as_raw_fd(),
                self.console.as_raw_fd(),
                self.log.as_raw_fd(),
            ];
            if let Some(terminal) = &self.terminal {
                descriptors.push(terminal.as_raw_fd());
            }
            fd::send(&connection, &descriptors)?;
            ensure!(
                matches!(
                    protocol::receive_value::<super::Reply>(&mut connection)?,
                    super::Reply::Ready
                ),
                "holder did not acknowledge ownership"
            );
            if let Some(path) = pid_file {
                fs::write(path, child.id().to_string())?;
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        result
    }
}

/// Hands the master side of a fresh pty to the console-socket consumer and
/// keeps the slave for the holder.
fn open_terminal(console_socket: Option<&Path>) -> Result<Option<File>> {
    let Some(socket) = console_socket else {
        return Ok(None);
    };
    let pty = nix::pty::openpty(None, None)?;
    let mut settings = nix::sys::termios::tcgetattr(&pty.slave)?;
    nix::sys::termios::cfmakeraw(&mut settings);
    nix::sys::termios::tcsetattr(&pty.slave, nix::sys::termios::SetArg::TCSANOW, &settings)?;
    fd::send(&UnixStream::connect(socket)?, &[pty.master.as_raw_fd()])?;
    Ok(Some(File::from(pty.slave)))
}

fn create_args(settings: &CreateSettings, config: &Config) -> Result<CreateArgs> {
    let mut args = CreateArgs {
        num_vcpus: settings.vcpus,
        max_grains: settings.max_grains,
        max_tasks: 256,
        oops_budget: 4,
        log_bytes_per_sec: 64 * 1024,
        ..Default::default()
    };
    if let Some(limit) = config
        .linux
        .pointer("/resources/memory/limit")
        .and_then(|value| value.as_i64())
        .filter(|value| *value >= 0)
    {
        args.max_grains = (limit as u64 / kernelet_abi::GRAIN_SIZE_BYTES).try_into()?;
    }
    args.initial_grains = (args.max_grains / 4).max(16).min(args.max_grains);
    args.max_meta_sections = args.max_grains;
    ensure!(
        args.max_grains > 0,
        "memory limit must cover at least one grain"
    );
    if let Some(cpu) = config.linux.pointer("/resources/cpu") {
        if let Some(cpus) = cpu
            .get("cpus")
            .and_then(|value| value.as_str())
            .filter(|value| !value.is_empty())
        {
            args.num_vcpus = cpuset_count(cpus)?;
        }
        if let Some(shares) = cpu.get("shares").and_then(|value| value.as_u64()) {
            ensure!(shares > 0, "cpu shares must be positive");
            args.nice = (10.0 - (shares as f64).log2())
                .round()
                .clamp(kernelet_abi::MIN_NICE as f64, kernelet_abi::MAX_NICE as f64)
                as i8;
        }
        if let Some(quota) = cpu
            .get("quota")
            .and_then(|value| value.as_i64())
            .filter(|value| *value > 0)
        {
            args.cpu_quota_us = quota.try_into()?;
            args.cpu_period_us = cpu
                .get("period")
                .and_then(|value| value.as_u64())
                .unwrap_or(100_000)
                .try_into()?;
        }
    }
    Ok(args)
}

fn cpuset_count(value: &str) -> Result<u16> {
    let mut cpus = std::collections::BTreeSet::new();
    for item in value.split(',') {
        let (start, end) = if let Some((first, last)) = item.split_once('-') {
            (first.parse::<u16>()?, last.parse::<u16>()?)
        } else {
            let cpu = item.parse::<u16>()?;
            (cpu, cpu)
        };
        ensure!(start <= end, "invalid cpuset range");
        cpus.extend(start..=end);
    }
    Ok(cpus.len().try_into()?)
}

const BOOT_OUTPUT_TAIL_BYTES: usize = 8 * 1024;
const BOOT_OUTPUT_RECORDS_PER_POLL: usize = 32;

/// Persists both early output streams until the holder takes over their FDs.
struct BootOutput<'a> {
    log: &'a File,
    console: &'a File,
    kernel_file: File,
    console_file: File,
    kernel_tail: Vec<u8>,
    console_tail: Vec<u8>,
}

impl<'a> BootOutput<'a> {
    fn new(log: &'a File, console: &'a File, directory: &Path) -> Result<Self> {
        let open_output = |name| {
            OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(directory.join(name))
        };
        Ok(Self {
            log,
            console,
            kernel_file: open_output("kernel.log")?,
            console_file: open_output("console.log")?,
            kernel_tail: Vec::new(),
            console_tail: Vec::new(),
        })
    }

    fn drain(&mut self) -> Result<()> {
        drain_boot_endpoint(self.log, &mut self.kernel_file, &mut self.kernel_tail)?;
        drain_boot_endpoint(self.console, &mut self.console_file, &mut self.console_tail)
    }
}

/// Waits for one agent message while draining both bounded device queues.
fn wait_for_agent_message(
    agent: &mut File,
    sandbox: &Sandbox,
    output: &mut BootOutput<'_>,
    phase: &str,
) -> Result<Message> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        output.drain()?;
        let status = sandbox.status().context("query kernelet boot status")?;
        if matches!(
            status.state,
            uapi::STATE_EXITED | uapi::STATE_DESTROYING | uapi::STATE_DESTROYED
        ) {
            bail!(
                "agent exited before {phase}: {}",
                boot_diagnostics(sandbox, output)
            );
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!(
                "agent {phase} timed out: {}",
                boot_diagnostics(sandbox, output)
            );
        }
        let mut descriptors = [
            libc::pollfd {
                fd: agent.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: output.log.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: output.console.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let timeout = remaining.as_millis().min(500).try_into()?;
        // SAFETY: all descriptors remain valid and the array has three entries.
        let ready = unsafe { libc::poll(descriptors.as_mut_ptr(), 3, timeout) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error).context("wait for guest agent and boot output");
            }
            continue;
        }
        if descriptors[1].revents & libc::POLLIN != 0 || descriptors[2].revents & libc::POLLIN != 0
        {
            output.drain()?;
        }
        if descriptors[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            return protocol::receive(agent).with_context(|| {
                let _ = output.drain();
                format!(
                    "read guest agent message during {phase}: {}",
                    boot_diagnostics(sandbox, output)
                )
            });
        }
    }
}

fn drain_boot_endpoint(source: &File, output: &mut File, tail: &mut Vec<u8>) -> Result<()> {
    for _ in 0..BOOT_OUTPUT_RECORDS_PER_POLL {
        let mut descriptor = libc::pollfd {
            fd: source.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: the source descriptor remains valid and contains one poll entry.
        let ready = unsafe { libc::poll(&mut descriptor, 1, 0) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error).context("poll boot output endpoint");
        }
        if ready == 0 || descriptor.revents & libc::POLLIN == 0 {
            break;
        }
        let mut record = [0; 256];
        let length = (&mut &*source)
            .read(&mut record)
            .context("read boot output endpoint")?;
        if length == 0 {
            break;
        }
        output.write_all(&record[..length])?;
        tail.extend_from_slice(&record[..length]);
        if tail.len() > BOOT_OUTPUT_TAIL_BYTES {
            tail.drain(..tail.len() - BOOT_OUTPUT_TAIL_BYTES);
        }
    }
    Ok(())
}

fn diagnostic_counter(value: u64) -> String {
    if value == kernelet_abi::STATS_UNAVAILABLE {
        "unavailable".to_owned()
    } else {
        value.to_string()
    }
}

fn boot_diagnostics(sandbox: &Sandbox, output: &BootOutput<'_>) -> String {
    let status = match sandbox.status() {
        Ok(status) => {
            let length = (status.message_len as usize).min(status.message.len());
            format!(
                "state={} reason={} code={} fault_ip={:#x} fault_addr={:#x} message={:?}",
                status.state,
                status.reason,
                status.code,
                status.fault_ip,
                status.fault_addr,
                String::from_utf8_lossy(&status.message[..length])
            )
        }
        Err(error) => format!("STATUS failed: {error:#}"),
    };
    let stats = match sandbox.stats() {
        Ok(stats) => format!(
            "grains={}/{} stacks={} oopses={} cpu_ns={} throttled_ns={} services={} mmio={} irqs={} host_overhead_bytes={} log_dropped={}",
            stats.grains_granted,
            stats.max_grains,
            stats.stacks_allocated,
            stats.oopses,
            stats.cpu_time_ns,
            stats.throttled_ns,
            diagnostic_counter(stats.service_calls),
            diagnostic_counter(stats.mmio_accesses),
            diagnostic_counter(stats.irqs_raised),
            stats.host_overhead_bytes,
            stats.log_records_dropped
        ),
        Err(error) => format!("STATS failed: {error:#}"),
    };
    format!(
        "STATUS({status}); STATS({stats}); kernel log tail ({} bytes): {}; console tail ({} bytes): {}",
        output.kernel_tail.len(),
        String::from_utf8_lossy(&output.kernel_tail),
        output.console_tail.len(),
        String::from_utf8_lossy(&output.console_tail)
    )
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    fn log_level_config(value: Option<&str>) -> Config {
        let mut config: Config = serde_json::from_value(serde_json::json!({
            "ociVersion": "1.0.2",
            "root": { "path": "rootfs" },
            "process": { "args": ["/bin/sh"], "cwd": "/" },
        }))
        .unwrap();
        if let Some(value) = value {
            config
                .annotations
                .insert(LOG_LEVEL_ANNOTATION.into(), value.into());
        }
        config
    }

    #[test]
    fn image_cmdline_preserves_unspecified_image_log_level() {
        assert_eq!(
            image_cmdline(&log_level_config(None)).unwrap(),
            "root=/dev/vda rootfstype=ext2 ro init=/sbin/kernelet-agent"
        );
    }

    #[test]
    fn image_cmdline_passes_one_valid_log_level_token() {
        for value in [
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "off", "emerg", "alert", "crit", "error",
            "err", "warning", "warn", "notice", "info", "debug",
        ] {
            assert_eq!(
                image_cmdline(&log_level_config(Some(value))).unwrap(),
                format!(
                    "root=/dev/vda rootfstype=ext2 ro init=/sbin/kernelet-agent loglevel={value}"
                )
            );
        }
    }

    #[test]
    fn image_cmdline_rejects_invalid_or_injected_log_levels() {
        for value in [
            "",
            "9",
            "99",
            "-1",
            "Trace",
            "trace",
            "Error",
            "error ",
            " error",
            "error init=/bin/sh",
            "error\ninit=/bin/sh",
            "error\0",
            "\"error\"",
            "error --",
            "error;reboot",
        ] {
            let error = image_cmdline(&log_level_config(Some(value))).unwrap_err();
            assert!(
                error.to_string().contains(LOG_LEVEL_ANNOTATION),
                "{value:?}: {error}"
            );
        }
    }

    #[test]
    fn rq1_ram_attachment_requires_explicit_annotation_and_one_root_image() {
        let mut config: Config = serde_json::from_value(serde_json::json!({
            "ociVersion": "1.0.2",
            "root": { "path": "rootfs" },
            "process": { "args": ["/bin/sh"], "cwd": "/" },
        }))
        .unwrap();
        assert!(!rq1_io_requested(&config, 1).unwrap());
        config
            .annotations
            .insert(RQ1_IO_ANNOTATION.into(), "ram".into());
        assert!(rq1_io_requested(&config, 1).unwrap());
        for count in [0, 2] {
            assert!(rq1_io_requested(&config, count).is_err());
        }
        for value in ["", "disk", "/dev/vda", "RAM"] {
            config
                .annotations
                .insert(RQ1_IO_ANNOTATION.into(), value.into());
            assert!(rq1_io_requested(&config, 1).is_err());
        }
    }

    #[test]
    fn rq1_ram_validation_checks_capacity_magic_and_resets_offset() {
        let mut bytes = vec![0u8; RQ1_RAM_BYTES as usize];
        bytes[..RQ1_RAM_MAGIC.len()].copy_from_slice(RQ1_RAM_MAGIC);
        let mut backing = std::io::Cursor::new(bytes);
        backing.set_position(123);
        validate_rq1_ram(&mut backing).unwrap();
        assert_eq!(backing.position(), 0);
        backing.get_mut()[0] ^= 1;
        assert!(validate_rq1_ram(&mut backing).is_err());
        backing.get_mut()[0] ^= 1;
        backing.get_mut().pop();
        assert!(validate_rq1_ram(&mut backing).is_err());
        backing.get_mut().extend_from_slice(&[0, 0]);
        assert!(validate_rq1_ram(&mut backing).is_err());
    }

    #[test]
    fn shim_create_defaults_match_the_parsed_cli() {
        let cli = Cli::parse_from(["kernelet-runtime", "create", "test", "--bundle", "/tmp"]);
        // The shim's create path must share the CLI's defaults instead of
        // repeating them, without fabricating a command-line operation.
        assert_eq!(CreateSettings::default(), CreateSettings::from(&cli));
    }

    #[test]
    fn unspecified_memory_limit_leaves_headroom_for_host_execution() {
        let cli = Cli::parse_from(["kernelet-runtime", "create", "test", "--bundle", "/tmp"]);
        let settings = CreateSettings::from(&cli);
        let mut config: Config = serde_json::from_value(serde_json::json!({
            "ociVersion": "1.0.2",
            "root": { "path": "rootfs" },
            "process": { "args": ["/bin/sh"], "cwd": "/" },
        }))
        .unwrap();

        for linux in [
            serde_json::json!({}),
            serde_json::json!({
                "resources": { "memory": { "limit": -1 } }
            }),
        ] {
            config.linux = linux;
            let args = create_args(&settings, &config).unwrap();
            assert_eq!(args.max_grains, super::super::DEFAULT_MAX_GRAINS);
            assert_eq!(args.max_grains, 256);
            assert_eq!(args.initial_grains, 64);
            assert_eq!(args.max_meta_sections, super::super::DEFAULT_MAX_GRAINS);
        }
    }

    #[test]
    fn memory_limit_converts_bytes_to_grains() {
        let settings = CreateSettings::default();
        let config: Config = serde_json::from_value(serde_json::json!({
            "ociVersion": "1.0.2",
            "root": { "path": "rootfs" },
            "process": { "args": ["/bin/sh"], "cwd": "/" },
            "linux": { "resources": { "memory": { "limit": 8388608 } } },
        }))
        .unwrap();
        let args = create_args(&settings, &config).unwrap();
        assert_eq!(
            u64::from(args.max_grains),
            8388608 / kernelet_abi::GRAIN_SIZE_BYTES
        );
        assert_eq!(args.max_grains, 4);
    }
}
