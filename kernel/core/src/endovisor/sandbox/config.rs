// SPDX-License-Identifier: MPL-2.0

//! Staged configuration of a sandbox before it starts: endpoint creation,
//! device attachments, and vsock service setup.

use core::sync::atomic::{AtomicU32, Ordering};

use kernelet_abi::{
    AttachArgs, BLOCK, BLOCK_READ_ONLY, CONSOLE, CreateArgs, EndpointArgs, LOG, NET, RNG, VSOCK,
    VsockArgs, VsockPolicyArgs,
};
use ostd::{
    kernelet::control::{CpuBudget, KerneletPolicy},
    sync::WaitQueue,
    task::Task,
};

use super::{
    SandboxFile, SandboxState,
    devices::{DeviceSlot, MMIO_CMDLINE_PREFIX},
};
use crate::{
    endovisor::{
        log_endpoint::LogEndpoint,
        policy::PrestartEndpointReservation,
        virtio_console::{ConsoleEndpoint, EndpointFile},
        virtio_net::{NetEndpoint, NetEndpointFile},
        vsock_switch,
    },
    fs::{
        file::{AccessMode, FileCommon, FileLike, SeekFrom, StatusFlags, file_table::FdFlags},
        pseudofs::AnonInodeFs,
    },
    prelude::*,
    process::{posix_thread::AsPosixThread, signal::Pollee},
    thread::Thread,
};

const MAX_CMDLINE_BYTES: usize = 1024;
// VirtIO 1.3, section 5.10.4: CIDs 0 and 1 are reserved, and CID 2 is the Host.
const FIRST_GUEST_CID: u32 = 3;
static NEXT_CID: AtomicU32 = AtomicU32::new(FIRST_GUEST_CID);

/// The configuration staged by `KERNELET_CREATE` and ATTACH ioctls.
pub(super) struct Pending {
    pub(super) cmdline: String,
    pub(super) initial_grains: u32,
    pub(super) max_grains: u32,
    pub(super) max_meta_sections: u32,
    pub(super) max_tasks: u32,
    pub(super) num_vcpus: u16,
    pub(super) budget: CpuBudget,
    pub(super) policy: KerneletPolicy,
    pub(super) blocks: Vec<BlockAttachment>,
    pub(super) console: Option<Arc<ConsoleEndpoint>>,
    pub(super) log: Option<Arc<LogEndpoint>>,
    pub(super) console_attached: bool,
    pub(super) console_vcpu: u16,
    pub(super) vsock_attached: bool,
    pub(super) vsock_vcpu: u16,
    pub(super) rng_attached: bool,
    pub(super) rng_vcpu: u16,
    pub(super) net: Option<Arc<NetEndpoint>>,
    pub(super) net_attached: bool,
    pub(super) net_vcpu: u16,
    pub(super) net_mac: [u8; 6],
    pub(super) endpoint_reservations: Vec<Arc<PrestartEndpointReservation>>,
}

impl Pending {
    /// Revokes every created endpoint, dropping staged buffers and waiters.
    pub(super) fn revoke_endpoints(&self) {
        if let Some(console) = &self.console {
            console.revoke();
        }
        if let Some(net) = &self.net {
            net.revoke();
        }
        if let Some(log) = &self.log {
            log.revoke();
        }
    }
}

/// One staged virtio-blk backing file.
pub(super) struct BlockAttachment {
    pub(super) backing: Arc<dyn FileLike>,
    pub(super) capacity_sectors: u64,
    pub(super) read_only: bool,
    pub(super) vcpu: u16,
}

impl SandboxFile {
    pub(super) fn create(mut args: CreateArgs) -> Result<(Arc<Self>, CreateArgs)> {
        if args.image != 0
            || args.num_vcpus == 0
            || args.num_vcpus as usize > ostd::cpu::num_cpus()
            || args.num_vcpus as usize > ostd::kernelet::abi::MAX_VCPUS
            || args.initial_grains == 0
            || args.max_grains < args.initial_grains
            || args.max_meta_sections == 0
            || args.max_tasks < u32::from(args.num_vcpus)
            || !(-20..=19).contains(&args.nice)
            || (args.cpu_quota_us != 0 && args.cpu_period_us <= 1_000)
            || args.reserved0 != [0; 3]
            || args.out_cid != 0
            || args.cmdline_len as usize > MAX_CMDLINE_BYTES
        {
            return_errno_with_message!(Errno::EINVAL, "unsupported kernelet configuration");
        }
        let mut bytes = vec![0u8; args.cmdline_len as usize];
        {
            let task = Task::current().unwrap();
            let thread_local = task.as_thread_local().unwrap();
            let user_space = CurrentUserSpace::new(thread_local);
            let mut reader = user_space.reader(args.cmdline_ptr as usize, bytes.len())?;
            reader.read_fallible(&mut VmWriter::from(bytes.as_mut_slice()))?;
        }
        let cmdline = String::from_utf8(bytes)
            .map_err(|_| Error::with_message(Errno::EINVAL, "invalid kernelet command line"))?;
        if cmdline
            .split_whitespace()
            .any(|arg| arg.starts_with(MMIO_CMDLINE_PREFIX))
        {
            return_errno_with_message!(Errno::EINVAL, "virtual devices are configured by ATTACH");
        }
        let cid = NEXT_CID
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                (next != u32::MAX).then(|| next + 1)
            })
            .map_err(|_| Error::with_message(Errno::ENOSPC, "kernelet CID space exhausted"))?;
        args.out_cid = cid;
        let common = FileCommon::new(
            AnonInodeFs::new_path(|_| "anon_inode:[kernelet]".into()),
            AccessMode::O_RDWR,
            StatusFlags::empty(),
        );
        let pending = Pending {
            cmdline,
            initial_grains: args.initial_grains,
            max_grains: args.max_grains,
            max_meta_sections: args.max_meta_sections,
            max_tasks: args.max_tasks,
            num_vcpus: args.num_vcpus,
            budget: CpuBudget {
                nice: args.nice,
                quota: (args.cpu_quota_us != 0).then_some((args.cpu_quota_us, args.cpu_period_us)),
            },
            policy: KerneletPolicy {
                oops_budget: args.oops_budget,
                log_bytes_per_sec: args.log_bytes_per_sec,
                ask_before_oom: true,
            },
            blocks: Vec::new(),
            console: None,
            log: None,
            console_attached: false,
            console_vcpu: 0,
            vsock_attached: false,
            vsock_vcpu: 0,
            rng_attached: false,
            rng_vcpu: 0,
            net: None,
            net_attached: false,
            net_vcpu: 0,
            net_mac: [0; 6],
            endpoint_reservations: Vec::with_capacity(3),
        };
        let owner = Thread::current()
            .unwrap()
            .as_posix_thread()
            .unwrap()
            .credentials()
            .euid();
        Ok((
            Arc::new(Self {
                common,
                state: Arc::new(Mutex::new(SandboxState::Configuring(pending))),
                pollee: Pollee::new(),
                start_waiters: WaitQueue::new(),
                cid,
                owner,
                admission: SpinLock::new(None),
            }),
            args,
        ))
    }

    pub(super) fn endpoint(&self, args: EndpointArgs) -> Result<i32> {
        if !matches!(args.kind, CONSOLE | NET | LOG) || args.reserved0 != 0 {
            return_errno_with_message!(Errno::EINVAL, "unsupported kernelet endpoint");
        }
        let console = (args.kind == CONSOLE).then(ConsoleEndpoint::new);
        let net = (args.kind == NET).then(|| NetEndpoint::new(self.owner));
        let log = (args.kind == LOG).then(LogEndpoint::new);
        let bytes = console
            .as_ref()
            .map_or(0, |endpoint| endpoint.reservation_bytes())
            + net
                .as_ref()
                .map_or(0, |endpoint| endpoint.reservation_bytes())
            + log
                .as_ref()
                .map_or(0, |endpoint| endpoint.reservation_bytes());
        let reservation = Arc::new(PrestartEndpointReservation::reserve(self.owner, bytes)?);
        {
            let mut state = self.state.lock();
            let SandboxState::Configuring(pending) = &mut *state else {
                return_errno_with_message!(Errno::EBUSY, "kernelet already started");
            };
            if args.kind == CONSOLE {
                if pending.console.is_some() {
                    return_errno_with_message!(Errno::EEXIST, "console endpoint already exists");
                }
                pending.console = console.clone();
            } else if args.kind == NET {
                if pending.net.is_some() {
                    return_errno_with_message!(Errno::EEXIST, "network endpoint already exists");
                }
                pending.net = net.clone();
            } else {
                if pending.log.is_some() {
                    return_errno_with_message!(Errno::EEXIST, "log endpoint already exists");
                }
                pending.log = log.clone();
            }
            pending.endpoint_reservations.push(reservation);
        }
        let task = Task::current().unwrap();
        let thread_local = task.as_thread_local().unwrap();
        let fd = thread_local.borrow_file_table().unwrap().write().insert(
            match (console, net, log) {
                (Some(endpoint), None, None) => endpoint.file(),
                (None, Some(endpoint), None) => endpoint.file(),
                (None, None, Some(endpoint)) => endpoint.file(),
                _ => unreachable!(),
            },
            FdFlags::CLOEXEC,
        );
        Ok(fd.into())
    }

    pub(super) fn attach(&self, mut args: AttachArgs) -> Result<AttachArgs> {
        if !matches!(args.kind, BLOCK | CONSOLE | VSOCK | NET | RNG)
            || (args.kind == BLOCK && args.flags & !BLOCK_READ_ONLY != 0)
            || (args.kind != BLOCK && args.flags != 0)
            || args.reserved0 != 0
            || args.out_index != 0
            || (args.kind != NET && args.arg != 0)
        {
            return_errno_with_message!(Errno::EINVAL, "invalid kernelet attachment");
        }
        if args.kind == NET {
            let mac = args.arg.to_le_bytes();
            if mac[6..] != [0; 2] || mac[..6] == [0; 6] || mac[0] & 1 != 0 {
                return_errno_with_message!(Errno::EINVAL, "invalid network MAC address");
            }
        }
        let file = if matches!(args.kind, VSOCK | RNG) {
            if args.backing_fd != -1 {
                return_errno_with_message!(Errno::EINVAL, "this device has no backing fd");
            }
            None
        } else {
            let fd = args
                .backing_fd
                .try_into()
                .map_err(|_| Error::with_message(Errno::EBADF, "invalid backing fd"))?;
            let task = Task::current().unwrap();
            let thread_local = task.as_thread_local().unwrap();
            Some(
                thread_local
                    .borrow_file_table()
                    .unwrap()
                    .read()
                    .get_file(fd)?
                    .clone(),
            )
        };
        let block = if args.kind == BLOCK {
            let file = file.as_ref().unwrap();
            let read_only = args.flags & BLOCK_READ_ONLY != 0;
            if !file.access_mode().is_readable()
                || (!read_only && !file.access_mode().is_writable())
            {
                return_errno_with_message!(Errno::EBADF, "block backing access mode is invalid");
            }
            let bytes = file.seek(SeekFrom::End(0))?;
            file.seek(SeekFrom::Start(0))?;
            if bytes == 0 || !bytes.is_multiple_of(512) {
                return_errno_with_message!(Errno::EINVAL, "block backing size is invalid");
            }
            Some(BlockAttachment {
                backing: file.clone(),
                capacity_sectors: (bytes / 512) as u64,
                read_only,
                vcpu: args.vcpu,
            })
        } else {
            None
        };
        let mut state = self.state.lock();
        let SandboxState::Configuring(pending) = &mut *state else {
            return_errno_with_message!(Errno::EBUSY, "kernelet already started");
        };
        if args.vcpu >= pending.num_vcpus {
            return_errno_with_message!(Errno::EINVAL, "invalid interrupt target vCPU");
        }
        if args.kind == CONSOLE {
            let endpoint = file
                .as_ref()
                .unwrap()
                .downcast_ref::<EndpointFile>()
                .ok_or_else(|| {
                    Error::with_message(Errno::EBADF, "console backing is not an endpoint")
                })?;
            let owned = pending.console.as_ref().ok_or_else(|| {
                Error::with_message(Errno::ENODEV, "console endpoint was not created")
            })?;
            if !Arc::ptr_eq(endpoint.endpoint(), owned) || pending.console_attached {
                return_errno_with_message!(Errno::EINVAL, "console endpoint cannot be attached");
            }
            pending.console_attached = true;
            pending.console_vcpu = args.vcpu;
            args.out_index = DeviceSlot::Console.wire_id();
        } else if args.kind == BLOCK {
            let next = pending.blocks.len();
            if next >= DeviceSlot::MAX_BLOCKS {
                return_errno_with_message!(Errno::ENOSPC, "too many block devices");
            }
            args.out_index = DeviceSlot::Block(next as u16).wire_id();
            pending.blocks.push(block.unwrap());
        } else if args.kind == NET {
            let endpoint = file
                .as_ref()
                .unwrap()
                .downcast_ref::<NetEndpointFile>()
                .ok_or_else(|| {
                    Error::with_message(Errno::EBADF, "network backing is not an endpoint")
                })?;
            let owned = pending.net.as_ref().ok_or_else(|| {
                Error::with_message(Errno::ENODEV, "network endpoint was not created")
            })?;
            if !Arc::ptr_eq(endpoint.endpoint(), owned)
                || pending.net_attached
                || !owned.is_configured()
            {
                return_errno_with_message!(Errno::EINVAL, "network endpoint cannot be attached");
            }
            pending.net_attached = true;
            pending.net_vcpu = args.vcpu;
            pending
                .net_mac
                .copy_from_slice(&args.arg.to_le_bytes()[..6]);
            args.out_index = DeviceSlot::Net.wire_id();
        } else if args.kind == VSOCK {
            if pending.vsock_attached {
                return_errno_with_message!(Errno::EEXIST, "vsock already attached");
            }
            pending.vsock_attached = true;
            pending.vsock_vcpu = args.vcpu;
            args.out_index = DeviceSlot::Vsock.wire_id();
        } else {
            if pending.rng_attached {
                return_errno_with_message!(Errno::EEXIST, "entropy device already attached");
            }
            pending.rng_attached = true;
            pending.rng_vcpu = args.vcpu;
            args.out_index = DeviceSlot::Rng.wire_id();
        }
        Ok(args)
    }

    pub(super) fn vsock_listen(&self, args: VsockArgs) -> Result<i32> {
        if args.port == 0 || args.flags != 0 {
            return_errno_with_message!(Errno::EINVAL, "invalid vsock listener");
        }
        {
            let state = self.state.lock();
            let SandboxState::Configuring(pending) = &*state else {
                return_errno_with_message!(Errno::EBUSY, "kernelet already started");
            };
            if !pending.vsock_attached {
                return_errno_with_message!(Errno::ENODEV, "vsock is not attached");
            }
        }
        let file = vsock_switch::listen(self.cid, args.port, self.owner)?;
        let task = Task::current().unwrap();
        let thread_local = task.as_thread_local().unwrap();
        let fd = thread_local
            .borrow_file_table()
            .unwrap()
            .write()
            .insert(file, FdFlags::CLOEXEC);
        Ok(fd.into())
    }

    pub(super) fn vsock_connect(&self, args: VsockArgs) -> Result<i32> {
        if args.port == 0 || args.flags != 0 {
            return_errno_with_message!(Errno::EINVAL, "invalid vsock connection");
        }
        if !matches!(&*self.state.lock(), SandboxState::Running { .. }) {
            return_errno_with_message!(Errno::ENODEV, "kernelet is not running");
        }
        let file = vsock_switch::connect(self.cid, args.port)?;
        let task = Task::current().unwrap();
        let thread_local = task.as_thread_local().unwrap();
        let fd = thread_local
            .borrow_file_table()
            .unwrap()
            .write()
            .insert(file, FdFlags::CLOEXEC);
        Ok(fd.into())
    }

    pub(super) fn vsock_policy(&self, args: VsockPolicyArgs) -> Result<()> {
        if args.allow > 1 {
            return_errno_with_message!(Errno::EINVAL, "invalid vsock policy value");
        }
        let fd = args
            .peer_fd
            .try_into()
            .map_err(|_| Error::with_message(Errno::EBADF, "invalid peer sandbox fd"))?;
        let task = Task::current().unwrap();
        let thread_local = task.as_thread_local().unwrap();
        let peer_file = thread_local
            .borrow_file_table()
            .unwrap()
            .read()
            .get_file(fd)?
            .clone();
        let peer = peer_file
            .downcast_ref::<SandboxFile>()
            .ok_or_else(|| Error::with_message(Errno::EBADF, "peer fd is not a sandbox"))?;
        if self.cid == peer.cid {
            return_errno_with_message!(Errno::EINVAL, "a sandbox cannot authorize itself");
        }
        if !matches!(&*self.state.lock(), SandboxState::Running { .. })
            || !matches!(&*peer.state.lock(), SandboxState::Running { .. })
        {
            return_errno_with_message!(Errno::ENODEV, "both sandboxes must be live");
        }
        vsock_switch::set_peer_allowed(self.cid, peer.cid, args.allow != 0)
    }
}
