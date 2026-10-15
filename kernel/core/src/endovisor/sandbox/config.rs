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
#[cfg(kernelet_nat_failure_diag_host)]
use crate::endovisor::policy::{QuotaClass, QuotaTag};
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
        let budget = CpuBudget {
            nice: args.nice,
            quota: (args.cpu_quota_us != 0).then_some((args.cpu_quota_us, args.cpu_period_us)),
        };
        if args.image != 0
            || args.num_vcpus == 0
            || args.num_vcpus as usize > ostd::cpu::num_cpus()
            || args.num_vcpus as usize > ostd::kernelet::abi::MAX_VCPUS
            || args.initial_grains == 0
            || args.max_grains < args.initial_grains
            || args.max_meta_sections == 0
            || args.max_tasks < u32::from(args.num_vcpus)
            || args.max_tasks > ostd::kernelet::control::MAX_TASKS
            || args.reserved0 != [0; 3]
            || args.out_cid != 0
            || args.cmdline_len as usize > MAX_CMDLINE_BYTES
        {
            return_errno_with_message!(Errno::EINVAL, "unsupported kernelet configuration");
        }
        budget
            .validate()
            .map_err(|_| Error::with_message(Errno::EINVAL, "invalid kernelet budget"))?;
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
            budget,
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
        let net = (args.kind == NET).then(|| {
            NetEndpoint::new(
                self.owner,
                #[cfg(kernelet_nat_failure_diag_host)]
                self.cid,
            )
        });
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
        let reservation = Arc::new(PrestartEndpointReservation::reserve(
            self.owner,
            bytes,
            #[cfg(kernelet_nat_failure_diag_host)]
            QuotaTag::new(
                match args.kind {
                    CONSOLE => QuotaClass::ConsoleFixed,
                    NET => QuotaClass::NetFixed,
                    LOG => QuotaClass::LogFixed,
                    _ => unreachable!(),
                },
                Some(self.cid),
            ),
        )?);
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
        let file = self.create_vsock_listener(args)?;
        let task = Task::current().unwrap();
        let thread_local = task.as_thread_local().unwrap();
        let fd = thread_local
            .borrow_file_table()
            .unwrap()
            .write()
            .insert(file, FdFlags::CLOEXEC);
        Ok(fd.into())
    }

    pub(super) fn create_vsock_listener(&self, args: VsockArgs) -> Result<Arc<dyn FileLike>> {
        if args.port == 0 || args.flags != 0 {
            return_errno_with_message!(Errno::EINVAL, "invalid vsock listener");
        }
        let state = self.state.lock();
        let SandboxState::Configuring(pending) = &*state else {
            return_errno_with_message!(Errno::EBUSY, "kernelet already started");
        };
        if !pending.vsock_attached {
            return_errno_with_message!(Errno::ENODEV, "vsock is not attached");
        }
        // Keep listener registration inside Configuring admission. KILL and
        // DESTROY take the same state lock before removing switch entries.
        #[cfg(ktest)]
        tests::before_listener_registration(self.cid);
        let file = vsock_switch::listen(self.cid, args.port, self.owner)?;
        drop(state);
        Ok(file)
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

#[cfg(ktest)]
pub(super) mod tests {
    use core::sync::atomic::AtomicBool;

    use ostd::{prelude::*, task::TaskOptions};

    use super::*;

    struct ListenCheckpoint {
        cid: u32,
        entered: AtomicBool,
        proceed: AtomicBool,
    }

    static LISTEN_CHECKPOINT: SpinLock<Option<Arc<ListenCheckpoint>>> = SpinLock::new(None);

    struct CheckpointRegistration(Arc<ListenCheckpoint>);

    impl Drop for CheckpointRegistration {
        fn drop(&mut self) {
            self.0.proceed.store(true, Ordering::Release);
            let checkpoint = LISTEN_CHECKPOINT.lock().take();
            drop(checkpoint);
        }
    }

    pub(super) fn before_listener_registration(cid: u32) {
        let checkpoint = LISTEN_CHECKPOINT.lock().clone();
        if let Some(checkpoint) = checkpoint.filter(|checkpoint| checkpoint.cid == cid) {
            checkpoint.entered.store(true, Ordering::Release);
            wait_for(|| checkpoint.proceed.load(Ordering::Acquire));
        }
    }

    pub(in crate::endovisor::sandbox) fn wait_for(mut ready: impl FnMut() -> bool) {
        for _ in 0..100_000 {
            if ready() {
                return;
            }
            Task::yield_now();
        }
        panic!("sandbox regression checkpoint did not complete");
    }

    pub(in crate::endovisor::sandbox) fn sandbox() -> Arc<SandboxFile> {
        crate::time::clocks::init_for_ktest();
        let cid = NEXT_CID
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                (next != u32::MAX).then(|| next + 1)
            })
            .unwrap();
        Arc::new(SandboxFile {
            common: FileCommon::new(
                AnonInodeFs::new_path(|_| "anon_inode:[kernelet-test]".into()),
                AccessMode::O_RDWR,
                StatusFlags::empty(),
            ),
            state: Arc::new(Mutex::new(SandboxState::Configuring(Pending {
                cmdline: String::new(),
                initial_grains: 1,
                max_grains: 1,
                max_meta_sections: 1,
                max_tasks: 1,
                num_vcpus: 1,
                budget: CpuBudget {
                    nice: 0,
                    quota: None,
                },
                policy: KerneletPolicy::default(),
                blocks: Vec::new(),
                console: None,
                log: None,
                console_attached: false,
                console_vcpu: 0,
                vsock_attached: true,
                vsock_vcpu: 0,
                rng_attached: false,
                rng_vcpu: 0,
                net: None,
                net_attached: false,
                net_vcpu: 0,
                net_mac: [0; 6],
                endpoint_reservations: Vec::new(),
            }))),
            pollee: Pollee::new(),
            start_waiters: WaitQueue::new(),
            cid,
            owner: crate::process::Uid::new(51_000),
            admission: SpinLock::new(None),
        })
    }

    pub(in crate::endovisor::sandbox) fn listener_args() -> VsockArgs {
        VsockArgs {
            port: 12_345,
            flags: 0,
        }
    }

    pub(in crate::endovisor::sandbox) fn assert_listener_removed(sandbox: &SandboxFile) {
        // The real switch rejects a duplicate port while the old entry exists.
        drop(vsock_switch::listen(sandbox.cid, listener_args().port, sandbox.owner).unwrap());
    }

    #[ktest]
    fn destroy_revokes_an_admitted_listener() {
        // Regression: Configuring could become Gone before LISTEN inserted.
        let sandbox = sandbox();
        let checkpoint = Arc::new(ListenCheckpoint {
            cid: sandbox.cid,
            entered: AtomicBool::new(false),
            proceed: AtomicBool::new(false),
        });
        *LISTEN_CHECKPOINT.lock() = Some(checkpoint.clone());
        let registration = CheckpointRegistration(checkpoint.clone());
        let listener_result = Arc::new(Mutex::new(None));
        let listener_task = {
            let sandbox = sandbox.clone();
            let result = listener_result.clone();
            TaskOptions::new(move || {
                *result.lock() = Some(sandbox.create_vsock_listener(listener_args()));
            })
            .spawn()
            .unwrap()
        };
        wait_for(|| checkpoint.entered.load(Ordering::Acquire));
        let destroy_started = Arc::new(AtomicBool::new(false));
        let destroy_result = Arc::new(Mutex::new(None));
        let destroy_task = {
            let sandbox = sandbox.clone();
            let started = destroy_started.clone();
            let result = destroy_result.clone();
            TaskOptions::new(move || {
                started.store(true, Ordering::Release);
                *result.lock() = Some(sandbox.destroy());
            })
            .spawn()
            .unwrap()
        };
        wait_for(|| destroy_started.load(Ordering::Acquire));
        let registration_is_admitted = sandbox.state.try_lock().is_none();
        let destroy_is_pending = destroy_result.lock().is_none();
        checkpoint.proceed.store(true, Ordering::Release);
        wait_for(|| listener_result.lock().is_some() && destroy_result.lock().is_some());
        drop(registration);
        destroy_result.lock().take().unwrap().unwrap();
        let listener = listener_result.lock().take().unwrap().unwrap();
        assert!(registration_is_admitted);
        assert!(destroy_is_pending);
        assert!(matches!(&*sandbox.state.lock(), SandboxState::Gone(_)));
        let mut byte = [0];
        assert_eq!(
            listener
                .read(&mut VmWriter::from(&mut byte[..]).to_fallible())
                .unwrap_err()
                .error(),
            Errno::ECONNRESET
        );
        assert_listener_removed(&sandbox);
        assert_eq!(
            sandbox
                .create_vsock_listener(listener_args())
                .err()
                .unwrap()
                .error(),
            Errno::EBUSY
        );
        drop(listener);
        drop((listener_task, destroy_task));
    }

    #[ktest]
    fn failed_start_preserves_listener_for_retry() {
        let sandbox = sandbox();
        let listener = sandbox.create_vsock_listener(listener_args()).unwrap();
        assert_eq!(sandbox.start().unwrap_err().error(), Errno::ENODEV);
        assert!(matches!(
            &*sandbox.state.lock(),
            SandboxState::Configuring(_)
        ));
        assert_eq!(
            sandbox
                .create_vsock_listener(listener_args())
                .err()
                .unwrap()
                .error(),
            Errno::EADDRINUSE
        );
        sandbox.destroy().unwrap();
        assert_listener_removed(&sandbox);
        drop(listener);
    }
}
