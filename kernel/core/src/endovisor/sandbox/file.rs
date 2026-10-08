// SPDX-License-Identifier: MPL-2.0

//! The `/dev/kernelet` file interface: ioctl dispatch, polling, and conversion
//! of kernel state into the UAPI `StatusRaw`/`StatsRaw` records.

use alloc::format;
use core::fmt::Display;

use kernelet_abi::{
    BudgetArgs, ImageInfoRaw, KILL_ENTRY_FAILED, KILL_HOST_HOOK_PANICKED, KILL_KERNEL_FAULT,
    KILL_OOPS_BUDGET, KILL_REQUESTED, KILL_STACK_OVERFLOW, KILL_STACK_RESERVE, STATE_CONFIGURING,
    STATE_DESTROYED, STATE_DESTROYING, STATE_DYING, STATE_EXITED, STATE_RUNNING, STATE_STARTING,
    STATUS_REASON_EXITED, STATUS_REASON_KILLED, STATUS_REASON_NONE, STATUS_REASON_PANICKED,
    StatsRaw, StatusRaw,
};
use ostd::{
    kernelet::control::{CpuBudget, ExitReason, ExitStatus, KerneletState, KillReason},
    task::Task,
};

use super::{SandboxFile, SandboxState};
use crate::{
    events::IoEvents,
    fs::file::{FileCommon, FileLike, file_table::FdFlags},
    prelude::*,
    process::signal::{PollHandle, Pollable},
    util::ioctl::{RawIoctl, dispatch_ioctl},
};

mod ioctl_defs {
    use kernelet_abi::{
        AttachArgs, BudgetArgs, CreateArgs, EndpointArgs, ImageInfoRaw, StatsRaw, StatusRaw,
        VsockArgs, VsockPolicyArgs,
    };

    use crate::util::ioctl::{InData, InOutData, NoData, OutData, PassByVal, ioc};

    pub(super) type Create = ioc!(KERNELET_CREATE, 0xc7, 0x01, InOutData<CreateArgs>);
    pub(super) type ListImages = ioc!(KERNELET_LIST_IMAGES, 0xc7, 0x02, OutData<[ImageInfoRaw; 8]>);
    pub(super) type Attach = ioc!(KERNELET_ATTACH, 0xc7, 0x10, InOutData<AttachArgs>);
    pub(super) type Endpoint = ioc!(KERNELET_ENDPOINT, 0xc7, 0x11, InData<EndpointArgs>);
    pub(super) type Start = ioc!(KERNELET_START, 0xc7, 0x20, NoData);
    pub(super) type Kill = ioc!(KERNELET_KILL, 0xc7, 0x21, InData<u32, PassByVal>);
    pub(super) type Grant = ioc!(KERNELET_GRANT, 0xc7, 0x22, InOutData<u32>);
    pub(super) type Budget = ioc!(KERNELET_BUDGET, 0xc7, 0x23, InData<BudgetArgs>);
    pub(super) type Stats = ioc!(KERNELET_STATS, 0xc7, 0x24, OutData<StatsRaw>);
    pub(super) type Status = ioc!(KERNELET_STATUS, 0xc7, 0x25, OutData<StatusRaw>);
    pub(super) type Destroy = ioc!(KERNELET_DESTROY, 0xc7, 0x2f, NoData);
    pub(super) type VsockListen = ioc!(KERNELET_VSOCK_LISTEN, 0xc7, 0x31, InData<VsockArgs>);
    pub(super) type VsockConnect = ioc!(KERNELET_VSOCK_CONNECT, 0xc7, 0x30, InData<VsockArgs>);
    pub(super) type VsockPolicy = ioc!(KERNELET_VSOCK_POLICY, 0xc7, 0x33, InData<VsockPolicyArgs>);
}

/// A status record carrying only the lifecycle state.
pub(super) fn blank_status(state: u32) -> StatusRaw {
    StatusRaw {
        state,
        reason: STATUS_REASON_NONE,
        code: 0,
        flags: 0,
        uptime_ns: 0,
        cpu_time_ns: 0,
        fault_addr: 0,
        fault_ip: 0,
        message_len: 0,
        reserved0: 0,
        message: [0; 256],
    }
}

fn duration_ns(duration: core::time::Duration) -> u64 {
    duration.as_nanos().min(u64::MAX as u128) as u64
}

/// A status record for an instance killed by the Host with `code`.
pub(super) fn killed_status(code: u32) -> StatusRaw {
    let mut status = blank_status(STATE_EXITED);
    status.reason = STATUS_REASON_KILLED;
    status.code = code;
    status
}

/// Converts an OSTD exit status into its UAPI record.
pub(super) fn exit_status_raw(exit: &ExitStatus) -> StatusRaw {
    let mut raw = blank_status(STATE_EXITED);
    raw.uptime_ns = duration_ns(exit.uptime);
    match &exit.reason {
        ExitReason::Exited(code) => {
            raw.reason = STATUS_REASON_EXITED;
            raw.code = *code;
        }
        ExitReason::Panicked(message) => {
            raw.reason = STATUS_REASON_PANICKED;
            let bytes = message.as_bytes();
            let len = bytes.len().min(raw.message.len());
            raw.message[..len].copy_from_slice(&bytes[..len]);
            raw.message_len = len as u32;
            if bytes.len() > len {
                raw.flags |= kernelet_abi::STATUS_MESSAGE_TRUNCATED;
            }
        }
        ExitReason::Killed(reason) => {
            raw.reason = STATUS_REASON_KILLED;
            raw.code = match reason {
                KillReason::Requested => KILL_REQUESTED,
                KillReason::OopsBudget => KILL_OOPS_BUDGET,
                KillReason::StackReserve => KILL_STACK_RESERVE,
                KillReason::StackOverflow => KILL_STACK_OVERFLOW,
                KillReason::HostHookPanicked => KILL_HOST_HOOK_PANICKED,
                KillReason::EntryFailed => KILL_ENTRY_FAILED,
                KillReason::KernelFault { addr, ip } => {
                    raw.fault_addr = *addr;
                    raw.fault_ip = *ip;
                    KILL_KERNEL_FAULT
                }
                KillReason::HostPolicy(code) => *code,
            };
        }
    }
    raw
}

impl SandboxFile {
    fn status(&self) -> StatusRaw {
        let live = {
            let state = self.state.lock();
            match &*state {
                SandboxState::Configuring(_) => return blank_status(STATE_CONFIGURING),
                SandboxState::Starting { .. } => return blank_status(STATE_STARTING),
                SandboxState::Running { kernelet, .. } => kernelet.clone(),
                SandboxState::Exited { status, .. } => return *status,
                SandboxState::Destroying => return blank_status(STATE_DESTROYING),
                SandboxState::Gone(status) => return *status,
            }
        };
        if let Some(exit) = live.exit_status() {
            return exit_status_raw(&exit);
        }
        blank_status(match live.state() {
            KerneletState::Created | KerneletState::Running => STATE_RUNNING,
            KerneletState::Dying => STATE_DYING,
            KerneletState::Exited => STATE_EXITED,
            KerneletState::Destroying => STATE_DESTROYING,
            KerneletState::Destroyed => STATE_DESTROYED,
        })
    }

    fn grant(&self, grains: u32) -> Result<u32> {
        let kernelet = {
            let state = self.state.lock();
            match &*state {
                SandboxState::Running { kernelet, .. } => kernelet.clone(),
                _ => return_errno_with_message!(Errno::EINVAL, "grant requires a live kernelet"),
            }
        };
        let admission = self
            .admission
            .lock()
            .as_ref()
            .cloned()
            .ok_or_else(|| Error::with_message(Errno::EINVAL, "kernelet is not admitted"))?;
        let reservation = admission.reserve_control_grant(grains)?;
        let published = kernelet.grant(grains).map_err(|error| {
            use ostd::kernelet::control::GrantError;
            match error {
                GrantError::State(_) => {
                    Error::with_message(Errno::EINVAL, "grant state is invalid")
                }
                GrantError::Limit | GrantError::MetadataCapacity => {
                    Error::with_message(Errno::ENOSPC, "grant ceiling was reached")
                }
                GrantError::NoMemory => {
                    Error::with_message(Errno::ENOMEM, "grant memory is unavailable")
                }
            }
        })?;
        reservation.settle(published);
        Ok(published)
    }

    fn set_budget(&self, args: BudgetArgs) -> Result<()> {
        if args.reserved0 != [0; 3]
            || !(-20..=19).contains(&args.nice)
            || (args.cpu_quota_us != 0 && args.cpu_period_us <= 1_000)
        {
            return_errno_with_message!(Errno::EINVAL, "invalid kernelet budget");
        }
        let budget = CpuBudget {
            nice: args.nice,
            quota: (args.cpu_quota_us != 0).then_some((args.cpu_quota_us, args.cpu_period_us)),
        };
        let kernelet = {
            let mut state = self.state.lock();
            match &mut *state {
                SandboxState::Configuring(pending) => {
                    pending.budget = budget;
                    return Ok(());
                }
                SandboxState::Running { kernelet, .. } => kernelet.clone(),
                _ => return_errno_with_message!(Errno::EBUSY, "kernelet budget is unavailable"),
            }
        };
        kernelet
            .set_budget(budget)
            .map_err(|_| Error::with_message(Errno::EINVAL, "kernelet budget update failed"))
    }

    fn stats(&self) -> StatsRaw {
        let kernelet = {
            let state = self.state.lock();
            match &*state {
                SandboxState::Running { kernelet, .. } => Some(kernelet.clone()),
                SandboxState::Exited { kernelet, .. } => kernelet.clone(),
                _ => None,
            }
        };
        let mut raw = StatsRaw {
            state: self.status().state,
            cid: self.cid,
            ..StatsRaw::default()
        };
        if let Some(kernelet) = kernelet {
            let stats = kernelet.stats();
            raw.grains_granted = stats.grains_granted;
            raw.max_grains = stats.max_grains;
            raw.stacks_allocated = stats.stacks_allocated;
            raw.oopses = stats.oopses;
            raw.host_bytes_charged = stats.host_bytes_charged as u64;
            raw.host_overhead_bytes = stats.host_overhead_bytes as u64;
            raw.cpu_time_ns = duration_ns(stats.cpu_time);
            raw.throttled_ns = duration_ns(stats.throttled);
            raw.completion_cpu_ns = duration_ns(stats.completion_cpu_time);
            raw.ingress_copy_cpu_ns = duration_ns(stats.ingress_copy_cpu_time);
            raw.service_calls = stats.service_calls;
            raw.mmio_accesses = stats.mmio_accesses;
            raw.irqs_raised = stats.irqs_raised;
            raw.log_bytes = stats.log_bytes;
            raw.log_records_dropped = stats.log_records_dropped;
        }
        raw
    }
}

impl Pollable for SandboxFile {
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.pollee
            .poll_with(mask, poller, || match &*self.state.lock() {
                SandboxState::Exited { .. } | SandboxState::Gone(_) => IoEvents::IN,
                _ => IoEvents::empty(),
            })
    }
}

impl FileLike for SandboxFile {
    fn ioctl(&self, raw_ioctl: RawIoctl) -> Result<i32> {
        use ioctl_defs::*;
        dispatch_ioctl!(match raw_ioctl {
            cmd @ Attach => {
                let args = self.attach(cmd.read()?)?;
                cmd.write(&args)?;
                Ok(args.out_index as i32)
            }
            cmd @ Endpoint => {
                self.endpoint(cmd.read()?)
            }
            _cmd @ Start => {
                self.start()?;
                Ok(0)
            }
            cmd @ Kill => {
                self.kill(cmd.get())?;
                Ok(0)
            }
            cmd @ Grant => {
                let grains = self.grant(cmd.read()?)?;
                cmd.write(&grains)?;
                Ok(0)
            }
            cmd @ Budget => {
                self.set_budget(cmd.read()?)?;
                Ok(0)
            }
            cmd @ Stats => {
                cmd.write(&self.stats())?;
                Ok(0)
            }
            _cmd @ Destroy => {
                self.destroy()?;
                Ok(0)
            }
            cmd @ Status => {
                cmd.write(&self.status())?;
                Ok(0)
            }
            cmd @ VsockListen => {
                self.vsock_listen(cmd.read()?)
            }
            cmd @ VsockConnect => {
                self.vsock_connect(cmd.read()?)
            }
            cmd @ VsockPolicy => {
                self.vsock_policy(cmd.read()?)?;
                Ok(0)
            }
            _ => return_errno_with_message!(Errno::ENOTTY, "unknown kernelet ioctl"),
        })
    }

    fn common(&self) -> &FileCommon {
        &self.common
    }

    fn dump_proc_fdinfo(self: Arc<Self>, _fd_flags: FdFlags) -> Box<dyn Display> {
        Box::new(format!("kernelet-cid:\t{}\n", self.cid))
    }
}

/// The file-control ioctls of `/dev/kernelet` that do not address a sandbox.
pub(in crate::endovisor) fn create_sandbox(raw_ioctl: RawIoctl) -> Result<i32> {
    use ioctl_defs::*;
    dispatch_ioctl!(match raw_ioctl {
        cmd @ Create => {
            let (sandbox, args) = SandboxFile::create(cmd.read()?)?;
            cmd.write(&args)?;
            let task = Task::current().unwrap();
            let thread_local = task.as_thread_local().unwrap();
            let fd = thread_local
                .borrow_file_table()
                .unwrap()
                .write()
                .insert(sandbox, FdFlags::CLOEXEC);
            Ok(fd.into())
        }
        cmd @ ListImages => {
            let mut images = [ImageInfoRaw::default(); 8];
            let Some(kind) = crate::endovisor::IMAGE.get() else {
                cmd.write(&images)?;
                return Ok(0);
            };
            let info = kind.image_info();
            const NAME: &[u8] = b"asterinas";
            images[0].image = 0;
            images[0].name_len = NAME.len() as u16;
            images[0].name[..NAME.len()].copy_from_slice(NAME);
            images[0].text_bytes = info.text_bytes as u64;
            images[0].template_bytes = info.template_bytes as u64;
            images[0].cpu_local_bytes = info.cpu_local_bytes as u32;
            cmd.write(&images)?;
            Ok(1)
        }
        _ => return_errno_with_message!(Errno::ENOTTY, "unknown kernelet ioctl"),
    })
}
