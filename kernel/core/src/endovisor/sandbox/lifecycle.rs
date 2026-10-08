// SPDX-License-Identifier: MPL-2.0

//! Sandbox lifecycle: start, kill, destroy, and failure reclamation.

use alloc::format;

use kernelet_abi::{STATE_DESTROYED, STATUS_REASON_NONE, StatusRaw};
use ostd::kernelet::{
    abi::DeviceEntry,
    control::{DestroyError, Kernelet, KerneletConfig, KerneletState, KillReason},
};
use spin::Once;

use super::{
    SandboxFile, SandboxState,
    config::Pending,
    devices::{DeviceSlot, MMIO_CMDLINE_PREFIX, MMIO_WINDOW_BYTES, SandboxDevices, SandboxHooks},
    file::{blank_status, exit_status_raw, killed_status},
};
use crate::{
    endovisor::{
        placement::CpuReservation, policy::Admission, reaper, virtio_block::VirtioBlock,
        virtio_console::VirtioConsole, virtio_net::VirtioNet, virtio_rng::VirtioRng,
        virtio_vsock::VirtioVsock, vsock_switch,
    },
    events::IoEvents,
    prelude::*,
    process::signal::Pollee,
};

/// Reclaims an instance if model construction fails after OSTD creation.
struct UnstartedKernelet {
    kernelet: Option<Arc<Kernelet>>,
    admission: Arc<Admission>,
    cid: u32,
    state: Weak<Mutex<SandboxState>>,
    pollee: Pollee,
}

impl Drop for UnstartedKernelet {
    fn drop(&mut self) {
        let Some(kernelet) = self.kernelet.take() else {
            return;
        };
        let status = self.state.upgrade().map(|state| {
            let mut state = state.lock();
            let reason = match &*state {
                SandboxState::Starting { kill } => {
                    kill.unwrap_or(kernelet_abi::KILL_INTERNAL_ERROR)
                }
                _ => kernelet_abi::KILL_INTERNAL_ERROR,
            };
            *state = SandboxState::Destroying;
            killed_status(reason)
        });
        vsock_switch::on_dying(self.cid);
        let _ = kernelet.kill(KillReason::Requested);
        let admission = self.admission.clone();
        let state = self.state.clone();
        let pollee = self.pollee.clone();
        reaper::enqueue(
            self.cid,
            kernelet,
            None,
            Some(Box::new(move || {
                admission.release_after_destroy();
                if let (Some(state), Some(mut status)) = (state.upgrade(), status) {
                    let mut state = state.lock();
                    if matches!(&*state, SandboxState::Destroying) {
                        status.state = STATE_DESTROYED;
                        *state = SandboxState::Gone(status);
                        drop(state);
                        pollee.notify(IoEvents::IN);
                    }
                }
            })),
        );
    }
}

impl SandboxFile {
    fn watch_exit(&self, kernelet: Arc<Kernelet>, hooks: Arc<SandboxHooks>) {
        let state = Arc::downgrade(&self.state);
        let pollee = self.pollee.clone();
        let cid = self.cid;
        reaper::watch_exit(
            cid,
            kernelet,
            Box::new(move || {
                hooks.cancel();
                vsock_switch::on_dying(cid);
            }),
            Box::new(move |exit| {
                let Some(state) = state.upgrade() else {
                    return;
                };
                let mut state = state.lock();
                if matches!(&*state, SandboxState::Running { .. }) {
                    let previous = core::mem::replace(&mut *state, SandboxState::Destroying);
                    let SandboxState::Running { kernelet, hooks } = previous else {
                        unreachable!();
                    };
                    *state = SandboxState::Exited {
                        kernelet: Some(kernelet),
                        hooks: Some(hooks),
                        status: exit_status_raw(&exit),
                        retry_queued: false,
                    };
                    drop(state);
                    pollee.notify(IoEvents::IN);
                }
            }),
        );
    }

    pub(super) fn start(&self) -> Result<()> {
        let pending = {
            let mut state = self.state.lock();
            let old = core::mem::replace(&mut *state, SandboxState::Starting { kill: None });
            match old {
                SandboxState::Configuring(pending) => pending,
                other => {
                    *state = other;
                    return_errno_with_message!(Errno::EBUSY, "kernelet already started");
                }
            }
        };
        let mut created = false;
        let (kernelet, hooks) = match self.start_pending(&pending, &mut created) {
            Ok(started) => started,
            Err(error) => {
                let mut state = self.state.lock();
                if created {
                    // The unstarted-instance guard handed reclamation to the
                    // reaper, which publishes Gone only after destroy.
                    debug_assert!(matches!(
                        &*state,
                        SandboxState::Destroying | SandboxState::Gone(_)
                    ));
                    drop(state);
                    pending.revoke_endpoints();
                    self.start_waiters.wake_all();
                    return Err(error);
                }
                let kill = match &*state {
                    SandboxState::Starting { kill } => *kill,
                    _ => unreachable!(),
                };
                let terminal = kill.is_some();
                let mut pending = Some(pending);
                if terminal {
                    *state = SandboxState::Gone(killed_status(
                        kill.unwrap_or(kernelet_abi::KILL_INTERNAL_ERROR),
                    ));
                } else {
                    *state = SandboxState::Configuring(pending.take().unwrap());
                }
                drop(state);
                if let Some(pending) = pending {
                    pending.revoke_endpoints();
                }
                self.start_waiters.wake_all();
                if terminal {
                    self.pollee.notify(IoEvents::IN);
                }
                return Err(error);
            }
        };
        *self.admission.lock() = Some(hooks.admission.clone());
        hooks
            .devices
            .get()
            .unwrap()
            .for_each(|device| device.start_worker());
        let kill = {
            let mut state = self.state.lock();
            let kill = match &*state {
                SandboxState::Starting { kill } => *kill,
                _ => unreachable!(),
            };
            *state = SandboxState::Running {
                kernelet: kernelet.clone(),
                hooks: hooks.clone(),
            };
            kill
        };
        self.watch_exit(kernelet.clone(), hooks.clone());
        if let Some(reason) = kill {
            let _ = kernelet.kill(KillReason::HostPolicy(reason));
            self.start_waiters.wake_all();
            return_errno_with_message!(Errno::EINTR, "kernelet start was killed");
        }
        if kernelet.start(hooks.clone()).is_err() {
            let _ = kernelet.kill(KillReason::Requested);
            self.start_waiters.wake_all();
            return_errno_with_message!(Errno::EINTR, "kernelet stopped before start");
        }
        self.start_waiters.wake_all();
        Ok(())
    }

    fn start_pending(
        &self,
        pending: &Pending,
        created: &mut bool,
    ) -> Result<(Arc<Kernelet>, Arc<SandboxHooks>)> {
        if pending.blocks.is_empty() {
            return_errno_with_message!(Errno::ENODEV, "no root block device was attached");
        }
        let mut slots = Vec::new();
        slots.push(DeviceSlot::Block(0));
        if pending.console_attached {
            slots.push(DeviceSlot::Console);
        }
        if pending.vsock_attached {
            slots.push(DeviceSlot::Vsock);
        }
        if pending.rng_attached {
            slots.push(DeviceSlot::Rng);
        }
        if pending.net_attached {
            slots.push(DeviceSlot::Net);
        }
        for index in 1..pending.blocks.len() as u16 {
            slots.push(DeviceSlot::Block(index));
        }
        let mut cmdline = pending.cmdline.clone();
        let mut devices = Vec::with_capacity(slots.len());
        for slot in &slots {
            cmdline.push_str(&format!(
                " {}{}@0x{:x}:{}",
                MMIO_CMDLINE_PREFIX,
                MMIO_WINDOW_BYTES,
                slot.mmio_base(),
                slot.irq()
            ));
            if matches!(slot, DeviceSlot::Console) {
                cmdline.push_str(" console=hvc0");
            }
            let vcpu = match slot {
                DeviceSlot::Block(index) => pending.blocks[*index as usize].vcpu,
                DeviceSlot::Console => pending.console_vcpu,
                DeviceSlot::Vsock => pending.vsock_vcpu,
                DeviceSlot::Rng => pending.rng_vcpu,
                DeviceSlot::Net => pending.net_vcpu,
            };
            devices.push(DeviceEntry {
                id: slot.wire_id(),
                kind: 1,
                irq: slot.irq(),
                reserved: 0,
                vcpu,
                reg_bytes: MMIO_WINDOW_BYTES,
                device_type: slot.device_type(),
                mmio_base: slot.mmio_base(),
            });
        }
        let placement = CpuReservation::reserve(pending.num_vcpus)?;
        let config = KerneletConfig {
            cmdline: &cmdline,
            initial_grains: pending.initial_grains,
            max_grains: pending.max_grains,
            max_meta_sections: pending.max_meta_sections,
            budget: pending.budget,
            policy: pending.policy,
            max_tasks: pending.max_tasks,
            devices: &devices,
            cpus: placement.cpu_set(),
        };
        let admission = Admission::reserve(self.owner, pending.max_grains, pending.num_vcpus, 0)?;
        let hooks = Arc::new(SandboxHooks {
            devices: Once::new(),
            console_endpoint: pending.console.clone(),
            net_endpoint: pending.net.clone(),
            log_endpoint: pending.log.clone(),
            _endpoint_reservations: pending.endpoint_reservations.clone(),
            admission: admission.clone(),
            _placement: placement,
            carriers: SpinLock::new(Vec::new()),
        });
        let kind = crate::endovisor::image_kind()?;
        let kernelet = kind
            .create(&config, hooks.as_ref())
            .map_err(|_| Error::with_message(Errno::EINVAL, "cannot create kernelet"))?;
        *created = true;
        admission.mark_created();
        let mut unstarted = UnstartedKernelet {
            kernelet: Some(kernelet.clone()),
            admission: admission.clone(),
            cid: self.cid,
            state: Arc::downgrade(&self.state),
            pollee: self.pollee.clone(),
        };
        let blocks = pending
            .blocks
            .iter()
            .enumerate()
            .map(|(index, block)| {
                VirtioBlock::new(
                    kernelet.clone(),
                    block.backing.clone(),
                    block.capacity_sectors,
                    block.read_only,
                    DeviceSlot::Block(index as u16).irq(),
                )
            })
            .collect::<ostd::Result<Vec<_>>>()
            .map_err(|_| Error::with_message(Errno::ENOMEM, "cannot charge block device"))?;
        let console = pending.console_attached.then(|| {
            VirtioConsole::new(
                kernelet.clone(),
                pending.console.as_ref().unwrap().clone(),
                DeviceSlot::Console.irq(),
            )
        });
        let vsock = pending
            .vsock_attached
            .then(|| {
                VirtioVsock::new(
                    kernelet.clone(),
                    self.cid,
                    DeviceSlot::Vsock.irq(),
                    admission.clone(),
                )
            })
            .transpose()?;
        let net = pending.net_attached.then(|| {
            VirtioNet::new(
                kernelet.clone(),
                pending.net.as_ref().unwrap().clone(),
                pending.net_mac,
                DeviceSlot::Net.irq(),
            )
        });
        let rng = pending
            .rng_attached
            .then(|| VirtioRng::new(kernelet.clone(), DeviceSlot::Rng.irq()));
        if let Some(console) = &pending.console {
            console.bind_account(kernelet.clone()).map_err(|_| {
                Error::with_message(Errno::ENOMEM, "cannot charge console endpoint")
            })?;
        }
        if let Some(log) = &pending.log
            && log.bind_account(kernelet.clone()).is_err()
        {
            if let Some(console) = &pending.console {
                console.unbind_account();
            }
            return_errno_with_message!(Errno::ENOMEM, "cannot charge log endpoint");
        }
        if pending.net_attached
            && pending
                .net
                .as_ref()
                .unwrap()
                .bind_account(kernelet.clone())
                .is_err()
        {
            if let Some(log) = &pending.log {
                log.unbind_account();
            }
            if let Some(console) = &pending.console {
                console.unbind_account();
            }
            return_errno_with_message!(Errno::ENOMEM, "cannot charge network endpoint");
        }
        hooks.devices.call_once(|| SandboxDevices {
            blocks,
            console,
            vsock,
            net,
            rng,
        });
        unstarted.kernelet = None;
        Ok((kernelet, hooks))
    }

    pub(super) fn kill(&self, reason: u32) -> Result<()> {
        let live = {
            let mut state = self.state.lock();
            match &mut *state {
                SandboxState::Configuring(pending) => {
                    let console = pending.console.clone();
                    let net = pending.net.clone();
                    let log = pending.log.clone();
                    *state = SandboxState::Gone(killed_status(reason));
                    drop(state);
                    if let Some(console) = console {
                        console.revoke();
                    }
                    if let Some(net) = net {
                        net.revoke();
                    }
                    if let Some(log) = log {
                        log.revoke();
                    }
                    vsock_switch::on_dying(self.cid);
                    self.pollee.notify(IoEvents::IN);
                    return Ok(());
                }
                SandboxState::Starting { kill } => {
                    if kill.is_none() {
                        *kill = Some(reason);
                    }
                    drop(state);
                    self.start_waiters.wait_until(|| {
                        (!matches!(&*self.state.lock(), SandboxState::Starting { .. }))
                            .then_some(())
                    });
                    return Ok(());
                }
                SandboxState::Running { kernelet, .. } => kernelet.clone(),
                SandboxState::Exited { .. } | SandboxState::Destroying | SandboxState::Gone(_) => {
                    return Ok(());
                }
            }
        };
        match live.kill(KillReason::HostPolicy(reason)) {
            Ok(()) => Ok(()),
            Err(_)
                if matches!(
                    live.state(),
                    KerneletState::Dying
                        | KerneletState::Exited
                        | KerneletState::Destroying
                        | KerneletState::Destroyed
                ) =>
            {
                Ok(())
            }
            Err(_) => return_errno_with_message!(Errno::EINVAL, "kernelet kill failed"),
        }
    }

    pub(super) fn destroy(&self) -> Result<()> {
        let (kernelet, hooks, status) = {
            let mut state = self.state.lock();
            let previous = core::mem::replace(&mut *state, SandboxState::Destroying);
            match previous {
                SandboxState::Configuring(pending) => {
                    let mut status = blank_status(STATE_DESTROYED);
                    status.reason = STATUS_REASON_NONE;
                    *state = SandboxState::Gone(status);
                    drop(state);
                    pending.revoke_endpoints();
                    vsock_switch::on_dying(self.cid);
                    self.pollee.notify(IoEvents::IN);
                    return Ok(());
                }
                SandboxState::Exited {
                    kernelet,
                    hooks,
                    status,
                    retry_queued: false,
                } => (kernelet, hooks, status),
                SandboxState::Gone(status) => {
                    *state = SandboxState::Gone(status);
                    return Ok(());
                }
                other => {
                    *state = other;
                    return_errno_with_message!(Errno::EBUSY, "kernelet is not ready for destroy");
                }
            }
        };
        if let Some(hooks) = hooks.as_ref() {
            hooks.revoke_endpoints();
            hooks.cancel();
        }
        drop(hooks);
        vsock_switch::on_dying(self.cid);
        let Some(kernelet) = kernelet else {
            let mut status = status;
            status.state = STATE_DESTROYED;
            *self.state.lock() = SandboxState::Gone(status);
            if let Some(admission) = self.admission.lock().take() {
                admission.release_after_destroy();
            }
            self.pollee.notify(IoEvents::IN);
            return Ok(());
        };
        if !vsock_switch::retired_drained(self.cid) {
            self.queue_reaper(kernelet, status);
            return Ok(());
        }
        match kernelet.destroy() {
            Ok(_) | Err(DestroyError::NotExited(KerneletState::Destroyed)) => {
                let mut status = status;
                status.state = STATE_DESTROYED;
                *self.state.lock() = SandboxState::Gone(status);
                if let Some(admission) = self.admission.lock().take() {
                    admission.release_after_destroy();
                }
                self.pollee.notify(IoEvents::IN);
                Ok(())
            }
            Err(DestroyError::Zombie { .. }) => {
                self.queue_reaper(kernelet, status);
                Ok(())
            }
            Err(DestroyError::NotExited(_)) => {
                *self.state.lock() = SandboxState::Exited {
                    kernelet: Some(kernelet),
                    hooks: None,
                    status,
                    retry_queued: false,
                };
                return_errno_with_message!(Errno::EBUSY, "kernelet is not exited");
            }
        }
    }

    fn queue_reaper(&self, kernelet: Arc<Kernelet>, status: StatusRaw) {
        *self.state.lock() = SandboxState::Exited {
            kernelet: Some(kernelet.clone()),
            hooks: None,
            status,
            retry_queued: true,
        };
        let state = self.state.clone();
        let pollee = self.pollee.clone();
        let admission = self.admission.lock().take();
        reaper::enqueue(
            self.cid,
            kernelet,
            None,
            Some(Box::new(move || {
                let mut status = status;
                status.state = STATE_DESTROYED;
                *state.lock() = SandboxState::Gone(status);
                if let Some(admission) = admission {
                    admission.release_after_destroy();
                }
                pollee.notify(IoEvents::IN);
            })),
        );
    }
}

impl Drop for SandboxFile {
    fn drop(&mut self) {
        let previous = core::mem::replace(&mut *self.state.lock(), SandboxState::Destroying);
        match previous {
            SandboxState::Configuring(pending) => {
                pending.revoke_endpoints();
                vsock_switch::on_dying(self.cid);
            }
            SandboxState::Running { kernelet, hooks } => {
                hooks.cancel();
                hooks.revoke_endpoints();
                vsock_switch::on_dying(self.cid);
                let _ = kernelet.kill(KillReason::Requested);
                let admission = self.admission.lock().take();
                reaper::enqueue(
                    self.cid,
                    kernelet,
                    Some(Box::new(move || drop(hooks))),
                    Some(Box::new(move || {
                        if let Some(admission) = admission {
                            admission.release_after_destroy();
                        }
                    })),
                );
            }
            SandboxState::Exited {
                kernelet,
                hooks,
                retry_queued,
                ..
            } => {
                if let Some(hooks) = hooks {
                    hooks.cancel();
                    hooks.revoke_endpoints();
                }
                vsock_switch::on_dying(self.cid);
                if !retry_queued {
                    if let Some(kernelet) = kernelet {
                        let admission = self.admission.lock().take();
                        reaper::enqueue(
                            self.cid,
                            kernelet,
                            None,
                            Some(Box::new(move || {
                                if let Some(admission) = admission {
                                    admission.release_after_destroy();
                                }
                            })),
                        );
                    } else if let Some(admission) = self.admission.lock().take() {
                        admission.release_after_destroy();
                    }
                }
            }
            SandboxState::Starting { .. } | SandboxState::Destroying | SandboxState::Gone(_) => {}
        }
    }
}
