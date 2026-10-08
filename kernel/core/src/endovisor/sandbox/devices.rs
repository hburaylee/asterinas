// SPDX-License-Identifier: MPL-2.0

//! Virtual device slots, device-model dispatch, and the sandbox's Host hooks.

use kernelet_abi::KILL_INTERNAL_ERROR;
use ostd::{
    kernelet::{
        abi::{INVALID, MmioResult},
        control::{Kernelet, KerneletHooks, KerneletState, KillReason},
    },
    task::Task,
};
use spin::Once;

use crate::{
    endovisor::{
        log_endpoint::LogEndpoint,
        placement::CpuReservation,
        policy::{Admission, PrestartEndpointReservation},
        virtio_block::VirtioBlock,
        virtio_console::{ConsoleEndpoint, VirtioConsole},
        virtio_net::{NetEndpoint, VirtioNet},
        virtio_rng::VirtioRng,
        virtio_vsock::VirtioVsock,
    },
    prelude::*,
    sched::{Nice, SchedPolicy},
    thread::{AsThread, Thread, kernel_thread::ThreadOptions},
    time::clocks::RealTimeClock,
};

/// Size and command-line spelling of each virtual MMIO register window.
pub(super) const MMIO_WINDOW_BYTES: u32 = 4096;
pub(super) const MMIO_CMDLINE_PREFIX: &str = "virtio_mmio.device=";
const MMIO_BASE: u64 = 0x8000_0000_0000;
const IRQ_BASE: u8 = 64;
const MAX_DEVICE_ID: u16 = 63;
const ADDITIONAL_BLOCK_ID_OFFSET: u16 = 4;
// Device IDs specified by VirtIO 1.3, section 5 (Device Types).
// https://docs.oasis-open.org/virtio/virtio/v1.3/virtio-v1.3.html
const VIRTIO_NET: u32 = 1;
const VIRTIO_BLOCK: u32 = 2;
const VIRTIO_CONSOLE: u32 = 3;
const VIRTIO_RNG: u32 = 4;
const VIRTIO_VSOCK: u32 = 19;

/// Slots fixed by the endovisor's device ABI, including additional block disks.
#[derive(Clone, Copy)]
pub(super) enum DeviceSlot {
    Block(u16),
    Console,
    Vsock,
    Rng,
    Net,
}
impl DeviceSlot {
    pub(super) const MAX_BLOCKS: usize = (MAX_DEVICE_ID - ADDITIONAL_BLOCK_ID_OFFSET + 1) as usize;
    pub(super) fn from_wire_id(id: u16) -> Option<Self> {
        Some(match id {
            0 => Self::Block(0),
            1 => Self::Console,
            2 => Self::Vsock,
            3 => Self::Rng,
            4 => Self::Net,
            5..=MAX_DEVICE_ID => Self::Block(id - ADDITIONAL_BLOCK_ID_OFFSET),
            _ => return None,
        })
    }
    pub(super) fn wire_id(self) -> u16 {
        match self {
            Self::Block(0) => 0,
            Self::Console => 1,
            Self::Vsock => 2,
            Self::Rng => 3,
            Self::Net => 4,
            Self::Block(index) => index + ADDITIONAL_BLOCK_ID_OFFSET,
        }
    }
    pub(super) fn mmio_base(self) -> u64 {
        MMIO_BASE + u64::from(self.wire_id()) * u64::from(MMIO_WINDOW_BYTES)
    }
    pub(super) fn irq(self) -> u8 {
        IRQ_BASE + self.wire_id() as u8
    }
    pub(super) fn device_type(self) -> u32 {
        match self {
            Self::Block(_) => VIRTIO_BLOCK,
            Self::Console => VIRTIO_CONSOLE,
            Self::Vsock => VIRTIO_VSOCK,
            Self::Rng => VIRTIO_RNG,
            Self::Net => VIRTIO_NET,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum DeviceModel<'a> {
    Block(&'a Arc<VirtioBlock>),
    Console(&'a Arc<VirtioConsole>),
    Vsock(&'a Arc<VirtioVsock>),
    Rng(&'a Arc<VirtioRng>),
    Net(&'a Arc<VirtioNet>),
}
impl DeviceModel<'_> {
    pub(super) fn start_worker(self) {
        match self {
            Self::Block(x) => x.start_worker(),
            Self::Console(x) => x.start_worker(),
            Self::Vsock(x) => x.start_worker(),
            Self::Rng(x) => x.start_worker(),
            Self::Net(x) => x.start_worker(),
        }
    }
    fn cancel(self) {
        match self {
            Self::Block(x) => x.cancel(),
            Self::Console(x) => x.cancel(),
            Self::Vsock(x) => x.cancel(),
            Self::Rng(x) => x.cancel(),
            Self::Net(x) => x.cancel(),
        }
    }
    fn read(self, offset: u32, width: u32) -> MmioResult {
        match self {
            Self::Block(x) => x.read(offset, width),
            Self::Console(x) => x.read(offset, width),
            Self::Vsock(x) => x.read(offset, width),
            Self::Rng(x) => x.read(offset, width),
            Self::Net(x) => x.read(offset, width),
        }
    }
    fn write(self, offset: u32, width: u32, value: u64) -> i64 {
        match self {
            Self::Block(x) => x.write(offset, width, value),
            Self::Console(x) => x.write(offset, width, value),
            Self::Vsock(x) => x.write(offset, width, value),
            Self::Rng(x) => x.write(offset, width, value),
            Self::Net(x) => x.write(offset, width, value),
        }
    }
}

impl SandboxDevices {
    fn lookup(&self, id: u16) -> Option<DeviceModel<'_>> {
        match DeviceSlot::from_wire_id(id)? {
            DeviceSlot::Block(index) => self.blocks.get(index as usize).map(DeviceModel::Block),
            DeviceSlot::Console => self.console.as_ref().map(DeviceModel::Console),
            DeviceSlot::Vsock => self.vsock.as_ref().map(DeviceModel::Vsock),
            DeviceSlot::Rng => self.rng.as_ref().map(DeviceModel::Rng),
            DeviceSlot::Net => self.net.as_ref().map(DeviceModel::Net),
        }
    }
    pub(super) fn for_each<'a>(&'a self, mut f: impl FnMut(DeviceModel<'a>)) {
        for block in &self.blocks {
            f(DeviceModel::Block(block));
        }
        if let Some(x) = &self.console {
            f(DeviceModel::Console(x));
        }
        if let Some(x) = &self.vsock {
            f(DeviceModel::Vsock(x));
        }
        if let Some(x) = &self.net {
            f(DeviceModel::Net(x));
        }
        if let Some(x) = &self.rng {
            f(DeviceModel::Rng(x));
        }
    }
}

pub(super) struct SandboxHooks {
    pub(super) devices: Once<SandboxDevices>,
    pub(super) console_endpoint: Option<Arc<ConsoleEndpoint>>,
    pub(super) net_endpoint: Option<Arc<NetEndpoint>>,
    pub(super) log_endpoint: Option<Arc<LogEndpoint>>,
    pub(super) _endpoint_reservations: Vec<Arc<PrestartEndpointReservation>>,
    pub(super) admission: Arc<Admission>,
    pub(super) _placement: CpuReservation,
    pub(super) carriers: SpinLock<Vec<Weak<Thread>>>,
}

pub(super) struct SandboxDevices {
    pub(super) blocks: Vec<Arc<VirtioBlock>>,
    pub(super) console: Option<Arc<VirtioConsole>>,
    pub(super) vsock: Option<Arc<VirtioVsock>>,
    pub(super) net: Option<Arc<VirtioNet>>,
    pub(super) rng: Option<Arc<VirtioRng>>,
}

impl SandboxHooks {
    pub(super) fn cancel(&self) {
        let Some(devices) = self.devices.get() else {
            return;
        };
        devices.for_each(|device| device.cancel());
    }

    pub(super) fn revoke_endpoints(&self) {
        if let Some(console) = &self.console_endpoint {
            console.revoke();
        }
        if let Some(net) = &self.net_endpoint {
            net.revoke();
        }
        if let Some(log) = &self.log_endpoint {
            log.revoke();
        }
    }
}

impl KerneletHooks for SandboxHooks {
    fn realtime_now(&self) -> core::time::Duration {
        RealTimeClock::get().read_time()
    }

    fn create_vcpu_thread(
        &self,
        kernelet: &Arc<Kernelet>,
        vcpu: u16,
        host_cpu: ostd::cpu::CpuId,
        nice: i8,
    ) -> ostd::Result<Arc<Task>> {
        let kernelet = Arc::downgrade(kernelet);
        let nice = Nice::try_from(nice).map_err(|_| ostd::Error::InvalidArgs)?;
        let task = ThreadOptions::new(move || {
            let Some(kernelet) = kernelet.upgrade() else {
                return;
            };
            if let Err(error) = kernelet.run_vcpu(vcpu)
                && matches!(
                    kernelet.state(),
                    KerneletState::Created | KerneletState::Running
                )
            {
                ostd::error!("kernelet carrier {} failed: {:?}", vcpu, error);
                let _ = kernelet.kill(KillReason::HostPolicy(KILL_INTERNAL_ERROR));
            }
        })
        .cpu_affinity(host_cpu.into())
        .sched_policy(SchedPolicy::Fair(nice))
        .build();
        self.carriers
            .lock()
            .push(Arc::downgrade(task.as_thread().unwrap()));
        Ok(task)
    }

    fn on_grant_exhausted(&self, requested: u32) -> u32 {
        self.admission.reserve_grains(requested)
    }

    fn on_grant_settled(&self, reserved: u32, committed: u32) {
        self.admission.settle_grains(reserved, committed);
    }

    fn set_vcpu_nice(&self, nice: i8) -> ostd::Result<()> {
        let nice = Nice::try_from(nice).map_err(|_| ostd::Error::InvalidArgs)?;
        let carriers = self.carriers.lock();
        if carriers.is_empty() {
            return Err(ostd::Error::InvalidArgs);
        }
        for thread in carriers.iter().filter_map(Weak::upgrade) {
            thread.sched_attr().set_policy(SchedPolicy::Fair(nice));
        }
        Ok(())
    }

    fn mmio_read(&self, device: u16, offset: u32, width: u32) -> MmioResult {
        let devices = self
            .devices
            .get()
            .expect("devices initialized before start");
        devices.lookup(device).map_or(
            MmioResult {
                status: -INVALID,
                value: 0,
            },
            |device| device.read(offset, width),
        )
    }

    fn mmio_write(&self, device: u16, offset: u32, width: u32, value: u64) -> i64 {
        let devices = self
            .devices
            .get()
            .expect("devices initialized before start");
        devices
            .lookup(device)
            .map_or(-INVALID, |device| device.write(offset, width, value))
    }

    fn log(&self, level: u32, module: &str, text: &str) -> bool {
        self.log_endpoint
            .as_ref()
            .is_some_and(|log| log.push(level, module, text))
    }

    fn on_oops(&self, message: &str) {
        let _ = self
            .log_endpoint
            .as_ref()
            .map(|log| log.push(0, "oops", message));
    }
}
