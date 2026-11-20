// SPDX-License-Identifier: MPL-2.0

//! The platform bus: devices whose hardware is statically known to the
//! system, as opposed to devices discovered on an enumerable bus such as PCI.
//!
//! The bus itself knows nothing about where a device's resources came from.
//! Device creators (e.g., the UART code) normalize the resources into a
//! [`PlatformResource`] before calling [`add_device`]: the FDT is parsed
//! on the creator's side, and statically known devices are declared as
//! identity nodes.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::{boxed::Box, sync::Arc};

use aster_device::{
    bus::{self, BusHandle, DriverHandle},
    common::Error,
    uevent::UeventVars,
};
// Re-exported for driver implementors, which otherwise have no reason to
// depend on aster-device directly.
pub use aster_device::{
    bus::{Bus, BusDevice, Driver},
    common::{AnyDevice, Attr, Result},
};
use component::{ComponentInitError, init_component};
use ostd::io::IoMem;
#[cfg(any(
    target_arch = "x86_64",
    target_arch = "riscv64",
    target_arch = "aarch64"
))]
use ostd::{
    arch::irq::MappedIrqLine,
    sync::{LocalIrqDisabled, SpinLock},
};
use spin::Once;

/// A device on the platform bus.
pub type PlatformDevice = BusDevice<PlatformBus>;

/// The payload of a platform device: its identity and hardware resources,
/// normalized by the device creator.
///
/// The discovery source does not exist beyond this point.
#[derive(Debug)]
pub struct PlatformResource {
    compatible: &'static str,
    io_mem: Option<IoMem>,
    /// The mapped interrupt line, if any.
    ///
    /// `on_active` requires `&mut self`; drivers reach the line through the
    /// shared device, so it is wrapped for interior mutability.
    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "riscv64",
        target_arch = "aarch64"
    ))]
    irq: Option<SpinLock<MappedIrqLine, LocalIrqDisabled>>,
    /// The clock frequency of the device (FDT `clock-frequency`), in Hz.
    ///
    /// Consumed by drivers whose device timing depends on it
    /// (e.g., the SiFive UART baud rate).
    clock_hz: Option<u32>,
}

impl PlatformResource {
    /// Creates a resource for a device identified by `compatible`.
    ///
    /// `io_mem` is `None` for devices whose driver reaches the hardware
    /// through other means (e.g., the early-probed serial port).
    pub fn new(compatible: &'static str, io_mem: Option<IoMem>) -> Self {
        Self {
            compatible,
            io_mem,
            #[cfg(any(
                target_arch = "x86_64",
                target_arch = "riscv64",
                target_arch = "aarch64"
            ))]
            irq: None,
            clock_hz: None,
        }
    }

    /// Attaches the mapped interrupt line of the device.
    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "riscv64",
        target_arch = "aarch64"
    ))]
    pub fn with_irq(self, irq: MappedIrqLine) -> Self {
        let mut this = self;
        this.irq = Some(SpinLock::new(irq));
        this
    }

    /// Sets the clock frequency of the device.
    pub fn with_clock_hz(mut self, clock_hz: u32) -> Self {
        self.clock_hz = Some(clock_hz);
        self
    }

    /// Returns the compatible string, used for matching devices with drivers.
    pub fn compatible(&self) -> &'static str {
        self.compatible
    }

    /// Returns the memory-mapped I/O region, if any.
    ///
    /// `IoMem` is a clonable handle; drivers take their copy.
    pub fn io_mem(&self) -> Option<IoMem> {
        self.io_mem.clone()
    }

    /// Returns the mapped interrupt line, if any.
    ///
    /// Its lifetime is held by the platform device; drivers register
    /// callbacks on it under the lock.
    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "riscv64",
        target_arch = "aarch64"
    ))]
    pub fn irq(&self) -> Option<&SpinLock<MappedIrqLine, LocalIrqDisabled>> {
        self.irq.as_ref()
    }

    /// Returns the clock frequency of the device, if any.
    pub fn clock_hz(&self) -> Option<u32> {
        self.clock_hz
    }
}

/// The platform bus, which owns `/sys/bus/platform`.
pub struct PlatformBus;

impl Bus for PlatformBus {
    const NAME: &'static str = "platform";

    type Device = PlatformResource;
    type MatchData = [&'static str];

    fn matches(&self, dev: &Self::Device, expected: &Self::MatchData) -> bool {
        expected.contains(&dev.compatible())
    }

    fn append_uevent_vars(&self, _dev: &BusDevice<Self>, _vars: &mut UeventVars) -> Result<()> {
        Ok(())
    }

    fn dev_attrs(&self) -> &'static [Attr<BusDevice<Self>>] {
        const COMPATIBLE: Attr<BusDevice<PlatformBus>> = Attr::ro("compatible", |dev, writer| {
            writeln!(writer, "{}", dev.payload().compatible()).map_err(|_| Error::Attribute)?;
            Ok(())
        });
        const ATTRS: &[Attr<BusDevice<PlatformBus>>] = &[COMPATIBLE];
        ATTRS
    }
}

static PLATFORM_BUS: Once<Arc<BusHandle<PlatformBus>>> = Once::new();

/// The registered platform bus.
pub fn bus() -> Arc<BusHandle<PlatformBus>> {
    PLATFORM_BUS
        .get()
        .expect("the platform bus has been initialized")
        .clone()
}

#[init_component]
fn init() -> Result<(), ComponentInitError> {
    let handle = bus::register(PlatformBus).map_err(|_| ComponentInitError::Unknown)?;
    PLATFORM_BUS.call_once(move || handle);
    Ok(())
}

/// Creates and registers a platform device.
///
/// The resources are normalized by the caller; the bus does not discover
/// devices on its own.
pub fn add_device(
    name: &'static str,
    resource: PlatformResource,
) -> Result<Arc<BusDevice<PlatformBus>>> {
    let bus = bus();
    let device = BusDevice::builder(&bus, name, resource).build();
    aster_device::add_device(&device)?;
    Ok(device)
}

/// Registers a platform driver.
///
/// Devices registered before (or after) the driver are bound automatically.
pub fn register_driver(
    driver: Box<dyn Driver<PlatformBus>>,
) -> Result<Arc<DriverHandle<PlatformBus>>> {
    bus().register_driver(driver)
}
