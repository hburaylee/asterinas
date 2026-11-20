// SPDX-License-Identifier: MPL-2.0

//! The x86 ISA serial port: an NS16550A at I/O port 0x3F8, statically
//! declared as a platform device and driven by the `isa-serial` driver.

use alloc::{boxed::Box, string::ToString, sync::Arc};

use aster_platform::{
    Attr, BusDevice, Driver, PlatformBus, PlatformDevice, PlatformResource, Result,
};
use ostd::{
    arch::{
        irq::{IRQ_CHIP, MappedIrqLine},
        serial::SERIAL_PORT,
    },
    irq::IrqLine,
};
use spin::Once;

use crate::console::{Uart, UartConsole};

/// The compatible string of the statically declared ISA serial device.
const ISA_SERIAL_COMPATIBLE: &str = "isa-serial";

/// ISA interrupt number for UART serial.
// FIXME: The interrupt number should be retrieved from the ACPI table instead of being hard-coded.
const ISA_INTR_NUM: u8 = 4;

/// IRQ line for UART serial.
///
/// The line is manufactured by the driver (the device is an identity node
/// and carries no IRQ resource), so the driver keeps it alive here.
static IRQ_LINE: Once<MappedIrqLine> = Once::new();

pub(super) fn init() {
    if SERIAL_PORT.get().is_none() {
        return;
    }

    let resource = PlatformResource::new(ISA_SERIAL_COMPATIBLE, None);
    if let Err(error) = aster_platform::add_device("serial0", resource) {
        ostd::warn!("failed to register the isa-serial device: {:?}", error);
        return;
    }

    if let Err(error) = aster_platform::register_driver(Box::new(IsaSerialDriver)) {
        ostd::warn!("failed to register the isa-serial driver: {:?}", error);
    }
}

/// The driver for the ISA serial device.
pub(super) struct IsaSerialDriver;

impl Driver<PlatformBus> for IsaSerialDriver {
    fn name(&self) -> &str {
        ISA_SERIAL_COMPATIBLE
    }

    fn match_data(&self) -> &'static [&'static str] {
        &[ISA_SERIAL_COMPATIBLE]
    }

    fn on_probe(&self, dev: &Arc<PlatformDevice>) -> Result<()> {
        let Some(serial_port) = SERIAL_PORT.get() else {
            return Ok(());
        };

        let Ok(mut irq_line) = IrqLine::alloc().and_then(|irq_line| {
            IRQ_CHIP
                .get()
                .unwrap()
                .map_isa_pin_to(irq_line, ISA_INTR_NUM)
        }) else {
            // As before, the console is not registered without an IRQ line.
            ostd::info!("IRQ line is not available");
            return Ok(());
        };

        let console = UartConsole::new(serial_port, dev.clone());
        aster_console::register_device(
            aster_console::UART_CONSOLE_NAME.to_string(),
            console.clone(),
        );

        let cloned_console = console.clone();
        irq_line.on_active(move |_| cloned_console.trigger_input_callbacks());
        IRQ_LINE.call_once(move || irq_line);
        console.uart().flush();

        ostd::info!("registered NS16550A as a console");
        Ok(())
    }

    fn on_release(&self, _dev: &Arc<PlatformDevice>) {}

    fn dev_attrs(&self) -> &'static [Attr<BusDevice<PlatformBus>>] {
        &[]
    }

    fn suppress_bind_attrs(&self) -> bool {
        false
    }
}
