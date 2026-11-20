// SPDX-License-Identifier: MPL-2.0

//! The PL011 UART: an ARM prime cell UART discovered in the FDT by the
//! early boot code and statically declared as a platform device.

use alloc::{boxed::Box, string::ToString, sync::Arc};

use aster_platform::{
    Attr, BusDevice, Driver, PlatformBus, PlatformDevice, PlatformResource, Result,
};
use fdt_util::AcquireIrqLines;
use ostd::arch::serial::{Pl011Uart, SERIAL_PORT};

use crate::console::{Uart, UartConsole, UartMut};

/// The compatible string of the PL011 serial device.
const PL011_COMPATIBLE: &str = "arm,pl011";

pub(super) fn init() {
    let Some(uart) = SERIAL_PORT.get() else {
        return;
    };

    // The early-probed UART keeps its FDT node. The IRQ line acquired from
    // it is held by the platform device.
    let node = uart.lock().fdt_node();
    let Some([irq_line]) = node.acquire_irq_lines() else {
        return;
    };

    let resource = PlatformResource::new(PL011_COMPATIBLE, None).with_irq(irq_line);
    if let Err(error) = aster_platform::add_device(node.name, resource) {
        ostd::warn!("failed to register the pl011 device: {:?}", error);
        return;
    }

    if let Err(error) = aster_platform::register_driver(Box::new(Pl011SerialDriver)) {
        ostd::warn!("failed to register the pl011 driver: {:?}", error);
    }
}

/// The driver for the PL011 serial device.
pub(super) struct Pl011SerialDriver;

impl Driver<PlatformBus> for Pl011SerialDriver {
    fn name(&self) -> &str {
        "pl011"
    }

    fn match_data(&self) -> &'static [&'static str] {
        &[PL011_COMPATIBLE]
    }

    fn on_probe(&self, dev: &Arc<PlatformDevice>) -> Result<()> {
        let Some(uart) = SERIAL_PORT.get() else {
            return Ok(());
        };
        let Some(irq_line) = dev.payload().irq() else {
            return Ok(());
        };

        let console = UartConsole::new(uart, dev.clone());
        aster_console::register_device(
            aster_console::UART_CONSOLE_NAME.to_string(),
            console.clone(),
        );

        // The IRQ line is kept alive by the platform device.
        let cloned_console = console.clone();
        irq_line
            .lock()
            .on_active(move |_| cloned_console.trigger_input_callbacks());
        uart.lock().enable_recv_interrupt();
        console.uart().flush();

        ostd::info!("registered PL011 as a console");
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

impl UartMut for Pl011Uart {
    fn send_byte(&mut self, byte: u8) {
        self.send(byte);
    }

    fn recv_byte(&mut self) -> Option<u8> {
        self.recv()
    }
}
