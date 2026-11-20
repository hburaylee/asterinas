// SPDX-License-Identifier: MPL-2.0

//! The LoongArch serial port: an NS16550A at a fixed MMIO address,
//! statically declared as a platform device and driven by the
//! `loongson-uart` driver.

use alloc::{boxed::Box, string::ToString, sync::Arc};

use aster_platform::{
    Attr, BusDevice, Driver, PlatformBus, PlatformDevice, PlatformResource, Result,
};
use ostd::arch::serial::SERIAL_PORT;

use crate::console::{Uart, UartConsole};

/// The compatible string of the statically declared LoongArch serial device.
const LOONGARCH_SERIAL_COMPATIBLE: &str = "loongson-uart";

pub(super) fn init() {
    if SERIAL_PORT.get().is_none() {
        return;
    }

    let resource = PlatformResource::new(LOONGARCH_SERIAL_COMPATIBLE, None);
    if let Err(error) = aster_platform::add_device("serial0", resource) {
        ostd::warn!("failed to register the loongson-uart device: {:?}", error);
        return;
    }

    if let Err(error) = aster_platform::register_driver(Box::new(LoongsonUartDriver)) {
        ostd::warn!("failed to register the loongson-uart driver: {:?}", error);
    }
}

/// The driver for the LoongArch serial device.
pub(super) struct LoongsonUartDriver;

impl Driver<PlatformBus> for LoongsonUartDriver {
    fn name(&self) -> &str {
        LOONGARCH_SERIAL_COMPATIBLE
    }

    fn match_data(&self) -> &'static [&'static str] {
        &[LOONGARCH_SERIAL_COMPATIBLE]
    }

    fn on_probe(&self, dev: &Arc<PlatformDevice>) -> Result<()> {
        let Some(serial_port) = SERIAL_PORT.get() else {
            return Ok(());
        };

        let console = UartConsole::new(serial_port, dev.clone());
        aster_console::register_device(
            aster_console::UART_CONSOLE_NAME.to_string(),
            console.clone(),
        );

        // TODO: Set up the IRQ line and handle the received data.
        // Suppress the dead code warnings of the related methods.
        let _ = || console.trigger_input_callbacks();
        let _ = || console.uart().flush();

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
