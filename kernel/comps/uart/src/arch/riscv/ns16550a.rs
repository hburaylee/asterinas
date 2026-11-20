// SPDX-License-Identifier: MPL-2.0

//! NS16550A UART console support.

use alloc::{string::ToString, sync::Arc};

use aster_platform::{
    Attr, BusDevice, Driver, PlatformBus, PlatformDevice, PlatformResource, Result,
};
use fdt::node::FdtNode;
use fdt_util::{AcquireIoMems, AcquireIrqLines};
use ostd::{
    console::uart_ns16650a::{Ns16550aAccess, Ns16550aRegister, Ns16550aUart},
    io::IoMem,
    mm::VmIoOnce,
    sync::{LocalIrqDisabled, SpinLock},
};

use crate::console::{Uart, UartConsole};

pub(super) const FDT_COMPATIBLES: [&str; 1] = ["ns16550a"];

/// Access to serial registers via `IoMem`.
struct SerialAccess {
    io_mem: IoMem,
}

impl Ns16550aAccess for SerialAccess {
    fn read(&self, reg: Ns16550aRegister) -> u8 {
        self.io_mem.read_once(reg as u16 as usize).unwrap()
    }

    fn write(&mut self, reg: Ns16550aRegister, val: u8) {
        self.io_mem.write_once(reg as u16 as usize, &val).unwrap();
    }
}

/// Parses the device resources from the FDT node.
pub(super) fn parse_resource(fdt_node: &FdtNode) -> Option<PlatformResource> {
    let Some([io_mem]) =
        fdt_node.acquire_io_mems([const { Ns16550aRegister::MAX as u16 as usize + 1 }])
    else {
        return None;
    };
    let Some([irq_line]) = fdt_node.acquire_irq_lines() else {
        return None;
    };

    Some(PlatformResource::new(FDT_COMPATIBLES[0], Some(io_mem)).with_irq(irq_line))
}

/// The driver for NS16550A serial devices discovered in the FDT.
pub(super) struct Ns16550aSerialDriver;

impl Driver<PlatformBus> for Ns16550aSerialDriver {
    fn name(&self) -> &str {
        "ns16550a"
    }

    fn match_data(&self) -> &'static [&'static str] {
        &FDT_COMPATIBLES
    }

    fn on_probe(&self, dev: &Arc<PlatformDevice>) -> Result<()> {
        let resource = dev.payload();
        let (Some(io_mem), Some(irq_line)) = (resource.io_mem(), resource.irq()) else {
            return Ok(());
        };

        let mut uart = Ns16550aUart::new(SerialAccess { io_mem });
        uart.init();

        let console = UartConsole::new(SpinLock::<_, LocalIrqDisabled>::new(uart), dev.clone());
        aster_console::register_device(
            aster_console::UART_CONSOLE_NAME.to_string(),
            console.clone(),
        );

        // The IRQ line is kept alive by the platform device.
        let cloned_console = console.clone();
        irq_line
            .lock()
            .on_active(move |_| cloned_console.trigger_input_callbacks());
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
