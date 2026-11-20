// SPDX-License-Identifier: MPL-2.0

//! SiFive UART console support.

use alloc::{string::ToString, sync::Arc};

use aster_platform::{
    Attr, BusDevice, Driver, PlatformBus, PlatformDevice, PlatformResource, Result,
};
use aster_util::{field_ptr, safe_ptr::SafePtr};
use fdt::node::FdtNode;
use fdt_util::{AcquireIoMems, AcquireIrqLines};
use ostd::{
    io::IoMem,
    mm::{VmIoOnce, VmReader},
    sync::{LocalIrqDisabled, SpinLock},
};

use crate::console::{Uart, UartConsole, UartMut};

pub(super) const FDT_COMPATIBLES: [&str; 2] = ["sifive,uart0", "sifive,fu540-c000-uart"];

/// Parses the device resources from the FDT node.
pub(super) fn parse_resource(fdt_node: &FdtNode) -> Option<PlatformResource> {
    let Some([io_mem]) = fdt_node.acquire_io_mems([size_of::<Registers>()]) else {
        return None;
    };
    let Some([irq_line]) = fdt_node.acquire_irq_lines() else {
        return None;
    };

    let clock_hz = fdt_node
        .property("clock-frequency")
        .and_then(|prop| prop.as_usize())
        .and_then(|freq| u32::try_from(freq).ok())
        // FIXME: Real FU540 device trees may provide the UART clock through
        // a PRCI clock provider instead of a direct `clock-frequency` property.
        .unwrap_or(SifiveUart::DEFAULT_CLOCK_HZ);

    Some(
        PlatformResource::new(FDT_COMPATIBLES[0], Some(io_mem))
            .with_irq(irq_line)
            .with_clock_hz(clock_hz),
    )
}

/// The driver for SiFive UART serial devices discovered in the FDT.
pub(super) struct SiFiveSerialDriver;

impl Driver<PlatformBus> for SiFiveSerialDriver {
    fn name(&self) -> &str {
        "sifive-uart"
    }

    fn match_data(&self) -> &'static [&'static str] {
        &FDT_COMPATIBLES
    }

    fn on_probe(&self, dev: &Arc<PlatformDevice>) -> Result<()> {
        let resource = dev.payload();
        let (Some(io_mem), Some(irq_line)) = (resource.io_mem(), resource.irq()) else {
            return Ok(());
        };

        let mut uart = SifiveUart::new(io_mem);
        uart.init(resource.clock_hz().unwrap_or(SifiveUart::DEFAULT_CLOCK_HZ));

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

        ostd::info!("registered SiFive UART as a console");
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

struct SifiveUart {
    registers: SafePtr<Registers, IoMem>,
}

impl SifiveUart {
    const DEFAULT_CLOCK_HZ: u32 = 500_000_000;
    const TARGET_BAUD: u32 = 115_200;

    const TXDATA_FULL: u32 = 1 << 31;
    const RXDATA_EMPTY: u32 = 1 << 31;
    const TXCTRL_TXEN: u32 = 1;
    const RXCTRL_RXEN: u32 = 1;
    const IE_RXWM: u32 = 1 << 1;

    fn new(io_mem: IoMem) -> Self {
        Self {
            registers: SafePtr::new(io_mem, 0),
        }
    }

    fn init(&mut self, clock_hz: u32) {
        let divisor = clock_hz
            .checked_div(Self::TARGET_BAUD)
            .and_then(|quotient| quotient.checked_sub(1))
            .unwrap_or(0);

        field_ptr!(&self.registers, Registers, div)
            .write_once(&divisor)
            .unwrap();
        field_ptr!(&self.registers, Registers, txctrl)
            .write_once(&Self::TXCTRL_TXEN)
            .unwrap();
        field_ptr!(&self.registers, Registers, rxctrl)
            .write_once(&Self::RXCTRL_RXEN)
            .unwrap();
        field_ptr!(&self.registers, Registers, ie)
            .write_once(&Self::IE_RXWM)
            .unwrap();
    }
}

impl UartMut for SifiveUart {
    fn send_byte(&mut self, byte: u8) {
        let txdata = field_ptr!(&self.registers, Registers, txdata);
        while txdata.read_once().unwrap() & Self::TXDATA_FULL != 0 {
            core::hint::spin_loop();
        }

        txdata.write_once(&u32::from(byte)).unwrap();
    }

    fn recv_byte(&mut self) -> Option<u8> {
        let rxdata = field_ptr!(&self.registers, Registers, rxdata)
            .read_once()
            .unwrap();
        if rxdata & Self::RXDATA_EMPTY != 0 {
            return None;
        }

        Some(rxdata as u8)
    }
}

// Register layout and bit definitions are from the SiFive FU540-C000 Manual,
// Chapter 13 "Universal Asynchronous Receiver/Transmitter (UART)".
// Reference: <https://pdos.csail.mit.edu/6.828/2025/readings/FU540-C000-v1.0.pdf>
#[repr(C)]
struct Registers {
    txdata: u32,
    rxdata: u32,
    txctrl: u32,
    rxctrl: u32,
    ie: u32,
    _ip: u32,
    div: u32,
}
