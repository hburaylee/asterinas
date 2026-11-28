// SPDX-License-Identifier: MPL-2.0

//! Universal asynchronous receiver-transmitter (UART).

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::{string::ToString, sync::Arc};

use aster_console::AnyConsoleDevice;
use component::{ComponentInitError, init_component};

// Set this crate's log prefix for `ostd::log`.
macro_rules! __log_prefix {
    () => {
        "uart: "
    };
}

#[cfg_attr(target_arch = "x86_64", path = "arch/x86/mod.rs")]
#[cfg_attr(target_arch = "riscv64", path = "arch/riscv/mod.rs")]
#[cfg_attr(target_arch = "loongarch64", path = "arch/loongarch/mod.rs")]
#[cfg_attr(target_arch = "aarch64", path = "arch/arm/mod.rs")]
mod arch;

mod console;
mod serial;

#[init_component]
fn init() -> Result<(), ComponentInitError> {
    arch::init();
    Ok(())
}

/// Publishes the UART console to the kernel logger and registers it as `/dev/ttyS0`.
///
/// A failure to register the TTY is logged rather than fatal: the console remains usable
/// through the logger, and `/dev/console` falls back to `tty0`.
pub(crate) fn register_console(console: Arc<dyn AnyConsoleDevice>) {
    aster_console::register_device(
        aster_console::UART_CONSOLE_NAME.to_string(),
        console.clone(),
    );

    if let Err(error) = serial::register(console) {
        ostd::warn!("failed to register the serial TTY: {:?}", error);
    }
}
