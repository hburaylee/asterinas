// SPDX-License-Identifier: MPL-2.0

use ostd::arch::serial::SERIAL_PORT;

use crate::{
    alloc::string::ToString,
    console::{Uart, UartConsole},
};

pub(super) fn init() {
    let Some(uart) = SERIAL_PORT.get() else {
        return;
    };

    let uart_console = UartConsole::new(uart);

    crate::register_console(uart_console.clone());

    // TODO: Set up the IRQ line and handle the received data.
    // Suppress the dead code warnings of the related methods.
    let _ = || uart_console.trigger_input_callbacks();
    let _ = || uart.flush();

    ostd::info!("Registered NS16550A as a console");
}
