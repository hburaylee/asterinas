// SPDX-License-Identifier: MPL-2.0

//! Console output.

use core::fmt::Arguments;
#[cfg(not(feature = "kernelet"))]
use core::fmt::Write;

#[cfg(not(feature = "kernelet"))]
use crate::arch::serial::SERIAL_PORT;

#[cfg(feature = "kernelet")]
mod kernelet;
pub mod uart_ns16650a;

/// Installs the image logger after the Host service table is available.
#[cfg(feature = "kernelet")]
pub(crate) fn init_kernelet_logging() {
    kernelet::init();
}

/// Prints formatted arguments to the console.
#[cfg(not(feature = "kernelet"))]
pub fn early_print(args: Arguments) {
    let Some(serial) = SERIAL_PORT.get() else {
        return;
    };

    #[cfg(target_arch = "x86_64")]
    crate::arch::if_tdx_enabled!({
        // Hold the lock to prevent the logs from interleaving.
        let _guard = serial.lock();
        tdx_guest::print(args);
    } else {
        serial.lock().write_fmt(args).unwrap();
    });
    #[cfg(not(target_arch = "x86_64"))]
    serial.lock().write_fmt(args).unwrap();
}

/// Prints formatted arguments to the console.
#[cfg(feature = "kernelet")]
pub fn early_print(args: Arguments) {
    kernelet::write(args);
}

/// Prints to the console.
#[macro_export]
macro_rules! early_print {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::console::early_print(format_args!($fmt $(, $($arg)+)?))
    }
}

/// Prints to the console with a newline.
#[macro_export]
macro_rules! early_println {
    () => { $crate::early_print!("\n") };
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::console::early_print(format_args!(concat!($fmt, "\n") $(, $($arg)+)?))
    }
}
