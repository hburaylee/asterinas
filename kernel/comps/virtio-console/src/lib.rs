// SPDX-License-Identifier: MPL-2.0

//! The VirtIO console driver, which provides the `hvc0` TTY.
//!
//! The hardware side lives in `aster-virtio`; this crate owns the functional driver.
//! When the driver is probed, it registers the console port with the kernel logger
//! and adds `/dev/hvc0` to the `tty` device class.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

use component::{ComponentInitError, init_component};

// Set this crate's log prefix for `ostd::log`.
macro_rules! __log_prefix {
    () => {
        "virtio_console: "
    };
}

mod driver;
mod hvc;

#[init_component]
fn init() -> Result<(), ComponentInitError> {
    aster_virtio::driver::register_driver(driver::ConsoleDriver).unwrap();
    Ok(())
}
