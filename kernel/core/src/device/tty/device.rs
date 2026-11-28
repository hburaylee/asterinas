// SPDX-License-Identifier: MPL-2.0

//! TTY devices.
//!
//! This module implements TTY devices such as `/dev/tty0`, `/dev/tty`, and `/dev/console`.
//!
//! Reference: <https://www.kernel.org/doc/html/latest/admin-guide/devices.html>

use aster_device::common::{Attr, Error as DeviceError, SysStr};
use device_id::{DeviceId, MajorId, MinorId};
use spin::Once;

use super::{
    class::{AnyTtyDevice, TtyClassDevice, add_tty_device, find_device},
    vt::active_vt,
};
use crate::{
    fs::file::{PerOpenFileOps, mkmod},
    prelude::*,
};

/// Corresponds to `/dev/tty0` in the file system. This device represents the active virtual
/// terminal.
pub(crate) struct Tty0Device;

impl AnyTtyDevice for Tty0Device {
    fn devnode_name(&self) -> Option<SysStr> {
        Some("tty0".into())
    }

    fn device_id(&self) -> DeviceId {
        DeviceId::new(MajorId::new(4), MinorId::new(0))
    }

    fn open_file(&self) -> Result<Box<dyn PerOpenFileOps>> {
        active_vt().open_file()
    }
}

/// Corresponds to `/dev/tty` in the file system. This device represents the controlling terminal
/// of the session of the current process.
pub(crate) struct TtyDevice;

impl AnyTtyDevice for TtyDevice {
    fn devnode_name(&self) -> Option<SysStr> {
        Some("tty".into())
    }

    fn device_id(&self) -> DeviceId {
        DeviceId::new(MajorId::new(5), MinorId::new(0))
    }

    fn devnode_mode(&self) -> u16 {
        // Reference: <https://elixir.bootlin.com/linux/v6.18/source/drivers/tty/tty_io.c#L3511>.
        mkmod!(a+rw).bits()
    }

    fn open_file(&self) -> Result<Box<dyn PerOpenFileOps>> {
        let Some(terminal) = current!().terminal() else {
            return Err(errno!(
                ENOTTY,
                "the process does not have a controlling terminal"
            ));
        };

        terminal.open()
    }
}

/// Corresponds to `/dev/console` in the file system. This device represents a console to which
/// system messages will be sent.
pub(crate) struct SystemConsole {
    inner: Arc<dyn AnyTtyDevice>,
    active_name: &'static str,
}

/// The device ID of `/dev/console`.
pub(crate) const CONSOLE_DEVICE_ID: DeviceId = DeviceId::new(MajorId::new(5), MinorId::new(1));

impl SystemConsole {
    /// Creates the console device that forwards I/O to the TTY selected by `console=`.
    pub(super) fn from_console_param() -> Self {
        // TODO: Support specifying multiple TTY devices, e.g., "console=hvc0 console=tty0".
        let console_name = CONSOLES
            .get()
            .and_then(|consoles| consoles.first().map(|s| s.as_str()))
            .unwrap_or("tty0");

        let console: Option<Arc<dyn AnyTtyDevice>> = match console_name {
            "tty0" => Some(Arc::new(Tty0Device)),
            "ttyS0" => find_device("ttyS0"),
            "hvc0" => find_device("hvc0"),
            _ => None,
        };
        let (inner, active_name) = match console {
            Some(inner) => (inner, console_name),
            None => {
                warn!(
                    "'{}' console not found, falling back to 'tty0'",
                    console_name
                );
                (Arc::new(Tty0Device) as Arc<dyn AnyTtyDevice>, "tty0")
            }
        };

        Self { inner, active_name }
    }

    /// Returns the name of the TTY this console forwards to.
    fn active_name(&self) -> &'static str {
        self.active_name
    }
}

impl AnyTtyDevice for SystemConsole {
    fn devnode_name(&self) -> Option<SysStr> {
        Some("console".into())
    }

    fn device_id(&self) -> DeviceId {
        CONSOLE_DEVICE_ID
    }

    fn attrs(&self) -> &'static [Attr<TtyClassDevice>] {
        const ATTRS: &[Attr<TtyClassDevice>] = &[Attr::ro("active", |dev, w| {
            let payload: &dyn Any = dev.payload().as_ref();
            let console = payload
                .downcast_ref::<SystemConsole>()
                .ok_or(DeviceError::Attribute)?;
            writeln!(w, "{}", console.active_name())?;
            Ok(())
        })];
        ATTRS
    }

    fn open_file(&self) -> Result<Box<dyn PerOpenFileOps>> {
        self.inner.open_file()
    }
}

pub(super) fn init_in_first_process() -> Result<()> {
    add_tty_device(Arc::new(Tty0Device), None)?;
    add_tty_device(Arc::new(TtyDevice), None)?;

    Ok(())
}

static CONSOLES: Once<Vec<String>> = Once::new();
aster_cmdline::define_repeatable_kv_param!("console", CONSOLES);
