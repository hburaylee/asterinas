// SPDX-License-Identifier: MPL-2.0

//! The serial TTY, `/dev/ttyS0`, backed by the UART console.

use alloc::{boxed::Box, format, sync::Arc, vec};

use aster_console::AnyConsoleDevice;
use aster_core::{
    device::tty::{SysStr, Tty, TtyDriver, TtyFile, add_tty_device, termio::CTermios},
    fs::file::PerOpenFileOps,
    prelude::*,
};
use ostd::mm::{Infallible, VmReader, VmWriter};

#[derive(Clone)]
struct SerialDriver {
    console: Arc<dyn AnyConsoleDevice>,
}

impl SerialDriver {
    /// The minor ID of `/dev/ttyS0`.
    const MINOR_ID_BASE: u32 = 64;
}

impl TtyDriver for SerialDriver {
    // Reference: <https://elixir.bootlin.com/linux/v6.17/source/include/uapi/linux/major.h#L18>.
    const DEVICE_MAJOR_ID: u32 = 4;

    fn devnode_name(&self, index: u32) -> Option<SysStr> {
        Some(format!("ttyS{}", index - Self::MINOR_ID_BASE).into())
    }

    fn open(tty: Arc<Tty<Self>>) -> Result<Box<dyn PerOpenFileOps>> {
        Ok(Box::new(TtyFile::new(tty)))
    }

    fn push_output(&self, chs: &[u8]) -> Result<usize> {
        self.console.send(chs);
        Ok(chs.len())
    }

    fn echo_callback(&self) -> impl FnMut(&[u8]) + '_ {
        |chs| self.console.send(chs)
    }

    fn can_push(&self) -> bool {
        true
    }

    fn notify_input(&self) {}

    fn on_termios_change(&self, _old_termios: &CTermios, _new_termios: &CTermios) {}
}

/// Registers `console` as `/dev/ttyS0` and routes its input to the TTY.
pub(super) fn register(console: Arc<dyn AnyConsoleDevice>) -> Result<()> {
    let driver = SerialDriver {
        console: console.clone(),
    };
    let tty = Tty::new(SerialDriver::MINOR_ID_BASE, driver);
    add_tty_device(tty.clone(), None)?;

    console.register_callback(Box::leak(Box::new(
        move |mut reader: VmReader<Infallible>| {
            let mut chs = vec![0u8; reader.remain()];
            reader.read(&mut VmWriter::from(chs.as_mut_slice()));
            let _ = tty.push_input(chs.as_slice());
        },
    )));

    Ok(())
}
