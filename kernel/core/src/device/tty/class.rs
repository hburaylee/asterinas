// SPDX-License-Identifier: MPL-2.0

//! The `tty` class.
//!
//! PTY slaves are not members because devpts owns their nodes.

use aster_device::{
    class::{self, Class, ClassDevice, ClassHandle},
    common::{AnyDevice, Attr, DevNode, DevNum, SysStr},
    uevent::UeventVars,
};
use device_id::DeviceId;
use spin::Once;

use super::device::SystemConsole;
use crate::{
    device::{Device, DeviceType, add_class_char_device},
    fs::{
        devtmpfs::DevtmpfsNodeMeta,
        file::{PerOpenFileOps, mkmod},
    },
    prelude::*,
};

/// The `tty` class, which groups terminal devices such as `/dev/ttyS0` and `/dev/console`.
pub struct TtyClass;

/// A device in the `tty` class.
pub type TtyClassDevice = ClassDevice<TtyClass>;

impl Class for TtyClass {
    const NAME: &'static str = "tty";
    type Device = Arc<dyn AnyTtyDevice>;

    fn devnode(&self, dev: &ClassDevice<Self>) -> Option<DevNode> {
        Some(DevNode {
            path: None,
            mode: Some(dev.payload().devnode_mode()),
        })
    }

    fn dev_attrs(&self) -> &'static [Attr<ClassDevice<Self>>] {
        &[]
    }

    fn append_uevent_vars(
        &self,
        _dev: &ClassDevice<Self>,
        _vars: &mut UeventVars,
    ) -> aster_device::common::Result<()> {
        Ok(())
    }
}

/// What a TTY device provides to the `tty` class.
pub trait AnyTtyDevice: Send + Sync + Any {
    /// The name of the device's node under `/dev`.
    ///
    /// `None` for a device without a node of its own (a PTY slave, whose node
    /// belongs to devpts). Such a device cannot join the class.
    fn devnode_name(&self) -> Option<SysStr>;

    /// The device number.
    fn device_id(&self) -> DeviceId;

    /// The permission bits of the `/dev` node.
    fn devnode_mode(&self) -> u16 {
        mkmod!(u+rw).bits()
    }

    /// The attributes shown in the device's sysfs directory.
    fn attrs(&self) -> &'static [Attr<TtyClassDevice>] {
        &[]
    }

    /// Opens the device.
    fn open_file(&self) -> Result<Box<dyn PerOpenFileOps>>;
}

impl Device for TtyClassDevice {
    fn type_(&self) -> DeviceType {
        DeviceType::Char
    }

    fn id(&self) -> DeviceId {
        self.payload().device_id()
    }

    fn devtmpfs_meta(&self) -> Option<DevtmpfsNodeMeta> {
        // The device model creates the node when the device is added.
        None
    }

    fn open(&self) -> Result<Box<dyn PerOpenFileOps>> {
        self.payload().open_file()
    }
}

static TTY_CLASS: Once<Arc<ClassHandle<TtyClass>>> = Once::new();

/// Returns the `tty` class, registering it on first use.
///
/// Registration is lazy: drivers add TTY devices from their component initialization,
/// which has no explicit ordering with aster-core's own initialization.
fn class() -> Result<&'static Arc<ClassHandle<TtyClass>>> {
    if let Some(class) = TTY_CLASS.get() {
        return Ok(class);
    }
    // A concurrent first caller may have registered the class in the meantime.
    match class::register(TtyClass) {
        Ok(class) => Ok(TTY_CLASS.call_once(|| class)),
        Err(error) => TTY_CLASS.get().ok_or_else(|| error.into()),
    }
}

/// Adds `payload` to the `tty` class and the char registry.
///
/// `parent` is the sysfs parent. `None` puts the device directly under
/// `/sys/devices/virtual/tty/`. Fails with `EINVAL` if the payload has no node.
pub fn add_tty_device(
    payload: Arc<dyn AnyTtyDevice>,
    parent: Option<Arc<dyn AnyDevice>>,
) -> Result<()> {
    let name = payload
        .devnode_name()
        .ok_or(errno!(EINVAL, "the TTY has no device node"))?;
    let mut builder = TtyClassDevice::builder(class()?, name, payload.clone())
        .devnum(DevNum::char(payload.device_id()))
        .attrs(payload.attrs());
    if let Some(parent) = parent {
        builder = builder.parent(parent);
    }
    add_class_char_device(&builder.build())
}

/// Adds `/dev/console`, which forwards I/O to the TTY selected by the `console=` parameter.
///
/// Must run after the other TTY devices have been added, so that the selected TTY exists.
pub(super) fn add_console_device() -> Result<()> {
    add_tty_device(Arc::new(SystemConsole::from_console_param()), None)
}

/// Returns the TTY registered under `name`, e.g. `"hvc0"`.
pub(crate) fn find_device(name: &str) -> Option<Arc<dyn AnyTtyDevice>> {
    let device = class().ok()?.find_device(name)?;
    Some(device.payload().clone())
}
