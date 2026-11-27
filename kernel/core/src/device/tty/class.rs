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
        file::{InodeMode, PerOpenFileOps, mkmod},
    },
    prelude::*,
};

/// The `tty` class, which groups terminal devices such as `/dev/ttyS0` and `/dev/console`.
pub(super) struct TtyClass;

/// A device in the `tty` class.
pub(super) type TtyClassDevice = ClassDevice<TtyClass>;

impl Class for TtyClass {
    const NAME: &'static str = "tty";
    type Device = Arc<dyn AnyTtyDevice>;

    fn devnode(&self, dev: &ClassDevice<Self>) -> Option<DevNode> {
        Some(DevNode {
            path: None,
            mode: Some(dev.payload().devnode_mode().bits()),
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
pub(super) trait AnyTtyDevice: Send + Sync + Any {
    /// The name of the device's node under `/dev`.
    ///
    /// `None` for a device without a node of its own (a PTY slave, whose node
    /// belongs to devpts). Such a device cannot join the class.
    fn devnode_name(&self) -> Option<SysStr>;

    /// The device number.
    fn device_id(&self) -> DeviceId;

    /// The permission bits of the `/dev` node.
    fn devnode_mode(&self) -> InodeMode {
        mkmod!(u+rw)
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

/// Registers the `tty` class, creating `/sys/class/tty`.
///
/// Must run before any device joins the class.
pub(super) fn register() -> Result<()> {
    let class = class::register(TtyClass)?;
    TTY_CLASS.call_once(|| class);
    Ok(())
}

/// Adds `payload` to the `tty` class and the char registry.
///
/// `parent` is the sysfs parent. `None` puts the device directly under
/// `/sys/devices/virtual/tty/`. Fails with `EINVAL` if the payload has no node.
pub(super) fn add_tty_device(
    payload: Arc<dyn AnyTtyDevice>,
    parent: Option<Arc<dyn AnyDevice>>,
) -> Result<()> {
    let name = payload
        .devnode_name()
        .ok_or(errno!(EINVAL, "the TTY has no device node"))?;
    let mut builder = TtyClassDevice::builder(TTY_CLASS.get().unwrap(), name, payload.clone())
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
