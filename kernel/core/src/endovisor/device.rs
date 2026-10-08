// SPDX-License-Identifier: MPL-2.0

//! The `/dev/kernelet` misc device.

use device_id::{DeviceId, MajorId, MinorId};

use crate::{
    device::{Device, DeviceType, register_char_device},
    events::IoEvents,
    fs::{
        devtmpfs::DevtmpfsNodeMeta,
        file::{PerOpenFileOps, StatusFlags},
        vfs::{inode::FileOps, path::Path},
    },
    prelude::*,
    process::signal::{PollHandle, Pollable},
    util::ioctl::RawIoctl,
};

const KERNELET_MINOR: u32 = 242;

#[derive(Debug)]
struct KerneletDevice {
    id: DeviceId,
}

pub(super) fn register(major: MajorId) -> Result<()> {
    register_char_device(Arc::new(KerneletDevice {
        id: DeviceId::new(major, MinorId::new(KERNELET_MINOR)),
    }))
}

impl Device for KerneletDevice {
    fn type_(&self) -> DeviceType {
        DeviceType::Char
    }

    fn id(&self) -> DeviceId {
        self.id
    }

    fn devtmpfs_meta(&self) -> Option<DevtmpfsNodeMeta> {
        Some(DevtmpfsNodeMeta::new("kernelet").unwrap())
    }

    fn open(&self) -> Result<Box<dyn PerOpenFileOps>> {
        Ok(Box::new(KerneletDeviceFile))
    }
}

struct KerneletDeviceFile;

impl Pollable for KerneletDeviceFile {
    fn poll(&self, mask: IoEvents, _poller: Option<&mut PollHandle>) -> IoEvents {
        mask & (IoEvents::IN | IoEvents::OUT)
    }
}

impl FileOps for KerneletDeviceFile {
    fn read_at(
        &self,
        _offset: usize,
        _writer: &mut VmWriter,
        _flags: StatusFlags,
    ) -> Result<usize> {
        return_errno_with_message!(Errno::EINVAL, "kernelet control cannot be read");
    }

    fn write_at(
        &self,
        _offset: usize,
        _reader: &mut VmReader,
        _flags: StatusFlags,
    ) -> Result<usize> {
        return_errno_with_message!(Errno::EINVAL, "kernelet control cannot be written");
    }
}

impl PerOpenFileOps for KerneletDeviceFile {
    fn check_seekable(&self) -> Result<()> {
        return_errno_with_message!(Errno::ESPIPE, "kernelet control is not seekable");
    }

    fn is_offset_aware(&self) -> bool {
        false
    }

    fn ioctl(&self, _path: &Path, raw_ioctl: RawIoctl) -> Result<i32> {
        super::sandbox::create_sandbox(raw_ioctl)
    }
}
