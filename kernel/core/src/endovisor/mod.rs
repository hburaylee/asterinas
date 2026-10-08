// SPDX-License-Identifier: MPL-2.0

//! Hosts OSDK-built kernelet images behind the `/dev/kernelet` control device.

mod device;
mod io_accounting;
mod log_endpoint;
mod placement;
mod policy;
mod reaper;
mod sandbox;
mod virtio_block;
mod virtio_console;
mod virtio_mmio;
mod virtio_net;
mod virtio_rng;
mod virtio_vsock;
mod vsock_switch;

use device_id::MajorId;
use ostd::kernelet::control::KerneletKind;
use spin::Once;

use crate::prelude::*;

include!(concat!(env!("OUT_DIR"), "/kernelet_image.rs"));

static IMAGE: Once<KerneletKind> = Once::new();

// Keep the independently usable ioctl ABI's unit consistent with OSTD grants.
const _: () = assert!(kernelet_abi::GRAIN_SIZE_BYTES == ostd::kernelet::abi::GRAIN_SIZE as u64);

pub(crate) fn init(major: MajorId) -> Result<()> {
    let Some(image) = EMBEDDED_IMAGE else {
        return Ok(());
    };
    let kind = KerneletKind::register(image)
        .map_err(|_| Error::with_message(Errno::EINVAL, "invalid embedded kernelet image"))?;
    IMAGE.call_once(|| kind);
    reaper::init();
    device::register(major)
}

fn image_kind() -> Result<&'static KerneletKind> {
    IMAGE
        .get()
        .ok_or_else(|| Error::with_message(Errno::ENODEV, "no kernelet image registered"))
}
