// SPDX-License-Identifier: MPL-2.0

//! Hosts OSDK-built kernelet images behind the `/dev/kernelet` control device.
//!
//! This module registers the embedded image as a [`KerneletKind`] and owns
//! the kernel's device model for each sandbox. The control device creates
//! sandboxes and changes their resource limits; sandbox hooks connect OSTD
//! carriers to placement, accounting, logging, and asynchronous reaping.
//! The VirtIO devices service requests from the image through guest memory
//! access APIs and the instance's resource account.

mod device;
mod io_accounting;
#[cfg(all(kernelet_rq1_diagnostics, not(feature = "kernelet")))]
pub(crate) mod io_copy_profile;
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
use ostd::kernelet::control::{CpuBudget, KerneletKind};
#[cfg(all(kernelet_rq1_crossing_diag, not(feature = "kernelet")))]
pub(crate) use sandbox::rq1_crossing_capture;
#[cfg(all(kernelet_rq1_diagnostics, not(feature = "kernelet")))]
pub(crate) use sandbox::rq1_tlb_capture;
use spin::Once;

pub(crate) use self::policy::NativeTcpBufferCharge;
use crate::prelude::*;

static IMAGE: Once<KerneletKind> = Once::new();

// Keep the independently usable ioctl ABI consistent with OSTD's resource policy.
const _: () = {
    assert!(kernelet_abi::GRAIN_SIZE_BYTES == ostd::kernelet::abi::GRAIN_SIZE as u64);
    assert!(kernelet_abi::MIN_NICE == CpuBudget::MIN_NICE);
    assert!(kernelet_abi::MAX_NICE == CpuBudget::MAX_NICE);
};

pub(crate) fn init(major: MajorId) -> Result<()> {
    let Some(kind) = KerneletKind::register_embedded()
        .map_err(|_| Error::with_message(Errno::EINVAL, "invalid embedded kernelet image"))?
    else {
        return Ok(());
    };
    IMAGE.call_once(|| kind);
    reaper::init()
        .map_err(|_| Error::with_message(Errno::EINVAL, "cannot initialize kernelet reaper"))?;
    device::register(major)
}

fn image_kind() -> Result<&'static KerneletKind> {
    IMAGE
        .get()
        .ok_or_else(|| Error::with_message(Errno::ENODEV, "no kernelet image registered"))
}
