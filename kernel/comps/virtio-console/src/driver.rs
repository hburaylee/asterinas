// SPDX-License-Identifier: MPL-2.0

use alloc::sync::Arc;

use aster_virtio::{
    bus::VirtioDevice,
    device::{VirtioDeviceError, VirtioDeviceType, console::device::ConsoleDevice},
    driver::VirtioDriver,
};

use super::hvc;

/// The functional driver for the VirtIO console device.
pub(crate) struct ConsoleDriver;

impl VirtioDriver for ConsoleDriver {
    fn name(&self) -> &str {
        "virtio_console"
    }

    fn match_data(&self) -> &VirtioDeviceType {
        &VirtioDeviceType::Console
    }

    fn negotiate_features(&self, offered: u64) -> u64 {
        ConsoleDevice::negotiate_features(offered)
    }

    fn probe(
        &self,
        device: Arc<VirtioDevice>,
        negotiated_features: u64,
    ) -> Result<(), VirtioDeviceError> {
        let console = ConsoleDevice::init(device, negotiated_features)?;

        // A failure here leaves the logger console working; `/dev/console` falls back.
        if let Err(error) = hvc::register(console) {
            ostd::warn!("failed to register the hvc0 TTY: {:?}", error);
        }

        Ok(())
    }
}
