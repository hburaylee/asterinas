// SPDX-License-Identifier: MPL-2.0

use alloc::boxed::Box;

use ostd::arch::boot::DEVICE_TREE;

mod ns16550a;
mod sifive;

pub(super) fn init() {
    let device_tree = DEVICE_TREE.get().unwrap();

    // As before, the NS16550A takes precedence: when it is found, no other
    // serial device is registered.
    if let Some(node) = device_tree.find_compatible(&ns16550a::FDT_COMPATIBLES) {
        add_serial_device(node.name, ns16550a::parse_resource(&node));
    } else if let Some(node) = device_tree.find_compatible(&sifive::FDT_COMPATIBLES) {
        add_serial_device(node.name, sifive::parse_resource(&node));
    }

    if let Err(error) = aster_platform::register_driver(Box::new(ns16550a::Ns16550aSerialDriver)) {
        ostd::warn!("failed to register the ns16550a driver: {:?}", error);
    }
    if let Err(error) = aster_platform::register_driver(Box::new(sifive::SiFiveSerialDriver)) {
        ostd::warn!("failed to register the sifive-uart driver: {:?}", error);
    }
}

fn add_serial_device(name: &'static str, resource: Option<aster_platform::PlatformResource>) {
    if let Some(resource) = resource {
        if let Err(error) = aster_platform::add_device(name, resource) {
            ostd::warn!(
                "failed to register the serial device {:?}: {:?}",
                name,
                error
            );
        }
    }
}
