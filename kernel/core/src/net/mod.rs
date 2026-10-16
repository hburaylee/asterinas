// SPDX-License-Identifier: MPL-2.0

mod iface;
#[cfg(ktest)]
pub(crate) use iface::{init_loopback_for_ktest, poll_loopback_for_ktest};
mod route;
pub(crate) mod socket;
pub(crate) mod uts_ns;

pub(crate) fn init() {
    iface::init();
    route::init();
    socket::netlink::init();
    socket::vsock::init();
}

/// Lazy init should be called after spawning init thread.
pub(crate) fn init_in_first_kthread() {
    iface::init_in_first_kthread();
}
