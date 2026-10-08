// SPDX-License-Identifier: MPL-2.0

//! Guest resolver setup for the kernel's static IPv4 network.

use anyhow::{Result, ensure};

use super::{GATEWAY, GUEST, NetworkConfig};

/// Configures the resolver for the kernel's static IPv4 network.
pub fn configure(config: &NetworkConfig) -> Result<()> {
    ensure!(
        config.address == GUEST && config.prefix_len == 24 && config.gateway == GATEWAY,
        "guest networking requires the kernel's static IPv4 configuration"
    );
    // SAFETY: the interface name is a statically terminated C string.
    let index = unsafe { libc::if_nametoindex(c"eth0".as_ptr()) };
    ensure!(index != 0, "guest eth0 is unavailable");
    std::fs::create_dir_all("/etc")?;
    std::fs::write(
        "/etc/resolv.conf",
        format!("nameserver {}\n", config.resolver),
    )?;
    Ok(())
}
