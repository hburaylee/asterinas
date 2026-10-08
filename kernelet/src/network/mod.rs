// SPDX-License-Identifier: MPL-2.0

//! Host network configuration and Guest resolver setup.

mod guest;

use std::{collections::BTreeMap, fs::File, net::Ipv4Addr};

use anyhow::{Context, Result, bail, ensure};
pub use guest::configure as configure_guest;
use serde::{Deserialize, Serialize};

use crate::uapi::{
    self, MAX_NET_PORTS, NET_PROTOCOL_TCP, NET_PROTOCOL_UDP, NetConfigArgs, NetPortMapping,
};

const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
const GUEST: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NetworkConfig {
    pub mac: [u8; 6],
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Ipv4Addr,
    pub resolver: Ipv4Addr,
    pub host_resolver: Ipv4Addr,
    pub ports: Vec<PortMapping>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PortMapping {
    pub host_port: u16,
    pub container_port: u16,
    #[serde(default = "localhost")]
    pub host_address: Ipv4Addr,
    #[serde(default = "tcp_protocol")]
    pub protocol: String,
}
fn localhost() -> Ipv4Addr {
    Ipv4Addr::LOCALHOST
}
fn tcp_protocol() -> String {
    "tcp".into()
}

pub fn configure(
    annotations: &BTreeMap<String, String>,
    cid: u32,
) -> Result<Option<NetworkConfig>> {
    match annotations
        .get("org.asterinas.kernelet.network")
        .map(String::as_str)
        .unwrap_or("none")
    {
        "none" => {
            ensure!(
                !annotations.contains_key("org.asterinas.kernelet.ports"),
                "port mappings require NAT networking"
            );
            return Ok(None);
        }
        "nat" => {}
        other => bail!("unsupported kernelet network {other}"),
    }
    let ports: Vec<PortMapping> = annotations
        .get("org.asterinas.kernelet.ports")
        .map(|value| serde_json::from_str(value))
        .transpose()?
        .unwrap_or_default();
    ensure!(ports.len() <= MAX_NET_PORTS, "too many port mappings");
    for mapping in &ports {
        ensure!(
            mapping.host_port != 0
                && mapping.container_port != 0
                && matches!(mapping.protocol.as_str(), "tcp" | "udp"),
            "port mapping requires nonzero TCP or UDP ports"
        );
    }
    let resolver = std::fs::read_to_string("/etc/resolv.conf")?
        .lines()
        .find_map(|line| {
            line.strip_prefix("nameserver ")
                .and_then(|value| value.trim().parse::<Ipv4Addr>().ok())
        })
        .context("host has no IPv4 DNS resolver")?;
    let mut mac = [2, 0xc7, 0, 0, 0, 0];
    mac[2..].copy_from_slice(&cid.to_be_bytes());
    Ok(Some(NetworkConfig {
        mac,
        address: GUEST,
        prefix_len: 24,
        gateway: GATEWAY,
        resolver: Ipv4Addr::new(10, 0, 2, 3),
        host_resolver: resolver,
        ports,
    }))
}

/// Configures Host-side forwarding on a network endpoint before its attach.
///
/// The Host binds mapped ports synchronously inside this ioctl, so occupied
/// ports reject the configuration and the container is never acknowledged.
pub fn configure_host(endpoint: &File, config: &NetworkConfig) -> Result<()> {
    let mut args = NetConfigArgs {
        host_resolver: config.host_resolver.octets(),
        num_ports: config.ports.len().try_into()?,
        ports: [NetPortMapping::default(); MAX_NET_PORTS],
        ..Default::default()
    };
    for (mapping, port) in args.ports.iter_mut().zip(&config.ports) {
        *mapping = NetPortMapping {
            host_address: port.host_address.octets(),
            host_port: port.host_port,
            guest_port: port.container_port,
            protocol: if port.protocol == "udp" {
                NET_PROTOCOL_UDP
            } else {
                NET_PROTOCOL_TCP
            },
            reserved0: 0,
        };
    }
    uapi::configure_network(endpoint, &args)
}
