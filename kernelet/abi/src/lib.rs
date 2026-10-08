// SPDX-License-Identifier: MPL-2.0

//! Raw endovisor ioctl ABI shared by kernel and userspace.

#![no_std]
#![deny(unsafe_code)]

#[macro_use]
extern crate ostd_pod;

pub const MAGIC: u32 = 0xc7;
/// Bytes in one physical-memory grain, the unit of the memory ioctls and stats.
pub const GRAIN_SIZE_BYTES: u64 = 2 * 1024 * 1024;
pub const BLOCK: u16 = 1;
pub const CONSOLE: u16 = 2;
pub const RNG: u16 = 3;
pub const VSOCK: u16 = 4;
pub const NET: u16 = 5;
/// Host forwarding protocol for TCP port mappings.
pub const NET_PROTOCOL_TCP: u16 = 1;
/// Host forwarding protocol for UDP port mappings.
pub const NET_PROTOCOL_UDP: u16 = 2;
/// Maximum port mappings in one network configuration.
pub const MAX_NET_PORTS: usize = 32;
/// Chosen endpoint-only kind following the five device kind values.
pub const LOG: u16 = 6;
pub const BLOCK_READ_ONLY: u32 = 1;
pub const STATE_CONFIGURING: u32 = 0;
pub const STATE_CREATED: u32 = 1;
pub const STATE_RUNNING: u32 = 2;
pub const STATE_DYING: u32 = 3;
pub const STATE_EXITED: u32 = 4;
pub const STATE_DESTROYING: u32 = 5;
pub const STATE_DESTROYED: u32 = 6;
pub const STATE_STARTING: u32 = 7;
pub const STATUS_REASON_NONE: u32 = 0;
pub const STATUS_REASON_EXITED: u32 = 1;
pub const STATUS_REASON_PANICKED: u32 = 2;
pub const STATUS_REASON_KILLED: u32 = 3;
pub const STATUS_MESSAGE_TRUNCATED: u32 = 1;
pub const KILL_REQUESTED: u32 = 1;
pub const KILL_OOPS_BUDGET: u32 = 2;
pub const KILL_STACK_RESERVE: u32 = 3;
pub const KILL_STACK_OVERFLOW: u32 = 4;
pub const KILL_HOST_HOOK_PANICKED: u32 = 5;
pub const KILL_ENTRY_FAILED: u32 = 6;
pub const KILL_KERNEL_FAULT: u32 = 7;
/// An internal Host failure for which no more specific reason is available.
pub const KILL_INTERNAL_ERROR: u32 = u32::MAX;

#[repr(C)]
#[derive(Clone, Copy, Default, Pod)]
pub struct CreateArgs {
    pub image: u16,
    pub num_vcpus: u16,
    /// Initially granted memory, in units of `GRAIN_SIZE_BYTES`.
    pub initial_grains: u32,
    /// Maximum granted memory, in units of `GRAIN_SIZE_BYTES`.
    pub max_grains: u32,
    pub max_meta_sections: u32,
    pub nice: i8,
    pub reserved0: [u8; 3],
    pub cpu_quota_us: u32,
    pub cpu_period_us: u32,
    pub oops_budget: u32,
    pub log_bytes_per_sec: u32,
    pub max_tasks: u32,
    pub cmdline_ptr: u64,
    pub cmdline_len: u32,
    pub out_cid: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default, Pod)]
pub struct AttachArgs {
    pub kind: u16,
    pub vcpu: u16,
    pub backing_fd: i32,
    pub flags: u32,
    pub out_index: u16,
    pub reserved0: u16,
    pub arg: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default, Pod)]
pub struct EndpointArgs {
    pub kind: u16,
    pub reserved0: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Default, Pod)]
pub struct VsockArgs {
    pub port: u32,
    pub flags: u32,
}

/// A second sandbox capability authorizes changing the inter-sandbox route.
#[repr(C)]
#[derive(Clone, Copy, Default, Pod)]
pub struct VsockPolicyArgs {
    pub peer_fd: i32,
    pub allow: u32,
}

/// One Host-to-guest port mapping on a network endpoint.
#[repr(C)]
#[derive(Clone, Copy, Default, Pod)]
pub struct NetPortMapping {
    pub host_address: [u8; 4],
    pub host_port: u16,
    pub guest_port: u16,
    pub protocol: u16,
    pub reserved0: u16,
}

/// Configures Host-side forwarding for a network endpoint.
#[repr(C)]
#[derive(Clone, Copy, Default, Pod)]
pub struct NetConfigArgs {
    pub host_resolver: [u8; 4],
    pub num_ports: u16,
    pub reserved0: u16,
    pub ports: [NetPortMapping; MAX_NET_PORTS],
}

#[repr(C)]
#[derive(Clone, Copy, Default, Pod)]
pub struct BudgetArgs {
    pub nice: i8,
    pub reserved0: [u8; 3],
    pub cpu_quota_us: u32,
    pub cpu_period_us: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default, Pod)]
pub struct StatsRaw {
    pub state: u32,
    pub cid: u32,
    /// Currently granted memory, in units of `GRAIN_SIZE_BYTES`.
    pub grains_granted: u32,
    /// Maximum granted memory, in units of `GRAIN_SIZE_BYTES`.
    pub max_grains: u32,
    pub stacks_allocated: u32,
    pub oopses: u32,
    pub host_bytes_charged: u64,
    pub host_overhead_bytes: u64,
    pub cpu_time_ns: u64,
    pub throttled_ns: u64,
    pub completion_cpu_ns: u64,
    pub ingress_copy_cpu_ns: u64,
    pub service_calls: u64,
    pub mmio_accesses: u64,
    pub irqs_raised: u64,
    pub log_bytes: u64,
    pub log_records_dropped: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Pod)]
pub struct StatusRaw {
    pub state: u32,
    pub reason: u32,
    pub code: u32,
    pub flags: u32,
    pub uptime_ns: u64,
    pub cpu_time_ns: u64,
    pub fault_addr: u64,
    pub fault_ip: u64,
    pub message_len: u32,
    pub reserved0: u32,
    pub message: [u8; 256],
}

#[repr(C)]
#[derive(Clone, Copy, Default, Pod)]
pub struct ImageInfoRaw {
    pub image: u16,
    pub name_len: u16,
    pub name: [u8; 32],
    pub reserved0: u32,
    pub text_bytes: u64,
    pub template_bytes: u64,
    pub cpu_local_bytes: u32,
    pub reserved1: u32,
}

const fn request(direction: u32, number: u32, size: usize) -> u64 {
    ((direction << 30) | ((size as u32) << 16) | (MAGIC << 8) | number) as u64
}

pub const CREATE: u64 = request(3, 0x01, size_of::<CreateArgs>());
pub const LIST_IMAGES: u64 = request(2, 0x02, size_of::<[ImageInfoRaw; 8]>());
pub const ATTACH: u64 = request(3, 0x10, size_of::<AttachArgs>());
pub const ENDPOINT: u64 = request(1, 0x11, size_of::<EndpointArgs>());
pub const NET_CONFIG: u64 = request(1, 0x12, size_of::<NetConfigArgs>());
pub const START: u64 = request(0, 0x20, 0);
pub const KILL: u64 = request(1, 0x21, size_of::<u32>());
pub const GRANT: u64 = request(3, 0x22, size_of::<u32>());
pub const BUDGET: u64 = request(1, 0x23, size_of::<BudgetArgs>());
pub const STATS: u64 = request(2, 0x24, size_of::<StatsRaw>());
pub const STATUS: u64 = request(2, 0x25, size_of::<StatusRaw>());
pub const DESTROY: u64 = request(0, 0x2f, 0);
pub const VSOCK_CONNECT: u64 = request(1, 0x30, size_of::<VsockArgs>());
pub const VSOCK_LISTEN: u64 = request(1, 0x31, size_of::<VsockArgs>());

const _: () = {
    assert!(size_of::<CreateArgs>() == 56);
    assert!(core::mem::offset_of!(CreateArgs, cmdline_ptr) == 40);
    assert!(size_of::<AttachArgs>() == 24);
    assert!(core::mem::offset_of!(AttachArgs, arg) == 16);
    assert!(size_of::<EndpointArgs>() == 4);
    assert!(size_of::<NetPortMapping>() == 12);
    assert!(size_of::<NetConfigArgs>() == 392);
    assert!(size_of::<VsockArgs>() == 8);
    assert!(size_of::<VsockPolicyArgs>() == 8);
    assert!(size_of::<StatusRaw>() == 312);
    assert!(size_of::<StatsRaw>() == 112);
    assert!(size_of::<ImageInfoRaw>() == 64);
};

/// Closes the write half of a vsock endpoint without dropping its read half.
pub const VSOCK_SHUTDOWN: u64 = request(0, 0x32, 0);

/// Grants or revokes a route using descriptors for both sandbox endpoints.
pub const VSOCK_POLICY: u64 = request(1, 0x33, size_of::<VsockPolicyArgs>());
