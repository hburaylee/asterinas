// SPDX-License-Identifier: MPL-2.0

//! Defines the C-compatible data exchanged by the host and a kernelet image.
//!
//! The first version of this ABI is x86-64 only. A service table is passed to
//! the image entry point; image code never resolves a host symbol by name.

use core::{
    mem::offset_of,
    sync::atomic::{AtomicU32, AtomicU64},
};

/// Records the image-relative targets and template bounds validated at registration.
#[repr(C)]
pub struct EntryTable {
    /// Size of this table in bytes.
    pub size: u64,
    /// Image-relative entry for a secondary virtual CPU.
    pub vcpu_entry_offset: u64,
    /// Image-relative entry for a virtual interrupt.
    pub virq_entry_offset: u64,
    /// Image-relative start of the CPU-local template.
    pub cpu_local_start_offset: u64,
    /// Image-relative end of the CPU-local template.
    pub cpu_local_end_offset: u64,
    /// Hash of the OSTD source and toolchain shared with the host build.
    pub source_hash: [u8; 32],
    /// Image-relative start of the exception table.
    pub ex_table_start_offset: u64,
    /// Image-relative end of the exception table.
    pub ex_table_end_offset: u64,
}

/// Bootstrap version of the read-only boot page shared by the Host and image.
///
/// The scheduling fields follow the common image ABI. Grant and device fields
/// will extend this structure as their services become available.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BootArgs {
    /// Size of this ABI version in bytes.
    pub size: u32,
    /// Generation of this instance.
    pub generation: u32,
    /// Hash of the common OSTD source and toolchain.
    pub source_hash: [u8; 32],
    /// Timestamp-counter frequency published by the Host.
    pub tsc_freq_hz: u64,
    /// Host-assigned kernelet identifier.
    pub kernelet: u16,
    /// Number of virtual CPUs in this instance.
    pub num_vcpus: u16,
    /// Physical CPU assigned to each virtual CPU.
    pub vcpu_host_cpu: [u16; MAX_VCPUS],
    /// Offset of the Host's native current-CPU slot from its GS base.
    pub cpu_slot_gs_offset: u32,
    /// Offset of the Host preemption word used by the outer guard mirror.
    pub host_preempt_gs_offset: u32,
    /// Size of one CPU-local replica in bytes.
    pub cpu_local_replica_bytes: u32,
    /// Base of the Host linear map shared by the kernelet.
    pub linear_map_base: u64,
    /// The stable kernel-half entries copied into every tenant user root.
    pub kernel_half_entries: [u64; 256],
    /// Base of this instance's sparse frame-metadata window.
    pub meta_base: u64,
    /// Offset from this boot page to the Host-written run table.
    pub grant_table: u32,
    /// Offset from this boot page to the physical-section index.
    pub meta_section_index: u32,
    /// Offset from this boot page to the compact-block reverse index.
    pub meta_block_sections: u32,
    /// Maximum number of compact metadata blocks in this instance.
    pub max_meta_sections: u32,
    /// Offset from this boot page to the shared clock page.
    pub clock_page: u32,
    /// Offset from this boot page to the shared info page.
    pub info_page: u32,
    /// Offset from this boot page to the first writable virtual-CPU record.
    pub vcpu_records: u32,
    /// Maximum number of live internal Task stacks.
    pub max_tasks: u32,
    /// Size of the tenant floating-point save area.
    pub fpu_area_bytes: u32,
    /// Offset from this boot page to the read-only kernel command line.
    pub cmdline_offset: u32,
    /// Number of command-line bytes, without a trailing NUL.
    pub cmdline_len: u32,
    /// Offset from this boot page to the virtual-device table.
    pub devices_offset: u32,
    /// Number of virtual devices in the table.
    pub num_devices: u32,
    /// Reserved and always zero.
    pub reserved: u32,
    /// Host realtime nanoseconds since the Unix epoch at the clock snapshot.
    pub realtime_base_ns: u64,
    /// Host monotonic nanoseconds at the same clock snapshot.
    pub monotonic_base_ns: u64,
}

/// One virtual MMIO device made available to the kernelet.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DeviceEntry {
    /// Host-assigned identifier used by the MMIO service calls.
    pub id: u16,
    /// Device kind; currently a virtio MMIO register file.
    pub kind: u16,
    /// Virtual interrupt line.
    pub irq: u8,
    /// Reserved and always zero.
    pub reserved: u8,
    /// Virtual CPU receiving this device's interrupt.
    pub vcpu: u16,
    /// Size of the register window in bytes.
    pub reg_bytes: u32,
    /// Virtio device type.
    pub device_type: u32,
    /// Pseudo-physical base of the register window.
    pub mmio_base: u64,
}

/// Maximum number of virtual CPUs supported by the common image ABI.
pub const MAX_VCPUS: usize = 64;

/// A physically contiguous run of 2 MiB grains published by the Host.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RunDesc {
    /// First physical byte of the run.
    pub paddr: u64,
    /// Number of grains in the run.
    pub grains: u32,
    /// Reserved and always zero.
    pub reserved: u32,
}

/// Host-published memory and lifecycle information.
#[repr(C)]
pub struct InfoPage {
    /// Published length of the grant table.
    pub runs: AtomicU32,
    /// Published number of compact frame-metadata blocks.
    pub meta_blocks: AtomicU32,
    /// End of the highest published grant run.
    pub max_paddr: AtomicU64,
    /// Nonzero when the Host has requested termination.
    pub dying: AtomicU32,
    /// Reserved and always zero.
    pub reserved: u32,
}

/// Host-published monotonic time since Host boot.
///
/// The Host writes through its linear mapping. Every kernelet maps the same
/// frame read-only, so the one atomic value needs no cross-field snapshot.
#[repr(C)]
pub struct ClockPage {
    /// Monotonic nanoseconds, advanced at least once per physical timer tick.
    pub monotonic_ns: AtomicU64,
}

/// Size of the Host's physical-memory grant unit.
pub const GRAIN_SIZE: usize = 2 * 1024 * 1024;
/// Physical-memory span represented by one compact metadata block.
pub const META_SECTION_BYTES: usize = 128 * 1024 * 1024;
/// Metadata value for a physical section not granted to this kernelet.
pub const NO_META_BLOCK: u32 = u32::MAX;

/// Communicates pending work and time for one virtual CPU.
///
/// This record is never authoritative for identity, ownership, or termination.
#[repr(C, align(64))]
#[derive(Default)]
pub struct VcpuRecord {
    /// Level-triggered summary of pending virtual interrupts.
    pub pending: AtomicU64,
    /// Pending device lines; lines below 32 are reserved.
    pub pending_lines: [AtomicU64; 4],
    /// User-mode execution ticks awaiting delivery.
    pub tick_user: AtomicU64,
    /// Kernel-mode execution ticks awaiting delivery.
    pub tick_kernel: AtomicU64,
    /// Bottom-half execution ticks awaiting delivery.
    pub tick_l2: AtomicU64,
    /// Host-published time runnable but not executing, in nanoseconds.
    pub stolen_ns: AtomicU64,
    /// Host-published offset excluded from the inner scheduler clock.
    pub nonrunning_tsc: AtomicU64,
    /// Inner preemption-guard depth, written by the current virtual CPU.
    pub guards: AtomicU32,
    /// Whether virtual interrupts are disabled on this virtual CPU.
    pub irq_off: AtomicU32,
    /// Immutable virtual CPU number, published before image entry.
    pub vcpu: u32,
    /// Virtual interrupt nesting level.
    pub irq_level: AtomicU32,
    /// Current internal Task's lower stack bound, retained as shared ABI metadata.
    pub stack_limit: AtomicU64,
    /// Immutable address of this virtual CPU's CPU-local replica.
    pub cpu_local_base: u64,
    /// Host-published time spent asleep in `vcpu_idle`, in nanoseconds.
    pub parked_ns: AtomicU64,
    /// Whether this vCPU owns one guard in the Host preemption word.
    pub mirrored: AtomicU32,
}

/// Recoverable user-copy fault state for one virtual CPU.
///
/// These records follow the complete `VcpuRecord` array in the Host-pinned
/// shared pages. Keeping them separate preserves the two-cache-line virtual
/// interrupt ABI even when the user-copy protocol changes.
#[repr(C, align(64))]
#[derive(Default)]
pub struct CopyFaultRecord {
    /// Address of the most recent validated image-side copy fault.
    pub addr: AtomicU64,
    /// Hardware page-fault error code.
    pub error: AtomicU64,
    /// One after the Host publishes `addr` and `error`.
    pub pending: AtomicU32,
}

/// Byte offset of the fault-record array from the first `VcpuRecord`.
pub const fn copy_fault_records_offset(vcpus: usize) -> usize {
    vcpus * size_of::<VcpuRecord>()
}

/// Number of bytes mapped for both per-vCPU shared arrays.
pub const fn vcpu_shared_bytes(vcpus: usize) -> usize {
    copy_fault_records_offset(vcpus) + vcpus * size_of::<CopyFaultRecord>()
}

/// Holds the x86-64 user state passed to the `user_run` service for one call.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct KletUserContext {
    /// Accumulator register.
    pub rax: u64,
    /// Base register.
    pub rbx: u64,
    /// Count register.
    pub rcx: u64,
    /// Data register.
    pub rdx: u64,
    /// Source index register.
    pub rsi: u64,
    /// Destination index register.
    pub rdi: u64,
    /// Frame pointer.
    pub rbp: u64,
    /// User stack pointer.
    pub rsp: u64,
    /// General register 8.
    pub r8: u64,
    /// General register 9.
    pub r9: u64,
    /// General register 10.
    pub r10: u64,
    /// General register 11.
    pub r11: u64,
    /// General register 12.
    pub r12: u64,
    /// General register 13.
    pub r13: u64,
    /// General register 14.
    pub r14: u64,
    /// General register 15.
    pub r15: u64,
    /// User instruction pointer.
    pub rip: u64,
    /// User flags.
    pub rflags: u64,
    /// User FS base.
    pub fsbase: u64,
    /// User GS base.
    pub gsbase: u64,
    /// Returned trap number.
    pub trap_num: u64,
    /// Returned trap error code.
    pub error_code: u64,
    /// Returned fault address.
    pub fault_addr: u64,
}

/// Returns the result of a virtual MMIO register read.
#[repr(C)]
pub struct MmioResult {
    /// Zero on success or a negative ABI error.
    pub status: i64,
    /// Register value on success.
    pub value: u64,
}

/// Supplies the fixed first-version services to an image.
#[repr(C)]
pub struct ServiceTable {
    /// Size of this table in bytes.
    pub size: u64,
    /// Requests more 2 MiB grains from the Host.
    pub grains_request: extern "C" fn(count: u32, contiguous: u32) -> i64,
    /// Registers a page-table root owned by the instance.
    pub pt_root_register: extern "C" fn(root_paddr: u64) -> i64,
    /// Unregisters an inactive page-table root.
    pub pt_root_unregister: extern "C" fn(root_paddr: u64) -> i64,
    /// Activates a registered page-table root.
    pub pt_activate: extern "C" fn(root_paddr: u64) -> i64,
    /// Invalidates translations belonging to a registered root.
    pub tlb_shootdown: extern "C" fn(root_paddr: u64, start: u64, len: u64) -> i64,
    /// Allocates one guarded internal Task stack.
    pub kstack_alloc: extern "C" fn() -> u64,
    /// Releases one inactive internal Task stack.
    pub kstack_free: extern "C" fn(vaddr: u64) -> i64,
    /// Starts a prepared secondary virtual CPU.
    pub vcpu_boot: extern "C" fn(vcpu: u32) -> i64,
    /// Parks the current virtual CPU until work, deadline, or stop.
    pub vcpu_idle: extern "C" fn(deadline_ns: u64) -> i64,
    /// Publishes work for another virtual CPU.
    pub vcpu_kick: extern "C" fn(vcpu: u32) -> i64,
    /// Yields the current carrier to the Host scheduler.
    pub vcpu_yield: extern "C" fn(),
    /// Hints that the current carrier is spinning on another carrier.
    pub vcpu_on_spin: extern "C" fn(),
    /// Executes user mode and returns the reason for re-entering the image.
    pub user_run: extern "C" fn(ctx: *mut KletUserContext) -> i64,
    /// Saves the current tenant floating-point state.
    pub fpu_save: extern "C" fn(area: *mut u8, len: u32) -> i64,
    /// Loads tenant floating-point state.
    pub fpu_load: extern "C" fn(area: *const u8, len: u32) -> i64,
    /// Reads a virtual device register.
    pub mmio_read: extern "C" fn(dev: u32, offset: u32, width: u32) -> MmioResult,
    /// Writes a virtual device register.
    pub mmio_write: extern "C" fn(dev: u32, offset: u32, width: u32, value: u64) -> i64,
    /// Writes one bounded log record.
    pub log_write: extern "C" fn(
        level: u32,
        module: *const u8,
        module_len: u32,
        text: *const u8,
        text_len: u32,
    ) -> i64,
    /// Reports an oops without necessarily stopping the instance.
    pub oops: extern "C" fn(msg: *const u8, len: u32) -> i64,
    /// Stops the current instance without returning to the image.
    pub stop: extern "C" fn(kind: u32, code: u32, msg: *const u8, len: u32) -> !,
}

/// Virtual timer tick is pending.
pub const VIRQ_TICK: u64 = 1 << 0;
/// Remote work is pending.
pub const VIRQ_KICK: u64 = 1 << 1;
/// One or more virtual device lines are pending.
pub const VIRQ_LINES: u64 = 1 << 2;

/// A tenant system call returned from `user_run`.
pub const USER_RETURN_SYSCALL: i64 = 0;
/// A tenant CPU exception returned from `user_run`.
pub const USER_RETURN_EXCEPTION: i64 = 1;
/// A physical interrupt or virtual work requires image-side processing.
pub const USER_RETURN_PENDING: i64 = 2;

/// The requested resource is not owned by this kernelet.
pub const NOT_OWNED: i64 = 2;
/// An argument or pointer is invalid.
pub const INVALID: i64 = 3;
/// A configured limit refuses the operation.
pub const LIMIT: i64 = 4;
/// The current lifecycle or service state refuses the operation.
pub const STATE: i64 = 5;
/// Console log level, written directly to the early serial console.
pub const LEVEL_CONSOLE: u32 = 8;
/// Maximum grains granted by one service crossing.
pub const MAX_GRAINS_PER_REQUEST: u32 = 16;
/// Maximum bytes in a log module name.
pub const MAX_LOG_MODULE_BYTES: u32 = 128;
/// Maximum bytes in a log text record.
pub const MAX_LOG_TEXT_BYTES: u32 = 4096;
/// Maximum bytes in an oops report.
pub const MAX_OOPS_BYTES: u32 = 4096;
/// Indicates an ordinary image exit.
pub const STOP_EXIT: u32 = 0;
/// Indicates an image panic.
pub const STOP_PANIC: u32 = 1;
/// Indicates a stack overflow reported by the image.
pub const STOP_STACK_OVERFLOW: u32 = 2;
/// Marks a requested restart in an exit code.
pub const EXIT_RESTART: u32 = 1 << 31;

const _: () = {
    assert!(size_of::<EntryTable>() == 88);
    assert!(offset_of!(EntryTable, source_hash) == 40);
    assert!(offset_of!(EntryTable, ex_table_start_offset) == 72);
    assert!(size_of::<BootArgs>() == 2328);
    assert!(size_of::<DeviceEntry>() == 24);
    assert!(size_of::<RunDesc>() == 16);
    assert!(size_of::<InfoPage>() == 24);
    assert!(size_of::<ClockPage>() == 8);
    assert!(offset_of!(BootArgs, generation) == 4);
    assert!(offset_of!(BootArgs, source_hash) == 8);
    assert!(offset_of!(BootArgs, realtime_base_ns) == 2312);
    assert!(offset_of!(BootArgs, monotonic_base_ns) == 2320);
    assert!(size_of::<VcpuRecord>() == 128);
    assert!(offset_of!(VcpuRecord, stolen_ns) == 64);
    assert!(offset_of!(VcpuRecord, guards) == 80);
    assert!(offset_of!(VcpuRecord, parked_ns) == 112);
    assert!(offset_of!(VcpuRecord, mirrored) == 120);
    assert!(size_of::<CopyFaultRecord>() == 64);
    assert!(offset_of!(CopyFaultRecord, pending) == 16);
    assert!(size_of::<KletUserContext>() == 184);
    assert!(size_of::<MmioResult>() == 16);
    assert!(size_of::<ServiceTable>() == 168);
    assert!(offset_of!(ServiceTable, stop) == 160);
};
