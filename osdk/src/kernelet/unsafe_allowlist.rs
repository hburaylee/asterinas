// SPDX-License-Identifier: MPL-2.0

//! Reviewed crates that need `unsafe` in the kernelet image.
//!
//! Versions of external crates are pinned so an update requires a new review.
//! The wrapper reports only entries it actually exempted from `-F unsafe_code`.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Origin {
    Toolchain,
    Ostd,
    GeneratedEntry,
    External,
}

pub(super) struct Exception {
    pub package: &'static str,
    pub version: Option<&'static str>,
    pub origin: Origin,
    pub reason: &'static str,
}

impl Exception {
    const fn external(package: &'static str, version: &'static str, reason: &'static str) -> Self {
        Self {
            package,
            version: Some(version),
            origin: Origin::External,
            reason,
        }
    }
}

pub(super) const EXCEPTIONS: &[Exception] = &[
    Exception {
        package: "core",
        version: None,
        origin: Origin::Toolchain,
        reason: "Rust's core library implements primitive memory and pointer operations",
    },
    Exception {
        package: "alloc",
        version: None,
        origin: Origin::Toolchain,
        reason: "Rust's alloc library implements heap-backed collections and allocation",
    },
    Exception {
        package: "compiler_builtins",
        version: None,
        origin: Origin::Toolchain,
        reason: "compiler intrinsics and memory primitives supplied by the toolchain",
    },
    Exception {
        package: "ostd",
        version: None,
        origin: Origin::Ostd,
        reason: "reviewed vOSTD owns privileged instructions and unsafe machine mechanisms",
    },
    Exception {
        package: "ostd-pod",
        version: None,
        origin: Origin::Ostd,
        reason: "reviewed POD implementations establish byte-layout invariants",
    },
    Exception {
        package: "ostd-test",
        version: None,
        origin: Origin::Ostd,
        reason: "OSTD test registry reads linker-defined test arrays",
    },
    Exception {
        package: "<OSDK-generated kernelet entry>",
        version: None,
        origin: Origin::GeneratedEntry,
        reason: "OSDK-generated panic handler crosses the OSTD extern Rust entry",
    },
    Exception::external(
        "unwinding",
        "0.2.10",
        "unwinder interprets frame metadata and restores machine state",
    ),
    Exception::external(
        "allocator-api2",
        "0.2.21",
        "generic allocation and collection internals use raw pointers",
    ),
    Exception::external(
        "byteorder",
        "1.5.0",
        "byte-order conversions use unchecked byte reinterpretation",
    ),
    Exception::external(
        "foldhash",
        "0.2.0",
        "hash implementation uses raw memory operations",
    ),
    Exception::external(
        "gimli",
        "0.28.1",
        "DWARF reader uses unchecked pointer and byte decoding",
    ),
    Exception::external(
        "gimli",
        "0.34.0",
        "DWARF reader uses unchecked pointer and byte decoding",
    ),
    Exception::external(
        "inventory",
        "0.3.24",
        "linker inventory walks raw registration pointers",
    ),
    Exception::external(
        "konst_macro_rules",
        "0.2.19",
        "const-evaluation helpers use raw pointer conversions",
    ),
    Exception::external(
        "log",
        "0.4.34",
        "global logger registration uses shared static state",
    ),
    Exception::external(
        "num-traits",
        "0.2.19",
        "numeric casts use unchecked conversion intrinsics",
    ),
    Exception::external(
        "once_cell",
        "1.21.4",
        "one-time initialization uses unsafe interior mutability",
    ),
    Exception::external(
        "polonius-the-crab",
        "0.2.1",
        "borrow helper uses lifetime casts in its macros",
    ),
    Exception::external(
        "ptr_meta",
        "0.3.2",
        "pointer metadata constructors use raw-pointer operations",
    ),
    Exception::external(
        "scopeguard",
        "1.2.0",
        "scope-exit guard moves a value from ManuallyDrop",
    ),
    Exception::external(
        "serde_core",
        "1.0.229",
        "serialization internals use unchecked pointer casts",
    ),
    Exception::external(
        "smallvec",
        "1.16.2",
        "inline vector storage manages uninitialized elements",
    ),
    Exception::external(
        "stable_deref_trait",
        "1.2.1",
        "unsafe trait implementations certify stable dereference",
    ),
    Exception::external(
        "uguid",
        "2.2.1",
        "GUID representation uses unchecked byte conversion",
    ),
    Exception::external(
        "volatile",
        "0.4.6",
        "volatile memory accesses use raw pointers",
    ),
    Exception::external(
        "volatile",
        "0.6.1",
        "volatile memory accesses use raw pointers",
    ),
    Exception::external(
        "zerocopy",
        "0.8.59",
        "byte-layout traits and slice casts use raw memory access",
    ),
    Exception::external(
        "zero",
        "0.1.3",
        "zero-initialization primitives write through raw pointers",
    ),
    Exception::external(
        "powerfmt",
        "0.2.0",
        "formatting internals manipulate raw byte buffers",
    ),
    Exception::external(
        "multiboot2-common",
        "0.3.0",
        "boot-tag parsing casts unaligned raw memory",
    ),
    Exception::external(
        "hash32",
        "0.3.1",
        "hashing uses unchecked byte views of primitive values",
    ),
    Exception::external(
        "wyz",
        "0.5.1",
        "bit-vector support implements aliasing and raw-pointer access",
    ),
    Exception::external(
        "lock_api",
        "0.4.14",
        "lock guards and interior mutability use unsafe synchronization primitives",
    ),
    Exception::external(
        "acpi",
        "5.2.0",
        "ACPI table parsing maps and reads firmware memory through raw pointers",
    ),
    Exception::external(
        "intrusive-collections",
        "0.9.7",
        "intrusive list nodes are linked through raw pointers",
    ),
    Exception::external(
        "raw-cpuid",
        "10.7.0",
        "processor capability reads use the CPUID instruction",
    ),
    Exception::external(
        "deranged",
        "0.5.8",
        "bounded integer helpers use unchecked construction",
    ),
    Exception::external(
        "x86_64",
        "0.15.5",
        "architecture primitives access registers, page tables, and interrupts",
    ),
    Exception::external(
        "uefi-raw",
        "0.12.0",
        "UEFI ABI exposes unsafe firmware functions and raw pointers",
    ),
    Exception::external(
        "konst",
        "0.2.20",
        "const-evaluation helpers use unchecked raw-pointer operations",
    ),
    Exception::external(
        "spin",
        "0.9.9",
        "spin locks implement synchronization with unsafe interior mutability",
    ),
    Exception::external(
        "xmas-elf",
        "0.10.0",
        "ELF parser reads unaligned binary headers through raw pointers",
    ),
    Exception::external(
        "heapless",
        "0.8.0",
        "fixed-capacity collections manage uninitialized array elements",
    ),
    Exception::external(
        "hashbrown",
        "0.16.1",
        "hash table controls bucket allocation and raw-pointer storage",
    ),
    Exception::external(
        "bitvec",
        "1.1.1",
        "bit-level references and slices use aliasing and raw-pointer operations",
    ),
    Exception::external(
        "ppv-lite86",
        "0.2.21",
        "SIMD random-number routines use target intrinsics and raw vector casts",
    ),
    Exception::external(
        "time",
        "0.3.55",
        "date-time internals use unchecked value construction and pointer operations",
    ),
    Exception::external(
        "multiboot2",
        "0.24.1",
        "boot information parser reads raw memory and packed tables",
    ),
    Exception::external(
        "hashbrown",
        "0.14.5",
        "hash table controls bucket allocation and raw-pointer storage",
    ),
    Exception::external(
        "x86",
        "0.52.0",
        "x86 instruction and register access uses privileged operations",
    ),
    Exception::external(
        "lru",
        "0.16.4",
        "LRU links and unlinks cache entries through raw pointers",
    ),
    Exception::external(
        "smoltcp",
        "0.11.0",
        "packet buffers and internal random generation use unsafe memory operations",
    ),
    Exception::external(
        "rand",
        "0.9.5",
        "random distribution implementations use SIMD and unchecked sampling internals",
    ),
];
