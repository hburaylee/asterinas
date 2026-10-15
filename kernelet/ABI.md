<!-- SPDX-License-Identifier: MPL-2.0 -->

# The kernelet image ABI

This document describes the contract between the Host kernel and a kernelet
image:
the ELF image format,
the build that produces it,
and the source files implementing the loader and the audit.
It is the tracked reference behind the image-format comments in
the Host loader (`ostd/src/kernelet`),
OSDK (`osdk/src/kernelet`),
and the generated linker script.

The `/dev/kernelet` ioctl ABI shared by the Host kernel and the userspace
runtime is a separate interface,
defined by the `kernelet/abi` crate
and rendered to C by the generator described in the
[README](README.md#c-abi-header).

## Image format

The Host loader (`ostd/src/kernelet/host_image.rs`
and its `elf.rs` module)
validates the loadable regions, entry-table bounds, relocations,
exception-table entries, and source hash when an image is registered.
The OSDK audit (`osdk/src/kernelet/audit.rs`)
also checks build-time conditions such as the absence of `PT_INTERP` and
undefined symbols, section and symbol placement, and fixed assembly contracts.
These build-time checks are required in addition to Host registration;
the Host loader does not inspect symbol tables or reject `PT_INTERP` itself.

- The image is a 64-bit little-endian x86-64 `ET_DYN` ELF that links at base 0:
  every link-time address is an offset from the image base,
  which the Host chooses per instance.
- The image imports nothing:
  no `PT_INTERP` segment,
  no `DT_NEEDED` entry,
  and no undefined symbol.
  The only dynamic-linking machinery it may carry
  is what its own relocations need.
- The image consists of at most three `PT_LOAD` segments —
  executable text (`R E`), read-only data (`R`), and writable data (`RW`) —
  at ascending, page-aligned image offsets,
  one segment per permission class, text first.
  The text and read-only segments are fully file-backed;
  only the writable segment may have a zero-filled `p_memsz` tail.
  One physical copy of the read-only segments serves every instance of a kind.
  Each instance owns private frames for the writable segment,
  copied from the image's data template and relocated for that instance.
- Permission transitions and the writable segment's base
  are aligned to 2 MiB boundaries,
  so an instance's shared read-only mapping
  and its private writable mapping can both use huge pages.
  The whole writable template, including its zero-filled tail,
  fits one 2 MiB page.
- Every dynamic relocation is `R_X86_64_RELATIVE`,
  located through the `PT_DYNAMIC` segment's
  `DT_RELA`, `DT_RELASZ`, and `DT_RELAENT` entries,
  and targets the writable segment only.
  The loader applies each relocation as
  *store the instance's base plus the entry's own addend*.
  `DT_REL`, packed `DT_RELR`, and non-empty PLT relocations are rejected.
- The entry table lies at offset `0x1000` from the image base,
  file-backed by a non-writable segment
  (the text segment in the generated layout),
  so the Host finds it without consulting a symbol table.
  All of its address-like fields are link-time image-relative offsets.

### Entry table

The 136-byte table mirrors `ostd::kernelet::abi::EntryTable`
in its declared field order:

| Offset | Size | Field |
|---|---|---|
| `0x00` | 8  | `size` |
| `0x08` | 8  | `vcpu_entry_offset` |
| `0x10` | 8  | `virq_entry_offset` |
| `0x18` | 8  | `cpu_local_start_offset` |
| `0x20` | 8  | `cpu_local_end_offset` |
| `0x28` | 32 | `source_hash` |
| `0x48` | 8  | `ex_table_start_offset` |
| `0x50` | 8  | `ex_table_end_offset` |
| `0x58` | 8  | `yield_entry_offset` |
| `0x60` | 8  | `exit_entry_offset` |
| `0x68` | 8  | `stub_range_start_offset` |
| `0x70` | 8  | `stub_range_end_offset` |
| `0x78` | 8  | `cpu_access_start_offset` |
| `0x80` | 8  | `cpu_access_end_offset` |

- `size` must equal the ABI's 136 bytes.
- The vCPU, virtual-interrupt, yield and exit entry offsets
  decode into the executable text segment. The stub range contains all three
  complete redirect stubs; the Host refuses a redirect inside that range.
- The separate CPU-access range contains short replica/record access sequences.
  It is nonempty executable text, disjoint from the fixed stub range.
  The Host defers redirection there while retaining physical timer sampling.
- The CPU-local bounds wrap the `.cpu_local` template
  inside the writable segment.
- `source_hash` is the SHA-256 of
  the UTF-8 string `rustc <version>`,
  with `<version>` formatted from `rustc_version::version()`,
  followed by the contents of `ostd/Cargo.toml`, `ostd/build.rs`,
  and every file recursively collected under `ostd/src/`.
  OSDK sorts and deduplicates the paths before hashing.
  Each readable file contributes its OSTD-relative path using Rust's lossy UTF-8 conversion,
  a zero byte,
  its content length as a little-endian `u64`,
  and its content bytes, in that order.
  An unreadable file or directory contributes nothing;
  a failed compiler-version query contributes the string `rustc unknown`.
  Files under `ostd/libs/` and other paths outside this set are not hash inputs.
  The Host refuses to register an image
  whose hash differs from its own build,
  and publishes its hash to the image in `BootArgs`.

### Host service table

`ServiceTable` starts with its byte size followed by function pointers.
The eighteen service offsets remain unchanged.
The optional `KERNELET_RQ1_BENCH` diagnostic `rq1_echo` follows `stop`.
The table is 152 bytes normally and 160 bytes with the diagnostic entry.
OSDK checks every linked destination against its fixed Host wrapper and
service-stub contract.

DMA ownership uses the existing 64-byte frame metadata slot. The low 31 bits
of `in_list` retain the Guest list ID, bit 31 marks retirement, and the high 32
bits hold atomic DMA owner and Host pin counts. vOSTD publishes dedicated
untyped buffer ownership in that shared word. Host I/O checks and pins that
ownership while also retaining the
memory pin; arbitrary grant memory containing typed kernel objects is excluded.
Retirement revokes new access and drains existing Host pins before vOSTD can
reclaim the buffer. This protocol adds no service call or metadata-slot space.

### Exception table

The bounds name the `.ex_table` section
in the shared read-only data.
Its entries are 16 bytes each:
two self-relative `i64` offsets —
the fault site, then the recovery site —
each stored relative to the field's own address,
so the shared table carries no relocation.
Entries are strictly sorted by unique decoded fault address,
and every decoded target lies in the executable text.

### Clock snapshot

The Host appends two nanosecond anchors to the immutable `BootArgs`:
`realtime_base_ns` is its Unix time,
and `monotonic_base_ns` is the Host monotonic time sampled immediately before it.
vOSTD extends the realtime anchor by the elapsed time in the shared,
read-only monotonic `ClockPage`.
The kernel's RTC driver consumes that value through the existing RTC interface;
its elapsed-time clocksource also reads `ClockPage` through vOSTD's `read_tsc()`.
That function converts the Host's monotonic nanoseconds into cycle units using
`BootArgs::tsc_freq_hz`, so the existing clocksource conversion remains usable.
The realtime snapshot is taken when the instance is created.
Later changes to the Host realtime clock do not update this snapshot.
The Guest does not expose the prebuilt native vDSO:
its raw-TSC extrapolation and idle-stale cached timestamps do not implement this clock.
Libc time calls therefore use the ordinary kernel clock syscalls.

## Build contract

When the OSDK manifest enables the `kernelet` build option,
one OSDK invocation builds the kernelet image first
and then the host image.
Both builds use the selected `run.build` or `test.build` configuration for
enablement, Cargo profile and Cargo configuration overrides, after inheritance
and command-line options have been applied.
The build applies this fixed policy
(see `build_kernelet_elf` in `osdk/src/kernelet/mod.rs`):

```text
-C link-arg=-Tx86_64-kernelet.ld   # the generated linker script
-C relocation-model=pic
-C code-model=small
-C relro-level=off
-C force-unwind-tables=yes
-C panic=unwind
-C no-redzone=y
-C target-feature=+ermsb
-C link-arg=--no-undefined
-Z default-visibility=hidden
-Z cf-protection=branch
```

- The image is built from the same kernel and OSTD sources as the host image,
  as a separate Cargo build with `--no-default-features --features kernelet`.
  Only x86-64 is supported.
- C code linked into the image is compiled with `-fPIC -fcf-protection=branch`.
- After linking, OSDK runs the artifact audit and rewrites nothing.
  Unsafe-code exemptions for external crates require the reviewed package,
  version, and complete source-tree SHA-256. Registry source identities derive
  from the Cargo.lock archive checksum; the Git dependency uses its reviewed
  revision. Toolchain exemptions require the active rustc sysroot source path.
  The build records these identities with its dependency audit evidence.
  The build adds no per-function stack-check instrumentation.
  The target's ordinary inline compiler stack probes stay enabled.
  The Host still validates virtual-upcall reserve against its private stack
  allocation records; it never trusts the shared `stack_limit` field.
- The audited artifact is written as `kernelet-image.elf`
  under a fingerprinted `kernelet-unsafe-audit-<fingerprint>` target directory,
  and handed to the host build through two environment variables:
  `KERNELET_IMAGE_PATH`
  (embedded into the Host kernel by `kernel/core/build.rs`,
  which also requires a `panic=unwind` Host)
  and `KERNELET_SOURCE_HASH` (the hash above, as 64 lowercase hex digits).

## Artifact audit items

The OSDK audit (`osdk/src/kernelet/audit.rs`) implements these checks.
Each violation message names its item with the number below:

1. The image imports nothing.
2. Every relocation is `R_X86_64_RELATIVE`,
   and none is packed into the compressed RELR encoding.
3. Exactly three `PT_LOAD` segments follow the fixed region layout:
   permissions,
   2 MiB alignment of the permission transitions and the writable base,
   a writable template of at most one huge page,
   congruent file offsets,
   and an entry point inside the text.
4. The entry table lies at the fixed offset,
   its size matches the ABI,
   its address-like fields decode into the right regions,
   and no dynamic relocation targets it.
5. The CPU-local template and the exception table
   lie where the entry table's bounds say;
   `.cpu_local` ends the file-backed writable run,
   with only zero-filled sections after it;
   the Host-only `.cpu_local_tss` is absent.
7. The entry table's source hash equals
   the hash computed from the compiler-version string and the file set above.
8. Every relocation lies inside the writable segment.
9. The exception table holds an integral number of fixed-size entries
   in the shared read-only data,
   matching the entry table's bounds,
   sorted by unique fault address,
   with every decoded target inside the executable text.
10. All fixed image entry targets and relocated indirect targets
    begin with `ENDBR64`.
11. Fixed entry symbols agree with the entry table.
    The linked virtual-interrupt
    and Task-switch assembly match their fixed contracts, including the upcall's
    call target and the incoming Task's `stack_limit` publication.
    Complete executable-byte decoding also rejects ordinary physical interrupt
    and execution-control instructions, including `CLI`, `STI`, `HLT`,
    `POPFQ`, `IRETQ`, `SYSRET`, `SYSCALL`, `SWAPGS` and virtualization entry.
    Only the complete, byte-checked virtual-interrupt and yield stubs may use
    their fixed `STI`/`CLI`/`IRETQ` sequence.
    The rustc wrapper additionally rejects `x86` and `x86_64` imports outside
    the reviewed OSTD crate, including renamed dependencies; safe kernel crates
    use the restricted OSTD interface. Disabling a dependency's default features
    alone cannot enforce this boundary because Cargo merges features.
    Existing OSTD page-table/TLB and TLS operations keep their current contracts;
    this check does not claim to reject every architecture instruction.
    This does not audit compiler-generated frame sizes.

## Where the code lives

| Concern | Location |
|---|---|
| Host loader: parse, register, instantiate | `ostd/src/kernelet/host_image.rs`, `ostd/src/kernelet/host_image/` |
| Shared image ABI types (`EntryTable`, `BootArgs`, `ServiceTable`) with layout assertions | `ostd/src/kernelet/abi.rs` |
| OSDK build of the image | `osdk/src/kernelet/mod.rs` |
| OSDK artifact audit | `osdk/src/kernelet/audit.rs`, `osdk/src/kernelet/audit/` |
| Entry-table offsets mirrored for the audit | `osdk/src/kernelet/abi.rs` |
| Linker script template | `osdk/src/base_crate/x86_64-kernelet.ld.template` |
| Host-side embedding of the audited image | `kernel/core/build.rs` |
