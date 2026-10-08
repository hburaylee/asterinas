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
validates everything in this section when an image is registered;
the OSDK audit (`osdk/src/kernelet/audit.rs`)
checks the same facts at build time and fails the build on a violation.

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

The 88-byte table mirrors `ostd::kernelet::abi::EntryTable`
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

- `size` must equal the ABI's 88 bytes.
- The vCPU and virtual-interrupt entry offsets
  decode into the executable text segment.
- The CPU-local bounds wrap the `.cpu_local` template
  inside the writable segment.
- `source_hash` is the SHA-256 of
  the rustc version and the OSTD source tree
  (every file contributing its path, length, and content),
  computed by OSDK as described under "Build contract" below.
  The Host refuses to register an image
  whose hash differs from its own build,
  and publishes its hash to the image in `BootArgs`.

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
its ordinary TSC clocksource continues to provide elapsed time.
The realtime snapshot is taken when the instance is created.
Later changes to the Host realtime clock do not update this snapshot.
The Guest does not expose the prebuilt native vDSO:
its raw-TSC extrapolation and idle-stale cached timestamps do not implement this clock.
Libc time calls therefore use the ordinary kernel clock syscalls.

## Build contract

When the OSDK manifest enables the `kernelet` build option,
one OSDK invocation builds the kernelet image first
and then the host image.
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
   the hash computed from the OSTD source tree and the toolchain.
8. Every relocation lies inside the writable segment.
9. The exception table holds an integral number of fixed-size entries
   in the shared read-only data,
   matching the entry table's bounds,
   sorted by unique fault address,
   with every decoded target inside the executable text.
10. All fixed image entry targets and relocated indirect targets
    begin with `ENDBR64`.
11. Fixed entry symbols agree with the entry table. The linked virtual-interrupt
    and Task-switch assembly match their fixed contracts, including the upcall's
    call target and the incoming Task's `stack_limit` publication.
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
