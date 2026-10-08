# Initramfs-Based Test Suites

This directory contains the test suites of Asterinas running in initramfs, including in-house syscall regression tests, third-party Linux conformance suites, benchmarks, configuration files, and Nix expressions to package them.

## Directory Structure

```
initramfs/
├── etc/               # Configuration files packaged into initramfs
├── nix/
│   ├── benchmark/     # Nix expressions for `benchmark`
│   ├── conformance/   # Nix expressions for `conformance`
│   ├── regression/    # Nix expressions for `regression`
│   └── initramfs.nix  # Nix expression for packaging initramfs
├── src/
│   ├── benchmark/     # Third-party benchmark suites to compare Asterinas against Linux
│   ├── conformance/   # Third-party test suites to verify Linux compatibility
│   │   ├── gvisor/    # Gvisor syscall test suite
│   │   ├── kselftest/ # Linux kernel in-tree selftests
│   │   └── ltp/       # Linux Test Project syscall test suite
│   ├── regression/    # In-house syscall and subsystem regression tests
│   └── boot_hello.sh  # Minimal boot smoke test script
├── Makefile
└── README.md
```

## Building and Packaging Tests

Most tests in this directory are compiled and packaged using [Nix](https://nixos.org/), a powerful package manager. This ensures consistency and reproducibility across environments.

> **Note**: If you are adding a new test to the `regression` directory, ensure that it supports multiple architectures. Some of the existing tests lack proper architecture-specific handling.

### Conformance Test Suite - gVisor Exception

While most tests rely on `Nix` for compilation, the `gvisor` conformance test suite currently cannot be built with `Nix`. Instead, the `gvisor` tests are compiled in the Docker image. For details, refer to `tools/dev_env/docker/kernel-dev/Dockerfile`.

### Linux Kernel Selftest (kselftest)

The `kselftest` suite builds a subset of Linux's in-tree selftests
(`tools/testing/selftests`) from the Linux version pinned in
`nix/conformance/kselftest.nix` (currently **v6.18**). Only the
subsystems listed in `baseKselftestTargets` are compiled, plus `x86`
on x86_64 hosts.

Invoke via:

```bash
make run_kernel AUTO_TEST=conformance CONFORMANCE_TEST_SUITE=kselftest
```

**Bumping the Linux version.** Edit `version` in
`nix/conformance/kselftest.nix`, temporarily set `hash = lib.fakeHash;`,
run the Nix build once, and copy the real hash reported by `fetchgit`
back into `hash`.

**Blocklist layout.** `src/conformance/kselftest/blocklists` is the
default blocklist; `blocklists.ext2` and `blocklists.exfat` hold
filesystem-specific extras. See the header of `blocklists` for the
entry format.

### Multi-Architecture Support

The test suite supports building for multiple architectures, including `x86_64` and `riscv64`. You can specify the desired architecture by running:

```bash
make kernel TARGET_ARCH=x86_64
# or
make kernel TARGET_ARCH=riscv64
```

The build artifacts (initramfs) can be found in the `test/initramfs/build` directory after the compilation.

### Kernelet userspace

On x86_64, run this command from the repository root inside the development
container:

```bash
make run_kernelet
```

This installs or updates OSDK,
builds the static runtime, agent, and containerd shim,
packages them with a Bash OCI bundle in the initramfs,
and boots a Host with an embedded kernelet image.
The Host and kernelet kernels use the optimized release profile by default.
Use `make run_kernelet RELEASE=0` for a development build.
It defaults to four Host CPUs:
the runtime's default sandbox uses two vCPUs,
and those vCPUs share the physical CPUs with the Host's worker threads
through the Host scheduler;
no CPU is reserved for a sandbox.
Use `make run_kernelet SMP=2` to select two.
When benchmarking `run_kernelet` against other boot targets,
boot both sides with the same explicitly set `SMP`.

To build the initramfs separately, provide all three static Rust binaries:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --manifest-path kernelet/Cargo.toml --release --target x86_64-unknown-linux-musl
make initramfs SMP=2 \
  KERNELET_RUNTIME="$PWD/kernelet/target/x86_64-unknown-linux-musl/release/kernelet-runtime" \
  KERNELET_AGENT="$PWD/kernelet/target/x86_64-unknown-linux-musl/release/kernelet-agent" \
  KERNELET_SHIM="$PWD/kernelet/target/x86_64-unknown-linux-musl/release/containerd-shim-kernelet-v2"
```

The build fails unless all three binaries are supplied.
These explicit inputs are copied into the Nix store,
so the resulting image is tied to their contents.
Nix builds a static musl `mke2fs` for the Host-side ext2 image builder,
and packages Bash, BusyBox, SQLite, and their ELF loaders and libraries
in the OCI bundle.
The installed paths are
`/usr/bin/kernelet-runtime`,
`/usr/bin/containerd-shim-kernelet-v2`,
`/usr/libexec/kernelet-agent`,
`/usr/libexec/kernelet-mke2fs`,
and `/opt/kernelet/bash-bundle`.

After booting a Host kernel built with OSDK's `--kernelet` option, run:

```sh
kernelet-runtime create --bundle /opt/kernelet/bash-bundle bash && kernelet-runtime start --attach bash
```

Keeping both commands on one line avoids the Host shell echoing a pasted
second command while `create` is still running.
The Guest's `kernelet-agent` runs as PID 1 to prepare the environment,
launch applications, and reap child processes; it appears in Guest `ps` output.

At the `kernelet#` prompt, run SQLite to create and query a database:

```sh
sqlite3 -bail /tmp/demo.db <<'SQL'
CREATE TABLE messages (id INTEGER PRIMARY KEY, text TEXT);
INSERT INTO messages (text) VALUES ('Hello from Kernelet!');
.headers on
.mode column
SELECT * FROM messages;
PRAGMA integrity_check;
SQL
```

The query prints the inserted row, and the integrity check prints `ok`.
The database is in the Guest's writable overlay and lasts for this sandbox's
lifetime. Run `exit` to leave Bash.

When Bash exits, check the container state and delete it:

```sh
kernelet-runtime state bash
kernelet-runtime delete bash
```

The bundle sets `terminal` to `true`, so `start --attach` runs Bash
interactively on the calling terminal and restores the terminal when Bash
exits. The attached terminal's window size is synchronized automatically.
For an external console, resize its terminal with
`kernelet-runtime resize bash <columns> <rows>`.
A manager that drives the container programmatically can instead pass
`--console-socket <path>` to `create` to receive the PTY master over a Unix
socket; the CLI attach needs no console socket.
The runtime defaults to two vCPUs;
boot the Host with at least `SMP=2`, or pass `--vcpus 1` before `create`.

## Supported Benchmarks

The following benchmarks are currently supported:

- fio
- hackbench
- iperf3
- lmbench
- memcached
- nginx
- redis
- schbench
- sqlite
- sysbench

### Architecture Compatibility

All benchmarks except `sysbench` support both `x86_64` and `riscv64` architectures.

These benchmarks are precompiled and packaged into the Docker image for convenience. Refer to `tools/dev_env/docker/prebuilt-nix-packages/Dockerfile` for details.

## Adding New Benchmarks

We recommend utilizing `Nix` when adding new benchmarks. To check if a benchmark is already available, use the [`Nix Package Search`](https://search.nixos.org/packages?channel=26.05). If a package exists in the Nix channel, you can directly use it or modify it if necessary.

If the desired benchmark is not available or cannot be easily adapted, you can add a custom `.nix` file to package it manually. Place the `.nix` files under the `test/initramfs/nix/benchmark` directory.

## Configuration Files

Configuration files required by benchmarks or regression tests should be placed in the `test/initramfs/etc` directory.

If additional configuration files or directories are needed, ensure they are appropriately packaged by updating the `initramfs.nix` file.

## Notes for Developers

- **Nix Usage**: Use `Nix` whenever possible to manage dependencies and builds for ease of maintenance and consistency.
- **Multi-Architecture Support**: Ensure new regression tests or benchmarks properly support multiple CPU architectures.
