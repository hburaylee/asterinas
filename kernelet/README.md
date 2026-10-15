<!-- SPDX-License-Identifier: MPL-2.0 -->

# Kernelet userspace

This workspace contains:
the `/dev/kernelet` ABI,
the OCI runtime,
the guest PID 1 agent,
and the containerd shim v2.
The image ABI shared with the Host kernel —
the ELF image format, its build contract,
and where the loader and audit code live —
is documented in [`ABI.md`](ABI.md).

## Kernel build modes

`kernelet-host` enables Host support and is disabled by default.
The separate `kernelet` feature builds the Image; the two features are mutually
exclusive and currently support only x86-64.
Run these commands from `kernel/` inside the development container:

| Command | Result |
|---|---|
| `cargo osdk build --release` | Native kernel without Kernelets Host support. |
| `cargo osdk build --release --features kernelet-host` | Host support without an embedded Image. |
| `cargo osdk build --release --kernelet` | Audited Image followed by a Host with `kernelet-host`, embedding that Image. |

The paired build enables `kernelet` only for its separate Image invocation.
Host builds with support enabled use panic unwinding for protected service
continuations.
An explicitly enabled Host without an embedded Image does not register
`/dev/kernelet`.

Without Host support, production builds exclude carrier accounting and switch
hooks, Host timer services, NAT charge fields, carrier page-table ownership,
and synchronous mapping-reclamation extensions.
Explicit RQ1 fixture and diagnostic builds retain their measurement code;
they are separate from production Native builds.
Enabling Host support still changes shared paths even before creating an
instance. This configuration needs its own performance measurements.

## Userspace build

Build all three statically linked programs with:

```sh
cargo build --manifest-path kernelet/Cargo.toml --release --target x86_64-unknown-linux-musl
```

For the Asterinas initramfs,
pass the built runtime, agent, and shim as explicit inputs to `make initramfs`
as described in
[`test/initramfs/README.md`](../test/initramfs/README.md#kernelet-userspace).
That image includes an OCI Bash bundle with SQLite
and a Nix-packaged `mke2fs` with its runtime closure.

The Host installation contains:

- `kernelet-runtime` and `containerd-shim-kernelet-v2` on `PATH`;
- `/usr/libexec/kernelet-agent`, the static guest binary;
- `/usr/libexec/kernelet-mke2fs`, a static `mke2fs` supplied by the distribution.

The OCI CLI accepts
`create`, `start`, `state`, `stats`, `kill`, `delete`, `exec`, and `resize`.
Global `--root`, `--cache`, `--agent`, and `--mke2fs` options
select installation paths.
`create --bundle <directory> <id>` consumes a standard OCI bundle.
`start --attach <id>` attaches the container to the calling terminal:
a `terminal=true` process runs interactively on the Guest PTY
and the CLI restores the tty when the attach ends,
while a `terminal=false` process has its standard streams forwarded.
`create --console-socket <socket>` remains for a manager,
transferring the Host PTY master with `SCM_RIGHTS`.
`exec --process <json> <id>` uses an OCI process object.
`pause`, `resume`, and `update` return an unsupported-operation error.

`stats <id>` reports JSON with
CPU execution, throttling, completion and receive-copy CPU time,
granted memory, memory limit, Host charges, and stacks.
Total CPU time includes carrier execution and adopted Host completion and
receive-copy work.
The completion and receive-copy counters describe portions of that total.
They are collected only in diagnostic kernel builds. Ordinary builds report
these two JSON fields as `null`; total CPU time and resource accounting remain
available. The raw `STATS` ioctl uses `STATS_UNAVAILABLE` (`UINT64_MAX`) for
uncollected diagnostic fields, preserving the structure's layout.
The CPU quota currently limits carrier execution time;
adopted Host work contributes to statistics without consuming that quota.
Throttle time is the sum of the wall-clock time each carrier spends waiting
for its CPU budget.

The runtime applies these OCI resource fields at creation:

| Field | Current behavior |
|---|---|
| `linux.resources.memory.limit` | A nonnegative limit is rounded down to a whole 2 MiB grain, with creation failing below one grain; a negative or omitted limit uses `--max-grains`. |
| `linux.resources.cpu.cpus` | The number of distinct CPU numbers selects the vCPU count; the Host's placement policy selects Host CPUs independently of those numbers. |
| `linux.resources.cpu.shares` | A positive value maps to the rounded nice value `10 - log2(shares)`, clamped to `[-20, 19]`; its fair weight is divided among the configured carriers. |
| `linux.resources.cpu.quota` and `period` | A positive quota sets carrier CPU time in microseconds per period, with an omitted period defaulting to `100000` microseconds; a nonpositive or omitted quota leaves this limit disabled. |
| `linux.resources.pids.limit` | A nonnegative limit is rejected; a negative limit does not install a finite OCI PID limit. |

For `N` configured vCPUs, each carrier receives `W/N` of the fair weight
selected by the sandbox's nice value.
The scheduler retains fractional precision instead of rounding to another nice value.
Later CPU budget updates preserve this divisor.
This normalizes the carriers' total weight;
it does not implement a sandbox group scheduler.
Sleeping carriers do not transfer their weight to the remaining runnable carriers,
and CPU placement still affects the time each carrier receives.
Adopted device workers remain separate Host scheduling entities outside this split.

`--max-grains` defaults to 256 grains (512 MiB) of Guest memory.
The Host's default per-user admission budget is 512 grains (1 GiB) in total,
including Guest memory ceilings and reserved Host execution storage.
The runtime default leaves room for Host Task stacks and carrier resources.
An explicit OCI memory limit or `--max-grains` value still sets the Guest
ceiling; creation fails if that ceiling plus Host reservations exceeds
the remaining per-user budget.

Other resource fields,
including memory reservation and swap limits,
block I/O limits,
huge-page limits,
and CPU memory-node selection,
are currently accepted without being applied.

The runtime builds content-addressed ext2 images,
including the agent in the root image.
The cached images are attached read-only.
The agent mounts a tmpfs upper and an overlay root
before processing the configuration.
Bind files are sent separately through the agent protocol
and preserve ownership and mode;
read-only directory binds become separate cached block images.
The runtime and agent require protocol version `4` in `Hello`;
build and deploy them together.
This version carries acknowledged `SignalAll` requests for every Guest process
except the PID 1 agent, including descendants that changed session or process group.
Per-process signals still address the selected launcher's process group.
Signal `0` probes existence without terminating a created process or sandbox.
A rootfs or agent that changes during image assembly
fails creation
instead of publishing a cache entry under an incorrect content key.

The CLI starts a holder after its own `exec`
and transfers its descriptors with an acknowledgment.
Later CLI invocations reconnect to its Unix control socket.
The containerd shim initializes that same holder in its own process
and retains the sandbox descriptors itself.
Containerd reconnects through the shim `Connect` and `State` RPCs.
If a holder dies,
its last capability closes and the sandbox is revoked;
`state` reports stopped,
and `delete` performs remaining host cleanup.
The shim persists the observed main-process exit
for its crash cleanup command.
If no exit was observed,
crash cleanup reports forced termination (137).
During normal deletion, `poststop` hooks can call `State` and `Wait`;
the task remains registered until cleanup finishes.

The agent gives stdout and stderr up to one second to finish after obtaining
the process's exit status.
The shim forwards each output stream through its own worker,
with a queue of at most eight 16 KiB chunks,
and uses nonblocking writes to avoid waiting indefinitely for a FIFO consumer.
It also bounds queue handoff and output draining after exit to one second.
Once it receives the exit status, it stops attachment input forwarding
before waiting for output workers.
A stream that cannot drain reports a local output failure and may be truncated;
the process keeps its actual exit code.
If an attachment disconnects,
the shim queries the holder's exit cache through a separate control connection.
An unavailable exit status makes `Wait` return an error.
Descendants that leave their launcher's process group can remain alive after
that process exits;
`kill(all=true)` signals these descendants as well.
Sandbox destruction terminates the remaining Guest execution.

Shim `Stats` exposes
the Host's CPU time, throttle time, and granted/capped memory
through containerd's cgroups metrics format.
Granted memory is an allocation, not Guest RSS.
`Pids` queries the agent
and returns PIDs in the Guest PID namespace;
these are not Host PIDs and exclude the agent itself.

## Networking

Networking is selected through these annotations
(the names are runtime API choices, not kernel ABI constants):

- `org.asterinas.kernelet.network`: `none` (default) or `nat`.
- `org.asterinas.kernelet.ports`:
  a JSON array of objects with `hostPort`, `containerPort`,
  optional `hostAddress` (default `127.0.0.1`),
  and `protocol` (`tcp` or `udp`).

Each sandbox uses `10.0.2.15/24`, gateway `10.0.2.2`, and DNS proxy `10.0.2.3`.
The DNS proxy reaches the Host's configured IPv4 resolver,
including a resolver bound to the Host loopback address.
These addresses belong to each sandbox's separate Ethernet link.

The Guest uses the kernel's existing static VirtIO network configuration.
The agent writes the DNS resolver file
without changing the link, address, or route through rtnetlink.
Custom Guest IPv4 addresses and gateways are not supported.

The runtime performs network configuration only;
the Host kernel forwards all payload traffic.
After creating the sandbox's network endpoint,
the runtime issues one `NET_CONFIG` ioctl on the endpoint file
carrying the Host resolver and up to 32 port mappings,
then attaches the endpoint to the sandbox with the guest MAC.
The Host validates the configuration
and binds the mapped host ports synchronously during `NET_CONFIG`,
so `create` fails before acknowledging a container
whose ports are already occupied.
After the attach,
the runtime keeps no network descriptor and exchanges no packets.
The existing per-user endpoint memory quota
also applies to listeners and active forwarding flows.
ICMP forwarding and IPv6 are not provided.

## C ABI header

Generate a C header from the shared Rust definitions with:

```sh
cargo run --manifest-path kernelet/abi/Cargo.toml --example header -- kernelet/target/kernelet-abi.h
cc -std=c11 -Werror -fsyntax-only -x c kernelet/target/kernelet-abi.h
```

The generator evaluates ioctl constants in Rust
and emits C structure-size assertions;
kernel and runtime consume the same `kernelet-abi` Rust crate.

## Validation

```sh
cargo clippy --manifest-path kernelet/Cargo.toml --all-targets -- -D warnings
KERNELET_TEST_MKE2FS=/path/to/mke2fs cargo test --manifest-path kernelet/Cargo.toml -- --include-ignored
```

Native tests cover
message bounds, descriptor transfer, and actual ext2 image creation and reuse.
They also exercise shim RPC deletion races
and hook callbacks through `State` and `Wait`,
plus local forwarding with real FIFOs and sockets under input backpressure.
They do not prove that the full guest boot, overlay, OCI lifecycle,
containerd integration, or Host network forwarding paths work.
Those require the integrated QEMU tests
and a Host kernel implementing the resource and lifecycle ABI.
