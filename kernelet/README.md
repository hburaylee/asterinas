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

Build all three statically linked programs with:

```sh
cargo build --manifest-path kernelet/Cargo.toml --release --target x86_64-unknown-linux-musl
```

For the Asterinas initramfs,
pass the built runtime and agent as explicit inputs to `make initramfs`
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
Completion and receive-copy counters describe portions of total CPU time;
they are not added to the aggregate quota again.

The runtime builds content-addressed ext2 images,
including the agent in the root image.
The cached images are attached read-only.
The agent mounts a tmpfs upper and an overlay root
before processing the configuration.
Bind files are sent separately through the agent protocol
and preserve ownership and mode;
read-only directory binds become separate cached block images.
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
They do not prove that the full guest boot, overlay, OCI lifecycle,
containerd integration, or Host network forwarding paths work.
Those require the integrated QEMU tests
and a Host kernel implementing the resource and lifecycle ABI;
the runtime does not silently replace unsupported resource settings
with different values.
