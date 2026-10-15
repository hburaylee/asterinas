# Build cache maintenance

Run OSDK and Makefile build commands in the project development container.
Keep Cargo compilation caches separate from each task's boot images and logs.
Use a stable `CARGO_TARGET_DIR` for normal development.
`make install_osdk` reuses `osdk/target` when rebuilding the development tool.
OSDK serializes the Guest build, Host build and packaging within that cache;
it releases the lock before starting QEMU.
Different tasks can select separate generated output directories:

```sh
make run_kernelet OSDK_OUTPUT=.scratch/my-task/osdk
```

The `kernel`, `run_kernel`, `run_kernelet` and `ktest` targets accept `OSDK_OUTPUT`.
It is relative to the repository root.
Direct OSDK commands accept `--output` (or `-o`), relative to the command's entry directory:

```sh
cd kernel
cargo osdk run --kernelet --release --output ../.scratch/my-task/osdk
cargo osdk test --output ../.scratch/my-tests/osdk
```

Choose a different output directory for each concurrent task.
QEMU ports, logs and writable disks still need separate configurations.
The lock coordinates updated OSDK processes sharing one Cargo target;
stop old OSDK builds before switching to this workflow.
Other Cargo commands do not acquire OSDK's packaging lock.

Normal development can keep incremental compilation enabled.
For a one-time validation that will not reuse its intermediate files, set
`CARGO_INCREMENTAL=0` for that command.
This avoids retaining incremental state and can increase subsequent build time.
Preserve the required Host/Guest, feature, architecture and test configurations.

## Clean compiler caches

Preview cleanup before applying it:

```sh
sudo python3 tools/clean_build_cache.py
sudo python3 tools/clean_build_cache.py --apply
```

`make clean_build_cache` also previews cleanup.
The tool recognizes Cargo caches under `target`, `.scratch`, `kernelet/target`
and `build/framevm/service-target`.
It removes only `deps`, `build`, `.fingerprint` and `incremental` directories
inside recognized Cargo profiles.
It preserves final binaries, ELF files, images, manifests, source snapshots,
logs and experiment results outside those compiler directories.
The newest audit cache for each owner is retained by default.
OSDK's audit fingerprint and audit checks remain unchanged.

Use `--incremental-only` to retain other compiler intermediates,
or repeat `--cache-root` to select exact discovered cache roots:

```sh
sudo python3 tools/clean_build_cache.py --incremental-only --cache-root kernelet/target
```

Stop starting builds during cleanup.
The tool checks process references, including container paths, and skips active caches.
Applying cleanup requires complete process visibility and existing Cargo profile locks;
it refuses incomplete process inspection and retains locked or unrecognized caches.
Cleanup also coordinates with the updated OSDK packaging lock when present.
Retained cache directories are reported with their reason.
Keep frozen benchmark bundles and accepted results separately;
their writable disks and images are not compiler caches.

## Validate changes

```sh
python3 -m unittest discover -s tools/tests -p test_clean_build_cache.py
cargo test --manifest-path osdk/Cargo.toml --bin cargo-osdk -- --test-threads=1
```
