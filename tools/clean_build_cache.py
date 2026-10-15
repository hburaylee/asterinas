#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Remove Cargo cache internals within the project's explicit cache scopes.

Scopes: target/, .scratch/, kernelet/target/, build/framevm/service-target/.

Dry-run is the default. --apply requires complete /proc visibility (usually
sudo). Sources, final binaries, manifests, logs and images outside Cargo's
deps/build/.fingerprint/incremental directories are retained. The advisory
root lock coordinates this tool only. Existing ancestor .osdk-build-lock and
profile/.cargo-lock files are also locked; caches without Cargo locks are retained. Stop
starting builds during --apply: /proc inspection is a conservative snapshot.
"""

import argparse
from contextlib import contextmanager, ExitStack
from dataclasses import dataclass
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys


CACHE_PARTS = {"deps", "build", ".fingerprint", "incremental"}
CACHE_SCOPES = ("target", ".scratch", "kernelet/target", "build/framevm/service-target")
PROFILES = {"debug", "release", "release-lto"}
AUDIT = re.compile(r"kernelet-unsafe-audit-[0-9a-f]+$")


@dataclass(frozen=True)
class Cache:
    root: Path
    domain: Path
    parts: tuple[Path, ...]
    modified: float


def validate_root(value):
    root = Path(os.path.abspath(value))
    for path in (root, *root.parents):
        if path.is_symlink():
            raise ValueError(f"symbolic link in root path: {path}")
    for name in ("Cargo.toml", "rust-toolchain.toml"):
        if not (root / name).is_file() or (root / name).is_symlink():
            raise ValueError(f"missing regular Asterinas root marker: {root / name}")
    if not all((root / name).is_dir() for name in ("kernel", "ostd", "osdk")):
        raise ValueError(f"not an Asterinas root: {root}")
    return root


@contextmanager
def lock_root(root):
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield descriptor
    finally:
        os.close(descriptor)


def regular_directory(path):
    return path.is_dir() and not path.is_symlink()


def profiles(directory):
    for child in directory.iterdir():
        if not regular_directory(child):
            continue
        marker = child / ".rustc_info.json"
        if marker.exists() or marker.is_symlink():
            # A nested cache owns its host and target profiles independently.
            # Treating its name as a target triple would bypass audit retention.
            continue
        if child.name in PROFILES:
            yield child
        elif re.fullmatch(r"[a-zA-Z0-9_]+(?:-[a-zA-Z0-9_.]+){2,}", child.name):
            for profile in child.iterdir():
                if profile.name in PROFILES and regular_directory(profile):
                    yield profile


def discover(root, incremental_only=False):
    caches = []
    for name in CACHE_SCOPES:
        scope = root / name
        if any(path.is_symlink() for path in (scope, *scope.parents) if path != root):
            raise ValueError(f"symbolic link in cache boundary: {scope}")
        if not scope.exists():
            continue
        for directory, children, files in os.walk(scope, followlinks=False):
            current = Path(directory)
            children[:] = [name for name in children
                           if not (current / name).is_symlink() and name != ".git"]
            if ".rustc_info.json" not in files:
                continue
            marker = current / ".rustc_info.json"
            if marker.is_symlink():
                continue
            try:
                info = json.loads(marker.read_text())
            except (ValueError, UnicodeError):
                continue
            if not isinstance(info, dict) or "rustc_fingerprint" not in info:
                continue
            parts = []
            selected_profiles = list(profiles(current))
            for profile in selected_profiles:
                # Two independent Cargo directories avoid treating a coincidental
                # debug/incremental directory as a compiler cache.
                if not all(regular_directory(profile / part) for part in ("deps", ".fingerprint")):
                    continue
                names = {"incremental"} if incremental_only else CACHE_PARTS
                parts.extend(profile / part for part in sorted(names)
                             if regular_directory(profile / part))
            if parts:
                relative = current.relative_to(scope)
                domain = scope / relative.parts[0] if relative.parts else scope
                modified = max(path.stat().st_mtime for path in (marker, *parts))
                caches.append(Cache(current, domain, tuple(parts), modified))
                # Cargo output trees can contain arbitrary dependency trees. Do
                # not discover nested candidates inside already selected output.
                children[:] = [name for name in children if current / name not in selected_profiles
                               and not any(profile.is_relative_to(current / name)
                                           for profile in selected_profiles)]
    return sorted(caches, key=lambda cache: str(cache.root))


def identity(path):
    value = path.stat()
    return value.st_dev, value.st_ino


def host_reference(process, value, root, cwd=None):
    """Translate a process-namespace path using an inode-verified repo ancestor."""
    value = value.removesuffix(" (deleted)")
    path = Path(value)
    if not path.is_absolute():
        if cwd is None:
            return None
        path = Path(cwd) / path
    path = Path(os.path.normpath(path))
    suffix = []
    root_identity = identity(root)
    for ancestor in (path, *path.parents):
        namespace_path = process / "root" / str(ancestor).lstrip("/")
        try:
            if identity(namespace_path) == root_identity:
                return root.joinpath(*reversed(suffix))
        except (FileNotFoundError, NotADirectoryError):
            pass
        suffix.append(ancestor.name)
    return None


def ancestor_pids(proc):
    """Exclude command wrappers that repeat this tool's cache selection."""
    excluded = {1}
    pid = os.getpid()
    while pid and pid not in excluded:
        excluded.add(pid)
        status = (proc / str(pid) / "status").read_text()
        pid = int(next(line.split()[1] for line in status.splitlines()
                       if line.startswith("PPid:")))
    return excluded


def inspect_processes(root, proc=Path("/proc")):
    references, errors = [], []
    try:
        excluded = ancestor_pids(proc)
    except (OSError, ValueError, StopIteration) as error:
        return [], [f"cannot identify cleanup process ancestors: {error}"]
    for process in proc.iterdir():
        if not process.name.isdecimal() or int(process.name) in excluded:
            continue
        try:
            arguments = (process / "cmdline").read_bytes().split(b"\0")
            if not arguments[0]:
                continue  # Kernel threads have no userspace paths.
            command = [argument.decode(errors="replace") for argument in arguments if argument]
            builder = any(re.fullmatch(r"(?:cargo(?:-osdk)?|rustc)(?:-[0-9a-f]+)?", Path(argument).name)
                          for argument in command[:1])
            virtual_machine = any(Path(argument).name.startswith("qemu-system-") for argument in command[:1])
            cwd = os.readlink(process / "cwd")
            paths = [cwd]
            for descriptor in (process / "fd").iterdir():
                try:
                    value = os.readlink(descriptor)
                    if value.startswith("/"):
                        paths.append(value)
                except FileNotFoundError:
                    pass
            for line in (process / "maps").read_text().splitlines():
                fields = line.split(None, 5)
                if len(fields) == 6 and fields[5].startswith("/"):
                    paths.append(fields[5])
            for argument in command:
                paths.extend(re.findall(r"(?:^|[=\s,])(/[^\s,'\"]+)", argument))
                if "/" in argument and not argument.startswith("-") and " " not in argument:
                    paths.append(argument)
            for value in set(paths):
                host = host_reference(process, value, root, cwd)
                if host is not None:
                    references.append((int(process.name), host, builder, virtual_machine))
        except (FileNotFoundError, ProcessLookupError):
            continue  # A process may exit during the snapshot.
        except OSError as error:
            errors.append(f"PID {process.name}: {error}")
    return references, errors


def retention(caches, references, keep_audits):
    groups = {}
    for cache in caches:
        if AUDIT.fullmatch(cache.root.name):
            groups.setdefault(cache.root.parent, []).append(cache)
    retained = {}
    for audits in groups.values():
        audits.sort(key=lambda cache: (-cache.modified, str(cache.root)))
        retained.update({cache.root: "recent audit cache for this owner"
                         for cache in audits[:keep_audits]})
    for cache in caches:
        for pid, path, builder, virtual_machine in references:
            direct = path == cache.root or path.is_relative_to(cache.root)
            owner = (builder or virtual_machine) and path.is_relative_to(cache.domain)
            ancestor = builder and cache.root.is_relative_to(path)
            if direct or owner or ancestor:
                retained[cache.root] = f"active PID {pid}: {path}"
                break
    return retained


@contextmanager
def parent_descriptor(root, path):
    relative = path.relative_to(root)
    if not any(relative.is_relative_to(scope) for scope in CACHE_SCOPES):
        raise ValueError(f"outside recognized Cargo cache: {path}")
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in relative.parts[:-1]:
            next_descriptor = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                      dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        yield descriptor
    finally:
        os.close(descriptor)


def remove_part(root, part, expected):
    """Open every parent with O_NOFOLLOW; rmtree uses fd-relative traversal."""
    if part.name not in CACHE_PARTS:
        raise ValueError(f"not a Cargo cache component: {part}")
    with parent_descriptor(root, part) as descriptor:
        actual = os.stat(part.name, dir_fd=descriptor, follow_symlinks=False)
        if not stat.S_ISDIR(actual.st_mode) or (actual.st_dev, actual.st_ino) != expected:
            raise ValueError(f"cache changed after inspection: {part}")
        if not shutil.rmtree.avoids_symlink_attacks:
            raise RuntimeError("this Python platform cannot safely remove cache trees")
        shutil.rmtree(part.name, dir_fd=descriptor)


def acquire_locks(root, paths, stack):
    with ExitStack() as pending:
        try:
            for path in sorted(set(paths)):
                with parent_descriptor(root, path) as parent:
                    descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
                pending.callback(os.close, descriptor)
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    return f"not a regular build lock: {path}"
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            return f"build lock unavailable: {error}"
        stack.enter_context(pending.pop_all())
    return None


def acquire_cargo_locks(root, cache, stack):
    # Cargo 3efb1f477 src/compiler/layout.rs:285-291 takes this compatibility
    # lock shared even with the newer build/artifact locks. LOCK_EX excludes it.
    # https://github.com/rust-lang/cargo/blob/3efb1f477/src/compiler/layout.rs
    return acquire_locks(root, {part.parent / ".cargo-lock" for part in cache.parts}, stack)


def osdk_locks(root, cache):
    paths = []
    for ancestor in (cache.root, *cache.root.parents):
        if ancestor == root:
            break
        path = ancestor / ".osdk-build-lock"
        if path.exists() or path.is_symlink():
            paths.append(path)
    return paths


def clean(root, *, apply=False, incremental_only=False, keep_audits=1,
          cache_roots=(), inspect=inspect_processes):
    root = validate_root(root)
    with lock_root(root), ExitStack() as locks:
        caches = discover(root, incremental_only)
        all_caches = caches
        if cache_roots:
            selected = {Path(os.path.abspath(root / value)) for value in cache_roots}
            unknown = selected - {cache.root for cache in caches}
            if unknown:
                raise ValueError(f"not a discovered Cargo cache root: {sorted(unknown)}")
            caches = [cache for cache in caches if cache.root in selected]
        references, errors = inspect(root)
        if errors:
            print("incomplete process inspection: " + "; ".join(errors[:5]), file=sys.stderr)
            if apply:
                raise RuntimeError("--apply requires complete /proc visibility; use sudo")
        retained = {path: reason for path, reason in retention(all_caches, references, keep_audits).items()
                    if path in {cache.root for cache in caches}}
        required_osdk = {cache.root: osdk_locks(root, cache) for cache in caches}
        # Match OSDK's order: all outer build locks precede Cargo profile locks.
        osdk_status = {path: acquire_locks(root, [path], locks)
                       for path in sorted({path for cache in caches if cache.root not in retained
                                           for path in required_osdk[cache.root]})}
        for cache in caches:
            if cache.root not in retained:
                reason = next((osdk_status[path] for path in required_osdk[cache.root]
                               if osdk_status[path] is not None), None)
                reason = reason or acquire_cargo_locks(root, cache, locks)
                if reason:
                    retained[cache.root] = reason
        expected = {part: identity(part) for cache in caches for part in cache.parts}
        if apply:
            print("Existing OSDK/Cargo locks held; do not start builds during cleanup.", file=sys.stderr)
            # Recheck immediately before mutation; a new process can still race
            # this snapshot, which the advisory lock cannot prevent.
            references, errors = inspect(root)
            if errors:
                raise RuntimeError("process inspection became incomplete; no caches removed")
            retained.update({path: reason for path, reason in retention(all_caches, references, keep_audits).items()
                             if path in {cache.root for cache in caches}})
        for cache in caches:
            if cache.root in retained:
                print(f"KEEP {cache.root}: {retained[cache.root]}")
                continue
            for part in cache.parts:
                print(f"{'REMOVE' if apply else 'WOULD REMOVE'} {part}")
                if apply:
                    remove_part(root, part, expected[part])
        print(f"{'applied' if apply else 'dry-run'}: {len(caches)} caches, {len(retained)} retained")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--apply", action="store_true", help="delete selected cache internals")
    parser.add_argument("--incremental-only", action="store_true", help="keep other Cargo cache internals")
    parser.add_argument("--keep-audits", type=int, default=1, help="retain this many most recent audit caches (default: 1)")
    parser.add_argument("--cache-root", type=Path, action="append", default=[],
                        help="select an exact discovered cache root; repeatable, relative to --root")
    arguments = parser.parse_args(argv)
    if arguments.keep_audits < 0:
        parser.error("--keep-audits must be nonnegative")
    try:
        clean(arguments.root, apply=arguments.apply, incremental_only=arguments.incremental_only,
              keep_audits=arguments.keep_audits, cache_roots=arguments.cache_root)
    except (OSError, ValueError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
