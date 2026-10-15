# SPDX-License-Identifier: MPL-2.0
"""Exercise destructive operations only on private, temporary fixtures."""

import contextlib
import fcntl
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "clean_build_cache", Path(__file__).resolve().parents[1] / "clean_build_cache.py")
cleaner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = cleaner
SPEC.loader.exec_module(cleaner)


class CleanBuildCacheTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "asterinas"
        self.root.mkdir()
        for name in ("Cargo.toml", "rust-toolchain.toml"):
            (self.root / name).touch()
        for name in ("kernel", "ostd", "osdk"):
            (self.root / name).mkdir()
        self.empty_processes = lambda root: ([], [])

    def cache(self, name="target", profile="debug"):
        cache = self.root / name
        cache.mkdir(parents=True, exist_ok=True)
        (cache / ".rustc_info.json").write_text(json.dumps({"rustc_fingerprint": 1}))
        for part in cleaner.CACHE_PARTS:
            directory = cache / profile / part
            directory.mkdir(parents=True)
            (directory / "data").write_text("cache")
        (cache / profile / ".cargo-lock").touch()
        return cache

    def clean(self, **options):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            cleaner.clean(self.root, inspect=self.empty_processes, **options)

    def test_dry_run_does_not_mutate_files_or_directories(self):
        self.cache()
        before = {str(path): path.lstat() for path in self.root.rglob("*")}
        self.clean()
        after = {str(path): path.lstat() for path in self.root.rglob("*")}
        self.assertEqual(before, after)

    def test_apply_preserves_manifest_images_logs_source_and_final_binary(self):
        cache = self.cache("target/task/cargo-target", "x86_64-unknown-none/release")
        for name in ("manifest.json", "host.iso", "qemu.log", "main.rs"):
            (cache / name).write_text("keep")
        executable = cache / "x86_64-unknown-none/release/kernel.elf"
        executable.write_text("keep")
        self.clean(apply=True)
        self.assertTrue(executable.exists())
        self.assertTrue(all((cache / name).exists() for name in
                            ("manifest.json", "host.iso", "qemu.log", "main.rs")))
        self.assertFalse((executable.parent / "deps").exists())

    def test_incremental_only_preserves_other_cache_parts(self):
        cache = self.cache()
        self.clean(apply=True, incremental_only=True)
        self.assertFalse((cache / "debug/incremental").exists())
        self.assertTrue((cache / "debug/deps/data").exists())

    def test_fake_cargo_directory_is_ignored(self):
        cache = self.cache()
        (cache / ".rustc_info.json").write_text("{}")
        self.clean(apply=True)
        self.assertTrue((cache / "debug/deps/data").exists())

    def test_symlink_boundary_and_root_are_rejected(self):
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        (self.root / "target").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.clean(apply=True)
        link = Path(self.temporary.name) / "link"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            cleaner.validate_root(link)

    def test_nested_symlink_is_not_followed_and_escape_is_refused(self):
        cache = self.cache()
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        sentinel = outside / "source.rs"
        sentinel.write_text("keep")
        (cache / "debug/deps/link").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            cleaner.remove_part(self.root, outside, cleaner.identity(outside))
        self.clean(apply=True)
        self.assertEqual(sentinel.read_text(), "keep")

    def test_active_reference_and_newest_audit_are_retained(self):
        old = self.cache("target/kernelet-unsafe-audit-a1")
        new = self.cache("target/kernelet-unsafe-audit-b2")
        active = self.cache("target/running/cargo-target")
        os.utime(old / ".rustc_info.json", (1, 1))
        os.utime(new / ".rustc_info.json", (4000000000, 4000000000))
        self.empty_processes = lambda root: ([(10, self.root / "target/running/image.iso", False, True)], [])
        self.clean(apply=True)
        self.assertFalse((old / "debug/deps").exists())
        self.assertTrue((new / "debug/deps").exists())
        self.assertTrue((active / "debug/deps").exists())

    def test_container_alias_is_translated_by_inode(self):
        proc = Path(self.temporary.name) / "proc/123"
        (proc / "root/mounted").mkdir(parents=True)
        (proc / "root/mounted/repository").symlink_to(self.root, target_is_directory=True)
        value = cleaner.host_reference(proc, "/mounted/repository/target/missing/deps/file", self.root)
        self.assertEqual(value, self.root / "target/missing/deps/file")
        self.assertIsNone(cleaner.host_reference(proc, "/unrelated/target/deps", self.root))

    def test_incomplete_proc_visibility_blocks_apply(self):
        cache = self.cache()
        self.empty_processes = lambda root: ([], ["PID 42: permission denied"])
        with self.assertRaises(RuntimeError):
            self.clean(apply=True)
        self.assertTrue((cache / "debug/deps/data").exists())

    def test_process_starting_before_second_snapshot_is_preserved(self):
        cache = self.cache()
        snapshots = iter([([], []), ([(11, cache / "debug/deps/data", True, False)], [])])
        self.empty_processes = lambda root: next(snapshots)
        self.clean(apply=True)
        self.assertTrue((cache / "debug/deps/data").exists())

    def test_audit_retention_is_per_owner(self):
        for owner in ("target", ".scratch/task/cache"):
            old = self.cache(owner + "/kernelet-unsafe-audit-a1")
            new = self.cache(owner + "/kernelet-unsafe-audit-b2")
            os.utime(new / ".rustc_info.json", (4000000000, 4000000000))
        self.clean(apply=True)
        for owner in ("target", ".scratch/task/cache"):
            self.assertFalse((self.root / owner / "kernelet-unsafe-audit-a1/debug/deps").exists())
            self.assertTrue((self.root / owner / "kernelet-unsafe-audit-b2/debug/deps").exists())

    def test_nested_audits_own_host_and_guest_profiles_with_outer_cache(self):
        outer = self.cache("target", "release")
        audit_names = ("target/kernelet-unsafe-audit-a1", "target/kernelet-unsafe-audit-b2")
        profiles = ("debug", "release", "x86_64-unknown-none/debug", "x86_64-unknown-none/release")
        for name in audit_names:
            for profile in profiles:
                self.cache(name, profile)
        old, new = (self.root / name for name in audit_names)
        os.utime(new / ".rustc_info.json", (4000000000, 4000000000))
        caches = {cache.root: cache for cache in cleaner.discover(self.root)}
        self.assertEqual(set(caches), {outer, old, new})
        self.assertTrue(all(part.parent == outer / "release" for part in caches[outer].parts))
        self.assertEqual(len(caches[new].parts), len(profiles) * len(cleaner.CACHE_PARTS))
        self.assertIn(new, cleaner.retention(list(caches.values()), [], keep_audits=1))
        self.clean(apply=True)
        for profile in profiles:
            self.assertFalse((old / profile / "deps").exists())
            self.assertTrue((new / profile / "deps/data").exists())
        self.assertFalse((outer / "release/deps").exists())
        self.assertTrue((old / ".rustc_info.json").exists())

    def test_only_explicit_framevm_service_scope_is_allowed(self):
        service = self.cache("build/framevm/service-target")
        unrelated = self.cache("build/framevm/other-target")
        self.assertEqual([cache.root for cache in cleaner.discover(self.root)], [service])
        self.clean(apply=True, cache_roots=[Path("build/framevm/service-target")])
        self.assertFalse((service / "debug/deps").exists())
        self.assertTrue((service / ".rustc_info.json").exists())
        self.assertTrue((unrelated / "debug/deps/data").exists())
        part = unrelated / "debug/deps"
        with self.assertRaises(ValueError):
            cleaner.remove_part(self.root, part, cleaner.identity(part))

    def test_symlink_in_framevm_scope_ancestor_is_rejected(self):
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        (self.root / "build").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.clean(apply=True)

    def test_exact_cache_selection_and_userspace_scope(self):
        main = self.cache()
        userspace = self.cache("kernelet/target")
        self.clean(apply=True, cache_roots=[Path("kernelet/target")])
        self.assertTrue((main / "debug/deps/data").exists())
        self.assertFalse((userspace / "debug/deps").exists())
        with self.assertRaises(ValueError):
            self.clean(apply=True, cache_roots=[Path("/tmp")])

    def test_busy_or_missing_cargo_lock_preserves_cache(self):
        cache = self.cache()
        path = cache / "debug/.cargo-lock"
        with path.open("rb") as stream:
            fcntl.flock(stream, fcntl.LOCK_SH | fcntl.LOCK_NB)
            self.clean(apply=True)
        self.assertTrue((cache / "debug/deps/data").exists())
        path.unlink()
        self.clean(apply=True)
        self.assertTrue((cache / "debug/deps/data").exists())

    def test_busy_ancestor_osdk_lock_preserves_nested_cache(self):
        cache = self.cache("target/owner/kernelet-unsafe-audit-a1")
        path = cache.parent / ".osdk-build-lock"
        path.touch()
        with path.open("rb") as stream:
            fcntl.flock(stream, fcntl.LOCK_SH | fcntl.LOCK_NB)
            self.clean(apply=True, keep_audits=0)
        self.assertTrue((cache / "debug/deps/data").exists())
        self.clean(apply=True, keep_audits=0)
        self.assertFalse((cache / "debug/deps").exists())
        self.assertTrue(path.exists())

    def test_symlink_in_userspace_scope_ancestor_is_rejected(self):
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        (self.root / "kernelet").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.clean(apply=True)

    def test_ancestor_pids_follow_status_ppid_chain(self):
        proc = Path(self.temporary.name) / "proc"
        for pid, parent in ((300, 200), (200, 100), (100, 1)):
            directory = proc / str(pid)
            directory.mkdir(parents=True)
            (directory / "status").write_text(f"Name:\twrapper\nPPid:\t{parent}\n")
        with patch.object(cleaner.os, "getpid", return_value=300):
            self.assertEqual(cleaner.ancestor_pids(proc), {300, 200, 100, 1})

    def test_real_wrapper_with_absolute_cache_argument_does_not_retain_it(self):
        cache = self.cache("kernelet/target")
        wrapper = "import subprocess,sys; sys.exit(subprocess.run(sys.argv[1:]).returncode)"
        result = subprocess.run(
            [sys.executable, "-c", wrapper, sys.executable, str(Path(cleaner.__file__)),
             "--root", str(self.root), "--cache-root", str(cache)],
            capture_output=True, text=True, timeout=30,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"WOULD REMOVE {cache / 'debug/deps'}", result.stdout)
        self.assertNotIn("KEEP ", result.stdout)
        self.assertTrue((cache / "debug/deps/data").exists())

    def test_unrelated_real_process_open_file_still_retains_cache(self):
        cache = self.cache()
        source = "import sys,time; f=open(sys.argv[1]); print('ready',flush=True); time.sleep(30)"
        process = subprocess.Popen([sys.executable, "-c", source, str(cache / "debug/deps/data")],
                                   stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(process.stdout.readline(), "ready\n")
            references, _ = cleaner.inspect_processes(self.root)
            self.assertTrue(any(pid == process.pid and path == cache / "debug/deps/data"
                                for pid, path, _, _ in references))
            retained = cleaner.retention(cleaner.discover(self.root), references, 1)
            self.assertIn(cache, retained)
        finally:
            process.terminate()
            process.wait(timeout=5)
            process.stdout.close()


if __name__ == "__main__":
    unittest.main()
