// SPDX-License-Identifier: MPL-2.0

use std::{
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
    process::Command,
};

use crate::util::{get_kernel_crate, new_command_checked_exists};

pub const COMMON_CARGO_ARGS: &[&str] = &[
    "-Zbuild-std=core,alloc,compiler_builtins",
    "-Zbuild-std-features=compiler-builtins-mem",
];

pub const DEFAULT_TARGET_RELPATH: &str = "osdk";

/// Resolves relative output paths before a command changes to a generated crate.
pub(super) fn resolve_output_directory(
    output: Option<&Path>,
    cargo_target_directory: &Path,
) -> io::Result<PathBuf> {
    let output = output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| cargo_target_directory.join(DEFAULT_TARGET_RELPATH));
    std::path::absolute(output)
}

/// Serializes OSDK builds through packaging, after which QEMU may run in parallel.
///
/// Cargo releases its own lock before OSDK copies and audits its ELF artifacts.
/// Hold this lock before invoking Cargo and retain the file until packaging ends.
/// Never unlink the lock file: other processes must keep locking the same inode.
pub(super) fn lock_build_directory(cargo_target_directory: &Path) -> io::Result<File> {
    fs::create_dir_all(cargo_target_directory)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(cargo_target_directory.join(".osdk-build-lock"))?;
    file.lock()?;
    Ok(file)
}

pub fn cargo() -> Command {
    new_command_checked_exists("cargo")
}

pub fn profile_name_adapter(profile: &str) -> &str {
    match profile {
        "dev" => "debug",
        _ => profile,
    }
}

pub fn bin_file_name() -> String {
    get_kernel_crate().name + "-osdk-bin"
}

pub(crate) fn is_tdx_enabled() -> bool {
    std::env::var("INTEL_TDX").is_ok_and(|s| s == "1")
}

#[cfg(test)]
mod tests {
    use std::fs::TryLockError;

    use super::*;

    #[test]
    fn relative_output_is_resolved_at_the_command_entry() {
        const CHILD_ENV: &str = "OSDK_TEST_OUTPUT_DIRECTORY_CHILD";
        if std::env::var_os(CHILD_ENV).is_none() {
            // Other unit tests change the process cwd; isolate the invocation cwd.
            let directory = tempfile::tempdir().unwrap();
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "commands::util::tests::relative_output_is_resolved_at_the_command_entry",
                    "--nocapture",
                ])
                .current_dir(directory.path())
                .env(CHILD_ENV, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "output path test failed: {output:?}"
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("running 1 test"));
            return;
        }

        let entry_directory = std::env::current_dir().unwrap();
        let output =
            resolve_output_directory(Some(Path::new("artifacts")), Path::new("target")).unwrap();
        let crate_directory = entry_directory.join("member");
        fs::create_dir(&crate_directory).unwrap();
        std::env::set_current_dir(crate_directory).unwrap();
        assert_eq!(output, entry_directory.join("artifacts"));
        assert!(output.is_absolute());
        assert_eq!(
            resolve_output_directory(None, &entry_directory.join("target")).unwrap(),
            entry_directory.join("target/osdk")
        );
    }

    #[test]
    fn build_lock_serializes_processes_and_releases_on_drop() {
        const TARGET_ENV: &str = "OSDK_TEST_BUILD_LOCK_TARGET";
        const BLOCKED_ENV: &str = "OSDK_TEST_BUILD_LOCK_BLOCKED";

        if let Some(target) = std::env::var_os(TARGET_ENV) {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(Path::new(&target).join(".osdk-build-lock"))
                .unwrap();
            let blocked = match file.try_lock() {
                Ok(()) => false,
                Err(TryLockError::WouldBlock) => true,
                Err(TryLockError::Error(error)) => panic!("failed to probe build lock: {error}"),
            };
            assert_eq!(blocked, std::env::var(BLOCKED_ENV).unwrap() == "true");
            return;
        }

        let directory = tempfile::tempdir().unwrap();
        let lock = lock_build_directory(directory.path()).unwrap();
        let probe = |blocked: bool| {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "commands::util::tests::build_lock_serializes_processes_and_releases_on_drop",
                    "--nocapture",
                ])
                .env(TARGET_ENV, directory.path())
                .env(BLOCKED_ENV, blocked.to_string())
                .output()
                .unwrap();
            assert!(output.status.success(), "lock probe failed: {output:?}");
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("running 1 test"),
                "the child did not execute the lock probe: {output:?}"
            );
        };
        probe(true);
        drop(lock);
        probe(false);
    }

    #[test]
    fn build_lock_reports_an_unusable_target_directory() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("not-a-directory");
        fs::write(&target, "").unwrap();
        assert!(lock_build_directory(&target).is_err());
    }
}
