// SPDX-License-Identifier: MPL-2.0

//! Enforces the kernelet image's unsafe-code allowlist at each target rustc.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    env,
    ffi::{OsStr, OsString},
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
};

use super::unsafe_allowlist::{EXCEPTIONS, Exception, Origin};

pub(crate) const MODE_ENV: &str = "OSDK_KERNELET_RUSTC_WRAPPER";
pub(super) const WORKSPACE_ENV: &str = "OSDK_KERNELET_WORKSPACE_ROOT";
pub(super) const OSTD_ENV: &str = "OSDK_KERNELET_OSTD_ROOT";
pub(super) const BASE_ENV: &str = "OSDK_KERNELET_BASE_ROOT";
pub(super) const LOG_ENV: &str = "OSDK_KERNELET_UNSAFE_LOG";
const TARGET: &str = "x86_64-unknown-none";

/// Dispatches an OSDK invocation acting as Cargo's rustc wrapper.
pub(crate) fn run() -> i32 {
    match run_inner() {
        Ok(status) => status.code().unwrap_or(1),
        Err(error) => {
            eprintln!("kernelet rustc audit: {error}");
            1
        }
    }
}

fn run_inner() -> io::Result<ExitStatus> {
    let mut invocation = env::args_os().skip(1);
    let rustc = invocation.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Cargo did not supply a rustc path",
        )
    })?;
    let mut args: Vec<OsString> = invocation.collect();

    // Cargo also wraps host build scripts, proc macros, and rustc probes. They
    // are not linked into the image; only target crate invocations are audited.
    if option(&args, "--target").is_some_and(|target| target == TARGET) {
        let crate_name = option(&args, "--crate-name").ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "target rustc has no crate name",
            )
        })?;
        let package = env::var("CARGO_PKG_NAME").unwrap_or_else(|_| crate_name.to_string());
        let version = env::var("CARGO_PKG_VERSION").unwrap_or_default();
        let manifest_dir = env::var_os("CARGO_MANIFEST_DIR")
            .map(PathBuf::from)
            .map(fs::canonicalize)
            .transpose()?;
        let workspace = required_root(WORKSPACE_ENV)?;
        let ostd = required_root(OSTD_ENV)?;
        let base = required_root(BASE_ENV)?;
        let exception = exemption(
            &package,
            &version,
            manifest_dir.as_deref(),
            &workspace,
            &ostd,
            &base,
        );

        if exception.is_none() {
            // Cargo may cap dependency lints at `allow`. Such a cap defeats
            // even `-F unsafe_code`, so remove it before adding the forbid.
            remove_lint_cap(&mut args);
            args.push("-F".into());
            args.push("unsafe_code".into());
        }

        let status = Command::new(rustc).args(&args).status()?;
        if status.success()
            && let Some(exception) = exception
        {
            record_exemption(&package, &version, manifest_dir.as_deref(), exception)?;
        }
        return Ok(status);
    }

    Command::new(rustc).args(&args).status()
}

fn option<'a>(args: &'a [OsString], name: &str) -> Option<&'a str> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == OsStr::new(name) {
            return iter.next().and_then(|value| value.to_str());
        }
        if let Some(value) = arg.to_str().and_then(|arg| arg.strip_prefix(name))
            && let Some(value) = value.strip_prefix('=')
        {
            return Some(value);
        }
    }
    None
}

fn remove_lint_cap(args: &mut Vec<OsString>) {
    let mut index = 0;
    while index < args.len() {
        if args[index] == OsStr::new("--cap-lints") {
            args.drain(index..(index + 2).min(args.len()));
        } else if args[index]
            .to_str()
            .is_some_and(|arg| arg.starts_with("--cap-lints="))
        {
            args.remove(index);
        } else {
            index += 1;
        }
    }
}

fn required_root(name: &str) -> io::Result<PathBuf> {
    let path = env::var_os(name)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("{name} is not set")))?;
    fs::canonicalize(path)
}

fn exemption<'a>(
    package: &str,
    version: &str,
    manifest_dir: Option<&Path>,
    workspace: &Path,
    ostd: &Path,
    base: &Path,
) -> Option<&'a Exception> {
    // A kernel-proper crate must never become exempt, even if its package name
    // collides with a reviewed third-party crate.
    if manifest_dir
        .is_some_and(|path| path.starts_with(workspace) && !path.starts_with(ostd) && path != base)
    {
        return None;
    }
    EXCEPTIONS.iter().find(|entry| {
        (entry.package == package
            || (entry.origin == Origin::GeneratedEntry && package.ends_with("-kernelet-bin")))
            && entry.version.is_none_or(|allowed| allowed == version)
            && match entry.origin {
                Origin::Toolchain => manifest_dir.is_none_or(|path| !path.starts_with(workspace)),
                Origin::Ostd => manifest_dir.is_some_and(|path| path.starts_with(ostd)),
                Origin::GeneratedEntry => manifest_dir == Some(base),
                Origin::External => manifest_dir.is_some_and(|path| !path.starts_with(workspace)),
            }
    })
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
struct AuditEntry {
    package: String,
    version: String,
    manifest_dir: String,
    reason: String,
}

fn record_exemption(
    package: &str,
    version: &str,
    manifest_dir: Option<&Path>,
    exception: &Exception,
) -> io::Result<()> {
    let path = env::var_os(LOG_ENV).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("{LOG_ENV} is not set"))
    })?;
    let mut log = OpenOptions::new().create(true).append(true).open(path)?;
    let entry = AuditEntry {
        package: package.to_string(),
        version: version.to_string(),
        manifest_dir: manifest_dir
            .map_or_else(String::new, |path| path.to_string_lossy().into_owned()),
        reason: exception.reason.to_string(),
    };
    let mut line = serde_json::to_vec(&entry).map_err(io::Error::other)?;
    line.push(b'\n');
    // One append write keeps each record intact across parallel rustc jobs.
    log.write_all(&line)
}

/// Prints exactly the distinct allowlisted target crates observed by this
/// audited Cargo build. The file is kept with its isolated Cargo target cache,
/// so a fresh build also retains the evidence for subsequently cached units.
pub(super) fn print_exemptions(
    path: &Path,
    base_crate: &Path,
    features: &[String],
    toolchain: Option<&OsStr>,
) -> io::Result<()> {
    let current_packages = image_dependency_closure(base_crate, features, toolchain)?;
    let content = fs::read_to_string(path)?;
    let entries: BTreeSet<AuditEntry> = content
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()
        .map_err(io::Error::other)?;
    let entries: Vec<_> = entries
        .into_iter()
        .filter(|entry| {
            matches!(
                entry.package.as_str(),
                "core" | "alloc" | "compiler_builtins"
            ) || current_packages.contains(&(
                entry.package.clone(),
                entry.version.clone(),
                entry.manifest_dir.clone(),
            ))
        })
        .collect();
    eprintln!(
        "Kernelet unsafe-code audit: {} exempted target crates:",
        entries.len()
    );
    for entry in entries {
        eprintln!("  {} {}: {}", entry.package, entry.version, entry.reason);
    }
    Ok(())
}

fn image_dependency_closure(
    base_crate: &Path,
    features: &[String],
    toolchain: Option<&OsStr>,
) -> io::Result<HashSet<(String, String, String)>> {
    let mut command = Command::new("cargo");
    command.current_dir(base_crate).args([
        "metadata",
        "--format-version=1",
        "--filter-platform=x86_64-unknown-none",
        "--no-default-features",
    ]);
    command.arg("--features").arg(features.join(" "));
    if let Some(toolchain) = toolchain {
        command.env("RUSTUP_TOOLCHAIN", toolchain);
    }
    let output = command.output()?;
    if !output.status.success() {
        return Err(io::Error::other(
            "Cargo could not resolve the kernelet dependency closure",
        ));
    }
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).map_err(io::Error::other)?;
    let root = metadata["resolve"]["root"]
        .as_str()
        .ok_or_else(|| io::Error::other("Cargo metadata has no root package"))?;
    let nodes: HashMap<&str, &serde_json::Value> = metadata["resolve"]["nodes"]
        .as_array()
        .ok_or_else(|| io::Error::other("Cargo metadata has no dependency graph"))?
        .iter()
        .filter_map(|node| Some((node["id"].as_str()?, node)))
        .collect();
    let mut seen = HashSet::new();
    let mut todo = vec![root];
    while let Some(id) = todo.pop() {
        if !seen.insert(id) {
            continue;
        }
        let node = nodes
            .get(id)
            .ok_or_else(|| io::Error::other("missing Cargo dependency node"))?;
        if let Some(deps) = node["deps"].as_array() {
            for dep in deps {
                let normal = dep["dep_kinds"]
                    .as_array()
                    .is_some_and(|kinds| kinds.iter().any(|kind| kind["kind"].is_null()));
                if normal && let Some(pkg) = dep["pkg"].as_str() {
                    todo.push(pkg);
                }
            }
        }
    }
    let mut packages = HashSet::new();
    for package in metadata["packages"]
        .as_array()
        .ok_or_else(|| io::Error::other("Cargo metadata has no packages"))?
    {
        if !package["id"].as_str().is_some_and(|id| seen.contains(id)) {
            continue;
        }
        let (Some(name), Some(version), Some(manifest_path)) = (
            package["name"].as_str(),
            package["version"].as_str(),
            package["manifest_path"].as_str(),
        ) else {
            return Err(io::Error::other("incomplete Cargo package metadata"));
        };
        let manifest_dir = Path::new(manifest_path)
            .parent()
            .ok_or_else(|| io::Error::other("package manifest has no parent"))?
            .canonicalize()?;
        packages.insert((
            name.to_string(),
            version.to_string(),
            manifest_dir.to_string_lossy().into_owned(),
        ));
    }
    Ok(packages)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_and_crate_options_accept_both_cargo_forms() {
        let args = vec![
            "--crate-name".into(),
            "aster_core".into(),
            "--target=x86_64-unknown-none".into(),
        ];
        assert_eq!(option(&args, "--crate-name"), Some("aster_core"));
        assert_eq!(option(&args, "--target"), Some(TARGET));
    }

    #[test]
    fn cargo_lint_cap_cannot_disable_the_target_forbid() {
        let mut args = vec![
            "--cap-lints".into(),
            "allow".into(),
            "--crate-name".into(),
            "kernel".into(),
            "--cap-lints=warn".into(),
        ];
        remove_lint_cap(&mut args);
        assert_eq!(
            args,
            vec![OsString::from("--crate-name"), OsString::from("kernel")]
        );
    }

    #[test]
    fn kernel_crate_cannot_claim_an_external_exception() {
        let workspace = Path::new("/tree");
        let ostd = Path::new("/tree/ostd");
        let base = Path::new("/tree/target/osdk/base");
        assert!(
            exemption(
                "unwinding",
                "0.2.10",
                Some(Path::new("/tree/kernel/unwinding")),
                workspace,
                ostd,
                base
            )
            .is_none()
        );
        assert!(
            exemption(
                "ostd",
                "0.18.1",
                Some(Path::new("/tree/kernel/ostd")),
                workspace,
                ostd,
                base
            )
            .is_none()
        );
    }

    #[test]
    fn external_version_change_requires_review() {
        let workspace = Path::new("/tree");
        let ostd = Path::new("/tree/ostd");
        let base = Path::new("/tree/target/osdk/base");
        assert!(
            exemption(
                "unwinding",
                "0.2.10",
                Some(Path::new("/cargo/unwinding")),
                workspace,
                ostd,
                base
            )
            .is_some()
        );
        assert!(
            exemption(
                "unwinding",
                "0.2.11",
                Some(Path::new("/cargo/unwinding")),
                workspace,
                ostd,
                base
            )
            .is_none()
        );
    }
}
