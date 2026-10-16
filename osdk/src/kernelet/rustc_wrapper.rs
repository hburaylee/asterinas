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
    let host = env::var_os("HOST");
    let cargo_target = env::var_os("TARGET");
    if is_image_invocation(&args, &rustc, host.as_deref(), cargo_target.as_deref())? {
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
        check_arch_dependencies(&args, &package, manifest_dir.as_deref(), &ostd)?;
        let exception = exemption(
            &package,
            &version,
            manifest_dir.as_deref(),
            &workspace,
            &ostd,
            &base,
        );

        // A matching package name/version is not a reviewed source identity.
        // Verify bytes before rustc can compile any exempt target source.
        let external_identity = exception
            .filter(|entry| entry.origin == Origin::External)
            .map(|_| {
                super::external_sources::verify(
                    &package,
                    &version,
                    manifest_dir.as_deref().ok_or_else(|| {
                        io::Error::other("external package has no source directory")
                    })?,
                )
            })
            .transpose()?;
        if exception.is_some_and(|entry| entry.origin == Origin::Toolchain) {
            let output = Command::new(&rustc).args(["--print", "sysroot"]).output()?;
            if !output.status.success() {
                return Err(io::Error::other("cannot resolve audited rustc sysroot"));
            }
            let sysroot = fs::canonicalize(
                String::from_utf8(output.stdout)
                    .map_err(io::Error::other)?
                    .trim(),
            )?;
            verify_toolchain_source(&package, manifest_dir.as_deref(), &sysroot)?;
        }

        if exception.is_none() {
            prepare_unsafe_forbid(&mut args)?;
        }

        let status = Command::new(rustc).args(&args).status()?;
        if status.success()
            && let Some(exception) = exception
        {
            record_exemption(
                &package,
                &version,
                manifest_dir.as_deref(),
                exception,
                external_identity,
            )?;
        }
        return Ok(status);
    }

    Command::new(rustc).args(&args).status()
}

/// Cargo omits `--target` for host build scripts and proc macros, but their
/// feature probes may explicitly select the compiler's host triple. Require
/// Cargo's `HOST` and `TARGET` to match that selected rustc identity; other
/// triples and JSON targets must not silently receive host audit privileges.
fn is_image_invocation(
    args: &[OsString],
    rustc: &OsStr,
    host: Option<&OsStr>,
    cargo_target: Option<&OsStr>,
) -> io::Result<bool> {
    let mut target = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        // Rust expands response files before parsing options. Cargo's supported
        // Linux invocation uses direct arguments; do not let a file hide target
        // options or lint caps from this wrapper.
        if arg.as_encoded_bytes().starts_with(b"@") {
            return Err(io::Error::other(
                "rustc response files are outside the Image audit contract",
            ));
        }
        let value = if arg == "--target" {
            Some(
                args.next()
                    .ok_or_else(|| io::Error::other("missing rustc target argument"))?
                    .to_str()
                    .ok_or_else(|| io::Error::other("rustc target is not UTF-8"))?,
            )
        } else if arg.as_encoded_bytes().starts_with(b"--target=") {
            Some(
                arg.to_str()
                    .ok_or_else(|| io::Error::other("rustc target is not UTF-8"))?
                    .strip_prefix("--target=")
                    .unwrap(),
            )
        } else {
            None
        };
        if let Some(value) = value {
            if value.is_empty() || target.replace(value).is_some() {
                return Err(io::Error::other("empty or repeated rustc target argument"));
            }
        }
    }
    match target {
        None => Ok(false),
        Some(TARGET) => Ok(true),
        Some(target) => {
            let compiler = rustc_version::VersionMeta::for_command(Command::new(rustc))
                .map_err(io::Error::other)?;
            if target == compiler.host
                && host == Some(OsStr::new(&compiler.host))
                && cargo_target == host
            {
                Ok(false)
            } else {
                Err(io::Error::other(format!(
                    "unsupported Image rustc target: {target}"
                )))
            }
        }
    }
}

fn verify_toolchain_source(
    package: &str,
    directory: Option<&Path>,
    sysroot: &Path,
) -> io::Result<()> {
    let relative = match package {
        "core" => "core",
        "alloc" => "alloc",
        "compiler_builtins" => "compiler-builtins/compiler-builtins",
        _ => return Err(io::Error::other("unreviewed toolchain package")),
    };
    let expected = fs::canonicalize(sysroot.join("lib/rustlib/src/rust/library").join(relative))?;
    if directory != Some(expected.as_path()) {
        return Err(io::Error::other(format!(
            "{package} must use the audited rustc sysroot source {}",
            expected.display()
        )));
    }
    Ok(())
}

/// The architecture crates contain safe APIs that execute physical privileged
/// instructions. Only the reviewed OSTD crate may import them into an Image;
/// kernel proper uses OSTD's restricted types and virtual operations instead.
/// Inspect both Cargo's extern name and the actual rlib name to cover renamed
/// dependencies. Cargo feature unification makes disabling defaults in one
/// consumer insufficient.
fn check_arch_dependencies(
    args: &[OsString],
    package: &str,
    manifest_dir: Option<&Path>,
    ostd: &Path,
) -> io::Result<()> {
    if package == "ostd" && manifest_dir == Some(ostd) {
        return Ok(());
    }
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let arg = arg.to_str().unwrap_or_default();
        let external = if arg == "--extern" {
            args.next().and_then(|value| value.to_str())
        } else {
            arg.strip_prefix("--extern=")
        };
        let Some(external) = external else { continue };
        let (name, path) = external.split_once('=').unwrap_or((external, ""));
        let filename = Path::new(path)
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default();
        if matches!(name, "x86" | "x86_64")
            || ["libx86-", "libx86_64-"]
                .iter()
                .any(|prefix| filename.starts_with(prefix))
        {
            return Err(io::Error::other(format!(
                "{package} imports physical architecture dependency {external}; only the reviewed OSTD crate may import x86/x86_64 in an Image"
            )));
        }
    }
    Ok(())
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

/// Establishes the unsafe prohibition for a non-exempt Image crate.
fn prepare_unsafe_forbid(args: &mut Vec<OsString>) -> io::Result<()> {
    // force-warn overrides forbid regardless of argument order. Reject this
    // option explicitly rather than reimplement rustc's lint groups/aliases or
    // silently changing a requested diagnostic level.
    if args
        .iter()
        .any(|arg| arg == "--force-warn" || arg.as_encoded_bytes().starts_with(b"--force-warn="))
    {
        return Err(io::Error::other(
            "force-warn is not supported for a non-exempt Image crate",
        ));
    }
    // Cargo's dependency cap also overrides forbid; the existing Image policy
    // deliberately removes that cap before installing the unsafe prohibition.
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
    args.push("-F".into());
    args.push("unsafe_code".into());
    Ok(())
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
                Origin::VendoredUnwinder => {
                    manifest_dir.is_some_and(|path| path == ostd.join("libs/unwinding"))
                }
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
    #[serde(default)]
    reviewed_source: Option<String>,
    #[serde(default)]
    archive_sha256: Option<String>,
    #[serde(default)]
    source_tree_sha256: Option<String>,
}

fn record_exemption(
    package: &str,
    version: &str,
    manifest_dir: Option<&Path>,
    exception: &Exception,
    external_identity: Option<&super::external_sources::Identity>,
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
        reviewed_source: external_identity.map(|identity| identity.source.to_string()),
        archive_sha256: external_identity
            .and_then(|identity| identity.archive_sha256.map(str::to_string)),
        source_tree_sha256: external_identity.map(|identity| identity.tree_sha256.to_string()),
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
    cargo_home: Option<&Path>,
) -> io::Result<()> {
    let current_packages = image_dependency_closure(base_crate, features, toolchain, cargo_home)?;
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
        if EXCEPTIONS.iter().any(|exception| {
            exception.origin == Origin::External
                && exception.package == entry.package
                && exception.version == Some(entry.version.as_str())
        }) {
            let identity = super::external_sources::verify(
                &entry.package,
                &entry.version,
                Path::new(&entry.manifest_dir),
            )?;
            if entry.source_tree_sha256.as_deref() != Some(identity.tree_sha256)
                || entry.reviewed_source.as_deref() != Some(identity.source)
            {
                return Err(io::Error::other(
                    "cached unsafe exemption lacks the current reviewed source identity",
                ));
            }
        }
        eprintln!("  {} {}: {}", entry.package, entry.version, entry.reason);
        if let Some(identity) = entry.source_tree_sha256 {
            eprintln!(
                "    reviewed source: {}; package tree sha256: {identity}",
                entry.reviewed_source.as_deref().unwrap_or("unavailable")
            );
        }
    }
    Ok(())
}

fn image_dependency_closure(
    base_crate: &Path,
    features: &[String],
    toolchain: Option<&OsStr>,
    cargo_home: Option<&Path>,
) -> io::Result<HashSet<(String, String, String)>> {
    let mut command = Command::new("cargo");
    if let Some(home) = cargo_home {
        command
            .env("CARGO_HOME", home)
            .env("CARGO_NET_OFFLINE", "true");
    }
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
    fn only_the_supported_explicit_target_gets_image_audit_privileges() {
        for args in [
            vec!["--target", TARGET],
            vec!["--target=x86_64-unknown-none"],
        ] {
            let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
            assert!(is_image_invocation(&args, OsStr::new("rustc"), None, None).unwrap());
        }
        for args in [
            vec!["--crate-name", "build_script_build"],
            vec!["--crate-type=proc-macro"],
            vec!["-vV"],
        ] {
            let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
            assert!(!is_image_invocation(&args, OsStr::new("rustc"), None, None).unwrap());
        }
        for args in [
            vec!["--target", "/tmp/target.json"],
            vec!["--target=/tmp/target.json"],
            vec!["--target=aarch64-unknown-none"],
            vec!["--target"],
            vec!["--target="],
            vec![
                "--target=x86_64-unknown-none",
                "--target=x86_64-unknown-none",
            ],
            vec!["@arguments.rsp"],
        ] {
            let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
            assert!(is_image_invocation(&args, OsStr::new("rustc"), None, None).is_err());
        }
    }

    #[test]
    fn explicit_host_probes_require_compiler_and_cargo_host_identity() {
        let rustc = OsStr::new("rustc");
        let compiler = rustc_version::VersionMeta::for_command(Command::new(rustc)).unwrap();
        assert_ne!(compiler.host, TARGET);
        let host = Some(OsStr::new(&compiler.host));
        for args in [
            vec![OsString::from("--target"), OsString::from(&compiler.host)],
            vec![OsString::from(format!("--target={}", compiler.host))],
        ] {
            assert!(!is_image_invocation(&args, rustc, host, host).unwrap());
            for (cargo_host, cargo_target) in [
                (None, None),
                (host, None),
                (None, host),
                (host, Some(OsStr::new(TARGET))),
                (Some(OsStr::new(TARGET)), host),
            ] {
                assert!(is_image_invocation(&args, rustc, cargo_host, cargo_target).is_err());
            }
            assert!(is_image_invocation(&args, OsStr::new("/no/such/rustc"), host, host).is_err());
        }
        for args in [
            vec![
                OsString::from("--target"),
                OsString::from(&compiler.host),
                OsString::from("--target"),
                OsString::from(TARGET),
            ],
            vec![
                OsString::from(format!("--target={}", compiler.host)),
                OsString::from("@probe.rsp"),
            ],
        ] {
            assert!(is_image_invocation(&args, rustc, host, host).is_err());
        }
        let unknown_host = Some(OsStr::new("aarch64-unknown-linux-gnu"));
        let args = [OsString::from("--target=aarch64-unknown-linux-gnu")];
        assert!(is_image_invocation(&args, rustc, unknown_host, unknown_host).is_err());
    }

    #[test]
    fn non_utf8_target_cannot_be_misclassified_as_host() {
        use std::os::unix::ffi::OsStringExt;
        for args in [
            vec!["--target".into(), OsString::from_vec(vec![0xff])],
            vec![OsString::from_vec(b"--target=\xff".to_vec())],
        ] {
            assert!(is_image_invocation(&args, OsStr::new("rustc"), None, None).is_err());
        }
    }

    #[test]
    fn physical_architecture_dependencies_are_ostd_only_even_when_renamed() {
        for external in [
            "x86_64=/cargo/libx86_64-deadbeef.rlib",
            "arch=/cargo/libx86_64-deadbeef.rmeta",
            "physical=/cargo/libx86-deadbeef.rlib",
        ] {
            for arguments in [
                vec!["--extern".into(), external.into()],
                vec![format!("--extern={external}").into()],
            ] {
                let ostd = Path::new("/tree/ostd");
                assert!(
                    check_arch_dependencies(
                        &arguments,
                        "aster-core",
                        Some(Path::new("/tree/kernel/core")),
                        ostd
                    )
                    .is_err()
                );
                assert!(
                    check_arch_dependencies(
                        &arguments,
                        "third-party",
                        Some(Path::new("/cargo/third-party")),
                        ostd
                    )
                    .is_err()
                );
                assert!(
                    check_arch_dependencies(
                        &arguments,
                        "ostd",
                        Some(Path::new("/tree/kernel/ostd")),
                        ostd
                    )
                    .is_err()
                );
                assert!(check_arch_dependencies(&arguments, "ostd", Some(ostd), ostd).is_ok());
            }
        }
    }

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
        prepare_unsafe_forbid(&mut args).unwrap();
        assert_eq!(
            args,
            vec![
                OsString::from("--crate-name"),
                OsString::from("kernel"),
                OsString::from("-F"),
                OsString::from("unsafe_code")
            ]
        );
    }

    #[test]
    fn force_warn_cannot_override_the_image_unsafe_prohibition() {
        for args in [
            vec!["--force-warn", "unsafe_code"],
            vec!["--force-warn=unsafe-code"],
            vec!["--force-warn", "warnings"],
        ] {
            let mut args: Vec<OsString> = args.into_iter().map(Into::into).collect();
            assert!(prepare_unsafe_forbid(&mut args).is_err());
        }
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
                "allocator-api2",
                "0.2.21",
                Some(Path::new("/cargo/allocator-api2")),
                workspace,
                ostd,
                base
            )
            .is_some()
        );
        assert!(
            exemption(
                "allocator-api2",
                "0.2.22",
                Some(Path::new("/cargo/allocator-api2")),
                workspace,
                ostd,
                base
            )
            .is_none()
        );
    }

    #[test]
    fn toolchain_package_name_does_not_exempt_an_external_path() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("lib/rustlib/src/rust/library/core");
        fs::create_dir_all(&source).unwrap();
        assert!(verify_toolchain_source("core", Some(&source), root.path()).is_ok());
        assert!(
            verify_toolchain_source("core", Some(Path::new("/outside/core")), root.path()).is_err()
        );
        assert!(verify_toolchain_source("core", None, root.path()).is_err());
    }

    #[test]
    fn vendored_unwinder_requires_reviewed_version_and_exact_ostd_path() {
        let workspace = Path::new("/tree");
        let ostd = Path::new("/tree/ostd");
        let base = Path::new("/tree/target/osdk/base");
        for (version, path, accepted) in [
            ("0.2.10", "/tree/ostd/libs/unwinding", true),
            ("0.2.11", "/tree/ostd/libs/unwinding", false),
            ("0.2.10", "/tree/ostd/unrelated/unwinding", false),
            ("0.2.10", "/cargo/unwinding", false),
            ("0.2.10", "/tree/kernel/unwinding", false),
        ] {
            assert_eq!(
                exemption(
                    "unwinding",
                    version,
                    Some(Path::new(path)),
                    workspace,
                    ostd,
                    base
                )
                .is_some(),
                accepted,
                "version {version}, path {path}"
            );
        }
    }
}
