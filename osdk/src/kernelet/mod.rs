// SPDX-License-Identifier: MPL-2.0

//! Building and auditing the kernelet image.
//!
//! When the OSDK manifest turns the `kernelet` build option on, one OSDK
//! invocation builds the kernelet image first — from the same kernel and OSTD
//! sources as the host image, but as a separate Cargo build with
//! `--no-default-features --features kernelet`, position-independent, and
//! linked by a generated kernelet linker script — audits it, and then builds
//! the host image with `KERNELET_IMAGE_PATH` pointing at the audited
//! artifact. The image format and the build contract are documented in
//! `kernelet/ABI.md`.

pub(crate) mod abi;
pub(crate) mod audit;
mod elf;
mod host_audit;
pub(crate) mod rustc_wrapper;
mod unsafe_allowlist;

use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process,
};

pub(crate) use host_audit::audit_host_services;
use sha2::{Digest, Sha256};

use crate::{
    arch::Arch,
    base_crate::{BaseCrateType, kernelet_package_name, new_base_crate},
    commands::util::{COMMON_CARGO_ARGS, cargo, profile_name_adapter},
    config::Config,
    error::Errno,
    error_msg,
    util::{CrateInfo, DirGuard, get_cargo_metadata},
};

/// The environment variable through which OSDK hands the audited kernelet
/// image's path to the host image's build.
pub(crate) const KERNELET_IMAGE_ENV: &str = "KERNELET_IMAGE_PATH";
const KERNELET_SOURCE_HASH_ENV: &str = "KERNELET_SOURCE_HASH";

/// The audited image and the independent hash expected by the Host build.
pub(crate) struct KerneletImage {
    path: PathBuf,
    source_hash: [u8; 32],
    toolchain: Option<OsString>,
}

struct GuestBuildContext<'a> {
    workspace_root: &'a Path,
    ostd_directory: &'a Path,
    base_crate_path: &'a Path,
    exemption_log: &'a Path,
    toolchain: Option<&'a std::ffi::OsStr>,
}

impl KerneletImage {
    /// Supplies both build-time values consumed by the Host control half.
    pub(crate) fn host_envs(&self) -> Vec<(String, OsString)> {
        let hash = hex_encode(&self.source_hash);
        let mut envs = vec![
            (
                KERNELET_IMAGE_ENV.to_string(),
                self.path.as_os_str().to_os_string(),
            ),
            (KERNELET_SOURCE_HASH_ENV.to_string(), hash.into()),
        ];
        if let Some(toolchain) = &self.toolchain {
            envs.push(("RUSTUP_TOOLCHAIN".to_string(), toolchain.clone()));
        }
        envs
    }
}

/// Builds the kernelet image if the manifest asks for it, and returns the
/// absolute path of the audited artifact.
pub(crate) fn build_image_if_requested(
    config: &Config,
    target_crate: &CrateInfo,
    osdk_output_directory: &Path,
    cargo_target_directory: &Path,
) -> Option<KerneletImage> {
    if !config.build.kernelet {
        return None;
    }
    Some(build_kernelet_image(
        config,
        target_crate,
        osdk_output_directory,
        cargo_target_directory,
    ))
}

/// Builds one kernelet image from the same kernel crate the host image is
/// built from, audits it, and returns the absolute path of the artifact.
fn build_kernelet_image(
    config: &Config,
    target_crate: &CrateInfo,
    osdk_output_directory: &Path,
    cargo_target_directory: &Path,
) -> KerneletImage {
    if config.target_arch != Arch::X86_64 {
        error_msg!("The `kernelet` build option currently supports only the x86-64 architecture");
        process::exit(Errno::Cli as _);
    }

    let ostd_directory = ostd_source_directory(target_crate);
    let source_hash = compute_source_hash(&ostd_directory);
    // The generated base crate may live outside the source tree. Preserve the
    // toolchain selected here before changing Cargo's working directory.
    let toolchain = active_rustup_toolchain();

    let base_crate_path = new_base_crate(
        BaseCrateType::Kernelet { source_hash },
        osdk_output_directory.join(&target_crate.name),
        &target_crate.name,
        &target_crate.path,
        false,
    );

    let workspace_root = get_cargo_metadata(Some(&target_crate.path), None::<&[&str]>)
        .and_then(|metadata| metadata["workspace_root"].as_str().map(PathBuf::from))
        .expect("Cargo metadata supplies the kernel workspace root");
    let audited_target_directory = audited_target_directory(cargo_target_directory);
    fs::create_dir_all(&audited_target_directory)
        .expect("the audited target directory is writable");
    let exemption_log = audited_target_directory.join("unsafe-exemptions.jsonl");

    let guest_build = GuestBuildContext {
        workspace_root: &workspace_root,
        ostd_directory: &ostd_directory,
        base_crate_path: &base_crate_path,
        exemption_log: &exemption_log,
        toolchain: toolchain.as_deref(),
    };
    let _dir_guard = DirGuard::change_dir(&base_crate_path);
    let linked_elf_path = build_kernelet_elf(
        config,
        &target_crate.name,
        &audited_target_directory,
        &guest_build,
    );
    let features = ["kernelet".to_string()];
    rustc_wrapper::print_exemptions(
        &exemption_log,
        &base_crate_path,
        &features,
        toolchain.as_deref(),
    )
    .expect("the kernelet rustc audit log is readable");

    let elf_path = audited_target_directory.join("kernelet-image.elf");
    let bytes = fs::read(&linked_elf_path).unwrap();
    fs::write(&elf_path, &bytes).unwrap();
    info!("Auditing the kernelet image at {:?}", elf_path);
    if let Err(violations) = audit::audit_kernelet_image(&bytes, &source_hash) {
        error_msg!("The kernelet image failed the artifact audit:");
        for violation in &violations {
            eprintln!("  - {violation}");
        }
        process::exit(Errno::BuildCrate as _);
    }

    KerneletImage {
        path: elf_path
            .canonicalize()
            .expect("the built kernelet image exists"),
        source_hash,
        toolchain,
    }
}

/// Builds the kernelet ELF with the flags the book fixes: position-independent,
/// small code model, the generated kernelet linker script, and no unresolved
/// symbol.
fn build_kernelet_elf(
    config: &Config,
    kernel_crate_name: &str,
    cargo_target_directory: &Path,
    build: &GuestBuildContext<'_>,
) -> PathBuf {
    const RUSTFLAGS: &[&str] = &[
        "-C link-arg=-Tx86_64-kernelet.ld",
        "-C relocation-model=pic",
        "-C code-model=small",
        "-C relro-level=off",
        "-C force-unwind-tables=yes",
        "-C panic=unwind",
        "-C no-redzone=y",
        "-C target-feature=+ermsb",
        "-C link-arg=--no-undefined",
        "-Z default-visibility=hidden",
        "-Z cf-protection=branch",
        // This is to let rustc know that "cfg(ktest)" is our well-known
        // configuration.
        "--check-cfg cfg(ktest)",
    ];

    let mut command = cargo();
    command.env("RUSTFLAGS", RUSTFLAGS.join(" "));
    command.env("RUSTC_WRAPPER", std::env::current_exe().unwrap());
    command.env(rustc_wrapper::MODE_ENV, "1");
    command.env(rustc_wrapper::WORKSPACE_ENV, build.workspace_root);
    command.env(rustc_wrapper::OSTD_ENV, build.ostd_directory);
    command.env(rustc_wrapper::BASE_ENV, build.base_crate_path);
    command.env(rustc_wrapper::LOG_ENV, build.exemption_log);
    if let Some(toolchain) = build.toolchain {
        command.env("RUSTUP_TOOLCHAIN", toolchain);
    }
    command.arg("build");
    command.arg("--features").arg("kernelet");
    // The kernelet build is always invoked without the default features, which
    // is how `cvm_guest` and the host-only components stay off.
    command.arg("--no-default-features");
    command.arg("--target").arg(Arch::X86_64.triple());
    command
        .arg("--target-dir")
        .arg(cargo_target_directory.as_os_str());
    command.args(COMMON_CARGO_ARGS);
    command.arg("--profile=".to_string() + &config.build.profile);
    for override_config in &config.build.override_configs {
        command.arg("--config").arg(override_config);
    }
    // C code linked into the image must be position-independent too.
    command.env("CFLAGS_x86_64-unknown-none", "-fPIC -fcf-protection=branch");

    info!("Building the kernelet image using command: {:#?}", command);
    let status = command.status().unwrap();
    if !status.success() {
        error_msg!("Cargo build of the kernelet image failed");
        process::exit(Errno::ExecuteCommand as _);
    }

    cargo_target_directory
        .join(Arch::X86_64.triple())
        .join(profile_name_adapter(&config.build.profile))
        .join(kernelet_package_name(kernel_crate_name))
}

fn active_rustup_toolchain() -> Option<OsString> {
    if let Some(toolchain) = std::env::var_os("RUSTUP_TOOLCHAIN") {
        return Some(toolchain);
    }
    let output = process::Command::new("rustup")
        .args(["show", "active-toolchain"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()?
        .split_whitespace()
        .next()
        .map(OsString::from)
}

/// Isolates audited artifacts from any pre-audit Cargo cache. A change to the
/// build policy, wrapper, or reviewed allowlist selects a fresh cache and
/// recompiles the full target closure under the new policy.
fn audited_target_directory(cargo_target_directory: &Path) -> PathBuf {
    let compiler = process::Command::new("rustc")
        .arg("-vV")
        .output()
        .expect("rustc is available for the kernelet build");
    assert!(compiler.status.success(), "rustc -vV failed");
    let digest = sha256(&[
        include_bytes!("mod.rs"),
        include_bytes!("rustc_wrapper.rs"),
        include_bytes!("unsafe_allowlist.rs"),
        &compiler.stdout,
    ]);
    let fingerprint = hex_encode(&digest[..8]);
    cargo_target_directory.join(format!("kernelet-unsafe-audit-{fingerprint}"))
}

/// Returns the directory of the OSTD crate that the target kernel crate
/// depends on, found through Cargo's metadata.
fn ostd_source_directory(target_crate: &CrateInfo) -> PathBuf {
    let metadata = get_cargo_metadata(Some(&target_crate.path), None::<&[&str]>).unwrap();
    let packages = metadata.get("packages").unwrap().as_array().unwrap();
    let ostd = packages
        .iter()
        .find(|package| package.get("name").and_then(|name| name.as_str()) == Some("ostd"))
        .unwrap_or_else(|| {
            error_msg!("Cannot find the `ostd` package in the Cargo metadata");
            process::exit(Errno::GetMetadata as _);
        });
    let manifest_path = PathBuf::from(
        ostd.get("manifest_path")
            .and_then(|path| path.as_str())
            .expect("the package metadata contains the manifest path"),
    );
    manifest_path
        .parent()
        .expect("the manifest path has a parent directory")
        .to_path_buf()
}

/// Computes the SHA-256 digest of the concatenation of `parts`.
fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&hasher.finalize());
    digest
}

/// Formats bytes as lowercase hexadecimal.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push(char::from(HEX[(byte >> 4) as usize]));
        hex.push(char::from(HEX[(byte & 0xf) as usize]));
    }
    hex
}

/// Computes the source hash shared by the generated linker script and the
/// artifact audit: the SHA-256 of the OSTD source tree and the toolchain
/// version.
fn compute_source_hash(ostd_directory: &Path) -> [u8; 32] {
    let rustc_version = rustc_version::version()
        .map(|version| format!("rustc {version}"))
        .unwrap_or_else(|_| "rustc unknown".to_string());

    let mut files = vec![
        ostd_directory.join("Cargo.toml"),
        ostd_directory.join("build.rs"),
    ];
    collect_files(&mut files, &ostd_directory.join("src"));
    files.sort();
    files.dedup();

    let mut parts: Vec<Vec<u8>> = vec![rustc_version.into_bytes()];
    for file in &files {
        let Ok(content) = fs::read(file) else {
            continue;
        };
        let relative = file.strip_prefix(ostd_directory).unwrap_or(file);
        parts.push(relative.to_string_lossy().into_owned().into_bytes());
        parts.push(vec![0]);
        parts.push((content.len() as u64).to_le_bytes().to_vec());
        parts.push(content);
    }
    let references: Vec<&[u8]> = parts.iter().map(|part| part.as_slice()).collect();
    sha256(&references)
}

/// Collects all files under `directory` into `files`, recursing into
/// subdirectories. A missing or unreadable directory contributes nothing.
fn collect_files(files: &mut Vec<PathBuf>, directory: &Path) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(files, &path);
        } else {
            files.push(path);
        }
    }
}
