// SPDX-License-Identifier: MPL-2.0

//! Private build inputs shared by both halves of a paired build.
//!
//! This protects builds against concurrent edits to the user's checkout and
//! Cargo source cache. It is not a sandbox for hostile build scripts or tools.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

use sha2::{Digest, Sha256};

use crate::util::{CrateInfo, get_cargo_metadata};

pub(crate) struct BuildSnapshot {
    root: PathBuf,
    workspace: PathBuf,
    target: CrateInfo,
}

impl BuildSnapshot {
    pub(crate) fn capture(
        target: &CrateInfo,
        output: &Path,
        build_output: Option<&Path>,
        overrides: &[String],
        features: &[String],
        no_default_features: bool,
    ) -> io::Result<Self> {
        let selected = metadata(
            Path::new(&target.path),
            overrides,
            features,
            no_default_features,
        )?;
        // component-macro executes plain `cargo metadata` while rustc expands
        // the kernel. That query enables default features even when both actual
        // compilers use --no-default-features. Freeze its real dependency inputs
        // too, instead of letting the macro consult the live Cargo source cache.
        let default_query = metadata(Path::new(&target.path), &[], &[], false)?;
        let mut packages_by_id = BTreeMap::new();
        for graph in [&selected, &default_query] {
            for package in graph["packages"]
                .as_array()
                .ok_or_else(|| io::Error::other("Cargo metadata has no package list"))?
            {
                let id = package["id"]
                    .as_str()
                    .ok_or_else(|| io::Error::other("Cargo package has no id"))?;
                packages_by_id.insert(id.to_owned(), package.clone());
            }
        }
        let mut metadata = selected;
        metadata["packages"] = serde_json::Value::Array(packages_by_id.into_values().collect());
        let workspace = PathBuf::from(
            metadata["workspace_root"]
                .as_str()
                .ok_or_else(|| io::Error::other("Cargo metadata has no workspace root"))?,
        );
        let original_home = std::env::var_os("CARGO_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
            .ok_or_else(|| io::Error::other("cannot locate Cargo's source cache"))?
            .canonicalize()?;
        let cache = output.join("osdk-inputs");
        fs::create_dir_all(&cache)?;
        let temporary = tempfile::Builder::new()
            .prefix("capture-")
            .tempdir_in(&cache)?;
        let root = temporary.path();
        let mut local_roots = BTreeSet::from([workspace.clone()]);
        let packages = metadata["packages"]
            .as_array()
            .ok_or_else(|| io::Error::other("Cargo metadata has no package list"))?;
        for package in packages {
            if !package["source"].is_null() {
                continue;
            }
            let manifest = Path::new(
                package["manifest_path"]
                    .as_str()
                    .ok_or_else(|| io::Error::other("Cargo package has no manifest"))?,
            );
            if !manifest.starts_with(&workspace) {
                let other = get_cargo_metadata(manifest.parent(), None::<&[&str]>)
                    .ok_or_else(|| io::Error::other("cannot resolve external path workspace"))?;
                local_roots.insert(PathBuf::from(other["workspace_root"].as_str().ok_or_else(
                    || io::Error::other("external path dependency has no workspace root"),
                )?));
            }
        }
        // Preserve relative paths between workspaces, including ../ dependencies.
        // Never retain a live symlink back into the original checkout.
        for source in &local_roots {
            copy_workspace(source, &mapped(root, source), &cache, build_output)?;
        }
        let home = root.join("cargo-home");
        for part in ["registry/index", "git"] {
            copy_if_exists(&original_home.join(part), &home.join(part))?;
        }
        for package in packages {
            if package["source"].is_null() {
                continue;
            }
            let manifest = Path::new(
                package["manifest_path"]
                    .as_str()
                    .ok_or_else(|| io::Error::other("Cargo dependency has no manifest"))?,
            );
            let directory = manifest.parent().unwrap();
            let relative = directory.strip_prefix(&original_home).map_err(|_| {
                io::Error::other(format!(
                    "dependency source outside Cargo home: {}",
                    directory.display()
                ))
            })?;
            copy_tree(directory, &home.join(relative), directory)?;
            if relative.starts_with("registry/src") {
                let registry = relative.components().nth(2).unwrap().as_os_str();
                let archive = format!("{}.crate", directory.file_name().unwrap().to_string_lossy());
                let archive = Path::new("registry/cache").join(registry).join(archive);
                copy_if_exists(&original_home.join(&archive), &home.join(archive))?;
            }
        }
        // build-std resolves an additional closure from the pinned sysroot. Its
        // lockfile identifies the small set of registry packages it needs.
        let compiler = Command::new("rustc")
            .args(["--print", "sysroot"])
            .output()?;
        if !compiler.status.success() {
            return Err(io::Error::other("rustc cannot identify its sysroot"));
        }
        let sysroot = PathBuf::from(
            String::from_utf8(compiler.stdout)
                .map_err(io::Error::other)?
                .trim(),
        );
        if let Ok(lock) =
            fs::read_to_string(sysroot.join("lib/rustlib/src/rust/library/Cargo.lock"))
        {
            let lock: toml::Value = toml::from_str(&lock).map_err(io::Error::other)?;
            if let Some(packages) = lock["package"].as_array() {
                for package in packages {
                    let (Some(name), Some(version)) =
                        (package["name"].as_str(), package["version"].as_str())
                    else {
                        continue;
                    };
                    let registry = original_home.join("registry");
                    for entry in fs::read_dir(registry.join("src"))? {
                        let entry = entry?;
                        let name_version = format!("{name}-{version}");
                        copy_if_exists(
                            &entry.path().join(&name_version),
                            &home
                                .join("registry/src")
                                .join(entry.file_name())
                                .join(&name_version),
                        )?;
                        let archive = Path::new("registry/cache")
                            .join(entry.file_name())
                            .join(format!("{name_version}.crate"));
                        copy_if_exists(&original_home.join(&archive), &home.join(archive))?;
                    }
                }
            }
        }
        // Source replacement settings must be explicit: silently inheriting a
        // live vendor directory would undo the dependency snapshot.
        for file in ["config", "config.toml"] {
            if original_home.join(file).exists() {
                let config: toml::Value =
                    toml::from_str(&fs::read_to_string(original_home.join(file))?)
                        .map_err(io::Error::other)?;
                if config.get("source").is_some() || config.get("patch").is_some() {
                    return Err(io::Error::other(
                        "paired builds require source/patch settings in workspace manifests, not Cargo-home config",
                    ));
                }
                fs::write(
                    home.join(file),
                    toml::to_string(&config).map_err(io::Error::other)?,
                )?;
            }
        }
        let fingerprint = fingerprint(root)?;
        let destination = cache.join(fingerprint);
        if !destination.exists() {
            // Rewrite only absolute local dependency paths. Relative paths keep
            // their layout in fs/<original absolute path>.
            rewrite_manifests(root, root, &destination, &local_roots)?;
            fs::write(root.join("frozen-source.sha256"), source_fingerprint(root)?)?;
            fs::rename(root, &destination)?;
        }
        verify_sources(&destination)?;
        // Cargo's bookkeeping stays writable; all source directories are private
        // copies, and source files are read-only. No hard links to live inputs.
        make_readonly_files(&destination.join("fs"))?;
        make_readonly_files(&destination.join("cargo-home/registry/src"))?;
        make_readonly_files(&destination.join("cargo-home/registry/cache"))?;
        make_readonly_files(&destination.join("cargo-home/git/checkouts"))?;
        let mut frozen_target = target.clone();
        frozen_target.path = mapped(&destination, Path::new(&target.path))
            .to_string_lossy()
            .into_owned();
        Ok(Self {
            workspace: mapped(&destination, &workspace),
            root: destination,
            target: frozen_target,
        })
    }

    pub(crate) fn target(&self) -> &CrateInfo {
        &self.target
    }
    pub(crate) fn workspace(&self) -> &Path {
        &self.workspace
    }
    pub(crate) fn cargo_home(&self) -> PathBuf {
        self.root.join("cargo-home")
    }
}

fn metadata(
    path: &Path,
    overrides: &[String],
    features: &[String],
    no_default_features: bool,
) -> io::Result<serde_json::Value> {
    let mut command = Command::new("cargo");
    command
        .current_dir(path)
        .args(["metadata", "--format-version=1", "--locked"]);
    if !features.is_empty() {
        command.arg("--features").arg(features.join(" "));
    }
    if no_default_features {
        command.arg("--no-default-features");
    }
    for config in overrides {
        command.arg("--config").arg(config);
    }
    let output = command.output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "resolve paired build inputs: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    serde_json::from_slice(&output.stdout).map_err(io::Error::other)
}

fn mapped(root: &Path, source: &Path) -> PathBuf {
    root.join("fs")
        .join(source.strip_prefix("/").expect("Cargo paths are absolute"))
}

fn copy_workspace(
    source: &Path,
    destination: &Path,
    cache: &Path,
    build_output: Option<&Path>,
) -> io::Result<()> {
    let git = Command::new("git")
        .current_dir(source)
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            ".",
        ])
        .output()?;
    if !git.status.success() {
        return copy_tree(source, destination, source);
    }
    use std::os::unix::ffi::OsStrExt;
    for relative in git
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        let relative = Path::new(std::ffi::OsStr::from_bytes(relative));
        if excluded(relative)
            || source.join(relative).starts_with(cache)
            || build_output.is_some_and(|output| source.join(relative).starts_with(output))
        {
            continue;
        }
        let input = source.join(relative);
        if input.exists() {
            copy_tree(&input, &destination.join(relative), source)?;
        }
    }
    Ok(())
}

fn excluded(relative: &Path) -> bool {
    relative.components().any(|part| {
        matches!(
            part.as_os_str().to_str(),
            Some(".git" | "target" | ".scratch" | "osdk-inputs")
        )
    })
}

fn copy_if_exists(source: &Path, destination: &Path) -> io::Result<()> {
    if source.exists() {
        copy_tree(source, destination, source)?;
    }
    Ok(())
}

fn copy_tree(source: &Path, destination: &Path, boundary: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() {
        let target = source.canonicalize()?;
        if !target.starts_with(boundary.canonicalize()?) {
            return Err(io::Error::other(format!(
                "source symlink escapes its input tree: {}",
                source.display()
            )));
        }
        // Resolve the symlink into an independent file/directory copy.
        return copy_tree(&target, destination, boundary);
    }
    if metadata.is_dir() {
        fs::create_dir_all(destination)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            if matches!(
                entry.file_name().to_str(),
                Some("target" | ".scratch" | "osdk-inputs")
            ) {
                continue;
            }
            copy_tree(
                &entry.path(),
                &destination.join(entry.file_name()),
                boundary,
            )?;
        }
    } else if metadata.is_file() {
        fs::create_dir_all(destination.parent().unwrap())?;
        fs::copy(source, destination)?;
    } else {
        return Err(io::Error::other(
            "source input is not a regular file or directory",
        ));
    }
    Ok(())
}

fn fingerprint(root: &Path) -> io::Result<String> {
    fn visit(root: &Path, directory: &Path, digest: &mut Sha256) -> io::Result<()> {
        let mut entries = fs::read_dir(directory)?.collect::<io::Result<Vec<_>>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            if matches!(entry.file_name().to_str(), Some(".cargo-ok" | ".git")) {
                continue;
            }
            if path.is_dir() {
                visit(root, &path, digest)?;
            } else {
                let content = fs::read(&path)?;
                digest.update(
                    path.strip_prefix(root)
                        .unwrap()
                        .as_os_str()
                        .as_encoded_bytes(),
                );
                digest.update([0]);
                digest.update((content.len() as u64).to_le_bytes());
                digest.update(content);
            }
        }
        Ok(())
    }
    let mut digest = Sha256::new();
    visit(root, root, &mut digest)?;
    Ok(super::hex_encode(&digest.finalize()))
}

fn source_fingerprint(root: &Path) -> io::Result<String> {
    // Cargo may update its index and lock bookkeeping. Those are not compiled
    // sources; validate the complete local/registry/git checkout source trees.
    let mut digest = Sha256::new();
    for relative in ["fs", "cargo-home/registry/src", "cargo-home/git/checkouts"] {
        let directory = root.join(relative);
        if directory.exists() {
            digest.update(fingerprint(&directory)?.as_bytes());
        }
    }
    Ok(super::hex_encode(&digest.finalize()))
}

fn verify_sources(root: &Path) -> io::Result<()> {
    if fs::read_to_string(root.join("frozen-source.sha256"))? != source_fingerprint(root)? {
        return Err(io::Error::other(
            "frozen paired build sources changed; refusing cached inputs",
        ));
    }
    Ok(())
}

fn rewrite_manifests(
    directory: &Path,
    original: &Path,
    destination: &Path,
    roots: &BTreeSet<PathBuf>,
) -> io::Result<()> {
    fn rewrite(value: &mut toml::Value, destination: &Path, roots: &BTreeSet<PathBuf>) {
        match value {
            toml::Value::Table(table) => {
                if let Some(toml::Value::String(path)) = table.get_mut("path") {
                    let input = Path::new(path);
                    if input.is_absolute() && roots.iter().any(|root| input.starts_with(root)) {
                        *path = mapped(destination, input).to_string_lossy().into_owned();
                    }
                }
                for (_, child) in table.iter_mut() {
                    rewrite(child, destination, roots);
                }
            }
            toml::Value::Array(array) => {
                for child in array {
                    rewrite(child, destination, roots);
                }
            }
            _ => {}
        }
    }
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            rewrite_manifests(&path, original, destination, roots)?;
        } else if path.file_name().is_some_and(|name| name == "Cargo.toml")
            && path.starts_with(original.join("fs"))
        {
            let mut manifest: toml::Value =
                toml::from_str(&fs::read_to_string(&path)?).map_err(io::Error::other)?;
            rewrite(&mut manifest, destination, roots);
            fs::write(path, toml::to_string(&manifest).map_err(io::Error::other)?)?;
        }
    }
    Ok(())
}

fn make_readonly_files(directory: &Path) -> io::Result<()> {
    if !directory.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            make_readonly_files(&path)?;
        } else {
            let mut permissions = fs::metadata(&path)?.permissions();
            permissions.set_mode(permissions.mode() & !0o222);
            fs::set_permissions(path, permissions)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires explicit production workspace and snapshot output"]
    fn capture_production_workspace_without_compiling() {
        let target = std::env::var("OSDK_SNAPSHOT_TARGET").expect("explicit target path required");
        let output = std::env::var("OSDK_SNAPSHOT_OUTPUT").expect("explicit output path required");
        let target = CrateInfo {
            name: "asterinas".into(),
            version: "0.19.0".into(),
            path: target,
            is_kernel_crate: true,
        };
        let snapshot = BuildSnapshot::capture(
            &target,
            Path::new(&output),
            None,
            &[],
            &["kernelet".into(), "kernelet-host".into()],
            true,
        )
        .unwrap();
        validate_dependencies(
            &snapshot.cargo_home(),
            Path::new(&snapshot.target.path),
            &[],
            false,
            &[],
            None,
        )
        .unwrap();
        // Match the production component-macro subprocess: no feature flags,
        // compiler package cwd, and the captured offline Cargo home.
        let core = Path::new(&snapshot.target.path).join("core");
        if core.join("Cargo.toml").is_file() {
            validate_dependencies(&snapshot.cargo_home(), &core, &[], false, &[], None).unwrap();
        }
        println!("frozen paired inputs: {}", snapshot.root.display());
    }

    #[test]
    fn paired_inputs_include_dirty_and_external_path_dependencies() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        let dependency = temp.path().join("outside");
        fs::create_dir_all(workspace.join("src")).unwrap();
        fs::create_dir_all(dependency.join("src")).unwrap();
        fs::write(
            dependency.join("Cargo.toml"),
            "[package]\nname='outside'\nversion='0.1.0'\nedition='2024'\n[workspace]\n",
        )
        .unwrap();
        fs::write(dependency.join("src/lib.rs"), "pub fn value() -> u8 { 1 }").unwrap();
        // Exercise absolute path rewriting as well as the sibling layout.
        fs::write(workspace.join("Cargo.toml"), format!(
            "[package]\nname='paired-inputs'\nversion='0.1.0'\nedition='2024'\n[workspace]\n[dependencies]\noutside={{path={:?},optional=true}}\n[features]\ndefault=['dep:outside']\n", dependency)).unwrap();
        fs::write(
            workspace.join("src/lib.rs"),
            "pub fn value() -> u8 { outside::value() }",
        )
        .unwrap();
        assert!(
            Command::new("cargo")
                .current_dir(&workspace)
                .args(["generate-lockfile", "--offline"])
                .status()
                .unwrap()
                .success()
        );
        let target = CrateInfo {
            name: "paired-inputs".into(),
            version: "0.1.0".into(),
            path: workspace.to_string_lossy().into_owned(),
            is_kernel_crate: true,
        };
        let snapshot =
            BuildSnapshot::capture(&target, &temp.path().join("output"), None, &[], &[], true)
                .unwrap();
        fs::write(workspace.join("src/lib.rs"), "broken later edit").unwrap();
        fs::write(dependency.join("src/lib.rs"), "broken dependency edit").unwrap();
        let frozen_dependency = mapped(&snapshot.root, &dependency);
        let override_config = format!("patch.crates-io.outside.path={:?}", dependency);
        let frozen_config = frozen_overrides(&snapshot.cargo_home(), &[override_config]).unwrap();
        let parsed: toml::Value = toml::from_str(&frozen_config[0]).unwrap();
        assert_eq!(
            parsed["patch"]["crates-io"]["outside"]["path"].as_str(),
            frozen_dependency.to_str()
        );
        assert_eq!(
            fs::read_to_string(frozen_dependency.join("src/lib.rs")).unwrap(),
            "pub fn value() -> u8 { 1 }"
        );
        let output = Command::new("cargo")
            .current_dir(snapshot.workspace())
            .env("CARGO_HOME", snapshot.cargo_home())
            .env("CARGO_NET_OFFLINE", "true")
            .args(["check", "--locked", "--target-dir"])
            .arg(temp.path().join("check-target"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            fs::metadata(Path::new(&snapshot.target.path).join("src/lib.rs"))
                .unwrap()
                .permissions()
                .readonly()
        );
        verify_sources(&snapshot.root).unwrap();
        // Detect accidental writes to a reused cache instead of trusting its name.
        let source = Path::new(&snapshot.target.path).join("src/lib.rs");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(source, "accidentally changed frozen source").unwrap();
        assert!(verify_sources(&snapshot.root).is_err());
    }

    #[test]
    fn copied_sources_keep_dirty_bytes_after_original_edits() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input");
        fs::create_dir_all(input.join("src")).unwrap();
        fs::write(input.join("src/lib.rs"), "dirty source").unwrap();
        fs::create_dir(input.join("target")).unwrap();
        fs::write(input.join("target/generated"), "artifact").unwrap();
        let output = temp.path().join("copy");
        copy_tree(&input, &output, &input).unwrap();
        fs::write(input.join("src/lib.rs"), "later edit").unwrap();
        assert_eq!(
            fs::read_to_string(output.join("src/lib.rs")).unwrap(),
            "dirty source"
        );
        assert!(!output.join("target").exists());
    }

    #[test]
    fn live_external_symlinks_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input");
        fs::create_dir(&input).unwrap();
        fs::write(temp.path().join("outside"), "external").unwrap();
        std::os::unix::fs::symlink("../outside", input.join("lib.rs")).unwrap();
        assert!(copy_tree(&input, &temp.path().join("copy"), &input).is_err());
    }
}

/// Refuse configurations that redirect either compiler back to live sources.
/// Generated entry crates are the only source outside the snapshot itself.
pub(super) fn validate_dependencies(
    home: &Path,
    base: &Path,
    features: &[String],
    no_default_features: bool,
    overrides: &[String],
    toolchain: Option<&std::ffi::OsStr>,
) -> io::Result<()> {
    verify_sources(
        home.parent()
            .ok_or_else(|| io::Error::other("snapshot Cargo home has no root"))?,
    )?;
    let mut command = Command::new("cargo");
    command
        .current_dir(base)
        .env("CARGO_HOME", home)
        .env("CARGO_NET_OFFLINE", "true")
        .args([
            "metadata",
            "--format-version=1",
            "--filter-platform=x86_64-unknown-none",
        ]);
    if no_default_features {
        command.arg("--no-default-features");
    }
    if !features.is_empty() {
        command.arg("--features").arg(features.join(" "));
    }
    for override_config in overrides {
        command.arg("--config").arg(override_config);
    }
    if let Some(toolchain) = toolchain {
        command.env("RUSTUP_TOOLCHAIN", toolchain);
    }
    let output = command.output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "resolve frozen compiler inputs: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).map_err(io::Error::other)?;
    let root = home
        .parent()
        .ok_or_else(|| io::Error::other("snapshot Cargo home has no root"))?
        .canonicalize()?;
    let base = base.canonicalize()?;
    for package in metadata["packages"]
        .as_array()
        .ok_or_else(|| io::Error::other("metadata has no packages"))?
    {
        let manifest = Path::new(
            package["manifest_path"]
                .as_str()
                .ok_or_else(|| io::Error::other("dependency has no manifest"))?,
        )
        .canonicalize()?;
        if !manifest.starts_with(&root) && !manifest.starts_with(&base) {
            return Err(io::Error::other(format!(
                "paired dependency escapes frozen inputs: {}",
                manifest.display()
            )));
        }
    }
    Ok(())
}

pub(super) fn frozen_overrides(home: &Path, overrides: &[String]) -> io::Result<Vec<String>> {
    fn replace_paths(value: &toml::Value, root: &Path, text: &mut String) -> io::Result<()> {
        match value {
            toml::Value::Table(table) => {
                if let Some(toml::Value::String(path)) = table.get("path") {
                    let source = Path::new(path);
                    if source.is_absolute() {
                        let frozen = mapped(root, source);
                        if !frozen.exists() {
                            return Err(io::Error::other(format!(
                                "override path is outside captured inputs: {path}"
                            )));
                        }
                        let replacement = serde_json::to_string(&frozen.to_string_lossy())
                            .map_err(io::Error::other)?;
                        let quoted = serde_json::to_string(path).map_err(io::Error::other)?;
                        *text = text
                            .replace(&quoted, &replacement)
                            .replace(&format!("'{path}'"), &replacement);
                    }
                }
                for child in table.values() {
                    replace_paths(child, root, text)?;
                }
            }
            toml::Value::Array(array) => {
                for child in array {
                    replace_paths(child, root, text)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    let root = home
        .parent()
        .ok_or_else(|| io::Error::other("snapshot has no root"))?;
    overrides
        .iter()
        .map(|original| {
            if !original.contains('=') {
                let source = std::path::absolute(original)?;
                let frozen = mapped(root, &source);
                if !frozen.is_file() {
                    return Err(io::Error::other(
                        "Cargo config file is outside captured inputs",
                    ));
                }
                return Ok(frozen.to_string_lossy().into_owned());
            }
            let value: toml::Value = toml::from_str(original).map_err(io::Error::other)?;
            let mut text = original.clone();
            replace_paths(&value, root, &mut text)?;
            Ok(text)
        })
        .collect()
}
