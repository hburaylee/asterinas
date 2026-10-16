// SPDX-License-Identifier: MPL-2.0

//! The base crate is the OSDK generated crate that is ultimately built by cargo.
//! It will depend on the to-be-built kernel crate or the to-be-tested crate.

use std::{
    fs,
    io::{ErrorKind, Read, Result},
    path::{Path, PathBuf},
    str::FromStr,
};

use crate::util::get_cargo_metadata;

const LINKER_SCRIPTS: &[(&str, &str)] = &[
    ("x86_64.ld", include_str!("x86_64.ld.template")),
    ("riscv64.ld", include_str!("riscv64.ld.template")),
    ("loongarch64.ld", include_str!("loongarch64.ld.template")),
    ("aarch64.ld", include_str!("aarch64.ld.template")),
];

/// The generated linker script of the kernelet base crate, emitted beside the
/// host's scripts. It is rendered from its template with the entry table's
/// ABI constants and the OSTD source hash baked in.
const KERNELET_LINKER_SCRIPT: &str = "x86_64-kernelet.ld";

/// Compares two files byte-by-byte to check if they are identical.
/// Returns `Ok(true)` if files are identical, `Ok(false)` if they are different, or `Err` if any I/O operation fails.
fn are_files_identical(file1: &PathBuf, file2: &PathBuf) -> Result<bool> {
    // Check file size first
    let metadata1 = fs::metadata(file1)?;
    let metadata2 = fs::metadata(file2)?;

    if metadata1.len() != metadata2.len() {
        return Ok(false); // Different sizes, not identical
    }

    // Compare file contents byte-by-byte
    let mut file1 = fs::File::open(file1)?;
    let mut file2 = fs::File::open(file2)?;

    let mut buffer1 = [0u8; 4096];
    let mut buffer2 = [0u8; 4096];

    loop {
        let bytes_read1 = file1.read(&mut buffer1)?;
        let bytes_read2 = file2.read(&mut buffer2)?;

        if bytes_read1 != bytes_read2 || buffer1[..bytes_read1] != buffer2[..bytes_read1] {
            return Ok(false); // Files are different
        }

        if bytes_read1 == 0 {
            return Ok(true); // End of both files, identical
        }
    }
}

fn are_base_crate_reuse_inputs_identical(
    base_type: BaseCrateType,
    existing_base_crate_path: &Path,
    candidate_base_crate_path: &Path,
) -> bool {
    let are_files_identical_fn = |file_name: &str| {
        are_files_identical(
            &existing_base_crate_path.join(file_name),
            &candidate_base_crate_path.join(file_name),
        )
        .is_ok_and(|is_identical| is_identical)
    };
    if !["Cargo.toml", "Cargo.lock.source", "src/main.rs"]
        .into_iter()
        .all(are_files_identical_fn)
    {
        return false;
    }

    match base_type {
        BaseCrateType::Kernelet { .. } => are_files_identical_fn(KERNELET_LINKER_SCRIPT),
        _ => LINKER_SCRIPTS
            .iter()
            .all(|(file_name, _)| are_files_identical_fn(file_name)),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BaseCrateType {
    /// The base crate is for running the target kernel crate.
    Run,
    /// The base crate is for testing the target crate.
    Test,
    /// The base crate is for building the position-independent kernelet image
    /// from the same kernel crate. The source hash is the OSTD source tree and
    /// toolchain hash that the generated linker script bakes into the image's
    /// entry table.
    Kernelet { source_hash: [u8; 32] },
    /// The base crate is for other actions using Cargo.
    #[expect(unused)]
    Other,
}

/// Returns the name of the Cargo package generated for the base crate.
pub fn base_crate_package_name(base_type: BaseCrateType, dep_crate_name: &str) -> String {
    let suffix = match base_type {
        BaseCrateType::Kernelet { .. } => "-kernelet-bin",
        _ => "-osdk-bin",
    };
    dep_crate_name.to_string() + suffix
}

/// Returns the name of the Cargo package of the kernelet base crate.
pub fn kernelet_package_name(dep_crate_name: &str) -> String {
    base_crate_package_name(
        BaseCrateType::Kernelet {
            source_hash: [0; 32],
        },
        dep_crate_name,
    )
}

/// Renders the kernelet linker script from its template, baking in the entry
/// table's ABI constants and the OSTD source hash.
fn render_kernelet_linker_script(source_hash: &[u8; 32]) -> String {
    let hash_quads: String = source_hash
        .as_chunks::<8>()
        .0
        .iter()
        .map(|chunk| {
            let word = u64::from_le_bytes(*chunk);
            format!("        QUAD(0x{word:016X});\n")
        })
        .collect();
    include_str!("x86_64-kernelet.ld.template")
        .replace(
            "#ENTRY_TABLE_SIZE#",
            &format!("{}", crate::kernelet::abi::entry_table::SIZE),
        )
        .replace("#SOURCE_HASH_QUADS#", &hash_quads)
}

/// Create a new base crate that will be built by cargo.
///
/// The dependencies of the base crate will be the target crate. If
/// `link_unit_test_kernel` is set to true, the base crate will also depend on
/// the `ostd-test-kernel` crate.
///
/// It returns the path to the base crate.
pub fn new_base_crate(
    base_type: BaseCrateType,
    base_crate_path_stem: impl AsRef<Path>,
    dep_crate_name: &str,
    dep_crate_path: impl AsRef<Path>,
    link_unit_test_kernel: bool,
) -> PathBuf {
    let base_crate_path: PathBuf = PathBuf::from(
        (base_crate_path_stem.as_ref().as_os_str().to_string_lossy()
            + match base_type {
                BaseCrateType::Run => "-run-base",
                BaseCrateType::Test => "-test-base",
                BaseCrateType::Kernelet { .. } => "-kernelet-base",
                BaseCrateType::Other => "-base",
            })
        .to_string(),
    );
    // Check if the existing crate base is reusable.
    if matches!(
        base_type,
        BaseCrateType::Run | BaseCrateType::Kernelet { .. }
    ) && base_crate_path.exists()
    {
        // Reuse the existing base crate if it is identical to the new one.
        let base_crate_tmp_path = base_crate_path.join("tmp");
        do_new_base_crate(
            &base_crate_tmp_path,
            base_type,
            dep_crate_name,
            &dep_crate_path,
            link_unit_test_kernel,
        );
        let is_reusable = are_base_crate_reuse_inputs_identical(
            base_type,
            &base_crate_path,
            &base_crate_tmp_path,
        );
        std::fs::remove_dir_all(&base_crate_tmp_path).unwrap();
        if is_reusable {
            info!("Reusing existing base crate");
            return base_crate_path;
        }
    }
    do_new_base_crate(
        &base_crate_path,
        base_type,
        dep_crate_name,
        dep_crate_path,
        link_unit_test_kernel,
    );

    base_crate_path
}

fn do_new_base_crate(
    base_crate_path: impl AsRef<Path>,
    base_type: BaseCrateType,
    dep_crate_name: &str,
    dep_crate_path: impl AsRef<Path>,
    link_unit_test_kernel: bool,
) {
    let workspace_root = {
        let meta = get_cargo_metadata(None::<&str>, None::<&[&str]>).unwrap();
        PathBuf::from(meta.get("workspace_root").unwrap().as_str().unwrap())
    };

    if base_crate_path.as_ref().exists() {
        std::fs::remove_dir_all(&base_crate_path).unwrap();
    }

    let dep_meta = get_cargo_metadata(Some(dep_crate_path.as_ref()), None::<&[&str]>).unwrap();
    let (dep_crate_version, dep_crate_features) = {
        let dep_meta = dep_meta.as_object().unwrap();

        let dep_package = {
            let packages = dep_meta.get("packages").unwrap().as_array().unwrap();
            packages
                .iter()
                .find(|package| {
                    let package = package.as_object().unwrap();
                    let name = package.get("name").unwrap().as_str().unwrap();
                    name == dep_crate_name
                })
                .unwrap()
                .as_object()
                .unwrap()
        };
        let dep_version = dep_package.get("version").unwrap().as_str().unwrap();
        let dep_features = dep_package.get("features").unwrap().as_object().unwrap();
        (dep_version, dep_features)
    };

    // Create the directory
    fs::create_dir_all(&base_crate_path).unwrap();
    // Create the src directory
    fs::create_dir_all(base_crate_path.as_ref().join("src")).unwrap();

    // Keep the workspace's dependency versions, including reviewed unsafe-code
    // exceptions, when Cargo resolves the generated package's dependencies.
    copy_workspace_lockfile(&workspace_root, base_crate_path.as_ref()).unwrap();

    // Write Cargo.toml
    let cargo_toml = include_str!("Cargo.toml.template");
    let cargo_toml = cargo_toml.replace(
        "#NAME#",
        &base_crate_package_name(base_type, dep_crate_name),
    );
    let cargo_toml = cargo_toml.replace("#VERSION#", dep_crate_version);
    fs::write(base_crate_path.as_ref().join("Cargo.toml"), cargo_toml).unwrap();

    // Set the current directory to the target osdk directory
    let original_dir = std::env::current_dir().unwrap();
    std::env::set_current_dir(&base_crate_path).unwrap();

    // The kernelet base crate is linked by the generated kernelet linker
    // script alone; it has no boot segments and no physical load addresses.
    if let BaseCrateType::Kernelet { source_hash } = base_type {
        fs::write(
            base_crate_path.as_ref().join(KERNELET_LINKER_SCRIPT),
            render_kernelet_linker_script(&source_hash),
        )
        .unwrap();
    } else {
        for (file_name, contents) in LINKER_SCRIPTS {
            fs::write(base_crate_path.as_ref().join(file_name), contents).unwrap();
        }
    }

    let default_allocators_cfg = match base_type {
        BaseCrateType::Kernelet { .. } => "any()",
        _ => "all()",
    };
    let main_rs = include_str!("main.rs.template")
        .replace("#TARGET_NAME#", &dep_crate_name.replace('-', "_"))
        .replace("#DEFAULT_ALLOCATORS_CFG#", default_allocators_cfg);
    fs::write("src/main.rs", main_rs).unwrap();

    // Add dependencies to the Cargo.toml
    add_manifest_dependency(
        dep_crate_name,
        dep_crate_path,
        link_unit_test_kernel,
        base_type,
        &workspace_root,
    );

    // Copy the manifest configurations from the target crate to the base crate
    copy_profile_configurations(workspace_root);

    // Generate the features by copying the features from the target crate
    let dep_crate_features = dep_crate_features.iter().map(|(feature, value)| {
        let array = value
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_string())
            .map(toml::Value::String)
            .collect();
        (feature.clone(), toml::Value::Array(array))
    });
    add_feature_entries(dep_crate_name, dep_crate_features);

    // Get back to the original directory
    std::env::set_current_dir(original_dir).unwrap();
}

fn copy_workspace_lockfile(workspace_root: &Path, base_crate_path: &Path) -> Result<()> {
    // Cargo can add the generated package and prune unrelated workspace members.
    // Keep the original bytes separately so reuse detects source lockfile changes.
    let source_snapshot = base_crate_path.join("Cargo.lock.source");
    let source = match fs::read(workspace_root.join("Cargo.lock")) {
        Ok(source) => source,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            // An unlocked workspace is valid; record that state for reuse checks.
            return fs::write(source_snapshot, []);
        }
        Err(error) => return Err(error),
    };
    fs::write(base_crate_path.join("Cargo.lock"), &source)?;
    fs::write(source_snapshot, source)
}

fn add_manifest_dependency(
    crate_name: &str,
    crate_path: impl AsRef<Path>,
    link_unit_test_kernel: bool,
    base_type: BaseCrateType,
    workspace_root: &Path,
) {
    let manifest_path = "Cargo.toml";

    let mut manifest: toml::Table = {
        let content = fs::read_to_string(manifest_path).unwrap();
        toml::from_str(&content).unwrap()
    };

    // Check if "dependencies" key exists, create it if it doesn't
    if !manifest.contains_key("dependencies") {
        manifest.insert(
            "dependencies".to_string(),
            toml::Value::Table(toml::Table::new()),
        );
    }

    let dependencies = manifest.get_mut("dependencies").unwrap();

    // We disable default features when depending on the target crate, and add
    // all the default features as the default features of the base crate, to
    // allow controls from the users.
    // See `add_feature_entries` for more details.
    let target_dep = toml::Table::from_str(&format!(
        "{} = {{ path = \"{}\", default-features = false }}",
        crate_name,
        crate_path.as_ref().display()
    ))
    .unwrap();
    dependencies.as_table_mut().unwrap().extend(target_dep);

    // The kernelet image gets its memory from the Host's services, so it does
    // not link the default boot allocators or depend on `ostd` directly.
    if matches!(base_type, BaseCrateType::Kernelet { .. }) {
        let content = toml::to_string(&manifest).unwrap();
        fs::write(manifest_path, content).unwrap();
        return;
    }

    if link_unit_test_kernel {
        add_manifest_dependency_to(
            dependencies,
            "osdk-test-kernel",
            Path::new("deps").join("test-kernel"),
            workspace_root,
        );
    }

    add_manifest_dependency_to(
        dependencies,
        "osdk-frame-allocator",
        Path::new("deps").join("frame-allocator"),
        workspace_root,
    );

    add_manifest_dependency_to(
        dependencies,
        "osdk-heap-allocator",
        Path::new("deps").join("heap-allocator"),
        workspace_root,
    );

    add_manifest_dependency_to(
        dependencies,
        "ostd",
        Path::new("..").join("ostd"),
        workspace_root,
    );

    let content = toml::to_string(&manifest).unwrap();
    fs::write(manifest_path, content).unwrap();
}

fn add_manifest_dependency_to(
    manifest: &mut toml::Value,
    dep_name: &str,
    path: PathBuf,
    workspace_root: &Path,
) {
    let dep_str = match option_env!("OSDK_LOCAL_DEV") {
        Some("1") => {
            // Paired builds must use the OSDK support crates in the same frozen
            // workspace rather than paths embedded when cargo-osdk was compiled.
            let local_osdk = workspace_root.join("osdk");
            let crate_dir = if local_osdk.join("Cargo.toml").is_file() {
                local_osdk
            } else {
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            };
            let dep_crate_dir = crate_dir.join(path);
            format!(
                "{} = {{ path = \"{}\" }}",
                dep_name,
                dep_crate_dir.display()
            )
        }
        _ => format!(
            "{} = {{ version = \"{}\" }}",
            dep_name,
            env!("CARGO_PKG_VERSION"),
        ),
    };
    let dep_val = toml::Table::from_str(&dep_str).unwrap();
    manifest.as_table_mut().unwrap().extend(dep_val);
}

fn copy_profile_configurations(workspace_root: impl AsRef<Path>) {
    let target_manifest_path = workspace_root.as_ref().join("Cargo.toml");
    let manifest_path = "Cargo.toml";

    let target_manifest: toml::Table = {
        let content = fs::read_to_string(target_manifest_path).unwrap();
        toml::from_str(&content).unwrap()
    };

    let mut manifest: toml::Table = {
        let content = fs::read_to_string(manifest_path).unwrap();
        toml::from_str(&content).unwrap()
    };

    // Copy the profile configurations
    let profile = target_manifest.get("profile");
    if let Some(profile) = profile {
        manifest.insert(
            "profile".to_string(),
            toml::Value::Table(profile.as_table().unwrap().clone()),
        );
    }

    let content = toml::to_string(&manifest).unwrap();
    fs::write(manifest_path, content).unwrap();
}

fn add_feature_entries(
    dep_crate_name: &str,
    features: impl Iterator<Item = (String, toml::Value)>,
) {
    let manifest_path = "Cargo.toml";
    let mut manifest: toml::Table = {
        let content = fs::read_to_string(manifest_path).unwrap();
        toml::from_str(&content).unwrap()
    };

    let mut table = toml::Table::new();
    for (feature, value) in features {
        let value = if feature != "default" {
            vec![toml::Value::String(format!(
                "{}/{}",
                dep_crate_name, feature
            ))]
        } else {
            value.as_array().unwrap().clone()
        };
        table.insert(feature.clone(), toml::Value::Array(value));
    }

    manifest.insert("features".to_string(), toml::Value::Table(table));

    let content = toml::to_string(&manifest).unwrap();
    fs::write(manifest_path, content).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Base-crate generation temporarily changes the process working directory.
    static BASE_CRATE_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn changed_linker_script_prevents_base_crate_reuse() {
        let _guard = BASE_CRATE_TEST_LOCK.lock().unwrap();
        // Regression test for https://github.com/asterinas/asterinas/issues/3649.
        let temp_dir = tempfile::tempdir().unwrap();
        let base_crate_path_stem = temp_dir.path().join("generated");
        let dep_crate_path = env!("CARGO_MANIFEST_DIR");
        let base_crate_path = new_base_crate(
            BaseCrateType::Run,
            &base_crate_path_stem,
            env!("CARGO_PKG_NAME"),
            dep_crate_path,
            false,
        );

        for (file_name, contents) in LINKER_SCRIPTS {
            let linker_script_path = base_crate_path.join(file_name);
            fs::write(&linker_script_path, "stale contents").unwrap();

            new_base_crate(
                BaseCrateType::Run,
                &base_crate_path_stem,
                env!("CARGO_PKG_NAME"),
                dep_crate_path,
                false,
            );

            assert_eq!(fs::read(linker_script_path).unwrap(), contents.as_bytes());
        }
    }

    #[test]
    fn kernelet_base_crate_has_no_boot_allocators() {
        let _guard = BASE_CRATE_TEST_LOCK.lock().unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let base_crate_path_stem = temp_dir.path().join("generated");
        let base_crate_path = new_base_crate(
            BaseCrateType::Kernelet {
                source_hash: [0; 32],
            },
            &base_crate_path_stem,
            env!("CARGO_PKG_NAME"),
            env!("CARGO_MANIFEST_DIR"),
            false,
        );
        let manifest = fs::read_to_string(base_crate_path.join("Cargo.toml")).unwrap();
        assert!(manifest.contains("kernelet-bin"));
        assert!(!manifest.contains("osdk-frame-allocator"));
        assert!(!manifest.contains("osdk-heap-allocator"));
        assert!(!fs::exists(base_crate_path.join("x86_64.ld")).unwrap());
        assert!(fs::exists(base_crate_path.join(KERNELET_LINKER_SCRIPT)).unwrap());
        assert_eq!(
            fs::read(base_crate_path.join("Cargo.lock")).unwrap(),
            fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock")).unwrap()
        );
    }

    #[test]
    fn unchanged_kernelet_base_crate_preserves_generated_files() {
        let _guard = BASE_CRATE_TEST_LOCK.lock().unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let base_crate_path_stem = temp_dir.path().join("generated");
        let base_type = BaseCrateType::Kernelet {
            source_hash: [0xab; 32],
        };
        let base_crate_path = new_base_crate(
            base_type,
            &base_crate_path_stem,
            env!("CARGO_PKG_NAME"),
            env!("CARGO_MANIFEST_DIR"),
            false,
        );
        let generated_files = [
            "Cargo.toml",
            "Cargo.lock",
            "Cargo.lock.source",
            "src/main.rs",
            KERNELET_LINKER_SCRIPT,
        ];
        let modified = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1);
        for file_name in generated_files {
            fs::File::open(base_crate_path.join(file_name))
                .unwrap()
                .set_modified(modified)
                .unwrap();
        }

        new_base_crate(
            base_type,
            &base_crate_path_stem,
            env!("CARGO_PKG_NAME"),
            env!("CARGO_MANIFEST_DIR"),
            false,
        );

        for file_name in generated_files {
            assert_eq!(
                fs::metadata(base_crate_path.join(file_name))
                    .unwrap()
                    .modified()
                    .unwrap(),
                modified,
                "unchanged generated file was rewritten: {file_name}"
            );
        }
    }

    #[test]
    fn changed_kernelet_source_hash_prevents_base_crate_reuse() {
        let _guard = BASE_CRATE_TEST_LOCK.lock().unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let base_crate_path_stem = temp_dir.path().join("generated");
        for source_hash in [[0; 32], [0xab; 32]] {
            let base_crate_path = new_base_crate(
                BaseCrateType::Kernelet { source_hash },
                &base_crate_path_stem,
                env!("CARGO_PKG_NAME"),
                env!("CARGO_MANIFEST_DIR"),
                false,
            );

            assert_eq!(
                fs::read_to_string(base_crate_path.join(KERNELET_LINKER_SCRIPT)).unwrap(),
                render_kernelet_linker_script(&source_hash)
            );
        }
    }

    #[test]
    fn changed_kernelet_inputs_prevent_base_crate_reuse() {
        let _guard = BASE_CRATE_TEST_LOCK.lock().unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let base_crate_path_stem = temp_dir.path().join("generated");
        let base_type = BaseCrateType::Kernelet {
            source_hash: [0; 32],
        };
        let base_crate_path = new_base_crate(
            base_type,
            &base_crate_path_stem,
            env!("CARGO_PKG_NAME"),
            env!("CARGO_MANIFEST_DIR"),
            false,
        );

        for file_name in [
            "Cargo.toml",
            "Cargo.lock.source",
            "src/main.rs",
            KERNELET_LINKER_SCRIPT,
        ] {
            let file_path = base_crate_path.join(file_name);
            let expected = fs::read(&file_path).unwrap();
            fs::write(&file_path, "stale contents").unwrap();

            new_base_crate(
                base_type,
                &base_crate_path_stem,
                env!("CARGO_PKG_NAME"),
                env!("CARGO_MANIFEST_DIR"),
                false,
            );

            assert_eq!(fs::read(file_path).unwrap(), expected, "{file_name}");
        }
    }

    #[test]
    fn changed_workspace_lockfile_prevents_base_crate_reuse() {
        let temp_dir = tempfile::tempdir().unwrap();
        let workspace_root = temp_dir.path().join("workspace");
        let existing = temp_dir.path().join("existing");
        let candidate = temp_dir.path().join("candidate");
        fs::create_dir(&workspace_root).unwrap();
        for path in [&existing, &candidate] {
            fs::create_dir_all(path.join("src")).unwrap();
            fs::write(path.join("Cargo.toml"), "same manifest").unwrap();
            fs::write(path.join("src/main.rs"), "same entry").unwrap();
            for (file_name, contents) in LINKER_SCRIPTS {
                fs::write(path.join(file_name), contents).unwrap();
            }
        }

        fs::write(workspace_root.join("Cargo.lock"), "reviewed versions").unwrap();
        copy_workspace_lockfile(&workspace_root, &existing).unwrap();
        copy_workspace_lockfile(&workspace_root, &candidate).unwrap();
        // Cargo's generated package may change its own lockfile without changing
        // the source dependency selection that controls reuse.
        fs::write(existing.join("Cargo.lock"), "resolved generated package").unwrap();
        assert!(are_base_crate_reuse_inputs_identical(
            BaseCrateType::Run,
            &existing,
            &candidate
        ));

        fs::write(workspace_root.join("Cargo.lock"), "new reviewed versions").unwrap();
        copy_workspace_lockfile(&workspace_root, &candidate).unwrap();
        assert!(!are_base_crate_reuse_inputs_identical(
            BaseCrateType::Run,
            &existing,
            &candidate
        ));
    }

    #[test]
    fn rendered_kernelet_linker_script_carries_the_hash() {
        let script = render_kernelet_linker_script(&[0xab; 32]);
        assert!(script.contains(&format!(
            "QUAD({});",
            crate::kernelet::abi::entry_table::SIZE
        )));
        assert!(!script.contains("#SOURCE_HASH_QUADS#"));
        assert!(!script.contains("#ENTRY_TABLE_SIZE#"));
        assert_eq!(script.matches("QUAD(0xAB").count(), 4);
    }
}
