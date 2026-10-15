// SPDX-License-Identifier: MPL-2.0

use std::{fs, path::Path};

use super::{
    build::do_cached_build,
    util::{lock_build_directory, resolve_output_directory},
};
use crate::{
    base_crate::{BaseCrateType, new_base_crate},
    bundle::{QemuExit, classify_qemu_exit_status},
    cli::TestArgs,
    config::{Config, scheme::ActionChoice},
    error::Errno,
    error_msg,
    util::{DirGuard, get_current_crates, get_target_directory},
};

pub fn execute_test_command(config: &Config, args: &TestArgs) {
    let cargo_target_directory = get_target_directory();
    let osdk_output_directory =
        resolve_output_directory(args.output_args.output.as_deref(), &cargo_target_directory)
            .unwrap_or_else(|error| {
                error_msg!("Failed to resolve the OSDK output directory: {error}");
                std::process::exit(Errno::Cli as _);
            });
    let crates = get_current_crates();
    let mut exit_code = 0;

    for crate_info in crates {
        std::env::set_current_dir(crate_info.path).unwrap();
        let qemu_exit = test_current_crate(
            config,
            args,
            &cargo_target_directory,
            &osdk_output_directory,
        );
        exit_code = exit_code.max(match qemu_exit {
            QemuExit::Success => 0,
            QemuExit::Failed => 1,
            QemuExit::Unknown => 2,
        });
    }

    if exit_code != 0 {
        std::process::exit(exit_code);
    }
}

fn test_current_crate(
    config: &Config,
    args: &TestArgs,
    cargo_target_directory: &Path,
    osdk_output_directory: &Path,
) -> QemuExit {
    let current_crates = get_current_crates();
    if current_crates.len() != 1 {
        error_msg!("The current directory contains more than one crate");
        std::process::exit(Errno::TooManyCrates as _);
    }
    let current_crate = get_current_crates().remove(0);

    // A special case is that we use OSDK to test the OSDK test runner crate
    // itself. We check it by name.
    let runner_self_test = if current_crate.name == "osdk-test-kernel" {
        if matches!(option_env!("OSDK_LOCAL_DEV"), Some("1")) {
            true
        } else {
            error_msg!("The tested crate name collides with the OSDK test runner crate");
            std::process::exit(Errno::BadCrateName as _);
        }
    } else {
        false
    };

    let build_lock = lock_build_directory(cargo_target_directory).unwrap_or_else(|error| {
        error_msg!(
            "Failed to lock the Cargo target directory {} for the OSDK build: {error}",
            cargo_target_directory.display()
        );
        std::process::exit(Errno::BuildCrate as _);
    });
    let target_crate_dir = new_base_crate(
        BaseCrateType::Test,
        osdk_output_directory.join(&current_crate.name),
        &current_crate.name,
        &current_crate.path,
        !runner_self_test,
    );

    let main_rs_path = target_crate_dir.join("src").join("main.rs");

    let ktest_test_whitelist = match &args.test_name {
        Some(name) => format!(r#"Some(&["{}"])"#, name),
        None => r#"None"#.to_string(),
    };

    let mut ktest_crate_whitelist = vec![current_crate.name.clone()];
    if let Some(name) = &args.test_name {
        ktest_crate_whitelist.push(name.clone());
    }

    // Append the ktest static variable and the runner reference to the
    // `main.rs` file.
    let ktest_main_rs = format!(
        r#"

{}

// SAFETY: The name does not collide with other symbols.
#[unsafe(no_mangle)]
pub static KTEST_TEST_WHITELIST: Option<&[&str]> = {};
// SAFETY: The name does not collide with other symbols.
#[unsafe(no_mangle)]
pub static KTEST_CRATE_WHITELIST: Option<&[&str]> = Some(&{:#?});

"#,
        if runner_self_test {
            ""
        } else {
            "extern crate osdk_test_kernel;"
        },
        ktest_test_whitelist,
        ktest_crate_whitelist,
    );
    let mut main_rs_content = fs::read_to_string(&main_rs_path).unwrap();
    main_rs_content.push_str(&ktest_main_rs);
    fs::write(&main_rs_path, main_rs_content).unwrap();

    // Build the kernel with the given base crate
    let default_bundle_directory = osdk_output_directory.join(&current_crate.name);
    let dir_guard = DirGuard::change_dir(&target_crate_dir);
    let bundle = do_cached_build(
        default_bundle_directory,
        osdk_output_directory,
        cargo_target_directory,
        config,
        ActionChoice::Test,
        &["--cfg ktest", "-C panic=unwind"],
        // Ktest kernels run in the host boot path; the kernelet image is not
        // built here. A kernelet-enabled manifest fails the build with an
        // explicit error inside `do_cached_build`.
        None,
    );
    drop(dir_guard);
    drop(build_lock);

    let exit_status = bundle.run_qemu_and_wait(config, ActionChoice::Test);
    classify_qemu_exit_status(exit_status)
}
