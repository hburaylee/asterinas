// SPDX-License-Identifier: MPL-2.0

//! Selects the audited kernelet image supplied by OSDK, when present.

use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=KERNELET_IMAGE_PATH");
    // Opt-in, experimental kernel-boundary measurements (`/proc/kernelet_rq1`).
    // The environment variable is expected to reach both Host and guest
    // (kernelet image) builds, so no OSDK feature propagation is needed.
    println!("cargo:rerun-if-env-changed=KERNELET_RQ1_BENCH");
    println!("cargo:rustc-check-cfg=cfg(kernelet_rq1)");
    if env::var("KERNELET_RQ1_BENCH").as_deref() == Ok("1") {
        println!("cargo:rustc-cfg=kernelet_rq1");
    }
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo must set OUT_DIR"))
        .join("kernelet_image.rs");
    let source = match env::var_os("KERNELET_IMAGE_PATH") {
        Some(path) => {
            let path = PathBuf::from(path);
            println!("cargo:rerun-if-changed={}", path.display());
            let path = path
                .to_str()
                .expect("the kernelet image path must be valid UTF-8");
            format!(
                "#[cfg(panic = \"abort\")]\ncompile_error!(\"a kernelet Host requires panic=unwind\");\npub(super) static EMBEDDED_IMAGE: Option<&[u8]> = Some(include_bytes!({path:?}));\n"
            )
        }
        None => "pub(super) static EMBEDDED_IMAGE: Option<&[u8]> = None;\n".to_string(),
    };
    fs::write(output, source).expect("failed to generate the kernelet image reference");
}
