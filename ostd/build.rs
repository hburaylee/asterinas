// SPDX-License-Identifier: MPL-2.0

fn main() {
    println!("cargo:rerun-if-env-changed=KERNELET_IMAGE_PATH");
    let image = std::env::var_os("CARGO_FEATURE_KERNELET_HOST")
        .and_then(|_| std::env::var_os("KERNELET_IMAGE_PATH"));
    let embedded = match image {
        Some(path) if !path.is_empty() => {
            let path = std::path::PathBuf::from(path);
            println!("cargo:rerun-if-changed={}", path.display());
            format!(
                "static EMBEDDED_IMAGE: Option<&[u8]> = Some(include_bytes!({:?}));\n",
                path.to_str().expect("image path must be UTF-8")
            )
        }
        _ => "static EMBEDDED_IMAGE: Option<&[u8]> = None;\n".to_string(),
    };
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(output.join("kernelet_image.rs"), embedded)
        .expect("cannot embed audited kernelet image");
    println!("cargo:rerun-if-env-changed=KERNELET_RQ1_BENCH");
    println!("cargo:rustc-check-cfg=cfg(kernelet_rq1)");
    if std::env::var_os("KERNELET_RQ1_BENCH").as_deref() == Some(std::ffi::OsStr::new("1")) {
        println!("cargo:rustc-cfg=kernelet_rq1");
    }
    // Fixture availability does not enable per-call diagnostics.
    println!("cargo:rerun-if-env-changed=KERNELET_RQ1_DIAGNOSTICS");
    println!("cargo:rustc-check-cfg=cfg(kernelet_rq1_diagnostics)");
    if std::env::var_os("KERNELET_RQ1_DIAGNOSTICS").as_deref() == Some(std::ffi::OsStr::new("1")) {
        assert!(
            std::env::var_os("KERNELET_RQ1_BENCH").as_deref() == Some(std::ffi::OsStr::new("1")),
            "KERNELET_RQ1_DIAGNOSTICS=1 requires KERNELET_RQ1_BENCH=1"
        );
        assert!(
            std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64"),
            "KERNELET_RQ1_DIAGNOSTICS=1 requires target_arch=x86_64"
        );
        println!("cargo:rustc-cfg=kernelet_rq1_diagnostics");
    }
    println!("cargo:rerun-if-env-changed=KERNELET_RQ1_CROSSING_DIAG");
    println!("cargo:rustc-check-cfg=cfg(kernelet_rq1_crossing_diag)");
    if std::env::var_os("KERNELET_RQ1_CROSSING_DIAG").as_deref() == Some(std::ffi::OsStr::new("1"))
    {
        assert!(
            std::env::var_os("KERNELET_RQ1_BENCH").as_deref() == Some(std::ffi::OsStr::new("1")),
            "KERNELET_RQ1_CROSSING_DIAG=1 requires KERNELET_RQ1_BENCH=1"
        );
        assert!(
            std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64"),
            "KERNELET_RQ1_CROSSING_DIAG=1 requires target_arch=x86_64"
        );
        println!("cargo:rustc-cfg=kernelet_rq1_crossing_diag");
    }
    println!("cargo:rerun-if-env-changed=KERNELET_GETPID_PROFILE");
    println!("cargo:rustc-check-cfg=cfg(kernelet_getpid_profile)");
    if std::env::var_os("KERNELET_GETPID_PROFILE").as_deref() == Some(std::ffi::OsStr::new("1")) {
        println!("cargo:rustc-cfg=kernelet_getpid_profile");
    }
}
