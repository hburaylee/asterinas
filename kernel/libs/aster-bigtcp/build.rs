// SPDX-License-Identifier: MPL-2.0

//! Enables TCP reset diagnostics only in a Kernelet Host build.

use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=KERNELET_NAT_FAILURE_DIAG");
    println!("cargo:rerun-if-env-changed=KERNELET_IMAGE_PATH");
    println!("cargo:rustc-check-cfg=cfg(kernelet_nat_failure_diag_host)");
    if env::var("KERNELET_NAT_FAILURE_DIAG").as_deref() == Ok("1")
        && env::var_os("KERNELET_IMAGE_PATH").is_some_and(|path| !path.is_empty())
    {
        println!("cargo:rustc-cfg=kernelet_nat_failure_diag_host");
    }
}
