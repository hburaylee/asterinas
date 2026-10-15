// SPDX-License-Identifier: MPL-2.0

//! Selects opt-in kernel fixtures and diagnostics for the current build.

use std::env;

fn main() {
    let host = env::var_os("CARGO_FEATURE_KERNELET_HOST").is_some();
    println!("cargo:rerun-if-env-changed=KERNELET_HOST_CONNECT_GATE");
    println!("cargo:rustc-check-cfg=cfg(kernelet_host_connect_gate)");
    if host
        && env::var("KERNELET_HOST_CONNECT_GATE").as_deref() == Ok("1")
        && env::var_os("KERNELET_IMAGE_PATH").is_some_and(|path| !path.is_empty())
    {
        println!("cargo:rustc-cfg=kernelet_host_connect_gate");
    }
    // Testbed addressing is independent of diagnostic timing instrumentation.
    println!("cargo:rerun-if-env-changed=KERNELET_BENCH_HOST_NETWORK");
    println!("cargo:rustc-check-cfg=cfg(kernelet_bench_host_network)");
    if env::var("KERNELET_BENCH_HOST_NETWORK").as_deref() == Ok("1") {
        println!("cargo:rustc-cfg=kernelet_bench_host_network");
    }
    // Failure diagnostics are independent of ordinary network measurements.
    println!("cargo:rerun-if-env-changed=KERNELET_NAT_FAILURE_DIAG");
    println!("cargo:rustc-check-cfg=cfg(kernelet_nat_failure_diag)");
    if env::var("KERNELET_NAT_FAILURE_DIAG").as_deref() == Ok("1") {
        println!("cargo:rustc-cfg=kernelet_nat_failure_diag");
    }
    println!("cargo:rustc-check-cfg=cfg(kernelet_nat_failure_diag_host)");
    if host
        && env::var("KERNELET_NAT_FAILURE_DIAG").as_deref() == Ok("1")
        && env::var_os("KERNELET_IMAGE_PATH").is_some_and(|path| !path.is_empty())
    {
        println!("cargo:rustc-cfg=kernelet_nat_failure_diag_host");
    }
    println!("cargo:rerun-if-env-changed=KERNELET_GETPID_PROFILE");
    println!("cargo:rustc-check-cfg=cfg(kernelet_getpid_profile)");
    if env::var("KERNELET_GETPID_PROFILE").as_deref() == Ok("1")
        && env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64")
    {
        println!("cargo:rustc-cfg=kernelet_getpid_profile");
    }
    println!("cargo:rerun-if-env-changed=KERNELET_IMAGE_PATH");
    // Opt-in, experimental kernel-boundary measurements (`/proc/kernelet_rq1`).
    // The environment variable is expected to reach both Host and guest
    // (kernelet image) builds, so no OSDK feature propagation is needed.
    println!("cargo:rerun-if-env-changed=KERNELET_RQ1_BENCH");
    println!("cargo:rustc-check-cfg=cfg(kernelet_rq1)");
    if env::var("KERNELET_RQ1_BENCH").as_deref() == Ok("1") {
        println!("cargo:rustc-cfg=kernelet_rq1");
    }
    // Fixture availability does not enable per-call diagnostics.
    println!("cargo:rerun-if-env-changed=KERNELET_RQ1_DIAGNOSTICS");
    println!("cargo:rustc-check-cfg=cfg(kernelet_rq1_diagnostics)");
    if env::var("KERNELET_RQ1_DIAGNOSTICS").as_deref() == Ok("1") {
        assert!(
            env::var("KERNELET_RQ1_BENCH").as_deref() == Ok("1"),
            "KERNELET_RQ1_DIAGNOSTICS=1 requires KERNELET_RQ1_BENCH=1"
        );
        assert!(
            env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64"),
            "KERNELET_RQ1_DIAGNOSTICS=1 requires target_arch=x86_64"
        );
        println!("cargo:rustc-cfg=kernelet_rq1_diagnostics");
    }
    println!("cargo:rerun-if-env-changed=KERNELET_RQ1_CROSSING_DIAG");
    println!("cargo:rustc-check-cfg=cfg(kernelet_rq1_crossing_diag)");
    if env::var("KERNELET_RQ1_CROSSING_DIAG").as_deref() == Ok("1") {
        assert!(
            env::var("KERNELET_RQ1_BENCH").as_deref() == Ok("1"),
            "KERNELET_RQ1_CROSSING_DIAG=1 requires KERNELET_RQ1_BENCH=1"
        );
        assert!(
            env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64"),
            "KERNELET_RQ1_CROSSING_DIAG=1 requires target_arch=x86_64"
        );
        println!("cargo:rustc-cfg=kernelet_rq1_crossing_diag");
    }
    println!("cargo:rerun-if-env-changed=KERNELET_RQ3_BENCH");
    println!("cargo:rustc-check-cfg=cfg(kernelet_rq3)");
    if env::var("KERNELET_RQ3_BENCH").as_deref() == Ok("1") {
        println!("cargo:rustc-cfg=kernelet_rq3");
    }
}
