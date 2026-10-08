{
  target ? "x86_64",
  enableBenchmarkTest ? false,
  enableConformanceTest ? false,
  enableRegressionTest ? false,
  conformanceTestSuite ? "ltp",
  conformanceTestWorkDir ? "/tmp",
  conformanceTestSelector ? "",
  regressionTestPlatform ? "asterinas",
  dnsServer ? "none",
  smp ? 1,
  initramfsCompressed ? true,
  benchmarkName ? "none",
  system ? builtins.currentSystem,
  kerneletRuntime ? null,
  kerneletAgent ? null,
  kerneletShim ? null,
}:
assert (kerneletRuntime == null) == (kerneletAgent == null);
assert (kerneletRuntime == null) == (kerneletShim == null);
assert kerneletRuntime == null || target == "x86_64";
let
  crossSystem.config =
    if target == "x86_64" then
      "x86_64-unknown-linux-gnu"
    else if target == "riscv64" then
      "riscv64-unknown-linux-gnu"
    else if target == "aarch64" then
      "aarch64-unknown-linux-gnu"
    else
      throw "Target arch ${target} not yet supported.";

  pkgs = import ../../../distro/nixpkgs.nix {
    config = { };
    overlays = [ ];
    inherit system crossSystem;
  };
  kerneletEnabled = kerneletRuntime != null;
in
rec {
  # Packages needed by initramfs
  busybox = pkgs.busybox;
  benchmark = pkgs.callPackage ./benchmark { inherit benchmarkName; };
  conformance = pkgs.callPackage ./conformance {
    inherit smp;
    testSuite = conformanceTestSuite;
    workDir = conformanceTestWorkDir;
    testSelector = conformanceTestSelector;
  };
  regression = pkgs.callPackage ./regression { testPlatform = regressionTestPlatform; };
  kernelet-bash-bundle = if kerneletEnabled then
    pkgs.callPackage ./kernelet-bash-bundle.nix { }
  else
    null;

  initramfs = pkgs.callPackage ./initramfs.nix {
    inherit busybox;
    benchmark = if enableBenchmarkTest then benchmark else null;
    conformance = if enableConformanceTest then conformance else null;
    regression = if enableRegressionTest then regression else null;
    dnsServer = dnsServer;
    kernelet = if kerneletEnabled then {
      runtime = builtins.path {
        path = kerneletRuntime;
        name = "kernelet-runtime";
      };
      agent = builtins.path {
        path = kerneletAgent;
        name = "kernelet-agent";
      };
      shim = builtins.path {
        path = kerneletShim;
        name = "containerd-shim-kernelet-v2";
      };
      mke2fs = pkgs.pkgsStatic.e2fsprogs.override { withFuse = false; };
      bashBundle = kernelet-bash-bundle;
    } else
      null;
  };
  initramfs-image = pkgs.callPackage ./initramfs-image.nix {
    inherit initramfs;
    compressed = initramfsCompressed;
  };
  rootfs-image = pkgs.callPackage ./rootfs-image.nix { inherit initramfs; };

  # Packages needed by host
  apacheHttpd = pkgs.apacheHttpd;
  iperf3 = pkgs.iperf3;
  libmemcached = pkgs.libmemcached.overrideAttrs (_: {
    configureFlags = [ "--enable-memaslap" ];
    LDFLAGS = "-lpthread";
    CPPFLAGS = "-fcommon -fpermissive";
  });
  lmbench = pkgs.callPackage ./benchmark/lmbench.nix { };
  redis =
    (pkgs.redis.overrideAttrs (old: {
      doCheck = false;
      makeFlags = (old.makeFlags or [ ]) ++ [
        "CC=${pkgs.stdenv.cc.targetPrefix}cc"
        "LD=${pkgs.stdenv.cc.targetPrefix}cc"
      ];
    })).override
      { withSystemd = false; };
}
