final: prev:
let
  inherit (final) lib stdenv fetchurl makeBinaryWrapper;
  version = "0.166.0";
  isSupported = stdenv.hostPlatform.system == "x86_64-linux" || stdenv.hostPlatform.system == "aarch64-linux";
  arch = if stdenv.hostPlatform.system == "aarch64-linux" then "aarch64" else "x86_64";

  codex-src = fetchurl {
    url = "https://github.com/openai/codex/releases/download/rust-v${version}/codex-${arch}-unknown-linux-musl.tar.gz";
    hash =
      if arch == "x86_64" then
        "sha256-oL9XLS+T8FbGcSpto0jpYHjchPOIX9e+Z4B+84nLOXg="
      else
        "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; # fill for aarch64
  };

  codex-binary = stdenv.mkDerivation {
    pname = "codex";
    inherit version;
    src = codex-src;

    dontUnpack = true;
    nativeBuildInputs = [ makeBinaryWrapper ];

    installPhase = ''
      runHook preInstall
      tar -xzf $src
      install -Dm755 codex-${arch}-unknown-linux-musl $out/bin/codex
      wrapProgram $out/bin/codex --prefix PATH : ${
        lib.makeBinPath [ final.ripgrep ]
      }
      runHook postInstall
    '';

    meta = prev.codex.meta;
  };

in
{
  codex = if isSupported then codex-binary else prev.codex;
}
