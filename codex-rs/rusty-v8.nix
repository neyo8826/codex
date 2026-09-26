# Prebuilt rusty_v8 artifacts for the `v8` crate, mirroring nixpkgs'
# pkgs/by-name/co/codex. The v8 build script would otherwise download these at
# build time, which the Nix sandbox forbids. Bump `version` and the hashes
# together with the `v8` pin in Cargo.toml.
{
  lib,
  stdenv,
  fetchurl,
}:
let
  version = "150.4.0";
  target = stdenv.hostPlatform.rust.rustcTarget;
  system = stdenv.hostPlatform.system;
  releaseUrl = "https://github.com/denoland/rusty_v8/releases/download/v${version}";

  lockedV8 = lib.findFirst (pkg: pkg.name == "v8") null
    (builtins.fromTOML (builtins.readFile ./Cargo.lock)).package;

  pick =
    what: shas:
    shas.${system} or (throw "rusty_v8 ${what}: no prebuilt artifact pinned for ${system}");

  fetch =
    what: url: shas:
    fetchurl {
      name = "${what}-${version}";
      inherit url;
      sha256 = pick what shas;
      meta.sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
    };
in
assert lib.assertMsg (lockedV8 != null && lockedV8.version == version)
  "rusty-v8.nix pins v8 ${version}, but Cargo.lock has ${lockedV8.version or "none"}";
{
  archive = fetch "librusty_v8" "${releaseUrl}/librusty_v8_release_${target}.a.gz" {
    x86_64-linux = "0v5hi3s56b6yk7nh5n0wygh7fn0j41yyjz5903r227qv0yvzssaq";
    aarch64-linux = "1lvx9xjzv7ibqvg5jnaxqaaim0lw4dwfgf6kw0pjfdrkmm97s5xp";
    aarch64-darwin = "043bgs3hcvrn1yzknrxchqnki8r9p7ggk9zbiaqwa8mqhlagin6c";
  };
  srcBinding = fetch "src_binding" "${releaseUrl}/src_binding_release_${target}.rs" {
    x86_64-linux = "01l53l6nk4p5brpz2v3svqijx3hz5nqry8q7x12vdgbrwim849vp";
    aarch64-linux = "01l53l6nk4p5brpz2v3svqijx3hz5nqry8q7x12vdgbrwim849vp";
    aarch64-darwin = "0krrb2vh4skvfmzwpcqkl55bg2gyn943drqa8snp16lwz06dynna";
  };
}
