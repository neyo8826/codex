{
  callPackage,
  cmake,
  lld,
  llvmPackages,
  openssl,
  libcap ? null,
  rustPlatform,
  pkg-config,
  lib,
  stdenv,
  version ? "0.0.0",
  rustyV8 ? callPackage ./rusty-v8.nix { },
  ...
}:
rustPlatform.buildRustPackage (_: {
  env.PKG_CONFIG_PATH = lib.makeSearchPathOutput "dev" "lib/pkgconfig" (
    [ openssl ] ++ lib.optionals stdenv.hostPlatform.isLinux [ libcap ]
  );
  # Point the v8 build script at pinned prebuilt artifacts instead of letting it
  # download them (no network in the Nix sandbox).
  env.RUSTY_V8_ARCHIVE = rustyV8.archive;
  env.RUSTY_V8_SRC_BINDING_PATH = rustyV8.srcBinding;
  pname = "codex-rs";
  inherit version;
  cargoLock.lockFile = ./Cargo.lock;
  doCheck = false;
  # Only build the CLI and its code-mode host; other workspace members (e.g.
  # codex-voice-host) pull in native deps such as GStreamer that we don't need.
  cargoBuildFlags = [ "--package" "codex-cli" "--package" "codex-code-mode-host" ];
  src = ./.;

  # Patch the workspace Cargo.toml so that cargo embeds the correct version in
  # CARGO_PKG_VERSION (which the binary reads via env!("CARGO_PKG_VERSION")).
  # On release commits the Cargo.toml already contains the real version and
  # this sed is a no-op.
  postPatch = ''
    sed -i 's/^version = "0\.0\.0"$/version = "${version}"/' Cargo.toml
  '';
  nativeBuildInputs = [
    cmake
    llvmPackages.clang
    llvmPackages.libclang.lib
    lld
    openssl
    pkg-config
  ] ++ lib.optionals stdenv.hostPlatform.isLinux [
    libcap
  ];

  cargoLock.outputHashes = {
    "appcontainer_common-0.8.0" = "sha256-XUkT2R+RYk9WIqgKnmIAagNW4xOTyp4bWHmQL1iznHw=";
    "crossterm-0.29.0" = "sha256-0OFnAzKZOd5lNkvwdXPu5zbfDWBRQG80OruXxqrFklQ=";
    "h3-0.0.8" = "sha256-fgE0AMj5d4iattTC/yQwnACV8uEu+KR7wD29xfEm8M0=";
    "nucleo-0.5.0" = "sha256-Hm4SxtTSBrcWpXrtSqeO0TACbUxq3gizg1zD/6Yw/sI=";
    "nucleo-matcher-0.3.1" = "sha256-Hm4SxtTSBrcWpXrtSqeO0TACbUxq3gizg1zD/6Yw/sI=";
    "runfiles-0.1.0" = "sha256-uJpVLcQh8wWZA3GPv9D8Nt43EOirajfDJ7eq/FB+tek=";
    "tokio-tungstenite-0.28.0" = "sha256-V1xmnrfRWOcZZogelZEA4vvyMj2awCfHVA5/glQ6KAI=";
    "tungstenite-0.27.0" = "sha256-VVHhk7l9J/sEmG3q/UuV/sQ3f+fGsmq5vumSy8vbMvw=";
  };

  meta = with lib; {
    description = "OpenAI Codex command‑line interface rust implementation";
    license = licenses.asl20;
    homepage = "https://github.com/openai/codex";
    mainProgram = "codex";
  };
})
