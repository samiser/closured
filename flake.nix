{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    crane.url = "github:ipetkov/crane";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
  outputs = {
    self,
    nixpkgs,
    fenix,
    crane,
    ...
  }: let
    systems = ["x86_64-linux" "aarch64-linux"];
    forAllSystems = nixpkgs.lib.genAttrs systems;

    # Fetched at evaluation time (not a derivation), so evaluating this
    # flake's outputs for one system from a machine of another system —
    # e.g. `nix flake check` on darwin evaluating the NixOS module —
    # never triggers import-from-derivation. fenix's toolchainOf would
    # fetch this same file via pkgs.fetchurl, which is a system-bound
    # derivation and breaks cross-system evaluation.
    rustManifest = builtins.fetchurl {
      url = "https://static.rust-lang.org/dist/2026-01-01/channel-rust-nightly.toml";
      sha256 = "sha256-KTCPimYDgP3en6gZzClSIezJ75wuFRnhhja93KsVxA0=";
    };

    outputsFor = system: let
      pkgs = nixpkgs.legacyPackages.${system};
      toolchainPkgs = fenix.packages.${system}.fromManifestFile rustManifest;
      toolchain = toolchainPkgs.withComponents ["cargo" "rustc" "rust-src" "clippy" "rustfmt"];
      craneLib = (crane.mkLib pkgs).overrideToolchain (_: toolchain);
      aya-tool = pkgs.rustPlatform.buildRustPackage {
        pname = "aya-tool";
        version = "unstable-2026-07";
        src = pkgs.fetchFromGitHub {
          owner = "aya-rs";
          repo = "aya";
          rev = "773ca715385b97eb0c26a581b53246c0c4306959";
          hash = "sha256-Tby/XRgY56/iYPktXbpMaHu+khrK6bhyeCzFVKxIBek=";
        };
        cargoHash = "sha256-2yareV2w5ZlqPdtBl94qZQTGa+2S34Wmsz4HkKLLSNg=";
        cargoBuildFlags = ["-p" "aya-tool"];
        doCheck = false;
      };
      commonArgs = {
        src = craneLib.cleanCargoSource ./.;
        pname = "closured";
        version = "0.1.0";
        strictDeps = true;
        # aya-build compiles with `-Z build-std=core`, which resolves the
        # toolchain's own library workspace, so we need to vendor the lock.
        # nix/rust-library-Cargo.lock is a checked-in copy of
        # ${toolchainPkgs.rust-src}/lib/rustlib/src/rust/library/Cargo.lock —
        # referencing that path directly would realise the rust-src
        # derivation at evaluation time (import-from-derivation), breaking
        # cross-system evaluation. Re-copy it when bumping the toolchain.
        cargoVendorDir = craneLib.vendorMultipleCargoDeps {
          cargoLockList = [
            ./Cargo.lock
            ./nix/rust-library-Cargo.lock
          ];
        };
        nativeBuildInputs = [
          pkgs.bpf-linker
          pkgs.llvmPackages.bintools-unwrapped
        ];
        doCheck = false;
      };
      cargoArtifacts = craneLib.buildDepsOnly commonArgs;
      closured = craneLib.buildPackage (commonArgs
        // {
          inherit cargoArtifacts;
        });
    in {
      package = closured;
      devShell = pkgs.mkShell {
        packages = [
          toolchain
          aya-tool
          pkgs.bacon
          pkgs.bpf-linker
          pkgs.bpftools
          pkgs.cargo-generate
          pkgs.llvmPackages.bintools-unwrapped
          pkgs.rust-bindgen
        ];
      };
    };
  in {
    packages = forAllSystems (system: {
      default = (outputsFor system).package;
    });

    nixosModules.default = import ./nix/module.nix self;

    devShells = forAllSystems (system: {
      default = (outputsFor system).devShell;
    });
  };
}
