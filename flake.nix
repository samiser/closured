{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    fenix.url = "github:nix-community/fenix";
    crane.url = "github:ipetkov/crane";
  };
  outputs = {
    self,
    nixpkgs,
    fenix,
    crane,
    ...
  }: let
    system = "x86_64-linux";
    pkgs = nixpkgs.legacyPackages.${system};
    toolchain = (fenix.packages.${system}.toolchainOf {
      channel = "nightly";
      date = "2026-01-01";
      sha256 = "sha256-KTCPimYDgP3en6gZzClSIezJ75wuFRnhhja93KsVxA0=";
    }).withComponents ["cargo" "rustc" "rust-src" "clippy" "rustfmt"];
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
      # toolchain's own library workspace, so we need to vendor the lock
      cargoVendorDir = craneLib.vendorMultipleCargoDeps {
        cargoLockList = [
          ./Cargo.lock
          "${toolchain}/lib/rustlib/src/rust/library/Cargo.lock"
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
    packages.${system}.default = closured;

    nixosModules.default = import ./nix/module.nix self;

    devShells.${system}.default = pkgs.mkShell {
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
}
