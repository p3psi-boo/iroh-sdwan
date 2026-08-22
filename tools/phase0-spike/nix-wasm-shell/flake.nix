{
  description = "Phase 0 spike: ironet devShell + wasm32 target + wasm-tools (scratchpad only)";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    systems.url = "github:nix-systems/default-linux";
  };
  outputs = { self, nixpkgs, flake-utils, rust-overlay, systems, ... }:
    flake-utils.lib.eachSystem (import systems) (system:
      let
        pkgs = import nixpkgs { inherit system; overlays = [ rust-overlay.overlays.default ]; };
        rust = pkgs.rust-bin.stable."1.91.0".default.override {
          extensions = [ "clippy" "rust-src" "rustfmt" ];
          targets = [ "x86_64-unknown-linux-musl" "wasm32-unknown-unknown" ];
        };
      in {
        devShells.default = pkgs.mkShell {
          packages = [ rust pkgs.cacert pkgs.git pkgs.pkg-config pkgs.wasm-tools pkgs.wit-bindgen pkgs.binutils ];
          shellHook = ''
            echo "phase0 wasm spike shell"; rustc --version; wasm-tools --version; wit-bindgen --version
          '';
        };
      });
}
