{
  description = "Development environment for the Linux-only iroh-sdwan prototype";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    systems.url = "github:nix-systems/default-linux";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      rust-overlay,
      systems,
      ...
    }:
    {
      nixosModules.default =
        { pkgs, ... }@moduleArgs:
        import ./nixos/module.nix (
          moduleArgs
          // {
            defaultPackage = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
          }
        );
    }
    // flake-utils.lib.eachSystem (import systems) (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
        rust = pkgs.rust-bin.stable."1.91.0".default.override {
          extensions = [
            "clippy"
            "rust-src"
            "rustfmt"
          ];
          targets = [ "x86_64-unknown-linux-musl" ];
        };
        rustPlatform = pkgs.makeRustPlatform {
          cargo = rust;
          rustc = rust;
        };
        # Expose musl-gcc without adding musl itself to the shell inputs.  A
        # direct musl build input injects its headers and libraries into host
        # build-script links, which breaks fresh cross-target builds.
        muslGcc = pkgs.writeShellScriptBin "musl-gcc" ''
          exec ${pkgs.musl.dev}/bin/musl-gcc "$@"
        '';
      in
      {
        packages.default = rustPlatform.buildRustPackage {
          pname = "iroh-sdwan";
          version = "0.1.0";
          src = self;
          cargoLock.lockFile = ./Cargo.lock;
          nativeBuildInputs = [
            pkgs.pkg-config
            pkgs.removeReferencesTo
          ];
          postInstall = ''
            # Rust embeds source paths used by panic locations. They are not
            # runtime dependencies and would otherwise retain the toolchain.
            remove-references-to -t ${rust} "$out/bin/iroh-sdwan"
            remove-references-to -t ${rust} "$out/bin/iroh-sdwand"
          '';
          doCheck = true;
          meta.mainProgram = "iroh-sdwan";
        };

        devShells.default = pkgs.mkShell {
          packages = [
            rust
            pkgs.cacert
            pkgs.git
            pkgs.iproute2
            pkgs.pkg-config
            pkgs.python3
          ];

          RUST_SRC_PATH = "${rust}/lib/rustlib/src/rust/library";
          shellHook = ''
            echo "iroh-sdwan dev shell"
            echo "  rustc:  $(rustc --version)"
          '';
        };

        devShells.static = pkgs.mkShell {
          packages = [
            rust
            muslGcc
            pkgs.binutils
            pkgs.dpkg
            pkgs.pkg-config
            pkgs.systemd
          ];

          CC_x86_64_unknown_linux_musl = "${muslGcc}/bin/musl-gcc";

          shellHook = ''
            echo "iroh-sdwan static release shell"
            echo "  scripts/build-deb.sh"
          '';
        };

        formatter = pkgs.nixfmt-rfc-style;
      }
    );
}
