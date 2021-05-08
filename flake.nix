{
  description = "quinn";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, rust-overlay, utils, ... }:
    utils.lib.eachSystem (utils.lib.defaultSystems) (system: rec {
      # `nix develop`
      devShell = with import nixpkgs {
        system = "${system}";
        overlays = [ rust-overlay.overlay ];
      };
        mkShell {
          nativeBuildInputs = [
            # write rustfmt first to ensure we are using nightly rustfmt
            rust-bin.nightly."2021-01-01".rustfmt
            (rust-bin.stable.latest.default.override {
              extensions = [ "rust-src" ];
              targets = [ "x86_64-unknown-linux-musl" ];
            })
            rust-analyzer

            binutils-unwrapped
            cargo-cache
          ];
        };
    });
}
