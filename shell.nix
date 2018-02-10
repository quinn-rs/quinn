with import <nixpkgs> { };
stdenv.mkDerivation {
  name = "quicr";
  buildInputs = with pkgs; [ rust-nightly ];
  shellHook = ''
    export CARGO_INCREMENTAL=1
  '';
}
