with import <nixpkgs> { };
in stdenv.mkDerivation {
  name = "quicr";
  buildInputs = with pkgs; [ rustChannels.stable.rust ];
  shellHook = ''
    export CARGO_INCREMENTAL=1
    export RUST_BACKTRACE=1
  '';
}
