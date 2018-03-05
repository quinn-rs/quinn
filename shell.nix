with import <nixpkgs> { };
let
openssl-pre = openssl_1_1_0.overrideAttrs (old: rec {
  name = "openssl-${version}";
  version = "1.1.1-pre";
  src = fetchFromGitHub {
    owner = "openssl";
    repo = "openssl";
    rev = "1c5b57bc0ae5e2d0efc245cd8dd227ea4a0a41f2";
    sha256 = "1i3dxszqm9ykqb5bdib9ji0f841gnfpbcxxn8mlwb52zpjn149k4";
  };
  patches = [];
});
in stdenv.mkDerivation {
  name = "quicr";
  buildInputs = with pkgs; [ rust-nightly pkgconfig openssl-pre ];
  shellHook = ''
    export CARGO_INCREMENTAL=1
  '';
}
