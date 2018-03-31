with import <nixpkgs> { };
let
openssl-pre = openssl_1_1_0.overrideAttrs (old: rec {
  name = "openssl-${version}";
  version = "1.1.1-pre3";
  src = fetchFromGitHub {
    owner = "openssl";
    repo = "openssl";
    rev = "OpenSSL_1_1_1-pre3";
    sha256 = "154xqi3v75kzzggwcji74jjn0iy78f7v7m3059125vb3fwk1pfrn";
  };
  patches = [];
  # dontStrip = true;
  # separateDebugInfo = false;
  # configureFlags = old.configureFlags ++ ["--debug"];
  # hardeningDisable = [ "fortify" ];
  # setSourceRoot = ''
  #   mkdir -p $out
  #   for i in *;
  #   do
  #       if [ -d "$i" ]; then
  #           case $dirsBefore in
  #               *\ $i\ *)

  #               ;;
  #               *)
  #                   if [ -n "$sourceRoot" ]; then
  #                       echo "unpacker produced multiple directories";
  #                       exit 1;
  #                   fi;
  #                   sourceRoot="$i"
  #               ;;
  #           esac;
  #       fi;
  #   done;
  #   cp -rpT $sourceRoot $out/src
  #   sourceRoot=$out/src
  # '';
  # postInstall = ''
  #   ${old.postInstall}
  #   make distclean
  # '';
  # postFixup = null;
});
in stdenv.mkDerivation {
  name = "quicr";
  buildInputs = with pkgs; [ rust-nightly pkgconfig openssl-pre ];
  shellHook = ''
    export CARGO_INCREMENTAL=1
  '';
}
