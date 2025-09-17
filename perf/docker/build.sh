#!/usr/bin/env -S bash -eu

CURDIR=$(pwd)
TOKIO_CONSOLE=0

function usage() {
	echo "usage: $0 [-t]"
	echo "  -t      enable tokio console"
	exit 1
}

while getopts "t" opt; do
	case $opt in
		t) TOKIO_CONSOLE=1;;
		h) usage;;
		*) usage;;
	esac
done

mkdir -p ./target

cd ../..

if [ ${TOKIO_CONSOLE} -eq 0 ]; then
	cargo build -p perf --release
else
	echo "Building with tokio console support"
	RUSTFLAGS="--cfg tokio_unstable" cargo build -p perf -r -F tokio-console
fi


cp -au ./target/release/quinn-perf ${CURDIR}/target

cd ${CURDIR}
docker compose build
