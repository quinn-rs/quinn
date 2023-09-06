#!/usr/bin/env -S bash -eu

CURDIR=$(pwd)

mkdir -p ./target

cd ../..
cargo build -p perf --release
cp -au ./target/release/perf_server ./target/release/perf_client ${CURDIR}/target

cd ${CURDIR}
docker compose build
