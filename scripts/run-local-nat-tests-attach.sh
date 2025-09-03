#!/usr/bin/env bash
set -euo pipefail

# Convenience wrapper to run local NAT tests with client reachability attached
# Usage:
#   scripts/run-local-nat-tests-attach.sh [smoke|nat|all]
#
# Sets LOCAL_NAT_ATTACH=1 so the test harness connects clients to the
# docker_internet network for direct reachability in local runs.

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
export LOCAL_NAT_ATTACH=1

exec bash "$ROOT_DIR/scripts/run-local-nat-tests.sh" "$@"
