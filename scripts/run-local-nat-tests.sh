#!/usr/bin/env bash
set -euo pipefail

# Local NAT traversal test runner
# Usage:
#   scripts/run-local-nat-tests.sh [smoke|nat|all]
# Defaults to 'nat'. Exits non-zero on failure.

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT_DIR/docker"

SUITE=${1:-nat}

# Ensure directories exist
mkdir -p results logs shared
chmod +x scripts/*.sh

case "$SUITE" in
  smoke)
    ./scripts/run-enhanced-nat-tests.sh test_basic_connectivity ;;
  nat)
    ./scripts/run-enhanced-nat-tests.sh test_nat_traversal ;;
  all)
    ./scripts/run-enhanced-nat-tests.sh ;; # full suite
  *)
    echo "Unknown suite: $SUITE" >&2
    exit 2 ;;

esac

# Evaluate status file
if [[ ! -f results/status ]]; then
  echo "No status file found; assuming failure" >&2
  exit 1
fi

STATUS=$(cat results/status)
echo "Local NAT tests status: $STATUS"
if [[ "$STATUS" != "PASS" ]]; then
  echo "Local NAT tests failed." >&2
  exit 1
fi

exit 0
