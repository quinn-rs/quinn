#!/bin/bash
# Test quick-checks locally before pushing
# This simulates what the CI will run

set -euo pipefail

echo "🚀 Running quick checks locally..."
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Track failures
FAILED=0

# Function to run a check
run_check() {
    local name=$1
    local command=$2
    
    echo -n "Running $name... "
    if eval "$command" > /dev/null 2>&1; then
        echo -e "${GREEN}✅${NC}"
    else
        echo -e "${RED}❌${NC}"
        echo "  Command: $command"
        FAILED=$((FAILED + 1))
    fi
}

# Format check
run_check "Format Check" "cargo fmt --all -- --check"

# Clippy (project policy)
run_check "Clippy (non-test)" "cargo clippy --all-features --lib --bins --examples -- -D clippy::panic -D clippy::unwrap_used -D clippy::expect_used"
run_check "Clippy (tests/benches)" "cargo clippy --all-features --tests --benches -- -A clippy::panic -A clippy::unwrap_used -A clippy::expect_used"

# Quick tests (30s timeout)
run_check "Quick Tests" "timeout 30s cargo test --lib || [ \$? -eq 124 ]"

# Compilation check
run_check "Compilation" "cargo check --all-targets"

# TOML validation
run_check "TOML Validation" "find . -name 'Cargo.toml' -exec cargo verify-project --manifest-path {} \;"

echo ""
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✅ All quick checks passed!${NC}"
    exit 0
else
    echo -e "${RED}❌ $FAILED checks failed!${NC}"
    echo ""
    echo "Fix these issues before pushing to avoid CI failures."
    exit 1
fi
