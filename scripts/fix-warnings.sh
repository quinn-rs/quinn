#!/bin/bash
# Script to identify and help fix warnings/errors in ant-quic

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BLUE}=== ANT-QUIC Warning/Error Finder ===${NC}"
echo

# 1. Find all unused variables
echo -e "${YELLOW}1. Finding unused variables...${NC}"
RUSTFLAGS="-D warnings" cargo build --all-targets 2>&1 | grep -E "unused variable:|help: if this is intentional" | sort | uniq || true
echo

# 2. Find all dead code
echo -e "${YELLOW}2. Finding dead code...${NC}"
RUSTFLAGS="-D warnings" cargo build --all-targets 2>&1 | grep -E "is never (read|used|constructed)|dead_code" | sort | uniq || true
echo

# 3. Find all clippy issues
echo -e "${YELLOW}3. Finding clippy issues...${NC}"
cargo clippy --all-targets --all-features -- -D warnings 2>&1 | grep -E "error:|warning:" | sort | uniq || true
echo

# 4. Find #[allow] patterns
echo -e "${YELLOW}4. Finding #[allow] patterns...${NC}"
grep -rn "#\[allow" src/ --include="*.rs" | while read -r line; do
    echo -e "${CYAN}$line${NC}"
done
echo

# 5. Find cfg issues
echo -e "${YELLOW}5. Finding unexpected cfg conditions...${NC}"
RUSTFLAGS="-D warnings" cargo build --all-targets 2>&1 | grep -E "unexpected.*cfg.*condition" -A2 | head -20 || true
echo

# 6. Create fix summary
echo -e "${BLUE}=== Fix Summary ===${NC}"
echo "To fix these issues:"
echo "1. Prefix unused variables with underscore: let _var = ..."
echo "2. Remove dead code or mark fields/functions as pub(crate) if needed internally"
echo "3. Fix clippy suggestions (usually shown with 'help:' lines)"
echo "4. Replace #[allow(dead_code)] with proper visibility or remove unused code"
echo "5. Fix cfg conditions by adding features to Cargo.toml or removing invalid conditions"
echo

# 7. Quick stats
ALLOW_COUNT=$(grep -r "#\[allow" src/ --include="*.rs" | wc -l)
echo -e "${YELLOW}Statistics:${NC}"
echo "- #[allow] patterns in src/: $ALLOW_COUNT"
echo

# 8. Generate fix commands
echo -e "${BLUE}=== Suggested Fix Commands ===${NC}"
echo "# Auto-fix formatting:"
echo "cargo fmt --all"
echo
echo "# Auto-fix some clippy issues:"
echo "cargo clippy --all-targets --all-features --fix"
echo
echo "# Find specific patterns:"
echo "grep -rn 'pattern' src/ tests/ examples/"
echo