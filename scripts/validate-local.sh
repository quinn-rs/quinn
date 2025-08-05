#!/bin/bash
# Local validation script for ant-quic
# Ensures 100% clean build with zero warnings/errors

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== ANT-QUIC Local Validation ===${NC}"
echo

# Track overall status
OVERALL_STATUS=0

# Function to run a check
run_check() {
    local name=$1
    local command=$2
    
    echo -e "${YELLOW}Running: $name${NC}"
    if eval "$command"; then
        echo -e "${GREEN}✓ $name passed${NC}\n"
    else
        echo -e "${RED}✗ $name failed${NC}\n"
        OVERALL_STATUS=1
    fi
}

# 1. Format check
run_check "Cargo format check" "cargo fmt --all -- --check"

# 2. Build with all warnings as errors
run_check "Build (warnings as errors)" "RUSTFLAGS='-D warnings' cargo build --all-targets"

# 3. Clippy with all warnings as errors
run_check "Clippy (strict)" "cargo clippy --all-targets --all-features -- -D warnings"

# 4. Test compilation
run_check "Test compilation" "cargo test --all-features --no-run"

# 5. Doc tests
run_check "Documentation build" "cargo doc --no-deps --all-features"

# 6. Check for #[allow] patterns
echo -e "${YELLOW}Checking for #[allow] patterns...${NC}"
ALLOW_COUNT=$(grep -r "#\[allow" src/ --include="*.rs" | wc -l)
if [ $ALLOW_COUNT -gt 0 ]; then
    echo -e "${RED}✗ Found $ALLOW_COUNT #[allow] patterns in src/${NC}"
    grep -r "#\[allow" src/ --include="*.rs" | head -10
    echo "..."
    OVERALL_STATUS=1
else
    echo -e "${GREEN}✓ No #[allow] patterns in src/${NC}"
fi
echo

# 7. Check for todo/fixme comments
echo -e "${YELLOW}Checking for TODO/FIXME comments...${NC}"
TODO_COUNT=$(grep -r "TODO\|FIXME" src/ --include="*.rs" | wc -l)
if [ $TODO_COUNT -gt 0 ]; then
    echo -e "${YELLOW}⚠ Found $TODO_COUNT TODO/FIXME comments${NC}"
    grep -r "TODO\|FIXME" src/ --include="*.rs" | head -5
    echo "..."
fi
echo

# 8. Check dependencies
run_check "Dependency check" "cargo tree --duplicates | wc -l | xargs -I {} test {} -eq 0"

# 9. Security audit (if cargo-audit is installed)
if command -v cargo-audit &> /dev/null; then
    run_check "Security audit" "cargo audit"
fi

# 10. Check examples compile
run_check "Examples compilation" "cargo build --examples"

# Summary
echo -e "${BLUE}=== Validation Summary ===${NC}"
if [ $OVERALL_STATUS -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed!${NC}"
    echo -e "${GREEN}Ready for GitHub workflows.${NC}"
else
    echo -e "${RED}✗ Some checks failed!${NC}"
    echo -e "${RED}Please fix the issues before pushing.${NC}"
    exit 1
fi

# Optional: Run quick tests
echo
read -p "Run quick tests? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    cargo test --all-features -- --test-threads=4
fi