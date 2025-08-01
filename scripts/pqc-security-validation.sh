#!/bin/bash
# PQC Security Validation Script
# Run this before any release to validate security standards

set -euo pipefail

echo "=== PQC Security Validation ==="
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track failures
FAILURES=0

# Function to check for patterns
check_pattern() {
    local pattern="$1"
    local description="$2"
    local severity="${3:-error}"
    
    echo -n "Checking for $description... "
    
    if grep -r "$pattern" src/crypto/pqc --include="*.rs" --exclude="*test*" --exclude="*bench*" 2>/dev/null | grep -v "^Binary file" > /dev/null; then
        if [ "$severity" = "error" ]; then
            echo -e "${RED}FAIL${NC}"
            echo "  Found instances of $description in PQC code:"
            grep -r "$pattern" src/crypto/pqc --include="*.rs" --exclude="*test*" --exclude="*bench*" -n 2>/dev/null | grep -v "^Binary file" | head -5
            ((FAILURES++))
        else
            echo -e "${YELLOW}WARNING${NC}"
            echo "  Found instances of $description in PQC code"
        fi
    else
        echo -e "${GREEN}PASS${NC}"
    fi
}

# 1. Check for unsafe code
echo "1. Memory Safety Checks"
echo -n "Checking for unsafe code blocks... "
if grep -r "unsafe" src/crypto/pqc --include="*.rs" 2>/dev/null | grep -v "^Binary file" > /dev/null; then
    echo -e "${RED}FAIL${NC}"
    echo "  Found unsafe code in PQC implementation:"
    grep -r "unsafe" src/crypto/pqc --include="*.rs" -n 2>/dev/null | grep -v "^Binary file"
    ((FAILURES++))
else
    echo -e "${GREEN}PASS${NC}"
fi

# 2. Check for unwrap() usage
echo
echo "2. Error Handling Checks"
check_pattern "\.unwrap()" "unwrap() calls (can panic)" "error"
check_pattern "\.expect(" "expect() calls (can panic)" "error"
check_pattern "panic!(" "panic! macros" "error"

# 3. Check for hardcoded secrets
echo
echo "3. Secret Management Checks"
check_pattern "0x[0-9a-fA-F]\{32,\}" "potential hardcoded secrets" "warning"
check_pattern "=\"[0-9a-fA-F]\{32,\}\"" "potential hardcoded keys" "warning"
check_pattern "b\"\[0-9a-fA-F\]\{32,\}\"" "potential hardcoded byte arrays" "warning"

# 4. Check for proper Drop implementations
echo
echo "4. Secure Memory Handling"
echo -n "Checking for Drop implementations on secret types... "
SECRET_TYPES=("MlKemSecretKey" "MlDsaSecretKey" "SharedSecret" "HybridKemSecretKey" "HybridSignatureSecretKey")
MISSING_DROP=0
for type in "${SECRET_TYPES[@]}"; do
    if ! grep -q "impl Drop for $type" src/crypto/pqc/types.rs; then
        echo -e "${RED}Missing Drop for $type${NC}"
        ((MISSING_DROP++))
    fi
done
if [ $MISSING_DROP -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC} - $MISSING_DROP types missing Drop implementation"
    ((FAILURES++))
fi

# 5. Check for proper input validation
echo
echo "5. Input Validation Checks"
check_pattern "as \[u8;" "unchecked array casts" "warning"
check_pattern "mem::transmute" "unsafe transmutes" "error"
check_pattern "slice::from_raw_parts" "raw pointer usage" "error"

# 6. Run cargo audit
echo
echo "6. Dependency Security Check"
echo -n "Running cargo audit... "
if cargo audit 2>&1 | grep -E "(Critical|High)" > /dev/null; then
    echo -e "${RED}FAIL${NC}"
    echo "  Found security vulnerabilities:"
    cargo audit 2>&1 | grep -E "(Critical|High)" | head -10
    ((FAILURES++))
else
    echo -e "${GREEN}PASS${NC}"
fi

# 7. Check for timing attack vulnerabilities
echo
echo "7. Side-Channel Attack Prevention"
check_pattern "if.*==.*secret\|secret.*==\|key.*==" "potential timing attacks in comparisons" "warning"

# 8. Check for proper error messages
echo
echo "8. Information Disclosure Prevention"
check_pattern "format!.*secret\|format!.*key\|println!.*secret" "secrets in error messages" "error"

# 9. Run clippy with security lints
echo
echo "9. Clippy Security Lints"
echo -n "Running clippy... "
if ! cargo clippy --manifest-path src/crypto/pqc/Cargo.toml 2>/dev/null -- \
    -W clippy::unwrap_used \
    -W clippy::expect_used \
    -W clippy::panic \
    -W clippy::unimplemented \
    -W clippy::todo \
    2>&1 | grep -q "warning"; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${YELLOW}WARNINGS${NC}"
    echo "  Run 'cargo clippy' to see all warnings"
fi

# 10. Check for test code in production
echo
echo "10. Test Code Isolation"
check_pattern "#\[cfg(test)\].*\n.*pub" "public items in test modules" "warning"
check_pattern "debug_assert!" "debug assertions (should use regular assert)" "warning"

# 11. Verify PQC implementations
echo
echo "11. PQC Implementation Status"
echo -n "Checking ML-KEM implementation... "
if grep -q "FeatureNotAvailable" src/crypto/pqc/ml_kem.rs; then
    echo -e "${YELLOW}PLACEHOLDER${NC} - Not yet implemented"
else
    echo -e "${GREEN}IMPLEMENTED${NC}"
fi

echo -n "Checking ML-DSA implementation... "
if grep -q "FeatureNotAvailable" src/crypto/pqc/ml_dsa.rs; then
    echo -e "${YELLOW}PLACEHOLDER${NC} - Not yet implemented"
else
    echo -e "${GREEN}IMPLEMENTED${NC}"
fi

# Summary
echo
echo "=== Summary ==="
if [ $FAILURES -eq 0 ]; then
    echo -e "${GREEN}All security checks passed!${NC}"
    exit 0
else
    echo -e "${RED}Found $FAILURES security issues that must be fixed${NC}"
    exit 1
fi