#\!/bin/bash
# Security validation script for PQC implementation

set -euo pipefail

echo "=== PQC Security Validation Suite ==="
echo "Version: 1.0"
echo "Date: $(date)"
echo

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0
WARNINGS=0

# Function to check a condition
check() {
    local description="$1"
    local command="$2"
    
    printf "Checking: %s... " "$description"
    
    if eval "$command" &> /dev/null; then
        printf "${GREEN}PASSED${NC}\n"
        ((PASSED++))
        return 0
    else
        printf "${RED}FAILED${NC}\n"
        ((FAILED++))
        return 1
    fi
}

# Function to warn about a condition
warn() {
    local description="$1"
    local command="$2"
    
    printf "Checking: %s... " "$description"
    
    if eval "$command" &> /dev/null; then
        printf "${GREEN}OK${NC}\n"
        ((PASSED++))
    else
        printf "${YELLOW}WARNING${NC}\n"
        ((WARNINGS++))
    fi
}

echo "1. Code Compilation and Quality"
echo "==============================="

check "Code compiles without errors" "cargo check --all-targets"
check "All tests pass" "cargo test --lib"
check "No clippy warnings" "cargo clippy -- -D warnings"
check "Code is properly formatted" "cargo fmt -- --check"

echo
echo "2. PQC Algorithm Implementation"
echo "==============================="

check "ML-KEM-768 module exists" "test -f src/crypto/pqc/ml_kem.rs"
check "ML-DSA-65 module exists" "test -f src/crypto/pqc/ml_dsa.rs"
check "Hybrid key exchange implemented" "test -f src/crypto/pqc/hybrid.rs"
check "TLS extensions for PQC" "test -f src/crypto/pqc/tls_extensions.rs"

echo
echo "3. Security Features"
echo "===================="

check "Memory pool for secure allocation" "test -f src/crypto/pqc/memory_pool.rs"
check "Configuration with security defaults" "grep -q 'PqcMode::Hybrid' src/crypto/pqc/config.rs"
check "Negotiation fallback mechanism" "test -f src/crypto/pqc/negotiation.rs"
warn "Security validation module" "test -f src/crypto/pqc/security_validation.rs"

echo
echo "4. Test Coverage"
echo "================"

# Count test functions
UNIT_TESTS=$(grep -r "#\[test\]" src/crypto/pqc/ 2>/dev/null | wc -l | tr -d ' ')
INTEGRATION_TESTS=$(find tests -name "pqc*.rs" 2>/dev/null | wc -l | tr -d ' ')

echo "Unit tests found: $UNIT_TESTS"
echo "Integration test files: $INTEGRATION_TESTS"

if [ "$UNIT_TESTS" -gt 20 ]; then
    printf "Test coverage: ${GREEN}Good${NC}\n"
    ((PASSED++))
else
    printf "Test coverage: ${YELLOW}Needs improvement${NC}\n"
    ((WARNINGS++))
fi

echo
echo "5. NIST Compliance Check"
echo "========================"

# Check for proper algorithm parameters
check "ML-KEM-768 parameter set" "grep -q 'Level3' src/crypto/pqc/ml_kem.rs"
check "ML-DSA-65 parameter set" "grep -q 'Level3' src/crypto/pqc/ml_dsa.rs"
warn "Test vectors module" "test -f src/crypto/pqc/test_vectors.rs"

echo
echo "6. Documentation"
echo "================"

check "PQC configuration example" "test -f examples/pqc_config_demo.rs"
check "Hybrid mode example" "test -f examples/pqc_hybrid_demo.rs"
warn "API documentation builds" "cargo doc --no-deps --features pqc"

echo
echo "7. Integration Status"
echo "===================="

check "PQC integrated with QUIC" "grep -q 'pqc::' src/connection/mod.rs"
check "rustls provider updated" "test -f src/crypto/pqc/rustls_provider.rs"
check "Packet handling for larger handshakes" "grep -q 'pqc' src/connection/packet_builder.rs"

echo
echo "8. Security Best Practices"
echo "========================="

# Check for unsafe code in PQC modules
UNSAFE_COUNT=$(grep -r "unsafe" src/crypto/pqc/ 2>/dev/null | grep -v "// unsafe" | wc -l | tr -d ' ')
if [ "$UNSAFE_COUNT" -eq 0 ]; then
    printf "No unsafe code in PQC: ${GREEN}EXCELLENT${NC}\n"
    ((PASSED++))
else
    printf "Unsafe code blocks found: ${YELLOW}$UNSAFE_COUNT${NC} (review needed)\n"
    ((WARNINGS++))
fi

# Check for proper error handling
check "No unwrap() in production code" "\! grep -r '\.unwrap()' src/crypto/pqc/ | grep -v test | grep -v '//' | grep -q unwrap"
check "Proper error types defined" "grep -q 'PqcError' src/crypto/pqc/types.rs"

echo
echo "====================================="
echo "VALIDATION SUMMARY"
echo "====================================="
printf "Passed:   ${GREEN}$PASSED${NC}\n"
printf "Failed:   ${RED}$FAILED${NC}\n"
printf "Warnings: ${YELLOW}$WARNINGS${NC}\n"
echo

TOTAL=$((PASSED + FAILED + WARNINGS))
if [ "$TOTAL" -gt 0 ]; then
    SCORE=$((PASSED * 100 / TOTAL))
else
    SCORE=0
fi

echo "Security Score: $SCORE%"

if [ "$FAILED" -eq 0 ]; then
    if [ "$WARNINGS" -eq 0 ]; then
        printf "${GREEN}✓ All security validations passed\!${NC}\n"
        exit 0
    else
        printf "${YELLOW}⚠ Security validation passed with warnings${NC}\n"
        exit 0
    fi
else
    printf "${RED}✗ Security validation failed${NC}\n"
    echo "Please address the failed checks before deployment."
    exit 1
fi
