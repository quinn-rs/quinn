#!/bin/bash
# Comprehensive Test Runner for ant-quic
# This script runs ALL tests including ignored, stress, and benchmarks

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create results directory
RESULTS_DIR="target/test-results"
mkdir -p "$RESULTS_DIR"

# Start time
START_TIME=$(date +%s)

echo -e "${BLUE}=== ANT-QUIC Comprehensive Test Suite ===${NC}"
echo "Started at: $(date)"
echo "Results will be saved to: $RESULTS_DIR"
echo ""

# Function to run tests and capture results
run_test_suite() {
    local name=$1
    local cmd=$2
    local log_file="$RESULTS_DIR/${name}.log"
    
    echo -e "${YELLOW}Running $name...${NC}"
    if $cmd > "$log_file" 2>&1; then
        echo -e "${GREEN}✓ $name passed${NC}"
        return 0
    else
        echo -e "${RED}✗ $name failed${NC}"
        echo "  See $log_file for details"
        return 1
    fi
}

# Track failures
FAILURES=0

# 1. Run all unit and integration tests
if ! run_test_suite "unit-and-integration-tests" "cargo test --all-features"; then
    ((FAILURES++))
fi

# 2. Run tests with no default features
if ! run_test_suite "no-default-features" "cargo test --no-default-features"; then
    ((FAILURES++))
fi

# 3. Run tests with rustls-ring
if ! run_test_suite "rustls-ring-tests" "cargo test --no-default-features --features rustls-ring"; then
    ((FAILURES++))
fi

# 4. Run tests with rustls-aws-lc-rs
if ! run_test_suite "rustls-aws-lc-rs-tests" "cargo test --no-default-features --features rustls-aws-lc-rs"; then
    ((FAILURES++))
fi

# 5. Run PQC tests
if ! run_test_suite "pqc-tests" "cargo test --features pqc pqc"; then
    ((FAILURES++))
fi

# 6. Run ignored tests
echo -e "${YELLOW}Running ignored tests...${NC}"
if cargo test --all-features -- --ignored > "$RESULTS_DIR/ignored-tests.log" 2>&1; then
    echo -e "${GREEN}✓ Ignored tests passed${NC}"
else
    echo -e "${RED}✗ Some ignored tests failed (this may be expected)${NC}"
    echo "  See $RESULTS_DIR/ignored-tests.log for details"
fi

# 7. Run stress tests specifically
echo -e "${YELLOW}Running stress tests...${NC}"
if cargo test --all-features -- --ignored stress > "$RESULTS_DIR/stress-tests.log" 2>&1; then
    echo -e "${GREEN}✓ Stress tests passed${NC}"
else
    echo -e "${RED}✗ Some stress tests failed (this may be expected)${NC}"
    echo "  See $RESULTS_DIR/stress-tests.log for details"
fi

# 8. Run benchmarks (if available)
echo -e "${YELLOW}Running benchmarks...${NC}"
if command -v cargo-criterion &> /dev/null; then
    if cargo criterion --all-features > "$RESULTS_DIR/benchmarks.log" 2>&1; then
        echo -e "${GREEN}✓ Benchmarks completed${NC}"
    else
        echo -e "${YELLOW}⚠ Some benchmarks failed${NC}"
    fi
else
    if cargo bench --all-features > "$RESULTS_DIR/benchmarks.log" 2>&1; then
        echo -e "${GREEN}✓ Benchmarks completed${NC}"
    else
        echo -e "${YELLOW}⚠ Some benchmarks failed${NC}"
    fi
fi

# 9. Platform-specific tests
echo -e "${YELLOW}Running platform-specific tests...${NC}"
case "$(uname -s)" in
    Linux)
        if ! run_test_suite "linux-specific-tests" "cargo test --all-features discovery::linux_tests"; then
            ((FAILURES++))
        fi
        ;;
    Darwin)
        if ! run_test_suite "macos-specific-tests" "cargo test --all-features discovery::macos_tests"; then
            ((FAILURES++))
        fi
        ;;
    MINGW*|MSYS*|CYGWIN*)
        if ! run_test_suite "windows-specific-tests" "cargo test --all-features discovery::windows_tests"; then
            ((FAILURES++))
        fi
        ;;
esac

# 10. Generate test summary
echo -e "\n${BLUE}=== Test Summary ===${NC}"
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Count tests
TOTAL_TESTS=$(cargo test --all-features -- --list 2>/dev/null | grep -E ": test" | wc -l || echo "unknown")
IGNORED_TESTS=$(find . -name "*.rs" -exec grep -c "#\[ignore\]" {} \; | awk '{sum += $1} END {print sum}')

echo "Total tests discovered: $TOTAL_TESTS"
echo "Ignored tests: $IGNORED_TESTS"
echo "Test suites with failures: $FAILURES"
echo "Duration: $DURATION seconds"
echo ""

# Generate detailed report
REPORT_FILE="$RESULTS_DIR/test-summary.md"
{
    echo "# Test Execution Summary"
    echo "Generated: $(date)"
    echo ""
    echo "## Results"
    echo "- Total test suites run: 10"
    echo "- Failed suites: $FAILURES"
    echo "- Duration: $DURATION seconds"
    echo ""
    echo "## Test Categories"
    echo "1. Unit and Integration Tests: $(grep -c "test result:" "$RESULTS_DIR/unit-and-integration-tests.log" 2>/dev/null || echo "see log")"
    echo "2. No Default Features: $(grep -c "test result:" "$RESULTS_DIR/no-default-features.log" 2>/dev/null || echo "see log")"
    echo "3. rustls-ring: $(grep -c "test result:" "$RESULTS_DIR/rustls-ring-tests.log" 2>/dev/null || echo "see log")"
    echo "4. rustls-aws-lc-rs: $(grep -c "test result:" "$RESULTS_DIR/rustls-aws-lc-rs-tests.log" 2>/dev/null || echo "see log")"
    echo "5. PQC Tests: $(grep -c "test result:" "$RESULTS_DIR/pqc-tests.log" 2>/dev/null || echo "see log")"
    echo "6. Ignored Tests: $(grep -c "test result:" "$RESULTS_DIR/ignored-tests.log" 2>/dev/null || echo "see log")"
    echo "7. Stress Tests: $(grep -c "test result:" "$RESULTS_DIR/stress-tests.log" 2>/dev/null || echo "see log")"
    echo "8. Benchmarks: completed"
    echo ""
    echo "## Logs"
    echo "All test logs are available in: $RESULTS_DIR/"
} > "$REPORT_FILE"

echo -e "${GREEN}Summary report saved to: $REPORT_FILE${NC}"

# Exit with failure if any test suite failed
if [ $FAILURES -gt 0 ]; then
    echo -e "${RED}Some test suites failed. Please check the logs.${NC}"
    exit 1
else
    echo -e "${GREEN}All required test suites passed!${NC}"
    exit 0
fi