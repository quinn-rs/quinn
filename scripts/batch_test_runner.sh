#!/bin/bash
# Batch Test Runner for ant-quic
# Runs tests in smaller batches to avoid timeouts

set -euo pipefail

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Results directory
RESULTS_DIR="target/test-results"
mkdir -p "$RESULTS_DIR"

echo -e "${BLUE}=== ANT-QUIC Batch Test Runner ===${NC}"
echo "Started at: $(date)"

# Function to run a test batch
run_batch() {
    local name=$1
    local pattern=$2
    local log_file="$RESULTS_DIR/${name}.log"
    
    echo -e "${YELLOW}Running $name...${NC}"
    if cargo test --all-features "$pattern" -- --test-threads=4 > "$log_file" 2>&1; then
        local passed=$(grep -E "test result: ok" "$log_file" | grep -oE "[0-9]+ passed" | grep -oE "[0-9]+" || echo "0")
        echo -e "${GREEN}✓ $name: $passed tests passed${NC}"
        return 0
    else
        echo -e "${RED}✗ $name: Some tests failed${NC}"
        return 1
    fi
}

# Track overall status
FAILED_BATCHES=0

# Run unit tests by module
echo -e "\n${BLUE}=== Unit Tests ===${NC}"
run_batch "unit-connection" "connection::" || ((FAILED_BATCHES++))
run_batch "unit-crypto" "crypto::" || ((FAILED_BATCHES++))
run_batch "unit-frame" "frame::" || ((FAILED_BATCHES++))
run_batch "unit-transport" "transport_parameters::" || ((FAILED_BATCHES++))
run_batch "unit-nat" "nat_traversal::" || ((FAILED_BATCHES++))
run_batch "unit-candidate" "candidate_discovery::" || ((FAILED_BATCHES++))
run_batch "unit-other" "" || ((FAILED_BATCHES++))

# Run integration tests
echo -e "\n${BLUE}=== Integration Tests ===${NC}"
run_batch "integration-nat" "--test nat_" || ((FAILED_BATCHES++))
run_batch "integration-auth" "--test auth_" || ((FAILED_BATCHES++))
run_batch "integration-address" "--test address_" || ((FAILED_BATCHES++))
run_batch "integration-pqc" "--test '*pqc*' --test '*ml_*'" || ((FAILED_BATCHES++))

# Run quick tests
echo -e "\n${BLUE}=== Quick Tests ===${NC}"
if cargo test --all-features --test quick 2>&1 | tee "$RESULTS_DIR/quick-tests.log"; then
    echo -e "${GREEN}✓ Quick tests passed${NC}"
else
    echo -e "${RED}✗ Quick tests failed${NC}"
    ((FAILED_BATCHES++))
fi

# Summary
echo -e "\n${BLUE}=== Test Summary ===${NC}"
echo "Failed test batches: $FAILED_BATCHES"
echo "Logs available in: $RESULTS_DIR/"

# Generate summary report
{
    echo "# Batch Test Results"
    echo "Generated: $(date)"
    echo ""
    echo "## Results by Module"
    for log in "$RESULTS_DIR"/*.log; do
        if [ -f "$log" ]; then
            name=$(basename "$log" .log)
            if grep -q "test result: ok" "$log" 2>/dev/null; then
                passed=$(grep -E "test result: ok" "$log" | grep -oE "[0-9]+ passed" | grep -oE "[0-9]+" || echo "0")
                echo "- ✓ $name: $passed tests passed"
            else
                echo "- ✗ $name: Failed or incomplete"
            fi
        fi
    done
    echo ""
    echo "## Overall Status"
    if [ $FAILED_BATCHES -eq 0 ]; then
        echo "All test batches passed successfully!"
    else
        echo "$FAILED_BATCHES test batches failed. Check individual logs for details."
    fi
} > "$RESULTS_DIR/batch-summary.md"

echo -e "${GREEN}Summary saved to: $RESULTS_DIR/batch-summary.md${NC}"

exit $FAILED_BATCHES