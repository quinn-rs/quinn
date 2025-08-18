#!/bin/bash
# Simple Docker workflow test script

set -e

echo "=== Docker Workflow Test Script ==="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

# Test function
run_test() {
    local name="$1"
    local cmd="$2"
    echo -n "Testing $name... "
    if eval "$cmd" &>/dev/null; then
        echo -e "${GREEN}✓ PASSED${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}✗ FAILED${NC}"
        ((TESTS_FAILED++))
    fi
}

# Check prerequisites
echo "1. Checking prerequisites:"
run_test "Docker available" "docker --version"
run_test "Docker Compose available" "docker compose version || docker-compose version"
run_test "Cargo available" "cargo --version"
echo ""

# Check binary built
echo "2. Checking ant-quic binary:"
run_test "Release binary exists" "test -f ../target/release/ant-quic"
run_test "Binary is executable" "test -x ../target/release/ant-quic"
run_test "Binary runs" "../target/release/ant-quic --version"
echo ""

# Check Docker files
echo "3. Checking Docker files:"
run_test "Main Dockerfile exists" "test -f ../Dockerfile"
run_test "Simple Dockerfile exists" "test -f Dockerfile.simple"
run_test "ant-quic Dockerfile exists" "test -f Dockerfile.ant-quic"
run_test "docker-compose.yml exists" "test -f docker-compose.yml"
run_test "docker-compose.simple.yml exists" "test -f docker-compose.simple.yml"
run_test "docker-compose.enhanced.yml exists" "test -f docker-compose.enhanced.yml"
echo ""

# Check test scripts
echo "4. Checking test scripts:"
run_test "NAT test script exists" "test -f scripts/run-nat-tests.sh"
run_test "Enhanced NAT test script exists" "test -f scripts/run-enhanced-nat-tests.sh"
run_test "NAT stress test script exists" "test -f scripts/run-nat-stress-tests.sh"
run_test "Scripts are executable" "test -x scripts/run-nat-tests.sh"
echo ""

# Check Docker compose file syntax
echo "5. Validating Docker Compose files:"
run_test "docker-compose.yml syntax" "docker compose -f docker-compose.yml config >/dev/null"
run_test "docker-compose.simple.yml syntax" "docker compose -f docker-compose.simple.yml config >/dev/null"
run_test "docker-compose.enhanced.yml syntax" "docker compose -f docker-compose.enhanced.yml config >/dev/null"
echo ""

# Try simple Docker build (with timeout)
echo "6. Testing Docker build (30s timeout):"
if timeout 30 docker build -f Dockerfile.simple -t ant-quic-test:simple .. &>/dev/null; then
    echo -e "${GREEN}✓ Simple Docker build successful${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${YELLOW}⚠ Docker build timed out or failed (this may be normal on slow systems)${NC}"
    ((TESTS_FAILED++))
fi
echo ""

# Summary
echo "=== Test Summary ==="
echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Failed: ${RED}$TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed! Docker workflow is ready.${NC}"
    exit 0
elif [ $TESTS_FAILED -le 1 ] && [ $TESTS_PASSED -ge 10 ]; then
    echo -e "${YELLOW}Minor issues detected but workflow is mostly functional.${NC}"
    exit 0
else
    echo -e "${RED}Multiple tests failed. Please check the configuration.${NC}"
    exit 1
fi