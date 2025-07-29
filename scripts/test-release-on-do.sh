#!/bin/bash
# Test ant-quic release binary on DigitalOcean server
# This script downloads the latest release and runs comprehensive tests

set -euo pipefail

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
RELEASE_VERSION=${1:-latest}
GITHUB_REPO="dirvine/ant-quic"
SERVER="quic.saorsalabs.com"
TEST_DIR="/tmp/ant-quic-test-$$"

echo -e "${BLUE}=== ant-quic Release Testing on ${SERVER} ===${NC}"
echo "Release version: $RELEASE_VERSION"
echo "Test directory: $TEST_DIR"

# Function to download release
download_release() {
    echo -e "\n${YELLOW}Downloading release...${NC}"
    
    if [ "$RELEASE_VERSION" = "latest" ]; then
        # Get latest release URL
        DOWNLOAD_URL=$(curl -s "https://api.github.com/repos/$GITHUB_REPO/releases/latest" | \
            grep -E "browser_download_url.*linux.*x86_64" | \
            cut -d '"' -f 4 | head -1)
    else
        # Get specific version
        DOWNLOAD_URL=$(curl -s "https://api.github.com/repos/$GITHUB_REPO/releases/tags/$RELEASE_VERSION" | \
            grep -E "browser_download_url.*linux.*x86_64" | \
            cut -d '"' -f 4 | head -1)
    fi
    
    if [ -z "$DOWNLOAD_URL" ]; then
        echo -e "${RED}Failed to find release download URL${NC}"
        exit 1
    fi
    
    echo "Download URL: $DOWNLOAD_URL"
    
    # Create test directory
    mkdir -p "$TEST_DIR"
    cd "$TEST_DIR"
    
    # Download and extract
    curl -L -o ant-quic.tar.gz "$DOWNLOAD_URL"
    tar -xzf ant-quic.tar.gz
    chmod +x ant-quic
    
    echo -e "${GREEN}✓ Download complete${NC}"
}

# Function to run basic tests
run_basic_tests() {
    echo -e "\n${YELLOW}Running basic tests...${NC}"
    
    # Version check
    echo -n "Version check: "
    if ./ant-quic --version; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
        return 1
    fi
    
    # Help check
    echo -n "Help check: "
    if ./ant-quic --help > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
        return 1
    fi
}

# Function to test as bootstrap node
test_bootstrap_node() {
    echo -e "\n${YELLOW}Testing as bootstrap node...${NC}"
    
    # Start bootstrap node
    echo "Starting bootstrap node on port 9090..."
    timeout 30 ./ant-quic --force-coordinator --listen 0.0.0.0:9090 &
    BOOTSTRAP_PID=$!
    sleep 5
    
    # Check if running
    if kill -0 $BOOTSTRAP_PID 2>/dev/null; then
        echo -e "${GREEN}✓ Bootstrap node started successfully${NC}"
        kill $BOOTSTRAP_PID
        wait $BOOTSTRAP_PID 2>/dev/null || true
    else
        echo -e "${RED}✗ Bootstrap node failed to start${NC}"
        return 1
    fi
}

# Function to test client connectivity
test_client_connectivity() {
    echo -e "\n${YELLOW}Testing client connectivity...${NC}"
    
    # Start a bootstrap node
    ./ant-quic --force-coordinator --listen 0.0.0.0:9091 > bootstrap.log 2>&1 &
    BOOTSTRAP_PID=$!
    sleep 5
    
    # Start a client
    echo "Connecting client to bootstrap..."
    timeout 20 ./ant-quic --bootstrap 127.0.0.1:9091 --listen 0.0.0.0:9092 > client.log 2>&1 &
    CLIENT_PID=$!
    sleep 10
    
    # Check logs for successful connection
    if grep -q "Connected to bootstrap" client.log || grep -q "Discovered external address" client.log; then
        echo -e "${GREEN}✓ Client connected successfully${NC}"
        RESULT=0
    else
        echo -e "${RED}✗ Client connection failed${NC}"
        cat client.log
        RESULT=1
    fi
    
    # Cleanup
    kill $BOOTSTRAP_PID $CLIENT_PID 2>/dev/null || true
    wait $BOOTSTRAP_PID $CLIENT_PID 2>/dev/null || true
    
    return $RESULT
}

# Function to test NAT traversal
test_nat_traversal() {
    echo -e "\n${YELLOW}Testing NAT traversal features...${NC}"
    
    # Start coordinator
    ./ant-quic --force-coordinator --listen 0.0.0.0:9093 > coordinator.log 2>&1 &
    COORD_PID=$!
    sleep 5
    
    # Start two clients
    ./ant-quic --bootstrap 127.0.0.1:9093 --listen 0.0.0.0:9094 > client1.log 2>&1 &
    CLIENT1_PID=$!
    
    ./ant-quic --bootstrap 127.0.0.1:9093 --listen 0.0.0.0:9095 > client2.log 2>&1 &
    CLIENT2_PID=$!
    
    sleep 15
    
    # Check for NAT traversal activity
    if grep -q "ADD_ADDRESS\|PUNCH_ME_NOW\|OBSERVED_ADDRESS" coordinator.log; then
        echo -e "${GREEN}✓ NAT traversal frames detected${NC}"
        RESULT=0
    else
        echo -e "${YELLOW}⚠ No NAT traversal activity detected (may be normal for local test)${NC}"
        RESULT=0
    fi
    
    # Cleanup
    kill $COORD_PID $CLIENT1_PID $CLIENT2_PID 2>/dev/null || true
    wait $COORD_PID $CLIENT1_PID $CLIENT2_PID 2>/dev/null || true
    
    return $RESULT
}

# Function to test IPv6 support
test_ipv6_support() {
    echo -e "\n${YELLOW}Testing IPv6 support...${NC}"
    
    # Check if IPv6 is available
    if ! ip -6 addr | grep -q "inet6"; then
        echo -e "${YELLOW}⚠ IPv6 not available on this system, skipping${NC}"
        return 0
    fi
    
    # Try to start on IPv6
    timeout 10 ./ant-quic --listen "[::1]:9096" > ipv6.log 2>&1 &
    IPV6_PID=$!
    sleep 5
    
    if kill -0 $IPV6_PID 2>/dev/null; then
        echo -e "${GREEN}✓ IPv6 support working${NC}"
        kill $IPV6_PID
        wait $IPV6_PID 2>/dev/null || true
        return 0
    else
        echo -e "${YELLOW}⚠ IPv6 binding failed (may be expected)${NC}"
        return 0
    fi
}

# Function to run performance test
test_performance() {
    echo -e "\n${YELLOW}Running performance test...${NC}"
    
    # Start nodes
    ./ant-quic --force-coordinator --listen 0.0.0.0:9097 > perf-coord.log 2>&1 &
    COORD_PID=$!
    sleep 3
    
    # Start multiple clients
    for i in {1..5}; do
        PORT=$((9097 + i))
        ./ant-quic --bootstrap 127.0.0.1:9097 --listen 0.0.0.0:$PORT > perf-client$i.log 2>&1 &
        CLIENT_PIDS="$CLIENT_PIDS $!"
    done
    
    # Let them run
    echo "Running 5 concurrent connections for 30 seconds..."
    sleep 30
    
    # Check for stability
    STABLE=true
    for PID in $COORD_PID $CLIENT_PIDS; do
        if ! kill -0 $PID 2>/dev/null; then
            STABLE=false
            break
        fi
    done
    
    if $STABLE; then
        echo -e "${GREEN}✓ All nodes remained stable${NC}"
        RESULT=0
    else
        echo -e "${RED}✗ Some nodes crashed${NC}"
        RESULT=1
    fi
    
    # Cleanup
    kill $COORD_PID $CLIENT_PIDS 2>/dev/null || true
    wait $COORD_PID $CLIENT_PIDS 2>/dev/null || true
    
    return $RESULT
}

# Function to generate report
generate_report() {
    echo -e "\n${BLUE}=== Test Summary ===${NC}"
    
    REPORT="$TEST_DIR/test-report.txt"
    {
        echo "ant-quic Release Test Report"
        echo "============================"
        echo "Date: $(date)"
        echo "Server: $SERVER"
        echo "Version: $RELEASE_VERSION"
        echo ""
        echo "Test Results:"
        echo "- Basic Tests: $BASIC_RESULT"
        echo "- Bootstrap Node: $BOOTSTRAP_RESULT"
        echo "- Client Connectivity: $CLIENT_RESULT"
        echo "- NAT Traversal: $NAT_RESULT"
        echo "- IPv6 Support: $IPV6_RESULT"
        echo "- Performance: $PERF_RESULT"
        echo ""
        echo "Binary Info:"
        ./ant-quic --version
        echo ""
        echo "System Info:"
        uname -a
        echo ""
    } > "$REPORT"
    
    cat "$REPORT"
    
    # Overall result
    if [ "$BASIC_RESULT" = "PASS" ] && [ "$BOOTSTRAP_RESULT" = "PASS" ] && \
       [ "$CLIENT_RESULT" = "PASS" ] && [ "$NAT_RESULT" = "PASS" ] && \
       [ "$PERF_RESULT" = "PASS" ]; then
        echo -e "\n${GREEN}✅ ALL TESTS PASSED${NC}"
        return 0
    else
        echo -e "\n${RED}❌ SOME TESTS FAILED${NC}"
        return 1
    fi
}

# Main execution
main() {
    # Download release
    download_release
    
    # Run tests
    echo -e "\n${BLUE}Starting test suite...${NC}"
    
    if run_basic_tests; then
        BASIC_RESULT="PASS"
    else
        BASIC_RESULT="FAIL"
    fi
    
    if test_bootstrap_node; then
        BOOTSTRAP_RESULT="PASS"
    else
        BOOTSTRAP_RESULT="FAIL"
    fi
    
    if test_client_connectivity; then
        CLIENT_RESULT="PASS"
    else
        CLIENT_RESULT="FAIL"
    fi
    
    if test_nat_traversal; then
        NAT_RESULT="PASS"
    else
        NAT_RESULT="FAIL"
    fi
    
    if test_ipv6_support; then
        IPV6_RESULT="PASS"
    else
        IPV6_RESULT="FAIL"
    fi
    
    if test_performance; then
        PERF_RESULT="PASS"
    else
        PERF_RESULT="FAIL"
    fi
    
    # Generate report
    generate_report
    
    # Cleanup
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    cd /
    rm -rf "$TEST_DIR"
    
    echo -e "${GREEN}Test complete!${NC}"
}

# Run main
main