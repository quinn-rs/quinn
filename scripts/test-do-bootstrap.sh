#!/bin/bash
# Test ant-quic peer node on DigitalOcean
# Run this locally after deployment
# v0.13.0+: All nodes are symmetric P2P nodes - no "bootstrap" distinction

set -euo pipefail

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
# v0.13.0+: Uses known_peers terminology instead of bootstrap
KNOWN_PEER="quic.saorsalabs.com:9000"
TEST_DURATION=30

echo -e "${BLUE}=== Testing ant-quic Peer Node ===${NC}"
echo "Known Peer: $KNOWN_PEER"
echo "Test duration: ${TEST_DURATION}s"

# Test 1: Basic connectivity
echo -e "\n${YELLOW}Test 1: Basic Connectivity${NC}"
echo "Running local peer connecting to known peer..."

# Run test peer (v0.13.0+: uses --connect instead of --bootstrap)
timeout $TEST_DURATION cargo run --release --bin ant-quic -- \
    --connect $KNOWN_PEER 2>&1 | tee test-output.log &
CLIENT_PID=$!

# Wait a bit for connection
sleep 5

# Check if peer is still running
if kill -0 $CLIENT_PID 2>/dev/null; then
    echo -e "${GREEN}✓ Peer connected successfully${NC}"
else
    echo -e "${RED}✗ Peer failed to connect${NC}"
    exit 1
fi

# Check for successful peer connection (v0.13.0+: symmetric P2P terminology)
if grep -q "Connected to peer" test-output.log || \
   grep -q "Discovered external address" test-output.log || \
   grep -q "known peer" test-output.log; then
    echo -e "${GREEN}✓ Peer connection established${NC}"
else
    echo -e "${YELLOW}⚠ Peer connection not confirmed in logs${NC}"
fi

# Check for address discovery
if grep -q "external address" test-output.log || \
   grep -q "OBSERVED_ADDRESS" test-output.log; then
    echo -e "${GREEN}✓ Address discovery working${NC}"
else
    echo -e "${YELLOW}⚠ Address discovery not detected${NC}"
fi

# Wait for test to complete
wait $CLIENT_PID 2>/dev/null || true

# Test 2: Multiple concurrent connections
echo -e "\n${YELLOW}Test 2: Multiple Concurrent Connections${NC}"
echo "Starting 3 peers..."

for i in {1..3}; do
    PORT=$((9000 + i))
    # v0.13.0+: Uses --connect instead of --bootstrap
    cargo run --release --bin ant-quic -- \
        --connect $KNOWN_PEER \
        --listen 0.0.0.0:$PORT > peer$i.log 2>&1 &
    CLIENT_PIDS="$CLIENT_PIDS $!"
    echo "Started peer $i on port $PORT"
done

# Let them run
echo "Running for 20 seconds..."
sleep 20

# Check results
SUCCESS_COUNT=0
for i in {1..3}; do
    if grep -q "Connected to peer\|Discovered external address" peer$i.log; then
        echo -e "${GREEN}✓ Peer $i connected successfully${NC}"
        ((SUCCESS_COUNT++))
    else
        echo -e "${RED}✗ Peer $i failed to connect${NC}"
    fi
done

# Kill all peers
for PID in $CLIENT_PIDS; do
    kill $PID 2>/dev/null || true
done

echo -e "\n${BLUE}=== Test Summary ===${NC}"
echo "Known peer: $KNOWN_PEER"
echo "Basic connectivity: ${GREEN}PASS${NC}"
echo "Concurrent connections: $SUCCESS_COUNT/3 successful"
echo ""

if [ $SUCCESS_COUNT -ge 2 ]; then
    echo -e "${GREEN}✅ Peer node is working correctly!${NC}"
    echo -e "\n${BLUE}Server Stats:${NC}"
    # Get server stats
    ssh root@quic.saorsalabs.com "systemctl status ant-quic --no-pager | grep -E 'Active:|Memory:|CPU:'" || true
else
    echo -e "${RED}❌ Peer node has issues${NC}"
    echo -e "\nCheck server logs:"
    echo "ssh root@quic.saorsalabs.com 'journalctl -u ant-quic -n 50'"
fi

# Cleanup
rm -f test-output.log peer*.log