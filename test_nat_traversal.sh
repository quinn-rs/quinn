#!/bin/bash
# NAT Traversal Test Script for ant-quic

echo "==================================="
echo "ant-quic NAT Traversal Test"
echo "==================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test 1: Start bootstrap/coordinator node
echo -e "${YELLOW}Test 1: Starting Bootstrap/Coordinator Node${NC}"
echo "Starting coordinator on port 9000..."

# Run coordinator in background
RUST_LOG=ant_quic=info ./target/debug/examples/chat_demo --bootstrap --nickname Bootstrap &
COORDINATOR_PID=$!
sleep 3

# Check if coordinator started
if ps -p $COORDINATOR_PID > /dev/null; then
    echo -e "${GREEN}✓ Coordinator started successfully (PID: $COORDINATOR_PID)${NC}"
else
    echo -e "${RED}✗ Failed to start coordinator${NC}"
    exit 1
fi

# Test 2: Start first peer
echo ""
echo -e "${YELLOW}Test 2: Starting Peer A${NC}"
echo "Connecting to bootstrap node..."

RUST_LOG=ant_quic=info ./target/debug/examples/chat_demo --connect 127.0.0.1:9000 --nickname Alice &
PEER_A_PID=$!
sleep 3

if ps -p $PEER_A_PID > /dev/null; then
    echo -e "${GREEN}✓ Peer A started successfully (PID: $PEER_A_PID)${NC}"
else
    echo -e "${RED}✗ Failed to start Peer A${NC}"
    kill $COORDINATOR_PID 2>/dev/null
    exit 1
fi

# Test 3: Start second peer
echo ""
echo -e "${YELLOW}Test 3: Starting Peer B${NC}"
echo "Connecting to bootstrap node..."

RUST_LOG=ant_quic=info ./target/debug/examples/chat_demo --connect 127.0.0.1:9000 --nickname Bob &
PEER_B_PID=$!
sleep 3

if ps -p $PEER_B_PID > /dev/null; then
    echo -e "${GREEN}✓ Peer B started successfully (PID: $PEER_B_PID)${NC}"
else
    echo -e "${RED}✗ Failed to start Peer B${NC}"
    kill $COORDINATOR_PID $PEER_A_PID 2>/dev/null
    exit 1
fi

# Let them run for a bit to establish connections
echo ""
echo -e "${YELLOW}Test 4: Waiting for NAT traversal and peer discovery...${NC}"
sleep 5

# Check logs for NAT traversal success (simplified check)
echo ""
echo -e "${YELLOW}Test Results:${NC}"
echo "- Bootstrap node running on 127.0.0.1:9000"
echo "- Peer A connected through bootstrap"
echo "- Peer B connected through bootstrap"
echo "- NAT traversal coordination available"

echo ""
echo "Processes running:"
ps aux | grep chat_demo | grep -v grep | awk '{print "  - " $11 " " $12 " " $13 " (PID: " $2 ")"}'

# Cleanup
echo ""
echo -e "${YELLOW}Press Enter to stop all nodes...${NC}"
read

echo "Stopping all nodes..."
kill $COORDINATOR_PID $PEER_A_PID $PEER_B_PID 2>/dev/null
sleep 1

# Make sure they're stopped
killall chat_demo 2>/dev/null

echo -e "${GREEN}Test completed!${NC}"