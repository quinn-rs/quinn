#!/bin/bash
# Test script to demonstrate four-word addresses for peer connections

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Starting ant-quic coordinator node...${NC}"
# Start coordinator in background
./target/release/ant-quic --listen 127.0.0.1:8001 > coordinator.log 2>&1 &
COORD_PID=$!
echo "Coordinator PID: $COORD_PID"
sleep 2

echo -e "${BLUE}Starting ant-quic client node...${NC}"
# Start client that connects to coordinator
./target/release/ant-quic --listen 127.0.0.1:8002 --bootstrap 127.0.0.1:8001 > client.log 2>&1 &
CLIENT_PID=$!
echo "Client PID: $CLIENT_PID"

echo -e "${GREEN}Nodes are running. Watch the coordinator output to see four-word addresses...${NC}"
echo
echo "Coordinator output:"
echo "==================="
tail -f coordinator.log &
TAIL_PID=$!

# Wait for user input
read -p "Press Enter to stop the test..."

# Cleanup
kill $COORD_PID $CLIENT_PID $TAIL_PID 2>/dev/null
rm -f coordinator.log client.log

echo -e "${GREEN}Test completed!${NC}"