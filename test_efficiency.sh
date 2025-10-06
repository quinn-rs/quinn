#!/bin/bash
# Comprehensive efficiency test for ant-quic
# Tests data sending efficiency with detailed statistics collection

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Ant-QUIC Comprehensive Efficiency Test ===${NC}"
echo ""

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    pkill -P $$ 2>/dev/null || true
    wait 2>/dev/null || true
    echo -e "${GREEN}Cleanup complete${NC}"
}
trap cleanup EXIT

# Build release binary if not already built
if [ ! -f target/release/ant-quic ]; then
    echo -e "${YELLOW}Building release binary...${NC}"
    cargo build --release --bin ant-quic
fi

# Create a temporary directory for logs
LOG_DIR=$(mktemp -d)
echo -e "${BLUE}Log directory: ${LOG_DIR}${NC}"

# 1. Start bootstrap node with dashboard
echo -e "\n${GREEN}Step 1: Starting bootstrap node with dashboard...${NC}"
BOOTSTRAP_LOG="${LOG_DIR}/bootstrap.log"
./target/release/ant-quic \
    --listen 127.0.0.1:9000 \
    --force-coordinator \
    --dashboard \
    --dashboard-interval 1 \
    --debug \
    > "${BOOTSTRAP_LOG}" 2>&1 &

BOOTSTRAP_PID=$!
echo -e "${GREEN}Bootstrap node started (PID: ${BOOTSTRAP_PID})${NC}"

# Wait for bootstrap to initialize
sleep 3

# 2. Start client node with data sending
echo -e "\n${GREEN}Step 2: Starting client node for data transfer...${NC}"
CLIENT_LOG="${LOG_DIR}/client.log"
./target/release/ant-quic \
    --listen 127.0.0.1:0 \
    --bootstrap 127.0.0.1:9000 \
    --dashboard \
    --dashboard-interval 1 \
    --debug \
    > "${CLIENT_LOG}" 2>&1 &

CLIENT_PID=$!
echo -e "${GREEN}Client node started (PID: ${CLIENT_PID})${NC}"

# Wait for client to connect
echo -e "${YELLOW}Waiting for connection establishment...${NC}"
sleep 5

# 3. Monitor statistics for 20 seconds
echo -e "\n${GREEN}Step 3: Monitoring statistics for 20 seconds...${NC}"
echo -e "${BLUE}Dashboard output (bootstrap node):${NC}"
echo ""

# Monitor both nodes
for i in {1..20}; do
    echo -e "${YELLOW}=== Second ${i}/20 ===${NC}"

    # Show recent dashboard output from bootstrap
    tail -n 30 "${BOOTSTRAP_LOG}" 2>/dev/null || true

    sleep 1
    clear
done

# 4. Collect and analyze statistics
echo -e "\n${GREEN}Step 4: Analyzing statistics...${NC}"
echo ""

# Parse statistics from logs
echo -e "${BLUE}Bootstrap Node Statistics:${NC}"
echo "----------------------------"
grep -E "Active connections:|Total connections:|Bytes sent:|Bytes received:|NAT traversal" "${BOOTSTRAP_LOG}" | tail -n 20 || echo "No stats found"

echo ""
echo -e "${BLUE}Client Node Statistics:${NC}"
echo "----------------------------"
grep -E "Active connections:|Total connections:|Bytes sent:|Bytes received:|NAT traversal" "${CLIENT_LOG}" | tail -n 20 || echo "No stats found"

echo ""
echo -e "${BLUE}Connection Details:${NC}"
echo "----------------------------"
grep -E "Connection established|RTT:|Congestion window:|Path MTU" "${CLIENT_LOG}" | tail -n 10 || echo "No connection details found"

echo ""
echo -e "${BLUE}Frame Statistics:${NC}"
echo "----------------------------"
grep -E "frames|ACK|STREAM|DATA" "${BOOTSTRAP_LOG}" "${CLIENT_LOG}" 2>/dev/null | tail -n 20 || echo "No frame stats found"

echo ""
echo -e "${BLUE}Performance Metrics:${NC}"
echo "----------------------------"

# Calculate throughput if we can extract byte counts
BYTES_SENT=$(grep -oE "bytes_sent: [0-9]+" "${CLIENT_LOG}" 2>/dev/null | tail -1 | grep -oE "[0-9]+" || echo "0")
BYTES_RECV=$(grep -oE "bytes_received: [0-9]+" "${BOOTSTRAP_LOG}" 2>/dev/null | tail -1 | grep -oE "[0-9]+" || echo "0")

if [ "$BYTES_SENT" -gt 0 ] || [ "$BYTES_RECV" -gt 0 ]; then
    echo "Total bytes sent by client: ${BYTES_SENT}"
    echo "Total bytes received by bootstrap: ${BYTES_RECV}"

    # Calculate throughput (bytes per 20 seconds)
    THROUGHPUT_SENT=$((BYTES_SENT / 20))
    THROUGHPUT_RECV=$((BYTES_RECV / 20))

    echo "Average throughput (sent): ${THROUGHPUT_SENT} bytes/sec"
    echo "Average throughput (recv): ${THROUGHPUT_RECV} bytes/sec"

    # Convert to Mbps if significant
    if [ "$THROUGHPUT_SENT" -gt 125000 ]; then
        MBPS_SENT=$((THROUGHPUT_SENT * 8 / 1000000))
        echo "Average throughput (sent): ${MBPS_SENT} Mbps"
    fi
else
    echo "No byte transfer data found in logs"
fi

echo ""
echo -e "${BLUE}NAT Traversal Statistics:${NC}"
echo "----------------------------"
grep -E "NAT|traversal|hole.punch|candidate" "${BOOTSTRAP_LOG}" "${CLIENT_LOG}" 2>/dev/null | tail -n 15 || echo "No NAT stats found"

# 5. Save full logs
echo ""
echo -e "${GREEN}Step 5: Full logs saved to:${NC}"
echo "  Bootstrap: ${BOOTSTRAP_LOG}"
echo "  Client: ${CLIENT_LOG}"

# 6. Summary
echo ""
echo -e "${GREEN}=== Test Summary ===${NC}"
echo "Duration: 20 seconds"
echo "Nodes: 2 (1 bootstrap + 1 client)"
echo "Connection type: Local loopback (127.0.0.1)"
echo ""

# Check if connection was successful
if grep -q "Connection established" "${CLIENT_LOG}"; then
    echo -e "${GREEN}✓ Connection established successfully${NC}"
else
    echo -e "${YELLOW}⚠ Connection may not have been established${NC}"
fi

if grep -q "NAT traversal" "${BOOTSTRAP_LOG}" "${CLIENT_LOG}"; then
    echo -e "${GREEN}✓ NAT traversal features active${NC}"
else
    echo -e "${YELLOW}⚠ NAT traversal may not have been triggered (local connection)${NC}"
fi

echo ""
echo -e "${BLUE}For detailed analysis, review the log files above${NC}"
echo ""
