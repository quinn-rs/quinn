#!/bin/bash
# Simple NAT Traversal Test for ant-quic

echo "======================================"
echo "ant-quic Simple NAT Traversal Test"
echo "======================================"
echo ""

# Kill any existing ant-quic processes
echo "Cleaning up any existing processes..."
pkill -f ant-quic 2>/dev/null
sleep 1

# Step 1: Start bootstrap coordinator
echo "1. Starting Bootstrap Coordinator on port 9000..."
RUST_LOG=ant_quic::nat_traversal=debug,ant_quic::connection=info ./target/debug/ant-quic --listen 0.0.0.0:9000 --force-coordinator --minimal > bootstrap.log 2>&1 &
BOOTSTRAP_PID=$!
echo "   Bootstrap PID: $BOOTSTRAP_PID"
sleep 2

# Step 2: Start first peer (simulating behind NAT)
echo ""
echo "2. Starting Peer A (simulating NAT environment)..."
RUST_LOG=ant_quic::nat_traversal=debug,ant_quic::connection=info ./target/debug/ant-quic --listen 0.0.0.0:0 --bootstrap 127.0.0.1:9000 --minimal > peer_a.log 2>&1 &
PEER_A_PID=$!
echo "   Peer A PID: $PEER_A_PID"
sleep 2

# Step 3: Start second peer (simulating behind different NAT)
echo ""
echo "3. Starting Peer B (simulating different NAT)..."
RUST_LOG=ant_quic::nat_traversal=debug,ant_quic::connection=info ./target/debug/ant-quic --listen 0.0.0.0:0 --bootstrap 127.0.0.1:9000 --minimal > peer_b.log 2>&1 &
PEER_B_PID=$!
echo "   Peer B PID: $PEER_B_PID"
sleep 3

# Step 4: Check results
echo ""
echo "4. Checking NAT traversal results..."
echo ""

# Check bootstrap log
echo "Bootstrap node activity:"
grep -E "(Listening|Coordinator|Client connected|Address discovery)" bootstrap.log | tail -5 || echo "   No relevant activity yet"

echo ""
echo "Peer A NAT traversal:"
grep -E "(NAT type|Discovered address|Hole punching|Connected to peer)" peer_a.log | tail -5 || echo "   No NAT activity yet"

echo ""
echo "Peer B NAT traversal:"
grep -E "(NAT type|Discovered address|Hole punching|Connected to peer)" peer_b.log | tail -5 || echo "   No NAT activity yet"

# Let it run a bit more
echo ""
echo "Waiting 5 seconds for peer discovery..."
sleep 5

# Final check
echo ""
echo "Final NAT Traversal Status:"
echo "============================"

# Check for successful connections
if grep -q "Connected to peer" peer_a.log 2>/dev/null || grep -q "Connected to peer" peer_b.log 2>/dev/null; then
    echo "✓ Direct peer connection established!"
else
    echo "✗ No direct peer connections found (this is normal in local testing)"
fi

# Check for address discovery
if grep -q "Discovered address" peer_a.log 2>/dev/null || grep -q "OBSERVED_ADDRESS" peer_a.log 2>/dev/null; then
    echo "✓ Address discovery working"
else
    echo "✗ No address discovery observed"
fi

# Show running processes
echo ""
echo "Active processes:"
ps aux | grep ant-quic | grep -v grep | grep -v "simple_nat_test" | awk '{print "  " $11 " " $12 " " $13 " (PID: " $2 ")"}'

echo ""
echo "Log files created:"
ls -la *.log 2>/dev/null | awk '{print "  " $9 " (" $5 " bytes)"}'

echo ""
echo "To examine detailed logs:"
echo "  cat bootstrap.log   # Bootstrap node logs"
echo "  cat peer_a.log      # Peer A logs"
echo "  cat peer_b.log      # Peer B logs"

echo ""
echo "Press Enter to stop all nodes and clean up..."
read

# Cleanup
echo "Stopping all nodes..."
kill $BOOTSTRAP_PID $PEER_A_PID $PEER_B_PID 2>/dev/null
sleep 1
pkill -f ant-quic 2>/dev/null

echo "Test completed!"
echo ""
echo "Note: In a real NAT environment, you would see:"
echo "- Different NAT types detected (Full Cone, Symmetric, etc.)"
echo "- Actual hole punching coordination"
echo "- Direct peer connections through NAT"