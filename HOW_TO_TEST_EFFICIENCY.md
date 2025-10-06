# How to Test ant-quic Data Transfer Efficiency

## Quick Test - Simple Transfer Example

This example transfers 1 MB of data and shows detailed efficiency metrics.

### Method 1: Automated Test (Single Command)

```bash
# Build and run both server and client automatically
cargo run --release --example simple_transfer &
sleep 2
cargo run --release --example simple_transfer -- --client
```

### Method 2: Manual Test (Two Terminals)

**Terminal 1 - Start Server:**
```bash
cargo run --release --example simple_transfer
```

Wait for the message: "✅ Server listening on 127.0.0.1:5000"

**Terminal 2 - Start Client:**
```bash
cargo run --release --example simple_transfer -- --client
```

### Expected Output

**Client Side:**
```
✅ Connected to server
📤 Transferring 1024 KB in 256 chunks of 4096 bytes

   📤 Sent: 19.5%
   📤 Sent: 39.1%
   📤 Sent: 58.6%
   📤 Sent: 78.1%
   📤 Sent: 97.7%

✅ Send complete in 0.03s
📥 Receiving echo...

✅ Transfer complete!
📊 Results:
   Sent: 1024 KB
   Received: 1024 KB
   Send time: 0.03s (267.89 Mbps)
   Receive time: 0.00s (26497.34 Mbps)
   Round-trip: 0.03s
   Average: 13382.62 Mbps

🔍 Efficiency Metrics:
   Application data: 1048576 bytes
   UDP bytes sent: 1086563 bytes
   Protocol overhead: 37987 bytes
   Efficiency: 96.50%
```

**Server Side:**
```
✅ Server listening on 127.0.0.1:5000
🔗 Client connected from 127.0.0.1:49526
📥 Receiving data...

✅ Transfer complete!
📊 Statistics:
   Total received: 1024 KB (1 MB)
   Time: 0.03s
   Throughput: 267.37 Mbps

🔍 Efficiency Metrics:
   Application data: 1048576 bytes
   UDP bytes received: 1085325 bytes
   Protocol overhead: 36749 bytes
   Efficiency: 96.61%
```

## Full P2P Test - ant-quic Binary

Test the complete P2P node with NAT traversal, bootstrap coordination, and monitoring.

### Terminal 1 - Bootstrap Node (Coordinator)

```bash
cargo run --release --bin ant-quic -- \
    --listen 127.0.0.1:9000 \
    --force-coordinator \
    --dashboard \
    --dashboard-interval 1
```

### Terminal 2 - Client Node

```bash
cargo run --release --bin ant-quic -- \
    --listen 127.0.0.1:0 \
    --bootstrap 127.0.0.1:9000 \
    --dashboard \
    --dashboard-interval 1
```

### Expected Features

- ✅ Connection establishment
- ✅ NAT traversal negotiation
- ✅ Address discovery (OBSERVED_ADDRESS frames)
- ✅ Real-time dashboard statistics
- ✅ Peer authentication
- ✅ Automatic coordinator services

### Dashboard Output

You'll see real-time statistics every second:
```
=== Ant-QUIC P2P Node Dashboard ===
Uptime: 5.2s
Local Address: 127.0.0.1:9000

Active Connections: 1
Total Connections: 1

Bootstrap Nodes: 0
Peers: 1

Bytes Sent: 12,456
Bytes Received: 45,678

NAT Traversal:
  Success Rate: 70%
  Active Sessions: 1
  Avg Coordination Time: 500ms

Recent Activity:
  [17:15:23] Connection established
  [17:15:24] NAT traversal negotiated
```

## Efficiency Testing Script

For comprehensive 20-second monitoring:

```bash
# Make script executable
chmod +x test_efficiency.sh

# Run the test
./test_efficiency.sh
```

This script:
- Starts bootstrap coordinator
- Starts client node
- Monitors for 20 seconds
- Collects comprehensive statistics
- Generates efficiency report

## Understanding the Results

### Efficiency Metrics

**96.5% Efficiency means:**
- Application data: 1,048,576 bytes (1 MB)
- UDP bytes sent: 1,086,563 bytes
- Protocol overhead: 37,987 bytes (3.5%)

**The overhead includes:**
- QUIC packet headers
- Encryption overhead
- ACK frames
- Flow control frames
- NAT traversal extension frames (when active)

### Throughput

**Localhost Performance:**
- Send: ~268 Mbps
- Receive: ~26,500 Mbps (echo is faster)
- Limited by CPU and localhost buffering

**Real-World Estimates (from EFFICIENCY_REPORT.md):**
- Practical throughput: 500-1000 Mbps with encryption
- Protocol efficiency: 85-95% typical

### NAT Traversal Success Rates

From testing and IETF draft expectations:
- Full Cone NAT: >95% success
- Port Restricted: 80-90% success
- Symmetric NAT: 60-80% success (with coordination)
- CGNAT: 50-70% success

## Troubleshooting

### Build Issues

```bash
# Clean build
cargo clean
cargo build --release --example simple_transfer

# Check for compilation errors
cargo check --example simple_transfer
```

### Connection Issues

```bash
# Check if port is in use
lsof -i :5000

# Use different port
cargo run --release --example simple_transfer -- --port 5001
```

### Enable Debug Logging

```bash
# For simple_transfer
RUST_LOG=simple_transfer=debug,ant_quic=debug cargo run --release --example simple_transfer

# For ant-quic binary
RUST_LOG=debug cargo run --release --bin ant-quic -- --listen 127.0.0.1:9000
```

## Key Files

- `examples/simple_transfer.rs` - Simple 1MB transfer with metrics
- `examples/throughput_test.rs` - Extended 10MB transfer test
- `test_efficiency.sh` - Automated comprehensive testing
- `EFFICIENCY_REPORT.md` - Full efficiency analysis report

## Performance Notes

**Why is localhost so fast?**
- No network latency (loopback interface)
- No packet loss
- No bandwidth constraints
- Optimized OS buffering

**Real-world performance** will be lower due to:
- Network latency (RTT)
- Bandwidth limitations
- Packet loss
- NAT traversal overhead
- Congestion control

The **efficiency percentage** is the most important metric as it shows how much overhead the protocol adds, regardless of network speed.
