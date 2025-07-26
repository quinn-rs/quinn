# Detailed Troubleshooting Guide for ant-quic Testing

This guide provides in-depth troubleshooting steps for common issues encountered when testing ant-quic.

## Table of Contents
- [Diagnostic Tools](#diagnostic-tools)
- [Connection Issues](#connection-issues)
- [NAT Traversal Problems](#nat-traversal-problems)
- [Performance Issues](#performance-issues)
- [Protocol Errors](#protocol-errors)
- [Platform-Specific Issues](#platform-specific-issues)
- [Advanced Debugging](#advanced-debugging)

## Diagnostic Tools

### Built-in Diagnostics

```bash
# Comprehensive system check
./ant-quic --diagnose

# Output includes:
✓ Network interfaces detected
✓ NAT type classification  
✓ Firewall detection
✓ MTU discovery
✓ DNS resolution check
✓ Certificate validation
```

### Network Analysis Tools

```bash
# 1. NAT behavior analysis
./ant-quic --analyze-nat --detailed

# Shows:
- Port allocation behavior
- Mapping timeout
- Hairpinning support
- Connection state tracking
- Recommended configurations

# 2. Path MTU discovery
./ant-quic --discover-mtu <target>

# 3. Network route tracing
./ant-quic --trace-route <target>
```

## Connection Issues

### Issue: Connection Timeout

**Symptoms:**
- No response from server
- Hangs at "Connecting..."
- Times out after 10-30 seconds

**Diagnosis Steps:**

```bash
# Step 1: Check basic connectivity
ping <target-host>
nslookup <target-host>

# Step 2: Verify UDP is not blocked
sudo nmap -sU -p <port> <target-host>

# Step 3: Test with verbose logging
RUST_LOG=ant_quic=trace ./ant-quic --connect <target> 2>&1 | grep -E "(send|recv|timeout)"

# Step 4: Packet capture
sudo tcpdump -i any -n -vv "udp and port <port>" -w debug.pcap
```

**Common Causes & Solutions:**

1. **Firewall Blocking UDP**
   ```bash
   # Linux: Allow UDP
   sudo iptables -A INPUT -p udp --dport 443 -j ACCEPT
   sudo iptables -A OUTPUT -p udp --sport 443 -j ACCEPT
   
   # Windows: PowerShell as Admin
   New-NetFirewallRule -DisplayName "QUIC" -Direction Inbound -Protocol UDP -LocalPort 443 -Action Allow
   ```

2. **DNS Resolution Failure**
   ```bash
   # Use IP directly
   ./ant-quic --connect 8.8.8.8:443
   
   # Or specify DNS server
   ./ant-quic --connect <target> --dns 8.8.8.8
   ```

3. **Wrong Port Number**
   ```bash
   # Common QUIC ports to try
   for port in 443 4433 4434 8443 9000; do
     echo "Trying port $port..."
     timeout 5 ./ant-quic --connect <host>:$port
   done
   ```

### Issue: TLS/Certificate Errors

**Symptoms:**
- "Certificate verification failed"
- "Unknown CA"
- "Certificate expired"

**Solutions:**

```bash
# 1. Update system certificates
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install ca-certificates

# macOS
brew install ca-certificates

# 2. Test with certificate details
./ant-quic --connect <target> --show-certs

# 3. For test servers (NOT PRODUCTION)
./ant-quic --connect <target> --insecure

# 4. Specify custom CA
./ant-quic --connect <target> --ca-cert /path/to/ca.pem
```

### Issue: Version Negotiation Failure

**Symptoms:**
- "Unsupported QUIC version"
- "Version negotiation failed"

**Diagnosis:**

```bash
# Show supported versions
./ant-quic --list-versions

# Force specific version
./ant-quic --connect <target> --quic-version 1

# Test version negotiation
./ant-quic --connect <target> --test-versions
```

## NAT Traversal Problems

### Issue: Cannot Establish P2P Connection

**Symptoms:**
- "Failed to punch through NAT"
- "No direct path available"
- Falls back to relay

**Comprehensive NAT Diagnosis:**

```bash
# 1. Detailed NAT analysis
./ant-quic --nat-analysis --full

# Output:
NAT Classification Report:
  Type: Symmetric NAT
  External IP: 203.0.113.1
  Port Mapping: Random
  Mapping Lifetime: 30 seconds
  Hairpinning: Not supported
  Multiple Routes: Detected
  
Hole Punching Feasibility:
  Full Cone → Your NAT: ✓ Possible
  Restricted → Your NAT: ✓ Possible  
  Symmetric → Your NAT: ⚠ Difficult (40% success)
  
Recommendations:
  - Use port prediction for symmetric NAT
  - Enable relay fallback
  - Consider UPnP/NAT-PMP if available
```

**Solutions by NAT Type:**

1. **Symmetric NAT**
   ```bash
   # Enable advanced strategies
   ./ant-quic --connect <peer> \
     --enable-port-prediction \
     --prediction-range 10 \
     --max-punch-attempts 50
   ```

2. **Carrier-Grade NAT (CGNAT)**
   ```bash
   # Use multiple coordinators
   ./ant-quic --connect <peer> \
     --coordinator coord1.example:9000 \
     --coordinator coord2.example:9000 \
     --enable-relay-fallback
   ```

3. **Restrictive Firewall**
   ```bash
   # Try different strategies
   ./ant-quic --connect <peer> \
     --punch-strategy aggressive \
     --stun-keepalive 5
   ```

### Issue: Unstable P2P Connection

**Symptoms:**
- Connection drops frequently
- High packet loss on direct path
- Switches between direct and relay

**Debugging:**

```bash
# Monitor connection stability
./ant-quic --connect <peer> --monitor

# Real-time statistics:
Connection to peer-id-123:
  Current Path: Direct
  Uptime: 00:05:23
  Packet Loss: 2.3%
  RTT: 45ms (min: 12ms, max: 234ms)
  Path Changes: 3
  Relay Usage: 12%
```

## Performance Issues

### Issue: Low Throughput

**Symptoms:**
- Transfer speeds below expected
- High CPU usage
- Stuttering or delays

**Performance Analysis:**

```bash
# 1. Comprehensive performance test
./ant-quic --performance-test <target>

# Generates report:
Performance Test Results:
  Throughput:
    Download: 45.3 Mbps (expected: 100+ Mbps)
    Upload: 12.1 Mbps
    
  Bottleneck Analysis:
    ✗ Receive Window: Limited to 64KB
    ✓ Congestion Control: Cubic performing well
    ✗ CPU: 95% usage (single core bound)
    ✓ Network: No packet loss detected
    
  Recommendations:
    - Increase receive window: --rcvbuf 2097152
    - Enable multi-threading: --threads 4
```

**Optimization Steps:**

```bash
# 1. Tune buffer sizes
./ant-quic --connect <target> \
  --rcvbuf 2097152 \
  --sndbuf 2097152

# 2. Adjust congestion control
./ant-quic --connect <target> \
  --congestion-algorithm bbr

# 3. Enable hardware offload
sudo ethtool -K eth0 tx-udp-segmentation on
```

### Issue: High Latency

**Symptoms:**
- RTT higher than expected
- Slow request/response
- Jittery connection

**Latency Debugging:**

```bash
# 1. Detailed latency analysis
./ant-quic --analyze-latency <target>

# Shows:
Latency Breakdown:
  Network RTT: 12ms
  Processing: 3ms
  Queuing: 45ms ← Problem here
  Crypto: 1ms
  Total: 61ms

# 2. Test different paths
./ant-quic --connect <target> --multipath-test
```

## Protocol Errors

### Issue: Frame Parsing Errors

**Symptoms:**
- "Invalid frame type"
- "Malformed packet"
- Connection terminates unexpectedly

**Debugging:**

```bash
# 1. Enable protocol logging
RUST_LOG=ant_quic::frame=trace ./ant-quic --connect <target>

# 2. Capture and analyze packets
./ant-quic --connect <target> --capture packets.bin
./ant-quic --analyze-capture packets.bin

# Shows exactly which frames fail parsing
```

### Issue: Transport Parameter Negotiation

**Symptoms:**
- "Incompatible transport parameters"
- Features not working as expected

**Analysis:**

```bash
# Show parameter negotiation
./ant-quic --connect <target> --show-params

# Output:
Local Parameters:
  max_idle_timeout: 30000
  max_udp_payload_size: 1472
  initial_max_data: 10485760
  nat_traversal: enabled (0x58)
  
Remote Parameters:
  max_idle_timeout: 60000
  max_udp_payload_size: 1452
  initial_max_data: 5242880
  nat_traversal: not supported ← Issue here
```

## Platform-Specific Issues

### Linux

**Issue: Operation not permitted**
```bash
# Need CAP_NET_ADMIN for some features
sudo setcap cap_net_admin+ep ./ant-quic

# Or run with sudo for testing
sudo ./ant-quic --diagnose
```

### macOS

**Issue: Firewall prompts**
```bash
# Add to firewall exceptions
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add ./ant-quic
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp ./ant-quic
```

### Windows

**Issue: Performance degradation**
```powershell
# Disable Windows Defender real-time scanning for test
Add-MpPreference -ExclusionPath "C:\path\to\ant-quic"

# Enable high-performance mode
powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
```

## Advanced Debugging

### Core Dumps and Stack Traces

```bash
# Enable core dumps
ulimit -c unlimited

# Run with debugging symbols
RUST_BACKTRACE=full ./ant-quic --connect <target>

# Analyze core dump
gdb ./ant-quic core
(gdb) bt full
(gdb) info registers
```

### Memory Profiling

```bash
# Use Valgrind
valgrind --leak-check=full --show-leak-kinds=all ./ant-quic --connect <target>

# Or built-in profiler
./ant-quic --connect <target> --profile-memory
```

### Network Simulation

```bash
# Simulate various network conditions
# 1. Packet loss
sudo tc qdisc add dev eth0 root netem loss 5%

# 2. Latency
sudo tc qdisc add dev eth0 root netem delay 100ms

# 3. Bandwidth limit
sudo tc qdisc add dev eth0 root tbf rate 1mbit burst 32kbit latency 400ms

# Clean up
sudo tc qdisc del dev eth0 root
```

### Protocol Fuzzing

```bash
# Fuzz testing for robustness
./ant-quic --fuzz-target <target> --fuzz-duration 3600

# Targeted fuzzing
./ant-quic --fuzz-component frame-parsing --iterations 100000
```

## Getting Help

If you're still experiencing issues:

1. **Collect Diagnostic Information**
   ```bash
   ./ant-quic --collect-diagnostics > diagnostics.txt
   ```

2. **Check Known Issues**
   - GitHub Issues: https://github.com/dirvine/ant-quic/issues
   - FAQ: https://ant-quic.net/faq

3. **Contact Support**
   - Discord: https://discord.gg/ant-quic
   - Email: support@ant-quic.net
   
   Include:
   - Diagnostic output
   - Exact commands used
   - Network environment details
   - Any error messages

Remember: Most issues have simple solutions. This guide covers edge cases and advanced scenarios.