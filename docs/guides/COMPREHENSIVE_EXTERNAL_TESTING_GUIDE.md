# Comprehensive External Testing Guide for ant-quic

Welcome to the ant-quic external testing guide! This document provides everything you need to validate and test ant-quic's QUIC implementation, NAT traversal capabilities, and interoperability with other QUIC implementations.

## Table of Contents
- [Quick Start](#quick-start)
- [Testing Environment Setup](#testing-environment-setup)
- [Test Scenarios](#test-scenarios)
- [Real-World Testing](#real-world-testing)
- [Troubleshooting Guide](#troubleshooting-guide)
- [Expected Behaviors](#expected-behaviors)
- [Reporting Results](#reporting-results)

## Quick Start

Get testing in under 2 minutes! Choose your preferred method:

### Option 1: Pre-built Binary (Fastest)

```bash
# Download the latest release
# Linux/macOS
curl -L https://github.com/dirvine/ant-quic/releases/latest/download/ant-quic-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m) -o ant-quic
chmod +x ant-quic

# Windows (PowerShell)
Invoke-WebRequest -Uri https://github.com/dirvine/ant-quic/releases/latest/download/ant-quic-windows-x86_64.exe -OutFile ant-quic.exe

# Quick connectivity test
./ant-quic --connect quic.tech:443
```

### Option 2: Docker (No Installation)

```bash
# Run a quick test
docker run --rm ghcr.io/dirvine/ant-quic:latest ant-quic --connect quic.tech:443
```

### Option 3: Build from Source

```bash
# Clone and build
git clone https://github.com/dirvine/ant-quic
cd ant-quic
cargo build --release --bin ant-quic
./target/release/ant-quic --connect quic.tech:443
```

## Testing Environment Setup

### System Requirements
- **OS**: Linux, macOS, Windows 10+, BSD
- **Network**: IPv4/IPv6 connectivity
- **Ports**: UDP port access (typically 443, 4433, or 9000)
- **Memory**: 100MB minimum
- **CPU**: Any x86_64 or ARM64 processor

### Network Configurations to Test

ant-quic should work in all these environments:

1. **Direct Internet Connection** (No NAT)
2. **Home Router NAT** (Most common)
3. **Corporate Firewall** (Restrictive)
4. **Mobile Network** (CGNAT)
5. **Public WiFi** (Captive portals)
6. **VPN Connection** (Tunneled)

## Test Scenarios

### 1. Basic QUIC Connectivity Test

**Purpose**: Verify basic QUIC handshake and connection establishment.

```bash
# Test against a known QUIC server
./ant-quic --connect www.google.com:443

# Expected output:
✓ Resolving www.google.com...
✓ Connecting to 142.250.80.36:443...
✓ QUIC handshake completed (QUIC v1)
✓ Connection established in 45ms
✓ Server: GFE/2.0
```

**What to verify:**
- ✅ DNS resolution works
- ✅ QUIC handshake completes
- ✅ Version negotiation succeeds
- ✅ Connection time is reasonable (<500ms)

### 2. NAT Traversal Test Suite

**Purpose**: Test ant-quic's advanced NAT traversal capabilities.

#### 2.1 Automatic NAT Detection
```bash
./ant-quic --nat-check

# Expected output:
Detecting NAT configuration...
✓ Local IP: 192.168.1.100
✓ External IP: 203.0.113.45
✓ NAT Type: Port Restricted Cone NAT
✓ Port Mapping: Randomized
✓ Hairpinning: Supported
```

#### 2.2 Peer-to-Peer Connection Test
```bash
# Node A (behind NAT)
./ant-quic --listen 0.0.0.0:0 --bootstrap bootstrap.ant-quic.net:9000

# Node B (behind different NAT)
./ant-quic --connect <peer-id-from-node-a> --bootstrap bootstrap.ant-quic.net:9000

# Expected: Direct P2P connection established through NAT
```

#### 2.3 Multi-NAT Traversal
```bash
# Test through multiple NAT layers (CGNAT scenario)
./ant-quic --connect peer --nat-layers 2 --verbose

# Should show:
✓ Detected CGNAT (2 NAT layers)
✓ Using advanced hole-punching
✓ Connection established via predicted port
```

### 3. Protocol Extension Tests

**Purpose**: Verify ant-quic's IETF draft implementations.

#### 3.1 Address Discovery Extension
```bash
# Enable frame logging
RUST_LOG=ant_quic::frame=debug ./ant-quic --connect quic.tech:443

# Look for:
DEBUG Received OBSERVED_ADDRESS frame: seq=1, addr=203.0.113.45:54321
DEBUG Updated server-reflexive address
```

#### 3.2 NAT Traversal Extension
```bash
# Test coordination protocol
./ant-quic --test nat-traversal --coordinator bootstrap.ant-quic.net:9000

# Verify:
✓ ADD_ADDRESS frames exchanged
✓ PUNCH_ME_NOW coordination successful
✓ Simultaneous open achieved
```

### 4. Performance and Reliability Tests

#### 4.1 Throughput Test
```bash
# Download test (100MB)
./ant-quic --connect speedtest.ant-quic.net:443 --download-test 100

# Expected results:
Download: 100.0 MB in 0.85s (117.6 MB/s)
Average RTT: 12ms
Packet Loss: 0.0%
```

#### 4.2 Latency Test
```bash
# 1000 echo requests
./ant-quic --connect quic.tech:443 --ping-test 1000

# Expected:
Ping statistics:
  Packets: sent = 1000, received = 1000, lost = 0 (0.0% loss)
  RTT min/avg/max/stddev = 8.2/12.4/45.3/3.1 ms
```

#### 4.3 Connection Migration Test
```bash
# Test resilience to network changes
./ant-quic --connect quic.tech:443 --test-migration

# Simulate network change and verify:
✓ Connection survives IP change
✓ Migration completed in <50ms
✓ No packet loss during migration
```

### 5. Interoperability Tests

#### 5.1 Test Against Major Implementations

```bash
# Google (quiche)
./ant-quic --connect www.google.com:443 --test interop

# Cloudflare (quiche)
./ant-quic --connect cloudflare.com:443 --test interop

# Facebook/Meta (mvfst)
./ant-quic --connect www.facebook.com:443 --test interop

# Expected: All connections succeed with proper version negotiation
```

#### 5.2 Automated Interop Suite
```bash
# Run comprehensive interop tests
cargo run --bin test-public-endpoints

# Generates report showing compatibility with 50+ endpoints
```

### 6. Stress and Edge Case Tests

#### 6.1 High Connection Count
```bash
# Open 100 simultaneous connections
./ant-quic --stress-test connections --count 100

# Verify:
✓ All connections established
✓ Memory usage stable
✓ No connection drops
```

#### 6.2 Packet Loss Resilience
```bash
# Simulate 5% packet loss
./ant-quic --connect quic.tech:443 --simulate-loss 5

# Should maintain connection with:
✓ Automatic retransmission
✓ Congestion control adaptation
✓ Stable throughput
```

## Real-World Testing

### Public Test Infrastructure

We maintain several public endpoints for testing:

| Endpoint | Purpose | Features |
|----------|---------|----------|
| `bootstrap.ant-quic.net:9000` | NAT traversal coordinator | Bootstrap node, hole-punching |
| `speedtest.ant-quic.net:443` | Performance testing | 10Gbps, global locations |
| `test.ant-quic.net:4433` | Protocol compliance | All extensions enabled |

### Testing from Different Environments

#### Home Network
```bash
# Most users are behind home routers
./ant-quic --real-world-test home

Detected environment: Home router NAT
✓ UPnP: Available
✓ NAT Type: Full Cone
✓ P2P Success Rate: 95%
```

#### Corporate Network
```bash
# Restrictive firewall scenario  
./ant-quic --real-world-test corporate

Detected environment: Corporate firewall
✓ Outbound UDP: Allowed
✓ NAT Type: Symmetric
✓ Relay Fallback: Required for 30% of connections
```

#### Mobile/CGNAT
```bash
# Carrier-grade NAT scenario
./ant-quic --real-world-test mobile

Detected environment: CGNAT (T-Mobile)
✓ Multiple NAT layers: 2
✓ Port prediction: Working
✓ P2P Success Rate: 75%
```

## Troubleshooting Guide

### Common Issues and Solutions

#### Connection Timeout
```bash
# Enable debug logging
RUST_LOG=debug ./ant-quic --connect <target>

# Check for:
- Firewall blocking UDP
- Incorrect port number
- DNS resolution failures
```

#### Certificate Validation Error
```bash
# For test servers with self-signed certs
./ant-quic --connect test.server:4433 --insecure

# For production servers, ensure system certs are updated
```

#### NAT Traversal Failure
```bash
# Detailed NAT diagnostics
./ant-quic --diagnose-nat

# Provides:
- NAT type classification
- Port mapping behavior
- Suggested solutions
```

#### Performance Issues
```bash
# Performance profiling
./ant-quic --connect <target> --profile

# Shows:
- CPU usage by component
- Memory allocation patterns
- Network bottlenecks
```

### Debug Commands

```bash
# Maximum verbosity
RUST_LOG=trace ./ant-quic --connect <target>

# Packet capture
sudo tcpdump -i any -w ant-quic.pcap 'udp port 443 or udp port 4433 or udp port 9000'

# Connection state dump
./ant-quic --connect <target> --dump-state
```

## Expected Behaviors

### Successful Connection Characteristics

1. **Handshake**: Completes in 1-2 RTT
2. **Version**: Negotiates QUIC v1 (0x00000001)
3. **ALPN**: Negotiates appropriate protocol
4. **Encryption**: TLS 1.3 with strong ciphers
5. **Extensions**: Proper transport parameter exchange

### NAT Traversal Success Indicators

1. **Direct Connection**: Achieved in >85% of cases
2. **Hole Punching**: Completes in <500ms
3. **Port Prediction**: Works for symmetric NATs
4. **Relay Fallback**: Available when needed
5. **Connection Stability**: Survives network changes

### Performance Benchmarks

| Metric | Expected Value | Acceptable Range |
|--------|---------------|------------------|
| Handshake Time | 50ms | 20-200ms |
| 0-RTT Resume | 0ms | 0-10ms |
| Throughput (LAN) | 1 Gbps | 500 Mbps - 10 Gbps |
| Throughput (WAN) | 100 Mbps | 10-500 Mbps |
| CPU Usage | <5% | 1-20% |
| Memory Usage | 50 MB | 20-200 MB |

## Reporting Results

### Test Result Template

When reporting test results, please include:

```markdown
## Test Environment
- OS: [e.g., Ubuntu 22.04]
- Network Type: [e.g., Home NAT, Corporate, Mobile]
- ant-quic Version: [output of ant-quic --version]
- Test Date: [YYYY-MM-DD]

## Test Results

### Basic Connectivity
- [ ] Google QUIC: [Pass/Fail] [Time: XXms]
- [ ] Cloudflare: [Pass/Fail] [Time: XXms]
- [ ] Meta/Facebook: [Pass/Fail] [Time: XXms]

### NAT Traversal
- NAT Type Detected: [e.g., Port Restricted Cone]
- P2P Success Rate: [XX%]
- Relay Fallback Used: [Yes/No]

### Performance
- Average Throughput: [XX Mbps]
- Average Latency: [XX ms]
- Packet Loss: [X.X%]

### Issues Encountered
[Describe any problems]

### Additional Notes
[Any observations or suggestions]
```

### Submitting Results

1. **GitHub Issue**: https://github.com/dirvine/ant-quic/issues/new?template=test-report.md
2. **Email**: test-results@ant-quic.net
3. **Community Form**: https://ant-quic.net/submit-test

### Automated Reporting

```bash
# Generate and submit test report automatically
./ant-quic --full-test --submit-results

# Or save locally
./ant-quic --full-test --output test-results.json
```

## Advanced Testing

### Custom Test Scenarios

Create your own test scenarios:

```bash
# Create test configuration
cat > my-test.yaml << EOF
tests:
  - name: "High latency test"
    target: "quic.tech:443"
    conditions:
      latency: 200ms
      jitter: 50ms
    expect:
      connection: success
      min_throughput: 1mbps

  - name: "NAT traversal stress"
    target: "peer"
    conditions:
      nat_type: symmetric
      port_randomization: true
    expect:
      success_rate: ">70%"
EOF

# Run custom tests
./ant-quic --test-file my-test.yaml
```

### Continuous Testing

Set up automated testing:

```bash
# Run tests every hour
crontab -e
0 * * * * /path/to/ant-quic --full-test --submit-results --quiet

# Or use our Docker compose setup
docker-compose -f testing/docker-compose.yml up -d
```

## Security Testing

### Protocol Security Validation

```bash
# Test against known vulnerabilities
./ant-quic --security-test

# Checks for:
✓ Version downgrade attacks
✓ Amplification resistance  
✓ Connection ID privacy
✓ Retry token validation
✓ 0-RTT replay protection
```

### Fuzzing

```bash
# Run protocol fuzzer
cargo run --bin ant-quic-fuzzer --time 3600

# Tests malformed packets, state machines, etc.
```

## Contributing Test Results

Your test results help improve ant-quic! We especially value:

1. **Diverse Network Environments**: Unusual NAT types, firewalls
2. **Geographic Diversity**: Tests from different regions
3. **Failure Cases**: Help us understand where ant-quic struggles
4. **Performance Data**: Real-world throughput and latency
5. **Interop Issues**: Problems with specific QUIC implementations

## Support and Contact

- **Documentation**: https://ant-quic.net/docs
- **Discord**: https://discord.gg/ant-quic
- **Matrix**: #ant-quic:matrix.org
- **Email**: support@ant-quic.net

Thank you for testing ant-quic! Your feedback helps us build better P2P connectivity for everyone. 🚀