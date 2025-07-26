# Quick Start Guide for Testing ant-quic

This guide helps you get started with testing ant-quic in under 5 minutes.

## Prerequisites

- Linux, macOS, or Windows with WSL2
- Internet connection
- Basic command line knowledge

## Option 1: Using Pre-built Binaries (Fastest)

### 1. Download ant-quic

```bash
# Linux/macOS
wget https://github.com/dirvine/ant-quic/releases/latest/download/ant-quic-$(uname -s)-$(uname -m)
chmod +x ant-quic-*
mv ant-quic-* ant-quic

# Windows (PowerShell)
Invoke-WebRequest -Uri https://github.com/dirvine/ant-quic/releases/latest/download/ant-quic-windows-x86_64.exe -OutFile ant-quic.exe
```

### 2. Test Basic Connectivity

```bash
# Connect to public test server
./ant-quic --connect quic.saorsalabs.com:9000

# Expected output:
# Connecting to quic.saorsalabs.com:9000...
# Connected! Your address: 203.0.113.5:54321
# Connection established in 127ms
```

### 3. Test NAT Traversal

```bash
# Test from behind NAT
./ant-quic --connect quic.saorsalabs.com:9000 --enable-nat-traversal

# Expected output:
# NAT traversal enabled
# Discovered local addresses: 192.168.1.100:54321
# Server reflexive address: 203.0.113.5:54321
# NAT type detected: Port Restricted Cone
# Connection established via direct path
```

## Option 2: Using Docker

### 1. Pull Docker Image

```bash
docker pull ghcr.io/dirvine/ant-quic:latest
```

### 2. Run Tests

```bash
# Basic test
docker run --rm ghcr.io/dirvine/ant-quic:latest \
    ant-quic --connect quic.saorsalabs.com:9000

# NAT traversal test
docker run --rm ghcr.io/dirvine/ant-quic:latest \
    ant-quic --connect quic.saorsalabs.com:9000 --enable-nat-traversal
```

## Option 3: Using Python Test Script

### 1. Download Test Script

```bash
wget https://raw.githubusercontent.com/dirvine/ant-quic/main/docs/examples/test_interop.py
chmod +x test_interop.py
```

### 2. Run Interoperability Tests

```bash
# Test against ant-quic server
./test_interop.py

# Test all known endpoints
./test_interop.py --all

# Save results
./test_interop.py --all --output results.json
```

## Quick Tests by Feature

### Test 0-RTT

```bash
# First connection (saves session)
./ant-quic --connect quic.saorsalabs.com:9000 --save-session

# Second connection (uses 0-RTT)
./ant-quic --connect quic.saorsalabs.com:9000 --enable-0rtt
```

### Test Performance

```bash
# Download speed test (10MB)
./ant-quic --connect quic.saorsalabs.com:9000 --download-test 10

# Upload speed test (10MB)
./ant-quic --connect quic.saorsalabs.com:9000 --upload-test 10

# Latency test (100 pings)
./ant-quic --connect quic.saorsalabs.com:9000 --ping-test 100
```

### Test Connection Migration

```bash
# Test path migration
./ant-quic --connect quic.saorsalabs.com:9000 --test-migration
```

## Debugging Failed Tests

### Enable Debug Logging

```bash
# Verbose output
RUST_LOG=debug ./ant-quic --connect quic.saorsalabs.com:9000

# Trace frames
RUST_LOG=ant_quic::frame=trace ./ant-quic --connect quic.saorsalabs.com:9000
```

### Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| Connection timeout | Check firewall allows UDP port 9000 |
| Certificate error | Update to latest ant-quic version |
| NAT traversal fails | Ensure outbound UDP is allowed |
| Performance is slow | Check network congestion, try different server |

### Check Your NAT Type

```bash
./ant-quic --nat-check

# Output:
# Checking NAT configuration...
# NAT Type: Port Restricted Cone
# External IP: 203.0.113.5
# Supports hairpinning: Yes
# Predictable ports: No
```

## Testing Your Own QUIC Implementation

### 1. Test Against ant-quic Server

```bash
# Your client should connect to:
# Host: quic.saorsalabs.com
# Port: 9000
# ALPN: "ant-quic/1"

your-quic-client connect quic.saorsalabs.com:9000
```

### 2. Expected Behavior

- TLS 1.3 handshake
- QUIC version 1 (0x00000001)
- Support for migration
- Echo service on stream 0

### 3. Validate Protocol Extensions

```bash
# Check for OBSERVED_ADDRESS frames
your-quic-client connect quic.saorsalabs.com:9000 --log-frames

# Should see:
# RX Frame: OBSERVED_ADDRESS seq=1 addr=203.0.113.5:12345
```

## Next Steps

1. **Full Testing Guide**: See [EXTERNAL_TESTING_GUIDE.md](EXTERNAL_TESTING_GUIDE.md)
2. **API Reference**: See [API_REFERENCE.md](API_REFERENCE.md)
3. **Protocol Details**: See [PROTOCOL_EXTENSIONS.md](PROTOCOL_EXTENSIONS.md)
4. **Report Issues**: https://github.com/dirvine/ant-quic/issues

## Quick Command Reference

```bash
# Help
./ant-quic --help

# Version
./ant-quic --version

# Basic connection
./ant-quic --connect <host:port>

# With options
./ant-quic --connect <host:port> \
    --enable-nat-traversal \
    --enable-0rtt \
    --log-level debug \
    --timeout 30

# Server mode
./ant-quic --listen 0.0.0.0:9000

# Bootstrap node
./ant-quic --listen 0.0.0.0:9000 --force-coordinator
```

## Support

- **Chat**: Discord/Matrix (see README)
- **Issues**: GitHub Issues
- **Email**: support@example.com

Happy testing! 🚀
