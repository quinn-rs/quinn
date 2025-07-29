# External Testing Guide for ant-quic

This guide is for external testers who want to validate the ant-quic QUIC implementation's interoperability and NAT traversal capabilities.

## Public Test Endpoint

We maintain a public ant-quic test instance for interoperability testing:

- **Endpoint**: `quic.saorsalabs.com:9000` (UDP)
- **IPv4**: `YOUR.IP.HERE:9000`
- **IPv6**: `[YOUR:IPv6:HERE]:9000`
- **Dashboard**: https://quic.saorsalabs.com
- **Health Check**: https://quic.saorsalabs.com/health

## Testing Scenarios

### 1. Basic QUIC Connectivity Test

Test basic QUIC handshake and connection establishment:

```bash
# Using ant-quic client
ant-quic --connect quic.saorsalabs.com:9000

# Using quinn-examples (if compatible)
cargo run --example client quic.saorsalabs.com:9000

# Using quiche
quiche-client https://quic.saorsalabs.com:9000
```

Expected result: Successful QUIC connection with TLS 1.3 handshake.

### 2. NAT Traversal Testing

Test NAT traversal capabilities with our QUIC extensions:

```bash
# Behind NAT (most home/office networks)
ant-quic --connect quic.saorsalabs.com:9000 --enable-nat-traversal

# Expected output:
# - Local candidate addresses discovered
# - Server reflexive address received
# - Successful connection through NAT
```

### 3. Address Discovery Protocol

Test the OBSERVED_ADDRESS frame implementation:

```bash
# Enable debug logging to see address discovery
RUST_LOG=ant_quic::frame=debug ant-quic --connect quic.saorsalabs.com:9000

# Look for:
# - "Received OBSERVED_ADDRESS frame"
# - "Updated server reflexive address"
```

### 4. Simultaneous Connection Test

Test connection racing and path migration:

```bash
# Start two connections simultaneously
ant-quic --connect quic.saorsalabs.com:9000 &
ant-quic --connect quic.saorsalabs.com:9000 &

# Both should succeed without interference
```

### 5. Performance Testing

Measure throughput and latency:

```bash
# Download test (1GB file)
ant-quic --connect quic.saorsalabs.com:9000 --download-test

# Upload test (100MB)
ant-quic --connect quic.saorsalabs.com:9000 --upload-test

# Latency test (1000 pings)
ant-quic --connect quic.saorsalabs.com:9000 --ping-test
```

## Interoperability Matrix

Test ant-quic against other QUIC implementations:

| Your Implementation | Test Type | Expected Result |
|-------------------|-----------|-----------------|
| quinn | Basic connectivity | ✅ Success |
| quiche | Basic connectivity | ✅ Success |
| mvfst | Basic connectivity | ✅ Success |
| picoquic | Basic connectivity | ✅ Success |
| Any | NAT traversal | ✅ Success (with our extensions) |

## Test Tools

### 1. Command-Line Client

```bash
# Install ant-quic client
wget https://github.com/dirvine/ant-quic/releases/latest/download/ant-quic-linux-x86_64
chmod +x ant-quic-linux-x86_64
./ant-quic-linux-x86_64 --help
```

### 2. Docker Test Environment

```bash
# Run test client in Docker
docker run --rm -it ghcr.io/dirvine/ant-quic:latest \
  ant-quic --connect quic.saorsalabs.com:9000
```

### 3. Python Test Script

```python
#!/usr/bin/env python3
import subprocess
import json
import sys

def test_ant_quic(endpoint):
    """Test ant-quic connectivity and features"""

    tests = {
        "basic_connectivity": [
            "ant-quic", "--connect", endpoint, "--test", "basic"
        ],
        "nat_traversal": [
            "ant-quic", "--connect", endpoint, "--test", "nat"
        ],
        "performance": [
            "ant-quic", "--connect", endpoint, "--test", "perf"
        ]
    }

    results = {}
    for test_name, cmd in tests.items():
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            results[test_name] = {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr
            }
        except subprocess.TimeoutExpired:
            results[test_name] = {
                "success": False,
                "error": "Timeout after 30 seconds"
            }

    return results

if __name__ == "__main__":
    endpoint = sys.argv[1] if len(sys.argv) > 1 else "quic.saorsalabs.com:9000"
    results = test_ant_quic(endpoint)
    print(json.dumps(results, indent=2))
```

## API Endpoints

The test server exposes several HTTP(S) API endpoints for testing:

### Health Check
```bash
curl https://quic.saorsalabs.com/health
# Response: "OK"
```

### Server Statistics
```bash
curl https://quic.saorsalabs.com/api/stats
# Response: JSON with connection statistics
```

### NAT Traversal Stats
```bash
curl https://quic.saorsalabs.com/api/stats/nat
# Response: JSON with NAT traversal success rates
```

### Test Echo Service
```bash
# Send data and receive echo
echo "Hello QUIC" | ant-quic --connect quic.saorsalabs.com:9000 --echo
```

## Debugging Connection Issues

### 1. Enable Verbose Logging

```bash
RUST_LOG=ant_quic=debug ant-quic --connect quic.saorsalabs.com:9000
```

### 2. Packet Capture

```bash
# Capture QUIC packets
sudo tcpdump -i any -w quic-test.pcap 'udp port 9000'

# Analyze with Wireshark (with QUIC dissector)
wireshark quic-test.pcap
```

### 3. Check NAT Type

```bash
# Our endpoint will report your NAT type
ant-quic --connect quic.saorsalabs.com:9000 --nat-check
```

## Reporting Issues

When reporting interoperability issues, please include:

1. **Your QUIC implementation** (name and version)
2. **Test scenario** that failed
3. **Error messages** or unexpected behavior
4. **Packet capture** if possible
5. **Your network environment** (NAT type, firewall, etc.)

Report issues at: https://github.com/dirvine/ant-quic/issues

## Advanced Testing

### Custom Transport Parameters

Test with specific transport parameters:

```bash
ant-quic --connect quic.saorsalabs.com:9000 \
  --max-idle-timeout 60000 \
  --initial-max-data 10485760 \
  --initial-max-stream-data-bidi-local 1048576
```

### Migration Testing

Test connection migration between networks:

```bash
# Start connection on WiFi
ant-quic --connect quic.saorsalabs.com:9000 --interactive

# In interactive mode:
> migrate eth0  # Switch to ethernet
> migrate wlan0 # Switch back to WiFi
```

### 0-RTT Testing

Test 0-RTT data transmission:

```bash
# First connection (saves session)
ant-quic --connect quic.saorsalabs.com:9000 --save-session

# Subsequent connection with 0-RTT
ant-quic --connect quic.saorsalabs.com:9000 --enable-0rtt
```

## Compliance Testing

Our implementation aims for compliance with:

- RFC 9000 (QUIC Transport)
- RFC 9001 (QUIC TLS)
- draft-ietf-quic-address-discovery-00
- draft-seemann-quic-nat-traversal-02

### Test Compliance

```bash
# Run compliance test suite
ant-quic --compliance-test quic.saorsalabs.com:9000

# Output includes:
# - Supported versions
# - Extension support
# - Transport parameter negotiation
# - Frame type support
```

## Performance Benchmarks

Expected performance metrics:

- **Handshake RTT**: < 2 RTT (< 1 RTT with 0-RTT)
- **Throughput**: > 1 Gbps (depends on network)
- **Connection establishment**: < 100ms
- **NAT traversal success rate**: > 85%

## Contact

- **Technical Issues**: https://github.com/dirvine/ant-quic/issues
- **Security Issues**: security@example.com
- **General Inquiries**: quic-quic.saorsalabs.com

Thank you for testing ant-quic!
