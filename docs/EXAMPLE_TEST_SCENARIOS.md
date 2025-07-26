# Example Test Scenarios for ant-quic

This document provides ready-to-run test scenarios for validating different aspects of ant-quic. Each scenario includes the exact commands to run and what to expect.

## Quick Test Suite (5 minutes)

Run these tests for a quick validation of ant-quic functionality:

```bash
#!/bin/bash
# Save as quick-test.sh and run with: bash quick-test.sh

echo "=== ant-quic Quick Test Suite ==="
echo "Version: $(./ant-quic --version)"
echo ""

# Test 1: Basic connectivity
echo "1. Testing basic QUIC connectivity..."
./ant-quic --connect www.google.com:443 --timeout 5
echo ""

# Test 2: NAT detection  
echo "2. Detecting NAT configuration..."
./ant-quic --nat-check
echo ""

# Test 3: Performance quick test
echo "3. Quick performance test..."
./ant-quic --connect quic.tech:443 --quick-perf
echo ""

echo "=== Quick Test Complete ==="
```

## Comprehensive Test Scenarios

### Scenario 1: Home Network Testing

**Purpose:** Validate ant-quic behavior on typical home networks with consumer routers.

```bash
# Step 1: Baseline network analysis
echo "=== Home Network Test Scenario ==="
./ant-quic --analyze-network

# Step 2: Test connectivity to multiple endpoints
for endpoint in "www.google.com:443" "cloudflare.com:443" "facebook.com:443"; do
    echo "Testing $endpoint..."
    ./ant-quic --connect "$endpoint" --test basic
done

# Step 3: P2P test with a friend
# On your machine:
./ant-quic --listen 0.0.0.0:0 --show-peer-id

# Have your friend run:
./ant-quic --connect <your-peer-id> --bootstrap bootstrap.ant-quic.net:9000

# Step 4: UPnP test (if router supports it)
./ant-quic --test-upnp
```

### Scenario 2: Corporate Network Testing  

**Purpose:** Test ant-quic in restrictive corporate environments.

```bash
# Corporate networks often have strict firewalls
# Run these tests to check compatibility

# Test 1: Restrictive firewall bypass
./ant-quic --connect quic.tech:443 --firewall-test

# Test 2: Proxy detection and bypass
./ant-quic --detect-proxy
./ant-quic --connect quic.tech:443 --proxy-aware

# Test 3: Alternative ports
for port in 443 8443 4433 9000; do
    echo "Trying port $port..."
    ./ant-quic --connect test.ant-quic.net:$port --timeout 10
done

# Test 4: Deep packet inspection evasion
./ant-quic --connect quic.tech:443 --obfuscate
```

### Scenario 3: Mobile/CGNAT Testing

**Purpose:** Validate functionality behind carrier-grade NAT.

```bash
# Mobile networks have challenging NAT configurations
# These tests verify ant-quic works properly

# Test 1: CGNAT detection
./ant-quic --detect-cgnat

# Test 2: Multiple NAT layer traversal
./ant-quic --connect peer --trace-nat-layers

# Test 3: Connection persistence
./ant-quic --connect test.ant-quic.net:443 --persist-test --duration 300

# Test 4: Rapid network changes (WiFi to Mobile)
./ant-quic --connect test.ant-quic.net:443 --migration-test
```

### Scenario 4: Performance Benchmarking

**Purpose:** Measure ant-quic performance in your environment.

```bash
#!/bin/bash
# Comprehensive performance testing

echo "=== Performance Benchmark ==="

# Test 1: Throughput test
echo "1. Throughput Test"
./ant-quic --benchmark throughput --server speedtest.ant-quic.net:443

# Test 2: Latency distribution
echo "2. Latency Analysis"
./ant-quic --benchmark latency --samples 1000 --server quic.tech:443

# Test 3: Concurrent connections
echo "3. Connection Scaling"
for conns in 1 10 50 100; do
    echo "Testing with $conns connections..."
    ./ant-quic --benchmark concurrent --connections $conns
done

# Test 4: Resource usage
echo "4. Resource Usage"
./ant-quic --benchmark resources --duration 60

# Generate report
./ant-quic --benchmark report --output perf-report.html
```

### Scenario 5: NAT Traversal Matrix Test

**Purpose:** Test P2P connectivity between different NAT types.

```bash
# This requires coordination between two testers
# Tester A and Tester B should be on different networks

# Both testers first identify their NAT type:
./ant-quic --nat-check --detailed

# Test Matrix:
# Run each combination and record results

# 1. Full Cone ↔ Full Cone
# Tester A: ./ant-quic --p2p-test --listen
# Tester B: ./ant-quic --p2p-test --connect <peer-id-A>

# 2. Full Cone ↔ Restricted
# 3. Full Cone ↔ Symmetric  
# 4. Restricted ↔ Restricted
# 5. Restricted ↔ Symmetric
# 6. Symmetric ↔ Symmetric

# Automated matrix test (requires test partner):
./ant-quic --nat-matrix-test --partner <partner-endpoint>
```

### Scenario 6: Protocol Compliance Testing

**Purpose:** Verify QUIC protocol compliance and extension support.

```bash
# Test 1: Version negotiation
echo "Testing QUIC version negotiation..."
./ant-quic --compliance-test version-negotiation

# Test 2: Transport parameters
echo "Testing transport parameter negotiation..."
./ant-quic --compliance-test transport-params --verbose

# Test 3: Extension frames
echo "Testing QUIC extensions..."
./ant-quic --compliance-test extensions --check-all

# Test 4: Error handling
echo "Testing error conditions..."
./ant-quic --compliance-test errors --fuzzing

# Full compliance report
./ant-quic --compliance-test full --output compliance-report.json
```

### Scenario 7: Stress Testing

**Purpose:** Push ant-quic to its limits to find breaking points.

```bash
# WARNING: These tests consume significant resources

# Test 1: Connection storm
echo "Connection storm test (1000 connections in 10 seconds)..."
./ant-quic --stress-test connection-storm --rate 100 --duration 10

# Test 2: Data flood
echo "Data flood test (1GB transfer on 10 connections)..."
./ant-quic --stress-test data-flood --connections 10 --data 1024MB

# Test 3: Rapid reconnection
echo "Rapid reconnection test..."
./ant-quic --stress-test reconnect --iterations 1000 --delay 100ms

# Test 4: Memory stress
echo "Memory stress test..."
./ant-quic --stress-test memory --allocations 100000

# Monitor during stress tests:
./ant-quic --monitor --interval 1
```

### Scenario 8: Security Testing

**Purpose:** Validate security features and resistance to attacks.

```bash
# Test 1: Certificate validation
echo "Testing certificate validation..."
./ant-quic --security-test certificates

# Test 2: Amplification resistance
echo "Testing amplification attack resistance..."
./ant-quic --security-test amplification

# Test 3: Connection ID privacy
echo "Testing connection ID privacy..."
./ant-quic --security-test connection-id-privacy

# Test 4: 0-RTT replay protection
echo "Testing 0-RTT replay protection..."
./ant-quic --security-test zero-rtt-replay

# Full security audit
./ant-quic --security-test full-audit --output security-report.pdf
```

### Scenario 9: Interoperability Testing

**Purpose:** Test compatibility with other QUIC implementations.

```bash
#!/bin/bash
# Test against major QUIC implementations

implementations=(
    "google:www.google.com:443"
    "cloudflare:cloudflare.com:443"
    "facebook:www.facebook.com:443"
    "akamai:akamai.com:443"
    "fastly:fastly.com:443"
)

echo "=== Interoperability Test ==="
for impl in "${implementations[@]}"; do
    IFS=':' read -r name host port <<< "$impl"
    echo "Testing $name ($host:$port)..."
    ./ant-quic --interop-test "$host:$port" --detailed
    echo ""
done

# Generate compatibility matrix
./ant-quic --interop-test report --format markdown > interop-results.md
```

### Scenario 10: Real-World Application Test

**Purpose:** Test ant-quic with real application workloads.

```bash
# Test 1: File transfer
echo "Testing file transfer..."
# Create test file
dd if=/dev/urandom of=test-100mb.bin bs=1M count=100

# Upload test
./ant-quic --file-transfer upload test-100mb.bin --to test.ant-quic.net:443

# Download test  
./ant-quic --file-transfer download test-100mb.bin --from test.ant-quic.net:443

# Test 2: Streaming
echo "Testing streaming..."
./ant-quic --stream-test video --bitrate 5mbps --duration 60

# Test 3: Interactive (gaming-like)
echo "Testing interactive workload..."
./ant-quic --app-test gaming --latency-target 50ms --duration 300

# Test 4: Web browsing pattern
echo "Testing web browsing pattern..."
./ant-quic --app-test web --concurrent-streams 6 --requests 1000
```

## Automated Test Runner

Save this script to run all tests automatically:

```bash
#!/bin/bash
# ant-quic-full-test.sh
# Run with: bash ant-quic-full-test.sh

set -e

REPORT_DIR="ant-quic-test-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$REPORT_DIR"

echo "ant-quic Full Test Suite"
echo "Results will be saved to: $REPORT_DIR"
echo ""

# Function to run test and save output
run_test() {
    local test_name=$1
    local test_command=$2
    echo "Running: $test_name"
    echo "Command: $test_command"
    eval "$test_command" > "$REPORT_DIR/$test_name.log" 2>&1
    if [ $? -eq 0 ]; then
        echo "✓ Passed"
    else
        echo "✗ Failed (see $REPORT_DIR/$test_name.log)"
    fi
    echo ""
}

# Run all test scenarios
run_test "version" "./ant-quic --version"
run_test "basic-connectivity" "./ant-quic --connect www.google.com:443 --timeout 10"
run_test "nat-detection" "./ant-quic --nat-check"
run_test "performance" "./ant-quic --quick-perf"
run_test "interop-google" "./ant-quic --connect www.google.com:443 --test basic"
run_test "interop-cloudflare" "./ant-quic --connect cloudflare.com:443 --test basic"
run_test "protocol-compliance" "./ant-quic --compliance-test basic"

# Generate summary report
echo "Generating summary report..."
./ant-quic --generate-report "$REPORT_DIR" --format html

echo "Test suite complete!"
echo "View report: open $REPORT_DIR/report.html"
```

## Test Result Interpretation

### Success Indicators
- ✅ Connection established in < 200ms
- ✅ NAT traversal success rate > 85%  
- ✅ Throughput > 80% of line speed
- ✅ CPU usage < 10% for normal operation
- ✅ No memory leaks over 24 hours

### Warning Signs
- ⚠️ Connection time > 500ms
- ⚠️ NAT traversal success < 70%
- ⚠️ Frequent connection drops
- ⚠️ High CPU usage (>50%)
- ⚠️ Throughput < 50% of line speed

### Failure Indicators  
- ❌ Cannot establish connections
- ❌ Crashes or panics
- ❌ Memory leaks
- ❌ Protocol violations
- ❌ Security vulnerabilities

## Tips for Effective Testing

1. **Test at Different Times**
   - Network conditions vary throughout the day
   - Test during peak and off-peak hours

2. **Test from Different Locations**
   - Home, office, coffee shop, mobile
   - Different ISPs and network types

3. **Document Everything**
   - Keep logs of all tests
   - Note any unusual observations
   - Screenshot errors

4. **Test Edge Cases**
   - Very slow connections
   - High packet loss
   - Rapid network changes
   - Resource constraints

5. **Compare with Other Tools**
   - Test same endpoints with curl/wget
   - Compare performance metrics
   - Note any differences

## Contributing Your Test Results

After running these scenarios, please:
1. Fill out the test report template
2. Include logs and screenshots
3. Submit via GitHub or email
4. Join our Discord to discuss results

Your testing helps make ant-quic better for everyone!