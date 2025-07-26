# ant-quic Test Report Template

Please use this template when reporting test results for ant-quic. Fill in all applicable sections.

## Test Information

**Date:** [YYYY-MM-DD]  
**Time:** [HH:MM UTC]  
**Tester:** [Your name/organization]  
**ant-quic Version:** [Run `ant-quic --version`]  
**Test Duration:** [How long did you test?]  

## Test Environment

### System Information
- **Operating System:** [e.g., Ubuntu 22.04, Windows 11, macOS 13.5]
- **Architecture:** [x86_64, arm64, etc.]
- **CPU:** [Model and cores]
- **RAM:** [Amount]
- **Network Interface:** [Ethernet/WiFi/Mobile]

### Network Configuration
- **Connection Type:** [ ] Home [ ] Office [ ] Data Center [ ] Mobile [ ] Public WiFi
- **NAT Type:** [Run `ant-quic --nat-check`]
- **ISP:** [Provider name]
- **Geographic Location:** [Country/Region]
- **IPv6 Support:** [ ] Yes [ ] No [ ] Partial

### Network Characteristics
- **Download Speed:** [Mbps]
- **Upload Speed:** [Mbps]
- **Latency to 8.8.8.8:** [ms]
- **Packet Loss:** [%]

## Test Results Summary

### Overall Assessment
- **Overall Success Rate:** [X/Y tests passed]
- **Critical Issues Found:** [ ] Yes [ ] No
- **Performance Assessment:** [ ] Excellent [ ] Good [ ] Fair [ ] Poor

### Quick Test Results

| Test Category | Pass | Fail | Notes |
|--------------|------|------|-------|
| Basic Connectivity | ☐ | ☐ | |
| NAT Traversal | ☐ | ☐ | |
| Performance | ☐ | ☐ | |
| Interoperability | ☐ | ☐ | |
| Stability | ☐ | ☐ | |

## Detailed Test Results

### 1. Basic Connectivity Tests

#### Test 1.1: QUIC Handshake
**Command:** `ant-quic --connect www.google.com:443`
- **Result:** [ ] Pass [ ] Fail
- **Connection Time:** ___ ms
- **QUIC Version Negotiated:** ___
- **Error Message (if failed):** ___

#### Test 1.2: Multiple Endpoints
Tested against the following endpoints:

| Endpoint | Success | Time (ms) | Notes |
|----------|---------|-----------|-------|
| google.com:443 | ☐ | | |
| cloudflare.com:443 | ☐ | | |
| facebook.com:443 | ☐ | | |
| quic.tech:443 | ☐ | | |

### 2. NAT Traversal Tests

#### Test 2.1: NAT Detection
**Command:** `ant-quic --nat-check`
- **Detected NAT Type:** ___
- **External IP:** ___
- **Port Mapping:** [ ] Consistent [ ] Random
- **Hairpinning:** [ ] Supported [ ] Not Supported

#### Test 2.2: P2P Connection
**Setup:** Two nodes behind different NATs
- **Node A NAT Type:** ___
- **Node B NAT Type:** ___
- **Connection Result:** [ ] Direct [ ] Relay [ ] Failed
- **Time to Connect:** ___ ms
- **Hole Punching Attempts:** ___

#### Test 2.3: Complex NAT Scenarios
- **CGNAT Test:** [ ] Pass [ ] Fail [ ] N/A
- **Symmetric NAT Test:** [ ] Pass [ ] Fail [ ] N/A
- **Double NAT Test:** [ ] Pass [ ] Fail [ ] N/A

### 3. Performance Tests

#### Test 3.1: Throughput
**Command:** `ant-quic --performance-test`
- **Download Speed:** ___ Mbps
- **Upload Speed:** ___ Mbps
- **Compared to Line Speed:** ___% efficiency

#### Test 3.2: Latency
**Command:** `ant-quic --ping-test 1000`
- **Min RTT:** ___ ms
- **Avg RTT:** ___ ms
- **Max RTT:** ___ ms
- **Jitter:** ___ ms
- **Packet Loss:** ____%

#### Test 3.3: Resource Usage
During sustained transfer:
- **CPU Usage:** ____%
- **Memory Usage:** ___ MB
- **Thread Count:** ___

### 4. Protocol Compliance Tests

#### Test 4.1: Extension Support
- **OBSERVED_ADDRESS frames:** [ ] Detected [ ] Not Detected
- **NAT Traversal Extension:** [ ] Working [ ] Not Working
- **Transport Parameters:** [ ] Properly Negotiated [ ] Issues

#### Test 4.2: Feature Tests
- **0-RTT:** [ ] Working [ ] Not Working [ ] Not Tested
- **Connection Migration:** [ ] Working [ ] Not Working [ ] Not Tested
- **Multipath:** [ ] Working [ ] Not Working [ ] Not Tested

### 5. Stability Tests

#### Test 5.1: Long Duration
**Duration:** ___ hours
- **Connections Maintained:** ___
- **Disconnections:** ___
- **Memory Leaks:** [ ] None [ ] Suspected [ ] Confirmed

#### Test 5.2: Stress Test
**Concurrent Connections:** ___
- **Success Rate:** ____%
- **Resource Exhaustion:** [ ] No [ ] Yes (describe: ___)

## Issues Encountered

### Issue 1
- **Description:** 
- **Steps to Reproduce:**
- **Expected Behavior:**
- **Actual Behavior:**
- **Error Messages:**
- **Workaround Found:** [ ] Yes [ ] No

### Issue 2
[Copy format from Issue 1]

## Performance Graphs/Data

[Attach or link to any performance graphs, packet captures, or raw data]

## Interoperability Matrix

| Implementation | Version | Basic | NAT | Perf | Notes |
|----------------|---------|-------|-----|------|-------|
| Google QUIC | | ☐ | ☐ | ☐ | |
| Cloudflare quiche | | ☐ | ☐ | ☐ | |
| Facebook mvfst | | ☐ | ☐ | ☐ | |
| Microsoft MsQuic | | ☐ | ☐ | ☐ | |
| Quinn | | ☐ | ☐ | ☐ | |

## Recommendations

### For ant-quic Development Team
1. 
2. 
3. 

### For Documentation
1. 
2. 

### For Future Testing
1. 
2. 

## Additional Comments

[Any other observations, suggestions, or feedback]

## Attachments

- [ ] Log files (`ant-quic-test-YYYYMMDD.log`)
- [ ] Packet captures (`test.pcap`)
- [ ] Performance graphs
- [ ] Screenshots (if UI-related)
- [ ] Configuration files used

---

**Submission Instructions:**
1. Save this completed template as `ant-quic-test-report-YYYYMMDD-[your-org].md`
2. Submit via one of these methods:
   - GitHub Issue: https://github.com/dirvine/ant-quic/issues/new
   - Email: test-reports@ant-quic.net
   - Community Portal: https://ant-quic.net/submit-test

**Thank you for testing ant-quic!**