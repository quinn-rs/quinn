# Test Result Submission Template

Please use this template when submitting test results for ant-quic interoperability testing.

## Tester Information

**Organization/Individual**: [Your name or organization]  
**Contact Email**: [your-email@example.com]  
**Date of Testing**: [YYYY-MM-DD]  
**ant-quic Version Tested**: [e.g., v0.4.4 or commit hash]  

## Test Environment

**Your QUIC Implementation**:
- Name: [e.g., quinn, quiche, mvfst]
- Version: [e.g., 0.10.0]
- Language: [e.g., Rust, C++, Go]
- Repository: [GitHub URL if open source]

**Test Platform**:
- OS: [e.g., Ubuntu 22.04, macOS 13.0, Windows 11]
- Architecture: [e.g., x86_64, arm64]
- Network Type: [e.g., Datacenter, Home broadband, Mobile]
- NAT Type: [e.g., Full Cone, Symmetric, None]

**Test Endpoint Used**:
- [ ] ant-quic-test.example.com:9000 (Production)
- [ ] Custom endpoint: _______________

## Test Results

### 1. Basic Connectivity

**Status**: [ ] PASS  [ ] FAIL  [ ] PARTIAL

**Details**:
```
Connection establishment time: _____ ms
QUIC version negotiated: 0x_________
ALPN negotiated: _______________
TLS cipher suite: ______________
```

**Issues/Notes**:
```
[Any errors or unexpected behavior]
```

### 2. Protocol Compliance

**RFC 9000 (QUIC v1) Compliance**: [ ] PASS  [ ] FAIL  [ ] N/A

**Supported Features**:
- [ ] Stream multiplexing
- [ ] Flow control
- [ ] Connection migration
- [ ] 0-RTT
- [ ] Stateless reset
- [ ] Key update

**Transport Parameters Exchanged**:
```
initial_max_data: _______
initial_max_stream_data_bidi_local: _______
initial_max_stream_data_bidi_remote: _______
initial_max_streams_bidi: _______
initial_max_streams_uni: _______
max_idle_timeout: _______
```

### 3. NAT Traversal Testing

**Status**: [ ] PASS  [ ] FAIL  [ ] NOT_TESTED

**Your NAT Configuration**:
- Type: [Full Cone / Restricted / Port Restricted / Symmetric]
- Predictable ports: [ ] Yes  [ ] No
- Hairpinning support: [ ] Yes  [ ] No

**Results**:
```
Direct connection: [ ] Success  [ ] Failed
Relay required: [ ] Yes  [ ] No
Connection establishment time: _____ ms
Number of candidates tried: _____
Hole punching rounds: _____
```

**OBSERVED_ADDRESS Frame Support**:
- [ ] Sent by ant-quic
- [ ] Received and processed
- [ ] Sequence numbers validated
- [ ] Address updated correctly

### 4. Extension Frame Support

**Frames Observed**:
- [ ] OBSERVED_ADDRESS (0x43)
- [ ] ADD_ADDRESS (0x40)
- [ ] PUNCH_ME_NOW (0x41)
- [ ] REMOVE_ADDRESS (0x42)

**Frame Handling**:
```
Unknown frame handling: [ ] Ignored  [ ] Connection error
Extension negotiation: [ ] Success  [ ] Failed
```

### 5. Performance Metrics

**Throughput Test** (10MB transfer):
```
Download: _____ Mbps
Upload: _____ Mbps
```

**Latency Test** (100 samples):
```
Min RTT: _____ ms
Avg RTT: _____ ms
Max RTT: _____ ms
Jitter: _____ ms
Packet loss: _____ %
```

**Resource Usage**:
```
CPU usage: _____ %
Memory usage: _____ MB
Active streams tested: _____
```

### 6. Stress Testing (Optional)

**Concurrent Connections**: _____  
**Streams per Connection**: _____  
**Test Duration**: _____ minutes  
**Failures**: _____  
**Success Rate**: _____ %

### 7. Interoperability Issues

**Issues Encountered**:

1. **Issue**: [Brief description]
   - **Severity**: [ ] Critical  [ ] Major  [ ] Minor
   - **Reproducible**: [ ] Always  [ ] Sometimes  [ ] Once
   - **Error Message**: `[exact error if any]`
   - **Expected Behavior**: [what should happen]
   - **Actual Behavior**: [what actually happened]

2. **Issue**: [Add more as needed]

### 8. Compatibility Matrix

Rate compatibility (1-5, where 5 is perfect):

| Feature | Rating | Notes |
|---------|---------|-------|
| Connection establishment | _/5 | |
| Stream handling | _/5 | |
| Flow control | _/5 | |
| Congestion control | _/5 | |
| NAT traversal | _/5 | |
| Error handling | _/5 | |
| Performance | _/5 | |
| Overall | _/5 | |

## Additional Testing

### Security Testing (Optional)
- [ ] Certificate validation works correctly
- [ ] Invalid certificates rejected
- [ ] Amplification prevention works
- [ ] Rate limiting effective

### Edge Cases Tested (Optional)
- [ ] Large number of streams (>1000)
- [ ] Very small MTU (1200 bytes)
- [ ] High packet loss (>5%)
- [ ] High latency (>500ms)
- [ ] Connection migration
- [ ] NAT rebinding

## Logs and Packet Captures

**Debug Logs**: [ ] Attached  [ ] Available on request  [ ] Not available

**Packet Capture**: [ ] Attached  [ ] Available on request  [ ] Not available

**How to Reproduce**:
```bash
# Commands used for testing
[your test commands here]
```

## Recommendations

**For ant-quic team**:
```
[Any suggestions for improvements]
```

**For other implementers**:
```
[Lessons learned or tips]
```

## Declaration

- [ ] I agree to share these test results publicly
- [ ] I can be contacted for follow-up questions
- [ ] I'm interested in participating in future tests

## Submission

Please submit this completed form via one of these methods:

1. **GitHub Issue**: https://github.com/dirvine/ant-quic/issues/new?template=test-results.md
2. **Email**: quic-test-results@example.com
3. **PR**: Add to `docs/test-results/[your-org]-[date].md`

Thank you for testing ant-quic!

---

*Template Version: 1.0*  
*Last Updated: 2025-07-26*