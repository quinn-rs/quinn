# Security Audit Report - ant-quic

## Executive Summary

This security audit identified several security vulnerabilities and hardcoded values in the ant-quic codebase. The most critical finding is the presence of a certificate verification bypass that could completely compromise TLS security. Additionally, numerous hardcoded values were found that should be made configurable.

## Critical Security Vulnerabilities

### 1. Certificate Verification Bypass (CRITICAL)

**Location**: `src/nat_traversal_api.rs:2391-2410`

A `SkipServerVerification` struct implements a certificate verifier that accepts ANY certificate without validation:

```rust
impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
```

**Risk**: This completely bypasses TLS certificate validation, allowing man-in-the-middle attacks. While marked for testing only, its presence in production code is dangerous.

**Recommendation**: Remove this code entirely or move to test-only modules with clear compile-time guards.

### 2. Memory Safety Concerns

**Location**: `src/candidate_discovery/linux.rs`

Extensive use of unsafe code for network interface discovery:
- Raw pointer manipulation (`std::ptr::copy_nonoverlapping`)
- Unsafe system calls (socket operations, ioctl)
- Manual memory management with `std::mem::zeroed()`

**Risk**: Potential for buffer overflows, use-after-free, and other memory corruption vulnerabilities.

**Recommendation**: 
- Audit all unsafe blocks for proper bounds checking
- Consider using safe wrappers or existing crates for system calls
- Add comprehensive tests for edge cases

## Hardcoded Values

### 1. Network Ports and Addresses

**Hardcoded ports found**:
- Port 9000 (multiple locations)
- Port 8080 (frame.rs tests)
- Port 443 (frame.rs)
- Port 80 (monitoring)
- Port range 5000-10000 (NAT traversal)

**Hardcoded addresses**:
- `0.0.0.0:0` (candidate_discovery.rs)
- `127.0.0.1` (tests)
- `localhost` (monitoring endpoints)

**Examples**:
```rust
// src/validation/environment.rs:237
EndpointType::Primary => 9000,

// src/monitoring/metrics.rs:459
endpoint: "http://localhost:9090/api/v1/write".to_string(),

// src/candidate_discovery.rs:1634
SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100)), 8080)
```

### 2. Buffer Sizes and Limits

**Critical hardcoded constants**:
```rust
// src/lib.rs
const LOC_CID_COUNT: u64 = 8;
const RESET_TOKEN_SIZE: usize = 16;
const MAX_CID_SIZE: usize = 20;
const MIN_INITIAL_SIZE: u16 = 1200;
const INITIAL_MTU: u16 = 1200;
const MAX_UDP_PAYLOAD: u16 = 65527;
const MAX_STREAM_COUNT: u64 = 1 << 60;

// src/bloom_token_log.rs
const DEFAULT_MAX_BYTES: usize = 10 << 20; // 10MB
const DEFAULT_EXPECTED_HITS: u64 = 1_000_000;
```

### 3. Timeout Values

**Hardcoded timeouts**:
- Connection time: 5000ms (multiple locations)
- Various protocol-specific timeouts embedded in code

### 4. External Service URLs

**Hardcoded URLs found**:
```rust
// src/monitoring/alerting.rs:339
"runbook": "https://docs.example.com/runbooks/nat-success-rate"

// src/monitoring/alerting.rs:638
webhook_url: "https://hooks.slack.com/services/..."

// src/monitoring/distributed_tracing.rs:374
endpoint: "http://localhost:14268/api/traces"
```

## Rate Limiting and DoS Protection

**Positive finding**: The codebase includes rate limiting infrastructure:
- `RateLimit` configuration in NAT profiles
- Bandwidth throttling mechanisms
- Connection rate limiting

**Concern**: Rate limits appear to be configurable but default values should be reviewed for production use.

## Recommendations

### Immediate Actions Required

1. **Remove or properly guard the `SkipServerVerification` struct**
   - Move to test-only code with `#[cfg(test)]` guards
   - Or remove entirely and use proper test certificates

2. **Audit all unsafe code blocks**
   - Focus on `candidate_discovery/linux.rs`
   - Ensure proper bounds checking and error handling
   - Consider safe alternatives

3. **Externalize configuration**
   - Move all hardcoded ports to configuration
   - Make buffer sizes configurable with sensible defaults
   - Extract URLs to environment variables or config files

### Medium-term Improvements

1. **Implement proper secret management**
   - No hardcoded API keys or tokens (none found currently - good!)
   - Use environment variables or secure vaults for sensitive data

2. **Add security-focused tests**
   - Test certificate validation is working properly
   - Test rate limiting under stress
   - Fuzz testing for protocol handlers

3. **Security hardening**
   - Implement connection limits per IP
   - Add amplification attack prevention
   - Enhance logging for security events

## Positive Security Features Noted

1. No SQL injection risks (no SQL usage)
2. No command injection vulnerabilities found
3. Proper use of Rust's type system for memory safety (except unsafe blocks)
4. Rate limiting infrastructure in place
5. No hardcoded passwords or API keys found

## Conclusion

While the codebase shows good security practices in many areas, the certificate verification bypass is a critical vulnerability that must be addressed immediately. The extensive use of unsafe code in platform-specific modules requires careful review. Hardcoded configuration values should be externalized to improve deployment flexibility and security.