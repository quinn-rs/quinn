# ant-quic Comprehensive Test Plan for NAT Traversal & Raw Public Keys

## Test Categories

### 1. Frame Protocol Tests

#### 1.1 Frame Encoding/Decoding Tests
```rust
#[cfg(test)]
mod frame_tests {
    use super::*;
    
    #[test]
    fn test_add_address_frame_ipv4() {
        let frame = AddAddressFrame {
            sequence: VarInt::from_u32(42),
            address: "192.168.1.1:9000".parse().unwrap(),
        };
        
        let mut buf = Vec::new();
        frame.encode(&mut buf).unwrap();
        
        let decoded = AddAddressFrame::decode(0x3d7e90, &mut &buf[..]).unwrap();
        assert_eq!(frame.sequence, decoded.sequence);
        assert_eq!(frame.address, decoded.address);
    }
    
    #[test]
    fn test_add_address_frame_ipv6() {
        let frame = AddAddressFrame {
            sequence: VarInt::from_u32(99),
            address: "[2001:db8::1]:9000".parse().unwrap(),
        };
        
        let mut buf = Vec::new();
        frame.encode(&mut buf).unwrap();
        
        let decoded = AddAddressFrame::decode(0x3d7e91, &mut &buf[..]).unwrap();
        assert_eq!(frame.sequence, decoded.sequence);
        assert_eq!(frame.address, decoded.address);
    }
    
    #[test]
    fn test_punch_me_now_frame() {
        let frame = PunchMeNowFrame {
            round: VarInt::from_u32(1),
            paired_with_sequence: VarInt::from_u32(42),
            address: "10.0.0.1:8080".parse().unwrap(),
        };
        
        let mut buf = Vec::new();
        frame.encode(&mut buf).unwrap();
        
        let frame_type = 0x3d7e92; // IPv4
        let decoded = PunchMeNowFrame::decode(frame_type, &mut &buf[..]).unwrap();
        assert_eq!(frame.round, decoded.round);
        assert_eq!(frame.paired_with_sequence, decoded.paired_with_sequence);
        assert_eq!(frame.address, decoded.address);
    }
    
    #[test]
    fn test_remove_address_frame() {
        let frame = RemoveAddressFrame {
            sequence: VarInt::from_u32(123),
        };
        
        let mut buf = Vec::new();
        frame.encode(&mut buf).unwrap();
        
        let decoded = RemoveAddressFrame::decode(&mut &buf[..]).unwrap();
        assert_eq!(frame.sequence, decoded.sequence);
    }
}
```

#### 1.2 Frame Integration Tests
```rust
#[tokio::test]
async fn test_frame_transmission() {
    let (client, server) = create_connected_pair().await;
    
    // Server sends ADD_ADDRESS
    server.send_frame(Frame::AddAddress(AddAddressFrame {
        sequence: VarInt::from_u32(1),
        address: "203.0.113.1:9001".parse().unwrap(),
    })).await.unwrap();
    
    // Client receives and processes
    let frame = client.recv_frame().await.unwrap();
    match frame {
        Frame::AddAddress(add) => {
            assert_eq!(add.sequence, VarInt::from_u32(1));
        }
        _ => panic!("Wrong frame type"),
    }
}
```

### 2. NAT Type Simulation Tests

#### 2.1 NAT Simulator Implementation
```rust
pub trait NatSimulator: Send + Sync {
    fn process_outbound(&self, packet: &mut UdpPacket) -> NatResult;
    fn process_inbound(&self, packet: &UdpPacket) -> NatResult;
    fn get_external_mapping(&self, internal: SocketAddr) -> Option<SocketAddr>;
}

pub struct FullConeNat {
    mappings: Arc<RwLock<HashMap<SocketAddr, SocketAddr>>>,
    external_ip: IpAddr,
    next_port: AtomicU16,
}

pub struct SymmetricNat {
    mappings: Arc<RwLock<HashMap<(SocketAddr, SocketAddr), SocketAddr>>>,
    external_ip: IpAddr,
    next_port: AtomicU16,
}

pub struct RestrictedConeNat {
    mappings: Arc<RwLock<HashMap<SocketAddr, (SocketAddr, HashSet<IpAddr>)>>>,
    external_ip: IpAddr,
    next_port: AtomicU16,
}
```

#### 2.2 NAT Traversal Scenario Tests
```rust
#[tokio::test]
async fn test_full_cone_nat_traversal() {
    let nat_a = FullConeNat::new("198.51.100.1".parse().unwrap());
    let nat_b = FullConeNat::new("198.51.100.2".parse().unwrap());
    
    test_nat_traversal_scenario(nat_a, nat_b, ExpectedResult::Success).await;
}

#[tokio::test]
async fn test_symmetric_to_full_cone() {
    let nat_a = SymmetricNat::new("198.51.100.1".parse().unwrap());
    let nat_b = FullConeNat::new("198.51.100.2".parse().unwrap());
    
    test_nat_traversal_scenario(nat_a, nat_b, ExpectedResult::Success).await;
}

#[tokio::test]
async fn test_symmetric_to_symmetric() {
    let nat_a = SymmetricNat::new("198.51.100.1".parse().unwrap());
    let nat_b = SymmetricNat::new("198.51.100.2".parse().unwrap());
    
    // Should succeed with proper prediction
    test_nat_traversal_scenario(nat_a, nat_b, ExpectedResult::Success).await;
}

#[tokio::test]
async fn test_hairpin_nat() {
    let nat = FullConeNat::with_hairpin("198.51.100.1".parse().unwrap());
    
    // Both clients behind same NAT
    test_hairpin_scenario(nat, ExpectedResult::Success).await;
}
```

### 3. Raw Public Key Tests

#### 3.1 Certificate Type Negotiation Tests
```rust
#[test]
fn test_certificate_type_preference_encoding() {
    let prefs = CertificateTypePreferences::prefer_raw_public_key();
    
    // Encode to TLS extension
    let mut buf = Vec::new();
    prefs.encode(&mut buf).unwrap();
    
    // Decode and verify
    let decoded = CertificateTypePreferences::decode(&mut &buf[..]).unwrap();
    assert_eq!(prefs.client_types.types, decoded.client_types.types);
    assert_eq!(prefs.server_types.types, decoded.server_types.types);
}

#[tokio::test]
async fn test_rpk_negotiation_success() {
    let (client_prefs, server_prefs) = (
        CertificateTypePreferences::prefer_raw_public_key(),
        CertificateTypePreferences::raw_public_key_only(),
    );
    
    let result = negotiate_certificate_types(client_prefs, server_prefs);
    assert_eq!(result.client_cert_type, CertificateType::RawPublicKey);
    assert_eq!(result.server_cert_type, CertificateType::RawPublicKey);
}

#[tokio::test]
async fn test_rpk_fallback_to_x509() {
    let (client_prefs, server_prefs) = (
        CertificateTypePreferences::prefer_raw_public_key(),
        CertificateTypePreferences::x509_only(),
    );
    
    let result = negotiate_certificate_types(client_prefs, server_prefs);
    assert_eq!(result.client_cert_type, CertificateType::X509);
    assert_eq!(result.server_cert_type, CertificateType::X509);
}
```

#### 3.2 Ed25519 Key Operations Tests
```rust
#[test]
fn test_ed25519_spki_encoding() {
    let (_, public_key) = generate_ed25519_keypair();
    let spki = create_ed25519_subject_public_key_info(&public_key);
    
    // Verify ASN.1 structure
    assert_eq!(spki.len(), 44);
    assert_eq!(&spki[0..2], &[0x30, 0x2a]); // SEQUENCE, length 42
    assert_eq!(&spki[2..11], &[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21]);
    assert_eq!(&spki[12..44], public_key.as_bytes());
}

#[test]
fn test_peer_id_derivation() {
    let (_, public_key) = generate_ed25519_keypair();
    let peer_id = derive_peer_id_from_public_key(&public_key);
    
    // Verify deterministic
    let peer_id2 = derive_peer_id_from_public_key(&public_key);
    assert_eq!(peer_id, peer_id2);
    
    // Verify collision resistance
    let mut peer_ids = HashSet::new();
    for _ in 0..1000 {
        let (_, key) = generate_ed25519_keypair();
        let id = derive_peer_id_from_public_key(&key);
        assert!(peer_ids.insert(id));
    }
}
```

### 4. Integration Tests

#### 4.1 End-to-End NAT Traversal Test
```rust
#[tokio::test(flavor = "multi_thread")]
async fn test_e2e_nat_traversal_with_rpk() {
    // Setup test infrastructure
    let bootstrap = TestBootstrapNode::start().await;
    let nat_a = SymmetricNat::new("198.51.100.1".parse().unwrap());
    let nat_b = RestrictedConeNat::new("198.51.100.2".parse().unwrap());
    
    // Generate key pairs
    let (key_a, pub_a) = generate_ed25519_keypair();
    let (key_b, pub_b) = generate_ed25519_keypair();
    
    // Create endpoints with RPK
    let endpoint_a = create_nat_endpoint(
        EndpointRole::Client,
        key_a,
        vec![public_key_to_bytes(&pub_b)],
        bootstrap.addr(),
        nat_a,
    ).await;
    
    let endpoint_b = create_nat_endpoint(
        EndpointRole::Client,
        key_b,
        vec![public_key_to_bytes(&pub_a)],
        bootstrap.addr(),
        nat_b,
    ).await;
    
    // Establish proxied connection through bootstrap
    let proxy_conn_a = endpoint_a.connect_via_bootstrap(&bootstrap).await.unwrap();
    let proxy_conn_b = endpoint_b.connect_via_bootstrap(&bootstrap).await.unwrap();
    
    // Exchange peer information
    bootstrap.introduce_peers(&endpoint_a, &endpoint_b).await;
    
    // Initiate NAT traversal
    let traversal_result = timeout(
        Duration::from_secs(30),
        endpoint_a.traverse_nat_to(&endpoint_b)
    ).await.unwrap();
    
    assert!(traversal_result.is_ok());
    let direct_conn = traversal_result.unwrap();
    
    // Verify connection uses raw public keys
    assert_eq!(
        direct_conn.peer_public_key().unwrap(),
        public_key_to_bytes(&pub_b)
    );
    
    // Test bidirectional data transfer
    test_data_transfer(&direct_conn).await;
}
```

#### 4.2 IPv6 NAT Traversal Test
```rust
#[tokio::test]
async fn test_ipv6_nat_traversal() {
    let nat_a = FullConeNat::new_v6("2001:db8:1::1".parse().unwrap());
    let nat_b = SymmetricNat::new_v6("2001:db8:2::1".parse().unwrap());
    
    test_nat_traversal_scenario_v6(nat_a, nat_b, ExpectedResult::Success).await;
}

#[tokio::test]
async fn test_dual_stack_nat_traversal() {
    // Test traversal when one peer has IPv4 only and other has dual stack
    let nat_a = FullConeNat::new("198.51.100.1".parse().unwrap());
    let nat_b = DualStackNat::new(
        "198.51.100.2".parse().unwrap(),
        "2001:db8::1".parse().unwrap()
    );
    
    test_dual_stack_scenario(nat_a, nat_b, ExpectedResult::SuccessV4).await;
}
```

### 5. Performance and Stress Tests

#### 5.1 Concurrent NAT Traversal Test
```rust
#[tokio::test]
async fn stress_test_concurrent_nat_traversals() {
    const NUM_PAIRS: usize = 50;
    
    let bootstrap = TestBootstrapNode::start().await;
    let mut tasks = Vec::new();
    
    for i in 0..NUM_PAIRS {
        let bootstrap_addr = bootstrap.addr();
        let task = tokio::spawn(async move {
            let nat_a = create_random_nat(i * 2);
            let nat_b = create_random_nat(i * 2 + 1);
            
            let start = Instant::now();
            let result = test_nat_traversal_pair(
                nat_a,
                nat_b,
                bootstrap_addr
            ).await;
            
            (result, start.elapsed())
        });
        tasks.push(task);
    }
    
    let results: Vec<_> = futures::future::join_all(tasks).await;
    
    let successful = results.iter().filter(|r| r.as_ref().unwrap().0.is_ok()).count();
    let avg_duration = results.iter()
        .filter_map(|r| r.as_ref().ok())
        .filter(|(res, _)| res.is_ok())
        .map(|(_, dur)| dur.as_millis())
        .sum::<u128>() / successful as u128;
    
    println!("Success rate: {}/{}", successful, NUM_PAIRS);
    println!("Average traversal time: {}ms", avg_duration);
    
    assert!(successful as f64 / NUM_PAIRS as f64 > 0.9); // 90% success rate
    assert!(avg_duration < 5000); // Less than 5 seconds average
}
```

#### 5.2 Resource Usage Test
```rust
#[tokio::test]
async fn test_resource_cleanup() {
    let endpoint = create_test_endpoint().await;
    
    // Start many traversal attempts
    for i in 0..100 {
        let peer_id = PeerId::from([i as u8; 32]);
        endpoint.initiate_nat_traversal(
            peer_id,
            "198.51.100.1:9000".parse().unwrap()
        ).unwrap();
    }
    
    // Let some time pass
    tokio::time::sleep(Duration::from_secs(2)).await;
    
    // Trigger cleanup
    endpoint.cleanup_stale_sessions(Duration::from_secs(1));
    
    // Verify resources are cleaned up
    let stats = endpoint.get_statistics().unwrap();
    assert!(stats.active_sessions < 10);
}
```

### 6. Security Tests

#### 6.1 Amplification Attack Prevention
```rust
#[tokio::test]
async fn test_punch_me_now_rate_limiting() {
    let (client, server) = create_connected_pair().await;
    
    // Send many PUNCH_ME_NOW frames rapidly
    let mut sent = 0;
    for round in 0..100 {
        let frame = PunchMeNowFrame {
            round: VarInt::from_u32(round),
            paired_with_sequence: VarInt::from_u32(1),
            address: format!("10.0.0.{}:8080", round).parse().unwrap(),
        };
        
        if client.send_frame(Frame::PunchMeNow(frame)).await.is_ok() {
            sent += 1;
        }
    }
    
    // Server should rate limit
    let server_stats = server.get_nat_traversal_stats();
    assert!(server_stats.frames_rate_limited > 0);
    assert!(sent < 100); // Not all frames should be accepted
}
```

#### 6.2 Raw Public Key Security Tests
```rust
#[test]
fn test_rpk_verification_untrusted_key() {
    let (attacker_key, attacker_pub) = generate_ed25519_keypair();
    let (trusted_key, trusted_pub) = generate_ed25519_keypair();
    
    // Verifier only trusts specific key
    let verifier = RawPublicKeyVerifier::new(vec![
        public_key_to_bytes(&trusted_pub)
    ]);
    
    // Try to verify with attacker's key
    let spki = create_ed25519_subject_public_key_info(&attacker_pub);
    let cert = CertificateDer::from(spki);
    
    let result = verifier.verify_server_cert(
        &cert,
        &[],
        &ServerName::try_from("test").unwrap(),
        &[],
        UnixTime::now(),
    );
    
    assert!(result.is_err());
}
```

### 7. Compatibility Tests

#### 7.1 Backward Compatibility Test
```rust
#[tokio::test]
async fn test_connection_without_nat_traversal() {
    // Create endpoint without NAT traversal support
    let legacy_config = TransportConfig::default();
    let legacy_endpoint = create_endpoint(legacy_config).await;
    
    // Create endpoint with NAT traversal
    let mut modern_config = TransportConfig::default();
    modern_config.nat_traversal_config = Some(NatTraversalConfig {
        role: NatTraversalRole::Client,
        max_candidates: VarInt::from_u32(10),
        coordination_timeout: VarInt::from_u32(5000),
        max_concurrent_attempts: VarInt::from_u32(3),
        peer_id: None,
    });
    let modern_endpoint = create_endpoint(modern_config).await;
    
    // Should connect successfully without NAT traversal
    let conn = modern_endpoint.connect_to(&legacy_endpoint).await.unwrap();
    assert!(conn.transport_parameters().nat_traversal_config().is_none());
}
```

## Test Execution Plan

### Phase 1: Unit Tests (Week 1)
- Frame encoding/decoding
- NAT simulator implementations
- Raw public key operations
- Certificate negotiation logic

### Phase 2: Integration Tests (Week 2-3)
- Basic NAT traversal scenarios
- Raw public key handshakes
- IPv4 and IPv6 support
- Error handling paths

### Phase 3: Stress Tests (Week 4)
- Concurrent operations
- Resource management
- Performance benchmarks
- Network condition simulation

### Phase 4: Security Tests (Week 5)
- Attack surface validation
- Rate limiting verification
- Key verification tests
- Protocol compliance

## Success Criteria

1. **Functional Requirements**
   - ✅ All frame types encode/decode correctly
   - ✅ NAT traversal succeeds for all common NAT types
   - ✅ Raw public keys negotiate and verify correctly
   - ✅ IPv4 and IPv6 are fully supported

2. **Performance Requirements**
   - ✅ 90%+ success rate for NAT traversal
   - ✅ < 5 second average traversal time
   - ✅ < 100MB memory usage under load
   - ✅ Handle 100+ concurrent traversals

3. **Security Requirements**
   - ✅ Rate limiting prevents amplification
   - ✅ Only trusted keys are accepted
   - ✅ No memory leaks or resource exhaustion
   - ✅ Proper error handling for all attack vectors

4. **Compatibility Requirements**
   - ✅ Works with standard QUIC implementations
   - ✅ Graceful fallback when extensions not supported
   - ✅ Certificate type negotiation follows RFC 7250# Comprehensive Test Plan for ant-quic

## Objective
Achieve near 100% test coverage for the ant-quic codebase with particular emphasis on NAT traversal, error handling, and stress testing.

## Current Coverage Analysis

### Critical Gaps Identified
- **NAT Traversal**: Core modules completely untested
- **Cryptography**: No tests for security-critical components
- **Error Paths**: Limited error condition testing
- **Platform Code**: Platform-specific paths untested
- **Performance**: No benchmarks or stress tests

## Test Implementation Strategy

### Phase 1: Critical NAT Traversal Tests

#### 1.1 NAT Traversal State Machine Tests
**File**: `tests/nat_traversal_state_tests.rs`
- State transitions for all NAT types
- Candidate discovery and validation
- Coordination protocol edge cases
- Timeout and retry logic
- Role switching scenarios

#### 1.2 Candidate Discovery Tests
**File**: `tests/candidate_discovery_tests.rs`
- Platform-specific interface enumeration
- IPv4/IPv6 dual-stack scenarios
- Network change detection
- Invalid address filtering
- Performance with many interfaces

#### 1.3 Connection Establishment Tests
**File**: `tests/connection_establishment_tests.rs`
- Simultaneous connection attempts
- NAT type combinations matrix
- Failure recovery scenarios
- Path migration during establishment
- Resource exhaustion handling

### Phase 2: Security and Cryptography Tests

#### 2.1 Crypto Module Tests
**File**: `tests/crypto_tests.rs`
- Key generation and validation
- Packet encryption/decryption
- Header protection
- Retry token validation
- Constant-time operations

#### 2.2 Attack Resistance Tests
**File**: `tests/security_tests.rs`
- Amplification attack prevention
- Connection ID confusion
- Replay attack resistance
- Resource exhaustion protection
- Malformed packet handling

### Phase 3: Stress and Performance Tests

#### 3.1 Load Tests
**File**: `tests/stress/load_tests.rs`
- 10,000+ simultaneous connections
- Connection churn scenarios
- Memory leak detection
- CPU usage under load
- Bandwidth saturation

#### 3.2 Chaos Engineering Tests
**File**: `tests/stress/chaos_tests.rs`
- Random packet drops (0-50%)
- Variable latency injection
- Network partition scenarios
- NAT rebinding during connection
- Clock skew simulation

#### 3.3 Endurance Tests
**File**: `tests/stress/endurance_tests.rs`
- 24-hour connection stability
- Memory growth over time
- Handle recycling
- Timer accuracy drift
- Statistics overflow

### Phase 4: Edge Cases and Error Conditions

#### 4.1 Protocol Edge Cases
**File**: `tests/edge_cases/protocol_tests.rs`
- Maximum size packets
- Minimum size packets
- Invalid version negotiation
- Malformed extension frames
- State machine violations

#### 4.2 Resource Limits
**File**: `tests/edge_cases/limits_tests.rs`
- Maximum streams per connection
- Maximum connections per endpoint
- Buffer exhaustion
- Timer queue overflow
- Connection ID pool exhaustion

### Phase 5: Property-Based and Fuzz Tests

#### 5.1 Property-Based Tests
**File**: `tests/property_based_tests.rs`
- Candidate priority ordering invariants
- Connection state consistency
- Stream ordering guarantees
- Congestion control fairness
- Retry token uniqueness

#### 5.2 Fuzz Testing
**Directory**: `fuzz/`
- Packet parsing fuzzer
- Frame encoding/decoding
- State machine fuzzer
- Transport parameter fuzzer
- Extension frame fuzzer

### Phase 6: Platform-Specific Tests

#### 6.1 Platform Integration
**Files**: `tests/platform_{linux,windows,macos}_tests.rs`
- Network interface discovery
- Socket options
- Platform-specific errors
- Performance characteristics
- Resource limits

## Test Infrastructure Requirements

### 1. Test Harness Extensions
```rust
// Enhanced test utilities needed
- NetworkTopologyBuilder
- NATSimulator with all NAT types
- PacketCaptureAnalyzer
- PerformanceProfiler
- MemoryLeakDetector
```

### 2. CI/CD Integration
- Coverage reporting with codecov
- Performance regression detection
- Platform matrix testing
- Stress test scheduling
- Security scanning

### 3. Benchmarking Framework
```toml
[dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }
proptest = "1.0"
arbitrary = { version = "1.3", features = ["derive"] }
tokio-test = "0.4"
```

## Success Metrics

### Coverage Targets
- Line coverage: >95%
- Branch coverage: >90%
- NAT traversal modules: 100%
- Error paths: >95%

### Performance Targets
- Connection establishment: <100ms (same network)
- NAT traversal success rate: >99%
- Memory per connection: <10KB
- CPU usage: Linear scaling

### Reliability Targets
- 24-hour stability test pass rate: 100%
- Stress test crash rate: 0%
- Memory leak detection: None
- Race condition detection: None

## Implementation Timeline

### Week 1-2: NAT Traversal Tests
- Implement comprehensive NAT state machine tests
- Add candidate discovery test suite
- Create connection establishment matrix tests

### Week 3-4: Security and Error Tests
- Complete crypto module testing
- Add attack resistance tests
- Implement error path coverage

### Week 5-6: Stress and Performance
- Build stress testing framework
- Implement chaos engineering tests
- Add performance benchmarks

### Week 7-8: Advanced Testing
- Property-based test implementation
- Fuzz testing setup
- Platform-specific test suites

## Maintenance Plan

### Continuous Testing
- Nightly stress test runs
- Weekly endurance tests
- Performance tracking dashboard
- Coverage trend monitoring

### Test Evolution
- Add tests for new features
- Update tests for protocol changes
- Expand stress scenarios
- Refine performance benchmarks
