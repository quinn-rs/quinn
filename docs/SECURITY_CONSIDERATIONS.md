# Security Considerations for ant-quic

This document outlines security considerations for ant-quic v0.13.0+'s NAT traversal, address discovery, and post-quantum cryptography features.

## Table of Contents

1. [Overview](#overview)
2. [Post-Quantum Cryptography](#post-quantum-cryptography)
3. [QUIC Address Discovery Security](#quic-address-discovery-security)
4. [NAT Traversal Security](#nat-traversal-security)
5. [Authentication and Identity](#authentication-and-identity)
6. [Network Attack Vectors](#network-attack-vectors)
7. [Implementation Security](#implementation-security)
8. [Best Practices](#best-practices)
9. [Security Checklist](#security-checklist)

## Overview

ant-quic v0.13.0+ implements comprehensive security measures:

- **Always-On PQC**: Hybrid post-quantum cryptography on every connection
- **Raw Public Keys**: Ed25519 identity without certificate authorities
- **Rate Limiting**: Protection against address observation flooding
- **Validated Connections**: Address validation before trusting
- **QUIC Security**: TLS 1.3, encrypted transport, connection binding

## Post-Quantum Cryptography

### Always-On Hybrid Cryptography

Every connection uses both classical and post-quantum algorithms:

```
┌─────────────────────┐     ┌─────────────────────┐
│    Classical        │     │   Post-Quantum      │
├─────────────────────┤     ├─────────────────────┤
│    X25519           │  +  │   ML-KEM-768        │ = Hybrid Key Exchange
│    Ed25519          │  +  │   ML-DSA-65         │ = Hybrid Signatures
└─────────────────────┘     └─────────────────────┘
```

**Security Property**: An attacker must break BOTH algorithm families to compromise security.

### Why Always-On?

1. **"Harvest Now, Decrypt Later"**: Adversaries can record encrypted traffic today and decrypt when quantum computers arrive
2. **No Configuration Errors**: Users cannot accidentally disable PQC
3. **Consistent Security**: Every connection has identical protection

### Algorithm Standards

| Algorithm | Standard | Security Level |
|-----------|----------|----------------|
| ML-KEM-768 | FIPS 203 | 192-bit classical, 175-bit quantum |
| ML-DSA-65 | FIPS 204 | 192-bit classical, 175-bit quantum |
| X25519 | RFC 7748 | 128-bit classical |
| Ed25519 | RFC 8032 | 128-bit classical |

### Configuration

PQC cannot be disabled. Configuration tunes behavior:

```rust
let pqc = PqcConfig::builder()
    .ml_kem(true)
    .ml_dsa(true)
    .memory_pool_size(10)
    .handshake_timeout_multiplier(1.5)
    .build()?;
```

## QUIC Address Discovery Security

### Address Spoofing Protection

The QUIC Address Discovery extension (draft-ietf-quic-address-discovery-00) includes protections:

**Protection 1: Connection-Bound Observations**
```
Addresses are only accepted from established QUIC connections:
- Peer has completed QUIC handshake
- TLS 1.3 authentication established
- Connection state prevents injection attacks
```

**Protection 2: Rate Limiting**
```rust
// Default: 30 observations/second per path
// Configurable per deployment
```

**Protection 3: Address Validation**
```
1. Address observed via OBSERVED_ADDRESS frame
2. Address becomes NAT traversal candidate
3. PATH_CHALLENGE/PATH_RESPONSE validates
4. Only validated addresses used for data
```

### Privacy Considerations

#### Address Disclosure
- **Risk**: Peers learn your external IP address
- **Mitigation**: Only share with authenticated peers
- **Note**: This is inherent to P2P networking

#### Tracking Prevention
- Addresses are ephemeral and change with network conditions
- Connection migration handles address changes gracefully

## NAT Traversal Security

### Symmetric P2P Model

In ant-quic v0.13.0+, **all nodes are symmetric**. Every node can:
- Initiate connections
- Accept connections
- Observe external addresses of peers
- Coordinate NAT traversal for other peers

There are no special "coordinator" or "bootstrap" roles.

### Hole Punching Security

1. **Mutual Authentication**: Both peers authenticate before hole punching
2. **Peer Validation**: Any peer helping coordinate verifies identities
3. **Time-Limited Windows**: Hole punching has strict timeouts

```rust
let nat = NatConfig {
    coordination_timeout: Duration::from_secs(15),
    max_candidates: 10,
    hole_punch_retries: 5,
    ..Default::default()
};
```

### Connection Validation

All connections undergo validation:

```
1. Exchange candidate addresses
2. Perform coordinated hole punching
3. Validate path with QUIC PATH_CHALLENGE
4. Verify peer identity via Raw Public Key
5. Establish encrypted QUIC connection with PQC
```

## Authentication and Identity

### Raw Public Keys (RFC 7250)

ant-quic uses Raw Public Keys instead of X.509 certificates:

```rust
use ant_quic::key_utils::{generate_ed25519_keypair, derive_peer_id};

// Generate Ed25519 keypair
let (private_key, public_key) = generate_ed25519_keypair();

// Derive peer ID from public key
let peer_id = derive_peer_id(&public_key);
```

**Benefits**:
- No certificate authorities required
- Self-sovereign identity
- Simple trust model (know peer IDs)
- No certificate expiration issues

### Peer Verification

```rust
// Verify peer identity
let mut events = endpoint.subscribe();
while let Ok(event) = events.recv().await {
    match event {
        P2pEvent::Connected { peer_id, .. } => {
            if trusted_peers.contains(&peer_id) {
                // Trusted peer connected
            } else {
                // Unknown peer - handle appropriately
            }
        }
        _ => {}
    }
}
```

## Network Attack Vectors

### 1. Denial of Service (DoS)

**Attack**: Flooding with connection attempts or observation frames

**Mitigations**:
```rust
let config = P2pConfig::builder()
    .max_connections(100)           // Limit total connections
    .connection_timeout(Duration::from_secs(30))
    .build()?;
```

### 2. Man-in-the-Middle (MITM)

**Attack**: Intercepting connection establishment

**Mitigations**:
- QUIC uses TLS 1.3 for all connections
- Hybrid PQC key exchange prevents quantum attacks
- Raw Public Keys verify peer identity

### 3. Address Injection

**Attack**: Injecting false addresses to redirect connections

**Mitigations**:
- Addresses only accepted from authenticated QUIC connections
- Rate limiting applied
- Addresses validated before use

### 4. Quantum Computer Attacks

**Attack**: Future quantum computers breaking classical cryptography

**Mitigations**:
- ML-KEM-768 for post-quantum key exchange
- ML-DSA-65 for post-quantum signatures
- Hybrid scheme protects against both classical and quantum attacks

## Implementation Security

### Memory Safety

ant-quic is written in Rust:
- Memory safety without garbage collection
- Thread safety through the type system
- No buffer overflows or use-after-free

### Secure Defaults

```rust
// v0.13.0+ secure defaults:
// - PQC: Always enabled (cannot disable)
// - Authentication: Raw Public Keys
// - Rate limiting: 30 observations/second
// - Connection timeout: 30 seconds
// - Max connections: 100
```

### Error Handling

Proper error handling prevents information leaks:

```rust
match endpoint.connect(addr).await {
    Ok(conn) => handle_connection(conn),
    Err(_) => {
        // Don't leak internal details
        log::warn!("Connection failed");
    }
}
```

## Best Practices

### 1. Use Multiple Known Peers

```rust
let config = P2pConfig::builder()
    .known_peer("peer1.example.com:9000".parse()?)
    .known_peer("peer2.example.com:9000".parse()?)
    .known_peer("peer3.example.com:9000".parse()?)
    .build()?;
```

### 2. Verify Peer Identities

```rust
// Application-level peer verification
let expected_peers: HashSet<PeerId> = load_trusted_peers();

if !expected_peers.contains(&peer_id) {
    connection.close(0u32.into(), b"untrusted");
}
```

### 3. Monitor Connection Events

```rust
let mut events = endpoint.subscribe();
while let Ok(event) = events.recv().await {
    match event {
        P2pEvent::ConnectionFailed { peer_id, reason } => {
            log::warn!("Connection failed: {} - {}", peer_id.to_hex(), reason);
        }
        P2pEvent::HolePunchFailed { peer_id, reason } => {
            log::warn!("NAT traversal failed: {} - {}", peer_id.to_hex(), reason);
        }
        _ => {}
    }
}
```

### 4. Configure Appropriate Limits

```rust
let config = P2pConfig::builder()
    .max_connections(50)              // Appropriate for your use case
    .connection_timeout(Duration::from_secs(30))
    .idle_timeout(Duration::from_secs(120))
    .build()?;
```

### 5. Keep Dependencies Updated

```bash
# Check for security updates
cargo audit

# Update dependencies
cargo update
```

## Security Checklist

Before deploying ant-quic in production:

- [ ] **PQC Active**: Verify PQC is enabled (automatic in v0.13.0+)
- [ ] **Connection Limits**: Set appropriate max_connections
- [ ] **Monitoring**: Implement event monitoring
- [ ] **Updates**: Keep ant-quic and dependencies updated
- [ ] **Network Security**: Configure firewalls appropriately
- [ ] **Logging**: Enable security event logging
- [ ] **Testing**: Test against common attack patterns
- [ ] **Incident Response**: Have a plan for security incidents

### Security Audit Recommendations

1. **Regular Updates**
   ```bash
   cargo audit
   cargo update
   ```

2. **Penetration Testing**
   - Test DoS resistance
   - Verify authentication
   - Check for amplification vulnerabilities
   - Test address injection scenarios

3. **Code Review Focus Areas**
   - Peer verification logic
   - Rate limiting implementation
   - Address validation
   - Error handling paths

## Reporting Security Issues

If you discover a security vulnerability:

1. **Do NOT** open a public issue
2. Email security@autonomi.com with details
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fixes (if any)

We aim to respond to security reports within 48 hours.

## References

- [FIPS 203 - ML-KEM](../../rfcs/fips-203-ml-kem.pdf)
- [FIPS 204 - ML-DSA](../../rfcs/fips-204-ml-dsa.pdf)
- [RFC 7250 - Raw Public Keys](https://www.rfc-editor.org/rfc/rfc7250)
- [RFC 9000 - QUIC](https://www.rfc-editor.org/rfc/rfc9000)
- [draft-seemann-quic-nat-traversal-02](../../rfcs/draft-seemann-quic-nat-traversal-02.txt)
- [draft-ietf-quic-address-discovery-00](../../rfcs/draft-ietf-quic-address-discovery-00.txt)

