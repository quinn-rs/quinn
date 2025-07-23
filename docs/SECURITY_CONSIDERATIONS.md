# Security Considerations for ant-quic

This document outlines security considerations for ant-quic's NAT traversal and address discovery features.

## Table of Contents
1. [Overview](#overview)
2. [QUIC Address Discovery Security](#quic-address-discovery-security)
3. [NAT Traversal Security](#nat-traversal-security)
4. [Authentication and Identity](#authentication-and-identity)
5. [Network Attack Vectors](#network-attack-vectors)
6. [Implementation Security](#implementation-security)
7. [Best Practices](#best-practices)
8. [Security Checklist](#security-checklist)

## Overview

ant-quic implements several security measures to protect against common attack vectors in P2P networks:
- **Cryptographic authentication** using Ed25519 signatures
- **Rate limiting** for address observations
- **Validated connection establishment** before trusting addresses
- **QUIC's built-in security** (TLS 1.3, encrypted transport)

## QUIC Address Discovery Security

### Address Spoofing Protection

The QUIC Address Discovery extension (draft-ietf-quic-address-discovery) includes several protections against address spoofing:

```rust
// 1. Addresses are only observed from authenticated QUIC connections
// 2. Rate limiting prevents observation flooding
// 3. Addresses must be validated through actual packet receipt
```

#### Implementation Details

**Protection Mechanism 1: Connection-Bound Observations**
```rust
// Addresses are only accepted from established QUIC connections
// This means:
// - The peer has completed the QUIC handshake
// - TLS 1.3 authentication is established
// - Connection state prevents injection attacks
```

**Protection Mechanism 2: Rate Limiting**
```rust
// Token bucket rate limiting per path
pub struct RateLimiter {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
    last_update: Instant,
}

// Default: 30 observations/second per path
// Bootstrap nodes: 150 observations/second (5x multiplier)
```

**Protection Mechanism 3: Address Validation**
```rust
// Observed addresses must be validated before use:
// 1. Address is observed via OBSERVED_ADDRESS frame
// 2. Address becomes a candidate for NAT traversal
// 3. PATH_CHALLENGE/PATH_RESPONSE validates the address
// 4. Only validated addresses are used for data transfer
```

### Privacy Considerations

#### Address Disclosure
- **Risk**: Peers learn your external IP address
- **Mitigation**: Only share with authenticated peers
- **Configuration**: Disable address discovery if privacy is critical

```rust
// Disable address discovery for privacy-sensitive applications
endpoint_config.set_address_discovery_enabled(false);
```

#### Tracking Prevention
- **Risk**: Addresses could be used for tracking
- **Mitigation**: Addresses are ephemeral and change with network conditions
- **Protection**: Connection migration handles address changes gracefully

### Rate Limiting Configuration

Configure rate limiting based on your security requirements:

```rust
// Conservative rate limiting for public endpoints
endpoint_config.set_max_observation_rate(10); // 10/second

// Standard rate limiting
endpoint_config.set_max_observation_rate(30); // Default

// Aggressive rate limiting for trusted networks
endpoint_config.set_max_observation_rate(60); // 60/second
```

## NAT Traversal Security

### Hole Punching Security

NAT traversal uses coordinated hole punching which has inherent security properties:

1. **Mutual Authentication**: Both peers must authenticate before hole punching
2. **Coordinator Validation**: Bootstrap nodes verify peer identities
3. **Time-Limited Windows**: Hole punching attempts have strict timeouts

```rust
// Hole punching is coordinated and time-limited
let config = NatTraversalConfig {
    coordination_timeout: Duration::from_secs(10), // Short window
    max_candidates: 10, // Limit candidate addresses
    ..Default::default()
};
```

### Connection Validation

All connections undergo validation before data transfer:

```rust
// Connection establishment flow with security checks:
// 1. Exchange candidate addresses (signed)
// 2. Perform coordinated hole punching
// 3. Validate path with QUIC PATH_CHALLENGE
// 4. Verify peer identity with Ed25519
// 5. Establish encrypted QUIC connection
```

## Authentication and Identity

### Ed25519 Peer Authentication

ant-quic uses Ed25519 signatures for peer authentication:

```rust
use ant_quic::auth::{AuthConfig, AuthManager};

// Configure authentication
let auth_config = AuthConfig {
    challenge_timeout: Duration::from_secs(30),
    max_pending_auths: 100,
    require_authentication: true, // Enforce authentication
};

// Authentication flow:
// 1. Generate Ed25519 keypair
// 2. Derive peer ID from public key (SHA-256)
// 3. Sign challenges to prove identity
// 4. Verify signatures before trusting peer
```

### Challenge-Response Protocol

The authentication protocol prevents replay attacks:

```rust
// Challenge structure includes:
// - Random nonce (prevents replay)
// - Timestamp (prevents old challenges)
// - Connection ID (binds to specific connection)

pub struct AuthChallenge {
    nonce: [u8; 32],
    timestamp: SystemTime,
    connection_id: ConnectionId,
}
```

### Identity Verification Best Practices

```rust
// Always verify peer identity before sensitive operations
let peer_id = connection.peer_id();
let verified = auth_manager.verify_peer(&connection).await?;

if !verified {
    return Err("Peer authentication failed");
}

// Now safe to exchange sensitive data
```

## Network Attack Vectors

### 1. Denial of Service (DoS)

**Attack Vector**: Flooding with connection attempts or observation frames

**Mitigations**:
```rust
// Connection limits
let config = QuicNodeConfig {
    max_connections: 100, // Limit total connections
    max_pending_auths: 50, // Limit pending authentications
    ..Default::default()
};

// Rate limiting per peer
pub struct PerPeerRateLimiter {
    limits: HashMap<PeerId, RateLimiter>,
    global_limit: RateLimiter,
}
```

### 2. Man-in-the-Middle (MITM)

**Attack Vector**: Intercepting connection establishment

**Mitigations**:
- QUIC uses TLS 1.3 for all connections
- Ed25519 signatures verify peer identity
- Certificate or raw public key validation

```rust
// Configure certificate validation
let mut transport_config = TransportConfig::default();
transport_config.max_concurrent_bidi_streams(100u32.into());
transport_config.max_concurrent_uni_streams(100u32.into());
```

### 3. Address Injection

**Attack Vector**: Injecting false addresses to redirect connections

**Mitigations**:
```rust
// Addresses are only accepted from:
// 1. Authenticated QUIC connections
// 2. After successful handshake
// 3. With rate limiting applied
// 4. Must be validated before use
```

### 4. Amplification Attacks

**Attack Vector**: Using the service to amplify traffic to victims

**Mitigations**:
- Response sizes are limited
- Rate limiting prevents amplification
- Connection state prevents reflection

## Implementation Security

### Memory Safety

ant-quic is written in Rust, providing:
- Memory safety without garbage collection
- Thread safety through the type system
- No buffer overflows or use-after-free

### Secure Defaults

The implementation uses secure defaults:

```rust
// Address discovery: Enabled (improves connectivity)
// Authentication: Required for all peers
// Rate limiting: 30 observations/second
// Connection timeout: 30 seconds
// Max connections: 100
```

### Error Handling

Proper error handling prevents information leaks:

```rust
// Don't leak internal information in errors
match connection.connect().await {
    Ok(_) => Ok(()),
    Err(_) => Err("Connection failed"), // Generic error
}
```

## Best Practices

### 1. Enable Authentication

Always enable and verify authentication:

```rust
let auth_config = AuthConfig {
    require_authentication: true,
    challenge_timeout: Duration::from_secs(30),
    ..Default::default()
};
```

### 2. Monitor Connection Patterns

Implement monitoring for suspicious patterns:

```rust
// Track connection attempts per peer
let mut connection_attempts: HashMap<SocketAddr, (u32, Instant)> = HashMap::new();

// Implement exponential backoff for repeated failures
if attempts > 5 {
    let backoff = Duration::from_secs(2u64.pow(attempts.min(10)));
    tokio::time::sleep(backoff).await;
}
```

### 3. Validate All Inputs

```rust
// Validate peer IDs
fn validate_peer_id(peer_id: &PeerId) -> bool {
    // Check for valid format
    peer_id.0.iter().any(|&b| b != 0) // Not all zeros
}

// Validate addresses
fn validate_address(addr: &SocketAddr) -> bool {
    match addr {
        SocketAddr::V4(addr) => {
            let ip = addr.ip();
            !ip.is_unspecified() && 
            !ip.is_loopback() &&
            !ip.is_multicast()
        }
        SocketAddr::V6(addr) => {
            let ip = addr.ip();
            !ip.is_unspecified() &&
            !ip.is_loopback() &&
            !ip.is_multicast()
        }
    }
}
```

### 4. Secure Bootstrap Nodes

Bootstrap nodes require extra security:

```rust
// For bootstrap nodes:
// 1. Run on dedicated infrastructure
// 2. Monitor for abuse patterns
// 3. Implement IP-based rate limiting
// 4. Log suspicious activities
// 5. Regular security updates
```

### 5. Network Isolation

For sensitive deployments:

```rust
// Create isolated networks
let config = NatTraversalConfig {
    bootstrap_nodes: vec!["private-bootstrap.internal:9000".parse()?],
    // Only connect to allowlisted peers
    peer_allowlist: Some(vec![trusted_peer_id]),
    ..Default::default()
};
```

## Security Checklist

Before deploying ant-quic in production:

- [ ] **Authentication**: Enable peer authentication
- [ ] **Rate Limiting**: Configure appropriate rate limits
- [ ] **Connection Limits**: Set max_connections appropriately
- [ ] **Monitoring**: Implement connection monitoring
- [ ] **Updates**: Keep ant-quic and dependencies updated
- [ ] **Network Security**: Use firewalls for bootstrap nodes
- [ ] **Logging**: Enable security event logging
- [ ] **Testing**: Test against common attack patterns
- [ ] **Documentation**: Document security procedures
- [ ] **Incident Response**: Have a plan for security incidents

### Security Audit Recommendations

1. **Regular Updates**
   ```bash
   # Check for security updates
   cargo audit
   
   # Update dependencies
   cargo update
   ```

2. **Penetration Testing**
   - Test DoS resistance
   - Verify authentication bypass isn't possible
   - Check for amplification vulnerabilities
   - Test address injection scenarios

3. **Code Review Focus Areas**
   - Authentication logic
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