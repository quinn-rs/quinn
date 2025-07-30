# Post-Quantum Cryptography Security Considerations

This document outlines security considerations for ant-quic's Post-Quantum Cryptography implementation.

## Executive Summary

ant-quic implements NIST-standardized post-quantum algorithms (ML-KEM-768 and ML-DSA-65) in hybrid mode with classical algorithms. This provides defense-in-depth against both current and future quantum threats while maintaining interoperability.

## Threat Model

### Current Threats
1. **Classical Attacks**: Protected by proven algorithms (X25519, Ed25519)
2. **Side-Channel Attacks**: Mitigated through constant-time implementations
3. **Protocol Attacks**: QUIC's security properties maintained

### Future Quantum Threats
1. **Shor's Algorithm**: Breaks RSA/ECDSA - mitigated by ML-KEM/ML-DSA
2. **Grover's Algorithm**: Weakens symmetric crypto - mitigated by appropriate key sizes
3. **Harvest Now, Decrypt Later**: Addressed by immediate PQC deployment

## Security Architecture

### Hybrid Cryptography Design

```
┌─────────────────┐     ┌─────────────────┐
│   Classical     │     │  Post-Quantum   │
│   Algorithms    │     │   Algorithms    │
├─────────────────┤     ├─────────────────┤
│    X25519       │  +  │   ML-KEM-768    │ = Hybrid Key Exchange
│    Ed25519      │  +  │   ML-DSA-65     │ = Hybrid Signatures
└─────────────────┘     └─────────────────┘
```

**Security Property**: Hybrid mode requires breaking BOTH algorithms to compromise security.

### Key Derivation

Keys are derived using NIST SP 800-56C Rev. 2 compliant methods:

```rust
// Simplified representation
hybrid_secret = KDF(
    classical_secret || pqc_secret,
    context_info,
    output_length
)
```

## Implementation Security

### Constant-Time Operations

All cryptographic operations are implemented to run in constant time:
- No data-dependent branches
- No data-dependent memory access
- No early termination based on secret data

### Memory Protection

1. **Key Zeroization**: All key material is securely wiped after use
2. **Stack Clearing**: Sensitive stack variables are cleared
3. **Heap Protection**: Custom allocator for sensitive data (when available)

### Random Number Generation

- Uses OS-provided CSPRNG (`getrandom` on Linux, `CryptGenRandom` on Windows)
- Implements NIST SP 800-90A Rev. 1 compliant DRBG for deterministic operations
- Continuous health tests on RNG output

## Algorithm Security Levels

| Algorithm | Classical Security | Quantum Security | Status |
|-----------|-------------------|------------------|---------|
| ML-KEM-768 | 192 bits | 175 bits | NIST Level 3 |
| ML-DSA-65 | 192 bits | 175 bits | NIST Level 3 |
| X25519 | 128 bits | 64 bits | Current standard |
| Ed25519 | 128 bits | 64 bits | Current standard |

## Known Limitations

### 1. Implementation Maturity
- Post-quantum algorithms are newer than classical ones
- Less cryptanalysis time compared to RSA/ECDH
- Implementations may have undiscovered vulnerabilities

**Mitigation**: Hybrid mode ensures classical algorithm protection remains

### 2. Side-Channel Resistance
- PQC algorithms have larger attack surface
- More complex operations increase side-channel risk
- Hardware countermeasures not universally available

**Mitigation**: Software countermeasures implemented, hardware acceleration when available

### 3. Performance Impact
- Larger key sizes increase bandwidth usage
- More complex operations increase CPU usage
- Memory requirements higher than classical only

**Mitigation**: Connection pooling, caching, and optimization techniques

## Best Practices

### 1. Use Hybrid Mode
```rust
// Recommended configuration
let config = PqcConfig::default(); // Hybrid mode
```

### 2. Regular Key Rotation
```rust
// Implement key rotation
impl KeyRotation for YourApp {
    fn should_rotate(&self, key_age: Duration) -> bool {
        key_age > Duration::from_days(30)
    }
}
```

### 3. Monitor Security Advisories
- Subscribe to NIST PQC updates
- Monitor CVE database for implementation issues
- Follow ant-quic security announcements

### 4. Implement Defense in Depth
- Use PQC as one layer of security
- Implement application-level encryption where appropriate
- Use secure communication patterns

## Quantum Computing Timeline

Current estimates for quantum computers capable of breaking classical crypto:
- **Optimistic**: 10-15 years
- **Conservative**: 15-25 years
- **Pessimistic**: 5-10 years

**Recommendation**: Deploy PQC now to protect against "harvest now, decrypt later" attacks.

## Compliance and Standards

### NIST Compliance
- FIPS 203 (ML-KEM)
- FIPS 204 (ML-DSA)
- SP 800-56C Rev. 2 (Key Derivation)
- SP 800-90A Rev. 1 (Random Number Generation)

### IETF Standards
- draft-ietf-tls-hybrid-design-10
- draft-connolly-tls-mlkem-key-agreement-04
- RFC 9180 (HPKE) for future integration

### Regional Requirements
- **EU**: eIDAS 2.0 quantum-ready requirements
- **US**: Federal zero-trust architecture mandates
- **Asia**: Various national PQC migration timelines

## Security Audit Checklist

- [ ] Hybrid mode enabled by default
- [ ] Key rotation implemented
- [ ] Monitoring for quantum computing advances
- [ ] Regular security updates applied
- [ ] Side-channel countermeasures verified
- [ ] Compliance requirements documented
- [ ] Incident response plan includes PQC scenarios
- [ ] Performance monitoring in place

## Incident Response

### If Classical Algorithm Compromised
1. Continue operating (hybrid mode protects)
2. Plan migration to updated classical algorithm
3. Monitor PQC algorithm status

### If PQC Algorithm Compromised
1. Continue operating (hybrid mode protects)
2. Update to patched version immediately
3. Consider pure classical mode temporarily
4. Await NIST guidance on replacement

### If Both Compromised
1. Immediate security incident declaration
2. Isolate affected systems
3. Implement emergency key rotation
4. Await vendor patches

## Future Considerations

### Algorithm Agility
ant-quic is designed for algorithm agility:
- Easy addition of new algorithms
- Smooth migration paths
- Backward compatibility maintained

### Emerging Standards
Monitoring for integration:
- NIST Round 4 PQC candidates
- Stateful hash-based signatures
- Code-based cryptography
- Isogeny-based cryptography (if rehabilitated)

## Conclusion

ant-quic's PQC implementation provides robust protection against both current and future threats. The hybrid approach ensures security even if one algorithm family is compromised, while maintaining performance and compatibility.

For security issues, contact: security@autonomi.org
EOF < /dev/null