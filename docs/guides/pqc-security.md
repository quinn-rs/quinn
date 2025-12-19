# Post-Quantum Cryptography Security Considerations

This document outlines security considerations for ant-quic's Post-Quantum Cryptography implementation.

## Executive Summary

In ant-quic v0.13.0+, **Post-Quantum Cryptography is always enabled**. Every connection uses NIST-standardized algorithms (ML-KEM-768 and ML-DSA-65) in hybrid mode with classical algorithms. This provides defense-in-depth against both current classical attacks and future quantum threats.

## Threat Model

### Current Threats
1. **Classical Attacks**: Protected by proven algorithms (X25519, Ed25519)
2. **Side-Channel Attacks**: Mitigated through constant-time implementations
3. **Protocol Attacks**: QUIC's security properties maintained

### Future Quantum Threats
1. **Shor's Algorithm**: Breaks RSA/ECDSA - mitigated by ML-KEM/ML-DSA
2. **Grover's Algorithm**: Weakens symmetric crypto - mitigated by appropriate key sizes
3. **Harvest Now, Decrypt Later**: Addressed by always-on PQC deployment

### Why Always-On PQC?

In v0.13.0, we removed the ability to disable PQC because:

1. **No Performance Excuse**: Modern implementations have ~8% overhead
2. **Consistent Security**: Every connection has the same protection
3. **No Configuration Errors**: Users cannot accidentally disable PQC
4. **Future-Proof**: All ant-quic networks are quantum-resistant

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

**Security Property**: An attacker must break BOTH algorithm families to compromise security. This provides:
- Protection if classical algorithms are broken (quantum computers)
- Protection if PQC algorithms have undiscovered weaknesses
- Best of both worlds security guarantee

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
| ML-KEM-768 | 192 bits | 175 bits | NIST FIPS 203 |
| ML-DSA-65 | 192 bits | 175 bits | NIST FIPS 204 |
| X25519 | 128 bits | 64 bits | Current standard |
| Ed25519 | 128 bits | 64 bits | Current standard |

**Hybrid Combined Security**:
- Classical: 192 bits (limited by weakest component)
- Quantum: 175 bits (ML-KEM/ML-DSA provide this)
- Requires breaking BOTH to compromise

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

**Mitigation**: Connection pooling, caching, and optimization techniques. Always-on design means these optimizations are well-tested.

### 4. Key/Ciphertext Sizes

| Component | ML-KEM-768 | X25519 |
|-----------|------------|--------|
| Public Key | 1,184 bytes | 32 bytes |
| Ciphertext | 1,088 bytes | 32 bytes |

| Component | ML-DSA-65 | Ed25519 |
|-----------|-----------|---------|
| Public Key | 1,952 bytes | 32 bytes |
| Signature | 3,293 bytes | 64 bytes |

**Impact**: Increased handshake packet sizes. See [PQC Configuration Guide](./pqc-configuration.md) for MTU tuning.

## Best Practices

### 1. Keep Updated
```bash
# Regularly update to latest version
cargo update ant-quic
```

### 2. Monitor Security Advisories
- Subscribe to NIST PQC updates
- Monitor CVE database for implementation issues
- Follow ant-quic security announcements
- Watch for [rfcs/](../../rfcs/) updates

### 3. Implement Defense in Depth
- PQC is one layer of security
- Implement application-level encryption where appropriate
- Use secure communication patterns
- Validate all inputs

### 4. Regular Key Rotation
```rust
// Ephemeral keys are used per-connection by default
// No manual key rotation needed for connection keys

// For long-term identity keys, consider rotation schedule
impl KeyRotation for YourApp {
    fn should_rotate(&self, key_age: Duration) -> bool {
        key_age > Duration::from_days(90)
    }
}
```

## Quantum Computing Timeline

Current estimates for cryptographically relevant quantum computers (CRQC):

| Estimate | Timeline | Source |
|----------|----------|--------|
| Optimistic | 5-10 years | Some researchers |
| Moderate | 10-15 years | NIST guidance |
| Conservative | 15-25 years | Industry consensus |

**Recommendation**: Deploy PQC now. "Harvest now, decrypt later" attacks mean data encrypted today could be decrypted when quantum computers arrive. ant-quic's always-on PQC protects against this threat.

## Compliance and Standards

### NIST Compliance
- **FIPS 203** (ML-KEM) - Final Standard 2024
- **FIPS 204** (ML-DSA) - Final Standard 2024
- **SP 800-56C Rev. 2** - Key Derivation
- **SP 800-90A Rev. 1** - Random Number Generation

### IETF Standards
- draft-ietf-tls-hybrid-design (hybrid key exchange)
- draft-connolly-tls-mlkem-key-agreement (ML-KEM in TLS)
- RFC 9180 (HPKE) for future integration

### Regional Requirements
- **EU**: eIDAS 2.0 quantum-ready requirements
- **US**: Federal zero-trust architecture mandates
- **NSA**: CNSA 2.0 timeline for PQC adoption
- **Asia**: Various national PQC migration timelines

## Security Audit Checklist

For deployments using ant-quic v0.13.0+:

- [x] PQC enabled (automatic - cannot be disabled)
- [x] Hybrid mode active (automatic)
- [ ] Version is latest stable release
- [ ] Monitoring for security advisories configured
- [ ] Side-channel countermeasures verified for deployment environment
- [ ] Compliance requirements documented
- [ ] Incident response plan includes PQC scenarios
- [ ] Performance monitoring in place

## Incident Response

### If Classical Algorithm Compromised
1. Continue operating (hybrid mode protects via PQC)
2. Monitor for ant-quic updates
3. Plan migration to updated classical algorithm
4. No immediate action required due to hybrid protection

### If PQC Algorithm Compromised
1. Continue operating (hybrid mode protects via classical)
2. Update to patched version immediately
3. Await NIST guidance on replacement algorithm
4. No immediate action required due to hybrid protection

### If Both Algorithm Families Compromised (Unlikely)
1. Immediate security incident declaration
2. Isolate affected systems
3. Implement emergency key rotation
4. Await vendor patches
5. This scenario is extremely unlikely - would require breaking both RSA/ECDH AND lattice-based crypto

### If Implementation Bug Found
1. Check ant-quic security advisories
2. Update to patched version
3. Rotate long-term identity keys if recommended
4. Review affected connections in logs

## Future Considerations

### Algorithm Agility
ant-quic is designed for algorithm agility:
- Easy addition of new algorithms
- Smooth migration paths
- Backward compatibility considered

### Emerging Standards
Monitoring for integration:
- NIST Round 4 PQC candidates (additional signatures)
- Stateful hash-based signatures (SPHINCS+)
- Code-based cryptography alternatives

### Autonomi Network Integration
ant-quic's always-on PQC provides the security foundation for:
- Long-term data storage protection
- Forward secrecy for all network communications
- Quantum-resistant peer authentication

## References

### Local RFC Copies
- [rfcs/fips-203-ml-kem.pdf](../../rfcs/fips-203-ml-kem.pdf)
- [rfcs/fips-204-ml-dsa.pdf](../../rfcs/fips-204-ml-dsa.pdf)
- [rfcs/draft-ietf-tls-hybrid-design-14.txt](../../rfcs/draft-ietf-tls-hybrid-design-14.txt)

### External Resources
- [NIST PQC Project](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [NIST FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
- [NIST FIPS 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)

## Security Contact

For security issues, report via:
- GitHub Security Advisories: [ant-quic/security](https://github.com/dirvine/ant-quic/security)
- Email: security@autonomi.org

---

## Conclusion

ant-quic v0.13.0+ provides robust, always-on protection against both current and future quantum threats. The hybrid approach ensures security even if one algorithm family is compromised, while the always-on design eliminates configuration errors and ensures consistent protection across all deployments.
