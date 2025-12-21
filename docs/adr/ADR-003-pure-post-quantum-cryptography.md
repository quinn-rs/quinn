# ADR-003: Pure Post-Quantum Cryptography

## Status

Accepted (2025-12-21)

## Context

Quantum computers threaten classical cryptography:
- **Shor's algorithm**: Breaks RSA, ECDH, ECDSA in polynomial time
- **Grover's algorithm**: Halves symmetric key security (128-bit becomes 64-bit effective)

Most projects adopt **hybrid** approaches (classical + PQC) for backwards compatibility. However, ant-quic is a **greenfield network** with no legacy peers, enabling a different choice.

Key requirements:
- Long-term data confidentiality (decades)
- Forward secrecy for key exchange
- Authentication without centralized PKI
- Compact peer identifiers for routing

## Decision

Adopt **pure post-quantum cryptography** with no classical fallback:

| Function | Algorithm | Standard | Parameters |
|----------|-----------|----------|------------|
| Key Exchange | ML-KEM-768 | FIPS 203 | NIST Level 3 |
| Authentication | ML-DSA-65 | FIPS 204 | NIST Level 3 |
| Peer Identity | Ed25519 | RFC 8032 | 32-byte PeerId only |

**Critical distinction**: Ed25519 is used **only** for the 32-byte PeerId (routing identifier), **not** for TLS authentication. All authentication uses ML-DSA-65.

**Raw Public Keys** (RFC 7250 inspired):
- No X.509 certificates or certificate chains
- Peers authenticate via public key fingerprints
- Trust-on-first-use model
- No CA infrastructure required

## Consequences

### Benefits
- **Quantum-safe from day one**: No "harvest now, decrypt later" risk
- **Simpler stack**: No hybrid negotiation complexity
- **No CA dependency**: Peers authenticate directly
- **Future-proof**: NIST FIPS 203/204 are final standards

### Trade-offs
- **Larger keys/signatures**: ML-KEM-768 ciphertext ~1088 bytes (vs 32 for X25519)
- **Higher CPU cost**: PQC operations slower than classical (~10x)
- **No classical interop**: Cannot connect to non-PQC peers
- **Algorithm risk**: If NIST standards are broken, no fallback

### Performance Impact
- Handshake: ~5ms additional (acceptable for P2P)
- Bandwidth: ~2KB additional per handshake
- CPU: Mitigated by connection reuse

## Alternatives Considered

1. **Hybrid (X25519 + ML-KEM)**: Classical + PQC combined
   - Rejected: Adds complexity, no benefit for greenfield network

2. **Classical only (X25519/Ed25519)**: Traditional crypto
   - Rejected: Not quantum-safe, defeats project goals

3. **NTRU/SIKE**: Alternative PQC algorithms
   - Rejected: SIKE broken, NTRU not NIST standardized

4. **X.509 certificates with PQC**: Standard PKI with new algorithms
   - Rejected: Adds CA complexity, not needed for P2P

## References

- Specification: `rfcs/ant-quic-pqc-authentication.md` (v0.2)
- Standards: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA)
- Files: `src/crypto/pqc/*.rs`
- Implementation: saorsa-pqc library
