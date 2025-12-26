# ant-quic Pure Post-Quantum Authentication Specification

**Version:** 2.1
**Date:** December 2025
**Status:** Draft (Supersedes v2.0 - single ML-DSA-65 key pair)
**Authors:** Saorsa Labs Ltd.

## Abstract

This document specifies the authentication and key exchange mechanisms used by
ant-quic for secure peer-to-peer communication. ant-quic employs **pure
post-quantum cryptography (PQC)** to provide quantum-resistant security.

As a greenfield network with no legacy compatibility requirements, ant-quic
uses ML-KEM for key exchange and ML-DSA for signatures **without classical
algorithm fallbacks**. This provides the strongest quantum resistance while
simplifying the protocol.

**Key Change from v1.0:** This specification removes hybrid algorithms
(X25519+ML-KEM, Ed25519+ML-DSA) in favor of pure PQC (ML-KEM-768, ML-DSA-65).

## Table of Contents

1. [Introduction](#1-introduction)
2. [Identity Model](#2-identity-model)
3. [Key Exchange (ML-KEM)](#3-key-exchange-ml-kem)
4. [Digital Signatures (ML-DSA)](#4-digital-signatures-ml-dsa)
5. [TLS Handshake Integration](#5-tls-handshake-integration)
6. [Security Considerations](#6-security-considerations)
7. [Wire Formats](#7-wire-formats)
8. [Code Point Registry](#8-code-point-registry)
9. [Migration from v1.0](#9-migration-from-v10)
10. [References](#10-references)

---

## 1. Introduction

### 1.1 Purpose

ant-quic is a QUIC transport implementation optimized for P2P networks with
advanced NAT traversal capabilities. This specification defines the
cryptographic mechanisms used for:

- **Peer Identity**: Node identification using SHA-256(ML-DSA-65 public key) PeerIds
- **Key Exchange**: Quantum-resistant session key establishment using ML-KEM-768
- **Authentication**: Handshake signing using ML-DSA-65

### 1.2 Design Philosophy: Pure PQC

ant-quic is a **greenfield network** with no legacy compatibility requirements.
This enables a pure PQC approach:

| Principle | Implementation |
|-----------|----------------|
| No classical key exchange | ML-KEM-768 only (no X25519, no ECDH) |
| No classical signatures | ML-DSA-65 only (no Ed25519, no ECDSA) |
| No hybrid complexity | Single algorithm per function |
| Fail-closed | Reject connections without PQC support |

**Why not hybrid?**
- Hybrid adds complexity without benefit for new networks
- Classical algorithms may be broken by quantum computers
- Pure PQC provides cleaner, auditable security properties
- No "downgrade" attack surface

### 1.3 Relationship to Standards

| Standard | Relationship |
|----------|--------------|
| RFC 7250 | Raw public key concept (no X.509 certificates) |
| RFC 9000 | Base QUIC protocol |
| FIPS 203 | ML-KEM key encapsulation (pure, no hybrid) |
| FIPS 204 | ML-DSA digital signatures (pure, no hybrid) |

### 1.4 Terminology

- **PQC**: Post-Quantum Cryptography resistant to quantum computer attacks
- **ML-KEM**: Module-Lattice Key Encapsulation Mechanism (FIPS 203)
- **ML-DSA**: Module-Lattice Digital Signature Algorithm (FIPS 204)
- **PeerId**: 32-byte node identifier derived from SHA-256 hash of ML-DSA-65 public key

---

## 2. Identity Model

### 2.1 PeerId: SHA-256 Hash of ML-DSA-65 Public Key

Each ant-quic node has a persistent identity based on a single ML-DSA-65 key pair.
The PeerId is derived by hashing the ML-DSA-65 public key:

```
ML-DSA-65 Public Key: 1952 bytes → SHA-256 → PeerId (32 bytes)
```

**Rationale:** This provides a compact 32-byte identifier suitable for DHT
routing and peer addressing while maintaining a single quantum-resistant key
pair for both identity and authentication. The SHA-256 hash provides:
- Uniform 32-byte identifiers regardless of public key size
- Collision resistance (2^128 security level)
- One-way function prevents recovering public key from PeerId
- Simplicity: one key pair to manage

### 2.2 Single Key Pair (Pure PQC)

Each node maintains a single ML-DSA-65 key pair:

| Purpose | Algorithm | Key Sizes | Usage |
|---------|-----------|-----------|-------|
| Identity & Auth | ML-DSA-65 | 1952B pub / 4032B priv | PeerId derivation, TLS handshake signatures |

This is simpler than the dual-key approach and provides full quantum resistance
for both identity and authentication.

### 2.3 PeerId Derivation

```
PeerId = SHA-256(ML-DSA-65_Public_Key)  (32 bytes)
```

Implementation:
```rust
pub fn derive_peer_id_from_public_key(public_key: &MlDsa65PublicKey) -> PeerId {
    let digest = sha256(public_key.as_bytes());
    PeerId(digest[..32].try_into().unwrap())
}
```

### 2.4 SubjectPublicKeyInfo Encoding

For TLS integration, the ML-DSA-65 key is encoded as DER-encoded SubjectPublicKeyInfo:

**ML-DSA-65 (variable, ~1960 bytes):**
```
30 82 07 a4 30 0b 06 09 60 86 48 01 65 03 04 03 11 03 82 07 93 00 [1952-byte ML-DSA-65 public key]
```

OID for ML-DSA-65: `2.16.840.1.101.3.4.3.17` (NIST assignment)

### 2.5 Trust Model

- **No Certificate Authorities**: Peers authenticate by public key
- **Trust-on-First-Use (TOFU)**: Applications cache peer public keys
- **Application-Level Trust**: Calling application decides trust

---

## 3. Key Exchange (ML-KEM)

### 3.1 Algorithm Selection

ant-quic uses **ML-KEM-768** exclusively for key exchange:

| Property | Value |
|----------|-------|
| Algorithm | ML-KEM-768 (FIPS 203) |
| Code Point | 0x0201 (513) |
| Security Level | NIST Level 3 (equivalent to AES-192) |
| Encapsulation Key | 1184 bytes |
| Ciphertext | 1088 bytes |
| Shared Secret | 32 bytes |

**No fallback to classical algorithms.** Connections without ML-KEM support
are rejected.

### 3.2 Key Exchange Procedure

**Initiator (ClientHello):**
1. Generate ephemeral ML-KEM-768 key pair: `(ek, dk)` (encapsulation key, decapsulation key)
2. Send: `key_share = ek` (1184 bytes)

**Responder (ServerHello):**
1. Receive initiator's encapsulation key: `ek`
2. Encapsulate: `(ciphertext, shared_secret) = ML-KEM.Encaps(ek)`
3. Send: `key_share = ciphertext` (1088 bytes)

**Shared Secret Derivation:**
```
Initiator: shared_secret = ML-KEM.Decaps(dk, ciphertext)
Responder: shared_secret = (from encapsulation)

Both derive session keys via TLS 1.3 key schedule using shared_secret
```

### 3.3 Wire Format

**ML-KEM-768 Client Key Share (1184 bytes):**
```
[1184 bytes: ML-KEM-768 encapsulation key]
```

**ML-KEM-768 Server Key Share (1088 bytes):**
```
[1088 bytes: ML-KEM-768 ciphertext]
```

---

## 4. Digital Signatures (ML-DSA)

### 4.1 Algorithm Selection

ant-quic uses **ML-DSA-65** exclusively for handshake authentication:

| Property | Value |
|----------|-------|
| Algorithm | ML-DSA-65 (FIPS 204) |
| Code Point | 0x0901 (2305) |
| Security Level | NIST Level 3 (equivalent to AES-192) |
| Public Key | 1952 bytes |
| Private Key | 4032 bytes |
| Signature | 3309 bytes |

**No fallback to classical algorithms.** Connections without ML-DSA support
are rejected.

### 4.2 Signature Procedure

**Signing (CertificateVerify):**
```
signature = ML-DSA-65.Sign(private_key, transcript_hash)
```

**Verification:**
```
valid = ML-DSA-65.Verify(public_key, transcript_hash, signature)
```

The transcript hash is computed per TLS 1.3 specification over the handshake
messages up to that point.

### 4.3 Wire Format

**ML-DSA-65 Signature (3309 bytes):**
```
[3309 bytes: ML-DSA-65 signature]
```

---

## 5. TLS Handshake Integration

### 5.1 Negotiation

ant-quic advertises and accepts only pure PQC algorithms:

**Named Groups (key exchange):**
```
Supported: ML-KEM-768 (0x0201)
Rejected:  X25519, secp256r1, hybrid groups
```

**Signature Algorithms:**
```
Supported: ML-DSA-65 (0x0901)
Rejected:  Ed25519, ECDSA, RSA, hybrid signatures
```

### 5.2 Certificate Type

ant-quic uses RFC 7250 raw public keys:

| Extension | Value |
|-----------|-------|
| client_certificate_type | RawPublicKey (2) |
| server_certificate_type | RawPublicKey (2) |

The Certificate message contains the ML-DSA-65 public key as
SubjectPublicKeyInfo (not the Ed25519 identity key).

### 5.3 Handshake Flow

```
Client                                Server
------                                ------
ClientHello
  + key_share(ML-KEM-768)
  + signature_algorithms(ML-DSA-65)
  + client_certificate_type(RawPublicKey)
  + server_certificate_type(RawPublicKey)
                            -------->
                                      ServerHello
                                        + key_share(ML-KEM-768)
                                      EncryptedExtensions
                                        + server_certificate_type(RawPublicKey)
                                      Certificate (ML-DSA-65 SubjectPublicKeyInfo)
                                      CertificateVerify (ML-DSA-65 signature)
                                      Finished
                            <--------
Certificate (ML-DSA-65 SubjectPublicKeyInfo)
CertificateVerify (ML-DSA-65 signature)
Finished
                            -------->
[Application Data]          <------->  [Application Data]
```

### 5.4 Connection Rejection

If a peer does not support ML-KEM-768 or ML-DSA-65, the connection is
terminated with:

- Alert: `handshake_failure` (40)
- Reason: No compatible PQC algorithms

---

## 6. Security Considerations

### 6.1 Quantum Resistance

All cryptographic operations use NIST-standardized post-quantum algorithms:

| Function | Algorithm | Quantum Resistance |
|----------|-----------|-------------------|
| Key Exchange | ML-KEM-768 | ✅ NIST Level 3 |
| Authentication | ML-DSA-65 | ✅ NIST Level 3 |
| Identity (PeerId) | SHA-256(ML-DSA-65) | ✅ Quantum-safe hash |

**Fully Quantum-Resistant Identity:** The PeerId is derived from the ML-DSA-65
public key via SHA-256. This provides:
- Complete quantum resistance for both identity and authentication
- No classical algorithm attack surface
- Single key pair simplifies key management and reduces attack vectors

### 6.2 Forward Secrecy

All key exchange is ephemeral:
- Fresh ML-KEM-768 key pairs per connection
- Compromising long-term ML-DSA-65 keys does not reveal past sessions
- Each session has unique cryptographic material

### 6.3 No Downgrade Attacks

Pure PQC eliminates algorithm downgrade attacks:
- No classical fallback means no downgrade target
- Attacker cannot force weaker algorithms
- Simpler security analysis

### 6.4 Side-Channel Resistance

ML-KEM and ML-DSA implementations must be constant-time. The reference
implementation uses FIPS-validated libraries designed for side-channel
resistance.

---

## 7. Wire Formats

### 7.1 Key Share Sizes

| Direction | Algorithm | Size |
|-----------|-----------|------|
| Client → Server | ML-KEM-768 encapsulation key | 1184 bytes |
| Server → Client | ML-KEM-768 ciphertext | 1088 bytes |

### 7.2 Certificate Sizes

| Component | Size |
|-----------|------|
| ML-DSA-65 SubjectPublicKeyInfo | ~1960 bytes |
| ML-DSA-65 signature | 3309 bytes |

### 7.3 Total Handshake Overhead

Compared to classical TLS 1.3 with X25519 + Ed25519:

| Component | Classical | Pure PQC | Delta |
|-----------|-----------|----------|-------|
| Client key share | 32 bytes | 1184 bytes | +1152 |
| Server key share | 32 bytes | 1088 bytes | +1056 |
| Certificate | ~100 bytes | ~1960 bytes | +1860 |
| Signature | 64 bytes | 3309 bytes | +3245 |
| **Total** | ~228 bytes | ~7541 bytes | **+7313** |

This overhead is acceptable for P2P networks where connections are long-lived.

---

## 8. Code Point Registry

### 8.1 Named Groups (Key Exchange)

| Name | Code Point | Status |
|------|------------|--------|
| ML-KEM-768 | 0x0201 (513) | **Primary - REQUIRED** |
| ML-KEM-512 | 0x0200 (512) | Reserved (Level 1) |
| ML-KEM-1024 | 0x0202 (514) | Reserved (Level 5) |

### 8.2 Signature Schemes

| Name | Code Point | Status |
|------|------------|--------|
| ML-DSA-65 | 0x0901 (2305) | **Primary - REQUIRED** |
| ML-DSA-44 | 0x0900 (2304) | Reserved (Level 2) |
| ML-DSA-87 | 0x0902 (2306) | Reserved (Level 5) |

### 8.3 Deprecated (v1.0 Hybrid)

The following hybrid code points from v1.0 are **deprecated** and will be
rejected:

| Name | Code Point | Status |
|------|------------|--------|
| X25519MLKEM768 | 0x11EC (4588) | ❌ DEPRECATED |
| SecP256r1MLKEM768 | 0x11EB (4587) | ❌ DEPRECATED |
| ed25519_ml_dsa_65 | 0x0920 (2336) | ❌ DEPRECATED |

---

## 9. Migration from v1.0

### 9.1 Breaking Changes

- Hybrid algorithms removed (X25519MLKEM768, ed25519_ml_dsa_65)
- Certificate now contains ML-DSA-65 key (not Ed25519)
- Key share sizes changed

### 9.2 Migration Path

Since ant-quic has not launched publicly, this is a clean break:

1. Update cryptographic provider to pure PQC
2. Regenerate node keys (single ML-DSA-65 key pair)
3. Update configuration to use new code points
4. Test interoperability with updated peers

### 9.3 Compatibility

v2.0 nodes **cannot** communicate with v1.0 nodes. This is intentional for
a pre-launch network.

---

## 10. References

### Normative References

- **FIPS 203**: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)
- **FIPS 204**: Module-Lattice-Based Digital Signature Standard (ML-DSA)
- **RFC 8032**: Edwards-Curve Digital Signature Algorithm (EdDSA)
- **RFC 9000**: QUIC: A UDP-Based Multiplexed and Secure Transport
- **RFC 7250**: Using Raw Public Keys in Transport Layer Security (TLS)

### Informative References

- **NIST SP 800-208**: Post-Quantum Cryptography Guidelines
- **draft-ietf-tls-mlkem-04**: ML-KEM for TLS 1.3

---

## Appendix A: Reference Implementation

The reference implementation is available in the ant-quic source code:

- **Identity**: `src/crypto/identity.rs`
- **ML-KEM**: `src/crypto/pqc/ml_kem.rs`
- **ML-DSA**: `src/crypto/pqc/ml_dsa.rs`
- **TLS Integration**: `src/crypto/pqc/tls_provider.rs`

---

## Appendix B: Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | December 2025 | Initial hybrid specification |
| 2.0 | December 2025 | **Pure PQC** - removed all hybrid algorithms |
| 2.1 | December 2025 | **Single key pair** - PeerId from SHA-256(ML-DSA-65), removed Ed25519 identity |

---

*Copyright 2024-2025 Saorsa Labs Ltd. Licensed under GPL-3.0.*
