# ant-quic Hybrid Post-Quantum Authentication Specification

**Version:** 1.0
**Date:** December 2025
**Status:** Stable
**Authors:** Saorsa Labs Ltd.

## Abstract

This document specifies the authentication and key exchange mechanisms used by
ant-quic for secure peer-to-peer communication. ant-quic employs a hybrid
cryptographic approach that combines classical algorithms with post-quantum
cryptography (PQC) to provide quantum-resistant security while maintaining
compatibility during the transition period.

This specification replaces previous references to RFC 7250, which ant-quic
uses only as inspiration for the raw public key concept. The cryptographic
algorithms and wire formats documented here are specific to ant-quic.

## Table of Contents

1. [Introduction](#1-introduction)
2. [Identity Model](#2-identity-model)
3. [Hybrid Key Exchange](#3-hybrid-key-exchange)
4. [Hybrid Signatures](#4-hybrid-signatures)
5. [TLS Handshake Integration](#5-tls-handshake-integration)
6. [Security Considerations](#6-security-considerations)
7. [Test Vectors](#7-test-vectors)
8. [IANA Code Point Registry](#8-iana-code-point-registry)
9. [References](#9-references)

---

## 1. Introduction

### 1.1 Purpose

ant-quic is a QUIC transport implementation optimized for P2P networks with
advanced NAT traversal capabilities. This specification defines the
cryptographic mechanisms used for:

- **Peer Identity**: Persistent node identification using Ed25519 public keys
- **Key Exchange**: Quantum-resistant session key establishment using hybrid
  ML-KEM algorithms
- **Authentication**: Handshake signing using hybrid ML-DSA algorithms

### 1.2 Design Philosophy

ant-quic follows a "hybrid-or-fail" policy: connections MUST use hybrid
post-quantum algorithms. Classical-only connections are rejected. This ensures
all traffic is protected against both current and future quantum attacks.

### 1.3 Relationship to Standards

| Standard | Relationship |
|----------|--------------|
| RFC 7250 | Inspired the raw public key concept (no X.509 certificates) |
| RFC 9000 | Base QUIC protocol |
| FIPS 203 | ML-KEM key encapsulation (used in hybrid groups) |
| FIPS 204 | ML-DSA digital signatures (used in hybrid schemes) |
| draft-ietf-tls-hybrid-design-14 | Hybrid key exchange framework |

### 1.4 Terminology

- **Classical**: Traditional cryptographic algorithms (Ed25519, X25519, ECDSA)
- **PQC**: Post-Quantum Cryptography resistant to quantum computer attacks
- **Hybrid**: Combination of classical + PQC algorithms
- **PeerId**: 32-byte identifier derived from an Ed25519 public key

---

## 2. Identity Model

### 2.1 Ed25519 Identity Keys

Each ant-quic node has a persistent identity based on an Ed25519 key pair:

```
Ed25519 Private Key: 32 bytes (256 bits)
Ed25519 Public Key:  32 bytes (256 bits)
```

The Ed25519 algorithm is defined in RFC 8032 and uses the edwards25519 curve.

### 2.2 PeerId Derivation

The PeerId is the 32-byte Ed25519 public key used directly as the node
identifier. No hashing is applied:

```
PeerId = Ed25519_Public_Key  (32 bytes)
```

### 2.3 SubjectPublicKeyInfo Encoding

For TLS integration, the Ed25519 public key is encoded as a DER-encoded
SubjectPublicKeyInfo structure (44 bytes total):

```asn1
SubjectPublicKeyInfo ::= SEQUENCE {
    algorithm  AlgorithmIdentifier,
    subjectPublicKey  BIT STRING
}

AlgorithmIdentifier ::= SEQUENCE {
    algorithm  OBJECT IDENTIFIER,  -- 1.3.101.112 (Ed25519)
    parameters  ANY DEFINED BY algorithm OPTIONAL
}
```

**DER Encoding (44 bytes):**

```
Offset  Hex             Description
------  --------------  -------------------------------------------
0       30 2a           SEQUENCE (42 bytes total)
2       30 05           AlgorithmIdentifier SEQUENCE (5 bytes)
4       06 03           OID (3 bytes)
6       2b 65 70        Ed25519 OID: 1.3.101.112
9       03 21           BIT STRING (33 bytes: 1 unused-bits + 32 key)
11      00              Unused bits = 0
12      [32 bytes]      Ed25519 public key bytes
```

**OID Values:**
- Ed25519: `1.3.101.112` = `0x2b 0x65 0x70`

### 2.4 Trust Model

ant-quic uses an out-of-band trust model:

- **No Certificate Authorities**: Peers are authenticated by public key, not
  certificate chains
- **Trust-on-First-Use (TOFU)**: Applications may cache peer public keys
- **Application-Level Trust**: The calling application decides which peers to
  trust

---

## 3. Hybrid Key Exchange

### 3.1 Overview

Hybrid key exchange combines a classical Diffie-Hellman (X25519 or ECDH) with
a post-quantum Key Encapsulation Mechanism (ML-KEM). Both shared secrets are
combined using a KDF to produce the final session keys.

### 3.2 Supported Named Groups

| Name | Code Point | Components | Security Level |
|------|------------|------------|----------------|
| X25519MLKEM768 | 0x11EC (4588) | X25519 + ML-KEM-768 | NIST Level 3 |
| SecP256r1MLKEM768 | 0x11EB (4587) | secp256r1 + ML-KEM-768 | NIST Level 3 |
| SecP384r1MLKEM1024 | 0x11ED (4589) | secp384r1 + ML-KEM-1024 | NIST Level 5 |
| ML-KEM-512 | 0x0200 (512) | Pure ML-KEM-512 | NIST Level 1 |
| ML-KEM-768 | 0x0201 (513) | Pure ML-KEM-768 | NIST Level 3 |
| ML-KEM-1024 | 0x0202 (514) | Pure ML-KEM-1024 | NIST Level 5 |

**Primary (Default):** X25519MLKEM768 (0x11EC)

### 3.3 Hybrid Key Exchange Procedure

For X25519MLKEM768, the key exchange proceeds as follows:

**Initiator (ClientHello):**
1. Generate ephemeral X25519 key pair: `(x_priv, x_pub)`
2. Generate ephemeral ML-KEM-768 key pair: `(kem_sk, kem_pk)`
3. Send: `key_share = x_pub || kem_pk`

**Responder (ServerHello):**
1. Generate ephemeral X25519 key pair: `(y_priv, y_pub)`
2. Compute X25519 shared secret: `ss_classical = X25519(y_priv, x_pub)`
3. Encapsulate to ML-KEM public key: `(ciphertext, ss_pqc) = ML-KEM.Encaps(kem_pk)`
4. Send: `key_share = y_pub || ciphertext`

**Shared Secret Derivation:**
Both parties compute:
```
ss_combined = HKDF-SHA256(
    salt = empty,
    ikm = ss_classical || ss_pqc,
    info = "ant-quic hybrid key exchange",
    len = 32
)
```

### 3.4 Wire Formats

**X25519MLKEM768 Client Key Share (1216 bytes):**
```
Offset  Length  Description
------  ------  -----------
0       32      X25519 public key
32      1184    ML-KEM-768 encapsulation key
```

**X25519MLKEM768 Server Key Share (1120 bytes):**
```
Offset  Length  Description
------  ------  -----------
0       32      X25519 public key
32      1088    ML-KEM-768 ciphertext
```

**ML-KEM Parameter Sizes:**
| Algorithm | Encapsulation Key | Ciphertext | Shared Secret |
|-----------|-------------------|------------|---------------|
| ML-KEM-512 | 800 bytes | 768 bytes | 32 bytes |
| ML-KEM-768 | 1184 bytes | 1088 bytes | 32 bytes |
| ML-KEM-1024 | 1568 bytes | 1568 bytes | 32 bytes |

---

## 4. Hybrid Signatures

### 4.1 Overview

Hybrid signatures combine a classical signature (Ed25519 or ECDSA) with a
post-quantum signature (ML-DSA). Both signatures are computed independently
and concatenated. Verification requires BOTH signatures to be valid.

### 4.2 Supported Signature Schemes

| Name | Code Point | Components | Security Level |
|------|------------|------------|----------------|
| ed25519_ml_dsa_65 | 0x0920 (2336) | Ed25519 + ML-DSA-65 | NIST Level 3 |
| ecdsa_p256_ml_dsa_65 | 0x0921 (2337) | ECDSA-P256 + ML-DSA-65 | NIST Level 3 |
| ecdsa_p384_ml_dsa_87 | 0x0922 (2338) | ECDSA-P384 + ML-DSA-87 | NIST Level 5 |
| ML-DSA-44 | 0x0900 (2304) | Pure ML-DSA-44 | NIST Level 2 |
| ML-DSA-65 | 0x0901 (2305) | Pure ML-DSA-65 | NIST Level 3 |
| ML-DSA-87 | 0x0902 (2306) | Pure ML-DSA-87 | NIST Level 5 |

**Primary (Default):** ed25519_ml_dsa_65 (0x0920)

### 4.3 Hybrid Signature Procedure

For ed25519_ml_dsa_65:

**Signing:**
1. Compute Ed25519 signature: `sig_ed25519 = Ed25519.Sign(sk_ed25519, message)`
2. Compute ML-DSA-65 signature: `sig_mldsa = ML-DSA-65.Sign(sk_mldsa, message)`
3. Concatenate: `hybrid_sig = sig_ed25519 || sig_mldsa`

**Verification:**
1. Split signature: `sig_ed25519 = hybrid_sig[0:64]`, `sig_mldsa = hybrid_sig[64:]`
2. Verify Ed25519: `Ed25519.Verify(pk_ed25519, message, sig_ed25519)`
3. Verify ML-DSA-65: `ML-DSA-65.Verify(pk_mldsa, message, sig_mldsa)`
4. Return success ONLY if BOTH verify

### 4.4 Wire Formats

**ed25519_ml_dsa_65 Signature (3373 bytes):**
```
Offset  Length  Description
------  ------  -----------
0       64      Ed25519 signature
64      3309    ML-DSA-65 signature
```

**ML-DSA Signature Sizes:**
| Algorithm | Signature Size |
|-----------|---------------|
| ML-DSA-44 | 2420 bytes |
| ML-DSA-65 | 3309 bytes |
| ML-DSA-87 | 4627 bytes |

---

## 5. TLS Handshake Integration

### 5.1 Certificate Type Extensions

ant-quic uses the RFC 7250 mechanism for negotiating raw public keys:

| Extension | Code Point | Purpose |
|-----------|------------|---------|
| client_certificate_type | 47 | Client cert type negotiation |
| server_certificate_type | 48 | Server cert type negotiation |

**Certificate Types:**
| Type | Value | Description |
|------|-------|-------------|
| X.509 | 0 | Traditional X.509 certificates |
| RawPublicKey | 2 | Raw SubjectPublicKeyInfo (ant-quic uses this) |

### 5.2 Negotiation Logic

ant-quic enforces hybrid-or-fail:

1. **Advertise**: Only hybrid and pure PQC named groups/signature schemes
2. **Select**: Prefer hybrid (X25519MLKEM768, ed25519_ml_dsa_65)
3. **Reject**: Fail connection if no PQC option available

**Priority Order (Named Groups):**
1. X25519MLKEM768 (0x11EC)
2. SecP256r1MLKEM768 (0x11EB)
3. SecP384r1MLKEM1024 (0x11ED)
4. ML-KEM-768 (0x0201)
5. ML-KEM-1024 (0x0202)

**Priority Order (Signature Schemes):**
1. ed25519_ml_dsa_65 (0x0920)
2. ecdsa_p256_ml_dsa_65 (0x0921)
3. ecdsa_p384_ml_dsa_87 (0x0922)
4. ML-DSA-65 (0x0901)
5. ML-DSA-87 (0x0902)

### 5.3 Handshake Flow

```
Client                                Server
------                                ------
ClientHello
  + key_share(X25519MLKEM768)
  + signature_algorithms(ed25519_ml_dsa_65,...)
  + client_certificate_type(RawPublicKey)
  + server_certificate_type(RawPublicKey)
                            -------->
                                      ServerHello
                                        + key_share(X25519MLKEM768)
                                      EncryptedExtensions
                                        + server_certificate_type(RawPublicKey)
                                      Certificate (SubjectPublicKeyInfo)
                                      CertificateVerify (hybrid signature)
                                      Finished
                            <--------
Certificate (SubjectPublicKeyInfo)
CertificateVerify (hybrid signature)
Finished
                            -------->
[Application Data]          <------->  [Application Data]
```

---

## 6. Security Considerations

### 6.1 Quantum Resistance

The hybrid approach provides defense-in-depth:

- **If classical is broken**: ML-KEM/ML-DSA still protect the session
- **If PQC is broken**: Classical algorithms still protect the session
- **Both must be broken**: To compromise a hybrid connection

This is the recommended approach during the PQC transition period.

### 6.2 Forward Secrecy

All key exchange is ephemeral:

- Fresh X25519 and ML-KEM key pairs per connection
- Compromising long-term keys does not reveal past sessions
- Each session has unique cryptographic material

### 6.3 Identity Binding

The Ed25519 identity key is bound to hybrid authentication:

- Identity: Ed25519 public key (long-term)
- Authentication: ed25519_ml_dsa_65 hybrid signature (per-handshake)
- Key Exchange: X25519MLKEM768 (ephemeral)

The hybrid signature during handshake proves possession of both:
1. The Ed25519 private key (identity proof)
2. The ML-DSA-65 private key (quantum-resistant proof)

### 6.4 Side-Channel Resistance

ML-KEM and ML-DSA implementations should be constant-time to prevent
timing attacks. The reference implementation uses the `ml-kem` and `ml-dsa`
crates which are designed for side-channel resistance.

---

## 7. Test Vectors

### 7.1 Ed25519 SubjectPublicKeyInfo Encoding

**Input (Ed25519 public key, 32 bytes):**
```
d75a980182b10ab7d54bfed3c964073a
0ee172f3daa62325af021a68f707511a
```

**Output (SubjectPublicKeyInfo DER, 44 bytes):**
```
302a300506032b6570032100d75a9801
82b10ab7d54bfed3c964073a0ee172f3
daa62325af021a68f707511a
```

### 7.2 Named Group Wire Encoding

**X25519MLKEM768 (0x11EC):**
```
11 EC
```

**SecP256r1MLKEM768 (0x11EB):**
```
11 EB
```

### 7.3 Signature Scheme Wire Encoding

**ed25519_ml_dsa_65 (0x0920):**
```
09 20
```

**ML-DSA-65 (0x0901):**
```
09 01
```

---

## 8. IANA Code Point Registry

### 8.1 Named Groups

| Name | Code Point (Hex) | Code Point (Dec) | Status |
|------|------------------|------------------|--------|
| secp256r1 | 0x0017 | 23 | IANA TLS 1.3 |
| secp384r1 | 0x0018 | 24 | IANA TLS 1.3 |
| secp521r1 | 0x0019 | 25 | IANA TLS 1.3 |
| x25519 | 0x001D | 29 | IANA TLS 1.3 |
| x448 | 0x001E | 30 | IANA TLS 1.3 |
| ML-KEM-512 | 0x0200 | 512 | ant-quic |
| ML-KEM-768 | 0x0201 | 513 | ant-quic |
| ML-KEM-1024 | 0x0202 | 514 | ant-quic |
| SecP256r1MLKEM768 | 0x11EB | 4587 | IANA assigned |
| X25519MLKEM768 | 0x11EC | 4588 | IANA assigned |
| SecP384r1MLKEM1024 | 0x11ED | 4589 | IANA assigned |

### 8.2 Signature Schemes

| Name | Code Point (Hex) | Code Point (Dec) | Status |
|------|------------------|------------------|--------|
| rsa_pkcs1_sha256 | 0x0401 | 1025 | IANA TLS 1.3 |
| ecdsa_secp256r1_sha256 | 0x0403 | 1027 | IANA TLS 1.3 |
| ecdsa_secp384r1_sha384 | 0x0503 | 1283 | IANA TLS 1.3 |
| ed25519 | 0x0807 | 2055 | IANA TLS 1.3 |
| ed448 | 0x0808 | 2056 | IANA TLS 1.3 |
| ML-DSA-44 | 0x0900 | 2304 | ant-quic |
| ML-DSA-65 | 0x0901 | 2305 | ant-quic |
| ML-DSA-87 | 0x0902 | 2306 | ant-quic |
| ed25519_ml_dsa_65 | 0x0920 | 2336 | ant-quic |
| ecdsa_p256_ml_dsa_65 | 0x0921 | 2337 | ant-quic |
| ecdsa_p384_ml_dsa_87 | 0x0922 | 2338 | ant-quic |

### 8.3 Certificate Types

| Type | Value | Source |
|------|-------|--------|
| X.509 | 0 | RFC 7250 |
| RawPublicKey | 2 | RFC 7250 |

---

## 9. References

### Normative References

- **FIPS 203**: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)
- **FIPS 204**: Module-Lattice-Based Digital Signature Standard (ML-DSA)
- **RFC 8032**: Edwards-Curve Digital Signature Algorithm (EdDSA)
- **RFC 9000**: QUIC: A UDP-Based Multiplexed and Secure Transport

### Informative References

- **RFC 7250**: Using Raw Public Keys in Transport Layer Security (TLS)
- **draft-ietf-tls-hybrid-design-14**: Hybrid Key Exchange in TLS 1.3
- **draft-ietf-tls-ecdhe-mlkem-00**: ECDHE-MLKEM Hybrid Key Agreement

---

## Appendix A: Reference Implementation

The reference implementation is available in the ant-quic source code:

- **Identity**: `src/crypto/raw_public_keys.rs`
- **Key Exchange**: `src/crypto/pqc/hybrid.rs`
- **ML-KEM**: `src/crypto/pqc/ml_kem.rs`
- **ML-DSA**: `src/crypto/pqc/ml_dsa.rs`
- **TLS Extensions**: `src/crypto/pqc/tls_extensions.rs`
- **Negotiation**: `src/crypto/pqc/negotiation.rs`

---

## Appendix B: Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | December 2025 | Initial release |

---

*Copyright 2024-2025 Saorsa Labs Ltd. Licensed under GPL-3.0.*
