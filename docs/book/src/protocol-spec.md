# Protocol Specification

Technical specification for ant-quic's QUIC extensions.

## Standards Compliance

ant-quic implements or extends:

| Standard | Description |
|----------|-------------|
| RFC 9000 | QUIC Transport Protocol |
| RFC 9001 | Using TLS with QUIC |
| RFC 7250 | Raw Public Keys in TLS |
| draft-seemann-quic-nat-traversal-02 | NAT Traversal for QUIC |
| draft-ietf-quic-address-discovery-00 | Address Discovery |
| FIPS 203 | ML-KEM-768 |
| FIPS 204 | ML-DSA-65 |

## Transport Parameters

### NAT Traversal Capability

```
Parameter ID: 0x3d7e9f0bca12fea6
Length: 0
Purpose: Indicates NAT traversal support
```

### RFC-Compliant Frame Format

```
Parameter ID: 0x3d7e9f0bca12fea8
Length: 0
Purpose: Indicates RFC-compliant frame format
```

### Address Discovery Configuration

```
Parameter ID: 0x9f81a176
Length: Variable
Purpose: Address discovery settings
Format:
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |  Flags (8)  | Lifetime (varint)|
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## Extension Frames

### ADD_ADDRESS

Advertises address candidates to peer.

```
Type: 0x3d7e90 (IPv4), 0x3d7e91 (IPv6)

Format:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Sequence Number (i)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                       IP Address (4/16)                       +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Port (16)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Fields:
- Sequence Number: Monotonically increasing identifier
- IP Address: 4 bytes (IPv4) or 16 bytes (IPv6)
- Port: 16-bit port number
```

### PUNCH_ME_NOW

Coordinates hole punching timing.

```
Type: 0x3d7e92 (IPv4), 0x3d7e93 (IPv6)

Format:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Sequence Number (i)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                     Target IP Address (4/16)                  +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Target Port (16)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Fields:
- Sequence Number: Matches ADD_ADDRESS sequence
- Target IP Address: Address to punch toward
- Target Port: Port to punch toward
```

### REMOVE_ADDRESS

Removes a previously advertised address.

```
Type: 0x3d7e94

Format:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Sequence Number (i)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Fields:
- Sequence Number: Identifies the address to remove
```

### OBSERVED_ADDRESS

Reports observed external address to peer.

```
Type: 0x9f81a6 (IPv4), 0x9f81a7 (IPv6)

Format:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Sequence Number (i)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                    Observed IP Address (4/16)                 +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Observed Port (16)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Fields:
- Sequence Number: Monotonically increasing
- Observed IP Address: Address seen by sender
- Observed Port: Port seen by sender
```

## Variable-Length Integer Encoding

QUIC uses variable-length integers:

| Range | Prefix | Bytes |
|-------|--------|-------|
| 0-63 | 00 | 1 |
| 0-16383 | 01 | 2 |
| 0-1073741823 | 10 | 4 |
| 0-4611686018427387903 | 11 | 8 |

## Handshake Protocol

### Connection Establishment

```
Client                                Server
   |                                     |
   |------------ Initial ---------------->|
   |   + ClientHello (with X25519+ML-KEM) |
   |                                     |
   |<----------- Initial ----------------|
   |   + ServerHello (with X25519+ML-KEM) |
   |   + EncryptedExtensions             |
   |   + Certificate (Raw Public Key)    |
   |   + CertificateVerify (Ed25519+ML-DSA)|
   |   + Finished                        |
   |                                     |
   |------------ Handshake ------------->|
   |   + Certificate (Raw Public Key)    |
   |   + CertificateVerify (Ed25519+ML-DSA)|
   |   + Finished                        |
   |                                     |
   |<========= Application Data ========>|
```

### NAT Traversal Negotiation

During handshake, peers exchange transport parameters:

```
Transport Parameters (Client):
  - 0x3d7e9f0bca12fea6: (NAT traversal capability)
  - 0x9f81a176: [discovery config]

Transport Parameters (Server):
  - 0x3d7e9f0bca12fea6: (NAT traversal capability)
  - 0x9f81a176: [discovery config]
```

## Cryptographic Specifications

### Key Exchange

1. **X25519**: Classical ECDH
   - Public key: 32 bytes
   - Shared secret: 32 bytes

2. **ML-KEM-768**: Post-quantum KEM
   - Public key: 1,184 bytes
   - Ciphertext: 1,088 bytes
   - Shared secret: 32 bytes

Combined shared secret:
```
shared_secret = KDF(x25519_shared || ml_kem_shared)
```

### Digital Signatures

1. **Ed25519**: Classical signatures
   - Public key: 32 bytes
   - Signature: 64 bytes

2. **ML-DSA-65**: Post-quantum signatures
   - Public key: 1,952 bytes
   - Signature: 3,293 bytes

Combined signature:
```
signature = ed25519_sig || ml_dsa_sig
```

### Raw Public Keys

Per RFC 7250:

```
struct {
    SubjectPublicKeyInfo public_key;
} Certificate;
```

No certificate chain, CA, or extensions.

## Address Discovery Protocol

### Discovery Flow

```
Connecting Node                      Known Peer
      |                                  |
      |--------- QUIC Handshake -------->|
      |                                  |
      |                     [Observe source address]
      |                                  |
      |<------- OBSERVED_ADDRESS --------|
      |   (addr: 203.0.113.50:45678)     |
      |                                  |
      |         [Now knows external address]
      |                                  |
```

### Hole Punching Protocol

```
Node A                 Coordinator              Node B
   |                       |                       |
   |-- ADD_ADDRESS ------->|                       |
   |                       |<------ ADD_ADDRESS ---|
   |                       |                       |
   |                   [Exchange candidates]       |
   |                       |                       |
   |<-- PUNCH_ME_NOW ------|                       |
   |                       |------- PUNCH_ME_NOW ->|
   |                       |                       |
   |============= Simultaneous UDP ===============>|
   |<============ Simultaneous UDP ================|
   |                       |                       |
   |<=== Direct QUIC Connection Established =====>|
```

## Security Considerations

### Frame Authentication

All extension frames are:
1. Sent over authenticated QUIC connections
2. Encrypted with TLS 1.3 (AEAD)
3. Bound to the connection ID

### Address Validation

Receivers MUST validate:
1. Sequence numbers are monotonic
2. Addresses are valid (no multicast, etc.)
3. Rate limits are respected

### Rate Limiting

Implementations SHOULD limit:
- ADD_ADDRESS: 10 per second
- PUNCH_ME_NOW: 5 per second
- OBSERVED_ADDRESS: 2 per second

## References

- [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000)
- [RFC 7250](https://www.rfc-editor.org/rfc/rfc7250)
- [draft-seemann-quic-nat-traversal-02](../../rfcs/draft-seemann-quic-nat-traversal-02.txt)
- [draft-ietf-quic-address-discovery-00](../../rfcs/draft-ietf-quic-address-discovery-00.txt)
- [FIPS 203](../../rfcs/fips-203-ml-kem.pdf)
- [FIPS 204](../../rfcs/fips-204-ml-dsa.pdf)

