# Protocol Extensions

ant-quic extends the QUIC protocol with custom frames and transport parameters for NAT traversal and address discovery.

## Overview

ant-quic implements two IETF drafts:
- **NAT Traversal**: draft-seemann-quic-nat-traversal-02
- **Address Discovery**: draft-ietf-quic-address-discovery-00

These extensions use the QUIC extensibility mechanism:
- Custom transport parameters for capability negotiation
- Custom frame types for protocol messages

## Transport Parameters

Transport parameters are exchanged during the QUIC handshake to negotiate capabilities.

### NAT Traversal Parameters

| Parameter ID | Name | Description |
|--------------|------|-------------|
| 0x3d7e9f0bca12fea6 | NAT Traversal Capability | Indicates NAT traversal support |
| 0x3d7e9f0bca12fea8 | RFC-Compliant Frames | Indicates RFC-compliant frame format |

### Address Discovery Parameters

| Parameter ID | Name | Description |
|--------------|------|-------------|
| 0x9f81a176 | Address Discovery Config | Configuration for address observation |

### Negotiation

Both endpoints must advertise support for NAT traversal in their transport parameters. If either endpoint doesn't support it, NAT traversal is disabled for that connection.

```rust
// Transport parameters are automatically negotiated
// Check if NAT traversal is available:
let nat_available = connection.nat_traversal_supported();
```

## Extension Frames

### ADD_ADDRESS Frame

Advertises a candidate address to the peer.

**Frame Types:**
- `0x3d7e90`: IPv4 address
- `0x3d7e91`: IPv6 address

**Format:**
```
ADD_ADDRESS Frame {
    Address ID (i),
    Sequence Number (i),
    IP Address (32 or 128 bits),
    Port (16 bits)
}
```

**Fields:**
- `Address ID`: Unique identifier for this address
- `Sequence Number`: Monotonically increasing for conflict resolution
- `IP Address`: IPv4 (4 bytes) or IPv6 (16 bytes) address
- `Port`: UDP port number

### PUNCH_ME_NOW Frame

Coordinates simultaneous hole punching between two peers.

**Frame Types:**
- `0x3d7e92`: IPv4 target address
- `0x3d7e93`: IPv6 target address

**Format:**
```
PUNCH_ME_NOW Frame {
    Coordination ID (i),
    Target IP Address (32 or 128 bits),
    Target Port (16 bits)
}
```

**Fields:**
- `Coordination ID`: Unique identifier for this punch attempt
- `Target IP Address`: Address to send packets to
- `Target Port`: Port to send packets to

### REMOVE_ADDRESS Frame

Removes a previously advertised address.

**Frame Type:** `0x3d7e94`

**Format:**
```
REMOVE_ADDRESS Frame {
    Address ID (i),
    Sequence Number (i)
}
```

### OBSERVED_ADDRESS Frame

Reports the external address observed by the peer.

**Frame Types:**
- `0x9f81a6`: IPv4 address
- `0x9f81a7`: IPv6 address

**Format:**
```
OBSERVED_ADDRESS Frame {
    IP Address (32 or 128 bits),
    Port (16 bits)
}
```

This is how address discovery works - when you connect to a peer, they see your source address and send it back to you.

## Frame Processing

### Sending Frames

Frames are sent through the standard QUIC connection:

```rust
// Internal: frames are sent automatically
// ADD_ADDRESS when discovering candidates
// PUNCH_ME_NOW when coordinating hole punch
// OBSERVED_ADDRESS on incoming connections
```

### Receiving Frames

The endpoint processes extension frames automatically:

```rust
// Subscribe to events for frame outcomes
let mut events = endpoint.subscribe();
while let Ok(event) = events.recv().await {
    match event {
        P2pEvent::AddressDiscovered { addr } => {
            // Received OBSERVED_ADDRESS
        }
        P2pEvent::CandidatesDiscovered { peer_id, count } => {
            // Received ADD_ADDRESS frames
        }
        _ => {}
    }
}
```

## Variable-Length Integer Encoding

Frame fields marked with `(i)` use QUIC's variable-length integer encoding:

| 2MSB | Length | Usable Bits | Range |
|------|--------|-------------|-------|
| 00   | 1 byte | 6 bits | 0-63 |
| 01   | 2 bytes | 14 bits | 0-16383 |
| 10   | 4 bytes | 30 bits | 0-1073741823 |
| 11   | 8 bytes | 62 bits | 0-4611686018427387903 |

## Security Considerations

### Frame Validation

All extension frames are validated:
- Address IDs must be unique
- Sequence numbers must be monotonically increasing
- IP addresses are checked for validity
- Rate limiting prevents flooding

### Authentication

Extension frames are only processed from authenticated peers. Since ant-quic uses Raw Public Keys (RFC 7250), peer identity is verified during the QUIC handshake.

### Encryption

All frames are encrypted using QUIC's encryption. In v0.13.0+, this includes hybrid PQC (ML-KEM-768).

## Implementation Details

### Frame IDs

The frame IDs follow QUIC's extensibility rules:
- Use the experimental range to avoid conflicts
- Include versioning for future compatibility

### Compatibility

ant-quic's extension frames are backward compatible:
- Peers that don't understand extensions ignore them
- Transport parameters negotiate capability

## References

- [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) - QUIC Transport Protocol
- [draft-seemann-quic-nat-traversal-02](../../rfcs/draft-seemann-quic-nat-traversal-02.txt)
- [draft-ietf-quic-address-discovery-00](../../rfcs/draft-ietf-quic-address-discovery-00.txt)
