# ant-quic Protocol Extensions

This document describes the QUIC protocol extensions implemented in ant-quic for NAT traversal and address discovery.

## Overview

ant-quic implements the following IETF drafts and custom extensions:

1. **draft-ietf-quic-address-discovery-00** - QUIC Address Discovery
2. **draft-seemann-quic-nat-traversal-02** - QUIC NAT Traversal
3. Custom extensions for enhanced P2P connectivity

## Transport Parameters

### NAT Traversal Parameters (0x58)

Negotiates NAT traversal capabilities during the handshake:

```
nat_traversal_enabled (0x58): {
    value: varint,  // 1 = enabled, 0 = disabled
}
```

### Address Discovery Parameters (0x1f00-0x1f02)

Configure address discovery behavior:

```
observed_address_enabled (0x1f00): {
    value: varint,  // 1 = enabled, 0 = disabled
}

max_observed_addresses (0x1f01): {
    value: varint,  // Maximum addresses to track (default: 10)
}

address_validation_token (0x1f02): {
    value: opaque<0..255>,  // Token for address validation
}
```

## Extension Frames

### OBSERVED_ADDRESS Frame (Type=0x43)

Informs the peer of their observed network address as seen by the sender.

#### Frame Structure

```
OBSERVED_ADDRESS Frame {
    Type (i) = 0x43,
    Sequence Number (i),
    IP Version (8),
    IP Address (32/128),
    Port (16),
}
```

#### Fields

- **Type**: Frame type identifier (0x43)
- **Sequence Number**: Monotonically increasing counter for ordering
- **IP Version**: 4 for IPv4, 6 for IPv6
- **IP Address**: 4 bytes for IPv4, 16 bytes for IPv6
- **Port**: UDP port number (network byte order)

#### Usage Example

```rust
// Sending an observed address
connection.send_observed_address(
    peer_addr.ip(),
    peer_addr.port(),
    sequence_num
)?;

// Receiving handler
match frame {
    Frame::ObservedAddress { ip, port, sequence } => {
        if sequence > last_sequence {
            update_reflexive_address(ip, port);
            last_sequence = sequence;
        }
    }
}
```

### ADD_ADDRESS Frame (Type=0x40)

Advertises additional addresses where the sender can be reached.

#### Frame Structure

```
ADD_ADDRESS Frame {
    Type (i) = 0x40,
    Address ID (i),
    IP Version (8),
    IP Address (32/128),
    Port (16),
    Priority (8),
    Address Type (8),
    [Token Length (i)],
    [Validation Token (...)],
}
```

#### Fields

- **Address ID**: Unique identifier for this address
- **Priority**: 0-255, higher = preferred
- **Address Type**: 
  - 0x00 = Direct
  - 0x01 = Server Reflexive
  - 0x02 = Relayed
  - 0x03 = Predicted

### PUNCH_ME_NOW Frame (Type=0x41)

Coordinates simultaneous hole punching attempts.

#### Frame Structure

```
PUNCH_ME_NOW Frame {
    Type (i) = 0x41,
    Round ID (i),
    Target Address Count (i),
    Target Addresses [...] {
        Address ID (i),
        Delay Microseconds (i),
    },
    Coordination Token (64),
}
```

#### Coordination Protocol

1. **Initiator** sends PUNCH_ME_NOW to coordinator
2. **Coordinator** forwards to target peer
3. Both peers simultaneously send packets after specified delay
4. Success reported via ADD_ADDRESS frame

### REMOVE_ADDRESS Frame (Type=0x42)

Removes a previously advertised address.

#### Frame Structure

```
REMOVE_ADDRESS Frame {
    Type (i) = 0x42,
    Address ID (i),
    Reason (8),
}
```

#### Reason Codes

- 0x00 = Address no longer valid
- 0x01 = Network interface down
- 0x02 = NAT mapping expired
- 0x03 = Administrative removal

## NAT Traversal Protocol

### Overview

The NAT traversal protocol enables direct peer-to-peer connections through various NAT types without requiring STUN/TURN servers.

### Roles

1. **Client**: Behind NAT, initiates connections
2. **Server**: Publicly accessible, can accept connections
3. **Bootstrap**: Server that also coordinates NAT traversal

### Connection Establishment Flow

```mermaid
sequenceDiagram
    participant Client A
    participant Bootstrap
    participant Client B
    
    Client A->>Bootstrap: Connect + NAT traversal enabled
    Bootstrap->>Client A: OBSERVED_ADDRESS (public IP:port)
    Client A->>Bootstrap: ADD_ADDRESS (local candidates)
    
    Client B->>Bootstrap: Connect + NAT traversal enabled
    Bootstrap->>Client B: OBSERVED_ADDRESS (public IP:port)
    Client B->>Bootstrap: ADD_ADDRESS (local candidates)
    
    Client A->>Bootstrap: Request connection to Client B
    Bootstrap->>Client B: Forward request + Client A addresses
    Bootstrap->>Client A: Send Client B addresses
    
    Bootstrap->>Client A: PUNCH_ME_NOW (round 1)
    Bootstrap->>Client B: PUNCH_ME_NOW (round 1)
    
    Client A-->>Client B: Simultaneous packets
    Client B-->>Client A: Simultaneous packets
    
    Client A->>Client B: QUIC handshake
```

### Candidate Types and Priority

Candidates are prioritized using a formula similar to ICE:

```
priority = (2^24 * type_preference) + 
           (2^8 * local_preference) + 
           (256 - component_id)
```

Type preferences:
- Local: 126
- Server Reflexive: 100
- Relayed: 10
- Predicted: 5

### Symmetric NAT Handling

For symmetric NATs, ant-quic implements port prediction:

1. **Linear Prediction**: Assumes sequential port allocation
2. **Delta Prediction**: Based on observed port differences
3. **Range Prediction**: Tests a range around predicted port

Example:
```rust
// Predict next port for symmetric NAT
let predicted_ports = predict_symmetric_ports(
    observed_ports,  // Historical observations
    target_addr,     // Destination address
    strategy         // PredictionStrategy
);

// Add predicted candidates
for port in predicted_ports {
    add_candidate(CandidateAddress {
        addr: SocketAddr::new(public_ip, port),
        source: CandidateSource::Predicted,
        priority: calculate_priority(CandidateSource::Predicted),
    });
}
```

## Security Considerations

### Address Validation

Observed addresses MUST be validated to prevent address spoofing:

1. **Token Validation**: Include cryptographic token in OBSERVED_ADDRESS
2. **Rate Limiting**: Limit frequency of address updates
3. **Source Verification**: Only accept from established connections

### Amplification Prevention

To prevent amplification attacks:

1. Limit response size to request size
2. Require established connection for NAT traversal
3. Rate limit hole punching attempts

### Privacy Considerations

1. **Address Disclosure**: Only share addresses with authorized peers
2. **Metadata Protection**: Encrypt coordination messages
3. **Timing Attacks**: Add random jitter to hole punching

## Implementation Notes

### Frame Parsing

```rust
impl Frame {
    pub fn parse(input: &mut impl Buf) -> Result<Self, FrameError> {
        let frame_type = input.get_var()?;
        
        match frame_type {
            0x40 => parse_add_address(input),
            0x41 => parse_punch_me_now(input),
            0x42 => parse_remove_address(input),
            0x43 => parse_observed_address(input),
            _ => Err(FrameError::UnknownType(frame_type)),
        }
    }
}
```

### State Management

```rust
struct NatTraversalState {
    role: NatTraversalRole,
    candidates: HashMap<u64, CandidateAddress>,
    observed_addresses: VecDeque<ObservedAddress>,
    coordination_rounds: HashMap<u64, CoordinationRound>,
    peer_candidates: HashMap<PeerId, Vec<CandidateAddress>>,
}
```

### Concurrency Considerations

1. **Thread Safety**: Use Arc<Mutex<>> for shared state
2. **Async Operations**: Non-blocking candidate discovery
3. **Timeout Handling**: Configurable timeouts for all operations

## Testing

### Unit Tests

```rust
#[test]
fn test_observed_address_frame_encoding() {
    let frame = Frame::ObservedAddress {
        sequence: 42,
        ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        port: 9000,
    };
    
    let mut buf = BytesMut::new();
    frame.encode(&mut buf);
    
    let decoded = Frame::parse(&mut buf.freeze()).unwrap();
    assert_eq!(frame, decoded);
}
```

### Integration Tests

Test against various NAT configurations:

```bash
# Test symmetric NAT traversal
cargo test --test nat_traversal -- symmetric_nat

# Test with packet loss
cargo test --test nat_traversal -- with_loss

# Test all NAT combinations
cargo test --test nat_traversal -- matrix
```

### Compliance Tests

Verify protocol compliance:

```bash
# Run IETF compliance tests
cargo run --bin compliance-test -- \
    --spec draft-ietf-quic-address-discovery-00 \
    --spec draft-seemann-quic-nat-traversal-02
```

## Debugging

### Enable Protocol Logging

```bash
RUST_LOG=ant_quic::frame=trace,ant_quic::connection::nat_traversal=debug \
    cargo run --bin ant-quic
```

### Packet Capture

Extension frames in Wireshark:

1. Filter: `quic.frame_type >= 0x40 && quic.frame_type <= 0x43`
2. Decode as: Custom QUIC frames
3. Export: JSON format for analysis

### Common Issues

1. **No OBSERVED_ADDRESS received**
   - Check transport parameter negotiation
   - Verify both peers support extension

2. **Hole punching fails**
   - Check firewall allows outbound UDP
   - Verify coordinator connectivity
   - Review timing logs

3. **Symmetric NAT issues**
   - Enable port prediction
   - Increase candidate count
   - Consider relay fallback

## Future Extensions

Planned enhancements:

1. **Multi-path Coordination**: Simultaneous attempts on multiple paths
2. **IPv6 Privacy Extensions**: Handle temporary addresses
3. **QUIC Multicast**: One-to-many NAT traversal
4. **Connection Migration**: Maintain connection across NAT changes

## References

- [draft-ietf-quic-address-discovery-00](https://datatracker.ietf.org/doc/draft-ietf-quic-address-discovery/)
- [draft-seemann-quic-nat-traversal-02](https://datatracker.ietf.org/doc/draft-seemann-quic-nat-traversal/)
- [RFC 9000 - QUIC Transport Protocol](https://www.rfc-editor.org/rfc/rfc9000.html)
- [RFC 8445 - ICE](https://www.rfc-editor.org/rfc/rfc8445.html)