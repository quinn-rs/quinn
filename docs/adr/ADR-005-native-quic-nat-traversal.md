# ADR-005: Native QUIC NAT Traversal

## Status

Accepted (2025-12-21)

## Context

### The Problem

Most Internet hosts are behind NAT (Network Address Translation), which blocks incoming connections. Traditional solutions:

- **STUN**: Discovers external address via external servers
- **TURN**: Relays all traffic through external servers
- **ICE**: Orchestrates STUN/TURN with complex state machine

These require **external infrastructure** (STUN/TURN servers) that must be:
- Operated by someone
- Highly available
- Geographically distributed
- Trusted not to manipulate addresses

### ant-quic's Scope

ant-quic should be the **smallest useful substrate** that can reliably connect machines across the public Internet without central coordinators.

**What ant-quic MUST provide**:
- Stable endpoint identity (cryptographic) distinct from network locator
- QUIC transport (streams + datagrams) with symmetric peer roles
- QUIC NAT traversal and address discovery
- Mandatory capability to coordinate and relay (with rate limits)
- Greedy bootstrap cache with peer capabilities
- Application protocol multiplexing

**What ant-quic must NOT provide**:
- DHT semantics (replication, close-groups, pricing)
- Naming, record formats, CRDTs
- Overlay-specific admission rules

## Decision

Implement **native QUIC NAT traversal** using QUIC extension frames, eliminating external infrastructure:

### Extension Frames

| Frame | Type ID | Purpose |
|-------|---------|---------|
| ADD_ADDRESS | 0x3d7e90-91 | Advertise candidate addresses |
| PUNCH_ME_NOW | 0x3d7e92-93 | Coordinate simultaneous hole punching |
| REMOVE_ADDRESS | 0x3d7e94 | Remove invalid candidates |
| OBSERVED_ADDRESS | 0x9f81a6-a7 | Report peer's external address |

### Transport Parameters

| Parameter | ID | Purpose |
|-----------|-------|---------|
| NAT capability | 0x3d7e9f0bca12fea6 | Negotiate NAT traversal support |
| Frame format | 0x3d7e9f0bca12fea8 | RFC-compliant frame format |
| Address discovery | 0x9f81a176 | Configure observation behavior |

### How It Works

1. **Address Discovery**: Peers report observed external addresses via OBSERVED_ADDRESS (no STUN needed)
2. **Candidate Exchange**: Peers share candidates via ADD_ADDRESS frames
3. **Hole Punching**: Coordinated via PUNCH_ME_NOW (any peer can coordinate)
4. **Validation**: Test candidate pairs, promote successful paths
5. **Fallback**: If direct fails, use MASQUE relay (see ADR-006)

### Three-Layer Connectivity Strategy

| Layer | Method | Success Rate | Used When |
|-------|--------|--------------|-----------|
| 1 | Direct QUIC | ~20% | No NAT, public IPs |
| 2 | Native NAT traversal | High* | Most NAT types |
| 3 | MASQUE relay (ADR-006) | ~100% | Symmetric NAT, CGNAT |

*Testing including CGNAT environments has shown excellent results. Specific success rates await broader deployment validation.

This layered approach ensures near-100% connectivity while minimizing relay usage.

### Symmetric NAT Handling

For symmetric NATs that use different ports per destination:
- Port prediction based on observed sequences
- Multiple candidate addresses with port ranges
- Higher coordination round count

## Consequences

### Benefits
- **No external servers**: Completely serverless NAT traversal
- **Lower latency**: No STUN round-trips before connecting
- **Simpler operations**: Nothing to deploy except nodes themselves
- **Native QUIC integration**: Leverages existing QUIC machinery
- **Symmetric**: Any connected peer can assist

### Trade-offs
- **Non-standard**: Custom extension frames (based on IETF drafts)
- **Requires seed peer**: Must connect to at least one peer first
- **Symmetric NAT limits**: Some challenging NAT configurations may require relay fallback

### Standards Basis

Based on IETF drafts (not yet RFCs):
- `draft-seemann-quic-nat-traversal-02`
- `draft-ietf-quic-address-discovery-00`

## Alternatives Considered

1. **STUN/ICE/TURN**: Traditional NAT traversal stack
   - Rejected: Requires external infrastructure we don't want

2. **libp2p AutoNAT**: Higher-level protocol over QUIC
   - Rejected: Additional complexity layer, still needs coordination

3. **UPnP/PCP**: Router port mapping protocols
   - Rejected: Not universally supported, security concerns

4. **Always relay**: Route all traffic through known peers
   - Rejected: Inefficient, creates bottlenecks

## References

- Specification: `docs/rfcs/draft-seemann-quic-nat-traversal-02.txt`
- Address Discovery: `docs/rfcs/draft-ietf-quic-address-discovery-00.txt`
- Documentation: `docs/NAT_TRAVERSAL_GUIDE.md`
- Implementation: `src/nat_traversal_api.rs`, `src/connection/nat_traversal.rs`
- Frame definitions: `src/frame.rs`
