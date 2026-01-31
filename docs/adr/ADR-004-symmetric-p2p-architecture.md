# ADR-004: Symmetric P2P Architecture

## Status

Accepted (2025-12-21)

## Context

Traditional P2P systems often have role distinctions:
- **Client/Server**: Asymmetric capabilities (servers accept, clients connect)
- **Bootstrap nodes**: Special infrastructure with well-known addresses
- **Coordinators**: Designated nodes for NAT traversal assistance

These roles create problems:
- **Operational burden**: Someone must run bootstrap/coordinator infrastructure
- **Single points of failure**: Network depends on special nodes
- **Complexity**: Different code paths for different roles
- **Centralization tendency**: Roles accumulate in well-resourced operators

## Decision

Adopt a **fully symmetric** architecture where all nodes are identical:

```rust
// v0.13.0: Removed role enums entirely
// Before: EndpointRole::Client | EndpointRole::Server | EndpointRole::Bootstrap
// After:  All nodes have equal capabilities

pub struct P2pEndpoint {
    // Every node can:
    // - Accept incoming connections
    // - Initiate outgoing connections
    // - Observe and report peer addresses
    // - Coordinate NAT traversal
    // - Relay traffic (subject to rate limits)
}
```

**Terminology changes**:
- "Bootstrap nodes" → "Known peers" (no special status)
- "Coordinator" → Any connected peer can coordinate
- "Server" → Removed (all nodes accept connections)

**Symmetric capabilities**:
- Every node binds a listening socket
- Every node can observe/report external addresses
- Every node participates in NAT traversal coordination
- Relaying is mandatory via MASQUE (ADR-006) with configurable rate limits

**Measure, don't trust**:
- Capability claims are treated as hints only
- Peer selection is based on observed success rates and reachability
- Nodes are not excluded from roles a priori; they are tested and scored in practice

## Consequences

### Benefits
- **No infrastructure**: No special servers to maintain
- **Resilience**: No single points of failure
- **Simpler code**: One code path, not three
- **True P2P**: Network works with any subset of nodes
- **Natural scaling**: More nodes = more capacity

### Trade-offs
- **Initial bootstrap**: Must know at least one peer to join
- **NAT challenges**: Some NAT types still need coordination
- **Resource equality**: All nodes bear relay/coordination costs

### API Simplification
```rust
// Before (v0.12):
let endpoint = Endpoint::new(EndpointRole::Server, config)?;
let coordinator = NatCoordinator::new(role)?;

// After (v0.13+):
let endpoint = P2pEndpoint::new(config)?;
// That's it - all capabilities included
```

## Alternatives Considered

1. **Traditional client/server**: Designated servers accept connections
   - Rejected: Creates dependency on server operators

2. **Supernodes**: Elect high-capacity nodes for special duties
   - Rejected: Adds election complexity, potential centralization

3. **Hybrid roles**: Optional role hints without enforcement
   - Rejected: Complexity without benefit - just make everyone equal

## References

- Documentation: `docs/SYMMETRIC_P2P.md`
- Version: v0.13.0 (role removal)
- File: `src/quic_node.rs`, `src/nat_traversal_api.rs`
- Removed: `EndpointRole`, `NatTraversalRole` enums
