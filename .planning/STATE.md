# Project State: Multi-Transport Wiring

## Current Position
- **Milestone**: 1 - Registry Wiring
- **Phase**: 1.1 - Node → P2pEndpoint Wiring
- **Status**: DESIGNED (run `/gsd:plan-phase` to detail first phase)

## The Problem

The transport abstraction exists but is completely unwired:

```
NodeConfig.transport_providers → IGNORED by Node::with_config()
                                      ↓
                               P2pConfig has no transport_providers field
                                      ↓
                               NatTraversalConfig has no transport_providers field
                                      ↓
                               create_inner_endpoint() hardcodes UdpSocket::bind()
```

**Result**: Registering BleTransport (or anything else) has zero effect. The runtime remains UDP-only.

## Interview Decisions

| Topic | Decision |
|-------|----------|
| Problem | Missing functionality - BLE/LoRa/etc unusable despite abstraction existing |
| Success Criteria | Production ready - full multi-transport with tested BLE, constrained engine, docs |
| Integration | Modify existing layers - wire through Node → P2pEndpoint → NatTraversalEndpoint |
| Error Handling | Dedicated error types with transport-specific context |
| Async Model | Fully async (tokio) - concurrent receive on multiple transports |
| Testing | Unit tests, Integration tests, Property-based tests |
| Documentation | Full public API docs with implementation guides |
| Priority | Core wiring first, then addresses, then BLE, then constrained engine |
| Risks | Platform-specific BLE, QUIC endpoint limitation, Performance sensitive |

## Implementation Guidance (from team)

1. **Pass TransportRegistry through Node → P2pEndpoint** constructors and store it in P2pEndpoint
2. **Update send/receive path** to use registry: loop over `registry.online_providers()` to bind/listen, select providers based on ProtocolEngine/capabilities when dialing
3. **Teach NatTraversalEndpoint** and peer adverts to include TransportAddr + capability summaries

This keeps the public API stable, enables incremental transport-by-transport improvements, and ensures existing observability and NAT traversal logic continues to work.

## Milestone Overview

```
MILESTONE 1: Registry Wiring
├─ Phase 1.1: Node → P2pEndpoint Wiring ← YOU ARE HERE
├─ Phase 1.2: P2pEndpoint → NatTraversalEndpoint Wiring
└─ Phase 1.3: Multi-Transport Send/Receive Path

MILESTONE 2: Address Migration
├─ Phase 2.1: Config Address Migration
├─ Phase 2.2: Event Address Migration
└─ Phase 2.3: NAT Traversal Adverts

MILESTONE 3: BLE Transport Completion
├─ Phase 3.1: BLE GATT Implementation
├─ Phase 3.2: BLE Fragmentation & Reliability
└─ Phase 3.3: BLE Session Caching

MILESTONE 4: Constrained Protocol Engine
├─ Phase 4.1: Constrained Engine Design
├─ Phase 4.2: Constrained Engine Implementation
└─ Phase 4.3: Protocol Engine Selection
```

## Key Files to Modify

| Layer | File | Current Issue |
|-------|------|---------------|
| Node | `src/node.rs:263-294` | Ignores transport_providers |
| Node | `src/node_config.rs` | Has field, builder methods work |
| P2P | `src/p2p_endpoint.rs` | No transport_providers field |
| P2P | `src/unified_config.rs` | P2pConfig uses SocketAddr |
| NAT | `src/nat_traversal_api.rs:1676-1682` | Hardcodes UdpSocket::bind() |

## Next Action

Run `/gsd:plan-phase` to detail Phase 1.1 into specific tasks.
