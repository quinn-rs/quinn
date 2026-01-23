# Multi-Transport Integration Roadmap

## Overview

Wire the existing TransportRegistry and TransportProvider abstractions into the ant-quic networking stack, enabling multi-transport P2P connectivity beyond UDP-only. The transport abstraction layer exists (`src/transport/`) but is completely disconnected from the runtime - this work connects it.

**Problem Statement**: The previous work created a comprehensive transport abstraction (TransportAddr, TransportProvider, TransportRegistry, BLE/UDP implementations) but never wired it in. NodeConfig.transport_providers is ignored by Node::with_config(). The entire stack still uses raw SocketAddr and hardcodes UdpSocket::bind() in create_inner_endpoint().

## Success Criteria

- TransportRegistry flows through Node → P2pEndpoint → NatTraversalEndpoint
- UDP works through the TransportProvider abstraction (no regression)
- BLE transport functional for basic P2P connectivity
- Constrained protocol engine for low-bandwidth transports
- Full public API documentation with examples
- Zero warnings, zero clippy violations, comprehensive tests

## Technical Decisions

| Topic | Decision |
|-------|----------|
| Problem | Missing functionality - BLE/LoRa/etc unusable despite abstraction existing |
| Integration | Modify existing layers - wire through Node → P2pEndpoint → NatTraversalEndpoint |
| Error Handling | Dedicated error types with transport-specific context |
| Async Model | Fully async (tokio) - concurrent receive on multiple transports |
| Testing | Unit tests + Integration tests + Property-based tests |
| Documentation | Full public API docs with implementation guides |
| Priority | Core wiring first, then addresses, then BLE, then constrained engine |

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Platform-specific BLE | Conditional compilation, platform-specific tests, CI matrix |
| QUIC endpoint limitation | Adapter pattern - UdpTransport provides socket to Quinn |
| Performance sensitive | Benchmark before/after, zero-cost abstraction design |

---

## Milestone 1: Registry Wiring

Wire TransportRegistry through the node construction chain so registered transports are actually used.

### Phase 1.1: Node → P2pEndpoint Wiring
- **Focus**: Pass TransportRegistry from NodeConfig through to P2pEndpoint
- **Key Deliverables**:
  - Add `transport_providers` field to P2pConfig
  - Modify Node::with_config() to pass providers through
  - Store TransportRegistry in P2pEndpoint
  - Backward-compatible: default to UDP if no providers specified
- **Dependencies**: None (first phase)
- **Files**: `src/node.rs`, `src/node_config.rs`, `src/p2p_endpoint.rs`, `src/unified_config.rs`
- **Estimated Tasks**: 4-6 tasks

### Phase 1.2: P2pEndpoint → NatTraversalEndpoint Wiring
- **Focus**: Pass registry to NatTraversalEndpoint, use for socket binding
- **Key Deliverables**:
  - Add `transport_providers` to NatTraversalConfig
  - Modify create_inner_endpoint() to accept TransportProvider
  - Extract UDP socket from UdpTransport for Quinn Endpoint
  - Fall back to direct UdpSocket::bind() if no providers
- **Dependencies**: Phase 1.1
- **Files**: `src/nat_traversal_api.rs`, `src/transport/udp.rs`
- **Estimated Tasks**: 5-7 tasks

### Phase 1.3: Multi-Transport Send/Receive Path
- **Focus**: Enable concurrent receive on all online transports
- **Key Deliverables**:
  - Loop over registry.online_providers() for listening
  - Select provider based on ProtocolEngine/capabilities when dialing
  - Route inbound datagrams to appropriate handler
  - Maintain backward compatibility with single-transport case
- **Dependencies**: Phase 1.2
- **Files**: `src/p2p_endpoint.rs`, `src/transport/provider.rs`
- **Estimated Tasks**: 6-8 tasks

---

## Milestone 2: Address Migration

Migrate from raw SocketAddr to TransportAddr throughout the stack.

### Phase 2.1: Config Address Migration
- **Focus**: Update configuration types to use TransportAddr
- **Key Deliverables**:
  - P2pConfig.bind_addr: SocketAddr → TransportAddr
  - P2pConfig.known_peers: Vec<SocketAddr> → Vec<TransportAddr>
  - NodeConfig address fields migration
  - Conversion utilities for backward compatibility
- **Dependencies**: Milestone 1
- **Files**: `src/unified_config.rs`, `src/node_config.rs`
- **Estimated Tasks**: 4-5 tasks

### Phase 2.2: Event Address Migration
- **Focus**: Update P2pEvent and connection events to use TransportAddr
- **Key Deliverables**:
  - P2pEvent::PeerConnected addr field
  - P2pEvent::ExternalAddressDiscovered addr field
  - Connection tracking uses TransportAddr
  - Event serialization updated
- **Dependencies**: Phase 2.1
- **Files**: `src/p2p_endpoint.rs`
- **Estimated Tasks**: 4-5 tasks

### Phase 2.3: NAT Traversal Adverts
- **Focus**: Include TransportAddr + capabilities in peer advertisements
- **Key Deliverables**:
  - ADD_ADDRESS frame carries TransportAddr type indicator
  - Capability summary in peer adverts
  - Remote peer transport awareness
  - Transport selection based on advertised capabilities
- **Dependencies**: Phase 2.2
- **Files**: `src/nat_traversal_api.rs`, `src/frame.rs`, `src/connection/nat_traversal.rs`
- **Estimated Tasks**: 5-7 tasks

---

## Milestone 3: BLE Transport Completion

Complete the BLE transport implementation for real-world P2P over Bluetooth.

### Phase 3.1: BLE GATT Implementation
- **Focus**: Implement actual BLE send/receive via btleplug
- **Key Deliverables**:
  - GATT service and characteristic definitions
  - Peripheral mode (advertising, accepting connections)
  - Central mode (scanning, connecting)
  - Platform-specific adapters (Linux/macOS/Windows)
- **Dependencies**: Milestone 2
- **Files**: `src/transport/ble.rs`
- **Estimated Tasks**: 8-10 tasks

### Phase 3.2: BLE Fragmentation & Reliability
- **Focus**: Handle packets larger than BLE MTU (244 bytes)
- **Key Deliverables**:
  - Fragmentation/reassembly protocol
  - Sequence numbers and acknowledgments
  - Retransmission on loss
  - Flow control for constrained bandwidth
- **Dependencies**: Phase 3.1
- **Files**: `src/transport/ble.rs`, new `src/transport/fragmentation.rs`
- **Estimated Tasks**: 6-8 tasks

### Phase 3.3: BLE Session Caching
- **Focus**: Optimize PQC handshake overhead via session resumption
- **Key Deliverables**:
  - Session key caching (24h default)
  - Resumption token protocol
  - Cache persistence across restarts
  - Graceful fallback to full handshake
- **Dependencies**: Phase 3.2
- **Files**: `src/transport/ble.rs`
- **Estimated Tasks**: 4-6 tasks

---

## Milestone 4: Constrained Protocol Engine

Implement lightweight protocol for low-bandwidth transports (BLE, LoRa).

### Phase 4.1: Constrained Engine Design
- **Focus**: Define minimal header format and reliability mechanisms
- **Key Deliverables**:
  - Header format (4-8 bytes vs QUIC's ~20+)
  - Connection state machine
  - ARQ (Automatic Repeat Request) protocol
  - Integration point with TransportProvider
- **Dependencies**: Milestone 3
- **Files**: New `src/constrained/` module
- **Estimated Tasks**: 6-8 tasks

### Phase 4.2: Constrained Engine Implementation
- **Focus**: Implement the constrained protocol engine
- **Key Deliverables**:
  - Packet encoding/decoding
  - Reliability layer
  - Congestion control (adapted for low bandwidth)
  - Stream abstraction matching QUIC semantics
- **Dependencies**: Phase 4.1
- **Files**: `src/constrained/`
- **Estimated Tasks**: 10-12 tasks

### Phase 4.3: Protocol Engine Selection
- **Focus**: Automatic engine selection based on transport capabilities
- **Key Deliverables**:
  - ProtocolEngine::Quic vs ProtocolEngine::Constrained routing
  - Capability-based selection logic
  - Unified API for both engines
  - Performance benchmarks
- **Dependencies**: Phase 4.2
- **Files**: `src/transport/provider.rs`, `src/p2p_endpoint.rs`
- **Estimated Tasks**: 5-7 tasks

---

## Out of Scope (for now)

- LoRa transport implementation (follows same pattern as BLE)
- Serial transport implementation
- I2P/Yggdrasil overlay transports
- Cross-transport connection migration
- Multi-path simultaneous transmission

---

## File Reference

### Transport Module (existing, to wire in)
- `src/transport/mod.rs` - Module exports, default_registry()
- `src/transport/addr.rs` - TransportAddr enum, TransportType
- `src/transport/capabilities.rs` - Capability profiles
- `src/transport/provider.rs` - TransportProvider trait, TransportRegistry
- `src/transport/udp.rs` - UdpTransport (implemented, unused)
- `src/transport/ble.rs` - BleTransport (partial, feature-gated)

### Node Layer (to modify)
- `src/node.rs:263-294` - Node::with_config() ignores transport_providers
- `src/node_config.rs:70-90` - NodeConfig has transport_providers field

### P2P Layer (to modify)
- `src/p2p_endpoint.rs:344-458` - P2pEndpoint::new()
- `src/unified_config.rs:48-82` - P2pConfig (no transport_providers)

### NAT Traversal Layer (to modify)
- `src/nat_traversal_api.rs:919-1106` - NatTraversalEndpoint::new()
- `src/nat_traversal_api.rs:1534-1683` - create_inner_endpoint() hardcodes UDP
