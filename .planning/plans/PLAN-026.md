# PLAN-026: Phase 5.3 Transport-Agnostic Endpoint (Critical)

## Overview

Critical-blocking task: Complete the multi-transport plumbing so higher layers (saorsa-gossip/Communitas) see a single, transport-agnostic endpoint.

## Three Deliverables

### Deliverable 1: Real Provider Selection in P2pEndpoint::send

**Problem**: The constrained branch in `send()` doesn't properly look up providers or manage connections.

**Requirements**:
- Store TransportAddr (not just SocketAddr) in `connected_peers` for BLE/LoRa peers
- Constrained send must:
  1. Look up TransportProvider from registry using peer's advertised address
  2. Reuse or establish constrained connection via `constrained_connections`
  3. For connectionless sends, call provider's `send()` directly
- Map constrained ConnectionId ↔ PeerId for round-trip send(peer_id, ...)

**Files**: `src/p2p_endpoint.rs`

### Deliverable 2: Unified Receive Path

**Problem**: `ConstrainedDataReceived` requires consumers to special-case constrained transports.

**Requirements**:
- Route constrained events into same pending buffer / `P2pEvent::DataReceived` path as QUIC
- When `EngineEvent::ConnectionAccepted/Established` fires, register peer (PeerId + TransportAddr)
- Higher layers receive `DataReceived` regardless of transport

**Files**: `src/p2p_endpoint.rs`, `src/node.rs`

### Deliverable 3: Socket Sharing in Default Constructors

**Problem**: `P2pEndpoint::new()` calls `NatTraversalEndpoint::new()` (not `new_with_shared_socket()`), creating separate sockets.

**Requirements**:
- `P2pEndpoint::new()` must:
  1. Bind single UDP socket via `UdpTransport::bind_for_quinn()`
  2. Register it in transport registry
  3. Pass same socket to `NatTraversalEndpoint::new_with_socket()`
- Only fall back to synthetic socket if no UDP provider registered

**Files**: `src/p2p_endpoint.rs`, `src/node.rs`

## Tasks

### Task 1: Wire Socket Sharing in P2pEndpoint::new()
- Modify `P2pEndpoint::new()` to use `new_with_shared_socket` pattern
- Create UDP transport via `bind_for_quinn()`
- Add to registry and pass socket to NAT endpoint

### Task 2: Register Constrained Peers on Connection Events
- Add `constrained_peer_addrs: HashMap<ConnectionId, (PeerId, TransportAddr)>`
- On `ConnectionAccepted/Established`, register the peer
- Provide lookup methods both ways: ConnectionId → PeerId and PeerId → ConnectionId

### Task 3: Unify Receive Path - DataReceived for All Transports
- Process `ConstrainedDataReceived` through same path as QUIC DataReceived
- Add received data to pending buffer with derived/registered PeerId
- Remove special-case handling in `Node::convert_event()`

### Task 4: Real Provider Selection in send()
- Look up provider via `transport_registry.provider_for_addr()`
- For constrained: check `constrained_connections`, create if needed
- Forward through constrained engine with proper connection management

### Task 5: Integration Tests
- Test BLE send/recv using same code paths as UDP
- Test socket sharing (no duplicate binds)
- Test peer registration from constrained connections

## Success Criteria

1. `Node::new()` / `P2pEndpoint::new()` create single shared UDP socket
2. `send(peer_id, ...)` works for BLE/LoRa peers transparently
3. `recv()` returns `DataReceived` for all transport types
4. No `ConstrainedDataReceived` special-casing in higher layers
5. All existing tests pass
