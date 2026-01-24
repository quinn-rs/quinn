# PLAN-024: Phase 5.1 - Multi-Transport Data Path Remediation

## Overview

Critical fixes for the multi-transport data path. Despite Milestones 1-4 being marked complete, three fundamental gaps prevent actual multi-transport operation:

1. **Send path ignores transport providers** - All data flows through QUIC/UDP
2. **Inbound datagrams are dropped** - Non-UDP transports log and discard data
3. **Socket sharing is broken** - Arc::try_unwrap fails, creates redundant sockets

## Issue Analysis

### Issue 1: P2pEndpoint::send Doesn't Use Transport Providers

**Location**: `src/p2p_endpoint.rs:1570-1639`

**Problem**: The `send()` method has a TODO comment explaining transport selection but unconditionally uses the QUIC connection. BLE/LoRa providers are never called.

**Fix**:
- Query peer's transport address from connection metadata
- Use ConnectionRouter to select appropriate engine
- Route constrained-engine traffic through TransportProvider::send()
- Keep QUIC path for UDP connections

### Issue 2: Inbound Datagrams Are Discarded

**Location**: `src/nat_traversal_api.rs:1190-1232`

**Problem**: Transport listener tasks receive datagrams but only log them at line 1211-1217, then drop. The TODO at line 1219 says "Route to QUIC endpoint for processing" but no code exists.

**Fix**:
- For constrained transports (BLE/LoRa): Route to ConstrainedEngine for processing
- Decode frames and emit events to P2pEndpoint
- Handle connection establishment over constrained transports
- Maintain connection state for non-UDP peers

### Issue 3: Socket Sharing Broken Due to Arc::try_unwrap

**Location**: `src/nat_traversal_api.rs:1897-1937`

**Problem**: `Arc::try_unwrap(udp_socket)` always fails because the provider retains its Arc. Fallback creates a brand new socket, defeating socket sharing.

**Fix**:
- Use `tokio::net::UdpSocket::try_clone()` instead of try_unwrap
- Or use Quinn's socket sharing via `quinn::Endpoint::rebind()`
- Or expose the underlying std socket directly from provider

---

## Tasks

### Task 1: Fix Socket Sharing (Foundation)
**Focus**: Make UDP socket sharing actually work
**Files**: `src/nat_traversal_api.rs`, `src/transport/udp.rs`
**Deliverables**:
- Add `take_socket()` or `clone_socket()` to UdpTransport
- Update `create_inner_endpoint()` to properly share socket
- Remove Arc::try_unwrap approach
- Verify single socket used by both provider and QUIC endpoint
**Tests**: Socket sharing validation

---

### Task 2: Implement Constrained Inbound Routing
**Focus**: Route non-UDP inbound data to constrained engine
**Files**: `src/nat_traversal_api.rs`, `src/constrained/engine.rs`
**Deliverables**:
- In transport listener task, route datagrams to ConstrainedEngine
- Parse constrained frames and handle connection state
- Emit events for established connections
- Forward application data to P2pEndpoint
**Tests**: BLE inbound data routing

---

### Task 3: Implement Transport-Aware Send Path
**Focus**: P2pEndpoint::send dispatches via correct provider
**Files**: `src/p2p_endpoint.rs`, `src/connection_router.rs`
**Deliverables**:
- Store peer's transport address in connection metadata
- Use ConnectionRouter to select engine based on peer address
- For Constrained engine: call TransportProvider::send()
- For QUIC engine: use existing connection.open_uni() path
**Tests**: Send to BLE peer uses BLE provider

---

### Task 4: Connection State for Constrained Peers
**Focus**: Track constrained connections in P2pEndpoint
**Files**: `src/p2p_endpoint.rs`, `src/constrained/transport.rs`
**Deliverables**:
- Add PeerConnection variant for constrained peers
- Track constrained connection state (connecting, established, closed)
- Handle constrained peer disconnection
- Emit P2pEvent::PeerConnected for constrained peers
**Tests**: Constrained peer connection lifecycle

---

### Task 5: Integration Test - BLE End-to-End
**Focus**: Verify complete BLE data path works
**Files**: `tests/ble_integration.rs` or inline tests
**Deliverables**:
- Test: BLE inbound datagram reaches application
- Test: send() to BLE peer uses BLE provider
- Test: Constrained connection lifecycle
- Test: Mixed UDP/BLE peer handling
**Tests**: Full integration coverage

---

## Success Criteria

1. **Send path works**: `P2pEndpoint::send()` to BLE peer uses BLE transport
2. **Receive path works**: Inbound BLE data reaches application layer
3. **Socket sharing works**: Single UDP socket for registry and QUIC endpoint
4. **Mixed transports work**: Can have UDP and BLE peers simultaneously
5. **No regressions**: Existing UDP/QUIC functionality unchanged

## Dependencies

- Phase 4.3 ConnectionRouter (complete)
- Phase 4.2 ConstrainedEngine (complete)
- Phase 3.1 BLE GATT (complete)

---

Generated: 2026-01-24
Phase: 5.1 (Multi-Transport Data Path Remediation)
Milestone: 5 (Data Path Completion)
Status: PLANNING
