# PLAN-025: Phase 5.2 Multi-Transport Data Path Completion

## Overview

External review identified that despite Phase 5.1 infrastructure, no real payload can traverse non-UDP transports yet. This plan addresses the remaining gaps to complete the multi-transport data path.

## Problem Statement

1. **Inbound constrained traffic dead-ends**: ConstrainedEngine events are logged but never delivered to P2pEndpoint
2. **Quinn socket sharing not wired**: `new_with_socket()` exists but `NatTraversalEndpoint::new()` doesn't use it
3. **No integration point**: Higher layers (Communitas/saorsa-gossip) can't receive BLE/LoRa messages

## Scope

- Fix event forwarding from ConstrainedEngine to P2pEndpoint
- Wire socket sharing so Quinn uses registry socket
- Add P2pEvent::ConstrainedDataReceived variant
- Minimal changes - no BLE expansion

## Tasks

### Task 1: Event Channel for Constrained Traffic
**Deliverables:**
- Add `constrained_event_tx/rx` channel to `NatTraversalEndpoint`
- Forward `EngineEvent::DataReceived` from transport listener to channel
- Add getter `constrained_events()` returning the receiver

**Files:**
- `src/nat_traversal_api.rs`

### Task 2: P2pEndpoint Constrained Event Integration
**Deliverables:**
- Add `P2pEvent::ConstrainedDataReceived { peer_addr, data }` variant
- Poll constrained events in `P2pEndpoint::recv()`
- Map ConstrainedEngine peer to synthetic PeerId if needed

**Files:**
- `src/p2p_endpoint.rs`

### Task 3: Wire Socket Sharing in Default Constructor
**Deliverables:**
- Modify `NatTraversalEndpoint::new()` to:
  1. If registry has UDP provider with socket, extract it
  2. Call `create_inner_endpoint` with that socket
- Ensure Quinn and registry share the same socket

**Files:**
- `src/nat_traversal_api.rs`

### Task 4: Integration Test - Constrained Receive Path
**Deliverables:**
- Test that simulates BLE inbound → ConstrainedEngine → P2pEndpoint.recv()
- Verify data arrives as `P2pEvent::ConstrainedDataReceived`

**Files:**
- `tests/constrained_integration.rs`

## Success Criteria

1. BLE/LoRa datagrams received by ConstrainedEngine appear in `P2pEndpoint::recv()`
2. Quinn endpoint uses the same socket as UDP transport provider
3. All existing tests pass
4. No new warnings

## Non-Goals

- BLE module expansion (defer until core works)
- LoRa module work
- Performance optimization
