# PLAN-023: Phase 4.3 - Protocol Engine Selection

## Overview

Implement automatic protocol engine selection based on transport capabilities, providing a unified API that routes connections through either QUIC (for broadband) or the Constrained engine (for BLE/LoRa).

## Phase 4.3 Tasks

### Task 1: Connection Router Types
**Focus**: Define types for unified connection routing

**Deliverables**:
- Create `src/connection_router.rs` module
- Define `RoutedConnection` enum (Quic/Constrained variants)
- Define `ConnectionRouter` struct to manage routing decisions
- Add `RouterConfig` for tuning selection behavior

**Files**: New `src/connection_router.rs`
**Tests**: Type construction, config validation

---

### Task 2: Protocol Selection Logic
**Focus**: Implement capability-based engine selection

**Deliverables**:
- `ConnectionRouter::select_engine()` method
- Use `TransportCapabilities::supports_full_quic()` for decision
- Handle fallback when preferred engine unavailable
- Add selection metrics/logging

**Files**: `src/connection_router.rs`
**Tests**: Selection for UDP/BLE/LoRa, fallback scenarios

---

### Task 3: Constrained Connection Integration
**Focus**: Connect router to constrained engine

**Deliverables**:
- `ConnectionRouter::connect_constrained()` method
- Integrate with `ConstrainedTransport` from Phase 4.2
- Handle connection lifecycle (open, send, receive, close)
- Map constrained events to unified events

**Files**: `src/connection_router.rs`, `src/constrained/transport.rs`
**Tests**: Constrained connection via router

---

### Task 4: QUIC Connection Integration
**Focus**: Connect router to existing QUIC stack

**Deliverables**:
- `ConnectionRouter::connect_quic()` method
- Integrate with `NatTraversalEndpoint` for QUIC connections
- Pass through QUIC events unchanged
- Handle QUIC-specific errors

**Files**: `src/connection_router.rs`, `src/nat_traversal_api.rs`
**Tests**: QUIC connection via router

---

### Task 5: Unified Send/Receive API
**Focus**: Single API for both engine types

**Deliverables**:
- `RoutedConnection::send()` - routes to appropriate engine
- `RoutedConnection::recv()` - unified receive
- `RoutedConnection::close()` - graceful close for both
- Stream abstraction compatibility

**Files**: `src/connection_router.rs`
**Tests**: Send/receive through both paths

---

### Task 6: P2pEndpoint Integration
**Focus**: Wire router into main P2P API

**Deliverables**:
- Add `ConnectionRouter` to `P2pEndpoint`
- Modify `P2pEndpoint::connect()` to use router
- Update event handling for routed connections
- Backward-compatible: default to QUIC if router unavailable

**Files**: `src/p2p_endpoint.rs`, `src/connection_router.rs`
**Tests**: P2pEndpoint with both engine types

---

### Task 7: Performance Benchmarks
**Focus**: Verify no regression, document characteristics

**Deliverables**:
- Benchmark QUIC path (should be identical to direct)
- Benchmark Constrained path overhead
- Document latency/throughput characteristics
- Add performance documentation

**Files**: `benches/connection_router.rs`, `docs/performance.md`
**Tests**: Benchmark tests

---

## Success Criteria

1. Connection to BLE address automatically uses Constrained engine
2. Connection to UDP address automatically uses QUIC engine
3. Unified API works identically for both engine types
4. Zero performance regression for QUIC path
5. All existing tests continue to pass
6. No clippy warnings, no compiler warnings
7. Comprehensive test coverage

## Dependencies

- Phase 4.1: Constrained Engine Design (complete)
- Phase 4.2: Constrained Transport Integration (complete)

## Files Reference

**New Files**:
- `src/connection_router.rs` - Main router module

**Modified Files**:
- `src/p2p_endpoint.rs` - Integration with router
- `src/lib.rs` - Export router module

**Related Files (read-only reference)**:
- `src/transport/provider.rs` - ProtocolEngine enum
- `src/constrained/transport.rs` - ConstrainedTransport
- `src/nat_traversal_api.rs` - NatTraversalEndpoint

---

Generated: 2026-01-24
Phase: 4.3 (Protocol Engine Selection)
Milestone: 4 (Constrained Protocol Engine)
Status: PLANNING
