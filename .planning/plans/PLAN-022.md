# PLAN-022: Phase 4.2 - Constrained Transport Integration

## Overview

Wire the constrained protocol engine (Phase 4.1) into the transport system to enable BLE and LoRa transports to use the lightweight protocol instead of QUIC.

## Goals

1. Create adapter that routes packets to appropriate engine (QUIC vs Constrained)
2. Integrate constrained engine with BLE transport
3. Create unified connection API that works with both engines
4. End-to-end integration tests

## Dependencies

- Phase 4.1: Constrained Engine Design (complete)
- Existing transport registry (`src/transport/provider.rs`)
- BLE transport (`src/transport/ble.rs`)
- Protocol engine selection (`ProtocolEngine::Quic | ProtocolEngine::Constrained`)

---

## Tasks

### Task 1: Transport Address Extension for Constrained
**Files**: `src/constrained/types.rs`, `src/constrained/mod.rs`
**Size**: ~50 lines

Add TransportAddr compatibility to constrained types:
- Add `From<SocketAddr>` and `From<TransportAddr>` for constrained addressing
- Create `ConstrainedAddr` wrapper if needed for BLE device IDs
- Update mod.rs exports

### Task 2: Engine Adapter Trait Definition
**Files**: `src/constrained/adapter.rs` (new)
**Size**: ~80 lines

Define adapter trait for engine integration:
```rust
pub trait EngineAdapter: Send + Sync {
    fn process_inbound(&mut self, source: &TransportAddr, data: &[u8]) -> Result<Vec<EngineOutput>, ConstrainedError>;
    fn generate_outbound(&mut self) -> Vec<EngineOutput>;
    fn poll_events(&mut self) -> Vec<EngineEvent>;
}
```

### Task 3: Constrained Transport Wrapper
**Files**: `src/constrained/transport.rs` (new)
**Size**: ~150 lines

Create wrapper that combines TransportProvider with ConstrainedEngine:
- `ConstrainedTransport` struct
- Spawns background task for packet processing
- Routes inbound packets through engine
- Sends engine output via transport

### Task 4: BLE Transport Constrained Integration
**Files**: `src/transport/ble.rs`
**Size**: ~100 lines

Modify BLE transport to use constrained engine:
- Add `ConstrainedEngine` field
- Route packets through engine when `protocol_engine() == Constrained`
- Handle engine events
- Add unit tests

### Task 5: Connection Unification Layer
**Files**: `src/constrained/unified.rs` (new)
**Size**: ~120 lines

Create unified connection API:
```rust
pub enum UnifiedConnection {
    Quic(quinn::Connection),
    Constrained { engine: Arc<Mutex<ConstrainedEngine>>, conn_id: ConnectionId },
}

impl UnifiedConnection {
    pub async fn send(&mut self, data: &[u8]) -> Result<(), Error>;
    pub async fn recv(&mut self) -> Result<Vec<u8>, Error>;
    pub async fn close(&mut self) -> Result<(), Error>;
}
```

### Task 6: Integration Tests
**Files**: `tests/constrained_integration.rs` (new)
**Size**: ~200 lines

End-to-end tests:
- BLE transport with constrained engine
- Connection establishment and data transfer
- Engine event handling
- Error recovery scenarios

### Task 7: Module Documentation
**Files**: `src/constrained/mod.rs`, `docs/CONSTRAINED_INTEGRATION.md` (new)
**Size**: ~80 lines

- Update module documentation
- Add integration guide
- Document configuration options

---

## Success Criteria

1. BLE transport automatically uses constrained engine
2. Data can be sent/received through BLE with constrained protocol
3. All existing tests still pass
4. New integration tests pass
5. Zero clippy warnings
6. Documentation complete

---

## Test Plan

### Unit Tests (per task)
- Task 1: Address conversion tests
- Task 2: Adapter trait tests
- Task 3: Transport wrapper tests
- Task 4: BLE integration tests
- Task 5: Unified connection tests

### Integration Tests (Task 6)
- Full round-trip data transfer
- Multiple connections
- Connection close/reset
- Error handling

---

Generated: 2026-01-24
Phase: 4.2 (Constrained Transport Integration)
Status: PLANNING
