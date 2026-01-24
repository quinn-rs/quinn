# Phase 4.1: Constrained Engine Design

**Phase**: 4.1
**Name**: Constrained Engine Design
**Depends On**: Phase 3.3 (BLE Session Caching)
**Status**: Executing

---

## Overview

Design and implement the constrained protocol engine for low-bandwidth transports like BLE and LoRa. Unlike full QUIC (~20+ byte headers), the constrained engine uses minimal 4-8 byte headers optimized for limited MTU and bandwidth.

Key design goals:
- Minimal header overhead (4-8 bytes vs QUIC's 20+)
- Simple ARQ (Automatic Repeat Request) reliability
- No congestion control (link layer handles it)
- Session resumption integration with BLE session cache
- Compatible with TransportProvider abstraction

---

## Success Criteria

1. `src/constrained/` module created with proper structure
2. Header format defined (4-8 bytes, sequence numbers, flags)
3. Connection state machine implemented
4. ARQ protocol for reliable delivery
5. Error types with proper handling
6. Integration point with TransportProvider trait
7. Zero warnings, comprehensive tests

---

## Tasks

### Task 1: Create module structure and types
**Files**: `src/constrained/mod.rs`, `src/constrained/types.rs`
**Changes**:
- Create `src/constrained/` directory
- Define module exports in `mod.rs`
- Define `ConstrainedError` error type
- Define `ConnectionId` (2 bytes), `SequenceNumber` (1 byte)
- Define `PacketType` enum (Data, Ack, Reset, Ping)
- Add module to `src/lib.rs` exports

### Task 2: Define packet header format
**Files**: `src/constrained/header.rs`
**Changes**:
- Define `ConstrainedHeader` struct (4-8 bytes):
  - Connection ID: 2 bytes
  - Sequence number: 1 byte (0-255, wrapping)
  - Ack number: 1 byte
  - Flags: 1 byte (SYN, ACK, FIN, RST, DATA)
  - Optional: 2-3 bytes for extensions
- Implement `to_bytes()` and `from_bytes()`
- Add tests for serialization/deserialization

### Task 3: Define connection state machine
**Files**: `src/constrained/state.rs`
**Changes**:
- Define `ConnectionState` enum:
  - Closed, SynSent, SynReceived, Established, FinWait, Closing, TimeWait
- Define `StateTransition` for valid transitions
- Implement state transition logic with validation
- Add timeout handling for each state
- Add tests for state machine

### Task 4: Implement ARQ reliability layer
**Files**: `src/constrained/arq.rs`
**Changes**:
- Define `ArqWindow` for tracking sent/acked packets
- Implement sliding window (8-16 packets)
- Track retransmission timeouts (RTO)
- Implement cumulative acknowledgments
- Add `RetransmitQueue` for pending retries
- Add tests for ARQ logic

### Task 5: Define constrained connection struct
**Files**: `src/constrained/connection.rs`
**Changes**:
- Define `ConstrainedConnection` struct combining:
  - Connection ID
  - State machine
  - ARQ layer
  - Send/receive queues
  - Statistics
- Implement `send()`, `receive()`, `ack()` methods
- Implement connection lifecycle (open, close, reset)
- Add tests for connection operations

### Task 6: Integration with TransportProvider
**Files**: `src/constrained/engine.rs`
**Changes**:
- Define `ConstrainedEngine` struct
- Accept `TransportProvider` for actual I/O
- Route packets through constrained protocol
- Manage multiple connections per engine
- Define `ConstrainedConfig` for tuning
- Add module-level documentation

### Task 7: Add comprehensive tests
**Files**: `src/constrained/mod.rs` (test module)
**Changes**:
- Unit tests for each component
- Integration tests for full send/receive cycle
- Property-based tests for ARQ reliability
- State machine transition tests
- Serialization roundtrip tests

---

## Technical Design

### Header Format (4 bytes minimum)

```
 0       1       2       3       4       5
+-------+-------+-------+-------+-------+...
|  CID (16b)    | SEQ   | ACK   | FLAGS |
+-------+-------+-------+-------+-------+...
```

- CID: Connection ID (2 bytes, identifies connection)
- SEQ: Sequence number (1 byte, 0-255 wrapping)
- ACK: Acknowledgment number (1 byte)
- FLAGS: Packet flags (1 byte)
  - Bit 0: SYN (connection request)
  - Bit 1: ACK (acknowledgment)
  - Bit 2: FIN (connection close)
  - Bit 3: RST (reset)
  - Bit 4: DATA (payload present)
  - Bit 5-7: Reserved

### State Machine

```
           SYN_SENT
              ↓
CLOSED → SYN_RCVD → ESTABLISHED → FIN_WAIT → CLOSING → TIME_WAIT → CLOSED
              ↑                      ↓
              └─────── RST ─────────┘
```

### ARQ Window

- Window size: 8 packets (configurable)
- RTO: Based on measured RTT (default 2s for BLE)
- Max retransmits: 5 before connection failure
- Cumulative ACKs for efficiency

---

## Files to Create

- `src/constrained/mod.rs` - Module exports
- `src/constrained/types.rs` - Core types
- `src/constrained/header.rs` - Packet header
- `src/constrained/state.rs` - State machine
- `src/constrained/arq.rs` - ARQ reliability
- `src/constrained/connection.rs` - Connection struct
- `src/constrained/engine.rs` - Engine integration

---
