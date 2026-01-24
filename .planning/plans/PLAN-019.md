# Phase 3.2: BLE Fragmentation Integration

**Phase**: 3.2
**Name**: BLE Fragmentation Integration
**Depends On**: Phase 3.1b (Real BLE I/O Implementation)
**Status**: In Progress

---

## Overview

BLE has a small MTU (244 bytes typical), but applications often need to send larger messages. This phase implements transparent fragmentation and reassembly to handle messages larger than the BLE MTU.

Phase 3.1b delivered real BLE I/O with characteristic writes/notifications. This phase adds the fragmentation layer on top.

---

## Success Criteria

1. Fragment header format defined (sequence, flags, total fragments)
2. `BlePacketFragmenter` splits data > MTU into sequential fragments
3. `BleReassemblyBuffer` combines fragments back to original data
4. `send()` automatically fragments large messages
5. Notification handler automatically reassembles fragments
6. Timeout handling for incomplete fragment sequences
7. Zero warnings, all existing tests pass, new fragmentation tests

---

## Technical Design

### Fragment Header Format (4 bytes)

```
+--------+--------+--------+--------+
| SeqNum | Flags  |  Total | MsgID  |
+--------+--------+--------+--------+
  1 byte   1 byte   1 byte   1 byte

SeqNum: Fragment sequence number (0-255)
Flags:  bit 0 = START (first fragment)
        bit 1 = END (last fragment)
        bit 2-7 = reserved
Total:  Total number of fragments (1-255)
MsgID:  Message identifier for correlating fragments
```

- Single-fragment messages: SeqNum=0, Flags=START|END, Total=1
- Multi-fragment: First has START, last has END, all have same MsgID
- Payload per fragment: MTU - 4 bytes header = 240 bytes

### Fragmentation Flow

```
send(1000 bytes) → BlePacketFragmenter
  ├─ Fragment 0: [Hdr: 0,START,5,42] + [240 bytes payload]
  ├─ Fragment 1: [Hdr: 1,0,5,42] + [240 bytes payload]
  ├─ Fragment 2: [Hdr: 2,0,5,42] + [240 bytes payload]
  ├─ Fragment 3: [Hdr: 3,0,5,42] + [240 bytes payload]
  └─ Fragment 4: [Hdr: 4,END,5,42] + [40 bytes payload]
```

### Reassembly Flow

```
notification(frag 0) → BleReassemblyBuffer
  ├─ START seen, create new entry for MsgID=42
notification(frag 1) → add to entry
notification(frag 2) → add to entry
notification(frag 3) → add to entry
notification(frag 4) → END seen, complete message
  └─ Return reassembled 1000 bytes
```

### Timeout Handling

- Incomplete sequences expire after 30 seconds
- Duplicate fragments are ignored
- Out-of-order delivery handled via sequence numbers

---

## Tasks

### Task 1: Define fragment header types
**Files**: `src/transport/ble.rs`
**Changes**:
- Add `FragmentHeader` struct with seq_num, flags, total, msg_id
- Add `FragmentFlags` constants (START=0x01, END=0x02)
- Add `FRAGMENT_HEADER_SIZE` constant (4 bytes)
- Add serialize/deserialize methods for header

### Task 2: Implement BlePacketFragmenter
**Files**: `src/transport/ble.rs`
**Changes**:
- Add `BlePacketFragmenter` struct
- Constructor takes MTU size
- `fragment(data: &[u8], msg_id: u8) -> Vec<Vec<u8>>` method
- Returns vector of fragments, each with header prepended
- Single fragment for data <= (MTU - header size)

### Task 3: Implement BleReassemblyBuffer
**Files**: `src/transport/ble.rs`
**Changes**:
- Add `BleReassemblyBuffer` struct with HashMap<(device_id, msg_id), Entry>
- Add `ReassemblyEntry` with fragments vec, timestamp, expected total
- `add_fragment(device_id, fragment) -> Option<Vec<u8>>` method
- Returns Some(data) when all fragments received
- `prune_stale(timeout)` method for cleanup

### Task 4: Wire fragmentation into send()
**Files**: `src/transport/ble.rs`
**Changes**:
- Add `fragmenter: BlePacketFragmenter` field to BleTransport
- Add `next_msg_id: AtomicU8` for message ID generation
- In `send()`: if data.len() > payload_mtu, use fragmenter
- Send each fragment via characteristic write
- Update statistics for fragments sent

### Task 5: Wire reassembly into receive notification path
**Files**: `src/transport/ble.rs`
**Changes**:
- Add `reassembly: RwLock<BleReassemblyBuffer>` to BleTransport
- In `process_notification()`: call reassembly.add_fragment()
- Only push to inbound channel when complete message received
- Spawn periodic task to prune stale incomplete sequences

### Task 6: Add fragmentation tests
**Files**: `src/transport/ble.rs`
**Changes**:
- Test fragment header serialization/deserialization
- Test fragmenter with various payload sizes
- Test reassembly with in-order fragments
- Test reassembly with out-of-order fragments
- Test timeout/expiry of incomplete sequences
- Test duplicate fragment handling

---

## Edge Cases

- Zero-length payload: Single fragment with START|END, no payload
- Exact MTU fit: Single fragment with full payload
- Fragment loss: Timeout and discard incomplete sequence
- Message ID wrap: 256 messages, then wrap to 0
- Concurrent messages: Different msg_ids distinguish them

---

## Files to Modify

- `src/transport/ble.rs` - All changes in this file

---
