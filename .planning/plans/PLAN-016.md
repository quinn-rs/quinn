# Phase 2.3: NAT Traversal Adverts

**Phase**: 2.3
**Name**: NAT Traversal Adverts
**Depends On**: Phase 2.2 (Event Address Migration)
**Status**: Planning

---

## Overview

Include TransportAddr + capabilities in peer advertisements. This enables remote peers to understand what transports we support and select appropriate connection methods.

Currently, ADD_ADDRESS frames only carry SocketAddr (IPv4/IPv6). We need to extend them to carry TransportAddr with a transport type indicator, plus optional capability summaries.

---

## Success Criteria

1. ADD_ADDRESS frame carries transport type indicator
2. Capability summary can be included in peer adverts
3. Remote peers become transport-aware
4. Transport selection based on advertised capabilities works
5. Backward compatibility with existing UDP-only peers
6. Zero warnings, comprehensive tests

---

## Technical Analysis

### Current State

- `AddAddress` struct in `src/nat_traversal/frames.rs` uses `SocketAddr`
- `AddAddress` in `src/frame/nat_traversal_unified.rs` also uses `SocketAddr`
- `AddAddress` in `src/nat_traversal/rfc_compliant_frames.rs` uses `SocketAddr`
- Peer advertisements only include IP:port, no transport type
- No capability exchange in NAT traversal frames

### Target State

- `AddAddress` carries `TransportAddr` (with type indicator in wire format)
- Optional capability flags (MTU, reliability, latency tier)
- Peers can filter addresses by transport type
- Selection logic picks compatible transport

### Wire Format Extension

Current ADD_ADDRESS format:
```
Sequence (VarInt)
Priority (VarInt)
AddressType (1 byte: 4=IPv4, 6=IPv6)
Address (4 or 16 bytes)
Port (2 bytes)
```

Extended format:
```
Sequence (VarInt)
Priority (VarInt)
TransportType (VarInt: 0=UDP, 1=BLE, 2=LoRa, 3=Serial, etc.)
AddressType (1 byte: depends on transport)
Address (variable: depends on transport)
Capabilities (VarInt, optional flags)
```

---

## Tasks

### Task 1: Add TransportType to AddAddress wire format
**Files**: `src/nat_traversal/frames.rs`
**Changes**:
- Add `transport_type: TransportType` field to `AddAddress` struct
- Update `encode()` to write transport type as VarInt
- Update `decode()` to read transport type (default to UDP for backward compat)
- Add tests for encode/decode with transport type

### Task 2: Update AddAddress unified frame
**Files**: `src/frame/nat_traversal_unified.rs`
**Changes**:
- Add transport type to unified AddAddress
- Ensure compatibility between frame versions
- Update address conversion logic for TransportAddr

### Task 3: Update RFC-compliant AddAddress frame
**Files**: `src/nat_traversal/rfc_compliant_frames.rs`
**Changes**:
- Add transport type field
- Maintain RFC wire format compliance (extension point)
- Document extension format

### Task 4: Add capability flags to advertisements
**Files**: `src/nat_traversal/frames.rs`, `src/transport/capabilities.rs`
**Changes**:
- Define capability flags bitfield (mtu_tier, reliability, latency)
- Add `capabilities: Option<CapabilityFlags>` to AddAddress
- Encode/decode capability flags (VarInt)
- Default to None for backward compatibility

### Task 5: Update NatTraversalEndpoint to use TransportAddr
**Files**: `src/nat_traversal_api.rs`
**Changes**:
- Update `broadcast_add_address()` to accept TransportAddr
- Convert TransportAddr to wire format in frame encoding
- Parse TransportAddr from received ADD_ADDRESS frames
- Store transport type with candidate addresses

### Task 6: Add transport-aware candidate selection
**Files**: `src/nat_traversal_api.rs`, `src/connection/nat_traversal.rs`
**Changes**:
- Filter candidates by transport type
- Prefer compatible transports when selecting candidates
- Fall back to UDP if no transport match
- Add selection logic tests

### Task 7: Update peer address storage
**Files**: `src/nat_traversal_api.rs`
**Changes**:
- Store TransportAddr (not SocketAddr) in peer address maps
- Update `known_addresses()` to return Vec<TransportAddr>
- Update address comparison logic for multi-transport

### Task 8: Add transport advert unit tests
**Files**: `src/nat_traversal/frames.rs`
**Changes**:
- Test encode/decode with all transport types
- Test capability flags encoding
- Test backward compatibility (UDP-only peers)
- Test malformed frame handling

### Task 9: Add integration tests for transport adverts
**Files**: `tests/transport_adverts.rs` (NEW)
**Changes**:
- Test advertising UDP addresses
- Test advertising BLE addresses
- Test advertising mixed transports
- Test capability exchange
- Test selection based on capabilities

### Task 10: Update documentation
**Files**: `src/nat_traversal/frames.rs`, `src/nat_traversal_api.rs`
**Changes**:
- Document extended wire format
- Document capability flags
- Add examples for multi-transport advertisements
- Update CLAUDE.md if needed

---

## Backward Compatibility

- UDP-only peers will continue to work (transport type 0 = UDP)
- Missing transport type defaults to UDP
- Missing capabilities defaults to None (standard UDP profile)
- Existing tests must continue to pass

---

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| Wire format change breaks existing peers | Use extension point, default to UDP |
| Capability negotiation adds complexity | Keep flags simple (bitfield) |
| Too many transport types | Start with UDP/BLE, extend later |

---

## Estimated Effort

- 10 tasks
- Complexity: Medium (wire format changes, but isolated to NAT traversal layer)
- Testing: ~15 new tests
