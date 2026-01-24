# Phase 2.2: Event Address Migration

**Status**: Planning
**Dependencies**: Phase 2.1 (Config Address Migration)
**Blocks**: Phase 2.3 (NAT Traversal Adverts)

## Overview

Migrate P2pEvent and connection event types from `SocketAddr` to `TransportAddr`. This enables the event system to communicate about multi-transport connections (UDP, BLE, LoRa, etc.) while maintaining backward compatibility.

## Success Criteria

- [ ] P2pEvent::PeerConnected uses TransportAddr
- [ ] P2pEvent::ExternalAddressDiscovered uses TransportAddr
- [ ] Connection tracking uses TransportAddr internally
- [ ] Event handlers receive transport type information
- [ ] Backward compatibility maintained
- [ ] Zero warnings, zero clippy violations
- [ ] Comprehensive unit and integration tests

## Tasks

### Task 1: Migrate P2pEvent::PeerConnected
**File**: `src/p2p_endpoint.rs`
**Estimate**: ~20 lines
**Prompt**:
```
Update P2pEvent::PeerConnected to use TransportAddr instead of SocketAddr.

Implementation:
1. Update the enum variant (line ~236):
   ```rust
   PeerConnected {
       /// Peer's ID
       peer_id: PeerId,
       /// Remote address (supports all transport types)
       addr: TransportAddr,
       /// Who initiated the connection
       side: Side,
   },
   ```

2. Add import at top of file:
   ```rust
   use crate::transport::TransportAddr;
   ```

3. Update all sites that construct PeerConnected events
4. Find usages: grep for "P2pEvent::PeerConnected" in src/
```

### Task 2: Migrate P2pEvent::ExternalAddressDiscovered
**File**: `src/p2p_endpoint.rs`
**Estimate**: ~15 lines
**Prompt**:
```
Update P2pEvent::ExternalAddressDiscovered to use TransportAddr.

Implementation:
1. Update the enum variant (line ~260):
   ```rust
   ExternalAddressDiscovered {
       /// Discovered external address (can be any transport)
       addr: TransportAddr,
   },
   ```

2. Update all sites that construct ExternalAddressDiscovered events
3. Find usages: grep for "ExternalAddressDiscovered" in src/
```

### Task 3: Update P2pEndpoint connection tracking
**File**: `src/p2p_endpoint.rs`
**Estimate**: ~40 lines
**Prompt**:
```
Update internal connection tracking to use TransportAddr.

Implementation:
1. Find all HashMap<SocketAddr, ...> or similar connection tracking structures
2. Change key types from SocketAddr to TransportAddr
3. Update connection establishment code to track TransportAddr
4. Update connection lookup logic

Key areas to check:
- Connection state tracking (if any)
- Peer address caching
- Event emission points

Ensure proper Hash/Eq implementations on TransportAddr support this usage.
```

### Task 4: Update NatTraversalEndpoint event emission
**File**: `src/nat_traversal_api.rs`
**Estimate**: ~30 lines
**Prompt**:
```
Update NAT traversal endpoint to emit events with TransportAddr.

Implementation:
1. Find where P2pEvent::PeerConnected is constructed
2. Update to use TransportAddr from connection info
3. Find where ExternalAddressDiscovered is constructed
4. Convert discovered SocketAddr to TransportAddr::Udp

For now, UDP-only NAT traversal means:
- Discovered addresses are TransportAddr::Udp(socket_addr)
- Peer connections are TransportAddr::Udp(remote_addr)

Future phases will add multi-transport NAT traversal.
```

### Task 5: Update event handler examples
**File**: `examples/` (multiple files if needed)
**Estimate**: ~30 lines
**Prompt**:
```
Update example code to work with TransportAddr events.

Implementation:
1. Find examples that match on P2pEvent
2. Update pattern matches to extract TransportAddr
3. Add helper to get SocketAddr for display:
   ```rust
   match event {
       P2pEvent::PeerConnected { peer_id, addr, side } => {
           let display_addr = addr.as_socket_addr()
               .map(|a| a.to_string())
               .unwrap_or_else(|| addr.to_string());
           println!("Connected to {peer_id} at {display_addr}");
       }
   }
   ```

4. Update any examples that construct configs with addresses
```

### Task 6: Update binary event handling
**File**: `src/bin/ant-quic.rs`
**Estimate**: ~25 lines
**Prompt**:
```
Update main binary to handle TransportAddr in events.

Implementation:
1. Find event handler match arms
2. Update to destructure TransportAddr
3. Add display logic for different transport types:
   ```rust
   match addr {
       TransportAddr::Udp(sa) => format!("UDP {sa}"),
       TransportAddr::Ble(mac, _) => format!("BLE {mac:?}"),
       _ => addr.to_string(),
   }
   ```

4. Update any logging that shows peer addresses
```

### Task 7: Add event migration unit tests
**File**: `src/p2p_endpoint.rs` (tests module)
**Estimate**: ~50 lines
**Prompt**:
```
Test P2pEvent with TransportAddr fields.

Tests to add:
1. `test_peer_connected_event_with_udp`:
   - Create PeerConnected event with TransportAddr::Udp
   - Verify fields
   - Verify as_socket_addr() works

2. `test_peer_connected_event_with_ble`:
   - Create PeerConnected with TransportAddr::Ble
   - Verify as_socket_addr() returns None
   - Verify event carries BLE MAC address

3. `test_external_address_discovered_udp`:
   - Create ExternalAddressDiscovered with UDP
   - Verify address preserved

4. `test_event_clone`:
   - Verify events are Clone as required
```

### Task 8: Add connection tracking tests
**File**: `src/p2p_endpoint.rs` (tests module)
**Estimate**: ~40 lines
**Prompt**:
```
Test connection tracking with TransportAddr.

Tests to add:
1. `test_connection_tracking_udp`:
   - Simulate UDP connection
   - Verify tracking uses TransportAddr::Udp
   - Lookup connection by address

2. `test_connection_tracking_multi_transport`:
   - Simulate connections on different transports
   - Verify each tracked independently
   - Same peer on different transports = different connections

3. `test_connection_lookup_by_transport_addr`:
   - Add multiple connections
   - Lookup by TransportAddr
   - Verify correct connection returned
```

### Task 9: Integration test for event migration
**File**: `tests/event_migration.rs` (new)
**Estimate**: ~60 lines
**Prompt**:
```
End-to-end test for event address migration.

Test scenario:
1. Create P2pEndpoint with UDP config
2. Simulate connection event
3. Verify PeerConnected event has TransportAddr::Udp
4. Extract SocketAddr via as_socket_addr()
5. Verify backward compatibility

Test multi-transport (when available):
1. Configure endpoint with multiple transports
2. Simulate BLE connection
3. Verify PeerConnected event has TransportAddr::Ble
4. Verify event handler can distinguish transport types

Validates entire event pipeline with new address types.
```

### Task 10: Update documentation
**File**: `src/p2p_endpoint.rs`
**Estimate**: ~30 lines
**Prompt**:
```
Update P2pEvent rustdoc with TransportAddr examples.

Implementation:
1. Update module-level documentation:
   - Explain events carry TransportAddr
   - Show example of handling different transport types

2. Update P2pEvent doc comments:
   ```rust
   /// P2P event for connection and network state changes
   ///
   /// Events use [`TransportAddr`] to support multi-transport connectivity.
   /// Use `addr.as_socket_addr()` for backward compatibility with UDP-only code.
   ///
   /// # Examples
   ///
   /// ```rust,ignore
   /// match event {
   ///     P2pEvent::PeerConnected { peer_id, addr, side } => {
   ///         match addr {
   ///             TransportAddr::Udp(socket_addr) => { /* UDP connection */ },
   ///             TransportAddr::Ble(mac, _) => { /* BLE connection */ },
   ///             _ => { /* Other transport */ }
   ///         }
   ///     }
   /// }
   /// ```
   ```

3. Update PeerConnected and ExternalAddressDiscovered field docs
```

## Files Modified

- `src/p2p_endpoint.rs` - P2pEvent enum, connection tracking, tests, docs
- `src/nat_traversal_api.rs` - Event emission with TransportAddr
- `src/bin/ant-quic.rs` - Binary event handling
- `examples/*.rs` - Example event handlers
- `tests/event_migration.rs` - Integration tests (new)

## Testing Strategy

- **Unit tests**: Event construction, connection tracking
- **Integration tests**: End-to-end event flow with TransportAddr
- **Compatibility**: Existing UDP event handlers work via as_socket_addr()

## Notes

- This phase enables multi-transport event handling
- Current runtime still UDP-only (multi-transport runtime in later phases)
- Event consumers can distinguish transport types
- Phase 2.3 will add multi-transport NAT traversal advertisements
- Maintains backward compatibility through TransportAddr::as_socket_addr()
