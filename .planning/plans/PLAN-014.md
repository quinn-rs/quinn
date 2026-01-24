# Phase 2.1: Config Address Migration

**Status**: In Progress
**Dependencies**: Phase 1.3 (Multi-Transport infrastructure)
**Blocks**: Phase 2.2 (Event Address Migration), Phase 2.3 (NAT Traversal Adverts)

## Overview

Migrate configuration types from raw `SocketAddr` to `TransportAddr` throughout the configuration layer. This enables multi-transport configuration while maintaining compatibility with existing UDP-only setups.

## Success Criteria

- [ ] `From<SocketAddr> for TransportAddr` conversion implemented
- [ ] P2pConfig.bind_addr uses `Option<TransportAddr>`
- [ ] P2pConfig.known_peers uses `Vec<TransportAddr>`
- [ ] NodeConfig fields migrated to TransportAddr
- [ ] Builder methods accept TransportAddr
- [ ] Backward compatibility via From trait
- [ ] Comprehensive unit and integration tests
- [ ] Zero warnings, zero clippy violations

## Tasks

### Task 1: Add TransportAddr conversion helpers
**File**: `src/transport/addr.rs`
**Estimate**: ~40 lines
**Prompt**:
```
Implement conversion helpers for TransportAddr to enable seamless migration from SocketAddr.

Implementation:
1. Add `impl From<SocketAddr> for TransportAddr`:
   ```rust
   impl From<SocketAddr> for TransportAddr {
       fn from(addr: SocketAddr) -> Self {
           TransportAddr::Udp(addr)
       }
   }
   ```

2. Add `as_socket_addr()` helper method:
   ```rust
   impl TransportAddr {
       pub fn as_socket_addr(&self) -> Option<SocketAddr> {
           match self {
               TransportAddr::Udp(addr) => Some(*addr),
               _ => None,
           }
       }
   }
   ```

3. Add Display implementation if not present
4. Document the conversion pattern in rustdoc

This enables: `TransportAddr::from(socket_addr)` and `addr.as_socket_addr()`.
```

### Task 2: Migrate P2pConfig.bind_addr field
**File**: `src/unified_config.rs`
**Estimate**: ~30 lines
**Prompt**:
```
Change P2pConfig.bind_addr from Option<SocketAddr> to Option<TransportAddr>.

Implementation:
1. Update struct field (line ~53):
   ```rust
   /// Local address to bind to. If None, ephemeral port is auto-assigned.
   pub bind_addr: Option<TransportAddr>,
   ```

2. Update Default implementation (line ~231):
   ```rust
   bind_addr: None, // Already correct
   ```

3. Update P2pConfigBuilder field (line ~292):
   ```rust
   bind_addr: Option<TransportAddr>,
   ```

4. Update any internal usage sites in this file

No breaking changes to public API yet - builder methods handle compatibility in Task 4.
```

### Task 3: Migrate P2pConfig.known_peers field
**File**: `src/unified_config.rs`
**Estimate**: ~30 lines
**Prompt**:
```
Change P2pConfig.known_peers from Vec<SocketAddr> to Vec<TransportAddr>.

Implementation:
1. Update struct field (line ~57):
   ```rust
   /// Known peers for initial discovery and NAT traversal coordination.
   pub known_peers: Vec<TransportAddr>,
   ```

2. Update Default implementation (line ~232):
   ```rust
   known_peers: Vec::new(), // Already correct
   ```

3. Update P2pConfigBuilder field (line ~293):
   ```rust
   known_peers: Vec<TransportAddr>,
   ```

4. Update to_nat_config_with_key() method to handle TransportAddr

Prepare for builder methods update in Task 4.
```

### Task 4: Update P2pConfigBuilder methods
**File**: `src/unified_config.rs`
**Estimate**: ~60 lines
**Prompt**:
```
Update all P2pConfigBuilder methods to accept TransportAddr while maintaining SocketAddr compatibility.

Implementation:
1. Update bind_addr() method (line ~328):
   ```rust
   pub fn bind_addr(mut self, addr: impl Into<TransportAddr>) -> Self {
       self.bind_addr = Some(addr.into());
       self
   }
   ```

2. Update known_peer() method (line ~335):
   ```rust
   pub fn known_peer(mut self, addr: impl Into<TransportAddr>) -> Self {
       self.known_peers.push(addr.into());
       self
   }
   ```

3. Update known_peers() method (line ~341):
   ```rust
   pub fn known_peers(mut self, addrs: impl IntoIterator<Item = impl Into<TransportAddr>>) -> Self {
       self.known_peers.extend(addrs.into_iter().map(|a| a.into()));
       self
   }
   ```

4. Update bootstrap() method (line ~348) similarly

The `impl Into<TransportAddr>` pattern allows both SocketAddr and TransportAddr arguments.
```

### Task 5: Migrate NodeConfig address fields
**File**: `src/node_config.rs`
**Estimate**: ~40 lines
**Prompt**:
```
Migrate NodeConfig.bind_addr and known_peers from SocketAddr to TransportAddr.

Implementation:
1. Add import at top:
   ```rust
   use crate::transport::TransportAddr;
   ```

2. Update struct fields (lines ~72, ~76):
   ```rust
   pub bind_addr: Option<TransportAddr>,
   pub known_peers: Vec<TransportAddr>,
   ```

3. Update NodeConfigBuilder fields (lines ~142-143):
   ```rust
   bind_addr: Option<TransportAddr>,
   known_peers: Vec<TransportAddr>,
   ```

4. Update Default implementation if needed
5. Update with_bind_addr() and with_known_peers() static constructors

Prepare for builder method updates in Task 6.
```

### Task 6: Update NodeConfig builder methods
**File**: `src/node_config.rs`
**Estimate**: ~50 lines
**Prompt**:
```
Update NodeConfig builder methods to work with TransportAddr.

Implementation:
1. Update bind_addr() method (line ~150):
   ```rust
   pub fn bind_addr(mut self, addr: impl Into<TransportAddr>) -> Self {
       self.bind_addr = Some(addr.into());
       self
   }
   ```

2. Update known_peer() method (line ~156):
   ```rust
   pub fn known_peer(mut self, addr: impl Into<TransportAddr>) -> Self {
       self.known_peers.push(addr.into());
       self
   }
   ```

3. Update known_peers() method (line ~162):
   ```rust
   pub fn known_peers(mut self, addrs: impl IntoIterator<Item = impl Into<TransportAddr>>) -> Self {
       self.known_peers.extend(addrs.into_iter().map(|a| a.into()));
       self
   }
   ```

4. Update static constructor methods (with_bind_addr, with_known_peers)

Maintains backward compatibility via Into trait.
```

### Task 7: Add conversion unit tests
**File**: `src/transport/addr.rs` (tests module)
**Estimate**: ~50 lines
**Prompt**:
```
Test TransportAddr conversion helpers from Task 1.

Tests to add:
1. `test_from_socket_addr_ipv4`:
   - Create SocketAddr from "127.0.0.1:9000"
   - Convert to TransportAddr via From trait
   - Verify it's TransportAddr::Udp variant
   - Verify as_socket_addr() roundtrips correctly

2. `test_from_socket_addr_ipv6`:
   - Create SocketAddr from "[::1]:9000"
   - Test same conversion pattern
   - Verify IPv6 preserved

3. `test_as_socket_addr_non_udp`:
   - Create TransportAddr::Ble
   - Verify as_socket_addr() returns None

4. `test_transport_addr_display`:
   - Test Display implementation for various variants

Add to existing #[cfg(test)] module in addr.rs.
```

### Task 8: Add P2pConfig unit tests
**File**: `src/unified_config.rs` (tests module)
**Estimate**: ~60 lines
**Prompt**:
```
Test P2pConfig with new TransportAddr fields.

Tests to add:
1. `test_p2p_config_with_transport_addr`:
   - Create config with TransportAddr::Udp bind address
   - Add TransportAddr::Udp known peers
   - Verify fields set correctly

2. `test_p2p_config_builder_socket_addr_compat`:
   - Use builder with SocketAddr (via Into conversion)
   - Verify it works seamlessly via From trait
   - Confirm backward compatibility

3. `test_p2p_config_mixed_transport_types`:
   - Add both UDP and BLE addresses to known_peers
   - Verify heterogeneous transport list works

4. `test_p2p_config_default_empty`:
   - Verify default config has empty known_peers
   - Verify None bind_addr

Add to existing tests module in unified_config.rs.
```

### Task 9: Add NodeConfig unit tests
**File**: `src/node_config.rs` (tests module)
**Estimate**: ~50 lines
**Prompt**:
```
Test NodeConfig with TransportAddr fields.

Tests to add:
1. `test_node_config_with_transport_addr`:
   - Create NodeConfig with TransportAddr bind and peers
   - Verify fields set correctly

2. `test_node_config_builder_backward_compat`:
   - Use builder with SocketAddr (should auto-convert)
   - Verify Into trait conversion works

3. `test_node_config_to_p2p_config_transport_addr`:
   - Create NodeConfig with TransportAddr
   - Convert to P2pConfig
   - Verify address types preserved

Update existing tests that use SocketAddr parsing to work with TransportAddr.
```

### Task 10: Integration test for backward compatibility
**File**: `tests/config_migration.rs` (new)
**Estimate**: ~70 lines
**Prompt**:
```
End-to-end integration test for config address migration.

Test scenario:
1. Create P2pConfig using old SocketAddr approach:
   ```rust
   let addr: SocketAddr = "127.0.0.1:9000".parse()?;
   let config = P2pConfig::builder()
       .bind_addr(addr)  // SocketAddr auto-converts
       .known_peer("127.0.0.1:9001".parse()?)
       .build()?;
   ```

2. Create P2pConfig using new TransportAddr approach:
   ```rust
   let config = P2pConfig::builder()
       .bind_addr(TransportAddr::Udp("127.0.0.1:9000".parse()?))
       .known_peer(TransportAddr::Ble { ... })
       .build()?;
   ```

3. Create NodeConfig with mixed transport types
4. Verify configs can be serialized/deserialized (if applicable)
5. Test that endpoints created with both config styles work identically

This validates the entire migration maintains backward compatibility.
```

## Files Modified

- `src/transport/addr.rs` - Conversion helpers, tests
- `src/unified_config.rs` - P2pConfig field migration, builder updates, tests
- `src/node_config.rs` - NodeConfig field migration, builder updates, tests
- `tests/config_migration.rs` - Integration tests (new)

## Testing Strategy

- **Unit tests**: Conversion helpers, config field access
- **Integration tests**: Backward compatibility, mixed transport types
- **Compatibility**: Existing SocketAddr code works via Into trait

## Notes

- This phase enables multi-transport configuration but doesn't change runtime behavior
- Phase 2.2 (Event migration) builds on this foundation
- Phase 2.3 (NAT adverts) requires config types to support multiple transports
- Maintains strict backward compatibility - existing SocketAddr usage still works
