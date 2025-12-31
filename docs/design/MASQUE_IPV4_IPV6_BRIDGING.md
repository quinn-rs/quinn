# Design: MASQUE IPv4↔IPv6 Bridging

**Status**: Design Locked (2024-12-31)
**Epic**: MASQUE Relay IPv4/IPv6 Translation & Validation

## Overview

Enable automatic IPv4↔IPv6 bridging through MASQUE relay, unified NAT coordinator, and comprehensive validation of all relay features.

## Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| R1 | Automatic IP version bridging - relay detects mismatch and bridges | P0 |
| R2 | Dual-stack capability advertisement via gossip | P0 |
| R3 | Unified NAT coordinator using MASQUE tunnel | P0 |
| R4 | All four IP scenarios tested (IPv4→4, IPv4→6, IPv6→4, IPv6→6) | P0 |
| R5 | Peer cache full validation (persistence, selection, capabilities) | P1 |
| R6 | All features default-on in configuration | P0 |
| R7 | 100% connectivity success metric | P0 |
| R8 | Relay chaining allowed when no direct dual-stack relay available | P1 |
| R9 | Best path wins for parallel connections | P1 |
| R10 | Quick 30-second CI load tests | P2 |

## Architecture

### IP Version Detection Flow

```
Client (IPv4-only) → Relay (Dual-stack) → Target (IPv6-only)
        │                    │                    │
        └── CONNECT-UDP ─────┤                    │
            target=IPv6      │                    │
                             └── Forward ─────────┘
                                (IPv6 socket)
```

### Dual-Stack Capability Advertisement

```rust
// In PeerCapabilities
pub struct PeerCapabilities {
    pub supports_relay: bool,
    pub supports_coordination: bool,
    pub supports_dual_stack: bool,  // NEW: Can bridge IPv4↔IPv6
    pub available_addresses: Vec<SocketAddr>,  // IPv4 and/or IPv6
    // ...
}
```

### MASQUE Relay Bridging Logic

```rust
// In relay_server.rs - handle_connect_request()
impl MasqueRelayServer {
    async fn can_bridge(&self, client: SocketAddr, target: SocketAddr) -> bool {
        let client_v4 = client.is_ipv4();
        let target_v4 = target.is_ipv4();

        // Same version - no bridging needed
        if client_v4 == target_v4 {
            return true;
        }

        // Different versions - check if we have both
        self.has_ipv4_socket() && self.has_ipv6_socket()
    }

    async fn forward_with_bridge(&self, datagram: Datagram) -> RelayResult<()> {
        // Route through appropriate socket based on target IP version
        match datagram.target.is_ipv4() {
            true => self.ipv4_socket.send_to(&datagram.payload, datagram.target).await?,
            false => self.ipv6_socket.send_to(&datagram.payload, datagram.target).await?,
        }
        Ok(())
    }
}
```

### NAT Coordinator Unification

```rust
// NAT coordinator uses MASQUE relay when direct path fails
impl NatTraversalEndpoint {
    async fn coordinate_connection(&self, target: PeerId) -> Result<Connection> {
        // 1. Try direct connection
        if let Ok(conn) = self.try_direct(target).await {
            return Ok(conn);
        }

        // 2. Try NAT hole-punch via any connected peer
        if let Ok(conn) = self.try_hole_punch(target).await {
            return Ok(conn);
        }

        // 3. Fall back to MASQUE relay (unified path)
        self.relay_manager.connect_via_relay(target).await
    }
}
```

## Implementation Tasks

### Phase 1: Core Bridging (Proof: Unit Tests)

1. **Add dual-stack capability to PeerCapabilities**
   - File: `src/bootstrap_cache/entry.rs`
   - Add `supports_dual_stack: bool` field
   - Add `available_ip_versions()` method

2. **Implement IP version detection in MASQUE relay**
   - File: `src/masque/relay_server.rs`
   - Add `can_bridge()` method
   - Add dual-socket support (IPv4 + IPv6)

3. **Auto-detect and bridge in datagram forwarding**
   - File: `src/masque/relay_session.rs`
   - Route datagrams through appropriate socket

### Phase 2: Capability Advertisement (Proof: Integration Tests)

4. **Add dual-stack to gossip messages**
   - File: `src/chat.rs` (GossipMessage)
   - Include `supports_dual_stack` in peer info

5. **Update peer cache to track dual-stack**
   - File: `src/bootstrap_cache/cache.rs`
   - Prefer dual-stack peers for cross-version targets

### Phase 3: NAT Coordinator Unification (Proof: E2E Tests)

6. **Unify coordinator with MASQUE relay**
   - File: `src/nat_traversal_api.rs`
   - Add unified fallback path
   - Remove duplicate relay logic

### Phase 4: Comprehensive Tests (Proof: All Scenarios Pass)

7. **IPv4→IPv4 relay test**
8. **IPv4→IPv6 bridging test**
9. **IPv6→IPv4 bridging test**
10. **IPv6→IPv6 relay test**
11. **Relay failure recovery test**
12. **Rate limiting test**
13. **Authentication failure test**
14. **Timeout handling test**

### Phase 5: Validation (Proof: CI Green)

15. **Verify default configuration**
16. **Validate peer cache persistence**
17. **Validate epsilon-greedy selection**
18. **Validate capability tracking**

## Test Matrix

| Test | Source IP | Relay | Target IP | Expected |
|------|-----------|-------|-----------|----------|
| same_v4 | 127.0.0.1:A | Dual | 127.0.0.1:B | Pass |
| bridge_4to6 | 127.0.0.1:A | Dual | [::1]:B | Pass (bridged) |
| bridge_6to4 | [::1]:A | Dual | 127.0.0.1:B | Pass (bridged) |
| same_v6 | [::1]:A | Dual | [::1]:B | Pass |
| no_relay | 127.0.0.1:A | None | [::1]:B | Fail (clear error) |
| relay_chain | IPv4 | IPv4→Dual | IPv6 | Pass (chained) |

## Success Metrics

- **Primary**: 100% node connectivity in any environment
- **Secondary**: Relay latency < 2x direct connection
- **Tertiary**: All 580+ existing tests continue to pass

## Files to Modify

| File | Changes |
|------|---------|
| `src/bootstrap_cache/entry.rs` | Add `supports_dual_stack` |
| `src/masque/relay_server.rs` | Add bridging logic |
| `src/masque/relay_session.rs` | Route by IP version |
| `src/nat_traversal_api.rs` | Unify coordinator |
| `src/chat.rs` | Gossip dual-stack capability |
| `src/unified_config.rs` | Verify defaults |
| `tests/ipv4_ipv6_bridging_tests.rs` | NEW: Comprehensive tests |

## Edge Cases

1. **No dual-stack relay**: Allow relay chaining (IPv4→relay1→relay2→IPv6)
2. **Parallel paths**: Best latency wins, close slower path
3. **Timeouts**: Same 10s timeout for relay and direct
4. **Relay failure mid-session**: Attempt migration to new relay

## Rollback Plan

All changes are additive. If issues arise:
1. Disable `supports_dual_stack` gossip flag
2. Revert to existing relay behavior
3. No breaking changes to existing functionality
