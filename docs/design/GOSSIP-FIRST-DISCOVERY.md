# Epic: Gossip-First Peer Discovery with Coordinated NAT Traversal

**Status**: Design Locked
**Target**: 99%+ connectivity rate
**Scope**: ant-quic-test-network (minimal ant-quic changes)

---

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Cache Gossip | Hybrid (full sync + deltas) | Balance consistency vs bandwidth |
| Direct Retry | 2-5s before escalation | Allow transient failures to resolve |
| Intermediary | Prefer NAT=None, any fallback | Public nodes most reliable coordinators |
| Relay TTL | 30 seconds | Quick failure detection |
| Public Node ID | NAT type field | Already in BootstrapCache |
| Cache Metrics | Full (RTT, success, last seen) | Better peer prioritization |
| Total Isolation | Exponential backoff | Eventually reconnect |
| Relay Failover | Auto-find new relay | Seamless recovery |
| Persistence | On significant change | Minimize data loss |

---

## Architecture

### Connection Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                     GOSSIP-FIRST CONNECTION FLOW                     │
└─────────────────────────────────────────────────────────────────────┘

1. BOOTSTRAP PHASE
   ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
   │ Load Cache   │────▶│ Cache Empty? │────▶│ Use Hardcoded│
   │ from Disk    │     │              │ YES │ Bootstrap    │
   └──────────────┘     └──────────────┘     └──────────────┘
                              │ NO
                              ▼
                        ┌──────────────┐
                        │ Try Cached   │
                        │ Peers First  │
                        └──────────────┘

2. DIRECT CONNECTION ATTEMPT
   ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
   │ Select Peer  │────▶│ Try Direct   │────▶│ Connected!   │
   │ from Cache   │     │ Connection   │ OK  │ Gossip Cache │
   └──────────────┘     └──────────────┘     └──────────────┘
                              │ FAIL (2-5s)
                              ▼
3. INTERMEDIARY COORDINATION
   ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
   │ Query Gossip │────▶│ Send PUNCH_  │────▶│ Connected!   │
   │ "Who has X?" │     │ ME_NOW via   │ OK  │ Gossip Cache │
   └──────────────┘     │ Intermediary │     └──────────────┘
                        └──────────────┘
                              │ FAIL (30s)
                              ▼
4. RELAY FALLBACK
   ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
   │ Find Relay   │────▶│ Relay Data   │────▶│ Connected    │
   │ Node         │     │ via Relay    │ OK  │ (relayed)    │
   └──────────────┘     └──────────────┘     └──────────────┘
                              │ FAIL
                              ▼
                        ┌──────────────┐
                        │ Mark Peer    │
                        │ Unreachable  │
                        └──────────────┘
```

### Component Changes

```
ant-quic-test-network/
├── src/
│   ├── node/
│   │   └── client.rs          # MAJOR: Replace registry-first with gossip-first
│   ├── gossip.rs              # MAJOR: Add cache gossip, intermediary coordination
│   ├── discovery.rs           # NEW: Gossip-first peer discovery module
│   ├── coordination.rs        # NEW: Intermediary PUNCH_ME_NOW coordination
│   └── registry/
│       └── store.rs           # MINOR: Change to reporting-only (remove discovery)

ant-quic/
├── src/
│   └── bootstrap_cache/       # NO CHANGES (already has what we need)
```

---

## Implementation Tasks (Beads)

### GOSSIP-1: Replace PeerCache with BootstrapCache
**Proof**: Unit tests

Replace saorsa-gossip `PeerCache` with ant-quic `BootstrapCache`:

```rust
// BEFORE (in gossip.rs)
use saorsa_gossip_pubsub::PeerCache;

// AFTER
use ant_quic::bootstrap_cache::{BootstrapCache, BootstrapCacheConfig, CachedPeer};
```

**Tests**:
- [ ] `test_bootstrap_cache_initialization`
- [ ] `test_cache_persistence_on_change`
- [ ] `test_cache_loads_on_startup`

---

### GOSSIP-2: Implement Cache Gossip Protocol
**Proof**: Integration tests

Gossip protocol:
1. On connect: Send full cache to new peer
2. On change: Broadcast delta (new peer, status change)

**Message Types**:
```rust
enum CacheGossipMessage {
    FullSync { peers: Vec<CachedPeer> },
    Delta { added: Vec<CachedPeer>, removed: Vec<PeerId> },
    Request,  // Ask peer for their cache
}
```

**Tests**:
- [ ] `test_full_sync_on_connect`
- [ ] `test_delta_broadcast_on_new_peer`
- [ ] `test_delta_broadcast_on_status_change`
- [ ] `test_cache_merge_deduplication`

---

### GOSSIP-3: Intermediary PUNCH_ME_NOW Coordination
**Proof**: Integration tests + VPS

When direct connection fails after 2-5s:
1. Query gossip: "Who is connected to peer X?"
2. Select intermediary (prefer NAT=None)
3. Send request to intermediary: "Send PUNCH_ME_NOW to X for me"
4. Intermediary sends PUNCH_ME_NOW to target with our address
5. Target sends packet to us, creating NAT mapping
6. We connect directly

**Protocol**:
```rust
struct CoordinatedPunchRequest {
    target_peer: PeerId,
    requester_addr: SocketAddr,
}

struct CoordinatedPunchResponse {
    success: bool,
    target_addr: Option<SocketAddr>,  // Target's observed address
}
```

**Tests**:
- [ ] `test_intermediary_selection_prefers_public`
- [ ] `test_punch_coordination_through_intermediary`
- [ ] `test_punch_success_via_coordination`
- [ ] `test_punch_timeout_fallback_to_relay`

---

### GOSSIP-4: Relay Fallback with 30s Timeout
**Proof**: Integration tests + VPS

If coordinated punch fails within 30s, fall back to relay:
1. Find available relay node (from cache, prefer public)
2. Establish relay connection
3. Mark connection as relayed in stats
4. Continue trying direct connection in background

**Tests**:
- [ ] `test_relay_fallback_after_punch_timeout`
- [ ] `test_relay_auto_failover_on_relay_death`
- [ ] `test_relay_upgrade_to_direct_in_background`

---

### GOSSIP-5: Change Registry to Reporting-Only
**Proof**: Unit tests

Remove:
- `registry.get_peers()` for discovery
- `is_active` filtering from registry

Add:
- Report successful connections to registry (for dashboard)
- Report NAT type, method (direct/punched/relayed)

**Tests**:
- [ ] `test_registry_receives_connection_reports`
- [ ] `test_no_registry_peer_discovery_calls`
- [ ] `test_dashboard_shows_reported_connections`

---

### GOSSIP-6: Comprehensive Test Suite
**Proof**: All unit + integration tests pass

Test matrix:
- Local: `cargo test`
- Integration: `cargo test --test integration`
- NAT scenarios: All NAT type combinations

---

### GOSSIP-7: VPS Fleet Validation
**Proof**: VPS test orchestrator

Deploy to all 8 VPS nodes and validate:
- Cache gossip propagates across all nodes
- Coordinated punch works cross-region
- Relay fallback works when needed

```bash
./scripts/vps-test-orchestrator.sh run gossip_discovery
./scripts/vps-test-orchestrator.sh run nat_matrix
./scripts/vps-test-orchestrator.sh run chaos_relay_failover
```

---

### GOSSIP-8: Dashboard KPI Validation
**Proof**: 99%+ connectivity on dashboard

Monitor for 24 hours:
- Connection success rate
- Direct vs punched vs relayed breakdown
- Average time to connect

Dashboard URL: https://saorsa-1.saorsalabs.com

---

## Success Criteria

| Metric | Target | Current |
|--------|--------|---------|
| Connectivity rate | 99%+ | ~21% |
| Direct connections | 60%+ | Unknown |
| Hole-punched | 35%+ | Unknown |
| Relayed | <5% | Unknown |
| Avg connect time | <5s | Unknown |
| Cache propagation | 100% | 0% |

---

## Files to Modify

### ant-quic-test-network (main work)

| File | Changes |
|------|---------|
| `src/node/client.rs` | Replace registry discovery with gossip-first |
| `src/gossip.rs` | Add cache gossip, use BootstrapCache |
| `src/discovery.rs` | NEW: Gossip-first discovery module |
| `src/coordination.rs` | NEW: Intermediary PUNCH_ME_NOW |
| `src/registry/store.rs` | Remove discovery, keep reporting |
| `Cargo.toml` | May need to expose more ant-quic types |

### ant-quic (minimal)

| File | Changes |
|------|---------|
| `src/lib.rs` | Ensure BootstrapCache is properly exported |
| Bug fixes only | As discovered during integration |

---

## Execution Order

1. **GOSSIP-1**: Replace PeerCache (foundation)
2. **GOSSIP-2**: Cache gossip protocol (enables discovery)
3. **GOSSIP-5**: Registry to reporting-only (decouple)
4. **GOSSIP-3**: Intermediary coordination (main feature)
5. **GOSSIP-4**: Relay fallback (completeness)
6. **GOSSIP-6**: Test suite (validation)
7. **GOSSIP-7**: VPS validation (real-world)
8. **GOSSIP-8**: Dashboard KPI (success proof)
