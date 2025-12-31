# Design: saorsa-gossip Integration for ant-quic-test-network

## Status: APPROVED

## Overview

Replace the passive gossip implementation in `ant-quic-test-network` with a full `saorsa-gossip` integration using true epidemic broadcast (HyParView + Plumtree).

## Problem Statement

The current gossip implementation in `ant-quic-test-network` is **passive**:
- `GossipDiscovery` only stores announcements, doesn't broadcast
- Gossip only exchanged on connection establishment
- `announce_to_gossip()` stores locally but never sends to peers
- No periodic re-announcement mechanism
- Network goes stale as peer info ages

## Solution

Integrate `saorsa-gossip` which provides:
- **HyParView** for peer membership (active/passive views)
- **SWIM** for failure detection (Ping/Ack with suspect timeout)
- **Plumtree** for epidemic message broadcast (Eager push + Lazy IHAVE)
- **AntQuicTransport** already using `ant-quic` for networking

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        ant-quic-test-network                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────────────┐        ┌──────────────────────────────────────┐  │
│  │    TestNode      │        │         Registry (Observer)          │  │
│  │                  │        │                                      │  │
│  │  ┌────────────┐  │  push  │  - Receives heartbeats               │  │
│  │  │ saorsa-    │  │ events │  - Tracks peer liveness              │  │
│  │  │ gossip     │◄─┼───────►│  - Aggregates connection stats       │  │
│  │  │            │  │        │  - Provides dashboard data           │  │
│  │  │ - HyParView│  │        │  - Does NOT coordinate connections   │  │
│  │  │ - SWIM     │  │        │                                      │  │
│  │  │ - Plumtree │  │        └──────────────────────────────────────┘  │
│  │  │ - Transport│  │                                                  │
│  │  └────────────┘  │                                                  │
│  │                  │                                                  │
│  │  Topic: test-net │        ┌──────────────────────────────────────┐  │
│  │                  │        │         Dashboard                     │  │
│  │  Events:         │        │                                      │  │
│  │  - peer_joined   │───────►│  - Active/Passive view sizes         │  │
│  │  - peer_left     │        │  - SWIM states (Alive/Suspect/Dead)  │  │
│  │  - conn_type     │        │  - Message rates                     │  │
│  │                  │        │  - Connection types                  │  │
│  └──────────────────┘        └──────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Implementation Tasks

### Phase 1: Core Integration

1. **Add saorsa-gossip dependency**
   - Add to Cargo.toml with path dependency for development
   - Publish to crates.io when stable

2. **Create GossipIntegration wrapper**
   - Wrap `AntQuicTransport`, `HyParViewMembership`, `PlumtreePubSub`
   - Expose events: `peer_joined`, `peer_left`, `connection_type`
   - Single topic: `TopicId::from_entity("ant-quic-test-network")`

3. **Modify TestNode**
   - Replace `GossipDiscovery` with `GossipIntegration`
   - Remove current gossip.rs code
   - Wire up event handling

### Phase 2: Registry Integration

4. **Update heartbeat format**
   - Add HyParView stats (active/passive counts)
   - Add SWIM states (alive/suspect/dead counts)
   - Add Plumtree stats (eager/lazy peer counts, message rates)

5. **Connection type reporting**
   - Extend heartbeat with connection breakdown
   - IPv4 direct / IPv6 direct / HolePunched / Relayed counts

### Phase 3: Testing

6. **Unit tests**
   - GossipIntegration initialization
   - Event emission on peer join/leave
   - Topic subscription

7. **Integration tests**
   - Two-node discovery within 30s
   - Multi-node mesh formation
   - Partition recovery

8. **VPS deployment test**
   - Deploy to all 9 nodes
   - Verify 100% discovery in 30s
   - Monitor dashboard metrics

## Dependencies

```toml
[dependencies]
saorsa-gossip-transport = { path = "../saorsa-gossip/crates/transport" }
saorsa-gossip-membership = { path = "../saorsa-gossip/crates/membership" }
saorsa-gossip-pubsub = { path = "../saorsa-gossip/crates/pubsub" }
saorsa-gossip-types = { path = "../saorsa-gossip/crates/types" }
```

## Files to Modify

| File | Action |
|------|--------|
| `crates/ant-quic-test-network/Cargo.toml` | Add saorsa-gossip deps |
| `crates/ant-quic-test-network/src/gossip.rs` | DELETE (replace entirely) |
| `crates/ant-quic-test-network/src/lib.rs` | Update exports |
| `crates/ant-quic-test-network/src/node/client.rs` | Use GossipIntegration |
| `crates/ant-quic-test-network/src/gossip_integration.rs` | NEW - wrapper |
| `crates/ant-quic-test-network/src/registry/types.rs` | Extend heartbeat |

## Success Criteria

- [ ] All nodes discover each other within 30 seconds
- [ ] Network heals from partition within 60 seconds
- [ ] Registry accurately reflects network state
- [ ] Dashboard shows HyParView/SWIM/Plumtree metrics
- [ ] Connection types correctly reported
- [ ] Zero compilation warnings
- [ ] All tests pass

## Timeline

Phase 1 (Core): Proof points 1-3
Phase 2 (Registry): Proof points 4-5
Phase 3 (Testing): Proof points 6-8

## Risk Mitigation

1. **saorsa-gossip API changes**: Use path dependencies for now
2. **Transport compatibility**: AntQuicTransport already uses ant-quic
3. **Heartbeat backward compat**: Add new fields as optional

---

Approved by: Design Review
Date: 2025-12-31
