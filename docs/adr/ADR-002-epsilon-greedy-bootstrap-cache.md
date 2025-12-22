# ADR-002: Epsilon-Greedy Bootstrap Cache

## Status

Accepted (2025-12-21)

## Context

Joining a P2P network requires knowing at least one reachable peer. Traditional approaches have limitations:

1. **Static bootstrap lists**: Become stale, create single points of failure
2. **Random selection**: Wastes time connecting to unreachable or slow peers
3. **Pure exploitation**: Gets stuck with suboptimal peers, never discovers better ones

We need a bootstrap cache that:
- Learns from connection outcomes
- Balances known-good peers with exploration
- Persists across restarts
- Handles multi-process access safely

### Latest Release

All features implemented and tested with 40 passing unit tests.

---

## Implementation Notes

### Naming Convention (2025-12-22)

The actual implementation uses the type name `BootstrapCache` rather than `GreedyBootstrapCache` as originally specified in this ADR. This decision prioritizes API simplicity and ergonomics:

- **Type name**: `BootstrapCache` (src/bootstrap_cache/cache.rs)
- **Algorithm**: Epsilon-greedy selection (unchanged)
- **Rationale**: The term "epsilon-greedy" describes the internal algorithm, not the user-facing purpose. Users interact with a "bootstrap cache" that happens to use smart selection internally.

The epsilon-greedy strategy remains fully implemented with all specified features:
- Quality scoring based on success/failure ratio
- Configurable exploration rate (ε = 0.1)
- Time-based decay
- Capacity limits with LRU eviction

This naming change affects only the public API surface - the algorithmic behavior is identical to the ADR specification.

## Decision

Implement an **epsilon-greedy** bootstrap cache with quality-based peer selection:

```rust
pub struct GreedyBootstrapCache {
    peers: HashMap<SocketAddr, CachedPeer>,
    config: BootstrapCacheConfig,
}

pub struct CachedPeer {
    addr: SocketAddr,
    peer_id: Option<PeerId>,
    capabilities: Capabilities,
    successes: u32,
    failures: u32,
    last_seen: SystemTime,
    quality_score: f64,
}
```

**Selection algorithm** (epsilon = 0.1 default):
- With probability `epsilon`: Explore - select random peer (discovers new good peers)
- With probability `1 - epsilon`: Exploit - select highest quality peer

**Quality scoring formula**:
```
base_score = success_rate * (1.0 - age_decay)
bonus = relay_bonus + coordination_bonus
penalty = symmetric_nat_penalty
quality = clamp(base_score + bonus - penalty, 0.0, 1.0)
```

**Persistence**:
- Atomic writes with file locking (prevents corruption)
- Checksum validation on load
- Periodic background saves (every 5 minutes)
- Capacity limits (10k-30k peers)

### Cache Semantics

**Large-capacity design** (10k-30k entries):
- Quality scoring with time-based expiry
- Merge sources: active connections, relay/coordinator traffic, user-provided seeds
- Record per peer:
  - Observed addresses (may have multiple)
  - Advertised protocols
  - Relay/coordination support flags
  - Soft metrics: RTT, success rate, last seen

**Dial strategy**:
- Best-first selection with epsilon-greedy exploration
- Avoids local minima by occasionally trying lower-ranked peers
- Configurable epsilon (default 0.1 = 10% exploration)

**Multi-process safety**:
- Atomic writes prevent partial file corruption
- File locking prevents concurrent write conflicts
- Background merge interval consolidates updates

### Mandatory Relay/Coordinator Participation

**Critical insight**: If peers can opt out of coordination/relaying, NAT traversal reliability collapses into a "best effort" overlay feature.

**Solution**: Enforce participation with predictable resource budgets:

| Resource | Limit | Purpose |
|----------|-------|---------|
| Bandwidth | bytes/sec | Prevent relay abuse |
| Concurrent relays | count | Limit memory/CPU |
| CPU cap | percentage | Protect local workloads |
| Per-peer fairness | quota | Prevent single-peer dominance |

This ensures NAT traversal works reliably while keeping resource usage bounded and predictable.

**Relay Protocol**: MASQUE CONNECT-UDP Bind (see ADR-006) provides standards-compliant relay capability. All peers must support MASQUE relay as part of their mandatory participation in the network.

## Consequences

### Benefits
- **Adaptive**: Learns network topology over time
- **Balanced**: Epsilon ensures continued exploration
- **Resilient**: Survives restarts, handles crashes gracefully
- **Efficient**: O(1) peer lookup, O(n) selection (acceptable for cache sizes)

### Trade-offs
- **Cold start**: First run has no learned data
- **Storage**: ~1MB for 10k peers (acceptable)
- **Staleness**: Peers can become unreachable between sessions

## Alternatives Considered

1. **Round-robin**: Cycle through peers sequentially
   - Rejected: No learning, wastes time on bad peers

2. **UCB1 (Upper Confidence Bound)**: Bandit algorithm with confidence intervals
   - Rejected: More complex, epsilon-greedy sufficient for this use case

3. **Thompson Sampling**: Bayesian approach
   - Rejected: Overkill for bootstrap selection

4. **Softmax/Boltzmann**: Probabilistic based on scores
   - Rejected: Epsilon-greedy simpler and well-understood

## References

- Commit: `5586820e` (feat(bootstrap): add greedy bootstrap cache)
- Files: `src/bootstrap_cache/*.rs`
- Config: `BootstrapCacheConfig` with tunable epsilon, capacity, decay rates
