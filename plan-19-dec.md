# ant-quic Improvement Plan - December 19, 2024

## Implementation Plan: Adopting Patterns from iroh

This document provides a comprehensive, TDD-driven implementation plan for improving ant-quic based on architectural patterns identified in the iroh P2P QUIC library.

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Prerequisites](#prerequisites)
3. [Phase 1: Foundation & Safety](#phase-1-foundation--safety-week-1)
4. [Phase 2: Path Management](#phase-2-path-management-week-2)
5. [Phase 3: State Management](#phase-3-state-management-week-3)
6. [Phase 4: Transport & Discovery](#phase-4-transport--discovery-week-4)
7. [Phase 5: Observability](#phase-5-observability-week-5)
8. [Testing Strategy](#testing-strategy)
9. [Migration Guide](#migration-guide)
10. [Appendix: Reference Code](#appendix-reference-code)

---

## Executive Summary

### Goal
Improve ant-quic's reliability, performance, and maintainability by adopting battle-tested patterns from iroh.

### Key Improvements
1. **Resource Safety**: Bounded buffers, path pruning, graceful shutdown
2. **Path Quality**: RTT-based selection with hysteresis, redundant path closure
3. **State Management**: Watchable pattern, actor-based remote state
4. **Transport**: Fair polling, graceful degradation
5. **Observability**: Structured events, actor tick metrics

### Success Criteria
- Zero unbounded collections
- Path selection based on measured RTT with 5ms hysteresis
- Clean shutdown completing within 500ms
- All tests pass with zero warnings
- 80%+ code coverage on new code

---

## Prerequisites

### Before Starting Any Phase

```bash
# Ensure clean build
cd /Users/davidirvine/Desktop/Devel/projects/ant-quic
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test

# Verify baseline metrics
cargo test --release -- --nocapture 2>&1 | grep -E "(test result|FAILED)"
```

### Required Dependencies to Add

```toml
# Add to Cargo.toml [dependencies]
# Phase 1
tokio-util = { version = "0.7", features = ["rt"] }  # Already present

# Phase 3 - Watchable pattern (evaluate options)
# Option A: Use tokio::sync::watch (already available via tokio)
# Option B: Create custom Watchable implementation
# Option C: Port n0_watcher concepts
```

---

## Phase 1: Foundation & Safety (Week 1)

### 1.1 Bounded Pending Data Buffer

**Problem**: `pending_data: Arc<RwLock<HashMap<PeerId, VecDeque<Vec<u8>>>>>` can grow unbounded.

**Location**: `/src/p2p_endpoint.rs`

#### Step 1.1.1: Write Tests First

Create file: `/src/p2p_endpoint/pending_data_tests.rs`

```rust
//! Tests for bounded pending data buffer
//!
//! These tests verify that the pending data buffer:
//! 1. Enforces maximum size limits
//! 2. Expires old entries based on TTL
//! 3. Handles overflow gracefully (drop oldest)

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;

    // Constants for testing
    const MAX_PENDING_BYTES_PER_PEER: usize = 1024 * 1024; // 1MB
    const MAX_PENDING_MESSAGES_PER_PEER: usize = 100;
    const PENDING_DATA_TTL: Duration = Duration::from_secs(30);

    #[test]
    fn test_pending_buffer_enforces_byte_limit() {
        let mut buffer = BoundedPendingBuffer::new(
            MAX_PENDING_BYTES_PER_PEER,
            MAX_PENDING_MESSAGES_PER_PEER,
            PENDING_DATA_TTL,
        );

        let peer_id = PeerId::random();

        // Add data up to limit
        let large_data = vec![0u8; MAX_PENDING_BYTES_PER_PEER / 2];
        assert!(buffer.push(&peer_id, large_data.clone()).is_ok());
        assert!(buffer.push(&peer_id, large_data.clone()).is_ok());

        // Next push should drop oldest
        let result = buffer.push(&peer_id, vec![0u8; 100]);
        assert!(result.is_ok());

        // Total bytes should not exceed limit
        assert!(buffer.total_bytes(&peer_id) <= MAX_PENDING_BYTES_PER_PEER);
    }

    #[test]
    fn test_pending_buffer_enforces_message_limit() {
        let mut buffer = BoundedPendingBuffer::new(
            MAX_PENDING_BYTES_PER_PEER,
            10, // Only 10 messages
            PENDING_DATA_TTL,
        );

        let peer_id = PeerId::random();

        // Add 10 messages
        for i in 0..10 {
            assert!(buffer.push(&peer_id, vec![i as u8]).is_ok());
        }

        // 11th message should drop oldest
        buffer.push(&peer_id, vec![10u8]).unwrap();
        assert_eq!(buffer.message_count(&peer_id), 10);

        // First message should be gone (was [0])
        let first = buffer.peek_oldest(&peer_id).unwrap();
        assert_eq!(first[0], 1u8); // Second message is now first
    }

    #[tokio::test]
    async fn test_pending_buffer_expires_old_entries() {
        let mut buffer = BoundedPendingBuffer::new(
            MAX_PENDING_BYTES_PER_PEER,
            MAX_PENDING_MESSAGES_PER_PEER,
            Duration::from_millis(50), // 50ms TTL for test
        );

        let peer_id = PeerId::random();
        buffer.push(&peer_id, vec![1, 2, 3]).unwrap();

        // Should exist immediately
        assert_eq!(buffer.message_count(&peer_id), 1);

        // Wait for expiry
        sleep(Duration::from_millis(100)).await;

        // Cleanup should remove expired
        buffer.cleanup_expired();
        assert_eq!(buffer.message_count(&peer_id), 0);
    }

    #[test]
    fn test_pending_buffer_pop_returns_oldest_first() {
        let mut buffer = BoundedPendingBuffer::new(
            MAX_PENDING_BYTES_PER_PEER,
            MAX_PENDING_MESSAGES_PER_PEER,
            PENDING_DATA_TTL,
        );

        let peer_id = PeerId::random();
        buffer.push(&peer_id, vec![1]).unwrap();
        buffer.push(&peer_id, vec![2]).unwrap();
        buffer.push(&peer_id, vec![3]).unwrap();

        assert_eq!(buffer.pop(&peer_id), Some(vec![1]));
        assert_eq!(buffer.pop(&peer_id), Some(vec![2]));
        assert_eq!(buffer.pop(&peer_id), Some(vec![3]));
        assert_eq!(buffer.pop(&peer_id), None);
    }

    #[test]
    fn test_pending_buffer_clear_peer() {
        let mut buffer = BoundedPendingBuffer::new(
            MAX_PENDING_BYTES_PER_PEER,
            MAX_PENDING_MESSAGES_PER_PEER,
            PENDING_DATA_TTL,
        );

        let peer_id = PeerId::random();
        buffer.push(&peer_id, vec![1, 2, 3]).unwrap();
        buffer.push(&peer_id, vec![4, 5, 6]).unwrap();

        buffer.clear_peer(&peer_id);
        assert_eq!(buffer.message_count(&peer_id), 0);
        assert_eq!(buffer.total_bytes(&peer_id), 0);
    }

    #[test]
    fn test_pending_buffer_stats() {
        let mut buffer = BoundedPendingBuffer::new(
            MAX_PENDING_BYTES_PER_PEER,
            MAX_PENDING_MESSAGES_PER_PEER,
            PENDING_DATA_TTL,
        );

        let peer1 = PeerId::random();
        let peer2 = PeerId::random();

        buffer.push(&peer1, vec![1, 2, 3]).unwrap();
        buffer.push(&peer2, vec![4, 5]).unwrap();

        let stats = buffer.stats();
        assert_eq!(stats.total_peers, 2);
        assert_eq!(stats.total_messages, 2);
        assert_eq!(stats.total_bytes, 5);
    }
}
```

#### Step 1.1.2: Implement BoundedPendingBuffer

Create file: `/src/p2p_endpoint/bounded_pending_buffer.rs`

```rust
//! Bounded pending data buffer with TTL expiration
//!
//! This module provides a memory-safe buffer for pending peer data
//! that enforces both size limits and time-based expiration.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::nat_traversal_api::PeerId;

/// Entry in the pending buffer with timestamp
#[derive(Debug)]
struct PendingEntry {
    data: Vec<u8>,
    created_at: Instant,
}

/// Per-peer pending data with tracking
#[derive(Debug, Default)]
struct PeerPendingData {
    entries: VecDeque<PendingEntry>,
    total_bytes: usize,
}

/// Statistics for the pending buffer
#[derive(Debug, Clone, Default)]
pub struct PendingBufferStats {
    pub total_peers: usize,
    pub total_messages: usize,
    pub total_bytes: usize,
    pub dropped_messages: u64,
    pub expired_messages: u64,
}

/// A bounded buffer for pending peer data with automatic expiration
#[derive(Debug)]
pub struct BoundedPendingBuffer {
    data: HashMap<PeerId, PeerPendingData>,
    max_bytes_per_peer: usize,
    max_messages_per_peer: usize,
    ttl: Duration,
    stats: PendingBufferStats,
}

impl BoundedPendingBuffer {
    /// Create a new bounded pending buffer
    pub fn new(
        max_bytes_per_peer: usize,
        max_messages_per_peer: usize,
        ttl: Duration,
    ) -> Self {
        Self {
            data: HashMap::new(),
            max_bytes_per_peer,
            max_messages_per_peer,
            ttl,
            stats: PendingBufferStats::default(),
        }
    }

    /// Push data for a peer, dropping oldest if limits exceeded
    pub fn push(&mut self, peer_id: &PeerId, data: Vec<u8>) -> Result<(), PendingBufferError> {
        let data_len = data.len();

        // Reject single messages larger than limit
        if data_len > self.max_bytes_per_peer {
            return Err(PendingBufferError::MessageTooLarge {
                size: data_len,
                max: self.max_bytes_per_peer,
            });
        }

        let peer_data = self.data.entry(*peer_id).or_default();

        // Drop oldest entries until we have room for new data
        while peer_data.total_bytes + data_len > self.max_bytes_per_peer
            || peer_data.entries.len() >= self.max_messages_per_peer
        {
            if let Some(dropped) = peer_data.entries.pop_front() {
                peer_data.total_bytes = peer_data.total_bytes.saturating_sub(dropped.data.len());
                self.stats.dropped_messages += 1;
            } else {
                break;
            }
        }

        // Add new entry
        peer_data.entries.push_back(PendingEntry {
            data,
            created_at: Instant::now(),
        });
        peer_data.total_bytes += data_len;

        Ok(())
    }

    /// Pop the oldest pending data for a peer
    pub fn pop(&mut self, peer_id: &PeerId) -> Option<Vec<u8>> {
        let peer_data = self.data.get_mut(peer_id)?;
        let entry = peer_data.entries.pop_front()?;
        peer_data.total_bytes = peer_data.total_bytes.saturating_sub(entry.data.len());

        // Clean up empty peer entries
        if peer_data.entries.is_empty() {
            self.data.remove(peer_id);
        }

        Some(entry.data)
    }

    /// Peek at the oldest entry without removing
    pub fn peek_oldest(&self, peer_id: &PeerId) -> Option<&[u8]> {
        self.data
            .get(peer_id)?
            .entries
            .front()
            .map(|e| e.data.as_slice())
    }

    /// Get message count for a peer
    pub fn message_count(&self, peer_id: &PeerId) -> usize {
        self.data
            .get(peer_id)
            .map(|d| d.entries.len())
            .unwrap_or(0)
    }

    /// Get total bytes for a peer
    pub fn total_bytes(&self, peer_id: &PeerId) -> usize {
        self.data
            .get(peer_id)
            .map(|d| d.total_bytes)
            .unwrap_or(0)
    }

    /// Clear all pending data for a peer
    pub fn clear_peer(&mut self, peer_id: &PeerId) {
        self.data.remove(peer_id);
    }

    /// Remove expired entries across all peers
    pub fn cleanup_expired(&mut self) {
        let now = Instant::now();
        let ttl = self.ttl;

        self.data.retain(|_, peer_data| {
            let before_len = peer_data.entries.len();

            peer_data.entries.retain(|entry| {
                let expired = now.duration_since(entry.created_at) < ttl;
                if !expired {
                    peer_data.total_bytes = peer_data.total_bytes.saturating_sub(entry.data.len());
                }
                expired
            });

            let expired_count = before_len - peer_data.entries.len();
            self.stats.expired_messages += expired_count as u64;

            !peer_data.entries.is_empty()
        });
    }

    /// Get buffer statistics
    pub fn stats(&self) -> PendingBufferStats {
        let mut stats = self.stats.clone();
        stats.total_peers = self.data.len();
        stats.total_messages = self.data.values().map(|d| d.entries.len()).sum();
        stats.total_bytes = self.data.values().map(|d| d.total_bytes).sum();
        stats
    }
}

/// Errors from the pending buffer
#[derive(Debug, thiserror::Error)]
pub enum PendingBufferError {
    #[error("Message too large: {size} bytes exceeds max {max} bytes")]
    MessageTooLarge { size: usize, max: usize },
}

#[cfg(test)]
mod tests;
```

#### Step 1.1.3: Integrate into P2pEndpoint

Edit: `/src/p2p_endpoint.rs`

```rust
// Add module declaration at top
mod bounded_pending_buffer;
pub use bounded_pending_buffer::{BoundedPendingBuffer, PendingBufferStats};

// Replace in P2pEndpoint struct:
// OLD: pending_data: Arc<RwLock<HashMap<PeerId, VecDeque<Vec<u8>>>>>,
// NEW:
pending_data: Arc<RwLock<BoundedPendingBuffer>>,

// Update constructor:
impl P2pEndpoint {
    pub async fn new(config: P2pConfig) -> Result<Self, ...> {
        // ...
        let pending_data = Arc::new(RwLock::new(BoundedPendingBuffer::new(
            1024 * 1024,  // 1MB per peer
            100,          // 100 messages per peer
            Duration::from_secs(30), // 30s TTL
        )));
        // ...
    }
}

// Add cleanup task in event loop:
async fn run_event_loop(&self) {
    let mut cleanup_interval = tokio::time::interval(Duration::from_secs(10));

    loop {
        tokio::select! {
            // ... existing branches ...

            _ = cleanup_interval.tick() => {
                let mut pending = self.pending_data.write().await;
                pending.cleanup_expired();
            }
        }
    }
}
```

#### Step 1.1.4: Verify

```bash
# Run tests
cargo test bounded_pending_buffer -- --nocapture

# Check for no warnings
cargo clippy --all-targets -- -D warnings

# Verify integration
cargo test p2p_endpoint -- --nocapture
```

---

### 1.2 Path/Candidate Pruning Limits

**Problem**: Candidate lists can grow unbounded per peer.

**Location**: `/src/connection/nat_traversal.rs`

#### Step 1.2.1: Write Tests First

Create: `/src/connection/nat_traversal_pruning_tests.rs`

```rust
//! Tests for candidate pruning
//!
//! Verifies that candidate lists are bounded and oldest/lowest-priority
//! candidates are pruned when limits are exceeded.

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_CANDIDATES_PER_PEER: usize = 30;
    const MAX_INACTIVE_CANDIDATES: usize = 10;

    #[test]
    fn test_candidate_list_enforces_max_limit() {
        let mut state = NatTraversalState::new_with_limits(
            MAX_CANDIDATES_PER_PEER,
            MAX_INACTIVE_CANDIDATES,
        );

        // Add candidates up to limit
        for i in 0..MAX_CANDIDATES_PER_PEER {
            let addr = format!("192.168.1.{}:5000", i).parse().unwrap();
            state.add_local_candidate(addr, CandidateSource::Local);
        }

        assert_eq!(state.local_candidates.len(), MAX_CANDIDATES_PER_PEER);

        // Adding one more should prune lowest priority
        let new_addr = "192.168.1.100:5000".parse().unwrap();
        state.add_local_candidate(new_addr, CandidateSource::ServerReflexive);

        assert_eq!(state.local_candidates.len(), MAX_CANDIDATES_PER_PEER);
        // Server reflexive should be kept (higher priority than Local)
        assert!(state.local_candidates.values().any(|c| c.source == CandidateSource::ServerReflexive));
    }

    #[test]
    fn test_inactive_candidates_pruned_first() {
        let mut state = NatTraversalState::new_with_limits(
            MAX_CANDIDATES_PER_PEER,
            MAX_INACTIVE_CANDIDATES,
        );

        // Add 20 candidates, mark 15 as inactive
        for i in 0..20 {
            let addr = format!("192.168.1.{}:5000", i).parse().unwrap();
            let seq = state.add_local_candidate(addr, CandidateSource::Local);
            if i < 15 {
                state.mark_candidate_inactive(seq);
            }
        }

        // Should have pruned inactive down to limit
        let inactive_count = state.local_candidates.values()
            .filter(|c| matches!(c.state, CandidateState::Inactive(_)))
            .count();

        assert!(inactive_count <= MAX_INACTIVE_CANDIDATES);
    }

    #[test]
    fn test_candidate_state_transitions() {
        let mut state = NatTraversalState::new_with_limits(
            MAX_CANDIDATES_PER_PEER,
            MAX_INACTIVE_CANDIDATES,
        );

        let addr = "192.168.1.1:5000".parse().unwrap();
        let seq = state.add_local_candidate(addr, CandidateSource::Local);

        // Initial state should be Unknown
        let candidate = state.local_candidates.get(&seq).unwrap();
        assert!(matches!(candidate.state, CandidateState::Unknown));

        // Transition to Validating
        state.start_validation(seq);
        let candidate = state.local_candidates.get(&seq).unwrap();
        assert!(matches!(candidate.state, CandidateState::Validating));

        // Transition to Validated
        state.mark_validated(seq);
        let candidate = state.local_candidates.get(&seq).unwrap();
        assert!(matches!(candidate.state, CandidateState::Validated(_)));

        // Transition to Inactive
        state.mark_candidate_inactive(seq);
        let candidate = state.local_candidates.get(&seq).unwrap();
        assert!(matches!(candidate.state, CandidateState::Inactive(_)));
    }

    #[test]
    fn test_prune_by_age_when_at_limit() {
        let mut state = NatTraversalState::new_with_limits(
            5, // Small limit for testing
            2,
        );

        // Add candidates with delays to ensure different timestamps
        for i in 0..5 {
            let addr = format!("192.168.1.{}:5000", i).parse().unwrap();
            state.add_local_candidate(addr, CandidateSource::Local);
        }

        // All at same priority, adding one more should remove oldest
        let first_addr: SocketAddr = "192.168.1.0:5000".parse().unwrap();
        let first_exists = state.local_candidates.values().any(|c| c.addr == first_addr);

        let new_addr = "192.168.1.99:5000".parse().unwrap();
        state.add_local_candidate(new_addr, CandidateSource::Local);

        // First candidate should be gone (oldest)
        let first_still_exists = state.local_candidates.values().any(|c| c.addr == first_addr);
        assert!(!first_still_exists || !first_exists);
    }
}
```

#### Step 1.2.2: Add Constants and State Tracking

Edit: `/src/connection/nat_traversal.rs`

```rust
// Add constants at top of file
/// Maximum number of candidates per peer (matches iroh's MAX_IP_PATHS)
pub const MAX_CANDIDATES_PER_PEER: usize = 30;

/// Maximum number of inactive candidates to keep (matches iroh's MAX_INACTIVE_IP_PATHS)
pub const MAX_INACTIVE_CANDIDATES: usize = 10;

// Update CandidateState enum if not already present
#[derive(Debug, Clone, PartialEq)]
pub enum CandidateState {
    /// Not yet tried
    Unknown,
    /// Currently being validated
    Validating,
    /// Successfully validated with timestamp
    Validated(Instant),
    /// Was active, now inactive with timestamp
    Inactive(Instant),
    /// Validation failed permanently
    Unusable,
}

// Update AddressCandidate struct
#[derive(Debug, Clone)]
pub struct AddressCandidate {
    pub addr: SocketAddr,
    pub source: CandidateSource,
    pub state: CandidateState,
    pub priority: u32,
    pub created_at: Instant,
    pub last_used: Option<Instant>,
}

impl AddressCandidate {
    /// Calculate effective priority for pruning decisions
    pub fn pruning_priority(&self) -> (u8, u32, Instant) {
        // Order: state priority (lower = prune first), source priority, age (older = prune first)
        let state_priority = match &self.state {
            CandidateState::Unusable => 0,
            CandidateState::Inactive(_) => 1,
            CandidateState::Unknown => 2,
            CandidateState::Validating => 3,
            CandidateState::Validated(_) => 4,
        };
        (state_priority, self.priority, self.created_at)
    }
}
```

#### Step 1.2.3: Implement Pruning Logic

```rust
impl NatTraversalState {
    /// Add a local candidate with automatic pruning
    pub fn add_local_candidate(
        &mut self,
        addr: SocketAddr,
        source: CandidateSource,
    ) -> VarInt {
        // Check if already exists
        if let Some((seq, _)) = self.local_candidates.iter().find(|(_, c)| c.addr == addr) {
            return *seq;
        }

        // Prune if at limit
        self.prune_candidates_if_needed();

        // Assign sequence number
        let seq = self.next_local_seq;
        self.next_local_seq = VarInt::from_u32(self.next_local_seq.into_inner() + 1);

        // Create candidate
        let candidate = AddressCandidate {
            addr,
            source: source.clone(),
            state: CandidateState::Unknown,
            priority: source.base_priority(),
            created_at: Instant::now(),
            last_used: None,
        };

        self.local_candidates.insert(seq, candidate);
        seq
    }

    /// Prune candidates when approaching limits
    fn prune_candidates_if_needed(&mut self) {
        // Count inactive candidates
        let inactive_count = self.local_candidates.values()
            .filter(|c| matches!(c.state, CandidateState::Inactive(_)))
            .count();

        // Prune excess inactive candidates first
        if inactive_count > MAX_INACTIVE_CANDIDATES {
            self.prune_inactive_candidates(inactive_count - MAX_INACTIVE_CANDIDATES);
        }

        // Prune if total exceeds limit
        if self.local_candidates.len() >= MAX_CANDIDATES_PER_PEER {
            self.prune_lowest_priority_candidate();
        }
    }

    /// Remove the specified number of inactive candidates (oldest first)
    fn prune_inactive_candidates(&mut self, count: usize) {
        let mut inactive: Vec<_> = self.local_candidates.iter()
            .filter(|(_, c)| matches!(c.state, CandidateState::Inactive(_)))
            .map(|(seq, c)| (*seq, c.created_at))
            .collect();

        // Sort by age (oldest first)
        inactive.sort_by_key(|(_, created)| *created);

        // Remove oldest inactive candidates
        for (seq, _) in inactive.into_iter().take(count) {
            self.local_candidates.remove(&seq);
            tracing::debug!(seq = %seq.into_inner(), "Pruned inactive candidate");
        }
    }

    /// Remove the lowest priority candidate
    fn prune_lowest_priority_candidate(&mut self) {
        let lowest = self.local_candidates.iter()
            .min_by_key(|(_, c)| c.pruning_priority())
            .map(|(seq, _)| *seq);

        if let Some(seq) = lowest {
            self.local_candidates.remove(&seq);
            tracing::debug!(seq = %seq.into_inner(), "Pruned lowest priority candidate");
        }
    }

    /// Mark a candidate as inactive
    pub fn mark_candidate_inactive(&mut self, seq: VarInt) {
        if let Some(candidate) = self.local_candidates.get_mut(&seq) {
            candidate.state = CandidateState::Inactive(Instant::now());

            // Trigger pruning if we now have too many inactive
            let inactive_count = self.local_candidates.values()
                .filter(|c| matches!(c.state, CandidateState::Inactive(_)))
                .count();

            if inactive_count > MAX_INACTIVE_CANDIDATES {
                self.prune_inactive_candidates(inactive_count - MAX_INACTIVE_CANDIDATES);
            }
        }
    }
}
```

#### Step 1.2.4: Verify

```bash
cargo test nat_traversal_pruning -- --nocapture
cargo clippy --all-targets -- -D warnings
```

---

### 1.3 Graceful Shutdown Sequence

**Problem**: `tokio::spawn()` without tracked handles; no coordinated shutdown.

**Location**: `/src/nat_traversal_api.rs`, `/src/p2p_endpoint.rs`

#### Step 1.3.1: Write Tests First

Create: `/src/shutdown_tests.rs`

```rust
//! Tests for graceful shutdown
//!
//! Verifies that shutdown:
//! 1. Completes within timeout
//! 2. Closes all connections properly
//! 3. Cleans up all resources
//! 4. Cancels background tasks

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    use tokio::time::timeout;

    const SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(500);

    #[tokio::test]
    async fn test_shutdown_completes_within_timeout() {
        let config = P2pConfig::builder()
            .bind_addr("127.0.0.1:0".parse().unwrap())
            .build()
            .unwrap();

        let endpoint = P2pEndpoint::new(config).await.unwrap();

        let start = Instant::now();
        let result = timeout(SHUTDOWN_TIMEOUT, endpoint.shutdown()).await;

        assert!(result.is_ok(), "Shutdown should complete within timeout");
        assert!(start.elapsed() < SHUTDOWN_TIMEOUT);
    }

    #[tokio::test]
    async fn test_shutdown_closes_connections() {
        let config1 = P2pConfig::builder()
            .bind_addr("127.0.0.1:0".parse().unwrap())
            .build()
            .unwrap();
        let config2 = P2pConfig::builder()
            .bind_addr("127.0.0.1:0".parse().unwrap())
            .build()
            .unwrap();

        let endpoint1 = P2pEndpoint::new(config1).await.unwrap();
        let endpoint2 = P2pEndpoint::new(config2).await.unwrap();

        // Connect endpoints
        let addr1 = endpoint1.local_addr().unwrap();
        endpoint2.connect_to_addr(addr1).await.unwrap();

        // Verify connected
        assert!(!endpoint1.connected_peers().is_empty() || !endpoint2.connected_peers().is_empty());

        // Shutdown endpoint1
        endpoint1.shutdown().await;

        // Give time for close to propagate
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connections should be cleaned up
        // Note: endpoint2 may still show the connection briefly
    }

    #[tokio::test]
    async fn test_shutdown_is_idempotent() {
        let config = P2pConfig::builder()
            .bind_addr("127.0.0.1:0".parse().unwrap())
            .build()
            .unwrap();

        let endpoint = P2pEndpoint::new(config).await.unwrap();

        // Multiple shutdowns should not panic
        endpoint.shutdown().await;
        endpoint.shutdown().await;
        endpoint.shutdown().await;
    }

    #[tokio::test]
    async fn test_shutdown_cancels_background_tasks() {
        let config = P2pConfig::builder()
            .bind_addr("127.0.0.1:0".parse().unwrap())
            .build()
            .unwrap();

        let endpoint = P2pEndpoint::new(config).await.unwrap();

        // Get task count before shutdown
        let tasks_before = endpoint.active_task_count();
        assert!(tasks_before > 0, "Should have background tasks");

        // Shutdown
        endpoint.shutdown().await;

        // All tasks should be cancelled
        let tasks_after = endpoint.active_task_count();
        assert_eq!(tasks_after, 0, "All tasks should be cancelled");
    }
}
```

#### Step 1.3.2: Implement Shutdown Coordinator

Create: `/src/shutdown.rs`

```rust
//! Coordinated shutdown for ant-quic endpoints
//!
//! Implements iroh-style staged shutdown:
//! 1. Stop accepting new work
//! 2. Drain existing work with timeout
//! 3. Cancel remaining tasks
//! 4. Clean up resources

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Default timeout for graceful shutdown
pub const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(500);

/// Timeout for waiting on individual tasks
pub const TASK_ABORT_TIMEOUT: Duration = Duration::from_millis(100);

/// Coordinates shutdown across all endpoint components
#[derive(Debug)]
pub struct ShutdownCoordinator {
    /// Token cancelled when shutdown starts (stop accepting new work)
    close_start: CancellationToken,

    /// Token cancelled after connections drained
    close_complete: CancellationToken,

    /// Whether shutdown has been initiated
    shutdown_initiated: AtomicBool,

    /// Count of active background tasks
    active_tasks: AtomicUsize,

    /// Notified when all tasks complete
    tasks_complete: Notify,

    /// Tracked task handles
    task_handles: parking_lot::Mutex<Vec<JoinHandle<()>>>,
}

impl ShutdownCoordinator {
    /// Create a new shutdown coordinator
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            close_start: CancellationToken::new(),
            close_complete: CancellationToken::new(),
            shutdown_initiated: AtomicBool::new(false),
            active_tasks: AtomicUsize::new(0),
            tasks_complete: Notify::new(),
            task_handles: parking_lot::Mutex::new(Vec::new()),
        })
    }

    /// Get a token that is cancelled when shutdown starts
    pub fn close_start_token(&self) -> CancellationToken {
        self.close_start.clone()
    }

    /// Get a token that is cancelled when shutdown completes
    pub fn close_complete_token(&self) -> CancellationToken {
        self.close_complete.clone()
    }

    /// Check if shutdown has been initiated
    pub fn is_shutting_down(&self) -> bool {
        self.shutdown_initiated.load(Ordering::SeqCst)
    }

    /// Register a background task for tracking
    pub fn register_task(&self, handle: JoinHandle<()>) {
        self.active_tasks.fetch_add(1, Ordering::SeqCst);
        self.task_handles.lock().push(handle);
    }

    /// Spawn a tracked task
    pub fn spawn_tracked<F>(&self, future: F) -> JoinHandle<()>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let active_tasks = self.active_tasks.clone();
        let tasks_complete = self.tasks_complete.clone();

        let handle = tokio::spawn(async move {
            future.await;
            if active_tasks.fetch_sub(1, Ordering::SeqCst) == 1 {
                tasks_complete.notify_waiters();
            }
        });

        self.active_tasks.fetch_add(1, Ordering::SeqCst);
        self.task_handles.lock().push(handle.abort_handle().into());
        handle
    }

    /// Get count of active tasks
    pub fn active_task_count(&self) -> usize {
        self.active_tasks.load(Ordering::SeqCst)
    }

    /// Execute coordinated shutdown
    pub async fn shutdown(&self) {
        // Prevent multiple shutdown attempts
        if self.shutdown_initiated.swap(true, Ordering::SeqCst) {
            debug!("Shutdown already in progress");
            return;
        }

        info!("Starting coordinated shutdown");

        // Stage 1: Signal close start (stop accepting new work)
        debug!("Stage 1: Signaling close start");
        self.close_start.cancel();

        // Stage 2: Wait for tasks with timeout
        debug!("Stage 2: Waiting for tasks to complete");
        let wait_result = timeout(
            DEFAULT_SHUTDOWN_TIMEOUT,
            self.wait_for_tasks(),
        ).await;

        if wait_result.is_err() {
            warn!("Shutdown timeout - aborting remaining tasks");
        }

        // Stage 3: Abort any remaining tasks
        debug!("Stage 3: Aborting remaining tasks");
        self.abort_remaining_tasks().await;

        // Stage 4: Signal close complete
        debug!("Stage 4: Signaling close complete");
        self.close_complete.cancel();

        info!("Shutdown complete");
    }

    /// Wait for all tasks to complete
    async fn wait_for_tasks(&self) {
        while self.active_tasks.load(Ordering::SeqCst) > 0 {
            self.tasks_complete.notified().await;
        }
    }

    /// Abort any tasks that didn't complete gracefully
    async fn abort_remaining_tasks(&self) {
        let handles: Vec<_> = self.task_handles.lock().drain(..).collect();

        for handle in handles {
            if !handle.is_finished() {
                handle.abort();
                // Give a moment for abort to take effect
                let _ = timeout(TASK_ABORT_TIMEOUT, async {
                    // Wait for task to actually finish
                    let _ = handle.await;
                }).await;
            }
        }

        self.active_tasks.store(0, Ordering::SeqCst);
    }
}

impl Default for ShutdownCoordinator {
    fn default() -> Self {
        Self {
            close_start: CancellationToken::new(),
            close_complete: CancellationToken::new(),
            shutdown_initiated: AtomicBool::new(false),
            active_tasks: AtomicUsize::new(0),
            tasks_complete: Notify::new(),
            task_handles: parking_lot::Mutex::new(Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests;
```

#### Step 1.3.3: Integrate with P2pEndpoint

Edit: `/src/p2p_endpoint.rs`

```rust
// Add to imports
use crate::shutdown::ShutdownCoordinator;

// Add to P2pEndpoint struct
pub struct P2pEndpoint {
    // ... existing fields ...
    shutdown: Arc<ShutdownCoordinator>,
}

// Update constructor
impl P2pEndpoint {
    pub async fn new(config: P2pConfig) -> Result<Self, ...> {
        let shutdown = ShutdownCoordinator::new();

        // Spawn background tasks using the coordinator
        let event_loop_handle = shutdown.spawn_tracked({
            let inner = inner.clone();
            let shutdown_token = shutdown.close_start_token();
            async move {
                Self::run_event_loop_inner(inner, shutdown_token).await;
            }
        });

        // ... rest of constructor ...
    }

    /// Shutdown the endpoint gracefully
    pub async fn shutdown(&self) {
        // Close QUIC endpoint first
        self.inner.close_endpoint();

        // Execute coordinated shutdown
        self.shutdown.shutdown().await;
    }

    /// Get count of active background tasks
    pub fn active_task_count(&self) -> usize {
        self.shutdown.active_task_count()
    }
}

// Update event loop to respect shutdown
async fn run_event_loop_inner(
    inner: Arc<NatTraversalEndpoint>,
    shutdown_token: CancellationToken,
) {
    let mut cleanup_interval = tokio::time::interval(Duration::from_secs(10));

    loop {
        tokio::select! {
            biased;

            _ = shutdown_token.cancelled() => {
                debug!("Event loop received shutdown signal");
                break;
            }

            // ... existing branches ...
        }
    }

    debug!("Event loop exited");
}
```

#### Step 1.3.4: Verify

```bash
cargo test shutdown -- --nocapture
cargo clippy --all-targets -- -D warnings
```

---

## Phase 2: Path Management (Week 2)

### 2.1 RTT-Based Path Selection with Hysteresis

**Problem**: Fixed priority-based selection doesn't adapt to network conditions.

**Reference**: iroh's `select_best_path` in `remote_state.rs:908-1105`

#### Step 2.1.1: Write Tests First

Create: `/src/path_selection_tests.rs`

```rust
//! Tests for RTT-based path selection
//!
//! Verifies:
//! 1. Lower RTT paths are preferred
//! 2. Hysteresis prevents path flapping
//! 3. Direct paths preferred over relay
//! 4. IPv6 gets slight preference over IPv4

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, Ipv4Addr, Ipv6Addr};

    // Constants matching iroh
    const RTT_SWITCHING_MIN: Duration = Duration::from_millis(5);
    const IPV6_RTT_ADVANTAGE: Duration = Duration::from_millis(3);

    fn v4_addr(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), port))
    }

    fn v6_addr(port: u16) -> SocketAddr {
        SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            port, 0, 0,
        ))
    }

    #[test]
    fn test_selects_lower_rtt_path() {
        let paths = vec![
            PathCandidate::new(v4_addr(5000), Duration::from_millis(50)),
            PathCandidate::new(v4_addr(5001), Duration::from_millis(20)),
            PathCandidate::new(v4_addr(5002), Duration::from_millis(100)),
        ];

        let selected = select_best_path(&paths, None);

        assert_eq!(selected.unwrap().addr.port(), 5001);
    }

    #[test]
    fn test_hysteresis_prevents_flapping() {
        let current = PathCandidate::new(v4_addr(5000), Duration::from_millis(50));

        let paths = vec![
            current.clone(),
            // Only 2ms better - should NOT switch (needs 5ms improvement)
            PathCandidate::new(v4_addr(5001), Duration::from_millis(48)),
        ];

        let selected = select_best_path(&paths, Some(&current));

        // Should keep current path (hysteresis)
        assert_eq!(selected.unwrap().addr.port(), 5000);
    }

    #[test]
    fn test_switches_when_significantly_better() {
        let current = PathCandidate::new(v4_addr(5000), Duration::from_millis(50));

        let paths = vec![
            current.clone(),
            // 10ms better - should switch (exceeds 5ms threshold)
            PathCandidate::new(v4_addr(5001), Duration::from_millis(40)),
        ];

        let selected = select_best_path(&paths, Some(&current));

        assert_eq!(selected.unwrap().addr.port(), 5001);
    }

    #[test]
    fn test_ipv6_preference() {
        let paths = vec![
            PathCandidate::new(v4_addr(5000), Duration::from_millis(50)),
            // IPv6 with same RTT should win due to 3ms advantage
            PathCandidate::new(v6_addr(5001), Duration::from_millis(50)),
        ];

        let selected = select_best_path(&paths, None);

        assert!(selected.unwrap().addr.is_ipv6());
    }

    #[test]
    fn test_ipv6_advantage_applied_correctly() {
        let paths = vec![
            // IPv4 is 2ms faster, but IPv6 gets 3ms advantage
            PathCandidate::new(v4_addr(5000), Duration::from_millis(48)),
            PathCandidate::new(v6_addr(5001), Duration::from_millis(50)),
        ];

        let selected = select_best_path(&paths, None);

        // IPv6 should win (50 - 3 = 47 effective RTT < 48)
        assert!(selected.unwrap().addr.is_ipv6());
    }

    #[test]
    fn test_direct_preferred_over_relay() {
        let paths = vec![
            PathCandidate::direct(v4_addr(5000), Duration::from_millis(100)),
            // Relay is faster but direct should be preferred
            PathCandidate::relay(v4_addr(5001), Duration::from_millis(50)),
        ];

        let selected = select_best_path(&paths, None);

        assert!(selected.unwrap().is_direct());
    }

    #[test]
    fn test_falls_back_to_relay_when_no_direct() {
        let paths = vec![
            PathCandidate::relay(v4_addr(5000), Duration::from_millis(100)),
            PathCandidate::relay(v4_addr(5001), Duration::from_millis(50)),
        ];

        let selected = select_best_path(&paths, None);

        // Should select faster relay
        assert_eq!(selected.unwrap().addr.port(), 5001);
    }

    #[test]
    fn test_never_switches_from_direct_to_relay() {
        let current = PathCandidate::direct(v4_addr(5000), Duration::from_millis(100));

        let paths = vec![
            current.clone(),
            // Much faster relay should NOT cause switch
            PathCandidate::relay(v4_addr(5001), Duration::from_millis(10)),
        ];

        let selected = select_best_path(&paths, Some(&current));

        assert!(selected.unwrap().is_direct());
    }

    #[test]
    fn test_empty_paths_returns_none() {
        let paths: Vec<PathCandidate> = vec![];
        let selected = select_best_path(&paths, None);
        assert!(selected.is_none());
    }

    #[test]
    fn test_all_paths_same_rtt() {
        let paths = vec![
            PathCandidate::new(v4_addr(5000), Duration::from_millis(50)),
            PathCandidate::new(v4_addr(5001), Duration::from_millis(50)),
            PathCandidate::new(v4_addr(5002), Duration::from_millis(50)),
        ];

        // Should return one of them (first or deterministic choice)
        let selected = select_best_path(&paths, None);
        assert!(selected.is_some());
    }
}
```

#### Step 2.1.2: Implement Path Selection

Create: `/src/path_selection.rs`

```rust
//! RTT-based path selection with hysteresis
//!
//! Implements iroh-style path selection:
//! - Lower RTT paths preferred
//! - 5ms hysteresis to prevent flapping
//! - 3ms advantage for IPv6
//! - Direct paths strongly preferred over relay

use std::net::SocketAddr;
use std::time::Duration;

/// Minimum RTT improvement required to switch paths (prevents flapping)
pub const RTT_SWITCHING_MIN: Duration = Duration::from_millis(5);

/// RTT advantage given to IPv6 paths
pub const IPV6_RTT_ADVANTAGE: Duration = Duration::from_millis(3);

/// Type of path connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathType {
    /// Direct UDP connection
    Direct,
    /// Via relay server
    Relay,
}

/// A candidate path with measured RTT
#[derive(Debug, Clone)]
pub struct PathCandidate {
    pub addr: SocketAddr,
    pub rtt: Duration,
    pub path_type: PathType,
}

impl PathCandidate {
    /// Create a new direct path candidate
    pub fn new(addr: SocketAddr, rtt: Duration) -> Self {
        Self {
            addr,
            rtt,
            path_type: PathType::Direct,
        }
    }

    /// Create a direct path candidate
    pub fn direct(addr: SocketAddr, rtt: Duration) -> Self {
        Self {
            addr,
            rtt,
            path_type: PathType::Direct,
        }
    }

    /// Create a relay path candidate
    pub fn relay(addr: SocketAddr, rtt: Duration) -> Self {
        Self {
            addr,
            rtt,
            path_type: PathType::Relay,
        }
    }

    /// Check if this is a direct path
    pub fn is_direct(&self) -> bool {
        self.path_type == PathType::Direct
    }

    /// Calculate effective RTT (with IPv6 advantage applied)
    pub fn effective_rtt(&self) -> Duration {
        if self.addr.is_ipv6() {
            self.rtt.saturating_sub(IPV6_RTT_ADVANTAGE)
        } else {
            self.rtt
        }
    }
}

/// Select the best path from candidates
///
/// Algorithm:
/// 1. Prefer direct paths over relay paths
/// 2. Among same type, prefer lower RTT
/// 3. Apply IPv6 advantage (3ms)
/// 4. Apply hysteresis (5ms) when switching from current path
pub fn select_best_path(
    paths: &[PathCandidate],
    current: Option<&PathCandidate>,
) -> Option<PathCandidate> {
    if paths.is_empty() {
        return None;
    }

    // Separate direct and relay paths
    let direct_paths: Vec<_> = paths.iter().filter(|p| p.is_direct()).collect();
    let relay_paths: Vec<_> = paths.iter().filter(|p| !p.is_direct()).collect();

    // Find best direct path
    let best_direct = find_best_by_rtt(&direct_paths);

    // Find best relay path
    let best_relay = find_best_by_rtt(&relay_paths);

    // Determine the best new path (prefer direct)
    let best_new = match (best_direct, best_relay) {
        (Some(direct), _) => Some(direct),
        (None, Some(relay)) => Some(relay),
        (None, None) => None,
    };

    // Apply hysteresis if we have a current path
    match (current, best_new) {
        (None, best) => best.cloned(),
        (Some(current), None) => Some(current.clone()),
        (Some(current), Some(new)) => {
            // Never switch from direct to relay
            if current.is_direct() && !new.is_direct() {
                return Some(current.clone());
            }

            // Check if new path is significantly better
            let current_eff = current.effective_rtt();
            let new_eff = new.effective_rtt();

            if current_eff > new_eff + RTT_SWITCHING_MIN {
                // New path is significantly better
                Some(new.clone())
            } else {
                // Keep current path (hysteresis)
                Some(current.clone())
            }
        }
    }
}

/// Find the path with lowest effective RTT
fn find_best_by_rtt<'a>(paths: &[&'a PathCandidate]) -> Option<&'a PathCandidate> {
    paths.iter()
        .min_by_key(|p| p.effective_rtt())
        .copied()
}

/// Compare IPv4 and IPv6 paths, applying IPv6 advantage
pub fn select_v4_v6(
    v4_addr: SocketAddr,
    v4_rtt: Duration,
    v6_addr: SocketAddr,
    v6_rtt: Duration,
) -> (SocketAddr, Duration) {
    // Apply IPv6 advantage
    let v6_effective = v6_rtt.saturating_sub(IPV6_RTT_ADVANTAGE);

    if v6_effective <= v4_rtt {
        (v6_addr, v6_rtt)
    } else {
        (v4_addr, v4_rtt)
    }
}

#[cfg(test)]
mod tests;
```

#### Step 2.1.3: Integrate with Connection

Edit: `/src/connection/nat_traversal.rs`

```rust
use crate::path_selection::{select_best_path, PathCandidate, PathType};

impl NatTraversalState {
    /// Select the best path from validated candidates
    pub fn select_best_validated_path(&self) -> Option<SocketAddr> {
        let candidates: Vec<PathCandidate> = self.local_candidates
            .values()
            .filter(|c| matches!(c.state, CandidateState::Validated(_)))
            .map(|c| {
                let path_type = if c.source == CandidateSource::Relay {
                    PathType::Relay
                } else {
                    PathType::Direct
                };
                PathCandidate {
                    addr: c.addr,
                    rtt: c.measured_rtt.unwrap_or(Duration::from_secs(1)),
                    path_type,
                }
            })
            .collect();

        let current = self.selected_path.as_ref().map(|addr| {
            let candidate = self.local_candidates.values()
                .find(|c| c.addr == *addr);
            PathCandidate {
                addr: *addr,
                rtt: candidate
                    .and_then(|c| c.measured_rtt)
                    .unwrap_or(Duration::from_secs(1)),
                path_type: if candidate.map(|c| c.source == CandidateSource::Relay).unwrap_or(false) {
                    PathType::Relay
                } else {
                    PathType::Direct
                },
            }
        });

        select_best_path(&candidates, current.as_ref())
            .map(|p| p.addr)
    }
}
```

#### Step 2.1.4: Verify

```bash
cargo test path_selection -- --nocapture
cargo test select_best -- --nocapture
cargo clippy --all-targets -- -D warnings
```

---

### 2.2 Redundant Path Closure

**Problem**: All paths kept open, wasting resources.

**Reference**: iroh's `close_redundant_paths` in `remote_state.rs:1001-1026`

#### Step 2.2.1: Write Tests First

Create: `/src/redundant_path_tests.rs`

```rust
//! Tests for redundant path closure
//!
//! Verifies:
//! 1. Redundant paths are closed when best path selected
//! 2. At least one backup path is kept
//! 3. Relay paths are never closed (fallback)
//! 4. Only client closes paths (not server)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_closes_redundant_direct_paths() {
        let mut manager = PathManager::new();

        // Add multiple direct paths
        manager.add_path(path_direct("192.168.1.1:5000"));
        manager.add_path(path_direct("192.168.1.2:5000"));
        manager.add_path(path_direct("192.168.1.3:5000"));

        // Select best path
        let best = "192.168.1.2:5000".parse().unwrap();
        manager.set_selected_path(best);

        // Close redundant
        let closed = manager.close_redundant_paths();

        // Should close 1 path (keep selected + 1 backup)
        assert_eq!(closed.len(), 1);
        assert!(!closed.contains(&best));
    }

    #[test]
    fn test_keeps_at_least_one_direct_backup() {
        let mut manager = PathManager::new();

        manager.add_path(path_direct("192.168.1.1:5000"));
        manager.add_path(path_direct("192.168.1.2:5000"));

        let best = "192.168.1.1:5000".parse().unwrap();
        manager.set_selected_path(best);

        let closed = manager.close_redundant_paths();

        // Should keep the backup (only 2 paths, keep both)
        assert_eq!(closed.len(), 0);
    }

    #[test]
    fn test_never_closes_relay_paths() {
        let mut manager = PathManager::new();

        manager.add_path(path_direct("192.168.1.1:5000"));
        manager.add_path(path_relay("relay.example.com:443"));
        manager.add_path(path_relay("relay2.example.com:443"));

        let best = "192.168.1.1:5000".parse().unwrap();
        manager.set_selected_path(best);

        let closed = manager.close_redundant_paths();

        // Relay paths should never be closed
        for addr in &closed {
            assert!(!manager.is_relay_path(addr));
        }
    }

    #[test]
    fn test_does_not_close_last_direct_path() {
        let mut manager = PathManager::new();

        manager.add_path(path_direct("192.168.1.1:5000"));
        manager.add_path(path_relay("relay.example.com:443"));

        let best = "192.168.1.1:5000".parse().unwrap();
        manager.set_selected_path(best);

        let closed = manager.close_redundant_paths();

        // Should not close only direct path
        assert!(closed.is_empty());
        assert_eq!(manager.direct_path_count(), 1);
    }

    fn path_direct(addr: &str) -> PathInfo {
        PathInfo {
            addr: addr.parse().unwrap(),
            path_type: PathType::Direct,
        }
    }

    fn path_relay(addr: &str) -> PathInfo {
        PathInfo {
            addr: addr.parse().unwrap(),
            path_type: PathType::Relay,
        }
    }
}
```

#### Step 2.2.2: Implement Redundant Path Closure

Add to: `/src/path_selection.rs`

```rust
/// Manager for tracking and closing redundant paths
#[derive(Debug)]
pub struct PathManager {
    paths: HashMap<SocketAddr, PathInfo>,
    selected_path: Option<SocketAddr>,
    min_direct_paths: usize,
}

#[derive(Debug, Clone)]
pub struct PathInfo {
    pub addr: SocketAddr,
    pub path_type: PathType,
    pub rtt: Option<Duration>,
    pub is_open: bool,
}

impl PathManager {
    pub fn new() -> Self {
        Self {
            paths: HashMap::new(),
            selected_path: None,
            min_direct_paths: 2, // Keep selected + 1 backup
        }
    }

    /// Add a path
    pub fn add_path(&mut self, info: PathInfo) {
        self.paths.insert(info.addr, info);
    }

    /// Set the selected (best) path
    pub fn set_selected_path(&mut self, addr: SocketAddr) {
        self.selected_path = Some(addr);
    }

    /// Close redundant paths, returning list of closed addresses
    ///
    /// Rules (from iroh):
    /// 1. Only close direct paths (never relay - they're fallback)
    /// 2. Don't close the selected path
    /// 3. Keep at least min_direct_paths direct paths open
    pub fn close_redundant_paths(&mut self) -> Vec<SocketAddr> {
        let Some(selected) = self.selected_path else {
            return Vec::new();
        };

        // Count open direct paths
        let open_direct: Vec<_> = self.paths.iter()
            .filter(|(_, p)| p.path_type == PathType::Direct && p.is_open)
            .map(|(addr, _)| *addr)
            .collect();

        // Don't close if at or below minimum
        if open_direct.len() <= self.min_direct_paths {
            return Vec::new();
        }

        // Close excess direct paths (not selected, not last backup)
        let mut to_close = Vec::new();
        let excess = open_direct.len() - self.min_direct_paths;

        for addr in open_direct {
            if to_close.len() >= excess {
                break;
            }
            if addr != selected {
                to_close.push(addr);
            }
        }

        // Mark as closed
        for addr in &to_close {
            if let Some(path) = self.paths.get_mut(addr) {
                path.is_open = false;
            }
        }

        tracing::debug!(
            closed = to_close.len(),
            remaining = self.direct_path_count(),
            "Closed redundant paths"
        );

        to_close
    }

    /// Count of open direct paths
    pub fn direct_path_count(&self) -> usize {
        self.paths.values()
            .filter(|p| p.path_type == PathType::Direct && p.is_open)
            .count()
    }

    /// Check if a path is a relay path
    pub fn is_relay_path(&self, addr: &SocketAddr) -> bool {
        self.paths.get(addr)
            .map(|p| p.path_type == PathType::Relay)
            .unwrap_or(false)
    }
}
```

#### Step 2.2.3: Verify

```bash
cargo test redundant_path -- --nocapture
cargo clippy --all-targets -- -D warnings
```

---

## Phase 3: State Management (Week 3)

### 3.1 Watchable State Pattern

**Problem**: `Arc<RwLock<>>` causes lock contention; consumers must poll.

**Reference**: iroh's `n0_watcher::Watchable`

#### Step 3.1.1: Write Tests First

Create: `/src/watchable_tests.rs`

```rust
//! Tests for Watchable state pattern
//!
//! Verifies:
//! 1. Current value accessible without blocking
//! 2. Watchers notified on change
//! 3. Multiple watchers supported
//! 4. No missed updates

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::time::{timeout, Duration};

    #[test]
    fn test_get_returns_current_value() {
        let watchable = Watchable::new(42);
        assert_eq!(watchable.get(), 42);
    }

    #[test]
    fn test_set_updates_value() {
        let watchable = Watchable::new(0);
        watchable.set(100);
        assert_eq!(watchable.get(), 100);
    }

    #[tokio::test]
    async fn test_watch_notified_on_change() {
        let watchable = Arc::new(Watchable::new(0));
        let mut watcher = watchable.watch();

        // Spawn task to update value
        let w = watchable.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            w.set(42);
        });

        // Wait for change
        let result = timeout(Duration::from_millis(100), watcher.changed()).await;
        assert!(result.is_ok());
        assert_eq!(watcher.borrow(), 42);
    }

    #[tokio::test]
    async fn test_multiple_watchers() {
        let watchable = Arc::new(Watchable::new(0));
        let mut watcher1 = watchable.watch();
        let mut watcher2 = watchable.watch();

        watchable.set(99);

        // Both watchers should see the change
        let r1 = timeout(Duration::from_millis(50), watcher1.changed()).await;
        let r2 = timeout(Duration::from_millis(50), watcher2.changed()).await;

        assert!(r1.is_ok());
        assert!(r2.is_ok());
        assert_eq!(watcher1.borrow(), 99);
        assert_eq!(watcher2.borrow(), 99);
    }

    #[test]
    fn test_watch_borrow_returns_current() {
        let watchable = Watchable::new("hello");
        let watcher = watchable.watch();
        assert_eq!(watcher.borrow(), "hello");

        watchable.set("world");
        // borrow() returns current even without calling changed()
        assert_eq!(watcher.borrow(), "world");
    }

    #[tokio::test]
    async fn test_no_notification_if_value_unchanged() {
        let watchable = Watchable::new(42);
        let mut watcher = watchable.watch();

        // Set to same value
        watchable.set(42);

        // Should not trigger notification (or timeout)
        let result = timeout(Duration::from_millis(50), watcher.changed()).await;
        // Depending on implementation, this might timeout or return immediately
        // The key is that calling set with same value shouldn't cause issues
    }

    #[test]
    fn test_watchable_with_option() {
        let watchable: Watchable<Option<String>> = Watchable::new(None);
        assert_eq!(watchable.get(), None);

        watchable.set(Some("test".to_string()));
        assert_eq!(watchable.get(), Some("test".to_string()));
    }
}
```

#### Step 3.1.2: Implement Watchable

Create: `/src/watchable.rs`

```rust
//! Watchable state pattern
//!
//! Provides reactive state observation without polling or lock contention.
//! Based on tokio::sync::watch but with a cleaner API.

use std::ops::Deref;
use std::sync::Arc;
use tokio::sync::watch;

/// A value that can be watched for changes
#[derive(Debug)]
pub struct Watchable<T> {
    sender: watch::Sender<T>,
}

impl<T: Clone + Send + Sync + 'static> Watchable<T> {
    /// Create a new watchable with initial value
    pub fn new(value: T) -> Self {
        let (sender, _) = watch::channel(value);
        Self { sender }
    }

    /// Get the current value
    pub fn get(&self) -> T {
        self.sender.borrow().clone()
    }

    /// Set a new value, notifying all watchers
    pub fn set(&self, value: T) {
        // send() only fails if there are no receivers, which is fine
        let _ = self.sender.send(value);
    }

    /// Modify the value in place
    pub fn modify<F>(&self, f: F)
    where
        F: FnOnce(&mut T),
    {
        self.sender.send_modify(f);
    }

    /// Create a watcher for this value
    pub fn watch(&self) -> Watcher<T> {
        Watcher {
            receiver: self.sender.subscribe(),
        }
    }

    /// Get a reference to the sender (for advanced use cases)
    pub fn sender(&self) -> &watch::Sender<T> {
        &self.sender
    }
}

impl<T: Clone + Default + Send + Sync + 'static> Default for Watchable<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

/// A watcher that receives updates from a Watchable
#[derive(Debug)]
pub struct Watcher<T> {
    receiver: watch::Receiver<T>,
}

impl<T: Clone> Watcher<T> {
    /// Wait for the value to change
    ///
    /// Returns `Ok(())` when the value has changed, or `Err` if the
    /// sender was dropped.
    pub async fn changed(&mut self) -> Result<(), watch::error::RecvError> {
        self.receiver.changed().await
    }

    /// Get the current value
    pub fn borrow(&self) -> T {
        self.receiver.borrow().clone()
    }

    /// Get a reference to the current value
    pub fn borrow_ref(&self) -> impl Deref<Target = T> + '_ {
        self.receiver.borrow()
    }

    /// Check if the value has changed since last check
    pub fn has_changed(&self) -> bool {
        self.receiver.has_changed().unwrap_or(false)
    }
}

impl<T: Clone> Clone for Watcher<T> {
    fn clone(&self) -> Self {
        Self {
            receiver: self.receiver.clone(),
        }
    }
}

/// Extension to combine multiple watchers
pub struct CombinedWatcher<T1, T2> {
    watcher1: Watcher<T1>,
    watcher2: Watcher<T2>,
}

impl<T1: Clone, T2: Clone> CombinedWatcher<T1, T2> {
    pub fn new(watcher1: Watcher<T1>, watcher2: Watcher<T2>) -> Self {
        Self { watcher1, watcher2 }
    }

    /// Wait for either value to change
    pub async fn changed(&mut self) -> Result<(), watch::error::RecvError> {
        tokio::select! {
            result = self.watcher1.changed() => result,
            result = self.watcher2.changed() => result,
        }
    }

    /// Get both current values
    pub fn borrow(&self) -> (T1, T2) {
        (self.watcher1.borrow(), self.watcher2.borrow())
    }
}

#[cfg(test)]
mod tests;
```

#### Step 3.1.3: Apply to Key State

Edit: `/src/nat_traversal_api.rs`

```rust
use crate::watchable::Watchable;

// Replace these fields in NatTraversalEndpoint:
// OLD:
// external_addr: Arc<RwLock<Option<SocketAddr>>>,
// selected_path: Arc<RwLock<Option<SocketAddr>>>,

// NEW:
pub struct NatTraversalEndpoint {
    // ... other fields ...
    external_addr: Watchable<Option<SocketAddr>>,
    selected_path: Watchable<Option<SocketAddr>>,
}

impl NatTraversalEndpoint {
    /// Get the current external address
    pub fn external_address(&self) -> Option<SocketAddr> {
        self.external_addr.get()
    }

    /// Watch for external address changes
    pub fn watch_external_address(&self) -> Watcher<Option<SocketAddr>> {
        self.external_addr.watch()
    }

    /// Get the current selected path
    pub fn selected_path(&self) -> Option<SocketAddr> {
        self.selected_path.get()
    }

    /// Watch for selected path changes
    pub fn watch_selected_path(&self) -> Watcher<Option<SocketAddr>> {
        self.selected_path.watch()
    }

    // Internal setter
    fn set_external_address(&self, addr: Option<SocketAddr>) {
        self.external_addr.set(addr);
        tracing::info!(?addr, "External address updated");
    }
}
```

#### Step 3.1.4: Verify

```bash
cargo test watchable -- --nocapture
cargo clippy --all-targets -- -D warnings
```

---

### 3.2 Fair Transport Polling

**Problem**: No explicit fairness in transport polling.

**Reference**: iroh's `poll_recv` in `transports.rs:180-216`

#### Step 3.2.1: Write Tests First

Create: `/src/fair_polling_tests.rs`

```rust
//! Tests for fair transport polling
//!
//! Verifies:
//! 1. Alternating poll direction prevents starvation
//! 2. Both transports get fair access
//! 3. Counter wraps correctly

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alternating_poll_order() {
        let mut poller = FairPoller::new();

        let order1 = poller.poll_order();
        let order2 = poller.poll_order();
        let order3 = poller.poll_order();

        // Should alternate
        assert_ne!(order1, order2);
        assert_eq!(order1, order3);
    }

    #[test]
    fn test_counter_wraps() {
        let mut poller = FairPoller::new();

        // Set counter near max
        poller.set_counter(u64::MAX);

        // Should wrap without panic
        let _ = poller.poll_order();
        let _ = poller.poll_order();
    }

    #[test]
    fn test_poll_order_is_opposite() {
        let mut poller = FairPoller::new();

        // Even counter: direct first
        poller.set_counter(0);
        assert_eq!(poller.poll_order(), PollOrder::DirectFirst);

        // Odd counter: relay first
        poller.set_counter(1);
        assert_eq!(poller.poll_order(), PollOrder::RelayFirst);
    }
}
```

#### Step 3.2.2: Implement Fair Polling

Create: `/src/fair_polling.rs`

```rust
//! Fair polling for multiple transports
//!
//! Prevents starvation by alternating poll order.

use std::sync::atomic::{AtomicU64, Ordering};

/// Order in which to poll transports
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollOrder {
    /// Poll direct transports first, then relay
    DirectFirst,
    /// Poll relay transports first, then direct
    RelayFirst,
}

/// Fair poller that alternates poll order
#[derive(Debug)]
pub struct FairPoller {
    counter: AtomicU64,
}

impl FairPoller {
    pub fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
        }
    }

    /// Get the poll order for this iteration
    ///
    /// Increments counter and returns appropriate order.
    pub fn poll_order(&self) -> PollOrder {
        let count = self.counter.fetch_add(1, Ordering::Relaxed);
        if count % 2 == 0 {
            PollOrder::DirectFirst
        } else {
            PollOrder::RelayFirst
        }
    }

    /// Set counter (for testing)
    #[cfg(test)]
    pub fn set_counter(&self, value: u64) {
        self.counter.store(value, Ordering::Relaxed);
    }
}

impl Default for FairPoller {
    fn default() -> Self {
        Self::new()
    }
}

/// Macro to poll transports in fair order
#[macro_export]
macro_rules! poll_transports_fair {
    ($poller:expr, $direct:expr, $relay:expr) => {{
        match $poller.poll_order() {
            PollOrder::DirectFirst => {
                if let Some(result) = $direct {
                    return result;
                }
                if let Some(result) = $relay {
                    return result;
                }
            }
            PollOrder::RelayFirst => {
                if let Some(result) = $relay {
                    return result;
                }
                if let Some(result) = $direct {
                    return result;
                }
            }
        }
    }};
}

#[cfg(test)]
mod tests;
```

#### Step 3.2.3: Verify

```bash
cargo test fair_polling -- --nocapture
cargo clippy --all-targets -- -D warnings
```

---

## Phase 4: Transport & Discovery (Week 4)

### 4.1 Graceful Transport Degradation

**Problem**: Transport errors interrupt flows.

**Reference**: iroh returns `Ok(())` for unsupported transports.

#### Step 4.1.1: Implement

Edit transport layer to return `Ok(())` for unsupported destinations rather than errors.

### 4.2 Discovery Stream Composition

**Problem**: Discovery sources intermingled in code.

**Reference**: iroh's `Discovery` trait and `ConcurrentDiscovery`.

Create trait-based discovery with stream composition.

---

## Phase 5: Observability (Week 5)

### 5.1 Structured Events

Add consistent event logging with structured fields.

### 5.2 Actor Tick Metrics

Add counters for each actor/loop iteration to monitor fairness.

---

## Testing Strategy

### Unit Test Coverage Targets

| Module | Target Coverage |
|--------|-----------------|
| `bounded_pending_buffer` | 90% |
| `path_selection` | 95% |
| `shutdown` | 85% |
| `watchable` | 90% |
| `fair_polling` | 95% |
| `candidate_pruning` | 90% |

### Integration Tests

Create: `/tests/integration/`

```rust
// tests/integration/path_selection_integration.rs
#[tokio::test]
async fn test_path_selection_under_load() {
    // Create two endpoints
    // Generate traffic
    // Verify path selection adapts to RTT changes
}

// tests/integration/shutdown_integration.rs
#[tokio::test]
async fn test_shutdown_with_active_connections() {
    // Create endpoints with active connections
    // Initiate shutdown
    // Verify clean termination
}
```

### Property-Based Tests

```rust
// tests/property_tests/path_selection_props.rs
proptest! {
    #[test]
    fn path_selection_always_returns_valid_path(
        paths in prop::collection::vec(path_strategy(), 1..50),
    ) {
        let result = select_best_path(&paths, None);
        prop_assert!(result.is_some());
        prop_assert!(paths.iter().any(|p| p.addr == result.unwrap().addr));
    }
}
```

### Benchmark Tests

```rust
// benches/path_selection_bench.rs
fn benchmark_path_selection(c: &mut Criterion) {
    let paths: Vec<_> = (0..100)
        .map(|i| PathCandidate::new(
            format!("192.168.1.{}:5000", i).parse().unwrap(),
            Duration::from_millis(i as u64 * 10),
        ))
        .collect();

    c.bench_function("select_best_path_100", |b| {
        b.iter(|| select_best_path(black_box(&paths), None))
    });
}
```

---

## Migration Guide

### Breaking Changes

1. **`pending_data` type change**:
   - Old: `Arc<RwLock<HashMap<PeerId, VecDeque<Vec<u8>>>>>`
   - New: `Arc<RwLock<BoundedPendingBuffer>>`
   - Action: Update any code directly accessing this field

2. **Shutdown API**:
   - Old: `drop(endpoint)`
   - New: `endpoint.shutdown().await`
   - Action: Update teardown code to call explicit shutdown

3. **External address access**:
   - Old: `endpoint.external_addr.read().await`
   - New: `endpoint.external_address()` or `endpoint.watch_external_address()`
   - Action: Update to new API

### Deprecation Timeline

| Feature | Deprecated | Removed |
|---------|------------|---------|
| Direct `pending_data` access | v0.14.0 | v0.15.0 |
| Implicit shutdown | v0.14.0 | v0.15.0 |
| Lock-based state access | v0.14.0 | v0.16.0 |

---

## Appendix: Reference Code

### iroh Files Referenced

| Pattern | iroh File | Lines |
|---------|-----------|-------|
| Path selection | `magicsock/remote_map/remote_state.rs` | 908-1105 |
| Fair polling | `magicsock/transports.rs` | 180-216 |
| Shutdown | `magicsock.rs` | 982-1038 |
| Path pruning | `magicsock/remote_map/path_state.rs` | 17-24 |
| Redundant closure | `magicsock/remote_map/remote_state.rs` | 1001-1026 |

### Commands Reference

```bash
# Run all tests
cargo test

# Run specific phase tests
cargo test bounded_pending_buffer
cargo test path_selection
cargo test shutdown
cargo test watchable
cargo test fair_polling

# Run with coverage
cargo tarpaulin --out Html

# Run benchmarks
cargo bench

# Lint check
cargo clippy --all-targets --all-features -- -D warnings

# Format check
cargo fmt --all -- --check
```

---

## Checklist

### Phase 1 Completion Criteria
- [ ] `BoundedPendingBuffer` implemented with tests
- [ ] Candidate pruning limits enforced
- [ ] Graceful shutdown coordinator working
- [ ] All Phase 1 tests passing
- [ ] No new warnings introduced

### Phase 2 Completion Criteria
- [ ] RTT-based path selection with hysteresis
- [ ] Redundant path closure implemented
- [ ] Path manager tests passing
- [ ] Integration tests for path switching

### Phase 3 Completion Criteria
- [ ] Watchable pattern implemented
- [ ] Key state converted to Watchable
- [ ] Fair polling implemented
- [ ] No lock contention in hot paths

### Phase 4 Completion Criteria
- [ ] Graceful transport degradation
- [ ] Discovery trait defined
- [ ] Stream-based discovery composition

### Phase 5 Completion Criteria
- [ ] Structured events throughout
- [ ] Actor tick metrics added
- [ ] Observability dashboard updated

---

*Document created: December 19, 2024*
*Based on analysis of iroh v0.95.1 and ant-quic v0.13.0*
