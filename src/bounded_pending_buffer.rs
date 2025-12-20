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
    /// Total number of peers with pending data
    pub total_peers: usize,
    /// Total number of pending messages
    pub total_messages: usize,
    /// Total bytes stored in the buffer
    pub total_bytes: usize,
    /// Messages dropped due to buffer limits
    pub dropped_messages: u64,
    /// Messages expired due to TTL
    pub expired_messages: u64,
}

/// A bounded buffer for pending peer data with automatic expiration
#[derive(Debug)]
pub struct BoundedPendingBuffer {
    data: HashMap<PeerId, PeerPendingData>,
    max_bytes_per_peer: usize,
    max_messages_per_peer: usize,
    ttl: Duration,
    dropped_messages: u64,
    expired_messages: u64,
}

impl BoundedPendingBuffer {
    /// Create a new bounded pending buffer
    pub fn new(max_bytes_per_peer: usize, max_messages_per_peer: usize, ttl: Duration) -> Self {
        Self {
            data: HashMap::new(),
            max_bytes_per_peer,
            max_messages_per_peer,
            ttl,
            dropped_messages: 0,
            expired_messages: 0,
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
                self.dropped_messages += 1;
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

    /// Pop oldest data from any peer (returns peer_id and data)
    pub fn pop_any(&mut self) -> Option<(PeerId, Vec<u8>)> {
        // Find first peer with data
        let peer_id = *self.data.keys().next()?;
        let data = self.pop(&peer_id)?;
        Some((peer_id, data))
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
        self.data.get(peer_id).map(|d| d.entries.len()).unwrap_or(0)
    }

    /// Get total bytes for a peer
    pub fn total_bytes(&self, peer_id: &PeerId) -> usize {
        self.data.get(peer_id).map(|d| d.total_bytes).unwrap_or(0)
    }

    /// Clear all pending data for a peer
    pub fn clear_peer(&mut self, peer_id: &PeerId) {
        self.data.remove(peer_id);
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Remove expired entries across all peers
    pub fn cleanup_expired(&mut self) {
        let now = Instant::now();
        let ttl = self.ttl;

        self.data.retain(|_, peer_data| {
            let before_len = peer_data.entries.len();

            peer_data.entries.retain(|entry| {
                let is_valid = now.duration_since(entry.created_at) < ttl;
                if !is_valid {
                    peer_data.total_bytes = peer_data.total_bytes.saturating_sub(entry.data.len());
                }
                is_valid
            });

            let expired_count = before_len - peer_data.entries.len();
            self.expired_messages += expired_count as u64;

            !peer_data.entries.is_empty()
        });
    }

    /// Get buffer statistics
    pub fn stats(&self) -> PendingBufferStats {
        PendingBufferStats {
            total_peers: self.data.len(),
            total_messages: self.data.values().map(|d| d.entries.len()).sum(),
            total_bytes: self.data.values().map(|d| d.total_bytes).sum(),
            dropped_messages: self.dropped_messages,
            expired_messages: self.expired_messages,
        }
    }

    /// Iterate over peers with pending data (for recv() compatibility)
    pub fn iter_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.data.keys()
    }
}

impl Default for BoundedPendingBuffer {
    fn default() -> Self {
        Self::new(
            1024 * 1024, // 1MB per peer
            100,         // 100 messages per peer
            Duration::from_secs(30),
        )
    }
}

/// Errors from the pending buffer
#[derive(Debug, Clone)]
pub enum PendingBufferError {
    /// Message too large to fit in buffer
    MessageTooLarge {
        /// Size of the message
        size: usize,
        /// Maximum allowed size
        max: usize,
    },
}

impl std::fmt::Display for PendingBufferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MessageTooLarge { size, max } => {
                write!(
                    f,
                    "Message too large: {} bytes exceeds max {} bytes",
                    size, max
                )
            }
        }
    }
}

impl std::error::Error for PendingBufferError {}

#[cfg(test)]
mod tests {
    use super::*;

    // Constants for testing
    const MAX_PENDING_BYTES_PER_PEER: usize = 1024 * 1024; // 1MB
    const MAX_PENDING_MESSAGES_PER_PEER: usize = 100;
    const PENDING_DATA_TTL: Duration = Duration::from_secs(30);

    fn random_peer_id() -> PeerId {
        use std::time::SystemTime;
        let seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = ((seed >> (i % 16)) & 0xFF) as u8;
        }
        PeerId(bytes)
    }

    #[test]
    fn test_pending_buffer_enforces_byte_limit() {
        let mut buffer = BoundedPendingBuffer::new(
            MAX_PENDING_BYTES_PER_PEER,
            MAX_PENDING_MESSAGES_PER_PEER,
            PENDING_DATA_TTL,
        );

        let peer_id = random_peer_id();

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

        let peer_id = random_peer_id();

        // Add 10 messages
        for i in 0..10 {
            assert!(buffer.push(&peer_id, vec![i as u8]).is_ok());
        }

        // 11th message should drop oldest
        buffer
            .push(&peer_id, vec![10u8])
            .expect("push should succeed");
        assert_eq!(buffer.message_count(&peer_id), 10);

        // First message should be gone (was [0])
        let first = buffer.peek_oldest(&peer_id).expect("should have data");
        assert_eq!(first[0], 1u8); // Second message is now first
    }

    #[tokio::test]
    async fn test_pending_buffer_expires_old_entries() {
        let mut buffer = BoundedPendingBuffer::new(
            MAX_PENDING_BYTES_PER_PEER,
            MAX_PENDING_MESSAGES_PER_PEER,
            Duration::from_millis(50), // 50ms TTL for test
        );

        let peer_id = random_peer_id();
        buffer
            .push(&peer_id, vec![1, 2, 3])
            .expect("push should succeed");

        // Should exist immediately
        assert_eq!(buffer.message_count(&peer_id), 1);

        // Wait for expiry
        tokio::time::sleep(Duration::from_millis(100)).await;

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

        let peer_id = random_peer_id();
        buffer.push(&peer_id, vec![1]).expect("push should succeed");
        buffer.push(&peer_id, vec![2]).expect("push should succeed");
        buffer.push(&peer_id, vec![3]).expect("push should succeed");

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

        let peer_id = random_peer_id();
        buffer
            .push(&peer_id, vec![1, 2, 3])
            .expect("push should succeed");
        buffer
            .push(&peer_id, vec![4, 5, 6])
            .expect("push should succeed");

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

        let peer1 = PeerId([1u8; 32]);
        let peer2 = PeerId([2u8; 32]);

        buffer
            .push(&peer1, vec![1, 2, 3])
            .expect("push should succeed");
        buffer
            .push(&peer2, vec![4, 5])
            .expect("push should succeed");

        let stats = buffer.stats();
        assert_eq!(stats.total_peers, 2);
        assert_eq!(stats.total_messages, 2);
        assert_eq!(stats.total_bytes, 5);
    }

    #[test]
    fn test_pending_buffer_pop_any() {
        let mut buffer = BoundedPendingBuffer::new(
            MAX_PENDING_BYTES_PER_PEER,
            MAX_PENDING_MESSAGES_PER_PEER,
            PENDING_DATA_TTL,
        );

        let peer1 = PeerId([1u8; 32]);
        buffer
            .push(&peer1, vec![1, 2, 3])
            .expect("push should succeed");

        let result = buffer.pop_any();
        assert!(result.is_some());
        let (peer_id, data) = result.unwrap();
        assert_eq!(peer_id, peer1);
        assert_eq!(data, vec![1, 2, 3]);

        // Buffer should be empty now
        assert!(buffer.is_empty());
        assert!(buffer.pop_any().is_none());
    }

    #[test]
    fn test_pending_buffer_rejects_too_large_message() {
        let mut buffer = BoundedPendingBuffer::new(
            1000, // Max 1000 bytes per peer
            MAX_PENDING_MESSAGES_PER_PEER,
            PENDING_DATA_TTL,
        );

        let peer_id = random_peer_id();

        // Try to push a message larger than max
        let result = buffer.push(&peer_id, vec![0u8; 2000]);
        assert!(matches!(
            result,
            Err(PendingBufferError::MessageTooLarge { .. })
        ));
    }

    #[test]
    fn test_pending_buffer_dropped_count() {
        let mut buffer = BoundedPendingBuffer::new(
            MAX_PENDING_BYTES_PER_PEER,
            5, // Only 5 messages
            PENDING_DATA_TTL,
        );

        let peer_id = random_peer_id();

        // Add 5 messages
        for i in 0..5 {
            buffer.push(&peer_id, vec![i]).expect("push should succeed");
        }

        // Add 3 more, which should drop 3 oldest
        for i in 5..8 {
            buffer.push(&peer_id, vec![i]).expect("push should succeed");
        }

        let stats = buffer.stats();
        assert_eq!(stats.dropped_messages, 3);
        assert_eq!(stats.total_messages, 5);
    }

    #[test]
    fn test_pending_buffer_default() {
        let buffer = BoundedPendingBuffer::default();
        assert!(buffer.is_empty());
        let stats = buffer.stats();
        assert_eq!(stats.total_peers, 0);
        assert_eq!(stats.total_messages, 0);
    }
}
