//! Test packet protocol for measuring connectivity.
//!
//! Implements a simple 5KB test packet exchange protocol to verify
//! connectivity and measure round-trip times.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

/// Size of test packet payload (approximately 5KB total with headers).
pub const TEST_PAYLOAD_SIZE: usize = 5000;

/// Magic bytes to identify test packets.
pub const TEST_PACKET_MAGIC: [u8; 4] = *b"TEST";

/// Test packet type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PacketType {
    /// Ping request - sender expects a pong response.
    Ping = 0,
    /// Pong response - acknowledges a ping.
    Pong = 1,
}

/// A 5KB test packet for connectivity verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestPacket {
    /// Magic bytes to identify test packets.
    pub magic: [u8; 4],
    /// Packet type (ping/pong).
    pub packet_type: PacketType,
    /// Sequence number for ordering.
    pub sequence: u64,
    /// Timestamp in nanoseconds since epoch.
    pub timestamp_ns: u64,
    /// Sender's peer ID (32 bytes).
    pub sender_id: [u8; 32],
    /// Random payload to reach ~5KB.
    pub payload: Vec<u8>,
    /// SHA-256 checksum of the packet contents.
    pub checksum: [u8; 32],
}

impl TestPacket {
    /// Create a new ping packet.
    pub fn new_ping(sender_id: [u8; 32], sequence: u64) -> Self {
        let mut packet = Self {
            magic: TEST_PACKET_MAGIC,
            packet_type: PacketType::Ping,
            sequence,
            timestamp_ns: current_timestamp_ns(),
            sender_id,
            payload: generate_random_payload(),
            checksum: [0u8; 32],
        };
        packet.checksum = packet.calculate_checksum();
        packet
    }

    /// Create a pong response from a ping.
    pub fn create_pong(&self, sender_id: [u8; 32]) -> Self {
        let mut packet = Self {
            magic: TEST_PACKET_MAGIC,
            packet_type: PacketType::Pong,
            sequence: self.sequence,
            timestamp_ns: current_timestamp_ns(),
            sender_id,
            payload: generate_random_payload(),
            checksum: [0u8; 32],
        };
        packet.checksum = packet.calculate_checksum();
        packet
    }

    /// Calculate the checksum for this packet.
    fn calculate_checksum(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.magic);
        hasher.update([self.packet_type as u8]);
        hasher.update(self.sequence.to_le_bytes());
        hasher.update(self.timestamp_ns.to_le_bytes());
        hasher.update(self.sender_id);
        hasher.update(&self.payload);
        hasher.finalize().into()
    }

    /// Verify the packet checksum.
    pub fn verify_checksum(&self) -> bool {
        self.checksum == self.calculate_checksum()
    }

    /// Get the packet size in bytes.
    pub fn size(&self) -> usize {
        // Approximate: 4 (magic) + 1 (type) + 8 (seq) + 8 (ts) + 32 (id) + payload + 32 (checksum)
        4 + 1 + 8 + 8 + 32 + self.payload.len() + 32
    }

    /// Serialize to bytes for transmission.
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }
}

/// Result of a test packet exchange.
#[derive(Debug, Clone)]
pub struct TestResult {
    /// Sequence number of the test.
    pub sequence: u64,
    /// Round-trip time.
    pub rtt: Duration,
    /// Whether the test was successful.
    pub success: bool,
    /// Error message if failed.
    pub error: Option<String>,
    /// Timestamp when the test was performed.
    pub timestamp: Instant,
}

impl TestResult {
    /// Create a successful test result.
    pub fn success(sequence: u64, rtt: Duration) -> Self {
        Self {
            sequence,
            rtt,
            success: true,
            error: None,
            timestamp: Instant::now(),
        }
    }

    /// Create a failed test result.
    pub fn failure(sequence: u64, error: String) -> Self {
        Self {
            sequence,
            rtt: Duration::ZERO,
            success: false,
            error: Some(error),
            timestamp: Instant::now(),
        }
    }
}

/// Generate random payload data.
fn generate_random_payload() -> Vec<u8> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..TEST_PAYLOAD_SIZE).map(|_| rng.r#gen()).collect()
}

/// Get current timestamp in nanoseconds.
fn current_timestamp_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ping_packet_creation() {
        let sender_id = [42u8; 32];
        let packet = TestPacket::new_ping(sender_id, 1);

        assert_eq!(packet.magic, TEST_PACKET_MAGIC);
        assert_eq!(packet.packet_type, PacketType::Ping);
        assert_eq!(packet.sequence, 1);
        assert_eq!(packet.sender_id, sender_id);
        assert!(packet.verify_checksum());
    }

    #[test]
    fn test_pong_response() {
        let sender_a = [1u8; 32];
        let sender_b = [2u8; 32];
        let ping = TestPacket::new_ping(sender_a, 1);
        let pong = ping.create_pong(sender_b);

        assert_eq!(pong.packet_type, PacketType::Pong);
        assert_eq!(pong.sequence, ping.sequence);
        assert_eq!(pong.sender_id, sender_b);
        assert!(pong.verify_checksum());
    }

    #[test]
    fn test_packet_size() {
        let sender_id = [0u8; 32];
        let packet = TestPacket::new_ping(sender_id, 0);
        // Should be approximately 5KB
        assert!(packet.size() > 5000);
        assert!(packet.size() < 6000);
    }

    #[test]
    fn test_serialization() {
        let sender_id = [42u8; 32];
        let packet = TestPacket::new_ping(sender_id, 100);
        let bytes = packet.to_bytes().expect("serialization failed");
        let restored = TestPacket::from_bytes(&bytes).expect("deserialization failed");

        assert_eq!(restored.sequence, packet.sequence);
        assert_eq!(restored.sender_id, sender_id);
        assert!(restored.verify_checksum());
    }
}
