// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Core types for the constrained protocol engine
//!
//! This module defines fundamental types used throughout the constrained protocol:
//! - [`ConnectionId`] - Unique identifier for connections
//! - [`SequenceNumber`] - Packet sequence tracking
//! - [`PacketType`] - Distinguishes control vs data packets
//! - [`ConstrainedError`] - Error handling

use std::fmt;
use thiserror::Error;

/// Connection identifier for the constrained protocol
///
/// A 16-bit identifier that uniquely identifies a connection between two peers.
/// Connection IDs are locally generated and do not need to be globally unique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId(pub u16);

impl ConnectionId {
    /// Create a new connection ID from raw value
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Get the raw u16 value
    pub const fn value(self) -> u16 {
        self.0
    }

    /// Serialize to bytes (big-endian)
    pub const fn to_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }

    /// Deserialize from bytes (big-endian)
    pub const fn from_bytes(bytes: [u8; 2]) -> Self {
        Self(u16::from_be_bytes(bytes))
    }

    /// Generate a random connection ID
    pub fn random() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u16;
        Self(seed ^ 0x5A5A) // XOR with pattern for better distribution
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CID:{:04X}", self.0)
    }
}

/// Sequence number for packet ordering and acknowledgment
///
/// An 8-bit sequence number that wraps around at 255. The constrained protocol
/// uses a sliding window to handle wrap-around correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SequenceNumber(pub u8);

impl SequenceNumber {
    /// Create a new sequence number
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    /// Get the raw u8 value
    pub const fn value(self) -> u8 {
        self.0
    }

    /// Increment the sequence number (wrapping at 255)
    pub const fn next(self) -> Self {
        Self(self.0.wrapping_add(1))
    }

    /// Calculate distance from self to other (considering wrap-around)
    ///
    /// Returns positive if other is ahead, negative if behind.
    /// Assumes window size is less than 128.
    pub fn distance_to(self, other: Self) -> i16 {
        let diff = other.0.wrapping_sub(self.0) as i8;
        diff as i16
    }

    /// Check if other is within the valid window ahead of self
    pub fn is_in_window(self, other: Self, window_size: u8) -> bool {
        let dist = self.distance_to(other);
        dist >= 0 && dist <= window_size as i16
    }
}

impl fmt::Display for SequenceNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SEQ:{}", self.0)
    }
}

/// Packet type flags for the constrained protocol
///
/// These flags are combined in a single byte in the packet header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    /// Connection request (SYN)
    Syn = 0x01,
    /// Acknowledgment (ACK)
    Ack = 0x02,
    /// Connection close (FIN)
    Fin = 0x04,
    /// Connection reset (RST)
    Reset = 0x08,
    /// Data packet
    Data = 0x10,
    /// Keep-alive ping
    Ping = 0x20,
    /// Pong response to ping
    Pong = 0x40,
}

impl PacketType {
    /// Get the flag value for this packet type
    pub const fn flag(self) -> u8 {
        self as u8
    }
}

/// Packet flags combining multiple packet types
///
/// A packet can have multiple flags set (e.g., SYN+ACK).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PacketFlags(pub u8);

impl PacketFlags {
    /// No flags set
    pub const NONE: Self = Self(0);

    /// SYN flag
    pub const SYN: Self = Self(0x01);
    /// ACK flag
    pub const ACK: Self = Self(0x02);
    /// FIN flag
    pub const FIN: Self = Self(0x04);
    /// RST flag
    pub const RST: Self = Self(0x08);
    /// DATA flag
    pub const DATA: Self = Self(0x10);
    /// PING flag
    pub const PING: Self = Self(0x20);
    /// PONG flag
    pub const PONG: Self = Self(0x40);

    /// SYN+ACK combination
    pub const SYN_ACK: Self = Self(0x03);

    /// Create flags from raw value
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    /// Get raw value
    pub const fn value(self) -> u8 {
        self.0
    }

    /// Check if a specific flag is set
    pub const fn has(self, flag: PacketType) -> bool {
        self.0 & (flag as u8) != 0
    }

    /// Check if SYN flag is set
    pub const fn is_syn(self) -> bool {
        self.0 & 0x01 != 0
    }

    /// Check if ACK flag is set
    pub const fn is_ack(self) -> bool {
        self.0 & 0x02 != 0
    }

    /// Check if FIN flag is set
    pub const fn is_fin(self) -> bool {
        self.0 & 0x04 != 0
    }

    /// Check if RST flag is set
    pub const fn is_rst(self) -> bool {
        self.0 & 0x08 != 0
    }

    /// Check if DATA flag is set
    pub const fn is_data(self) -> bool {
        self.0 & 0x10 != 0
    }

    /// Check if PING flag is set
    pub const fn is_ping(self) -> bool {
        self.0 & 0x20 != 0
    }

    /// Check if PONG flag is set
    pub const fn is_pong(self) -> bool {
        self.0 & 0x40 != 0
    }

    /// Combine with another flag
    pub const fn with(self, flag: PacketType) -> Self {
        Self(self.0 | flag as u8)
    }

    /// Combine two flag sets
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl fmt::Display for PacketFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut flags = Vec::new();
        if self.is_syn() {
            flags.push("SYN");
        }
        if self.is_ack() {
            flags.push("ACK");
        }
        if self.is_fin() {
            flags.push("FIN");
        }
        if self.is_rst() {
            flags.push("RST");
        }
        if self.is_data() {
            flags.push("DATA");
        }
        if self.is_ping() {
            flags.push("PING");
        }
        if self.is_pong() {
            flags.push("PONG");
        }
        if flags.is_empty() {
            write!(f, "NONE")
        } else {
            write!(f, "{}", flags.join("|"))
        }
    }
}

/// Errors that can occur in the constrained protocol
#[derive(Debug, Error)]
pub enum ConstrainedError {
    /// Packet too small to contain header
    #[error("packet too small: expected at least {expected} bytes, got {actual}")]
    PacketTooSmall {
        /// Minimum expected size in bytes
        expected: usize,
        /// Actual size received
        actual: usize,
    },

    /// Invalid header format
    #[error("invalid header: {0}")]
    InvalidHeader(String),

    /// Connection not found
    #[error("connection not found: {0}")]
    ConnectionNotFound(ConnectionId),

    /// Connection already exists
    #[error("connection already exists: {0}")]
    ConnectionExists(ConnectionId),

    /// Invalid state transition
    #[error("invalid state transition from {from} to {to}")]
    InvalidStateTransition {
        /// Current state name
        from: String,
        /// Attempted target state
        to: String,
    },

    /// Connection reset by peer
    #[error("connection reset by peer")]
    ConnectionReset,

    /// Connection timed out
    #[error("connection timed out")]
    Timeout,

    /// Maximum retransmissions exceeded
    #[error("maximum retransmissions exceeded ({count})")]
    MaxRetransmissions {
        /// Number of retransmissions attempted
        count: u32,
    },

    /// Send buffer full
    #[error("send buffer full")]
    SendBufferFull,

    /// Receive buffer full
    #[error("receive buffer full")]
    ReceiveBufferFull,

    /// Transport error
    #[error("transport error: {0}")]
    Transport(String),

    /// Sequence number out of window
    #[error("sequence number {seq} out of window (expected {expected_min}-{expected_max})")]
    SequenceOutOfWindow {
        /// Received sequence number
        seq: u8,
        /// Minimum expected sequence number
        expected_min: u8,
        /// Maximum expected sequence number
        expected_max: u8,
    },

    /// Connection closed
    #[error("connection closed")]
    ConnectionClosed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_id() {
        let cid = ConnectionId::new(0x1234);
        assert_eq!(cid.value(), 0x1234);
        assert_eq!(cid.to_bytes(), [0x12, 0x34]);
        assert_eq!(ConnectionId::from_bytes([0x12, 0x34]), cid);
    }

    #[test]
    fn test_connection_id_display() {
        let cid = ConnectionId::new(0xABCD);
        assert_eq!(format!("{}", cid), "CID:ABCD");
    }

    #[test]
    fn test_connection_id_random() {
        let cid1 = ConnectionId::random();
        let cid2 = ConnectionId::random();
        // Random IDs should be different (with very high probability)
        // But we can't guarantee it in a test, so just verify they're valid
        assert!(cid1.value() != 0 || cid2.value() != 0);
    }

    #[test]
    fn test_sequence_number_next() {
        assert_eq!(SequenceNumber::new(0).next(), SequenceNumber::new(1));
        assert_eq!(SequenceNumber::new(254).next(), SequenceNumber::new(255));
        assert_eq!(SequenceNumber::new(255).next(), SequenceNumber::new(0));
    }

    #[test]
    fn test_sequence_number_distance() {
        let a = SequenceNumber::new(10);
        let b = SequenceNumber::new(15);
        assert_eq!(a.distance_to(b), 5);
        assert_eq!(b.distance_to(a), -5);

        // Wrap-around case
        let x = SequenceNumber::new(250);
        let y = SequenceNumber::new(5);
        assert_eq!(x.distance_to(y), 11); // 5 is 11 ahead of 250 (wrapping)
    }

    #[test]
    fn test_sequence_number_in_window() {
        let base = SequenceNumber::new(100);
        assert!(base.is_in_window(SequenceNumber::new(100), 16));
        assert!(base.is_in_window(SequenceNumber::new(110), 16));
        assert!(base.is_in_window(SequenceNumber::new(116), 16));
        assert!(!base.is_in_window(SequenceNumber::new(117), 16));
        assert!(!base.is_in_window(SequenceNumber::new(99), 16));
    }

    #[test]
    fn test_packet_flags() {
        let flags = PacketFlags::SYN;
        assert!(flags.is_syn());
        assert!(!flags.is_ack());

        let syn_ack = flags.with(PacketType::Ack);
        assert!(syn_ack.is_syn());
        assert!(syn_ack.is_ack());
        assert_eq!(syn_ack, PacketFlags::SYN_ACK);
    }

    #[test]
    fn test_packet_flags_display() {
        assert_eq!(format!("{}", PacketFlags::NONE), "NONE");
        assert_eq!(format!("{}", PacketFlags::SYN), "SYN");
        assert_eq!(format!("{}", PacketFlags::SYN_ACK), "SYN|ACK");
        assert_eq!(
            format!("{}", PacketFlags::DATA.with(PacketType::Ack)),
            "ACK|DATA"
        );
    }

    #[test]
    fn test_packet_flags_union() {
        let a = PacketFlags::SYN;
        let b = PacketFlags::DATA;
        let combined = a.union(b);
        assert!(combined.is_syn());
        assert!(combined.is_data());
        assert!(!combined.is_ack());
    }

    #[test]
    fn test_constrained_error_display() {
        let err = ConstrainedError::PacketTooSmall {
            expected: 5,
            actual: 3,
        };
        assert!(format!("{}", err).contains("expected at least 5 bytes"));

        let err = ConstrainedError::ConnectionNotFound(ConnectionId::new(0x1234));
        assert!(format!("{}", err).contains("CID:1234"));
    }
}
