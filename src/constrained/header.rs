// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Packet header format for the constrained protocol
//!
//! The constrained protocol uses a minimal 5-byte header designed for low-MTU transports:
//!
//! ```text
//!  0       1       2       3       4
//! +-------+-------+-------+-------+-------+
//! |  CID (16b)    | SEQ   | ACK   | FLAGS |
//! +-------+-------+-------+-------+-------+
//! ```
//!
//! This compares favorably to QUIC's minimum ~20 byte headers.

use super::types::{ConnectionId, ConstrainedError, PacketFlags, SequenceNumber};

/// Minimum header size in bytes
pub const HEADER_SIZE: usize = 5;

/// Constrained protocol packet header
///
/// A compact 5-byte header containing all information needed for reliable delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConstrainedHeader {
    /// Connection identifier (2 bytes)
    pub connection_id: ConnectionId,
    /// Sequence number for this packet (1 byte)
    pub seq: SequenceNumber,
    /// Acknowledgment number (cumulative) (1 byte)
    pub ack: SequenceNumber,
    /// Packet flags (1 byte)
    pub flags: PacketFlags,
}

impl ConstrainedHeader {
    /// Create a new header with the specified fields
    pub const fn new(
        connection_id: ConnectionId,
        seq: SequenceNumber,
        ack: SequenceNumber,
        flags: PacketFlags,
    ) -> Self {
        Self {
            connection_id,
            seq,
            ack,
            flags,
        }
    }

    /// Create a SYN header for connection initiation
    pub fn syn(connection_id: ConnectionId) -> Self {
        Self {
            connection_id,
            seq: SequenceNumber::new(0),
            ack: SequenceNumber::new(0),
            flags: PacketFlags::SYN,
        }
    }

    /// Create a SYN-ACK header for connection response
    pub fn syn_ack(connection_id: ConnectionId, ack: SequenceNumber) -> Self {
        Self {
            connection_id,
            seq: SequenceNumber::new(0),
            ack,
            flags: PacketFlags::SYN_ACK,
        }
    }

    /// Create an ACK-only header
    pub fn ack(connection_id: ConnectionId, seq: SequenceNumber, ack: SequenceNumber) -> Self {
        Self {
            connection_id,
            seq,
            ack,
            flags: PacketFlags::ACK,
        }
    }

    /// Create a DATA header
    pub fn data(connection_id: ConnectionId, seq: SequenceNumber, ack: SequenceNumber) -> Self {
        Self {
            connection_id,
            seq,
            ack,
            flags: PacketFlags::DATA.union(PacketFlags::ACK),
        }
    }

    /// Create a FIN header for connection close
    pub fn fin(connection_id: ConnectionId, seq: SequenceNumber, ack: SequenceNumber) -> Self {
        Self {
            connection_id,
            seq,
            ack,
            flags: PacketFlags::FIN.union(PacketFlags::ACK),
        }
    }

    /// Create a RST header for connection reset
    pub fn reset(connection_id: ConnectionId) -> Self {
        Self {
            connection_id,
            seq: SequenceNumber::new(0),
            ack: SequenceNumber::new(0),
            flags: PacketFlags::RST,
        }
    }

    /// Create a PING header for keep-alive
    pub fn ping(connection_id: ConnectionId, seq: SequenceNumber) -> Self {
        Self {
            connection_id,
            seq,
            ack: SequenceNumber::new(0),
            flags: PacketFlags::PING,
        }
    }

    /// Create a PONG header in response to ping
    pub fn pong(connection_id: ConnectionId, ack: SequenceNumber) -> Self {
        Self {
            connection_id,
            seq: SequenceNumber::new(0),
            ack,
            flags: PacketFlags::PONG,
        }
    }

    /// Serialize header to bytes
    ///
    /// Returns a 5-byte array containing the serialized header.
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let cid_bytes = self.connection_id.to_bytes();
        [
            cid_bytes[0],
            cid_bytes[1],
            self.seq.value(),
            self.ack.value(),
            self.flags.value(),
        ]
    }

    /// Deserialize header from bytes
    ///
    /// Returns an error if the slice is too short.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConstrainedError> {
        if bytes.len() < HEADER_SIZE {
            return Err(ConstrainedError::PacketTooSmall {
                expected: HEADER_SIZE,
                actual: bytes.len(),
            });
        }

        Ok(Self {
            connection_id: ConnectionId::from_bytes([bytes[0], bytes[1]]),
            seq: SequenceNumber::new(bytes[2]),
            ack: SequenceNumber::new(bytes[3]),
            flags: PacketFlags::new(bytes[4]),
        })
    }

    /// Check if this is a SYN packet
    pub const fn is_syn(&self) -> bool {
        self.flags.is_syn()
    }

    /// Check if this is a SYN-ACK packet
    pub const fn is_syn_ack(&self) -> bool {
        self.flags.is_syn() && self.flags.is_ack()
    }

    /// Check if this has the ACK flag
    pub const fn is_ack(&self) -> bool {
        self.flags.is_ack()
    }

    /// Check if this is a FIN packet
    pub const fn is_fin(&self) -> bool {
        self.flags.is_fin()
    }

    /// Check if this is a RST packet
    pub const fn is_rst(&self) -> bool {
        self.flags.is_rst()
    }

    /// Check if this is a DATA packet
    pub const fn is_data(&self) -> bool {
        self.flags.is_data()
    }

    /// Check if this is a PING packet
    pub const fn is_ping(&self) -> bool {
        self.flags.is_ping()
    }

    /// Check if this is a PONG packet
    pub const fn is_pong(&self) -> bool {
        self.flags.is_pong()
    }
}

impl std::fmt::Display for ConstrainedHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{} {} {} {}]",
            self.connection_id, self.seq, self.ack, self.flags
        )
    }
}

/// A complete packet with header and optional payload
#[derive(Debug, Clone)]
pub struct ConstrainedPacket {
    /// Packet header
    pub header: ConstrainedHeader,
    /// Packet payload (empty for control packets)
    pub payload: Vec<u8>,
}

impl ConstrainedPacket {
    /// Create a new packet with header and payload
    pub fn new(header: ConstrainedHeader, payload: Vec<u8>) -> Self {
        Self { header, payload }
    }

    /// Create a control packet (no payload)
    pub fn control(header: ConstrainedHeader) -> Self {
        Self {
            header,
            payload: Vec::new(),
        }
    }

    /// Create a data packet
    pub fn data(
        connection_id: ConnectionId,
        seq: SequenceNumber,
        ack: SequenceNumber,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            header: ConstrainedHeader::data(connection_id, seq, ack),
            payload,
        }
    }

    /// Total size of the packet (header + payload)
    pub fn total_size(&self) -> usize {
        HEADER_SIZE + self.payload.len()
    }

    /// Serialize the complete packet to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.total_size());
        bytes.extend_from_slice(&self.header.to_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    /// Deserialize a packet from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConstrainedError> {
        let header = ConstrainedHeader::from_bytes(bytes)?;
        let payload = if bytes.len() > HEADER_SIZE {
            bytes[HEADER_SIZE..].to_vec()
        } else {
            Vec::new()
        };
        Ok(Self { header, payload })
    }

    /// Check if this packet has a payload
    pub fn has_payload(&self) -> bool {
        !self.payload.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_serialization() {
        let header = ConstrainedHeader::new(
            ConnectionId::new(0x1234),
            SequenceNumber::new(10),
            SequenceNumber::new(5),
            PacketFlags::DATA.union(PacketFlags::ACK),
        );

        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), HEADER_SIZE);
        assert_eq!(bytes[0], 0x12); // CID high byte
        assert_eq!(bytes[1], 0x34); // CID low byte
        assert_eq!(bytes[2], 10); // SEQ
        assert_eq!(bytes[3], 5); // ACK
        assert_eq!(bytes[4], 0x12); // DATA | ACK

        let restored = ConstrainedHeader::from_bytes(&bytes).unwrap();
        assert_eq!(restored, header);
    }

    #[test]
    fn test_header_from_bytes_too_short() {
        let result = ConstrainedHeader::from_bytes(&[1, 2, 3]);
        assert!(result.is_err());
        match result {
            Err(ConstrainedError::PacketTooSmall { expected, actual }) => {
                assert_eq!(expected, HEADER_SIZE);
                assert_eq!(actual, 3);
            }
            _ => panic!("Expected PacketTooSmall error"),
        }
    }

    #[test]
    fn test_syn_header() {
        let header = ConstrainedHeader::syn(ConnectionId::new(0xABCD));
        assert!(header.is_syn());
        assert!(!header.is_ack());
        assert_eq!(header.seq, SequenceNumber::new(0));
    }

    #[test]
    fn test_syn_ack_header() {
        let header = ConstrainedHeader::syn_ack(ConnectionId::new(0xABCD), SequenceNumber::new(1));
        assert!(header.is_syn());
        assert!(header.is_ack());
        assert!(header.is_syn_ack());
        assert_eq!(header.ack, SequenceNumber::new(1));
    }

    #[test]
    fn test_data_header() {
        let header = ConstrainedHeader::data(
            ConnectionId::new(0x1234),
            SequenceNumber::new(5),
            SequenceNumber::new(3),
        );
        assert!(header.is_data());
        assert!(header.is_ack());
        assert!(!header.is_syn());
    }

    #[test]
    fn test_fin_header() {
        let header = ConstrainedHeader::fin(
            ConnectionId::new(0x1234),
            SequenceNumber::new(10),
            SequenceNumber::new(8),
        );
        assert!(header.is_fin());
        assert!(header.is_ack());
    }

    #[test]
    fn test_reset_header() {
        let header = ConstrainedHeader::reset(ConnectionId::new(0x1234));
        assert!(header.is_rst());
        assert!(!header.is_ack());
    }

    #[test]
    fn test_ping_pong_headers() {
        let ping = ConstrainedHeader::ping(ConnectionId::new(0x1234), SequenceNumber::new(5));
        assert!(ping.is_ping());
        assert!(!ping.is_pong());

        let pong = ConstrainedHeader::pong(ConnectionId::new(0x1234), SequenceNumber::new(5));
        assert!(pong.is_pong());
        assert!(!pong.is_ping());
    }

    #[test]
    fn test_header_display() {
        let header = ConstrainedHeader::data(
            ConnectionId::new(0xABCD),
            SequenceNumber::new(10),
            SequenceNumber::new(5),
        );
        let display = format!("{}", header);
        assert!(display.contains("ABCD"));
        assert!(display.contains("SEQ:10"));
        assert!(display.contains("ACK|DATA"));
    }

    #[test]
    fn test_packet_serialization() {
        let packet = ConstrainedPacket::data(
            ConnectionId::new(0x1234),
            SequenceNumber::new(5),
            SequenceNumber::new(3),
            b"Hello".to_vec(),
        );

        assert_eq!(packet.total_size(), HEADER_SIZE + 5);
        assert!(packet.has_payload());

        let bytes = packet.to_bytes();
        assert_eq!(bytes.len(), HEADER_SIZE + 5);
        assert_eq!(&bytes[HEADER_SIZE..], b"Hello");

        let restored = ConstrainedPacket::from_bytes(&bytes).unwrap();
        assert_eq!(restored.header, packet.header);
        assert_eq!(restored.payload, packet.payload);
    }

    #[test]
    fn test_control_packet() {
        let packet = ConstrainedPacket::control(ConstrainedHeader::syn(ConnectionId::new(0x1234)));
        assert!(!packet.has_payload());
        assert_eq!(packet.total_size(), HEADER_SIZE);
    }

    #[test]
    fn test_packet_from_bytes_header_only() {
        let header = ConstrainedHeader::ack(
            ConnectionId::new(0x1234),
            SequenceNumber::new(1),
            SequenceNumber::new(0),
        );
        let bytes = header.to_bytes();

        let packet = ConstrainedPacket::from_bytes(&bytes).unwrap();
        assert_eq!(packet.header, header);
        assert!(packet.payload.is_empty());
    }
}
