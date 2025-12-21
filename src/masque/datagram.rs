// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! HTTP Datagram encoding for MASQUE CONNECT-UDP Bind
//!
//! Two formats are supported per draft-ietf-masque-connect-udp-listen-10:
//!
//! 1. **Uncompressed**: `[Context ID][IP Version][IP Address][UDP Port][Payload]`
//!    - Used when sending to arbitrary targets via an uncompressed context
//!    - Includes full target addressing information in each datagram
//!
//! 2. **Compressed**: `[Context ID][Payload]`
//!    - Used when a compressed context has been established for the target
//!    - Target information is implicit from the context registration
//!
//! The choice between formats depends on whether a compressed context exists
//! for the target address.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::VarInt;
use crate::coding::{self, Codec};

/// Uncompressed datagram format
///
/// Used when sending via an uncompressed context. Each datagram includes
/// the full target address information.
///
/// Wire format:
/// ```text
/// +----------------+------------+-------------+----------+---------+
/// | Context ID (V) | IP Ver (1) | IP Addr (V) | Port (2) | Payload |
/// +----------------+------------+-------------+----------+---------+
/// ```
///
/// Where:
/// - Context ID: Variable-length integer identifying the uncompressed context
/// - IP Version: 4 for IPv4, 6 for IPv6
/// - IP Address: 4 bytes for IPv4, 16 bytes for IPv6
/// - Port: 2 bytes in network byte order
/// - Payload: Remaining bytes
#[derive(Debug, Clone)]
pub struct UncompressedDatagram {
    /// Context ID for the uncompressed context
    pub context_id: VarInt,
    /// Target address (IP and port)
    pub target: SocketAddr,
    /// UDP payload data
    pub payload: Bytes,
}

/// Compressed datagram format
///
/// Used when a compressed context has been established for the target.
/// The target information is implicit from the context registration.
///
/// Wire format:
/// ```text
/// +----------------+---------+
/// | Context ID (V) | Payload |
/// +----------------+---------+
/// ```
#[derive(Debug, Clone)]
pub struct CompressedDatagram {
    /// Context ID for the compressed context
    pub context_id: VarInt,
    /// UDP payload data
    pub payload: Bytes,
}

impl UncompressedDatagram {
    /// Create a new uncompressed datagram
    ///
    /// # Arguments
    ///
    /// * `context_id` - The uncompressed context ID
    /// * `target` - The target socket address
    /// * `payload` - The UDP payload data
    pub fn new(context_id: VarInt, target: SocketAddr, payload: Bytes) -> Self {
        Self {
            context_id,
            target,
            payload,
        }
    }

    /// Encode the datagram to bytes
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();

        self.context_id.encode(&mut buf);

        match self.target.ip() {
            IpAddr::V4(v4) => {
                buf.put_u8(4);
                buf.put_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                buf.put_u8(6);
                buf.put_slice(&v6.octets());
            }
        }

        buf.put_u16(self.target.port());
        buf.put_slice(&self.payload);

        buf.freeze()
    }

    /// Decode a datagram from bytes
    ///
    /// # Errors
    ///
    /// Returns `UnexpectedEnd` if the buffer is too short
    pub fn decode(buf: &mut impl Buf) -> coding::Result<Self> {
        let context_id = VarInt::decode(buf)?;

        if buf.remaining() < 1 {
            return Err(coding::UnexpectedEnd);
        }
        let ip_version = buf.get_u8();

        let ip = match ip_version {
            4 => {
                if buf.remaining() < 4 {
                    return Err(coding::UnexpectedEnd);
                }
                let mut octets = [0u8; 4];
                buf.copy_to_slice(&mut octets);
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            6 => {
                if buf.remaining() < 16 {
                    return Err(coding::UnexpectedEnd);
                }
                let mut octets = [0u8; 16];
                buf.copy_to_slice(&mut octets);
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => return Err(coding::UnexpectedEnd),
        };

        if buf.remaining() < 2 {
            return Err(coding::UnexpectedEnd);
        }
        let port = buf.get_u16();

        let payload = buf.copy_to_bytes(buf.remaining());

        Ok(Self {
            context_id,
            target: SocketAddr::new(ip, port),
            payload,
        })
    }

    /// Calculate the encoded size of this datagram
    pub fn encoded_size(&self) -> usize {
        let ip_size = match self.target.ip() {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 16,
        };
        self.context_id.size() + 1 + ip_size + 2 + self.payload.len()
    }
}

impl CompressedDatagram {
    /// Create a new compressed datagram
    ///
    /// # Arguments
    ///
    /// * `context_id` - The compressed context ID
    /// * `payload` - The UDP payload data
    pub fn new(context_id: VarInt, payload: Bytes) -> Self {
        Self {
            context_id,
            payload,
        }
    }

    /// Encode the datagram to bytes
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        self.context_id.encode(&mut buf);
        buf.put_slice(&self.payload);
        buf.freeze()
    }

    /// Decode a datagram from bytes
    ///
    /// # Errors
    ///
    /// Returns `UnexpectedEnd` if the buffer is too short
    pub fn decode(buf: &mut impl Buf) -> coding::Result<Self> {
        let context_id = VarInt::decode(buf)?;
        let payload = buf.copy_to_bytes(buf.remaining());
        Ok(Self {
            context_id,
            payload,
        })
    }

    /// Calculate the encoded size of this datagram
    pub fn encoded_size(&self) -> usize {
        self.context_id.size() + self.payload.len()
    }
}

/// Unified datagram type that can represent either format
#[derive(Debug, Clone)]
pub enum Datagram {
    /// Uncompressed datagram with inline target info
    Uncompressed(UncompressedDatagram),
    /// Compressed datagram with implicit target
    Compressed(CompressedDatagram),
}

impl Datagram {
    /// Get the context ID for this datagram
    pub fn context_id(&self) -> VarInt {
        match self {
            Datagram::Uncompressed(d) => d.context_id,
            Datagram::Compressed(d) => d.context_id,
        }
    }

    /// Get the payload for this datagram
    pub fn payload(&self) -> &Bytes {
        match self {
            Datagram::Uncompressed(d) => &d.payload,
            Datagram::Compressed(d) => &d.payload,
        }
    }

    /// Get the target address if this is an uncompressed datagram
    pub fn target(&self) -> Option<SocketAddr> {
        match self {
            Datagram::Uncompressed(d) => Some(d.target),
            Datagram::Compressed(_) => None,
        }
    }

    /// Encode the datagram to bytes
    pub fn encode(&self) -> Bytes {
        match self {
            Datagram::Uncompressed(d) => d.encode(),
            Datagram::Compressed(d) => d.encode(),
        }
    }

    /// Calculate the encoded size of this datagram
    pub fn encoded_size(&self) -> usize {
        match self {
            Datagram::Uncompressed(d) => d.encoded_size(),
            Datagram::Compressed(d) => d.encoded_size(),
        }
    }

    /// Check if this is an uncompressed datagram
    pub fn is_uncompressed(&self) -> bool {
        matches!(self, Datagram::Uncompressed(_))
    }

    /// Check if this is a compressed datagram
    pub fn is_compressed(&self) -> bool {
        matches!(self, Datagram::Compressed(_))
    }
}

impl From<UncompressedDatagram> for Datagram {
    fn from(d: UncompressedDatagram) -> Self {
        Datagram::Uncompressed(d)
    }
}

impl From<CompressedDatagram> for Datagram {
    fn from(d: CompressedDatagram) -> Self {
        Datagram::Compressed(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uncompressed_datagram_ipv4_roundtrip() {
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8080);
        let payload = Bytes::from("Hello, MASQUE!");
        let original = UncompressedDatagram::new(VarInt::from_u32(2), target, payload.clone());

        let encoded = original.encode();
        let decoded = UncompressedDatagram::decode(&mut encoded.clone()).unwrap();

        assert_eq!(decoded.context_id, original.context_id);
        assert_eq!(decoded.target, original.target);
        assert_eq!(decoded.payload, original.payload);
    }

    #[test]
    fn test_uncompressed_datagram_ipv6_roundtrip() {
        let target = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            443,
        );
        let payload = Bytes::from("IPv6 data");
        let original = UncompressedDatagram::new(VarInt::from_u32(4), target, payload);

        let encoded = original.encode();
        let decoded = UncompressedDatagram::decode(&mut encoded.clone()).unwrap();

        assert_eq!(decoded.context_id, original.context_id);
        assert_eq!(decoded.target, original.target);
        assert_eq!(decoded.payload, original.payload);
    }

    #[test]
    fn test_compressed_datagram_roundtrip() {
        let payload = Bytes::from("Compressed payload");
        let original = CompressedDatagram::new(VarInt::from_u32(6), payload.clone());

        let encoded = original.encode();
        let decoded = CompressedDatagram::decode(&mut encoded.clone()).unwrap();

        assert_eq!(decoded.context_id, original.context_id);
        assert_eq!(decoded.payload, original.payload);
    }

    #[test]
    fn test_encoded_size_calculation() {
        // IPv4 uncompressed: context_id(1) + ip_ver(1) + ipv4(4) + port(2) + payload
        let payload = Bytes::from("test");
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1234);
        let uncompressed = UncompressedDatagram::new(VarInt::from_u32(2), target, payload.clone());

        let encoded = uncompressed.encode();
        assert_eq!(encoded.len(), uncompressed.encoded_size());

        // IPv6 uncompressed: context_id(1) + ip_ver(1) + ipv6(16) + port(2) + payload
        let target_v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5678);
        let uncompressed_v6 =
            UncompressedDatagram::new(VarInt::from_u32(4), target_v6, payload.clone());

        let encoded_v6 = uncompressed_v6.encode();
        assert_eq!(encoded_v6.len(), uncompressed_v6.encoded_size());

        // Compressed: context_id(1) + payload
        let compressed = CompressedDatagram::new(VarInt::from_u32(6), payload);
        let encoded_compressed = compressed.encode();
        assert_eq!(encoded_compressed.len(), compressed.encoded_size());
    }

    #[test]
    fn test_datagram_enum_conversions() {
        let payload = Bytes::from("test");
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);

        let uncompressed = UncompressedDatagram::new(VarInt::from_u32(2), target, payload.clone());
        let datagram: Datagram = uncompressed.into();

        assert!(datagram.is_uncompressed());
        assert!(!datagram.is_compressed());
        assert_eq!(datagram.context_id(), VarInt::from_u32(2));
        assert_eq!(datagram.target(), Some(target));
        assert_eq!(datagram.payload(), &payload);

        let compressed = CompressedDatagram::new(VarInt::from_u32(4), payload.clone());
        let datagram: Datagram = compressed.into();

        assert!(!datagram.is_uncompressed());
        assert!(datagram.is_compressed());
        assert_eq!(datagram.context_id(), VarInt::from_u32(4));
        assert_eq!(datagram.target(), None);
        assert_eq!(datagram.payload(), &payload);
    }

    #[test]
    fn test_empty_payload() {
        let payload = Bytes::new();
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1234);
        let datagram = UncompressedDatagram::new(VarInt::from_u32(2), target, payload);

        let encoded = datagram.encode();
        let decoded = UncompressedDatagram::decode(&mut encoded.clone()).unwrap();

        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn test_large_context_id() {
        let payload = Bytes::from("test");
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);

        // Use a large context ID that requires multi-byte VarInt encoding
        let large_id = VarInt::from_u64(0x4000).unwrap(); // Requires 2 bytes
        let datagram = UncompressedDatagram::new(large_id, target, payload);

        let encoded = datagram.encode();
        let decoded = UncompressedDatagram::decode(&mut encoded.clone()).unwrap();

        assert_eq!(decoded.context_id, large_id);
    }

    #[test]
    fn test_decode_truncated_buffer() {
        // Too short for context ID
        let mut buf = Bytes::new();
        assert!(UncompressedDatagram::decode(&mut buf).is_err());

        // Has context ID but no IP version
        let mut buf = BytesMut::new();
        VarInt::from_u32(2).encode(&mut buf);
        assert!(UncompressedDatagram::decode(&mut buf.freeze()).is_err());

        // Has context ID and IP version but no IP address
        let mut buf = BytesMut::new();
        VarInt::from_u32(2).encode(&mut buf);
        buf.put_u8(4);
        assert!(UncompressedDatagram::decode(&mut buf.freeze()).is_err());
    }

    #[test]
    fn test_invalid_ip_version() {
        let mut buf = BytesMut::new();
        VarInt::from_u32(2).encode(&mut buf);
        buf.put_u8(5); // Invalid IP version
        buf.put_slice(&[0u8; 4]); // Fake IPv4
        buf.put_u16(8080);

        assert!(UncompressedDatagram::decode(&mut buf.freeze()).is_err());
    }
}
