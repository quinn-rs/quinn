/// Standalone NAT traversal frame encoding/decoding tests
/// This test file is independent of the main codebase compilation issues
/// and focuses specifically on testing the frame encoding/decoding logic.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use bytes::{Bytes, BytesMut, Buf, BufMut};

// Test-specific VarInt implementation for standalone testing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VarInt(u64);

impl VarInt {
    pub fn from_u32(value: u32) -> Self {
        VarInt(value as u64)
    }
    
    pub fn from_u64(value: u64) -> Result<Self, &'static str> {
        if value > 0x3FFFFFFF {
            Err("VarInt too large")
        } else {
            Ok(VarInt(value))
        }
    }
    
    pub fn encode<W: BufMut>(&self, buf: &mut W) {
        let value = self.0;
        if value < 64 {
            buf.put_u8(value as u8);
        } else if value < 16384 {
            buf.put_u16((value | 0x4000) as u16);
        } else if value < 1073741824 {
            buf.put_u32((value | 0x80000000) as u32);
        } else {
            buf.put_u64(value | 0xC000000000000000);
        }
    }
    
    pub fn decode<R: Buf>(buf: &mut R) -> Result<Self, &'static str> {
        if !buf.has_remaining() {
            return Err("Unexpected end");
        }
        
        let first = buf.get_u8();
        let tag = first >> 6;
        
        match tag {
            0 => Ok(VarInt(first as u64)),
            1 => {
                if !buf.has_remaining() {
                    return Err("Unexpected end");
                }
                let second = buf.get_u8();
                Ok(VarInt(((first & 0x3F) as u64) << 8 | second as u64))
            }
            2 => {
                if buf.remaining() < 3 {
                    return Err("Unexpected end");
                }
                let mut bytes = [0u8; 4];
                bytes[0] = first & 0x3F;
                buf.copy_to_slice(&mut bytes[1..]);
                Ok(VarInt(u32::from_be_bytes(bytes) as u64))
            }
            3 => {
                if buf.remaining() < 7 {
                    return Err("Unexpected end");
                }
                let mut bytes = [0u8; 8];
                bytes[0] = first & 0x3F;
                buf.copy_to_slice(&mut bytes[1..]);
                Ok(VarInt(u64::from_be_bytes(bytes)))
            }
            _ => unreachable!(),
        }
    }
}

/// NAT traversal frame for advertising candidate addresses
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddAddress {
    pub sequence: VarInt,
    pub address: SocketAddr,
    pub priority: VarInt,
}

impl AddAddress {
    pub fn encode<W: BufMut>(&self, buf: &mut W) {
        buf.put_u8(0x40); // ADD_ADDRESS frame type
        self.sequence.encode(buf);
        self.priority.encode(buf);
        
        match self.address {
            SocketAddr::V4(addr) => {
                buf.put_u8(4); // IPv4 indicator
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            SocketAddr::V6(addr) => {
                buf.put_u8(6); // IPv6 indicator
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
                buf.put_u32(addr.flowinfo());
                buf.put_u32(addr.scope_id());
            }
        }
    }
    
    pub fn decode<R: Buf>(r: &mut R) -> Result<Self, &'static str> {
        let sequence = VarInt::decode(r)?;
        let priority = VarInt::decode(r)?;
        let ip_version = r.get_u8();
        
        let address = match ip_version {
            4 => {
                if r.remaining() < 6 {
                    return Err("Unexpected end");
                }
                let mut octets = [0u8; 4];
                r.copy_to_slice(&mut octets);
                let port = r.get_u16();
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(octets), port))
            }
            6 => {
                if r.remaining() < 24 {
                    return Err("Unexpected end");
                }
                let mut octets = [0u8; 16];
                r.copy_to_slice(&mut octets);
                let port = r.get_u16();
                let flowinfo = r.get_u32();
                let scope_id = r.get_u32();
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(octets), port, flowinfo, scope_id))
            }
            _ => return Err("Invalid IP version"),
        };
        
        Ok(Self { sequence, address, priority })
    }
}

/// NAT traversal frame for requesting simultaneous hole punching
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PunchMeNow {
    pub round: VarInt,
    pub target_sequence: VarInt,
    pub local_address: SocketAddr,
    pub target_peer_id: Option<[u8; 32]>,
}

impl PunchMeNow {
    pub fn encode<W: BufMut>(&self, buf: &mut W) {
        buf.put_u8(0x41); // PUNCH_ME_NOW frame type
        self.round.encode(buf);
        self.target_sequence.encode(buf);
        
        match self.local_address {
            SocketAddr::V4(addr) => {
                buf.put_u8(4); // IPv4 indicator
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            SocketAddr::V6(addr) => {
                buf.put_u8(6); // IPv6 indicator
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
                buf.put_u32(addr.flowinfo());
                buf.put_u32(addr.scope_id());
            }
        }
        
        // Encode target_peer_id if present
        match &self.target_peer_id {
            Some(peer_id) => {
                buf.put_u8(1); // Presence indicator
                buf.put_slice(peer_id);
            }
            None => {
                buf.put_u8(0); // Absence indicator
            }
        }
    }
    
    pub fn decode<R: Buf>(r: &mut R) -> Result<Self, &'static str> {
        let round = VarInt::decode(r)?;
        let target_sequence = VarInt::decode(r)?;
        let ip_version = r.get_u8();
        
        let local_address = match ip_version {
            4 => {
                if r.remaining() < 6 {
                    return Err("Unexpected end");
                }
                let mut octets = [0u8; 4];
                r.copy_to_slice(&mut octets);
                let port = r.get_u16();
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(octets), port))
            }
            6 => {
                if r.remaining() < 24 {
                    return Err("Unexpected end");
                }
                let mut octets = [0u8; 16];
                r.copy_to_slice(&mut octets);
                let port = r.get_u16();
                let flowinfo = r.get_u32();
                let scope_id = r.get_u32();
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(octets), port, flowinfo, scope_id))
            }
            _ => return Err("Invalid IP version"),
        };
        
        // Decode target_peer_id if present
        let target_peer_id = if r.has_remaining() {
            let has_peer_id = r.get_u8();
            if has_peer_id == 1 {
                if r.remaining() < 32 {
                    return Err("Unexpected end");
                }
                let mut peer_id = [0u8; 32];
                r.copy_to_slice(&mut peer_id);
                Some(peer_id)
            } else {
                None
            }
        } else {
            None
        };
        
        Ok(Self { round, target_sequence, local_address, target_peer_id })
    }
}

/// NAT traversal frame for removing stale addresses
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoveAddress {
    pub sequence: VarInt,
}

impl RemoveAddress {
    pub fn encode<W: BufMut>(&self, buf: &mut W) {
        buf.put_u8(0x42); // REMOVE_ADDRESS frame type
        self.sequence.encode(buf);
    }
    
    pub fn decode<R: Buf>(r: &mut R) -> Result<Self, &'static str> {
        let sequence = VarInt::decode(r)?;
        Ok(Self { sequence })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_encoding_decoding() {
        let test_values = vec![0, 1, 63, 64, 16383, 16384, 1073741823];
        
        for value in test_values {
            let varint = VarInt::from_u64(value).unwrap();
            let mut buf = BytesMut::new();
            varint.encode(&mut buf);
            
            let mut decode_buf = buf.freeze();
            let decoded = VarInt::decode(&mut decode_buf).unwrap();
            
            assert_eq!(varint, decoded, "VarInt roundtrip failed for value {}", value);
        }
    }

    #[test]
    fn test_add_address_ipv4_encoding() {
        let frame = AddAddress {
            sequence: VarInt::from_u32(42),
            address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 8080)),
            priority: VarInt::from_u32(100),
        };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        // Expected encoding:
        // - Frame type: 0x40 (ADD_ADDRESS)
        // - Sequence: 42 (VarInt - single byte)
        // - Priority: 100 (VarInt - single byte)
        // - IP version: 4
        // - IPv4 address: 192.168.1.100 (4 bytes)
        // - Port: 8080 (2 bytes, big-endian)
        let expected = vec![
            0x40,           // Frame type
            42,             // Sequence (VarInt)
            100,            // Priority (VarInt)
            4,              // IPv4 indicator
            192, 168, 1, 100, // IPv4 address
            0x1f, 0x90,     // Port 8080 in big-endian
        ];

        assert_eq!(buf.to_vec(), expected);
    }

    #[test]
    fn test_add_address_ipv6_encoding() {
        let frame = AddAddress {
            sequence: VarInt::from_u32(123),
            address: SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334),
                9000,
                0x12345678,
                0x87654321,
            )),
            priority: VarInt::from_u32(200),
        };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        let expected = vec![
            0x40,           // Frame type
            123,            // Sequence (VarInt)
            200,            // Priority (VarInt)
            6,              // IPv6 indicator
            // IPv6 address bytes
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
            0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34,
            0x23, 0x28,     // Port 9000 in big-endian
            0x12, 0x34, 0x56, 0x78, // Flow info
            0x87, 0x65, 0x43, 0x21, // Scope ID
        ];

        assert_eq!(buf.to_vec(), expected);
    }

    #[test]
    fn test_add_address_decoding_ipv4() {
        let data = vec![
            42,             // Sequence (VarInt)
            100,            // Priority (VarInt)
            4,              // IPv4 indicator
            10, 0, 0, 1,    // IPv4 address 10.0.0.1
            0x1f, 0x90,     // Port 8080
        ];

        let mut buf = Bytes::from(data);
        let frame = AddAddress::decode(&mut buf).expect("Failed to decode AddAddress");

        assert_eq!(frame.sequence, VarInt::from_u32(42));
        assert_eq!(frame.priority, VarInt::from_u32(100));
        assert_eq!(frame.address, SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 8080)));
    }

    #[test]
    fn test_punch_me_now_ipv4_without_peer_id() {
        let frame = PunchMeNow {
            round: VarInt::from_u32(5),
            target_sequence: VarInt::from_u32(42),
            local_address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(172, 16, 0, 1), 12345)),
            target_peer_id: None,
        };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        let expected = vec![
            0x41,           // Frame type (PUNCH_ME_NOW)
            5,              // Round (VarInt)
            42,             // Target sequence (VarInt)
            4,              // IPv4 indicator
            172, 16, 0, 1,  // IPv4 address
            0x30, 0x39,     // Port 12345 in big-endian
            0,              // No peer ID
        ];

        assert_eq!(buf.to_vec(), expected);
    }

    #[test]
    fn test_punch_me_now_with_peer_id() {
        let peer_id = [0x42; 32]; // Test peer ID
        let frame = PunchMeNow {
            round: VarInt::from_u32(10),
            target_sequence: VarInt::from_u32(99),
            local_address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 54321)),
            target_peer_id: Some(peer_id),
        };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        let mut expected = vec![
            0x41,           // Frame type (PUNCH_ME_NOW)
            10,             // Round (VarInt)
            99,             // Target sequence (VarInt)
            4,              // IPv4 indicator
            127, 0, 0, 1,   // IPv4 localhost address
            0xd4, 0x31,     // Port 54321 in big-endian
            1,              // Has peer ID
        ];
        expected.extend_from_slice(&peer_id); // Peer ID bytes

        assert_eq!(buf.to_vec(), expected);
    }

    #[test]
    fn test_remove_address_encoding() {
        let frame = RemoveAddress {
            sequence: VarInt::from_u32(777),
        };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        // For sequence 777, VarInt encoding uses 2 bytes
        let expected = vec![
            0x42,           // Frame type (REMOVE_ADDRESS)
            0x43, 0x09,     // Sequence 777 as VarInt (2 bytes: 0x4000 | 777)
        ];

        assert_eq!(buf.to_vec(), expected);
    }

    #[test]
    fn test_malformed_frame_handling() {
        // Test truncated IPv4 address
        let data = vec![
            42,             // Sequence
            100,            // Priority
            4,              // IPv4 indicator
            192, 168,       // Incomplete IPv4 address (only 2 bytes)
        ];

        let mut buf = Bytes::from(data);
        let result = AddAddress::decode(&mut buf);
        assert!(result.is_err(), "Should fail on truncated IPv4 address");

        // Test invalid IP version
        let data = vec![
            42,             // Sequence
            100,            // Priority
            7,              // Invalid IP version
            192, 168, 1, 1, // Some data
        ];

        let mut buf = Bytes::from(data);
        let result = AddAddress::decode(&mut buf);
        assert!(result.is_err(), "Should fail on invalid IP version");
    }

    #[test]
    fn test_frame_size_bounds() {
        // Test IPv4 frame size
        let ipv4_frame = AddAddress {
            sequence: VarInt::from_u32(1),
            address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080)),
            priority: VarInt::from_u32(1),
        };

        let mut buf = BytesMut::new();
        ipv4_frame.encode(&mut buf);
        
        // IPv4 frame should be: 1 (type) + 1 (seq) + 1 (pri) + 1 (ver) + 4 (ip) + 2 (port) = 10 bytes
        assert_eq!(buf.len(), 10);

        // Test IPv6 frame size (worst case)
        let ipv6_frame = AddAddress {
            sequence: VarInt::from_u64(0x3FFFFFFF).unwrap(), // Max VarInt (4 bytes)
            address: SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 65535, 0xffffffff, 0xffffffff)),
            priority: VarInt::from_u64(0x3FFFFFFF).unwrap(), // Max VarInt (4 bytes)
        };

        let mut buf = BytesMut::new();
        ipv6_frame.encode(&mut buf);
        
        // IPv6 frame should be: 1 (type) + 4 (seq) + 4 (pri) + 1 (ver) + 16 (ip) + 2 (port) + 4 (flow) + 4 (scope) = 36 bytes
        assert_eq!(buf.len(), 36);
    }

    #[test]
    fn test_roundtrip_consistency() {
        // Test that encoding and then decoding produces the same frame
        let original_frames = vec![
            AddAddress {
                sequence: VarInt::from_u32(42),
                address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 8080)),
                priority: VarInt::from_u32(100),
            },
            AddAddress {
                sequence: VarInt::from_u32(123),
                address: SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9000, 0x12345678, 0x87654321)),
                priority: VarInt::from_u32(200),
            },
        ];

        for original in original_frames {
            let mut buf = BytesMut::new();
            original.encode(&mut buf);

            let mut decode_buf = buf.freeze();
            decode_buf.advance(1); // Skip frame type
            let decoded = AddAddress::decode(&mut decode_buf).expect("Failed to decode frame");

            assert_eq!(original, decoded, "Roundtrip failed for frame: {:?}", original);
        }
    }

    #[test]
    fn test_edge_cases() {
        // Test zero values
        let frame = AddAddress {
            sequence: VarInt::from_u32(0),
            address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0)),
            priority: VarInt::from_u32(0),
        };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        let mut decode_buf = buf.freeze();
        decode_buf.advance(1); // Skip frame type
        let decoded = AddAddress::decode(&mut decode_buf).expect("Failed to decode zero values");

        assert_eq!(decoded.sequence, VarInt::from_u32(0));
        assert_eq!(decoded.priority, VarInt::from_u32(0));
        assert_eq!(decoded.address.port(), 0);

        // Test maximum port values
        let frame = AddAddress {
            sequence: VarInt::from_u32(1),
            address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 65535)),
            priority: VarInt::from_u32(1),
        };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        let mut decode_buf = buf.freeze();
        decode_buf.advance(1); // Skip frame type
        let decoded = AddAddress::decode(&mut decode_buf).expect("Failed to decode max port");

        assert_eq!(decoded.address.port(), 65535);
    }

    #[test]
    fn test_ipv6_special_addresses() {
        let addresses = vec![
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::UNSPECIFIED,
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), // Link-local
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), // Documentation
        ];

        for addr in addresses {
            let frame = AddAddress {
                sequence: VarInt::from_u32(1),
                address: SocketAddr::V6(SocketAddrV6::new(addr, 8080, 0, 0)),
                priority: VarInt::from_u32(1),
            };

            let mut buf = BytesMut::new();
            frame.encode(&mut buf);

            let mut decode_buf = buf.freeze();
            decode_buf.advance(1); // Skip frame type
            let decoded = AddAddress::decode(&mut decode_buf)
                .expect(&format!("Failed to decode IPv6 address: {}", addr));

            if let SocketAddr::V6(decoded_addr) = decoded.address {
                assert_eq!(decoded_addr.ip(), &addr);
            } else {
                panic!("Expected IPv6 address");
            }
        }
    }
}