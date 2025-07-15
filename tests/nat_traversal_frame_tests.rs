use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use bytes::{Bytes, BytesMut, Buf, BufMut};

// Import the frame types directly from the source
use ant_quic::{VarInt, coding::{BufExt, BufMutExt, UnexpectedEnd}};

/// NAT traversal frame for advertising candidate addresses
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddAddress {
    /// Sequence number for this address advertisement
    pub sequence: VarInt,
    /// Socket address being advertised
    pub address: SocketAddr,
    /// Priority of this address candidate
    pub priority: VarInt,
}

impl AddAddress {
    pub fn encode<W: BufMut>(&self, buf: &mut W) {
        buf.put_u8(0x40); // ADD_ADDRESS frame type
        buf.write(self.sequence);
        buf.write(self.priority);
        
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
    
    pub fn decode<R: Buf>(r: &mut R) -> Result<Self, UnexpectedEnd> {
        let sequence = r.get()?;
        let priority = r.get()?;
        let ip_version = r.get::<u8>()?;
        
        let address = match ip_version {
            4 => {
                let mut octets = [0u8; 4];
                r.copy_to_slice(&mut octets);
                let port = r.get::<u16>()?;
                SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from(octets),
                    port,
                ))
            }
            6 => {
                let mut octets = [0u8; 16];
                r.copy_to_slice(&mut octets);
                let port = r.get::<u16>()?;
                let flowinfo = r.get::<u32>()?;
                let scope_id = r.get::<u32>()?;
                SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(octets),
                    port,
                    flowinfo,
                    scope_id,
                ))
            }
            _ => return Err(UnexpectedEnd),
        };
        
        Ok(Self {
            sequence,
            address,
            priority,
        })
    }
}

/// NAT traversal frame for requesting simultaneous hole punching
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PunchMeNow {
    /// Round number for coordination
    pub round: VarInt,
    /// Sequence number of the address to punch to (from AddAddress)
    pub target_sequence: VarInt,
    /// Local address for this punch attempt
    pub local_address: SocketAddr,
    /// Target peer ID for relay by bootstrap nodes (optional)
    pub target_peer_id: Option<[u8; 32]>,
}

impl PunchMeNow {
    pub fn encode<W: BufMut>(&self, buf: &mut W) {
        buf.put_u8(0x41); // PUNCH_ME_NOW frame type
        buf.write(self.round);
        buf.write(self.target_sequence);
        
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
    
    pub fn decode<R: Buf>(r: &mut R) -> Result<Self, UnexpectedEnd> {
        let round = r.get()?;
        let target_sequence = r.get()?;
        let ip_version = r.get::<u8>()?;
        
        let local_address = match ip_version {
            4 => {
                let mut octets = [0u8; 4];
                r.copy_to_slice(&mut octets);
                let port = r.get::<u16>()?;
                SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from(octets),
                    port,
                ))
            }
            6 => {
                let mut octets = [0u8; 16];
                r.copy_to_slice(&mut octets);
                let port = r.get::<u16>()?;
                let flowinfo = r.get::<u32>()?;
                let scope_id = r.get::<u32>()?;
                SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(octets),
                    port,
                    flowinfo,
                    scope_id,
                ))
            }
            _ => return Err(UnexpectedEnd),
        };
        
        // Decode target_peer_id if present
        let target_peer_id = if r.remaining() > 0 {
            let has_peer_id = r.get::<u8>()?;
            if has_peer_id == 1 {
                let mut peer_id = [0u8; 32];
                r.copy_to_slice(&mut peer_id);
                Some(peer_id)
            } else {
                None
            }
        } else {
            None
        };
        
        Ok(Self {
            round,
            target_sequence,
            local_address,
            target_peer_id,
        })
    }
}

/// NAT traversal frame for removing stale addresses
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoveAddress {
    /// Sequence number of the address to remove (from AddAddress)
    pub sequence: VarInt,
}

impl RemoveAddress {
    pub fn encode<W: BufMut>(&self, buf: &mut W) {
        buf.put_u8(0x42); // REMOVE_ADDRESS frame type
        buf.write(self.sequence);
    }
    
    pub fn decode<R: Buf>(r: &mut R) -> Result<Self, UnexpectedEnd> {
        let sequence = r.get()?;
        Ok(Self { sequence })
    }
}

/// Test vectors for NAT traversal frame encoding/decoding
#[cfg(test)]
mod frame_test_vectors {
    use super::*;

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
        // - Sequence: 42 (VarInt)
        // - Priority: 100 (VarInt)
        // - IP version: 4
        // - IPv4 address: 192.168.1.100 (4 bytes)
        // - Port: 8080 (2 bytes)
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
    fn test_add_address_decoding_ipv6() {
        let data = vec![
            123,            // Sequence (VarInt)
            200,            // Priority (VarInt)
            6,              // IPv6 indicator
            // IPv6 address ::1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x1f, 0x90,     // Port 8080
            0x00, 0x00, 0x00, 0x00, // Flow info
            0x00, 0x00, 0x00, 0x00, // Scope ID
        ];

        let mut buf = Bytes::from(data);
        let frame = AddAddress::decode(&mut buf).expect("Failed to decode AddAddress");

        assert_eq!(frame.sequence, VarInt::from_u32(123));
        assert_eq!(frame.priority, VarInt::from_u32(200));
        assert_eq!(frame.address, SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8080, 0, 0)));
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
    fn test_punch_me_now_ipv6_with_peer_id() {
        let peer_id = [0x42; 32]; // Test peer ID
        let frame = PunchMeNow {
            round: VarInt::from_u32(10),
            target_sequence: VarInt::from_u32(99),
            local_address: SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 54321, 0, 0)),
            target_peer_id: Some(peer_id),
        };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        let mut expected = vec![
            0x41,           // Frame type (PUNCH_ME_NOW)
            10,             // Round (VarInt)
            99,             // Target sequence (VarInt)
            6,              // IPv6 indicator
            // IPv6 localhost address
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0xd4, 0x31,     // Port 54321 in big-endian
            0x00, 0x00, 0x00, 0x00, // Flow info
            0x00, 0x00, 0x00, 0x00, // Scope ID
            1,              // Has peer ID
        ];
        expected.extend_from_slice(&peer_id); // Peer ID bytes

        assert_eq!(buf.to_vec(), expected);
    }

    #[test]
    fn test_punch_me_now_decoding() {
        let peer_id = [0x33; 32];
        let mut data = vec![
            7,              // Round (VarInt)
            88,             // Target sequence (VarInt)
            4,              // IPv4 indicator
            127, 0, 0, 1,   // IPv4 address 127.0.0.1
            0x27, 0x10,     // Port 10000
            1,              // Has peer ID
        ];
        data.extend_from_slice(&peer_id);

        let mut buf = Bytes::from(data);
        let frame = PunchMeNow::decode(&mut buf).expect("Failed to decode PunchMeNow");

        assert_eq!(frame.round, VarInt::from_u32(7));
        assert_eq!(frame.target_sequence, VarInt::from_u32(88));
        assert_eq!(frame.local_address, SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 10000)));
        assert_eq!(frame.target_peer_id, Some(peer_id));
    }

    #[test]
    fn test_remove_address_encoding() {
        let frame = RemoveAddress {
            sequence: VarInt::from_u32(777),
        };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        // For sequence 777, VarInt encoding uses 2 bytes: 0x89, 0x09
        let expected = vec![
            0x42,           // Frame type (REMOVE_ADDRESS)
            0x89, 0x09,     // Sequence 777 as VarInt (2 bytes)
        ];

        assert_eq!(buf.to_vec(), expected);
    }

    #[test]
    fn test_remove_address_decoding() {
        let data = vec![
            0x89, 0x09,     // Sequence 777 as VarInt
        ];

        let mut buf = Bytes::from(data);
        let frame = RemoveAddress::decode(&mut buf).expect("Failed to decode RemoveAddress");

        assert_eq!(frame.sequence, VarInt::from_u32(777));
    }

    #[test]
    fn test_large_varint_encoding() {
        // Test with large VarInt values to ensure proper encoding
        let frame = AddAddress {
            sequence: VarInt::from_u64(0x3FFFFFFF).unwrap(), // Max 30-bit value
            address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 65535)),
            priority: VarInt::from_u64(0x3FFFFFFF).unwrap(),
        };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        // Decode it back to verify
        let mut decode_buf = buf.clone().freeze();
        decode_buf.advance(1); // Skip frame type
        let decoded = AddAddress::decode(&mut decode_buf).expect("Failed to decode large VarInt frame");

        assert_eq!(decoded.sequence, frame.sequence);
        assert_eq!(decoded.priority, frame.priority);
        assert_eq!(decoded.address, frame.address);
    }
}

/// Tests for malformed frame handling
#[cfg(test)]
mod malformed_frame_tests {
    use super::*;

    #[test]
    fn test_add_address_truncated_ipv4() {
        let data = vec![
            42,             // Sequence
            100,            // Priority
            4,              // IPv4 indicator
            192, 168,       // Incomplete IPv4 address (only 2 bytes)
        ];

        let mut buf = Bytes::from(data);
        let result = AddAddress::decode(&mut buf);
        assert!(result.is_err(), "Should fail on truncated IPv4 address");
    }

    #[test]
    fn test_add_address_truncated_ipv6() {
        let data = vec![
            42,             // Sequence
            100,            // Priority
            6,              // IPv6 indicator
            0x20, 0x01, 0x0d, 0xb8, // Incomplete IPv6 address (only 4 bytes)
        ];

        let mut buf = Bytes::from(data);
        let result = AddAddress::decode(&mut buf);
        assert!(result.is_err(), "Should fail on truncated IPv6 address");
    }

    #[test]
    fn test_add_address_invalid_ip_version() {
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
    fn test_punch_me_now_truncated_peer_id() {
        let data = vec![
            5,              // Round
            42,             // Target sequence
            4,              // IPv4 indicator
            127, 0, 0, 1,   // IPv4 address
            0x1f, 0x90,     // Port
            1,              // Has peer ID indicator
            0x42, 0x43,     // Incomplete peer ID (only 2 bytes instead of 32)
        ];

        let mut buf = Bytes::from(data);
        let result = PunchMeNow::decode(&mut buf);
        assert!(result.is_err(), "Should fail on truncated peer ID");
    }

    #[test]
    fn test_remove_address_empty_buffer() {
        let data = vec![];
        let mut buf = Bytes::from(data);
        let result = RemoveAddress::decode(&mut buf);
        assert!(result.is_err(), "Should fail on empty buffer");
    }
}

/// Tests for frame size bounds and limits
#[cfg(test)]
mod frame_size_tests {
    use super::*;

    // Define size bounds based on the frame structure
    const ADD_ADDRESS_SIZE_BOUND: usize = 1 + 9 + 9 + 1 + 16 + 2 + 4 + 4; // Worst case IPv6
    const PUNCH_ME_NOW_SIZE_BOUND: usize = 1 + 9 + 9 + 1 + 16 + 2 + 4 + 4 + 1 + 32; // Worst case IPv6 + peer ID
    const REMOVE_ADDRESS_SIZE_BOUND: usize = 1 + 9; // frame type + sequence

    #[test]
    fn test_add_address_size_bounds() {
        // Test IPv4 frame size
        let ipv4_frame = AddAddress {
            sequence: VarInt::from_u32(1),
            address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080)),
            priority: VarInt::from_u32(1),
        };

        let mut buf = BytesMut::new();
        ipv4_frame.encode(&mut buf);
        assert!(buf.len() <= ADD_ADDRESS_SIZE_BOUND, "IPv4 frame exceeds size bound");

        // Test IPv6 frame size (worst case)
        let ipv6_frame = AddAddress {
            sequence: VarInt::from_u64(0x3FFFFFFF).unwrap(), // Max VarInt
            address: SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff),
                65535,
                0xffffffff,
                0xffffffff,
            )),
            priority: VarInt::from_u64(0x3FFFFFFF).unwrap(),
        };

        let mut buf = BytesMut::new();
        ipv6_frame.encode(&mut buf);
        assert!(buf.len() <= ADD_ADDRESS_SIZE_BOUND, "IPv6 frame exceeds size bound");
    }

    #[test]
    fn test_punch_me_now_size_bounds() {
        // Test worst case: IPv6 + peer ID
        let frame = PunchMeNow {
            round: VarInt::from_u64(0x3FFFFFFF).unwrap(),
            target_sequence: VarInt::from_u64(0x3FFFFFFF).unwrap(),
            local_address: SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff),
                65535,
                0xffffffff,
                0xffffffff,
            )),
            target_peer_id: Some([0xff; 32]),
        };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);
        assert!(buf.len() <= PUNCH_ME_NOW_SIZE_BOUND, "PunchMeNow frame exceeds size bound");
    }

    #[test]
    fn test_remove_address_size_bounds() {
        let frame = RemoveAddress {
            sequence: VarInt::from_u64(0x3FFFFFFF).unwrap(), // Max VarInt
        };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);
        assert!(buf.len() <= REMOVE_ADDRESS_SIZE_BOUND, "RemoveAddress frame exceeds size bound");
    }
}

/// Integration tests for multiple frames in sequence
#[cfg(test)]
mod frame_integration_tests {
    use super::*;

    #[test]
    fn test_multiple_frames_in_sequence() {
        let mut packet_data = BytesMut::new();

        // Add multiple NAT traversal frames to a packet
        let add_addr = AddAddress {
            sequence: VarInt::from_u32(1),
            address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 8080)),
            priority: VarInt::from_u32(100),
        };

        let punch_me = PunchMeNow {
            round: VarInt::from_u32(1),
            target_sequence: VarInt::from_u32(1),
            local_address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 9000)),
            target_peer_id: None,
        };

        let remove_addr = RemoveAddress {
            sequence: VarInt::from_u32(2),
        };

        // Encode frames into packet
        add_addr.encode(&mut packet_data);
        punch_me.encode(&mut packet_data);
        remove_addr.encode(&mut packet_data);

        // Manually parse frames by reading from the buffer
        let mut buf = packet_data.freeze();
        
        // Parse first frame (AddAddress)
        assert_eq!(buf.get_u8(), 0x40); // ADD_ADDRESS frame type
        let decoded_add = AddAddress::decode(&mut buf).expect("Failed to decode AddAddress");
        assert_eq!(decoded_add.sequence, VarInt::from_u32(1));
        assert_eq!(decoded_add.priority, VarInt::from_u32(100));

        // Parse second frame (PunchMeNow)
        assert_eq!(buf.get_u8(), 0x41); // PUNCH_ME_NOW frame type
        let decoded_punch = PunchMeNow::decode(&mut buf).expect("Failed to decode PunchMeNow");
        assert_eq!(decoded_punch.round, VarInt::from_u32(1));
        assert_eq!(decoded_punch.target_sequence, VarInt::from_u32(1));

        // Parse third frame (RemoveAddress)
        assert_eq!(buf.get_u8(), 0x42); // REMOVE_ADDRESS frame type
        let decoded_remove = RemoveAddress::decode(&mut buf).expect("Failed to decode RemoveAddress");
        assert_eq!(decoded_remove.sequence, VarInt::from_u32(2));
    }

    #[test]
    fn test_frame_roundtrip_consistency() {
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
}

/// Edge case and boundary condition tests
#[cfg(test)]
mod edge_case_tests {
    use super::*;

    #[test]
    fn test_zero_values() {
        let frame = AddAddress {
            sequence: VarInt::from_u32(0),
            address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0)),
            priority: VarInt::from_u32(0),
        };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        let mut decode_buf = buf.clone().freeze();
        decode_buf.advance(1); // Skip frame type
        let decoded = AddAddress::decode(&mut decode_buf).expect("Failed to decode zero values");

        assert_eq!(decoded.sequence, VarInt::from_u32(0));
        assert_eq!(decoded.priority, VarInt::from_u32(0));
        assert_eq!(decoded.address.port(), 0);
    }

    #[test]
    fn test_maximum_port_values() {
        let frame = AddAddress {
            sequence: VarInt::from_u32(1),
            address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 65535)),
            priority: VarInt::from_u32(1),
        };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        let mut decode_buf = buf.clone().freeze();
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

            let mut decode_buf = buf.clone().freeze();
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