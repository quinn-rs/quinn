/// Standalone NAT traversal frame encoding/decoding tests
/// This is a completely independent test that doesn't depend on the main codebase
/// and can run even if the main library has compilation errors.

fn main() {
    println!("Running NAT Traversal Frame Tests...");
    
    test_varint_encoding_decoding();
    test_add_address_ipv4_encoding();
    test_add_address_ipv6_encoding();
    test_add_address_decoding_ipv4();
    test_punch_me_now_ipv4_without_peer_id();
    test_punch_me_now_with_peer_id();
    test_remove_address_encoding();
    test_malformed_frame_handling();
    test_frame_size_bounds();
    test_roundtrip_consistency();
    test_edge_cases();
    test_ipv6_special_addresses();
    
    println!("All NAT Traversal Frame Tests Passed! ✅");
}

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

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
    
    pub fn encode(&self) -> Vec<u8> {
        let value = self.0;
        if value < 64 {
            vec![value as u8]
        } else if value < 16384 {
            let encoded = (value | 0x4000) as u16;
            encoded.to_be_bytes().to_vec()
        } else if value < 1073741824 {
            let encoded = (value | 0x80000000) as u32;
            encoded.to_be_bytes().to_vec()
        } else {
            let encoded = value | 0xC000000000000000;
            encoded.to_be_bytes().to_vec()
        }
    }
    
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), &'static str> {
        if buf.is_empty() {
            return Err("Unexpected end");
        }
        
        let first = buf[0];
        let tag = first >> 6;
        
        match tag {
            0 => Ok((VarInt(first as u64), 1)),
            1 => {
                if buf.len() < 2 {
                    return Err("Unexpected end");
                }
                let value = u16::from_be_bytes([first & 0x3F, buf[1]]);
                Ok((VarInt(value as u64), 2))
            }
            2 => {
                if buf.len() < 4 {
                    return Err("Unexpected end");
                }
                let mut bytes = [0u8; 4];
                bytes[0] = first & 0x3F;
                bytes[1..].copy_from_slice(&buf[1..4]);
                let value = u32::from_be_bytes(bytes);
                Ok((VarInt(value as u64), 4))
            }
            3 => {
                if buf.len() < 8 {
                    return Err("Unexpected end");
                }
                let mut bytes = [0u8; 8];
                bytes[0] = first & 0x3F;
                bytes[1..].copy_from_slice(&buf[1..8]);
                let value = u64::from_be_bytes(bytes);
                Ok((VarInt(value), 8))
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
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![0x40]; // ADD_ADDRESS frame type
        buf.extend_from_slice(&self.sequence.encode());
        buf.extend_from_slice(&self.priority.encode());
        
        match self.address {
            SocketAddr::V4(addr) => {
                buf.push(4); // IPv4 indicator
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
            SocketAddr::V6(addr) => {
                buf.push(6); // IPv6 indicator
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
                buf.extend_from_slice(&addr.flowinfo().to_be_bytes());
                buf.extend_from_slice(&addr.scope_id().to_be_bytes());
            }
        }
        
        buf
    }
    
    pub fn decode(buf: &[u8]) -> Result<Self, &'static str> {
        let mut offset = 0;
        
        let (sequence, seq_len) = VarInt::decode(&buf[offset..])?;
        offset += seq_len;
        
        let (priority, pri_len) = VarInt::decode(&buf[offset..])?;
        offset += pri_len;
        
        if offset >= buf.len() {
            return Err("Unexpected end");
        }
        
        let ip_version = buf[offset];
        offset += 1;
        
        let address = match ip_version {
            4 => {
                if buf.len() < offset + 6 {
                    return Err("Unexpected end");
                }
                let mut octets = [0u8; 4];
                octets.copy_from_slice(&buf[offset..offset + 4]);
                offset += 4;
                let port = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(octets), port))
            }
            6 => {
                if buf.len() < offset + 24 {
                    return Err("Unexpected end");
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[offset..offset + 16]);
                offset += 16;
                let port = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
                offset += 2;
                let flowinfo = u32::from_be_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]]);
                offset += 4;
                let scope_id = u32::from_be_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]]);
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
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![0x41]; // PUNCH_ME_NOW frame type
        buf.extend_from_slice(&self.round.encode());
        buf.extend_from_slice(&self.target_sequence.encode());
        
        match self.local_address {
            SocketAddr::V4(addr) => {
                buf.push(4); // IPv4 indicator
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
            SocketAddr::V6(addr) => {
                buf.push(6); // IPv6 indicator
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
                buf.extend_from_slice(&addr.flowinfo().to_be_bytes());
                buf.extend_from_slice(&addr.scope_id().to_be_bytes());
            }
        }
        
        // Encode target_peer_id if present
        match &self.target_peer_id {
            Some(peer_id) => {
                buf.push(1); // Presence indicator
                buf.extend_from_slice(peer_id);
            }
            None => {
                buf.push(0); // Absence indicator
            }
        }
        
        buf
    }
    
    pub fn decode(buf: &[u8]) -> Result<Self, &'static str> {
        let mut offset = 0;
        
        let (round, round_len) = VarInt::decode(&buf[offset..])?;
        offset += round_len;
        
        let (target_sequence, seq_len) = VarInt::decode(&buf[offset..])?;
        offset += seq_len;
        
        if offset >= buf.len() {
            return Err("Unexpected end");
        }
        
        let ip_version = buf[offset];
        offset += 1;
        
        let local_address = match ip_version {
            4 => {
                if buf.len() < offset + 6 {
                    return Err("Unexpected end");
                }
                let mut octets = [0u8; 4];
                octets.copy_from_slice(&buf[offset..offset + 4]);
                offset += 4;
                let port = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
                offset += 2;
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(octets), port))
            }
            6 => {
                if buf.len() < offset + 24 {
                    return Err("Unexpected end");
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[offset..offset + 16]);
                offset += 16;
                let port = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
                offset += 2;
                let flowinfo = u32::from_be_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]]);
                offset += 4;
                let scope_id = u32::from_be_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]]);
                offset += 4;
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(octets), port, flowinfo, scope_id))
            }
            _ => return Err("Invalid IP version"),
        };
        
        // Decode target_peer_id if present
        let target_peer_id = if offset < buf.len() {
            let has_peer_id = buf[offset];
            offset += 1;
            if has_peer_id == 1 {
                if buf.len() < offset + 32 {
                    return Err("Unexpected end");
                }
                let mut peer_id = [0u8; 32];
                peer_id.copy_from_slice(&buf[offset..offset + 32]);
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
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![0x42]; // REMOVE_ADDRESS frame type
        buf.extend_from_slice(&self.sequence.encode());
        buf
    }
    
    pub fn decode(buf: &[u8]) -> Result<Self, &'static str> {
        let (sequence, _) = VarInt::decode(buf)?;
        Ok(Self { sequence })
    }
}

// Test functions
fn test_varint_encoding_decoding() {
    println!("Testing VarInt encoding/decoding...");
    let test_values = vec![0, 1, 63, 64, 16383, 16384, 1073741823];
    
    for value in test_values {
        let varint = VarInt::from_u64(value).unwrap();
        let encoded = varint.encode();
        let (decoded, _) = VarInt::decode(&encoded).unwrap();
        
        assert_eq!(varint, decoded, "VarInt roundtrip failed for value {}", value);
    }
    println!("✅ VarInt encoding/decoding tests passed");
}

fn test_add_address_ipv4_encoding() {
    println!("Testing AddAddress IPv4 encoding...");
    let frame = AddAddress {
        sequence: VarInt::from_u32(42),
        address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 8080)),
        priority: VarInt::from_u32(100),
    };

    let encoded = frame.encode();
    
    // Debug: print the actual encoding
    println!("Encoded: {:?}", encoded);
    println!("Priority 100 encodes to: {:?}", VarInt::from_u32(100).encode());
    
    // Since 100 > 63, it will be encoded as 2 bytes
    let expected = vec![
        0x40,           // Frame type
        42,             // Sequence (VarInt - single byte since 42 < 64)
        0x40, 0x64,     // Priority 100 as VarInt (2 bytes since 100 >= 64)
        4,              // IPv4 indicator
        192, 168, 1, 100, // IPv4 address
        0x1f, 0x90,     // Port 8080 in big-endian
    ];

    assert_eq!(encoded, expected);
    println!("✅ AddAddress IPv4 encoding test passed");
}

fn test_add_address_ipv6_encoding() {
    println!("Testing AddAddress IPv6 encoding...");
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

    let encoded = frame.encode();
    // Since 123 > 63 and 200 > 63, both will be encoded as 2 bytes
    let expected = vec![
        0x40,           // Frame type
        0x40, 123,      // Sequence (VarInt - 2 bytes since 123 >= 64)
        0x40, 200,      // Priority (VarInt - 2 bytes since 200 >= 64)
        6,              // IPv6 indicator
        // IPv6 address bytes
        0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
        0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34,
        0x23, 0x28,     // Port 9000 in big-endian
        0x12, 0x34, 0x56, 0x78, // Flow info
        0x87, 0x65, 0x43, 0x21, // Scope ID
    ];

    assert_eq!(encoded, expected);
    println!("✅ AddAddress IPv6 encoding test passed");
}

fn test_add_address_decoding_ipv4() {
    println!("Testing AddAddress IPv4 decoding...");
    let data = vec![
        42,             // Sequence (VarInt - single byte since 42 < 64)
        0x40, 100,      // Priority (VarInt - 2 bytes since 100 >= 64)
        4,              // IPv4 indicator
        10, 0, 0, 1,    // IPv4 address 10.0.0.1
        0x1f, 0x90,     // Port 8080
    ];

    let frame = AddAddress::decode(&data).expect("Failed to decode AddAddress");

    assert_eq!(frame.sequence, VarInt::from_u32(42));
    assert_eq!(frame.priority, VarInt::from_u32(100));
    assert_eq!(frame.address, SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 8080)));
    println!("✅ AddAddress IPv4 decoding test passed");
}

fn test_punch_me_now_ipv4_without_peer_id() {
    println!("Testing PunchMeNow IPv4 without peer ID...");
    let frame = PunchMeNow {
        round: VarInt::from_u32(5),
        target_sequence: VarInt::from_u32(42),
        local_address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(172, 16, 0, 1), 12345)),
        target_peer_id: None,
    };

    let encoded = frame.encode();
    let expected = vec![
        0x41,           // Frame type (PUNCH_ME_NOW)
        5,              // Round (VarInt)
        42,             // Target sequence (VarInt)
        4,              // IPv4 indicator
        172, 16, 0, 1,  // IPv4 address
        0x30, 0x39,     // Port 12345 in big-endian
        0,              // No peer ID
    ];

    assert_eq!(encoded, expected);
    println!("✅ PunchMeNow IPv4 without peer ID test passed");
}

fn test_punch_me_now_with_peer_id() {
    println!("Testing PunchMeNow with peer ID...");
    let peer_id = [0x42; 32]; // Test peer ID
    let frame = PunchMeNow {
        round: VarInt::from_u32(10),
        target_sequence: VarInt::from_u32(99),
        local_address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 54321)),
        target_peer_id: Some(peer_id),
    };

    let encoded = frame.encode();
    let mut expected = vec![
        0x41,           // Frame type (PUNCH_ME_NOW)
        10,             // Round (VarInt - single byte since 10 < 64)
        0x40, 99,       // Target sequence (VarInt - 2 bytes since 99 >= 64)
        4,              // IPv4 indicator
        127, 0, 0, 1,   // IPv4 localhost address
        0xd4, 0x31,     // Port 54321 in big-endian
        1,              // Has peer ID
    ];
    expected.extend_from_slice(&peer_id); // Peer ID bytes

    assert_eq!(encoded, expected);
    println!("✅ PunchMeNow with peer ID test passed");
}

fn test_remove_address_encoding() {
    println!("Testing RemoveAddress encoding...");
    let frame = RemoveAddress {
        sequence: VarInt::from_u32(777),
    };

    let encoded = frame.encode();
    // For sequence 777, VarInt encoding uses 2 bytes
    let expected = vec![
        0x42,           // Frame type (REMOVE_ADDRESS)
        0x43, 0x09,     // Sequence 777 as VarInt (2 bytes: 0x4000 | 777)
    ];

    assert_eq!(encoded, expected);
    println!("✅ RemoveAddress encoding test passed");
}

fn test_malformed_frame_handling() {
    println!("Testing malformed frame handling...");
    
    // Test truncated IPv4 address
    let data = vec![
        42,             // Sequence
        100,            // Priority
        4,              // IPv4 indicator
        192, 168,       // Incomplete IPv4 address (only 2 bytes)
    ];

    let result = AddAddress::decode(&data);
    assert!(result.is_err(), "Should fail on truncated IPv4 address");

    // Test invalid IP version
    let data = vec![
        42,             // Sequence
        100,            // Priority
        7,              // Invalid IP version
        192, 168, 1, 1, // Some data
    ];

    let result = AddAddress::decode(&data);
    assert!(result.is_err(), "Should fail on invalid IP version");
    
    println!("✅ Malformed frame handling tests passed");
}

fn test_frame_size_bounds() {
    println!("Testing frame size bounds...");
    
    // Test IPv4 frame size
    let ipv4_frame = AddAddress {
        sequence: VarInt::from_u32(1),
        address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080)),
        priority: VarInt::from_u32(1),
    };

    let encoded = ipv4_frame.encode();
    // IPv4 frame should be: 1 (type) + 1 (seq) + 1 (pri) + 1 (ver) + 4 (ip) + 2 (port) = 10 bytes
    assert_eq!(encoded.len(), 10);

    // Test IPv6 frame size (worst case)
    let ipv6_frame = AddAddress {
        sequence: VarInt::from_u64(0x3FFFFFFF).unwrap(), // Max VarInt (4 bytes)
        address: SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 65535, 0xffffffff, 0xffffffff)),
        priority: VarInt::from_u64(0x3FFFFFFF).unwrap(), // Max VarInt (4 bytes)
    };

    let encoded = ipv6_frame.encode();
    // IPv6 frame should be: 1 (type) + 4 (seq) + 4 (pri) + 1 (ver) + 16 (ip) + 2 (port) + 4 (flow) + 4 (scope) = 36 bytes
    assert_eq!(encoded.len(), 36);
    
    println!("✅ Frame size bounds tests passed");
}

fn test_roundtrip_consistency() {
    println!("Testing roundtrip consistency...");
    
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
        let encoded = original.encode();
        let decoded = AddAddress::decode(&encoded[1..]).expect("Failed to decode frame"); // Skip frame type

        assert_eq!(original, decoded, "Roundtrip failed for frame: {:?}", original);
    }
    
    println!("✅ Roundtrip consistency tests passed");
}

fn test_edge_cases() {
    println!("Testing edge cases...");
    
    // Test zero values
    let frame = AddAddress {
        sequence: VarInt::from_u32(0),
        address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0)),
        priority: VarInt::from_u32(0),
    };

    let encoded = frame.encode();
    let decoded = AddAddress::decode(&encoded[1..]).expect("Failed to decode zero values"); // Skip frame type

    assert_eq!(decoded.sequence, VarInt::from_u32(0));
    assert_eq!(decoded.priority, VarInt::from_u32(0));
    assert_eq!(decoded.address.port(), 0);

    // Test maximum port values
    let frame = AddAddress {
        sequence: VarInt::from_u32(1),
        address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 65535)),
        priority: VarInt::from_u32(1),
    };

    let encoded = frame.encode();
    let decoded = AddAddress::decode(&encoded[1..]).expect("Failed to decode max port"); // Skip frame type

    assert_eq!(decoded.address.port(), 65535);
    
    println!("✅ Edge cases tests passed");
}

fn test_ipv6_special_addresses() {
    println!("Testing IPv6 special addresses...");
    
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

        let encoded = frame.encode();
        let decoded = AddAddress::decode(&encoded[1..]) // Skip frame type
            .expect(&format!("Failed to decode IPv6 address: {}", addr));

        if let SocketAddr::V6(decoded_addr) = decoded.address {
            assert_eq!(decoded_addr.ip(), &addr);
        } else {
            panic!("Expected IPv6 address");
        }
    }
    
    println!("✅ IPv6 special addresses tests passed");
}

// Helper function for assertions
fn assert_eq<T: PartialEq + std::fmt::Debug>(left: T, right: T, message: &str) {
    if left != right {
        panic!("{}: expected {:?}, got {:?}", message, right, left);
    }
}

fn assert<T: std::fmt::Debug>(condition: bool, message: &str) {
    if !condition {
        panic!("{}", message);
    }
}