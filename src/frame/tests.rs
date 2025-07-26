// Comprehensive unit tests for QUIC Address Discovery frames

use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use bytes::{BufMut, BytesMut};
use crate::VarInt;

#[test]
fn test_observed_address_frame_ipv4() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
    let frame = ObservedAddress {
        sequence_number: VarInt::from_u32(1),
        address: addr,
    };
    
    // Test encoding
    let mut buf = BytesMut::new();
    frame.encode(&mut buf);
    
    // Frame type is written by encode() as VarInt
    // 0x9f81a6 (10452390) uses 4-byte VarInt encoding
    // QUIC VarInt encoding for values >= 2^21 uses pattern 11xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
    assert_eq!(buf[0], 0x80); // First byte of 4-byte VarInt for 0x9f81a6
    assert_eq!(buf[1], 0x9f); // Second byte
    assert_eq!(buf[2], 0x81); // Third byte
    assert_eq!(buf[3], 0xa6); // Fourth byte
    
    // Test decoding - skip frame type bytes (4 bytes for VarInt)
    let mut reader = &buf[4..];
    let decoded = ObservedAddress::decode(&mut reader, false).unwrap();
    
    assert_eq!(decoded.sequence_number, VarInt::from_u32(1));
    assert_eq!(decoded.address, addr);
}

#[test]
fn test_observed_address_frame_ipv6() {
    let addr = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), 
        443
    );
    let frame = ObservedAddress {
        sequence_number: VarInt::from_u32(2),
        address: addr,
    };
    
    // Test encoding
    let mut buf = BytesMut::new();
    frame.encode(&mut buf);
    
    // Frame type is written by encode() as VarInt
    // 0x9f81a7 (10452391) uses 4-byte VarInt encoding
    // QUIC VarInt encoding for values >= 2^21 uses pattern 11xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
    assert_eq!(buf[0], 0x80); // First byte of 4-byte VarInt for 0x9f81a7
    assert_eq!(buf[1], 0x9f); // Second byte
    assert_eq!(buf[2], 0x81); // Third byte
    assert_eq!(buf[3], 0xa7); // Fourth byte
    
    // Test decoding - skip frame type bytes (4 bytes for VarInt)
    let mut reader = &buf[4..];
    let decoded = ObservedAddress::decode(&mut reader, true).unwrap(); // true for IPv6
    
    assert_eq!(decoded.sequence_number, VarInt::from_u32(2));
    assert_eq!(decoded.address, addr);
}

#[test]
fn test_observed_address_malformed() {
    // Test various malformed inputs
    
    // Empty buffer
    let buf = BytesMut::new();
    let mut reader = &buf[..];
    assert!(ObservedAddress::decode(&mut reader, false).is_err());
    
    // Truncated sequence number
    let buf = BytesMut::new();
    // Missing sequence number and rest of data
    let mut reader = &buf[..];
    assert!(ObservedAddress::decode(&mut reader, false).is_err());
    
    // Truncated IPv4 address
    let mut buf = BytesMut::new();
    crate::coding::BufMutExt::write_var(&mut buf, 1); // sequence number
    buf.put_slice(&[192, 168]); // Only 2 bytes instead of 4
    let mut reader = &buf[..];
    assert!(ObservedAddress::decode(&mut reader, false).is_err());
    
    // Truncated IPv6 address
    let mut buf = BytesMut::new();
    crate::coding::BufMutExt::write_var(&mut buf, 1); // sequence number
    buf.put_slice(&[0; 8]); // Only 8 bytes instead of 16
    let mut reader = &buf[..];
    assert!(ObservedAddress::decode(&mut reader, true).is_err());
}

#[test]
fn test_observed_address_edge_cases() {
    // Test edge case addresses
    
    // Loopback addresses
    let loopback_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80);
    let loopback_v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 80);
    
    for addr in [loopback_v4, loopback_v6] {
        let frame = ObservedAddress {
            sequence_number: VarInt::from_u32(3),
            address: addr,
        };
        
        let mut buf = BytesMut::new();
        frame.encode(&mut buf);
        
        let mut reader = &buf[4..]; // Skip frame type (4 bytes for VarInt)
        let is_ipv6 = addr.is_ipv6();
        let decoded = ObservedAddress::decode(&mut reader, is_ipv6).unwrap();
        assert_eq!(decoded.sequence_number, VarInt::from_u32(3));
        assert_eq!(decoded.address, addr);
    }
    
    // Edge case ports
    let test_ports = vec![0, 1, 80, 443, 8080, 32768, 65535];
    
    for port in test_ports {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port);
        let frame = ObservedAddress {
            sequence_number: VarInt::from_u32(4),
            address: addr,
        };
        
        let mut buf = BytesMut::new();
        frame.encode(&mut buf);
        
        let mut reader = &buf[4..]; // Skip frame type (4 bytes for VarInt)
        let decoded = ObservedAddress::decode(&mut reader, false).unwrap(); // IPv4
        assert_eq!(decoded.sequence_number, VarInt::from_u32(4));
        assert_eq!(decoded.address.port(), port);
    }
}

#[test]
fn test_observed_address_wire_format() {
    // Test exact wire format for compatibility
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
    let frame = ObservedAddress {
        sequence_number: VarInt::from_u32(5),
        address: addr,
    };
    
    let mut buf = BytesMut::new();
    frame.encode(&mut buf);
    
    // Verify wire format:
    // - Frame type (OBSERVED_ADDRESS_IPV4 = 0x9f81a6 as 4-byte VarInt)
    // - Sequence number (5 as 1-byte VarInt)
    // - IPv4 bytes (192, 168, 1, 1) 
    // - Port in network byte order (8080 = 0x1F90)
    
    let expected = vec![
        0x80, 0x9f, 0x81, 0xa6, // Frame type as 4-byte VarInt
        5,                      // Sequence number as 1-byte VarInt
        192, 168, 1, 1,         // IPv4 address
        0x1F, 0x90,             // Port 8080 in big-endian
    ];
    
    assert_eq!(&buf[..], &expected[..]);
}

#[test]
fn test_observed_address_frame_integration() {
    // Test that ObservedAddress integrates properly with Frame enum
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5000);
    let observed_frame = ObservedAddress {
        sequence_number: VarInt::from_u32(6),
        address: addr,
    };
    
    let frame = Frame::ObservedAddress(observed_frame);
    
    // Test that we can create the frame variant and encode it
    match &frame {
        Frame::ObservedAddress(obs) => {
            assert_eq!(obs.address, addr);
            
            // Test encoding through the struct directly
            let mut buf = BytesMut::new();
            obs.encode(&mut buf);
            assert_eq!(buf[0], 0x80); // First byte of VarInt for 0x9f81a6
            assert_eq!(buf[1], 0x9f); // Second byte of VarInt
            assert_eq!(buf[2], 0x81); // Third byte of VarInt
            assert_eq!(buf[3], 0xa6); // Fourth byte of VarInt
        }
        _ => panic!("Wrong frame type"),
    }
}

#[test] 
fn test_observed_address_unspecified() {
    // Test that unspecified addresses are handled correctly
    let unspecified_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    let unspecified_v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
    
    for addr in [unspecified_v4, unspecified_v6] {
        let frame = ObservedAddress {
            sequence_number: VarInt::from_u32(7),
            address: addr,
        };
        
        let mut buf = BytesMut::new();
        frame.encode(&mut buf);
        
        let mut reader = &buf[4..]; // Skip frame type (4 bytes for VarInt)
        let is_ipv6 = addr.is_ipv6();
        let decoded = ObservedAddress::decode(&mut reader, is_ipv6).unwrap();
        assert_eq!(decoded.sequence_number, VarInt::from_u32(7));
        assert_eq!(decoded.address, addr);
    }
}