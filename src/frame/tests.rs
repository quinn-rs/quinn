// Comprehensive unit tests for QUIC Address Discovery frames

use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use bytes::{Buf, BufMut, BytesMut};
use crate::coding::BufMutExt;

#[test]
fn test_observed_address_frame_ipv4() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
    let frame = ObservedAddress {
        address: addr,
    };
    
    // Test encoding
    let mut buf = BytesMut::new();
    frame.encode(&mut buf);
    
    // Frame type is written by encode() as VarInt
    // 0x43 (67) uses 2-byte VarInt encoding: first byte 0x40, second byte 0x43
    assert_eq!(buf[0], 0x40); // First byte of VarInt encoding for 67
    assert_eq!(buf[1], 0x43); // Second byte contains the actual value
    
    // Test decoding - skip frame type bytes (2 bytes for VarInt)
    let mut reader = &buf[2..];
    let decoded = ObservedAddress::decode(&mut reader).unwrap();
    
    assert_eq!(decoded.address, addr);
}

#[test]
fn test_observed_address_frame_ipv6() {
    let addr = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), 
        443
    );
    let frame = ObservedAddress {
        address: addr,
    };
    
    // Test encoding
    let mut buf = BytesMut::new();
    frame.encode(&mut buf);
    
    // Frame type is written by encode() as VarInt
    // 0x43 (67) uses 2-byte VarInt encoding: first byte 0x40, second byte 0x43
    assert_eq!(buf[0], 0x40); // First byte of VarInt encoding for 67
    assert_eq!(buf[1], 0x43); // Second byte contains the actual value
    
    // Test decoding - skip frame type bytes (2 bytes for VarInt)
    let mut reader = &buf[2..];
    let decoded = ObservedAddress::decode(&mut reader).unwrap();
    
    assert_eq!(decoded.address, addr);
}

#[test]
fn test_observed_address_malformed() {
    // Test various malformed inputs
    
    // Empty buffer
    let buf = BytesMut::new();
    let mut reader = &buf[..];
    assert!(ObservedAddress::decode(&mut reader).is_err());
    
    // Invalid address family
    let mut buf = BytesMut::new();
    buf.put_u8(0xFF); // Invalid address family
    let mut reader = &buf[..];
    assert!(ObservedAddress::decode(&mut reader).is_err());
    
    // Truncated IPv4 address
    let mut buf = BytesMut::new();
    buf.put_u8(4); // IPv4 indicator
    buf.put_slice(&[192, 168]); // Only 2 bytes instead of 4
    let mut reader = &buf[..];
    assert!(ObservedAddress::decode(&mut reader).is_err());
    
    // Truncated IPv6 address
    let mut buf = BytesMut::new();
    buf.put_u8(6); // IPv6 indicator
    buf.put_slice(&[0; 8]); // Only 8 bytes instead of 16
    let mut reader = &buf[..];
    assert!(ObservedAddress::decode(&mut reader).is_err());
}

#[test]
fn test_observed_address_edge_cases() {
    // Test edge case addresses
    
    // Loopback addresses
    let loopback_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80);
    let loopback_v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 80);
    
    for addr in vec![loopback_v4, loopback_v6] {
        let frame = ObservedAddress {
            address: addr,
        };
        
        let mut buf = BytesMut::new();
        frame.encode(&mut buf);
        
        let mut reader = &buf[2..]; // Skip frame type (2 bytes for VarInt)
        let decoded = ObservedAddress::decode(&mut reader).unwrap();
        assert_eq!(decoded.address, addr);
    }
    
    // Edge case ports
    let test_ports = vec![0, 1, 80, 443, 8080, 32768, 65535];
    
    for port in test_ports {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port);
        let frame = ObservedAddress {
            address: addr,
        };
        
        let mut buf = BytesMut::new();
        frame.encode(&mut buf);
        
        let mut reader = &buf[2..]; // Skip frame type (2 bytes for VarInt)
        let decoded = ObservedAddress::decode(&mut reader).unwrap();
        assert_eq!(decoded.address.port(), port);
    }
}

#[test]
fn test_observed_address_wire_format() {
    // Test exact wire format for compatibility
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
    let frame = ObservedAddress {
        address: addr,
    };
    
    let mut buf = BytesMut::new();
    frame.encode(&mut buf);
    
    // Verify wire format:
    // - Frame type (OBSERVED_ADDRESS = 0x43 as 2-byte VarInt: 0x40, 0x43)
    // - Address family (4 for IPv4)
    // - IPv4 bytes (192, 168, 1, 1) 
    // - Port in network byte order (8080 = 0x1F90)
    
    let expected = vec![
        0x40, 0x43,             // Frame type as 2-byte VarInt
        4,                      // IPv4 indicator
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
            assert_eq!(buf[0], 0x40); // First byte of VarInt for 0x43
            assert_eq!(buf[1], 0x43); // Second byte of VarInt
        }
        _ => panic!("Wrong frame type"),
    }
}

#[test] 
fn test_observed_address_unspecified() {
    // Test that unspecified addresses are handled correctly
    let unspecified_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    let unspecified_v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
    
    for addr in vec![unspecified_v4, unspecified_v6] {
        let frame = ObservedAddress {
            address: addr,
        };
        
        let mut buf = BytesMut::new();
        frame.encode(&mut buf);
        
        let mut reader = &buf[2..]; // Skip frame type (2 bytes for VarInt)
        let decoded = ObservedAddress::decode(&mut reader).unwrap();
        assert_eq!(decoded.address, addr);
    }
}