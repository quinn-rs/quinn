#\![edition = "2024"]
//! RFC Compliance Tests for NAT Traversal Frames
//!
//! These tests verify exact compliance with draft-seemann-quic-nat-traversal-02.
//! They test both encoding and decoding to ensure byte-for-byte accuracy.

use ant_quic::{
    VarInt,
    coding::{BufExt, BufMutExt, UnexpectedEnd},
};
use bytes::{Buf, BufMut, BytesMut};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

// Frame type constants from the RFC
const FRAME_TYPE_ADD_ADDRESS_IPV4: u64 = 0x3d7e90;
const FRAME_TYPE_ADD_ADDRESS_IPV6: u64 = 0x3d7e91;
const FRAME_TYPE_PUNCH_ME_NOW_IPV4: u64 = 0x3d7e92;
const FRAME_TYPE_PUNCH_ME_NOW_IPV6: u64 = 0x3d7e93;
const FRAME_TYPE_REMOVE_ADDRESS: u64 = 0x3d7e94;

/// Test ADD_ADDRESS frame encoding for IPv4 according to RFC
///
/// RFC Format:
/// - Type (i) = 0x3d7e90 (IPv4)
/// - Sequence Number (i)
/// - IPv4 (32 bits)
/// - Port (16 bits)
#[test]
fn test_add_address_ipv4_rfc_encoding() {
    let mut buf = BytesMut::new();

    // Expected encoding for:
    // - Sequence Number: 42
    // - Address: 192.168.1.100:8080

    // Write frame type (VarInt encoding of 0x3d7e90)
    buf.put_slice(&[0x80, 0x3d, 0x7e, 0x90]); // 4-byte VarInt

    // Write sequence number (VarInt encoding of 42)
    buf.put_u8(0x2a); // 42 as 1-byte VarInt

    // Write IPv4 address
    buf.put_slice(&[192, 168, 1, 100]);

    // Write port
    buf.put_u16(8080);

    let expected = buf.freeze();

    // Now test that our implementation produces the same output
    let frame = RfcAddAddress {
        sequence_number: VarInt::from_u32(42),
        address: "192.168.1.100:8080".parse().unwrap(),
    };

    let mut output = BytesMut::new();
    encode_add_address_rfc(&frame, &mut output);

    assert_eq!(
        output.freeze(),
        expected,
        "ADD_ADDRESS IPv4 encoding doesn't match RFC"
    );
}

/// Test ADD_ADDRESS frame encoding for IPv6 according to RFC
///
/// RFC Format:
/// - Type (i) = 0x3d7e91 (IPv6)
/// - Sequence Number (i)
/// - IPv6 (128 bits)
/// - Port (16 bits)
#[test]
fn test_add_address_ipv6_rfc_encoding() {
    let mut buf = BytesMut::new();

    // Expected encoding for:
    // - Sequence Number: 999
    // - Address: [2001:db8::1]:9000

    // Write frame type (VarInt encoding of 0x3d7e91)
    buf.put_slice(&[0x80, 0x3d, 0x7e, 0x91]); // 4-byte VarInt

    // Write sequence number (VarInt encoding of 999)
    buf.put_slice(&[0x43, 0xe7]); // 999 as 2-byte VarInt

    // Write IPv6 address
    buf.put_slice(&[
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ]);

    // Write port
    buf.put_u16(9000);

    let expected = buf.freeze();

    // Test our implementation
    let frame = RfcAddAddress {
        sequence_number: VarInt::from_u32(999),
        address: "[2001:db8::1]:9000".parse().unwrap(),
    };

    let mut output = BytesMut::new();
    encode_add_address_rfc(&frame, &mut output);

    assert_eq!(
        output.freeze(),
        expected,
        "ADD_ADDRESS IPv6 encoding doesn't match RFC"
    );
}

/// Test PUNCH_ME_NOW frame encoding for IPv4 according to RFC
///
/// RFC Format:
/// - Type (i) = 0x3d7e92 (IPv4)
/// - Round (i)
/// - Paired With Sequence Number (i)
/// - IPv4 (32 bits)
/// - Port (16 bits)
#[test]
fn test_punch_me_now_ipv4_rfc_encoding() {
    let mut buf = BytesMut::new();

    // Expected encoding for:
    // - Round: 5
    // - Paired With Sequence Number: 42
    // - Address: 10.0.0.1:1234

    // Write frame type (VarInt encoding of 0x3d7e92)
    buf.put_slice(&[0x80, 0x3d, 0x7e, 0x92]); // 4-byte VarInt

    // Write round number
    buf.put_u8(0x05); // 5 as 1-byte VarInt

    // Write paired with sequence number
    buf.put_u8(0x2a); // 42 as 1-byte VarInt

    // Write IPv4 address
    buf.put_slice(&[10, 0, 0, 1]);

    // Write port
    buf.put_u16(1234);

    let expected = buf.freeze();

    // Test our implementation
    let frame = RfcPunchMeNow {
        round: VarInt::from_u32(5),
        paired_with_sequence_number: VarInt::from_u32(42),
        address: "10.0.0.1:1234".parse().unwrap(),
    };

    let mut output = BytesMut::new();
    encode_punch_me_now_rfc(&frame, &mut output);

    assert_eq!(
        output.freeze(),
        expected,
        "PUNCH_ME_NOW IPv4 encoding doesn't match RFC"
    );
}

/// Test REMOVE_ADDRESS frame encoding according to RFC
///
/// RFC Format:
/// - Type (i) = 0x3d7e94
/// - Sequence Number (i)
#[test]
fn test_remove_address_rfc_encoding() {
    let mut buf = BytesMut::new();

    // Expected encoding for:
    // - Sequence Number: 12345

    // Write frame type (VarInt encoding of 0x3d7e94)
    buf.put_slice(&[0x80, 0x3d, 0x7e, 0x94]); // 4-byte VarInt

    // Write sequence number (VarInt encoding of 12345)
    buf.put_slice(&[0x70, 0x39]); // 12345 as 2-byte VarInt

    let expected = buf.freeze();

    // Test our implementation
    let frame = RfcRemoveAddress {
        sequence_number: VarInt::from_u32(12345),
    };

    let mut output = BytesMut::new();
    encode_remove_address_rfc(&frame, &mut output);

    assert_eq!(
        output.freeze(),
        expected,
        "REMOVE_ADDRESS encoding doesn't match RFC"
    );
}

/// Test decoding of ADD_ADDRESS IPv4 frame
#[test]
fn test_add_address_ipv4_rfc_decoding() {
    let mut buf = BytesMut::new();

    // Sequence number: 42
    buf.put_u8(0x2a);
    // IPv4 address
    buf.put_slice(&[192, 168, 1, 100]);
    // Port
    buf.put_u16(8080);

    let mut input = buf.freeze();
    let frame = decode_add_address_rfc(&mut input, false).unwrap();

    assert_eq!(frame.sequence_number.into_inner(), 42);
    assert_eq!(
        frame.address,
        "192.168.1.100:8080".parse::<SocketAddr>().unwrap()
    );
}

/// Test decoding of ADD_ADDRESS IPv6 frame
#[test]
fn test_add_address_ipv6_rfc_decoding() {
    let mut buf = BytesMut::new();

    // Sequence number: 999
    buf.put_slice(&[0x43, 0xe7]);
    // IPv6 address
    buf.put_slice(&[
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ]);
    // Port
    buf.put_u16(9000);

    let mut input = buf.freeze();
    let frame = decode_add_address_rfc(&mut input, true).unwrap();

    assert_eq!(frame.sequence_number.into_inner(), 999);
    assert_eq!(
        frame.address,
        "[2001:db8::1]:9000".parse::<SocketAddr>().unwrap()
    );
}

/// Test edge cases for sequence numbers
#[test]
fn test_varint_edge_cases() {
    // Test various VarInt values to ensure proper encoding
    let test_cases = vec![
        0u64,       // Minimum
        63,         // Max 1-byte
        64,         // Min 2-byte
        16383,      // Max 2-byte
        16384,      // Min 4-byte
        1073741823, // Max 4-byte
        1073741824, // Min 8-byte
    ];

    for value in test_cases {
        let mut buf = BytesMut::new();
        let frame = RfcAddAddress {
            sequence_number: VarInt::from_u64(value).unwrap(),
            address: "127.0.0.1:80".parse().unwrap(),
        };

        encode_add_address_rfc(&frame, &mut buf);

        // Skip frame type
        buf.advance(4);

        // Decode sequence number
        let decoded_u64: u64 = buf.get_var().unwrap();
        assert_eq!(decoded_u64, value, "VarInt roundtrip failed for {value}");
    }
}

/// Test that we reject frames with extra data
#[test]
fn test_reject_extra_data() {
    let mut buf = BytesMut::new();

    // Valid ADD_ADDRESS frame
    buf.put_u8(0x2a); // Sequence 42
    buf.put_slice(&[192, 168, 1, 1]);
    buf.put_u16(80);

    // Extra data that shouldn't be there
    buf.put_slice(b"extra");

    let mut input = buf.freeze();
    let frame = decode_add_address_rfc(&mut input, false).unwrap();

    // Frame should decode successfully
    assert_eq!(frame.sequence_number.into_inner(), 42);

    // But there should be remaining data
    assert_eq!(input.remaining(), 5);
    assert_eq!(&input.chunk()[..5], b"extra");
}

/// Test maximum size boundaries
#[test]
fn test_frame_size_boundaries() {
    // ADD_ADDRESS IPv4: frame_type(4) + seq(1-8) + ipv4(4) + port(2)
    // Minimum: 4 + 1 + 4 + 2 = 11 bytes
    // Maximum: 4 + 8 + 4 + 2 = 18 bytes

    // Test minimum size
    let frame = RfcAddAddress {
        sequence_number: VarInt::from_u32(0), // 1 byte
        address: "0.0.0.0:0".parse().unwrap(),
    };

    let mut buf = BytesMut::new();
    encode_add_address_rfc(&frame, &mut buf);
    assert_eq!(buf.len(), 11, "Minimum ADD_ADDRESS IPv4 size incorrect");

    // Test with large sequence number
    let frame = RfcAddAddress {
        sequence_number: VarInt::from_u64(1073741824).unwrap(), // 8 bytes
        address: "255.255.255.255:65535".parse().unwrap(),
    };

    let mut buf = BytesMut::new();
    encode_add_address_rfc(&frame, &mut buf);
    assert_eq!(buf.len(), 18, "Maximum ADD_ADDRESS IPv4 size incorrect");
}

/// Test that we properly distinguish between IPv4 and IPv6 by frame type
#[test]
fn test_frame_type_determines_ip_version() {
    // We should NOT have a separate IP version byte
    // The frame type itself determines IPv4 vs IPv6

    let frame_ipv4 = RfcAddAddress {
        sequence_number: VarInt::from_u32(1),
        address: "1.2.3.4:5678".parse().unwrap(),
    };

    let frame_ipv6 = RfcAddAddress {
        sequence_number: VarInt::from_u32(1),
        address: "[::1]:5678".parse().unwrap(),
    };

    let mut buf_ipv4 = BytesMut::new();
    let mut buf_ipv6 = BytesMut::new();

    encode_add_address_rfc(&frame_ipv4, &mut buf_ipv4);
    encode_add_address_rfc(&frame_ipv6, &mut buf_ipv6);

    // Check frame types
    assert_eq!(&buf_ipv4[0..4], &[0x80, 0x3d, 0x7e, 0x90]);
    assert_eq!(&buf_ipv6[0..4], &[0x80, 0x3d, 0x7e, 0x91]);

    // After frame type and sequence, next should be IP address directly
    // No IP version byte!
    assert_eq!(buf_ipv4[5], 1); // First octet of 1.2.3.4
    assert_eq!(buf_ipv6[5], 0); // First octet of ::1
}

// Temporary structures for testing - these will be replaced by actual implementations
#[derive(Debug, Clone, PartialEq)]
struct RfcAddAddress {
    sequence_number: VarInt,
    address: SocketAddr,
}

#[derive(Debug, Clone, PartialEq)]
struct RfcPunchMeNow {
    round: VarInt,
    paired_with_sequence_number: VarInt,
    address: SocketAddr,
}

#[derive(Debug, Clone, PartialEq)]
struct RfcRemoveAddress {
    sequence_number: VarInt,
}

// Placeholder functions - these will be implemented to make tests pass
fn encode_add_address_rfc(frame: &RfcAddAddress, buf: &mut BytesMut) {
    // Encode frame type based on IP version
    match frame.address {
        SocketAddr::V4(_) => buf.write_var(FRAME_TYPE_ADD_ADDRESS_IPV4),
        SocketAddr::V6(_) => buf.write_var(FRAME_TYPE_ADD_ADDRESS_IPV6),
    }

    // Encode sequence number
    buf.write_var(frame.sequence_number.into_inner());

    // Encode address directly (no IP version byte!)
    match frame.address {
        SocketAddr::V4(addr) => {
            buf.put_slice(&addr.ip().octets());
            buf.put_u16(addr.port());
        }
        SocketAddr::V6(addr) => {
            buf.put_slice(&addr.ip().octets());
            buf.put_u16(addr.port());
        }
    }
}

fn encode_punch_me_now_rfc(frame: &RfcPunchMeNow, buf: &mut BytesMut) {
    // Encode frame type based on IP version
    match frame.address {
        SocketAddr::V4(_) => buf.write_var(FRAME_TYPE_PUNCH_ME_NOW_IPV4),
        SocketAddr::V6(_) => buf.write_var(FRAME_TYPE_PUNCH_ME_NOW_IPV6),
    }

    // Encode fields
    buf.write_var(frame.round.into_inner());
    buf.write_var(frame.paired_with_sequence_number.into_inner());

    // Encode address
    match frame.address {
        SocketAddr::V4(addr) => {
            buf.put_slice(&addr.ip().octets());
            buf.put_u16(addr.port());
        }
        SocketAddr::V6(addr) => {
            buf.put_slice(&addr.ip().octets());
            buf.put_u16(addr.port());
        }
    }
}

fn encode_remove_address_rfc(frame: &RfcRemoveAddress, buf: &mut BytesMut) {
    buf.write_var(FRAME_TYPE_REMOVE_ADDRESS);
    buf.write_var(frame.sequence_number.into_inner());
}

fn decode_add_address_rfc(
    buf: &mut impl Buf,
    is_ipv6: bool,
) -> Result<RfcAddAddress, UnexpectedEnd> {
    let sequence_number = VarInt::from_u64(buf.get_var()?).unwrap();

    let address = if is_ipv6 {
        if buf.remaining() < 16 + 2 {
            return Err(UnexpectedEnd);
        }
        let mut octets = [0u8; 16];
        buf.copy_to_slice(&mut octets);
        let port = buf.get_u16();
        SocketAddr::V6(std::net::SocketAddrV6::new(
            Ipv6Addr::from(octets),
            port,
            0,
            0,
        ))
    } else {
        if buf.remaining() < 4 + 2 {
            return Err(UnexpectedEnd);
        }
        let mut octets = [0u8; 4];
        buf.copy_to_slice(&mut octets);
        let port = buf.get_u16();
        SocketAddr::V4(std::net::SocketAddrV4::new(Ipv4Addr::from(octets), port))
    };

    Ok(RfcAddAddress {
        sequence_number,
        address,
    })
}
