//! Property test generators for ant-quic types

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::{
    VarInt,
    frame::{Ack, EcnCounts, FrameType},
};
use proptest::prelude::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

/// Generate arbitrary VarInt values
pub fn arb_varint() -> impl Strategy<Value = VarInt> {
    prop_oneof![
        // Small values (1 byte)
        (0u64..=63).prop_map(|n| VarInt::from_u32(n as u32)),
        // Medium values (2 bytes)
        (64u64..=16383).prop_map(|n| VarInt::from_u32(n as u32)),
        // Large values (4 bytes)
        (16384u64..=1073741823).prop_map(|n| VarInt::from_u32(n as u32)),
        // Very large values (8 bytes)
        (1073741824u64..=4611686018427387903).prop_map(|n| VarInt::from_u64(n).unwrap()),
    ]
}

/// Generate arbitrary IPv4 addresses
pub fn arb_ipv4() -> impl Strategy<Value = Ipv4Addr> {
    (any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>())
        .prop_map(|(a, b, c, d)| Ipv4Addr::new(a, b, c, d))
}

/// Generate arbitrary IPv6 addresses
pub fn arb_ipv6() -> impl Strategy<Value = Ipv6Addr> {
    (
        any::<u16>(),
        any::<u16>(),
        any::<u16>(),
        any::<u16>(),
        any::<u16>(),
        any::<u16>(),
        any::<u16>(),
        any::<u16>(),
    )
        .prop_map(|(a, b, c, d, e, f, g, h)| Ipv6Addr::new(a, b, c, d, e, f, g, h))
}

/// Generate arbitrary IP addresses
pub fn arb_ip_addr() -> impl Strategy<Value = IpAddr> {
    prop_oneof![
        arb_ipv4().prop_map(IpAddr::V4),
        arb_ipv6().prop_map(IpAddr::V6),
    ]
}

/// Generate arbitrary socket addresses
pub fn arb_socket_addr() -> impl Strategy<Value = SocketAddr> {
    (arb_ip_addr(), 1u16..=65535).prop_map(|(ip, port)| SocketAddr::new(ip, port))
}

/// Generate arbitrary durations within reasonable bounds
pub fn arb_duration() -> impl Strategy<Value = Duration> {
    (0u64..=3600_000) // 0 to 1 hour in milliseconds
        .prop_map(Duration::from_millis)
}

/// Generate arbitrary connection IDs
pub fn arb_connection_id() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=20)
}

/// Generate arbitrary frame types for testing
/// Since FrameType constructor is private, we'll generate raw values and decode them
pub fn arb_frame_type() -> impl Strategy<Value = FrameType> {
    use ant_quic::coding::Codec;
    use bytes::BytesMut;

    // Generate common frame type values
    prop_oneof![
        Just(0x00u64), // PADDING
        Just(0x01u64), // PING
        Just(0x02u64), // ACK
        Just(0x04u64), // RESET_STREAM
        Just(0x05u64), // STOP_SENDING
        Just(0x06u64), // CRYPTO
        Just(0x07u64), // NEW_TOKEN
        Just(0x08u64), // STREAM
        Just(0x10u64), // MAX_DATA
        Just(0x11u64), // MAX_STREAM_DATA
        Just(0x12u64), // MAX_STREAMS_BIDI
        Just(0x13u64), // MAX_STREAMS_UNI
        Just(0x14u64), // DATA_BLOCKED
        Just(0x15u64), // STREAM_DATA_BLOCKED
        Just(0x16u64), // STREAMS_BLOCKED_BIDI
        Just(0x17u64), // STREAMS_BLOCKED_UNI
        Just(0x18u64), // NEW_CONNECTION_ID
        Just(0x19u64), // RETIRE_CONNECTION_ID
        Just(0x1au64), // PATH_CHALLENGE
        Just(0x1bu64), // PATH_RESPONSE
        Just(0x1cu64), // CONNECTION_CLOSE
        Just(0x1eu64), // HANDSHAKE_DONE
        // NAT traversal extension frames
        Just(0x40u64), // ADD_ADDRESS
        Just(0x41u64), // PUNCH_ME_NOW
        Just(0x42u64), // REMOVE_ADDRESS
        Just(0x43u64), // OBSERVED_ADDRESS
    ]
    .prop_map(|value| {
        // Encode and decode to create a valid FrameType
        let mut buf = BytesMut::new();
        VarInt::from_u64(value).unwrap().encode(&mut buf);
        let mut cursor = std::io::Cursor::new(&buf[..]);
        FrameType::decode(&mut cursor).unwrap()
    })
}

/// Generate arbitrary ACK frames
pub fn arb_ack() -> impl Strategy<Value = Ack> {
    (
        any::<u64>(),     // largest
        0u64..=1000,      // delay
        arb_bytes(0..32), // additional
        proptest::option::of(arb_ecn_counts()),
    )
        .prop_map(|(largest, delay, additional, ecn)| Ack {
            largest,
            delay,
            additional: additional.into(),
            ecn,
        })
}

/// Generate arbitrary ECN counts
pub fn arb_ecn_counts() -> impl Strategy<Value = EcnCounts> {
    (
        any::<u64>(), // ect0
        any::<u64>(), // ect1
        any::<u64>(), // ce
    )
        .prop_map(|(ect0, ect1, ce)| EcnCounts { ect0, ect1, ce })
}

/// Generate arbitrary NAT types for testing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    FullCone,
    Restricted,
    PortRestricted,
    Symmetric,
}

pub fn arb_nat_type() -> impl Strategy<Value = NatType> {
    prop_oneof![
        Just(NatType::FullCone),
        Just(NatType::Restricted),
        Just(NatType::PortRestricted),
        Just(NatType::Symmetric),
    ]
}

/// Generate arbitrary byte vectors of reasonable size
pub fn arb_bytes(size: std::ops::Range<usize>) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), size)
}

/// Generate arbitrary packet loss rates (0.0 to 1.0)
pub fn arb_loss_rate() -> impl Strategy<Value = f64> {
    (0u32..=100).prop_map(|n| n as f64 / 100.0)
}

/// Generate arbitrary network delays
pub fn arb_network_delay() -> impl Strategy<Value = Duration> {
    prop_oneof![
        // Local network (0-10ms)
        (0u64..=10).prop_map(Duration::from_millis),
        // Regional network (10-50ms)
        (10u64..=50).prop_map(Duration::from_millis),
        // Continental network (50-150ms)
        (50u64..=150).prop_map(Duration::from_millis),
        // Intercontinental (150-300ms)
        (150u64..=300).prop_map(Duration::from_millis),
        // Satellite (300-600ms)
        (300u64..=600).prop_map(Duration::from_millis),
    ]
}
