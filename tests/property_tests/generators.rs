//! Property test generators for ant-quic types

use ant_quic::{VarInt, frame::*, transport_parameters::*};
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
        (1073741824u64..=4611686018427387903).prop_map(VarInt::from),
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
pub fn arb_frame_type() -> impl Strategy<Value = FrameType> {
    prop_oneof![
        Just(FrameType::PADDING),
        Just(FrameType::PING),
        Just(FrameType::ACK),
        Just(FrameType::RESET_STREAM),
        Just(FrameType::STOP_SENDING),
        Just(FrameType::CRYPTO),
        Just(FrameType::NEW_TOKEN),
        Just(FrameType::STREAM),
        Just(FrameType::MAX_DATA),
        Just(FrameType::MAX_STREAM_DATA),
        Just(FrameType::MAX_STREAMS_BIDI),
        Just(FrameType::MAX_STREAMS_UNI),
        Just(FrameType::DATA_BLOCKED),
        Just(FrameType::STREAM_DATA_BLOCKED),
        Just(FrameType::STREAMS_BLOCKED_BIDI),
        Just(FrameType::STREAMS_BLOCKED_UNI),
        Just(FrameType::NEW_CONNECTION_ID),
        Just(FrameType::RETIRE_CONNECTION_ID),
        Just(FrameType::PATH_CHALLENGE),
        Just(FrameType::PATH_RESPONSE),
        Just(FrameType::CONNECTION_CLOSE),
        Just(FrameType::HANDSHAKE_DONE),
        // NAT traversal extension frames
        Just(Type(0x40)), // ADD_ADDRESS
        Just(Type(0x41)), // PUNCH_ME_NOW
        Just(Type(0x42)), // REMOVE_ADDRESS
        Just(Type(0x43)), // OBSERVED_ADDRESS
    ]
}

/// Generate arbitrary transport parameters
pub fn arb_transport_params() -> impl Strategy<Value = TransportParameters> {
    (
        proptest::option::of(arb_socket_addr()),
        proptest::option::of(arb_varint()),
        proptest::option::of(arb_varint()),
        proptest::option::of(arb_varint()),
        proptest::option::of(arb_varint()),
        proptest::option::of(arb_duration()),
        proptest::option::of(arb_varint()),
        proptest::option::of(arb_varint()),
        proptest::option::of(arb_varint()),
        proptest::option::of(any::<bool>()),
        proptest::option::of(prop::collection::vec(any::<u8>(), 0..=255)),
    )
        .prop_map(
            |(
                original_dst_cid,
                max_idle_timeout,
                max_udp_payload_size,
                initial_max_data,
                initial_max_stream_data_bidi_local,
                max_ack_delay,
                initial_max_streams_bidi,
                initial_max_streams_uni,
                ack_delay_exponent,
                disable_active_migration,
                stateless_reset_token,
            )| {
                let mut params = TransportParameters::default();

                if let Some(addr) = original_dst_cid {
                    params.original_dst_cid = Some(format!("{}", addr).into_bytes());
                }

                if let Some(timeout) = max_idle_timeout {
                    params.max_idle_timeout = Some(timeout.into());
                }

                if let Some(size) = max_udp_payload_size {
                    params.max_udp_payload_size = Some(size.into());
                }

                if let Some(data) = initial_max_data {
                    params.initial_max_data = data.into();
                }

                if let Some(data) = initial_max_stream_data_bidi_local {
                    params.initial_max_stream_data_bidi_local = data.into();
                }

                if let Some(delay) = max_ack_delay {
                    params.max_ack_delay = Some(delay.into());
                }

                if let Some(streams) = initial_max_streams_bidi {
                    params.initial_max_streams_bidi = streams.into();
                }

                if let Some(streams) = initial_max_streams_uni {
                    params.initial_max_streams_uni = streams.into();
                }

                if let Some(exp) = ack_delay_exponent {
                    params.ack_delay_exponent = Some(exp.into());
                }

                if let Some(disable) = disable_active_migration {
                    params.disable_active_migration = disable;
                }

                if let Some(token) = stateless_reset_token {
                    if token.len() == 16 {
                        params.stateless_reset_token = Some(token.try_into().unwrap());
                    }
                }

                params
            },
        )
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
