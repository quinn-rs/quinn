//! Enhanced property testing configuration for ant-quic
//!
//! This module provides comprehensive property testing strategies and configurations
//! to ensure the robustness and correctness of the QUIC implementation.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use proptest::prelude::*;
use proptest::prop_oneof;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

/// Default configuration for property tests with increased coverage
pub fn default_config() -> ProptestConfig {
    ProptestConfig {
        cases: 1000, // Increased from default 256
        max_shrink_iters: 1000,
        max_global_rejects: 10000,
        max_local_rejects: 1000,
        ..ProptestConfig::default()
    }
}

/// Strategy for generating valid IPv4 addresses
pub fn arb_ipv4_addr() -> impl Strategy<Value = Ipv4Addr> {
    any::<[u8; 4]>().prop_map(Ipv4Addr::from)
}

/// Strategy for generating valid IPv6 addresses
pub fn arb_ipv6_addr() -> impl Strategy<Value = Ipv6Addr> {
    any::<[u8; 16]>().prop_map(Ipv6Addr::from)
}

/// Strategy for generating valid IP addresses (both v4 and v6)
pub fn arb_ip_addr() -> impl Strategy<Value = IpAddr> {
    prop_oneof![
        arb_ipv4_addr().prop_map(IpAddr::V4),
        arb_ipv6_addr().prop_map(IpAddr::V6),
    ]
}

/// Strategy for generating valid port numbers
pub fn arb_port() -> impl Strategy<Value = u16> {
    1024u16..=65535u16
}

/// Strategy for generating valid socket addresses
pub fn arb_socket_addr() -> impl Strategy<Value = SocketAddr> {
    (arb_ip_addr(), arb_port()).prop_map(|(ip, port)| SocketAddr::new(ip, port))
}

/// Strategy for generating connection IDs
pub fn arb_connection_id() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..=20) // Valid CID length range
}

/// Strategy for generating durations within reasonable bounds
pub fn arb_duration() -> impl Strategy<Value = Duration> {
    (1..=3600u64).prop_map(Duration::from_secs) // 1 second to 1 hour
}

/// Strategy for generating valid peer IDs
pub fn arb_peer_id() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>()
}

/// Strategy for generating network interface names
pub fn arb_interface_name() -> impl Strategy<Value = String> {
    "[a-zA-Z][a-zA-Z0-9._-]{0,15}".prop_map(|s| s.to_string())
}

/// Strategy for generating valid priority values
pub fn arb_priority() -> impl Strategy<Value = u32> {
    1..=u32::MAX
}

/// Strategy for generating candidate addresses with various characteristics
pub fn arb_candidate_address() -> impl Strategy<Value = ant_quic::CandidateAddress> {
    (arb_socket_addr(), arb_priority()).prop_map(|(addr, priority)| ant_quic::CandidateAddress {
        address: addr,
        priority,
        source: ant_quic::CandidateSource::Local,
        state: ant_quic::CandidateState::New,
    })
}

/// Strategy for generating realistic network delays
pub fn arb_network_delay() -> impl Strategy<Value = Duration> {
    prop_oneof![
        (1..=100u64).prop_map(Duration::from_millis), // Fast network
        (100..=500u64).prop_map(Duration::from_millis), // Normal network
        (500..=2000u64).prop_map(Duration::from_millis), // Slow network
    ]
}

/// Strategy for generating packet sizes within realistic bounds
pub fn arb_packet_size() -> impl Strategy<Value = usize> {
    64usize..=65535usize
}

/// Strategy for generating realistic RTT values
pub fn arb_rtt() -> impl Strategy<Value = Duration> {
    prop_oneof![
        (1..=50u64).prop_map(Duration::from_millis), // Excellent connection
        (50..=100u64).prop_map(Duration::from_millis), // Good connection
        (100..=200u64).prop_map(Duration::from_millis), // Fair connection
        (200..=500u64).prop_map(Duration::from_millis), // Poor connection
    ]
}

/// Strategy for generating realistic bandwidth values (in Mbps)
pub fn arb_bandwidth() -> impl Strategy<Value = u32> {
    prop_oneof![
        1u32..=10u32,     // Slow connection
        10u32..=50u32,    // Average connection
        50u32..=200u32,   // Fast connection
        200u32..=1000u32, // Very fast connection
    ]
}

/// Strategy for generating realistic packet loss rates
pub fn arb_packet_loss_rate() -> impl Strategy<Value = f64> {
    prop_oneof![
        0.0..=0.001,  // Excellent network
        0.001..=0.01, // Good network
        0.01..=0.05,  // Fair network
        0.05..=0.15,  // Poor network
    ]
}

/// Strategy for generating realistic jitter values
pub fn arb_jitter() -> impl Strategy<Value = Duration> {
    (0..=100u64).prop_map(Duration::from_millis)
}

/// Comprehensive network condition strategy
pub fn arb_network_conditions() -> impl Strategy<Value = NetworkConditions> {
    (
        arb_rtt(),
        arb_bandwidth(),
        arb_packet_loss_rate(),
        arb_jitter(),
    )
        .prop_map(|(rtt, bandwidth, loss_rate, jitter)| NetworkConditions {
            rtt,
            bandwidth_mbps: bandwidth,
            packet_loss_rate: loss_rate,
            jitter,
        })
}

/// Network conditions for property testing
#[derive(Debug, Clone)]
pub struct NetworkConditions {
    pub rtt: Duration,
    pub bandwidth_mbps: u32,
    pub packet_loss_rate: f64,
    pub jitter: Duration,
}

/// Strategy for generating valid transport parameter values
use ant_quic::transport_parameters::TransportParameters;

pub fn arb_transport_params() -> impl Strategy<Value = TransportParameters> {
    // Generate transport parameters by decoding what we encode using the public codec APIs
    (
        any::<u32>(), // initial_max_data
        any::<u32>(), // initial_max_stream_data_bidi_local
        any::<u32>(), // initial_max_stream_data_bidi_remote
        any::<u32>(), // initial_max_stream_data_uni
        any::<u32>(), // initial_max_streams_bidi
        any::<u32>(), // initial_max_streams_uni
        any::<u16>(), // ack_delay_exponent (clamped in writer)
        any::<u16>(), // max_ack_delay
        any::<u8>(),  // active_connection_id_limit
    )
        .prop_map(
            |(
                max_data,
                stream_data_bidi_local,
                stream_data_bidi_remote,
                stream_data_uni,
                streams_bidi,
                streams_uni,
                ack_delay_exp,
                max_ack_delay,
                cid_limit,
            )| {
                use ant_quic::coding::Codec;
                use bytes::BytesMut;

                // Build a writer using the same encoding routine as the stack by constructing
                // a minimal `TransportParameters` via the public constructor equivalent: decode of what we encode.
                // We leverage the fact that TransportParameters::encode/::decode are public.

                // Start from library defaults by encoding an internally created params via Connection::handshake path
                // Since we cannot construct directly, synthesize a buffer of well-formed fields.

                // Helper to write a single varint field pair (id, value)
                fn write_kv(buf: &mut BytesMut, id: u64, val: u64) {
                    ant_quic::VarInt::try_from(id).unwrap().encode(buf);
                    // Values are encoded as varint with a preceding length
                    let mut tmp = BytesMut::new();
                    ant_quic::VarInt::try_from(val).unwrap().encode(&mut tmp);
                    ant_quic::VarInt::from_u32(tmp.len() as u32).encode(buf);
                    buf.extend_from_slice(&tmp);
                }

                let mut buf = BytesMut::new();

                // Use the known standard IDs from the enum inside TransportParameterId
                // We mirror minimal core parameters; decoder ignores unknowns safely.
                // initial_max_data (0x04)
                write_kv(&mut buf, 0x04, max_data as u64);
                // initial_max_stream_data_bidi_local (0x05)
                write_kv(&mut buf, 0x05, stream_data_bidi_local as u64);
                // initial_max_stream_data_bidi_remote (0x06)
                write_kv(&mut buf, 0x06, stream_data_bidi_remote as u64);
                // initial_max_stream_data_uni (0x07)
                write_kv(&mut buf, 0x07, stream_data_uni as u64);
                // initial_max_streams_bidi (0x08)
                write_kv(&mut buf, 0x08, streams_bidi as u64);
                // initial_max_streams_uni (0x09)
                write_kv(&mut buf, 0x09, streams_uni as u64);
                // ack_delay_exponent (0x0a)
                write_kv(&mut buf, 0x0a, (ack_delay_exp.min(20)) as u64);
                // max_ack_delay (0x0b)
                write_kv(&mut buf, 0x0b, max_ack_delay as u64);
                // active_connection_id_limit (0x0e)
                write_kv(&mut buf, 0x0e, cid_limit.max(2) as u64);

                // Now decode via public API
                let mut cursor = std::io::Cursor::new(&buf[..]);
                // Use server side for decoding in tests (side doesn't affect these core params)
                TransportParameters::read(ant_quic::Side::Server, &mut cursor)
                    .expect("Failed to decode synthesized transport parameters")
            },
        )
}

// Note: Frame and Packet types are internal to ant_quic and not exposed in the public API.
// These strategies are commented out but kept for potential future use if the types become public.

/*
/// Strategy for generating frame sequences
pub fn arb_frame_sequence() -> impl Strategy<Value = Vec<ant_quic::Frame>> {
    prop::collection::vec(
        prop_oneof![
            arb_stream_frame(),
            arb_ack_frame(),
            arb_padding_frame(),
            arb_ping_frame(),
            arb_close_frame(),
        ],
        0..=10
    )
}

/// Strategy for generating stream frames
pub fn arb_stream_frame() -> impl Strategy<Value = ant_quic::Frame> {
    (any::<u64>(), any::<u64>(), any::<Vec<u8>>()).prop_map(|(stream_id, offset, data)| {
        ant_quic::Frame::Stream {
            id: ant_quic::StreamId(stream_id),
            offset,
            length: data.len() as u64,
            fin: false,
            data,
        }
    })
}

/// Strategy for generating ACK frames
pub fn arb_ack_frame() -> impl Strategy<Value = ant_quic::Frame> {
    (1..=100u64, 1..=1000u64).prop_map(|(delay, largest)| {
        ant_quic::Frame::Ack {
            delay,
            largest,
            ranges: vec![0..=largest],
        }
    })
}

/// Strategy for generating padding frames
pub fn arb_padding_frame() -> impl Strategy<Value = ant_quic::Frame> {
    (1..=100usize).prop_map(ant_quic::Frame::Padding)
}

/// Strategy for generating ping frames
pub fn arb_ping_frame() -> impl Strategy<Value = ant_quic::Frame> {
    Just(ant_quic::Frame::Ping)
}

/// Strategy for generating close frames
pub fn arb_close_frame() -> impl Strategy<Value = ant_quic::Frame> {
    (any::<u64>(), any::<String>()).prop_map(|(code, reason)| {
        ant_quic::Frame::Close {
            error_code: ant_quic::TransportErrorCode(code & 0xFF), // Valid code range
            frame_type: None,
            reason: reason.into_bytes().into(),
        }
    })
}

/// Strategy for generating realistic QUIC packet sequences
pub fn arb_packet_sequence() -> impl Strategy<Value = Vec<ant_quic::Packet>> {
    prop::collection::vec(arb_packet(), 1..=5)
}

/// Strategy for generating QUIC packets
pub fn arb_packet() -> impl Strategy<Value = ant_quic::Packet> {
    (arb_connection_id(), arb_frame_sequence()).prop_map(|(dst_cid, frames)| {
        ant_quic::Packet {
            header: ant_quic::Header::Short {
                dst_cid,
                number: 0,
                spin: false,
                key_phase: false,
            },
            frames,
        }
    })
}
*/
