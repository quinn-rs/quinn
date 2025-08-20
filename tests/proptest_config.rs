//! Enhanced property testing configuration for ant-quic
//!
//! This module provides comprehensive property testing strategies and configurations
//! to ensure the robustness and correctness of the QUIC implementation.

use proptest::prelude::*;
use proptest::{prop_oneof, strategy::Just};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

/// Default configuration for property tests with increased coverage
pub fn default_config() -> ProptestConfig {
    ProptestConfig {
        cases: 1000,           // Increased from default 256
        max_shrink_iters: 1000,
        max_shrink_time: Duration::from_secs(30),
        max_global_rejects: 10000,
        max_local_rejects: 1000,
        ..ProptestConfig::default()
    }
}

/// Strategy for generating valid IPv4 addresses
pub fn arb_ipv4_addr() -> impl Strategy<Value = Ipv4Addr> {
    any::<[u8; 4]>().prop_map(|bytes| Ipv4Addr::from(bytes))
}

/// Strategy for generating valid IPv6 addresses
pub fn arb_ipv6_addr() -> impl Strategy<Value = Ipv6Addr> {
    any::<[u8; 16]>().prop_map(|bytes| Ipv6Addr::from(bytes))
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
    (1024..=65535u16) // Avoid system ports
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
    (arb_socket_addr(), arb_priority()).prop_map(|(addr, priority)| {
        ant_quic::CandidateAddress {
            address: addr,
            priority,
            source: ant_quic::CandidateSource::Local,
            state: ant_quic::CandidateState::New,
        }
    })
}

/// Strategy for generating realistic network delays
pub fn arb_network_delay() -> impl Strategy<Value = Duration> {
    prop_oneof![
        (1..=100u64).prop_map(Duration::from_millis),      // Fast network
        (100..=500u64).prop_map(Duration::from_millis),   // Normal network
        (500..=2000u64).prop_map(Duration::from_millis),  // Slow network
    ]
}

/// Strategy for generating packet sizes within realistic bounds
pub fn arb_packet_size() -> impl Strategy<Value = usize> {
    64..=65535 // Min Ethernet frame to max UDP packet
}

/// Strategy for generating realistic RTT values
pub fn arb_rtt() -> impl Strategy<Value = Duration> {
    prop_oneof![
        (1..=50u64).prop_map(Duration::from_millis),      // Excellent connection
        (50..=100u64).prop_map(Duration::from_millis),   // Good connection
        (100..=200u64).prop_map(Duration::from_millis),  // Fair connection
        (200..=500u64).prop_map(Duration::from_millis),  // Poor connection
    ]
}

/// Strategy for generating realistic bandwidth values (in Mbps)
pub fn arb_bandwidth() -> impl Strategy<Value = u32> {
    prop_oneof![
        1..=10,      // Slow connection
        10..=50,     // Average connection
        50..=200,    // Fast connection
        200..=1000,  // Very fast connection
    ]
}

/// Strategy for generating realistic packet loss rates
pub fn arb_packet_loss_rate() -> impl Strategy<Value = f64> {
    prop_oneof![
        0.0..=0.001,   // Excellent network
        0.001..=0.01,  // Good network
        0.01..=0.05,   // Fair network
        0.05..=0.15,   // Poor network
    ]
}

/// Strategy for generating realistic jitter values
pub fn arb_jitter() -> impl Strategy<Value = Duration> {
    (0..=100u64).prop_map(Duration::from_millis)
}

/// Comprehensive network condition strategy
pub fn arb_network_conditions() -> impl Strategy<Value = NetworkConditions> {
    (arb_rtt(), arb_bandwidth(), arb_packet_loss_rate(), arb_jitter())
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
pub fn arb_transport_params() -> impl Strategy<Value = ant_quic::TransportParameters> {
    // Generate valid transport parameters within specification limits
    (
        any::<u32>(), // initial_max_data
        any::<u32>(), // initial_max_stream_data_bidi_local
        any::<u32>(), // initial_max_stream_data_bidi_remote
        any::<u32>(), // initial_max_stream_data_uni
        any::<u32>(), // initial_max_streams_bidi
        any::<u32>(), // initial_max_streams_uni
        any::<u16>(), // ack_delay_exponent
        any::<u16>(), // max_ack_delay
        any::<u8>(),  // active_connection_id_limit
    )
    .prop_map(|(
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
        let mut params = ant_quic::TransportParameters::default();
        params.initial_max_data = max_data;
        params.initial_max_stream_data_bidi_local = stream_data_bidi_local;
        params.initial_max_stream_data_bidi_remote = stream_data_bidi_remote;
        params.initial_max_stream_data_uni = stream_data_uni;
        params.initial_max_streams_bidi = streams_bidi;
        params.initial_max_streams_uni = streams_uni;
        params.ack_delay_exponent = ack_delay_exp.min(20); // RFC limit
        params.max_ack_delay = max_ack_delay;
        params.active_connection_id_limit = cid_limit.max(2).min(8); // RFC limits
        params
    })
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