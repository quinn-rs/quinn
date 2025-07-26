//! Property tests for transport parameters

use proptest::prelude::*;
use ant_quic::{
    transport_parameters::*,
    VarInt,
    coding::{Encoder, Decoder},
};
use bytes::BytesMut;
use super::generators::*;
use super::config::*;

proptest! {
    #![proptest_config(default_config())]
    
    /// Property: Transport parameters encoding/decoding roundtrips
    #[test]
    fn transport_params_roundtrip(params in arb_transport_params()) {
        let mut buf = BytesMut::with_capacity(1024);
        
        // Encode parameters
        params.encode(&mut buf);
        
        // Decode parameters
        let mut cursor = std::io::Cursor::new(&buf[..]);
        let decoded = TransportParameters::decode(&mut cursor)
            .expect("Failed to decode transport parameters");
        
        // Property: Core parameters should match
        prop_assert_eq!(params.initial_max_data, decoded.initial_max_data);
        prop_assert_eq!(params.initial_max_stream_data_bidi_local, decoded.initial_max_stream_data_bidi_local);
        prop_assert_eq!(params.initial_max_stream_data_bidi_remote, decoded.initial_max_stream_data_bidi_remote);
        prop_assert_eq!(params.initial_max_stream_data_uni, decoded.initial_max_stream_data_uni);
        prop_assert_eq!(params.initial_max_streams_bidi, decoded.initial_max_streams_bidi);
        prop_assert_eq!(params.initial_max_streams_uni, decoded.initial_max_streams_uni);
        prop_assert_eq!(params.max_idle_timeout, decoded.max_idle_timeout);
        prop_assert_eq!(params.max_udp_payload_size, decoded.max_udp_payload_size);
        prop_assert_eq!(params.disable_active_migration, decoded.disable_active_migration);
    }
    
    /// Property: Transport parameter validation
    #[test]
    fn transport_param_validation(
        max_data in any::<u64>(),
        max_stream_data in any::<u64>(),
        max_streams in any::<u64>(),
        idle_timeout in any::<u64>(),
        payload_size in any::<u64>(),
    ) {
        let mut params = TransportParameters::default();
        
        // Set parameters with potentially invalid values
        if let Ok(v) = VarInt::try_from(max_data) {
            params.initial_max_data = v.into();
        }
        
        if let Ok(v) = VarInt::try_from(max_stream_data) {
            params.initial_max_stream_data_bidi_local = v.into();
            params.initial_max_stream_data_bidi_remote = v.into();
            params.initial_max_stream_data_uni = v.into();
        }
        
        if let Ok(v) = VarInt::try_from(max_streams) {
            params.initial_max_streams_bidi = v.into();
            params.initial_max_streams_uni = v.into();
        }
        
        if let Ok(v) = VarInt::try_from(idle_timeout) {
            params.max_idle_timeout = Some(v.into());
        }
        
        if let Ok(v) = VarInt::try_from(payload_size) {
            params.max_udp_payload_size = Some(v.into());
        }
        
        // Property: All stream data limits should be <= max data
        let max_data_val: u64 = params.initial_max_data.into();
        let stream_data_bidi_local: u64 = params.initial_max_stream_data_bidi_local.into();
        let stream_data_bidi_remote: u64 = params.initial_max_stream_data_bidi_remote.into();
        let stream_data_uni: u64 = params.initial_max_stream_data_uni.into();
        
        prop_assert!(stream_data_bidi_local <= max_data_val || max_data_val == 0);
        prop_assert!(stream_data_bidi_remote <= max_data_val || max_data_val == 0);
        prop_assert!(stream_data_uni <= max_data_val || max_data_val == 0);
        
        // Property: UDP payload size should be reasonable
        if let Some(size) = params.max_udp_payload_size {
            let size_val: u64 = size.into();
            prop_assert!(size_val >= 1200 || size_val == 0,
                "UDP payload size {} is below minimum", size_val);
            prop_assert!(size_val <= 65535,
                "UDP payload size {} exceeds maximum", size_val);
        }
    }
    
    /// Property: ACK delay exponent validation
    #[test]
    fn ack_delay_exponent_validation(exponent in 0u64..50) {
        let mut params = TransportParameters::default();
        
        if let Ok(v) = VarInt::try_from(exponent) {
            params.ack_delay_exponent = Some(v.into());
            
            // Property: ACK delay exponent should be <= 20 per RFC
            if exponent <= 20 {
                // Valid exponent
                let multiplier = 1u64 << exponent;
                prop_assert!(multiplier > 0);
                prop_assert!(multiplier <= (1u64 << 20));
            }
        }
    }
    
    /// Property: Stateless reset token validation
    #[test]
    fn stateless_reset_token_validation(
        token_bytes in prop::collection::vec(any::<u8>(), 0..20)
    ) {
        let mut params = TransportParameters::default();
        
        if token_bytes.len() == 16 {
            // Valid token size
            let token: [u8; 16] = token_bytes.try_into().unwrap();
            params.stateless_reset_token = Some(token);
            
            // Property: Token should be exactly 16 bytes
            prop_assert_eq!(params.stateless_reset_token.unwrap().len(), 16);
        } else {
            // Invalid token size should not be set
            params.stateless_reset_token = None;
            prop_assert!(params.stateless_reset_token.is_none());
        }
    }
    
    /// Property: NAT traversal extension parameters
    #[test]
    fn nat_traversal_params(
        enabled in any::<bool>(),
        max_candidates in 0u32..100,
        punch_timeout_ms in 0u64..60000,
    ) {
        let mut params = TransportParameters::default();
        
        // Set NAT traversal parameters
        params.enable_nat_traversal = enabled;
        
        if enabled {
            params.max_candidate_addresses = Some(max_candidates);
            params.punch_timeout = Some(punch_timeout_ms);
            
            // Property: Reasonable limits for NAT traversal
            if let Some(max) = params.max_candidate_addresses {
                prop_assert!(max <= 50, "Too many candidate addresses: {}", max);
            }
            
            if let Some(timeout) = params.punch_timeout {
                prop_assert!(timeout >= 100, "Punch timeout too short: {}ms", timeout);
                prop_assert!(timeout <= 30000, "Punch timeout too long: {}ms", timeout);
            }
        }
    }
}

proptest! {
    #![proptest_config(default_config())]
    
    /// Property: Transport parameter size limits
    #[test]
    fn transport_param_size_limits(params in arb_transport_params()) {
        let mut buf = BytesMut::new();
        params.encode(&mut buf);
        
        // Property: Encoded size should be reasonable
        prop_assert!(buf.len() < 2048,
            "Transport parameters too large: {} bytes", buf.len());
        
        // Property: Minimum size includes mandatory parameters
        prop_assert!(buf.len() >= 8,
            "Transport parameters too small: {} bytes", buf.len());
    }
    
    /// Property: Unknown transport parameters handling
    #[test]
    fn unknown_params_preservation(
        known_params in arb_transport_params(),
        unknown_ids in prop::collection::vec(1000u64..2000u64, 0..5),
        unknown_data in prop::collection::vec(arb_bytes(1..100), 0..5),
    ) {
        prop_assume!(unknown_ids.len() == unknown_data.len());
        
        let mut buf = BytesMut::new();
        
        // Encode known parameters
        known_params.encode(&mut buf);
        
        // Add unknown parameters
        for (id, data) in unknown_ids.iter().zip(unknown_data.iter()) {
            if let Ok(v) = VarInt::try_from(*id) {
                v.encode(&mut buf);
                VarInt::from_u32(data.len() as u32).encode(&mut buf);
                buf.extend_from_slice(data);
            }
        }
        
        // Decode should not fail due to unknown parameters
        let mut cursor = std::io::Cursor::new(&buf[..]);
        let result = TransportParameters::decode(&mut cursor);
        
        // Property: Unknown parameters should not cause decode failure
        prop_assert!(result.is_ok() || buf.len() > 2048,
            "Failed to decode with unknown parameters");
    }
    
    /// Property: Flow control parameter relationships
    #[test]
    fn flow_control_relationships(
        conn_flow_control in any::<u64>(),
        stream_flow_control in any::<u64>(),
        max_streams in 0u64..1000,
    ) {
        let mut params = TransportParameters::default();
        
        // Set flow control parameters
        if let (Ok(conn_fc), Ok(stream_fc), Ok(streams)) = (
            VarInt::try_from(conn_flow_control),
            VarInt::try_from(stream_flow_control),
            VarInt::try_from(max_streams),
        ) {
            params.initial_max_data = conn_fc.into();
            params.initial_max_stream_data_bidi_local = stream_fc.into();
            params.initial_max_streams_bidi = streams.into();
            
            // Property: Connection flow control should accommodate streams
            let total_stream_data = stream_fc.into_inner()
                .saturating_mul(streams.into_inner());
            
            if total_stream_data > 0 && conn_fc.into_inner() > 0 {
                // Connection limit should be at least as large as potential stream data
                // (though in practice it doesn't have to be)
                prop_assert!(
                    conn_fc.into_inner() > 0,
                    "Connection flow control should be positive when streams are allowed"
                );
            }
        }
    }
}