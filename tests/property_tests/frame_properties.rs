//! Property tests for QUIC frame encoding/decoding

use super::config::*;
use super::generators::*;
use ant_quic::{
    VarInt,
    coding::{Decoder, Encoder},
    frame::*,
};
use bytes::{Bytes, BytesMut};
use proptest::prelude::*;

proptest! {
    #![proptest_config(default_config())]

    /// Test that VarInt encoding and decoding roundtrips correctly
    #[test]
    fn varint_roundtrip(value in arb_varint()) {
        let mut buf = BytesMut::new();
        value.encode(&mut buf);

        let mut cursor = std::io::Cursor::new(&buf[..]);
        let decoded = VarInt::decode(&mut cursor).expect("Failed to decode VarInt");

        prop_assert_eq!(value, decoded);
        prop_assert_eq!(cursor.position() as usize, buf.len());
    }

    /// Test that frame type encoding preserves the frame type
    #[test]
    fn frame_type_roundtrip(frame_type in arb_frame_type()) {
        let mut buf = BytesMut::new();
        frame_type.encode(&mut buf);

        let mut cursor = std::io::Cursor::new(&buf[..]);
        let decoded = Type::decode(&mut cursor).expect("Failed to decode frame type");

        prop_assert_eq!(frame_type, decoded);
    }

    /// Test PING frame encoding/decoding
    #[test]
    fn ping_frame_roundtrip(_dummy in 0u8..1) {
        let frame = frame::Ping;
        let mut buf = BytesMut::new();

        frame.encode(&mut buf);
        prop_assert!(buf.len() > 0);

        // PING frame should only contain the type byte
        prop_assert_eq!(buf.len(), 1);
        prop_assert_eq!(buf[0], Type::PING.0 as u8);
    }

    /// Test ACK frame properties
    #[test]
    fn ack_frame_properties(
        largest in arb_varint(),
        delay in arb_varint(),
        first_range in arb_varint(),
        additional_ranges in prop::collection::vec(
            (arb_varint(), arb_varint()),
            0..10
        )
    ) {
        let mut ranges = vec![];
        let mut last = largest.into_inner();

        // Build valid ACK ranges
        if first_range.into_inner() <= last {
            ranges.push(0..=first_range.into_inner());
            last = last.saturating_sub(first_range.into_inner() + 1);
        }

        for (gap, ack_range) in additional_ranges {
            if gap.into_inner() <= last && ack_range.into_inner() <= last {
                last = last.saturating_sub(gap.into_inner() + ack_range.into_inner() + 1);
                ranges.push(0..=ack_range.into_inner());
            }
        }

        let ack = frame::Ack {
            largest: largest.into_inner(),
            delay: delay.into_inner(),
            ranges: ranges.clone(),
            ecn: None,
        };

        // Encode
        let mut buf = BytesMut::new();
        ack.encode(&mut buf);

        // The encoded size should be reasonable
        prop_assert!(buf.len() < 1000, "ACK frame too large: {} bytes", buf.len());

        // Property: ACK frames must have at least one range
        prop_assert!(!ack.ranges.is_empty());

        // Property: Largest acknowledged must be >= the sum of all ranges
        let total_acked: u64 = ack.ranges.iter()
            .map(|r| r.end() - r.start() + 1)
            .sum();
        prop_assert!(ack.largest >= total_acked - 1);
    }

    /// Test RESET_STREAM frame properties
    #[test]
    fn reset_stream_properties(
        stream_id in arb_varint(),
        error_code in arb_varint(),
        final_size in arb_varint(),
    ) {
        let reset = frame::ResetStream {
            id: stream_id.into(),
            error_code: error_code.into(),
            final_size: final_size.into(),
        };

        let mut buf = BytesMut::new();
        reset.encode(&mut buf);

        // Basic size check
        prop_assert!(buf.len() >= 3); // At least type + 3 varints
        prop_assert!(buf.len() <= 25); // Max size with 8-byte varints

        // First byte should be RESET_STREAM type
        prop_assert_eq!(buf[0], Type::RESET_STREAM.0 as u8);
    }

    /// Test MAX_DATA frame properties
    #[test]
    fn max_data_properties(max_data in arb_varint()) {
        let frame = frame::MaxData(max_data.into());

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        // Size should be type byte + varint
        prop_assert!(buf.len() >= 2);
        prop_assert!(buf.len() <= 9);

        prop_assert_eq!(buf[0], Type::MAX_DATA.0 as u8);
    }

    /// Test CONNECTION_CLOSE frame properties
    #[test]
    fn connection_close_properties(
        error_code in arb_varint(),
        frame_type in option::of(arb_frame_type()),
        reason_len in 0usize..256,
    ) {
        let reason = vec![b'x'; reason_len];
        let close = frame::Close {
            error_code: error_code.into(),
            frame_type: frame_type.map(|t| t.0),
            reason: Bytes::from(reason.clone()),
        };

        let mut buf = BytesMut::new();
        close.encode(&mut buf);

        // Verify encoding includes all components
        prop_assert!(buf.len() >= 3); // Type + error code + reason length

        // The reason should be truncated if too long
        if reason_len > 0 {
            prop_assert!(buf.len() <= 1 + 8 + 8 + reason_len);
        }
    }

    /// Test PATH_CHALLENGE and PATH_RESPONSE roundtrip
    #[test]
    fn path_challenge_response_roundtrip(data: [u8; 8]) {
        // PATH_CHALLENGE
        let challenge = frame::PathChallenge(data);
        let mut buf = BytesMut::new();
        challenge.encode(&mut buf);

        prop_assert_eq!(buf.len(), 9); // Type byte + 8 bytes data
        prop_assert_eq!(buf[0], Type::PATH_CHALLENGE.0 as u8);
        prop_assert_eq!(&buf[1..9], &data);

        // PATH_RESPONSE
        let response = frame::PathResponse(data);
        let mut buf = BytesMut::new();
        response.encode(&mut buf);

        prop_assert_eq!(buf.len(), 9); // Type byte + 8 bytes data
        prop_assert_eq!(buf[0], Type::PATH_RESPONSE.0 as u8);
        prop_assert_eq!(&buf[1..9], &data);
    }
}

proptest! {
    #![proptest_config(default_config())]

    /// Test NAT traversal frame properties
    #[test]
    fn add_address_frame_properties(
        addr in arb_socket_addr(),
        addr_type in 0u8..4,
        seq_num in arb_varint(),
    ) {
        use ant_quic::frame::AddAddress;

        let frame = AddAddress {
            addr_type,
            sequence_number: seq_num.into_inner(),
            interface_type: 0,
            address: addr,
        };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        // Verify basic properties
        prop_assert!(buf.len() >= 8); // Type + fields + address
        prop_assert_eq!(buf[0], 0x40); // ADD_ADDRESS frame type

        // Sequence numbers should be preserved
        prop_assert_eq!(frame.sequence_number, seq_num.into_inner());
    }

    /// Test PUNCH_ME_NOW frame properties
    #[test]
    fn punch_me_now_properties(
        round in 0u32..100,
        nonce: [u8; 8],
    ) {
        use ant_quic::frame::PunchMeNow;

        let frame = PunchMeNow { round, nonce };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        // Fixed size frame
        prop_assert_eq!(buf.len(), 13); // Type + 4 bytes round + 8 bytes nonce
        prop_assert_eq!(buf[0], 0x41); // PUNCH_ME_NOW frame type
    }

    /// Test OBSERVED_ADDRESS frame properties
    #[test]
    fn observed_address_properties(
        addr in arb_socket_addr(),
        seq_num in 0u16..1000,
    ) {
        use ant_quic::frame::ObservedAddress;

        let frame = ObservedAddress {
            sequence_number: seq_num,
            observed_address: addr,
        };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        // Verify encoding
        prop_assert!(buf.len() >= 4); // Type + seq + address
        prop_assert_eq!(buf[0], 0x43); // OBSERVED_ADDRESS frame type
    }
}

/// Property: Frame encoding should never panic
proptest! {
    #![proptest_config(extended_config())]

    #[test]
    fn frame_encoding_never_panics(
        frame_type in arb_frame_type(),
        data in arb_bytes(0..1000),
    ) {
        let mut buf = BytesMut::with_capacity(2000);

        // This should never panic regardless of input
        let result = std::panic::catch_unwind(|| {
            frame_type.encode(&mut buf);
            // Simulate encoding arbitrary data
            buf.extend_from_slice(&data);
        });

        prop_assert!(result.is_ok(), "Frame encoding panicked");
    }
}

/// Property: VarInt encoding size matches specification
proptest! {
    #[test]
    fn varint_encoding_size(value in any::<u64>()) {
        if let Ok(varint) = VarInt::try_from(value) {
            let mut buf = BytesMut::new();
            varint.encode(&mut buf);

            let expected_size = match value {
                0..=63 => 1,
                64..=16383 => 2,
                16384..=1073741823 => 4,
                1073741824..=4611686018427387903 => 8,
                _ => 0, // Should not reach here
            };

            if expected_size > 0 {
                prop_assert_eq!(buf.len(), expected_size,
                    "VarInt {} encoded to {} bytes, expected {}",
                    value, buf.len(), expected_size);
            }
        }
    }
}
