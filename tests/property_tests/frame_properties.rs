//! Property tests for QUIC frame encoding/decoding

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::config::*;
use super::generators::*;
use ant_quic::{
    VarInt,
    coding::Codec,
    frame::{ApplicationClose, ConnectionClose, FrameType},
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
        let decoded = FrameType::decode(&mut cursor).expect("Failed to decode frame type");

        prop_assert_eq!(frame_type, decoded);
    }

    /// Test CONNECTION_CLOSE frame properties
    #[test]
    fn connection_close_properties(
        frame_type in proptest::option::of(arb_frame_type()),
        reason_len in 0usize..256,
    ) {
        use ant_quic::TransportErrorCode;

        let reason = vec![b'x'; reason_len];
        let close = ConnectionClose {
            error_code: TransportErrorCode::NO_ERROR,
            frame_type,
            reason: Bytes::from(reason.clone()),
        };

        // Basic property checks
        prop_assert!(close.reason.len() == reason_len);
    }

    /// Test APPLICATION_CLOSE frame properties
    #[test]
    fn application_close_properties(
        error_code in arb_varint(),
        reason_len in 0usize..256,
    ) {
        let reason = vec![b'y'; reason_len];
        let close = ApplicationClose {
            error_code,
            reason: Bytes::from(reason.clone()),
        };

        // Basic property checks
        prop_assert!(close.reason.len() == reason_len);
        prop_assert_eq!(close.error_code, error_code);
    }
}

// Property: Frame encoding should never panic
proptest! {
    #![proptest_config(extended_config())]

    #[test]
    fn frame_encoding_never_panics(
        frame_type in arb_frame_type(),
        data in arb_bytes(0..1000),
    ) {
        let mut buf = BytesMut::with_capacity(2000);

        // Encode frame type and data
        frame_type.encode(&mut buf);
        buf.extend_from_slice(&data);

        prop_assert!(!buf.is_empty(), "Frame encoding should produce output");
    }
}

// Property: VarInt encoding size matches specification
proptest! {
    #[test]
    fn varint_encoding_size(value in any::<u64>()) {
        if let Ok(varint) = VarInt::from_u64(value) {
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
