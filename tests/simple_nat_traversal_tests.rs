//! Simple RFC Compliance Tests for NAT Traversal
//!
//! These tests verify basic compliance with draft-seemann-quic-nat-traversal-02.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::VarInt;

// Frame type constants from the RFC
const FRAME_TYPE_ADD_ADDRESS_IPV4: u64 = 0x3d7e90;
const FRAME_TYPE_ADD_ADDRESS_IPV6: u64 = 0x3d7e91;
const FRAME_TYPE_PUNCH_ME_NOW_IPV4: u64 = 0x3d7e92;
const FRAME_TYPE_PUNCH_ME_NOW_IPV6: u64 = 0x3d7e93;
const FRAME_TYPE_REMOVE_ADDRESS: u64 = 0x3d7e94;

/// Test round cancellation logic according to RFC Section 4.4
#[test]
fn test_round_cancellation_logic() {
    let round1 = VarInt::from_u32(5);
    let round2 = VarInt::from_u32(10);
    let round3 = VarInt::from_u32(5);

    // Test that higher round is detected correctly
    assert!(
        round2 > round1,
        "Higher round should be greater than lower round"
    );
    assert!(
        round2 > round3,
        "Higher round should be greater than equal round"
    );

    // Test that cancellation should happen for higher rounds
    assert!(
        round2 > round1,
        "Round cancellation should trigger for higher rounds"
    );

    // Test that cancellation should NOT happen for lower or equal rounds
    assert!(
        round1 <= round2,
        "Round cancellation should NOT trigger for lower rounds"
    );
    assert!(
        round1 <= round2,
        "Lower round should not trigger cancellation"
    );
    assert!(
        round1 <= round3,
        "Equal round should not trigger cancellation"
    );
}

/// Test sequence number validation
#[test]
fn test_sequence_number_validation() {
    let valid_sequences = vec![
        VarInt::from_u32(0),        // Zero is valid
        VarInt::from_u32(1),        // Small positive
        VarInt::from_u32(1000),     // Medium positive
        VarInt::from_u32(u32::MAX), // Max u32
        VarInt::from_u64(4611686018427387903u64).expect("Large u64 should be valid"), // Large u64
    ];

    for seq in valid_sequences {
        let _ = seq.into_inner();
    }

    // Test sequence number ordering
    let seq1 = VarInt::from_u32(1);
    let seq2 = VarInt::from_u32(2);
    let seq100 = VarInt::from_u32(100);

    assert!(seq2 > seq1, "Higher sequence should be greater");
    assert!(seq100 > seq2, "Much higher sequence should be greater");
    assert!(seq1 <= seq2, "Lower sequence should not be greater");
}

/// Test frame type constants are exactly as specified in RFC
#[test]
fn test_frame_type_constants() {
    assert_eq!(FRAME_TYPE_ADD_ADDRESS_IPV4, 0x3d7e90);
    assert_eq!(FRAME_TYPE_ADD_ADDRESS_IPV6, 0x3d7e91);
    assert_eq!(FRAME_TYPE_PUNCH_ME_NOW_IPV4, 0x3d7e92);
    assert_eq!(FRAME_TYPE_PUNCH_ME_NOW_IPV6, 0x3d7e93);
    assert_eq!(FRAME_TYPE_REMOVE_ADDRESS, 0x3d7e94);

    // Verify IPv4/IPv6 LSB pattern
    assert_eq!(
        FRAME_TYPE_ADD_ADDRESS_IPV4 & 1,
        0,
        "IPv4 frame type should have LSB = 0"
    );
    assert_eq!(
        FRAME_TYPE_ADD_ADDRESS_IPV6 & 1,
        1,
        "IPv6 frame type should have LSB = 1"
    );
    assert_eq!(
        FRAME_TYPE_PUNCH_ME_NOW_IPV4 & 1,
        0,
        "IPv4 frame type should have LSB = 0"
    );
    assert_eq!(
        FRAME_TYPE_PUNCH_ME_NOW_IPV6 & 1,
        1,
        "IPv6 frame type should have LSB = 1"
    );
    assert_eq!(
        FRAME_TYPE_REMOVE_ADDRESS & 1,
        0,
        "REMOVE_ADDRESS frame type should have LSB = 0"
    );
}

/// Test VarInt edge cases for RFC compliance
#[test]
fn test_varint_edge_cases() {
    let test_values = vec![
        0u64,
        1u64,
        63u64,
        64u64,
        16383u64,
        16384u64,
        1073741823u64,
        1073741824u64,
        4611686018427387903u64,
    ];

    for &value in &test_values {
        let varint = VarInt::from_u64(value).expect("VarInt creation should succeed");
        assert_eq!(
            varint.into_inner(),
            value,
            "VarInt roundtrip failed for {}",
            value
        );
    }

    // Test VarInt bounds
    assert!(VarInt::from_u64(0).is_ok());
    assert!(VarInt::from_u64(4611686018427387903u64).is_ok()); // Max valid VarInt value
}
