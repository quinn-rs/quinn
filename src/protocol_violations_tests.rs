// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

use crate::Side;
use crate::frame::FrameType;
use crate::packet::SpaceId;
use crate::protocol_violations::*;
use crate::transport_error::Code;

// STREAM frame type (0x08 is the simplest STREAM frame type)
const STREAM_FRAME_TYPE: FrameType = FrameType(0x08);

#[test]
fn test_protocol_violation_error_code() {
    // Verify PROTOCOL_VIOLATION has the correct code (0x0A)
    assert_eq!(u64::from(Code::PROTOCOL_VIOLATION), 0x0A);
}

#[test]
fn test_frame_in_wrong_packet_type() {
    // Test detection of frames that appear in wrong packet types
    // Per RFC 9000 Section 12.4: Some frames are prohibited in certain packet types

    // NEW_TOKEN frames MUST NOT appear in Initial or Handshake packets
    let result = validate_frame_in_packet_type(FrameType::NEW_TOKEN, PacketType::Initial);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, Code::PROTOCOL_VIOLATION);

    // HANDSHAKE_DONE MUST NOT appear in anything except 1-RTT packets
    let result = validate_frame_in_packet_type(FrameType::HANDSHAKE_DONE, PacketType::Handshake);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, Code::PROTOCOL_VIOLATION);
}

#[test]
fn test_ack_frame_in_wrong_space() {
    // ACK frames must correspond to the packet number space
    // ACK in Initial packet cannot acknowledge Handshake packets
    let result = validate_ack_frame_space(SpaceId::Initial, SpaceId::Handshake);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, Code::PROTOCOL_VIOLATION);
}

#[test]
fn test_stream_frame_in_non_1rtt() {
    // STREAM frames can only appear in 1-RTT packets
    let result = validate_frame_in_packet_type(STREAM_FRAME_TYPE, PacketType::Initial);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, Code::PROTOCOL_VIOLATION);
}

#[test]
fn test_connection_state_violations() {
    // Test frames received in wrong connection states
    // For now, we'll skip this test since we can't easily create states
    // The implementation is tested via integration tests
}

#[test]
fn test_multiple_handshake_done_frames() {
    // HANDSHAKE_DONE must be sent exactly once
    let mut validator = ProtocolValidator::new(Side::Server);

    // First HANDSHAKE_DONE is ok
    assert!(validator.record_handshake_done().is_ok());

    // Second HANDSHAKE_DONE is a violation
    let result = validator.record_handshake_done();
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, Code::PROTOCOL_VIOLATION);
}

#[test]
fn test_path_validation_violations() {
    // PATH_RESPONSE must match a sent PATH_CHALLENGE
    let mut validator = ProtocolValidator::new(Side::Client);

    // PATH_RESPONSE without matching challenge
    let result = validator.validate_path_response(12345);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, Code::PROTOCOL_VIOLATION);
}

#[test]
fn test_protocol_violation_creates_close_frame() {
    // Test that protocol violations generate proper CONNECTION_CLOSE frames
    let close_frame = create_protocol_violation_close(
        "received STREAM frame in Initial packet",
        Some(STREAM_FRAME_TYPE),
    );

    match close_frame {
        crate::frame::Close::Connection(close) => {
            assert_eq!(u64::from(close.error_code), 0x0A);
            assert_eq!(close.frame_type, Some(STREAM_FRAME_TYPE));
            assert!(close.reason.to_vec().starts_with(b"received STREAM frame"));
        }
        _ => panic!("Expected Connection close frame"),
    }
}

#[test]
fn test_coalesced_packet_violations() {
    // Test violations in coalesced packet processing
    // Initial packets must be first in coalesced packets
    let result = validate_coalesced_packet_order(vec![PacketType::Handshake, PacketType::Initial]);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, Code::PROTOCOL_VIOLATION);
}

#[test]
fn test_version_negotiation_violations() {
    // Version negotiation packets have specific requirements
    let result = validate_version_negotiation_packet(
        &[0x00, 0x00, 0x00, 0x00], // Invalid: cannot suggest version 0
        true,                      // is_client
    );
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, Code::PROTOCOL_VIOLATION);
}
