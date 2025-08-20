// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses


//! Protocol violation detection and handling for QUIC compliance
//!
//! This module implements RFC 9000 protocol violation detection, generating
//! PROTOCOL_VIOLATION (0x0A) errors for violations not covered by more specific errors.

use crate::Side;
use crate::connection::State as ConnectionState;
use crate::frame::{self, FrameType};
use crate::packet::{Header, LongType, SpaceId};
use crate::transport_error::{Code as TransportErrorCode, Error as TransportError};
use std::collections::HashSet;
use tracing::error;

/// Simplified packet type for protocol validation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PacketType {
    /// Initial packet
    Initial,
    /// Handshake packet
    Handshake,
    /// 0-RTT packet
    ZeroRtt,
    /// 1-RTT short header packet
    Short,
    /// Retry packet
    Retry,
}

impl PacketType {
    /// Convert from Header to PacketType
    pub(crate) fn from_header(header: &Header) -> Self {
        match header {
            Header::Initial(_) => Self::Initial,
            Header::Long {
                ty: LongType::Handshake,
                ..
            } => Self::Handshake,
            Header::Long {
                ty: LongType::ZeroRtt,
                ..
            } => Self::ZeroRtt,
            Header::Short { .. } => Self::Short,
            Header::Retry { .. } => Self::Retry,
            Header::VersionNegotiate { .. } => Self::Retry, // Treat as special case
        }
    }
}

/// Protocol validator for tracking connection-wide protocol state
pub(crate) struct ProtocolValidator {
    /// Track if HANDSHAKE_DONE has been sent (must be exactly once)
    handshake_done_sent: bool,
    /// Track outstanding PATH_CHALLENGE values
    path_challenges: HashSet<u64>,
    /// Connection side (client or server)
    side: Side,
}

impl ProtocolValidator {
    /// Create a new protocol validator
    pub(crate) fn new(side: Side) -> Self {
        Self {
            handshake_done_sent: false,
            path_challenges: HashSet::new(),
            side,
        }
    }

    /// Record that a HANDSHAKE_DONE frame was sent
    pub(crate) fn record_handshake_done(&mut self) -> Result<(), TransportError> {
        if self.handshake_done_sent {
            error!(
                side = ?self.side,
                compliance = "RFC 9000 Section 19.20",
                "HANDSHAKE_DONE sent multiple times"
            );
            return Err(create_protocol_violation(
                "HANDSHAKE_DONE sent multiple times",
                Some(FrameType::HANDSHAKE_DONE),
            ));
        }
        self.handshake_done_sent = true;
        Ok(())
    }

    /// Record a sent PATH_CHALLENGE
    pub(crate) fn record_path_challenge(&mut self, data: u64) {
        self.path_challenges.insert(data);
    }

    /// Validate a received PATH_RESPONSE
    pub(crate) fn validate_path_response(&mut self, data: u64) -> Result<(), TransportError> {
        if !self.path_challenges.remove(&data) {
            error!(
                data = data,
                compliance = "RFC 9000 Section 8.2.2",
                "PATH_RESPONSE without matching PATH_CHALLENGE"
            );
            return Err(create_protocol_violation(
                "PATH_RESPONSE without matching PATH_CHALLENGE",
                Some(FrameType::PATH_RESPONSE),
            ));
        }
        Ok(())
    }
}

/// Validate that a frame type is allowed in a given packet type
pub(crate) fn validate_frame_in_packet_type(
    frame_type: FrameType,
    packet_type: PacketType,
) -> Result<(), TransportError> {
    // RFC 9000 Section 12.4: Frame types restricted by packet type
    let allowed = match frame_type {
        // PADDING, PING, and ACK can appear in any packet type
        FrameType::PADDING | FrameType::PING | FrameType::ACK | FrameType::ACK_ECN => true,

        // CRYPTO and CONNECTION_CLOSE can appear in any packet type
        FrameType::CRYPTO | FrameType::CONNECTION_CLOSE => true,

        // NEW_TOKEN can only appear in 1-RTT packets
        FrameType::NEW_TOKEN => matches!(packet_type, PacketType::Short),

        // HANDSHAKE_DONE can only appear in 1-RTT packets
        FrameType::HANDSHAKE_DONE => matches!(packet_type, PacketType::Short),

        // All STREAM-related frames can only appear in 1-RTT packets
        // STREAM frames are in the range 0x08-0x0f
        _ if frame_type.is_stream() => matches!(packet_type, PacketType::Short),

        FrameType::MAX_DATA
        | FrameType::MAX_STREAM_DATA
        | FrameType::MAX_STREAMS_BIDI
        | FrameType::MAX_STREAMS_UNI
        | FrameType::DATA_BLOCKED
        | FrameType::STREAM_DATA_BLOCKED
        | FrameType::STREAMS_BLOCKED_BIDI
        | FrameType::STREAMS_BLOCKED_UNI
        | FrameType::RESET_STREAM
        | FrameType::STOP_SENDING => matches!(packet_type, PacketType::Short),

        // Connection ID management frames in 1-RTT only
        FrameType::NEW_CONNECTION_ID | FrameType::RETIRE_CONNECTION_ID => {
            matches!(packet_type, PacketType::Short)
        }

        // PATH_CHALLENGE and PATH_RESPONSE in 1-RTT only
        FrameType::PATH_CHALLENGE | FrameType::PATH_RESPONSE => {
            matches!(packet_type, PacketType::Short)
        }

        // Application close in 1-RTT only
        FrameType::APPLICATION_CLOSE => matches!(packet_type, PacketType::Short),

        // Extension frames follow their own rules
        _ => {
            // For unknown frame types, assume 1-RTT only to be safe
            matches!(packet_type, PacketType::Short)
        }
    };

    if !allowed {
        error!(
            frame_type = ?frame_type,
            packet_type = ?packet_type,
            compliance = "RFC 9000 Section 12.4",
            "Frame type not allowed in packet type"
        );
        return Err(create_protocol_violation(
            &format!("{frame_type:?} frame not allowed in {packet_type:?} packet"),
            Some(frame_type),
        ));
    }

    Ok(())
}

/// Validate ACK frame packet number space
pub(crate) fn validate_ack_frame_space(
    packet_space: SpaceId,
    acked_space: SpaceId,
) -> Result<(), TransportError> {
    // RFC 9000 Section 12.3: ACK frames acknowledge packets in the same space
    if packet_space != acked_space {
        error!(
            packet_space = ?packet_space,
            acked_space = ?acked_space,
            compliance = "RFC 9000 Section 12.3",
            "ACK frame acknowledges packets from different space"
        );
        return Err(create_protocol_violation(
            "ACK frame acknowledges packets from different packet number space",
            Some(FrameType::ACK),
        ));
    }
    Ok(())
}

/// Check if connection is in handshake state
pub(crate) fn is_handshake_state(conn_state: &ConnectionState) -> bool {
    matches!(conn_state, ConnectionState::Handshake(_))
}

/// Check if connection is established
pub(crate) fn is_established_state(conn_state: &ConnectionState) -> bool {
    matches!(conn_state, ConnectionState::Established)
}

/// Validate frame is allowed in current connection state
pub(crate) fn validate_frame_in_connection_state(
    frame_type: FrameType,
    conn_state: &ConnectionState,
) -> Result<(), TransportError> {
    let allowed = match frame_type {
        // STREAM frames require established connection
        _ if frame_type.is_stream() => is_established_state(conn_state),

        // HANDSHAKE_DONE requires confirmed handshake
        FrameType::HANDSHAKE_DONE => is_established_state(conn_state),

        // Most frames allowed after handshake starts
        _ => true,
    };

    if !allowed {
        let state_name = if is_handshake_state(conn_state) {
            "Handshake"
        } else if is_established_state(conn_state) {
            "Established"
        } else {
            "Other"
        };

        error!(
            frame_type = ?frame_type,
            state = state_name,
            compliance = "RFC 9000 Section 4",
            "Frame type not allowed in connection state"
        );
        return Err(create_protocol_violation(
            &format!("{frame_type:?} frame not allowed in {state_name} state"),
            Some(frame_type),
        ));
    }

    Ok(())
}

/// Validate coalesced packet ordering
pub(crate) fn validate_coalesced_packet_order(
    packet_types: Vec<PacketType>,
) -> Result<(), TransportError> {
    // RFC 9000 Section 12.2: Initial packets must come first in coalesced packets
    let mut saw_non_initial = false;

    for packet_type in packet_types {
        match packet_type {
            PacketType::Initial => {
                if saw_non_initial {
                    error!(
                        compliance = "RFC 9000 Section 12.2",
                        "Initial packet after non-Initial in coalesced packet"
                    );
                    return Err(create_protocol_violation(
                        "Initial packet must be first in coalesced packet",
                        None,
                    ));
                }
            }
            _ => saw_non_initial = true,
        }
    }

    Ok(())
}

/// Validate version negotiation packet
pub(crate) fn validate_version_negotiation_packet(
    versions: &[u8],
    is_client: bool,
) -> Result<(), TransportError> {
    // RFC 9000 Section 6: Version negotiation validation

    // Clients must not send version negotiation packets
    if is_client {
        error!(
            compliance = "RFC 9000 Section 6",
            "Client attempted to send version negotiation packet"
        );
        return Err(create_protocol_violation(
            "Clients must not send version negotiation packets",
            None,
        ));
    }

    // Check for version 0 in the list (not allowed)
    for chunk in versions.chunks(4) {
        if chunk.len() == 4 && chunk == [0, 0, 0, 0] {
            error!(
                compliance = "RFC 9000 Section 6",
                "Version negotiation packet contains version 0"
            );
            return Err(create_protocol_violation(
                "Version negotiation packet must not contain version 0",
                None,
            ));
        }
    }

    Ok(())
}

/// Create a PROTOCOL_VIOLATION error with proper context
pub(crate) fn create_protocol_violation(
    reason: &str,
    frame_type: Option<FrameType>,
) -> TransportError {
    TransportError {
        code: TransportErrorCode::PROTOCOL_VIOLATION,
        frame: frame_type,
        reason: reason.to_string(),
    }
}

/// Create a CONNECTION_CLOSE frame for protocol violations
pub(crate) fn create_protocol_violation_close(
    reason: &str,
    frame_type: Option<FrameType>,
) -> frame::Close {
    let connection_close = frame::ConnectionClose {
        error_code: TransportErrorCode::PROTOCOL_VIOLATION,
        frame_type,
        reason: reason.as_bytes().to_vec().into(),
    };
    frame::Close::Connection(connection_close)
}

/// Log protocol violation with RFC reference
pub(crate) fn log_protocol_violation(violation_type: &str, details: &str, rfc_section: &str) {
    error!(
        violation = violation_type,
        details = details,
        compliance = rfc_section,
        "QUIC protocol violation detected"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_validator_handshake_done() {
        let mut validator = ProtocolValidator::new(Side::Server);

        // First HANDSHAKE_DONE is ok
        assert!(validator.record_handshake_done().is_ok());

        // Second is a violation
        assert!(validator.record_handshake_done().is_err());
    }

    #[test]
    fn test_path_challenge_response_tracking() {
        let mut validator = ProtocolValidator::new(Side::Client);

        // Record a challenge
        validator.record_path_challenge(12345);

        // Valid response
        assert!(validator.validate_path_response(12345).is_ok());

        // Invalid response (no matching challenge)
        assert!(validator.validate_path_response(67890).is_err());
    }

    #[test]
    fn test_frame_packet_type_validation() {
        // NEW_TOKEN in Initial packet is invalid
        assert!(validate_frame_in_packet_type(FrameType::NEW_TOKEN, PacketType::Initial).is_err());

        // CRYPTO in Initial is valid
        assert!(validate_frame_in_packet_type(FrameType::CRYPTO, PacketType::Initial).is_ok());

        // STREAM in Short (1-RTT) is valid
        // Use a STREAM frame type (0x08)
        assert!(
            validate_frame_in_packet_type(
                FrameType(0x08), // STREAM frame
                PacketType::Short
            )
            .is_ok()
        );
    }
}
