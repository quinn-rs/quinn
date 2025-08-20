// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

use crate::TransportError;
use crate::VarInt;
use crate::frame;
use crate::transport_parameters::{Side, TransportParameterId, TransportParameters};
use tracing::error;

/// Enhanced error handling for transport parameter validation
pub(crate) struct TransportParameterErrorHandler;

impl TransportParameterErrorHandler {
    /// Log specific validation failures with RFC references
    pub(super) fn log_validation_failure(
        param_name: &str,
        value: u64,
        expected: &str,
        rfc_ref: &str,
    ) {
        error!(
            param_name = param_name,
            value = value,
            expected = expected,
            rfc_ref = rfc_ref,
            "Transport parameter validation failed"
        );
    }

    /// Log semantic validation errors
    pub(super) fn log_semantic_error(error_desc: &str, context: &str) {
        error!(
            error = error_desc,
            context = context,
            compliance = "RFC 9000 Section 18",
            "Transport parameter semantic validation failed"
        );
    }

    /// Log NAT traversal parameter errors
    pub(super) fn log_nat_traversal_error(side: Side, received_variant: &str, expected: &str) {
        error!(
            side = ?side,
            received = received_variant,
            expected = expected,
            compliance = "draft-seemann-quic-nat-traversal-02",
            "NAT traversal parameter role mismatch"
        );
    }

    /// Create a properly formatted CONNECTION_CLOSE frame for parameter errors
    pub(super) fn create_close_frame(error_msg: &str) -> frame::Close {
        let connection_close = frame::ConnectionClose {
            error_code: crate::transport_error::Code::TRANSPORT_PARAMETER_ERROR,
            frame_type: None,
            reason: error_msg.as_bytes().to_vec().into(),
        };
        frame::Close::Connection(connection_close)
    }
}

/// Validation helper functions with detailed error reporting
pub(crate) fn validate_ack_delay_exponent(value: u8) -> Result<(), TransportError> {
    if value > 20 {
        TransportParameterErrorHandler::log_validation_failure(
            "ack_delay_exponent",
            value as u64,
            "must be <= 20",
            "RFC 9000 Section 18.2-4.26.1",
        );
        return Err(TransportError {
            code: crate::transport_error::Code::TRANSPORT_PARAMETER_ERROR,
            frame: None,
            reason: "ack_delay_exponent exceeds maximum value of 20".into(),
        });
    }
    Ok(())
}

pub(crate) fn validate_max_ack_delay(value: VarInt) -> Result<(), TransportError> {
    if value.0 >= (1 << 14) {
        TransportParameterErrorHandler::log_validation_failure(
            "max_ack_delay",
            value.0,
            "must be < 2^14",
            "RFC 9000 Section 18.2-4.28.1",
        );
        return Err(TransportError {
            code: crate::transport_error::Code::TRANSPORT_PARAMETER_ERROR,
            frame: None,
            reason: "max_ack_delay exceeds maximum value".into(),
        });
    }
    Ok(())
}

pub(crate) fn validate_active_connection_id_limit(value: VarInt) -> Result<(), TransportError> {
    if value.0 < 2 {
        TransportParameterErrorHandler::log_validation_failure(
            "active_connection_id_limit",
            value.0,
            "must be >= 2",
            "RFC 9000 Section 18.2-6.2.1",
        );
        return Err(TransportError {
            code: crate::transport_error::Code::TRANSPORT_PARAMETER_ERROR,
            frame: None,
            reason: "active_connection_id_limit must be at least 2".into(),
        });
    }
    Ok(())
}

pub(crate) fn validate_max_udp_payload_size(value: VarInt) -> Result<(), TransportError> {
    if value.0 < 1200 {
        TransportParameterErrorHandler::log_validation_failure(
            "max_udp_payload_size",
            value.0,
            "must be >= 1200",
            "RFC 9000 Section 18.2-4.10.1",
        );
        return Err(TransportError {
            code: crate::transport_error::Code::TRANSPORT_PARAMETER_ERROR,
            frame: None,
            reason: "max_udp_payload_size below minimum value of 1200".into(),
        });
    }
    Ok(())
}

pub(crate) fn validate_min_ack_delay(
    min_delay: Option<VarInt>,
    max_delay: VarInt,
) -> Result<(), TransportError> {
    if let Some(min) = min_delay {
        // min_ack_delay is in microseconds, max_ack_delay is in milliseconds
        if min.0 > max_delay.0 * 1000 {
            TransportParameterErrorHandler::log_semantic_error(
                "min_ack_delay exceeds max_ack_delay",
                &format!("min: {}μs, max: {}ms", min.0, max_delay.0),
            );
            return Err(TransportError {
                code: crate::transport_error::Code::TRANSPORT_PARAMETER_ERROR,
                frame: None,
                reason: "min_ack_delay exceeds max_ack_delay".into(),
            });
        }
    }
    Ok(())
}

pub(crate) fn validate_server_only_params(
    side: Side,
    params: &TransportParameters,
) -> Result<(), TransportError> {
    if side.is_server() {
        let mut violations = Vec::new();

        if params.original_dst_cid.is_some() {
            violations.push("original_dst_cid");
        }
        if params.preferred_address.is_some() {
            violations.push("preferred_address");
        }
        if params.retry_src_cid.is_some() {
            violations.push("retry_src_cid");
        }
        if params.stateless_reset_token.is_some() {
            violations.push("stateless_reset_token");
        }

        if !violations.is_empty() {
            TransportParameterErrorHandler::log_semantic_error(
                "Server received server-only parameters",
                &format!("Invalid parameters: {violations:?}"),
            );
            return Err(TransportError {
                code: crate::transport_error::Code::TRANSPORT_PARAMETER_ERROR,
                frame: None,
                reason: "received server-only transport parameters from client".into(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ack_delay_exponent_validation() {
        assert!(validate_ack_delay_exponent(20).is_ok());
        assert!(validate_ack_delay_exponent(21).is_err());
        assert!(validate_ack_delay_exponent(0).is_ok());
        assert!(validate_ack_delay_exponent(255).is_err());
    }

    #[test]
    fn test_max_ack_delay_validation() {
        assert!(validate_max_ack_delay(VarInt::from_u32(16383)).is_ok());
        assert!(validate_max_ack_delay(VarInt::from_u32(16384)).is_err());
        assert!(validate_max_ack_delay(VarInt::from_u32(0)).is_ok());
    }

    #[test]
    fn test_active_connection_id_limit_validation() {
        assert!(validate_active_connection_id_limit(VarInt::from_u32(2)).is_ok());
        assert!(validate_active_connection_id_limit(VarInt::from_u32(1)).is_err());
        assert!(validate_active_connection_id_limit(VarInt::from_u32(0)).is_err());
        assert!(validate_active_connection_id_limit(VarInt::from_u32(100)).is_ok());
    }

    #[test]
    fn test_max_udp_payload_size_validation() {
        assert!(validate_max_udp_payload_size(VarInt::from_u32(1200)).is_ok());
        assert!(validate_max_udp_payload_size(VarInt::from_u32(1199)).is_err());
        assert!(validate_max_udp_payload_size(VarInt::from_u32(65535)).is_ok());
    }

    #[test]
    fn test_min_ack_delay_validation() {
        let max_delay = VarInt::from_u32(25); // 25ms

        // Valid: 25ms = 25000μs
        assert!(validate_min_ack_delay(Some(VarInt::from_u32(25000)), max_delay).is_ok());

        // Invalid: 26ms = 26000μs > 25ms
        assert!(validate_min_ack_delay(Some(VarInt::from_u32(26000)), max_delay).is_err());

        // Valid: No min_ack_delay
        assert!(validate_min_ack_delay(None, max_delay).is_ok());
    }

    #[test]
    fn test_close_frame_creation() {
        let close = TransportParameterErrorHandler::create_close_frame("test error");
        match close {
            frame::Close::Connection(conn_close) => {
                assert_eq!(u64::from(conn_close.error_code), 0x08); // TRANSPORT_PARAMETER_ERROR code
                assert_eq!(conn_close.reason.as_ref(), b"test error");
            }
            _ => panic!("Expected Connection close frame"),
        }
    }
}
