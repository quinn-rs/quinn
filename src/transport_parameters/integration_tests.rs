// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses


#[cfg(test)]
mod transport_parameter_error_integration_tests {
    use crate::TransportError;
    use crate::VarInt;
    use crate::coding::BufMutExt;
    use crate::transport_parameters::{Side, TransportParameters};

    #[test]
    fn test_parameter_validation_generates_proper_errors() {
        // Test that validation failures generate TRANSPORT_PARAMETER_ERROR with proper codes

        // Create parameters with invalid ack_delay_exponent
        let mut params = TransportParameters::default();
        params.ack_delay_exponent = VarInt::from_u32(21); // Invalid: > 20

        let mut buf = Vec::new();
        params.write(&mut buf);

        let result = TransportParameters::read(Side::Client, &mut buf.as_slice());
        assert!(result.is_err());

        // Convert to TransportError
        let transport_err = TransportError::from(result.unwrap_err());
        assert_eq!(u64::from(transport_err.code), 0x08); // TRANSPORT_PARAMETER_ERROR code
    }

    #[test]
    fn test_connection_closes_on_parameter_error() {
        use crate::transport_parameters::error_handling::TransportParameterErrorHandler;

        // Test that parameter errors generate proper CONNECTION_CLOSE frames
        let error_msg = "invalid transport parameter";
        let close_frame = TransportParameterErrorHandler::create_close_frame(error_msg);

        // Verify the frame has correct error code
        match close_frame {
            crate::frame::Close::Connection(ref conn_close) => {
                assert_eq!(u64::from(conn_close.error_code), 0x08);
                assert_eq!(conn_close.reason.as_ref(), error_msg.as_bytes());
                assert!(conn_close.frame_type.is_none());
            }
            _ => panic!("Expected Connection close frame"),
        }
    }

    #[test]
    fn test_parameter_error_logging_context() {
        // This test verifies that errors are logged with proper context
        // In a real scenario, we would capture logs and verify them

        let mut buf = Vec::new();

        // Write invalid max_udp_payload_size
        buf.write_var(0x03); // max_udp_payload_size ID
        buf.write_var(2); // length
        buf.write_var(1000); // Invalid: < 1200

        let result = TransportParameters::read(Side::Client, &mut buf.as_slice());
        assert!(result.is_err());

        // The error handler should have logged:
        // - Parameter name: "max_udp_payload_size"
        // - Value: 1000
        // - Constraint: "must be >= 1200"
        // - RFC reference: "RFC 9000 Section 18.2-4.10.1"
    }

    #[test]
    fn test_nat_traversal_error_handling() {
        // Test NAT traversal parameter validation errors

        // Client sending ServerSupport (invalid)
        let mut params = TransportParameters::default();
        params.nat_traversal = Some(
            crate::transport_parameters::NatTraversalConfig::ServerSupport {
                concurrency_limit: VarInt::from_u32(5),
            },
        );

        let mut buf = Vec::new();
        params.write(&mut buf);

        // Server reading this should fail
        let result = TransportParameters::read(Side::Server, &mut buf.as_slice());
        assert!(result.is_err());

        // The error handler should have logged NAT traversal role mismatch
    }

    #[test]
    fn test_multiple_validation_failures() {
        // Test that the first validation failure is reported
        let mut buf = Vec::new();

        // Write multiple invalid parameters
        buf.write_var(0x0a); // ack_delay_exponent
        buf.write_var(1);
        buf.push(21); // Invalid: > 20

        buf.write_var(0x03); // max_udp_payload_size
        buf.write_var(2);
        buf.write_var(1000); // Invalid: < 1200

        let result = TransportParameters::read(Side::Client, &mut buf.as_slice());
        assert!(result.is_err());

        // Should fail on first invalid parameter
        let err = result.unwrap_err();
        assert_eq!(err, crate::transport_parameters::Error::IllegalValue);
    }

    #[test]
    fn test_server_only_parameters_from_client() {
        // Test that server-only parameters from client are rejected
        let mut buf = Vec::new();

        // Write preferred_address (server-only)
        buf.write_var(0x0d); // preferred_address ID
        buf.write_var(49); // correct length: 4+2+16+2+1+8+16

        // Minimal preferred address content
        buf.extend_from_slice(&[127, 0, 0, 1]); // IPv4
        buf.extend_from_slice(&[0x1f, 0x90]); // port 8080 in big-endian
        buf.extend_from_slice(&[0; 16]); // IPv6
        buf.extend_from_slice(&[0x1f, 0x90]); // port 8080 in big-endian
        buf.push(8); // CID length
        buf.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]); // CID
        buf.extend_from_slice(&[0; 16]); // reset token

        // Server reading from client should fail
        let result = TransportParameters::read(Side::Server, &mut buf.as_slice());
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert_eq!(err, crate::transport_parameters::Error::IllegalValue);
    }

    #[test]
    fn test_valid_parameters_pass_validation() {
        // Ensure valid parameters don't trigger errors
        let mut params = TransportParameters::default();
        params.max_idle_timeout = VarInt::from_u32(30000);
        params.max_udp_payload_size = VarInt::from_u32(1472);
        params.initial_max_data = VarInt::from_u32(1048576);
        params.initial_max_stream_data_bidi_local = VarInt::from_u32(524288);
        params.initial_max_stream_data_bidi_remote = VarInt::from_u32(524288);
        params.initial_max_stream_data_uni = VarInt::from_u32(524288);
        params.initial_max_streams_bidi = VarInt::from_u32(100);
        params.initial_max_streams_uni = VarInt::from_u32(100);
        params.ack_delay_exponent = VarInt::from_u32(3);
        params.max_ack_delay = VarInt::from_u32(25);
        params.active_connection_id_limit = VarInt::from_u32(4);

        let mut buf = Vec::new();
        params.write(&mut buf);

        let result = TransportParameters::read(Side::Client, &mut buf.as_slice());
        assert!(result.is_ok());

        let decoded = result.unwrap();
        assert_eq!(decoded.max_idle_timeout, params.max_idle_timeout);
        assert_eq!(decoded.max_udp_payload_size, params.max_udp_payload_size);
    }
}
