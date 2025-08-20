// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses


#[cfg(test)]
mod transport_parameter_error_tests {
    use crate::TransportError;
    use crate::VarInt;
    use crate::coding::BufMutExt;
    use crate::transport_parameters::{Error, Side, TransportParameters};

    #[test]
    fn test_transport_parameter_error_from_malformed() {
        // Test that malformed parameters generate TRANSPORT_PARAMETER_ERROR
        let err = TransportError::from(Error::Malformed);
        assert_eq!(
            err.code,
            crate::transport_error::Code::TRANSPORT_PARAMETER_ERROR
        );
        assert_eq!(err.reason, "malformed");
    }

    #[test]
    fn test_transport_parameter_error_from_illegal_value() {
        // Test that illegal values generate TRANSPORT_PARAMETER_ERROR
        let err = TransportError::from(Error::IllegalValue);
        assert_eq!(
            err.code,
            crate::transport_error::Code::TRANSPORT_PARAMETER_ERROR
        );
        assert_eq!(err.reason, "illegal value");
    }

    #[test]
    fn test_ack_delay_exponent_validation() {
        // ack_delay_exponent must be <= 20
        let mut buf = Vec::new();
        buf.write_var(0x0a); // ack_delay_exponent ID
        buf.write_var(1); // length
        buf.push(21); // Invalid value > 20

        let result = TransportParameters::read(Side::Client, &mut buf.as_slice());
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, Error::IllegalValue);
        }
    }

    #[test]
    fn test_max_ack_delay_validation() {
        // max_ack_delay must be < 2^14
        let mut buf = Vec::new();
        buf.write_var(0x0b); // max_ack_delay ID
        let invalid_delay = 1u64 << 14; // 2^14 is invalid
        buf.write_var(VarInt::from_u64(invalid_delay).unwrap().size() as u64); // length
        buf.write_var(invalid_delay); // value as VarInt

        let result = TransportParameters::read(Side::Client, &mut buf.as_slice());
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, Error::IllegalValue);
        }
    }

    #[test]
    fn test_active_connection_id_limit_validation() {
        // active_connection_id_limit must be >= 2
        let mut buf = Vec::new();
        buf.write_var(0x0e); // active_connection_id_limit ID
        buf.write_var(1); // length
        buf.write_var(1); // Invalid value < 2

        let result = TransportParameters::read(Side::Client, &mut buf.as_slice());
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, Error::IllegalValue);
        }
    }

    #[test]
    fn test_max_udp_payload_size_validation() {
        // max_udp_payload_size must be >= 1200
        let mut buf = Vec::new();
        buf.write_var(0x03); // max_udp_payload_size ID
        buf.write_var(2); // length
        buf.write_var(1199); // Invalid value < 1200

        let result = TransportParameters::read(Side::Client, &mut buf.as_slice());
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, Error::IllegalValue);
        }
    }

    #[test]
    fn test_min_ack_delay_validation() {
        // min_ack_delay must be <= max_ack_delay * 1000 (converting ms to us)
        let mut params = TransportParameters::default();
        params.max_ack_delay = VarInt::from_u32(25); // 25ms

        let mut buf = Vec::new();
        params.write(&mut buf);

        // Append min_ack_delay parameter
        buf.write_var(0xFF04DE1B); // min_ack_delay ID (draft-ietf-quic-ack-frequency)
        buf.write_var(4); // length
        buf.write_var(26000); // 26ms in microseconds, which is > max_ack_delay

        let result = TransportParameters::read(Side::Client, &mut buf.as_slice());
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, Error::IllegalValue);
        }
    }

    #[test]
    fn test_preferred_address_server_only() {
        // preferred_address can only be sent by servers
        let mut buf = Vec::new();
        buf.write_var(0x0d); // preferred_address ID
        buf.write_var(49); // correct length: 4+2+16+2+1+8+16

        // Write a minimal preferred address
        buf.extend_from_slice(&[127, 0, 0, 1]); // IPv4
        buf.extend_from_slice(&[0x1f, 0x90]); // port 8080 in big-endian
        buf.extend_from_slice(&[0; 16]); // IPv6
        buf.extend_from_slice(&[0x1f, 0x90]); // port 8080 in big-endian
        buf.push(8); // CID length
        buf.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]); // CID
        buf.extend_from_slice(&[0; 16]); // reset token

        // Reading as server (from client) should fail
        let result = TransportParameters::read(Side::Server, &mut buf.as_slice());
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, Error::IllegalValue);
        }
    }

    #[test]
    fn test_duplicate_parameter_error() {
        // Duplicate parameters should cause an error
        let mut buf = Vec::new();

        // First max_idle_timeout
        buf.write_var(0x01); // max_idle_timeout ID
        buf.write_var(2); // length
        buf.write_var(30000); // value

        // Duplicate max_idle_timeout
        buf.write_var(0x01); // max_idle_timeout ID again
        buf.write_var(2); // length
        buf.write_var(60000); // different value

        let result = TransportParameters::read(Side::Client, &mut buf.as_slice());
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, Error::Malformed);
        }
    }

    #[test]
    fn test_malformed_varint_parameter() {
        // Test malformed VarInt encoding
        let mut buf = Vec::new();
        buf.write_var(0x01); // max_idle_timeout ID
        buf.write_var(5); // length claims 5 bytes
        buf.push(0xc0); // Start of 8-byte varint
        // But only provide 1 byte instead of 8

        let result = TransportParameters::read(Side::Client, &mut buf.as_slice());
        assert!(result.is_err());
        // This should be caught as Malformed
    }

    #[test]
    fn test_nat_traversal_wrong_side_error() {
        // Test NAT traversal parameter validation per draft-seemann-quic-nat-traversal-02

        // Client sending non-empty value (invalid - clients must send empty)
        let mut buf = Vec::new();
        buf.write_var(0x3d7e9f0bca12fea6); // NAT traversal parameter ID
        buf.write_var(1); // length
        buf.push(5); // Invalid: client should send empty

        let result = TransportParameters::read(Side::Server, &mut buf.as_slice());
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, Error::IllegalValue);
        }

        // Server sending empty value (invalid - servers must send concurrency limit)
        let mut buf = Vec::new();
        buf.write_var(0x3d7e9f0bca12fea6); // NAT traversal parameter ID
        buf.write_var(0); // Empty value - invalid for server

        let result = TransportParameters::read(Side::Client, &mut buf.as_slice());
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, Error::IllegalValue);
        }
    }

    #[test]
    fn test_transport_error_code_value() {
        // Verify TRANSPORT_PARAMETER_ERROR has the correct code (0x08)
        let err = TransportError {
            code: crate::transport_error::Code::TRANSPORT_PARAMETER_ERROR,
            frame: None,
            reason: "test".into(),
        };
        assert_eq!(u64::from(err.code), 0x08);
    }

    #[test]
    fn test_transport_parameter_error_messages() {
        // Test various error messages
        let test_cases = vec![
            "malformed",
            "illegal value",
            "missing mandatory parameter",
            "forbidden parameter present",
            "invalid parameter length",
            "CID authentication failure",
            "concurrency_limit must be greater than 0",
            "concurrency_limit must not exceed 100",
        ];

        for msg in test_cases {
            let err = TransportError {
                code: crate::transport_error::Code::TRANSPORT_PARAMETER_ERROR,
                frame: None,
                reason: msg.into(),
            };
            assert_eq!(
                err.code,
                crate::transport_error::Code::TRANSPORT_PARAMETER_ERROR
            );
            assert_eq!(err.reason, msg);
        }
    }

    #[test]
    fn test_parameter_length_mismatch() {
        // Test parameter with incorrect length
        let mut buf = Vec::new();
        buf.write_var(0x00); // original_dst_cid ID
        buf.write_var(5); // claim 5 bytes
        buf.extend_from_slice(&[1, 2, 3]); // but only provide 3

        let result = TransportParameters::read(Side::Client, &mut buf.as_slice());
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_parameters_ignored() {
        // Unknown parameters should be ignored, not cause errors
        let mut buf = Vec::new();

        // Known parameter
        buf.write_var(0x01); // max_idle_timeout
        buf.write_var(VarInt::from_u32(30000).size() as u64); // length
        buf.write_var(30000); // value

        // Unknown parameter (should be ignored)
        buf.write_var(0xffffff); // Unknown ID
        buf.write_var(4); // length
        buf.extend_from_slice(&[1, 2, 3, 4]); // arbitrary data

        let result = TransportParameters::read(Side::Client, &mut buf.as_slice());
        if let Err(e) = &result {
            panic!("Expected unknown parameters to be ignored, but got error: {e:?}");
        }
        assert!(result.is_ok());
        let params = result.unwrap();
        assert_eq!(params.max_idle_timeout, VarInt::from_u32(30000));
    }
}
