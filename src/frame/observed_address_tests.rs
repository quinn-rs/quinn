#[cfg(test)]
mod observed_address_sequence_tests {
    
    // use crate::coding::{BufMutExt, Codec}; // Not needed - imported through frame module
    use crate::frame::{Frame, FrameType, Iter, ObservedAddress};
    use crate::VarInt;
    use bytes::{BufMut, Bytes};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    #[test]
    fn test_observed_address_with_sequence_number_encoding() {
        // Test IPv4 with sequence number
        let frame_ipv4 = ObservedAddress {
            sequence_number: VarInt::from_u32(42),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080),
        };

        let mut buf = Vec::new();
        frame_ipv4.encode(&mut buf);

        // Verify we can decode it back
        let decoded_frames = frames(buf);
        assert_eq!(decoded_frames.len(), 1);

        match &decoded_frames[0] {
            Frame::ObservedAddress(decoded) => {
                assert_eq!(decoded.sequence_number, VarInt::from_u32(42));
                assert_eq!(decoded.address, frame_ipv4.address);
            }
            _ => panic!("Expected ObservedAddress frame"),
        }
    }

    #[test]
    fn test_observed_address_sequence_number_ordering() {
        // Create frames with different sequence numbers
        let test_frames = vec![
            ObservedAddress {
                sequence_number: VarInt::from_u32(1),
                address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1234),
            },
            ObservedAddress {
                sequence_number: VarInt::from_u32(5),
                address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 1234),
            },
            ObservedAddress {
                sequence_number: VarInt::from_u32(10),
                address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), 1234),
            },
        ];

        // Encode all frames
        let mut buf = Vec::new();
        for frame in &test_frames {
            frame.encode(&mut buf);
        }

        // Decode and verify sequence numbers are preserved
        let decoded_frames = frames(buf);
        assert_eq!(decoded_frames.len(), 3);

        for (i, decoded) in decoded_frames.iter().enumerate() {
            match decoded {
                Frame::ObservedAddress(obs) => {
                    assert_eq!(obs.sequence_number, test_frames[i].sequence_number);
                    assert_eq!(obs.address, test_frames[i].address);
                }
                _ => panic!("Expected ObservedAddress frame"),
            }
        }
    }

    #[test]
    fn test_observed_address_large_sequence_numbers() {
        // Test with large sequence numbers that require multi-byte varint encoding
        let test_cases = vec![
            VarInt::from_u32(0),        // 1 byte
            VarInt::from_u32(63),       // 1 byte boundary
            VarInt::from_u32(64),       // 2 bytes
            VarInt::from_u32(16383),    // 2 byte boundary
            VarInt::from_u32(16384),    // 4 bytes
            VarInt::from_u32(1073741823), // 4 byte boundary
            VarInt::from_u64(1073741824).unwrap(), // 8 bytes
        ];

        for seq_num in test_cases {
            let frame = ObservedAddress {
                sequence_number: seq_num,
                address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80),
            };

            let mut buf = Vec::new();
            frame.encode(&mut buf);

            let decoded_frames = frames(buf);
            assert_eq!(decoded_frames.len(), 1);

            match &decoded_frames[0] {
                Frame::ObservedAddress(decoded) => {
                    assert_eq!(decoded.sequence_number, seq_num);
                }
                _ => panic!("Expected ObservedAddress frame"),
            }
        }
    }

    #[test]
    fn test_observed_address_ipv6_with_sequence() {
        let frame_ipv6 = ObservedAddress {
            sequence_number: VarInt::from_u32(999),
            address: SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                443,
            ),
        };

        let mut buf = Vec::new();
        frame_ipv6.encode(&mut buf);

        let decoded_frames = frames(buf);
        assert_eq!(decoded_frames.len(), 1);

        match &decoded_frames[0] {
            Frame::ObservedAddress(decoded) => {
                assert_eq!(decoded.sequence_number, VarInt::from_u32(999));
                assert_eq!(decoded.address, frame_ipv6.address);
            }
            _ => panic!("Expected ObservedAddress frame"),
        }
    }

    #[test]
    fn test_observed_address_malformed_sequence() {
        use crate::coding::BufMutExt;

        // Test truncated sequence number
        let mut buf = Vec::new();
        buf.write(FrameType::OBSERVED_ADDRESS_IPV4);
        // Start writing a 2-byte varint but truncate
        buf.put_u8(0x40); // Indicates 2-byte varint
        // Missing second byte

        let result = Iter::new(Bytes::from(buf));
        assert!(result.is_ok());
        let mut iter = result.unwrap();
        let frame_result = iter.next();
        assert!(frame_result.is_some());
        assert!(frame_result.unwrap().is_err());
    }

    #[test]
    fn test_observed_address_sequence_wraparound() {
        // Test maximum sequence number
        let max_seq = VarInt::MAX;
        let frame = ObservedAddress {
            sequence_number: max_seq,
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 65535),
        };

        let mut buf = Vec::new();
        frame.encode(&mut buf);

        let decoded_frames = frames(buf);
        assert_eq!(decoded_frames.len(), 1);

        match &decoded_frames[0] {
            Frame::ObservedAddress(decoded) => {
                assert_eq!(decoded.sequence_number, max_seq);
            }
            _ => panic!("Expected ObservedAddress frame"),
        }
    }

    #[test]
    fn test_observed_address_frame_size_with_sequence() {
        // Verify frame sizes with sequence numbers
        let test_cases = vec![
            (
                ObservedAddress {
                    sequence_number: VarInt::from_u32(0),
                    address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80),
                },
                // Frame type (4) + seq (1) + IPv4 (4) + port (2) = 11 bytes
                11,
            ),
            (
                ObservedAddress {
                    sequence_number: VarInt::from_u32(16384), // 4-byte varint
                    address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80),
                },
                // Frame type (4) + seq (4) + IPv4 (4) + port (2) = 14 bytes
                14,
            ),
            (
                ObservedAddress {
                    sequence_number: VarInt::from_u32(0),
                    address: SocketAddr::new(
                        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                        443,
                    ),
                },
                // Frame type (4) + seq (1) + IPv6 (16) + port (2) = 23 bytes
                23,
            ),
        ];

        for (frame, expected_size) in test_cases {
            let mut buf = Vec::new();
            frame.encode(&mut buf);
            assert_eq!(
                buf.len(),
                expected_size,
                "Unexpected frame size for {frame:?}"
            );
        }
    }

    fn frames(buf: Vec<u8>) -> Vec<Frame> {
        Iter::new(Bytes::from(buf))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }
}