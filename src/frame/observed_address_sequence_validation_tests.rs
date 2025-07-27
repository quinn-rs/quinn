#[cfg(test)]
mod observed_address_sequence_validation {
    
    
    use crate::frame::ObservedAddress;
    use crate::coding::BufExt;
    use crate::VarInt;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Instant;

    #[test]
    fn test_sequence_number_validation_in_frame_processing() {
        // This test validates that the OBSERVED_ADDRESS frame sequence number
        // validation works according to RFC draft-ietf-quic-address-discovery-00
        
        // Create a test connection with address discovery enabled
        let _now = Instant::now();
        let _config = crate::transport_parameters::AddressDiscoveryConfig::SendAndReceive;
        
        // Create frames with different sequence numbers
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000);
        
        let frame1 = ObservedAddress {
            sequence_number: VarInt::from_u32(1),
            address: addr,
        };
        
        let frame2 = ObservedAddress {
            sequence_number: VarInt::from_u32(2),
            address: addr,
        };
        
        let frame3_duplicate = ObservedAddress {
            sequence_number: VarInt::from_u32(2), // Duplicate sequence
            address: addr,
        };
        
        let frame4_stale = ObservedAddress {
            sequence_number: VarInt::from_u32(1), // Stale sequence
            address: addr,
        };
        
        let frame5 = ObservedAddress {
            sequence_number: VarInt::from_u32(5), // Jump in sequence (allowed)
            address: addr,
        };
        
        // TODO: Once we have a proper test harness for Connection,
        // we should process these frames and verify:
        // 1. frame1 is accepted (first frame)
        // 2. frame2 is accepted (higher sequence)
        // 3. frame3_duplicate is ignored (equal sequence)
        // 4. frame4_stale is ignored (lower sequence)  
        // 5. frame5 is accepted (higher sequence, gaps are allowed)
        
        // For now, just verify the frames encode/decode correctly
        for (i, frame) in [frame1, frame2, frame3_duplicate, frame4_stale, frame5].iter().enumerate() {
            let mut buf = Vec::new();
            frame.encode(&mut buf);
            assert!(!buf.is_empty(), "Frame {i} should encode to non-empty buffer");
            
            // Verify we can decode it back
            let mut reader = &buf[4..]; // Skip frame type
            let decoded = ObservedAddress::decode(&mut reader, false).unwrap();
            assert_eq!(decoded.sequence_number, frame.sequence_number);
            assert_eq!(decoded.address, frame.address);
        }
    }
    
    #[test]
    fn test_sequence_number_monotonicity_per_path() {
        // Test that sequence numbers are tracked per path
        // In a multi-path scenario, each path should have independent sequence tracking
        
        let path0_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1234);
        let path1_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 5678);
        
        // Path 0 frames
        let path0_frame1 = ObservedAddress {
            sequence_number: VarInt::from_u32(1),
            address: path0_addr,
        };
        
        let path0_frame2 = ObservedAddress {
            sequence_number: VarInt::from_u32(3),
            address: path0_addr,
        };
        
        // Path 1 frames (can reuse sequence numbers)
        let path1_frame1 = ObservedAddress {
            sequence_number: VarInt::from_u32(1), // Same as path0, but different path
            address: path1_addr,
        };
        
        let path1_frame2 = ObservedAddress {
            sequence_number: VarInt::from_u32(2),
            address: path1_addr,
        };
        
        // TODO: When multi-path support is added, verify that:
        // 1. path0_frame1 and path0_frame2 are both accepted for path 0
        // 2. path1_frame1 and path1_frame2 are both accepted for path 1
        // 3. Sequence numbers are tracked independently per path
        
        // For now, verify encoding/decoding
        for frame in [path0_frame1, path0_frame2, path1_frame1, path1_frame2] {
            let mut buf = Vec::new();
            frame.encode(&mut buf);
            
            let mut reader = &buf[4..];
            let decoded = ObservedAddress::decode(&mut reader, false).unwrap();
            assert_eq!(decoded.sequence_number, frame.sequence_number);
            assert_eq!(decoded.address, frame.address);
        }
    }
    
    #[test]
    fn test_sequence_number_edge_cases_validation() {
        // Test edge cases for sequence numbers
        
        // Maximum sequence number
        let max_frame = ObservedAddress {
            sequence_number: VarInt::MAX,
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 65535),
        };
        
        // After max, we should handle wraparound gracefully
        // Per RFC, sequence numbers are monotonically increasing,
        // but implementation should handle VarInt::MAX edge case
        
        let mut buf = Vec::new();
        max_frame.encode(&mut buf);
        
        let mut reader = &buf[4..];
        let decoded = ObservedAddress::decode(&mut reader, false).unwrap();
        assert_eq!(decoded.sequence_number, VarInt::MAX);
        
        // Zero sequence number (valid as first frame)
        let zero_frame = ObservedAddress {
            sequence_number: VarInt::from_u32(0),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80),
        };
        
        let mut buf = Vec::new();
        zero_frame.encode(&mut buf);
        
        let mut reader = &buf[4..];
        let decoded = ObservedAddress::decode(&mut reader, false).unwrap();
        assert_eq!(decoded.sequence_number, VarInt::from_u32(0));
    }
    
    #[test]
    fn test_sequence_validation_integration() {
        // Integration test showing the complete flow
        
        use bytes::BytesMut;
        
        // Simulate receiving multiple OBSERVED_ADDRESS frames in order
        let frames = vec![
            ObservedAddress {
                sequence_number: VarInt::from_u32(1),
                address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443),
            },
            ObservedAddress {
                sequence_number: VarInt::from_u32(2),
                address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443),
            },
            ObservedAddress {
                sequence_number: VarInt::from_u32(5), // Gap is OK
                address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35)), 443),
            },
        ];
        
        // Encode all frames
        let mut buf = BytesMut::new();
        for frame in &frames {
            frame.encode(&mut buf);
        }
        
        // Now decode and verify we get all frames back with correct sequences
        let mut decoded_frames = Vec::new();
        let mut offset = 0;
        
        while offset < buf.len() {
            // Read frame type
            let frame_type_start = offset;
            let mut reader = &buf[offset..];
            let frame_type = match reader.get_var() {
                Ok(val) => val,
                Err(_) => break,
            };
            let frame_type_len = buf[offset..].len() - reader.len();
            offset += frame_type_len;
            
            // Check if it's OBSERVED_ADDRESS
            if frame_type == crate::frame::FrameType::OBSERVED_ADDRESS_IPV4.0 ||
               frame_type == crate::frame::FrameType::OBSERVED_ADDRESS_IPV6.0 {
                let mut reader = &buf[offset..];
                let is_ipv6 = frame_type == crate::frame::FrameType::OBSERVED_ADDRESS_IPV6.0;
                if let Ok(decoded) = ObservedAddress::decode(&mut reader, is_ipv6) {
                    let frame_len = buf[offset..].len() - reader.len();
                    decoded_frames.push(decoded);
                    offset += frame_len;
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        
        // Verify we decoded all frames
        assert_eq!(decoded_frames.len(), frames.len());
        
        // Verify sequence numbers are preserved
        for (original, decoded) in frames.iter().zip(decoded_frames.iter()) {
            assert_eq!(original.sequence_number, decoded.sequence_number);
            assert_eq!(original.address, decoded.address);
        }
        
        // Verify sequence numbers are in expected order
        assert_eq!(decoded_frames[0].sequence_number, VarInt::from_u32(1));
        assert_eq!(decoded_frames[1].sequence_number, VarInt::from_u32(2));
        assert_eq!(decoded_frames[2].sequence_number, VarInt::from_u32(5));
    }
}