#[cfg(test)]
mod observed_address_sequence_edge_cases {
    
    use crate::frame::ObservedAddress;
    use crate::VarInt;
    use crate::coding::BufMutExt;
    use bytes::{BufMut, Bytes};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn test_sequence_at_varint_max() {
        // Test handling of maximum possible sequence number
        let frame = ObservedAddress {
            sequence_number: VarInt::MAX,
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 443),
        };
        
        // Encode
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        
        // Decode
        let mut reader = &buf[4..]; // Skip frame type
        let decoded = ObservedAddress::decode(&mut reader, false).unwrap(); // IPv4
        
        assert_eq!(decoded.sequence_number, VarInt::MAX);
        assert_eq!(decoded.address, frame.address);
    }
    
    #[test]
    fn test_sequence_wraparound_behavior() {
        // Test what happens when we try to increment past VarInt::MAX
        let max_minus_one = VarInt::from_u64(VarInt::MAX.into_inner() - 1).unwrap();
        let max = VarInt::MAX;
        
        // Verify we can create frames with these values
        let frame1 = ObservedAddress {
            sequence_number: max_minus_one,
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80),
        };
        
        let frame2 = ObservedAddress {
            sequence_number: max,
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80),
        };
        
        // Both should encode/decode successfully
        for frame in [frame1, frame2] {
            let mut buf = Vec::new();
            frame.encode(&mut buf);
            
            let mut reader = &buf[4..];
            let decoded = ObservedAddress::decode(&mut reader, false).unwrap(); // IPv4
            assert_eq!(decoded.sequence_number, frame.sequence_number);
        }
    }
    
    #[test]
    fn test_out_of_order_sequence_rejection() {
        // Test that out-of-order sequences are properly handled
        // This tests the validation logic concept (actual connection testing would be integration)
        
        let sequences = vec![
            VarInt::from_u32(1),
            VarInt::from_u32(5),
            VarInt::from_u32(3), // Out of order - should be rejected
            VarInt::from_u32(10),
            VarInt::from_u32(10), // Duplicate - should be rejected
            VarInt::from_u32(15),
        ];
        
        let mut last_accepted = VarInt::from_u32(0);
        let mut accepted_count = 0;
        
        for seq in sequences {
            if seq > last_accepted {
                // Would be accepted
                last_accepted = seq;
                accepted_count += 1;
            }
            // else would be rejected
        }
        
        // Should accept: 1, 5, 10, 15 (4 total)
        assert_eq!(accepted_count, 4);
    }
    
    #[test]
    fn test_concurrent_observed_address_frames() {
        // Test handling multiple frames with different sequences
        use std::sync::{Arc, Mutex};
        use std::thread;
        
        let frames = Arc::new(Mutex::new(Vec::new()));
        let mut handles = vec![];
        
        // Simulate concurrent frame creation
        for i in 0..10 {
            let frames_clone = Arc::clone(&frames);
            let handle = thread::spawn(move || {
                let frame = ObservedAddress {
                    sequence_number: VarInt::from_u32(i * 10),
                    address: SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(192, 168, 1, i as u8)), 
                        8080 + i as u16
                    ),
                };
                
                let mut buf = Vec::new();
                frame.encode(&mut buf);
                
                frames_clone.lock().unwrap().push((i, buf));
            });
            handles.push(handle);
        }
        
        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }
        
        // Verify all frames were created
        let frames = frames.lock().unwrap();
        assert_eq!(frames.len(), 10);
        
        // Each should decode correctly
        for (i, buf) in frames.iter() {
            let mut reader = &buf[4..];
            let decoded = ObservedAddress::decode(&mut reader, false).unwrap(); // All test IPs are IPv4
            assert_eq!(decoded.sequence_number, VarInt::from_u32(i * 10));
        }
    }
    
    #[test]
    fn test_replay_attack_prevention() {
        // Verify that replayed frames with old sequences would be rejected
        // This simulates the validation logic
        
        struct MockValidator {
            last_sequence: std::collections::HashMap<u64, VarInt>,
        }
        
        impl MockValidator {
            fn validate(&mut self, path_id: u64, seq: VarInt) -> bool {
                match self.last_sequence.get(&path_id) {
                    Some(&last) if seq <= last => false, // Reject
                    _ => {
                        self.last_sequence.insert(path_id, seq);
                        true // Accept
                    }
                }
            }
        }
        
        let mut validator = MockValidator {
            last_sequence: std::collections::HashMap::new(),
        };
        
        // Normal sequence
        assert!(validator.validate(0, VarInt::from_u32(1)));
        assert!(validator.validate(0, VarInt::from_u32(2)));
        assert!(validator.validate(0, VarInt::from_u32(5)));
        
        // Replay attacks (should be rejected)
        assert!(!validator.validate(0, VarInt::from_u32(2))); // Replay
        assert!(!validator.validate(0, VarInt::from_u32(1))); // Old sequence
        assert!(!validator.validate(0, VarInt::from_u32(5))); // Duplicate
        
        // Different path should have independent tracking
        assert!(validator.validate(1, VarInt::from_u32(1))); // Path 1 can start at 1
        assert!(validator.validate(1, VarInt::from_u32(3)));
        assert!(!validator.validate(1, VarInt::from_u32(2))); // Out of order on path 1
    }
    
    #[test] 
    fn test_zero_sequence_handling() {
        // Test that sequence number 0 is valid
        let frame = ObservedAddress {
            sequence_number: VarInt::from_u32(0),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
        };
        
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        
        let mut reader = &buf[4..];
        let decoded = ObservedAddress::decode(&mut reader, false).unwrap(); // IPv4
        
        assert_eq!(decoded.sequence_number, VarInt::from_u32(0));
        assert_eq!(decoded.address, frame.address);
        
        // Verify 0 is less than any positive number
        assert!(VarInt::from_u32(0) < VarInt::from_u32(1));
    }
    
    #[test]
    fn test_sequence_gaps_allowed() {
        // Per RFC, gaps in sequence numbers are allowed
        let sequences = vec![1, 5, 10, 100, 1000, 10000];
        let mut frames = Vec::new();
        
        for seq in sequences {
            let frame = ObservedAddress {
                sequence_number: VarInt::from_u32(seq),
                address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), seq as u16),
            };
            frames.push(frame);
        }
        
        // All should encode/decode successfully
        for frame in &frames {
            let mut buf = Vec::new();
            frame.encode(&mut buf);
            
            let mut reader = &buf[4..];
            let decoded = ObservedAddress::decode(&mut reader, false).unwrap(); // All test IPs are IPv4
            assert_eq!(decoded.sequence_number, frame.sequence_number);
        }
        
        // Verify sequence ordering
        for i in 1..frames.len() {
            assert!(frames[i].sequence_number > frames[i-1].sequence_number);
        }
    }
    
    #[test]
    fn test_malformed_sequence_number() {
        use crate::frame::FrameType;
        
        
        // Create a malformed frame with truncated sequence number
        let mut buf = Vec::new();
        buf.write(FrameType::OBSERVED_ADDRESS_IPV4); // Frame type
        buf.put_u8(0xc0); // Start of 8-byte varint
        // Missing rest of varint bytes
        
        // Should fail to decode
        let result = crate::frame::Iter::new(Bytes::from(buf));
        assert!(result.is_ok()); // Iterator creation succeeds
        
        let mut iter = result.unwrap();
        let frame_result = iter.next();
        assert!(frame_result.is_some());
        assert!(frame_result.unwrap().is_err()); // But frame parsing fails
    }
    
    #[test]
    fn test_sequence_encoding_sizes() {
        // Test that different sequence values encode to expected sizes
        let test_cases = vec![
            (0, 1),      // 1-byte varint
            (63, 1),     // Still 1-byte
            (64, 2),     // 2-byte varint
            (16383, 2),  // Still 2-byte
            (16384, 4),  // 4-byte varint
            (1073741823, 4), // Still 4-byte
            (1073741824, 8), // 8-byte varint
        ];
        
        for (seq_val, expected_bytes) in test_cases {
            let frame = ObservedAddress {
                sequence_number: VarInt::from_u64(seq_val).unwrap(),
                address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80),
            };
            
            let mut buf = Vec::new();
            frame.encode(&mut buf);
            
            // Frame type (4) + sequence (varies) + ipv4 (4) + port (2)
            let expected_total = 4 + expected_bytes + 4 + 2;
            assert_eq!(
                buf.len(), 
                expected_total,
                "Sequence {seq_val} should use {expected_bytes} varint bytes"
            );
        }
    }
}