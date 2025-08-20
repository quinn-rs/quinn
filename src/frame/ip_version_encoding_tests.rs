// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses


#[cfg(test)]
mod observed_address_ip_version_tests {
    
    use crate::frame::{Frame, FrameType, ObservedAddress};
    use crate::VarInt;
    use crate::coding::BufMutExt;
    use bytes::Bytes;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    #[test]
    fn test_ipv4_encoding_without_version_byte() {
        // Test that IPv4 addresses encode without IP version byte
        let frame = ObservedAddress {
            sequence_number: VarInt::from_u32(1),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080),
        };
        
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        
        // Expected format:
        // - Frame type: 0x9f81a6 (4 bytes as VarInt)
        // - Sequence: 1 (1 byte as VarInt)
        // - IPv4: 192.168.1.1 (4 bytes)
        // - Port: 8080 (2 bytes)
        // Total: 11 bytes (not 12 with IP version)
        
        assert_eq!(buf.len(), 11, "IPv4 frame should be 11 bytes without IP version byte");
        
        // Verify frame type
        assert_eq!(buf[0], 0x80); // First byte of 4-byte VarInt
        assert_eq!(buf[1], 0x9f);
        assert_eq!(buf[2], 0x81);
        assert_eq!(buf[3], 0xa6); // 0x9f81a6 for IPv4
        
        // Verify sequence number
        assert_eq!(buf[4], 1); // Sequence number 1
        
        // Verify IPv4 address directly follows (no version byte)
        assert_eq!(buf[5], 192);
        assert_eq!(buf[6], 168);
        assert_eq!(buf[7], 1);
        assert_eq!(buf[8], 1);
        
        // Verify port
        assert_eq!(buf[9], 0x1F); // 8080 >> 8
        assert_eq!(buf[10], 0x90); // 8080 & 0xFF
    }
    
    #[test]
    fn test_ipv6_encoding_without_version_byte() {
        // Test that IPv6 addresses encode without IP version byte
        let frame = ObservedAddress {
            sequence_number: VarInt::from_u32(2),
            address: SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                443
            ),
        };
        
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        
        // Expected format:
        // - Frame type: 0x9f81a7 (4 bytes as VarInt)
        // - Sequence: 2 (1 byte as VarInt)
        // - IPv6: 2001:db8::1 (16 bytes)
        // - Port: 443 (2 bytes)
        // Total: 23 bytes (not 24 with IP version)
        
        assert_eq!(buf.len(), 23, "IPv6 frame should be 23 bytes without IP version byte");
        
        // Verify frame type
        assert_eq!(buf[0], 0x80); // First byte of 4-byte VarInt
        assert_eq!(buf[1], 0x9f);
        assert_eq!(buf[2], 0x81);
        assert_eq!(buf[3], 0xa7); // 0x9f81a7 for IPv6
        
        // Verify sequence number
        assert_eq!(buf[4], 2); // Sequence number 2
        
        // Verify IPv6 address directly follows (no version byte)
        assert_eq!(buf[5], 0x20); // First byte of 2001:db8::1
        assert_eq!(buf[6], 0x01);
        // ... rest of IPv6 address
        
        // Verify port at correct offset
        assert_eq!(buf[21], 0x01); // 443 >> 8
        assert_eq!(buf[22], 0xBB); // 443 & 0xFF
    }
    
    #[test]
    fn test_decode_without_version_byte() {
        // Test decoding frames without IP version byte
        
        // Manually construct IPv4 frame
        let mut buf = Vec::new();
        buf.write(FrameType::OBSERVED_ADDRESS_IPV4); // Frame type
        buf.write_var(42); // Sequence number
        buf.extend_from_slice(&[10, 0, 0, 1]); // IPv4 address
        buf.extend_from_slice(&[0x00, 0x50]); // Port 80
        
        // Decode
        let frames = super::super::Iter::new(Bytes::from(buf))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        
        assert_eq!(frames.len(), 1);
        match &frames[0] {
            Frame::ObservedAddress(obs) => {
                assert_eq!(obs.sequence_number, VarInt::from_u32(42));
                assert_eq!(obs.address, SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    80
                ));
            }
            _ => panic!("Expected ObservedAddress frame"),
        }
    }
    
    #[test]
    fn test_frame_type_determines_ip_version() {
        // Test that frame type alone determines IP version
        
        // IPv4 frame type
        let frame_type_v4 = FrameType::OBSERVED_ADDRESS_IPV4;
        assert_eq!(frame_type_v4.0 & 1, 0, "IPv4 frame type should have LSB = 0");
        
        // IPv6 frame type
        let frame_type_v6 = FrameType::OBSERVED_ADDRESS_IPV6;
        assert_eq!(frame_type_v6.0 & 1, 1, "IPv6 frame type should have LSB = 1");
    }
    
    #[test]
    fn test_roundtrip_without_version_byte() {
        // Test encoding and decoding roundtrip
        let test_frames = vec![
            ObservedAddress {
                sequence_number: VarInt::from_u32(100),
                address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            },
            ObservedAddress {
                sequence_number: VarInt::from_u32(200),
                address: SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                    443
                ),
            },
        ];
        
        for original in test_frames {
            let mut buf = Vec::new();
            original.encode(&mut buf);
            
            // Decode and verify
            let frames = super::super::Iter::new(Bytes::from(buf))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            
            assert_eq!(frames.len(), 1);
            match &frames[0] {
                Frame::ObservedAddress(decoded) => {
                    assert_eq!(decoded.sequence_number, original.sequence_number);
                    assert_eq!(decoded.address, original.address);
                }
                _ => panic!("Expected ObservedAddress frame"),
            }
        }
    }
}