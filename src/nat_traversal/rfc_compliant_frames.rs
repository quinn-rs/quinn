//! RFC-Compliant NAT Traversal Frame Implementations
//!
//! This module implements the QUIC NAT traversal extension frames exactly as specified
//! in draft-seemann-quic-nat-traversal-02. These implementations strictly follow the
//! RFC specification without any extensions or modifications.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use bytes::{Buf, BufMut};

use crate::coding::{self, Codec, BufExt, BufMutExt};
use crate::VarInt;

/// ADD_ADDRESS frame for advertising candidate addresses (RFC-compliant)
/// 
/// As defined in draft-seemann-quic-nat-traversal-02:
/// - Frame type 0x3d7e90 for IPv4
/// - Frame type 0x3d7e91 for IPv6
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddAddress {
    /// Sequence number for the address (used for referencing in other frames)
    pub sequence_number: VarInt,
    /// The socket address being advertised
    pub address: SocketAddr,
}

/// PUNCH_ME_NOW frame for coordinating hole punching (RFC-compliant)
/// 
/// As defined in draft-seemann-quic-nat-traversal-02:
/// - Frame type 0x3d7e92 for IPv4
/// - Frame type 0x3d7e93 for IPv6
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PunchMeNow {
    /// Round number for coordination
    pub round: VarInt,
    /// Sequence number of the address that was paired with this address
    pub paired_with_sequence_number: VarInt,
    /// The address to punch to
    pub address: SocketAddr,
}

/// REMOVE_ADDRESS frame for removing candidate addresses (RFC-compliant)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoveAddress {
    /// Sequence number of the address to remove
    pub sequence_number: VarInt,
}

impl AddAddress {
    pub fn decode<B: Buf>(buf: &mut B, is_ipv6: bool) -> coding::Result<Self> {
        let sequence_number = buf.get_var()?;
        
        let ip = if is_ipv6 {
            if buf.remaining() < 16 {
                return Err(coding::UnexpectedEnd);
            }
            let mut octets = [0u8; 16];
            buf.copy_to_slice(&mut octets);
            IpAddr::V6(Ipv6Addr::from(octets))
        } else {
            if buf.remaining() < 4 {
                return Err(coding::UnexpectedEnd);
            }
            let mut octets = [0u8; 4];
            buf.copy_to_slice(&mut octets);
            IpAddr::V4(Ipv4Addr::from(octets))
        };
        
        if buf.remaining() < 2 {
            return Err(coding::UnexpectedEnd);
        }
        let port = buf.get_u16();
        
        Ok(Self {
            sequence_number,
            address: SocketAddr::new(ip, port),
        })
    }
    
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.write_var(self.sequence_number.into_inner());
        
        match self.address.ip() {
            IpAddr::V4(ipv4) => {
                buf.put_slice(&ipv4.octets());
            },
            IpAddr::V6(ipv6) => {
                buf.put_slice(&ipv6.octets());
            },
        }
        
        buf.put_u16(self.address.port());
    }
}

impl PunchMeNow {
    pub fn decode<B: Buf>(buf: &mut B, is_ipv6: bool) -> coding::Result<Self> {
        let round = buf.get_var()?;
        let paired_with_sequence_number = buf.get_var()?;
        
        let ip = if is_ipv6 {
            if buf.remaining() < 16 {
                return Err(coding::UnexpectedEnd);
            }
            let mut octets = [0u8; 16];
            buf.copy_to_slice(&mut octets);
            IpAddr::V6(Ipv6Addr::from(octets))
        } else {
            if buf.remaining() < 4 {
                return Err(coding::UnexpectedEnd);
            }
            let mut octets = [0u8; 4];
            buf.copy_to_slice(&mut octets);
            IpAddr::V4(Ipv4Addr::from(octets))
        };
        
        if buf.remaining() < 2 {
            return Err(coding::UnexpectedEnd);
        }
        let port = buf.get_u16();
        
        Ok(Self {
            round,
            paired_with_sequence_number,
            address: SocketAddr::new(ip, port),
        })
    }
    
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.write_var(self.round.into_inner());
        buf.write_var(self.paired_with_sequence_number.into_inner());
        
        match self.address.ip() {
            IpAddr::V4(ipv4) => {
                buf.put_slice(&ipv4.octets());
            },
            IpAddr::V6(ipv6) => {
                buf.put_slice(&ipv6.octets());
            },
        }
        
        buf.put_u16(self.address.port());
    }
}

impl RemoveAddress {
    pub fn decode<B: Buf>(buf: &mut B) -> coding::Result<Self> {
        let sequence_number = buf.get_var()?;
        
        Ok(Self { sequence_number })
    }
    
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.write_var(self.sequence_number.into_inner());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    
    #[test]
    fn test_add_address_ipv4_roundtrip() {
        let frame = AddAddress {
            sequence_number: VarInt::from_u32(42),
            address: "192.168.1.1:8080".parse().unwrap(),
        };
        
        let mut buf = BytesMut::new();
        frame.encode(&mut buf);
        
        let decoded = AddAddress::decode(&mut buf.freeze(), false).unwrap();
        assert_eq!(frame, decoded);
    }
    
    #[test]
    fn test_add_address_ipv6_roundtrip() {
        let frame = AddAddress {
            sequence_number: VarInt::from_u32(123),
            address: "[2001:db8::1]:9000".parse().unwrap(),
        };
        
        let mut buf = BytesMut::new();
        frame.encode(&mut buf);
        
        let decoded = AddAddress::decode(&mut buf.freeze(), true).unwrap();
        assert_eq!(frame, decoded);
    }
    
    #[test]
    fn test_punch_me_now_roundtrip() {
        let frame = PunchMeNow {
            round: VarInt::from_u32(5),
            paired_with_sequence_number: VarInt::from_u32(42),
            address: "10.0.0.1:1234".parse().unwrap(),
        };
        
        let mut buf = BytesMut::new();
        frame.encode(&mut buf);
        
        let decoded = PunchMeNow::decode(&mut buf.freeze(), false).unwrap();
        assert_eq!(frame, decoded);
    }
    
    #[test]
    fn test_remove_address_roundtrip() {
        let frame = RemoveAddress {
            sequence_number: VarInt::from_u32(999),
        };
        
        let mut buf = BytesMut::new();
        frame.encode(&mut buf);
        
        let decoded = RemoveAddress::decode(&mut buf.freeze()).unwrap();
        assert_eq!(frame, decoded);
    }
}