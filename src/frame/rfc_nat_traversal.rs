// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! RFC-compliant NAT traversal frames according to draft-seemann-quic-nat-traversal-02
//!
//! This module provides frame implementations that exactly match the RFC specification,
//! without any proprietary extensions.

use crate::{
    VarInt,
    coding::{BufExt, BufMutExt, UnexpectedEnd},
    frame::{FrameStruct, FrameType},
};
use bytes::{Buf, BufMut};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

/// RFC-compliant ADD_ADDRESS frame
///
/// Format:
/// - Type (i) = 0x3d7e90 (IPv4) or 0x3d7e91 (IPv6)
/// - Sequence Number (i)
/// - IPv4 Address (32 bits) or IPv6 Address (128 bits)
/// - Port (16 bits)
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct RfcAddAddress {
    /// Sequence number for this address advertisement
    pub sequence_number: VarInt,
    /// Socket address being advertised
    pub address: SocketAddr,
}

#[allow(dead_code)]
impl RfcAddAddress {
    pub fn encode<W: BufMut>(&self, buf: &mut W) {
        // Frame type determines IPv4 vs IPv6
        match self.address {
            SocketAddr::V4(_) => buf.write_var(FrameType::ADD_ADDRESS_IPV4.0),
            SocketAddr::V6(_) => buf.write_var(FrameType::ADD_ADDRESS_IPV6.0),
        }

        // Sequence number
        buf.write_var(self.sequence_number.0);

        // Address (no IP version byte!)
        match self.address {
            SocketAddr::V4(addr) => {
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            SocketAddr::V6(addr) => {
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
                // No flowinfo or scope_id in RFC!
            }
        }
    }

    pub fn decode<R: Buf>(r: &mut R, is_ipv6: bool) -> Result<Self, UnexpectedEnd> {
        let sequence_number = VarInt::from_u64(r.get_var()?).map_err(|_| UnexpectedEnd)?;

        let address = if is_ipv6 {
            if r.remaining() < 16 + 2 {
                return Err(UnexpectedEnd);
            }
            let mut octets = [0u8; 16];
            r.copy_to_slice(&mut octets);
            let port = r.get_u16();
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(octets),
                port,
                0, // flowinfo always 0
                0, // scope_id always 0
            ))
        } else {
            if r.remaining() < 4 + 2 {
                return Err(UnexpectedEnd);
            }
            let mut octets = [0u8; 4];
            r.copy_to_slice(&mut octets);
            let port = r.get_u16();
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(octets), port))
        };

        Ok(Self {
            sequence_number,
            address,
        })
    }
}

impl FrameStruct for RfcAddAddress {
    // Frame type (4) + sequence (1-8) + address (4 or 16) + port (2)
    const SIZE_BOUND: usize = 4 + 8 + 16 + 2;
}

/// RFC-compliant PUNCH_ME_NOW frame
///
/// Format:
/// - Type (i) = 0x3d7e92 (IPv4) or 0x3d7e93 (IPv6)
/// - Round (i)
/// - Paired With Sequence Number (i)
/// - IPv4 Address (32 bits) or IPv6 Address (128 bits)
/// - Port (16 bits)
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct RfcPunchMeNow {
    /// Round number for coordination
    pub round: VarInt,
    /// Sequence number of the address to punch to (from ADD_ADDRESS)
    pub paired_with_sequence_number: VarInt,
    /// Address to send the punch packet to
    pub address: SocketAddr,
}

#[allow(dead_code)]
impl RfcPunchMeNow {
    pub fn encode<W: BufMut>(&self, buf: &mut W) {
        // Frame type determines IPv4 vs IPv6
        match self.address {
            SocketAddr::V4(_) => buf.write_var(FrameType::PUNCH_ME_NOW_IPV4.0),
            SocketAddr::V6(_) => buf.write_var(FrameType::PUNCH_ME_NOW_IPV6.0),
        }

        // Fields
        buf.write_var(self.round.0);
        buf.write_var(self.paired_with_sequence_number.0);

        // Address (no IP version byte!)
        match self.address {
            SocketAddr::V4(addr) => {
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            SocketAddr::V6(addr) => {
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
        }
    }

    pub fn decode<R: Buf>(r: &mut R, is_ipv6: bool) -> Result<Self, UnexpectedEnd> {
        let round = VarInt::from_u64(r.get_var()?).map_err(|_| UnexpectedEnd)?;
        let paired_with_sequence_number =
            VarInt::from_u64(r.get_var()?).map_err(|_| UnexpectedEnd)?;

        let address = if is_ipv6 {
            if r.remaining() < 16 + 2 {
                return Err(UnexpectedEnd);
            }
            let mut octets = [0u8; 16];
            r.copy_to_slice(&mut octets);
            let port = r.get_u16();
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(octets), port, 0, 0))
        } else {
            if r.remaining() < 4 + 2 {
                return Err(UnexpectedEnd);
            }
            let mut octets = [0u8; 4];
            r.copy_to_slice(&mut octets);
            let port = r.get_u16();
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(octets), port))
        };

        Ok(Self {
            round,
            paired_with_sequence_number,
            address,
        })
    }
}

impl FrameStruct for RfcPunchMeNow {
    // Frame type (4) + round (1-8) + sequence (1-8) + address (4 or 16) + port (2)
    const SIZE_BOUND: usize = 4 + 8 + 8 + 16 + 2;
}

/// RFC-compliant REMOVE_ADDRESS frame
///
/// Format:
/// - Type (i) = 0x3d7e94
/// - Sequence Number (i)
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct RfcRemoveAddress {
    /// Sequence number of the address to remove
    pub sequence_number: VarInt,
}

#[allow(dead_code)]
impl RfcRemoveAddress {
    pub fn encode<W: BufMut>(&self, buf: &mut W) {
        buf.write_var(FrameType::REMOVE_ADDRESS.0);
        buf.write_var(self.sequence_number.0);
    }

    pub fn decode<R: Buf>(r: &mut R) -> Result<Self, UnexpectedEnd> {
        let sequence_number = VarInt::from_u64(r.get_var()?).map_err(|_| UnexpectedEnd)?;
        Ok(Self { sequence_number })
    }
}

impl FrameStruct for RfcRemoveAddress {
    // Frame type (4) + sequence (1-8)
    const SIZE_BOUND: usize = 4 + 8;
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_rfc_add_address_roundtrip() {
        let frame = RfcAddAddress {
            sequence_number: VarInt::from_u32(42),
            address: "192.168.1.100:8080".parse().unwrap(),
        };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        // Skip frame type for decoding
        buf.advance(4);
        let decoded = RfcAddAddress::decode(&mut buf, false).unwrap();

        assert_eq!(frame.sequence_number, decoded.sequence_number);
        assert_eq!(frame.address, decoded.address);
    }

    #[test]
    fn test_rfc_punch_me_now_roundtrip() {
        let frame = RfcPunchMeNow {
            round: VarInt::from_u32(5),
            paired_with_sequence_number: VarInt::from_u32(42),
            address: "[2001:db8::1]:9000".parse().unwrap(),
        };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        // Skip frame type for decoding
        buf.advance(4);
        let decoded = RfcPunchMeNow::decode(&mut buf, true).unwrap();

        assert_eq!(frame.round, decoded.round);
        assert_eq!(
            frame.paired_with_sequence_number,
            decoded.paired_with_sequence_number
        );
        assert_eq!(frame.address, decoded.address);
    }
}
