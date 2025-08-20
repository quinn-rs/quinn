// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses


//! NAT Traversal Frame Implementations
//!
//! This module implements the three required QUIC extension frames for NAT traversal
//! as defined in draft-seemann-quic-nat-traversal-01:
//! - ADD_ADDRESS
//! - PUNCH_ME_NOW
//! - REMOVE_ADDRESS
//!
//! These frames are used to coordinate NAT traversal between peers using a pure QUIC-native
//! approach without relying on external protocols like STUN or ICE.

use std::net::{IpAddr, SocketAddr};
use bytes::{Buf, BufMut};

use crate::coding::{self, Codec};
use crate::frame::Frame;
use crate::varint::VarInt;

// Frame type constants from draft-seemann-quic-nat-traversal-01
pub const FRAME_TYPE_ADD_ADDRESS: u64 = 0x3d7e90;
pub const FRAME_TYPE_PUNCH_ME_NOW: u64 = 0x3d7e91;
pub const FRAME_TYPE_REMOVE_ADDRESS: u64 = 0x3d7e92;

/// ADD_ADDRESS frame for advertising candidate addresses
/// 
/// As defined in draft-seemann-quic-nat-traversal-01, this frame includes:
/// - Sequence number (VarInt)
/// - Priority (VarInt)
/// - Address (IP address and port)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddAddress {
    /// Sequence number for the address (used for referencing in other frames)
    pub sequence: u64,
    /// Priority of this address candidate (higher values are preferred)
    pub priority: u64,
    /// The socket address being advertised
    pub address: SocketAddr,
}

/// PUNCH_ME_NOW frame for coordinating hole punching
/// 
/// As defined in draft-seemann-quic-nat-traversal-01, this frame includes:
/// - Round number (VarInt) for coordination
/// - Target sequence number (VarInt) referencing an ADD_ADDRESS frame
/// - Local address for this punch attempt
/// - Optional target peer ID for relay by bootstrap nodes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PunchMeNow {
    /// Round number for coordination
    pub round: u64,
    /// Sequence number of the address to punch (references an ADD_ADDRESS frame)
    pub paired_with_sequence_number: u64,
    /// Address for this punch attempt
    pub address: SocketAddr,
    /// Target peer ID for relay by bootstrap nodes (optional)
    pub target_peer_id: Option<[u8; 32]>,
}

/// REMOVE_ADDRESS frame for removing candidate addresses
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoveAddress {
    /// Sequence number of the address to remove
    pub sequence: u64,
}

impl Codec for AddAddress {
    fn decode<B: Buf>(buf: &mut B) -> coding::Result<Self> {
        if buf.remaining() < 1 {
            return Err(coding::UnexpectedEnd);
        }
        
        // Decode sequence number (VarInt)
        let sequence = VarInt::decode(buf)?.into_inner();
        
        // Decode priority (VarInt)
        let priority = VarInt::decode(buf)?.into_inner();
        
        // Decode address type (IPv4 or IPv6)
        let addr_type = buf.get_u8();
        let ip = match addr_type {
            4 => {
                if buf.remaining() < 4 {
                    return Err(coding::UnexpectedEnd);
                }
                let mut addr = [0u8; 4];
                buf.copy_to_slice(&mut addr);
                IpAddr::from(addr)
            },
            6 => {
                if buf.remaining() < 16 {
                    return Err(coding::UnexpectedEnd);
                }
                let mut addr = [0u8; 16];
                buf.copy_to_slice(&mut addr);
                IpAddr::from(addr)
            },
            _ => return Err(coding::UnexpectedEnd),
        };
        
        // Decode port
        if buf.remaining() < 2 {
            return Err(coding::UnexpectedEnd);
        }
        let port = buf.get_u16();
        
        Ok(Self {
            sequence,
            priority,
            address: SocketAddr::new(ip, port),
        })
    }
    
    fn encode<B: BufMut>(&self, buf: &mut B) {
        // Encode sequence number (VarInt)
        VarInt::from_u64(self.sequence).unwrap().encode(buf);
        
        // Encode priority (VarInt)
        VarInt::from_u64(self.priority).unwrap().encode(buf);
        
        // Encode address
        match self.address.ip() {
            IpAddr::V4(ipv4) => {
                buf.put_u8(4); // IPv4 type
                buf.put_slice(&ipv4.octets());
            },
            IpAddr::V6(ipv6) => {
                buf.put_u8(6); // IPv6 type
                buf.put_slice(&ipv6.octets());
            },
        }
        
        // Encode port
        buf.put_u16(self.address.port());
    }
}

impl Codec for PunchMeNow {
    fn decode<B: Buf>(buf: &mut B) -> coding::Result<Self> {
        if buf.remaining() < 1 {
            return Err(coding::UnexpectedEnd);
        }
        
        // Decode round number (VarInt)
        let round = VarInt::decode(buf)?.into_inner();
        
        // Decode target sequence (VarInt)
        let paired_with_sequence_number = VarInt::decode(buf)?.into_inner();
        
        // Decode local address
        let addr_type = buf.get_u8();
        let ip = match addr_type {
            4 => {
                if buf.remaining() < 4 {
                    return Err(coding::UnexpectedEnd);
                }
                let mut addr = [0u8; 4];
                buf.copy_to_slice(&mut addr);
                IpAddr::from(addr)
            },
            6 => {
                if buf.remaining() < 16 {
                    return Err(coding::UnexpectedEnd);
                }
                let mut addr = [0u8; 16];
                buf.copy_to_slice(&mut addr);
                IpAddr::from(addr)
            },
            _ => return Err(coding::UnexpectedEnd),
        };
        
        // Decode port
        if buf.remaining() < 2 {
            return Err(coding::UnexpectedEnd);
        }
        let port = buf.get_u16();
        
        // Decode target peer ID if present
        let target_peer_id = if buf.remaining() > 0 {
            let has_peer_id = buf.get_u8();
            if has_peer_id == 1 {
                if buf.remaining() < 32 {
                    return Err(coding::UnexpectedEnd);
                }
                let mut peer_id = [0u8; 32];
                buf.copy_to_slice(&mut peer_id);
                Some(peer_id)
            } else {
                None
            }
        } else {
            None
        };
        
        Ok(Self {
            round,
            paired_with_sequence_number,
            address: SocketAddr::new(ip, port),
            target_peer_id,
        })
    }
    
    fn encode<B: BufMut>(&self, buf: &mut B) {
        // Encode round number (VarInt)
        VarInt::from_u64(self.round).unwrap().encode(buf);
        
        // Encode target sequence (VarInt)
        VarInt::from_u64(self.paired_with_sequence_number).unwrap().encode(buf);
        
        // Encode local address
        match self.address.ip() {
            IpAddr::V4(ipv4) => {
                buf.put_u8(4); // IPv4 type
                buf.put_slice(&ipv4.octets());
            },
            IpAddr::V6(ipv6) => {
                buf.put_u8(6); // IPv6 type
                buf.put_slice(&ipv6.octets());
            },
        }
        
        // Encode port
        buf.put_u16(self.address.port());
        
        // Encode target peer ID if present
        match &self.target_peer_id {
            Some(peer_id) => {
                buf.put_u8(1); // Has peer ID
                buf.put_slice(peer_id);
            },
            None => {
                buf.put_u8(0); // No peer ID
            },
        }
    }
}

impl Codec for RemoveAddress {
    fn decode<B: Buf>(buf: &mut B) -> coding::Result<Self> {
        if buf.remaining() < 1 {
            return Err(coding::UnexpectedEnd);
        }
        
        let sequence = VarInt::decode(buf)?.into_inner();
        
        Ok(Self { sequence })
    }
    
    fn encode<B: BufMut>(&self, buf: &mut B) {
        VarInt::from_u64(self.sequence).unwrap().encode(buf);
    }
}

impl Frame for AddAddress {
    const TYPE: u64 = FRAME_TYPE_ADD_ADDRESS;
    
    fn encode<B: BufMut>(&self, buf: &mut B) {
        VarInt::from_u64(Self::TYPE).unwrap().encode(buf);
        Codec::encode(self, buf);
    }
}

impl Frame for PunchMeNow {
    const TYPE: u64 = FRAME_TYPE_PUNCH_ME_NOW;
    
    fn encode<B: BufMut>(&self, buf: &mut B) {
        VarInt::from_u64(Self::TYPE).unwrap().encode(buf);
        Codec::encode(self, buf);
    }
}

impl Frame for RemoveAddress {
    const TYPE: u64 = FRAME_TYPE_REMOVE_ADDRESS;
    
    fn encode<B: BufMut>(&self, buf: &mut B) {
        VarInt::from_u64(Self::TYPE).unwrap().encode(buf);
        Codec::encode(self, buf);
    }
}