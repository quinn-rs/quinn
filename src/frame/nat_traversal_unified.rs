// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Unified NAT traversal frame handling for RFC compliance with backward compatibility
//!
//! This module provides a unified approach to handle both RFC-compliant frames
//! and legacy frames from older endpoints.

use super::{FrameStruct, FrameType};
use crate::{
    VarInt,
    coding::{BufExt, BufMutExt, UnexpectedEnd},
    transport_parameters::TransportParameters,
};
use bytes::{Buf, BufMut};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

/// Transport parameter to indicate RFC NAT traversal support
/// This is a different parameter from the standard NAT traversal parameter
/// to allow independent negotiation of RFC-compliant frame formats
pub const TRANSPORT_PARAM_RFC_NAT_TRAVERSAL: u64 = 0x3d7e9f0bca12fea8;

/// Unified ADD_ADDRESS frame that can handle both formats
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddAddress {
    /// Sequence number for this address advertisement
    pub sequence: VarInt,
    /// Socket address being advertised
    pub address: SocketAddr,
    /// Priority (calculated internally, not sent in RFC mode)
    pub(crate) priority: VarInt,
}

impl AddAddress {
    /// Create a new AddAddress frame
    pub fn new(sequence: VarInt, address: SocketAddr) -> Self {
        // Calculate priority based on address type
        let priority = calculate_priority(&address);
        Self {
            sequence,
            address,
            priority: VarInt::from_u32(priority),
        }
    }

    /// Encode method for compatibility with existing code
    /// Uses the legacy format by default for backward compatibility
    pub fn encode<W: BufMut>(&self, buf: &mut W) {
        self.encode_legacy(buf);
    }

    /// Encode in RFC-compliant format
    pub fn encode_rfc<W: BufMut>(&self, buf: &mut W) {
        // Frame type determines IPv4 vs IPv6
        match self.address {
            SocketAddr::V4(_) => buf.write_var(FrameType::ADD_ADDRESS_IPV4.0),
            SocketAddr::V6(_) => buf.write_var(FrameType::ADD_ADDRESS_IPV6.0),
        }

        // Sequence number
        buf.write(self.sequence);

        // Address (no IP version byte, no priority!)
        match self.address {
            SocketAddr::V4(addr) => {
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            SocketAddr::V6(addr) => {
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
                // No flowinfo or scope_id in RFC
            }
        }
    }

    /// Encode in legacy format (for compatibility)
    pub fn encode_legacy<W: BufMut>(&self, buf: &mut W) {
        match self.address {
            SocketAddr::V4(_) => buf.write_var(FrameType::ADD_ADDRESS_IPV4.0),
            SocketAddr::V6(_) => buf.write_var(FrameType::ADD_ADDRESS_IPV6.0),
        }

        buf.write(self.sequence);
        buf.write(self.priority);

        match self.address {
            SocketAddr::V4(addr) => {
                buf.put_u8(4); // IPv4 indicator
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            SocketAddr::V6(addr) => {
                buf.put_u8(6); // IPv6 indicator
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
                buf.put_u32(addr.flowinfo());
                buf.put_u32(addr.scope_id());
            }
        }
    }

    /// Decode from RFC format
    pub fn decode_rfc<R: Buf>(r: &mut R, is_ipv6: bool) -> Result<Self, UnexpectedEnd> {
        let sequence = r.get()?;

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
                0, // flowinfo always 0 in RFC
                0, // scope_id always 0 in RFC
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

        Ok(Self::new(sequence, address))
    }

    /// Decode from legacy format
    pub fn decode_legacy<R: Buf>(r: &mut R) -> Result<Self, UnexpectedEnd> {
        let sequence = r.get()?;
        let priority = r.get()?;
        let ip_version = r.get::<u8>()?;

        let address = match ip_version {
            4 => {
                if r.remaining() < 4 + 2 {
                    return Err(UnexpectedEnd);
                }
                let mut octets = [0u8; 4];
                r.copy_to_slice(&mut octets);
                let port = r.get::<u16>()?;
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(octets), port))
            }
            6 => {
                if r.remaining() < 16 + 2 + 4 + 4 {
                    return Err(UnexpectedEnd);
                }
                let mut octets = [0u8; 16];
                r.copy_to_slice(&mut octets);
                let port = r.get::<u16>()?;
                let flowinfo = r.get::<u32>()?;
                let scope_id = r.get::<u32>()?;
                SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(octets),
                    port,
                    flowinfo,
                    scope_id,
                ))
            }
            _ => return Err(UnexpectedEnd),
        };

        Ok(Self {
            sequence,
            address,
            priority,
        })
    }

    /// Try to decode, detecting format automatically
    pub fn decode_auto<R: Buf>(r: &mut R, is_ipv6: bool) -> Result<Self, UnexpectedEnd> {
        // Peek at the data to detect format
        // RFC format: sequence (varint) + address
        // Legacy format: sequence (varint) + priority (varint) + ip_version (u8) + address

        // Save position
        let _start_pos = r.remaining();

        // Try RFC format first
        match Self::decode_rfc(r, is_ipv6) {
            Ok(frame) => Ok(frame),
            Err(_) => {
                // Rewind and try legacy format
                // This is a simplified approach - in production we'd need better detection
                Self::decode_legacy(r)
            }
        }
    }
}

/// Unified PUNCH_ME_NOW frame
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PunchMeNow {
    /// Round number for coordination
    pub round: VarInt,
    /// Sequence number of the address to punch to
    pub paired_with_sequence_number: VarInt,
    /// Address to punch to
    pub address: SocketAddr,
    /// Legacy field - target peer ID for relay
    pub(crate) target_peer_id: Option<[u8; 32]>,
}

impl PunchMeNow {
    /// Create a new PunchMeNow frame
    pub fn new(round: VarInt, paired_with_sequence_number: VarInt, address: SocketAddr) -> Self {
        Self {
            round,
            paired_with_sequence_number,
            address,
            target_peer_id: None,
        }
    }

    /// Encode method for compatibility with existing code
    /// Uses the legacy format by default for backward compatibility
    pub fn encode<W: BufMut>(&self, buf: &mut W) {
        self.encode_legacy(buf);
    }

    /// Encode in RFC-compliant format
    pub fn encode_rfc<W: BufMut>(&self, buf: &mut W) {
        match self.address {
            SocketAddr::V4(_) => buf.write_var(FrameType::PUNCH_ME_NOW_IPV4.0),
            SocketAddr::V6(_) => buf.write_var(FrameType::PUNCH_ME_NOW_IPV6.0),
        }

        buf.write(self.round);
        buf.write(self.paired_with_sequence_number);

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

    /// Encode in legacy format
    pub fn encode_legacy<W: BufMut>(&self, buf: &mut W) {
        match self.address {
            SocketAddr::V4(_) => buf.write_var(FrameType::PUNCH_ME_NOW_IPV4.0),
            SocketAddr::V6(_) => buf.write_var(FrameType::PUNCH_ME_NOW_IPV6.0),
        }

        buf.write(self.round);
        buf.write(self.paired_with_sequence_number); // Called target_sequence in legacy

        match self.address {
            SocketAddr::V4(addr) => {
                buf.put_u8(4); // IPv4 indicator
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            SocketAddr::V6(addr) => {
                buf.put_u8(6); // IPv6 indicator
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
                buf.put_u32(addr.flowinfo());
                buf.put_u32(addr.scope_id());
            }
        }

        // Encode target_peer_id if present
        match &self.target_peer_id {
            Some(peer_id) => {
                buf.put_u8(1); // Has peer ID
                buf.put_slice(peer_id);
            }
            None => {
                buf.put_u8(0); // No peer ID
            }
        }
    }

    /// Decode from RFC format
    pub fn decode_rfc<R: Buf>(r: &mut R, is_ipv6: bool) -> Result<Self, UnexpectedEnd> {
        let round = r.get()?;
        let paired_with_sequence_number = r.get()?;

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

        Ok(Self::new(round, paired_with_sequence_number, address))
    }

    /// Try to decode, detecting format automatically
    pub fn decode_auto<R: Buf>(r: &mut R, is_ipv6: bool) -> Result<Self, UnexpectedEnd> {
        // Try RFC format first, then fall back to legacy
        match Self::decode_rfc(r, is_ipv6) {
            Ok(frame) => Ok(frame),
            Err(_) => {
                // Fall back to legacy format
                Self::decode_legacy(r)
            }
        }
    }

    /// Decode from legacy format
    pub fn decode_legacy<R: Buf>(r: &mut R) -> Result<Self, UnexpectedEnd> {
        let round = r.get()?;
        let target_sequence = r.get()?; // Called target_sequence in legacy
        let ip_version = r.get::<u8>()?;

        let address = match ip_version {
            4 => {
                if r.remaining() < 4 + 2 {
                    return Err(UnexpectedEnd);
                }
                let mut octets = [0u8; 4];
                r.copy_to_slice(&mut octets);
                let port = r.get::<u16>()?;
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(octets), port))
            }
            6 => {
                if r.remaining() < 16 + 2 + 4 + 4 {
                    return Err(UnexpectedEnd);
                }
                let mut octets = [0u8; 16];
                r.copy_to_slice(&mut octets);
                let port = r.get::<u16>()?;
                let flowinfo = r.get::<u32>()?;
                let scope_id = r.get::<u32>()?;
                SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(octets),
                    port,
                    flowinfo,
                    scope_id,
                ))
            }
            _ => return Err(UnexpectedEnd),
        };

        // Check for optional target_peer_id
        let target_peer_id = if r.remaining() > 0 {
            let has_peer_id = r.get::<u8>()?;
            if has_peer_id == 1 && r.remaining() >= 32 {
                let mut peer_id = [0u8; 32];
                r.copy_to_slice(&mut peer_id);
                Some(peer_id)
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            round,
            paired_with_sequence_number: target_sequence,
            address,
            target_peer_id,
        })
    }
}

// Add FrameStruct implementations
impl FrameStruct for AddAddress {
    const SIZE_BOUND: usize = 4 + 9 + 9 + 1 + 16 + 2 + 4 + 4; // frame type (4) + worst case IPv6
}

impl FrameStruct for PunchMeNow {
    const SIZE_BOUND: usize = 4 + 9 + 9 + 1 + 16 + 2 + 4 + 4 + 1 + 32; // frame type (4) + worst case IPv6 + peer ID
}

impl FrameStruct for RemoveAddress {
    const SIZE_BOUND: usize = 4 + 9; // frame type (4) + sequence
}

/// Calculate priority for an address
fn calculate_priority(addr: &SocketAddr) -> u32 {
    // ICE-like priority calculation
    let type_pref = match addr {
        SocketAddr::V4(v4) => {
            let ip = v4.ip();
            if ip.is_loopback() {
                0
            } else if ip.is_private() {
                100
            } else {
                126 // Server reflexive
            }
        }
        SocketAddr::V6(v6) => {
            let ip = v6.ip();
            if ip.is_loopback() {
                0
            } else if ip.is_unicast_link_local() {
                90
            } else {
                120
            }
        }
    };

    let local_pref = match addr {
        SocketAddr::V4(_) => 65535,
        SocketAddr::V6(_) => 65534,
    };

    ((type_pref as u32) << 24) + ((local_pref as u32) << 8) + 255
}

/// Unified REMOVE_ADDRESS frame
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoveAddress {
    /// Sequence number of the address to remove
    pub sequence: VarInt,
}

impl RemoveAddress {
    /// Create a new RemoveAddress frame
    pub fn new(sequence: VarInt) -> Self {
        Self { sequence }
    }

    /// Encode (same format for RFC and legacy)
    pub fn encode<W: BufMut>(&self, buf: &mut W) {
        buf.write_var(FrameType::REMOVE_ADDRESS.0);
        buf.write(self.sequence);
    }

    /// Decode
    pub fn decode<R: Buf>(r: &mut R) -> Result<Self, UnexpectedEnd> {
        let sequence = r.get()?;
        Ok(Self { sequence })
    }
}

/// Configuration for NAT traversal frame handling
#[derive(Debug, Clone)]
pub struct NatTraversalFrameConfig {
    /// Whether to send RFC-compliant frames
    pub use_rfc_format: bool,
    /// Whether to accept legacy format frames
    pub accept_legacy: bool,
}

impl Default for NatTraversalFrameConfig {
    fn default() -> Self {
        Self {
            use_rfc_format: true, // Default to RFC-compliant format
            accept_legacy: true,  // Still accept legacy for compatibility
        }
    }
}

impl NatTraversalFrameConfig {
    /// Create config based on transport parameters negotiation
    pub fn from_transport_params(local: &TransportParameters, peer: &TransportParameters) -> Self {
        Self {
            // Use RFC format only if both endpoints support it
            use_rfc_format: local.supports_rfc_nat_traversal() && peer.supports_rfc_nat_traversal(),
            // Always accept legacy for backward compatibility
            accept_legacy: true,
        }
    }

    /// Create RFC-only config for testing
    pub fn rfc_only() -> Self {
        Self {
            use_rfc_format: true,
            accept_legacy: false,
        }
    }
}

/// Helper to determine if peer supports RFC NAT traversal
pub fn peer_supports_rfc_nat(transport_params: &[u8]) -> bool {
    // Look for TRANSPORT_PARAM_RFC_NAT_TRAVERSAL in transport parameters
    // This is a simplified check - real implementation would parse properly
    transport_params.windows(8).any(|window| {
        let param = u64::from_be_bytes(window.try_into().unwrap_or_default());
        param == TRANSPORT_PARAM_RFC_NAT_TRAVERSAL
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_add_address_rfc_encoding() {
        let frame = AddAddress::new(VarInt::from_u32(42), "192.168.1.100:8080".parse().unwrap());

        let mut buf = BytesMut::new();
        frame.encode_rfc(&mut buf);

        // Verify frame type
        assert_eq!(buf[0..4], [0x80, 0x3d, 0x7e, 0x90]);

        // Skip frame type and verify content
        buf.advance(4);
        let decoded = AddAddress::decode_rfc(&mut buf, false).unwrap();

        assert_eq!(decoded.sequence, frame.sequence);
        assert_eq!(decoded.address, frame.address);
    }

    #[test]
    fn test_add_address_legacy_compatibility() {
        let frame = AddAddress {
            sequence: VarInt::from_u32(100),
            address: "10.0.0.1:1234".parse().unwrap(),
            priority: VarInt::from_u32(12345),
        };

        let mut buf = BytesMut::new();
        frame.encode_legacy(&mut buf);

        // Skip frame type
        buf.advance(4);
        let decoded = AddAddress::decode_legacy(&mut buf).unwrap();

        assert_eq!(decoded.sequence, frame.sequence);
        assert_eq!(decoded.address, frame.address);
        assert_eq!(decoded.priority, frame.priority);
    }

    #[test]
    fn test_punch_me_now_rfc_encoding() {
        let frame = PunchMeNow::new(
            VarInt::from_u32(1),
            VarInt::from_u32(42),
            "192.168.1.100:8080".parse().unwrap(),
        );

        let mut buf = BytesMut::new();
        frame.encode_rfc(&mut buf);

        // Verify frame type
        assert_eq!(buf[0..4], [0x80, 0x3d, 0x7e, 0x92]);

        // Skip frame type and verify content
        buf.advance(4);
        let decoded = PunchMeNow::decode_rfc(&mut buf, false).unwrap();

        assert_eq!(decoded.round, frame.round);
        assert_eq!(
            decoded.paired_with_sequence_number,
            frame.paired_with_sequence_number
        );
        assert_eq!(decoded.address, frame.address);
    }

    #[test]
    fn test_punch_me_now_legacy_compatibility() {
        let frame = PunchMeNow {
            round: VarInt::from_u32(5),
            paired_with_sequence_number: VarInt::from_u32(100),
            address: "10.0.0.1:1234".parse().unwrap(),
            target_peer_id: Some([0xAB; 32]),
        };

        let mut buf = BytesMut::new();
        frame.encode_legacy(&mut buf);

        // Skip frame type
        buf.advance(4);
        let decoded = PunchMeNow::decode_legacy(&mut buf).unwrap();

        assert_eq!(decoded.round, frame.round);
        assert_eq!(
            decoded.paired_with_sequence_number,
            frame.paired_with_sequence_number
        );
        assert_eq!(decoded.address, frame.address);
        assert_eq!(decoded.target_peer_id, frame.target_peer_id);
    }

    #[test]
    fn test_remove_address_encoding() {
        let frame = RemoveAddress::new(VarInt::from_u32(42));

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        // Skip frame type
        buf.advance(4);
        let decoded = RemoveAddress::decode(&mut buf).unwrap();

        assert_eq!(decoded.sequence, frame.sequence);
    }
}
