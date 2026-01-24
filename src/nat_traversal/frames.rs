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
//!
//! # Multi-Transport Extension
//!
//! The ADD_ADDRESS frame has been extended to support multiple transport types beyond
//! UDP/IP. The wire format includes a transport type indicator that allows peers to
//! advertise addresses on different transports (BLE, LoRa, etc.).
//!
//! # Capability Flags
//!
//! The ADD_ADDRESS frame can optionally include capability flags that summarize the
//! transport's characteristics. This allows peers to make informed routing decisions
//! without a full capability exchange.
//!
//! ```text
//! CapabilityFlags (u16 bitfield):
//!   Bit 0: supports_full_quic - Can run full QUIC protocol
//!   Bit 1: half_duplex - Link can only send OR receive at once
//!   Bit 2: broadcast - Supports broadcast/multicast
//!   Bit 3: metered - Connection has per-byte cost
//!   Bit 4: power_constrained - Battery-operated device
//!   Bit 5: link_layer_acks - Transport provides acknowledgements
//!   Bits 6-7: mtu_tier - MTU classification (0=<500, 1=500-1200, 2=1200-4096, 3=>4096)
//!   Bits 8-9: bandwidth_tier - Bandwidth classification (0=VeryLow, 1=Low, 2=Medium, 3=High)
//!   Bits 10-11: latency_tier - RTT classification (0=>2s, 1=500ms-2s, 2=100ms-500ms, 3=<100ms)
//!   Bits 12-15: Reserved for future use
//! ```

use bytes::{Buf, BufMut};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::coding::{self, Codec};
use crate::transport::{TransportAddr, TransportCapabilities, TransportType};
use crate::varint::VarInt;

/// Compact capability flags for wire transmission in ADD_ADDRESS frames
///
/// This is a compact 16-bit representation of transport capabilities suitable
/// for wire transmission. It summarizes the most important routing-relevant
/// characteristics without the full detail of [`TransportCapabilities`].
///
/// # Wire Format
///
/// ```text
/// Bit 0: supports_full_quic
/// Bit 1: half_duplex
/// Bit 2: broadcast
/// Bit 3: metered
/// Bit 4: power_constrained
/// Bit 5: link_layer_acks
/// Bits 6-7: mtu_tier (0=<500, 1=500-1200, 2=1200-4096, 3=>4096)
/// Bits 8-9: bandwidth_tier (0=VeryLow, 1=Low, 2=Medium, 3=High)
/// Bits 10-11: latency_tier (0=>2s, 1=500ms-2s, 2=100ms-500ms, 3=<100ms)
/// Bits 12-15: Reserved
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CapabilityFlags(u16);

impl CapabilityFlags {
    /// Bit positions for capability flags
    const SUPPORTS_FULL_QUIC: u16 = 1 << 0;
    const HALF_DUPLEX: u16 = 1 << 1;
    const BROADCAST: u16 = 1 << 2;
    const METERED: u16 = 1 << 3;
    const POWER_CONSTRAINED: u16 = 1 << 4;
    const LINK_LAYER_ACKS: u16 = 1 << 5;
    const MTU_TIER_SHIFT: u16 = 6;
    const MTU_TIER_MASK: u16 = 0b11 << 6;
    const BANDWIDTH_TIER_SHIFT: u16 = 8;
    const BANDWIDTH_TIER_MASK: u16 = 0b11 << 8;
    const LATENCY_TIER_SHIFT: u16 = 10;
    const LATENCY_TIER_MASK: u16 = 0b11 << 10;

    /// Create empty capability flags (all false, tier 0)
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Create capability flags from raw u16 value
    pub const fn from_raw(raw: u16) -> Self {
        Self(raw)
    }

    /// Get the raw u16 value
    pub const fn to_raw(self) -> u16 {
        self.0
    }

    /// Create capability flags from full TransportCapabilities
    pub fn from_capabilities(caps: &TransportCapabilities) -> Self {
        let mut flags = 0u16;

        if caps.supports_full_quic() {
            flags |= Self::SUPPORTS_FULL_QUIC;
        }
        if caps.half_duplex {
            flags |= Self::HALF_DUPLEX;
        }
        if caps.broadcast {
            flags |= Self::BROADCAST;
        }
        if caps.metered {
            flags |= Self::METERED;
        }
        if caps.power_constrained {
            flags |= Self::POWER_CONSTRAINED;
        }
        if caps.link_layer_acks {
            flags |= Self::LINK_LAYER_ACKS;
        }

        // MTU tier: 0=<500, 1=500-1200, 2=1200-4096, 3=>4096
        let mtu_tier = match caps.mtu {
            0..=499 => 0,
            500..=1199 => 1,
            1200..=4095 => 2,
            _ => 3,
        };
        flags |= (mtu_tier as u16) << Self::MTU_TIER_SHIFT;

        // Bandwidth tier: matches BandwidthClass
        let bandwidth_tier = match caps.bandwidth_class() {
            crate::transport::BandwidthClass::VeryLow => 0,
            crate::transport::BandwidthClass::Low => 1,
            crate::transport::BandwidthClass::Medium => 2,
            crate::transport::BandwidthClass::High => 3,
        };
        flags |= (bandwidth_tier as u16) << Self::BANDWIDTH_TIER_SHIFT;

        // Latency tier: 0=>2s, 1=500ms-2s, 2=100ms-500ms, 3=<100ms
        let latency_tier = if caps.typical_rtt >= Duration::from_secs(2) {
            0
        } else if caps.typical_rtt >= Duration::from_millis(500) {
            1
        } else if caps.typical_rtt >= Duration::from_millis(100) {
            2
        } else {
            3
        };
        flags |= (latency_tier as u16) << Self::LATENCY_TIER_SHIFT;

        Self(flags)
    }

    /// Check if this transport supports full QUIC protocol
    pub const fn supports_full_quic(self) -> bool {
        (self.0 & Self::SUPPORTS_FULL_QUIC) != 0
    }

    /// Check if this is a half-duplex link
    pub const fn half_duplex(self) -> bool {
        (self.0 & Self::HALF_DUPLEX) != 0
    }

    /// Check if this transport supports broadcast
    pub const fn broadcast(self) -> bool {
        (self.0 & Self::BROADCAST) != 0
    }

    /// Check if this is a metered connection
    pub const fn metered(self) -> bool {
        (self.0 & Self::METERED) != 0
    }

    /// Check if this is a power-constrained device
    pub const fn power_constrained(self) -> bool {
        (self.0 & Self::POWER_CONSTRAINED) != 0
    }

    /// Check if link layer provides acknowledgements
    pub const fn link_layer_acks(self) -> bool {
        (self.0 & Self::LINK_LAYER_ACKS) != 0
    }

    /// Get MTU tier (0-3)
    pub const fn mtu_tier(self) -> u8 {
        ((self.0 & Self::MTU_TIER_MASK) >> Self::MTU_TIER_SHIFT) as u8
    }

    /// Get bandwidth tier (0-3, maps to BandwidthClass)
    pub const fn bandwidth_tier(self) -> u8 {
        ((self.0 & Self::BANDWIDTH_TIER_MASK) >> Self::BANDWIDTH_TIER_SHIFT) as u8
    }

    /// Get latency tier (0-3, 3 being fastest)
    pub const fn latency_tier(self) -> u8 {
        ((self.0 & Self::LATENCY_TIER_MASK) >> Self::LATENCY_TIER_SHIFT) as u8
    }

    /// Get approximate MTU range for this tier
    pub fn mtu_range(self) -> (usize, usize) {
        match self.mtu_tier() {
            0 => (0, 499),
            1 => (500, 1199),
            2 => (1200, 4095),
            _ => (4096, 65535),
        }
    }

    /// Get approximate RTT range for this tier
    pub fn latency_range(self) -> (Duration, Duration) {
        match self.latency_tier() {
            0 => (Duration::from_secs(2), Duration::from_secs(60)),
            1 => (Duration::from_millis(500), Duration::from_secs(2)),
            2 => (Duration::from_millis(100), Duration::from_millis(500)),
            _ => (Duration::ZERO, Duration::from_millis(100)),
        }
    }

    /// Builder-style method to set supports_full_quic flag
    pub const fn with_supports_full_quic(mut self, value: bool) -> Self {
        if value {
            self.0 |= Self::SUPPORTS_FULL_QUIC;
        } else {
            self.0 &= !Self::SUPPORTS_FULL_QUIC;
        }
        self
    }

    /// Builder-style method to set half_duplex flag
    pub const fn with_half_duplex(mut self, value: bool) -> Self {
        if value {
            self.0 |= Self::HALF_DUPLEX;
        } else {
            self.0 &= !Self::HALF_DUPLEX;
        }
        self
    }

    /// Builder-style method to set broadcast flag
    pub const fn with_broadcast(mut self, value: bool) -> Self {
        if value {
            self.0 |= Self::BROADCAST;
        } else {
            self.0 &= !Self::BROADCAST;
        }
        self
    }

    /// Builder-style method to set metered flag
    pub const fn with_metered(mut self, value: bool) -> Self {
        if value {
            self.0 |= Self::METERED;
        } else {
            self.0 &= !Self::METERED;
        }
        self
    }

    /// Builder-style method to set power_constrained flag
    pub const fn with_power_constrained(mut self, value: bool) -> Self {
        if value {
            self.0 |= Self::POWER_CONSTRAINED;
        } else {
            self.0 &= !Self::POWER_CONSTRAINED;
        }
        self
    }

    /// Builder-style method to set link_layer_acks flag
    pub const fn with_link_layer_acks(mut self, value: bool) -> Self {
        if value {
            self.0 |= Self::LINK_LAYER_ACKS;
        } else {
            self.0 &= !Self::LINK_LAYER_ACKS;
        }
        self
    }

    /// Builder-style method to set MTU tier (clamped to 0-3)
    pub const fn with_mtu_tier(mut self, tier: u8) -> Self {
        let tier = if tier > 3 { 3 } else { tier };
        self.0 = (self.0 & !Self::MTU_TIER_MASK) | ((tier as u16) << Self::MTU_TIER_SHIFT);
        self
    }

    /// Builder-style method to set bandwidth tier (clamped to 0-3)
    pub const fn with_bandwidth_tier(mut self, tier: u8) -> Self {
        let tier = if tier > 3 { 3 } else { tier };
        self.0 =
            (self.0 & !Self::BANDWIDTH_TIER_MASK) | ((tier as u16) << Self::BANDWIDTH_TIER_SHIFT);
        self
    }

    /// Builder-style method to set latency tier (clamped to 0-3)
    pub const fn with_latency_tier(mut self, tier: u8) -> Self {
        let tier = if tier > 3 { 3 } else { tier };
        self.0 = (self.0 & !Self::LATENCY_TIER_MASK) | ((tier as u16) << Self::LATENCY_TIER_SHIFT);
        self
    }

    /// Create flags for typical UDP/IP broadband connection
    pub const fn broadband() -> Self {
        Self::empty()
            .with_supports_full_quic(true)
            .with_broadcast(true)
            .with_mtu_tier(2) // 1200-4096
            .with_bandwidth_tier(3) // High
            .with_latency_tier(3) // <100ms
    }

    /// Create flags for typical BLE connection
    pub const fn ble() -> Self {
        Self::empty()
            .with_broadcast(true)
            .with_power_constrained(true)
            .with_link_layer_acks(true)
            .with_mtu_tier(0) // <500
            .with_bandwidth_tier(2) // Medium
            .with_latency_tier(2) // 100-500ms
    }

    /// Create flags for typical LoRa long-range connection
    pub const fn lora_long_range() -> Self {
        Self::empty()
            .with_half_duplex(true)
            .with_broadcast(true)
            .with_power_constrained(true)
            .with_mtu_tier(0) // <500
            .with_bandwidth_tier(0) // VeryLow
            .with_latency_tier(0) // >2s
    }
}

/// Frame type for ADD_ADDRESS (draft-seemann-quic-nat-traversal-01)
pub const FRAME_TYPE_ADD_ADDRESS: u64 = 0x3d7e90;
/// Frame type for PUNCH_ME_NOW (draft-seemann-quic-nat-traversal-01)
pub const FRAME_TYPE_PUNCH_ME_NOW: u64 = 0x3d7e91;
/// Frame type for REMOVE_ADDRESS (draft-seemann-quic-nat-traversal-01)
pub const FRAME_TYPE_REMOVE_ADDRESS: u64 = 0x3d7e92;

/// ADD_ADDRESS frame for advertising candidate addresses
///
/// As defined in draft-seemann-quic-nat-traversal-01, this frame includes:
/// - Sequence number (VarInt)
/// - Priority (VarInt)
/// - Transport type (VarInt) - extension for multi-transport support
/// - Address (transport-specific format)
/// - Capability flags (VarInt, optional) - extension for capability advertisement
///
/// # Wire Format
///
/// ```text
/// Sequence (VarInt)
/// Priority (VarInt)
/// TransportType (VarInt): 0=UDP, 1=BLE, 2=LoRa, 3=Serial, etc.
/// AddressType (1 byte): depends on transport type
/// Address (variable): transport-specific address bytes
/// Port (2 bytes): for UDP addresses only
/// HasCapabilities (1 byte): 0=no, 1=yes
/// Capabilities (2 bytes): if HasCapabilities==1, CapabilityFlags bitfield
/// ```
///
/// # Backward Compatibility
///
/// When decoding, if transport_type is not present (legacy frames), UDP is assumed.
/// When encoding, transport_type 0 (UDP) uses the legacy format for compatibility.
/// Capability flags are optional and default to None for backward compatibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddAddress {
    /// Sequence number for the address (used for referencing in other frames)
    pub sequence: u64,
    /// Priority of this address candidate (higher values are preferred)
    pub priority: u64,
    /// Transport type for this address (UDP, BLE, LoRa, etc.)
    pub transport_type: TransportType,
    /// The transport address being advertised
    pub address: TransportAddr,
    /// Optional capability flags summarizing transport characteristics
    pub capabilities: Option<CapabilityFlags>,
}

impl AddAddress {
    /// Create a new ADD_ADDRESS frame for a UDP address
    ///
    /// This is the most common case and maintains backward compatibility.
    /// No capability flags are included by default.
    pub fn udp(sequence: u64, priority: u64, socket_addr: SocketAddr) -> Self {
        Self {
            sequence,
            priority,
            transport_type: TransportType::Udp,
            address: TransportAddr::Udp(socket_addr),
            capabilities: None,
        }
    }

    /// Create a new ADD_ADDRESS frame for any transport address
    ///
    /// No capability flags are included by default. Use `with_capabilities()`
    /// to add capability information.
    pub fn new(sequence: u64, priority: u64, address: TransportAddr) -> Self {
        Self {
            sequence,
            priority,
            transport_type: address.transport_type(),
            address,
            capabilities: None,
        }
    }

    /// Create a new ADD_ADDRESS frame with capability flags
    pub fn with_capabilities(
        sequence: u64,
        priority: u64,
        address: TransportAddr,
        capabilities: CapabilityFlags,
    ) -> Self {
        Self {
            sequence,
            priority,
            transport_type: address.transport_type(),
            address,
            capabilities: Some(capabilities),
        }
    }

    /// Create a new ADD_ADDRESS frame from a TransportAddr and TransportCapabilities
    ///
    /// This automatically converts the full capabilities to compact CapabilityFlags.
    pub fn from_capabilities(
        sequence: u64,
        priority: u64,
        address: TransportAddr,
        capabilities: &TransportCapabilities,
    ) -> Self {
        Self {
            sequence,
            priority,
            transport_type: address.transport_type(),
            address,
            capabilities: Some(CapabilityFlags::from_capabilities(capabilities)),
        }
    }

    /// Get the socket address if this is a UDP transport
    ///
    /// Returns `None` for non-UDP transports.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.address.as_socket_addr()
    }

    /// Check if this address has capability information
    pub fn has_capabilities(&self) -> bool {
        self.capabilities.is_some()
    }

    /// Get the capability flags if present
    pub fn capability_flags(&self) -> Option<CapabilityFlags> {
        self.capabilities
    }

    /// Check if this transport supports full QUIC (if capability info is available)
    pub fn supports_full_quic(&self) -> Option<bool> {
        self.capabilities.map(|c| c.supports_full_quic())
    }
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

/// Wire format transport type values
const TRANSPORT_TYPE_UDP: u64 = 0;
const TRANSPORT_TYPE_BLE: u64 = 1;
const TRANSPORT_TYPE_LORA: u64 = 2;
const TRANSPORT_TYPE_SERIAL: u64 = 3;
const TRANSPORT_TYPE_AX25: u64 = 4;
const TRANSPORT_TYPE_I2P: u64 = 5;
const TRANSPORT_TYPE_YGGDRASIL: u64 = 6;

impl Codec for AddAddress {
    fn decode<B: Buf>(buf: &mut B) -> coding::Result<Self> {
        if buf.remaining() < 1 {
            return Err(coding::UnexpectedEnd);
        }

        // Decode sequence number (VarInt)
        let sequence = VarInt::decode(buf)?.into_inner();

        // Decode priority (VarInt)
        let priority = VarInt::decode(buf)?.into_inner();

        // Decode transport type (VarInt) - extension field
        // Default to UDP for backward compatibility with legacy frames
        let transport_type_raw = if buf.remaining() > 0 {
            VarInt::decode(buf)?.into_inner()
        } else {
            TRANSPORT_TYPE_UDP
        };

        let transport_type = match transport_type_raw {
            TRANSPORT_TYPE_UDP => TransportType::Udp,
            TRANSPORT_TYPE_BLE => TransportType::Ble,
            TRANSPORT_TYPE_LORA => TransportType::LoRa,
            TRANSPORT_TYPE_SERIAL => TransportType::Serial,
            TRANSPORT_TYPE_AX25 => TransportType::Ax25,
            TRANSPORT_TYPE_I2P => TransportType::I2p,
            TRANSPORT_TYPE_YGGDRASIL => TransportType::Yggdrasil,
            _ => TransportType::Udp, // Unknown types fall back to UDP
        };

        // Decode transport-specific address
        let address = match transport_type {
            TransportType::Udp => {
                // UDP: address type (1 byte) + IP (4 or 16 bytes) + port (2 bytes)
                if buf.remaining() < 1 {
                    return Err(coding::UnexpectedEnd);
                }
                let addr_type = buf.get_u8();
                let ip = match addr_type {
                    4 => {
                        if buf.remaining() < 4 {
                            return Err(coding::UnexpectedEnd);
                        }
                        let mut addr = [0u8; 4];
                        buf.copy_to_slice(&mut addr);
                        IpAddr::from(addr)
                    }
                    6 => {
                        if buf.remaining() < 16 {
                            return Err(coding::UnexpectedEnd);
                        }
                        let mut addr = [0u8; 16];
                        buf.copy_to_slice(&mut addr);
                        IpAddr::from(addr)
                    }
                    _ => return Err(coding::UnexpectedEnd),
                };

                if buf.remaining() < 2 {
                    return Err(coding::UnexpectedEnd);
                }
                let port = buf.get_u16();
                TransportAddr::Udp(SocketAddr::new(ip, port))
            }
            TransportType::Ble => {
                // BLE: device ID (6 bytes) + optional service UUID flag (1 byte) + UUID (16 bytes if present)
                if buf.remaining() < 6 {
                    return Err(coding::UnexpectedEnd);
                }
                let mut device_id = [0u8; 6];
                buf.copy_to_slice(&mut device_id);

                let service_uuid = if buf.remaining() > 0 {
                    let has_uuid = buf.get_u8();
                    if has_uuid == 1 && buf.remaining() >= 16 {
                        let mut uuid = [0u8; 16];
                        buf.copy_to_slice(&mut uuid);
                        Some(uuid)
                    } else {
                        None
                    }
                } else {
                    None
                };

                TransportAddr::Ble {
                    device_id,
                    service_uuid,
                }
            }
            TransportType::LoRa => {
                // LoRa: device address (4 bytes) + SF (1 byte) + BW (2 bytes) + CR (1 byte)
                if buf.remaining() < 8 {
                    return Err(coding::UnexpectedEnd);
                }
                let mut device_addr = [0u8; 4];
                buf.copy_to_slice(&mut device_addr);
                let spreading_factor = buf.get_u8();
                let bandwidth_khz = buf.get_u16();
                let coding_rate = buf.get_u8();

                TransportAddr::LoRa {
                    device_addr,
                    params: crate::transport::LoRaParams {
                        spreading_factor,
                        bandwidth_khz,
                        coding_rate,
                    },
                }
            }
            TransportType::Serial => {
                // Serial: port name length (VarInt) + port name (UTF-8 string)
                let name_len = VarInt::decode(buf)?.into_inner() as usize;
                if buf.remaining() < name_len {
                    return Err(coding::UnexpectedEnd);
                }
                let mut name_bytes = vec![0u8; name_len];
                buf.copy_to_slice(&mut name_bytes);
                let port_name =
                    String::from_utf8(name_bytes).unwrap_or_else(|_| String::from("/dev/null"));
                TransportAddr::Serial { port: port_name }
            }
            TransportType::Ax25 | TransportType::I2p | TransportType::Yggdrasil => {
                // Other transports: fall back to raw bytes storage
                // For now, skip remaining bytes and return a placeholder
                // TODO: Implement proper decoding for these transport types
                TransportAddr::Udp(SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 0))
            }
        };

        // Decode optional capability flags
        let capabilities = if buf.remaining() > 0 {
            let has_caps = buf.get_u8();
            if has_caps == 1 && buf.remaining() >= 2 {
                Some(CapabilityFlags::from_raw(buf.get_u16()))
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            sequence,
            priority,
            transport_type,
            address,
            capabilities,
        })
    }

    fn encode<B: BufMut>(&self, buf: &mut B) {
        // Encode sequence number (VarInt)
        VarInt::from_u64(self.sequence)
            .unwrap_or(VarInt::from_u32(0))
            .encode(buf);

        // Encode priority (VarInt)
        VarInt::from_u64(self.priority)
            .unwrap_or(VarInt::from_u32(0))
            .encode(buf);

        // Encode transport type (VarInt)
        let transport_type_raw = match self.transport_type {
            TransportType::Udp => TRANSPORT_TYPE_UDP,
            TransportType::Ble => TRANSPORT_TYPE_BLE,
            TransportType::LoRa => TRANSPORT_TYPE_LORA,
            TransportType::Serial => TRANSPORT_TYPE_SERIAL,
            TransportType::Ax25 => TRANSPORT_TYPE_AX25,
            TransportType::I2p => TRANSPORT_TYPE_I2P,
            TransportType::Yggdrasil => TRANSPORT_TYPE_YGGDRASIL,
        };
        VarInt::from_u64(transport_type_raw)
            .unwrap_or(VarInt::from_u32(0))
            .encode(buf);

        // Encode transport-specific address
        match &self.address {
            TransportAddr::Udp(socket_addr) => {
                match socket_addr.ip() {
                    IpAddr::V4(ipv4) => {
                        buf.put_u8(4); // IPv4 type
                        buf.put_slice(&ipv4.octets());
                    }
                    IpAddr::V6(ipv6) => {
                        buf.put_u8(6); // IPv6 type
                        buf.put_slice(&ipv6.octets());
                    }
                }
                buf.put_u16(socket_addr.port());
            }
            TransportAddr::Ble {
                device_id,
                service_uuid,
            } => {
                buf.put_slice(device_id);
                match service_uuid {
                    Some(uuid) => {
                        buf.put_u8(1); // Has UUID
                        buf.put_slice(uuid);
                    }
                    None => {
                        buf.put_u8(0); // No UUID
                    }
                }
            }
            TransportAddr::LoRa {
                device_addr,
                params,
            } => {
                buf.put_slice(device_addr);
                buf.put_u8(params.spreading_factor);
                buf.put_u16(params.bandwidth_khz);
                buf.put_u8(params.coding_rate);
            }
            TransportAddr::Serial { port } => {
                let name_bytes = port.as_bytes();
                VarInt::from_u64(name_bytes.len() as u64)
                    .unwrap_or(VarInt::from_u32(0))
                    .encode(buf);
                buf.put_slice(name_bytes);
            }
            TransportAddr::Ax25 { callsign, ssid } => {
                // AX.25: callsign length (VarInt) + callsign (UTF-8) + SSID (1 byte)
                let callsign_bytes = callsign.as_bytes();
                VarInt::from_u64(callsign_bytes.len() as u64)
                    .unwrap_or(VarInt::from_u32(0))
                    .encode(buf);
                buf.put_slice(callsign_bytes);
                buf.put_u8(*ssid);
            }
            TransportAddr::I2p { destination } => {
                // I2P: 387-byte destination
                buf.put_slice(destination.as_ref());
            }
            TransportAddr::Yggdrasil { address } => {
                // Yggdrasil: 16-byte address
                buf.put_slice(address);
            }
            TransportAddr::Broadcast { transport_type: _ } => {
                // Broadcast addresses are not advertised over the wire
                // Encode as empty UDP placeholder
                buf.put_u8(4);
                buf.put_slice(&[0, 0, 0, 0]);
                buf.put_u16(0);
            }
        }

        // Encode optional capability flags
        match &self.capabilities {
            Some(caps) => {
                buf.put_u8(1); // Has capabilities
                buf.put_u16(caps.to_raw());
            }
            None => {
                buf.put_u8(0); // No capabilities
            }
        }
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
            }
            6 => {
                if buf.remaining() < 16 {
                    return Err(coding::UnexpectedEnd);
                }
                let mut addr = [0u8; 16];
                buf.copy_to_slice(&mut addr);
                IpAddr::from(addr)
            }
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
        VarInt::from_u64(self.round)
            .unwrap_or(VarInt::from_u32(0))
            .encode(buf);

        // Encode target sequence (VarInt)
        VarInt::from_u64(self.paired_with_sequence_number)
            .unwrap_or(VarInt::from_u32(0))
            .encode(buf);

        // Encode local address
        match self.address.ip() {
            IpAddr::V4(ipv4) => {
                buf.put_u8(4); // IPv4 type
                buf.put_slice(&ipv4.octets());
            }
            IpAddr::V6(ipv6) => {
                buf.put_u8(6); // IPv6 type
                buf.put_slice(&ipv6.octets());
            }
        }

        // Encode port
        buf.put_u16(self.address.port());

        // Encode target peer ID if present
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
        VarInt::from_u64(self.sequence)
            .unwrap_or(VarInt::from_u32(0))
            .encode(buf);
    }
}

impl AddAddress {
    /// Encode this frame with its type prefix for transmission
    pub fn encode_with_type<B: BufMut>(&self, buf: &mut B) {
        VarInt::from_u64(FRAME_TYPE_ADD_ADDRESS)
            .unwrap_or(VarInt::from_u32(0))
            .encode(buf);
        Codec::encode(self, buf);
    }
}

impl PunchMeNow {
    /// Encode this frame with its type prefix for transmission
    pub fn encode_with_type<B: BufMut>(&self, buf: &mut B) {
        VarInt::from_u64(FRAME_TYPE_PUNCH_ME_NOW)
            .unwrap_or(VarInt::from_u32(0))
            .encode(buf);
        Codec::encode(self, buf);
    }
}

impl RemoveAddress {
    /// Encode this frame with its type prefix for transmission
    pub fn encode_with_type<B: BufMut>(&self, buf: &mut B) {
        VarInt::from_u64(FRAME_TYPE_REMOVE_ADDRESS)
            .unwrap_or(VarInt::from_u32(0))
            .encode(buf);
        Codec::encode(self, buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    fn test_socket_addr_v4() -> SocketAddr {
        "192.168.1.100:9000".parse().expect("valid addr")
    }

    fn test_socket_addr_v6() -> SocketAddr {
        "[::1]:9000".parse().expect("valid addr")
    }

    #[test]
    fn test_add_address_udp_ipv4_roundtrip() {
        let original = AddAddress::udp(42, 100, test_socket_addr_v4());

        // Encode
        let mut buf = BytesMut::new();
        Codec::encode(&original, &mut buf);

        // Decode
        let decoded = AddAddress::decode(&mut buf.freeze()).expect("decode failed");

        assert_eq!(decoded.sequence, 42);
        assert_eq!(decoded.priority, 100);
        assert_eq!(decoded.transport_type, TransportType::Udp);
        assert_eq!(decoded.socket_addr(), Some(test_socket_addr_v4()));
    }

    #[test]
    fn test_add_address_udp_ipv6_roundtrip() {
        let original = AddAddress::udp(1, 50, test_socket_addr_v6());

        let mut buf = BytesMut::new();
        Codec::encode(&original, &mut buf);

        let decoded = AddAddress::decode(&mut buf.freeze()).expect("decode failed");

        assert_eq!(decoded.sequence, 1);
        assert_eq!(decoded.transport_type, TransportType::Udp);
        assert_eq!(decoded.socket_addr(), Some(test_socket_addr_v6()));
    }

    #[test]
    fn test_add_address_ble_roundtrip() {
        let device_id = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];
        let original = AddAddress::new(
            10,
            200,
            TransportAddr::Ble {
                device_id,
                service_uuid: None,
            },
        );

        let mut buf = BytesMut::new();
        Codec::encode(&original, &mut buf);

        let decoded = AddAddress::decode(&mut buf.freeze()).expect("decode failed");

        assert_eq!(decoded.sequence, 10);
        assert_eq!(decoded.priority, 200);
        assert_eq!(decoded.transport_type, TransportType::Ble);

        if let TransportAddr::Ble {
            device_id: decoded_id,
            service_uuid,
        } = decoded.address
        {
            assert_eq!(decoded_id, device_id);
            assert!(service_uuid.is_none());
        } else {
            panic!("Expected BLE address");
        }
    }

    #[test]
    fn test_add_address_ble_with_uuid_roundtrip() {
        let device_id = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let service_uuid = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let original = AddAddress::new(
            5,
            300,
            TransportAddr::Ble {
                device_id,
                service_uuid: Some(service_uuid),
            },
        );

        let mut buf = BytesMut::new();
        Codec::encode(&original, &mut buf);

        let decoded = AddAddress::decode(&mut buf.freeze()).expect("decode failed");

        if let TransportAddr::Ble {
            device_id: decoded_id,
            service_uuid: decoded_uuid,
        } = decoded.address
        {
            assert_eq!(decoded_id, device_id);
            assert_eq!(decoded_uuid, Some(service_uuid));
        } else {
            panic!("Expected BLE address");
        }
    }

    #[test]
    fn test_add_address_lora_roundtrip() {
        let device_addr = [0xDE, 0xAD, 0xBE, 0xEF];
        let params = crate::transport::LoRaParams {
            spreading_factor: 10,
            bandwidth_khz: 250,
            coding_rate: 6,
        };
        let original = AddAddress::new(
            99,
            500,
            TransportAddr::LoRa {
                device_addr,
                params: params.clone(),
            },
        );

        let mut buf = BytesMut::new();
        Codec::encode(&original, &mut buf);

        let decoded = AddAddress::decode(&mut buf.freeze()).expect("decode failed");

        assert_eq!(decoded.sequence, 99);
        assert_eq!(decoded.transport_type, TransportType::LoRa);

        if let TransportAddr::LoRa {
            device_addr: decoded_addr,
            params: decoded_params,
        } = decoded.address
        {
            assert_eq!(decoded_addr, device_addr);
            assert_eq!(decoded_params.spreading_factor, 10);
            assert_eq!(decoded_params.bandwidth_khz, 250);
            assert_eq!(decoded_params.coding_rate, 6);
        } else {
            panic!("Expected LoRa address");
        }
    }

    #[test]
    fn test_add_address_serial_roundtrip() {
        let original = AddAddress::new(
            7,
            50,
            TransportAddr::Serial {
                port: "/dev/ttyUSB0".to_string(),
            },
        );

        let mut buf = BytesMut::new();
        Codec::encode(&original, &mut buf);

        let decoded = AddAddress::decode(&mut buf.freeze()).expect("decode failed");

        assert_eq!(decoded.sequence, 7);
        assert_eq!(decoded.transport_type, TransportType::Serial);

        if let TransportAddr::Serial { port } = decoded.address {
            assert_eq!(port, "/dev/ttyUSB0");
        } else {
            panic!("Expected Serial address");
        }
    }

    #[test]
    fn test_add_address_helper_methods() {
        let socket_addr = test_socket_addr_v4();
        let frame = AddAddress::udp(1, 100, socket_addr);

        assert_eq!(frame.socket_addr(), Some(socket_addr));

        let ble_frame = AddAddress::new(
            2,
            100,
            TransportAddr::Ble {
                device_id: [0; 6],
                service_uuid: None,
            },
        );
        assert_eq!(ble_frame.socket_addr(), None);
    }

    #[test]
    fn test_punch_me_now_roundtrip() {
        let original = PunchMeNow {
            round: 3,
            paired_with_sequence_number: 42,
            address: test_socket_addr_v4(),
            target_peer_id: None,
        };

        let mut buf = BytesMut::new();
        Codec::encode(&original, &mut buf);

        let decoded = PunchMeNow::decode(&mut buf.freeze()).expect("decode failed");

        assert_eq!(decoded.round, 3);
        assert_eq!(decoded.paired_with_sequence_number, 42);
        assert_eq!(decoded.address, test_socket_addr_v4());
        assert!(decoded.target_peer_id.is_none());
    }

    #[test]
    fn test_punch_me_now_with_peer_id_roundtrip() {
        let peer_id = [0x42u8; 32];
        let original = PunchMeNow {
            round: 5,
            paired_with_sequence_number: 10,
            address: test_socket_addr_v6(),
            target_peer_id: Some(peer_id),
        };

        let mut buf = BytesMut::new();
        Codec::encode(&original, &mut buf);

        let decoded = PunchMeNow::decode(&mut buf.freeze()).expect("decode failed");

        assert_eq!(decoded.round, 5);
        assert_eq!(decoded.target_peer_id, Some(peer_id));
    }

    #[test]
    fn test_remove_address_roundtrip() {
        let original = RemoveAddress { sequence: 123 };

        let mut buf = BytesMut::new();
        Codec::encode(&original, &mut buf);

        let decoded = RemoveAddress::decode(&mut buf.freeze()).expect("decode failed");

        assert_eq!(decoded.sequence, 123);
    }

    #[test]
    fn test_transport_type_wire_values() {
        // Verify our wire format constants
        assert_eq!(TRANSPORT_TYPE_UDP, 0);
        assert_eq!(TRANSPORT_TYPE_BLE, 1);
        assert_eq!(TRANSPORT_TYPE_LORA, 2);
        assert_eq!(TRANSPORT_TYPE_SERIAL, 3);
    }

    #[test]
    fn test_frame_types() {
        // Verify frame type constants match the spec
        assert_eq!(FRAME_TYPE_ADD_ADDRESS, 0x3d7e90);
        assert_eq!(FRAME_TYPE_PUNCH_ME_NOW, 0x3d7e91);
        assert_eq!(FRAME_TYPE_REMOVE_ADDRESS, 0x3d7e92);
    }

    // ============ Capability Flags Tests ============

    #[test]
    fn test_capability_flags_empty() {
        let flags = CapabilityFlags::empty();
        assert_eq!(flags.to_raw(), 0);
        assert!(!flags.supports_full_quic());
        assert!(!flags.half_duplex());
        assert!(!flags.broadcast());
        assert!(!flags.metered());
        assert!(!flags.power_constrained());
        assert!(!flags.link_layer_acks());
        assert_eq!(flags.mtu_tier(), 0);
        assert_eq!(flags.bandwidth_tier(), 0);
        assert_eq!(flags.latency_tier(), 0);
    }

    #[test]
    fn test_capability_flags_individual_bits() {
        // Test each flag individually
        let flags = CapabilityFlags::empty().with_supports_full_quic(true);
        assert!(flags.supports_full_quic());
        assert_eq!(flags.to_raw(), 1);

        let flags = CapabilityFlags::empty().with_half_duplex(true);
        assert!(flags.half_duplex());
        assert_eq!(flags.to_raw(), 2);

        let flags = CapabilityFlags::empty().with_broadcast(true);
        assert!(flags.broadcast());
        assert_eq!(flags.to_raw(), 4);

        let flags = CapabilityFlags::empty().with_metered(true);
        assert!(flags.metered());
        assert_eq!(flags.to_raw(), 8);

        let flags = CapabilityFlags::empty().with_power_constrained(true);
        assert!(flags.power_constrained());
        assert_eq!(flags.to_raw(), 16);

        let flags = CapabilityFlags::empty().with_link_layer_acks(true);
        assert!(flags.link_layer_acks());
        assert_eq!(flags.to_raw(), 32);
    }

    #[test]
    fn test_capability_flags_tiers() {
        // MTU tiers: bits 6-7
        let flags = CapabilityFlags::empty().with_mtu_tier(0);
        assert_eq!(flags.mtu_tier(), 0);
        assert_eq!(flags.mtu_range(), (0, 499));

        let flags = CapabilityFlags::empty().with_mtu_tier(1);
        assert_eq!(flags.mtu_tier(), 1);
        assert_eq!(flags.mtu_range(), (500, 1199));

        let flags = CapabilityFlags::empty().with_mtu_tier(2);
        assert_eq!(flags.mtu_tier(), 2);
        assert_eq!(flags.mtu_range(), (1200, 4095));

        let flags = CapabilityFlags::empty().with_mtu_tier(3);
        assert_eq!(flags.mtu_tier(), 3);
        assert_eq!(flags.mtu_range(), (4096, 65535));

        // Bandwidth tiers: bits 8-9
        let flags = CapabilityFlags::empty().with_bandwidth_tier(0);
        assert_eq!(flags.bandwidth_tier(), 0);

        let flags = CapabilityFlags::empty().with_bandwidth_tier(3);
        assert_eq!(flags.bandwidth_tier(), 3);

        // Latency tiers: bits 10-11
        let flags = CapabilityFlags::empty().with_latency_tier(0);
        assert_eq!(flags.latency_tier(), 0);
        assert_eq!(flags.latency_range().0, Duration::from_secs(2));

        let flags = CapabilityFlags::empty().with_latency_tier(3);
        assert_eq!(flags.latency_tier(), 3);
        assert_eq!(flags.latency_range().1, Duration::from_millis(100));
    }

    #[test]
    fn test_capability_flags_tier_clamping() {
        // Tiers should be clamped to 0-3
        let flags = CapabilityFlags::empty().with_mtu_tier(10);
        assert_eq!(flags.mtu_tier(), 3);

        let flags = CapabilityFlags::empty().with_bandwidth_tier(255);
        assert_eq!(flags.bandwidth_tier(), 3);

        let flags = CapabilityFlags::empty().with_latency_tier(100);
        assert_eq!(flags.latency_tier(), 3);
    }

    #[test]
    fn test_capability_flags_presets() {
        // Broadband preset
        let broadband = CapabilityFlags::broadband();
        assert!(broadband.supports_full_quic());
        assert!(broadband.broadcast());
        assert!(!broadband.half_duplex());
        assert!(!broadband.power_constrained());
        assert_eq!(broadband.mtu_tier(), 2);
        assert_eq!(broadband.bandwidth_tier(), 3);
        assert_eq!(broadband.latency_tier(), 3);

        // BLE preset
        let ble = CapabilityFlags::ble();
        assert!(!ble.supports_full_quic());
        assert!(ble.broadcast());
        assert!(ble.power_constrained());
        assert!(ble.link_layer_acks());
        assert_eq!(ble.mtu_tier(), 0);
        assert_eq!(ble.bandwidth_tier(), 2);
        assert_eq!(ble.latency_tier(), 2);

        // LoRa preset
        let lora = CapabilityFlags::lora_long_range();
        assert!(!lora.supports_full_quic());
        assert!(lora.half_duplex());
        assert!(lora.broadcast());
        assert!(lora.power_constrained());
        assert_eq!(lora.mtu_tier(), 0);
        assert_eq!(lora.bandwidth_tier(), 0);
        assert_eq!(lora.latency_tier(), 0);
    }

    #[test]
    fn test_capability_flags_from_transport_capabilities() {
        // Test conversion from full TransportCapabilities
        let caps = TransportCapabilities::broadband();
        let flags = CapabilityFlags::from_capabilities(&caps);

        assert!(flags.supports_full_quic());
        assert!(!flags.half_duplex());
        assert!(flags.broadcast());
        assert!(!flags.metered());
        assert!(!flags.power_constrained());
        assert_eq!(flags.bandwidth_tier(), 3); // High

        // BLE caps
        let caps = TransportCapabilities::ble();
        let flags = CapabilityFlags::from_capabilities(&caps);

        assert!(!flags.supports_full_quic()); // MTU too small
        assert!(flags.power_constrained());
        assert!(flags.link_layer_acks());
        assert_eq!(flags.bandwidth_tier(), 2); // Medium (125kbps)

        // LoRa long range
        let caps = TransportCapabilities::lora_long_range();
        let flags = CapabilityFlags::from_capabilities(&caps);

        assert!(!flags.supports_full_quic());
        assert!(flags.half_duplex());
        assert!(flags.broadcast());
        assert!(flags.power_constrained());
        assert_eq!(flags.bandwidth_tier(), 0); // VeryLow
        assert_eq!(flags.latency_tier(), 0); // >2s RTT
    }

    #[test]
    fn test_capability_flags_roundtrip() {
        // Test encode/decode through raw value
        let original = CapabilityFlags::empty()
            .with_supports_full_quic(true)
            .with_broadcast(true)
            .with_mtu_tier(2)
            .with_bandwidth_tier(3)
            .with_latency_tier(1);

        let raw = original.to_raw();
        let decoded = CapabilityFlags::from_raw(raw);

        assert_eq!(decoded.supports_full_quic(), original.supports_full_quic());
        assert_eq!(decoded.broadcast(), original.broadcast());
        assert_eq!(decoded.mtu_tier(), original.mtu_tier());
        assert_eq!(decoded.bandwidth_tier(), original.bandwidth_tier());
        assert_eq!(decoded.latency_tier(), original.latency_tier());
    }

    #[test]
    fn test_add_address_with_capabilities_roundtrip() {
        let caps = CapabilityFlags::broadband();
        let original =
            AddAddress::with_capabilities(42, 100, TransportAddr::Udp(test_socket_addr_v4()), caps);

        assert!(original.has_capabilities());
        assert_eq!(original.capability_flags(), Some(caps));
        assert_eq!(original.supports_full_quic(), Some(true));

        // Encode and decode
        let mut buf = BytesMut::new();
        Codec::encode(&original, &mut buf);

        let decoded = AddAddress::decode(&mut buf.freeze()).expect("decode failed");

        assert_eq!(decoded.sequence, 42);
        assert_eq!(decoded.priority, 100);
        assert!(decoded.has_capabilities());
        assert_eq!(decoded.capability_flags(), Some(caps));
        assert_eq!(decoded.supports_full_quic(), Some(true));
    }

    #[test]
    fn test_add_address_without_capabilities_roundtrip() {
        let original = AddAddress::udp(1, 50, test_socket_addr_v4());

        assert!(!original.has_capabilities());
        assert_eq!(original.capability_flags(), None);
        assert_eq!(original.supports_full_quic(), None);

        // Encode and decode
        let mut buf = BytesMut::new();
        Codec::encode(&original, &mut buf);

        let decoded = AddAddress::decode(&mut buf.freeze()).expect("decode failed");

        assert!(!decoded.has_capabilities());
        assert_eq!(decoded.capability_flags(), None);
    }

    #[test]
    fn test_add_address_from_transport_capabilities() {
        let caps = TransportCapabilities::ble();
        let original = AddAddress::from_capabilities(
            10,
            200,
            TransportAddr::Ble {
                device_id: [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC],
                service_uuid: None,
            },
            &caps,
        );

        assert!(original.has_capabilities());
        // BLE doesn't support full QUIC (MTU too small)
        assert_eq!(original.supports_full_quic(), Some(false));

        // Encode and decode
        let mut buf = BytesMut::new();
        Codec::encode(&original, &mut buf);

        let decoded = AddAddress::decode(&mut buf.freeze()).expect("decode failed");

        assert!(decoded.has_capabilities());
        let flags = decoded.capability_flags().expect("expected flags");
        assert!(!flags.supports_full_quic());
        assert!(flags.power_constrained());
        assert!(flags.link_layer_acks());
    }

    #[test]
    fn test_add_address_ble_with_capabilities_roundtrip() {
        let caps = CapabilityFlags::ble();
        let device_id = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let original = AddAddress::with_capabilities(
            5,
            300,
            TransportAddr::Ble {
                device_id,
                service_uuid: None,
            },
            caps,
        );

        let mut buf = BytesMut::new();
        Codec::encode(&original, &mut buf);

        let decoded = AddAddress::decode(&mut buf.freeze()).expect("decode failed");

        assert_eq!(decoded.transport_type, TransportType::Ble);
        assert!(decoded.has_capabilities());
        let flags = decoded.capability_flags().expect("expected flags");
        assert!(flags.power_constrained());
        assert_eq!(flags.mtu_tier(), 0);
    }

    #[test]
    fn test_add_address_lora_with_capabilities_roundtrip() {
        let caps = CapabilityFlags::lora_long_range();
        let device_addr = [0xDE, 0xAD, 0xBE, 0xEF];
        let params = crate::transport::LoRaParams {
            spreading_factor: 12,
            bandwidth_khz: 125,
            coding_rate: 5,
        };
        let original = AddAddress::with_capabilities(
            99,
            500,
            TransportAddr::LoRa {
                device_addr,
                params,
            },
            caps,
        );

        let mut buf = BytesMut::new();
        Codec::encode(&original, &mut buf);

        let decoded = AddAddress::decode(&mut buf.freeze()).expect("decode failed");

        assert_eq!(decoded.transport_type, TransportType::LoRa);
        assert!(decoded.has_capabilities());
        let flags = decoded.capability_flags().expect("expected flags");
        assert!(flags.half_duplex());
        assert!(flags.power_constrained());
        assert_eq!(flags.bandwidth_tier(), 0); // VeryLow
        assert_eq!(flags.latency_tier(), 0); // >2s
    }
}
