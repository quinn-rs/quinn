//! Compatibility layer for migrating between old and RFC-compliant NAT traversal frames
//!
//! This module provides conversion functions and compatibility wrappers to enable
//! smooth migration from the current implementation to RFC-compliant frames.

use super::rfc_nat_traversal::{RfcAddAddress, RfcPunchMeNow, RfcRemoveAddress};
use crate::{
    VarInt,
    frame::{AddAddress, PunchMeNow, RemoveAddress},
};
use std::net::SocketAddr;

/// Configuration for NAT traversal compatibility mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NatCompatMode {
    /// Use only the old frame format (current implementation)
    Legacy,
    /// Use only RFC-compliant frames
    RfcCompliant,
    /// Support both formats (for migration period)
    #[default]
    Mixed,
}

/// Convert from old AddAddress to RFC-compliant format
pub fn add_address_to_rfc(old: &AddAddress) -> RfcAddAddress {
    RfcAddAddress {
        sequence_number: old.sequence,
        address: old.address,
        // Note: priority field is dropped as it's not in the RFC
    }
}

/// Convert from RFC-compliant AddAddress to old format
/// The priority field will be set to a default value
pub fn rfc_to_add_address(rfc: &RfcAddAddress, default_priority: VarInt) -> AddAddress {
    AddAddress {
        sequence: rfc.sequence_number,
        address: rfc.address,
        priority: default_priority,
    }
}

/// Convert from old PunchMeNow to RFC-compliant format
pub fn punch_me_now_to_rfc(old: &PunchMeNow) -> RfcPunchMeNow {
    RfcPunchMeNow {
        round: old.round,
        paired_with_sequence_number: old.paired_with_sequence_number,
        address: old.address,
        // Note: target_peer_id is dropped as it's not in the RFC
    }
}

/// Convert from RFC-compliant PunchMeNow to old format
/// The address will be set to the provided address, and target_peer_id will be None
pub fn rfc_to_punch_me_now(rfc: &RfcPunchMeNow) -> PunchMeNow {
    PunchMeNow {
        round: rfc.round,
        paired_with_sequence_number: rfc.paired_with_sequence_number,
        address: rfc.address,
        target_peer_id: None,
    }
}

/// Convert between RemoveAddress formats (they're the same)
pub fn remove_address_to_rfc(old: &RemoveAddress) -> RfcRemoveAddress {
    RfcRemoveAddress {
        sequence_number: old.sequence,
    }
}

/// Convert from RFC RemoveAddress to old format
pub fn rfc_to_remove_address(rfc: &RfcRemoveAddress) -> RemoveAddress {
    RemoveAddress {
        sequence: rfc.sequence_number,
    }
}

/// Helper trait for determining compatibility requirements
pub trait NatFrameCompat {
    /// Check if this frame requires special handling for compatibility
    fn needs_compat(&self) -> bool;

    /// Get the compatibility mode for this frame
    fn compat_mode(&self) -> NatCompatMode;
}

/// Migration helper to determine frame format from wire data
pub fn detect_frame_format(frame_type: u64) -> FrameFormat {
    match frame_type {
        // RFC frame types
        0x3d7e90..=0x3d7e94 => FrameFormat::Rfc,
        // Old frame types (if different) - this would need actual values
        _ => FrameFormat::Legacy,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameFormat {
    Legacy,
    Rfc,
}

/// Priority assignment strategy for migration
#[derive(Debug, Clone, Copy)]
pub struct PriorityStrategy {
    /// Default priority for addresses without explicit priority
    pub default_priority: VarInt,
    /// Whether to use ICE-style priority calculation
    pub use_ice_priority: bool,
}

impl Default for PriorityStrategy {
    fn default() -> Self {
        Self {
            default_priority: VarInt::from_u32(65535), // Medium priority
            use_ice_priority: false,
        }
    }
}

impl PriorityStrategy {
    /// Calculate priority for an address (for migration from RFC to old format)
    pub fn calculate_priority(&self, address: &SocketAddr) -> VarInt {
        if !self.use_ice_priority {
            return self.default_priority;
        }

        // Simple priority calculation based on address type
        let priority = match address {
            SocketAddr::V4(addr) => {
                if addr.ip().is_loopback() {
                    65535 // Lowest priority for loopback
                } else if addr.ip().is_private() {
                    98304 // Medium priority for private addresses
                } else {
                    131071 // Highest priority for public addresses
                }
            }
            SocketAddr::V6(addr) => {
                if addr.ip().is_loopback() {
                    32768 // Lower than IPv4 loopback
                } else if addr.ip().is_unicast_link_local() {
                    49152 // Link-local
                } else {
                    114688 // Slightly lower than public IPv4
                }
            }
        };

        VarInt::from_u32(priority)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_address_conversion() {
        let old = AddAddress {
            sequence: VarInt::from_u32(42),
            address: "192.168.1.1:8080".parse().unwrap(),
            priority: VarInt::from_u32(12345),
        };

        let rfc = add_address_to_rfc(&old);
        assert_eq!(rfc.sequence_number, old.sequence);
        assert_eq!(rfc.address, old.address);

        let converted_back = rfc_to_add_address(&rfc, VarInt::from_u32(99999));
        assert_eq!(converted_back.sequence, old.sequence);
        assert_eq!(converted_back.address, old.address);
        assert_eq!(converted_back.priority, VarInt::from_u32(99999)); // Default priority
    }

    #[test]
    fn test_priority_strategy() {
        let strategy = PriorityStrategy {
            use_ice_priority: true,
            ..Default::default()
        };

        let public_v4 = "8.8.8.8:53".parse().unwrap();
        let private_v4 = "192.168.1.1:80".parse().unwrap();
        let loopback_v4 = "127.0.0.1:8080".parse().unwrap();

        let pub_priority = strategy.calculate_priority(&public_v4);
        let priv_priority = strategy.calculate_priority(&private_v4);
        let loop_priority = strategy.calculate_priority(&loopback_v4);

        // Public should have highest priority
        assert!(pub_priority.into_inner() > priv_priority.into_inner());
        assert!(priv_priority.into_inner() > loop_priority.into_inner());
    }
}
