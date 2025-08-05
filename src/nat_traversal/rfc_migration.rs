//! RFC Migration Strategy for NAT Traversal
//!
//! This module provides a migration path from the current implementation
//! to RFC-compliant frames while maintaining backward compatibility and
//! preserving essential functionality like priority-based candidate selection.

use crate::{
    TransportError, VarInt,
    frame::{Frame, FrameType},
};
use std::net::SocketAddr;

/// Migration configuration for NAT traversal
#[derive(Debug, Clone)]
pub struct NatMigrationConfig {
    /// Whether to accept old format frames
    pub accept_legacy_frames: bool,
    /// Whether to send RFC-compliant frames
    pub send_rfc_frames: bool,
    /// Default priority calculation strategy
    pub priority_strategy: PriorityCalculation,
}

impl Default for NatMigrationConfig {
    fn default() -> Self {
        Self {
            // Start in compatibility mode
            accept_legacy_frames: true,
            send_rfc_frames: false,
            priority_strategy: PriorityCalculation::IceLike,
        }
    }
}

/// Priority calculation strategies
#[derive(Debug, Clone, Copy)]
pub enum PriorityCalculation {
    /// Use ICE-like priority calculation
    IceLike,
    /// Simple priority based on address type
    Simple,
    /// Fixed priority for all addresses
    Fixed(u32),
}

impl NatMigrationConfig {
    /// Create a config for full RFC compliance
    pub fn rfc_compliant() -> Self {
        Self {
            accept_legacy_frames: false,
            send_rfc_frames: true,
            priority_strategy: PriorityCalculation::IceLike,
        }
    }

    /// Create a config for legacy mode
    pub fn legacy_only() -> Self {
        Self {
            accept_legacy_frames: true,
            send_rfc_frames: false,
            priority_strategy: PriorityCalculation::IceLike,
        }
    }
}

/// Calculate priority for an address based on its characteristics
pub fn calculate_address_priority(addr: &SocketAddr, strategy: PriorityCalculation) -> u32 {
    match strategy {
        PriorityCalculation::Fixed(p) => p,
        PriorityCalculation::Simple => simple_priority(addr),
        PriorityCalculation::IceLike => ice_like_priority(addr),
    }
}

/// Simple priority calculation based on address type
fn simple_priority(addr: &SocketAddr) -> u32 {
    match addr {
        SocketAddr::V4(v4) => {
            let ip = v4.ip();
            if ip.is_loopback() {
                100 // Lowest
            } else if ip.is_private() {
                200 // Medium
            } else {
                300 // Highest
            }
        }
        SocketAddr::V6(v6) => {
            let ip = v6.ip();
            if ip.is_loopback() {
                50 // Lower than IPv4 loopback
            } else if ip.is_unicast_link_local() {
                150 // Link-local
            } else {
                250 // Slightly lower than public IPv4
            }
        }
    }
}

/// ICE-like priority calculation (RFC 5245 Section 4.1.2.1)
fn ice_like_priority(addr: &SocketAddr) -> u32 {
    // Priority = (2^24)*(type preference) + (2^8)*(local preference) + (256 - component ID)

    let type_pref = match addr {
        SocketAddr::V4(v4) => {
            let ip = v4.ip();
            if ip.is_loopback() {
                0 // Host candidate (loopback)
            } else if ip.is_private() {
                100 // Host candidate (private)
            } else {
                126 // Server reflexive (public)
            }
        }
        SocketAddr::V6(v6) => {
            let ip = v6.ip();
            if ip.is_loopback() {
                0 // Host candidate (loopback)
            } else if ip.is_unicast_link_local() {
                90 // Host candidate (link-local)
            } else {
                120 // Server reflexive (public IPv6)
            }
        }
    };

    // Local preference based on IP family
    let local_pref = match addr {
        SocketAddr::V4(_) => 65535, // Prefer IPv4 for compatibility
        SocketAddr::V6(_) => 65534, // Slightly lower for IPv6
    };

    // Component ID (we only have one component in QUIC)
    let component_id = 1;

    // Calculate priority
    ((type_pref as u32) << 24) + ((local_pref as u32) << 8) + (256 - component_id)
}

/// Frame conversion wrapper for migration
pub struct FrameMigrator {
    config: NatMigrationConfig,
}

impl FrameMigrator {
    pub fn new(config: NatMigrationConfig) -> Self {
        Self { config }
    }

    /// Check if we should send RFC frames based on configuration
    pub fn should_send_rfc_frames(&self) -> bool {
        self.config.send_rfc_frames
    }

    /// Process incoming frames based on configuration
    pub fn process_incoming_frame(
        &self,
        _frame_type: FrameType,
        frame: Frame,
        _sender_addr: SocketAddr,
    ) -> Result<Frame, TransportError> {
        match frame {
            Frame::AddAddress(mut add) => {
                // If we received an RFC frame (no priority), calculate it
                if add.priority == VarInt::from_u32(0) {
                    add.priority = VarInt::from_u32(calculate_address_priority(
                        &add.address,
                        self.config.priority_strategy,
                    ));
                }
                Ok(Frame::AddAddress(add))
            }
            Frame::PunchMeNow(punch) => {
                // Handle both formats
                Ok(Frame::PunchMeNow(punch))
            }
            _ => Ok(frame),
        }
    }

    /// Check if we should accept this frame type
    pub fn should_accept_frame(&self, frame_type: FrameType) -> bool {
        if self.config.accept_legacy_frames {
            // Accept all NAT traversal frames
            true
        } else {
            // Only accept RFC-compliant frame types
            matches!(
                frame_type,
                FrameType::ADD_ADDRESS_IPV4
                    | FrameType::ADD_ADDRESS_IPV6
                    | FrameType::PUNCH_ME_NOW_IPV4
                    | FrameType::PUNCH_ME_NOW_IPV6
                    | FrameType::REMOVE_ADDRESS
            )
        }
    }
}

/// Helper to determine if a peer supports RFC frames
#[derive(Debug, Clone)]
pub struct PeerCapabilities {
    /// Peer's connection ID
    pub peer_id: Vec<u8>,
    /// Whether peer supports RFC NAT traversal
    pub supports_rfc_nat: bool,
    /// When we learned about this capability
    pub discovered_at: std::time::Instant,
}

/// Tracks peer capabilities for gradual migration
pub struct CapabilityTracker {
    peers: std::collections::HashMap<Vec<u8>, PeerCapabilities>,
}

impl CapabilityTracker {
    pub fn new() -> Self {
        Self {
            peers: std::collections::HashMap::new(),
        }
    }

    /// Record that a peer supports RFC frames
    pub fn mark_rfc_capable(&mut self, peer_id: Vec<u8>) {
        self.peers.insert(
            peer_id.clone(),
            PeerCapabilities {
                peer_id,
                supports_rfc_nat: true,
                discovered_at: std::time::Instant::now(),
            },
        );
    }

    /// Check if a peer supports RFC frames
    pub fn is_rfc_capable(&self, peer_id: &[u8]) -> bool {
        self.peers
            .get(peer_id)
            .map(|cap| cap.supports_rfc_nat)
            .unwrap_or(false)
    }

    /// Clean up old entries
    pub fn cleanup_old_entries(&mut self, max_age: std::time::Duration) {
        let now = std::time::Instant::now();
        self.peers
            .retain(|_, cap| now.duration_since(cap.discovered_at) < max_age);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_calculation() {
        let public_v4: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let private_v4: SocketAddr = "192.168.1.1:80".parse().unwrap();
        let loopback_v4: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        // Test simple strategy
        let simple_pub = calculate_address_priority(&public_v4, PriorityCalculation::Simple);
        let simple_priv = calculate_address_priority(&private_v4, PriorityCalculation::Simple);
        let simple_loop = calculate_address_priority(&loopback_v4, PriorityCalculation::Simple);

        assert!(simple_pub > simple_priv);
        assert!(simple_priv > simple_loop);

        // Test ICE-like strategy
        let ice_pub = calculate_address_priority(&public_v4, PriorityCalculation::IceLike);
        let ice_priv = calculate_address_priority(&private_v4, PriorityCalculation::IceLike);
        let ice_loop = calculate_address_priority(&loopback_v4, PriorityCalculation::IceLike);

        assert!(ice_pub > ice_priv);
        assert!(ice_priv > ice_loop);

        // Test fixed strategy
        let fixed = calculate_address_priority(&public_v4, PriorityCalculation::Fixed(12345));
        assert_eq!(fixed, 12345);
    }

    #[test]
    fn test_migration_configs() {
        let default_config = NatMigrationConfig::default();
        assert!(default_config.accept_legacy_frames);
        assert!(!default_config.send_rfc_frames);

        let rfc_config = NatMigrationConfig::rfc_compliant();
        assert!(!rfc_config.accept_legacy_frames);
        assert!(rfc_config.send_rfc_frames);

        let legacy_config = NatMigrationConfig::legacy_only();
        assert!(legacy_config.accept_legacy_frames);
        assert!(!legacy_config.send_rfc_frames);
    }

    #[test]
    fn test_capability_tracker() {
        let mut tracker = CapabilityTracker::new();
        let peer_id = vec![1, 2, 3, 4];

        assert!(!tracker.is_rfc_capable(&peer_id));

        tracker.mark_rfc_capable(peer_id.clone());
        assert!(tracker.is_rfc_capable(&peer_id));

        // Test cleanup
        tracker.cleanup_old_entries(std::time::Duration::from_secs(3600));
        assert!(tracker.is_rfc_capable(&peer_id)); // Should still be there
    }
}
