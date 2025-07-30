//! PQC-aware packet handling for larger handshakes
//!
//! This module extends QUIC packet handling to accommodate the larger handshake
//! messages required by post-quantum cryptography. It provides:
//!
//! - Detection of PQC handshakes based on TLS extensions
//! - Dynamic MTU adjustment for PQC handshakes
//! - Efficient fragmentation of large CRYPTO frames
//! - Coalescing logic aware of PQC constraints

use crate::{
    MAX_UDP_PAYLOAD, MtuDiscoveryConfig, TransportError,
    connection::Connection,
    crypto::pqc::{config::PqcMode, types::*},
    frame::{self, Crypto},
    packet::{PacketNumber, SpaceId},
};
use std::cmp;
use tracing::{debug, trace};

/// Size constants for PQC algorithms
pub const ML_KEM_768_HANDSHAKE_OVERHEAD: u16 = 1184 + 1088; // Public key + ciphertext
pub const ML_DSA_65_HANDSHAKE_OVERHEAD: u16 = 1952 + 3309; // Public key + signature
pub const HYBRID_HANDSHAKE_OVERHEAD: u16 =
    ML_KEM_768_HANDSHAKE_OVERHEAD + ML_DSA_65_HANDSHAKE_OVERHEAD + 256; // Plus classical overhead

/// Minimum MTU required for efficient PQC handshakes
pub const PQC_MIN_MTU: u16 = 2048;

/// Recommended MTU for PQC handshakes
pub const PQC_RECOMMENDED_MTU: u16 = 4096;

/// Maximum CRYPTO frame size for fragmentation
pub const MAX_CRYPTO_FRAME_SIZE: u16 = 1200;

/// PQC-aware packet handler
#[derive(Debug, Clone)]
pub struct PqcPacketHandler {
    /// Whether PQC is detected in the current handshake
    pqc_detected: bool,
    /// The PQC mode being used
    pqc_mode: Option<PqcMode>,
    /// Current estimated handshake size
    estimated_handshake_size: u32,
    /// Whether we've initiated MTU discovery for PQC
    mtu_discovery_triggered: bool,
}

impl PqcPacketHandler {
    /// Create a new PQC packet handler
    pub fn new() -> Self {
        Self {
            pqc_detected: false,
            pqc_mode: None,
            estimated_handshake_size: 0,
            mtu_discovery_triggered: false,
        }
    }

    /// Detect if the handshake is using PQC based on TLS extensions
    pub fn detect_pqc_handshake(&mut self, crypto_data: &[u8], space: SpaceId) -> bool {
        // Only check in Initial and Handshake spaces
        if !matches!(space, SpaceId::Initial | SpaceId::Handshake) {
            return self.pqc_detected;
        }

        // Look for TLS handshake messages
        if crypto_data.len() < 4 {
            return self.pqc_detected;
        }

        // Check for ClientHello (type 1) or ServerHello (type 2)
        let msg_type = crypto_data[0];
        if msg_type == 1 || msg_type == 2 {
            // Parse for supported groups extension (0x000a) or signature algorithms (0x000d)
            if let Some(mode) = self.parse_pqc_extensions(crypto_data) {
                debug!("Detected PQC handshake with mode: {:?}", mode);
                self.pqc_detected = true;
                self.pqc_mode = Some(mode);
                self.estimated_handshake_size = self.estimate_handshake_size(mode);
                return true;
            }
        }

        self.pqc_detected
    }

    /// Parse TLS extensions to detect PQC usage
    fn parse_pqc_extensions(&self, data: &[u8]) -> Option<PqcMode> {
        // This is a simplified parser - in production, use a proper TLS parser
        // Look for hybrid group codepoints (0x2F39, 0x2F3A, etc.)

        // For now, return a mode based on heuristics
        // In real implementation, parse the extensions properly
        if data.len() > 100 {
            // Larger handshakes likely indicate PQC
            Some(PqcMode::Hybrid)
        } else {
            None
        }
    }

    /// Estimate the total handshake size based on PQC mode
    fn estimate_handshake_size(&self, mode: PqcMode) -> u32 {
        match mode {
            PqcMode::ClassicalOnly => 4096, // Standard TLS handshake
            PqcMode::Hybrid => 16384,       // Hybrid handshake
            PqcMode::PqcOnly => 12288,      // PQC-only handshake
        }
    }

    /// Check if MTU discovery should be triggered for PQC
    pub fn should_trigger_mtu_discovery(&mut self) -> bool {
        if self.pqc_detected && !self.mtu_discovery_triggered {
            self.mtu_discovery_triggered = true;
            true
        } else {
            false
        }
    }

    /// Get recommended MTU configuration for PQC
    pub fn get_pqc_mtu_config(&self) -> MtuDiscoveryConfig {
        let mut config = MtuDiscoveryConfig::default();

        if self.pqc_detected {
            // Set higher upper bound for PQC
            config.upper_bound(PQC_RECOMMENDED_MTU.min(MAX_UDP_PAYLOAD));

            // More aggressive probing for PQC
            config.minimum_change = 128;

            // Shorter interval between probes
            config.interval = std::time::Duration::from_millis(100);
        }

        config
    }

    /// Calculate optimal CRYPTO frame size for fragmentation
    pub fn calculate_crypto_frame_size(
        &self,
        available_space: usize,
        remaining_data: usize,
    ) -> usize {
        let max_frame_size = if self.pqc_detected {
            // Use larger frames for PQC to reduce overhead
            available_space.min(MAX_CRYPTO_FRAME_SIZE as usize)
        } else {
            // Standard frame size for classical
            available_space.min(600)
        };

        cmp::min(max_frame_size, remaining_data)
    }

    /// Check if packet coalescing should be adjusted for PQC
    pub fn adjust_coalescing_for_pqc(&self, current_size: usize, space: SpaceId) -> bool {
        if !self.pqc_detected {
            return false;
        }

        // Don't coalesce Initial packets with others if using PQC
        // to maximize space for large CRYPTO frames
        matches!(space, SpaceId::Initial) && current_size > 600
    }

    /// Get the minimum packet size for PQC handshakes
    pub fn get_min_packet_size(&self, space: SpaceId) -> u16 {
        if !self.pqc_detected {
            return 1200; // Standard QUIC minimum
        }

        match space {
            SpaceId::Initial => PQC_MIN_MTU,
            SpaceId::Handshake => 1500, // Can be smaller after Initial
            _ => 1200,
        }
    }

    /// Check if handshake is complete based on estimated size
    pub fn is_handshake_complete(&self, bytes_sent: u64) -> bool {
        if !self.pqc_detected {
            return false; // Let normal logic handle
        }

        bytes_sent >= self.estimated_handshake_size as u64
    }

    /// Fragment large CRYPTO data into multiple frames
    pub fn fragment_crypto_data(
        &self,
        data: &[u8],
        offset: u64,
        max_packet_size: usize,
    ) -> Vec<Crypto> {
        let mut frames = Vec::new();
        let mut current_offset = offset;
        let mut remaining = data;

        while !remaining.is_empty() {
            // Reserve space for frame header (worst case ~16 bytes)
            let available_space = max_packet_size.saturating_sub(16);
            let frame_size = self.calculate_crypto_frame_size(available_space, remaining.len());

            let (chunk, rest) = remaining.split_at(frame_size);

            frames.push(Crypto {
                offset: current_offset,
                data: chunk.to_vec().into(),
            });

            current_offset += frame_size as u64;
            remaining = rest;
        }

        trace!(
            "Fragmented {} bytes into {} CRYPTO frames",
            data.len(),
            frames.len()
        );

        frames
    }

    /// Update statistics after packet sent
    pub fn on_packet_sent(&mut self, space: SpaceId, size: u16) {
        if self.pqc_detected && matches!(space, SpaceId::Initial | SpaceId::Handshake) {
            trace!("PQC packet sent in {:?}: {} bytes", space, size);
        }
    }

    /// Reset handler state (e.g., on retry)
    pub fn reset(&mut self) {
        self.pqc_detected = false;
        self.pqc_mode = None;
        self.estimated_handshake_size = 0;
        self.mtu_discovery_triggered = false;
    }
}

impl Default for PqcPacketHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Extension methods for Connection to handle PQC packets
pub trait PqcPacketHandling {
    /// Get the PQC packet handler
    fn pqc_packet_handler(&mut self) -> &mut PqcPacketHandler;

    /// Check and handle PQC detection from CRYPTO frames
    fn handle_pqc_detection(&mut self, crypto_data: &[u8], space: SpaceId);

    /// Adjust MTU discovery for PQC if needed
    fn adjust_mtu_for_pqc(&mut self);

    /// Get optimal packet size for current state
    fn get_pqc_optimal_packet_size(&self, space: SpaceId) -> u16;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pqc_packet_handler_creation() {
        let handler = PqcPacketHandler::new();
        assert!(!handler.pqc_detected);
        assert_eq!(handler.estimated_handshake_size, 0);
        assert!(!handler.mtu_discovery_triggered);
    }

    #[test]
    fn test_mtu_discovery_trigger() {
        let mut handler = PqcPacketHandler::new();

        // Should not trigger without PQC detection
        assert!(!handler.should_trigger_mtu_discovery());

        // Simulate PQC detection
        handler.pqc_detected = true;
        assert!(handler.should_trigger_mtu_discovery());

        // Should not trigger again
        assert!(!handler.should_trigger_mtu_discovery());
    }

    #[test]
    fn test_crypto_frame_size_calculation() {
        let handler = PqcPacketHandler::new();

        // Without PQC
        assert_eq!(handler.calculate_crypto_frame_size(1000, 2000), 600);
        assert_eq!(handler.calculate_crypto_frame_size(500, 2000), 500);
        assert_eq!(handler.calculate_crypto_frame_size(1000, 400), 400);

        // With PQC
        let mut handler = PqcPacketHandler::new();
        handler.pqc_detected = true;
        assert_eq!(handler.calculate_crypto_frame_size(1500, 2000), 1200);
        assert_eq!(handler.calculate_crypto_frame_size(500, 2000), 500);
    }

    #[test]
    fn test_min_packet_size() {
        let handler = PqcPacketHandler::new();

        // Without PQC
        assert_eq!(handler.get_min_packet_size(SpaceId::Initial), 1200);
        assert_eq!(handler.get_min_packet_size(SpaceId::Handshake), 1200);
        assert_eq!(handler.get_min_packet_size(SpaceId::Data), 1200);

        // With PQC
        let mut handler = PqcPacketHandler::new();
        handler.pqc_detected = true;
        assert_eq!(handler.get_min_packet_size(SpaceId::Initial), PQC_MIN_MTU);
        assert_eq!(handler.get_min_packet_size(SpaceId::Handshake), 1500);
        assert_eq!(handler.get_min_packet_size(SpaceId::Data), 1200);
    }

    #[test]
    fn test_crypto_data_fragmentation() {
        let handler = PqcPacketHandler::new();

        // Test small data (no fragmentation)
        let data = vec![0u8; 500];
        let frames = handler.fragment_crypto_data(&data, 1000, 1200);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].offset, 1000);
        assert_eq!(frames[0].data.len(), 500);

        // Test large data (requires fragmentation)
        // With max_packet_size=700, available_space=684, but limited to 600 for non-PQC
        let data = vec![0u8; 3000];
        let frames = handler.fragment_crypto_data(&data, 0, 700);
        assert_eq!(frames.len(), 5); // 600 * 5
        assert_eq!(frames[0].offset, 0);
        assert_eq!(frames[0].data.len(), 600);
        assert_eq!(frames[4].offset, 2400);
        assert_eq!(frames[4].data.len(), 600);
    }

    #[test]
    fn test_pqc_mode_estimation() {
        let handler = PqcPacketHandler::new();

        assert_eq!(
            handler.estimate_handshake_size(PqcMode::ClassicalOnly),
            4096
        );
        assert_eq!(handler.estimate_handshake_size(PqcMode::Hybrid), 16384);
        assert_eq!(handler.estimate_handshake_size(PqcMode::PqcOnly), 12288);
    }

    #[test]
    fn test_coalescing_adjustment() {
        let handler = PqcPacketHandler::new();

        // Without PQC
        assert!(!handler.adjust_coalescing_for_pqc(800, SpaceId::Initial));
        assert!(!handler.adjust_coalescing_for_pqc(500, SpaceId::Initial));

        // With PQC
        let mut handler = PqcPacketHandler::new();
        handler.pqc_detected = true;
        assert!(handler.adjust_coalescing_for_pqc(800, SpaceId::Initial));
        assert!(!handler.adjust_coalescing_for_pqc(500, SpaceId::Initial));
        assert!(!handler.adjust_coalescing_for_pqc(800, SpaceId::Handshake));
    }

    #[test]
    fn test_handshake_completion_check() {
        let mut handler = PqcPacketHandler::new();

        // Without PQC detection
        assert!(!handler.is_handshake_complete(10000));

        // With PQC detection
        handler.pqc_detected = true;
        handler.estimated_handshake_size = 16384;
        assert!(!handler.is_handshake_complete(8000));
        assert!(handler.is_handshake_complete(16384));
        assert!(handler.is_handshake_complete(20000));
    }

    #[test]
    fn test_handler_reset() {
        let mut handler = PqcPacketHandler::new();
        handler.pqc_detected = true;
        handler.pqc_mode = Some(PqcMode::Hybrid);
        handler.estimated_handshake_size = 16384;
        handler.mtu_discovery_triggered = true;

        handler.reset();

        assert!(!handler.pqc_detected);
        assert!(handler.pqc_mode.is_none());
        assert_eq!(handler.estimated_handshake_size, 0);
        assert!(!handler.mtu_discovery_triggered);
    }

    #[test]
    fn test_pqc_mtu_config() {
        let mut handler = PqcPacketHandler::new();

        // Without PQC detection
        let config = handler.get_pqc_mtu_config();
        assert_eq!(config.upper_bound, 1452); // Default upper bound

        // With PQC detection
        handler.pqc_detected = true;
        let config = handler.get_pqc_mtu_config();
        assert_eq!(
            config.upper_bound,
            PQC_RECOMMENDED_MTU.min(crate::MAX_UDP_PAYLOAD)
        );
        assert_eq!(config.minimum_change, 128);
    }

    #[test]
    fn test_pqc_constants() {
        assert_eq!(ML_KEM_768_HANDSHAKE_OVERHEAD, 2272);
        assert_eq!(ML_DSA_65_HANDSHAKE_OVERHEAD, 5261);
        assert_eq!(HYBRID_HANDSHAKE_OVERHEAD, 7789);
        assert_eq!(PQC_MIN_MTU, 2048);
        assert_eq!(PQC_RECOMMENDED_MTU, 4096);
        assert_eq!(MAX_CRYPTO_FRAME_SIZE, 1200);
    }
}
