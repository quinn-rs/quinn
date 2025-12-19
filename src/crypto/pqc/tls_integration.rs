// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Integration of PQC negotiation with rustls TLS handshake
//!
//! v0.13.0+: PQC is always on.
//! This module bridges the PQC negotiation logic with rustls's TLS 1.3
//! handshake process, ensuring proper algorithm selection.

use crate::crypto::pqc::{
    config::PqcConfig,
    negotiation::{NegotiationResult, PqcNegotiator, filter_algorithms, order_by_preference},
    tls_extensions::{NamedGroup, SignatureScheme},
    types::*,
};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// TLS handshake extension for PQC negotiation
///
/// v0.13.0+: PQC is always enabled on all connections.
#[derive(Debug, Clone)]
pub struct PqcHandshakeExtension {
    /// Negotiator instance
    negotiator: PqcNegotiator,
}

impl PqcHandshakeExtension {
    /// Create a new PQC handshake extension
    pub fn new(config: Arc<PqcConfig>) -> Self {
        let negotiator = PqcNegotiator::new((*config).clone());
        Self { negotiator }
    }

    /// Process ClientHello and filter supported algorithms
    pub fn process_client_hello(
        &mut self,
        supported_groups: &[u16],
        signature_schemes: &[u16],
    ) -> PqcResult<()> {
        debug!("Processing ClientHello for PQC negotiation");

        // Convert wire format to our types
        let client_groups: Vec<NamedGroup> = supported_groups
            .iter()
            .filter_map(|&code| NamedGroup::from_u16(code))
            .collect();

        let client_signatures: Vec<SignatureScheme> = signature_schemes
            .iter()
            .filter_map(|&code| SignatureScheme::from_u16(code))
            .collect();

        debug!(
            "Client supports {} groups and {} signatures",
            client_groups.len(),
            client_signatures.len()
        );

        self.negotiator
            .set_client_algorithms(client_groups, client_signatures);
        Ok(())
    }

    /// Process ServerHello and perform negotiation
    pub fn process_server_hello(
        &mut self,
        server_groups: &[u16],
        server_signatures: &[u16],
    ) -> PqcResult<NegotiationResult> {
        debug!("Processing ServerHello for PQC negotiation");

        // Convert wire format to our types
        let groups: Vec<NamedGroup> = server_groups
            .iter()
            .filter_map(|&code| NamedGroup::from_u16(code))
            .collect();

        let signatures: Vec<SignatureScheme> = server_signatures
            .iter()
            .filter_map(|&code| SignatureScheme::from_u16(code))
            .collect();

        self.negotiator.set_server_algorithms(groups, signatures);

        // Perform negotiation
        let result = self.negotiator.negotiate();

        // Check if we should fail (v0.13.0+: fail if no PQC)
        if self.negotiator.should_fail(&result) {
            warn!("Negotiation failed - no PQC algorithms: {}", result.reason);
            return Err(PqcError::NegotiationFailed(result.reason));
        }

        info!("PQC negotiation successful: {}", result.reason);
        Ok(result)
    }

    /// Get filtered algorithms for client (v0.13.0+: PQC only)
    pub fn get_client_algorithms(&self) -> (Vec<u16>, Vec<u16>) {
        let all_groups = Self::all_supported_groups();
        let all_signatures = Self::all_supported_signatures();

        let (mut groups, mut signatures) = filter_algorithms(&all_groups, &all_signatures);

        // Order by preference
        order_by_preference(&mut groups, &mut signatures);

        // Convert to wire format
        let group_codes: Vec<u16> = groups.iter().map(|g| g.to_u16()).collect();
        let sig_codes: Vec<u16> = signatures.iter().map(|s| s.to_u16()).collect();

        (group_codes, sig_codes)
    }

    /// Get all supported named groups
    fn all_supported_groups() -> Vec<NamedGroup> {
        vec![
            // Hybrid (PQC) groups - these are the only ones we use in v0.13.0+
            NamedGroup::X25519MlKem768,
            NamedGroup::P256MlKem768,
            NamedGroup::P384MlKem1024,
            // Pure PQC
            NamedGroup::MlKem768,
            NamedGroup::MlKem1024,
        ]
    }

    /// Get all supported signature schemes
    fn all_supported_signatures() -> Vec<SignatureScheme> {
        vec![
            // Hybrid (PQC) signatures - these are the only ones we use in v0.13.0+
            SignatureScheme::EcdsaP256MlDsa65,
            SignatureScheme::EcdsaP384MlDsa87,
            SignatureScheme::Ed25519MlDsa65,
            // Pure PQC
            SignatureScheme::MlDsa65,
            SignatureScheme::MlDsa87,
        ]
    }
}

/// Extension trait for rustls ServerConfig
pub trait PqcServerConfig {
    /// Configure PQC negotiation for the server
    fn with_pqc_config(self, config: Arc<PqcConfig>) -> Self;
}

/// Extension trait for rustls ClientConfig
pub trait PqcClientConfig {
    /// Configure PQC negotiation for the client
    fn with_pqc_config(self, config: Arc<PqcConfig>) -> Self;
}

/// State tracker for PQC handshake progress
#[derive(Debug, Clone, Default)]
pub struct PqcHandshakeState {
    /// Whether PQC negotiation has started
    pub started: bool,
    /// Selected key exchange group
    pub key_exchange: Option<NamedGroup>,
    /// Selected signature scheme
    pub signature_scheme: Option<SignatureScheme>,
    /// Whether PQC was used
    pub used_pqc: bool,
    /// Negotiation result message
    pub result_message: Option<String>,
}

impl PqcHandshakeState {
    /// Create a new handshake state
    pub fn new() -> Self {
        Self::default()
    }

    /// Update state from negotiation result
    pub fn update_from_result(&mut self, result: &NegotiationResult) {
        self.started = true;
        self.key_exchange = result.key_exchange;
        self.signature_scheme = result.signature_scheme;
        self.used_pqc = result.used_pqc;
        self.result_message = Some(result.reason.clone());
    }

    /// Check if handshake used PQC
    pub fn is_pqc(&self) -> bool {
        self.used_pqc
    }

    /// Get selected algorithms as a string
    pub fn selected_algorithms(&self) -> String {
        match (self.key_exchange, self.signature_scheme) {
            (Some(ke), Some(sig)) => format!("{} + {}", ke, sig),
            (Some(ke), None) => format!("{} (no signature)", ke),
            (None, Some(sig)) => format!("(no key exchange) + {}", sig),
            (None, None) => "No algorithms selected".to_string(),
        }
    }
}

/// Helper to check if a handshake should use larger packet sizes
pub fn requires_larger_packets(state: &PqcHandshakeState) -> bool {
    state.used_pqc
}

/// Helper to estimate handshake size based on selected algorithms
pub fn estimate_handshake_size(state: &PqcHandshakeState) -> usize {
    let mut size = 4096; // Base TLS handshake size

    // Add key exchange overhead
    if let Some(group) = state.key_exchange {
        size += match group {
            NamedGroup::X25519MlKem768 | NamedGroup::P256MlKem768 => 2272,
            NamedGroup::P384MlKem1024 => 3168,
            NamedGroup::MlKem768 => 2272,
            NamedGroup::MlKem1024 => 3168,
            _ => 0,
        };
    }

    // Add signature overhead
    if let Some(sig) = state.signature_scheme {
        size += match sig {
            SignatureScheme::Ed25519MlDsa65 | SignatureScheme::EcdsaP256MlDsa65 => 5261,
            SignatureScheme::EcdsaP384MlDsa87 => 7404,
            SignatureScheme::MlDsa65 => 5261,
            SignatureScheme::MlDsa87 => 7404,
            _ => 0,
        };
    }

    size
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_extension_creation() {
        let config = Arc::new(PqcConfig::default());
        let extension = PqcHandshakeExtension::new(config);
        assert!(extension.negotiator.client_groups.is_empty());
    }

    #[test]
    fn test_process_client_hello() {
        let config = Arc::new(PqcConfig::default());
        let mut extension = PqcHandshakeExtension::new(config);

        // Simulate ClientHello with groups and signatures
        let groups = vec![
            NamedGroup::X25519.to_u16(),
            NamedGroup::X25519MlKem768.to_u16(),
        ];
        let signatures = vec![
            SignatureScheme::Ed25519.to_u16(),
            SignatureScheme::Ed25519MlDsa65.to_u16(),
        ];

        extension
            .process_client_hello(&groups, &signatures)
            .unwrap();
        assert_eq!(extension.negotiator.client_groups.len(), 2);
        assert_eq!(extension.negotiator.client_signatures.len(), 2);
    }

    #[test]
    fn test_get_client_algorithms_pqc_only() {
        let config = Arc::new(PqcConfig::builder().build().unwrap());
        let extension = PqcHandshakeExtension::new(config);

        let (groups, signatures) = extension.get_client_algorithms();

        // Should only contain PQC algorithms
        for &group_code in &groups {
            if let Some(group) = NamedGroup::from_u16(group_code) {
                assert!(group.is_hybrid() || group.is_pqc());
            }
        }

        for &sig_code in &signatures {
            if let Some(sig) = SignatureScheme::from_u16(sig_code) {
                assert!(sig.is_hybrid() || sig.is_pqc());
            }
        }
    }

    #[test]
    fn test_handshake_state() {
        let mut state = PqcHandshakeState::new();
        assert!(!state.started);
        assert!(!state.is_pqc());

        let result = NegotiationResult {
            key_exchange: Some(NamedGroup::X25519MlKem768),
            signature_scheme: Some(SignatureScheme::Ed25519MlDsa65),
            used_pqc: true,
            reason: "Test negotiation".to_string(),
        };

        state.update_from_result(&result);
        assert!(state.started);
        assert!(state.is_pqc());
        assert_eq!(state.key_exchange, Some(NamedGroup::X25519MlKem768));
        assert_eq!(
            state.signature_scheme,
            Some(SignatureScheme::Ed25519MlDsa65)
        );
    }

    #[test]
    fn test_requires_larger_packets() {
        let mut state = PqcHandshakeState::new();
        assert!(!requires_larger_packets(&state));

        state.used_pqc = true;
        assert!(requires_larger_packets(&state));
    }

    #[test]
    fn test_estimate_handshake_size() {
        let mut state = PqcHandshakeState::new();

        // Base size
        assert_eq!(estimate_handshake_size(&state), 4096);

        // With hybrid key exchange
        state.key_exchange = Some(NamedGroup::X25519MlKem768);
        assert_eq!(estimate_handshake_size(&state), 4096 + 2272);

        // With hybrid signature too
        state.signature_scheme = Some(SignatureScheme::Ed25519MlDsa65);
        assert_eq!(estimate_handshake_size(&state), 4096 + 2272 + 5261);
    }

    #[test]
    fn test_selected_algorithms_display() {
        let mut state = PqcHandshakeState::new();
        assert_eq!(state.selected_algorithms(), "No algorithms selected");

        state.key_exchange = Some(NamedGroup::X25519);
        assert_eq!(state.selected_algorithms(), "x25519 (no signature)");

        state.signature_scheme = Some(SignatureScheme::Ed25519);
        assert_eq!(state.selected_algorithms(), "x25519 + ed25519");
    }
}
