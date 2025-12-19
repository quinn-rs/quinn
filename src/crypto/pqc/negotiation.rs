// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! PQC algorithm negotiation
//!
//! v0.13.0+: PQC is always on. This module implements the negotiation
//! logic for post-quantum cryptography in TLS 1.3 handshakes. It handles:
//!
//! - Algorithm selection with PQC preference
//! - Client/server negotiation of supported algorithms
//! - Debugging and logging of negotiation decisions

use crate::crypto::pqc::{
    config::PqcConfig,
    tls_extensions::{NamedGroup, SignatureScheme},
    types::*,
};
use std::collections::HashSet;
use tracing::{debug, info, trace, warn};

/// Result of algorithm negotiation
#[derive(Debug, Clone, PartialEq)]
pub struct NegotiationResult {
    /// Selected key exchange group
    pub key_exchange: Option<NamedGroup>,
    /// Selected signature scheme
    pub signature_scheme: Option<SignatureScheme>,
    /// Whether PQC was used
    pub used_pqc: bool,
    /// Reason for selection
    pub reason: String,
}

/// PQC negotiation handler
#[derive(Debug, Clone)]
pub struct PqcNegotiator {
    /// Configuration for PQC
    config: PqcConfig,
    /// Client's supported groups
    pub(crate) client_groups: Vec<NamedGroup>,
    /// Client's supported signature schemes
    pub(crate) client_signatures: Vec<SignatureScheme>,
    /// Server's supported groups
    pub(crate) server_groups: Vec<NamedGroup>,
    /// Server's supported signature schemes
    pub(crate) server_signatures: Vec<SignatureScheme>,
}

impl PqcNegotiator {
    /// Create a new negotiator with configuration
    pub fn new(config: PqcConfig) -> Self {
        Self {
            config,
            client_groups: Vec::new(),
            client_signatures: Vec::new(),
            server_groups: Vec::new(),
            server_signatures: Vec::new(),
        }
    }

    /// Set client's supported algorithms
    pub fn set_client_algorithms(
        &mut self,
        groups: Vec<NamedGroup>,
        signatures: Vec<SignatureScheme>,
    ) {
        self.client_groups = groups;
        self.client_signatures = signatures;
        trace!(
            "Client algorithms set: {} groups, {} signatures",
            self.client_groups.len(),
            self.client_signatures.len()
        );
    }

    /// Set server's supported algorithms
    pub fn set_server_algorithms(
        &mut self,
        groups: Vec<NamedGroup>,
        signatures: Vec<SignatureScheme>,
    ) {
        self.server_groups = groups;
        self.server_signatures = signatures;
        trace!(
            "Server algorithms set: {} groups, {} signatures",
            self.server_groups.len(),
            self.server_signatures.len()
        );
    }

    /// Negotiate algorithms (v0.13.0+: always prefers PQC)
    pub fn negotiate(&self) -> NegotiationResult {
        debug!("Starting PQC negotiation");

        // Negotiate key exchange
        let key_exchange_result = self.negotiate_key_exchange();

        // Negotiate signature scheme
        let signature_result = self.negotiate_signature();

        // Determine if PQC was used
        let used_pqc = key_exchange_result
            .as_ref()
            .map(|g| g.is_hybrid() || g.is_pqc())
            .unwrap_or(false)
            || signature_result
                .as_ref()
                .map(|s| s.is_hybrid() || s.is_pqc())
                .unwrap_or(false);

        // Build reason message
        let reason = self.build_reason_message(&key_exchange_result, &signature_result, used_pqc);

        info!(
            "Negotiation complete: key_exchange={:?}, signature={:?}, pqc={}",
            key_exchange_result, signature_result, used_pqc
        );

        NegotiationResult {
            key_exchange: key_exchange_result,
            signature_scheme: signature_result,
            used_pqc,
            reason,
        }
    }

    /// Negotiate key exchange group (v0.13.0+: PQC required)
    fn negotiate_key_exchange(&self) -> Option<NamedGroup> {
        let client_set: HashSet<_> = self.client_groups.iter().cloned().collect();
        let server_set: HashSet<_> = self.server_groups.iter().cloned().collect();
        let common: Vec<_> = client_set.intersection(&server_set).cloned().collect();

        if common.is_empty() {
            warn!("No common key exchange groups between client and server");
            return None;
        }

        // v0.13.0+: Only select PQC algorithms (hybrid or pure)
        let pqc = common.iter().find(|g| g.is_hybrid() || g.is_pqc()).cloned();

        if pqc.is_none() {
            warn!("No PQC key exchange groups available");
        }
        pqc
    }

    /// Negotiate signature scheme (v0.13.0+: PQC required)
    fn negotiate_signature(&self) -> Option<SignatureScheme> {
        let client_set: HashSet<_> = self.client_signatures.iter().cloned().collect();
        let server_set: HashSet<_> = self.server_signatures.iter().cloned().collect();
        let common: Vec<_> = client_set.intersection(&server_set).cloned().collect();

        if common.is_empty() {
            warn!("No common signature schemes between client and server");
            return None;
        }

        // v0.13.0+: Only select PQC algorithms (hybrid or pure)
        let pqc = common.iter().find(|s| s.is_hybrid() || s.is_pqc()).cloned();

        if pqc.is_none() {
            warn!("No PQC signature schemes available");
        }
        pqc
    }

    /// Build a human-readable reason message
    fn build_reason_message(
        &self,
        key_exchange: &Option<NamedGroup>,
        signature: &Option<SignatureScheme>,
        used_pqc: bool,
    ) -> String {
        match (key_exchange, signature) {
            (Some(ke), Some(sig)) => {
                if used_pqc {
                    format!("Successfully negotiated PQC algorithms: {} + {}", ke, sig)
                } else {
                    format!(
                        "Warning: Classical algorithms selected (PQC required): {} + {}",
                        ke, sig
                    )
                }
            }
            (None, Some(sig)) => {
                format!(
                    "Failed to negotiate key exchange, only signature selected: {}",
                    sig
                )
            }
            (Some(ke), None) => {
                format!(
                    "Failed to negotiate signature, only key exchange selected: {}",
                    ke
                )
            }
            (None, None) => {
                "Failed to negotiate any algorithms - no common ground between client and server"
                    .to_string()
            }
        }
    }

    /// Check if negotiation should fail (v0.13.0+: fail if no PQC)
    pub fn should_fail(&self, result: &NegotiationResult) -> bool {
        // v0.13.0+: Fail if we couldn't negotiate PQC
        !result.used_pqc
    }

    /// Get detailed negotiation debug info
    pub fn debug_info(&self) -> String {
        format!(
            "PQC Negotiation Debug Info:\n\
             Client Groups: {:?}\n\
             Server Groups: {:?}\n\
             Client Signatures: {:?}\n\
             Server Signatures: {:?}\n\
             Common Groups: {:?}\n\
             Common Signatures: {:?}",
            self.client_groups,
            self.server_groups,
            self.client_signatures,
            self.server_signatures,
            self.find_common_groups(),
            self.find_common_signatures()
        )
    }

    fn find_common_groups(&self) -> Vec<NamedGroup> {
        let client_set: HashSet<_> = self.client_groups.iter().cloned().collect();
        let server_set: HashSet<_> = self.server_groups.iter().cloned().collect();
        client_set.intersection(&server_set).cloned().collect()
    }

    fn find_common_signatures(&self) -> Vec<SignatureScheme> {
        let client_set: HashSet<_> = self.client_signatures.iter().cloned().collect();
        let server_set: HashSet<_> = self.server_signatures.iter().cloned().collect();
        client_set.intersection(&server_set).cloned().collect()
    }

    /// Get the PQC config
    pub fn config(&self) -> &PqcConfig {
        &self.config
    }
}

/// Helper to filter algorithms for PQC-only mode
pub fn filter_algorithms(
    groups: &[NamedGroup],
    signatures: &[SignatureScheme],
) -> (Vec<NamedGroup>, Vec<SignatureScheme>) {
    // v0.13.0+: Only keep PQC algorithms
    let filtered_groups = groups
        .iter()
        .filter(|g| g.is_hybrid() || g.is_pqc())
        .cloned()
        .collect();

    let filtered_signatures = signatures
        .iter()
        .filter(|s| s.is_hybrid() || s.is_pqc())
        .cloned()
        .collect();

    (filtered_groups, filtered_signatures)
}

/// Order algorithms by preference (v0.13.0+: PQC first)
pub fn order_by_preference(groups: &mut Vec<NamedGroup>, signatures: &mut Vec<SignatureScheme>) {
    // PQC algorithms first, prefer hybrid
    groups.sort_by_key(|g| match (g.is_hybrid(), g.is_pqc()) {
        (true, _) => 0,     // Hybrid first
        (false, true) => 1, // Pure PQC second
        _ => 2,             // Classical last (shouldn't be present)
    });
    signatures.sort_by_key(|s| match (s.is_hybrid(), s.is_pqc()) {
        (true, _) => 0,
        (false, true) => 1,
        _ => 2,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_negotiator_creation() {
        let config = PqcConfig::default();
        let negotiator = PqcNegotiator::new(config);
        assert_eq!(negotiator.client_groups.len(), 0);
        assert_eq!(negotiator.server_groups.len(), 0);
    }

    #[test]
    fn test_pqc_negotiation() {
        let config = PqcConfig::builder().build().unwrap();
        let mut negotiator = PqcNegotiator::new(config);

        // Set up with PQC algorithms
        negotiator.set_client_algorithms(
            vec![
                NamedGroup::X25519,
                NamedGroup::X25519MlKem768,
                NamedGroup::P256MlKem768,
            ],
            vec![
                SignatureScheme::Ed25519,
                SignatureScheme::Ed25519MlDsa65,
                SignatureScheme::EcdsaP256MlDsa65,
            ],
        );

        negotiator.set_server_algorithms(
            vec![NamedGroup::X25519MlKem768, NamedGroup::P256MlKem768],
            vec![
                SignatureScheme::Ed25519MlDsa65,
                SignatureScheme::EcdsaP256MlDsa65,
            ],
        );

        let result = negotiator.negotiate();

        // Should select PQC algorithms
        assert!(result.used_pqc);
        // Should select one of the PQC groups
        assert!(matches!(
            result.key_exchange,
            Some(NamedGroup::X25519MlKem768) | Some(NamedGroup::P256MlKem768)
        ));
        // Should select one of the PQC signatures
        assert!(matches!(
            result.signature_scheme,
            Some(SignatureScheme::Ed25519MlDsa65) | Some(SignatureScheme::EcdsaP256MlDsa65)
        ));
        assert!(!negotiator.should_fail(&result));
    }

    #[test]
    fn test_negotiation_failure_no_pqc() {
        let config = PqcConfig::builder().build().unwrap();
        let mut negotiator = PqcNegotiator::new(config);

        // Only classical algorithms available
        negotiator.set_client_algorithms(vec![NamedGroup::X25519], vec![SignatureScheme::Ed25519]);

        negotiator.set_server_algorithms(vec![NamedGroup::X25519], vec![SignatureScheme::Ed25519]);

        let result = negotiator.negotiate();

        // Should fail - no PQC available
        assert!(!result.used_pqc);
        assert_eq!(result.key_exchange, None);
        assert_eq!(result.signature_scheme, None);
        assert!(negotiator.should_fail(&result));
    }

    #[test]
    fn test_no_common_algorithms() {
        let config = PqcConfig::default();
        let mut negotiator = PqcNegotiator::new(config);

        // Completely disjoint sets
        negotiator.set_client_algorithms(vec![NamedGroup::X25519], vec![SignatureScheme::Ed25519]);

        negotiator.set_server_algorithms(
            vec![NamedGroup::Secp256r1],
            vec![SignatureScheme::EcdsaSecp256r1Sha256],
        );

        let result = negotiator.negotiate();

        // Should fail completely
        assert_eq!(result.key_exchange, None);
        assert_eq!(result.signature_scheme, None);
        assert!(!result.used_pqc);
        assert!(result.reason.contains("no common ground"));
    }

    #[test]
    fn test_filter_algorithms() {
        let groups = vec![
            NamedGroup::X25519,
            NamedGroup::X25519MlKem768,
            NamedGroup::Secp256r1,
        ];
        let signatures = vec![
            SignatureScheme::Ed25519,
            SignatureScheme::Ed25519MlDsa65,
            SignatureScheme::EcdsaSecp256r1Sha256,
        ];

        let (filtered_groups, filtered_sigs) = filter_algorithms(&groups, &signatures);

        // Should only keep PQC algorithms
        assert_eq!(filtered_groups.len(), 1);
        assert_eq!(filtered_sigs.len(), 1);
        assert!(filtered_groups.iter().all(|g| g.is_hybrid() || g.is_pqc()));
        assert!(filtered_sigs.iter().all(|s| s.is_hybrid() || s.is_pqc()));
    }

    #[test]
    fn test_order_by_preference() {
        let mut groups = vec![
            NamedGroup::X25519,
            NamedGroup::X25519MlKem768,
            NamedGroup::Secp256r1,
        ];
        let mut signatures = vec![
            SignatureScheme::Ed25519,
            SignatureScheme::Ed25519MlDsa65,
            SignatureScheme::EcdsaSecp256r1Sha256,
        ];

        order_by_preference(&mut groups, &mut signatures);
        assert_eq!(groups[0], NamedGroup::X25519MlKem768);
        assert_eq!(signatures[0], SignatureScheme::Ed25519MlDsa65);
    }

    #[test]
    fn test_debug_info() {
        let config = PqcConfig::default();
        let mut negotiator = PqcNegotiator::new(config);

        negotiator.set_client_algorithms(vec![NamedGroup::X25519], vec![SignatureScheme::Ed25519]);
        negotiator.set_server_algorithms(vec![NamedGroup::X25519], vec![SignatureScheme::Ed25519]);

        let debug_info = negotiator.debug_info();
        assert!(debug_info.contains("Client Groups"));
        assert!(debug_info.contains("Server Groups"));
        assert!(debug_info.contains("Common Groups"));
    }
}
