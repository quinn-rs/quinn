// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses


//! PQC algorithm negotiation and fallback handling
//!
//! This module implements the negotiation logic for post-quantum cryptography
//! in TLS 1.3 handshakes. It handles:
//!
//! - Algorithm selection based on configured PQC mode
//! - Client/server negotiation of supported algorithms
//! - Mode-specific constraints enforcement
//! - Graceful fallback to classical algorithms
//! - Debugging and logging of negotiation decisions

use crate::crypto::pqc::{
    config::{PqcConfig, PqcMode},
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
    /// Reason for selection/fallback
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

    /// Negotiate algorithms based on mode and preferences
    pub fn negotiate(&self) -> NegotiationResult {
        debug!("Starting PQC negotiation with mode: {:?}", self.config.mode);

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

    /// Negotiate key exchange group
    fn negotiate_key_exchange(&self) -> Option<NamedGroup> {
        let client_set: HashSet<_> = self.client_groups.iter().cloned().collect();
        let server_set: HashSet<_> = self.server_groups.iter().cloned().collect();
        let common: Vec<_> = client_set.intersection(&server_set).cloned().collect();

        if common.is_empty() {
            warn!("No common key exchange groups between client and server");
            return None;
        }

        match self.config.mode {
            PqcMode::ClassicalOnly => {
                // Only select classical algorithms
                let classical = common
                    .iter()
                    .find(|g| !g.is_hybrid() && !g.is_pqc())
                    .cloned();

                if classical.is_none() {
                    warn!("ClassicalOnly mode but no classical groups available");
                }
                classical
            }
            PqcMode::PqcOnly => {
                // Only select PQC algorithms (hybrid or pure)
                let pqc = common.iter().find(|g| g.is_hybrid() || g.is_pqc()).cloned();

                if pqc.is_none() {
                    warn!("PqcOnly mode but no PQC groups available");
                }
                pqc
            }
            PqcMode::Hybrid => {
                // Prefer hybrid, then PQC, then classical
                common
                    .iter()
                    .find(|g| g.is_hybrid())
                    .or_else(|| common.iter().find(|g| g.is_pqc()))
                    .or_else(|| common.iter().find(|g| !g.is_hybrid() && !g.is_pqc()))
                    .cloned()
            }
        }
    }

    /// Negotiate signature scheme
    fn negotiate_signature(&self) -> Option<SignatureScheme> {
        let client_set: HashSet<_> = self.client_signatures.iter().cloned().collect();
        let server_set: HashSet<_> = self.server_signatures.iter().cloned().collect();
        let common: Vec<_> = client_set.intersection(&server_set).cloned().collect();

        if common.is_empty() {
            warn!("No common signature schemes between client and server");
            return None;
        }

        match self.config.mode {
            PqcMode::ClassicalOnly => {
                // Only select classical algorithms
                let classical = common
                    .iter()
                    .find(|s| !s.is_hybrid() && !s.is_pqc())
                    .cloned();

                if classical.is_none() {
                    warn!("ClassicalOnly mode but no classical signatures available");
                }
                classical
            }
            PqcMode::PqcOnly => {
                // Only select PQC algorithms (hybrid or pure)
                let pqc = common.iter().find(|s| s.is_hybrid() || s.is_pqc()).cloned();

                if pqc.is_none() {
                    warn!("PqcOnly mode but no PQC signatures available");
                }
                pqc
            }
            PqcMode::Hybrid => {
                // Prefer hybrid, then PQC, then classical
                common
                    .iter()
                    .find(|s| s.is_hybrid())
                    .or_else(|| common.iter().find(|s| s.is_pqc()))
                    .or_else(|| common.iter().find(|s| !s.is_hybrid() && !s.is_pqc()))
                    .cloned()
            }
        }
    }

    /// Build a human-readable reason message
    fn build_reason_message(
        &self,
        key_exchange: &Option<NamedGroup>,
        signature: &Option<SignatureScheme>,
        used_pqc: bool,
    ) -> String {
        let mode = self.config.mode;

        match (key_exchange, signature) {
            (Some(ke), Some(sig)) => {
                if used_pqc {
                    match mode {
                        PqcMode::PqcOnly => {
                            format!(
                                "Successfully negotiated PQC algorithms as required by PqcOnly mode: {} + {}",
                                ke, sig
                            )
                        }
                        PqcMode::Hybrid => {
                            format!(
                                "Successfully negotiated PQC algorithms in Hybrid mode: {} + {}",
                                ke, sig
                            )
                        }
                        PqcMode::ClassicalOnly => {
                            // This shouldn't happen
                            format!(
                                "Warning: PQC algorithms selected in ClassicalOnly mode: {} + {}",
                                ke, sig
                            )
                        }
                    }
                } else {
                    match mode {
                        PqcMode::ClassicalOnly => {
                            format!(
                                "Successfully negotiated classical algorithms as required: {} + {}",
                                ke, sig
                            )
                        }
                        PqcMode::Hybrid => {
                            format!(
                                "Fell back to classical algorithms in Hybrid mode: {} + {}",
                                ke, sig
                            )
                        }
                        PqcMode::PqcOnly => {
                            // This shouldn't happen
                            format!(
                                "Warning: Classical algorithms selected in PqcOnly mode: {} + {}",
                                ke, sig
                            )
                        }
                    }
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

    /// Check if negotiation should fail based on mode constraints
    pub fn should_fail(&self, result: &NegotiationResult) -> bool {
        match self.config.mode {
            PqcMode::PqcOnly => {
                // Fail if we couldn't negotiate PQC
                !result.used_pqc
            }
            PqcMode::ClassicalOnly => {
                // Fail if we somehow negotiated PQC
                result.used_pqc
            }
            PqcMode::Hybrid => {
                // Never fail in hybrid mode - we can always fall back
                false
            }
        }
    }

    /// Get detailed negotiation debug info
    pub fn debug_info(&self) -> String {
        format!(
            "PQC Negotiation Debug Info:\n\
             Mode: {:?}\n\
             Client Groups: {:?}\n\
             Server Groups: {:?}\n\
             Client Signatures: {:?}\n\
             Server Signatures: {:?}\n\
             Common Groups: {:?}\n\
             Common Signatures: {:?}",
            self.config.mode,
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
}

/// Helper to filter algorithms based on mode
pub fn filter_algorithms_for_mode(
    mode: PqcMode,
    groups: &[NamedGroup],
    signatures: &[SignatureScheme],
) -> (Vec<NamedGroup>, Vec<SignatureScheme>) {
    let filtered_groups = match mode {
        PqcMode::ClassicalOnly => groups
            .iter()
            .filter(|g| !g.is_hybrid() && !g.is_pqc())
            .cloned()
            .collect(),
        PqcMode::PqcOnly => groups
            .iter()
            .filter(|g| g.is_hybrid() || g.is_pqc())
            .cloned()
            .collect(),
        PqcMode::Hybrid => groups.to_vec(),
    };

    let filtered_signatures = match mode {
        PqcMode::ClassicalOnly => signatures
            .iter()
            .filter(|s| !s.is_hybrid() && !s.is_pqc())
            .cloned()
            .collect(),
        PqcMode::PqcOnly => signatures
            .iter()
            .filter(|s| s.is_hybrid() || s.is_pqc())
            .cloned()
            .collect(),
        PqcMode::Hybrid => signatures.to_vec(),
    };

    (filtered_groups, filtered_signatures)
}

/// Order algorithms by preference for a given mode
pub fn order_by_preference(
    mode: PqcMode,
    groups: &mut Vec<NamedGroup>,
    signatures: &mut Vec<SignatureScheme>,
) {
    match mode {
        PqcMode::ClassicalOnly => {
            // Classical algorithms first
            groups.sort_by_key(|g| if g.is_hybrid() || g.is_pqc() { 1 } else { 0 });
            signatures.sort_by_key(|s| if s.is_hybrid() || s.is_pqc() { 1 } else { 0 });
        }
        PqcMode::PqcOnly => {
            // PQC algorithms first, prefer hybrid
            groups.sort_by_key(|g| match (g.is_hybrid(), g.is_pqc()) {
                (true, _) => 0,     // Hybrid first
                (false, true) => 1, // Pure PQC second
                _ => 2,             // Classical last
            });
            signatures.sort_by_key(|s| match (s.is_hybrid(), s.is_pqc()) {
                (true, _) => 0,
                (false, true) => 1,
                _ => 2,
            });
        }
        PqcMode::Hybrid => {
            // Hybrid first, then PQC, then classical
            groups.sort_by_key(|g| match (g.is_hybrid(), g.is_pqc()) {
                (true, _) => 0,     // Hybrid first
                (false, true) => 1, // Pure PQC second
                _ => 2,             // Classical last
            });
            signatures.sort_by_key(|s| match (s.is_hybrid(), s.is_pqc()) {
                (true, _) => 0,
                (false, true) => 1,
                _ => 2,
            });
        }
    }
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
    fn test_classical_only_negotiation() {
        let config = PqcConfig::builder()
            .mode(PqcMode::ClassicalOnly)
            .build()
            .unwrap();
        let mut negotiator = PqcNegotiator::new(config);

        // Set up client and server with both classical and PQC
        negotiator.set_client_algorithms(
            vec![
                NamedGroup::X25519,
                NamedGroup::X25519MlKem768,
                NamedGroup::Secp256r1,
            ],
            vec![
                SignatureScheme::Ed25519,
                SignatureScheme::Ed25519MlDsa65,
                SignatureScheme::EcdsaSecp256r1Sha256,
            ],
        );

        negotiator.set_server_algorithms(
            vec![
                NamedGroup::X25519,
                NamedGroup::X25519MlKem768,
                NamedGroup::Secp256r1,
            ],
            vec![
                SignatureScheme::Ed25519,
                SignatureScheme::Ed25519MlDsa65,
                SignatureScheme::EcdsaSecp256r1Sha256,
            ],
        );

        let result = negotiator.negotiate();

        // Should select classical algorithms only
        assert!(!result.used_pqc);
        // Should select one of the classical groups
        assert!(matches!(
            result.key_exchange,
            Some(NamedGroup::X25519) | Some(NamedGroup::Secp256r1)
        ));
        // Should select one of the classical signatures
        assert!(matches!(
            result.signature_scheme,
            Some(SignatureScheme::Ed25519) | Some(SignatureScheme::EcdsaSecp256r1Sha256)
        ));
        assert!(!negotiator.should_fail(&result));
    }

    #[test]
    fn test_pqc_only_negotiation() {
        let config = PqcConfig::builder().mode(PqcMode::PqcOnly).build().unwrap();
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
    fn test_pqc_only_fallback_failure() {
        let config = PqcConfig::builder().mode(PqcMode::PqcOnly).build().unwrap();
        let mut negotiator = PqcNegotiator::new(config);

        // Client supports PQC, server doesn't
        negotiator.set_client_algorithms(
            vec![NamedGroup::X25519MlKem768],
            vec![SignatureScheme::Ed25519MlDsa65],
        );

        negotiator.set_server_algorithms(vec![NamedGroup::X25519], vec![SignatureScheme::Ed25519]);

        let result = negotiator.negotiate();

        // Should fail to negotiate
        assert!(!result.used_pqc);
        assert_eq!(result.key_exchange, None);
        assert_eq!(result.signature_scheme, None);
        assert!(negotiator.should_fail(&result));
    }

    #[test]
    fn test_hybrid_mode_preferences() {
        let config = PqcConfig::builder().mode(PqcMode::Hybrid).build().unwrap();
        let mut negotiator = PqcNegotiator::new(config);

        // Server prefers classical, client has everything
        negotiator.set_client_algorithms(
            vec![
                NamedGroup::X25519,
                NamedGroup::X25519MlKem768,
                NamedGroup::Secp256r1,
            ],
            vec![
                SignatureScheme::Ed25519,
                SignatureScheme::Ed25519MlDsa65,
                SignatureScheme::EcdsaSecp256r1Sha256,
            ],
        );

        negotiator.set_server_algorithms(
            vec![NamedGroup::X25519, NamedGroup::X25519MlKem768],
            vec![SignatureScheme::Ed25519, SignatureScheme::Ed25519MlDsa65],
        );

        let result = negotiator.negotiate();

        // Should prefer hybrid
        assert!(result.used_pqc);
        assert_eq!(result.key_exchange, Some(NamedGroup::X25519MlKem768));
        assert_eq!(
            result.signature_scheme,
            Some(SignatureScheme::Ed25519MlDsa65)
        );
        assert!(!negotiator.should_fail(&result));
    }

    #[test]
    fn test_hybrid_fallback_to_classical() {
        let config = PqcConfig::builder().mode(PqcMode::Hybrid).build().unwrap();
        let mut negotiator = PqcNegotiator::new(config);

        // No common PQC algorithms
        negotiator.set_client_algorithms(
            vec![NamedGroup::X25519, NamedGroup::X25519MlKem768],
            vec![SignatureScheme::Ed25519, SignatureScheme::Ed25519MlDsa65],
        );

        negotiator.set_server_algorithms(
            vec![NamedGroup::X25519, NamedGroup::Secp256r1],
            vec![
                SignatureScheme::Ed25519,
                SignatureScheme::EcdsaSecp256r1Sha256,
            ],
        );

        let result = negotiator.negotiate();

        // Should fall back to classical
        assert!(!result.used_pqc);
        assert_eq!(result.key_exchange, Some(NamedGroup::X25519));
        assert_eq!(result.signature_scheme, Some(SignatureScheme::Ed25519));
        assert!(!negotiator.should_fail(&result));
        assert!(result.reason.contains("Fell back to classical"));
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
    fn test_filter_algorithms_for_mode() {
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

        // Classical only
        let (filtered_groups, filtered_sigs) =
            filter_algorithms_for_mode(PqcMode::ClassicalOnly, &groups, &signatures);
        assert_eq!(filtered_groups.len(), 2);
        assert_eq!(filtered_sigs.len(), 2);
        assert!(!filtered_groups.iter().any(|g| g.is_hybrid()));

        // PQC only
        let (filtered_groups, filtered_sigs) =
            filter_algorithms_for_mode(PqcMode::PqcOnly, &groups, &signatures);
        assert_eq!(filtered_groups.len(), 1);
        assert_eq!(filtered_sigs.len(), 1);
        assert!(filtered_groups.iter().all(|g| g.is_hybrid() || g.is_pqc()));

        // Hybrid - should keep all
        let (filtered_groups, filtered_sigs) =
            filter_algorithms_for_mode(PqcMode::Hybrid, &groups, &signatures);
        assert_eq!(filtered_groups.len(), 3);
        assert_eq!(filtered_sigs.len(), 3);
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

        // Hybrid mode should prefer hybrid algorithms
        order_by_preference(PqcMode::Hybrid, &mut groups, &mut signatures);
        assert_eq!(groups[0], NamedGroup::X25519MlKem768);
        assert_eq!(signatures[0], SignatureScheme::Ed25519MlDsa65);

        // Classical mode should prefer classical
        order_by_preference(PqcMode::ClassicalOnly, &mut groups, &mut signatures);
        assert!(!groups[0].is_hybrid());
        assert!(!signatures[0].is_hybrid());
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
