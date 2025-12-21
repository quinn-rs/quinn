// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! PQC algorithm negotiation
//!
//! v0.2: Pure Post-Quantum Cryptography - NO hybrid or classical algorithms.
//!
//! This module implements the negotiation logic for pure PQC in TLS 1.3 handshakes:
//! - Key Exchange: ML-KEM-768 (0x0201) ONLY
//! - Signatures: ML-DSA-65 (IANA 0x0905) ONLY
//! - NO classical fallback, NO hybrid algorithms
//!
//! This is a greenfield network with no legacy compatibility requirements.

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

    /// Negotiate algorithms (v0.2: ONLY pure PQC accepted)
    pub fn negotiate(&self) -> NegotiationResult {
        debug!("Starting pure PQC negotiation (v0.2)");

        // Negotiate key exchange - ONLY pure ML-KEM
        let key_exchange_result = self.negotiate_key_exchange();

        // Negotiate signature scheme - ONLY pure ML-DSA
        let signature_result = self.negotiate_signature();

        // v0.2: PQC is used if we have pure PQC algorithms
        let used_pqc = key_exchange_result
            .as_ref()
            .map(|g| g.is_pqc())
            .unwrap_or(false)
            || signature_result
                .as_ref()
                .map(|s| s.is_pqc())
                .unwrap_or(false);

        // Build reason message
        let reason = self.build_reason_message(&key_exchange_result, &signature_result, used_pqc);

        info!(
            "Pure PQC negotiation complete: key_exchange={:?}, signature={:?}, pqc={}",
            key_exchange_result, signature_result, used_pqc
        );

        NegotiationResult {
            key_exchange: key_exchange_result,
            signature_scheme: signature_result,
            used_pqc,
            reason,
        }
    }

    /// Negotiate key exchange group (v0.2: Pure PQC ONLY)
    fn negotiate_key_exchange(&self) -> Option<NamedGroup> {
        let client_set: HashSet<_> = self.client_groups.iter().cloned().collect();
        let server_set: HashSet<_> = self.server_groups.iter().cloned().collect();
        let common: Vec<_> = client_set.intersection(&server_set).cloned().collect();

        if common.is_empty() {
            warn!("No common key exchange groups between client and server");
            return None;
        }

        // v0.2: ONLY select pure PQC algorithms (NO hybrids)
        let pqc = common.iter().find(|g| g.is_pqc()).cloned();

        if pqc.is_none() {
            warn!("No pure PQC key exchange groups available - hybrid and classical rejected");
        }
        pqc
    }

    /// Negotiate signature scheme (v0.2: Pure PQC ONLY)
    fn negotiate_signature(&self) -> Option<SignatureScheme> {
        let client_set: HashSet<_> = self.client_signatures.iter().cloned().collect();
        let server_set: HashSet<_> = self.server_signatures.iter().cloned().collect();
        let common: Vec<_> = client_set.intersection(&server_set).cloned().collect();

        if common.is_empty() {
            warn!("No common signature schemes between client and server");
            return None;
        }

        // v0.2: ONLY select pure PQC algorithms (NO hybrids)
        let pqc = common.iter().find(|s| s.is_pqc()).cloned();

        if pqc.is_none() {
            warn!("No pure PQC signature schemes available - hybrid and classical rejected");
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

/// Helper to filter algorithms for pure PQC-only mode
pub fn filter_algorithms(
    groups: &[NamedGroup],
    signatures: &[SignatureScheme],
) -> (Vec<NamedGroup>, Vec<SignatureScheme>) {
    // v0.2: Only keep pure PQC algorithms (NO hybrids)
    let filtered_groups = groups.iter().filter(|g| g.is_pqc()).cloned().collect();

    let filtered_signatures = signatures.iter().filter(|s| s.is_pqc()).cloned().collect();

    (filtered_groups, filtered_signatures)
}

/// Order algorithms by preference (v0.2: Pure PQC only)
pub fn order_by_preference(groups: &mut Vec<NamedGroup>, signatures: &mut Vec<SignatureScheme>) {
    // v0.2: Only pure PQC algorithms, prefer ML-KEM-768 and ML-DSA-65 (Level 3)
    groups.sort_by_key(|g| {
        if g.is_pqc() {
            // Order by security level: Level 3 (768) preferred, then 5 (1024), then 1 (512)
            match g.to_u16() {
                0x0201 => 0, // ML-KEM-768 (PRIMARY)
                0x0202 => 1, // ML-KEM-1024
                0x0200 => 2, // ML-KEM-512
                _ => 3,
            }
        } else {
            99 // Non-PQC at end (shouldn't be present)
        }
    });
    signatures.sort_by_key(|s| {
        if s.is_pqc() {
            match s.to_u16() {
                0x0905 => 0, // ML-DSA-65 (PRIMARY) - IANA code
                0x0906 => 1, // ML-DSA-87 - IANA code
                0x0904 => 2, // ML-DSA-44 - IANA code
                _ => 3,
            }
        } else {
            99 // Non-PQC at end (shouldn't be present)
        }
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
    fn test_pure_pqc_negotiation() {
        let config = PqcConfig::builder().build().unwrap();
        let mut negotiator = PqcNegotiator::new(config);

        // v0.2: Set up with pure PQC algorithms ONLY
        negotiator.set_client_algorithms(
            vec![NamedGroup::MlKem768, NamedGroup::MlKem1024],
            vec![SignatureScheme::MlDsa65, SignatureScheme::MlDsa87],
        );

        negotiator.set_server_algorithms(
            vec![NamedGroup::MlKem768, NamedGroup::MlKem1024],
            vec![SignatureScheme::MlDsa65, SignatureScheme::MlDsa87],
        );

        let result = negotiator.negotiate();

        // Should select pure PQC algorithms
        assert!(result.used_pqc);
        // Should select one of the pure PQC groups
        assert!(matches!(
            result.key_exchange,
            Some(NamedGroup::MlKem768) | Some(NamedGroup::MlKem1024)
        ));
        // Should select one of the pure PQC signatures
        assert!(matches!(
            result.signature_scheme,
            Some(SignatureScheme::MlDsa65) | Some(SignatureScheme::MlDsa87)
        ));
        assert!(!negotiator.should_fail(&result));
    }

    #[test]
    fn test_negotiation_primary_algorithms() {
        let config = PqcConfig::builder().build().unwrap();
        let mut negotiator = PqcNegotiator::new(config);

        // v0.2: Both sides offer PRIMARY algorithms
        negotiator.set_client_algorithms(
            vec![NamedGroup::MlKem768],
            vec![SignatureScheme::MlDsa65],
        );

        negotiator.set_server_algorithms(
            vec![NamedGroup::MlKem768],
            vec![SignatureScheme::MlDsa65],
        );

        let result = negotiator.negotiate();

        // Should select PRIMARY algorithms
        assert!(result.used_pqc);
        assert_eq!(result.key_exchange, Some(NamedGroup::MlKem768));
        assert_eq!(result.signature_scheme, Some(SignatureScheme::MlDsa65));
        assert!(!negotiator.should_fail(&result));
    }

    #[test]
    fn test_negotiation_failure_no_common() {
        let config = PqcConfig::builder().build().unwrap();
        let mut negotiator = PqcNegotiator::new(config);

        // Disjoint sets of pure PQC algorithms
        negotiator.set_client_algorithms(
            vec![NamedGroup::MlKem512],
            vec![SignatureScheme::MlDsa44],
        );

        negotiator.set_server_algorithms(
            vec![NamedGroup::MlKem1024],
            vec![SignatureScheme::MlDsa87],
        );

        let result = negotiator.negotiate();

        // Should fail - no common PQC available
        assert!(!result.used_pqc);
        assert_eq!(result.key_exchange, None);
        assert_eq!(result.signature_scheme, None);
        assert!(negotiator.should_fail(&result));
    }

    #[test]
    fn test_no_algorithms() {
        let config = PqcConfig::default();
        let mut negotiator = PqcNegotiator::new(config);

        // Empty sets
        negotiator.set_client_algorithms(vec![], vec![]);
        negotiator.set_server_algorithms(vec![], vec![]);

        let result = negotiator.negotiate();

        // Should fail completely
        assert_eq!(result.key_exchange, None);
        assert_eq!(result.signature_scheme, None);
        assert!(!result.used_pqc);
        assert!(result.reason.contains("no common ground"));
    }

    #[test]
    fn test_filter_algorithms_pure_pqc() {
        let groups = vec![
            NamedGroup::MlKem512,
            NamedGroup::MlKem768,
            NamedGroup::MlKem1024,
        ];
        let signatures = vec![
            SignatureScheme::MlDsa44,
            SignatureScheme::MlDsa65,
            SignatureScheme::MlDsa87,
        ];

        let (filtered_groups, filtered_sigs) = filter_algorithms(&groups, &signatures);

        // v0.2: Should keep all pure PQC algorithms
        assert_eq!(filtered_groups.len(), 3);
        assert_eq!(filtered_sigs.len(), 3);
        assert!(filtered_groups.iter().all(|g| g.is_pqc()));
        assert!(filtered_sigs.iter().all(|s| s.is_pqc()));
    }

    #[test]
    fn test_order_by_preference_pure_pqc() {
        let mut groups = vec![
            NamedGroup::MlKem512,
            NamedGroup::MlKem1024,
            NamedGroup::MlKem768,
        ];
        let mut signatures = vec![
            SignatureScheme::MlDsa44,
            SignatureScheme::MlDsa87,
            SignatureScheme::MlDsa65,
        ];

        order_by_preference(&mut groups, &mut signatures);

        // v0.2: PRIMARY (Level 3) should be first
        assert_eq!(groups[0], NamedGroup::MlKem768);
        assert_eq!(signatures[0], SignatureScheme::MlDsa65);
    }

    #[test]
    fn test_debug_info() {
        let config = PqcConfig::default();
        let mut negotiator = PqcNegotiator::new(config);

        negotiator.set_client_algorithms(
            vec![NamedGroup::MlKem768],
            vec![SignatureScheme::MlDsa65],
        );
        negotiator.set_server_algorithms(
            vec![NamedGroup::MlKem768],
            vec![SignatureScheme::MlDsa65],
        );

        let debug_info = negotiator.debug_info();
        assert!(debug_info.contains("Client Groups"));
        assert!(debug_info.contains("Server Groups"));
        assert!(debug_info.contains("Common Groups"));
    }
}
