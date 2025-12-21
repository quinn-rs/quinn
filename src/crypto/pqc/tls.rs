// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! TLS integration for Pure Post-Quantum Cryptography
//!
//! v0.2: Pure PQC - NO hybrid or classical algorithms.
//!
//! This module provides TLS extensions for pure PQC key exchange and signatures:
//! - Key Exchange: ML-KEM-768 (0x0201) ONLY
//! - Signatures: ML-DSA-65 (IANA 0x0905) ONLY
//!
//! This is a greenfield network with no legacy compatibility requirements.

use crate::crypto::pqc::tls_extensions::{NamedGroup, SignatureScheme};
use crate::crypto::pqc::types::*;

/// TLS extension handler for Pure PQC negotiation
///
/// v0.2: Pure PQC is always enabled. NO hybrid or classical algorithms.
pub struct PqcTlsExtension {
    /// Supported named groups in preference order (pure ML-KEM only)
    pub supported_groups: Vec<NamedGroup>,

    /// Supported signature schemes in preference order (pure ML-DSA only)
    pub supported_signatures: Vec<SignatureScheme>,
}

impl PqcTlsExtension {
    /// Create a new Pure PQC TLS extension handler
    ///
    /// v0.2: ONLY pure PQC algorithms. NO hybrids, NO classical fallback.
    pub fn new() -> Self {
        Self {
            supported_groups: vec![
                // Pure ML-KEM ONLY - ordered by preference (Level 3 first)
                NamedGroup::MlKem768,  // PRIMARY - NIST Level 3
                NamedGroup::MlKem1024, // NIST Level 5
                NamedGroup::MlKem512,  // NIST Level 1
            ],
            supported_signatures: vec![
                // Pure ML-DSA ONLY - ordered by preference (Level 3 first)
                SignatureScheme::MlDsa65, // PRIMARY - NIST Level 3
                SignatureScheme::MlDsa87, // NIST Level 5
                SignatureScheme::MlDsa44, // NIST Level 2
            ],
        }
    }

    /// Alias for new() - pure PQC is the only mode
    ///
    /// v0.2: This method is kept for API compatibility.
    /// Both new() and pqc_only() return the same pure PQC configuration.
    pub fn pqc_only() -> Self {
        Self::new()
    }

    /// Get supported named groups for TLS negotiation
    pub fn supported_groups(&self) -> &[NamedGroup] {
        &self.supported_groups
    }

    /// Get supported signature schemes for TLS negotiation
    pub fn supported_signatures(&self) -> &[SignatureScheme] {
        &self.supported_signatures
    }

    /// Select the best named group from peer's list
    pub fn select_group(&self, peer_groups: &[NamedGroup]) -> Option<NamedGroup> {
        // Find first match in our preference order
        self.supported_groups
            .iter()
            .find(|&&our_group| peer_groups.contains(&our_group))
            .copied()
    }

    /// Select the best signature scheme from peer's list
    pub fn select_signature(&self, peer_schemes: &[SignatureScheme]) -> Option<SignatureScheme> {
        // Find first match in our preference order
        self.supported_signatures
            .iter()
            .find(|&&our_scheme| peer_schemes.contains(&our_scheme))
            .copied()
    }

    /// Check if a named group is supported
    pub fn supports_group(&self, group: NamedGroup) -> bool {
        self.supported_groups.contains(&group)
    }

    /// Check if a signature scheme is supported
    pub fn supports_signature(&self, scheme: SignatureScheme) -> bool {
        self.supported_signatures.contains(&scheme)
    }

    /// Negotiate key exchange group (v0.2: Pure PQC ONLY)
    ///
    /// Selects the first mutually supported pure ML-KEM group.
    /// Classical and hybrid groups are NOT accepted.
    pub fn negotiate_group(&self, peer_groups: &[NamedGroup]) -> NegotiationResult<NamedGroup> {
        // v0.2: ONLY accept pure PQC groups
        let pqc_groups: Vec<NamedGroup> =
            peer_groups.iter().filter(|g| g.is_pqc()).copied().collect();

        if let Some(group) = self.select_group(&pqc_groups) {
            return NegotiationResult::Selected(group);
        }

        // v0.2: No classical fallback - fail if no pure PQC
        NegotiationResult::Failed
    }

    /// Negotiate signature scheme (v0.2: Pure PQC ONLY)
    ///
    /// Selects the first mutually supported pure ML-DSA scheme.
    /// Classical and hybrid schemes are NOT accepted.
    pub fn negotiate_signature(
        &self,
        peer_schemes: &[SignatureScheme],
    ) -> NegotiationResult<SignatureScheme> {
        // v0.2: ONLY accept pure PQC schemes
        let pqc_schemes: Vec<SignatureScheme> = peer_schemes
            .iter()
            .filter(|s| s.is_pqc())
            .copied()
            .collect();

        if let Some(scheme) = self.select_signature(&pqc_schemes) {
            return NegotiationResult::Selected(scheme);
        }

        // v0.2: No classical fallback - fail if no pure PQC
        NegotiationResult::Failed
    }
}

/// Result of algorithm negotiation
///
/// v0.2: Simplified - no Downgraded variant since we don't have fallbacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiationResult<T> {
    /// Successfully selected a pure PQC algorithm
    Selected(T),
    /// No common pure PQC algorithms found
    Failed,
}

impl<T> NegotiationResult<T> {
    /// Check if negotiation succeeded
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Selected(_))
    }

    /// Get the selected value if any
    pub fn value(&self) -> Option<&T> {
        match self {
            Self::Selected(v) => Some(v),
            Self::Failed => None,
        }
    }
}

impl Default for PqcTlsExtension {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert between TLS wire format and internal types
pub mod wire_format {
    use super::*;

    /// Encode supported groups extension
    pub fn encode_supported_groups(groups: &[NamedGroup]) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(2 + groups.len() * 2);

        // Length prefix (2 bytes)
        let len = (groups.len() * 2) as u16;
        encoded.extend_from_slice(&len.to_be_bytes());

        // Group codepoints
        for group in groups {
            encoded.extend_from_slice(&group.to_bytes());
        }

        encoded
    }

    /// Decode supported groups extension
    pub fn decode_supported_groups(data: &[u8]) -> Result<Vec<NamedGroup>, PqcError> {
        if data.len() < 2 {
            return Err(PqcError::InvalidKeySize {
                expected: 2,
                actual: data.len(),
            });
        }

        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() != 2 + len {
            return Err(PqcError::InvalidKeySize {
                expected: 2 + len,
                actual: data.len(),
            });
        }

        let mut groups = Vec::new();
        let mut offset = 2;

        while offset + 2 <= data.len() {
            match NamedGroup::from_bytes(&data[offset..offset + 2]) {
                Ok(group) => groups.push(group),
                Err(_) => {} // Skip unknown groups silently (per TLS spec)
            }
            offset += 2;
        }

        Ok(groups)
    }

    /// Encode signature algorithms extension
    pub fn encode_signature_schemes(schemes: &[SignatureScheme]) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(2 + schemes.len() * 2);

        // Length prefix (2 bytes)
        let len = (schemes.len() * 2) as u16;
        encoded.extend_from_slice(&len.to_be_bytes());

        // Scheme codepoints
        for scheme in schemes {
            encoded.extend_from_slice(&scheme.to_bytes());
        }

        encoded
    }

    /// Decode signature algorithms extension
    pub fn decode_signature_schemes(data: &[u8]) -> Result<Vec<SignatureScheme>, PqcError> {
        if data.len() < 2 {
            return Err(PqcError::InvalidSignatureSize {
                expected: 2,
                actual: data.len(),
            });
        }

        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() != 2 + len {
            return Err(PqcError::InvalidSignatureSize {
                expected: 2 + len,
                actual: data.len(),
            });
        }

        let mut schemes = Vec::new();
        let mut offset = 2;

        while offset + 2 <= data.len() {
            match SignatureScheme::from_bytes(&data[offset..offset + 2]) {
                Ok(scheme) => schemes.push(scheme),
                Err(_) => {} // Skip unknown schemes silently (per TLS spec)
            }
            offset += 2;
        }

        Ok(schemes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pqc_extension_default_pure_pqc() {
        let ext = PqcTlsExtension::new();

        // v0.2: Should only have pure PQC groups
        assert!(ext.supported_groups()[0].is_pqc());
        assert!(ext.supported_signatures()[0].is_pqc());

        // Should have ML-KEM-768 as first (PRIMARY)
        assert_eq!(ext.supported_groups()[0], NamedGroup::MlKem768);
        assert_eq!(ext.supported_signatures()[0], SignatureScheme::MlDsa65);

        // Should support pure PQC
        assert!(ext.supports_group(NamedGroup::MlKem768));
        assert!(ext.supports_group(NamedGroup::MlKem1024));
        assert!(ext.supports_signature(SignatureScheme::MlDsa65));
        assert!(ext.supports_signature(SignatureScheme::MlDsa87));
    }

    #[test]
    fn test_pqc_extension_pqc_only_same_as_new() {
        let ext1 = PqcTlsExtension::new();
        let ext2 = PqcTlsExtension::pqc_only();

        // v0.2: Both should return the same pure PQC configuration
        assert_eq!(ext1.supported_groups, ext2.supported_groups);
        assert_eq!(ext1.supported_signatures, ext2.supported_signatures);
    }

    #[test]
    fn test_negotiation_both_support_pure_pqc() {
        let ext = PqcTlsExtension::new();

        // v0.2: Peer supports pure PQC
        let peer_groups = vec![NamedGroup::MlKem768, NamedGroup::MlKem1024];

        let result = ext.negotiate_group(&peer_groups);
        assert!(result.is_success());
        assert_eq!(result.value(), Some(&NamedGroup::MlKem768));
    }

    #[test]
    fn test_negotiation_fails_no_pqc() {
        let ext = PqcTlsExtension::new();

        // v0.2: Peer has no pure PQC groups - should fail (no classical fallback)
        let peer_groups: Vec<NamedGroup> = vec![];

        let result = ext.negotiate_group(&peer_groups);
        assert!(!result.is_success());
        assert_eq!(result.value(), None);
    }

    #[test]
    fn test_negotiation_signature_pure_pqc() {
        let ext = PqcTlsExtension::new();

        // v0.2: Peer supports pure PQC signatures
        let peer_schemes = vec![SignatureScheme::MlDsa65, SignatureScheme::MlDsa87];

        let result = ext.negotiate_signature(&peer_schemes);
        assert!(result.is_success());
        assert_eq!(result.value(), Some(&SignatureScheme::MlDsa65));
    }

    #[test]
    fn test_wire_format_encoding_pure_pqc() {
        use wire_format::*;

        // v0.2: Use pure PQC groups
        let groups = vec![NamedGroup::MlKem768, NamedGroup::MlKem1024];

        let encoded = encode_supported_groups(&groups);
        assert_eq!(encoded.len(), 2 + 4); // Length + 2 groups

        let decoded = decode_supported_groups(&encoded).unwrap();
        assert_eq!(decoded, groups);
    }

    #[test]
    fn test_wire_format_signature_schemes() {
        use wire_format::*;

        // v0.2: Use pure PQC signatures
        let schemes = vec![SignatureScheme::MlDsa65, SignatureScheme::MlDsa87];

        let encoded = encode_signature_schemes(&schemes);
        assert_eq!(encoded.len(), 2 + 4); // Length + 2 schemes

        let decoded = decode_signature_schemes(&encoded).unwrap();
        assert_eq!(decoded, schemes);
    }
}
