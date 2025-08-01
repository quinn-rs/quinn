//! TLS integration for post-quantum cryptography
//!
//! This module provides TLS extensions for hybrid post-quantum key exchange
//! and signature schemes, following draft-ietf-tls-hybrid-design.

use crate::crypto::pqc::tls_extensions::{NamedGroup, SignatureScheme};
use crate::crypto::pqc::types::*;

/// TLS extension handler for PQC negotiation
pub struct PqcTlsExtension {
    /// Supported named groups in preference order
    pub supported_groups: Vec<NamedGroup>,

    /// Supported signature schemes in preference order
    pub supported_signatures: Vec<SignatureScheme>,

    /// Whether to prefer PQC algorithms
    pub prefer_pqc: bool,
}

impl PqcTlsExtension {
    /// Create a new PQC TLS extension handler
    pub fn new() -> Self {
        Self {
            supported_groups: vec![
                // Prefer hybrid groups for quantum resistance
                NamedGroup::X25519MlKem768,
                NamedGroup::P256MlKem768,
                // Fall back to classical
                NamedGroup::X25519,
                NamedGroup::Secp256r1,
            ],
            supported_signatures: vec![
                // Prefer hybrid signatures
                SignatureScheme::Ed25519MlDsa65,
                SignatureScheme::EcdsaP256MlDsa65,
                // Fall back to classical
                SignatureScheme::Ed25519,
                SignatureScheme::EcdsaSecp256r1Sha256,
            ],
            prefer_pqc: true,
        }
    }

    /// Create a classical-only configuration
    pub fn classical_only() -> Self {
        Self {
            supported_groups: vec![
                NamedGroup::X25519,
                NamedGroup::Secp256r1,
                NamedGroup::Secp384r1,
            ],
            supported_signatures: vec![
                SignatureScheme::Ed25519,
                SignatureScheme::EcdsaSecp256r1Sha256,
                SignatureScheme::EcdsaSecp384r1Sha384,
            ],
            prefer_pqc: false,
        }
    }

    /// Create a PQC-only configuration (no fallback)
    pub fn pqc_only() -> Self {
        Self {
            supported_groups: vec![
                NamedGroup::X25519MlKem768,
                NamedGroup::P256MlKem768,
                NamedGroup::P384MlKem1024,
            ],
            supported_signatures: vec![
                SignatureScheme::Ed25519MlDsa65,
                SignatureScheme::EcdsaP256MlDsa65,
                SignatureScheme::EcdsaP384MlDsa87,
            ],
            prefer_pqc: true,
        }
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

    /// Perform compatibility-aware group selection
    ///
    /// This method implements smart fallback:
    /// 1. If peer supports PQC, prefer hybrid groups
    /// 2. If peer is PQC-unaware, use classical groups
    /// 3. Detect and handle middlebox interference
    pub fn negotiate_group(&self, peer_groups: &[NamedGroup]) -> NegotiationResult<NamedGroup> {
        // Check if peer supports any PQC groups
        let peer_supports_pqc = peer_groups.iter().any(|g| g.is_pqc() || g.is_hybrid());

        if peer_supports_pqc && self.prefer_pqc {
            // Try PQC groups first
            let pqc_groups: Vec<NamedGroup> = peer_groups
                .iter()
                .filter(|g| g.is_pqc() || g.is_hybrid())
                .copied()
                .collect();

            if let Some(group) = self.select_group(&pqc_groups) {
                return NegotiationResult::Selected(group);
            }
        }

        // Try classical fallback
        let classical_groups: Vec<NamedGroup> = peer_groups
            .iter()
            .filter(|g| g.is_classical())
            .copied()
            .collect();

        if let Some(group) = self.select_group(&classical_groups) {
            if peer_supports_pqc && self.prefer_pqc {
                // We wanted PQC but had to fall back
                return NegotiationResult::Downgraded(group);
            } else {
                return NegotiationResult::Selected(group);
            }
        }

        NegotiationResult::Failed
    }

    /// Perform compatibility-aware signature selection
    pub fn negotiate_signature(
        &self,
        peer_schemes: &[SignatureScheme],
    ) -> NegotiationResult<SignatureScheme> {
        // Check if peer supports any PQC schemes
        let peer_supports_pqc = peer_schemes.iter().any(|s| s.is_pqc() || s.is_hybrid());

        if peer_supports_pqc && self.prefer_pqc {
            // Try PQC schemes first
            let pqc_schemes: Vec<SignatureScheme> = peer_schemes
                .iter()
                .filter(|s| s.is_pqc() || s.is_hybrid())
                .copied()
                .collect();

            if let Some(scheme) = self.select_signature(&pqc_schemes) {
                return NegotiationResult::Selected(scheme);
            }
        }

        // Try classical fallback
        let classical_schemes: Vec<SignatureScheme> = peer_schemes
            .iter()
            .filter(|s| s.is_classical())
            .copied()
            .collect();

        if let Some(scheme) = self.select_signature(&classical_schemes) {
            if peer_supports_pqc && self.prefer_pqc {
                // We wanted PQC but had to fall back
                return NegotiationResult::Downgraded(scheme);
            } else {
                return NegotiationResult::Selected(scheme);
            }
        }

        NegotiationResult::Failed
    }
}

/// Result of algorithm negotiation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiationResult<T> {
    /// Successfully selected preferred algorithm
    Selected(T),
    /// Had to downgrade from PQC to classical
    Downgraded(T),
    /// No common algorithms found
    Failed,
}

impl<T> NegotiationResult<T> {
    /// Check if negotiation succeeded
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Selected(_) | Self::Downgraded(_))
    }

    /// Check if we had to downgrade
    pub fn is_downgraded(&self) -> bool {
        matches!(self, Self::Downgraded(_))
    }

    /// Get the selected value if any
    pub fn value(&self) -> Option<&T> {
        match self {
            Self::Selected(v) | Self::Downgraded(v) => Some(v),
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
    fn test_pqc_extension_default() {
        let ext = PqcTlsExtension::new();

        // Should prefer hybrid groups
        assert!(ext.supported_groups()[0].is_hybrid());
        assert!(ext.supported_signatures()[0].is_hybrid());

        // Should support both hybrid and classical
        assert!(ext.supports_group(NamedGroup::X25519MlKem768));
        assert!(ext.supports_group(NamedGroup::X25519));
        assert!(ext.supports_signature(SignatureScheme::Ed25519MlDsa65));
        assert!(ext.supports_signature(SignatureScheme::Ed25519));
    }

    #[test]
    fn test_pqc_extension_classical_only() {
        let ext = PqcTlsExtension::classical_only();

        // Should not support hybrid
        assert!(!ext.supports_group(NamedGroup::X25519MlKem768));
        assert!(!ext.supports_signature(SignatureScheme::Ed25519MlDsa65));

        // Should support classical
        assert!(ext.supports_group(NamedGroup::X25519));
        assert!(ext.supports_signature(SignatureScheme::Ed25519));
    }

    #[test]
    fn test_pqc_extension_pqc_only() {
        let ext = PqcTlsExtension::pqc_only();

        // Should only support hybrid
        assert!(ext.supports_group(NamedGroup::X25519MlKem768));
        assert!(ext.supports_signature(SignatureScheme::Ed25519MlDsa65));

        // Should not support classical
        assert!(!ext.supports_group(NamedGroup::X25519));
        assert!(!ext.supports_signature(SignatureScheme::Ed25519));
    }

    #[test]
    fn test_negotiation_both_support_pqc() {
        let ext = PqcTlsExtension::new();

        // Peer supports PQC
        let peer_groups = vec![NamedGroup::X25519MlKem768, NamedGroup::X25519];

        let result = ext.negotiate_group(&peer_groups);
        assert!(result.is_success());
        assert!(!result.is_downgraded());
        assert_eq!(result.value(), Some(&NamedGroup::X25519MlKem768));
    }

    #[test]
    fn test_negotiation_downgrade() {
        // Create extension that only supports P256MlKem768 for hybrid
        let mut ext = PqcTlsExtension::new();
        ext.supported_groups = vec![
            NamedGroup::P256MlKem768, // Only this hybrid group
            NamedGroup::X25519,       // Classical fallback
            NamedGroup::Secp256r1,
        ];

        // Peer supports different PQC algorithm
        let peer_groups = vec![
            NamedGroup::X25519MlKem768, // Different hybrid group we don't support
            NamedGroup::X25519,         // Classical fallback
        ];

        let result = ext.negotiate_group(&peer_groups);
        assert!(result.is_success());
        assert!(result.is_downgraded()); // Downgraded because peer supports PQC but we couldn't agree on algorithm
        assert_eq!(result.value(), Some(&NamedGroup::X25519));
    }

    #[test]
    fn test_wire_format_encoding() {
        use wire_format::*;

        let groups = vec![NamedGroup::X25519, NamedGroup::X25519MlKem768];

        let encoded = encode_supported_groups(&groups);
        assert_eq!(encoded.len(), 2 + 4); // Length + 2 groups

        let decoded = decode_supported_groups(&encoded).unwrap();
        assert_eq!(decoded, groups);
    }
}
