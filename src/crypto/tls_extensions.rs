//! TLS Extensions for RFC 7250 Raw Public Keys Certificate Type Negotiation
//!
//! This module implements the TLS 1.3 extensions defined in RFC 7250 Section 4.2:
//! - client_certificate_type (47): Client's certificate type preferences
//! - server_certificate_type (48): Server's certificate type preferences
//!
//! These extensions enable proper negotiation of certificate types during TLS handshake,
//! allowing clients and servers to indicate support for Raw Public Keys (value 2)
//! in addition to traditional X.509 certificates (value 0).

use std::{
    collections::HashMap,
    fmt::{self, Debug},
};

/// Certificate type values as defined in RFC 7250 and IANA registry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum CertificateType {
    /// X.509 certificate (traditional PKI certificates)
    X509 = 0,
    /// Raw Public Key (RFC 7250)
    RawPublicKey = 2,
}

impl CertificateType {
    /// Parse certificate type from wire format
    pub fn from_u8(value: u8) -> Result<Self, TlsExtensionError> {
        match value {
            0 => Ok(CertificateType::X509),
            2 => Ok(CertificateType::RawPublicKey),
            _ => Err(TlsExtensionError::UnsupportedCertificateType(value)),
        }
    }

    /// Convert certificate type to wire format
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Check if this certificate type is Raw Public Key
    pub fn is_raw_public_key(self) -> bool {
        matches!(self, CertificateType::RawPublicKey)
    }

    /// Check if this certificate type is X.509
    pub fn is_x509(self) -> bool {
        matches!(self, CertificateType::X509)
    }
}

impl fmt::Display for CertificateType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CertificateType::X509 => write!(f, "X.509"),
            CertificateType::RawPublicKey => write!(f, "RawPublicKey"),
        }
    }
}

/// Certificate type preference list for negotiation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateTypeList {
    /// Ordered list of certificate types by preference (most preferred first)
    pub types: Vec<CertificateType>,
}

impl CertificateTypeList {
    /// Create a new certificate type list
    pub fn new(types: Vec<CertificateType>) -> Result<Self, TlsExtensionError> {
        if types.is_empty() {
            return Err(TlsExtensionError::EmptyCertificateTypeList);
        }
        if types.len() > 255 {
            return Err(TlsExtensionError::CertificateTypeListTooLong(types.len()));
        }

        // Check for duplicates
        let mut seen = std::collections::HashSet::new();
        for cert_type in &types {
            if !seen.insert(*cert_type) {
                return Err(TlsExtensionError::DuplicateCertificateType(*cert_type));
            }
        }

        Ok(CertificateTypeList { types })
    }

    /// Create a Raw Public Key only preference list
    pub fn raw_public_key_only() -> Self {
        CertificateTypeList {
            types: vec![CertificateType::RawPublicKey],
        }
    }

    /// Create a preference list favoring Raw Public Keys with X.509 fallback
    pub fn prefer_raw_public_key() -> Self {
        CertificateTypeList {
            types: vec![CertificateType::RawPublicKey, CertificateType::X509],
        }
    }

    /// Create an X.509 only preference list
    pub fn x509_only() -> Self {
        CertificateTypeList {
            types: vec![CertificateType::X509],
        }
    }

    /// Get the most preferred certificate type
    pub fn most_preferred(&self) -> CertificateType {
        self.types[0]
    }

    /// Check if Raw Public Key is supported
    pub fn supports_raw_public_key(&self) -> bool {
        self.types.contains(&CertificateType::RawPublicKey)
    }

    /// Check if X.509 is supported
    pub fn supports_x509(&self) -> bool {
        self.types.contains(&CertificateType::X509)
    }

    /// Find the best common certificate type between two preference lists
    pub fn negotiate(&self, other: &CertificateTypeList) -> Option<CertificateType> {
        // Find the first certificate type in our preference list that is also supported by the other party
        for cert_type in &self.types {
            if other.types.contains(cert_type) {
                return Some(*cert_type);
            }
        }
        None
    }

    /// Serialize to wire format (length-prefixed list)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + self.types.len());
        bytes.push(self.types.len() as u8);
        for cert_type in &self.types {
            bytes.push(cert_type.to_u8());
        }
        bytes
    }

    /// Parse from wire format
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TlsExtensionError> {
        if bytes.is_empty() {
            return Err(TlsExtensionError::InvalidExtensionData(
                "Empty certificate type list".to_string(),
            ));
        }

        let length = bytes[0] as usize;
        if length == 0 {
            return Err(TlsExtensionError::EmptyCertificateTypeList);
        }
        if length > 255 {
            return Err(TlsExtensionError::CertificateTypeListTooLong(length));
        }
        if bytes.len() != 1 + length {
            return Err(TlsExtensionError::InvalidExtensionData(format!(
                "Certificate type list length mismatch: expected {}, got {}",
                1 + length,
                bytes.len()
            )));
        }

        let mut types = Vec::with_capacity(length);
        for i in 1..=length {
            let cert_type = CertificateType::from_u8(bytes[i])?;
            types.push(cert_type);
        }

        CertificateTypeList::new(types)
    }
}

/// TLS extension IDs for certificate type negotiation (RFC 7250)
pub mod extension_ids {
    /// Client certificate type extension ID
    pub const CLIENT_CERTIFICATE_TYPE: u16 = 47;
    /// Server certificate type extension ID  
    pub const SERVER_CERTIFICATE_TYPE: u16 = 48;
}

/// Errors that can occur during TLS extension processing
#[derive(Debug, Clone)]
pub enum TlsExtensionError {
    /// Unsupported certificate type value
    UnsupportedCertificateType(u8),
    /// Empty certificate type list
    EmptyCertificateTypeList,
    /// Certificate type list too long (>255 entries)
    CertificateTypeListTooLong(usize),
    /// Duplicate certificate type in list
    DuplicateCertificateType(CertificateType),
    /// Invalid extension data format
    InvalidExtensionData(String),
    /// Certificate type negotiation failed
    NegotiationFailed {
        client_types: CertificateTypeList,
        server_types: CertificateTypeList,
    },
    /// Extension already registered
    ExtensionAlreadyRegistered(u16),
    /// rustls integration error
    RustlsError(String),
}

impl fmt::Display for TlsExtensionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsExtensionError::UnsupportedCertificateType(value) => {
                write!(f, "Unsupported certificate type: {}", value)
            }
            TlsExtensionError::EmptyCertificateTypeList => {
                write!(f, "Certificate type list cannot be empty")
            }
            TlsExtensionError::CertificateTypeListTooLong(len) => {
                write!(f, "Certificate type list too long: {} (max 255)", len)
            }
            TlsExtensionError::DuplicateCertificateType(cert_type) => {
                write!(f, "Duplicate certificate type: {}", cert_type)
            }
            TlsExtensionError::InvalidExtensionData(msg) => {
                write!(f, "Invalid extension data: {}", msg)
            }
            TlsExtensionError::NegotiationFailed {
                client_types,
                server_types,
            } => {
                write!(
                    f,
                    "Certificate type negotiation failed: client={:?}, server={:?}",
                    client_types, server_types
                )
            }
            TlsExtensionError::ExtensionAlreadyRegistered(id) => {
                write!(f, "Extension already registered: {}", id)
            }
            TlsExtensionError::RustlsError(msg) => {
                write!(f, "rustls error: {}", msg)
            }
        }
    }
}

impl std::error::Error for TlsExtensionError {}

/// Certificate type negotiation result
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NegotiationResult {
    /// Negotiated client certificate type
    pub client_cert_type: CertificateType,
    /// Negotiated server certificate type
    pub server_cert_type: CertificateType,
}

impl NegotiationResult {
    /// Create a new negotiation result
    pub fn new(client_cert_type: CertificateType, server_cert_type: CertificateType) -> Self {
        Self {
            client_cert_type,
            server_cert_type,
        }
    }

    /// Check if Raw Public Keys are used for both client and server
    pub fn is_raw_public_key_only(&self) -> bool {
        self.client_cert_type.is_raw_public_key() && self.server_cert_type.is_raw_public_key()
    }

    /// Check if X.509 certificates are used for both client and server
    pub fn is_x509_only(&self) -> bool {
        self.client_cert_type.is_x509() && self.server_cert_type.is_x509()
    }

    /// Check if this is a mixed deployment (one RPK, one X.509)
    pub fn is_mixed(&self) -> bool {
        !self.is_raw_public_key_only() && !self.is_x509_only()
    }
}

/// Certificate type negotiation preferences and state
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateTypePreferences {
    /// Client certificate type preferences (what types we support for client auth)
    pub client_types: CertificateTypeList,
    /// Server certificate type preferences (what types we support for server auth)
    pub server_types: CertificateTypeList,
    /// Whether to require certificate type extensions (strict mode)
    pub require_extensions: bool,
    /// Default fallback certificate types if negotiation fails
    pub fallback_client: CertificateType,
    pub fallback_server: CertificateType,
}

impl CertificateTypePreferences {
    /// Create preferences favoring Raw Public Keys
    pub fn prefer_raw_public_key() -> Self {
        Self {
            client_types: CertificateTypeList::prefer_raw_public_key(),
            server_types: CertificateTypeList::prefer_raw_public_key(),
            require_extensions: false,
            fallback_client: CertificateType::X509,
            fallback_server: CertificateType::X509,
        }
    }

    /// Create preferences for Raw Public Key only
    pub fn raw_public_key_only() -> Self {
        Self {
            client_types: CertificateTypeList::raw_public_key_only(),
            server_types: CertificateTypeList::raw_public_key_only(),
            require_extensions: true,
            fallback_client: CertificateType::RawPublicKey,
            fallback_server: CertificateType::RawPublicKey,
        }
    }

    /// Create preferences for X.509 only (legacy mode)
    pub fn x509_only() -> Self {
        Self {
            client_types: CertificateTypeList::x509_only(),
            server_types: CertificateTypeList::x509_only(),
            require_extensions: false,
            fallback_client: CertificateType::X509,
            fallback_server: CertificateType::X509,
        }
    }

    /// Negotiate certificate types with remote peer preferences
    pub fn negotiate(
        &self,
        remote_client_types: Option<&CertificateTypeList>,
        remote_server_types: Option<&CertificateTypeList>,
    ) -> Result<NegotiationResult, TlsExtensionError> {
        let client_cert_type = if let Some(remote_types) = remote_client_types {
            self.client_types.negotiate(remote_types).ok_or_else(|| {
                TlsExtensionError::NegotiationFailed {
                    client_types: self.client_types.clone(),
                    server_types: remote_types.clone(),
                }
            })?
        } else if self.require_extensions {
            return Err(TlsExtensionError::NegotiationFailed {
                client_types: self.client_types.clone(),
                server_types: CertificateTypeList::x509_only(),
            });
        } else {
            self.fallback_client
        };

        let server_cert_type = if let Some(remote_types) = remote_server_types {
            self.server_types.negotiate(remote_types).ok_or_else(|| {
                TlsExtensionError::NegotiationFailed {
                    client_types: self.server_types.clone(),
                    server_types: remote_types.clone(),
                }
            })?
        } else if self.require_extensions {
            return Err(TlsExtensionError::NegotiationFailed {
                client_types: self.server_types.clone(),
                server_types: CertificateTypeList::x509_only(),
            });
        } else {
            self.fallback_server
        };

        Ok(NegotiationResult::new(client_cert_type, server_cert_type))
    }
}

impl Default for CertificateTypePreferences {
    fn default() -> Self {
        Self::prefer_raw_public_key()
    }
}

/// Certificate type negotiation cache for performance optimization
#[derive(Debug)]
pub struct NegotiationCache {
    /// Cache of negotiation results keyed by (local_prefs, remote_prefs) hash
    cache: HashMap<u64, NegotiationResult>,
    /// Maximum cache size to prevent unbounded growth
    max_size: usize,
}

impl NegotiationCache {
    /// Create a new negotiation cache
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: HashMap::with_capacity(max_size.min(1000)),
            max_size,
        }
    }

    /// Get cached negotiation result
    pub fn get(&self, key: u64) -> Option<&NegotiationResult> {
        self.cache.get(&key)
    }

    /// Cache a negotiation result
    pub fn insert(&mut self, key: u64, result: NegotiationResult) {
        if self.cache.len() >= self.max_size {
            // Simple eviction: remove oldest entry (first in iteration order)
            if let Some(oldest_key) = self.cache.keys().next().copied() {
                self.cache.remove(&oldest_key);
            }
        }
        self.cache.insert(key, result);
    }

    /// Clear the cache
    pub fn clear(&mut self) {
        self.cache.clear();
    }

    /// Get cache statistics
    pub fn stats(&self) -> (usize, usize) {
        (self.cache.len(), self.max_size)
    }
}

impl Default for NegotiationCache {
    fn default() -> Self {
        Self::new(1000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_type_conversion() {
        assert_eq!(CertificateType::X509.to_u8(), 0);
        assert_eq!(CertificateType::RawPublicKey.to_u8(), 2);

        assert_eq!(CertificateType::from_u8(0).unwrap(), CertificateType::X509);
        assert_eq!(
            CertificateType::from_u8(2).unwrap(),
            CertificateType::RawPublicKey
        );

        assert!(CertificateType::from_u8(1).is_err());
        assert!(CertificateType::from_u8(255).is_err());
    }

    #[test]
    fn test_certificate_type_list_creation() {
        let list =
            CertificateTypeList::new(vec![CertificateType::RawPublicKey, CertificateType::X509])
                .unwrap();
        assert_eq!(list.types.len(), 2);
        assert_eq!(list.most_preferred(), CertificateType::RawPublicKey);
        assert!(list.supports_raw_public_key());
        assert!(list.supports_x509());

        // Test empty list error
        assert!(CertificateTypeList::new(vec![]).is_err());

        // Test duplicate error
        assert!(
            CertificateTypeList::new(vec![CertificateType::X509, CertificateType::X509]).is_err()
        );
    }

    #[test]
    fn test_certificate_type_list_serialization() {
        let list = CertificateTypeList::prefer_raw_public_key();
        let bytes = list.to_bytes();
        assert_eq!(bytes, vec![2, 2, 0]); // length=2, RPK=2, X509=0

        let parsed = CertificateTypeList::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, list);
    }

    #[test]
    fn test_certificate_type_list_negotiation() {
        let rpk_only = CertificateTypeList::raw_public_key_only();
        let prefer_rpk = CertificateTypeList::prefer_raw_public_key();
        let x509_only = CertificateTypeList::x509_only();

        // RPK only with prefer RPK should negotiate to RPK
        assert_eq!(
            rpk_only.negotiate(&prefer_rpk).unwrap(),
            CertificateType::RawPublicKey
        );

        // Prefer RPK with X509 only should negotiate to X509
        assert_eq!(
            prefer_rpk.negotiate(&x509_only).unwrap(),
            CertificateType::X509
        );

        // RPK only with X509 only should fail
        assert!(rpk_only.negotiate(&x509_only).is_none());
    }

    #[test]
    fn test_preferences_negotiation() {
        let rpk_prefs = CertificateTypePreferences::raw_public_key_only();
        let mixed_prefs = CertificateTypePreferences::prefer_raw_public_key();

        let result = rpk_prefs
            .negotiate(
                Some(&mixed_prefs.client_types),
                Some(&mixed_prefs.server_types),
            )
            .unwrap();

        assert_eq!(result.client_cert_type, CertificateType::RawPublicKey);
        assert_eq!(result.server_cert_type, CertificateType::RawPublicKey);
        assert!(result.is_raw_public_key_only());
    }

    #[test]
    fn test_negotiation_cache() {
        let mut cache = NegotiationCache::new(2);
        let result = NegotiationResult::new(CertificateType::RawPublicKey, CertificateType::X509);

        assert!(cache.get(123).is_none());

        cache.insert(123, result.clone());
        assert_eq!(cache.get(123).unwrap(), &result);

        // Test that cache size is limited
        cache.insert(456, result.clone());
        assert_eq!(cache.cache.len(), 2); // Should have 2 entries

        cache.insert(789, result.clone());
        assert_eq!(cache.cache.len(), 2); // Should still have 2 entries after eviction

        // At least one of the new entries should be present
        assert!(cache.get(456).is_some() || cache.get(789).is_some());
    }
}
