// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses


//! TLS Extension Handling
//!
//! This module implements TLS extension handling for certificate type negotiation
//! as specified in RFC 7250. It focuses on the minimal set of extensions needed
//! for raw public key authentication.

use std::sync::Arc;
use thiserror::Error;

/// Errors that can occur during TLS extension handling
#[derive(Debug, Error)]
pub enum TlsExtensionError {
    #[error("Unsupported certificate type")]
    UnsupportedCertificateType,
    
    #[error("Extension encoding error: {0}")]
    EncodingError(String),
    
    #[error("Extension decoding error: {0}")]
    DecodingError(String),
}

/// Certificate types as defined in RFC 7250
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateType {
    /// X.509 certificate
    X509 = 0,
    /// Raw public key
    RawPublicKey = 2,
}

/// Handler for certificate type negotiation
pub struct CertificateTypeHandler {
    // Supported certificate types in order of preference
    supported_types: Vec<CertificateType>,
}

impl CertificateTypeHandler {
    /// Create a new handler with the specified supported types
    pub fn new(supported_types: Vec<CertificateType>) -> Self {
        Self { supported_types }
    }
    
    /// Create a handler that only supports raw public keys
    pub fn raw_public_key_only() -> Self {
        Self {
            supported_types: vec![CertificateType::RawPublicKey],
        }
    }
    
    /// Get the supported certificate types
    pub fn supported_types(&self) -> &[CertificateType] {
        &self.supported_types
    }
}

// Implementation of TLS extension handling
// (Placeholder - actual implementation would go here)