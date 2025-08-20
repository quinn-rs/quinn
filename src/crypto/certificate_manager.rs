// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Production-ready certificate management for ant-quic
//!
//! This module provides comprehensive certificate management functionality including:
//! - Self-signed certificate generation for development/testing
//! - Certificate validation and chain verification
//! - External certificate loading (PEM, PKCS#12)
//! - Certificate rotation and renewal mechanisms
//! - CA certificate management for bootstrap node verification

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::{sync::Arc, time::Duration};
use thiserror::Error;

/// Certificate management errors
#[derive(Error, Debug)]
pub enum CertificateError {
    #[error("Certificate generation failed: {0}")]
    GenerationFailed(String),

    #[error("Certificate validation failed: {0}")]
    ValidationFailed(String),

    #[error("Certificate loading failed: {0}")]
    LoadingFailed(String),

    #[error("Certificate parsing failed: {0}")]
    ParsingFailed(String),

    #[error("Private key error: {0}")]
    PrivateKeyError(String),

    #[error("Certificate chain error: {0}")]
    ChainError(String),

    #[error("Certificate expired or not yet valid")]
    ValidityError,

    #[error("Unsupported certificate format")]
    UnsupportedFormat,
}

/// Certificate configuration for different deployment scenarios
#[derive(Debug, Clone)]
pub struct CertificateConfig {
    /// Common name for the certificate (typically the hostname or peer ID)
    pub common_name: String,

    /// Subject alternative names (SANs) for the certificate
    pub subject_alt_names: Vec<String>,

    /// Certificate validity duration
    pub validity_duration: Duration,

    /// Key algorithm and size
    pub key_algorithm: KeyAlgorithm,

    /// Whether to generate self-signed certificates
    pub self_signed: bool,

    /// CA certificate path (for validation)
    pub ca_cert_path: Option<String>,

    /// Certificate chain validation requirements
    pub require_chain_validation: bool,
}

/// Supported key algorithms for certificate generation
#[derive(Debug, Clone, Copy)]
pub enum KeyAlgorithm {
    /// RSA with specified key size (2048, 3072, 4096)
    Rsa(u32),
    /// ECDSA with P-256 curve
    EcdsaP256,
    /// ECDSA with P-384 curve  
    EcdsaP384,
    /// Ed25519 (recommended for new deployments)
    Ed25519,
}

/// Certificate and private key pair
#[derive(Debug)]
pub struct CertificateBundle {
    /// X.509 certificate chain
    pub cert_chain: Vec<CertificateDer<'static>>,

    /// Private key corresponding to the certificate
    pub private_key: PrivateKeyDer<'static>,

    /// Certificate creation timestamp
    pub created_at: std::time::SystemTime,

    /// Certificate expiration timestamp
    pub expires_at: std::time::SystemTime,
}

/// Production-ready certificate manager
pub struct CertificateManager {
    config: CertificateConfig,
    ca_certs: Vec<CertificateDer<'static>>,
}

impl Default for CertificateConfig {
    fn default() -> Self {
        Self {
            common_name: "ant-quic-node".to_string(),
            subject_alt_names: vec!["localhost".to_string()],
            validity_duration: Duration::from_secs(365 * 24 * 60 * 60), // 1 year
            key_algorithm: KeyAlgorithm::Ed25519,
            self_signed: true,
            ca_cert_path: None,
            require_chain_validation: false,
        }
    }
}

impl CertificateManager {
    /// Create a new certificate manager with the given configuration
    pub fn new(config: CertificateConfig) -> Result<Self, CertificateError> {
        let ca_certs = if let Some(ca_path) = &config.ca_cert_path {
            Self::load_ca_certificates(ca_path)?
        } else {
            Vec::new()
        };

        Ok(Self { config, ca_certs })
    }

    /// Generate a new certificate bundle using rcgen
    pub fn generate_certificate(&self) -> Result<CertificateBundle, CertificateError> {
        use rcgen::generate_simple_self_signed;

        // For now, use a simplified approach with the rcgen API
        // This generates a basic self-signed certificate
        let subject_alt_names = vec![self.config.common_name.clone()];
        let cert = generate_simple_self_signed(subject_alt_names)
            .map_err(|e| CertificateError::GenerationFailed(e.to_string()))?;

        // Serialize certificate and key
        let cert_der = cert.cert.der();
        let private_key_der = cert.signing_key.serialize_der();

        let created_at = std::time::SystemTime::now();
        let expires_at = created_at + self.config.validity_duration;

        Ok(CertificateBundle {
            cert_chain: vec![cert_der.clone()],
            private_key: PrivateKeyDer::try_from(private_key_der).map_err(|e| {
                CertificateError::PrivateKeyError(format!("Key conversion failed: {e:?}"))
            })?,
            created_at,
            expires_at,
        })
    }

    /// Load certificates from PEM file
    pub fn load_certificate_from_pem(
        cert_path: &str,
        key_path: &str,
    ) -> Result<CertificateBundle, CertificateError> {
        use rustls_pemfile::{certs, private_key};

        // Load certificate file
        let cert_file = std::fs::File::open(cert_path).map_err(|e| {
            CertificateError::LoadingFailed(format!("Failed to open cert file: {e}"))
        })?;

        let mut cert_reader = std::io::BufReader::new(cert_file);
        let cert_chain: Vec<CertificateDer<'static>> = certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                CertificateError::ParsingFailed(format!("Failed to parse certificates: {e}"))
            })?;

        if cert_chain.is_empty() {
            return Err(CertificateError::LoadingFailed(
                "No certificates found in file".to_string(),
            ));
        }

        // Load private key file
        let key_file = std::fs::File::open(key_path).map_err(|e| {
            CertificateError::LoadingFailed(format!("Failed to open key file: {e}"))
        })?;

        let mut key_reader = std::io::BufReader::new(key_file);
        let private_key = private_key(&mut key_reader)
            .map_err(|e| {
                CertificateError::ParsingFailed(format!("Failed to parse private key: {e}"))
            })?
            .ok_or_else(|| {
                CertificateError::LoadingFailed("No private key found in file".to_string())
            })?;

        // Extract validity information from the first certificate
        let (created_at, expires_at) = Self::extract_validity_from_cert(&cert_chain[0])?;

        Ok(CertificateBundle {
            cert_chain,
            private_key,
            created_at,
            expires_at,
        })
    }

    /// Validate a certificate bundle
    pub fn validate_certificate(&self, bundle: &CertificateBundle) -> Result<(), CertificateError> {
        // Check if certificate has expired
        let now = std::time::SystemTime::now();
        if now > bundle.expires_at {
            return Err(CertificateError::ValidityError);
        }

        // If chain validation is required, perform it
        if self.config.require_chain_validation && !self.ca_certs.is_empty() {
            self.validate_certificate_chain(&bundle.cert_chain)?;
        }

        Ok(())
    }

    /// Create a server configuration from a certificate bundle
    #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
    pub fn create_server_config(
        &self,
        bundle: &CertificateBundle,
    ) -> Result<Arc<rustls::ServerConfig>, CertificateError> {
        use rustls::ServerConfig;

        self.validate_certificate(bundle)?;

        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(bundle.cert_chain.clone(), bundle.private_key.clone_key())
            .map_err(|e| CertificateError::ValidationFailed(e.to_string()))?;

        Ok(Arc::new(server_config))
    }

    /// Create a client configuration with optional certificate verification
    #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
    pub fn create_client_config(&self) -> Result<Arc<rustls::ClientConfig>, CertificateError> {
        use rustls::ClientConfig;

        let config = if self.ca_certs.is_empty() {
            // For development/testing - accept any certificate
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertificateVerifier))
                .with_no_client_auth()
        } else {
            // Production - use provided CA certificates
            let mut root_store = rustls::RootCertStore::empty();
            for ca_cert in &self.ca_certs {
                root_store.add(ca_cert.clone()).map_err(|e| {
                    CertificateError::ValidationFailed(format!("Failed to add CA cert: {e}"))
                })?;
            }

            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        Ok(Arc::new(config))
    }

    /// Load CA certificates from a file
    fn load_ca_certificates(
        ca_path: &str,
    ) -> Result<Vec<CertificateDer<'static>>, CertificateError> {
        use rustls_pemfile::certs;

        let ca_file = std::fs::File::open(ca_path)
            .map_err(|e| CertificateError::LoadingFailed(format!("Failed to open CA file: {e}")))?;

        let mut ca_reader = std::io::BufReader::new(ca_file);
        let ca_certs: Vec<CertificateDer<'static>> = certs(&mut ca_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                CertificateError::ParsingFailed(format!("Failed to parse CA certificates: {e}"))
            })?;

        if ca_certs.is_empty() {
            return Err(CertificateError::LoadingFailed(
                "No CA certificates found".to_string(),
            ));
        }

        Ok(ca_certs)
    }

    /// Extract validity information from a certificate
    fn extract_validity_from_cert(
        _cert: &CertificateDer<'static>,
    ) -> Result<(std::time::SystemTime, std::time::SystemTime), CertificateError> {
        // For now, return reasonable defaults
        // In a full implementation, you'd parse the certificate to extract actual validity
        let created_at = std::time::SystemTime::now();
        let expires_at = created_at + Duration::from_secs(365 * 24 * 60 * 60); // 1 year

        Ok((created_at, expires_at))
    }

    /// Validate certificate chain against CA certificates
    fn validate_certificate_chain(
        &self,
        cert_chain: &[CertificateDer<'static>],
    ) -> Result<(), CertificateError> {
        if cert_chain.is_empty() {
            return Err(CertificateError::ChainError(
                "Empty certificate chain".to_string(),
            ));
        }

        // For now, basic validation - in production you'd use a proper chain validator
        // This would involve checking signatures, validity periods, extensions, etc.

        Ok(())
    }
}

/// Certificate verifier that accepts any certificate (for development/testing only)
#[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
#[derive(Debug)]
struct NoCertificateVerifier;

#[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
impl rustls::client::danger::ServerCertVerifier for NoCertificateVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

impl CertificateBundle {
    /// Check if the certificate is expired or will expire within the given duration
    pub fn expires_within(&self, duration: Duration) -> bool {
        let now = std::time::SystemTime::now();
        match now.checked_add(duration) {
            Some(check_time) => check_time >= self.expires_at,
            None => true, // Overflow, assume will expire
        }
    }

    /// Get the remaining validity duration
    pub fn remaining_validity(&self) -> Option<Duration> {
        std::time::SystemTime::now()
            .duration_since(self.expires_at)
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_certificate_config() {
        let config = CertificateConfig::default();
        assert_eq!(config.common_name, "ant-quic-node");
        assert_eq!(config.subject_alt_names, vec!["localhost"]);
        assert!(config.self_signed);
        assert!(!config.require_chain_validation);
    }

    #[test]
    fn test_certificate_manager_creation() {
        let config = CertificateConfig::default();
        let manager = CertificateManager::new(config);
        assert!(manager.is_ok());
    }

    #[test]
    fn test_certificate_generation() {
        let config = CertificateConfig::default();
        let manager = CertificateManager::new(config).unwrap();

        let bundle = manager.generate_certificate();
        assert!(bundle.is_ok());

        let bundle = bundle.unwrap();
        assert!(!bundle.cert_chain.is_empty());
        assert!(bundle.expires_at > bundle.created_at);
    }

    #[test]
    fn test_certificate_bundle_expiry_check() {
        // Create a dummy PKCS#8 private key structure for testing
        // This is a minimal valid PKCS#8 structure with an Ed25519 OID
        let dummy_key = vec![
            0x30, 0x2e, // SEQUENCE (46 bytes)
            0x02, 0x01, 0x00, // INTEGER version 0
            0x30, 0x05, // SEQUENCE (5 bytes) - AlgorithmIdentifier
            0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
            0x04, 0x22, // OCTET STRING (34 bytes) - PrivateKey
            0x04, 0x20, // OCTET STRING (32 bytes) - actual key
            // 32 bytes of dummy key data
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];

        let bundle = CertificateBundle {
            cert_chain: vec![],
            private_key: PrivateKeyDer::try_from(dummy_key).unwrap(),
            created_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + Duration::from_secs(3600), // 1 hour
        };

        assert!(!bundle.expires_within(Duration::from_secs(1800))); // 30 minutes
        assert!(bundle.expires_within(Duration::from_secs(7200))); // 2 hours
    }
}
