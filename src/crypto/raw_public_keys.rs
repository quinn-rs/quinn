// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! RFC 7250 Raw Public Keys Support for ant-quic
//!
//! v0.2: Pure PQC - ML-DSA-65 for all authentication.
//!
//! This module implements Raw Public Keys (RPK) support as defined in RFC 7250,
//! using ML-DSA-65 (FIPS 204) for post-quantum secure authentication.

pub mod pqc;

use std::{fmt::Debug, sync::Arc};

use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as TlsError, ServerConfig,
    SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::ResolvesServerCert,
    sign::{CertifiedKey, SigningKey},
};

use super::tls_extension_simulation::{Rfc7250ClientConfig, Rfc7250ServerConfig};

use tracing::{debug, info, warn};

// Re-export Pure PQC types from pqc module
pub use pqc::{
    ML_DSA_65_PUBLIC_KEY_SIZE, ML_DSA_65_SECRET_KEY_SIZE, ML_DSA_65_SIGNATURE_SIZE,
    PqcRawPublicKeyVerifier, create_subject_public_key_info, derive_peer_id_from_key_bytes,
    derive_peer_id_from_public_key, extract_public_key_from_spki, generate_ml_dsa_keypair,
    supported_signature_schemes, verify_peer_id, verify_signature,
};

use crate::crypto::pqc::{
    MlDsaOperations,
    ml_dsa::MlDsa65,
    types::{
        MlDsaPublicKey as MlDsa65PublicKey, MlDsaSecretKey as MlDsa65SecretKey,
        MlDsaSignature as MlDsa65Signature, PqcError,
    },
};

/// ML-DSA-65 signature scheme - uses rustls native enum (IANA 0x0905)
const ML_DSA_65_SCHEME: SignatureScheme = SignatureScheme::ML_DSA_65;

/// Raw Public Key verifier for client-side authentication
#[derive(Debug)]
pub struct RawPublicKeyVerifier {
    /// Trusted public keys
    trusted_keys: Vec<MlDsa65PublicKey>,
    /// Whether to allow any key (for development/testing)
    allow_any_key: bool,
}

impl RawPublicKeyVerifier {
    /// Create a new RPK verifier with trusted public keys
    pub fn new(trusted_keys: Vec<MlDsa65PublicKey>) -> Self {
        Self {
            trusted_keys,
            allow_any_key: false,
        }
    }

    /// Create a verifier that accepts any valid ML-DSA-65 public key
    /// WARNING: Only use for development/testing!
    pub fn allow_any() -> Self {
        Self {
            trusted_keys: Vec::new(),
            allow_any_key: true,
        }
    }

    /// Add a trusted public key
    pub fn add_trusted_key(&mut self, public_key: MlDsa65PublicKey) {
        self.trusted_keys.push(public_key);
    }

    /// Extract ML-DSA-65 public key from SubjectPublicKeyInfo
    fn extract_ml_dsa_key(&self, spki_der: &[u8]) -> Result<MlDsa65PublicKey, TlsError> {
        extract_public_key_from_spki(spki_der)
            .map_err(|_| TlsError::InvalidCertificate(CertificateError::BadEncoding))
    }
}

impl ServerCertVerifier for RawPublicKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, TlsError> {
        debug!("Verifying server certificate with ML-DSA-65 Raw Public Key verifier");

        let public_key = self.extract_ml_dsa_key(end_entity.as_ref())?;

        if self.allow_any_key {
            info!("Accepting any ML-DSA-65 public key (development mode)");
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }

        for trusted in &self.trusted_keys {
            if public_key.as_bytes() == trusted.as_bytes() {
                info!(
                    "Server public key is trusted: {}",
                    hex::encode(&public_key.as_bytes()[..16])
                );
                return Ok(rustls::client::danger::ServerCertVerified::assertion());
            }
        }

        warn!(
            "Unknown server public key: {}",
            hex::encode(&public_key.as_bytes()[..16])
        );
        Err(TlsError::InvalidCertificate(
            CertificateError::UnknownIssuer,
        ))
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        // TLS 1.2 not supported for Raw Public Keys
        Err(TlsError::UnsupportedNameType)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        debug!("Verifying TLS 1.3 ML-DSA-65 signature");

        let public_key = self.extract_ml_dsa_key(cert.as_ref())?;

        // Verify ML-DSA-65 signature
        let sig = MlDsa65Signature::from_bytes(dss.signature())
            .map_err(|_| TlsError::General("Invalid ML-DSA-65 signature format".to_string()))?;

        let verifier = MlDsa65::new();
        match verifier.verify(&public_key, message, &sig) {
            Ok(true) => {
                debug!("TLS 1.3 ML-DSA-65 signature verification successful");
                Ok(HandshakeSignatureValid::assertion())
            }
            Ok(false) => Err(TlsError::General(
                "Signature verification failed".to_string(),
            )),
            Err(_) => Err(TlsError::General(
                "Signature verification error".to_string(),
            )),
        }
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![ML_DSA_65_SCHEME]
    }
}

/// Raw Public Key resolver for server-side
#[derive(Debug)]
pub struct RawPublicKeyResolver {
    certified_key: Arc<CertifiedKey>,
}

impl RawPublicKeyResolver {
    /// Create a new RPK resolver with an ML-DSA-65 key pair
    pub fn new(
        public_key: MlDsa65PublicKey,
        secret_key: MlDsa65SecretKey,
    ) -> Result<Self, TlsError> {
        let public_key_der = create_subject_public_key_info(&public_key)
            .map_err(|_| TlsError::General("Failed to create SPKI".into()))?;

        let signing_key = MlDsaSigningKey::new(public_key.clone(), secret_key);

        let certified_key = Arc::new(CertifiedKey {
            cert: vec![CertificateDer::from(public_key_der)],
            key: Arc::new(signing_key),
            ocsp: None,
        });

        Ok(Self { certified_key })
    }
}

impl ResolvesServerCert for RawPublicKeyResolver {
    fn resolve(&self, _client_hello: rustls::server::ClientHello) -> Option<Arc<CertifiedKey>> {
        debug!("Resolving server certificate with ML-DSA-65 Raw Public Key");
        Some(self.certified_key.clone())
    }
}

/// ML-DSA-65 signing key implementation for rustls
#[derive(Debug)]
struct MlDsaSigningKey {
    public_key: MlDsa65PublicKey,
    secret_key: MlDsa65SecretKey,
}

impl MlDsaSigningKey {
    fn new(public_key: MlDsa65PublicKey, secret_key: MlDsa65SecretKey) -> Self {
        Self {
            public_key,
            secret_key,
        }
    }
}

impl SigningKey for MlDsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        debug!(
            "MlDsaSigningKey::choose_scheme called with {} offered schemes: {:?}",
            offered.len(),
            offered
        );
        debug!("Looking for ML_DSA_65_SCHEME: {:?}", ML_DSA_65_SCHEME);

        if offered.contains(&ML_DSA_65_SCHEME) {
            debug!("Found ML-DSA-65 scheme, returning signer");
            Some(Box::new(MlDsaSigner {
                public_key: self.public_key.clone(),
                secret_key: self.secret_key.clone(),
            }))
        } else {
            warn!(
                "ML-DSA-65 scheme not found in offered schemes. Offered: {:?}",
                offered
            );
            None
        }
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        // Use Unknown since ML-DSA-65 isn't in rustls's enum yet
        rustls::SignatureAlgorithm::Unknown(0x09)
    }
}

/// ML-DSA-65 signer implementation
#[derive(Debug)]
struct MlDsaSigner {
    #[allow(dead_code)]
    public_key: MlDsa65PublicKey,
    secret_key: MlDsa65SecretKey,
}

impl rustls::sign::Signer for MlDsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, TlsError> {
        let ml_dsa = MlDsa65::new();
        let signature = ml_dsa
            .sign(&self.secret_key, message)
            .map_err(|e| TlsError::General(format!("ML-DSA-65 sign failed: {e:?}")))?;
        Ok(signature.as_bytes().to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        ML_DSA_65_SCHEME
    }
}

/// Configuration builder for Raw Public Keys with TLS extension support
#[derive(Debug, Clone)]
pub struct RawPublicKeyConfigBuilder {
    trusted_keys: Vec<MlDsa65PublicKey>,
    allow_any: bool,
    server_key: Option<(MlDsa65PublicKey, MlDsa65SecretKey)>,
    client_key: Option<(MlDsa65PublicKey, MlDsa65SecretKey)>,
    enable_extensions: bool,
    cert_type_preferences: Option<super::tls_extensions::CertificateTypePreferences>,
    pqc: Option<super::pqc::PqcConfig>,
}

impl Default for RawPublicKeyConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RawPublicKeyConfigBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            trusted_keys: Vec::new(),
            allow_any: false,
            server_key: None,
            client_key: None,
            enable_extensions: false,
            cert_type_preferences: None,
            pqc: None,
        }
    }

    /// Add a trusted ML-DSA-65 public key
    pub fn add_trusted_key(mut self, public_key: MlDsa65PublicKey) -> Self {
        self.trusted_keys.push(public_key);
        self
    }

    /// Allow any valid ML-DSA-65 public key (development only)
    pub fn allow_any_key(mut self) -> Self {
        self.allow_any = true;
        self
    }

    /// Set the server's key pair
    pub fn with_server_key(
        mut self,
        public_key: MlDsa65PublicKey,
        secret_key: MlDsa65SecretKey,
    ) -> Self {
        self.server_key = Some((public_key, secret_key));
        self
    }

    /// Set the client's key pair for mutual authentication
    pub fn with_client_key(
        mut self,
        public_key: MlDsa65PublicKey,
        secret_key: MlDsa65SecretKey,
    ) -> Self {
        self.client_key = Some((public_key, secret_key));
        self
    }

    /// Enable TLS certificate type extensions for negotiation
    pub fn with_certificate_type_extensions(
        mut self,
        preferences: super::tls_extensions::CertificateTypePreferences,
    ) -> Self {
        self.enable_extensions = true;
        self.cert_type_preferences = Some(preferences);
        self
    }

    /// Enable TLS extensions with default Raw Public Key preferences
    pub fn enable_certificate_type_extensions(mut self) -> Self {
        self.enable_extensions = true;
        self.cert_type_preferences =
            Some(super::tls_extensions::CertificateTypePreferences::prefer_raw_public_key());
        self
    }

    /// Set PQC configuration
    pub fn with_pqc(mut self, config: super::pqc::PqcConfig) -> Self {
        self.pqc = Some(config);
        self
    }

    /// Build a client configuration with Raw Public Keys
    pub fn build_client_config(self) -> Result<ClientConfig, TlsError> {
        let verifier = if self.allow_any {
            RawPublicKeyVerifier::allow_any()
        } else {
            RawPublicKeyVerifier::new(self.trusted_keys)
        };

        let provider = super::rustls::configured_provider_with_pqc(self.pqc.as_ref());

        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();

        Ok(config)
    }

    /// Build a server configuration with Raw Public Keys
    pub fn build_server_config(self) -> Result<ServerConfig, TlsError> {
        let (public_key, secret_key) = self
            .server_key
            .ok_or_else(|| TlsError::General("Server key pair required".into()))?;

        let resolver = RawPublicKeyResolver::new(public_key, secret_key)?;

        let provider = super::rustls::configured_provider_with_pqc(self.pqc.as_ref());

        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));

        Ok(config)
    }

    /// Build a client configuration with RFC 7250 extension simulation
    pub fn build_rfc7250_client_config(self) -> Result<Rfc7250ClientConfig, TlsError> {
        let preferences = self.cert_type_preferences.clone().unwrap_or_else(|| {
            super::tls_extensions::CertificateTypePreferences::prefer_raw_public_key()
        });
        let base_config = self.build_client_config()?;

        Ok(Rfc7250ClientConfig::new(base_config, preferences))
    }

    /// Build a server configuration with RFC 7250 extension simulation
    pub fn build_rfc7250_server_config(self) -> Result<Rfc7250ServerConfig, TlsError> {
        let preferences = self.cert_type_preferences.clone().unwrap_or_else(|| {
            super::tls_extensions::CertificateTypePreferences::prefer_raw_public_key()
        });
        let base_config = self.build_server_config()?;

        Ok(Rfc7250ServerConfig::new(base_config, preferences))
    }
}

/// Utility functions for key generation and conversion
pub mod key_utils {
    pub use super::pqc::{
        ML_DSA_65_PUBLIC_KEY_SIZE, ML_DSA_65_SECRET_KEY_SIZE, ML_DSA_65_SIGNATURE_SIZE,
        MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, derive_peer_id_from_key_bytes,
        derive_peer_id_from_public_key, generate_ml_dsa_keypair, verify_peer_id,
    };

    /// Type alias for ML-DSA-65 public key
    pub type MlDsa65PublicKey = MlDsaPublicKey;
    /// Type alias for ML-DSA-65 secret key
    pub type MlDsa65SecretKey = MlDsaSecretKey;

    use super::*;

    /// Generate a new ML-DSA-65 key pair
    ///
    /// Returns (public_key, secret_key) for use in TLS and peer identification.
    pub fn generate_keypair() -> Result<(MlDsa65PublicKey, MlDsa65SecretKey), PqcError> {
        generate_ml_dsa_keypair()
    }

    /// Derive a peer ID from an ML-DSA-65 public key
    pub fn peer_id_from_public_key(
        public_key: &MlDsa65PublicKey,
    ) -> crate::nat_traversal_api::PeerId {
        derive_peer_id_from_public_key(public_key)
    }

    /// Derive a peer ID from raw ML-DSA-65 public key bytes
    pub fn peer_id_from_key_bytes(
        key_bytes: &[u8],
    ) -> Result<crate::nat_traversal_api::PeerId, PqcError> {
        derive_peer_id_from_key_bytes(key_bytes)
    }

    /// Verify that a peer ID was correctly derived from a public key
    pub fn verify_peer_id_matches(
        peer_id: &crate::nat_traversal_api::PeerId,
        public_key: &MlDsa65PublicKey,
    ) -> bool {
        verify_peer_id(peer_id, public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn ensure_crypto_provider() {
        INIT.call_once(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    #[test]
    fn test_generate_ml_dsa_keypair() {
        let result = generate_ml_dsa_keypair();
        assert!(result.is_ok());

        let (public_key, secret_key) = result.unwrap();
        assert_eq!(public_key.as_bytes().len(), ML_DSA_65_PUBLIC_KEY_SIZE);
        assert_eq!(secret_key.as_bytes().len(), ML_DSA_65_SECRET_KEY_SIZE);
    }

    #[test]
    fn test_spki_round_trip() {
        let (public_key, _) = generate_ml_dsa_keypair().unwrap();

        let spki = create_subject_public_key_info(&public_key).unwrap();
        let recovered = extract_public_key_from_spki(&spki).unwrap();

        assert_eq!(recovered.as_bytes(), public_key.as_bytes());
    }

    #[test]
    fn test_raw_public_key_verifier_trusted_key() {
        let (public_key, _) = generate_ml_dsa_keypair().unwrap();

        let verifier = RawPublicKeyVerifier::new(vec![public_key.clone()]);

        let spki = create_subject_public_key_info(&public_key).unwrap();
        let cert = CertificateDer::from(spki);

        let result = verifier.verify_server_cert(
            &cert,
            &[],
            &ServerName::try_from("test").unwrap(),
            &[],
            UnixTime::now(),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_raw_public_key_verifier_unknown_key() {
        let (public_key1, _) = generate_ml_dsa_keypair().unwrap();
        let (public_key2, _) = generate_ml_dsa_keypair().unwrap();

        let verifier = RawPublicKeyVerifier::new(vec![public_key1]);

        let spki = create_subject_public_key_info(&public_key2).unwrap();
        let cert = CertificateDer::from(spki);

        let result = verifier.verify_server_cert(
            &cert,
            &[],
            &ServerName::try_from("test").unwrap(),
            &[],
            UnixTime::now(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_raw_public_key_verifier_allow_any() {
        let (public_key, _) = generate_ml_dsa_keypair().unwrap();
        let verifier = RawPublicKeyVerifier::allow_any();

        let spki = create_subject_public_key_info(&public_key).unwrap();
        let cert = CertificateDer::from(spki);

        let result = verifier.verify_server_cert(
            &cert,
            &[],
            &ServerName::try_from("test").unwrap(),
            &[],
            UnixTime::now(),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_config_builder() {
        ensure_crypto_provider();
        let (public_key, secret_key) = generate_ml_dsa_keypair().unwrap();

        // Test client config
        let client_config = RawPublicKeyConfigBuilder::new()
            .add_trusted_key(public_key.clone())
            .build_client_config();
        assert!(client_config.is_ok());

        // Test server config
        let server_config = RawPublicKeyConfigBuilder::new()
            .with_server_key(public_key, secret_key)
            .build_server_config();
        assert!(server_config.is_ok());
    }

    #[test]
    fn test_peer_id_derivation() {
        let (public_key, _) = generate_ml_dsa_keypair().unwrap();

        let peer_id1 = derive_peer_id_from_public_key(&public_key);
        let peer_id2 = derive_peer_id_from_public_key(&public_key);

        // Deterministic
        assert_eq!(peer_id1, peer_id2);

        // Different keys produce different IDs
        let (public_key2, _) = generate_ml_dsa_keypair().unwrap();
        let peer_id3 = derive_peer_id_from_public_key(&public_key2);
        assert_ne!(peer_id1, peer_id3);
    }

    #[test]
    fn test_verify_peer_id() {
        let (public_key, _) = generate_ml_dsa_keypair().unwrap();
        let peer_id = derive_peer_id_from_public_key(&public_key);

        assert!(verify_peer_id(&peer_id, &public_key));

        let (other_key, _) = generate_ml_dsa_keypair().unwrap();
        assert!(!verify_peer_id(&peer_id, &other_key));
    }

    #[test]
    fn test_supported_signature_schemes() {
        let verifier = RawPublicKeyVerifier::allow_any();
        let schemes = verifier.supported_verify_schemes();
        assert_eq!(schemes, vec![ML_DSA_65_SCHEME]);
    }

    #[test]
    fn test_key_utils_module() {
        let (public_key, secret_key) = key_utils::generate_keypair().unwrap();

        assert_eq!(public_key.as_bytes().len(), ML_DSA_65_PUBLIC_KEY_SIZE);
        assert_eq!(secret_key.as_bytes().len(), ML_DSA_65_SECRET_KEY_SIZE);

        let peer_id = key_utils::peer_id_from_public_key(&public_key);
        assert!(key_utils::verify_peer_id_matches(&peer_id, &public_key));

        let peer_id2 = key_utils::peer_id_from_key_bytes(public_key.as_bytes()).unwrap();
        assert_eq!(peer_id, peer_id2);
    }
}
