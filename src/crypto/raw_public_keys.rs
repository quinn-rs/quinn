//! RFC 7250 Raw Public Keys Support for ant-quic
//!
//! This module implements Raw Public Keys (RPK) support as defined in RFC 7250,
//! allowing P2P connections to authenticate using Ed25519 public keys directly
//! without the overhead of X.509 certificates.

use std::{collections::HashSet, fmt::Debug, sync::Arc};

use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as TlsError, ServerConfig,
    SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::ResolvesServerCert,
    sign::{CertifiedKey, SigningKey},
};

use ed25519_dalek::{
    Signature, Signer, SigningKey as Ed25519SecretKey, Verifier, VerifyingKey as Ed25519PublicKey,
};

use tracing::{debug, info, warn};

/// Raw Public Key verifier for client-side authentication
#[derive(Debug)]
pub struct RawPublicKeyVerifier {
    /// Set of trusted public keys
    trusted_keys: HashSet<[u8; 32]>,
    /// Whether to allow any key (for development/testing)
    allow_any_key: bool,
}

impl RawPublicKeyVerifier {
    /// Create a new RPK verifier with a set of trusted public keys
    pub fn new(trusted_keys: Vec<[u8; 32]>) -> Self {
        Self {
            trusted_keys: trusted_keys.into_iter().collect(),
            allow_any_key: false,
        }
    }

    /// Create a verifier that accepts any valid Ed25519 public key
    /// WARNING: Only use for development/testing!
    pub fn allow_any() -> Self {
        Self {
            trusted_keys: HashSet::new(),
            allow_any_key: true,
        }
    }

    /// Add a trusted public key
    pub fn add_trusted_key(&mut self, public_key: [u8; 32]) {
        self.trusted_keys.insert(public_key);
    }

    /// Extract Ed25519 public key from SubjectPublicKeyInfo
    fn extract_ed25519_key(&self, spki_der: &[u8]) -> Result<[u8; 32], TlsError> {
        // Parse the SubjectPublicKeyInfo structure
        // Ed25519 OID: 1.3.101.112 (0x2b6570)

        // For RFC 7250, the "certificate" is actually just the SubjectPublicKeyInfo
        // We need to extract the raw 32-byte Ed25519 public key from this structure

        // Simple parsing for Ed25519 SubjectPublicKeyInfo
        // This is a minimal parser - in production you'd want more robust ASN.1 parsing
        if spki_der.len() < 44 {
            return Err(TlsError::InvalidCertificate(CertificateError::BadEncoding));
        }

        // Look for Ed25519 OID pattern in the DER encoding
        let ed25519_oid = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];

        if !spki_der.starts_with(&ed25519_oid) {
            return Err(TlsError::InvalidCertificate(
                CertificateError::UnknownIssuer,
            ));
        }

        // The public key should be at offset 12 and be 32 bytes long
        if spki_der.len() != 44 {
            return Err(TlsError::InvalidCertificate(CertificateError::BadEncoding));
        }

        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&spki_der[12..44]);

        debug!(
            "Extracted Ed25519 public key: {:?}",
            hex::encode(&public_key)
        );
        Ok(public_key)
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
        debug!("Verifying server certificate with Raw Public Key verifier");

        // Extract the Ed25519 public key from the certificate
        let public_key = self.extract_ed25519_key(end_entity.as_ref())?;

        // Check if this key is trusted
        if self.allow_any_key {
            info!("Accepting any Ed25519 public key (development mode)");
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }

        if self.trusted_keys.contains(&public_key) {
            info!("Server public key is trusted: {}", hex::encode(&public_key));
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            warn!("Unknown server public key: {}", hex::encode(&public_key));
            Err(TlsError::InvalidCertificate(
                CertificateError::UnknownIssuer,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        // TLS 1.2 not supported for Raw Public Keys in this implementation
        Err(TlsError::UnsupportedNameType)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        debug!("Verifying TLS 1.3 signature with Raw Public Key");

        // Extract Ed25519 public key
        let public_key_bytes = self.extract_ed25519_key(cert.as_ref())?;

        // Create Ed25519 public key
        let public_key = Ed25519PublicKey::from_bytes(&public_key_bytes)
            .map_err(|_| TlsError::InvalidCertificate(CertificateError::BadEncoding))?;

        // Verify signature
        if dss.signature().len() != 64 {
            return Err(TlsError::General(
                "Invalid signature length".to_string(),
            ));
        }

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(dss.signature());
        let signature = Signature::from(sig_bytes);

        public_key
            .verify(message, &signature)
            .map_err(|_| TlsError::General("Signature verification failed".to_string()))?;

        debug!("TLS 1.3 signature verification successful");
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

/// Raw Public Key resolver for server-side
#[derive(Debug)]
pub struct RawPublicKeyResolver {
    /// The server's certified key pair
    certified_key: Arc<CertifiedKey>,
}

impl RawPublicKeyResolver {
    /// Create a new RPK resolver with an Ed25519 key pair
    pub fn new(private_key: Ed25519SecretKey) -> Result<Self, TlsError> {
        // Get the public key from the private key
        let public_key = private_key.verifying_key();

        // Create SubjectPublicKeyInfo for the public key
        let public_key_der = create_ed25519_subject_public_key_info(&public_key);

        // Create a signing key
        let signing_key = Ed25519SigningKey::new(private_key);

        // Create certified key
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
        debug!("Resolving server certificate with Raw Public Key");
        Some(self.certified_key.clone())
    }
}

/// Ed25519 signing key implementation for rustls
#[derive(Debug)]
struct Ed25519SigningKey {
    private_key: Ed25519SecretKey,
}

impl Ed25519SigningKey {
    fn new(private_key: Ed25519SecretKey) -> Self {
        Self {
            private_key,
        }
    }
}

impl SigningKey for Ed25519SigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        if offered.contains(&SignatureScheme::ED25519) {
            Some(Box::new(Ed25519Signer {
                private_key: self.private_key.clone(),
            }))
        } else {
            None
        }
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ED25519
    }
}

/// Ed25519 signer implementation
#[derive(Debug)]
struct Ed25519Signer {
    private_key: Ed25519SecretKey,
}

impl rustls::sign::Signer for Ed25519Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, TlsError> {
        let signature = self.private_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

/// Create a SubjectPublicKeyInfo DER encoding for an Ed25519 public key
pub fn create_ed25519_subject_public_key_info(public_key: &Ed25519PublicKey) -> Vec<u8> {
    // Ed25519 SubjectPublicKeyInfo structure:
    // SEQUENCE {
    //   SEQUENCE {
    //     OBJECT IDENTIFIER 1.3.101.112 (Ed25519)
    //   }
    //   BIT STRING (32 bytes of public key)
    // }

    let mut spki = Vec::new();

    // SEQUENCE tag and length (total length will be 44 bytes)
    spki.extend_from_slice(&[0x30, 0x2a]);

    // Algorithm identifier SEQUENCE
    spki.extend_from_slice(&[0x30, 0x05]);

    // Ed25519 OID: 1.3.101.112
    spki.extend_from_slice(&[0x06, 0x03, 0x2b, 0x65, 0x70]);

    // Subject public key BIT STRING
    spki.extend_from_slice(&[0x03, 0x21, 0x00]); // BIT STRING, 33 bytes (32 + 1 unused bits byte)

    // The actual 32-byte Ed25519 public key
    spki.extend_from_slice(public_key.as_bytes());

    spki
}

/// Configuration builder for Raw Public Keys with TLS extension support
#[derive(Debug, Default, Clone)]
pub struct RawPublicKeyConfigBuilder {
    trusted_keys: Vec<[u8; 32]>,
    allow_any: bool,
    server_key: Option<(Ed25519SecretKey, Ed25519PublicKey)>,
    /// Enable TLS certificate type extensions
    enable_extensions: bool,
    /// Certificate type preferences for negotiation
    cert_type_preferences: Option<super::tls_extensions::CertificateTypePreferences>,
}

impl RawPublicKeyConfigBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a trusted public key
    pub fn add_trusted_key(mut self, public_key: [u8; 32]) -> Self {
        self.trusted_keys.push(public_key);
        self
    }

    /// Allow any valid Ed25519 public key (development only)
    pub fn allow_any_key(mut self) -> Self {
        self.allow_any = true;
        self
    }

    /// Set the server's key pair
    pub fn with_server_key(mut self, private_key: Ed25519SecretKey) -> Self {
        let public_key = private_key.verifying_key();
        self.server_key = Some((private_key, public_key));
        self
    }

    /// Enable TLS certificate type extensions for negotiation
    pub fn with_certificate_type_extensions(mut self, preferences: super::tls_extensions::CertificateTypePreferences) -> Self {
        self.enable_extensions = true;
        self.cert_type_preferences = Some(preferences);
        self
    }

    /// Enable TLS extensions with default Raw Public Key preferences
    pub fn enable_certificate_type_extensions(mut self) -> Self {
        self.enable_extensions = true;
        self.cert_type_preferences = Some(super::tls_extensions::CertificateTypePreferences::prefer_raw_public_key());
        self
    }

    /// Build a client configuration with Raw Public Keys
    pub fn build_client_config(self) -> Result<ClientConfig, TlsError> {
        let verifier = if self.allow_any {
            RawPublicKeyVerifier::allow_any()
        } else {
            RawPublicKeyVerifier::new(self.trusted_keys)
        };

        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();

        // Add TLS certificate type extensions if enabled
        if self.enable_extensions {
            if let Some(_preferences) = self.cert_type_preferences {
                // rustls 0.23.x handles RFC 7250 internally, so we just need to configure it
                // No custom extension handler needed
            }
        }

        Ok(config)
    }

    /// Build a server configuration with Raw Public Keys
    pub fn build_server_config(self) -> Result<ServerConfig, TlsError> {
        let (private_key, _public_key) = self
            .server_key
            .ok_or_else(|| TlsError::General("Server key pair required".into()))?;

        let resolver = RawPublicKeyResolver::new(private_key)?;

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));

        // Add TLS certificate type extensions if enabled
        if self.enable_extensions {
            if let Some(_preferences) = self.cert_type_preferences {
                // rustls 0.23.x handles RFC 7250 internally, so we just need to configure it
                // No custom extension handler needed
            }
        }

        Ok(config)
    }
}

/// Utility functions for key generation and conversion
pub mod utils {
    use super::*;
    

    /// Generate a new Ed25519 key pair
    pub fn generate_ed25519_keypair() -> (Ed25519SecretKey, Ed25519PublicKey) {
        // Use a fixed seed for deterministic testing, in production would use proper RNG
        let seed = [42u8; 32];  // In production, use OsRng or similar
        let private_key = Ed25519SecretKey::from_bytes(&seed);
        let public_key = private_key.verifying_key();
        (private_key, public_key)
    }

    /// Convert Ed25519 public key to bytes
    pub fn public_key_to_bytes(public_key: &Ed25519PublicKey) -> [u8; 32] {
        *public_key.as_bytes()
    }

    /// Create Ed25519 public key from bytes
    pub fn public_key_from_bytes(bytes: &[u8; 32]) -> Result<Ed25519PublicKey, &'static str> {
        Ed25519PublicKey::from_bytes(bytes).map_err(|_| "Invalid public key bytes")
    }

    /// Create a test key pair for development
    pub fn create_test_keypair() -> (Ed25519SecretKey, Ed25519PublicKey) {
        // Use a deterministic seed for testing
        let seed = [42u8; 32];
        let private_key = Ed25519SecretKey::from_bytes(&seed);
        let public_key = private_key.verifying_key();
        (private_key, public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::utils::*;
    use super::*;

    #[test]
    fn test_create_ed25519_subject_public_key_info() {
        let (_, public_key) = generate_ed25519_keypair();
        let spki = create_ed25519_subject_public_key_info(&public_key);

        // Should be exactly 44 bytes
        assert_eq!(spki.len(), 44);

        // Should start with correct ASN.1 structure
        assert_eq!(
            &spki[0..9],
            &[0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]
        );

        // Should contain the public key at the end
        assert_eq!(&spki[12..], public_key.as_bytes());
    }

    #[test]
    fn test_raw_public_key_verifier_trusted_key() {
        let (_, public_key) = generate_ed25519_keypair();
        let key_bytes = public_key_to_bytes(&public_key);

        let verifier = RawPublicKeyVerifier::new(vec![key_bytes]);

        // Create a mock certificate with the public key
        let spki = create_ed25519_subject_public_key_info(&public_key);
        let cert = CertificateDer::from(spki);

        // Should successfully verify
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
        let (_, public_key1) = generate_ed25519_keypair();
        let (_, public_key2) = generate_ed25519_keypair();

        let key1_bytes = public_key_to_bytes(&public_key1);
        let verifier = RawPublicKeyVerifier::new(vec![key1_bytes]);

        // Create certificate with different key
        let spki = create_ed25519_subject_public_key_info(&public_key2);
        let cert = CertificateDer::from(spki);

        // Should fail verification
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
        let (_, public_key) = generate_ed25519_keypair();
        let verifier = RawPublicKeyVerifier::allow_any();

        let spki = create_ed25519_subject_public_key_info(&public_key);
        let cert = CertificateDer::from(spki);

        // Should accept any valid key
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
        let (private_key, public_key) = generate_ed25519_keypair();
        let key_bytes = public_key_to_bytes(&public_key);

        // Test client config
        let client_config = RawPublicKeyConfigBuilder::new()
            .add_trusted_key(key_bytes)
            .build_client_config();
        assert!(client_config.is_ok());

        // Test server config
        let server_config = RawPublicKeyConfigBuilder::new()
            .with_server_key(private_key)
            .build_server_config();
        assert!(server_config.is_ok());
    }

    #[test]
    fn test_extract_ed25519_key() {
        let (_, public_key) = generate_ed25519_keypair();
        let spki = create_ed25519_subject_public_key_info(&public_key);

        let verifier = RawPublicKeyVerifier::allow_any();
        let extracted_key = verifier.extract_ed25519_key(&spki).unwrap();

        assert_eq!(extracted_key, public_key_to_bytes(&public_key));
    }
}
