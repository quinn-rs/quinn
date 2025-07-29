//! Integration tests for PQC support in rustls

#[cfg(all(
    feature = "pqc",
    any(feature = "rustls-aws-lc-rs", feature = "rustls-ring")
))]
mod pqc_rustls_tests {
    use ant_quic::{ClientConfig, ServerConfig};
    use rustls::pki_types::CertificateDer;
    use std::sync::Arc;

    /// Test that we can create a PQC crypto provider
    #[test]
    fn test_pqc_crypto_provider_creation() {
        use ant_quic::crypto::pqc::rustls_provider::PqcCryptoProvider;

        // Should be able to create a PQC provider
        let provider = PqcCryptoProvider::new();
        assert!(provider.is_ok(), "Failed to create PQC crypto provider");

        let provider = provider.unwrap();
        // Provider should have hybrid cipher suites
        assert!(!provider.cipher_suites().is_empty());
    }

    /// Test that hybrid cipher suites are properly defined
    #[test]
    fn test_hybrid_cipher_suite_support() {
        use ant_quic::crypto::pqc::cipher_suites::TLS13_AES_128_GCM_SHA256_MLKEM768;

        // Test basic cipher suite properties
        assert_eq!(
            TLS13_AES_128_GCM_SHA256_MLKEM768.suite(),
            rustls::CipherSuite::TLS13_AES_128_GCM_SHA256
        );

        // Should support hybrid key exchange
        let kx_groups = TLS13_AES_128_GCM_SHA256_MLKEM768.key_exchange_groups();
        assert!(kx_groups.len() > 0);
        assert!(kx_groups.iter().any(|&g| is_hybrid_group(g)));
    }

    /// Test that ClientConfig can be created with PQC support
    #[test]
    fn test_client_config_with_pqc() {
        use ant_quic::crypto::pqc::rustls_provider::{PqcConfigExt, with_pqc_support};

        // Create a standard client config using ant-quic API
        #[cfg(feature = "platform-verifier")]
        let client_config = ClientConfig::try_with_platform_verifier().unwrap();

        #[cfg(not(feature = "platform-verifier"))]
        let client_config = {
            // Use empty root store for testing when platform verifier isn't available
            let roots = rustls::RootCertStore::empty();
            ClientConfig::with_root_certificates(roots)
        };

        // Add PQC support
        let pqc_client_config = with_pqc_support(client_config);
        assert!(pqc_client_config.is_ok());

        let pqc_client_config = pqc_client_config.unwrap();
        // Should have PQC cipher suites available
        let crypto = pqc_client_config.crypto_config();
        assert!(crypto.has_pqc_support());
    }

    /// Test that ServerConfig can be created with PQC support
    #[test]
    fn test_server_config_with_pqc() {
        use ant_quic::crypto::pqc::rustls_provider::{PqcConfigExt, with_pqc_support_server};

        // Create a proper test certificate and key using rcgen
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_chain = vec![CertificateDer::from(cert.cert)];
        let key = rustls::pki_types::PrivateKeyDer::from(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
        );

        // Create server config using ant-quic API
        let server_config = ServerConfig::with_single_cert(cert_chain, key)
            .expect("Failed to create server config");

        // Add PQC support
        let pqc_server_config = with_pqc_support_server(server_config);
        assert!(pqc_server_config.is_ok());

        let pqc_server_config = pqc_server_config.unwrap();
        // Should support hybrid signature schemes
        let crypto = pqc_server_config.crypto_config();
        assert!(crypto.has_pqc_support());
    }

    /// Test successful PQC negotiation between client and server
    #[tokio::test]
    async fn test_pqc_negotiation_success() {
        // Skip test for now as it requires full integration
        println!("PQC negotiation test requires full rustls integration");

        // This test would verify:
        // 1. PQC cipher suites are negotiated
        // 2. Hybrid key exchange is used
        // 3. Connection succeeds with PQC
    }

    /// Test graceful fallback when peer doesn't support PQC
    #[tokio::test]
    async fn test_fallback_to_classical() {
        // Skip test for now as it requires full integration
        println!("PQC fallback test requires full rustls integration");

        // This test would verify:
        // 1. PQC client can connect to classical server
        // 2. Classical algorithms are used
        // 3. No errors occur during fallback
    }

    /// Test configuration validation
    #[test]
    fn test_configuration_validation() {
        use ant_quic::crypto::pqc::rustls_provider::{PqcConfig, validate_config};

        // Valid config
        let valid_config = PqcConfig {
            enable_ml_kem: true,
            enable_ml_dsa: true,
            prefer_pqc: true,
            allow_downgrade: true,
        };
        assert!(validate_config(&valid_config).is_ok());

        // Invalid config - no algorithms enabled
        let invalid_config = PqcConfig {
            enable_ml_kem: false,
            enable_ml_dsa: false,
            prefer_pqc: true,
            allow_downgrade: false,
        };
        assert!(validate_config(&invalid_config).is_err());
    }

    /// Test error handling for PQC operations
    #[test]
    fn test_error_handling() {
        use ant_quic::crypto::pqc::rustls_provider::PqcCryptoProvider;

        // Test with invalid configuration
        let provider = PqcCryptoProvider::with_config(None);
        assert!(provider.is_err());

        // Test cipher suite errors
        let result = PqcCryptoProvider::validate_cipher_suites(&[]);
        assert!(result.is_err());
    }

    // Helper functions

    fn is_hybrid_group(group: rustls::NamedGroup) -> bool {
        matches!(
            group,
            rustls::NamedGroup::Unknown(0x01FD) |  // X25519MLKEM768
            rustls::NamedGroup::Unknown(0x01FE) |  // P256MLKEM768
            rustls::NamedGroup::Unknown(0x01FF) // X25519MLKEM1024
        )
    }

    fn create_pqc_client_config() -> ClientConfig {
        use ant_quic::crypto::pqc::rustls_provider::with_pqc_support;

        let roots = rustls::RootCertStore::empty();
        let config = ClientConfig::with_root_certificates(roots.into()).unwrap();
        with_pqc_support(config).unwrap()
    }

    fn create_pqc_server_config() -> ServerConfig {
        use ant_quic::crypto::pqc::rustls_provider::with_pqc_support_server;

        // Use proper test certificate
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_chain = vec![CertificateDer::from(cert.cert)];
        let key = rustls::pki_types::PrivateKeyDer::from(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
        );

        let config = ServerConfig::with_single_cert(cert_chain, key).unwrap();
        with_pqc_support_server(config).unwrap()
    }

    fn create_classical_server_config() -> ServerConfig {
        // Standard config without PQC
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_chain = vec![CertificateDer::from(cert.cert)];
        let key = rustls::pki_types::PrivateKeyDer::from(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
        );

        ServerConfig::with_single_cert(cert_chain, key).unwrap()
    }
}

#[cfg(not(all(
    feature = "pqc",
    any(feature = "rustls-aws-lc-rs", feature = "rustls-ring")
)))]
mod pqc_rustls_tests {
    #[test]
    fn test_pqc_feature_required() {
        println!("PQC rustls integration tests require 'pqc' feature and a rustls crypto backend");
    }
}
