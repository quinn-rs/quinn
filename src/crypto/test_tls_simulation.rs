// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses


//! Test module for TLS extension simulation integration
//!
//! This module tests the integration of RFC 7250 certificate type negotiation
//! simulation with Raw Public Keys support.

#[cfg(test)]
mod tests {
    use super::super::{
        raw_public_keys::{RawPublicKeyConfigBuilder, key_utils::*},
        tls_extension_simulation::create_connection_id,
        tls_extensions::{CertificateType, CertificateTypePreferences},
    };
    use std::sync::Once;

    static INIT: Once = Once::new();

    // Ensure crypto provider is installed for tests
    fn ensure_crypto_provider() {
        INIT.call_once(|| {
            // Install the crypto provider if not already installed
            #[cfg(feature = "rustls-aws-lc-rs")]
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

            #[cfg(feature = "rustls-ring")]
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    #[test]
    fn test_rfc7250_client_config_creation() {
        ensure_crypto_provider();
        let (_, public_key) = generate_ed25519_keypair();
        let key_bytes = public_key_to_bytes(&public_key);

        let config_builder = RawPublicKeyConfigBuilder::new()
            .add_trusted_key(key_bytes)
            .enable_certificate_type_extensions();

        let rfc7250_client = config_builder.build_rfc7250_client_config().unwrap();
        // inner() returns Arc<ClientConfig>, not Option
        let _ = rfc7250_client.inner();
        let _ = rfc7250_client.extension_context();
    }

    #[test]
    fn test_rfc7250_server_config_creation() {
        ensure_crypto_provider();
        let (private_key, _) = generate_ed25519_keypair();

        let config_builder = RawPublicKeyConfigBuilder::new()
            .with_server_key(private_key)
            .enable_certificate_type_extensions();

        let rfc7250_server = config_builder.build_rfc7250_server_config().unwrap();
        // inner() returns Arc<ServerConfig>, not Option
        let _ = rfc7250_server.inner();
        let _ = rfc7250_server.extension_context();
    }

    #[test]
    fn test_simulated_negotiation_flow() {
        ensure_crypto_provider();
        let (server_private_key, server_public_key) = generate_ed25519_keypair();
        let server_key_bytes = public_key_to_bytes(&server_public_key);

        // Client configuration
        let client_config = RawPublicKeyConfigBuilder::new()
            .add_trusted_key(server_key_bytes)
            .enable_certificate_type_extensions()
            .build_rfc7250_client_config()
            .unwrap();

        // Server configuration
        let server_config = RawPublicKeyConfigBuilder::new()
            .with_server_key(server_private_key)
            .enable_certificate_type_extensions()
            .build_rfc7250_server_config()
            .unwrap();

        // Simulate connection establishment
        let conn_id = create_connection_id("client:1234", "server:5678");

        // Client sends extensions
        let client_extensions = client_config.get_client_hello_extensions(&conn_id);
        assert_eq!(client_extensions.len(), 2);
        assert_eq!(client_extensions[0].0, 47); // client_certificate_type
        assert_eq!(client_extensions[1].0, 48); // server_certificate_type

        // Server processes and responds
        let server_response = server_config
            .process_client_hello_extensions(&conn_id, &client_extensions)
            .unwrap();
        assert_eq!(server_response.len(), 2);

        // Both should negotiate to Raw Public Key
        assert_eq!(
            server_response[0].1[1],
            CertificateType::RawPublicKey.to_u8()
        );
        assert_eq!(
            server_response[1].1[1],
            CertificateType::RawPublicKey.to_u8()
        );
    }

    #[test]
    fn test_mixed_preferences_negotiation() {
        ensure_crypto_provider();
        let (server_private_key, server_public_key) = generate_ed25519_keypair();
        let server_key_bytes = public_key_to_bytes(&server_public_key);

        // Client prefers RPK but supports X.509
        let client_prefs = CertificateTypePreferences::prefer_raw_public_key();
        let client_config = RawPublicKeyConfigBuilder::new()
            .add_trusted_key(server_key_bytes)
            .with_certificate_type_extensions(client_prefs)
            .build_rfc7250_client_config()
            .unwrap();

        // Server only supports RPK
        let server_prefs = CertificateTypePreferences::raw_public_key_only();
        let server_config = RawPublicKeyConfigBuilder::new()
            .with_server_key(server_private_key)
            .with_certificate_type_extensions(server_prefs)
            .build_rfc7250_server_config()
            .unwrap();

        let conn_id = create_connection_id("client:1234", "server:5678");

        // Test negotiation
        let client_extensions = client_config.get_client_hello_extensions(&conn_id);
        let server_response = server_config
            .process_client_hello_extensions(&conn_id, &client_extensions)
            .unwrap();

        // Should negotiate to RPK since both support it
        assert_eq!(
            server_response[0].1[1],
            CertificateType::RawPublicKey.to_u8()
        );
        assert_eq!(
            server_response[1].1[1],
            CertificateType::RawPublicKey.to_u8()
        );
    }

    #[test]
    fn test_extension_context_cleanup() {
        ensure_crypto_provider();
        let (_, public_key) = generate_ed25519_keypair();
        let key_bytes = public_key_to_bytes(&public_key);

        let client_config = RawPublicKeyConfigBuilder::new()
            .add_trusted_key(key_bytes)
            .enable_certificate_type_extensions()
            .build_rfc7250_client_config()
            .unwrap();

        let conn_id = create_connection_id("client:1234", "server:5678");

        // Create negotiation state
        client_config.get_client_hello_extensions(&conn_id);

        // Cleanup should remove the state
        client_config
            .extension_context()
            .cleanup_connection(&conn_id);

        // New negotiation should work fine
        let extensions = client_config.get_client_hello_extensions(&conn_id);
        assert_eq!(extensions.len(), 2);
    }
}
