//! Tests for TLS Extension Simulation and RFC 7250 Integration

use super::*;
use crate::crypto::{ClientConfig, ServerConfig, Session};
use crate::transport_parameters::TransportParameters;
use crate::{ConnectionId, Side};
use std::sync::Arc;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rustls::{QuicClientConfig, QuicServerConfig};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    
    /// Mock certificate and key for testing
    fn test_cert_and_key() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        // This is a self-signed certificate for testing
        let cert_der = include_bytes!("../../tests/certs/cert.der");
        let key_der = include_bytes!("../../tests/certs/key.der");
        
        let cert = CertificateDer::from(cert_der.to_vec());
        let key = PrivateKeyDer::try_from(key_der.to_vec()).unwrap();
        
        (vec![cert], key)
    }
    
    #[test]
    fn test_extension_aware_session_wrapper() {
        // Create a basic client config
        let client_config = QuicClientConfig::with_platform_verifier().unwrap();
        let client_config = Arc::new(client_config);
        
        // Create extension context
        let prefs = CertificateTypePreferences::prefer_raw_public_key();
        let extension_context = Arc::new(SimulatedExtensionContext::new(prefs));
        
        // Start a session
        let params = TransportParameters::default();
        let inner_session = client_config.clone().start_session(
            0x00000001, // QUIC version 1
            "example.com",
            &params,
        ).unwrap();
        
        // Wrap it with extension awareness
        let mut wrapped_session = ExtensionAwareTlsSession::new(
            inner_session,
            extension_context.clone() as Arc<dyn TlsExtensionHooks>,
            "test-conn-1".to_string(),
            true, // is_client
        );
        
        // Test basic session functionality
        let dst_cid = ConnectionId::from_vec(vec![1, 2, 3, 4]);
        let keys = wrapped_session.initial_keys(&dst_cid, Side::Client);
        assert!(keys.header.local.sample_size() > 0);
        assert!(keys.packet.local.tag_len() > 0);
        
        // Verify handshake tracking
        assert!(wrapped_session.is_handshaking());
        assert!(!wrapped_session.handshake_complete);
    }
    
    #[test]
    fn test_rfc7250_quic_client_config() {
        // Create base QUIC client config
        let base_config = Arc::new(QuicClientConfig::with_platform_verifier().unwrap());
        
        // Create RFC 7250 aware config
        let prefs = CertificateTypePreferences::prefer_raw_public_key();
        let rfc7250_config = Rfc7250QuicClientConfig::new(base_config, prefs);
        let rfc7250_config = Arc::new(rfc7250_config);
        
        // Start a session
        let params = TransportParameters::default();
        let session = rfc7250_config.clone().start_session(
            0x00000001,
            "example.com",
            &params,
        ).unwrap();
        
        // Verify it's an ExtensionAwareTlsSession
        // We can't directly check the type, but we can verify functionality
        assert!(session.is_handshaking());
    }
    
    #[test]
    fn test_rfc7250_quic_server_config() {
        // Get test certificate and key
        let (cert_chain, key) = test_cert_and_key();
        
        // Create base QUIC server config
        let base_config = Arc::new(
            QuicServerConfig::new(cert_chain, key).unwrap()
        );
        
        // Create RFC 7250 aware config
        let prefs = CertificateTypePreferences::raw_public_key_only();
        let rfc7250_config = Rfc7250QuicServerConfig::new(base_config, prefs);
        let rfc7250_config = Arc::new(rfc7250_config);
        
        // Start a session
        let params = TransportParameters::default();
        let mut session = rfc7250_config.clone().start_session(0x00000001, &params);
        
        // Test initial keys
        let dst_cid = ConnectionId::from_vec(vec![5, 6, 7, 8]);
        let keys = rfc7250_config.initial_keys(0x00000001, &dst_cid).unwrap();
        assert!(keys.header.local.sample_size() > 0);
        
        // Test retry tag
        let packet = vec![0u8; 100];
        let tag = rfc7250_config.retry_tag(0x00000001, &dst_cid, &packet);
        assert_eq!(tag.len(), 16);
    }
    
    #[test]
    fn test_extension_hooks_integration() {
        let prefs = CertificateTypePreferences::prefer_raw_public_key();
        let context = Arc::new(SimulatedExtensionContext::new(prefs));
        
        let conn_id = "test-hooks";
        
        // Get client hello extensions
        let extensions = context.get_client_hello_extensions(conn_id);
        assert_eq!(extensions.len(), 2);
        assert_eq!(extensions[0].0, 47); // client_certificate_type
        assert_eq!(extensions[1].0, 48); // server_certificate_type
        
        // Simulate server response
        let server_extensions = vec![
            (47, vec![1, 2]), // RawPublicKey
            (48, vec![1, 2]), // RawPublicKey
        ];
        
        context.process_server_hello_extensions(conn_id, &server_extensions).unwrap();
        
        // Get negotiation result
        let result = context.get_negotiation_result(conn_id);
        assert!(result.is_some());
        
        // Clean up
        context.cleanup_connection(conn_id);
    }
    
    #[test]
    fn test_negotiation_flow_simulation() {
        // Client side setup
        let client_prefs = CertificateTypePreferences::prefer_raw_public_key();
        let client_ctx = SimulatedExtensionContext::new(client_prefs);
        
        // Server side setup
        let server_prefs = CertificateTypePreferences::raw_public_key_only();
        let server_ctx = SimulatedExtensionContext::new(server_prefs);
        
        let conn_id = "negotiation-test";
        
        // Client initiates
        let (client_types, server_types) = client_ctx.simulate_send_preferences(conn_id);
        
        // Server receives and processes
        server_ctx.simulate_send_preferences(conn_id);
        server_ctx.simulate_receive_preferences(
            conn_id,
            client_types.as_deref(),
            server_types.as_deref(),
        ).unwrap();
        
        // Server completes negotiation
        let server_result = server_ctx.complete_negotiation(conn_id).unwrap();
        assert!(server_result.is_raw_public_key_only());
        
        // Verify handshake complete hook
        server_ctx.on_handshake_complete(conn_id, false);
        
        // Clean up
        client_ctx.cleanup_connection(conn_id);
        server_ctx.cleanup_connection(conn_id);
    }
}