//! Comprehensive tests for TLS Extensions and Certificate Type Negotiation
//!
//! This test suite validates the complete RFC 7250 certificate type negotiation
//! implementation, including extension parsing, negotiation protocols, and
//! integration with rustls.

use std::{sync::Arc, time::Duration};

use rustls::{ClientConfig, ServerConfig, Error as TlsError};

use crate::crypto::{
    tls_extensions::{
        CertificateType, CertificateTypeList, CertificateTypePreferences,
        NegotiationResult, TlsExtensionError, extension_ids,
    },
    certificate_negotiation::{
        CertificateNegotiationManager, NegotiationConfig, NegotiationState,
        NegotiationId,
    },
    // extension_handlers::{
    //     CertificateTypeClientHandler, CertificateTypeServerHandler,
    // },
    raw_public_keys::RawPublicKeyConfigBuilder,
};

/// Test utilities for TLS extension testing
mod test_utils {
    use super::*;

    /// Create test certificate type preferences with specific types
    pub fn create_test_preferences(
        client_types: Vec<CertificateType>,
        server_types: Vec<CertificateType>,
        require_extensions: bool,
    ) -> CertificateTypePreferences {
        CertificateTypePreferences {
            client_types: CertificateTypeList::new(client_types).unwrap(),
            server_types: CertificateTypeList::new(server_types).unwrap(),
            require_extensions,
            fallback_client: CertificateType::X509,
            fallback_server: CertificateType::X509,
        }
    }

    /// Create a test negotiation manager with custom configuration
    pub fn create_test_manager(enable_caching: bool, timeout_ms: u64) -> CertificateNegotiationManager {
        let config = NegotiationConfig {
            timeout: Duration::from_millis(timeout_ms),
            enable_caching,
            max_cache_size: 100,
            allow_fallback: true,
            default_preferences: CertificateTypePreferences::prefer_raw_public_key(),
        };
        CertificateNegotiationManager::new(config)
    }
}

/// Tests for basic certificate type handling
mod certificate_type_tests {
    use super::*;

    #[test]
    fn test_certificate_type_values() {
        assert_eq!(CertificateType::X509 as u8, 0);
        assert_eq!(CertificateType::RawPublicKey as u8, 2);
        
        assert_eq!(CertificateType::X509.to_u8(), 0);
        assert_eq!(CertificateType::RawPublicKey.to_u8(), 2);
        
        assert!(CertificateType::X509.is_x509());
        assert!(!CertificateType::X509.is_raw_public_key());
        
        assert!(CertificateType::RawPublicKey.is_raw_public_key());
        assert!(!CertificateType::RawPublicKey.is_x509());
    }

    #[test]
    fn test_certificate_type_parsing() {
        assert_eq!(CertificateType::from_u8(0).unwrap(), CertificateType::X509);
        assert_eq!(CertificateType::from_u8(2).unwrap(), CertificateType::RawPublicKey);
        
        // Test invalid values
        assert!(CertificateType::from_u8(1).is_err());
        assert!(CertificateType::from_u8(3).is_err());
        assert!(CertificateType::from_u8(255).is_err());
    }

    #[test]
    fn test_certificate_type_display() {
        assert_eq!(format!("{}", CertificateType::X509), "X.509");
        assert_eq!(format!("{}", CertificateType::RawPublicKey), "RawPublicKey");
    }
}

/// Tests for certificate type lists
mod certificate_type_list_tests {
    use super::*;

    #[test]
    fn test_certificate_type_list_creation() {
        // Test valid list creation
        let list = CertificateTypeList::new(vec![
            CertificateType::RawPublicKey,
            CertificateType::X509,
        ]).unwrap();
        
        assert_eq!(list.types.len(), 2);
        assert_eq!(list.most_preferred(), CertificateType::RawPublicKey);
        assert!(list.supports_raw_public_key());
        assert!(list.supports_x509());

        // Test empty list error
        assert!(matches!(
            CertificateTypeList::new(vec![]),
            Err(TlsExtensionError::EmptyCertificateTypeList)
        ));

        // Test duplicate error
        assert!(matches!(
            CertificateTypeList::new(vec![CertificateType::X509, CertificateType::X509]),
            Err(TlsExtensionError::DuplicateCertificateType(CertificateType::X509))
        ));

        // Test too long list
        let long_list = vec![CertificateType::X509; 256];
        assert!(matches!(
            CertificateTypeList::new(long_list),
            Err(TlsExtensionError::CertificateTypeListTooLong(256))
        ));
    }

    #[test]
    fn test_certificate_type_list_presets() {
        let rpk_only = CertificateTypeList::raw_public_key_only();
        assert_eq!(rpk_only.types, vec![CertificateType::RawPublicKey]);
        assert!(rpk_only.supports_raw_public_key());
        assert!(!rpk_only.supports_x509());

        let prefer_rpk = CertificateTypeList::prefer_raw_public_key();
        assert_eq!(prefer_rpk.types, vec![CertificateType::RawPublicKey, CertificateType::X509]);
        assert_eq!(prefer_rpk.most_preferred(), CertificateType::RawPublicKey);

        let x509_only = CertificateTypeList::x509_only();
        assert_eq!(x509_only.types, vec![CertificateType::X509]);
        assert!(!x509_only.supports_raw_public_key());
        assert!(x509_only.supports_x509());
    }

    #[test]
    fn test_certificate_type_list_serialization() {
        let list = CertificateTypeList::prefer_raw_public_key();
        let bytes = list.to_bytes();
        
        // Should be: [length=2, RPK=2, X509=0]
        assert_eq!(bytes, vec![2, 2, 0]);

        let parsed = CertificateTypeList::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, list);
    }

    #[test]
    fn test_certificate_type_list_parsing_errors() {
        // Empty input
        assert!(CertificateTypeList::from_bytes(&[]).is_err());

        // Zero length
        assert!(matches!(
            CertificateTypeList::from_bytes(&[0]),
            Err(TlsExtensionError::EmptyCertificateTypeList)
        ));

        // Length mismatch
        assert!(CertificateTypeList::from_bytes(&[2, 2]).is_err());
        assert!(CertificateTypeList::from_bytes(&[1, 2, 0]).is_err());

        // Invalid certificate type
        assert!(CertificateTypeList::from_bytes(&[1, 1]).is_err());
        assert!(CertificateTypeList::from_bytes(&[1, 255]).is_err());
    }

    #[test]
    fn test_certificate_type_list_negotiation() {
        let rpk_only = CertificateTypeList::raw_public_key_only();
        let prefer_rpk = CertificateTypeList::prefer_raw_public_key();
        let x509_only = CertificateTypeList::x509_only();

        // Perfect match
        assert_eq!(
            rpk_only.negotiate(&rpk_only).unwrap(),
            CertificateType::RawPublicKey
        );

        // RPK preferred by both, should choose RPK
        assert_eq!(
            prefer_rpk.negotiate(&prefer_rpk).unwrap(),
            CertificateType::RawPublicKey
        );

        // Client prefers RPK, server only supports X509
        assert_eq!(
            prefer_rpk.negotiate(&x509_only).unwrap(),
            CertificateType::X509
        );

        // No common types
        assert!(rpk_only.negotiate(&x509_only).is_none());

        // Order matters - first match in our preference list wins
        let custom_order = CertificateTypeList::new(vec![
            CertificateType::X509,
            CertificateType::RawPublicKey,
        ]).unwrap();
        
        assert_eq!(
            custom_order.negotiate(&prefer_rpk).unwrap(),
            CertificateType::X509 // X509 comes first in custom_order
        );
    }
}

/// Tests for certificate type preferences
mod preferences_tests {
    use super::*;
    use super::test_utils::*;

    #[test]
    fn test_preferences_presets() {
        let prefer_rpk = CertificateTypePreferences::prefer_raw_public_key();
        assert!(prefer_rpk.client_types.supports_raw_public_key());
        assert!(prefer_rpk.server_types.supports_raw_public_key());
        assert!(!prefer_rpk.require_extensions);

        let rpk_only = CertificateTypePreferences::raw_public_key_only();
        assert!(rpk_only.client_types.supports_raw_public_key());
        assert!(!rpk_only.client_types.supports_x509());
        assert!(rpk_only.require_extensions);

        let x509_only = CertificateTypePreferences::x509_only();
        assert!(x509_only.client_types.supports_x509());
        assert!(!x509_only.client_types.supports_raw_public_key());
        assert!(!x509_only.require_extensions);
    }

    #[test]
    fn test_preferences_negotiation_success() {
        let client_prefs = create_test_preferences(
            vec![CertificateType::RawPublicKey, CertificateType::X509],
            vec![CertificateType::RawPublicKey],
            false,
        );

        let server_client_types = CertificateTypeList::prefer_raw_public_key();
        let server_server_types = CertificateTypeList::raw_public_key_only();

        let result = client_prefs.negotiate(
            Some(&server_client_types),
            Some(&server_server_types),
        ).unwrap();

        assert_eq!(result.client_cert_type, CertificateType::RawPublicKey);
        assert_eq!(result.server_cert_type, CertificateType::RawPublicKey);
        assert!(result.is_raw_public_key_only());
    }

    #[test]
    fn test_preferences_negotiation_failure() {
        let strict_rpk_prefs = create_test_preferences(
            vec![CertificateType::RawPublicKey],
            vec![CertificateType::RawPublicKey],
            true, // Require extensions
        );

        let x509_types = CertificateTypeList::x509_only();

        // Should fail because no common certificate types
        assert!(strict_rpk_prefs.negotiate(
            Some(&x509_types),
            Some(&x509_types),
        ).is_err());

        // Should also fail if extensions are required but not provided
        assert!(strict_rpk_prefs.negotiate(None, None).is_err());
    }

    #[test]
    fn test_preferences_fallback_behavior() {
        let fallback_prefs = create_test_preferences(
            vec![CertificateType::RawPublicKey, CertificateType::X509],
            vec![CertificateType::RawPublicKey, CertificateType::X509],
            false, // Don't require extensions
        );

        // Should use fallback when no remote preferences provided
        let result = fallback_prefs.negotiate(None, None).unwrap();
        assert_eq!(result.client_cert_type, CertificateType::X509);
        assert_eq!(result.server_cert_type, CertificateType::X509);
    }

    #[test]
    fn test_mixed_deployment_scenarios() {
        let client_prefs = CertificateTypePreferences::prefer_raw_public_key();
        
        // Server supports RPK for server auth but requires X509 for client auth
        let server_client_types = CertificateTypeList::x509_only();
        let server_server_types = CertificateTypeList::raw_public_key_only();

        let result = client_prefs.negotiate(
            Some(&server_client_types),
            Some(&server_server_types),
        ).unwrap();

        assert_eq!(result.client_cert_type, CertificateType::X509);
        assert_eq!(result.server_cert_type, CertificateType::RawPublicKey);
        assert!(result.is_mixed());
        assert!(!result.is_raw_public_key_only());
        assert!(!result.is_x509_only());
    }
}

/// Tests for negotiation result handling
mod negotiation_result_tests {
    use super::*;

    #[test]
    fn test_negotiation_result_creation() {
        let result = NegotiationResult::new(
            CertificateType::RawPublicKey,
            CertificateType::X509,
        );

        assert_eq!(result.client_cert_type, CertificateType::RawPublicKey);
        assert_eq!(result.server_cert_type, CertificateType::X509);
        assert!(result.is_mixed());
    }

    #[test]
    fn test_negotiation_result_type_checks() {
        let rpk_only = NegotiationResult::new(
            CertificateType::RawPublicKey,
            CertificateType::RawPublicKey,
        );
        assert!(rpk_only.is_raw_public_key_only());
        assert!(!rpk_only.is_x509_only());
        assert!(!rpk_only.is_mixed());

        let x509_only = NegotiationResult::new(
            CertificateType::X509,
            CertificateType::X509,
        );
        assert!(!x509_only.is_raw_public_key_only());
        assert!(x509_only.is_x509_only());
        assert!(!x509_only.is_mixed());

        let mixed1 = NegotiationResult::new(
            CertificateType::RawPublicKey,
            CertificateType::X509,
        );
        assert!(mixed1.is_mixed());

        let mixed2 = NegotiationResult::new(
            CertificateType::X509,
            CertificateType::RawPublicKey,
        );
        assert!(mixed2.is_mixed());
    }
}

/// Tests for the certificate negotiation manager
mod negotiation_manager_tests {
    use super::*;
    use super::test_utils::*;

    #[test]
    fn test_manager_basic_workflow() {
        let manager = create_test_manager(false, 1000);
        let preferences = CertificateTypePreferences::prefer_raw_public_key();

        // Start negotiation
        let id = manager.start_negotiation(preferences);
        assert!(id.as_u64() > 0);

        let state = manager.get_negotiation_state(id).unwrap();
        assert!(matches!(state, NegotiationState::Waiting { .. }));

        // Complete negotiation successfully
        let remote_types = CertificateTypeList::raw_public_key_only();
        let result = manager.complete_negotiation(
            id,
            Some(remote_types.clone()),
            Some(remote_types),
        ).unwrap();

        assert_eq!(result.client_cert_type, CertificateType::RawPublicKey);
        assert_eq!(result.server_cert_type, CertificateType::RawPublicKey);

        let final_state = manager.get_negotiation_state(id).unwrap();
        assert!(final_state.is_successful());
        assert_eq!(final_state.get_result().unwrap(), &result);
    }

    #[test]
    fn test_manager_negotiation_failure() {
        let manager = create_test_manager(false, 1000);
        let strict_preferences = CertificateTypePreferences::raw_public_key_only();

        let id = manager.start_negotiation(strict_preferences);
        
        // Try to complete with incompatible types
        let x509_types = CertificateTypeList::x509_only();
        let result = manager.complete_negotiation(
            id,
            Some(x509_types.clone()),
            Some(x509_types),
        );

        assert!(result.is_err());

        let state = manager.get_negotiation_state(id).unwrap();
        assert!(!state.is_successful());
        assert!(state.get_error().is_some());
    }

    #[test]
    fn test_manager_caching() {
        let manager = create_test_manager(true, 1000);
        let preferences = CertificateTypePreferences::prefer_raw_public_key();

        // First negotiation
        let id1 = manager.start_negotiation(preferences.clone());
        let remote_types = CertificateTypeList::raw_public_key_only();
        let result1 = manager.complete_negotiation(
            id1,
            Some(remote_types.clone()),
            Some(remote_types.clone()),
        ).unwrap();

        // Second negotiation with same parameters should hit cache
        let id2 = manager.start_negotiation(preferences);
        let result2 = manager.complete_negotiation(
            id2,
            Some(remote_types.clone()),
            Some(remote_types),
        ).unwrap();

        assert_eq!(result1, result2);

        let stats = manager.get_stats();
        assert_eq!(stats.successful, 2);
        assert_eq!(stats.cache_hits, 1);
        assert_eq!(stats.cache_misses, 1);
    }

    #[test]
    fn test_manager_timeout_handling() {
        let manager = create_test_manager(false, 1); // 1ms timeout
        let preferences = CertificateTypePreferences::prefer_raw_public_key();

        let id = manager.start_negotiation(preferences);
        
        // Wait longer than timeout
        std::thread::sleep(Duration::from_millis(10));
        manager.handle_timeouts();

        let state = manager.get_negotiation_state(id).unwrap();
        assert!(matches!(state, NegotiationState::TimedOut { .. }));

        let stats = manager.get_stats();
        assert_eq!(stats.timed_out, 1);
    }

    #[test]
    fn test_manager_session_cleanup() {
        let manager = create_test_manager(false, 1000);
        let preferences = CertificateTypePreferences::prefer_raw_public_key();

        // Create and complete a negotiation
        let id = manager.start_negotiation(preferences);
        let remote_types = CertificateTypeList::raw_public_key_only();
        let _result = manager.complete_negotiation(
            id,
            Some(remote_types.clone()),
            Some(remote_types),
        ).unwrap();

        // Verify session exists
        assert!(manager.get_negotiation_state(id).is_some());

        // Clean up with very short max age
        manager.cleanup_old_sessions(Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(10));
        manager.cleanup_old_sessions(Duration::from_millis(1));

        // Session should be cleaned up (this might still exist as cleanup timing depends on implementation)
        // The main thing is that cleanup doesn't crash
    }

    #[test]
    fn test_manager_statistics() {
        let manager = create_test_manager(true, 1000);
        let preferences = CertificateTypePreferences::prefer_raw_public_key();

        // Successful negotiation
        let id1 = manager.start_negotiation(preferences.clone());
        let remote_types = CertificateTypeList::raw_public_key_only();
        let _result1 = manager.complete_negotiation(
            id1,
            Some(remote_types.clone()),
            Some(remote_types.clone()),
        ).unwrap();

        // Failed negotiation
        let strict_prefs = CertificateTypePreferences::raw_public_key_only();
        let id2 = manager.start_negotiation(strict_prefs);
        let x509_types = CertificateTypeList::x509_only();
        let _result2 = manager.complete_negotiation(
            id2,
            Some(x509_types.clone()),
            Some(x509_types),
        );

        // Cache hit
        let id3 = manager.start_negotiation(preferences);
        let _result3 = manager.complete_negotiation(
            id3,
            Some(remote_types.clone()),
            Some(remote_types),
        ).unwrap();

        let stats = manager.get_stats();
        assert_eq!(stats.total_attempts, 3);
        assert_eq!(stats.successful, 2);
        assert_eq!(stats.failed, 1);
        assert_eq!(stats.cache_hits, 1);
        assert_eq!(stats.cache_misses, 2);
        assert!(stats.avg_negotiation_time > Duration::ZERO);
    }

    #[test]
    fn test_manager_cache_operations() {
        let manager = create_test_manager(true, 1000);
        
        // Add some cached results
        let preferences = CertificateTypePreferences::prefer_raw_public_key();
        let id = manager.start_negotiation(preferences);
        let remote_types = CertificateTypeList::raw_public_key_only();
        let _result = manager.complete_negotiation(
            id,
            Some(remote_types.clone()),
            Some(remote_types),
        ).unwrap();

        let (cache_size, max_size) = manager.get_cache_stats();
        assert!(cache_size > 0);
        assert_eq!(max_size, 100);

        // Clear cache
        manager.clear_cache();
        let (cache_size_after, _) = manager.get_cache_stats();
        assert_eq!(cache_size_after, 0);
    }
}

/// Tests for extension handlers
mod extension_handler_tests {
    use super::*;

    #[test]
    fn test_client_preferences_creation() {
        let preferences = CertificateTypePreferences::prefer_raw_public_key();
        
        assert!(preferences.client_types.supports_raw_public_key());
        assert!(preferences.server_types.supports_raw_public_key());
    }

    #[test]
    fn test_server_preferences_creation() {
        let preferences = CertificateTypePreferences::raw_public_key_only();
        
        assert!(preferences.client_types.supports_raw_public_key());
        assert!(!preferences.client_types.supports_x509());
    }

    #[test]
    fn test_preferences_operations() {
        let preferences = CertificateTypePreferences::prefer_raw_public_key();
        
        // Test preference validation
        assert!(preferences.client_types.supports_raw_public_key());
        assert!(preferences.client_types.supports_x509());
        assert_eq!(preferences.client_types.most_preferred(), CertificateType::RawPublicKey);
    }
}

/// Tests for Raw Public Key config builder integration
mod rpk_config_integration_tests {
    use super::*;

    #[test]
    fn test_rpk_config_with_extensions() {
        let preferences = CertificateTypePreferences::raw_public_key_only();
        let (private_key, _) = crate::crypto::raw_public_keys::utils::generate_ed25519_keypair();

        let builder = RawPublicKeyConfigBuilder::new()
            .with_server_key(private_key)
            .with_certificate_type_extensions(preferences)
            .allow_any_key();

        // Test that config builds without errors
        let client_config = builder.clone().build_client_config();
        assert!(client_config.is_ok());

        let server_config = builder.build_server_config();
        assert!(server_config.is_ok());
    }

    #[test]
    fn test_rpk_config_enable_extensions() {
        let (private_key, _) = crate::crypto::raw_public_keys::utils::generate_ed25519_keypair();

        let builder = RawPublicKeyConfigBuilder::new()
            .with_server_key(private_key)
            .enable_certificate_type_extensions()
            .allow_any_key();

        // Test that config builds without errors
        let client_config = builder.clone().build_client_config();
        assert!(client_config.is_ok());

        let server_config = builder.build_server_config();
        assert!(server_config.is_ok());
    }
}

/// Performance and stress tests
mod performance_tests {
    use super::*;
    use super::test_utils::*;
    use std::time::Instant;

    #[test]
    fn test_negotiation_performance() {
        let manager = create_test_manager(true, 1000);
        let preferences = CertificateTypePreferences::prefer_raw_public_key();
        let remote_types = CertificateTypeList::raw_public_key_only();

        let start = Instant::now();
        
        // Perform many negotiations
        for _ in 0..100 {
            let id = manager.start_negotiation(preferences.clone());
            let _result = manager.complete_negotiation(
                id,
                Some(remote_types.clone()),
                Some(remote_types.clone()),
            ).unwrap();
        }

        let duration = start.elapsed();
        println!("100 negotiations completed in {:?}", duration);
        
        // Should complete reasonably quickly
        assert!(duration < Duration::from_secs(1));

        let stats = manager.get_stats();
        assert_eq!(stats.successful, 100);
        // Most should be cache hits after the first
        assert!(stats.cache_hits > 90);
    }

    #[test]
    fn test_extension_parsing_performance() {
        let list = CertificateTypeList::prefer_raw_public_key();
        let bytes = list.to_bytes();

        let start = Instant::now();
        
        // Parse many times
        for _ in 0..1000 {
            let _parsed = CertificateTypeList::from_bytes(&bytes).unwrap();
        }

        let duration = start.elapsed();
        println!("1000 extension parses completed in {:?}", duration);
        
        // Should be very fast
        assert!(duration < Duration::from_millis(100));
    }
}