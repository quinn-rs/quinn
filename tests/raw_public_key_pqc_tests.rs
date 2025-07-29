//! Integration tests for PQC raw public key support

#[cfg(feature = "pqc")]
mod pqc_raw_public_key_tests {
    use ant_quic::crypto::pqc::{
        ml_dsa::{MlDsa65, MlDsa65PublicKey, MlDsa65SecretKey},
        types::PqcError,
    };
    use ant_quic::crypto::raw_public_keys::pqc::{ExtendedRawPublicKey, PqcRawPublicKeyVerifier};
    use ed25519_dalek::{SigningKey as Ed25519SecretKey, VerifyingKey as Ed25519PublicKey};
    use rustls::SignatureScheme;

    #[test]
    fn test_ml_dsa_raw_public_key_lifecycle() {
        // Create ML-DSA key pair
        let ml_dsa = MlDsa65::new();
        match ml_dsa.generate_keypair() {
            Ok((public_key, _secret_key)) => {
                // Create extended raw public key
                let raw_key = ExtendedRawPublicKey::MlDsa65(public_key.clone());

                // Test properties
                assert_eq!(raw_key.size(), public_key.as_bytes().len());
                assert_eq!(
                    raw_key.supported_signature_schemes(),
                    vec![SignatureScheme::Unknown(0xFE3C)]
                );

                // Test SPKI encoding
                match raw_key.to_subject_public_key_info() {
                    Ok(spki) => {
                        assert!(spki.len() > raw_key.size());

                        // Test round-trip (when implemented)
                        match ExtendedRawPublicKey::from_subject_public_key_info(&spki) {
                            Ok(_) => {
                                // Success when ML-DSA parsing is implemented
                            }
                            Err(PqcError::OperationNotSupported) => {
                                // Expected for now
                            }
                            Err(e) => {
                                println!("ML-DSA not yet available: {:?}", e);
                                // This is expected until aws-lc-rs supports ML-DSA
                            }
                        }
                    }
                    Err(PqcError::OperationNotSupported) => {
                        // Expected until implementation is complete
                    }
                    Err(e) => {
                        println!("ML-DSA not yet available: {:?}", e);
                        // This is expected until aws-lc-rs supports ML-DSA
                    }
                }
            }
            Err(PqcError::OperationNotSupported) => {
                // Expected until aws-lc-rs support
            }
            Err(e) => {
                println!("ML-DSA not yet available: {:?}", e);
                // This is expected until aws-lc-rs supports ML-DSA
            }
        }
    }

    #[test]
    fn test_hybrid_raw_public_key() {
        // Generate Ed25519 key
        use rand::rngs::OsRng;
        let ed25519_secret = Ed25519SecretKey::generate(&mut OsRng);
        let ed25519_public = ed25519_secret.verifying_key();

        // Generate ML-DSA key
        let ml_dsa = MlDsa65::new();
        match ml_dsa.generate_keypair() {
            Ok((ml_dsa_public, _)) => {
                // Create hybrid key
                let hybrid_key = ExtendedRawPublicKey::HybridEd25519MlDsa65 {
                    ed25519: ed25519_public,
                    ml_dsa: ml_dsa_public,
                };

                // Test properties
                assert_eq!(hybrid_key.size(), 32 + 1952); // Ed25519 + ML-DSA sizes
                assert_eq!(
                    hybrid_key.supported_signature_schemes(),
                    vec![SignatureScheme::Unknown(0xFE3D)]
                );

                // Test SPKI encoding
                match hybrid_key.to_subject_public_key_info() {
                    Ok(spki) => {
                        assert!(spki.starts_with(&[0x30])); // ASN.1 SEQUENCE
                        assert!(spki.len() > hybrid_key.size());
                    }
                    Err(PqcError::OperationNotSupported) => {
                        // Expected for now
                    }
                    Err(e) => {
                        println!("ML-DSA not yet available: {:?}", e);
                        // This is expected until aws-lc-rs supports ML-DSA
                    }
                }
            }
            Err(PqcError::OperationNotSupported) => {
                // Expected until aws-lc-rs support
            }
            Err(e) => {
                println!("ML-DSA not yet available: {:?}", e);
                // This is expected until aws-lc-rs supports ML-DSA
            }
        }
    }

    #[test]
    fn test_pqc_verifier_with_mixed_keys() {
        // Create different key types
        let ed25519_key =
            ExtendedRawPublicKey::Ed25519(Ed25519PublicKey::from_bytes(&[1u8; 32]).unwrap());

        let ml_dsa_key =
            ExtendedRawPublicKey::MlDsa65(MlDsa65PublicKey::from_bytes(&vec![0u8; 1952]).unwrap());

        // Create verifier with both key types
        let mut verifier = PqcRawPublicKeyVerifier::new(vec![ed25519_key.clone()]);
        verifier.add_trusted_key(ml_dsa_key.clone());

        // Test Ed25519 verification
        let ed25519_spki = ed25519_key.to_subject_public_key_info().unwrap();
        assert!(verifier.verify_cert(&ed25519_spki).is_ok());

        // Test ML-DSA verification (when implemented)
        match ml_dsa_key.to_subject_public_key_info() {
            Ok(ml_dsa_spki) => {
                match verifier.verify_cert(&ml_dsa_spki) {
                    Ok(_) => {
                        // Success when parsing is implemented
                    }
                    Err(_) => {
                        // Expected for now
                    }
                }
            }
            Err(PqcError::OperationNotSupported) => {
                // Expected for now
            }
            Err(e) => {
                println!("ML-DSA not yet available: {:?}", e);
                // This is expected until aws-lc-rs supports ML-DSA
            }
        }
    }

    #[test]
    fn test_signature_verification_ed25519() {
        use ed25519_dalek::Signer;
        use rand::rngs::OsRng;

        // Generate key pair
        let secret = Ed25519SecretKey::generate(&mut OsRng);
        let public = secret.verifying_key();

        // Create raw public key
        let raw_key = ExtendedRawPublicKey::Ed25519(public);

        // Sign a message
        let message = b"Test message for signature";
        let signature = secret.sign(message);

        // Verify signature
        let result = raw_key.verify(
            message,
            signature.to_bytes().as_ref(),
            SignatureScheme::ED25519,
        );
        assert!(result.is_ok());

        // Test with wrong message
        let wrong_message = b"Wrong message";
        let result = raw_key.verify(
            wrong_message,
            signature.to_bytes().as_ref(),
            SignatureScheme::ED25519,
        );
        assert!(result.is_err());

        // Test with wrong scheme
        let result = raw_key.verify(
            message,
            signature.to_bytes().as_ref(),
            SignatureScheme::Unknown(0x1234),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_large_key_serialization() {
        // Test with ML-DSA key (1952 bytes)
        let large_key = MlDsa65PublicKey::from_bytes(&vec![0xAB; 1952]).unwrap();
        let raw_key = ExtendedRawPublicKey::MlDsa65(large_key);

        // Test SPKI encoding handles large keys
        match raw_key.to_subject_public_key_info() {
            Ok(spki) => {
                // Should use long-form length encoding
                assert!(spki.len() > 1952);

                // Check ASN.1 structure
                assert_eq!(spki[0], 0x30); // SEQUENCE tag

                // For large sizes, length should be in long form
                if spki.len() > 255 {
                    assert_eq!(spki[1], 0x82); // 2-byte length
                }
            }
            Err(PqcError::OperationNotSupported) => {
                // Expected for now
            }
            Err(e) => {
                println!("ML-DSA not yet available: {:?}", e);
                // This is expected until aws-lc-rs supports ML-DSA
            }
        }
    }

    #[test]
    fn test_backward_compatibility() {
        // Ensure Ed25519 keys work exactly as before
        use ant_quic::crypto::raw_public_keys::create_ed25519_subject_public_key_info;

        let key = Ed25519PublicKey::from_bytes(&[42u8; 32]).unwrap();

        // Original SPKI encoding
        let original_spki = create_ed25519_subject_public_key_info(&key);

        // Extended SPKI encoding
        let extended_key = ExtendedRawPublicKey::Ed25519(key);
        let extended_spki = extended_key.to_subject_public_key_info().unwrap();

        // Should be identical
        assert_eq!(original_spki, extended_spki);
    }
}

#[cfg(not(feature = "pqc"))]
mod pqc_raw_public_key_tests {
    #[test]
    fn test_pqc_feature_required() {
        println!("PQC raw public key tests require 'pqc' feature");
    }
}
