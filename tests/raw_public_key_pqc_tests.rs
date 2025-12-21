//! Integration tests for Pure PQC raw public key support
//!
//! v0.2.0+: Updated for Pure PQC - uses ML-DSA-65 only, no Ed25519.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod pqc_raw_public_key_tests {
    use ant_quic::crypto::pqc::{MlDsaOperations, ml_dsa::MlDsa65};
    use ant_quic::crypto::raw_public_keys::pqc::{
        PqcRawPublicKeyVerifier, create_subject_public_key_info, derive_peer_id_from_public_key,
        extract_public_key_from_spki, generate_ml_dsa_keypair, sign_with_ml_dsa,
        supported_signature_schemes, verify_signature, verify_with_ml_dsa,
    };
    use rustls::SignatureScheme;

    #[test]
    fn test_ml_dsa_raw_public_key_lifecycle() {
        // Create ML-DSA-65 key pair
        let (public_key, _secret_key) = generate_ml_dsa_keypair().expect("keygen");

        // Test key properties
        assert_eq!(public_key.as_bytes().len(), 1952);

        // Test SPKI encoding
        let spki = create_subject_public_key_info(&public_key).expect("spki creation");
        assert!(spki.len() > public_key.as_bytes().len());

        // Test round-trip: SPKI -> public key
        let recovered_key = extract_public_key_from_spki(&spki).expect("spki extraction");
        assert_eq!(public_key.as_bytes(), recovered_key.as_bytes());
    }

    #[test]
    fn test_ml_dsa_keypair_generation() {
        // Generate multiple keypairs and verify they're different
        let (pk1, sk1) = generate_ml_dsa_keypair().expect("keygen1");
        let (pk2, sk2) = generate_ml_dsa_keypair().expect("keygen2");

        // Different public keys
        assert_ne!(pk1.as_bytes(), pk2.as_bytes());

        // Different secret keys
        assert_ne!(sk1.as_bytes(), sk2.as_bytes());
    }

    #[test]
    fn test_ml_dsa_signature_verification() {
        let (public_key, secret_key) = generate_ml_dsa_keypair().expect("keygen");
        let message = b"Test message for ML-DSA-65 signature";

        // Sign the message
        let signature = sign_with_ml_dsa(&secret_key, message).expect("signing");

        // Verify signature
        verify_with_ml_dsa(&public_key, message, &signature).expect("verification");

        // Verify with wrong message should fail
        let wrong_message = b"Wrong message";
        assert!(verify_with_ml_dsa(&public_key, wrong_message, &signature).is_err());
    }

    #[test]
    fn test_pqc_verifier_with_ml_dsa_keys() {
        // Generate two key pairs
        let (pk1, _sk1) = generate_ml_dsa_keypair().expect("keygen1");
        let (pk2, _sk2) = generate_ml_dsa_keypair().expect("keygen2");
        let (pk_untrusted, _sk_untrusted) = generate_ml_dsa_keypair().expect("keygen_untrusted");

        // Create verifier with pk1 as trusted
        let mut verifier = PqcRawPublicKeyVerifier::new(vec![pk1.clone()]);
        verifier.add_trusted_key(pk2.clone());

        // Trusted keys should verify
        let spki1 = create_subject_public_key_info(&pk1).expect("spki1");
        assert!(verifier.verify_cert(&spki1).is_ok());

        let spki2 = create_subject_public_key_info(&pk2).expect("spki2");
        assert!(verifier.verify_cert(&spki2).is_ok());

        // Untrusted key should fail
        let spki_untrusted = create_subject_public_key_info(&pk_untrusted).expect("spki_untrusted");
        assert!(verifier.verify_cert(&spki_untrusted).is_err());
    }

    #[test]
    fn test_verifier_allow_any() {
        // Create "allow any" verifier (development mode)
        let verifier = PqcRawPublicKeyVerifier::allow_any();

        // Any valid key should be accepted
        let (pk, _sk) = generate_ml_dsa_keypair().expect("keygen");
        let spki = create_subject_public_key_info(&pk).expect("spki");
        assert!(verifier.verify_cert(&spki).is_ok());
    }

    #[test]
    fn test_supported_signature_schemes() {
        let schemes = supported_signature_schemes();

        // Should only contain ML-DSA-65 scheme (0x0901 per IANA)
        assert_eq!(schemes.len(), 1);
        assert_eq!(schemes[0], SignatureScheme::Unknown(0x0901));
    }

    #[test]
    fn test_peer_id_derivation() {
        let (public_key, _secret_key) = generate_ml_dsa_keypair().expect("keygen");

        // Derive peer ID
        let peer_id = derive_peer_id_from_public_key(&public_key);

        // Peer ID should be 32 bytes (PeerId is tuple struct with pub [u8; 32])
        assert_eq!(peer_id.0.len(), 32);

        // Same key should produce same peer ID
        let peer_id2 = derive_peer_id_from_public_key(&public_key);
        assert_eq!(peer_id.0, peer_id2.0);

        // Different key should produce different peer ID
        let (pk2, _sk2) = generate_ml_dsa_keypair().expect("keygen2");
        let peer_id3 = derive_peer_id_from_public_key(&pk2);
        assert_ne!(peer_id.0, peer_id3.0);
    }

    #[test]
    fn test_large_key_serialization() {
        // ML-DSA-65 keys are 1952 bytes
        let (public_key, _secret_key) = generate_ml_dsa_keypair().expect("keygen");
        assert_eq!(public_key.as_bytes().len(), 1952);

        // Test SPKI encoding handles large keys
        let spki = create_subject_public_key_info(&public_key).expect("spki");

        // Should use long-form length encoding for large sizes
        assert!(spki.len() > 1952);
        assert_eq!(spki[0], 0x30); // SEQUENCE tag

        // For sizes > 255, length should be in long form (0x82 = 2-byte length)
        assert_eq!(spki[1], 0x82);
    }

    #[test]
    fn test_spki_round_trip() {
        let (public_key, _secret_key) = generate_ml_dsa_keypair().expect("keygen");

        // Encode to SPKI
        let spki = create_subject_public_key_info(&public_key).expect("spki encode");

        // Decode from SPKI
        let recovered = extract_public_key_from_spki(&spki).expect("spki decode");

        // Keys should match
        assert_eq!(public_key.as_bytes(), recovered.as_bytes());
    }

    #[test]
    fn test_verify_signature_function() {
        let (public_key, secret_key) = generate_ml_dsa_keypair().expect("keygen");
        let message = b"Test data for verify_signature function";

        // Sign
        let signature = sign_with_ml_dsa(&secret_key, message).expect("signing");

        // Use the verify_signature function with correct scheme
        assert!(
            verify_signature(
                &public_key,
                message,
                signature.as_bytes(),
                SignatureScheme::Unknown(0x0901)
            )
            .is_ok()
        );

        // Wrong scheme should fail
        assert!(
            verify_signature(
                &public_key,
                message,
                signature.as_bytes(),
                SignatureScheme::ED25519
            )
            .is_err()
        );
    }

    #[test]
    fn test_invalid_spki_handling() {
        // Empty SPKI
        assert!(extract_public_key_from_spki(&[]).is_err());

        // Too short SPKI
        assert!(extract_public_key_from_spki(&[0x30, 0x00]).is_err());

        // Invalid ASN.1 structure
        assert!(extract_public_key_from_spki(&[0xFF; 100]).is_err());
    }

    #[test]
    fn test_ml_dsa_operations_direct() {
        let ml_dsa = MlDsa65::new();

        // Generate keypair via MlDsaOperations trait
        let (pk, sk) = ml_dsa.generate_keypair().expect("keygen");

        // Sign message
        let message = b"Direct ML-DSA operations test";
        let signature = ml_dsa.sign(&sk, message).expect("sign");

        // Verify signature
        let valid = ml_dsa.verify(&pk, message, &signature).expect("verify");
        assert!(valid);

        // Wrong message should fail verification
        let wrong_message = b"Wrong message for verification";
        let valid = ml_dsa
            .verify(&pk, wrong_message, &signature)
            .expect("verify wrong");
        assert!(!valid);
    }
}
