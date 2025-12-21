//! Integration test: NAT traversal RFC frame config + Pure PQC raw public keys
//!
//! v0.2.0+: Updated for Pure PQC - uses ML-DSA-65 only, no Ed25519.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod pqc_integration {
    use ant_quic::VarInt;
    use ant_quic::crypto::raw_public_keys::pqc::{
        PqcRawPublicKeyVerifier, create_subject_public_key_info, generate_ml_dsa_keypair,
    };
    use ant_quic::frame::nat_traversal_unified::{
        NatTraversalFrameConfig, TRANSPORT_PARAM_RFC_NAT_TRAVERSAL, peer_supports_rfc_nat,
    };

    // Helper to synthesize a minimal TransportParameters byte blob that contains
    // the RFC NAT traversal transport parameter identifier, so peer_supports_rfc_nat() returns true.
    fn synthesize_tp_bytes_with_rfc_nat_param() -> Vec<u8> {
        // Embed the 8-byte constant somewhere in the byte stream
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 7]);
        buf.extend_from_slice(&TRANSPORT_PARAM_RFC_NAT_TRAVERSAL.to_be_bytes());
        buf.extend_from_slice(&[0u8; 5]);
        buf
    }

    #[test]
    fn nat_traversal_rfc_and_rpk_pqc_can_be_configured_together() {
        // 1) NAT traversal RFC support detected from TP bytes (no STUN/TURN involved)
        let tp_bytes = synthesize_tp_bytes_with_rfc_nat_param();
        assert!(
            peer_supports_rfc_nat(&tp_bytes),
            "Peer should support RFC NAT traversal format"
        );

        // Force RFC-only frame formatting (what we negotiate when both sides support it)
        let cfg = NatTraversalFrameConfig::rfc_only();
        assert!(cfg.use_rfc_format);
        assert!(!cfg.accept_legacy);

        // 2) Pure PQC Raw Public Keys with ML-DSA-65
        let (public_key, _secret_key) = generate_ml_dsa_keypair().expect("keygen");

        // Create SPKI from ML-DSA-65 public key
        let spki = create_subject_public_key_info(&public_key).expect("spki");

        // Verify with allow-any verifier
        let verifier = PqcRawPublicKeyVerifier::allow_any();
        let result = verifier.verify_cert(&spki);
        assert!(result.is_ok(), "ML-DSA-65 SPKI verification should succeed");

        // 3) Sanity: RFC NAT traversal frame types are available and VarInt encodes as expected
        let v = VarInt::from_u32(123);
        assert_eq!(u64::from(v), 123);
    }
}
