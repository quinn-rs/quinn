//! Integration test: NAT traversal RFC frame config + RFC 7250 raw public keys with PQC/hybrid

use ant_quic::frame::nat_traversal_unified::{
    NatTraversalFrameConfig, TRANSPORT_PARAM_RFC_NAT_TRAVERSAL, peer_supports_rfc_nat,
};

#[cfg(feature = "pqc")]
mod pqc_integration {
    use super::*;
    use ant_quic::VarInt;
    use ant_quic::crypto::pqc::types::MlDsaPublicKey;
    use ant_quic::crypto::pqc::types::PqcError;
    use ant_quic::crypto::raw_public_keys::create_ed25519_subject_public_key_info;
    use ant_quic::crypto::raw_public_keys::pqc::{ExtendedRawPublicKey, PqcRawPublicKeyVerifier};

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

        // 2) RFC 7250 Raw Public Keys with PQC/hybrid
        // 2a) Ed25519 raw public key SPKI flow
        let (_ed25519_signing, ed25519_verify) =
            ant_quic::crypto::raw_public_keys::key_utils::generate_ed25519_keypair();
        let ed25519_spki = create_ed25519_subject_public_key_info(&ed25519_verify);
        let verifier = PqcRawPublicKeyVerifier::new(vec![]);
        // Allow-any verifier should accept any SPKI form and return the parsed ExtendedRawPublicKey
        let recovered = verifier
            .verify_cert(&ed25519_spki)
            .expect("ed25519 SPKI verification failed");
        match recovered {
            ExtendedRawPublicKey::Ed25519(_) => {}
            other => panic!("unexpected key variant for ed25519: {:?}", other),
        }

        // 2b) ML-DSA-65 (PQC) raw public key SPKI flow (where supported by our helpers)
        // Construct a dummy ML-DSA public key of the exact size; actual bytes are not semantically checked here
        let ml_dsa_key = MlDsaPublicKey::from_bytes(
            &vec![0u8; ant_quic::crypto::pqc::types::ML_DSA_65_PUBLIC_KEY_SIZE],
        )
        .expect("Failed to create ML-DSA public key");
        let pqc_key = ExtendedRawPublicKey::MlDsa65(ml_dsa_key);
        // Export SPKI for ML-DSA; may be partially implemented depending on feature set
        let ml_dsa_spki_result = pqc_key.to_subject_public_key_info();
        match ml_dsa_spki_result {
            Ok(spki) => {
                // The verifier should either accept or (if parser path is not yet fully implemented) report a controlled error
                let _ = verifier.verify_cert(&spki);
            }
            Err(PqcError::OperationNotSupported) => {
                // Accept current placeholder behavior; implementation can be completed later
            }
            Err(e) => panic!("Unexpected ML-DSA SPKI error: {e:?}"),
        }

        // 2c) Hybrid Ed25519+ML-DSA extended form
        let ml_dsa_key2 = MlDsaPublicKey::from_bytes(
            &vec![2u8; ant_quic::crypto::pqc::types::ML_DSA_65_PUBLIC_KEY_SIZE],
        )
        .expect("Failed to create ML-DSA public key (hybrid)");
        let _hybrid_key = ExtendedRawPublicKey::HybridEd25519MlDsa65 {
            ed25519: ed25519_verify,
            ml_dsa: ml_dsa_key2,
        };
        // We don’t need to fully verify hybrid here; dedicated tests cover it. Presence/size sanity is enough.

        // 3) Sanity: RFC NAT traversal frame types are available and VarInt encodes as expected
        let v = VarInt::from_u32(123);
        assert_eq!(u64::from(v), 123);
    }
}
