//! Transport trust model tests (TOFU, rotations, channel binding, token binding)
//!
//! These tests define the expected behavior and public surface for the upcoming
//! transport trust work. They are added before implementation (TDD) and will
//! initially fail to compile until the corresponding modules are introduced.

use ant_quic as quic;

use sha2::{Digest, Sha256};
use tempfile::TempDir;

use quic::nat_traversal_api::PeerId;

// Helper: compute PeerId and fingerprint (H(SPKI))
fn peer_id_and_fpr(spki: &[u8]) -> (PeerId, [u8; 32]) {
    let mut h = Sha256::new();
    h.update(spki);
    let f = h.finalize();
    let mut fpr = [0u8; 32];
    fpr.copy_from_slice(&f);
    (PeerId(fpr), fpr)
}

#[test]
fn tofu_first_contact_pins_and_emits_event() {
    // Arrange: temp FS PinStore and an event collector policy
    let dir = TempDir::new().unwrap();
    let pinstore = quic::trust::FsPinStore::new(dir.path());

    let events = std::sync::Arc::new(quic::trust::EventCollector::default());
    let policy = quic::trust::TransportPolicy::default()
        .with_allow_tofu(true)
        .with_require_continuity(true)
        .with_event_sink(events.clone());

    // Peer SPKI (ed25519 for now)
    let (_, ed_pub) = quic::generate_ed25519_keypair();
    let spki = quic::crypto::raw_public_keys::ExtendedRawPublicKey::Ed25519(ed_pub)
        .to_subject_public_key_info()
        .unwrap();
    let (peer_id, fpr) = peer_id_and_fpr(&spki);

    // Act: first seen
    quic::trust::register_first_seen(&pinstore, &policy, &spki).expect("TOFU should accept");

    // Assert: pin persisted and event emitted
    let rec = pinstore.load(&peer_id).expect("load ok").expect("present");
    assert_eq!(rec.current_fingerprint, fpr);
    assert!(events.first_seen_called_with(&peer_id, &fpr));
}

#[test]
fn rotation_with_continuity_is_accepted() {
    let dir = TempDir::new().unwrap();
    let pinstore = quic::trust::FsPinStore::new(dir.path());
    let policy = quic::trust::TransportPolicy::default().with_require_continuity(true);

    // Old key
    let (old_sk, old_pk) = quic::generate_ed25519_keypair();
    let old_spki = quic::crypto::raw_public_keys::ExtendedRawPublicKey::Ed25519(old_pk)
        .to_subject_public_key_info()
        .unwrap();
    let (peer_id, old_fpr) = peer_id_and_fpr(&old_spki);
    quic::trust::register_first_seen(&pinstore, &policy, &old_spki).unwrap();

    // New key + continuity signature by old key over new SPKI fingerprint
    let (_new_sk_unused, new_pk) = quic::generate_ed25519_keypair();
    let new_spki = quic::crypto::raw_public_keys::ExtendedRawPublicKey::Ed25519(new_pk)
        .to_subject_public_key_info()
        .unwrap();
    let (_pid2, new_fpr) = peer_id_and_fpr(&new_spki);

    let continuity_sig = quic::trust::sign_continuity(&old_sk, &new_fpr);

    quic::trust::register_rotation(&pinstore, &policy, &peer_id, &old_fpr, &new_spki, &continuity_sig)
        .expect("rotation accepted");

    let rec = pinstore.load(&peer_id).unwrap().unwrap();
    assert_eq!(rec.current_fingerprint, new_fpr);
    assert_eq!(rec.previous_fingerprint, Some(old_fpr));
}

#[test]
fn rotation_without_continuity_is_rejected() {
    let dir = TempDir::new().unwrap();
    let pinstore = quic::trust::FsPinStore::new(dir.path());
    let policy = quic::trust::TransportPolicy::default().with_require_continuity(true);

    // Old key
    let (_old_sk, old_pk) = quic::generate_ed25519_keypair();
    let old_spki = quic::crypto::raw_public_keys::ExtendedRawPublicKey::Ed25519(old_pk)
        .to_subject_public_key_info()
        .unwrap();
    let (peer_id, old_fpr) = peer_id_and_fpr(&old_spki);
    quic::trust::register_first_seen(&pinstore, &policy, &old_spki).unwrap();

    // New key, but no continuity signature provided
    let (_new_sk_unused, new_pk) = quic::generate_ed25519_keypair();
    let new_spki = quic::crypto::raw_public_keys::ExtendedRawPublicKey::Ed25519(new_pk)
        .to_subject_public_key_info()
        .unwrap();

    let err = quic::trust::register_rotation(&pinstore, &policy, &peer_id, &old_fpr, &new_spki, &[]) // empty sig
        .expect_err("rotation must be rejected without continuity");
    let _ = err; // documented error type TBD
}

#[test]
fn channel_binding_verifies_and_emits_event() {
    // Trust policy & events
    let events = std::sync::Arc::new(quic::trust::EventCollector::default());
    let policy = quic::trust::TransportPolicy::default()
        .with_enable_channel_binding(true)
        .with_event_sink(events.clone());

    // Exporter bytes (pretend derived via TLS exporter)
    let exporter = [42u8; 32];
    quic::trust::perform_channel_binding_from_exporter(&exporter, &policy).expect("ok");
    assert!(events.binding_verified_called());
}

#[test]
fn token_binding_uses_peerid_cid_nonce() {
    // Arrange: fake PeerId and CID
    let peer_id = PeerId([7u8; 32]);
    let cid = quic::shared::ConnectionId::from_bytes(&[9u8; quic::MAX_CID_SIZE]);

    // Key and nonce
    let mut rng = rand::thread_rng();
    let token_key = quic::token_v2::test_key_from_rng(&mut rng);

    // Act: encode
    let token = quic::token_v2::encode_retry_token(&token_key, &peer_id, &cid);

    // Assert: decode and verify binding
    let decoded = quic::token_v2::decode_retry_token(&token_key, &token).expect("decodes");
    assert_eq!(decoded.peer_id, peer_id);
    assert_eq!(decoded.cid, cid);
}
