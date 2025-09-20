//! Server-side validation tests for token_v2 semantics.

use ant_quic::{nat_traversal_api::PeerId, shared::ConnectionId};

#[test]
fn server_accepts_matching_peer_and_cid() {
    let mut rng = rand::thread_rng();
    let key = ant_quic::token_v2::test_key_from_rng(&mut rng);
    let peer = PeerId([1u8; 32]);
    let cid = ConnectionId::new(&[7u8; 8]);

    let tok = ant_quic::token_v2::encode_retry_token(&key, &peer, &cid);
    assert!(ant_quic::token_v2::validate_token(&key, &tok, &peer, &cid));
}

#[test]
fn server_rejects_mismatch_peer() {
    let mut rng = rand::thread_rng();
    let key = ant_quic::token_v2::test_key_from_rng(&mut rng);
    let peer_ok = PeerId([2u8; 32]);
    let peer_bad = PeerId([3u8; 32]);
    let cid = ConnectionId::new(&[9u8; 8]);
    let tok = ant_quic::token_v2::encode_retry_token(&key, &peer_ok, &cid);
    assert!(!ant_quic::token_v2::validate_token(
        &key, &tok, &peer_bad, &cid
    ));
}

#[test]
fn server_rejects_mismatch_cid() {
    let mut rng = rand::thread_rng();
    let key = ant_quic::token_v2::test_key_from_rng(&mut rng);
    let peer = PeerId([4u8; 32]);
    let cid_ok = ConnectionId::new(&[5u8; 8]);
    let cid_bad = ConnectionId::new(&[6u8; 8]);
    let tok = ant_quic::token_v2::encode_retry_token(&key, &peer, &cid_ok);
    assert!(!ant_quic::token_v2::validate_token(
        &key, &tok, &peer, &cid_bad
    ));
}
