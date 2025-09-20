//! Tests for token_v2 binding to (PeerId || CID || nonce)

use ant_quic::{nat_traversal_api::PeerId, shared::ConnectionId};

#[test]
fn retry_token_round_trip_binds_peer_and_cid() {
    let mut rng = rand::thread_rng();
    let key = ant_quic::token_v2::test_key_from_rng(&mut rng);

    let pid = PeerId([7u8; 32]);
    let cid = ConnectionId::new(&[9u8; 8]); // use 8-byte cid

    let tok = ant_quic::token_v2::encode_retry_token(&key, &pid, &cid);
    let dec = ant_quic::token_v2::decode_retry_token(&key, &tok).expect("decodes");

    assert_eq!(dec.peer_id, pid);
    assert_eq!(dec.cid, cid);
}
