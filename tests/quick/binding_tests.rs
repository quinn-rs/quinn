//! Channel binding tests using Ed25519 as a stand-in for PQ signatures.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::{
    config::{ClientConfig, ServerConfig},
    high_level::Endpoint,
    nat_traversal_api::PeerId,
    trust::{self, EventCollector, FsPinStore, PinStore, TransportPolicy},
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::{net::SocketAddr, sync::Arc};
use tempfile::TempDir;
use tokio::time::{timeout, Duration};

fn gen_self_signed_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate self-signed");
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    (vec![cert_der], key_der)
}

fn ed25519_keypair() -> (ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey) {
    use rand::rngs::OsRng;
    let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    (sk, vk)
}

fn spki_from_vk(vk: &ed25519_dalek::VerifyingKey) -> Vec<u8> {
    ant_quic::crypto::raw_keys::create_ed25519_subject_public_key_info(vk)
}

fn peer_id_from_spki(spki: &[u8]) -> PeerId {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(spki);
    let r = h.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&r);
    PeerId(id)
}

async fn loopback_pair() -> (ant_quic::Connection, ant_quic::Connection) {
    let (chain, key) = gen_self_signed_cert();
    let server_cfg = ServerConfig::with_single_cert(chain.clone(), key).expect("server cfg");
    let server = Endpoint::server(server_cfg, ([127, 0, 0, 1], 0).into()).expect("server ep");
    let addr: SocketAddr = server.local_addr().unwrap();

    let accept = tokio::spawn(async move {
        let inc = timeout(Duration::from_secs(10), server.accept()).await.unwrap().unwrap();
        timeout(Duration::from_secs(10), inc).await.unwrap().unwrap()
    });

    let mut roots = rustls::RootCertStore::empty();
    for c in chain { roots.add(c).unwrap(); }
    let client_cfg = ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
    let mut client = Endpoint::client(([127, 0, 0, 1], 0).into()).expect("client ep");
    client.set_default_client_config(client_cfg);
    let c_conn = timeout(Duration::from_secs(10), client.connect(addr, "localhost").expect("start")).await.unwrap().unwrap();
    let s_conn = accept.await.unwrap();
    (c_conn, s_conn)
}

#[tokio::test]
async fn binding_success_with_pinned_key() {
    let (client_conn, server_conn) = loopback_pair().await;

    // Generate test keys for client and server identity (stand-in for PQ keys)
    let (c_sk, c_vk) = ed25519_keypair();
    let (s_sk, s_vk) = ed25519_keypair();
    let c_spki = spki_from_vk(&c_vk);
    let s_spki = spki_from_vk(&s_vk);
    let c_peer = peer_id_from_spki(&c_spki);
    let s_peer = peer_id_from_spki(&s_spki);

    // Pin each other's keys
    let client_store_dir = TempDir::new().unwrap();
    let server_store_dir = TempDir::new().unwrap();
    let c_store = FsPinStore::new(client_store_dir.path());
    let s_store = FsPinStore::new(server_store_dir.path());

    // Client pins server
    trust::register_first_seen(&c_store, &TransportPolicy::default(), &s_spki).unwrap();
    // Server pins client
    trust::register_first_seen(&s_store, &TransportPolicy::default(), &c_spki).unwrap();

    // Event sinks
    let c_events = Arc::new(EventCollector::default());
    let s_events = Arc::new(EventCollector::default());
    let c_policy = TransportPolicy::default().with_event_sink(c_events.clone());
    let s_policy = TransportPolicy::default().with_event_sink(s_events.clone());

    // Derive exporter (same for both sides)
    let exp_client = trust::derive_exporter(&client_conn).unwrap();
    let exp_server = trust::derive_exporter(&server_conn).unwrap();
    assert_eq!(exp_client, exp_server);

    // Sign exporters with each side's key
    let sig_c = trust::sign_exporter_ed25519(&c_sk, &exp_client);
    let sig_s = trust::sign_exporter_ed25519(&s_sk, &exp_server);

    // Each side verifies the other's signature against the pinned SPKI
    let pid_s = trust::verify_binding_ed25519(&c_store, &c_policy, &s_spki, &exp_client, &sig_s).unwrap();
    let pid_c = trust::verify_binding_ed25519(&s_store, &s_policy, &c_spki, &exp_server, &sig_c).unwrap();
    assert_eq!(pid_s, s_peer);
    assert_eq!(pid_c, c_peer);
    assert!(c_events.binding_verified_called());
    assert!(s_events.binding_verified_called());
}

#[tokio::test]
async fn binding_reject_on_key_mismatch() {
    let (client_conn, server_conn) = loopback_pair().await;
    let (c_sk, c_vk) = ed25519_keypair();
    let (s_sk, _s_vk) = ed25519_keypair();
    let c_spki = spki_from_vk(&c_vk);
    let s_spki = spki_from_vk(&ed25519_keypair().1); // wrong key pinned

    let c_store_dir = TempDir::new().unwrap();
    let s_store_dir = TempDir::new().unwrap();
    let c_store = FsPinStore::new(c_store_dir.path());
    let s_store = FsPinStore::new(s_store_dir.path());
    trust::register_first_seen(&c_store, &TransportPolicy::default(), &s_spki).unwrap();
    trust::register_first_seen(&s_store, &TransportPolicy::default(), &c_spki).unwrap();

    let exp = trust::derive_exporter(&client_conn).unwrap();
    let sig_s = trust::sign_exporter_ed25519(&s_sk, &exp);
    let policy = TransportPolicy::default();
    let err = trust::verify_binding_ed25519(&c_store, &policy, &s_spki, &exp, &sig_s).expect_err("should reject");
    let _ = server_conn; let _ = client_conn; let _ = c_sk; // silence unused
    match err { ant_quic::trust::TrustError::ChannelBinding(_) => {}, _ => panic!("wrong error") }
}

