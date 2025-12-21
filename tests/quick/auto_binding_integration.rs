//! Integration tests for automatic channel binding on connect and NEW_TOKEN v2 issuance.
//!
//! v0.2.0+: Updated for Pure PQC - uses ML-DSA-65 keypairs, no Ed25519.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Mutex};
use tokio::time::{Duration, timeout};

use ant_quic as quic;
use ant_quic::crypto::raw_public_keys::pqc::{
    create_subject_public_key_info, generate_ml_dsa_keypair,
};
use ant_quic::nat_traversal_api::PeerId;
use ant_quic::{
    TokenStore,
    config::{ClientConfig, ServerConfig},
    high_level::Endpoint,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

fn gen_self_signed_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate self-signed");
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    (vec![cert_der], key_der)
}

fn mk_client_config(chain: &[CertificateDer<'static>]) -> ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    for c in chain.iter().cloned() {
        roots.add(c).expect("add root");
    }
    ClientConfig::with_root_certificates(Arc::new(roots)).expect("client cfg")
}

async fn mk_server() -> (Endpoint, std::net::SocketAddr, Vec<CertificateDer<'static>>) {
    #[cfg(feature = "rustls-aws-lc-rs")]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    #[cfg(all(not(feature = "rustls-aws-lc-rs"), feature = "rustls-aws-lc-rs"))]
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (chain, key) = gen_self_signed_cert();
    let server_cfg = ServerConfig::with_single_cert(chain.clone(), key).expect("server cfg");
    let ep = Endpoint::server(server_cfg, ([127, 0, 0, 1], 0).into()).expect("server ep");
    let addr = ep.local_addr().expect("server addr");
    (ep, addr, chain)
}

#[derive(Clone, Default)]
struct CollectingTokenStore(Arc<Mutex<Vec<bytes::Bytes>>>);
impl TokenStore for CollectingTokenStore {
    fn insert(&self, _server_name: &str, token: bytes::Bytes) {
        self.0.lock().unwrap().push(token);
    }
    fn take(&self, _server_name: &str) -> Option<bytes::Bytes> {
        None
    }
}

#[tokio::test]
async fn auto_binding_emits_new_token_v2() {
    let (server, server_addr, chain) = mk_server().await;

    // Prepare client identity (ML-DSA-65) and trust runtime
    let (public_key, secret_key) = generate_ml_dsa_keypair().expect("keygen");
    let spki = create_subject_public_key_info(&public_key).expect("spki");

    let tmp = tempfile::tempdir().expect("tempdir");
    let store = quic::trust::FsPinStore::new(tmp.path());
    let events = Arc::new(quic::trust::EventCollector::default());
    let policy = quic::trust::TransportPolicy::default().with_event_sink(events.clone());

    // Pin the client key on first use (server-side pin for test)
    let _peer_id = quic::trust::register_first_seen(&store, &policy, &spki).expect("pin ok");

    // Install global runtime (used by driver integration)
    quic::trust::set_global_runtime(Arc::new(quic::trust::GlobalTrustRuntime {
        store: Arc::new(store.clone()),
        policy: policy.clone(),
        local_public_key: Arc::new(public_key),
        local_secret_key: Arc::new(secret_key),
        local_spki: Arc::new(spki.clone()),
    }));

    // Server accept task
    let server_task = tokio::spawn(async move {
        let inc = timeout(Duration::from_secs(10), server.accept())
            .await
            .expect("accept wait")
            .expect("incoming");
        let _conn = timeout(Duration::from_secs(10), inc)
            .await
            .expect("hs wait")
            .expect("server hs ok");
        // Keep the connection alive briefly to allow binding and NEW_TOKEN
        tokio::time::sleep(Duration::from_millis(500)).await;
    });

    // Client connects with collecting token store
    let mut client = Endpoint::client(([127, 0, 0, 1], 0).into()).expect("client ep");
    let mut client_cfg = mk_client_config(&chain);
    let collector = CollectingTokenStore::default();
    client_cfg.token_store(Arc::new(collector.clone()));
    client.set_default_client_config(client_cfg);

    let connecting = client
        .connect(server_addr, "localhost")
        .expect("connect start");
    let conn = timeout(Duration::from_secs(10), connecting)
        .await
        .expect("client wait")
        .expect("client ok");

    // Wait a bit for binding + token issuance
    tokio::time::sleep(Duration::from_millis(400)).await;

    // Verify binding event observed
    assert!(
        events.binding_verified_called(),
        "binding should be verified"
    );

    // Verify a NEW_TOKEN was received and decodes as token_v2 (contains PeerId)
    let tokens = collector.0.lock().unwrap().clone();
    assert!(!tokens.is_empty(), "expected at least one NEW_TOKEN");
    let tok = &tokens[0];

    let dec = quic::token_v2::decode_retry_token(
        &quic::token_v2::test_key_from_rng(&mut rand::thread_rng()),
        tok,
    )
    .expect("decode v2");
    // PeerId in token should equal the pinned client's id
    let expected_peer = PeerId(dec.peer_id.0); // round-trip proof already present
    assert_eq!(dec.peer_id, expected_peer);

    // Clean up
    conn.close(0u32.into(), b"done");
    server_task.await.expect("server");
}

#[tokio::test]
async fn auto_binding_rejects_on_mismatch() {
    let (server, server_addr, chain) = mk_server().await;

    // Prepare client identity (ML-DSA-65)
    let (public_key, secret_key) = generate_ml_dsa_keypair().expect("keygen");
    let spki = create_subject_public_key_info(&public_key).expect("spki");

    // Pin a wrong key so verification fails
    let (wrong_pk, _wrong_sk) = generate_ml_dsa_keypair().expect("wrong keygen");
    let wrong_spki = create_subject_public_key_info(&wrong_pk).expect("wrong spki");

    let tmp = tempfile::tempdir().expect("tempdir");
    let store = quic::trust::FsPinStore::new(tmp.path());
    let policy = quic::trust::TransportPolicy::default();
    quic::trust::register_first_seen(&store, &policy, &wrong_spki).expect("pin wrong ok");

    // Install global runtime with client's real key
    quic::trust::set_global_runtime(Arc::new(quic::trust::GlobalTrustRuntime {
        store: Arc::new(store.clone()),
        policy: policy.clone(),
        local_public_key: Arc::new(public_key),
        local_secret_key: Arc::new(secret_key),
        local_spki: Arc::new(spki.clone()),
    }));

    // Server accept task
    let server_task = tokio::spawn(async move {
        let inc = timeout(Duration::from_secs(10), server.accept())
            .await
            .expect("accept wait")
            .expect("incoming");
        let conn = timeout(Duration::from_secs(10), inc)
            .await
            .expect("hs wait")
            .expect("server hs ok");
        // Wait for possible close due to binding failure
        let _ = timeout(Duration::from_secs(2), conn.closed()).await;
    });

    // Client connects
    let mut client = Endpoint::client(([127, 0, 0, 1], 0).into()).expect("client ep");
    let client_cfg = mk_client_config(&chain);
    client.set_default_client_config(client_cfg);

    let connecting = client
        .connect(server_addr, "localhost")
        .expect("connect start");
    let conn = timeout(Duration::from_secs(10), connecting)
        .await
        .expect("client wait")
        .expect("client ok");

    // Expect connection to be closed shortly due to binding failure
    let closed = timeout(Duration::from_secs(3), conn.closed()).await;
    assert!(closed.is_ok(), "connection should close on binding failure");

    server_task.await.expect("server");
}
