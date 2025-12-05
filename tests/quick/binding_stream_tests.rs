//! On-wire binding exchange tests using a unidirectional stream.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::{
    config::{ClientConfig, ServerConfig},
    high_level::Endpoint,
    trust::{self, EventCollector, FsPinStore, TransportPolicy},
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::{net::SocketAddr, sync::Arc};
use tempfile::TempDir;
use tokio::time::{Duration, timeout};

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

async fn loopback_pair() -> (
    ant_quic::high_level::Connection,
    ant_quic::high_level::Connection,
) {
    let (chain, key) = gen_self_signed_cert();
    let server_cfg = ServerConfig::with_single_cert(chain.clone(), key).expect("server cfg");
    let server = Endpoint::server(server_cfg, ([127, 0, 0, 1], 0).into()).expect("server ep");
    let addr: SocketAddr = server.local_addr().unwrap();

    let accept = tokio::spawn(async move {
        let inc = timeout(Duration::from_secs(10), server.accept())
            .await
            .unwrap()
            .unwrap();
        timeout(Duration::from_secs(10), inc)
            .await
            .unwrap()
            .unwrap()
    });

    let mut roots = rustls::RootCertStore::empty();
    for c in chain {
        roots.add(c).unwrap();
    }
    let client_cfg = ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
    let mut client = Endpoint::client(([127, 0, 0, 1], 0).into()).expect("client ep");
    client.set_default_client_config(client_cfg);
    let c_conn: ant_quic::high_level::Connection = timeout(
        Duration::from_secs(10),
        client.connect(addr, "localhost").expect("start"),
    )
    .await
    .unwrap()
    .unwrap();
    let s_conn: ant_quic::high_level::Connection = accept.await.unwrap();
    (c_conn, s_conn)
}

#[tokio::test]
async fn binding_over_stream_success() {
    let (client_conn, server_conn) = loopback_pair().await;
    let (c_sk, c_vk) = ed25519_keypair();
    let (_s_sk, s_vk) = ed25519_keypair();
    let c_spki = spki_from_vk(&c_vk);
    let s_spki = spki_from_vk(&s_vk);

    let c_tmp = TempDir::new().unwrap();
    let s_tmp = TempDir::new().unwrap();
    let c_store = FsPinStore::new(c_tmp.path());
    let s_store = FsPinStore::new(s_tmp.path());
    // Pin reciprocally
    trust::register_first_seen(&c_store, &TransportPolicy::default(), &s_spki).unwrap();
    trust::register_first_seen(&s_store, &TransportPolicy::default(), &c_spki).unwrap();

    // Derive exporter
    let exp_client = trust::derive_exporter(&client_conn).unwrap();
    let exp_server = trust::derive_exporter(&server_conn).unwrap();
    assert_eq!(exp_client, exp_server);

    let c_events = Arc::new(EventCollector::default());
    let s_events = Arc::new(EventCollector::default());
    let _c_policy = TransportPolicy::default().with_event_sink(c_events.clone());
    let s_policy = TransportPolicy::default().with_event_sink(s_events.clone());

    // Server waits to receive; client sends
    let s_store_owned = s_store.clone();
    let s_policy_owned = s_policy.clone();
    let s_conn_clone = server_conn.clone();
    let recv_task = tokio::spawn(async move {
        trust::recv_verify_binding_ed25519(&s_conn_clone, &s_store_owned, &s_policy_owned).await
    });
    trust::send_binding_ed25519(&client_conn, &exp_client, &c_sk, &c_spki)
        .await
        .expect("send ok");
    let pid = recv_task.await.unwrap().expect("verify ok");
    assert!(s_events.binding_verified_called());
    let _ = pid;
    let _ = exp_server; // silence
}

#[tokio::test]
async fn binding_over_stream_reject_on_mismatch() {
    let (client_conn, server_conn) = loopback_pair().await;
    let (c_sk, _c_vk) = ed25519_keypair();
    let (_, s_vk) = ed25519_keypair();
    let c_spki = spki_from_vk(&_c_vk);
    let wrong_spki = spki_from_vk(&s_vk); // wrong pin

    let c_tmp = TempDir::new().unwrap();
    let s_tmp = TempDir::new().unwrap();
    let c_store = FsPinStore::new(c_tmp.path());
    let s_store = FsPinStore::new(s_tmp.path());
    trust::register_first_seen(&c_store, &TransportPolicy::default(), &wrong_spki).unwrap();
    trust::register_first_seen(&s_store, &TransportPolicy::default(), &c_spki).unwrap();

    let exp = trust::derive_exporter(&client_conn).unwrap();
    // Server waits and should reject because pin mismatches
    let s_conn_clone = server_conn.clone();
    let c_store_owned = c_store.clone();
    let policy_owned = TransportPolicy::default();
    let recv_task = tokio::spawn(async move {
        trust::recv_verify_binding_ed25519(&s_conn_clone, &c_store_owned, &policy_owned).await
    });
    trust::send_binding_ed25519(&client_conn, &exp, &c_sk, &c_spki)
        .await
        .expect("send ok");
    let err = recv_task.await.unwrap().expect_err("should reject");
    match err {
        ant_quic::trust::TrustError::ChannelBinding(_) | ant_quic::trust::TrustError::NotPinned => {
        }
        _ => panic!("unexpected err"),
    }
}
