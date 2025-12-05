//! Validates that the connection reports PQC usage when ML-KEM-only is enabled by default.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::{
    config::{ClientConfig, ServerConfig},
    high_level::Endpoint,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::{Duration, timeout};

fn gen_self_signed_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate self-signed");
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    (vec![cert_der], key_der)
}

#[tokio::test]
async fn kem_only_handshake_is_active() {
    // Server
    let (chain, key) = gen_self_signed_cert();
    let server_cfg = ServerConfig::with_single_cert(chain.clone(), key).expect("server cfg");
    let server = Endpoint::server(server_cfg, ([127, 0, 0, 1], 0).into()).expect("server ep");
    let addr: SocketAddr = server.local_addr().unwrap();

    // Accept in background
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

    // Client trusts the self-signed cert
    let mut roots = rustls::RootCertStore::empty();
    for c in chain {
        roots.add(c).unwrap();
    }
    let client_cfg = ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();

    let mut client = Endpoint::client(([127, 0, 0, 1], 0).into()).expect("client ep");
    client.set_default_client_config(client_cfg);

    let connecting = client.connect(addr, "localhost").expect("start connect");
    let conn = timeout(Duration::from_secs(10), connecting)
        .await
        .unwrap()
        .unwrap();

    // Both sides report PQC usage (driven by default transport params)
    assert!(conn.is_pqc(), "client should report PQC in use");
    let server_conn = accept.await.unwrap();
    assert!(server_conn.is_pqc(), "server should report PQC in use");
}

/// With aws-lc-rs provider available, we signal KEM-only intent through the
/// debug flag; this is a diagnostic aid confirming configuration.
#[cfg(feature = "rustls-aws-lc-rs")]
#[tokio::test]
async fn kem_group_is_restricted_with_provider() {
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

    let conn = timeout(
        Duration::from_secs(10),
        client.connect(addr, "localhost").expect("start"),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        conn.debug_kem_only(),
        "KEM-only debug flag should be set with aws-lc-rs provider"
    );
    let _ = accept.await.unwrap();
}
