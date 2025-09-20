//! Minimal smoke tests to prove two local nodes can connect.
//!
//! These are intended to be fast and robust on developer machines and CI.

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
        .expect("failed to generate self-signed certificate");
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    (vec![cert_der], key_der)
}

async fn do_connect_classical_tls_loopback() {
    // Install a default crypto provider for rustls.
    #[cfg(feature = "rustls-aws-lc-rs")]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    #[cfg(all(not(feature = "rustls-aws-lc-rs"), feature = "rustls-ring"))]
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Server config with a self-signed cert
    let (chain, key) = gen_self_signed_cert();
    let server_cfg =
        ServerConfig::with_single_cert(chain.clone(), key).expect("failed to build ServerConfig");

    // Bind server on an ephemeral port
    let server_addr: SocketAddr = ([127, 0, 0, 1], 0).into();
    let server_ep = Endpoint::server(server_cfg, server_addr).expect("server endpoint");
    let listen_addr = server_ep.local_addr().expect("obtain server local addr");

    // Spawn accept loop for a single connection
    let accept_task = tokio::spawn(async move {
        let inc = timeout(Duration::from_secs(10), server_ep.accept())
            .await
            .expect("server accept wait")
            .expect("incoming");
        let conn = timeout(Duration::from_secs(10), inc)
            .await
            .expect("server handshake wait")
            .expect("server handshake ok");
        conn.remote_address()
    });

    // Client trusts the server's self-signed cert
    let mut roots = rustls::RootCertStore::empty();
    for c in chain {
        roots.add(c).expect("add server cert to roots");
    }
    let client_cfg = ClientConfig::with_root_certificates(Arc::new(roots)).expect("client config");

    // Client endpoint on ephemeral port
    let client_addr: SocketAddr = ([127, 0, 0, 1], 0).into();
    let mut client_ep = Endpoint::client(client_addr).expect("client endpoint");
    client_ep.set_default_client_config(client_cfg);

    // Connect
    let connecting = client_ep
        .connect(listen_addr, "localhost")
        .expect("start connect");
    let conn = timeout(Duration::from_secs(10), connecting)
        .await
        .expect("client connect wait")
        .expect("client connected");

    // Round-trip: ensure both sides completed
    let _server_remote = accept_task.await.expect("accept task join");
    assert!(conn.remote_address().port() > 0);
}

#[tokio::test]
async fn connect_classical_tls_loopback() {
    do_connect_classical_tls_loopback().await;
}

// PQC capability + connection smoke: ensure PQC primitives work and a classical QUIC
// handshake still succeeds on the same runtime. This validates local readiness for
// enabling hybrid KEX in CI or dockerized envs.
#[cfg(feature = "pqc")]
#[tokio::test]
async fn pqc_capability_plus_connection_smoke() {
    use ant_quic::crypto::pqc::{MlDsa65, MlDsaOperations, MlKem768, MlKemOperations};

    // Exercise PQC primitives quickly (keygen + one op each)
    let kem = MlKem768::new();
    let dsa = MlDsa65::new();
    let (kem_pk, kem_sk) = kem.generate_keypair().expect("kem keypair");
    let (ct, ss1) = kem.encapsulate(&kem_pk).expect("kem encap");
    let ss2 = kem.decapsulate(&kem_sk, &ct).expect("kem decap");
    assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    let (dsa_pk, dsa_sk) = dsa.generate_keypair().expect("dsa keypair");
    let sig = dsa.sign(&dsa_sk, b"smoke").expect("dsa sign");
    assert!(dsa.verify(&dsa_pk, b"smoke", &sig).expect("dsa verify"));

    // Then run the classical handshake smoke test to ensure the stack is operational.
    do_connect_classical_tls_loopback().await;
}
