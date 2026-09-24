#![cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
//! Integration tests for [`quinn::Connecting::peer_identity`].

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use quinn::{
    ClientConfig, Endpoint, ServerConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
#[cfg(all(feature = "rustls-aws-lc-rs", not(feature = "rustls-ring")))]
use rustls::crypto::aws_lc_rs::default_provider;
#[cfg(feature = "rustls-ring")]
use rustls::crypto::ring::default_provider;
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    server::WebPkiClientVerifier,
};

/// Generate a self-signed certificate for `localhost`.
fn make_cert() -> (CertificateDer<'static>, PrivatePkcs8KeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    (
        cert.cert.into(),
        PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
    )
}

/// Build a server [`Endpoint`] with a self-signed cert. Returns the endpoint and the cert.
fn make_server(addr: SocketAddr) -> (Endpoint, CertificateDer<'static>) {
    let (cert, key) = make_cert();
    let server_config = ServerConfig::with_single_cert(vec![cert.clone()], key.into()).unwrap();
    let endpoint = Endpoint::server(server_config, addr).unwrap();
    (endpoint, cert)
}

/// Build a client [`Endpoint`] that trusts `server_cert`.
fn make_client(server_cert: CertificateDer<'static>) -> Endpoint {
    let mut roots = RootCertStore::empty();
    roots.add(server_cert).unwrap();
    let client_config = ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
    let endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).unwrap();
    endpoint.set_default_client_config(client_config);
    endpoint
}

/// Build a client [`Endpoint`] that does NOT trust any certificate (TLS will fail).
fn make_untrusting_client() -> Endpoint {
    let (unrelated_cert, _) = make_cert();
    let mut roots = RootCertStore::empty();
    roots.add(unrelated_cert).unwrap();
    let client_config = ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
    let endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).unwrap();
    endpoint.set_default_client_config(client_config);
    endpoint
}

// ---------------------------------------------------------------------------
// Test 1: Happy path — client obtains server cert on Connecting, then finishes
// connecting into a functional Connection
// ---------------------------------------------------------------------------
#[tokio::test]
async fn peer_identity_resolves_to_server_cert_and_connects() {
    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let (server_endpoint, server_cert) = make_server(server_addr);
    let server_addr = server_endpoint.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let _conn = incoming.await.unwrap();
        server_endpoint.wait_idle().await;
    });

    let client_endpoint = make_client(server_cert.clone());
    let connecting = client_endpoint.connect(server_addr, "localhost").unwrap();

    // Call peer_identity() *before* awaiting the Connecting future.
    let identity = connecting.peer_identity().await.unwrap();
    let certs = identity
        .expect("expected a certificate chain from the server")
        .downcast::<Vec<CertificateDer<'static>>>()
        .expect("peer_identity should downcast to Vec<CertificateDer>");

    assert!(
        certs.contains(&server_cert),
        "server certificate was not found in peer identity chain"
    );

    // Verify that after inspecting peer_identity, Connecting can be awaited into a working Connection.
    let conn = connecting.await.unwrap();
    assert_eq!(conn.remote_address(), server_addr);

    server_task.await.unwrap();
}

// ---------------------------------------------------------------------------
// Test 2: Multiple concurrent callers on peer_identity(&self)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn peer_identity_concurrent_callers() {
    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let (server_endpoint, server_cert) = make_server(server_addr);
    let server_addr = server_endpoint.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let _conn = incoming.await.unwrap();
        server_endpoint.wait_idle().await;
    });

    let client_endpoint = make_client(server_cert.clone());
    let connecting = client_endpoint.connect(server_addr, "localhost").unwrap();

    // Two concurrent tasks awaiting peer_identity(&self) on the same Connecting handle.
    let (id1, id2) = tokio::join!(connecting.peer_identity(), connecting.peer_identity());
    let certs1 = id1
        .unwrap()
        .unwrap()
        .downcast::<Vec<CertificateDer<'static>>>()
        .unwrap();
    let certs2 = id2
        .unwrap()
        .unwrap()
        .downcast::<Vec<CertificateDer<'static>>>()
        .unwrap();

    assert!(certs1.contains(&server_cert));
    assert!(certs2.contains(&server_cert));

    let _conn = connecting.await.unwrap();
    server_task.await.unwrap();
}

// ---------------------------------------------------------------------------
// Test 3: Error path — peer_identity() returns Err when TLS verification fails
// ---------------------------------------------------------------------------
#[tokio::test]
async fn peer_identity_fails_when_connection_fails() {
    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let (server_endpoint, _server_cert) = make_server(server_addr);
    let server_addr = server_endpoint.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        if let Some(incoming) = server_endpoint.accept().await {
            let _ = incoming.await;
        }
        server_endpoint.wait_idle().await;
    });

    let client_endpoint = make_untrusting_client();
    let connecting = client_endpoint.connect(server_addr, "localhost").unwrap();

    // peer_identity() should return Err because the TLS handshake fails.
    let result = connecting.peer_identity().await;
    assert!(
        result.is_err(),
        "expected an error when TLS verification fails, got {result:?}"
    );

    server_task.await.unwrap();
}

// ---------------------------------------------------------------------------
// Test 4: No-cert case — server-side peer_identity() is Ok(None) without mTLS
// ---------------------------------------------------------------------------
#[tokio::test]
async fn peer_identity_none_when_no_client_cert() {
    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let (server_endpoint, server_cert) = make_server(server_addr);
    let server_addr = server_endpoint.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let connecting = incoming.accept().unwrap();

        {
            let identity = connecting.peer_identity().await.unwrap();
            assert!(
                identity.is_none(),
                "expected no client certificate when mTLS is not configured"
            );
        }

        let _conn = connecting.await.unwrap();
        server_endpoint.wait_idle().await;
    });

    let client_endpoint = make_client(server_cert);
    let connecting = client_endpoint.connect(server_addr, "localhost").unwrap();
    let _conn = connecting.await.unwrap();

    server_task.await.unwrap();
}

// ---------------------------------------------------------------------------
// Test 5: mTLS on Server (Issue #1922 primary case) — server inspects client cert
// on Connecting before completing the connection
// ---------------------------------------------------------------------------
#[tokio::test]
async fn peer_identity_resolves_client_cert_on_mtls_server() {
    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let (server_cert, server_key) = make_cert();
    let (client_cert, client_key) = make_cert();

    let provider = Arc::new(default_provider());

    // Configure server with mTLS client cert verifier trusting `client_cert`.
    let mut client_roots = RootCertStore::empty();
    client_roots.add(client_cert.clone()).unwrap();
    let client_verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(client_roots), provider.clone())
            .build()
            .unwrap();

    let server_crypto = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(vec![server_cert.clone()], server_key.into())
        .unwrap();

    let server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto).unwrap()));
    let server_endpoint = Endpoint::server(server_config, server_addr).unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();

    let expected_client_cert = client_cert.clone();
    let server_task = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let connecting = incoming.accept().unwrap();

        // Server inspects client certificate during Connecting.
        let identity = connecting.peer_identity().await.unwrap();
        let certs = identity
            .expect("expected client certificate on mTLS connection")
            .downcast::<Vec<CertificateDer<'static>>>()
            .expect("peer_identity should downcast to Vec<CertificateDer>");

        assert!(
            certs.contains(&expected_client_cert),
            "client certificate was not found in peer identity chain"
        );

        let _server_conn = connecting.await.unwrap();
        server_endpoint.wait_idle().await;
    });

    // Configure client to present `client_cert` and trust `server_cert`.
    let mut server_roots = RootCertStore::empty();
    server_roots.add(server_cert).unwrap();

    let client_crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(server_roots)
        .with_client_auth_cert(vec![client_cert], client_key.into())
        .unwrap();

    let client_config =
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
    let client_endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).unwrap();

    let connecting = client_endpoint
        .connect_with(client_config, server_addr, "localhost")
        .unwrap();
    let _client_conn = connecting.await.unwrap();

    server_task.await.unwrap();
}
