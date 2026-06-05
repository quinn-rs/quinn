//! This example demonstrates how to make a QUIC connection that ignores the server certificate.
//!
//! Checkout the `README.md` for guidance.

use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use proto::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint};

mod common;
use common::make_server_endpoint;

#[cfg(feature = "rustls-aws-lc-rs")]
fn default_provider() -> rustls::crypto::CryptoProvider {
    rustls_aws_lc_rs::DEFAULT_PROVIDER
}

#[cfg(all(not(feature = "rustls-aws-lc-rs"), feature = "rustls-ring"))]
fn default_provider() -> rustls::crypto::CryptoProvider {
    rustls_ring::DEFAULT_PROVIDER
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    // server and client are running on the same thread asynchronously
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
    tokio::spawn(run_server(addr));
    run_client(addr).await?;
    Ok(())
}

/// Runs a QUIC server bound to given address.
async fn run_server(addr: SocketAddr) {
    let (endpoint, _server_cert) = make_server_endpoint(addr).unwrap();
    // accept a single connection
    let incoming_conn = endpoint.accept().await.unwrap();
    let conn = incoming_conn.await.unwrap();
    println!(
        "[server] connection accepted: addr={}",
        conn.remote_address()
    );
}

async fn run_client(server_addr: SocketAddr) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let endpoint = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;

    endpoint.set_default_client_config(ClientConfig::new(Arc::new(QuicClientConfig::try_from(
        rustls::ClientConfig::builder(Arc::new(default_provider()))
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth()?,
    )?)));

    // connect to server
    let connection = endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    println!("[client] connected: addr={}", connection.remote_address());
    // Dropping handles allows the corresponding objects to automatically shut down
    drop(connection);
    // Make sure the server has a chance to clean up
    endpoint.wait_idle().await;

    Ok(())
}

/// Dummy certificate verifier that treats any certificate as valid.
/// NOTE, such verification is vulnerable to MITM attacks, but convenient for testing.
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(default_provider())))
    }
}

impl rustls::client::danger::ServerVerifier for SkipServerVerification {
    fn verify_identity(
        &self,
        _identity: &rustls::client::danger::ServerIdentity<'_>,
    ) -> Result<rustls::client::danger::PeerVerified, rustls::Error> {
        Ok(rustls::client::danger::PeerVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        input: &rustls::client::danger::SignatureVerificationInput<'_>,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(input, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        input: &rustls::client::danger::SignatureVerificationInput<'_>,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(input, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::crypto::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }

    fn request_ocsp_response(&self) -> bool {
        false
    }

    fn hash_config(&self, _h: &mut dyn std::hash::Hasher) {}
}
