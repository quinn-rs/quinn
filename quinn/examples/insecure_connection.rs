//! Demonstrates how to make a QUIC connection that ignores the server certificate.
//!
//! Run:
//! ```text
//! $ cargo run --example insecure_connection --features="rustls/dangerous_configuration"
//! ```

use futures::StreamExt;
use std::{error::Error, net::SocketAddr, sync::Arc};

use quinn::{ClientConfig, ClientConfigBuilder, Endpoint};

mod common;
use common::make_server_endpoint;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // server and client are running on the same thread asynchronously
    let addr = "127.0.0.1:5000".parse().unwrap();
    tokio::spawn(run_server(addr));
    run_client(addr).await?;
    Ok(())
}

/// Runs a QUIC server bound to given address.
async fn run_server(addr: SocketAddr) {
    let (mut incoming, _server_cert) = make_server_endpoint(addr).unwrap();
    // accept a single connection
    let incoming_conn = incoming.next().await.unwrap();
    let new_conn = incoming_conn.await.unwrap();
    println!(
        "[server] connection accepted: addr={}",
        new_conn.connection.remote_address()
    );
}

async fn run_client(server_addr: SocketAddr) -> Result<(), Box<dyn Error>> {
    let client_cfg = configure_client();
    let mut endpoint_builder = Endpoint::builder();
    endpoint_builder.default_client_config(client_cfg);

    let (endpoint, _) = endpoint_builder.bind(&"127.0.0.1:0".parse().unwrap())?;

    // connect to server
    let quinn::NewConnection { connection, .. } = endpoint
        .connect(&server_addr, "localhost")
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
struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _roots: &rustls::RootCertStore,
        _presented_certs: &[rustls::Certificate],
        _dns_name: webpki::DNSNameRef,
        _ocsp_response: &[u8],
    ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        Ok(rustls::ServerCertVerified::assertion())
    }
}

fn configure_client() -> ClientConfig {
    let mut cfg = ClientConfigBuilder::default().build();
    let tls_cfg: &mut rustls::ClientConfig = Arc::get_mut(&mut cfg.crypto).unwrap();
    // this is only available when compiled with "dangerous_configuration" feature
    tls_cfg
        .dangerous()
        .set_certificate_verifier(SkipServerVerification::new());
    cfg
}
