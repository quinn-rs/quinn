//! Demonstrates how to make a QUIC connection that ignores the server certificate.
//!
//! Run:
//! ```text
//! $ cargo run --example insecure_connection --features="rustls/dangerous_configuration"
//! ```

use futures::{StreamExt, TryFutureExt};
use std::{
    error::Error,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs},
    sync::Arc,
};
use tokio::{
    runtime::{Builder, Runtime},
    task::JoinHandle,
};

use quinn::{ClientConfig, ClientConfigBuilder, Endpoint};

mod common;
use common::make_server_endpoint;

const SERVER_PORT: u16 = 5000;

fn main() -> Result<(), Box<dyn Error>> {
    let mut runtime = Builder::new().basic_scheduler().enable_all().build()?;

    // server and client are running on the same thread asynchronously
    run_server(&mut runtime, ("0.0.0.0", SERVER_PORT))?;
    let handle = run_client(&mut runtime, SERVER_PORT)?;

    runtime.block_on(handle)?;
    Ok(())
}

/// Runs a QUIC server bound to given address.
fn run_server<A: ToSocketAddrs>(runtime: &mut Runtime, addr: A) -> Result<(), Box<dyn Error>> {
    let (driver, mut incoming, _server_cert) = runtime.enter(|| make_server_endpoint(addr))?;
    // drive UDP socket
    runtime.spawn(driver.unwrap_or_else(|e| panic!("IO error: {}", e)));
    // accept a single connection
    runtime.spawn(async move {
        let incoming_conn = incoming.next().await.unwrap();
        let new_conn = incoming_conn.await.unwrap();
        println!(
            "[server] connection accepted: id={} addr={}",
            new_conn.connection.remote_id(),
            new_conn.connection.remote_address()
        );
        // Drive the connection to completion
        if let Err(e) = new_conn.driver.await {
            println!("[server] connection lost: {}", e);
        }
    });
    Ok(())
}

fn run_client(runtime: &mut Runtime, server_port: u16) -> Result<JoinHandle<()>, Box<dyn Error>> {
    let client_cfg = configure_client();
    let mut endpoint_builder = Endpoint::builder();
    endpoint_builder.default_client_config(client_cfg);

    let (driver, endpoint, _) =
        runtime.enter(|| endpoint_builder.bind(&"0.0.0.0:0".parse().unwrap()))?;
    runtime.spawn(driver.unwrap_or_else(|e| panic!("IO error: {}", e)));

    let server_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), server_port));
    // connect to server
    let handle = runtime.spawn(async move {
        let quinn::NewConnection {
            driver, connection, ..
        } = endpoint
            .connect(&server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        println!(
            "[client] connected: id={}, addr={}",
            connection.remote_id(),
            connection.remote_address()
        );
        // Dropping handles allows the corresponding objects to automatically shut down
        drop((endpoint, connection));
        // Drive the connection to completion
        driver.await.unwrap();
    });

    Ok(handle)
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
