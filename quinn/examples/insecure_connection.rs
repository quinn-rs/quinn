//! Demonstrates how to make a QUIC connection that ignores the server certificate.
//!
//! Run:
//! ```text
//! $ cargo run --example insecure_connection --features="rustls/dangerous_configuration"
//! ```

use futures::{Future, Stream};
use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::sync::Arc;
use tokio::runtime::current_thread::{self, Runtime};

use quinn::{ClientConfig, ClientConfigBuilder, Endpoint};

mod common;
use common::make_server_endpoint;

const SERVER_PORT: u16 = 5000;

fn main() -> Result<(), Box<Error>> {
    let mut runtime = Runtime::new()?;

    // server and client are running on the same thread asynchronously
    run_server(&mut runtime, ("0.0.0.0", SERVER_PORT))?;
    run_client(&mut runtime, SERVER_PORT)?;

    runtime.run()?;
    Ok(())
}

/// Runs a QUIC server bound to given address.
fn run_server<A: ToSocketAddrs>(runtime: &mut Runtime, addr: A) -> Result<(), Box<Error>> {
    let (driver, incoming, _server_cert) = make_server_endpoint(addr)?;
    // drive UDP socket
    runtime.spawn(driver.map_err(|e| panic!("IO error: {}", e)));
    let handle_incoming_conns = incoming.take(1).for_each(move |incoming_conn| {
        current_thread::spawn(
            incoming_conn
                .and_then(|(conn_driver, conn, _incoming)| {
                    println!(
                        "[server] incoming connection: id={} addr={}",
                        conn.remote_id(),
                        conn.remote_address()
                    );
                    conn_driver
                })
                .map_err(|_| ()),
        );
        Ok(())
    });
    runtime.spawn(handle_incoming_conns);

    Ok(())
}

fn run_client(runtime: &mut Runtime, server_port: u16) -> Result<(), Box<Error>> {
    let client_cfg = configure_client();
    let mut endpoint_builder = Endpoint::builder();
    endpoint_builder.default_client_config(client_cfg);

    let (driver, endpoint, _) = endpoint_builder.bind("0.0.0.0:0")?;
    runtime.spawn(driver.map_err(|e| panic!("IO error: {}", e)));

    let server_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), server_port));
    let connect = endpoint
        .connect(&server_addr, "localhost")?
        .map_err(|e| panic!("Failed to connect: {}", e))
        .and_then(|(conn_driver, conn, _)| {
            current_thread::spawn(conn_driver.map_err(|_| ()));
            println!(
                "[client] connected: id={}, addr={}",
                conn.remote_id(),
                conn.remote_address()
            );
            Ok(())
        });
    runtime.spawn(connect);

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
