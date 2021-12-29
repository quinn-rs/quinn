//! This example demonstrates how to make multiple outgoing connections on a single UDP socket.
//!
//! Checkout the `README.md` for guidance.

use std::{error::Error, net::SocketAddr};

use quinn::Endpoint;

mod common;
use common::{make_client_endpoint, make_server_endpoint};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let addr1 = "127.0.0.1:5000".parse().unwrap();
    let addr2 = "127.0.0.1:5001".parse().unwrap();
    let addr3 = "127.0.0.1:5002".parse().unwrap();
    let server1_cert = run_server(addr1)?;
    let server2_cert = run_server(addr2)?;
    let server3_cert = run_server(addr3)?;

    let client = make_client_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        &[&server1_cert, &server2_cert, &server3_cert],
    )?;

    // connect to multiple endpoints using the same socket/endpoint
    tokio::join!(
        run_client(&client, addr1),
        run_client(&client, addr2),
        run_client(&client, addr3),
    );

    // Make sure the server has a chance to clean up
    client.wait_idle().await;

    Ok(())
}

/// Runs a QUIC server bound to given address and returns server certificate.
fn run_server(addr: SocketAddr) -> Result<Vec<u8>, Box<dyn Error>> {
    let (mut incoming, server_cert) = make_server_endpoint(addr)?;
    // accept a single connection
    tokio::spawn(async move {
        let quinn::NewConnection { connection, .. } = incoming.next().await.unwrap().await.unwrap();
        println!(
            "[server] incoming connection: addr={}",
            connection.remote_address()
        );
    });

    Ok(server_cert)
}

/// Attempt QUIC connection with the given server address.
async fn run_client(endpoint: &Endpoint, server_addr: SocketAddr) {
    let connect = endpoint.connect(server_addr, "localhost").unwrap();
    let quinn::NewConnection { connection, .. } = connect.await.unwrap();
    println!("[client] connected: addr={}", connection.remote_address());
}
