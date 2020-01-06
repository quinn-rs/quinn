//! You can have multiple QUIC connections over a single UDP socket. This is especially
//! useful, if you are building a peer-to-peer system where you potentially need to communicate with
//! thousands of peers or if you have a
//! [hole punched](https://en.wikipedia.org/wiki/UDP_hole_punching) UDP socket.
//! In addition, QUIC servers and clients can both operate on the same UDP socket.
//!
//! This example demonstrate how to make multiple outgoing connections on a single UDP socket.
//!
//! Run:
//! ```text
//! $ cargo run --example single_socket
//! ```
//!
//! The expected output should be something like:
//! ```text
//! [server] incoming connection: id=bdd481e853111f09 addr=127.0.0.1:43149
//! [server] incoming connection: id=bfdeae5f7a67d89f addr=127.0.0.1:43149
//! [server] incoming connection: id=36ae757fc0d81d6a addr=127.0.0.1:43149
//! [client] connected: id=751758ed2c93350e, addr=127.0.0.1:5001
//! [client] connected: id=3722568139d78726, addr=127.0.0.1:5000
//! [client] connected: id=621265b108a59fad, addr=127.0.0.1:5002
//! ```
//!
//! Notice how server sees multiple incoming connections with different IDs coming from the same
//! endpoint.

use futures::StreamExt;
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
    futures::future::join_all(vec![
        run_client(&client, addr1),
        run_client(&client, addr2),
        run_client(&client, addr3),
    ])
    .await;

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
    let connect = endpoint.connect(&server_addr, "localhost").unwrap();
    let quinn::NewConnection { connection, .. } = connect.await.unwrap();
    println!("[client] connected: addr={}", connection.remote_address());
}
