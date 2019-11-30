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

use futures::{StreamExt, TryFutureExt};
use std::{
    error::Error,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs},
};
use tokio::runtime::{Builder, Runtime};

use quinn::Endpoint;

mod common;
use common::{make_client_endpoint, make_server_endpoint};

fn main() -> Result<(), Box<dyn Error>> {
    let mut runtime = Builder::new().basic_scheduler().enable_all().build()?;
    let server1_cert = run_server(&mut runtime, "0.0.0.0:5000")?;
    let server2_cert = run_server(&mut runtime, "0.0.0.0:5001")?;
    let server3_cert = run_server(&mut runtime, "0.0.0.0:5002")?;

    let (client, driver) = runtime.enter(|| {
        make_client_endpoint("0.0.0.0:0", &[&server1_cert, &server2_cert, &server3_cert])
    })?;
    // drive UDP socket
    let handle = runtime.spawn(driver.unwrap_or_else(|e| panic!("IO error: {}", e)));

    // connect to multiple endpoints using the same socket/endpoint
    run_client(&mut runtime, &client, 5000)?;
    run_client(&mut runtime, &client, 5001)?;
    run_client(&mut runtime, &client, 5002)?;
    drop(client);

    runtime.block_on(handle)?;
    Ok(())
}

/// Runs a QUIC server bound to given address and returns server certificate.
fn run_server<A: ToSocketAddrs>(runtime: &mut Runtime, addr: A) -> Result<Vec<u8>, Box<dyn Error>> {
    let (driver, mut incoming, server_cert) = runtime.enter(|| make_server_endpoint(addr))?;
    // drive UDP socket
    runtime.spawn(driver.unwrap_or_else(|e| panic!("IO error: {}", e)));
    // accept a single connection
    runtime.spawn(async move {
        let quinn::NewConnection {
            driver, connection, ..
        } = incoming.next().await.unwrap().await.unwrap();
        println!(
            "[server] incoming connection: id={} addr={}",
            connection.remote_id(),
            connection.remote_address()
        );
        let _ = driver.await;
    });

    Ok(server_cert)
}

/// Attempt QUIC connection with the given server address.
fn run_client(
    runtime: &mut Runtime,
    endpoint: &Endpoint,
    server_port: u16,
) -> Result<(), Box<dyn Error>> {
    let server_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), server_port));
    runtime.spawn(
        endpoint
            .connect(&server_addr, "localhost")?
            .map_ok(|new_conn| {
                tokio::spawn(new_conn.driver.unwrap_or_else(|_| ()));
                let conn = new_conn.connection;
                println!(
                    "[client] connected: id={}, addr={}",
                    conn.remote_id(),
                    conn.remote_address()
                );
            })
            .unwrap_or_else(|e| panic!("Failed to connect: {}", e)),
    );

    Ok(())
}
