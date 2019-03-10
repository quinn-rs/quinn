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

use futures::{Future, Stream};
use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use tokio::runtime::current_thread::{self, Runtime};

use quinn::Endpoint;

mod common;
use common::{make_client_endpoint, make_server_endpoint};

fn main() -> Result<(), Box<Error>> {
    let mut runtime = Runtime::new()?;
    let server1_cert = run_server(&mut runtime, "0.0.0.0:5000")?;
    let server2_cert = run_server(&mut runtime, "0.0.0.0:5001")?;
    let server3_cert = run_server(&mut runtime, "0.0.0.0:5002")?;

    let (client, driver) =
        make_client_endpoint("0.0.0.0:0", &[&server1_cert, &server2_cert, &server3_cert])?;
    // drive UDP socket
    runtime.spawn(driver.map_err(|e| panic!("IO error: {}", e)));

    // connect to multiple endpoints using the same socket/endpoint
    run_client(&mut runtime, &client, 5000)?;
    run_client(&mut runtime, &client, 5001)?;
    run_client(&mut runtime, &client, 5002)?;
    drop(client);

    runtime.run()?;
    Ok(())
}

/// Runs a QUIC server bound to given address and returns server certificate.
fn run_server<A: ToSocketAddrs>(runtime: &mut Runtime, addr: A) -> Result<Vec<u8>, Box<Error>> {
    let (driver, incoming, server_cert) = make_server_endpoint(addr)?;
    // drive UDP socket
    runtime.spawn(driver.map_err(|e| panic!("IO error: {}", e)));
    let handle_incoming_conns = incoming
        .take(1)
        .for_each(move |(conn_driver, conn, _incoming)| {
            current_thread::spawn(conn_driver.map_err(|_| ()));
            println!(
                "[server] incoming connection: id={} addr={}",
                conn.remote_id(),
                conn.remote_address()
            );
            Ok(())
        });
    runtime.spawn(handle_incoming_conns);

    Ok(server_cert)
}

/// Attempt QUIC connection with the given server address.
fn run_client(
    runtime: &mut Runtime,
    endpoint: &Endpoint,
    server_port: u16,
) -> Result<(), Box<Error>> {
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
