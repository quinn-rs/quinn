//! This example intends to use the smallest amout of code to make a simple QUIC connection.
//!
//! The server issues it's own certificate and passes it to the client to trust.
//!
//! Run:
//! ```text
//! $ cargo run --example connection
//! ```
//!
//! This example will make a QUIC connection on localhost, and you should see output like:
//! ```text
//! [server] incoming connection: id=3680c7d3b3ebd250 addr=127.0.0.1:50469
//! [client] connected: id=61a2df1548935aeb, addr=127.0.0.1:5000
//! ```

use futures::{Future, Stream};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use tokio::runtime::current_thread::{self, Runtime};

mod common;
use common::{make_client_endpoint, make_server_endpoint};

const SERVER_PORT: u16 = 5000;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut runtime = Runtime::new()?;

    let (driver, incoming, server_cert) = make_server_endpoint(("0.0.0.0", SERVER_PORT))?;
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

    let (endpoint, driver) = make_client_endpoint("0.0.0.0:0", &[&server_cert])?;
    // drive UDP socket
    runtime.spawn(driver.map_err(|e| panic!("IO error: {}", e)));

    let server_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), SERVER_PORT));
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

    // We don't need it anymore and dropping the endpoint will make it's driver finish eventually.
    drop(endpoint);

    runtime.run()?;
    Ok(())
}
