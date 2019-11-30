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

use futures::{StreamExt, TryFutureExt};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use tokio::runtime::Builder;

mod common;
use common::{make_client_endpoint, make_server_endpoint};

const SERVER_PORT: u16 = 5000;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut runtime = Builder::new().basic_scheduler().enable_all().build()?;

    let server_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), SERVER_PORT));
    let (driver, mut incoming, server_cert) =
        runtime.enter(|| make_server_endpoint(server_addr))?;
    // drive server's UDP socket
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

    let (endpoint, driver) =
        runtime.enter(|| make_client_endpoint("0.0.0.0:0", &[&server_cert]))?;
    // drive client's UDP socket
    runtime.spawn(driver.unwrap_or_else(|e| panic!("IO error: {}", e)));
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

    runtime.block_on(handle)?;
    Ok(())
}
