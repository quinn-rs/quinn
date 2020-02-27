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

// Provides the async `next()` method on `incoming` below
use futures::StreamExt;

mod common;
use common::{make_client_endpoint, make_server_endpoint};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_addr = "127.0.0.1:5000".parse().unwrap();
    let (mut incoming, server_cert) = make_server_endpoint(server_addr)?;
    // accept a single connection
    tokio::spawn(async move {
        let incoming_conn = incoming.next().await.unwrap();
        let new_conn = incoming_conn.await.unwrap();
        println!(
            "[server] connection accepted: addr={}",
            new_conn.connection.remote_address()
        );
        // Dropping all handles associated with a connection implicitly closes it
    });

    let endpoint = make_client_endpoint("0.0.0.0:0".parse().unwrap(), &[&server_cert])?;
    // connect to server
    let quinn::NewConnection {
        connection,
        mut uni_streams,
        ..
    } = endpoint
        .connect(&server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    println!("[client] connected: addr={}", connection.remote_address());

    // Waiting for a stream will complete with an error when the server closes the connection
    let _ = uni_streams.next().await;

    // Give the server has a chance to clean up
    endpoint.wait_idle().await;

    Ok(())
}
