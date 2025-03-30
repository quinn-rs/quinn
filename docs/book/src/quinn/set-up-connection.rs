use quinn::{Endpoint, ServerConfig};
use std::error::Error;
use std::net::SocketAddr;

static SERVER_NAME: &str = "localhost";

fn client_addr() -> SocketAddr {
    "127.0.0.1:5000".parse::<SocketAddr>().unwrap()
}

fn server_addr() -> SocketAddr {
    "127.0.0.1:5001".parse::<SocketAddr>().unwrap()
}

#[allow(dead_code, unused_variables)] // Included in `set-up-connection.md`
async fn server(config: ServerConfig) -> Result<(), Box<dyn Error>> {
    // Bind this endpoint to a UDP socket on the given server address.
    let endpoint = Endpoint::server(config, server_addr())?;

    // Start iterating over incoming connections.
    while let Some(conn) = endpoint.accept().await {
        let connection = conn.await?;

        // Save connection somewhere, start transferring, receiving data, see DataTransfer tutorial.
    }

    Ok(())
}

#[allow(dead_code, unused_variables)] // Included in `set-up-connection.md`
async fn client() -> Result<(), Box<dyn Error>> {
    // Bind this endpoint to a UDP socket on the given client address.
    let endpoint = Endpoint::client(client_addr())?;

    // Connect to the server passing in the server name which is supposed to be in the server certificate.
    let connection = endpoint.connect(server_addr(), SERVER_NAME)?.await?;

    // Start transferring, receiving data, see data transfer page.

    Ok(())
}

fn main() {}
