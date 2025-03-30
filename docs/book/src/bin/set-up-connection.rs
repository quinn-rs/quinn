use quinn::{Endpoint, ServerConfig};
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn main() {}

#[allow(dead_code, unused_variables)] // Included in `set-up-connection.md`
async fn server(config: ServerConfig) -> Result<(), Box<dyn Error>> {
    // Bind this endpoint to a UDP socket on the given server address.
    let endpoint = Endpoint::server(config, SERVER_ADDR)?;

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
    let endpoint = Endpoint::client(CLIENT_ADDR)?;

    // Connect to the server passing in the server name which is supposed to be in the server certificate.
    let connection = endpoint.connect(SERVER_ADDR, SERVER_NAME)?.await?;

    // Start transferring, receiving data, see data transfer page.

    Ok(())
}

const SERVER_NAME: &str = "localhost";
const LOCALHOST_V4: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const CLIENT_ADDR: SocketAddr = SocketAddr::new(LOCALHOST_V4, 5000);
const SERVER_ADDR: SocketAddr = SocketAddr::new(LOCALHOST_V4, 5001);
