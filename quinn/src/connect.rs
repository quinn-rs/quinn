use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use crate::{ClientConfig, Connecting, Endpoint};

/// Connect to `server_address`, authenticating it as `server_name`, using a new endpoint
pub fn connect(
    config: ClientConfig,
    server_address: SocketAddr,
    server_name: &str,
) -> io::Result<Connecting> {
    let bind_addr = match server_address {
        SocketAddr::V6(_) => IpAddr::from(Ipv6Addr::UNSPECIFIED),
        SocketAddr::V4(_) => IpAddr::from(Ipv4Addr::UNSPECIFIED),
    };
    let endpoint = Endpoint::client(SocketAddr::new(bind_addr, 0))?;
    let fut = endpoint.connect_with(config, server_address, server_name)?;
    Ok(fut)
}
