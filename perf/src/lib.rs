use std::net::SocketAddr;

use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use tracing::warn;

#[cfg_attr(not(feature = "json-output"), allow(dead_code))]
pub mod stats;

pub fn bind_socket(
    addr: SocketAddr,
    send_buffer_size: usize,
    recv_buffer_size: usize,
) -> Result<std::net::UdpSocket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))
        .context("create socket")?;

    if addr.is_ipv6() {
        socket.set_only_v6(false).context("set_only_v6")?;
    }

    socket
        .bind(&socket2::SockAddr::from(addr))
        .context("binding endpoint")?;
    socket
        .set_send_buffer_size(send_buffer_size)
        .context("send buffer size")?;
    socket
        .set_recv_buffer_size(recv_buffer_size)
        .context("recv buffer size")?;

    let buf_size = socket.send_buffer_size().context("send buffer size")?;
    if buf_size < send_buffer_size {
        warn!(
            "Unable to set desired send buffer size. Desired: {}, Actual: {}",
            send_buffer_size, buf_size
        );
    }

    let buf_size = socket.recv_buffer_size().context("recv buffer size")?;
    if buf_size < recv_buffer_size {
        warn!(
            "Unable to set desired recv buffer size. Desired: {}, Actual: {}",
            recv_buffer_size, buf_size
        );
    }

    Ok(socket.into())
}

pub static PERF_CIPHER_SUITES: &[rustls::SupportedCipherSuite] = &[
    rustls::cipher_suite::TLS13_AES_128_GCM_SHA256,
    rustls::cipher_suite::TLS13_AES_256_GCM_SHA384,
    rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
];
