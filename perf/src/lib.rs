use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use socket2::{Domain, Protocol, Socket, Type};
use tracing::{debug, warn};

use noprotection::{NoProtectionClientConfig, NoProtectionServerConfig};

#[cfg_attr(not(feature = "json-output"), allow(dead_code))]
pub mod stats;

pub mod noprotection;

pub fn get_cert(
    key_path: Option<&Path>,
    cert_path: Option<&Path>,
) -> Result<(rustls::PrivateKey, Vec<rustls::Certificate>)> {
    match (key_path, cert_path) {
        (Some(key), Some(cert)) => {
            let key = std::fs::read(key).context("reading key")?;
            let cert = std::fs::read(cert).expect("reading cert");

            let mut certs = Vec::new();
            for cert in rustls_pemfile::certs(&mut cert.as_ref()).context("parsing cert")? {
                certs.push(rustls::Certificate(cert));
            }

            Ok((rustls::PrivateKey(key), certs))
        }
        _ => {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            Ok((
                rustls::PrivateKey(cert.serialize_private_key_der()),
                vec![rustls::Certificate(cert.serialize_der().unwrap())],
            ))
        }
    }
}

pub fn get_server_crypto(
    key_path: Option<&Path>,
    cert_path: Option<&Path>,
    keylog: bool,
) -> Result<rustls::ServerConfig> {
    let (key, cert) = get_cert(key_path, cert_path)?;

    let mut crypto = rustls::ServerConfig::builder()
        .with_cipher_suites(PERF_CIPHER_SUITES)
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(cert, key)
        .unwrap();
    crypto.alpn_protocols = vec![b"perf".to_vec()];

    if keylog {
        crypto.key_log = Arc::new(rustls::KeyLogFile::new());
    }

    Ok(crypto)
}

pub fn get_client_crypto(keylog: bool) -> Result<rustls::ClientConfig> {
    let mut crypto = rustls::ClientConfig::builder()
        .with_cipher_suites(PERF_CIPHER_SUITES)
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"perf".to_vec()];

    if keylog {
        crypto.key_log = Arc::new(rustls::KeyLogFile::new());
    }

    Ok(crypto)
}

pub fn get_transport_config(initial_mtu: u16) -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.initial_mtu(initial_mtu);
    transport
}

pub fn get_server_config(
    transport: quinn::TransportConfig,
    crypto: rustls::ServerConfig,
    no_protection: bool,
) -> quinn::ServerConfig {
    let mut server_config = if no_protection {
        quinn::ServerConfig::with_crypto(Arc::new(NoProtectionServerConfig::new(Arc::new(crypto))))
    } else {
        quinn::ServerConfig::with_crypto(Arc::new(crypto))
    };
    server_config.transport_config(Arc::new(transport));
    server_config
}

pub fn get_client_config(
    transport: quinn::TransportConfig,
    crypto: rustls::ClientConfig,
    no_protection: bool,
) -> quinn::ClientConfig {
    let mut client_config = if no_protection {
        quinn::ClientConfig::new(Arc::new(NoProtectionClientConfig::new(Arc::new(crypto))))
    } else {
        quinn::ClientConfig::new(Arc::new(crypto))
    };
    client_config.transport_config(Arc::new(transport));
    client_config
}

pub fn get_local_addr(remote_addr: SocketAddr, local_addr: Option<SocketAddr>) -> SocketAddr {
    local_addr.unwrap_or_else(|| {
        let unspec = if remote_addr.is_ipv4() {
            Ipv4Addr::UNSPECIFIED.into()
        } else {
            Ipv6Addr::UNSPECIFIED.into()
        };
        SocketAddr::new(unspec, 0)
    })
}

pub async fn drain_stream(mut stream: quinn::RecvStream) -> Result<()> {
    #[rustfmt::skip]
        let mut bufs = [
        Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
        Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
        Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
        Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
        Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
        Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
        Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
        Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
    ];
    while stream.read_chunks(&mut bufs[..]).await?.is_some() {}
    debug!("finished reading {}", stream.id());
    Ok(())
}

pub async fn lookup_host(host: &str, resolved_host: Option<IpAddr>) -> Result<(&str, SocketAddr)> {
    let mut host_parts = host.split(':');
    let host_name = host_parts.next().unwrap();
    let host_port = host_parts
        .next()
        .map_or(Ok(443), |x| x.parse())
        .context("parsing port")?;
    let addr = match resolved_host {
        None => tokio::net::lookup_host(host)
            .await
            .context("resolving host")?
            .next()
            .unwrap(),
        Some(ip) => SocketAddr::new(ip, host_port),
    };

    Ok((host_name, addr))
}

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

struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}
