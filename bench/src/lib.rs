use std::{
    convert::TryInto,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    num::ParseIntError,
    str::FromStr,
    sync::Arc,
};

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use rustls::RootCertStore;
use tokio::runtime::{Builder, Runtime};
use tracing::trace;

pub mod stats;

pub fn configure_tracing_subscriber() {
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();
}

/// Creates a server endpoint which runs on the given runtime
pub fn server_endpoint(
    rt: &tokio::runtime::Runtime,
    cert: rustls::Certificate,
    key: rustls::PrivateKey,
    opt: &Opt,
) -> (SocketAddr, quinn::Endpoint) {
    let cert_chain = vec![cert];
    let mut server_config = quinn::ServerConfig::with_single_cert(cert_chain, key).unwrap();
    server_config.transport = Arc::new(transport_config(opt));

    let endpoint = {
        let _guard = rt.enter();
        quinn::Endpoint::server(
            server_config,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
        )
        .unwrap()
    };
    let server_addr = endpoint.local_addr().unwrap();
    (server_addr, endpoint)
}

/// Create a client endpoint and client connection
pub async fn connect_client(
    server_addr: SocketAddr,
    server_cert: rustls::Certificate,
    opt: Opt,
) -> Result<(quinn::Endpoint, quinn::Connection)> {
    let endpoint =
        quinn::Endpoint::client(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0)).unwrap();

    let mut roots = RootCertStore::empty();
    roots.add(&server_cert)?;
    let crypto = rustls::ClientConfig::builder()
        .with_cipher_suites(&[opt.cipher.as_rustls()])
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
    client_config.transport_config(Arc::new(transport_config(&opt)));

    let connection = endpoint
        .connect_with(client_config, server_addr, "localhost")
        .unwrap()
        .await
        .context("unable to connect")?;
    trace!("connected");

    Ok((endpoint, connection))
}

pub async fn drain_stream(stream: &mut quinn::RecvStream, read_unordered: bool) -> Result<usize> {
    let mut read = 0;

    if read_unordered {
        while let Some(chunk) = stream.read_chunk(usize::MAX, false).await? {
            read += chunk.bytes.len();
        }
    } else {
        // These are 32 buffers, for reading approximately 32kB at once
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

        while let Some(n) = stream.read_chunks(&mut bufs[..]).await? {
            read += bufs.iter().take(n).map(|buf| buf.len()).sum::<usize>();
        }
    }

    Ok(read)
}

pub async fn send_data_on_stream(stream: &mut quinn::SendStream, stream_size: u64) -> Result<()> {
    const DATA: &[u8] = &[0xAB; 1024 * 1024];
    let bytes_data = Bytes::from_static(DATA);

    let full_chunks = stream_size / (DATA.len() as u64);
    let remaining = (stream_size % (DATA.len() as u64)) as usize;

    for _ in 0..full_chunks {
        stream
            .write_chunk(bytes_data.clone())
            .await
            .context("failed sending data")?;
    }

    if remaining != 0 {
        stream
            .write_chunk(bytes_data.slice(0..remaining))
            .await
            .context("failed sending data")?;
    }

    stream.finish().await.context("failed finishing stream")?;

    Ok(())
}

pub fn rt() -> Runtime {
    Builder::new_current_thread().enable_all().build().unwrap()
}

pub fn transport_config(opt: &Opt) -> quinn::TransportConfig {
    // High stream windows are chosen because the amount of concurrent streams
    // is configurable as a parameter.
    let mut config = quinn::TransportConfig::default();
    config.max_concurrent_uni_streams(opt.max_streams.try_into().unwrap());
    config.initial_mtu(opt.initial_mtu);

    let mut acks = quinn::AckFrequencyConfig::default();
    acks.ack_eliciting_threshold(10u32.into());
    config.ack_frequency_config(Some(acks));

    config
}

#[derive(Parser, Debug, Clone, Copy)]
#[clap(name = "bulk")]
pub struct Opt {
    /// The total number of clients which should be created
    #[clap(long = "clients", short = 'c', default_value = "1")]
    pub clients: usize,
    /// The total number of streams which should be created
    #[clap(long = "streams", short = 'n', default_value = "1")]
    pub streams: usize,
    /// The amount of concurrent streams which should be used
    #[clap(long = "max_streams", short = 'm', default_value = "1")]
    pub max_streams: usize,
    /// Number of bytes to transmit from server to client
    ///
    /// This can use SI prefixes for sizes. E.g. 1M will transfer 1MiB, 10G
    /// will transfer 10GiB.
    #[clap(long, default_value = "1G", value_parser = parse_byte_size)]
    pub download_size: u64,
    /// Number of bytes to transmit from client to server
    ///
    /// This can use SI prefixes for sizes. E.g. 1M will transfer 1MiB, 10G
    /// will transfer 10GiB.
    #[clap(long, default_value = "0", value_parser = parse_byte_size)]
    pub upload_size: u64,
    /// Show connection stats the at the end of the benchmark
    #[clap(long = "stats")]
    pub stats: bool,
    /// Whether to use the unordered read API
    #[clap(long = "unordered")]
    pub read_unordered: bool,
    /// Allows to configure the desired cipher suite
    ///
    /// Valid options are: aes128, aes256, chacha20
    #[clap(long = "cipher", default_value = "aes128")]
    pub cipher: CipherSuite,
    /// Starting guess for maximum UDP payload size
    #[clap(long, default_value = "1200")]
    pub initial_mtu: u16,
}

fn parse_byte_size(s: &str) -> Result<u64, ParseIntError> {
    let s = s.trim();

    let multiplier = match s.chars().last() {
        Some('T') => 1024 * 1024 * 1024 * 1024,
        Some('G') => 1024 * 1024 * 1024,
        Some('M') => 1024 * 1024,
        Some('k') => 1024,
        _ => 1,
    };

    let s = if multiplier != 1 {
        &s[..s.len() - 1]
    } else {
        s
    };

    let base: u64 = u64::from_str(s)?;

    Ok(base * multiplier)
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CipherSuite {
    Aes128,
    Aes256,
    Chacha20,
}

impl CipherSuite {
    pub fn as_rustls(self) -> rustls::SupportedCipherSuite {
        match self {
            CipherSuite::Aes128 => rustls::cipher_suite::TLS13_AES_128_GCM_SHA256,
            CipherSuite::Aes256 => rustls::cipher_suite::TLS13_AES_256_GCM_SHA384,
            CipherSuite::Chacha20 => rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        }
    }
}

impl FromStr for CipherSuite {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "aes128" => Ok(CipherSuite::Aes128),
            "aes256" => Ok(CipherSuite::Aes256),
            "chacha20" => Ok(CipherSuite::Chacha20),
            _ => Err(anyhow::anyhow!("Unknown cipher suite {}", s)),
        }
    }
}
