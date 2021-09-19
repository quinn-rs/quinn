use std::{
    convert::TryInto,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
};

use anyhow::{Context, Result};
use bytes::Bytes;
use structopt::StructOpt;
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
    cert: quinn::Certificate,
    key: quinn::PrivateKey,
    opt: &Opt,
) -> (SocketAddr, quinn::Incoming) {
    let mut server_config = quinn::ServerConfigBuilder::default();
    server_config
        .certificate(quinn::CertificateChain::from_certs(vec![cert]), key)
        .unwrap();

    let mut server_config = server_config.build();
    server_config.transport = Arc::new(transport_config(opt));

    let mut endpoint = quinn::EndpointBuilder::default();
    endpoint.listen(server_config);
    let (endpoint, incoming) = {
        let _guard = rt.enter();
        endpoint
            .bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
            .unwrap()
    };
    let server_addr = endpoint.local_addr().unwrap();
    drop(endpoint); // Ensure server shuts down when finished
    (server_addr, incoming)
}

/// Create a client endpoint and client connection
pub async fn connect_client(
    server_addr: SocketAddr,
    server_cert: quinn::Certificate,
    opt: Opt,
) -> Result<(quinn::Endpoint, quinn::Connection)> {
    let (endpoint, _) = quinn::EndpointBuilder::default()
        .bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
        .unwrap();

    let mut config = quinn::ClientConfig::default();
    let crypto_config = Arc::get_mut(&mut config.crypto).unwrap();

    crypto_config.ciphersuites.clear();
    crypto_config.ciphersuites.push(opt.cipher.as_rustls());

    let mut client_config = quinn::ClientConfigBuilder::new(config);
    client_config
        .add_certificate_authority(server_cert)
        .unwrap();
    let mut client_config = client_config.build();
    client_config.transport = Arc::new(transport_config(&opt));

    let quinn::NewConnection { connection, .. } = endpoint
        .connect_with(client_config, &server_addr, "localhost")
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

pub async fn send_data_on_stream(
    stream: &mut quinn::SendStream,
    stream_size_mb: usize,
) -> Result<()> {
    const DATA: &[u8] = &[0xAB; 1024 * 1024];
    let bytes_data = Bytes::from_static(DATA);

    for _ in 0..stream_size_mb {
        stream
            .write_chunk(bytes_data.clone())
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
    config
}

#[derive(StructOpt, Debug, Clone, Copy)]
#[structopt(name = "bulk")]
pub struct Opt {
    /// The total number of streams which should be created
    #[structopt(long = "streams", short = "n", default_value = "1")]
    pub streams: usize,
    /// The amount of concurrent streams which should be used
    #[structopt(long = "max_streams", short = "m", default_value = "1")]
    pub max_streams: usize,
    /// The amount of data to transfer on a stream in megabytes
    #[structopt(long = "stream_size", default_value = "1024")]
    pub stream_size_mb: usize,
    /// Show connection stats the at the end of the benchmark
    #[structopt(long = "stats")]
    pub stats: bool,
    /// Whether to use the unordered read API
    #[structopt(long = "unordered")]
    pub read_unordered: bool,
    /// Allows to configure the desired cipher suite
    ///
    /// Valid options are: aes128, aes256, chacha20
    #[structopt(long = "cipher", default_value = "aes128")]
    pub cipher: CipherSuite,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CipherSuite {
    Aes128,
    Aes256,
    Chacha20,
}

impl CipherSuite {
    pub fn as_rustls(self) -> &'static rustls::SupportedCipherSuite {
        match self {
            CipherSuite::Aes128 => &rustls::ciphersuite::TLS13_AES_128_GCM_SHA256,
            CipherSuite::Aes256 => &rustls::ciphersuite::TLS13_AES_256_GCM_SHA384,
            CipherSuite::Chacha20 => &rustls::ciphersuite::TLS13_CHACHA20_POLY1305_SHA256,
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
