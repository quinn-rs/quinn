use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use bytes::Bytes;
use futures::StreamExt;
use structopt::StructOpt;
use tokio::sync::Semaphore;
use tracing::{debug, error, info};

/// Connects to a QUIC perf server and maintains a specified pattern of requests until interrupted
#[derive(StructOpt)]
#[structopt(name = "client")]
struct Opt {
    /// Host to connect to
    #[structopt(default_value = "localhost:4433")]
    host: String,
    /// Override DNS resolution for host
    #[structopt(long)]
    ip: Option<IpAddr>,
    /// Number of unidirectional requests to maintain concurrently
    #[structopt(long, default_value = "0")]
    uni_requests: u64,
    /// Number of bidirectional requests to maintain concurrently
    #[structopt(long, default_value = "1")]
    bi_requests: u64,
    /// Number of bytes to request
    #[structopt(long, default_value = "1048576")]
    download_size: u64,
    /// Number of bytes to transmit, in addition to the request header
    #[structopt(long, default_value = "1048576")]
    upload_size: u64,
    /// Whether to skip certificate validation
    #[structopt(long)]
    insecure: bool,
    /// The time to run in seconds
    #[structopt(long, default_value = "60")]
    duration: u64,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let opt = Opt::from_args();

    tracing_subscriber::fmt::init();

    if let Err(e) = run(opt).await {
        error!("{:#}", e);
    }
}

async fn run(opt: Opt) -> Result<()> {
    let mut host_parts = opt.host.split(':');
    let host_name = host_parts.next().unwrap();
    let host_port = host_parts
        .next()
        .map_or(Ok(443), |x| x.parse())
        .context("parsing port")?;
    let addr = match opt.ip {
        None => tokio::net::lookup_host(&opt.host)
            .await
            .context("resolving host")?
            .next()
            .unwrap(),
        Some(ip) => SocketAddr::new(ip, host_port),
    };

    info!("connecting to {} at {}", host_name, addr);

    let endpoint = quinn::EndpointBuilder::default();

    let (endpoint, _) = endpoint
        .bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0))
        .context("binding endpoint")?;

    let mut cfg = quinn::ClientConfigBuilder::default();
    cfg.protocols(&[b"perf"]);
    let mut cfg = cfg.build();
    if opt.insecure {
        let tls_cfg: &mut rustls::ClientConfig = Arc::get_mut(&mut cfg.crypto).unwrap();
        tls_cfg
            .dangerous()
            .set_certificate_verifier(SkipServerVerification::new());
    }

    let quinn::NewConnection {
        connection,
        uni_streams,
        ..
    } = endpoint
        .connect_with(cfg, &addr, &host_name)?
        .await
        .context("connecting")?;

    info!("established");

    let acceptor = UniAcceptor(Arc::new(tokio::sync::Mutex::new(uni_streams)));

    let drive_fut = async {
        tokio::try_join!(
            drive_uni(
                connection.clone(),
                acceptor,
                opt.uni_requests,
                opt.upload_size,
                opt.download_size
            ),
            drive_bi(
                connection.clone(),
                opt.bi_requests,
                opt.upload_size,
                opt.download_size
            )
        )
    };

    tokio::select! {
        _ = drive_fut => {}
        _ = tokio::signal::ctrl_c() => {
            info!("shutting down");
            connection.close(0u32.into(), b"interrupted");
        }
        _ = tokio::time::sleep(Duration::from_secs(opt.duration)) => {
            info!("shutting down");
            connection.close(0u32.into(), b"done");
        }
    }

    endpoint.wait_idle().await;

    // TODO: Print stats

    Ok(())
}

async fn drain_stream(mut stream: quinn::RecvStream, stats: &mut RequestStats) -> Result<()> {
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
    while stream.read_chunks(&mut bufs[..]).await?.is_some() {
        if stats.first_byte.is_none() {
            stats.first_byte = Some(Instant::now());
        }
    }

    let now = Instant::now();
    if stats.first_byte.is_none() {
        stats.first_byte = Some(now);
    }
    stats.download_end = Some(now);

    debug!("response finished on {}", stream.id());
    Ok(())
}

async fn drive_uni(
    connection: quinn::Connection,
    acceptor: UniAcceptor,
    concurrency: u64,
    upload: u64,
    download: u64,
) -> Result<()> {
    let sem = Arc::new(Semaphore::new(concurrency as usize));

    loop {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let mut stats = RequestStats::new(upload, download);
        let send = connection.open_uni().await?;
        let acceptor = acceptor.clone();
        debug!("sending request on {}", send.id());
        tokio::spawn(async move {
            if let Err(e) = request_uni(send, acceptor, upload, download, &mut stats).await {
                error!("sending request failed: {:#}", e);
            } else {
                stats.success = true;
            }
            drop(permit);
        });
    }
}

async fn request_uni(
    send: quinn::SendStream,
    acceptor: UniAcceptor,
    upload: u64,
    download: u64,
    stats: &mut RequestStats,
) -> Result<()> {
    request(send, upload, download, stats).await?;
    let recv = {
        let mut guard = acceptor.0.lock().await;
        guard
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("End of stream"))
    }??;
    drain_stream(recv, stats).await?;
    Ok(())
}

async fn request(
    mut send: quinn::SendStream,
    mut upload: u64,
    download: u64,
    stats: &mut RequestStats,
) -> Result<()> {
    stats.upload_start = Some(Instant::now());
    send.write_all(&download.to_be_bytes()).await?;
    let buf = [42; 4 * 1024];
    while upload > 0 {
        let n = send
            .write(&buf[..upload.min(buf.len() as u64) as usize])
            .await
            .context("sending response")?;
        upload -= n as u64;
    }
    send.finish().await?;

    let now = Instant::now();
    stats.download_start = Some(now);

    debug!("upload finished on {}", send.id());
    Ok(())
}

async fn drive_bi(
    connection: quinn::Connection,
    concurrency: u64,
    upload: u64,
    download: u64,
) -> Result<()> {
    let sem = Arc::new(Semaphore::new(concurrency as usize));

    loop {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let mut stats = RequestStats::new(upload, download);
        let (send, recv) = connection.open_bi().await?;
        debug!("sending request on {}", send.id());
        tokio::spawn(async move {
            if let Err(e) = request_bi(send, recv, upload, download, &mut stats).await {
                error!("request failed: {:#}", e);
            } else {
                stats.success = true;
            }
            drop(permit);
        });
    }
}

async fn request_bi(
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    upload: u64,
    download: u64,
    stats: &mut RequestStats,
) -> Result<()> {
    request(send, upload, download, stats).await?;
    drain_stream(recv, stats).await?;
    Ok(())
}

#[derive(Clone)]
struct UniAcceptor(Arc<tokio::sync::Mutex<quinn::IncomingUniStreams>>);

struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _roots: &rustls::RootCertStore,
        _presented_certs: &[rustls::Certificate],
        _dns_name: webpki::DNSNameRef,
        _ocsp_response: &[u8],
    ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        Ok(rustls::ServerCertVerified::assertion())
    }
}

struct RequestStats {
    start: Instant,
    upload_start: Option<Instant>,
    download_start: Option<Instant>,
    first_byte: Option<Instant>,
    download_end: Option<Instant>,
    finish: Option<Instant>,
    upload_size: u64,
    download_size: u64,
    success: bool,
}

impl RequestStats {
    pub fn new(upload_size: u64, download_size: u64) -> Self {
        Self {
            start: Instant::now(),
            upload_start: None,
            download_start: None,
            first_byte: None,
            upload_size,
            download_size,
            download_end: None,
            finish: None,
            success: false,
        }
    }

    fn fbl(&self) -> Option<Duration> {
        match self.first_byte {
            Some(first_byte) => Some(first_byte.duration_since(self.start)),
            None => None,
        }
    }
}

