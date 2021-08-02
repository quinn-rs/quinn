use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use bytes::Bytes;
use futures_util::StreamExt;
use structopt::StructOpt;
use tokio::sync::Semaphore;
use tracing::{debug, error, info};

use perf::bind_socket;
use perf::stats::{RequestStats, Stats};

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
    /// Send buffer size in bytes
    #[structopt(long, default_value = "2097152")]
    send_buffer_size: usize,
    /// Receive buffer size in bytes
    #[structopt(long, default_value = "2097152")]
    recv_buffer_size: usize,
    /// Specify the local socket address
    #[structopt(long)]
    local_addr: Option<SocketAddr>,
    /// Whether to print connection statistics
    #[structopt(long)]
    conn_stats: bool,
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

    let bind_addr = opt.local_addr.unwrap_or_else(|| {
        let unspec = if addr.is_ipv4() {
            Ipv4Addr::UNSPECIFIED.into()
        } else {
            Ipv6Addr::UNSPECIFIED.into()
        };
        SocketAddr::new(unspec, 0)
    });

    info!("local addr {:?}", bind_addr);

    let socket = bind_socket(bind_addr, opt.send_buffer_size, opt.recv_buffer_size)?;

    let endpoint = quinn::EndpointBuilder::default();

    let (endpoint, _) = endpoint.with_socket(socket).context("binding endpoint")?;

    let mut cfg = quinn::ClientConfigBuilder::default();
    cfg.protocols(&[b"perf"]);
    let mut cfg = cfg.build();

    let tls_config: &mut rustls::ClientConfig = Arc::get_mut(&mut cfg.crypto).unwrap();
    if opt.insecure {
        tls_config
            .dangerous()
            .set_certificate_verifier(SkipServerVerification::new());
    }
    // Configure cipher suites for efficiency
    tls_config.ciphersuites.clear();
    tls_config
        .ciphersuites
        .push(&rustls::ciphersuite::TLS13_AES_128_GCM_SHA256);
    tls_config
        .ciphersuites
        .push(&rustls::ciphersuite::TLS13_AES_256_GCM_SHA384);
    tls_config
        .ciphersuites
        .push(&rustls::ciphersuite::TLS13_CHACHA20_POLY1305_SHA256);

    let stats = Arc::new(Mutex::new(Stats::default()));

    let quinn::NewConnection {
        connection,
        uni_streams,
        ..
    } = endpoint
        .connect_with(cfg, &addr, host_name)?
        .await
        .context("connecting")?;

    info!("established");

    let acceptor = UniAcceptor(Arc::new(tokio::sync::Mutex::new(uni_streams)));

    let drive_fut = async {
        tokio::try_join!(
            drive_uni(
                connection.clone(),
                acceptor,
                stats.clone(),
                opt.uni_requests,
                opt.upload_size,
                opt.download_size
            ),
            drive_bi(
                connection.clone(),
                stats.clone(),
                opt.bi_requests,
                opt.upload_size,
                opt.download_size
            )
        )
    };

    let print_fut = async {
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            {
                let guard = stats.lock().unwrap();
                guard.print();
                if opt.conn_stats {
                    println!("{:?}\n", connection.stats());
                }
            }
        }
    };

    tokio::select! {
        _ = drive_fut => {}
        _ = print_fut => {}
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
    stats: Arc<Mutex<Stats>>,
    concurrency: u64,
    upload: u64,
    download: u64,
) -> Result<()> {
    let sem = Arc::new(Semaphore::new(concurrency as usize));

    loop {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let mut request_stats = RequestStats::new(upload, download);
        let send = connection.open_uni().await?;
        let acceptor = acceptor.clone();
        let stats = stats.clone();

        debug!("sending request on {}", send.id());
        tokio::spawn(async move {
            if let Err(e) = request_uni(send, acceptor, upload, download, &mut request_stats).await
            {
                error!("sending request failed: {:#}", e);
            } else {
                request_stats.success = true;
            }

            {
                let mut guard = stats.lock().unwrap();
                guard.record(request_stats);
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

    const DATA: [u8; 1024 * 1024] = [42; 1024 * 1024];
    while upload > 0 {
        let chunk_len = upload.min(DATA.len() as u64);
        send.write_chunk(Bytes::from_static(&DATA[..chunk_len as usize]))
            .await
            .context("sending response")?;
        upload -= chunk_len;
    }
    send.finish().await?;

    let now = Instant::now();
    stats.download_start = Some(now);

    debug!("upload finished on {}", send.id());
    Ok(())
}

async fn drive_bi(
    connection: quinn::Connection,
    stats: Arc<Mutex<Stats>>,
    concurrency: u64,
    upload: u64,
    download: u64,
) -> Result<()> {
    let sem = Arc::new(Semaphore::new(concurrency as usize));

    loop {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let mut request_stats = RequestStats::new(upload, download);
        let (send, recv) = connection.open_bi().await?;
        let stats = stats.clone();

        debug!("sending request on {}", send.id());
        tokio::spawn(async move {
            if let Err(e) = request_bi(send, recv, upload, download, &mut request_stats).await {
                error!("request failed: {:#}", e);
            } else {
                request_stats.success = true;
            }

            {
                let mut guard = stats.lock().unwrap();
                guard.record(request_stats);
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
