use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use bytes::Bytes;
use structopt::StructOpt;
use tokio::sync::Semaphore;
use tracing::{debug, error, info};

use perf::bind_socket;
use perf::stats::{OpenStreamStats, Stats};
#[cfg(feature = "json-output")]
use std::path::PathBuf;

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
    /// The time to run in seconds
    #[structopt(long, default_value = "60")]
    duration: u64,
    /// The interval in seconds at which stats are reported
    #[structopt(long, default_value = "1")]
    interval: u64,
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
    /// File path to output JSON statistics to. If the file is '-', stdout will be used
    #[cfg(feature = "json-output")]
    #[structopt(long)]
    json: Option<PathBuf>,
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

    let (endpoint, _) = quinn::Endpoint::new(Default::default(), None, socket)?;

    let mut crypto = rustls::ClientConfig::builder()
        .with_cipher_suites(perf::PERF_CIPHER_SUITES)
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"perf".to_vec()];

    let cfg = quinn::ClientConfig::new(Arc::new(crypto));

    let stream_stats = OpenStreamStats::default();

    let quinn::NewConnection {
        connection,
        uni_streams,
        ..
    } = endpoint
        .connect_with(cfg, addr, host_name)?
        .await
        .context("connecting")?;

    info!("established");

    let acceptor = UniAcceptor(Arc::new(tokio::sync::Mutex::new(uni_streams)));

    let drive_fut = async {
        tokio::try_join!(
            drive_uni(
                connection.clone(),
                acceptor,
                stream_stats.clone(),
                opt.uni_requests,
                opt.upload_size,
                opt.download_size
            ),
            drive_bi(
                connection.clone(),
                stream_stats.clone(),
                opt.bi_requests,
                opt.upload_size,
                opt.download_size
            )
        )
    };

    let mut stats = Stats::default();

    let stats_fut = async {
        let interval_duration = Duration::from_secs(opt.interval);

        loop {
            let start = Instant::now();
            tokio::time::sleep(interval_duration).await;
            {
                stats.on_interval(start, &stream_stats);

                stats.print();
                if opt.conn_stats {
                    println!("{:?}\n", connection.stats());
                }
            }
        }
    };

    tokio::select! {
        _ = drive_fut => {}
        _ = stats_fut => {}
        _ = tokio::signal::ctrl_c() => {
            info!("shutting down");
            connection.close(0u32.into(), b"interrupted");
        }
        // Add a small duration so the final interval can be reported
        _ = tokio::time::sleep(Duration::from_secs(opt.duration) + Duration::from_millis(200)) => {
            info!("shutting down");
            connection.close(0u32.into(), b"done");
        }
    }

    endpoint.wait_idle().await;

    #[cfg(feature = "json-output")]
    if let Some(path) = opt.json {
        stats.print_json(path.as_path())?;
    }

    Ok(())
}

async fn drain_stream(
    mut stream: quinn::RecvStream,
    download: u64,
    stream_stats: OpenStreamStats,
) -> Result<()> {
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
    let download_start = Instant::now();
    let recv_stream_stats = stream_stats.new_receiver(&stream, download);

    let mut first_byte = true;

    while let Some(size) = stream.read_chunks(&mut bufs[..]).await? {
        if first_byte {
            recv_stream_stats.on_first_byte(download_start.elapsed());
            first_byte = false;
        }
        let bytes_received = bufs[..size].iter().map(|b| b.len()).sum();
        recv_stream_stats.on_bytes(bytes_received);
    }

    if first_byte {
        recv_stream_stats.on_first_byte(download_start.elapsed());
    }
    recv_stream_stats.finish(download_start.elapsed());

    debug!("response finished on {}", stream.id());
    Ok(())
}

async fn drive_uni(
    connection: quinn::Connection,
    acceptor: UniAcceptor,
    stream_stats: OpenStreamStats,
    concurrency: u64,
    upload: u64,
    download: u64,
) -> Result<()> {
    let sem = Arc::new(Semaphore::new(concurrency as usize));

    loop {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let send = connection.open_uni().await?;
        let acceptor = acceptor.clone();
        let stream_stats = stream_stats.clone();

        debug!("sending request on {}", send.id());
        tokio::spawn(async move {
            if let Err(e) = request_uni(send, acceptor, upload, download, stream_stats).await {
                error!("sending request failed: {:#}", e);
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
    stream_stats: OpenStreamStats,
) -> Result<()> {
    request(send, upload, download, stream_stats.clone()).await?;
    let recv = {
        let mut guard = acceptor.0.lock().await;
        guard
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("End of stream"))
    }??;
    drain_stream(recv, download, stream_stats).await?;
    Ok(())
}

async fn request(
    mut send: quinn::SendStream,
    mut upload: u64,
    download: u64,
    stream_stats: OpenStreamStats,
) -> Result<()> {
    let upload_start = Instant::now();
    send.write_all(&download.to_be_bytes()).await?;
    if upload == 0 {
        send.finish().await?;
        return Ok(());
    }

    let send_stream_stats = stream_stats.new_sender(&send, upload);

    const DATA: [u8; 1024 * 1024] = [42; 1024 * 1024];
    while upload > 0 {
        let chunk_len = upload.min(DATA.len() as u64);
        send.write_chunk(Bytes::from_static(&DATA[..chunk_len as usize]))
            .await
            .context("sending response")?;
        send_stream_stats.on_bytes(chunk_len as usize);
        upload -= chunk_len;
    }
    send.finish().await?;
    send_stream_stats.finish(upload_start.elapsed());

    debug!("upload finished on {}", send.id());
    Ok(())
}

async fn drive_bi(
    connection: quinn::Connection,
    stream_stats: OpenStreamStats,
    concurrency: u64,
    upload: u64,
    download: u64,
) -> Result<()> {
    let sem = Arc::new(Semaphore::new(concurrency as usize));

    loop {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let (send, recv) = connection.open_bi().await?;
        let stream_stats = stream_stats.clone();

        debug!("sending request on {}", send.id());
        tokio::spawn(async move {
            if let Err(e) = request_bi(send, recv, upload, download, stream_stats).await {
                error!("request failed: {:#}", e);
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
    stream_stats: OpenStreamStats,
) -> Result<()> {
    request(send, upload, download, stream_stats.clone()).await?;
    drain_stream(recv, download, stream_stats).await?;
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
