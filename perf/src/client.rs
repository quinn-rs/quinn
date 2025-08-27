#[cfg(feature = "json-output")]
use std::path::PathBuf;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use quinn::{TokioRuntime, crypto::rustls::QuicClientConfig};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

use crate::{
    CommonOpt, PERF_CIPHER_SUITES,
    noprotection::NoProtectionClientConfig,
    parse_byte_size,
    stats::{OpenStreamStats, Stats},
};

/// Connects to a QUIC perf server and maintains a specified pattern of requests until interrupted
#[derive(Parser)]
#[clap(name = "client")]
pub struct Opt {
    /// Host to connect to
    #[clap(default_value = "localhost:4433")]
    host: String,
    /// Override DNS resolution for host
    #[clap(long)]
    ip: Option<IpAddr>,
    /// Specify the local socket address
    #[clap(long)]
    local_addr: Option<SocketAddr>,
    /// Number of unidirectional requests to maintain concurrently
    #[clap(long, default_value = "0")]
    uni_requests: u64,
    /// Number of bidirectional requests to maintain concurrently
    #[clap(long, default_value = "1")]
    bi_requests: u64,
    /// Number of bytes to request
    ///
    /// This can use SI suffixes for sizes. For example, 1M will transfer
    /// 1MiB, 10G will transfer 10GiB.
    #[clap(long, default_value = "1M", value_parser = parse_byte_size)]
    download_size: u64,
    /// Number of bytes to transmit, in addition to the request header
    ///
    /// This can use SI suffixes for sizes. For example, 1M will transfer
    /// 1MiB, 10G will transfer 10GiB.
    #[clap(long, default_value = "1M", value_parser = parse_byte_size)]
    upload_size: u64,
    /// The time to run in seconds
    #[clap(long, default_value = "60")]
    duration: u64,
    /// The interval in seconds at which stats are reported
    #[clap(long, default_value = "1")]
    interval: u64,
    /// File path to output JSON statistics to. If the file is '-', stdout will be used
    #[cfg(feature = "json-output")]
    #[clap(long)]
    json: Option<PathBuf>,
    /// Common options
    #[command(flatten)]
    common: CommonOpt,
}

pub async fn run(opt: Opt) -> Result<()> {
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

    let socket = opt.common.bind_socket(bind_addr)?;

    let mut endpoint_cfg = quinn::EndpointConfig::default();
    endpoint_cfg.max_udp_payload_size(opt.common.max_udp_payload_size)?;

    let endpoint = quinn::Endpoint::new(endpoint_cfg, None, socket, Arc::new(TokioRuntime))?;

    let default_provider = rustls::crypto::ring::default_provider();
    let provider = Arc::new(rustls::crypto::CryptoProvider {
        cipher_suites: PERF_CIPHER_SUITES.into(),
        ..default_provider
    });

    let mut crypto = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new(provider))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"perf".to_vec()];

    if opt.common.keylog {
        crypto.key_log = Arc::new(rustls::KeyLogFile::new());
    }

    let transport = opt.common.build_transport_config(
        #[cfg(feature = "qlog")]
        "perf-client",
    )?;

    let crypto = Arc::new(QuicClientConfig::try_from(crypto)?);
    let mut config = quinn::ClientConfig::new(match opt.common.no_protection {
        true => Arc::new(NoProtectionClientConfig::new(crypto)),
        false => crypto,
    });
    config.transport_config(Arc::new(transport));

    let stream_stats = OpenStreamStats::default();

    let connection = endpoint
        .connect_with(config, addr, host_name)?
        .await
        .context("connecting")?;

    info!("established");

    // This will be used to cancel drive futures
    let shutdown_drive = CancellationToken::new();

    // This will be used to cancel stat future once the drive futures are finished
    let shutdown_stats = CancellationToken::new();

    let shutdown2 = shutdown_drive.clone();
    let connection2 = connection.clone();
    let stream_stats2 = stream_stats.clone();
    let mut drive_uni_fut = tokio::spawn(async move {
        drive_uni(
            shutdown2,
            connection2,
            stream_stats2,
            opt.uni_requests,
            opt.upload_size,
            opt.download_size,
        )
        .await
    });

    let shutdown2 = shutdown_drive.clone();
    let connection2 = connection.clone();
    let stream_stats2 = stream_stats.clone();
    let mut drive_bi_fut = tokio::spawn(async move {
        drive_bi(
            shutdown2,
            connection2,
            stream_stats2,
            opt.bi_requests,
            opt.upload_size,
            opt.download_size,
        )
        .await
    });

    let mut stats = Stats::default();

    let shutdown2 = shutdown_stats.clone();
    let connection2 = connection.clone();
    let mut stats_fut = tokio::spawn(async move {
        let interval_duration = Duration::from_secs(opt.interval);

        let start = Instant::now();

        loop {
            tokio::select! {
                biased;
                _ = shutdown2.cancelled() => {
                    debug!("stats_fut: leaving");

                    stats.on_interval(start, &stream_stats);

                    stats.print();
                    if opt.common.conn_stats {
                        println!("{:?}\n", connection2.stats());
                    }

                    #[cfg(feature = "json-output")]
                    if let Some(path) = opt.json {
                        stats.print_json(path.as_path()).unwrap(); // FIXME handle ?
                    }

                    break;
                },
                _ = tokio::time::sleep(interval_duration) => {
                    stats.on_interval(start, &stream_stats);

                    stats.print();
                    if opt.common.conn_stats {
                        println!("{:?}\n", connection2.stats());
                    }
                }
            }
        }
    });

    let mut drive_uni_fut_exited = false;
    let mut drive_bi_fut_exited = false;
    let mut ctrlc_fut_exited = false;
    let mut duration_fut_exited = false;
    let mut remaining_drive_tasks = 2;
    let mut reason = String::new();
    loop {
        tokio::select! {
            res = &mut drive_uni_fut, if !drive_uni_fut_exited => {
                if let Err(err) = res {
                    error!("drive_uni left with error {err}");
                }

                drive_uni_fut_exited = true;
                remaining_drive_tasks -= 1;

                if remaining_drive_tasks == 0 {
                    // we can cancel stats future as all drive futures have finished
                    shutdown_stats.cancel();
                }
            }
            res = &mut drive_bi_fut, if !drive_bi_fut_exited => {
                if let Err(err) = res {
                    error!("drive_bi left with error {err}");
                }

                drive_bi_fut_exited = true;
                remaining_drive_tasks -= 1;

                if remaining_drive_tasks == 0 {
                    // we can cancel stats future as all drive futures have finished
                    shutdown_stats.cancel();
                }
            }
            _ = &mut stats_fut => {
                break;
            }
            _ = tokio::signal::ctrl_c(), if !ctrlc_fut_exited => {
                info!("shutting down (ctrl-c)");
                ctrlc_fut_exited = true;

                shutdown_drive.cancel();

                reason = "interrupted".to_owned();
            }
            _ = tokio::time::sleep(Duration::from_secs(opt.duration)), if !duration_fut_exited => {
                duration_fut_exited = true;
                info!("shutting down (timeout)");

                shutdown_drive.cancel();

                reason = "done".to_owned();
            }
        }
    }

    connection.close(0u32.into(), &reason.into_bytes());

    endpoint.wait_idle().await;

    Ok(())
}

async fn drain_stream(
    shutdown: CancellationToken,
    mut stream: quinn::RecvStream,
    download: u64,
    stream_stats: OpenStreamStats,
) -> Result<()> {
    if download == 0 {
        return Ok(());
    }

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
    let recv_stream_stats = stream_stats.new_receiver(&stream, download);

    let mut first_byte = true;
    let mut total_bytes_received = 0;
    let download_start = Instant::now();
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                break;
            },
            res = stream.read_chunks(&mut bufs[..]) => {
                if let Some(size) = res? {
                    if first_byte {
                        recv_stream_stats.on_first_byte(download_start.elapsed());
                        first_byte = false;
                    }
                    let bytes_received = bufs[..size].iter().map(|b| b.len()).sum();
                    recv_stream_stats.on_bytes(bytes_received);
                    total_bytes_received += bytes_received as u64;
                } else {
                    break;
                }
            }
        }
    }

    if first_byte {
        recv_stream_stats.on_first_byte(download_start.elapsed());
    }
    recv_stream_stats.finish(download_start.elapsed(), total_bytes_received);

    debug!("response finished on {}", stream.id());
    Ok(())
}

async fn drive_uni(
    shutdown: CancellationToken,
    connection: quinn::Connection,
    stream_stats: OpenStreamStats,
    concurrency: u64,
    upload: u64,
    download: u64,
) -> Result<()> {
    if concurrency == 0 {
        return Ok(());
    }

    let sem = Arc::new(Semaphore::new(concurrency as usize));

    loop {
        if shutdown.is_cancelled() {
            debug!("drive_uni: leaving");
            return Ok(());
        }

        let permit = sem.clone().acquire_owned().await.unwrap();
        let send = connection.open_uni().await?;
        let stream_stats = stream_stats.clone();

        debug!("sending request on {}", send.id());
        let connection = connection.clone();
        let shutdown2 = shutdown.clone();
        tokio::spawn(async move {
            if let Err(e) =
                request_uni(shutdown2, send, connection, upload, download, stream_stats).await
            {
                error!("sending request failed: {:#}", e);
            }

            drop(permit);
        });
    }
}

async fn request_uni(
    shutdown: CancellationToken,
    send: quinn::SendStream,
    conn: quinn::Connection,
    upload: u64,
    download: u64,
    stream_stats: OpenStreamStats,
) -> Result<()> {
    request(
        shutdown.clone(),
        send,
        upload,
        download,
        stream_stats.clone(),
    )
    .await?;
    let recv = conn.accept_uni().await?; // FIXME select ?
    drain_stream(shutdown, recv, download, stream_stats).await?;
    Ok(())
}

async fn request(
    shutdown: CancellationToken,
    mut send: quinn::SendStream,
    upload: u64,
    download: u64,
    stream_stats: OpenStreamStats,
) -> Result<()> {
    // FIXME select ?
    send.write_all(&download.to_be_bytes()).await?;
    if upload == 0 {
        send.finish().unwrap();
        return Ok(());
    }

    let send_stream_stats = stream_stats.new_sender(&send, upload);

    static DATA: [u8; 1024 * 1024] = [42; 1024 * 1024]; // 1MB of data
    let unrolled = true;

    let mut remaining = upload;
    let upload_start = Instant::now();
    while remaining > 0 {
        if unrolled {
            #[rustfmt::skip]
            let mut data_chunks = [ // 32 MB of data
                Bytes::from_static(&DATA), Bytes::from_static(&DATA),
                Bytes::from_static(&DATA), Bytes::from_static(&DATA),
                Bytes::from_static(&DATA), Bytes::from_static(&DATA),
                Bytes::from_static(&DATA), Bytes::from_static(&DATA),
                Bytes::from_static(&DATA), Bytes::from_static(&DATA),
                Bytes::from_static(&DATA), Bytes::from_static(&DATA),
                Bytes::from_static(&DATA), Bytes::from_static(&DATA),
                Bytes::from_static(&DATA), Bytes::from_static(&DATA),
                Bytes::from_static(&DATA), Bytes::from_static(&DATA),
                Bytes::from_static(&DATA), Bytes::from_static(&DATA),
                Bytes::from_static(&DATA), Bytes::from_static(&DATA),
                Bytes::from_static(&DATA), Bytes::from_static(&DATA),
                Bytes::from_static(&DATA), Bytes::from_static(&DATA),
                Bytes::from_static(&DATA), Bytes::from_static(&DATA),
                Bytes::from_static(&DATA), Bytes::from_static(&DATA),
                Bytes::from_static(&DATA), Bytes::from_static(&DATA),
            ];
            let one_data_chunks_len = data_chunks[0].len() as u64;
            let all_data_chunks_len = data_chunks[..data_chunks.len()]
                .iter()
                .map(|b| b.len() as u64)
                .sum::<u64>();

            if remaining > all_data_chunks_len {
                // send all chunks at the same time
                tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => {
                        break;
                    },
                    res = send.write_chunks(&mut data_chunks) => {
                        let res = res.context("sending all chunks")?;

                        info!("sent {} chunks for {} bytes remaining {remaining}", res.chunks, res.bytes);

                        send_stream_stats.on_bytes(res.bytes);
                        remaining -= res.bytes as u64;
                    }
                }
            } else if remaining <= one_data_chunks_len {
                // manually send remaining data
                let chunk_len = remaining.min(DATA.len() as u64);

                tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => {
                        break;
                    },
                    res = send.write_chunk(Bytes::from_static(&DATA[..chunk_len as usize])) => {
                        res.context("sending response")?;

                        info!("sent {chunk_len} bytes remaining {remaining}");

                        send_stream_stats.on_bytes(chunk_len as usize);
                        remaining -= chunk_len;
                    }
                }
            } else {
                // send a bunch of chunks but not all
                let chunk_count = remaining / one_data_chunks_len;
                tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => {
                        break;
                    },
                    res = send.write_chunks(&mut data_chunks[..chunk_count as usize]) => {
                        let res = res.context("sending some chunks")?;

                        info!("sent {} chunks for {} bytes remaining {remaining}", res.chunks, res.bytes);

                        send_stream_stats.on_bytes(res.bytes);
                        remaining -= res.bytes as u64;
                    }
                }
            }
        } else {
            let chunk_len = remaining.min(DATA.len() as u64);

            tokio::select! {
                biased;
                _ = shutdown.cancelled() => {
                    break;
                },
                res = send.write_chunk(Bytes::from_static(&DATA[..chunk_len as usize])) => {
                    res.context("sending response")?;

                    send_stream_stats.on_bytes(chunk_len as usize);
                    remaining -= chunk_len;
                }
            }
        }
    }

    send.finish().unwrap();
    // Wait for stream to close
    let _ = send.stopped().await;

    let elapsed = upload_start.elapsed();
    send_stream_stats.finish(elapsed, upload - remaining);

    debug!("upload finished on {}", send.id());
    Ok(())
}

async fn drive_bi(
    shutdown: CancellationToken,
    connection: quinn::Connection,
    stream_stats: OpenStreamStats,
    concurrency: u64,
    upload: u64,
    download: u64,
) -> Result<()> {
    if concurrency == 0 {
        return Ok(());
    }

    let sem = Arc::new(Semaphore::new(concurrency as usize));

    loop {
        if shutdown.is_cancelled() {
            debug!("drive_bi: leaving");
            return Ok(());
        }

        let permit = sem.clone().acquire_owned().await.unwrap();
        let (send, recv) = connection.open_bi().await?;
        let stream_stats = stream_stats.clone();

        debug!("sending request on {}", send.id());
        let shutdown2 = shutdown.clone();
        // FIXME store handle and wait for everyone to get cancelled before leaving the function
        tokio::spawn(async move {
            if let Err(e) = request_bi(shutdown2, send, recv, upload, download, stream_stats).await
            {
                error!("request failed: {:#}", e);
            }

            drop(permit);
        });
    }
}

async fn request_bi(
    shutdown: CancellationToken,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    upload: u64,
    download: u64,
    stream_stats: OpenStreamStats,
) -> Result<()> {
    request(
        shutdown.clone(),
        send,
        upload,
        download,
        stream_stats.clone(),
    )
    .await?;
    drain_stream(shutdown, recv, download, stream_stats).await?;
    Ok(())
}

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Arc<Self> {
        Arc::new(Self(provider))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
