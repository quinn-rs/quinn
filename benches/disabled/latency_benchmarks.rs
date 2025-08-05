//! Benchmarks for latency and round-trip time measurements
//!
//! This benchmark suite measures round-trip times for different packet sizes,
//! connection types, and network conditions.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use ant_quic::{
    ClientConfig, Connection, Endpoint, EndpointConfig, RecvStream, SendStream, ServerConfig,
    TransportConfig,
};
use bytes::Bytes;
use criterion::{BatchSize, BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use rand::{RngCore, thread_rng};
use tokio::runtime::Runtime;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Test packet sizes for latency benchmarks
const PACKET_SIZES: &[usize] = &[
    64,   // Minimum
    256,  // Small
    512,  // Medium
    1024, // 1KB
    1400, // Near MTU
    4096, // Large
];

/// Number of round-trips to measure
const PING_COUNT: usize = 100;

/// Generate a test certificate and private key
fn generate_test_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = cert.cert.der();
    let key_der = cert.key_pair.serialize_der();

    (cert_der.clone(), key_der.try_into().unwrap())
}

/// Skip server certificate verification for testing
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Create endpoints optimized for low latency
async fn create_latency_endpoints()
-> Result<(Endpoint, Endpoint, SocketAddr), Box<dyn std::error::Error>> {
    // Server configuration
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
    let mut server_config = EndpointConfig::default();

    let (cert, key) = generate_test_cert();
    let mut server_cfg = ServerConfig::with_single_cert(vec![cert], key)?;
    let mut transport = TransportConfig::default();

    // Configure for low latency
    transport.max_concurrent_bidi_streams(50u32.into());
    transport.max_concurrent_uni_streams(50u32.into());
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    transport.max_idle_timeout(Some(Duration::from_secs(30).try_into()?));

    server_cfg.transport_config(Arc::new(transport.clone()));

    let server = Endpoint::server(server_config, server_addr, server_cfg)?;
    let server_addr = server.local_addr()?;

    // Client configuration
    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
    let mut client_config = EndpointConfig::default();

    let mut client_cfg = ClientConfig::new(Arc::new(
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth(),
    ));
    client_cfg.transport_config(Arc::new(transport));

    let client = Endpoint::client(client_config, client_addr)?;
    client.set_default_client_config(client_cfg);

    Ok((server, client, server_addr))
}

/// Ping server that immediately echoes received data
async fn run_ping_server(conn: Connection) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        match conn.accept_bi().await {
            Ok((mut send, mut recv)) => {
                tokio::spawn(async move {
                    // Read and immediately echo
                    let mut buffer = vec![0u8; 4096];
                    loop {
                        match recv.read(&mut buffer).await {
                            Ok(Some(n)) => {
                                if send.write_all(&buffer[..n]).await.is_err() {
                                    break;
                                }
                            }
                            Ok(None) => break,
                            Err(_) => break,
                        }
                    }
                    let _ = send.finish().await;
                });
            }
            Err(_) => break,
        }
    }
    Ok(())
}

/// Measure single packet round-trip time
async fn measure_rtt(
    send: &mut SendStream<'_>,
    recv: &mut RecvStream<'_>,
    data: &[u8],
) -> Result<Duration, Box<dyn std::error::Error>> {
    let start = Instant::now();

    // Send ping
    send.write_all(data).await?;

    // Receive pong
    let mut buffer = vec![0u8; data.len()];
    recv.read_exact(&mut buffer).await?;

    Ok(start.elapsed())
}

/// Benchmark basic round-trip times
fn bench_basic_rtt(c: &mut Criterion) {
    let mut group = c.benchmark_group("basic_rtt");
    let rt = Runtime::new().unwrap();

    for &size in PACKET_SIZES {
        group.bench_with_input(BenchmarkId::new("packet_size", size), &size, |b, &size| {
            b.iter_batched(
                || {
                    let rt_handle = tokio::runtime::Handle::current();
                    rt_handle.block_on(async {
                        let (server, client, server_addr) =
                            create_latency_endpoints().await.unwrap();

                        // Run ping server
                        tokio::spawn(async move {
                            while let Some(conn) = server.accept().await {
                                tokio::spawn(async move {
                                    if let Ok(conn) = conn.await {
                                        let _ = run_ping_server(conn).await;
                                    }
                                });
                            }
                        });

                        let connecting = client.connect(server_addr, "localhost").unwrap();
                        let conn = connecting.await.unwrap();
                        let (send, recv) = conn.open_bi().await.unwrap();

                        let mut data = vec![0u8; size];
                        thread_rng().fill_bytes(&mut data);

                        (send, recv, data)
                    })
                },
                |(mut send, mut recv, data)| {
                    let rt_handle = tokio::runtime::Handle::current();
                    rt_handle.block_on(async {
                        let rtt = measure_rtt(&mut send, &mut recv, &data).await.unwrap();
                        black_box(rtt);
                    })
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

/// Benchmark RTT jitter (consistency)
fn bench_rtt_jitter(c: &mut Criterion) {
    let mut group = c.benchmark_group("rtt_jitter");
    let rt = Runtime::new().unwrap();

    let packet_size = 512; // Use medium size packet

    group.bench_function("jitter_measurement", |b| {
        b.iter_batched(
            || {
                let rt_handle = tokio::runtime::Handle::current();
                rt_handle.block_on(async {
                    let (server, client, server_addr) = create_latency_endpoints().await.unwrap();

                    // Run ping server
                    tokio::spawn(async move {
                        while let Some(conn) = server.accept().await {
                            tokio::spawn(async move {
                                if let Ok(conn) = conn.await {
                                    let _ = run_ping_server(conn).await;
                                }
                            });
                        }
                    });

                    let connecting = client.connect(server_addr, "localhost").unwrap();
                    let conn = connecting.await.unwrap();
                    let (send, recv) = conn.open_bi().await.unwrap();

                    let mut data = vec![0u8; packet_size];
                    thread_rng().fill_bytes(&mut data);

                    (send, recv, data)
                })
            },
            |(mut send, mut recv, data)| {
                let rt_handle = tokio::runtime::Handle::current();
                rt_handle.block_on(async {
                    let mut rtts = Vec::with_capacity(PING_COUNT);

                    // Measure multiple RTTs
                    for _ in 0..PING_COUNT {
                        let rtt = measure_rtt(&mut send, &mut recv, &data).await.unwrap();
                        rtts.push(rtt.as_micros() as f64);
                    }

                    // Calculate jitter metrics
                    let mean = rtts.iter().sum::<f64>() / rtts.len() as f64;
                    let variance = rtts.iter().map(|&rtt| (rtt - mean).powi(2)).sum::<f64>()
                        / rtts.len() as f64;
                    let std_dev = variance.sqrt();

                    black_box((mean, std_dev));
                })
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Benchmark latency under concurrent load
fn bench_concurrent_latency(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_latency");
    let rt = Runtime::new().unwrap();

    let concurrent_streams = [1, 5, 10, 20];
    let packet_size = 256;

    for &stream_count in &concurrent_streams {
        group.bench_with_input(
            BenchmarkId::new("concurrent_streams", stream_count),
            &stream_count,
            |b, &stream_count| {
                b.iter_batched(
                    || {
                        let rt_handle = tokio::runtime::Handle::current();
                        rt_handle.block_on(async {
                            let (server, client, server_addr) =
                                create_latency_endpoints().await.unwrap();

                            // Run ping server
                            tokio::spawn(async move {
                                while let Some(conn) = server.accept().await {
                                    tokio::spawn(async move {
                                        if let Ok(conn) = conn.await {
                                            let _ = run_ping_server(conn).await;
                                        }
                                    });
                                }
                            });

                            let connecting = client.connect(server_addr, "localhost").unwrap();
                            let conn = connecting.await.unwrap();

                            // Open multiple streams
                            let mut streams = Vec::new();
                            for _ in 0..stream_count {
                                let (send, recv) = conn.open_bi().await.unwrap();
                                streams.push((send, recv));
                            }

                            let mut data = vec![0u8; packet_size];
                            thread_rng().fill_bytes(&mut data);

                            (streams, data)
                        })
                    },
                    |(mut streams, data)| {
                        let rt_handle = tokio::runtime::Handle::current();
                        rt_handle.block_on(async {
                            let start = Instant::now();

                            // Send pings on all streams concurrently
                            let mut handles = vec![];

                            for (mut send, mut recv) in streams {
                                let data = data.clone();
                                let handle = tokio::spawn(async move {
                                    measure_rtt(&mut send, &mut recv, &data).await.unwrap()
                                });
                                handles.push(handle);
                            }

                            // Collect all RTTs
                            let mut total_rtt = Duration::ZERO;
                            for handle in handles {
                                let rtt = handle.await.unwrap();
                                total_rtt += rtt;
                            }

                            let avg_rtt = total_rtt / stream_count as u32;
                            let elapsed = start.elapsed(); // Total time for all

                            black_box((avg_rtt, elapsed));
                        })
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

/// Benchmark latency percentiles
fn bench_latency_percentiles(c: &mut Criterion) {
    let mut group = c.benchmark_group("latency_percentiles");
    group.sample_size(10); // Reduce sample size as we measure many RTTs internally

    let rt = Runtime::new().unwrap();
    let packet_size = 512;

    group.bench_function("percentile_distribution", |b| {
        b.iter_batched(
            || {
                let rt_handle = tokio::runtime::Handle::current();
                rt_handle.block_on(async {
                    let (server, client, server_addr) = create_latency_endpoints().await.unwrap();

                    // Run ping server
                    tokio::spawn(async move {
                        while let Some(conn) = server.accept().await {
                            tokio::spawn(async move {
                                if let Ok(conn) = conn.await {
                                    let _ = run_ping_server(conn).await;
                                }
                            });
                        }
                    });

                    let connecting = client.connect(server_addr, "localhost").unwrap();
                    let conn = connecting.await.unwrap();
                    let (send, recv) = conn.open_bi().await.unwrap();

                    let mut data = vec![0u8; packet_size];
                    thread_rng().fill_bytes(&mut data);

                    (send, recv, data)
                })
            },
            |(mut send, mut recv, data)| {
                let rt_handle = tokio::runtime::Handle::current();
                rt_handle.block_on(async {
                    let mut rtts = Vec::with_capacity(1000);

                    // Collect many RTT samples
                    for _ in 0..1000 {
                        let rtt = measure_rtt(&mut send, &mut recv, &data).await.unwrap();
                        rtts.push(rtt.as_micros() as u64);
                    }

                    // Sort for percentile calculation
                    rtts.sort_unstable();

                    // Calculate percentiles
                    let p50 = rtts[rtts.len() * 50 / 100];
                    let p90 = rtts[rtts.len() * 90 / 100];
                    let p95 = rtts[rtts.len() * 95 / 100];
                    let p99 = rtts[rtts.len() * 99 / 100];

                    black_box((p50, p90, p95, p99));
                })
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Benchmark connection handshake latency
fn bench_handshake_latency(c: &mut Criterion) {
    let mut group = c.benchmark_group("handshake_latency");
    let rt = Runtime::new().unwrap();

    group.bench_function("quic_handshake", |b| {
        b.iter_batched(
            || {
                let rt_handle = tokio::runtime::Handle::current();
                rt_handle.block_on(async {
                    let (server, client, server_addr) = create_latency_endpoints().await.unwrap();

                    // Accept connections on server
                    tokio::spawn(async move {
                        while let Some(conn) = server.accept().await {
                            tokio::spawn(async move {
                                let _ = conn.await;
                            });
                        }
                    });

                    (client, server_addr)
                })
            },
            |(client, server_addr)| {
                let rt_handle = tokio::runtime::Handle::current();
                rt_handle.block_on(async {
                    let start = Instant::now();

                    // Measure handshake time
                    let connecting = client.connect(server_addr, "localhost").unwrap();
                    let _conn = connecting.await.unwrap();

                    let handshake_time = start.elapsed();
                    black_box(handshake_time);
                })
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Benchmark first byte latency
fn bench_first_byte_latency(c: &mut Criterion) {
    let mut group = c.benchmark_group("first_byte_latency");
    let rt = Runtime::new().unwrap();

    group.bench_function("time_to_first_byte", |b| {
        b.iter_batched(
            || {
                let rt_handle = tokio::runtime::Handle::current();
                rt_handle.block_on(async {
                    let (server, client, server_addr) = create_latency_endpoints().await.unwrap();

                    // Server sends data immediately on connection
                    tokio::spawn(async move {
                        while let Some(conn) = server.accept().await {
                            tokio::spawn(async move {
                                if let Ok(conn) = conn.await {
                                    if let Ok((mut send, _recv)) = conn.accept_bi().await {
                                        let _ = send.write_all(b"Hello").await;
                                        let _ = send.finish();
                                    }
                                }
                            });
                        }
                    });

                    (client, server_addr)
                })
            },
            |(client, server_addr)| {
                let rt_handle = tokio::runtime::Handle::current();
                rt_handle.block_on(async {
                    let start = Instant::now();

                    // Connect and receive first byte
                    let connecting = client.connect(server_addr, "localhost").unwrap();
                    let conn = connecting.await.unwrap();
                    let (_send, mut recv) = conn.open_bi().await.unwrap();

                    let mut buf = [0u8; 1];
                    recv.read_exact(&mut buf).await.unwrap();

                    let time_to_first_byte = start.elapsed();
                    black_box(time_to_first_byte);
                })
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_basic_rtt,
    bench_rtt_jitter,
    bench_concurrent_latency,
    bench_latency_percentiles,
    bench_handshake_latency,
    bench_first_byte_latency
);

criterion_main!(benches);
