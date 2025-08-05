//! Benchmarks for data throughput performance
//!
//! This benchmark suite measures data transfer rates for different message sizes,
//! connection types, and stream configurations.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use ant_quic::{
    ClientConfig, Connection, Endpoint, EndpointConfig, RecvStream, SendStream, ServerConfig,
    TransportConfig,
};
use bytes::Bytes;
use criterion::{
    BatchSize, BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main,
};
use rand::{RngCore, thread_rng};
use tokio::runtime::Runtime;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Test data sizes for throughput benchmarks
const DATA_SIZES: &[usize] = &[
    1024,             // 1 KB
    10 * 1024,        // 10 KB
    100 * 1024,       // 100 KB
    1024 * 1024,      // 1 MB
    10 * 1024 * 1024, // 10 MB
];

/// Generate random test data
fn generate_test_data(size: usize) -> Bytes {
    let mut data = vec![0u8; size];
    thread_rng().fill_bytes(&mut data);
    Bytes::from(data)
}

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

/// Create test endpoints for throughput testing
async fn create_throughput_endpoints()
-> Result<(Endpoint, Endpoint, SocketAddr), Box<dyn std::error::Error>> {
    // Server configuration
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
    let mut server_config = EndpointConfig::default();

    let (cert, key) = generate_test_cert();
    let mut server_cfg = ServerConfig::with_single_cert(vec![cert], key)?;
    let mut transport = TransportConfig::default();

    // Configure for throughput testing
    transport.max_concurrent_bidi_streams(100u32.into());
    transport.max_concurrent_uni_streams(100u32.into());
    transport.receive_window(10 * 1024 * 1024u32.into()); // 10MB window
    transport.send_window(10 * 1024 * 1024);
    transport.stream_receive_window(5 * 1024 * 1024u32.into()); // 5MB per stream
    transport.keep_alive_interval(Some(Duration::from_secs(10)));

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

/// Echo server handler for throughput testing
async fn run_echo_server(conn: Connection) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                tokio::spawn(handle_echo_stream(send, recv));
            }
            Err(_) => break,
        }
    }
    Ok(())
}

/// Handle individual echo stream
async fn handle_echo_stream(
    mut send: SendStream<'_>,
    mut recv: RecvStream<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Echo all received data back
    let data = recv.read_to_end(10 * 1024 * 1024).await?;
    send.write_all(&data).await?;
    send.finish().await?;
    Ok(())
}

/// Benchmark unidirectional throughput
fn bench_unidirectional_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("unidirectional_throughput");
    let rt = Runtime::new().unwrap();

    for &size in DATA_SIZES {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("send_only", size), &size, |b, &size| {
            b.iter_batched(
                || {
                    let rt_handle = tokio::runtime::Handle::current();
                    rt_handle.block_on(async {
                        let (server, client, server_addr) =
                            create_throughput_endpoints().await.unwrap();

                        // Accept connections on server
                        tokio::spawn(async move {
                            while let Some(conn) = server.accept().await {
                                tokio::spawn(async move {
                                    if let Ok(conn) = conn.await {
                                        // Just accept streams, don't echo
                                        while let Ok((_send, mut recv)) = conn.accept_bi().await {
                                            tokio::spawn(async move {
                                                let _ = recv.read_to_end(10 * 1024 * 1024).await;
                                            });
                                        }
                                    }
                                });
                            }
                        });

                        let connecting = client.connect(server_addr, "localhost").unwrap();
                        let conn = connecting.await.unwrap();
                        let data = generate_test_data(size);
                        (conn, data)
                    })
                },
                |(conn, data)| {
                    let rt_handle = tokio::runtime::Handle::current();
                    rt_handle.block_on(async {
                        let start = Instant::now();

                        let (mut send, _recv) = conn.open_bi().await.unwrap();
                        send.write_all(&data).await.unwrap();
                        send.finish().await.unwrap();

                        let elapsed = start.elapsed();
                        black_box(elapsed);
                    })
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

/// Benchmark bidirectional throughput (echo)
fn bench_bidirectional_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("bidirectional_throughput");
    let rt = Runtime::new().unwrap();

    for &size in DATA_SIZES {
        group.throughput(Throughput::Bytes(size as u64 * 2)); // Both directions
        group.bench_with_input(BenchmarkId::new("echo", size), &size, |b, &size| {
            b.iter_batched(
                || {
                    let rt_handle = tokio::runtime::Handle::current();
                    rt_handle.block_on(async {
                        let (server, client, server_addr) =
                            create_throughput_endpoints().await.unwrap();

                        // Run echo server
                        tokio::spawn(async move {
                            while let Some(conn) = server.accept().await {
                                tokio::spawn(async move {
                                    if let Ok(conn) = conn.await {
                                        let _ = run_echo_server(conn).await;
                                    }
                                });
                            }
                        });

                        let connecting = client.connect(server_addr, "localhost").unwrap();
                        let conn = connecting.await.unwrap();
                        let data = generate_test_data(size);
                        (conn, data)
                    })
                },
                |(conn, data)| {
                    let rt_handle = tokio::runtime::Handle::current();
                    rt_handle.block_on(async {
                        let start = Instant::now();

                        let (mut send, mut recv) = conn.open_bi().await.unwrap();

                        // Send data
                        send.write_all(&data).await.unwrap();
                        send.finish().await.unwrap();

                        // Receive echo
                        let echoed = recv.read_to_end(data.len()).await.unwrap();
                        assert_eq!(echoed.len(), data.len());

                        let elapsed = start.elapsed();
                        black_box(elapsed);
                    })
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

/// Benchmark multi-stream throughput
fn bench_multi_stream_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("multi_stream_throughput");
    let rt = Runtime::new().unwrap();

    let stream_counts = [1, 5, 10, 20];
    let data_size = 100 * 1024; // 100KB per stream

    for &stream_count in &stream_counts {
        group.throughput(Throughput::Bytes(data_size as u64 * stream_count as u64));
        group.bench_with_input(
            BenchmarkId::new("parallel_streams", stream_count),
            &stream_count,
            |b, &stream_count| {
                b.iter_batched(
                    || {
                        let rt_handle = tokio::runtime::Handle::current();
                        rt_handle.block_on(async {
                            let (server, client, server_addr) =
                                create_throughput_endpoints().await.unwrap();

                            // Run server that accepts streams
                            tokio::spawn(async move {
                                while let Some(conn) = server.accept().await {
                                    tokio::spawn(async move {
                                        if let Ok(conn) = conn.await {
                                            while let Ok((_send, mut recv)) = conn.accept_bi().await
                                            {
                                                tokio::spawn(async move {
                                                    let _ =
                                                        recv.read_to_end(10 * 1024 * 1024).await;
                                                });
                                            }
                                        }
                                    });
                                }
                            });

                            let connecting = client.connect(server_addr, "localhost").unwrap();
                            let conn = connecting.await.unwrap();
                            let data = generate_test_data(data_size);
                            (conn, data, stream_count)
                        })
                    },
                    |(conn, data, stream_count)| {
                        let rt_handle = tokio::runtime::Handle::current();
                        rt_handle.block_on(async {
                            let start = Instant::now();

                            // Open multiple streams in parallel
                            let mut handles = vec![];

                            for _ in 0..stream_count {
                                let conn = conn.clone();
                                let data = data.clone();

                                let handle = tokio::spawn(async move {
                                    let (mut send, _recv) = conn.open_bi().await.unwrap();
                                    send.write_all(&data).await.unwrap();
                                    send.finish().await.unwrap();
                                });

                                handles.push(handle);
                            }

                            // Wait for all streams to complete
                            for handle in handles {
                                handle.await.unwrap();
                            }

                            let elapsed = start.elapsed();
                            black_box(elapsed);
                        })
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

/// Benchmark throughput with different congestion conditions
fn bench_congestion_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("congestion_throughput");
    let rt = Runtime::new().unwrap();

    let data_size = 1024 * 1024; // 1MB
    let concurrent_connections = [1, 5, 10];

    for &conn_count in &concurrent_connections {
        group.throughput(Throughput::Bytes(data_size as u64 * conn_count as u64));
        group.bench_with_input(
            BenchmarkId::new("concurrent_connections", conn_count),
            &conn_count,
            |b, &conn_count| {
                b.iter_batched(
                    || {
                        let rt_handle = tokio::runtime::Handle::current();
                        rt_handle.block_on(async {
                            let (server, client, server_addr) =
                                create_throughput_endpoints().await.unwrap();

                            // Run server
                            tokio::spawn(async move {
                                while let Some(conn) = server.accept().await {
                                    tokio::spawn(async move {
                                        if let Ok(conn) = conn.await {
                                            while let Ok((_send, mut recv)) = conn.accept_bi().await
                                            {
                                                tokio::spawn(async move {
                                                    let _ =
                                                        recv.read_to_end(10 * 1024 * 1024).await;
                                                });
                                            }
                                        }
                                    });
                                }
                            });

                            // Create multiple connections
                            let mut connections = vec![];
                            for _ in 0..conn_count {
                                let connecting = client.connect(server_addr, "localhost").unwrap();
                                let conn = connecting.await.unwrap();
                                connections.push(conn);
                            }

                            let data = generate_test_data(data_size);
                            (connections, data)
                        })
                    },
                    |(connections, data)| {
                        let rt_handle = tokio::runtime::Handle::current();
                        rt_handle.block_on(async {
                            let start = Instant::now();

                            // Send data on all connections in parallel
                            let mut handles = vec![];

                            for conn in connections {
                                let data = data.clone();

                                let handle = tokio::spawn(async move {
                                    let (mut send, _recv) = conn.open_bi().await.unwrap();
                                    send.write_all(&data).await.unwrap();
                                    send.finish().await.unwrap();
                                });

                                handles.push(handle);
                            }

                            // Wait for all to complete
                            for handle in handles {
                                handle.await.unwrap();
                            }

                            let elapsed = start.elapsed();
                            black_box(elapsed);
                        })
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_unidirectional_throughput,
    bench_bidirectional_throughput,
    bench_multi_stream_throughput,
    bench_congestion_throughput
);

criterion_main!(benches);
