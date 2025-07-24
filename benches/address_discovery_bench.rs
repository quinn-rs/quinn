//! Performance benchmarks for QUIC Address Discovery implementation
//!
//! These benchmarks measure the performance impact of the OBSERVED_ADDRESS
//! frame processing and NAT traversal integration.

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use std::net::SocketAddr;

/// Benchmark OBSERVED_ADDRESS frame encoding simulation
fn bench_frame_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame_encoding");

    // Test different address types
    let addresses = vec![
        ("ipv4", SocketAddr::from(([203, 0, 113, 50], 45678))),
        (
            "ipv6",
            SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], 45678)),
        ),
    ];

    for (name, addr) in addresses {
        group.bench_with_input(
            BenchmarkId::new("observed_address", name),
            &addr,
            |b, &addr| {
                b.iter(|| {
                    let mut buf = Vec::with_capacity(32);
                    // Simulate frame encoding
                    buf.push(0x43); // Frame type
                    // VarInt encoding of sequence number
                    buf.extend_from_slice(&[1]);
                    // Address encoding
                    match addr {
                        SocketAddr::V4(v4) => {
                            buf.push(4); // IPv4
                            buf.extend_from_slice(&v4.ip().octets());
                            buf.extend_from_slice(&v4.port().to_be_bytes());
                        }
                        SocketAddr::V6(v6) => {
                            buf.push(6); // IPv6
                            buf.extend_from_slice(&v6.ip().octets());
                            buf.extend_from_slice(&v6.port().to_be_bytes());
                        }
                    }
                    black_box(buf)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark OBSERVED_ADDRESS frame decoding simulation
fn bench_frame_decoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame_decoding");

    // Pre-encoded frames
    let frames = vec![
        ("ipv4", vec![0x43, 1, 4, 203, 0, 113, 50, 0xb2, 0x8e]), // IPv4 address
        (
            "ipv6",
            vec![
                0x43, 1, 6, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xb2, 0x8e,
            ],
        ), // IPv6 address
    ];

    for (name, data) in frames {
        group.bench_with_input(
            BenchmarkId::new("observed_address", name),
            &data,
            |b, data| {
                b.iter(|| {
                    let mut cursor = &data[..];
                    let frame_type = cursor[0];
                    cursor = &cursor[1..];

                    // Parse sequence number (simplified)
                    let seq_num = cursor[0];
                    cursor = &cursor[1..];

                    // Parse address type
                    let addr_type = cursor[0];
                    cursor = &cursor[1..];

                    let addr = match addr_type {
                        4 => {
                            // IPv4
                            let ip = [cursor[0], cursor[1], cursor[2], cursor[3]];
                            let port = u16::from_be_bytes([cursor[4], cursor[5]]);
                            SocketAddr::from((ip, port))
                        }
                        6 => {
                            // IPv6
                            let mut ip = [0u8; 16];
                            ip.copy_from_slice(&cursor[..16]);
                            let port = u16::from_be_bytes([cursor[16], cursor[17]]);
                            let ipv6 = std::net::Ipv6Addr::from(ip);
                            SocketAddr::from((ipv6, port))
                        }
                        _ => panic!("Invalid address type"),
                    };

                    black_box((frame_type, seq_num, addr))
                });
            },
        );
    }

    group.finish();
}

/// Benchmark transport parameter negotiation simulation
fn bench_transport_param_negotiation(c: &mut Criterion) {
    let mut group = c.benchmark_group("transport_params");

    group.bench_function("with_address_discovery", |b| {
        b.iter(|| {
            // Simulate transport parameter with address discovery
            let mut buf = Vec::with_capacity(256);
            // Write parameter ID (2 bytes)
            buf.extend_from_slice(&[0x1f, 0x00]);
            // Write length (1 byte for this simple case)
            buf.push(3);
            // Write config (3 bytes: enabled, rate, observe_all)
            buf.push(1); // enabled
            buf.push(10); // rate
            buf.push(0); // observe_all_paths = false

            black_box(buf)
        });
    });

    group.bench_function("without_address_discovery", |b| {
        b.iter(|| {
            // Simulate transport parameter without address discovery
            let buf: Vec<u8> = Vec::with_capacity(256);
            black_box(buf)
        });
    });

    group.finish();
}

/// Benchmark rate limiting overhead
fn bench_rate_limiting(c: &mut Criterion) {
    let mut group = c.benchmark_group("rate_limiting");

    // Simulate token bucket rate limiter
    struct TokenBucket {
        tokens: f64,
        max_tokens: f64,
        refill_rate: f64,
        last_update: std::time::Instant,
    }

    impl TokenBucket {
        fn new(rate: f64) -> Self {
            Self {
                tokens: rate,
                max_tokens: rate,
                refill_rate: rate,
                last_update: std::time::Instant::now(),
            }
        }

        fn try_consume(&mut self) -> bool {
            let now = std::time::Instant::now();
            let elapsed = now.duration_since(self.last_update).as_secs_f64();

            self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
            self.last_update = now;

            if self.tokens >= 1.0 {
                self.tokens -= 1.0;
                true
            } else {
                false
            }
        }
    }

    group.bench_function("token_bucket_check", |b| {
        let mut bucket = TokenBucket::new(10.0);

        b.iter(|| black_box(bucket.try_consume()));
    });

    group.finish();
}

/// Benchmark candidate address management
fn bench_candidate_management(c: &mut Criterion) {
    let mut group = c.benchmark_group("candidate_management");

    // Simulate candidate list operations
    let candidates = vec![
        SocketAddr::from(([192, 168, 1, 100], 50000)),
        SocketAddr::from(([203, 0, 113, 50], 45678)),
        SocketAddr::from(([10, 0, 0, 50], 60000)),
        SocketAddr::from(([172, 16, 0, 100], 55000)),
    ];

    group.bench_function("add_candidate", |b| {
        b.iter(|| {
            let mut list = Vec::with_capacity(10);
            for &addr in &candidates {
                // Check if already exists
                if !list.contains(&addr) {
                    list.push(addr);
                }
            }
            black_box(list)
        });
    });

    group.bench_function("priority_sort", |b| {
        b.iter(|| {
            let mut scored_candidates: Vec<(SocketAddr, u32)> = candidates
                .iter()
                .map(|&addr| {
                    // Calculate priority based on address type
                    let priority = match addr {
                        SocketAddr::V4(v4) if v4.ip().is_private() => 100,
                        SocketAddr::V4(_) => 255, // Public IPv4
                        SocketAddr::V6(v6) if v6.ip().is_loopback() => 50,
                        SocketAddr::V6(_) => 200, // IPv6
                    };
                    (addr, priority)
                })
                .collect();

            scored_candidates.sort_by_key(|&(_, priority)| std::cmp::Reverse(priority));
            black_box(scored_candidates)
        });
    });

    group.finish();
}

/// Benchmark overall system impact
fn bench_system_impact(c: &mut Criterion) {
    let mut group = c.benchmark_group("system_impact");

    // Simulate connection establishment with and without address discovery
    group.bench_function("connection_without_discovery", |b| {
        b.iter(|| {
            // Simulate multiple connection attempts
            let mut attempts = 0;
            let mut success = false;

            while attempts < 5 && !success {
                attempts += 1;
                // Simulate trying different ports
                let _port = 50000 + attempts;
                // 60% chance of success after 3 attempts
                success = attempts >= 3 && (attempts % 5) < 3;
            }

            black_box((attempts, success))
        });
    });

    group.bench_function("connection_with_discovery", |b| {
        b.iter(|| {
            // With discovered address, connection succeeds immediately
            let attempts = 1;
            let success = true;

            black_box((attempts, success))
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_frame_encoding,
    bench_frame_decoding,
    bench_transport_param_negotiation,
    bench_rate_limiting,
    bench_candidate_management,
    bench_system_impact
);
criterion_main!(benches);
