//! Benchmarks for NAT traversal performance
//!
//! This benchmark suite measures the performance of NAT traversal coordination,
//! validation state management, and multi-path transmission algorithms.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use rand::{Rng, thread_rng};
use uuid::Uuid;

use ant_quic::{CandidateAddress, CandidateSource, CandidateState, PeerId};

/// Mock path validation state for benchmarking
#[derive(Clone, Debug)]
#[allow(dead_code)]
struct PathValidationState {
    pub address: SocketAddr,
    pub attempts: u32,
    pub last_attempt: Instant,
    pub rtt: Option<Duration>,
    pub state: ValidationState,
}

#[derive(Clone, Debug)]
enum ValidationState {
    InProgress,
    Succeeded,
    Failed,
}

/// Mock coordination state for benchmarking
#[derive(Clone, Debug)]
#[allow(dead_code)]
struct CoordinationState {
    pub round: u32,
    pub participants: Vec<PeerId>,
    pub responses: HashMap<PeerId, CoordinationResponse>,
    pub started_at: Instant,
    pub timeout: Duration,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct CoordinationResponse {
    pub peer_id: PeerId,
    pub ready: bool,
    pub timestamp: Instant,
}

/// Generate test socket addresses
fn generate_socket_addresses(count: usize) -> Vec<SocketAddr> {
    let mut rng = thread_rng();
    let mut addresses = Vec::with_capacity(count);

    for _ in 0..count {
        let addr = if rng.gen_bool(0.5) {
            // IPv4
            let octets = [
                rng.gen_range(1..=254),
                rng.gen_range(0..=255),
                rng.gen_range(0..=255),
                rng.gen_range(1..=254),
            ];
            IpAddr::V4(Ipv4Addr::from(octets))
        } else {
            // IPv6
            let segments = [
                0x2001,
                0x0db8, // Global unicast prefix
                rng.r#gen(),
                rng.r#gen(),
                rng.r#gen(),
                rng.r#gen(),
                rng.r#gen(),
                rng.r#gen(),
            ];
            IpAddr::V6(Ipv6Addr::from(segments))
        };

        let port = rng.gen_range(1024..=65535);
        addresses.push(SocketAddr::new(addr, port));
    }

    addresses
}

/// Generate test candidate addresses
fn generate_candidates(count: usize) -> Vec<CandidateAddress> {
    let addresses = generate_socket_addresses(count);
    let mut rng = thread_rng();

    addresses
        .into_iter()
        .map(|addr| {
            let priority = rng.gen_range(1..10000);
            let source = match rng.gen_range(0..3) {
                0 => CandidateSource::Local,
                1 => CandidateSource::Observed { by_node: None },
                _ => CandidateSource::Peer,
            };

            CandidateAddress {
                address: addr,
                priority,
                source,
                state: CandidateState::New,
            }
        })
        .collect()
}

/// Benchmark path validation state management
fn bench_path_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("path_validation");

    for validation_count in [10, 100, 1000] {
        group.throughput(Throughput::Elements(validation_count as u64));

        group.bench_with_input(
            BenchmarkId::new("create_validations", validation_count),
            &validation_count,
            |b, &size| {
                let addresses = generate_socket_addresses(size);

                b.iter(|| {
                    let mut validations = HashMap::new();

                    for addr in &addresses {
                        let validation = PathValidationState {
                            address: *addr,
                            attempts: 0,
                            last_attempt: Instant::now(),
                            rtt: None,
                            state: ValidationState::InProgress,
                        };

                        validations.insert(*addr, black_box(validation));
                    }

                    validations
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("update_validations", validation_count),
            &validation_count,
            |b, &size| {
                let addresses = generate_socket_addresses(size);
                let mut rng = thread_rng();

                b.iter_batched(
                    || {
                        let mut validations = HashMap::new();

                        for addr in &addresses {
                            let validation = PathValidationState {
                                address: *addr,
                                attempts: 0,
                                last_attempt: Instant::now(),
                                rtt: None,
                                state: ValidationState::InProgress,
                            };

                            validations.insert(*addr, validation);
                        }

                        validations
                    },
                    |mut validations| {
                        // Update random validations
                        for addr in addresses.iter().take(size / 2) {
                            if let Some(validation) = validations.get_mut(addr) {
                                validation.attempts += 1;
                                validation.last_attempt = Instant::now();
                                validation.rtt = Some(Duration::from_millis(rng.gen_range(1..200)));
                                validation.state = if rng.gen_bool(0.8) {
                                    ValidationState::Succeeded
                                } else {
                                    ValidationState::Failed
                                };
                            }
                        }

                        black_box(validations);
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("cleanup_validations", validation_count),
            &validation_count,
            |b, &size| {
                let addresses = generate_socket_addresses(size);
                let mut rng = thread_rng();

                b.iter_batched(
                    || {
                        let mut validations = HashMap::new();
                        let now = Instant::now();

                        for addr in &addresses {
                            let age = Duration::from_millis(rng.gen_range(0..300_000));
                            let validation = PathValidationState {
                                address: *addr,
                                attempts: rng.gen_range(0..10),
                                last_attempt: now - age,
                                rtt: if rng.gen_bool(0.7) {
                                    Some(Duration::from_millis(rng.gen_range(1..200)))
                                } else {
                                    None
                                },
                                state: match rng.gen_range(0..3) {
                                    0 => ValidationState::InProgress,
                                    1 => ValidationState::Succeeded,
                                    _ => ValidationState::Failed,
                                },
                            };

                            validations.insert(*addr, validation);
                        }

                        (validations, now)
                    },
                    |(mut validations, now)| {
                        let timeout = Duration::from_secs(30);

                        // Remove old validations
                        validations.retain(|_, validation| {
                            now.duration_since(validation.last_attempt) < timeout
                        });

                        black_box(validations);
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

/// Benchmark coordination state management
fn bench_coordination(c: &mut Criterion) {
    let mut group = c.benchmark_group("coordination");

    for peer_count in [5, 20, 50] {
        group.throughput(Throughput::Elements(peer_count as u64));

        group.bench_with_input(
            BenchmarkId::new("create_coordination", peer_count),
            &peer_count,
            |b, &size| {
                b.iter(|| {
                    let participants: Vec<PeerId> = (0..size)
                        .map(|_| {
                            let mut peer_id_bytes = [0u8; 32];
                            let uuid = Uuid::new_v4();
                            let uuid_bytes = uuid.as_bytes();
                            peer_id_bytes[..16].copy_from_slice(uuid_bytes);
                            PeerId(peer_id_bytes)
                        })
                        .collect();

                    let coordination = CoordinationState {
                        round: 1,
                        participants,
                        responses: HashMap::new(),
                        started_at: Instant::now(),
                        timeout: Duration::from_secs(10),
                    };

                    black_box(coordination);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("process_responses", peer_count),
            &peer_count,
            |b, &size| {
                b.iter_batched(
                    || {
                        let participants: Vec<PeerId> = (0..size)
                            .map(|_| {
                                let mut peer_id_bytes = [0u8; 32];
                                let uuid = Uuid::new_v4();
                                let uuid_bytes = uuid.as_bytes();
                                peer_id_bytes[..16].copy_from_slice(uuid_bytes);
                                PeerId(peer_id_bytes)
                            })
                            .collect();

                        let mut coordination = CoordinationState {
                            round: 1,
                            participants: participants.clone(),
                            responses: HashMap::new(),
                            started_at: Instant::now(),
                            timeout: Duration::from_secs(10),
                        };

                        // Pre-populate some responses
                        for peer in participants.iter().take(size / 2) {
                            let response = CoordinationResponse {
                                peer_id: *peer,
                                ready: rand::thread_rng().gen_bool(0.8),
                                timestamp: Instant::now(),
                            };
                            coordination.responses.insert(*peer, response);
                        }

                        coordination
                    },
                    |mut coordination| {
                        // Process remaining responses
                        for peer in coordination
                            .participants
                            .iter()
                            .skip(coordination.responses.len())
                        {
                            let response = CoordinationResponse {
                                peer_id: *peer,
                                ready: rand::thread_rng().gen_bool(0.8),
                                timestamp: Instant::now(),
                            };
                            coordination.responses.insert(*peer, response);
                        }

                        // Check if all ready
                        let all_ready = coordination.responses.values().all(|r| r.ready);

                        black_box((coordination, all_ready));
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

/// Benchmark candidate pair priority calculation
fn bench_pair_priority(c: &mut Criterion) {
    let mut group = c.benchmark_group("pair_priority");

    for pair_count in [10, 100, 1000, 10000] {
        group.throughput(Throughput::Elements(pair_count as u64));

        group.bench_with_input(
            BenchmarkId::new("calculate_priorities", pair_count),
            &pair_count,
            |b, &size| {
                let mut rng = thread_rng();
                let priorities: Vec<(u32, u32)> = (0..size)
                    .map(|_| (rng.gen_range(1..10000), rng.gen_range(1..10000)))
                    .collect();

                b.iter(|| {
                    let mut pair_priorities = Vec::new();

                    for (local, remote) in &priorities {
                        let pair_priority = calculate_pair_priority(*local, *remote);
                        pair_priorities.push(black_box(pair_priority));
                    }

                    pair_priorities
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("sort_by_priority", pair_count),
            &pair_count,
            |b, &size| {
                let mut rng = thread_rng();
                let priorities: Vec<(u32, u32)> = (0..size)
                    .map(|_| (rng.gen_range(1..10000), rng.gen_range(1..10000)))
                    .collect();

                b.iter_batched(
                    || {
                        priorities
                            .iter()
                            .map(|(local, remote)| calculate_pair_priority(*local, *remote))
                            .collect::<Vec<_>>()
                    },
                    |mut pair_priorities| {
                        pair_priorities.sort_by(|a, b| b.cmp(a));
                        black_box(pair_priorities);
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("sort_unstable_by_priority", pair_count),
            &pair_count,
            |b, &size| {
                let mut rng = thread_rng();
                let priorities: Vec<(u32, u32)> = (0..size)
                    .map(|_| (rng.gen_range(1..10000), rng.gen_range(1..10000)))
                    .collect();

                b.iter_batched(
                    || {
                        priorities
                            .iter()
                            .map(|(local, remote)| calculate_pair_priority(*local, *remote))
                            .collect::<Vec<_>>()
                    },
                    |mut pair_priorities| {
                        pair_priorities.sort_unstable_by(|a, b| b.cmp(a));
                        black_box(pair_priorities);
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

/// Benchmark multi-destination transmission simulation
fn bench_multi_destination(c: &mut Criterion) {
    let mut group = c.benchmark_group("multi_destination");

    for dest_count in [2, 5, 10, 20] {
        group.throughput(Throughput::Elements(dest_count as u64));

        group.bench_with_input(
            BenchmarkId::new("select_destinations", dest_count),
            &dest_count,
            |b, &size| {
                let candidates = generate_candidates(size * 2);

                b.iter(|| {
                    // Select top candidates for transmission
                    let mut sorted_candidates = candidates.clone();
                    sorted_candidates.sort_by(|a, b| b.priority.cmp(&a.priority));

                    let selected: Vec<_> = sorted_candidates.into_iter().take(size).collect();

                    black_box(selected);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("transmission_simulation", dest_count),
            &dest_count,
            |b, &size| {
                let candidates = generate_candidates(size);
                let mut rng = thread_rng();

                b.iter(|| {
                    // Simulate packet transmission to multiple destinations
                    let mut results = Vec::new();

                    for candidate in &candidates {
                        let transmission_time = Duration::from_millis(rng.gen_range(1..50));
                        let success = rng.gen_bool(0.85); // 85% success rate

                        results.push(black_box((candidate.address, transmission_time, success)));
                    }

                    results
                });
            },
        );
    }

    group.finish();
}

/// Helper function to calculate candidate pair priority
fn calculate_pair_priority(local_priority: u32, remote_priority: u32) -> u64 {
    // ICE-like pair priority calculation
    let (controlling_priority, controlled_priority) = if local_priority > remote_priority {
        (local_priority as u64, remote_priority as u64)
    } else {
        (remote_priority as u64, local_priority as u64)
    };

    (controlling_priority << 32) | controlled_priority
}

/// Benchmark connection routing performance
fn bench_connection_routing(c: &mut Criterion) {
    let mut group = c.benchmark_group("connection_routing");

    for connection_count in [10, 100, 1000, 10000] {
        group.throughput(Throughput::Elements(connection_count as u64));

        group.bench_with_input(
            BenchmarkId::new("routing_lookup", connection_count),
            &connection_count,
            |b, &size| {
                let addresses = generate_socket_addresses(size);
                let mut rng = thread_rng();

                b.iter(|| {
                    let mut lookup_count = 0;

                    // Simulate connection routing lookups
                    for _ in 0..size {
                        let random_addr = addresses[rng.gen_range(0..addresses.len())];
                        let success = rng.gen_bool(0.85); // 85% lookup success rate

                        if success {
                            // Use the random address to prevent unused variable warning
                            black_box(random_addr);
                            lookup_count += 1;
                        }
                    }

                    black_box(lookup_count)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark optimized candidate pair generation
fn bench_pair_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("pair_generation");

    for candidate_count in [10, 25, 50, 100] {
        group.throughput(Throughput::Elements(
            (candidate_count * candidate_count) as u64,
        ));

        group.bench_with_input(
            BenchmarkId::new("generate_pairs", candidate_count),
            &candidate_count,
            |b, &size| {
                let local_candidates = generate_candidates(size);
                let remote_candidates = generate_candidates(size);

                b.iter(|| {
                    // Simulate pair generation algorithm
                    let mut pairs = Vec::new();
                    let mut compatibility_cache = HashMap::new();

                    // Pre-allocate
                    pairs.reserve(size * size);

                    for local in &local_candidates {
                        let local_type = match local.source {
                            CandidateSource::Local => 0,
                            CandidateSource::Observed { .. } => 1,
                            CandidateSource::Peer => 2,
                            CandidateSource::Predicted => 3,
                        };

                        for remote in &remote_candidates {
                            // Cache compatibility check
                            let cache_key = (local.address, remote.address);
                            let compatible =
                                *compatibility_cache.entry(cache_key).or_insert_with(|| {
                                    matches!(
                                        (local.address, remote.address),
                                        (SocketAddr::V4(_), SocketAddr::V4(_))
                                            | (SocketAddr::V6(_), SocketAddr::V6(_))
                                    )
                                });

                            if compatible {
                                let remote_type = match remote.source {
                                    CandidateSource::Local => 0,
                                    CandidateSource::Observed { .. } => 1,
                                    CandidateSource::Peer => 2,
                                    CandidateSource::Predicted => 3,
                                };

                                // Calculate priority
                                let g = local.priority as u64;
                                let d = remote.priority as u64;
                                let priority = (1u64 << 32) * g.min(d)
                                    + 2 * g.max(d)
                                    + if g > d { 1 } else { 0 };

                                pairs.push((
                                    local.address,
                                    remote.address,
                                    priority,
                                    local_type,
                                    remote_type,
                                ));
                            }
                        }
                    }

                    // Sort by priority (unstable sort for performance)
                    pairs.sort_unstable_by(|a, b| b.2.cmp(&a.2));

                    black_box(pairs)
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("pair_lookup", candidate_count),
            &candidate_count,
            |b, &size| {
                let candidates = generate_candidates(size);
                let addresses: Vec<_> = candidates.iter().map(|c| c.address).collect();

                // Create index for O(1) lookup
                let mut index = HashMap::new();
                for (i, addr) in addresses.iter().enumerate() {
                    index.insert(*addr, i);
                }

                let mut rng = thread_rng();

                b.iter(|| {
                    let mut found_count = 0;

                    // Simulate lookups
                    for _ in 0..size {
                        let addr = addresses[rng.gen_range(0..addresses.len())];
                        if index.contains_key(&addr) {
                            found_count += 1;
                        }
                    }

                    black_box(found_count)
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_path_validation,
    bench_coordination,
    bench_pair_priority,
    bench_multi_destination,
    bench_connection_routing,
    bench_pair_generation
);

criterion_main!(benches);
