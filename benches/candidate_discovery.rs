//! Benchmarks for candidate discovery performance
//!
//! This benchmark suite measures the performance of address candidate discovery,
//! priority calculation, and candidate pair generation algorithms.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use rand::{Rng, thread_rng};

use ant_quic::{CandidateAddress, CandidateSource, CandidateState};

/// Generate test IPv4 addresses for benchmarking
fn generate_ipv4_addresses(count: usize) -> Vec<IpAddr> {
    let mut rng = thread_rng();
    let mut addresses = Vec::with_capacity(count);

    for _ in 0..count {
        let octets = [
            rng.gen_range(1..=254),
            rng.gen_range(0..=255),
            rng.gen_range(0..=255),
            rng.gen_range(1..=254),
        ];
        addresses.push(IpAddr::V4(Ipv4Addr::from(octets)));
    }

    addresses
}

/// Generate test IPv6 addresses for benchmarking
fn generate_ipv6_addresses(count: usize) -> Vec<IpAddr> {
    let mut rng = thread_rng();
    let mut addresses = Vec::with_capacity(count);

    for _ in 0..count {
        let segments = [
            0x2001,
            0x0db8, // Global unicast prefix
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
        ];
        addresses.push(IpAddr::V6(Ipv6Addr::from(segments)));
    }

    addresses
}

/// Generate mixed IPv4 and IPv6 addresses
fn generate_mixed_addresses(count: usize) -> Vec<IpAddr> {
    let mut addresses = Vec::with_capacity(count);
    let ipv4_count = count / 2;
    let ipv6_count = count - ipv4_count;

    addresses.extend(generate_ipv4_addresses(ipv4_count));
    addresses.extend(generate_ipv6_addresses(ipv6_count));

    addresses
}

/// Simple priority calculation for benchmarking
fn calculate_priority(addr: &IpAddr) -> u32 {
    match addr {
        IpAddr::V4(ipv4) => {
            if ipv4.is_private() {
                100
            } else if ipv4.is_loopback() {
                0
            } else {
                50
            }
        }
        IpAddr::V6(ipv6) => {
            if ipv6.is_loopback() {
                0
            } else if !ipv6.is_multicast() {
                60
            } else {
                30
            }
        }
    }
}

/// Benchmark candidate address creation
fn bench_candidate_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("candidate_creation");

    for addr_count in [10, 100, 1000] {
        group.throughput(Throughput::Elements(addr_count as u64));

        group.bench_with_input(
            BenchmarkId::new("create_candidates", addr_count),
            &addr_count,
            |b, &size| {
                let addresses = generate_mixed_addresses(size);
                let mut rng = thread_rng();

                b.iter(|| {
                    let mut candidates = Vec::new();
                    for addr in &addresses {
                        let port = rng.gen_range(1024..=65535);
                        let socket_addr = SocketAddr::new(*addr, port);
                        let priority = calculate_priority(addr);

                        let candidate = CandidateAddress {
                            address: socket_addr,
                            priority,
                            source: CandidateSource::Local,
                            state: CandidateState::New,
                        };

                        candidates.push(black_box(candidate));
                    }
                    candidates
                });
            },
        );
    }

    group.finish();
}

/// Benchmark candidate pair generation
fn bench_candidate_pairing(c: &mut Criterion) {
    let mut group = c.benchmark_group("candidate_pairing");

    for local_count in [10, 50, 100] {
        for remote_count in [10, 50, 100] {
            let pair_name = format!("{}x{}", local_count, remote_count);
            group.throughput(Throughput::Elements((local_count * remote_count) as u64));

            group.bench_with_input(
                BenchmarkId::new("generate_pairs", &pair_name),
                &(local_count, remote_count),
                |b, &(local_size, remote_size)| {
                    let local_addrs = generate_mixed_addresses(local_size);
                    let remote_addrs = generate_mixed_addresses(remote_size);
                    let mut rng = thread_rng();

                    // Create candidate addresses
                    let local_candidates: Vec<CandidateAddress> = local_addrs
                        .iter()
                        .map(|addr| {
                            let port = rng.gen_range(1024..=65535);
                            let socket_addr = SocketAddr::new(*addr, port);
                            let priority = calculate_priority(addr);

                            CandidateAddress {
                                address: socket_addr,
                                priority,
                                source: CandidateSource::Local,
                                state: CandidateState::New,
                            }
                        })
                        .collect();

                    let remote_candidates: Vec<CandidateAddress> = remote_addrs
                        .iter()
                        .map(|addr| {
                            let port = rng.gen_range(1024..=65535);
                            let socket_addr = SocketAddr::new(*addr, port);
                            let priority = calculate_priority(addr);

                            CandidateAddress {
                                address: socket_addr,
                                priority,
                                source: CandidateSource::Peer,
                                state: CandidateState::New,
                            }
                        })
                        .collect();

                    b.iter(|| {
                        let mut pairs = Vec::new();

                        for local in &local_candidates {
                            for remote in &remote_candidates {
                                // Only pair same IP version
                                if local.address.is_ipv4() == remote.address.is_ipv4() {
                                    let pair_priority =
                                        calculate_pair_priority(local.priority, remote.priority);
                                    pairs.push(black_box((
                                        local.clone(),
                                        remote.clone(),
                                        pair_priority,
                                    )));
                                }
                            }
                        }

                        // Sort pairs by priority
                        pairs.sort_by(|a, b| b.2.cmp(&a.2));
                        pairs
                    });
                },
            );
        }
    }

    group.finish();
}

/// Benchmark candidate sorting and filtering
fn bench_candidate_sorting(c: &mut Criterion) {
    let mut group = c.benchmark_group("candidate_sorting");

    for candidate_count in [10, 100, 1000] {
        group.throughput(Throughput::Elements(candidate_count as u64));

        group.bench_with_input(
            BenchmarkId::new("sort_by_priority", candidate_count),
            &candidate_count,
            |b, &size| {
                let addresses = generate_mixed_addresses(size);
                let mut rng = thread_rng();

                // Pre-generate candidates
                let candidates: Vec<CandidateAddress> = addresses
                    .iter()
                    .map(|addr| {
                        let port = rng.gen_range(1024..=65535);
                        let socket_addr = SocketAddr::new(*addr, port);
                        let priority = calculate_priority(addr);

                        CandidateAddress {
                            address: socket_addr,
                            priority,
                            source: CandidateSource::Local,
                            state: CandidateState::New,
                        }
                    })
                    .collect();

                b.iter(|| {
                    let mut sorted_candidates = candidates.clone();
                    sorted_candidates.sort_by(|a, b| b.priority.cmp(&a.priority));
                    black_box(sorted_candidates);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("filter_by_type", candidate_count),
            &candidate_count,
            |b, &size| {
                let addresses = generate_mixed_addresses(size);
                let mut rng = thread_rng();

                // Pre-generate candidates
                let candidates: Vec<CandidateAddress> = addresses
                    .iter()
                    .map(|addr| {
                        let port = rng.gen_range(1024..=65535);
                        let socket_addr = SocketAddr::new(*addr, port);
                        let priority = calculate_priority(addr);

                        CandidateAddress {
                            address: socket_addr,
                            priority,
                            source: CandidateSource::Local,
                            state: CandidateState::New,
                        }
                    })
                    .collect();

                b.iter(|| {
                    let ipv4_candidates: Vec<_> =
                        candidates.iter().filter(|c| c.address.is_ipv4()).collect();
                    let ipv6_candidates: Vec<_> =
                        candidates.iter().filter(|c| c.address.is_ipv6()).collect();

                    black_box((ipv4_candidates, ipv6_candidates));
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

/// Benchmark HashMap operations for candidate storage
fn bench_candidate_storage(c: &mut Criterion) {
    let mut group = c.benchmark_group("candidate_storage");

    for candidate_count in [10, 100, 1000] {
        group.throughput(Throughput::Elements(candidate_count as u64));

        group.bench_with_input(
            BenchmarkId::new("hashmap_operations", candidate_count),
            &candidate_count,
            |b, &size| {
                let addresses = generate_mixed_addresses(size);
                let mut rng = thread_rng();

                b.iter(|| {
                    let mut candidate_map = HashMap::new();

                    // Insert candidates
                    for (i, addr) in addresses.iter().enumerate() {
                        let port = rng.gen_range(1024..=65535);
                        let socket_addr = SocketAddr::new(*addr, port);
                        let priority = calculate_priority(addr);

                        let candidate = CandidateAddress {
                            address: socket_addr,
                            priority,
                            source: CandidateSource::Local,
                            state: CandidateState::New,
                        };

                        candidate_map.insert(i as u32, candidate);
                    }

                    // Lookup and update candidates
                    for i in 0..size / 2 {
                        if let Some(candidate) = candidate_map.get_mut(&(i as u32)) {
                            candidate.state = CandidateState::Valid;
                        }
                    }

                    // Remove some candidates
                    for i in 0..size / 4 {
                        candidate_map.remove(&(i as u32));
                    }

                    black_box(candidate_map);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_candidate_creation,
    bench_candidate_pairing,
    bench_candidate_sorting,
    bench_candidate_storage
);

criterion_main!(benches);
