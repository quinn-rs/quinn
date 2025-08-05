//! Benchmarks for RelayQueue performance
//!
//! This benchmark suite measures the performance of the RelayQueue implementation
//! to identify bottlenecks and validate optimization improvements.

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use rand::{Rng, thread_rng};
use uuid::Uuid;

use ant_quic::PeerId;

/// Mock RelayQueueItem for benchmarking
#[derive(Clone, Debug)]
#[allow(dead_code)]
struct RelayQueueItem {
    pub peer_id: PeerId,
    pub data: Vec<u8>,
    pub timestamp: Instant,
    pub attempts: u32,
}

impl RelayQueueItem {
    fn new(peer_id: PeerId, data_size: usize) -> Self {
        let mut rng = thread_rng();
        let data = (0..data_size).map(|_| rng.r#gen::<u8>()).collect();

        Self {
            peer_id,
            data,
            timestamp: Instant::now(),
            attempts: 0,
        }
    }
}

/// Benchmark the current VecDeque-based RelayQueue implementation
fn bench_vecdeque_relay_queue(c: &mut Criterion) {
    let mut group = c.benchmark_group("relay_queue_vecdeque");

    // Test with different queue sizes
    for queue_size in [10, 100, 1000, 10000] {
        group.throughput(Throughput::Elements(queue_size as u64));

        group.bench_with_input(
            BenchmarkId::new("push_back", queue_size),
            &queue_size,
            |b, &size| {
                b.iter(|| {
                    let mut queue = VecDeque::new();
                    for _i in 0..size {
                        let mut peer_id_bytes = [0u8; 32];
                        let uuid = Uuid::new_v4();
                        let uuid_bytes = uuid.as_bytes();
                        peer_id_bytes[..16].copy_from_slice(uuid_bytes);
                        let peer_id = PeerId(peer_id_bytes);
                        let item = RelayQueueItem::new(peer_id, 1024);
                        queue.push_back(black_box(item));
                    }
                    queue
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("pop_front", queue_size),
            &queue_size,
            |b, &size| {
                b.iter_batched(
                    || {
                        let mut queue = VecDeque::new();
                        for _i in 0..size {
                            let mut peer_id_bytes = [0u8; 32];
                            let uuid = Uuid::new_v4();
                            let uuid_bytes = uuid.as_bytes();
                            peer_id_bytes[..16].copy_from_slice(uuid_bytes);
                            let peer_id = PeerId(peer_id_bytes);
                            let item = RelayQueueItem::new(peer_id, 1024);
                            queue.push_back(item);
                        }
                        queue
                    },
                    |mut queue| {
                        while let Some(item) = queue.pop_front() {
                            black_box(item);
                        }
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("find_and_remove", queue_size),
            &queue_size,
            |b, &size| {
                b.iter_batched(
                    || {
                        let mut queue = VecDeque::new();
                        let mut target_peers = Vec::new();
                        for i in 0..size {
                            let mut peer_id_bytes = [0u8; 32];
                            let uuid = Uuid::new_v4();
                            let uuid_bytes = uuid.as_bytes();
                            peer_id_bytes[..16].copy_from_slice(uuid_bytes);
                            let peer_id = PeerId(peer_id_bytes);
                            let item = RelayQueueItem::new(peer_id, 1024);
                            if i % 10 == 0 {
                                target_peers.push(peer_id);
                            }
                            queue.push_back(item);
                        }
                        (queue, target_peers)
                    },
                    |(mut queue, target_peers)| {
                        for target_peer in target_peers {
                            queue.retain(|item| item.peer_id != target_peer);
                        }
                        black_box(queue);
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

/// Benchmark cleanup operations for rate limiting
fn bench_rate_limit_cleanup(c: &mut Criterion) {
    let mut group = c.benchmark_group("rate_limit_cleanup");

    // Test with different numbers of peers
    for num_peers in [10, 100, 1000] {
        group.throughput(Throughput::Elements(num_peers as u64));

        group.bench_with_input(
            BenchmarkId::new("cleanup_old_entries", num_peers),
            &num_peers,
            |b, &size| {
                use std::collections::HashMap;

                b.iter_batched(
                    || {
                        let mut rate_limits = HashMap::new();
                        let now = Instant::now();
                        let mut rng = thread_rng();

                        for _i in 0..size {
                            let mut peer_id_bytes = [0u8; 32];
                            let uuid = Uuid::new_v4();
                            let uuid_bytes = uuid.as_bytes();
                            peer_id_bytes[..16].copy_from_slice(uuid_bytes);
                            let peer_id = PeerId(peer_id_bytes);
                            let mut timestamps = VecDeque::new();

                            // Add some old and some recent timestamps
                            for _j in 0..20 {
                                let age = Duration::from_millis(rng.gen_range(0..120_000));
                                timestamps.push_back(now - age);
                            }

                            rate_limits.insert(peer_id, timestamps);
                        }

                        (rate_limits, now)
                    },
                    |(mut rate_limits, now)| {
                        let cutoff = now - Duration::from_secs(60);

                        // Cleanup old entries (current inefficient approach)
                        for (_, timestamps) in rate_limits.iter_mut() {
                            while let Some(&front) = timestamps.front() {
                                if front < cutoff {
                                    timestamps.pop_front();
                                } else {
                                    break;
                                }
                            }
                        }

                        // Remove empty entries
                        rate_limits.retain(|_, timestamps| !timestamps.is_empty());

                        black_box(rate_limits);
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

/// Benchmark memory allocation patterns
fn bench_memory_allocations(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_allocations");

    group.bench_function("vecdeque_vs_vec", |b| {
        b.iter(|| {
            // VecDeque allocation pattern
            let mut vecdeque = VecDeque::new();
            for _i in 0..1000 {
                let mut peer_id_bytes = [0u8; 32];
                let uuid = Uuid::new_v4();
                let uuid_bytes = uuid.as_bytes();
                peer_id_bytes[..16].copy_from_slice(uuid_bytes);
                let peer_id = PeerId(peer_id_bytes);
                let item = RelayQueueItem::new(peer_id, 256);
                vecdeque.push_back(item);
            }

            // Process half the items
            for _ in 0..500 {
                if let Some(item) = vecdeque.pop_front() {
                    black_box(item);
                }
            }

            black_box(vecdeque);
        });
    });

    group.bench_function("frequent_resize", |b| {
        b.iter(|| {
            let mut queue = VecDeque::new();

            // Simulate frequent growth and shrinkage
            for _cycle in 0..10 {
                // Grow
                for _i in 0..100 {
                    let mut peer_id_bytes = [0u8; 32];
                    let uuid = Uuid::new_v4();
                    let uuid_bytes = uuid.as_bytes();
                    peer_id_bytes[..16].copy_from_slice(uuid_bytes);
                    let peer_id = PeerId(peer_id_bytes);
                    let item = RelayQueueItem::new(peer_id, 64);
                    queue.push_back(item);
                }

                // Shrink
                for _ in 0..80 {
                    if let Some(item) = queue.pop_front() {
                        black_box(item);
                    }
                }
            }

            black_box(queue);
        });
    });

    group.finish();
}

/// Benchmark different data structure alternatives
fn bench_alternatives(c: &mut Criterion) {
    let mut group = c.benchmark_group("data_structure_alternatives");

    group.bench_function("indexmap_vs_vecdeque", |b| {
        use indexmap::IndexMap;

        b.iter(|| {
            let mut map = IndexMap::new();

            // Add items
            for counter in 0..1000 {
                let mut peer_id_bytes = [0u8; 32];
                let uuid = Uuid::new_v4();
                let uuid_bytes = uuid.as_bytes();
                peer_id_bytes[..16].copy_from_slice(uuid_bytes);
                let peer_id = PeerId(peer_id_bytes);
                let item = RelayQueueItem::new(peer_id, 256);
                map.insert(counter, item);
            }

            // Remove items in FIFO order
            for i in 0..500 {
                if let Some(item) = map.shift_remove(&(i as u64)) {
                    black_box(item);
                }
            }

            black_box(map);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_vecdeque_relay_queue,
    bench_rate_limit_cleanup,
    bench_memory_allocations,
    bench_alternatives
);

criterion_main!(benches);
