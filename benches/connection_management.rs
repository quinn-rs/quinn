//! Benchmarks for connection management performance
//!
//! This benchmark suite measures the performance of connection tracking,
//! resource management, and connection state transitions.

use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use rand::{Rng, thread_rng};
use uuid::Uuid;

use ant_quic::PeerId;

/// Mock connection state for benchmarking
#[derive(Clone, Debug)]
struct MockConnection {
    pub peer_id: PeerId,
    #[allow(dead_code)]
    pub local_addr: SocketAddr,
    #[allow(dead_code)]
    pub remote_addr: SocketAddr,
    pub state: ConnectionState,
    pub last_activity: Instant,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub rtt: Option<Duration>,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
enum ConnectionState {
    Connecting,
    Connected,
    Disconnecting,
    Disconnected,
}

/// Mock connection manager for benchmarking
#[derive(Clone)]
struct MockConnectionManager {
    pub connections: Arc<RwLock<HashMap<PeerId, MockConnection>>>,
    pub active_connections: Arc<RwLock<Vec<PeerId>>>,
    pub _connection_events: Arc<RwLock<VecDeque<ConnectionEvent>>>,
}

#[derive(Clone, Debug)]
enum ConnectionEvent {
    _Connected(()),
    _Disconnected(()),
    _DataReceived((), ()),
    _DataSent((), ()),
}

impl MockConnectionManager {
    fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            active_connections: Arc::new(RwLock::new(Vec::new())),
            _connection_events: Arc::new(RwLock::new(VecDeque::new())),
        }
    }
}

/// Generate test socket addresses
fn generate_socket_addresses(count: usize) -> Vec<SocketAddr> {
    let mut rng = thread_rng();
    let mut addresses = Vec::with_capacity(count);

    for _ in 0..count {
        let ip = format!(
            "192.168.{}.{}",
            rng.gen_range(0..255),
            rng.gen_range(1..254)
        )
        .parse()
        .unwrap();
        let port = rng.gen_range(1024..=65535);
        addresses.push(SocketAddr::new(ip, port));
    }

    addresses
}

/// Generate test connections
fn generate_connections(count: usize) -> Vec<MockConnection> {
    let local_addrs = generate_socket_addresses(count);
    let remote_addrs = generate_socket_addresses(count);
    let mut rng = thread_rng();

    local_addrs
        .into_iter()
        .zip(remote_addrs)
        .map(|(local, remote)| MockConnection {
            peer_id: {
                let mut peer_id_bytes = [0u8; 32];
                let uuid = Uuid::new_v4();
                let uuid_bytes = uuid.as_bytes();
                peer_id_bytes[..16].copy_from_slice(uuid_bytes);
                PeerId(peer_id_bytes)
            },
            local_addr: local,
            remote_addr: remote,
            state: ConnectionState::Connected,
            last_activity: Instant::now(),
            bytes_sent: rng.gen_range(0..1_000_000),
            bytes_received: rng.gen_range(0..1_000_000),
            rtt: Some(Duration::from_millis(rng.gen_range(1..200))),
        })
        .collect()
}

/// Benchmark connection tracking operations
fn bench_connection_tracking(c: &mut Criterion) {
    let mut group = c.benchmark_group("connection_tracking");

    for connection_count in [10, 100, 1000, 5000] {
        group.throughput(Throughput::Elements(connection_count as u64));

        group.bench_with_input(
            BenchmarkId::new("add_connections", connection_count),
            &connection_count,
            |b, &size| {
                let connections = generate_connections(size);

                b.iter(|| {
                    let manager = MockConnectionManager::new();

                    for connection in &connections {
                        let mut conn_map = manager.connections.write().unwrap();
                        conn_map.insert(connection.peer_id, connection.clone());

                        let mut active_list = manager.active_connections.write().unwrap();
                        active_list.push(connection.peer_id);
                    }

                    black_box(manager);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("lookup_connections", connection_count),
            &connection_count,
            |b, &size| {
                let connections = generate_connections(size);
                let manager = MockConnectionManager::new();

                // Pre-populate connections
                {
                    let mut conn_map = manager.connections.write().unwrap();
                    for connection in &connections {
                        conn_map.insert(connection.peer_id, connection.clone());
                    }
                }

                b.iter(|| {
                    let conn_map = manager.connections.read().unwrap();
                    let mut found = Vec::new();

                    for connection in &connections {
                        if let Some(conn) = conn_map.get(&connection.peer_id) {
                            found.push(black_box(conn.clone()));
                        }
                    }

                    found
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("update_connections", connection_count),
            &connection_count,
            |b, &size| {
                let connections = generate_connections(size);
                let mut rng = thread_rng();

                b.iter_batched(
                    || {
                        let manager = MockConnectionManager::new();

                        // Pre-populate connections
                        {
                            let mut conn_map = manager.connections.write().unwrap();
                            for connection in &connections {
                                conn_map.insert(connection.peer_id, connection.clone());
                            }
                        }

                        manager
                    },
                    |manager| {
                        {
                            let mut conn_map = manager.connections.write().unwrap();

                            // Update random connections
                            for connection in connections.iter().take(size / 2) {
                                if let Some(conn) = conn_map.get_mut(&connection.peer_id) {
                                    conn.last_activity = Instant::now();
                                    conn.bytes_sent += rng.gen_range(1..10000);
                                    conn.bytes_received += rng.gen_range(1..10000);
                                    conn.rtt = Some(Duration::from_millis(rng.gen_range(1..200)));
                                }
                            }
                        }

                        black_box(manager);
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("remove_connections", connection_count),
            &connection_count,
            |b, &size| {
                let connections = generate_connections(size);

                b.iter_batched(
                    || {
                        let manager = MockConnectionManager::new();

                        // Pre-populate connections
                        {
                            let mut conn_map = manager.connections.write().unwrap();
                            let mut active_list = manager.active_connections.write().unwrap();
                            for connection in &connections {
                                conn_map.insert(connection.peer_id, connection.clone());
                                active_list.push(connection.peer_id);
                            }
                        }

                        manager
                    },
                    |manager| {
                        {
                            let mut conn_map = manager.connections.write().unwrap();
                            let mut active_list = manager.active_connections.write().unwrap();

                            // Remove half the connections
                            for connection in connections.iter().take(size / 2) {
                                conn_map.remove(&connection.peer_id);
                                active_list.retain(|&id| id != connection.peer_id);
                            }
                        }

                        black_box(manager);
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

/// Benchmark event processing
fn bench_event_processing(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_processing");

    for event_count in [10, 100, 1000, 10000] {
        group.throughput(Throughput::Elements(event_count as u64));

        group.bench_with_input(
            BenchmarkId::new("queue_events", event_count),
            &event_count,
            |b, &size| {
                let peer_ids: Vec<PeerId> = (0..100)
                    .map(|_| {
                        let mut peer_id_bytes = [0u8; 32];
                        let uuid = Uuid::new_v4();
                        let uuid_bytes = uuid.as_bytes();
                        peer_id_bytes[..16].copy_from_slice(uuid_bytes);
                        PeerId(peer_id_bytes)
                    })
                    .collect();
                let mut rng = thread_rng();

                b.iter(|| {
                    let events = Arc::new(RwLock::new(VecDeque::new()));

                    for _ in 0..size {
                        let _peer_id = peer_ids[rng.gen_range(0..peer_ids.len())];
                        let event = match rng.gen_range(0..4) {
                            0 => ConnectionEvent::_Connected(()),
                            1 => ConnectionEvent::_Disconnected(()),
                            2 => ConnectionEvent::_DataReceived((), ()),
                            _ => ConnectionEvent::_DataSent((), ()),
                        };

                        let mut event_queue = events.write().unwrap();
                        event_queue.push_back(event);
                    }

                    black_box(events);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("process_events", event_count),
            &event_count,
            |b, &size| {
                let peer_ids: Vec<PeerId> = (0..100)
                    .map(|_| {
                        let mut peer_id_bytes = [0u8; 32];
                        let uuid = Uuid::new_v4();
                        let uuid_bytes = uuid.as_bytes();
                        peer_id_bytes[..16].copy_from_slice(uuid_bytes);
                        PeerId(peer_id_bytes)
                    })
                    .collect();
                let mut rng = thread_rng();

                b.iter_batched(
                    || {
                        let events = Arc::new(RwLock::new(VecDeque::new()));

                        // Pre-populate events
                        {
                            let mut event_queue = events.write().unwrap();
                            for _ in 0..size {
                                let _peer_id = peer_ids[rng.gen_range(0..peer_ids.len())];
                                let event = match rng.gen_range(0..4) {
                                    0 => ConnectionEvent::_Connected(()),
                                    1 => ConnectionEvent::_Disconnected(()),
                                    2 => ConnectionEvent::_DataReceived((), ()),
                                    _ => ConnectionEvent::_DataSent((), ()),
                                };
                                event_queue.push_back(event);
                            }
                        }

                        events
                    },
                    |events| {
                        let mut processed = Vec::new();

                        loop {
                            let event = {
                                let mut event_queue = events.write().unwrap();
                                event_queue.pop_front()
                            };

                            match event {
                                Some(event) => processed.push(black_box(event)),
                                None => break,
                            }
                        }

                        processed
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

/// Benchmark resource cleanup
fn bench_resource_cleanup(c: &mut Criterion) {
    let mut group = c.benchmark_group("resource_cleanup");

    for connection_count in [100, 1000, 5000] {
        group.throughput(Throughput::Elements(connection_count as u64));

        group.bench_with_input(
            BenchmarkId::new("cleanup_inactive", connection_count),
            &connection_count,
            |b, &size| {
                let mut rng = thread_rng();

                b.iter_batched(
                    || {
                        let manager = MockConnectionManager::new();
                        let now = Instant::now();

                        // Pre-populate connections with varying activity times
                        {
                            let mut conn_map = manager.connections.write().unwrap();
                            let mut active_list = manager.active_connections.write().unwrap();

                            for _i in 0..size {
                                let mut peer_id_bytes = [0u8; 32];
                                let uuid = Uuid::new_v4();
                                let uuid_bytes = uuid.as_bytes();
                                peer_id_bytes[..16].copy_from_slice(uuid_bytes);
                                let peer_id = PeerId(peer_id_bytes);
                                let age = Duration::from_secs(rng.gen_range(0..3600));
                                let local_addr = generate_socket_addresses(1)[0];
                                let remote_addr = generate_socket_addresses(1)[0];

                                let connection = MockConnection {
                                    peer_id,
                                    local_addr,
                                    remote_addr,
                                    state: if rng.gen_bool(0.1) {
                                        ConnectionState::Disconnected
                                    } else {
                                        ConnectionState::Connected
                                    },
                                    last_activity: now - age,
                                    bytes_sent: rng.gen_range(0..1_000_000),
                                    bytes_received: rng.gen_range(0..1_000_000),
                                    rtt: Some(Duration::from_millis(rng.gen_range(1..200))),
                                };

                                conn_map.insert(peer_id, connection);
                                active_list.push(peer_id);
                            }
                        }

                        (manager, now)
                    },
                    |(manager, now)| {
                        let timeout = Duration::from_secs(300); // 5 minutes
                        let mut removed = Vec::new();

                        // Cleanup inactive connections
                        {
                            let mut conn_map = manager.connections.write().unwrap();
                            let mut active_list = manager.active_connections.write().unwrap();

                            conn_map.retain(|&peer_id, connection| {
                                let should_keep = matches!(
                                    connection.state,
                                    ConnectionState::Connected | ConnectionState::Connecting
                                ) && now.duration_since(connection.last_activity)
                                    < timeout;

                                if !should_keep {
                                    removed.push(peer_id);
                                }

                                should_keep
                            });

                            active_list.retain(|&peer_id| !removed.contains(&peer_id));
                        }

                        black_box((manager, removed));
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

/// Benchmark concurrent access patterns
fn bench_concurrent_access(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_access");

    for connection_count in [100, 1000] {
        group.throughput(Throughput::Elements(connection_count as u64));

        group.bench_with_input(
            BenchmarkId::new("read_heavy_workload", connection_count),
            &connection_count,
            |b, &size| {
                let connections = generate_connections(size);
                let manager = MockConnectionManager::new();

                // Pre-populate connections
                {
                    let mut conn_map = manager.connections.write().unwrap();
                    for connection in &connections {
                        conn_map.insert(connection.peer_id, connection.clone());
                    }
                }

                b.iter(|| {
                    // Simulate multiple read operations
                    let mut results = Vec::new();

                    for _ in 0..10 {
                        let conn_map = manager.connections.read().unwrap();

                        for connection in &connections {
                            if let Some(conn) = conn_map.get(&connection.peer_id) {
                                results.push(black_box((conn.peer_id, conn.state.clone())));
                            }
                        }
                    }

                    results
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("write_heavy_workload", connection_count),
            &connection_count,
            |b, &size| {
                let connections = generate_connections(size);
                let mut rng = thread_rng();

                b.iter_batched(
                    || {
                        let manager = MockConnectionManager::new();

                        // Pre-populate connections
                        {
                            let mut conn_map = manager.connections.write().unwrap();
                            for connection in &connections {
                                conn_map.insert(connection.peer_id, connection.clone());
                            }
                        }

                        manager
                    },
                    |manager| {
                        // Simulate multiple write operations
                        for _ in 0..10 {
                            let mut conn_map = manager.connections.write().unwrap();

                            for connection in connections.iter().take(size / 10) {
                                if let Some(conn) = conn_map.get_mut(&connection.peer_id) {
                                    conn.last_activity = Instant::now();
                                    conn.bytes_sent += rng.gen_range(1..1000);
                                }
                            }
                        }

                        black_box(manager);
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_connection_tracking,
    bench_event_processing,
    bench_resource_cleanup,
    bench_concurrent_access
);

criterion_main!(benches);
