/// NAT Traversal Performance Benchmarks
/// 
/// Benchmarks for measuring NAT traversal performance under various conditions

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::runtime::Runtime;

/// Benchmark candidate discovery performance
fn bench_candidate_discovery(c: &mut Criterion) {
    let mut group = c.benchmark_group("candidate_discovery");
    
    // Different numbers of interfaces to test
    let interface_counts = vec![1, 5, 10, 20];
    
    for count in interface_counts {
        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &count,
            |b, &interface_count| {
                b.iter(|| {
                    // Simulate multiple interfaces
                    let mut candidates = Vec::new();
                    for i in 0..interface_count {
                        let addr = SocketAddr::new(
                            IpAddr::V4(Ipv4Addr::new(192, 168, 1, i as u8)),
                            9000 + i as u16,
                        );
                        candidates.push((addr, 100)); // (address, priority)
                    }
                    
                    // Sort by priority
                    candidates.sort_by_key(|(_, priority)| std::cmp::Reverse(*priority));
                    
                    black_box(candidates)
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark hole punching coordination
fn bench_hole_punching_coordination(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("hole_punching");
    group.measurement_time(Duration::from_secs(10));
    
    // Different numbers of simultaneous connections
    let connection_counts = vec![1, 5, 10, 25];
    
    for count in connection_counts {
        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &count,
            |b, &conn_count| {
                b.iter(|| {
                    rt.block_on(async {
                        // Simulate hole punching coordination
                        let mut tasks = Vec::new();
                        
                        for i in 0..conn_count {
                            let task = tokio::spawn(async move {
                                // Simulate punch packet sending
                                tokio::time::sleep(Duration::from_micros(100)).await;
                                i
                            });
                            tasks.push(task);
                        }
                        
                        // Wait for all punches to complete
                        for task in tasks {
                            let _ = task.await;
                        }
                        
                        black_box(conn_count)
                    })
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark candidate pair prioritization
fn bench_candidate_prioritization(c: &mut Criterion) {
    let mut group = c.benchmark_group("candidate_prioritization");
    
    // Different numbers of candidates
    let candidate_counts = vec![10, 50, 100, 500];
    
    for count in candidate_counts {
        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &count,
            |b, &candidate_count| {
                // Generate candidates with (address, priority, source_type)
                let mut candidates = Vec::new();
                for i in 0..candidate_count {
                    let source_type = i % 3; // 0=Local, 1=ServerReflexive, 2=Predicted
                    
                    let addr = SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(10, 0, 0, (i % 256) as u8)),
                        30000 + (i as u16),
                    );
                    
                    let priority = calculate_priority_by_type(source_type, i);
                    candidates.push((addr, priority, source_type));
                }
                
                b.iter(|| {
                    // Sort by priority
                    let mut sorted = candidates.clone();
                    sorted.sort_by_key(|(_, priority, _)| std::cmp::Reverse(*priority));
                    black_box(sorted)
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark NAT type detection
fn bench_nat_type_detection(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("nat_type_detection");
    
    group.bench_function("detect_nat_type", |b| {
        b.iter(|| {
            rt.block_on(async {
                // Simulate NAT type detection process
                let tests = vec![
                    // Test 1: Basic connectivity
                    tokio::time::sleep(Duration::from_millis(10)),
                    // Test 2: Port preservation
                    tokio::time::sleep(Duration::from_millis(10)),
                    // Test 3: IP restriction
                    tokio::time::sleep(Duration::from_millis(10)),
                    // Test 4: Port restriction
                    tokio::time::sleep(Duration::from_millis(10)),
                ];
                
                for test in tests {
                    test.await;
                }
                
                // Return detected NAT type
                black_box("PortRestrictedCone")
            })
        });
    });
    
    group.finish();
}

/// Benchmark relay fallback decision
fn bench_relay_fallback(c: &mut Criterion) {
    let mut group = c.benchmark_group("relay_fallback");
    
    // Different failure counts before relay
    let failure_thresholds = vec![1, 3, 5, 10];
    
    for threshold in failure_thresholds {
        group.bench_with_input(
            BenchmarkId::from_parameter(threshold),
            &threshold,
            |b, &failure_count| {
                b.iter(|| {
                    let mut attempts = 0;
                    let mut should_use_relay = false;
                    
                    // Simulate connection attempts
                    for _ in 0..failure_count {
                        attempts += 1;
                        
                        // Check if we should fall back to relay
                        if attempts >= failure_count {
                            should_use_relay = true;
                            break;
                        }
                        
                        // Simulate failed connection
                        black_box(false);
                    }
                    
                    black_box(should_use_relay)
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark address mapping table operations
fn bench_address_mapping(c: &mut Criterion) {
    use std::collections::HashMap;
    
    let mut group = c.benchmark_group("address_mapping");
    
    // Different table sizes
    let table_sizes = vec![100, 1000, 10000];
    
    for size in table_sizes {
        // Benchmark insertion
        group.bench_with_input(
            BenchmarkId::new("insert", size),
            &size,
            |b, &table_size| {
                b.iter(|| {
                    let mut mapping: HashMap<SocketAddr, SocketAddr> = HashMap::new();
                    for i in 0..table_size {
                        let internal = SocketAddr::new(
                            IpAddr::V4(Ipv4Addr::new(192, 168, 1, (i % 256) as u8)),
                            10000 + (i as u16),
                        );
                        let external = SocketAddr::new(
                            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                            20000 + (i as u16),
                        );
                        mapping.insert(internal, external);
                    }
                    black_box(mapping)
                });
            },
        );
        
        // Benchmark lookup
        group.bench_with_input(
            BenchmarkId::new("lookup", size),
            &size,
            |b, &table_size| {
                let mut mapping: HashMap<SocketAddr, SocketAddr> = HashMap::new();
                
                // Pre-populate
                for i in 0..table_size {
                    let internal = SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(192, 168, 1, (i % 256) as u8)),
                        10000 + (i as u16),
                    );
                    let external = SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                        20000 + (i as u16),
                    );
                    mapping.insert(internal, external);
                }
                
                b.iter(|| {
                    let addr = SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
                        10050,
                    );
                    black_box(mapping.get(&addr))
                });
            },
        );
    }
    
    group.finish();
}

/// Helper function to calculate candidate priority by type
fn calculate_priority_by_type(source_type: usize, index: usize) -> u32 {
    match source_type {
        0 => 100 + (index as u32), // Local
        1 => 200 + (index as u32), // ServerReflexive
        _ => 50 + (index as u32),  // Predicted
    }
}

criterion_group!(
    benches,
    bench_candidate_discovery,
    bench_hole_punching_coordination,
    bench_candidate_prioritization,
    bench_nat_type_detection,
    bench_relay_fallback,
    bench_address_mapping
);

criterion_main!(benches);