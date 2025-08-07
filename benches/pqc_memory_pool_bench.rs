//! Benchmarks for PQC memory pool

#[cfg(feature = "pqc")]
use ant_quic::crypto::pqc::memory_pool::{PoolConfig, PqcMemoryPool};
#[cfg(feature = "pqc")]
use ant_quic::crypto::pqc::types::*;
#[cfg(feature = "pqc")]
use criterion::{Criterion, black_box, criterion_group, criterion_main};
#[cfg(feature = "pqc")]
use std::time::Duration;

#[cfg(feature = "pqc")]
fn bench_pool_allocation(c: &mut Criterion) {
    let pool = PqcMemoryPool::new(PoolConfig {
        initial_size: 10,
        max_size: 100,
        growth_increment: 5,
        acquire_timeout: Duration::from_secs(1),
    });

    c.bench_function("pool_ml_kem_public_key", |b| {
        b.iter(|| {
            let guard = pool.acquire_ml_kem_public_key().unwrap();
            black_box(&guard);
            // Guard automatically returned on drop
        });
    });
}

#[cfg(feature = "pqc")]
fn bench_direct_allocation(c: &mut Criterion) {
    c.bench_function("direct_ml_kem_public_key", |b| {
        b.iter(|| {
            let buffer = Box::new([0u8; ML_KEM_768_PUBLIC_KEY_SIZE]);
            black_box(&buffer);
        });
    });
}

#[cfg(feature = "pqc")]
fn bench_pool_secret_key(c: &mut Criterion) {
    let pool = PqcMemoryPool::new(PoolConfig::default());

    c.bench_function("pool_ml_kem_secret_key", |b| {
        b.iter(|| {
            let mut guard = pool.acquire_ml_kem_secret_key().unwrap();
            // Simulate some work
            guard.as_mut().0[0] = 42;
            black_box(&guard);
            // Guard automatically zeros and returns on drop
        });
    });
}

#[cfg(feature = "pqc")]
fn bench_concurrent_pool_access(c: &mut Criterion) {
    use std::sync::Arc;
    use std::thread;

    let pool = Arc::new(PqcMemoryPool::new(PoolConfig {
        initial_size: 20,
        max_size: 100,
        growth_increment: 10,
        acquire_timeout: Duration::from_secs(1),
    }));

    c.bench_function("concurrent_pool_access", |b| {
        b.iter(|| {
            let mut handles = vec![];

            for _ in 0..4 {
                let pool_clone = pool.clone();
                let handle = thread::spawn(move || {
                    for _ in 0..5 {
                        let _guard = pool_clone.acquire_ml_kem_ciphertext().unwrap();
                        // Simulate some work
                        std::thread::yield_now();
                    }
                });
                handles.push(handle);
            }

            for handle in handles {
                handle.join().unwrap();
            }
        });
    });
}

#[cfg(feature = "pqc")]
criterion_group!(
    benches,
    bench_pool_allocation,
    bench_direct_allocation,
    bench_pool_secret_key,
    bench_concurrent_pool_access
);

#[cfg(feature = "pqc")]
criterion_main!(benches);

#[cfg(not(feature = "pqc"))]
fn main() {
    println!("PQC memory pool benchmarks require the 'pqc' feature to be enabled.");
}
