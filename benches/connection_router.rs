//! Benchmarks for connection router performance
//!
//! This benchmark suite measures the performance of the connection router's
//! engine selection logic, ensuring no regression from the routing layer.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};

use ant_quic::{
    connection_router::{ConnectionRouter, RouterConfig},
    transport::{TransportAddr, TransportCapabilities, TransportRegistry},
};

/// Benchmark engine selection for different transport types
fn bench_engine_selection(c: &mut Criterion) {
    let mut group = c.benchmark_group("engine_selection");

    // Create addresses for testing
    let udp_addr: std::net::SocketAddr = "192.168.1.100:9000".parse().unwrap();
    let udp_transport = TransportAddr::Udp(udp_addr);
    let ble_transport = TransportAddr::Ble {
        device_id: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        service_uuid: None,
    };
    let lora_transport = TransportAddr::LoRa {
        device_addr: [0x12, 0x34, 0x56, 0x78],
        params: ant_quic::transport::LoRaParams::default(),
    };

    // Benchmark UDP address selection
    group.bench_function("udp_address", |b| {
        let mut router = ConnectionRouter::new(RouterConfig::default());
        b.iter(|| {
            let engine = router.select_engine_for_addr(black_box(&udp_transport));
            black_box(engine)
        });
    });

    // Benchmark BLE address selection
    group.bench_function("ble_address", |b| {
        let mut router = ConnectionRouter::new(RouterConfig::default());
        b.iter(|| {
            let engine = router.select_engine_for_addr(black_box(&ble_transport));
            black_box(engine)
        });
    });

    // Benchmark LoRa address selection
    group.bench_function("lora_address", |b| {
        let mut router = ConnectionRouter::new(RouterConfig::default());
        b.iter(|| {
            let engine = router.select_engine_for_addr(black_box(&lora_transport));
            black_box(engine)
        });
    });

    group.finish();
}

/// Benchmark detailed engine selection with result tracking
fn bench_engine_selection_detailed(c: &mut Criterion) {
    let mut group = c.benchmark_group("engine_selection_detailed");

    let broadband_caps = TransportCapabilities::broadband();
    let ble_caps = TransportCapabilities::ble();
    let lora_caps = TransportCapabilities::lora_long_range();

    // Benchmark broadband selection
    group.bench_function("broadband_detailed", |b| {
        let mut router = ConnectionRouter::new(RouterConfig::default());
        b.iter(|| {
            let result = router.select_engine_detailed(black_box(&broadband_caps));
            black_box(result)
        });
    });

    // Benchmark BLE selection
    group.bench_function("ble_detailed", |b| {
        let mut router = ConnectionRouter::new(RouterConfig::default());
        b.iter(|| {
            let result = router.select_engine_detailed(black_box(&ble_caps));
            black_box(result)
        });
    });

    // Benchmark LoRa selection
    group.bench_function("lora_detailed", |b| {
        let mut router = ConnectionRouter::new(RouterConfig::default());
        b.iter(|| {
            let result = router.select_engine_detailed(black_box(&lora_caps));
            black_box(result)
        });
    });

    group.finish();
}

/// Benchmark fallback selection logic
fn bench_fallback_selection(c: &mut Criterion) {
    let mut group = c.benchmark_group("fallback_selection");

    let broadband_caps = TransportCapabilities::broadband();

    // Benchmark with QUIC available
    group.bench_function("quic_available", |b| {
        let mut router = ConnectionRouter::new(RouterConfig::default());
        b.iter(|| {
            let result = router.select_engine_with_fallback(
                black_box(&broadband_caps),
                black_box(true), // QUIC available
                black_box(true), // Constrained available
            );
            black_box(result)
        });
    });

    // Benchmark with fallback needed
    group.bench_function("quic_fallback", |b| {
        let mut router = ConnectionRouter::new(RouterConfig::default());
        b.iter(|| {
            let result = router.select_engine_with_fallback(
                black_box(&broadband_caps),
                black_box(false), // QUIC not available
                black_box(true),  // Constrained available
            );
            black_box(result)
        });
    });

    group.finish();
}

/// Benchmark capabilities lookup for addresses
fn bench_capabilities_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("capabilities_lookup");
    group.throughput(Throughput::Elements(1));

    let addresses = vec![
        TransportAddr::Udp("192.168.1.1:9000".parse().unwrap()),
        TransportAddr::Ble {
            device_id: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            service_uuid: None,
        },
        TransportAddr::LoRa {
            device_addr: [0x12, 0x34, 0x56, 0x78],
            params: ant_quic::transport::LoRaParams::default(),
        },
        TransportAddr::serial("/dev/ttyUSB0"),
        TransportAddr::I2p {
            destination: Box::new([0u8; 387]),
        },
        TransportAddr::yggdrasil([0; 16]),
    ];

    group.bench_function("mixed_addresses", |b| {
        b.iter(|| {
            for addr in &addresses {
                let caps = ConnectionRouter::capabilities_for_addr(black_box(addr));
                black_box(caps);
            }
        });
    });

    group.finish();
}

/// Benchmark constrained connection through router
fn bench_constrained_connect(c: &mut Criterion) {
    let mut group = c.benchmark_group("constrained_connect");

    let ble_addr = TransportAddr::Ble {
        device_id: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        service_uuid: None,
    };

    // Benchmark constrained connection creation
    group.bench_function("ble_connect", |b| {
        let mut router = ConnectionRouter::new(RouterConfig::default());
        b.iter(|| {
            let result = router.connect(black_box(&ble_addr));
            black_box(result)
        });
    });

    group.finish();
}

/// Benchmark router statistics tracking overhead
fn bench_stats_tracking(c: &mut Criterion) {
    let mut group = c.benchmark_group("stats_tracking");

    let udp_addr = TransportAddr::Udp("192.168.1.100:9000".parse().unwrap());
    let ble_addr = TransportAddr::Ble {
        device_id: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        service_uuid: None,
    };

    // Benchmark stats access
    group.bench_function("stats_access", |b| {
        let router = ConnectionRouter::new(RouterConfig::default());
        b.iter(|| {
            let stats = router.stats();
            black_box(stats)
        });
    });

    // Benchmark selection with stats update
    group.bench_function("selection_with_stats", |b| {
        let mut router = ConnectionRouter::new(RouterConfig::default());
        b.iter(|| {
            let _ = router.select_engine_for_addr(black_box(&udp_addr));
            let _ = router.select_engine_for_addr(black_box(&ble_addr));
            let stats = router.stats().clone();
            black_box(stats)
        });
    });

    group.finish();
}

/// Benchmark router creation with different configurations
fn bench_router_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("router_creation");

    // Default config
    group.bench_function("default_config", |b| {
        b.iter(|| {
            let router = ConnectionRouter::new(black_box(RouterConfig::default()));
            black_box(router)
        });
    });

    // BLE-focused config
    group.bench_function("ble_focused_config", |b| {
        b.iter(|| {
            let router = ConnectionRouter::new(black_box(RouterConfig::for_ble_focus()));
            black_box(router)
        });
    });

    // With registry
    group.bench_function("with_registry", |b| {
        let registry = Arc::new(TransportRegistry::new());
        b.iter(|| {
            let router = ConnectionRouter::with_registry(
                black_box(RouterConfig::default()),
                black_box(Arc::clone(&registry)),
            );
            black_box(router)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_engine_selection,
    bench_engine_selection_detailed,
    bench_fallback_selection,
    bench_capabilities_lookup,
    bench_constrained_connect,
    bench_stats_tracking,
    bench_router_creation,
);
criterion_main!(benches);
