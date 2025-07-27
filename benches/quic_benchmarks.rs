use ant_quic::{TransportError, TransportErrorCode, VarInt};
use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use std::time::Duration;

fn varint_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("varint");

    // Benchmark VarInt creation and comparison
    group.bench_function("create_small", |b| {
        b.iter(|| {
            let v = VarInt::from_u32(black_box(42));
            black_box(v);
        });
    });

    group.bench_function("create_medium", |b| {
        b.iter(|| {
            let v = VarInt::from_u32(black_box(16383));
            black_box(v);
        });
    });

    group.bench_function("create_large", |b| {
        b.iter(|| {
            let v = VarInt::from_u32(black_box(1073741823));
            black_box(v);
        });
    });

    // Benchmark comparisons
    let v1 = VarInt::from_u32(100);
    let v2 = VarInt::from_u32(200);

    group.bench_function("compare", |b| {
        b.iter(|| {
            let result = black_box(&v1) < black_box(&v2);
            black_box(result);
        });
    });

    group.finish();
}

fn transport_error_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("transport_error");

    group.bench_function("create_protocol_violation", |b| {
        b.iter(|| {
            let err = TransportError {
                code: TransportErrorCode::PROTOCOL_VIOLATION,
                frame: None,
                reason: "test error".into(),
            };
            black_box(err);
        });
    });

    group.bench_function("create_with_reason", |b| {
        b.iter(|| {
            let err = TransportError {
                code: TransportErrorCode::INTERNAL_ERROR,
                frame: None,
                reason: "internal error occurred".into(),
            };
            black_box(err);
        });
    });

    group.finish();
}

fn bytes_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("bytes");

    // Small bytes
    group.bench_function("create_small", |b| {
        b.iter(|| {
            let data = Bytes::from_static(b"hello world");
            black_box(data);
        });
    });

    // Medium bytes
    group.bench_function("create_medium", |b| {
        let data = vec![0u8; 1024];
        b.iter(|| {
            let bytes = Bytes::from(black_box(data.clone()));
            black_box(bytes);
        });
    });

    // Large bytes
    group.bench_function("create_large", |b| {
        let data = vec![0u8; 65536];
        b.iter(|| {
            let bytes = Bytes::from(black_box(data.clone()));
            black_box(bytes);
        });
    });

    // Clone operations
    let original = Bytes::from(vec![0u8; 1024]);
    group.bench_function("clone_1kb", |b| {
        b.iter(|| {
            let cloned = black_box(&original).clone();
            black_box(cloned);
        });
    });

    group.finish();
}

fn duration_conversions(c: &mut Criterion) {
    let mut group = c.benchmark_group("duration");

    group.bench_function("from_millis", |b| {
        b.iter(|| {
            let dur = Duration::from_millis(black_box(1234));
            black_box(dur);
        });
    });

    group.bench_function("as_nanos", |b| {
        let dur = Duration::from_millis(1234);
        b.iter(|| {
            let nanos = black_box(&dur).as_nanos();
            black_box(nanos);
        });
    });

    group.finish();
}

// Benchmark common patterns
fn common_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("patterns");

    // Option handling
    group.bench_function("option_unwrap_or", |b| {
        let opt: Option<u32> = None;
        b.iter(|| {
            let value = black_box(&opt).unwrap_or(42);
            black_box(value);
        });
    });

    // Result handling
    group.bench_function("result_ok", |b| {
        let res: Result<u32, &str> = Ok(42);
        b.iter(|| {
            let is_ok = black_box(&res).is_ok();
            black_box(is_ok);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    varint_operations,
    transport_error_creation,
    bytes_operations,
    duration_conversions,
    common_patterns
);
criterion_main!(benches);
