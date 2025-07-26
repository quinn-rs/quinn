# Performance Monitoring Documentation

This document describes the performance monitoring infrastructure for ant-quic.

## Overview

ant-quic uses automated performance benchmarking to:
- Track performance over time
- Detect regressions in pull requests
- Generate performance dashboards
- Maintain historical performance data

## Components

### 1. Benchmarks

Located in `benches/`, using the Criterion.rs framework:
- `quic_benchmarks.rs` - Frame encoding/decoding benchmarks
- `nat_traversal_performance.rs` - NAT traversal performance
- `connection_management.rs` - Connection handling benchmarks
- `auth_benchmarks.rs` - Authentication performance
- `address_discovery_bench.rs` - Address discovery benchmarks

### 2. CI/CD Workflow

The `.github/workflows/benchmarks.yml` workflow:
- Runs on every PR to detect regressions
- Runs on master/main pushes to track history
- Weekly scheduled runs for trend analysis
- Configurable regression thresholds

### 3. Analysis Scripts

Located in `.github/scripts/`:
- `analyze-benchmarks.py` - Generate benchmark reports
- `compare-benchmarks.py` - Compare PR vs baseline
- `benchmark-trends.py` - Analyze historical trends
- `generate-dashboard.py` - Create HTML dashboards

## Usage

### Running Benchmarks Locally

```bash
# Run all benchmarks
make bench

# Run with criterion (detailed reports)
make bench-criterion

# Quick benchmark check
make bench-quick

# Compare with saved baseline
make bench-compare

# Save current results as baseline
make bench-save
```

### Adding New Benchmarks

1. Create a new file in `benches/` directory:
```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn my_benchmark(c: &mut Criterion) {
    c.bench_function("my_function", |b| {
        b.iter(|| {
            // Code to benchmark
            black_box(my_function());
        });
    });
}

criterion_group!(benches, my_benchmark);
criterion_main!(benches);
```

2. Add to `Cargo.toml`:
```toml
[[bench]]
name = "my_benchmark"
harness = false
```

### Performance Regression Detection

The CI system automatically detects performance regressions:

- **>10% slower**: Marked as REGRESSION (PR fails)
- **5-10% slower**: Marked as SLOWER (warning)
- **5-10% faster**: Marked as FASTER
- **>10% faster**: Marked as IMPROVED

### PR Comments

Every PR receives an automated comment with:
- Performance comparison table
- Regression/improvement summary
- Links to detailed reports

Example:
```
## 📊 Benchmark Results

| Benchmark | Baseline | Current | Change | Status |
|-----------|----------|---------|--------|--------|
| frame_encoding/encode | 125.3µs | 127.1µs | +1.4% | ⚪ STABLE |
| frame_decoding/decode | 89.2µs | 85.7µs | -3.9% | 🟢 FASTER |
| nat_traversal/setup | 1.2ms | 1.4ms | +16.7% | 🔴 REGRESSION |

### Summary

⚠️ 1 Performance Regression Detected:
- nat_traversal/setup: +16.7% slower
```

### Historical Tracking

Performance data is stored in the `benchmark-history` branch:
- Results saved as JSON files
- Automatic cleanup (keeps last 50 runs)
- Trend analysis available

### Performance Dashboard

Access the dashboard at:
`https://[username].github.io/ant-quic/performance/`

Features:
- Interactive charts for each benchmark
- Historical trends
- Performance statistics

## Configuration

### Regression Thresholds

Edit `.github/workflows/benchmarks.yml`:
```yaml
env:
  REGRESSION_THRESHOLD: 10  # Percentage
  IMPROVEMENT_THRESHOLD: 10 # Percentage
```

### Benchmark Timeout

Criterion timeout in `Cargo.toml`:
```toml
[profile.bench]
debug = true
lto = true
opt-level = 3
```

### Adding Benchmarks to CI

New benchmarks are automatically included if they:
1. Are in the `benches/` directory
2. Use the Criterion framework
3. Are listed in `Cargo.toml`

## Best Practices

### Writing Good Benchmarks

1. **Use black_box** to prevent optimization:
```rust
b.iter(|| {
    let result = compute_value();
    black_box(result);
});
```

2. **Benchmark realistic scenarios**:
- Use real-world data sizes
- Include setup/teardown in measurements
- Test edge cases

3. **Group related benchmarks**:
```rust
let mut group = c.benchmark_group("encoding");
group.bench_function("small", |b| b.iter(|| encode_small()));
group.bench_function("large", |b| b.iter(|| encode_large()));
group.finish();
```

### Interpreting Results

1. **Single run variations**: ±5% is normal
2. **Consistent trends**: Look at 7-day/30-day averages
3. **System factors**: CPU throttling, background processes

### Troubleshooting

**Benchmarks not running in CI:**
- Check workflow logs
- Verify Cargo.toml configuration
- Ensure criterion is in dev-dependencies

**High variance in results:**
- Increase sample size
- Check for system load
- Use dedicated benchmark machines

**Missing baseline comparisons:**
- Ensure base branch has benchmark history
- Check artifact download in workflow

## Advanced Usage

### Custom Metrics

Add custom metrics to benchmarks:
```rust
use criterion::{BenchmarkId, Throughput};

let mut group = c.benchmark_group("throughput");
for size in [1024, 2048, 4096] {
    group.throughput(Throughput::Bytes(size as u64));
    group.bench_with_input(
        BenchmarkId::from_parameter(size),
        &size,
        |b, &size| {
            b.iter(|| process_bytes(size));
        }
    );
}
```

### Profiling Integration

Use with profiling tools:
```bash
# Profile with perf
cargo bench --bench my_benchmark -- --profile-time=10

# Generate flamegraphs
cargo flamegraph --bench my_benchmark
```

### Export Formats

Export results for external analysis:
```bash
# JSON format
cargo criterion --message-format=json > results.json

# CSV export (custom script)
python3 .github/scripts/export-csv.py results.json
```

## Maintenance

### Regular Tasks

1. **Review trends monthly**: Check for gradual degradation
2. **Update baselines quarterly**: Reflect optimization improvements
3. **Clean old data**: Automated via workflow
4. **Monitor CI costs**: Benchmark runs use compute time

### Optimization Workflow

When regressions are detected:
1. Reproduce locally with `make bench-compare`
2. Profile the specific benchmark
3. Identify bottlenecks
4. Implement fixes
5. Verify with benchmarks
6. Update baseline if needed

## Future Improvements

Planned enhancements:
- Memory usage tracking
- Allocation profiling
- Network throughput benchmarks
- Multi-platform performance comparison
- Integration with observability platforms