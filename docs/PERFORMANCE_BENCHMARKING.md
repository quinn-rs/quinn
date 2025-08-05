# Performance Benchmarking Guide

This guide provides comprehensive instructions for benchmarking ant-quic performance, establishing baselines, and identifying optimization opportunities.

## Table of Contents

1. [Benchmarking Overview](#benchmarking-overview)
2. [Local Benchmarking](#local-benchmarking)
3. [Production Benchmarking](#production-benchmarking)
4. [Performance Metrics](#performance-metrics)
5. [Baseline Management](#baseline-management)
6. [Performance Analysis](#performance-analysis)
7. [Optimization Guide](#optimization-guide)
8. [Continuous Performance Testing](#continuous-performance-testing)

## Benchmarking Overview

ant-quic includes comprehensive benchmarking suites measuring:

- **Throughput**: Maximum data transfer rates
- **Latency**: Round-trip times and percentiles
- **Connection Establishment**: Handshake performance
- **NAT Traversal**: Hole punching success and timing
- **Scalability**: Concurrent connection handling

### Benchmark Architecture

```
benches/
├── throughput_benchmarks.rs      # Data transfer performance
├── latency_benchmarks.rs        # RTT measurements
├── nat_traversal_performance.rs  # NAT traversal timing
└── connection_management.rs      # Connection scaling
```

## Local Benchmarking

### Running Benchmarks

#### All Benchmarks
```bash
# Run all benchmarks with default settings
cargo bench

# Save results as baseline
cargo bench -- --save-baseline main

# Compare with baseline
cargo bench -- --baseline main
```

#### Specific Benchmarks
```bash
# Throughput only
cargo bench --bench throughput_benchmarks

# Latency measurements
cargo bench --bench latency_benchmarks

# NAT traversal performance
cargo bench --bench nat_traversal_performance

# Connection management
cargo bench --bench connection_management
```

#### Benchmark Options
```bash
# Longer measurement time for accuracy
cargo bench -- --measurement-time 20

# More samples
cargo bench -- --sample-size 200

# Disable outlier detection
cargo bench -- --noplot

# Export results
cargo bench -- --export json > results.json
```

### Local Environment Setup

#### System Preparation
```bash
# Disable CPU frequency scaling (Linux)
sudo cpupower frequency-set --governor performance

# Increase file descriptor limits
ulimit -n 65536

# Disable swap
sudo swapoff -a

# Set process priority
nice -n -20 cargo bench
```

#### Network Configuration
```bash
# Increase network buffers (Linux)
sudo sysctl -w net.core.rmem_max=134217728
sudo sysctl -w net.core.wmem_max=134217728
sudo sysctl -w net.ipv4.tcp_rmem="4096 87380 134217728"
sudo sysctl -w net.ipv4.tcp_wmem="4096 65536 134217728"

# Enable BBR congestion control
sudo sysctl -w net.core.default_qdisc=fq
sudo sysctl -w net.ipv4.tcp_congestion_control=bbr
```

### Benchmark Harness

Example throughput benchmark:

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use ant_quic::{QuicP2PNode, ConnectionHandle};

fn throughput_benchmark(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("throughput");
    
    // Test different payload sizes
    for size in [1024, 4096, 16384, 65536, 1048576] {
        group.throughput(Throughput::Bytes(size as u64));
        
        group.bench_function(format!("payload_{}B", size), |b| {
            b.to_async(&runtime).iter(|| async {
                let data = vec![0u8; size];
                let node = setup_test_node().await;
                let conn = establish_connection(&node).await;
                
                // Measure throughput
                conn.send(black_box(&data)).await.unwrap();
            });
        });
    }
    
    group.finish();
}

criterion_group!(benches, throughput_benchmark);
criterion_main!(benches);
```

## Production Benchmarking

### DigitalOcean Performance Testing

#### Setup
```bash
# Deploy to DigitalOcean
./scripts/deploy-do.sh deploy

# Wait for service to stabilize
sleep 60

# Run performance tests
./scripts/do-performance-test.sh
```

#### Test Scenarios

1. **Connection Establishment**
   ```bash
   ./target/release/examples/perf_client \
     --server quic.saorsalabs.com:9000 \
     --test connection_establishment \
     --iterations 100
   ```

2. **Throughput Testing**
   ```bash
   ./target/release/examples/perf_client \
     --server quic.saorsalabs.com:9000 \
     --test throughput \
     --payload-size 1048576 \
     --duration 300
   ```

3. **Latency Measurement**
   ```bash
   ./target/release/examples/perf_client \
     --server quic.saorsalabs.com:9000 \
     --test latency \
     --interval 100ms \
     --duration 300
   ```

### Multi-Region Testing

Test across different geographic regions:

```bash
# Deploy test clients in multiple regions
for region in nyc3 sfo3 lon1 sgp1; do
  doctl compute droplet create "perf-client-$region" \
    --region $region \
    --size s-2vcpu-4gb \
    --image ubuntu-22-04-x64 \
    --ssh-keys $SSH_KEY_ID \
    --user-data-file cloud-init.yaml
done

# Run coordinated tests
./scripts/multi-region-perf-test.sh
```

### Load Testing

Simulate production load:

```bash
# Using Locust for load testing
locust -f locustfile.py \
  --host quic.saorsalabs.com:9000 \
  --users 1000 \
  --spawn-rate 10 \
  --run-time 30m
```

Example `locustfile.py`:

```python
from locust import User, task, between
import subprocess
import json

class QuicUser(User):
    wait_time = between(1, 3)
    
    @task(3)
    def send_message(self):
        result = subprocess.run([
            "./perf_client",
            "--server", self.host,
            "--test", "message",
            "--size", "1024"
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            self.environment.events.request.fire(
                request_type="QUIC",
                name="send_message",
                response_time=0,
                exception=Exception(result.stderr)
            )
    
    @task(1)
    def establish_connection(self):
        result = subprocess.run([
            "./perf_client",
            "--server", self.host,
            "--test", "connection_establishment"
        ], capture_output=True, text=True)
        
        data = json.loads(result.stdout)
        self.environment.events.request.fire(
            request_type="QUIC",
            name="connection_establishment",
            response_time=data["duration_ms"],
            response_length=0
        )
```

## Performance Metrics

### Key Metrics

#### 1. Throughput Metrics
- **Bytes per second**: Raw data transfer rate
- **Messages per second**: Application-level throughput
- **Goodput**: Effective application data rate (excluding protocol overhead)

#### 2. Latency Metrics
- **RTT (Round Trip Time)**: Network round trip
- **TTFB (Time To First Byte)**: Connection establishment + first data
- **Percentiles**: p50, p95, p99, p99.9

#### 3. Connection Metrics
- **Handshake duration**: Time to establish QUIC connection
- **Concurrent connections**: Maximum simultaneous connections
- **Connection rate**: New connections per second

#### 4. NAT Traversal Metrics
- **Success rate**: Percentage of successful hole punching
- **Time to traverse**: Duration from attempt to success
- **Candidate discovery time**: Time to find all addresses

### Metrics Collection

```rust
use prometheus::{Counter, Histogram, Registry};

lazy_static! {
    static ref METRICS: Metrics = Metrics::new();
}

struct Metrics {
    throughput_bytes: Counter,
    latency_histogram: Histogram,
    connection_duration: Histogram,
    nat_success_rate: Counter,
}

impl Metrics {
    fn new() -> Self {
        let registry = Registry::new();
        
        Self {
            throughput_bytes: Counter::new(
                "quic_throughput_bytes_total",
                "Total bytes transferred"
            ).unwrap(),
            
            latency_histogram: Histogram::with_opts(
                HistogramOpts::new(
                    "quic_latency_seconds",
                    "Message round-trip latency"
                ).buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0])
            ).unwrap(),
            
            connection_duration: Histogram::with_opts(
                HistogramOpts::new(
                    "quic_connection_duration_seconds",
                    "Time to establish connection"
                ).buckets(vec![0.01, 0.05, 0.1, 0.5, 1.0, 5.0])
            ).unwrap(),
            
            nat_success_rate: Counter::new(
                "nat_traversal_success_total",
                "Successful NAT traversals"
            ).unwrap(),
        }
    }
}
```

## Baseline Management

### Establishing Baselines

#### Initial Baseline
```bash
# Clean environment
cargo clean
cargo build --release

# Warm up
cargo bench -- --warm-up-time 10

# Create baseline
cargo bench -- --save-baseline initial

# Document environment
cat > baselines/initial/environment.json << EOF
{
  "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "rust_version": "$(rustc --version)",
  "os": "$(uname -a)",
  "cpu": "$(lscpu | grep 'Model name' | cut -d: -f2 | xargs)",
  "memory": "$(free -h | grep Mem | awk '{print $2}')",
  "kernel_version": "$(uname -r)"
}
EOF
```

#### Version-Specific Baselines
```bash
# Tag baseline with version
git tag -a "baseline-v0.5.0" -m "Performance baseline for v0.5.0"

# Create release baseline
cargo bench -- --save-baseline v0.5.0

# Archive results
tar -czf baseline-v0.5.0.tar.gz target/criterion
```

### Baseline Comparison

#### Automated Comparison
```bash
#!/bin/bash
# compare-baselines.sh

CURRENT_BASELINE="$1"
PREVIOUS_BASELINE="$2"
THRESHOLD=5  # 5% regression threshold

# Run comparison
cargo bench -- --baseline $PREVIOUS_BASELINE > comparison.txt

# Extract regression data
REGRESSIONS=$(grep -E "Performance has regressed" comparison.txt | wc -l)

if [ $REGRESSIONS -gt 0 ]; then
    echo "Performance regressions detected:"
    grep -A 2 -B 2 "Performance has regressed" comparison.txt
    exit 1
fi

# Check specific metrics
check_metric() {
    local metric=$1
    local current=$(cargo bench --bench $metric -- --baseline $CURRENT_BASELINE --export json | jq '.mean')
    local previous=$(cargo bench --bench $metric -- --baseline $PREVIOUS_BASELINE --export json | jq '.mean')
    local change=$(echo "scale=2; (($current - $previous) / $previous) * 100" | bc)
    
    if (( $(echo "$change > $THRESHOLD" | bc -l) )); then
        echo "Regression in $metric: ${change}%"
        return 1
    fi
}

check_metric "throughput_benchmarks"
check_metric "latency_benchmarks"
check_metric "nat_traversal_performance"
```

### Historical Tracking

Store baseline data for trend analysis:

```sql
-- Create performance tracking database
CREATE TABLE benchmarks (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    git_sha VARCHAR(40) NOT NULL,
    benchmark_name VARCHAR(255) NOT NULL,
    metric_name VARCHAR(255) NOT NULL,
    value DOUBLE PRECISION NOT NULL,
    unit VARCHAR(50) NOT NULL,
    environment JSONB
);

-- Insert baseline data
INSERT INTO benchmarks (timestamp, git_sha, benchmark_name, metric_name, value, unit, environment)
VALUES 
    (NOW(), 'abc123', 'throughput', 'bytes_per_sec', 125000000, 'B/s', '{"os": "Linux", "cpu": "Intel i7"}'),
    (NOW(), 'abc123', 'latency', 'p50', 0.0012, 'seconds', '{"os": "Linux", "cpu": "Intel i7"}');
```

## Performance Analysis

### Profiling Tools

#### CPU Profiling
```bash
# Using perf (Linux)
sudo perf record -g ./target/release/ant-quic
sudo perf report

# Using flamegraph
cargo install flamegraph
cargo flamegraph --bench throughput_benchmarks

# Using Instruments (macOS)
cargo instruments -t "Time Profiler" --bench throughput_benchmarks
```

#### Memory Profiling
```bash
# Using Valgrind
valgrind --tool=massif ./target/release/ant-quic
ms_print massif.out.*

# Using heaptrack
heaptrack ./target/release/ant-quic
heaptrack_gui heaptrack.ant-quic.*

# Built-in allocator stats
RUST_LOG=ant_quic::alloc=debug cargo run
```

### Bottleneck Identification

#### Network Analysis
```bash
# Packet capture
sudo tcpdump -i any -w quic.pcap 'udp port 9000'

# Analysis with tshark
tshark -r quic.pcap -Y quic -T fields \
  -e frame.time_epoch \
  -e quic.packet_length \
  -e quic.packet_number

# Bandwidth utilization
iftop -i eth0 -f "port 9000"
```

#### Lock Contention
```rust
// Add to Cargo.toml
[dependencies]
parking_lot = { version = "0.12", features = ["deadlock_detection"] }

// In main.rs
#[cfg(debug_assertions)]
{
    use parking_lot::deadlock;
    use std::thread;
    use std::time::Duration;
    
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(10));
            let deadlocks = deadlock::check_deadlock();
            if !deadlocks.is_empty() {
                eprintln!("Deadlock detected!");
                for (i, threads) in deadlocks.iter().enumerate() {
                    eprintln!("Deadlock #{}", i);
                    for t in threads {
                        eprintln!("Thread Id {:#?}", t.thread_id());
                        eprintln!("{:#?}", t.backtrace());
                    }
                }
            }
        }
    });
}
```

## Optimization Guide

### Common Optimizations

#### 1. Buffer Management
```rust
// Before: Allocating new buffers
let mut buffer = vec![0u8; 65536];

// After: Buffer pool
lazy_static! {
    static ref BUFFER_POOL: ArrayQueue<Vec<u8>> = ArrayQueue::new(100);
}

fn get_buffer() -> Vec<u8> {
    BUFFER_POOL.pop().unwrap_or_else(|| vec![0u8; 65536])
}

fn return_buffer(mut buffer: Vec<u8>) {
    buffer.clear();
    let _ = BUFFER_POOL.push(buffer);
}
```

#### 2. Batch Processing
```rust
// Before: Individual packet processing
for packet in packets {
    process_packet(packet)?;
}

// After: Batch processing
const BATCH_SIZE: usize = 32;
let mut batch = Vec::with_capacity(BATCH_SIZE);

for packet in packets {
    batch.push(packet);
    if batch.len() >= BATCH_SIZE {
        process_batch(&batch)?;
        batch.clear();
    }
}

if !batch.is_empty() {
    process_batch(&batch)?;
}
```

#### 3. Zero-Copy Operations
```rust
// Before: Copying data
let data = buffer.to_vec();
send_data(data);

// After: Zero-copy with Bytes
use bytes::Bytes;

let data = Bytes::from(buffer);
send_data(data.clone()); // Cheap clone, no copy
```

### Platform-Specific Optimizations

#### Linux
```rust
// Enable SO_REUSEPORT for better load distribution
socket.set_reuse_port(true)?;

// Use io_uring for async I/O
#[cfg(target_os = "linux")]
use io_uring::{IoUring, SubmissionQueue};

// GSO (Generic Segmentation Offload)
const UDP_SEGMENT: libc::c_int = 103;
setsockopt(sock, SOL_UDP, UDP_SEGMENT, &gso_size)?;
```

#### macOS
```rust
// Use kqueue for better performance
#[cfg(target_os = "macos")]
use mio::Poll;

// Disable Nagle's algorithm
socket.set_nodelay(true)?;
```

#### Windows
```rust
// Use IOCP (I/O Completion Ports)
#[cfg(target_os = "windows")]
use mio::windows::NamedPipe;

// Increase socket buffer sizes
socket.set_recv_buffer_size(2 * 1024 * 1024)?;
socket.set_send_buffer_size(2 * 1024 * 1024)?;
```

## Continuous Performance Testing

### CI Integration

#### GitHub Actions Workflow
```yaml
name: Performance Tests
on:
  push:
    branches: [master]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
      
      - name: Cache dependencies
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            target
          key: ${{ runner.os }}-cargo-bench-${{ hashFiles('**/Cargo.lock') }}
      
      - name: Run benchmarks
        run: |
          cargo bench -- --save-baseline current
          
      - name: Compare with main
        run: |
          git fetch origin main
          git checkout origin/main
          cargo bench -- --save-baseline main
          git checkout -
          cargo bench -- --baseline main
          
      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: benchmark-results
          path: target/criterion
          
      - name: Comment PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const results = fs.readFileSync('comparison.txt', 'utf8');
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: '## Benchmark Results\n\n```\n' + results + '\n```'
            });
```

### Performance Dashboard

Create a Grafana dashboard for continuous monitoring:

```json
{
  "dashboard": {
    "title": "ant-quic Performance",
    "panels": [
      {
        "title": "Throughput",
        "targets": [
          {
            "expr": "rate(quic_throughput_bytes_total[5m])",
            "legendFormat": "Throughput"
          }
        ],
        "yaxis": {
          "format": "Bps"
        }
      },
      {
        "title": "Latency Percentiles",
        "targets": [
          {
            "expr": "histogram_quantile(0.5, rate(quic_latency_seconds_bucket[5m]))",
            "legendFormat": "p50"
          },
          {
            "expr": "histogram_quantile(0.95, rate(quic_latency_seconds_bucket[5m]))",
            "legendFormat": "p95"
          },
          {
            "expr": "histogram_quantile(0.99, rate(quic_latency_seconds_bucket[5m]))",
            "legendFormat": "p99"
          }
        ]
      },
      {
        "title": "NAT Traversal Success Rate",
        "targets": [
          {
            "expr": "rate(nat_traversal_success_total[5m]) / rate(nat_traversal_attempts_total[5m])",
            "legendFormat": "Success Rate"
          }
        ],
        "yaxis": {
          "format": "percentunit"
        }
      }
    ]
  }
}
```

### Alerting on Regressions

```yaml
# prometheus/alerts.yml
groups:
  - name: performance
    rules:
      - alert: ThroughputRegression
        expr: |
          (
            rate(quic_throughput_bytes_total[5m]) < 
            rate(quic_throughput_bytes_total[5m] offset 1d) * 0.9
          )
        for: 30m
        annotations:
          summary: "Throughput decreased by >10% compared to yesterday"
          
      - alert: LatencyRegression
        expr: |
          histogram_quantile(0.99, rate(quic_latency_seconds_bucket[5m])) >
          histogram_quantile(0.99, rate(quic_latency_seconds_bucket[5m] offset 1d)) * 1.2
        for: 30m
        annotations:
          summary: "P99 latency increased by >20% compared to yesterday"
```

## Best Practices

### Benchmarking Best Practices

1. **Consistent Environment**
   - Use dedicated hardware
   - Disable CPU frequency scaling
   - Run with exclusive access
   - Document system configuration

2. **Statistical Significance**
   - Run multiple iterations
   - Use appropriate sample sizes
   - Account for outliers
   - Report confidence intervals

3. **Realistic Workloads**
   - Test with production-like data
   - Simulate real network conditions
   - Include failure scenarios
   - Vary load patterns

4. **Comprehensive Coverage**
   - Test all critical paths
   - Include edge cases
   - Measure resource usage
   - Profile memory allocation

### Performance Culture

1. **Regular Benchmarking**
   - Run benchmarks nightly
   - Track trends over time
   - Alert on regressions
   - Celebrate improvements

2. **Performance Reviews**
   - Include in code reviews
   - Require benchmarks for PRs
   - Document optimization decisions
   - Share learnings

3. **Continuous Improvement**
   - Set performance goals
   - Regular optimization sprints
   - Learn from production metrics
   - Update baselines regularly

## Conclusion

Effective performance benchmarking requires:

- Comprehensive benchmark suites
- Consistent testing environments
- Careful baseline management
- Continuous monitoring
- Proactive optimization

Following this guide ensures ant-quic maintains excellent performance characteristics while identifying and addressing regressions quickly.