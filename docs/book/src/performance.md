# Performance Tuning

This guide covers performance optimization for ant-quic.

## PQC Performance Impact

Post-quantum cryptography adds overhead to handshakes:

### Handshake Sizes

| Phase | Classical | Hybrid PQC | Increase |
|-------|-----------|------------|----------|
| ClientHello | ~300 bytes | ~1,600 bytes | +1,300 |
| ServerHello | ~1,200 bytes | ~5,500 bytes | +4,300 |
| Total Handshake | ~2KB | ~8KB | ~4x |

### Handshake Latency

| Operation | Classical | Hybrid PQC | Impact |
|-----------|-----------|------------|--------|
| Key Generation | 0.1ms | 0.8ms | +700% |
| Key Exchange | 0.2ms | 1.2ms | +500% |
| Signature | 0.1ms | 2.5ms | +2400% |
| Total Handshake | ~0.5ms | ~5ms | ~10x |

**Note**: These overheads only affect connection establishment. Data transfer speed is identical.

### Mitigations

```rust
let pqc = PqcConfig::builder()
    // Use memory pool to reduce allocations
    .memory_pool_size(20)
    // Adjust timeout for PQC overhead
    .handshake_timeout_multiplier(2.0)
    .build()?;
```

## Connection Management

### Maximum Connections

```rust
let config = P2pConfig::builder()
    // Limit concurrent connections
    .max_connections(100)
    // Set idle timeout
    .idle_timeout(Duration::from_secs(60))
    .build()?;
```

### Connection Reuse

Reuse connections instead of creating new ones:

```rust
// Keep connections in a map
let mut connections: HashMap<PeerId, Connection> = HashMap::new();

// Reuse existing connection
if let Some(conn) = connections.get(&peer_id) {
    if !conn.is_closed() {
        return conn.clone();
    }
}

// Create new if needed
let conn = endpoint.connect(addr).await?;
connections.insert(peer_id, conn.clone());
```

## NAT Traversal Tuning

### Candidate Discovery

```rust
let nat = NatConfig {
    // Limit candidates for faster pairing
    max_candidates: 10,

    // Shorter discovery for responsive UX
    discovery_timeout: Duration::from_secs(3),

    // More retries for difficult NATs
    hole_punch_retries: 5,

    ..Default::default()
};
```

### Symmetric NAT

For symmetric NATs, port prediction adds overhead:

```rust
let nat = NatConfig {
    // Enable for symmetric NAT support (slight overhead)
    enable_symmetric_nat: true,

    // More candidates for port prediction
    max_candidates: 15,

    ..Default::default()
};
```

## MTU Configuration

### PQC-Aware MTU

PQC increases handshake packet sizes:

```rust
let mtu = MtuConfig {
    // Conservative initial MTU
    initial: 1200,

    // Minimum for QUIC
    min: 1200,

    // Maximum after path validation
    max: 1500,
};
```

### Networks with Low MTU

```rust
// For VPNs, tunnels, or restrictive networks
let mtu = MtuConfig {
    initial: 1200,
    min: 1200,
    max: 1280, // Conservative max
};
```

## Memory Optimization

### Buffer Pools

```rust
let pqc = PqcConfig::builder()
    // Reuse crypto buffers
    .memory_pool_size(10)
    .build()?;
```

### Connection Limits

```rust
let config = P2pConfig::builder()
    // Limit memory per connection
    .max_connections(50)
    // Close idle connections
    .idle_timeout(Duration::from_secs(30))
    .build()?;
```

## Benchmarking

### Running Benchmarks

```bash
# Run all benchmarks
cargo bench

# Specific benchmark
cargo bench handshake

# With profiling
cargo bench -- --profile-time=10
```

### Custom Benchmarks

```rust
use criterion::{criterion_group, criterion_main, Criterion};

fn benchmark_connection(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("connect", |b| {
        b.iter(|| {
            rt.block_on(async {
                let config = P2pConfig::builder().build().unwrap();
                let endpoint = P2pEndpoint::new(config).await.unwrap();
                // Connect to peer...
            })
        })
    });
}

criterion_group!(benches, benchmark_connection);
criterion_main!(benches);
```

## Profiling

### CPU Profiling

```bash
# With perf
cargo build --release
perf record -g ./target/release/ant-quic
perf report

# With flamegraph
cargo install flamegraph
cargo flamegraph --bin ant-quic
```

### Memory Profiling

```bash
# With valgrind
cargo build --release
valgrind --tool=massif ./target/release/ant-quic

# With heaptrack
heaptrack ./target/release/ant-quic
heaptrack_gui heaptrack.ant-quic.*.gz
```

## Monitoring

### Statistics

```rust
loop {
    tokio::time::sleep(Duration::from_secs(10)).await;

    let stats = endpoint.stats();

    println!("Active connections: {}", stats.active_connections);
    println!("Bytes sent: {}", stats.bytes_sent);
    println!("Bytes received: {}", stats.bytes_received);
    println!("Successful punches: {}", stats.successful_hole_punches);
    println!("Failed punches: {}", stats.failed_hole_punches);
}
```

### Logging for Performance

```bash
# Minimal logging for production
RUST_LOG=warn cargo run --release

# Connection timing
RUST_LOG=ant_quic::connection=info cargo run

# Full debug (impacts performance)
RUST_LOG=ant_quic=debug cargo run
```

## Platform-Specific Optimization

### Linux

```bash
# Increase UDP buffer sizes
sudo sysctl -w net.core.rmem_max=26214400
sudo sysctl -w net.core.wmem_max=26214400
```

### macOS

```bash
# Increase socket buffer sizes
sudo sysctl -w kern.ipc.maxsockbuf=8388608
```

### Windows

Configure via registry:
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters`
- `DefaultReceiveWindow`
- `DefaultSendWindow`

## Best Practices

1. **Reuse connections** - Don't create new connections for each request
2. **Tune timeouts** - Adjust for your network conditions
3. **Monitor statistics** - Track connection success rates
4. **Profile before optimizing** - Measure don't guess
5. **Use release builds** - Debug builds are 10-100x slower

## See Also

- [Configuration](./configuration.md) - Full configuration reference
- [Troubleshooting](./troubleshooting.md) - Common issues
- [Platform Support](./platform-support.md) - Platform details

