# Technology Stack

## Language & Edition
- **Rust 2021 Edition** (minimum version 1.74.1)
- Uses modern Rust features and async/await patterns

## Build System
- **Cargo** with workspace configuration
- Custom feature flags for different crypto providers and optional components
- Platform-specific dependencies for Windows, Linux, and macOS

## Core Dependencies
- **Quinn**: Foundation QUIC implementation
- **Tokio**: Async runtime and networking
- **Rustls**: TLS implementation with multiple crypto provider options
- **Tracing**: Structured logging and instrumentation
- **Serde**: Serialization for configuration and protocol messages

## Crypto Providers
- **Ring**: Default crypto provider (`rustls-ring` feature)
- **AWS-LC-RS**: Alternative crypto provider (`rustls-aws-lc-rs` feature)
- **FIPS compliance**: Available via `aws-lc-rs-fips` feature

## Platform-Specific Libraries
- **Windows**: Windows API for network interface discovery
- **Linux**: Netlink for network interface enumeration
- **macOS**: System Configuration framework for network discovery

## Common Commands

### Building
```bash
# Standard build
cargo build

# Release build
cargo build --release

# Build with specific features
cargo build --features "rustls-aws-lc-rs,stun"

# Build all binaries
cargo build --bins
```

### Testing
```bash
# Run all tests
cargo test

# Run tests with all features
cargo test --all-features

# Run specific test categories
cargo test nat_traversal
cargo test candidate_discovery

# Run with verbose output
cargo test -- --nocapture
```

### Running
```bash
# Run main binary
cargo run --bin ant-quic -- --help

# Run as P2P node
cargo run --bin ant-quic -- --listen 0.0.0.0:9000

# Run with bootstrap nodes
cargo run --bin ant-quic -- --bootstrap node1.example.com:9000
```

### Benchmarking
```bash
# Run all benchmarks
cargo bench

# Run specific benchmark
cargo bench relay_queue
cargo bench candidate_discovery
```

### Code Quality
```bash
# Format code
cargo fmt

# Check with clippy
cargo clippy --all-targets --all-features

# Security audit
cargo deny check
```

## Feature Flags
- `default`: Includes `rustls-ring`, `log`, `bloom`, `production-ready`
- `production-ready`: Enables full networking stack with DNS resolution
- `bloom`: Enables BloomTokenLog for token management
- `stun`: STUN protocol support for NAT traversal
- `network-discovery`: Enhanced network interface discovery
- `platform-verifier`: Platform-specific certificate verification