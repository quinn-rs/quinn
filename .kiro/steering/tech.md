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
  - Uses Quinn's high-level API: `Endpoint`, `Connection`, `SendStream`, `RecvStream`
  - Extends Quinn with NAT traversal while maintaining API compatibility
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
cargo build --features "rustls-aws-lc-rs,network-discovery"

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

## NAT Traversal Protocol
- **QUIC-native NAT traversal only**: Based on [draft-seemann-quic-nat-traversal-01](https://www.ietf.org/archive/id/draft-seemann-quic-nat-traversal-01.html)
- **No STUN or ICE**: We do NOT use STUN, ICE, or any external protocols
- **Pure QUIC extension**: NAT traversal is implemented entirely within QUIC using custom transport parameters and frames
- **Coordinated hole punching**: Uses QUIC-native coordination protocol for symmetric NAT penetration
- **Transport parameter negotiation**: NAT traversal capabilities are negotiated during QUIC handshake

## Feature Flags
- `default`: Includes `rustls-ring`, `log`, `bloom`, `production-ready`
- `production-ready`: Enables full networking stack with DNS resolution
- `bloom`: Enables BloomTokenLog for token management
- `network-discovery`: Enhanced network interface discovery
- `platform-verifier`: Platform-specific certificate verification

## API Design Philosophy
- **Quinn Compatibility**: Maintain consistency with Quinn's high-level API patterns
- **Default Features Focus**: Optimize for default feature compilation and testing
- **Extension Pattern**: Add NAT traversal capabilities as natural extensions to Quinn's API
- **Type Safety**: Use Quinn's existing types (`Endpoint`, `Connection`) for familiarity