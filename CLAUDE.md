# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## ⚠️ CRITICAL: Repository Independence

**ant-quic is NOT a fork of Quinn anymore - it's a completely independent project!**

- **NEVER** create PRs to quinn-rs/quinn
- **NEVER** push to any quinn-rs repositories
- **NEVER** add quinn-rs/quinn as an upstream remote
- This repository: github.com/dirvine/ant-quic (standalone project)
- Although GitHub shows it as a fork (legacy), we DO NOT contribute back to Quinn

## Project Overview

ant-quic is a QUIC transport protocol implementation with advanced NAT traversal capabilities, optimized for P2P networks and the Autonomi ecosystem. It extends the proven Quinn QUIC implementation with sophisticated hole-punching protocols to achieve near 100% connectivity through restrictive NATs.

## Project Insights

- This started as a fork of Quinn but has diverged completely into an independent project
- We use Quinn's high-level API patterns (Endpoint, Connection) for consistency
- Focus on default features for compilation and testing
- Post-Quantum Cryptography (PQC) support with ML-KEM-768 and ML-DSA-65

## Development Commands

### Building and Testing
```bash
# Build the project
cargo build --release

# Run all tests (comprehensive suite with 266+ tests)
cargo test

# Run tests with output (useful for debugging)
cargo test -- --nocapture

# Run stress tests (normally ignored)
cargo test -- --ignored stress

# Quick compilation check
cargo check --all-targets

# Run specific test categories
cargo test nat_traversal
cargo test candidate_discovery
cargo test connection_establishment
```

### Code Quality
```bash
# Format code (required before commits)
cargo fmt --all

# Lint with clippy (fix warnings before commits)
cargo clippy --all-targets -- -D warnings

# Check code formatting
cargo fmt --all -- --check
```

### Running Examples and Binaries

#### Main QUIC Binary
```bash
# Run the QUIC P2P binary
cargo run --bin ant-quic -- --listen 0.0.0.0:9000

# Connect to bootstrap nodes
cargo run --bin ant-quic -- --bootstrap quic.saorsalabs.com:9000

# Run with monitoring dashboard
cargo run --bin ant-quic -- --dashboard --listen 0.0.0.0:9000

# Force coordinator mode
cargo run --bin ant-quic -- --force-coordinator --listen 0.0.0.0:9000
```

#### Examples
```bash
# Chat demo with QUIC
cargo run --example chat_demo

# Simple chat example
cargo run --example simple_chat

# Dashboard demo
cargo run --example dashboard_demo
```

### Feature Testing
```bash
# Test different crypto providers
cargo test --no-default-features --features rustls-ring
cargo test --no-default-features --features rustls-aws-lc-rs

# Test with PQC features
cargo test --features "pqc aws-lc-rs"
cargo build --features "pqc aws-lc-rs" --all-targets

# WASM target testing (quinn-proto is not a separate package anymore)
cargo test --target wasm32-unknown-unknown
```

## Architecture Overview

ant-quic has a three-layer architecture:

### Layer 1: Protocol Implementation (Low-Level)
- **`src/endpoint.rs`**: Core QUIC endpoint (forked from Quinn)
- **`src/connection/`**: QUIC connection state machine with NAT traversal extensions
- **`src/frame.rs`**: QUIC frames including NAT traversal extension frames
- **`src/crypto/`**: TLS and Raw Public Key (RFC 7250) implementation

### Layer 2: Integration APIs (High-Level)
- **`src/nat_traversal_api.rs`**: `NatTraversalEndpoint` - High-level NAT traversal API with working poll() state machine
- **`src/quic_node.rs`**: `QuicP2PNode` - Application-friendly P2P node wrapper
- **`src/high_level/`**: Evolved fork of Quinn's async API (NOT external Quinn - this is ant-quic's own implementation)

### Layer 3: Applications (Binaries)
- **`src/bin/ant-quic.rs`**: Main QUIC P2P binary using `QuicP2PNode`
- **`examples/`**: Demo applications showing various use cases

### NAT Traversal Architecture

**IMPORTANT: This implementation uses QUIC protocol extensions (draft-seemann-quic-nat-traversal-01), NOT STUN/TURN protocols.**

The NAT traversal system implements the IETF QUIC NAT traversal draft with custom extension frames:

- **Transport Parameter 0x58**: Negotiates NAT traversal capabilities
- **Extension Frames**:
  - `ADD_ADDRESS` (0x40): Advertise candidate addresses
  - `PUNCH_ME_NOW` (0x41): Coordinate simultaneous hole punching
  - `REMOVE_ADDRESS` (0x42): Remove invalid candidates
- **Roles**: Client, Server (with relay capability), Bootstrap coordinator
- **Candidate Pairing**: Priority-based ICE-like connection establishment

#### Address Discovery (No STUN Required)

Unlike traditional NAT traversal, we discover addresses through:

1. **Local Interface Enumeration**: Discover local IP addresses directly
2. **Bootstrap Node Observation**: Bootstrap nodes observe the source address of incoming QUIC connections and inform clients via ADD_ADDRESS frames
3. **Symmetric NAT Prediction**: Predict likely external ports for symmetric NATs
4. **Peer Exchange**: Learn addresses from successful connections

Bootstrap nodes act as **address observers and coordinators**, not STUN servers. They:
- Observe the public address:port of connecting clients
- Send this information back via ADD_ADDRESS frames
- Coordinate hole punching timing via PUNCH_ME_NOW frames
- All communication happens over existing QUIC connections

### Key Data Flow

1. **Discovery**: Enumerate local and server-reflexive addresses via bootstrap nodes
2. **Advertisement**: Exchange candidate addresses using extension frames
3. **Coordination**: Synchronized hole punching through bootstrap coordinators
4. **Validation**: Test candidate pairs and promote successful paths
5. **Migration**: Adapt to network changes and maintain connectivity

## Testing Infrastructure

### Test Organization
- **Unit Tests**: Embedded in source files with `#[cfg(test)]` modules
- **Integration Tests**: `tests/nat_traversal_comprehensive.rs` (comprehensive NAT simulation)
- **Test Utilities**: `src/tests/util.rs` with network simulation helpers
- **Examples**: Functional test binaries in `examples/`

### Test Patterns
- **Pair Testing**: Simulated client-server pairs with controllable network conditions
- **NAT Simulation**: Multiple NAT types (Full Cone, Symmetric, Port Restricted, CGNAT)
- **Network Conditions**: MTU, latency, packet loss, congestion simulation
- **Multi-platform**: Unix, Windows, macOS, Android, WASM targets

### Running Tests
```bash
# Comprehensive test suite
cargo test --locked

# Specific test modules
cargo test range_set
cargo test transport_parameters
cargo test connection::nat_traversal

# Integration tests only
cargo test --test nat_traversal_comprehensive

# Run security validation tests
cargo test --test address_discovery_security

# Run PQC tests
cargo test pqc
cargo test ml_kem
cargo test ml_dsa

# Run stress tests (normally ignored)
cargo test -- --ignored stress
```

## Code Conventions

### Error Handling
- Use `Result<T, E>` types throughout (no `unwrap()` in production)
- Custom error types with `thiserror` derive
- Proper error propagation with `?` operator

### NAT Traversal Patterns
- **Roles**: Use `NatTraversalRole` enum for endpoint behavior
- **Candidates**: `CandidateAddress` with priority and source tracking
- **Coordination**: Round-based protocol with timeouts
- **Statistics**: Comprehensive metrics via `NatTraversalStatistics`

### Module Structure
- Connection-level state in `connection/nat_traversal.rs`
- High-level API in `nat_traversal_api.rs`
- Discovery logic in `candidate_discovery.rs`
- Shared types and utilities throughout

## Current Development Status

### Completed ✅
- Core QUIC protocol with NAT traversal extensions (forked from Quinn)
- Transport parameter negotiation (ID 0x58) and extension frames
- NAT traversal frames: ADD_ADDRESS (0x40), PUNCH_ME_NOW (0x41), REMOVE_ADDRESS (0x42)
- ICE-like candidate pairing with priority calculation
- Raw Public Keys (RFC 7250) implementation with Ed25519
- High-level APIs: `QuicP2PNode` and `NatTraversalEndpoint`
- Production binary `ant-quic` with full QUIC implementation
- Comprehensive test suite (580+ tests)
- Automatic bootstrap node connection on startup (v0.4.1)
- Peer authentication with Ed25519 signatures
- Secure chat protocol with message versioning
- Real-time monitoring dashboard
- GitHub Actions for automated releases
- Multi-platform binary releases
- Platform-specific network interface discovery (Windows, Linux, macOS)
- QUIC Address Discovery Extension (draft-ietf-quic-address-discovery-00)
- OBSERVED_ADDRESS frame (0x43) implementation
- Transport parameter 0x1f00 for address discovery configuration
- Post-Quantum Cryptography (v0.5.0) with ML-KEM-768 and ML-DSA-65
- Hybrid (classical + PQC) and pure PQC modes

### In Progress 🚧
- Session state machine polling in `nat_traversal_api.rs` (line 2022)
- Windows and Linux ARM builds in GitHub Actions (failing)

### Architecture Notes
- Bootstrap "registration" happens automatically via QUIC connections (per spec)
- No STUN/TURN servers - address observation via QUIC extension frames
- Three-layer architecture: Protocol → Integration APIs → Applications
- **IMPORTANT**: The `high_level` module is ant-quic's evolved fork of Quinn's async API, not an external dependency
- NAT traversal is fully functional through the `poll()` state machine in `nat_traversal_api.rs`

## Development Notes

- **Minimum Rust Version**: 1.85.0
- **Rust Edition**: 2024 (enhanced async syntax and performance)
- **Primary Dependencies**: Quinn, tokio, rustls, ring/aws-lc-rs
- **License**: Dual MIT/Apache-2.0
- **Target**: P2P networking for Autonomi ecosystem
- **Focus**: Maximum connectivity through NAT traversal rather than raw performance

## Debugging and Diagnostics

### Logging
```bash
# Enable verbose NAT traversal logging
RUST_LOG=ant_quic::nat_traversal=debug cargo run --bin ant-quic

# Connection-level debugging
RUST_LOG=ant_quic::connection=trace cargo test -- --nocapture

# Full debugging
RUST_LOG=debug cargo run --example nat_simulation

# PQC-specific debugging
RUST_LOG=ant_quic::crypto::pqc=debug cargo run --bin ant-quic
```

### Network Simulation
Use `examples/nat_simulation.rs` for testing different network topologies and NAT behaviors in controlled environments.

### Validation Scripts
```bash
# Security validation
./scripts/security-validation.sh

# PQC security validation
./scripts/pqc-security-validation.sh

# PQC release validation
./scripts/pqc-release-validation.sh

# Test discovery endpoints
./scripts/test-do-bootstrap.sh
```

## Key File Locations

- **Main Library**: `src/lib.rs` - Entry point, exports all public APIs
- **NAT Traversal API**: `src/nat_traversal_api.rs` - High-level NAT traversal endpoint
- **QUIC Node**: `src/quic_node.rs` - P2P node implementation
- **Connection Logic**: `src/connection_establishment.rs` - Connection orchestration
- **PQC Implementation**: `src/crypto/pqc/` - Post-quantum crypto modules
- **Binary**: `src/bin/ant-quic.rs` - Main executable with CLI
- **Config**: `Cargo.toml` - Feature flags, dependencies, build configuration
