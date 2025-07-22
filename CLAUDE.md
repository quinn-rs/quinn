# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ant-quic is a QUIC transport protocol implementation with advanced NAT traversal capabilities, optimized for P2P networks and the Autonomi ecosystem. It extends the proven Quinn QUIC implementation with sophisticated hole-punching protocols to achieve near 100% connectivity through restrictive NATs.

## Project Insights

- This is not a library to integrate with Quinn, it's a fork of Quinn that we are upgrading
- We use Quinn's high-level API patterns (Endpoint, Connection) for consistency
- Focus on default features for compilation and testing

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
cargo run --bin ant-quic -- --bootstrap node1.example.com:9000,node2.example.com:9000

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

# WASM target testing
cargo test --target wasm32-unknown-unknown -p quinn-proto
```

## Architecture Overview

ant-quic has a three-layer architecture:

### Layer 1: Protocol Implementation (Low-Level)
- **`src/endpoint.rs`**: Core QUIC endpoint (forked from Quinn)
- **`src/connection/`**: QUIC connection state machine with NAT traversal extensions
- **`src/frame.rs`**: QUIC frames including NAT traversal extension frames
- **`src/crypto/`**: TLS and Raw Public Key (RFC 7250) implementation

### Layer 2: Integration APIs (High-Level)
- **`src/nat_traversal_api.rs`**: `NatTraversalEndpoint` - High-level NAT traversal API
- **`src/quic_node.rs`**: `QuicP2PNode` - Application-friendly P2P node wrapper
- **`src/quinn_high_level/`**: Async wrapper around low-level Quinn
- **`src/connection_establishment.rs`**: Connection orchestration (needs wiring to actual QUIC)

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

### In Progress 🚧
- Session state machine polling in `nat_traversal_api.rs` (line 2022)
- Connection status checking in `connection_establishment.rs` (line 844)
- Wiring `SimpleConnectionEstablishmentManager` to actual QUIC connections
- Platform-specific network interface discovery (placeholders exist)
- Windows and Linux ARM builds in GitHub Actions (failing)

### Architecture Notes
- Bootstrap "registration" happens automatically via QUIC connections (per spec)
- No STUN/TURN servers - address observation via QUIC extension frames
- Three-layer architecture: Protocol → Integration APIs → Applications

## Development Notes

- **Minimum Rust Version**: 1.74.1
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
```

### Network Simulation
Use `examples/nat_simulation.rs` for testing different network topologies and NAT behaviors in controlled environments.