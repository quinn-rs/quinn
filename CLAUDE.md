# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ant-quic is a QUIC transport protocol implementation with advanced NAT traversal capabilities, optimized for P2P networks and the Autonomi ecosystem. It extends the proven Quinn QUIC implementation with sophisticated hole-punching protocols to achieve near 100% connectivity through restrictive NATs.

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
```bash
# Main P2P binary (auto-detects coordinator role)
cargo run --bin ant-quic -- --listen 0.0.0.0:9000

# Connect to bootstrap nodes
cargo run --bin ant-quic -- --bootstrap node1.example.com:9000,node2.example.com:9000

# Network simulation testing
cargo run --example nat_simulation

# Other examples
cargo run --example nat_coordinator
cargo run --example nat_p2p_node
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

### Core Components Structure

- **`src/lib.rs`**: Main library exports and QUIC protocol constants
- **`src/endpoint.rs`**: QUIC endpoint management and connection dispatch
- **`src/connection/`**: Connection state management, streams, and protocol logic
- **`src/connection/nat_traversal.rs`**: NAT traversal state and coordination logic
- **`src/nat_traversal_api.rs`**: High-level NAT traversal API for applications
- **`src/candidate_discovery.rs`**: Network interface and address candidate discovery
- **`src/connection_establishment*.rs`**: Connection establishment managers

### NAT Traversal Architecture

The NAT traversal system implements an ICE-like protocol with custom QUIC extension frames:

- **Transport Parameter 0x58**: Negotiates NAT traversal capabilities
- **Extension Frames**:
  - `ADD_ADDRESS` (0xBAAD): Advertise candidate addresses
  - `PUNCH_ME_NOW` (0xBEEF): Coordinate simultaneous hole punching  
  - `REMOVE_ADDRESS` (0xDEAD): Remove invalid candidates
- **Roles**: Client, Server (with relay capability), Bootstrap coordinator
- **Candidate Pairing**: Priority-based ICE-like connection establishment

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
- Core QUIC protocol with NAT traversal extensions
- Transport parameter negotiation and extension frames
- ICE-like candidate pairing with priority calculation
- Multi-path packet transmission and coordination
- Comprehensive test suite with network simulation
- High-level NAT traversal API

### In Progress 🚧
- Platform-specific network interface discovery (Windows IP Helper, Linux Netlink, macOS SCF)
- Real Quinn endpoint integration in high-level API
- Session state machine polling implementation
- Relay connection logic for fallback scenarios

### Known Limitations
- Platform network discovery needs completion for full functionality
- IPv6 dual-stack support requires enhancement
- Performance optimization needed for high-scale deployments
- Relay selection algorithms need real-world testing

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