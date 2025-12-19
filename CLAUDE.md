# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **Related AI Assistant Guides**: See also [AGENTS.md](AGENTS.md) and [GEMINI.md](GEMINI.md) for alternative AI assistant configurations. All guides share the same core project information.

## ⚠️ CRITICAL: Repository Independence

**ant-quic is NOT a fork of Quinn anymore - it's a completely independent project!**

- **NEVER** create PRs to quinn-rs/quinn
- **NEVER** push to any quinn-rs repositories
- **NEVER** add quinn-rs/quinn as an upstream remote
- This repository: github.com/dirvine/ant-quic (standalone project)
- Although GitHub shows it as a fork (legacy), we DO NOT contribute back to Quinn

## Project Overview

ant-quic is a QUIC transport protocol implementation with advanced NAT traversal capabilities, optimized for P2P networks and the Autonomi ecosystem. It extends the proven Quinn QUIC implementation with sophisticated hole-punching protocols to achieve near 100% connectivity through restrictive NATs.

**v0.13.0+: Pure Symmetric P2P Architecture**
- **One Node Type**: All nodes are identical - every node can connect AND accept connections
- **100% PQC Always**: ML-KEM-768 key exchange on every connection, no classical crypto fallback
- **No Roles**: No Client/Server/Bootstrap distinction - all nodes are symmetric peers
- **Known Peers**: Uses `known_peers` terminology instead of "bootstrap nodes"

## Key Technical Decisions

### Authentication: Raw Public Keys (NOT Certificates)

We use **Raw Public Keys (RFC 7250)** instead of X.509 certificates:
- **Reference**: `rfcs/rfc7250.txt` (local copy)
- **Implementation**: Ed25519 key pairs for peer authentication
- **Benefits**: No PKI infrastructure, simpler P2P trust model, smaller handshake
- **No CA dependency**: Peers authenticate directly via public key fingerprints

This is fundamentally different from traditional TLS which uses certificate chains.

### Network: Dual-Stack IPv4 and IPv6 Support

ant-quic supports **both IPv4 and IPv6** addresses:
- Dual-stack socket binding when available
- IPv4-mapped IPv6 addresses handled transparently
- NAT traversal works across both IP versions
- Address candidates can be either IPv4 or IPv6
- QUIC connection migration works across address families

### NAT Traversal: Native QUIC (No External Protocols)

See [NAT Traversal Architecture](#nat-traversal-architecture) below for details on our implementation of the Seemann draft specification. We do NOT use STUN, ICE, or TURN.

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

# Run all tests (comprehensive suite with 580+ tests)
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
# Run the QUIC P2P binary (v0.13.0+: all nodes are symmetric)
cargo run --bin ant-quic -- --listen 0.0.0.0:9000

# Connect to known peers (v0.13.0+: no "bootstrap" distinction)
cargo run --bin ant-quic -- --connect quic.saorsalabs.com:9000

# Run with monitoring dashboard
cargo run --bin ant-quic -- --dashboard --listen 0.0.0.0:9000
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
```

**Note:** WASM is not supported. ant-quic uses raw UDP sockets and NAT traversal which are incompatible with the browser sandbox environment.

## Architecture Overview

ant-quic has a three-layer architecture:

### Layer 1: Protocol Implementation (Low-Level)
- **`src/endpoint.rs`**: Core QUIC endpoint (forked from Quinn)
- **`src/connection/`**: QUIC connection state machine with NAT traversal extensions
- **`src/frame.rs`**: QUIC frames including NAT traversal extension frames
- **`src/crypto/`**: TLS 1.3 with Raw Public Keys (RFC 7250) - **NO X.509 CERTIFICATES**

### Layer 2: Integration APIs (High-Level)
- **`src/nat_traversal_api.rs`**: `NatTraversalEndpoint` - High-level NAT traversal API with working poll() state machine
- **`src/quic_node.rs`**: `QuicP2PNode` - Application-friendly P2P node wrapper
- **`src/high_level/`**: Evolved fork of Quinn's async API (NOT external Quinn - this is ant-quic's own implementation)

### Layer 3: Applications (Binaries)
- **`src/bin/ant-quic.rs`**: Main QUIC P2P binary using `QuicP2PNode`
- **`examples/`**: Demo applications showing various use cases

### NAT Traversal Architecture

**CRITICAL: Native QUIC NAT Traversal - NO STUN, NO ICE, NO TURN**

This implementation uses **native QUIC protocol extensions** based on the Seemann draft specification:
- **Reference**: `rfcs/draft-seemann-quic-nat-traversal-02.txt` (local copy)
- **Specification**: [draft-seemann-quic-nat-traversal](https://datatracker.ietf.org/doc/draft-seemann-quic-nat-traversal/)

We do **NOT** use:
- ❌ STUN (Session Traversal Utilities for NAT)
- ❌ ICE (Interactive Connectivity Establishment)
- ❌ TURN (Traversal Using Relays around NAT)
- ❌ External NAT traversal servers

Instead, all NAT traversal is performed **natively within QUIC** using extension frames and transport parameters.

The NAT traversal system implements the IETF QUIC NAT traversal draft with custom extension frames:

- **Transport Parameters**:
  - `0x3d7e9f0bca12fea6`: NAT traversal capability negotiation
  - `0x3d7e9f0bca12fea8`: RFC-compliant frame format
  - `0x9f81a176`: Address discovery configuration
- **Extension Frames**:
  - `ADD_ADDRESS` (0x3d7e90-91): Advertise candidate addresses
  - `PUNCH_ME_NOW` (0x3d7e92-93): Coordinate simultaneous hole punching
  - `REMOVE_ADDRESS` (0x3d7e94)`: Remove invalid candidates
  - `OBSERVED_ADDRESS` (0x9f81a6-a7): Report observed external address
- **Symmetric P2P** (v0.13.0+): All nodes have equal capabilities - can connect, accept, and coordinate
- **Candidate Pairing**: Priority-based connection establishment

#### Address Discovery (No STUN Required)

v0.13.0+: All nodes are symmetric peers - any node can observe and report addresses.

Unlike traditional NAT traversal, we discover addresses through:

1. **Local Interface Enumeration**: Discover local IP addresses directly
2. **Peer Address Observation**: Any connected peer can observe and report your external address via OBSERVED_ADDRESS frames
3. **Symmetric NAT Prediction**: Predict likely external ports for symmetric NATs
4. **Peer Exchange**: Learn addresses from successful connections

Known peers (specified via `known_peers` config) act as **initial connection targets**, but any connected peer can:
- Observe your public address:port
- Report this information via OBSERVED_ADDRESS frames
- Coordinate hole punching timing via PUNCH_ME_NOW frames
- All communication happens over existing QUIC connections

### Key Data Flow

1. **Discovery**: Enumerate local addresses and learn external addresses from connected peers
2. **Advertisement**: Exchange candidate addresses using extension frames
3. **Coordination**: Synchronized hole punching through any connected peer
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
- **Multi-platform**: Unix, Windows, macOS, Android targets (WASM not supported)

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

### NAT Traversal Patterns (v0.13.0+)
- **Symmetric Nodes**: All nodes have equal capabilities - no roles needed
- **Known Peers**: Configure initial peers via `known_peers` in config
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
- **Native QUIC NAT traversal** per `draft-seemann-quic-nat-traversal-02` (NO STUN/ICE/TURN)
- Transport parameter negotiation (0x3d7e9f0bca12fea6+) and extension frames
- NAT traversal frames: ADD_ADDRESS (0x3d7e90-91), PUNCH_ME_NOW (0x3d7e92-93), REMOVE_ADDRESS (0x3d7e94)
- Priority-based candidate pairing (inspired by ICE, but native QUIC implementation)
- **Raw Public Keys (RFC 7250)** with Ed25519 - NO X.509 certificates
- **Dual-stack IPv4/IPv6** support with transparent address handling
- High-level APIs: `QuicP2PNode` and `NatTraversalEndpoint`
- Production binary `ant-quic` with full QUIC implementation
- Comprehensive test suite (580+ tests)
- Automatic connection to known peers on startup (v0.4.1+)
- Peer authentication with Ed25519 signatures
- Secure chat protocol with message versioning
- Real-time monitoring dashboard
- GitHub Actions for automated releases
- Multi-platform binary releases
- Platform-specific network interface discovery (Windows, Linux, macOS)
- QUIC Address Discovery Extension (draft-ietf-quic-address-discovery-00)
- OBSERVED_ADDRESS frame (0x9f81a6-a7) implementation
- Transport parameter 0x9f81a176 for address discovery configuration
- Post-Quantum Cryptography (v0.5.0) with ML-KEM-768 and ML-DSA-65
- 100% Post-Quantum Cryptography (v0.13.0+): ML-KEM-768 on every connection
- CI Consolidated workflow passing (v0.10.4)

### In Progress 🚧
- Session state machine polling in `nat_traversal_api.rs` (line 2022)
- Cross-platform builds for ARM targets

### Architecture Notes (v0.13.0+)
- **Symmetric P2P**: All nodes are equal - can connect, accept, and coordinate NAT traversal
- **100% PQC**: ML-KEM-768 key exchange on every connection, no classical fallback
- **Native QUIC NAT traversal**: All hole-punching via QUIC extension frames, NO external protocols
- **Raw Public Keys**: Authentication via Ed25519 key pairs, NO X.509 certificate chains
- **Dual-stack networking**: Full IPv4 and IPv6 support with transparent handling
- Address discovery via connected peers (per draft-ietf-quic-address-discovery-00)
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

## Reference Specifications (rfcs/ directory)

Local copies of all relevant specifications are in the `rfcs/` directory:

### Core Protocol
- `rfc9000.txt` - QUIC: A UDP-Based Multiplexed and Secure Transport
- `rfc7250.txt` - **Raw Public Keys in TLS** (our authentication method)

### NAT Traversal (Native QUIC - NO STUN/ICE)
- `draft-seemann-quic-nat-traversal-02.txt` - **QUIC NAT Traversal** (primary specification)
- `draft-ietf-quic-address-discovery-00.txt` - QUIC Address Discovery Extension

### Post-Quantum Cryptography
- `fips-203-ml-kem.pdf` - ML-KEM (Kyber) key encapsulation
- `fips-204-ml-dsa.pdf` - ML-DSA (Dilithium) digital signatures
- `draft-ietf-tls-hybrid-design-14.txt` - Hybrid key exchange design
- `draft-ietf-tls-mlkem-04.txt` - ML-KEM in TLS 1.3

---

## AI Assistant Guide Synchronization

This project maintains three AI assistant configuration files that should be kept in sync:

| File | Purpose |
|------|---------|
| [CLAUDE.md](CLAUDE.md) | Claude Code (Anthropic) - this file |
| [AGENTS.md](AGENTS.md) | Generic AI coding assistants |
| [GEMINI.md](GEMINI.md) | Google Gemini |

**When updating any of these files, ensure the core technical information remains consistent across all three.**

Key shared information that must stay synchronized:
- Repository independence (not a Quinn fork for contributions)
- Native QUIC NAT traversal (NO STUN/ICE/TURN)
- Raw Public Keys (RFC 7250) - NO certificates
- IPv4 and IPv6 dual-stack support
- Development commands and code conventions
- Architecture overview and key file locations
