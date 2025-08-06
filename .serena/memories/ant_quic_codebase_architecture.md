# Ant-QUIC Codebase Architecture Overview

## Project Overview
ant-quic is a QUIC transport protocol implementation with advanced NAT traversal capabilities, forked from Quinn. It implements RFC-compliant QUIC with custom NAT traversal extensions for P2P networking, particularly optimized for the Autonomi ecosystem.

## Key Features
- Post-Quantum Cryptography (PQC) support with ML-KEM-768 and ML-DSA-65
- Advanced NAT traversal using QUIC protocol extensions (not STUN/TURN)
- Raw Public Keys (RFC 7250) implementation with Ed25519
- High-level P2P APIs built on Quinn's foundations
- Comprehensive testing suite (580+ tests)

## Core Architecture (Three Layers)

### Layer 1: Protocol Implementation (Low-Level QUIC)
- **`src/endpoint.rs`**: Core QUIC endpoint (forked from Quinn) with relay capabilities
- **`src/connection/`**: QUIC connection state machine with NAT traversal extensions
- **`src/frame.rs`**: QUIC frames including NAT traversal extension frames
- **`src/crypto/`**: TLS, Raw Public Keys, and Post-Quantum Cryptography
- **`src/transport*.rs`**: Transport parameters and protocol handling

### Layer 2: Integration APIs (High-Level)
- **`src/nat_traversal_api.rs`**: `NatTraversalEndpoint` - High-level NAT traversal API
- **`src/quic_node.rs`**: `QuicP2PNode` - Application-friendly P2P node wrapper
- **`src/connection_establishment.rs`**: Connection orchestration manager
- **`src/candidate_discovery.rs`**: Address discovery and candidate management

### Layer 3: Applications (Binaries & Examples)
- **`src/bin/ant-quic.rs`**: Main QUIC P2P binary using `QuicP2PNode`
- **`examples/`**: Demo applications (chat, dashboard, PQC demos)

## Core Modules & Files

### Primary Entry Points
- **`src/lib.rs`**: Main library entry, exports all public APIs
- **`src/endpoint.rs`**: Core QUIC endpoint with relay queue and address discovery
- **`src/nat_traversal_api.rs`**: High-level NAT traversal endpoint
- **`src/quic_node.rs`**: P2P node implementation for applications

### NAT Traversal System
- **`src/nat_traversal/`**: NAT traversal implementation
  - `mod.rs`: Core NAT traversal logic
  - `frames.rs`: Extension frames (ADD_ADDRESS, PUNCH_ME_NOW, etc.)
  - `state_machine.rs`: NAT traversal state management
  - `hole_punching.rs`: Coordinated hole punching protocol
  - `bootstrap.rs`: Bootstrap node functionality
- **`src/candidate_discovery.rs`**: Address discovery and candidate management
- **`src/connection_establishment.rs`**: Connection orchestration

### Cryptography
- **`src/crypto/`**: Cryptographic implementations
  - `rustls.rs`: Rustls integration
  - `raw_public_keys.rs`: RFC 7250 Raw Public Keys implementation
  - `pqc/`: Post-Quantum Cryptography modules
    - `ml_kem.rs` & `ml_kem_impl.rs`: ML-KEM-768 implementation
    - `ml_dsa.rs` & `ml_dsa_impl.rs`: ML-DSA-65 implementation
    - `hybrid.rs`: Hybrid (classical + PQC) cryptography
    - `tls_integration.rs`: PQC TLS integration

### Quinn Core (Forked)
- **`src/frame.rs`**: QUIC frames with NAT traversal extensions
- **`src/connection/`**: Connection state machine
- **`src/transport_parameters.rs`**: Transport parameters including NAT traversal (0x58)
- **`src/congestion.rs`**: Congestion control
- **`src/packet.rs`**: Packet handling

### High-Level APIs
- **`src/api/`**: Public API definitions
- **`src/high_level/`**: Async wrappers around low-level Quinn
- **`src/auth.rs`**: Authentication and peer verification
- **`src/chat.rs`**: Secure chat protocol implementation

### Testing Infrastructure
- **`tests/`**: Comprehensive test suite (580+ tests)
  - NAT traversal simulation tests
  - PQC integration tests  
  - Platform compatibility tests
  - Security validation tests
  - Integration and end-to-end tests
- **`src/tests/`**: Test utilities and helpers

## NAT Traversal Architecture

The NAT traversal system implements IETF QUIC NAT traversal draft (draft-seemann-quic-nat-traversal-01):

### Extension Frames
- **Transport Parameter 0x58**: Negotiates NAT traversal capabilities
- **ADD_ADDRESS (0x40)**: Advertise candidate addresses
- **PUNCH_ME_NOW (0x41)**: Coordinate simultaneous hole punching
- **REMOVE_ADDRESS (0x42)**: Remove invalid candidates
- **OBSERVED_ADDRESS (0x43)**: Address observation (draft-ietf-quic-address-discovery-00)

### Address Discovery Process
1. **Local Interface Enumeration**: Direct IP address discovery
2. **Bootstrap Node Observation**: Bootstrap nodes observe source addresses
3. **Symmetric NAT Prediction**: Predict external ports
4. **Peer Exchange**: Learn addresses from successful connections

### Roles & Coordination
- **Client**: Initiates connections, performs hole punching
- **Server**: Accepts connections, can relay for coordination
- **Bootstrap**: Coordinates hole punching, observes addresses

## Key Data Structures

### NAT Traversal
- `NatTraversalEndpoint`: High-level NAT traversal API
- `CandidateAddress`: Address candidates with priority
- `NatTraversalSession`: Session state management
- `BootstrapNode`: Bootstrap node configuration

### QUIC Core
- `Endpoint`: Core QUIC endpoint with relay capabilities
- `Connection`: QUIC connection with NAT extensions
- `QuicP2PNode`: Application-friendly P2P wrapper

### Cryptography
- `PqcConfig`: Post-quantum crypto configuration
- `MlKem768`: ML-KEM-768 key encapsulation
- `MlDsa65`: ML-DSA-65 digital signatures
- `HybridKeyExchange`: Classical + PQC hybrid mode

## Build & Test Configuration

### Feature Flags (Cargo.toml)
- `pqc`: Enable Post-Quantum Cryptography
- `rustls-ring`: Use ring crypto provider
- `rustls-aws-lc-rs`: Use AWS-LC crypto provider
- `platform-verifier`: Platform-specific certificate verification

### Build Commands
- `cargo build --release`: Production build
- `cargo test`: Run all tests
- `cargo test --features "pqc aws-lc-rs"`: Test with PQC
- `cargo clippy -- -D warnings`: Lint checks

## File Organization Patterns

### Module Structure
- Each major component has its own module directory
- Core Quinn components at `src/` root level
- Extensions in `src/nat_traversal/`, `src/crypto/`, etc.
- High-level APIs in dedicated modules

### Test Organization
- Unit tests embedded with `#[cfg(test)]`
- Integration tests in `tests/` directory
- Organized by functionality (NAT, PQC, auth, etc.)
- Platform-specific tests in subdirectories

### Documentation
- Extensive README with usage examples
- RFC compliance documentation
- Performance and security reports
- Architecture decision records

## Development Status
- ✅ Core QUIC with NAT traversal extensions
- ✅ Post-Quantum Cryptography (ML-KEM-768, ML-DSA-65)
- ✅ Raw Public Keys (RFC 7250)
- ✅ Production binary with P2P capabilities
- ✅ Comprehensive test suite (580+ tests)
- 🚧 Connection establishment wiring to actual QUIC
- 🚧 Session state machine polling optimization