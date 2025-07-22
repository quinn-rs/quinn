# ant-quic

A QUIC transport protocol implementation with advanced NAT traversal capabilities, optimized for P2P networks and the Autonomi ecosystem.

[![Documentation](https://docs.rs/ant-quic/badge.svg)](https://docs.rs/ant-quic/)
[![Crates.io](https://img.shields.io/crates/v/ant-quic.svg)](https://crates.io/crates/ant-quic)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE-APACHE)
[![Build Status](https://github.com/dirvine/ant-quic/actions/workflows/ci.yml/badge.svg)](https://github.com/dirvine/ant-quic/actions)
[![Release](https://github.com/dirvine/ant-quic/actions/workflows/release.yml/badge.svg)](https://github.com/dirvine/ant-quic/releases)

## Features

- **Advanced NAT Traversal**: ICE-like candidate discovery and coordinated hole punching
- **P2P Optimized**: Designed for peer-to-peer networks with minimal infrastructure
- **High Connectivity**: Near 100% connection success rate through sophisticated NAT handling
- **Autonomi Ready**: Integrated with Autonomi's decentralized networking requirements
- **Built on Quinn**: Leverages the proven Quinn QUIC implementation as foundation
- **Automatic Bootstrap Connection**: Nodes automatically connect to configured bootstrap nodes
- **Production-Ready Binary**: Full-featured `ant-quic` binary for immediate deployment

## Key Capabilities

- **Symmetric NAT Penetration**: Breakthrough restrictive NATs through coordinated hole punching
- **Server Reflexive Discovery**: Automatic detection of external addresses and port mappings
- **Multi-path Connectivity**: Test multiple connection paths simultaneously for reliability
- **Automatic Role Detection**: Nodes dynamically become coordinators when publicly reachable
- **Bootstrap Node Coordination**: Decentralized discovery and coordination services
- **Connection Migration**: Seamless adaptation to changing network conditions
- **Path Validation**: Robust verification of connection paths before use
- **Peer Authentication**: Ed25519-based cryptographic authentication with challenge-response protocol
- **Secure Chat Messaging**: Encrypted peer-to-peer messaging with protocol versioning
- **Real-time Monitoring**: Built-in statistics dashboard for connection and performance metrics

## Quick Start

### Installation

```bash
# Install the binary
cargo install ant-quic

# Or build from source
git clone https://github.com/autonomi/ant-quic
cd ant-quic
cargo build --release
```

### Basic Usage

```bash
# Run as P2P node with QUIC protocol
ant-quic --listen 0.0.0.0:9000

# Connect to bootstrap nodes for peer discovery (automatic connection on startup)
ant-quic --bootstrap node1.example.com:9000,node2.example.com:9000

# Run as coordinator with NAT traversal event monitoring
ant-quic --force-coordinator --listen 0.0.0.0:9000

# Run with dashboard for real-time statistics
ant-quic --dashboard --listen 0.0.0.0:9000

# Run multiple nodes locally for testing
ant-quic --listen 0.0.0.0:9000 # Bootstrap node
ant-quic --listen 0.0.0.0:9001 --bootstrap 127.0.0.1:9000 # Client node

# Check NAT traversal status while running
# Type /status to see discovered addresses and coordination sessions
# Type /help for available commands
```

### How It Works

ant-quic automatically detects its network reachability and adapts its role:

- **Public IP + Reachable**: Becomes full coordinator providing bootstrap services to other nodes
- **Limited Reachability**: Provides limited coordinator services while also acting as client
- **Behind NAT**: Client-only mode, connects to others through NAT traversal

This creates a **decentralized bootstrap network** where any publicly reachable node automatically helps coordinate connections for nodes behind NATs.

### Library Usage

```rust
use ant_quic::{
    nat_traversal_api::{NatTraversalEndpoint, NatTraversalConfig, EndpointRole},
    CandidateSource, NatTraversalRole,
};

// Create NAT traversal endpoint
let config = NatTraversalConfig {
    role: EndpointRole::Client,
    bootstrap_nodes: vec!["bootstrap.example.com:9000".parse().unwrap()],
    max_candidates: 8,
    coordination_timeout: Duration::from_secs(10),
    discovery_timeout: Duration::from_secs(5),
};

let endpoint = NatTraversalEndpoint::new(config).await?;

// Connect to peer through NAT traversal
let peer_id = PeerId([0x12; 32]);
let connection = endpoint.connect_to_peer(peer_id).await?;
```

### Examples

The repository includes several example applications demonstrating various features:

- **[simple_chat](examples/simple_chat.rs)**: Basic P2P chat with authentication
- **[chat_demo](examples/chat_demo.rs)**: Advanced chat with peer discovery and messaging
- **[dashboard_demo](examples/dashboard_demo.rs)**: Real-time connection statistics monitoring

Run examples with:
```bash
cargo run --example simple_chat -- --listen 0.0.0.0:9000
cargo run --example chat_demo -- --bootstrap node1.example.com:9000,node2.example.com:9000
cargo run --example dashboard_demo
```

## Architecture

ant-quic extends the proven Quinn QUIC implementation with sophisticated NAT traversal capabilities:

### Core Components

- **Transport Parameter Extensions**: RFC-style negotiation of NAT traversal capabilities
- **Extension Frames**: Custom QUIC frames for address advertisement and coordination
  - `ADD_ADDRESS` (0xBAAD): Advertise candidate addresses
  - `PUNCH_ME_NOW` (0xBEEF): Coordinate simultaneous hole punching
  - `REMOVE_ADDRESS` (0xDEAD): Remove invalid candidates
- **ICE-like Candidate Pairing**: Priority-based connection establishment
- **Round-based Coordination**: Synchronized hole punching protocol

### NAT Traversal Process

1. **Candidate Discovery**: Enumerate local and server-reflexive addresses
2. **Bootstrap Coordination**: Connect to bootstrap nodes for peer discovery
3. **Address Advertisement**: Exchange candidate addresses with peers
4. **Priority Calculation**: Rank candidate pairs using ICE-like algorithms
5. **Coordinated Hole Punching**: Synchronized transmission to establish connectivity
6. **Path Validation**: Verify connection paths before promoting to active
7. **Connection Migration**: Adapt to network changes and path failures

### Network Topology Support

- **Full Cone NAT**: Direct connection establishment
- **Restricted Cone NAT**: Coordinated hole punching with address filtering
- **Port Restricted NAT**: Port-specific coordination protocols
- **Symmetric NAT**: Advanced prediction and multi-path establishment
- **Carrier Grade NAT (CGNAT)**: Relay-assisted connection fallback

## Specifications

ant-quic implements and extends the following IETF specifications and drafts:

### 1. QUIC Core Specification
- **RFC 9000** – "QUIC: A UDP-Based Multiplexed and Secure Transport"  
  https://datatracker.ietf.org/doc/rfc9000/  
  (Companion RFCs: RFC 9001 for TLS integration and RFC 9002 for loss detection)

### 2. Raw Key Encoding / Key Schedule Used by QUIC
- **RFC 9001** – "Using TLS to Secure QUIC" (see §5 Key Derivation)  
  https://datatracker.ietf.org/doc/rfc9001/  
- **RFC 7250** – "Using Raw Public Keys in TLS/DTLS"  
  https://www.rfc-editor.org/rfc/rfc7250  
  Used for raw public key support instead of X.509 certificates

### 3. QUIC Address Discovery Extension
- **draft-ietf-quic-address-discovery-00** – "QUIC Address Discovery"  
  https://datatracker.ietf.org/doc/draft-ietf-quic-address-discovery-00/  
  Enables endpoints to learn the public IP:port a peer sees for any QUIC path

### 4. Native NAT Traversal for QUIC
- **draft-seemann-quic-nat-traversal-02** – "Using QUIC to traverse NATs"  
  https://datatracker.ietf.org/doc/draft-seemann-quic-nat-traversal/  
  Describes hole-punching and ICE-style techniques directly over QUIC, including new frames such as ADD_ADDRESS and PUNCH_ME_NOW

## Future Work & Roadmap

### Current Implementation Status

✅ **Completed**:
- Core QUIC protocol with NAT traversal extensions
- Transport parameter negotiation (ID 0x58)
- Extension frames (ADD_ADDRESS, PUNCH_ME_NOW, REMOVE_ADDRESS)
- ICE-like candidate pairing with priority calculation
- Multi-path packet transmission
- Round-based coordination protocol
- High-level NAT traversal API with Quinn integration
- Candidate discovery framework
- Connection establishment with fallback
- Comprehensive test suite (580+ tests including auth, chat, and security tests)
- Test binaries: coordinator, P2P node, network simulation
- Automatic bootstrap node connection on startup
- Peer authentication with Ed25519 signatures
- Secure chat protocol with version negotiation
- Real-time monitoring dashboard

🚧 **In Progress/TODO**:
- Platform-specific network interface discovery:
  - Windows: IP Helper API integration
  - Linux: Netlink interface enumeration
  - macOS: System Configuration framework
- Session state machine polling implementation
- Relay connection logic for fallback scenarios

### Roadmap

#### v0.1.0 - Foundation Release ✅
- ✅ Core NAT traversal functionality
- ✅ Basic binary tools
- ✅ Full Quinn endpoint integration
- 🚧 Complete platform-specific interface discovery
- 📋 Performance benchmarking and optimization

#### v0.2.0 - Authentication & Security ✅
- ✅ Peer authentication with Ed25519
- ✅ Secure chat protocol implementation
- ✅ Challenge-response authentication protocol
- ✅ Message versioning and protocol negotiation

#### v0.3.0 - Production Features ✅
- ✅ Real-time monitoring dashboard
- ✅ Automatic bootstrap node connection
- ✅ Comprehensive error handling
- ✅ GitHub Actions for automated releases
- ✅ Binary releases for multiple platforms

#### v0.4.0 - Bootstrap & Connectivity ✅
- ✅ Automatic bootstrap connection on startup
- ✅ Multi-bootstrap node support
- ✅ Connection state management
- ✅ Improved peer ID generation
- 🚧 Platform-specific optimizations

#### v0.5.0 - Advanced Features (Planned)
- 📋 Adaptive retry strategies based on network conditions
- 📋 Advanced relay selection algorithms
- 📋 Protocol optimizations from real-world usage data
- 📋 Enhanced debugging and diagnostic tools
- 📋 Performance profiling and bottleneck analysis

#### v1.0.0 - Autonomi Integration (Future)
- 📋 Native Autonomi network protocol integration
- 📋 Decentralized bootstrap node discovery
- 📋 Enhanced security features for P2P networks
- 📋 Integration with additional discovery mechanisms
- 📋 Production-ready defaults and configurations

### Technical Debt & Improvements

**High Priority (Blocking v0.1.0)**:
- Replace placeholder implementations with real peer ID management
- Implement comprehensive session lifecycle management
- Add adaptive timeout mechanisms based on network conditions
- Complete path validation with sophisticated algorithms

**Medium Priority (v0.2.0)**:
- Enhance connection migration optimization strategies
- Add support for IPv6 dual-stack configurations
- Implement connection quality-based path selection
- Add comprehensive error recovery mechanisms

**Low Priority (v0.3.0+)**:
- Optimize memory usage in high-throughput scenarios
- Add advanced congestion control for P2P networks
- Implement sophisticated relay overlay networks
- Add machine learning-based NAT prediction

### Known Limitations

- Platform-specific interface discovery requires completion for full functionality
- Relay selection algorithms need real-world testing and optimization
- IPv6 support needs enhancement for production deployment
- Performance optimization required for high-scale deployments

## Performance

ant-quic is designed for high-performance P2P networking:

- **Low Latency**: Minimized connection establishment time through parallel candidate testing
- **High Throughput**: Leverages Quinn's optimized QUIC implementation
- **Scalability**: Efficient resource usage for large-scale P2P networks
- **Reliability**: Multiple connection paths and automatic failover

Performance benchmarks will be added in future releases after comprehensive testing across different network scenarios.

## Contributing

Contributions are welcome! Please see our [contributing guidelines](CONTRIBUTING.md) for details.

### Development Setup

```bash
git clone https://github.com/autonomi/ant-quic
cd ant-quic
cargo test --all-features

# Run the QUIC binary
cargo run --bin ant-quic -- --help
```

### Testing

```bash
# Run all tests
cargo test

# Run with verbose output
cargo test -- --nocapture

# Run specific test categories
cargo test nat_traversal
cargo test candidate_discovery
cargo test connection_establishment

# Run benchmarks
cargo bench
```

## License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Acknowledgments

- Built on the excellent [Quinn](https://github.com/quinn-rs/quinn) QUIC implementation
- Implements NAT traversal based on [draft-seemann-quic-nat-traversal-01](https://www.ietf.org/archive/id/draft-seemann-quic-nat-traversal-01.html)
- Inspired by WebRTC ICE protocols and P2P networking research
- Developed for the [Autonomi](https://autonomi.com) decentralized network ecosystem

## Contributors

We are deeply grateful to all our [contributors](CONTRIBUTORS.md) who have helped make this project possible. These true heroes dedicate their time and expertise to help others at their own cost. Thank you for your contributions to open source!

See our [CONTRIBUTORS.md](CONTRIBUTORS.md) file for a full list of amazing people who have contributed to this project.

## Security

For security vulnerabilities, please email security@autonomi.com rather than filing a public issue.
