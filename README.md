# ant-quic

**Pure Post-Quantum QUIC** transport with NAT traversal for P2P networks. Every node is symmetric - can connect AND accept connections.

[![Documentation](https://docs.rs/ant-quic/badge.svg)](https://docs.rs/ant-quic/)
[![Crates.io](https://img.shields.io/crates/v/ant-quic.svg)](https://crates.io/crates/ant-quic)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE-APACHE)

[![CI Status](https://github.com/dirvine/ant-quic/actions/workflows/quick-checks.yml/badge.svg)](https://github.com/dirvine/ant-quic/actions/workflows/quick-checks.yml)
[![Build Status](https://github.com/dirvine/ant-quic/actions/workflows/ci-consolidated.yml/badge.svg)](https://github.com/dirvine/ant-quic/actions/workflows/ci-consolidated.yml)
[![Security Audit](https://github.com/dirvine/ant-quic/actions/workflows/security.yml/badge.svg)](https://github.com/dirvine/ant-quic/actions/workflows/security.yml)

## Key Features

- **🔐 Pure Post-Quantum Cryptography (v0.2)** - ML-KEM-768 + ML-DSA-65 ONLY - no classical fallback
- **Symmetric P2P Nodes** - Every node is identical: connect, accept, coordinate
- **Automatic NAT Traversal** - Per [draft-seemann-quic-nat-traversal-02](rfcs/draft-seemann-quic-nat-traversal-02.txt)
- **External Address Discovery** - Per [draft-ietf-quic-address-discovery-00](rfcs/draft-ietf-quic-address-discovery-00.txt)
- **Pure PQC Raw Public Keys** - ML-DSA-65 authentication per [our specification](rfcs/ant-quic-pqc-authentication.md)
- **Zero Configuration Required** - Sensible defaults, just create and connect
- **Powered by [saorsa-pqc](https://crates.io/crates/saorsa-pqc)** - NIST FIPS 203/204 compliant implementations

## Quick Start

```rust
use ant_quic::{P2pEndpoint, P2pConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create a P2P endpoint - PQC is always on
    let config = P2pConfig::builder()
        .known_peer("peer.example.com:9000".parse()?)
        .build()?;

    let endpoint = P2pEndpoint::new(config).await?;
    println!("Peer ID: {:?}", endpoint.peer_id());

    // Connect to known peers for address discovery
    endpoint.connect_bootstrap().await?;

    // Your external address is now known
    if let Some(addr) = endpoint.external_address() {
        println!("External address: {}", addr);
    }

    Ok(())
}
```

## Architecture

ant-quic uses a **symmetric P2P model** where every node has identical capabilities:

```
┌─────────────┐         ┌─────────────┐
│   Node A    │◄───────►│   Node B    │
│  (peer)     │   QUIC  │  (peer)     │
│             │   PQC   │             │
└─────────────┘         └─────────────┘
       │                       │
       │    OBSERVED_ADDRESS   │
       │◄──────────────────────┤
       │                       │
       ├──────────────────────►│
       │    ADD_ADDRESS        │
       └───────────────────────┘
```

### No Roles - All Nodes Are Equal

In v0.13.0, we removed all role distinctions:
- No `EndpointRole::Client/Server/Bootstrap`
- No `NatTraversalRole` enum
- **Any peer can coordinate** NAT traversal for other peers
- **Any peer can report** your external address via OBSERVED_ADDRESS frames

The term "known_peers" replaces "bootstrap_nodes" - they're just addresses to connect to first. Any connected peer can help with address discovery.

### Three-Layer Design

1. **Protocol Layer**: QUIC + NAT traversal extension frames
2. **Integration APIs**: `P2pEndpoint`, `P2pConfig`
3. **Applications**: Binary, examples

## Pure Post-Quantum Cryptography (v0.2)

**ant-quic v0.2 uses PURE post-quantum cryptography** - no classical algorithms, no hybrid modes, no fallback.

This is a greenfield network with no legacy compatibility requirements.

### Algorithms

| Algorithm | Standard | Purpose | Security Level | IANA Code |
|-----------|----------|---------|----------------|-----------|
| **ML-KEM-768** | FIPS 203 | Key Exchange | NIST Level 3 (192-bit) | 0x0201 |
| **ML-DSA-65** | FIPS 204 | Digital Signatures | NIST Level 3 (192-bit) | 0x0905 |

### Powered by saorsa-pqc

ant-quic uses [saorsa-pqc](https://crates.io/crates/saorsa-pqc) for all PQC operations:

- **NIST FIPS 203/204 compliant** implementations
- **AVX2/AVX-512/NEON** hardware acceleration
- **Constant-time operations** for side-channel resistance
- **Extensively tested** against NIST Known Answer Tests (KATs)

```rust
use ant_quic::crypto::pqc::PqcConfig;

let pqc = PqcConfig::builder()
    .ml_kem(true)               // ML-KEM-768 key exchange
    .ml_dsa(true)               // ML-DSA-65 signatures
    .memory_pool_size(10)       // Memory pool for crypto ops
    .handshake_timeout_multiplier(2.0)  // PQC handshakes are larger
    .build()?;
```

### Why Pure PQC (No Hybrid)?

- **Greenfield Network** - No legacy systems to maintain compatibility with
- **Maximum Security** - No weak classical algorithms in the chain
- **Simpler Implementation** - One cryptographic path, fewer edge cases
- **Future-Proof** - All connections quantum-resistant from day one
- **NIST Standardized** - ML-KEM and ML-DSA are FIPS 203/204 standards

### Identity Model

- **Ed25519 PeerId** - 32-byte identifier for addressing (NOT for TLS authentication)
- **ML-DSA-65 Authentication** - All TLS handshake signatures use pure PQC
- **ML-KEM-768 Key Exchange** - All key agreement uses pure PQC

See [docs/guides/pqc-security.md](docs/guides/pqc-security.md) for security analysis.

## NAT Traversal

NAT traversal is built into the QUIC protocol via extension frames, not STUN/TURN.

### How It Works

1. **Connect to any known peer**
2. **Peer observes your external address** from incoming packets
3. **Peer sends OBSERVED_ADDRESS frame** back to you
4. **You learn your public address** and can coordinate hole punching
5. **Direct P2P connection** established through NAT

### Extension Frames

| Frame | Type ID | Purpose |
|-------|---------|---------|
| `ADD_ADDRESS` | 0x3d7e90 (IPv4), 0x3d7e91 (IPv6) | Advertise candidate addresses |
| `PUNCH_ME_NOW` | 0x3d7e92 (IPv4), 0x3d7e93 (IPv6) | Coordinate hole punching timing |
| `REMOVE_ADDRESS` | 0x3d7e94 | Remove stale address |
| `OBSERVED_ADDRESS` | 0x9f81a6 (IPv4), 0x9f81a7 (IPv6) | Report external address to peer |

### Transport Parameters

| Parameter | ID | Purpose |
|-----------|---|---------|
| NAT Traversal Capability | 0x3d7e9f0bca12fea6 | Negotiates NAT traversal support |
| RFC-Compliant Frames | 0x3d7e9f0bca12fea8 | Enables RFC frame format |
| Address Discovery | 0x9f81a176 | Configures address observation |

### NAT Type Support

| NAT Type | Success Rate | Notes |
|----------|--------------|-------|
| Full Cone | >95% | Direct connection |
| Restricted Cone | 80-90% | Coordinated punch |
| Port Restricted | 70-85% | Port-specific coordination |
| Symmetric | 60-80% | Prediction algorithms |
| CGNAT | 50-70% | Relay fallback may be needed |

See [docs/NAT_TRAVERSAL_GUIDE.md](docs/NAT_TRAVERSAL_GUIDE.md) for detailed information.

## Raw Public Key Identity (v0.2)

Each node has an Ed25519 key pair for addressing, with ML-DSA-65 for authentication:

```rust
// PeerId = Ed25519 public key (32 bytes) - used for addressing ONLY
let (public_key, secret_key) = generate_ed25519_keypair();
let peer_id = derive_peer_id_from_public_key(&public_key);

// ML-DSA-65 keypair - used for TLS authentication
let (ml_dsa_pub, ml_dsa_sec) = generate_ml_dsa_65_keypair();
```

This follows our [Pure PQC Authentication specification](rfcs/ant-quic-pqc-authentication.md).

### v0.2 Changes

- **Ed25519**: Used ONLY for compact 32-byte PeerId addressing
- **ML-DSA-65**: Used for ALL TLS handshake signatures (pure PQC)
- **No Hybrid**: Previous hybrid Ed25519+ML-DSA scheme removed

### Trust Model

- **TOFU (Trust On First Use)**: First contact stores ML-DSA-65 public key fingerprint
- **Rotation**: New keys must be signed by old key (continuity)
- **Channel Binding**: TLS exporter signed with ML-DSA-65 (pure PQC)
- **NAT/Path Changes**: Token binding uses (PeerId || CID || nonce)

## Installation

### From Crates.io

```bash
cargo add ant-quic
```

### Pre-built Binaries

Download from [GitHub Releases](https://github.com/dirvine/ant-quic/releases):
- Linux: `ant-quic-linux-x86_64`, `ant-quic-linux-aarch64`
- Windows: `ant-quic-windows-x86_64.exe`
- macOS: `ant-quic-macos-x86_64`, `ant-quic-macos-aarch64`

### From Source

```bash
git clone https://github.com/dirvine/ant-quic
cd ant-quic
cargo build --release
```

## Binary Usage

```bash
# Run as P2P node (connects and accepts)
ant-quic --listen 0.0.0.0:9000

# Connect to known peers for discovery
ant-quic --listen 0.0.0.0:9000 --known-peers peer1.example.com:9000,peer2.example.com:9000

# Show your external address (discovered via peers)
ant-quic --listen 0.0.0.0:9000 --known-peers 159.89.81.21:9000
# Output: External address: YOUR.PUBLIC.IP:PORT

# Run with monitoring dashboard
ant-quic --dashboard --listen 0.0.0.0:9000

# Interactive commands while running:
# /status - Show connections and discovered addresses
# /peers  - List connected peers
# /help   - Show all commands
```

## API Reference

### Primary Types

| Type | Purpose |
|------|---------|
| `P2pEndpoint` | Main entry point for P2P networking |
| `P2pConfig` | Configuration builder |
| `P2pEvent` | Events from the endpoint |
| `PeerId` | 32-byte peer identifier |
| `PqcConfig` | Post-quantum crypto tuning |
| `NatConfig` | NAT traversal tuning |

### P2pEndpoint Methods

```rust
impl P2pEndpoint {
    // Creation
    async fn new(config: P2pConfig) -> Result<Self>;

    // Identity
    fn peer_id(&self) -> PeerId;
    fn local_addr(&self) -> Option<SocketAddr>;
    fn external_address(&self) -> Option<SocketAddr>;

    // Connections
    async fn connect_bootstrap(&self) -> Result<()>;
    async fn connect_to_peer(&self, peer: PeerId) -> Result<Connection>;
    fn connected_peers(&self) -> Vec<PeerId>;

    // Events
    fn subscribe(&self) -> broadcast::Receiver<P2pEvent>;

    // Statistics
    fn stats(&self) -> EndpointStats;
    fn nat_stats(&self) -> NatTraversalStatistics;
}
```

### P2pConfig Builder

```rust
let config = P2pConfig::builder()
    .bind_addr("0.0.0.0:9000".parse()?)  // Local address
    .known_peer(addr1)                    // Add known peer
    .known_peers(vec![addr2, addr3])      // Add multiple
    .max_connections(100)                 // Connection limit
    .pqc(pqc_config)                      // PQC tuning
    .nat(nat_config)                      // NAT tuning
    .mtu(MtuConfig::pqc_optimized())      // MTU for PQC
    .build()?;
```

See [docs/API_GUIDE.md](docs/API_GUIDE.md) for the complete API reference.

## RFC Compliance

ant-quic implements these specifications:

| Specification | Status | Notes |
|---------------|--------|-------|
| [RFC 9000](rfcs/rfc9000.txt) | Full | QUIC Transport Protocol |
| [RFC 9001](rfcs/rfc9001.txt) | Full | QUIC TLS |
| [Pure PQC Auth](rfcs/ant-quic-pqc-authentication.md) | Full | Raw Public Keys + Pure PQC (v0.2) |
| [draft-seemann-quic-nat-traversal-02](rfcs/draft-seemann-quic-nat-traversal-02.txt) | Full | NAT Traversal |
| [draft-ietf-quic-address-discovery-00](rfcs/draft-ietf-quic-address-discovery-00.txt) | Full | Address Discovery |
| [FIPS 203](rfcs/fips-203-ml-kem.pdf) | Full | ML-KEM (via saorsa-pqc) |
| [FIPS 204](rfcs/fips-204-ml-dsa.pdf) | Full | ML-DSA (via saorsa-pqc) |

See [docs/review.md](docs/review.md) for detailed RFC compliance analysis.

## Performance

### Connection Establishment

| Metric | Value |
|--------|-------|
| Handshake (PQC) | ~50ms typical |
| Address Discovery | <100ms |
| NAT Traversal | 200-500ms |
| PQC Overhead | ~8.7% |

### Data Transfer (localhost)

| Metric | Value |
|--------|-------|
| Send Throughput | 267 Mbps |
| Protocol Efficiency | 96.5% |
| Protocol Overhead | 3.5% |

### Scalability

| Connections | Memory | CPU |
|-------------|--------|-----|
| 100 | 56 KB | Minimal |
| 1,000 | 547 KB | Minimal |
| 5,000 | 2.7 MB | Linear |

## System Requirements

- **Rust**: 1.85.0+ (Edition 2024)
- **OS**: Linux 3.10+, Windows 10+, macOS 10.15+
- **Memory**: 64MB minimum, 256MB recommended
- **Network**: UDP traffic on chosen port

## Documentation

- [API Guide](docs/API_GUIDE.md) - Complete API reference
- [Symmetric P2P](docs/SYMMETRIC_P2P.md) - Architecture explanation
- [NAT Traversal Guide](docs/NAT_TRAVERSAL_GUIDE.md) - NAT traversal details
- [PQC Configuration](docs/guides/pqc-configuration.md) - PQC tuning
- [Architecture](docs/architecture/ARCHITECTURE.md) - System design
- [Troubleshooting](docs/TROUBLESHOOTING.md) - Common issues

## Examples

```bash
# Simple chat application
cargo run --example simple_chat -- --listen 0.0.0.0:9000

# Chat with peer discovery
cargo run --example chat_demo -- --known-peers peer.example.com:9000

# Statistics dashboard
cargo run --example dashboard_demo
```

## Testing

```bash
# Run all tests
cargo test

# Run with verbose output
cargo test -- --nocapture

# Specific test categories
cargo test nat_traversal
cargo test pqc
cargo test address_discovery

# Run benchmarks
cargo bench
```

## Contributing

Contributions welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md).

```bash
# Development setup
git clone https://github.com/dirvine/ant-quic
cd ant-quic
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
```

## License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Acknowledgments

- Built on [Quinn](https://github.com/quinn-rs/quinn) QUIC implementation
- **Pure PQC powered by [saorsa-pqc](https://crates.io/crates/saorsa-pqc)** - NIST FIPS 203/204 compliant ML-KEM and ML-DSA
- NAT traversal per [draft-seemann-quic-nat-traversal-02](https://datatracker.ietf.org/doc/draft-seemann-quic-nat-traversal/)
- Developed for the [Autonomi](https://autonomi.com) decentralized network

## Security

For security vulnerabilities, please email security@autonomi.com rather than filing a public issue.
