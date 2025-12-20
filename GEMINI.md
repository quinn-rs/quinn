# GEMINI.md

Repository guidelines for Google Gemini when working with ant-quic.

> **Related AI Assistant Guides**: See also [CLAUDE.md](CLAUDE.md) and [AGENTS.md](AGENTS.md) for alternative AI assistant configurations. All guides share the same core project information.

## Repository Independence

**ant-quic is an independent project (NOT a Quinn fork for contributions).**

- Do NOT open PRs to `quinn-rs/quinn`
- Do NOT add `quinn-rs/quinn` as an upstream remote
- Contribute only to `github.com/dirvine/ant-quic`
- Although GitHub shows it as a fork (legacy), we do NOT contribute back to Quinn

## Project Overview

ant-quic is a QUIC transport protocol implementation with advanced NAT traversal capabilities, optimized for P2P networks and the Autonomi ecosystem.

**v0.13.0+: Pure Symmetric P2P Architecture**
- **One Node Type**: All nodes are identical - every node can connect AND accept connections
- **100% PQC Always**: ML-KEM-768 key exchange on every connection, no classical crypto fallback
- **No Roles**: No Client/Server/Bootstrap distinction - all nodes are symmetric peers
- **Known Peers**: Uses `known_peers` terminology instead of "bootstrap nodes"

## Key Technical Decisions

### Authentication: Pure PQC with Raw Public Keys (v0.2)

We use **Pure Post-Quantum Cryptography** with raw public keys (inspired by RFC 7250):
- Reference: `rfcs/ant-quic-hybrid-pqc-authentication.md` (our specification)
- Identity: Ed25519 key pairs (32-byte PeerId compact identifier ONLY)
- Key Exchange: ML-KEM-768 (IANA 0x0201) - FIPS 203
- Signatures: ML-DSA-65 (IANA 0x0901) - FIPS 204
- No PKI infrastructure required
- No CA dependency - peers authenticate directly via public key fingerprints

v0.2: This is a greenfield network - NO hybrid algorithms, NO classical fallback.
Ed25519 is used ONLY for the 32-byte PeerId identifier, NOT for TLS authentication.

### Post-Quantum Cryptography: Always On (v0.13.0+)

**100% PQC on every connection** - there is no classical-only mode:
- **ML-KEM-768**: Key encapsulation (FIPS 203, NIST Level 3)
- **ML-DSA-65**: Digital signatures (FIPS 204, optional)
- Reference: `rfcs/fips-203-ml-kem.pdf`, `rfcs/fips-204-ml-dsa.pdf`

### Network: Dual-Stack IPv4 and IPv6 Support

ant-quic supports **both IPv4 and IPv6** addresses:
- Dual-stack socket binding when available
- IPv4-mapped IPv6 addresses handled transparently
- NAT traversal works across both IP versions
- Address candidates can be either IPv4 or IPv6
- QUIC connection migration works across address families

### NAT Traversal: Native QUIC (NO STUN, NO ICE, NO TURN)

**CRITICAL**: We use **native QUIC protocol extensions** based on the Seemann draft:
- Reference: `rfcs/draft-seemann-quic-nat-traversal-02.txt`
- Specification: [draft-seemann-quic-nat-traversal](https://datatracker.ietf.org/doc/draft-seemann-quic-nat-traversal/)

We do **NOT** use:
- STUN (Session Traversal Utilities for NAT)
- ICE (Interactive Connectivity Establishment)
- TURN (Traversal Using Relays around NAT)
- External NAT traversal servers

All NAT traversal is performed **natively within QUIC** using:

**Transport Parameters:**
- `0x3d7e9f0bca12fea6`: NAT traversal capability negotiation
- `0x3d7e9f0bca12fea8`: RFC-compliant frame format
- `0x9f81a176`: Address discovery configuration

**Extension Frames:**
- `ADD_ADDRESS`: 0x3d7e90 (IPv4), 0x3d7e91 (IPv6) - Advertise candidate addresses
- `PUNCH_ME_NOW`: 0x3d7e92 (IPv4), 0x3d7e93 (IPv6) - Coordinate hole punching
- `REMOVE_ADDRESS`: 0x3d7e94 - Remove stale address
- `OBSERVED_ADDRESS`: 0x9f81a6 (IPv4), 0x9f81a7 (IPv6) - Report external address

### Symmetric P2P Model (v0.13.0+)

All nodes are equal. Any connected peer can:
- Observe your external address from incoming packets
- Report your address via OBSERVED_ADDRESS frames
- Coordinate NAT traversal for other peers
- Act as relay when direct connection fails

## Project Structure

```
src/                    # Core library
  bin/                  # CLI binary (ant-quic)
  connection/           # QUIC connection with NAT traversal extensions
  crypto/               # TLS 1.3 with Pure PQC Raw Public Keys (v0.2)
  crypto/pqc/           # Post-quantum cryptography (ML-KEM, ML-DSA)
  unified_config.rs     # P2pConfig, NatConfig, MtuConfig
tests/                  # Integration test suites
examples/               # Runnable demos
benches/                # Criterion benchmarks
scripts/                # CI/coverage helpers
rfcs/                   # Local copies of reference specifications
docs/                   # Documentation
```

## Build and Test Commands

```bash
# Build optimized
cargo build --release

# Test all
cargo test --all-features

# Quick checks
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings

# Run binary (all nodes are symmetric)
cargo run --bin ant-quic -- --listen 0.0.0.0:9000

# Run example
cargo run --example simple_chat

# Fast compilation check
cargo check --all-targets
```

## Primary API (v0.13.0+)

```rust
use ant_quic::{P2pEndpoint, P2pConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = P2pConfig::builder()
        .known_peer("peer.example.com:9000".parse()?)
        .build()?;

    let endpoint = P2pEndpoint::new(config).await?;
    println!("Peer ID: {:?}", endpoint.peer_id());

    // Connect to known peers for address discovery
    endpoint.connect_bootstrap().await?;

    // Your external address is now discoverable
    if let Some(addr) = endpoint.external_address() {
        println!("External address: {}", addr);
    }

    Ok(())
}
```

## Coding Conventions

- **Rust Edition**: 2024
- **Formatting**: `cargo fmt --all`
- **Linting**: `cargo clippy --all-targets -- -D warnings` (zero warnings)
- **Error Handling**:
  - Non-test code: NO `unwrap`, `expect`, or `panic!`
  - Use `thiserror` for custom errors
  - Use `tracing` for structured logging
- **Naming**: `snake_case` functions, `CamelCase` types, `SCREAMING_SNAKE_CASE` constants

## Commit Guidelines

Conventional Commits required:
- `feat(nat): add punch scheduling`
- `fix(frame): correct varint parse`
- `test: add pqc regressions`
- `docs: update NAT traversal architecture`

## Reference Specifications (rfcs/)

### Core Protocol
- `rfc9000.txt` - QUIC: A UDP-Based Multiplexed and Secure Transport
- `ant-quic-hybrid-pqc-authentication.md` - **Pure PQC Raw Public Keys** (v0.2 - our specification)

### NAT Traversal (Native QUIC - NO STUN/ICE)
- `draft-seemann-quic-nat-traversal-02.txt` - **QUIC NAT Traversal** (primary spec)
- `draft-ietf-quic-address-discovery-00.txt` - QUIC Address Discovery Extension

### Post-Quantum Cryptography
- `fips-203-ml-kem.pdf` - ML-KEM (Kyber) key encapsulation
- `fips-204-ml-dsa.pdf` - ML-DSA (Dilithium) digital signatures
- `draft-ietf-tls-hybrid-design-14.txt` - Hybrid key exchange design

## Key File Locations

- **Main Library**: `src/lib.rs`
- **P2P Endpoint**: `src/p2p_endpoint.rs` - Primary API
- **Configuration**: `src/unified_config.rs` - P2pConfig, NatConfig
- **NAT Traversal API**: `src/nat_traversal_api.rs`
- **QUIC Node**: `src/quic_node.rs`
- **PQC Implementation**: `src/crypto/pqc/`
- **Binary**: `src/bin/ant-quic.rs`

---

## AI Assistant Guide Synchronization

| File | Purpose |
|------|---------|
| [CLAUDE.md](CLAUDE.md) | Claude Code (Anthropic) |
| [AGENTS.md](AGENTS.md) | Generic AI coding assistants |
| [GEMINI.md](GEMINI.md) | Google Gemini - this file |

**Keep core technical information consistent across all three files:**
- Repository independence (not a Quinn fork for contributions)
- v0.13.0+ symmetric P2P architecture (no roles)
- v0.2 Pure PQC: ML-KEM-768 (0x0201) + ML-DSA-65 (0x0901)
- Native QUIC NAT traversal (NO STUN/ICE/TURN)
- Correct frame IDs (0x3d7e90+, 0x9f81a6+)
- Pure PQC Raw Public Keys (v0.2 - see `rfcs/ant-quic-hybrid-pqc-authentication.md`)
- IPv4 and IPv6 dual-stack support
