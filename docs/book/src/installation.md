# Installation

## Requirements

### Minimum Rust Version

ant-quic requires **Rust 1.85.0** or later (Rust Edition 2024).

### Platform Requirements

| Platform | Requirements |
|----------|-------------|
| Linux | glibc 2.17+, kernel 3.10+ |
| Windows | Windows 10+ |
| macOS | macOS 10.13+ |
| Android | API level 21+ |

**Note**: WASM is not supported. ant-quic uses raw UDP sockets and NAT traversal which are incompatible with the browser sandbox environment.

## Installing from crates.io

Add ant-quic to your project:

```bash
cargo add ant-quic
```

Or manually add to `Cargo.toml`:

```toml
[dependencies]
ant-quic = "0.13"
tokio = { version = "1", features = ["full"] }
```

## Feature Flags

ant-quic supports various feature flags:

### Cryptography Providers

| Feature | Description |
|---------|-------------|
| `rustls-ring` | Use ring for cryptography (default) |
| `rustls-aws-lc-rs` | Use AWS-LC for cryptography (recommended for PQC) |

### Development Features

| Feature | Description |
|---------|-------------|
| `trace` | Enable tracing functionality |
| `test-utils` | Testing utilities |

### Example Configurations

```toml
# Default (ring crypto)
[dependencies]
ant-quic = "0.13"

# AWS-LC crypto (better PQC performance)
[dependencies]
ant-quic = { version = "0.13", default-features = false, features = ["rustls-aws-lc-rs"] }

# With tracing
[dependencies]
ant-quic = { version = "0.13", features = ["trace"] }
```

## Post-Quantum Cryptography

PQC is **always enabled** in ant-quic v0.13.0+. Every connection uses:

- **ML-KEM-768** for key encapsulation (FIPS 203)
- **ML-DSA-65** for digital signatures (FIPS 204)

These are combined with classical algorithms (X25519, Ed25519) in a hybrid scheme. There is no way to disable PQC.

### PQC Performance Considerations

PQC algorithms have larger key and signature sizes:

| Component | Classical | Post-Quantum |
|-----------|-----------|--------------|
| Public Key (KEM) | 32 bytes | 1,184 bytes |
| Ciphertext | 32 bytes | 1,088 bytes |
| Public Key (Sig) | 32 bytes | 1,952 bytes |
| Signature | 64 bytes | 3,293 bytes |

This affects handshake size and latency. The `aws-lc-rs` feature provides optimized implementations.

## Building from Source

```bash
git clone https://github.com/dirvine/ant-quic
cd ant-quic
cargo build --release
```

### Development Build

```bash
# Quick build for development
cargo build

# Build with all checks
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
```

## Running the Binary

ant-quic includes a binary for P2P networking:

```bash
# Show help
cargo run --bin ant-quic -- --help

# Start a node
cargo run --bin ant-quic -- --listen 0.0.0.0:9000

# Connect to known peers
cargo run --bin ant-quic -- --bootstrap quic.saorsalabs.com:9000

# Run with dashboard
cargo run --bin ant-quic -- --dashboard --listen 0.0.0.0:9000
```

## Verifying Installation

Create a test file to verify everything works:

```rust
// src/main.rs
use ant_quic::{P2pEndpoint, P2pConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = P2pConfig::builder().build()?;
    let endpoint = P2pEndpoint::new(config).await?;

    println!("ant-quic v0.13.0 installed successfully!");
    println!("Peer ID: {}", endpoint.peer_id().to_hex());

    Ok(())
}
```

Run:

```bash
cargo run
```

## Troubleshooting Installation

### Crypto Provider Conflicts

If you get errors about multiple crypto providers:

```toml
# Use only one crypto backend
ant-quic = { version = "0.13", default-features = false, features = ["rustls-aws-lc-rs"] }
```

### AWS-LC Build Failures

AWS-LC requires a C compiler and CMake. Install them:

```bash
# Ubuntu/Debian
sudo apt install build-essential cmake

# macOS
xcode-select --install
brew install cmake

# Windows
# Install Visual Studio Build Tools and CMake
```

### Link Errors

If you see link errors with ring:

```bash
# Clear build cache
cargo clean
cargo build
```

## See Also

- [Getting Started](./getting-started.md) - First steps with ant-quic
- [Quick Start](./quick-start.md) - Build your first application
- [Platform Support](./platform-support.md) - Detailed platform information

