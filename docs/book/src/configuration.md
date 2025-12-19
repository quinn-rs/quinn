# Configuration

ant-quic v0.13.0+ provides configuration through `P2pConfig` with a builder pattern.

## Basic Configuration

```rust
use ant_quic::{P2pEndpoint, P2pConfig, NatConfig, PqcConfig, MtuConfig};
use std::time::Duration;

let config = P2pConfig::builder()
    // Known peers for address discovery
    .known_peer("peer1.example.com:9000".parse()?)
    .known_peer("peer2.example.com:9000".parse()?)
    // Bind address (optional)
    .bind_addr("0.0.0.0:9000".parse()?)
    // Connection limits
    .max_connections(100)
    .build()?;

let endpoint = P2pEndpoint::new(config).await?;
```

## P2pConfig Builder

All configuration is done through the builder pattern:

```rust
let config = P2pConfig::builder()
    // Network configuration
    .bind_addr("0.0.0.0:9000".parse()?)
    .known_peer("peer.example.com:9000".parse()?)

    // NAT traversal tuning
    .nat(NatConfig { ... })

    // PQC tuning (cannot disable PQC)
    .pqc(PqcConfig::builder().build()?)

    // MTU configuration
    .mtu(MtuConfig { ... })

    // Connection limits
    .max_connections(100)
    .connection_timeout(Duration::from_secs(30))
    .idle_timeout(Duration::from_secs(60))

    .build()?;
```

## Symmetric P2P Model

In v0.13.0+, there are **no roles to configure**. All nodes are symmetric:

```rust
// OLD (v0.12 and earlier) - DO NOT USE
// let config = QuicNodeConfig {
//     role: EndpointRole::Client,  // REMOVED
//     enable_coordinator: false,   // REMOVED
//     ...
// };

// NEW (v0.13.0+)
let config = P2pConfig::builder()
    .known_peer("peer.example.com:9000".parse()?)
    .build()?;

// Every node can both connect AND accept connections
```

## NAT Traversal Configuration

```rust
use ant_quic::NatConfig;

let nat_config = NatConfig {
    // Maximum candidate addresses per peer
    max_candidates: 10,

    // Timeout for hole punch coordination
    coordination_timeout: Duration::from_secs(15),

    // Timeout for candidate discovery
    discovery_timeout: Duration::from_secs(5),

    // Enable port prediction for symmetric NAT
    enable_symmetric_nat: true,

    // Number of hole punch attempts
    hole_punch_retries: 5,

    ..Default::default()
};

let config = P2pConfig::builder()
    .nat(nat_config)
    .build()?;
```

### NatConfig Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `max_candidates` | `usize` | `10` | Maximum address candidates per peer |
| `coordination_timeout` | `Duration` | `15s` | Timeout for hole punch coordination |
| `discovery_timeout` | `Duration` | `5s` | Timeout for candidate discovery |
| `enable_symmetric_nat` | `bool` | `true` | Enable port prediction for symmetric NAT |
| `hole_punch_retries` | `u32` | `5` | Number of hole punch attempts |

## PQC Configuration

PQC is **always enabled** in v0.13.0+. Configuration is for tuning only:

```rust
use ant_quic::PqcConfig;

let pqc_config = PqcConfig::builder()
    // Enable/disable specific algorithms (both default to true)
    .ml_kem(true)           // ML-KEM-768 for key encapsulation
    .ml_dsa(true)           // ML-DSA-65 for signatures

    // Memory pool for key operations
    .memory_pool_size(10)

    // Adjust handshake timeout for slower hardware
    .handshake_timeout_multiplier(1.5)
    .build()?;

let config = P2pConfig::builder()
    .pqc(pqc_config)
    .build()?;
```

### PqcConfig Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `ml_kem` | `bool` | `true` | Enable ML-KEM-768 key encapsulation |
| `ml_dsa` | `bool` | `true` | Enable ML-DSA-65 signatures |
| `memory_pool_size` | `usize` | `10` | Pre-allocated key operation buffers |
| `handshake_timeout_multiplier` | `f64` | `1.0` | Multiplier for handshake timeouts |

**Note**: At least one of `ml_kem` or `ml_dsa` must be true. PQC cannot be completely disabled.

## MTU Configuration

Configure MTU for networks with PQC overhead:

```rust
use ant_quic::MtuConfig;

let mtu_config = MtuConfig {
    initial: 1200,  // Conservative initial MTU
    min: 1200,      // Minimum MTU
    max: 1500,      // Maximum MTU
};

let config = P2pConfig::builder()
    .mtu(mtu_config)
    .build()?;
```

### MTU Considerations

PQC increases packet sizes:
- ML-KEM-768 public key: 1,184 bytes
- ML-KEM-768 ciphertext: 1,088 bytes
- ML-DSA-65 signature: 3,293 bytes

For constrained networks, use conservative MTU settings.

## Connection Settings

```rust
let config = P2pConfig::builder()
    // Maximum concurrent connections
    .max_connections(100)

    // Connection establishment timeout
    .connection_timeout(Duration::from_secs(30))

    // Idle timeout before closing connection
    .idle_timeout(Duration::from_secs(60))

    .build()?;
```

## Known Peers

Known peers are addresses you connect to first for address discovery:

```rust
let config = P2pConfig::builder()
    // Add multiple known peers for redundancy
    .known_peer("us-east.example.com:9000".parse()?)
    .known_peer("eu-west.example.com:9000".parse()?)
    .known_peer("asia.example.com:9000".parse()?)
    .build()?;

// Connect to known peers and discover external address
endpoint.connect_bootstrap().await?;

// Check discovered address
if let Some(addr) = endpoint.external_address() {
    println!("External address: {}", addr);
}
```

**Best Practice**: Use at least 3 known peers in different geographic regions.

## Configuration Removed in v0.13.0

The following configuration options were **removed** in v0.13.0:

| Removed | Reason |
|---------|--------|
| `EndpointRole` | All nodes are symmetric |
| `NatTraversalRole` | All nodes are symmetric |
| `PqcMode` | PQC is always enabled |
| `HybridPreference` | No hybrid mode selection |
| `fallback_enabled` | No classical-only fallback |
| `enable_coordinator` | All nodes can coordinate |
| `bootstrap_nodes` | Replaced by `known_peer()` |

## Environment Variables

Some settings can be configured via environment:

```bash
# Logging
RUST_LOG=ant_quic=debug cargo run

# Specific modules
RUST_LOG=ant_quic::crypto::pqc=trace cargo run
```

## Full Example

```rust
use ant_quic::{P2pEndpoint, P2pConfig, NatConfig, PqcConfig, MtuConfig};
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = P2pConfig::builder()
        // Network
        .bind_addr("0.0.0.0:9000".parse()?)
        .known_peer("quic.saorsalabs.com:9000".parse()?)

        // NAT traversal
        .nat(NatConfig {
            max_candidates: 10,
            coordination_timeout: Duration::from_secs(15),
            discovery_timeout: Duration::from_secs(5),
            enable_symmetric_nat: true,
            hole_punch_retries: 5,
            ..Default::default()
        })

        // PQC tuning
        .pqc(PqcConfig::builder()
            .ml_kem(true)
            .ml_dsa(true)
            .memory_pool_size(10)
            .build()?)

        // MTU
        .mtu(MtuConfig {
            initial: 1200,
            min: 1200,
            max: 1500,
        })

        // Connections
        .max_connections(100)
        .connection_timeout(Duration::from_secs(30))
        .idle_timeout(Duration::from_secs(60))

        .build()?;

    let endpoint = P2pEndpoint::new(config).await?;

    // Discover external address
    endpoint.connect_bootstrap().await?;

    Ok(())
}
```

## See Also

- [Quick Start](./quick-start.md)
- [NAT Traversal](./nat-traversal.md)
- [Security](./security.md)
- [Configuration Reference](./config-reference.md)
