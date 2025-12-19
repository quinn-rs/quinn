# Configuration Reference

Complete reference for all ant-quic configuration options.

## P2pConfig

Main configuration for P2P endpoints.

### Builder Methods

```rust
let config = P2pConfig::builder()
    .bind_addr(addr)          // Local address to bind
    .known_peer(addr)         // Address to connect for discovery
    .nat(nat_config)          // NAT traversal configuration
    .pqc(pqc_config)          // Post-quantum crypto configuration
    .mtu(mtu_config)          // MTU configuration
    .max_connections(n)       // Maximum concurrent connections
    .connection_timeout(d)    // Connection establishment timeout
    .idle_timeout(d)          // Idle connection timeout
    .build()?;
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `bind_addr` | `SocketAddr` | `0.0.0.0:0` | Local address to bind |
| `known_peer` | `SocketAddr` | (none) | Known peer address (can add multiple) |
| `nat` | `NatConfig` | `Default` | NAT traversal settings |
| `pqc` | `PqcConfig` | `Default` | PQC settings |
| `mtu` | `MtuConfig` | `Default` | MTU settings |
| `max_connections` | `usize` | `100` | Max concurrent connections |
| `connection_timeout` | `Duration` | `30s` | Connection timeout |
| `idle_timeout` | `Duration` | `60s` | Idle connection timeout |

### Example

```rust
let config = P2pConfig::builder()
    .bind_addr("0.0.0.0:9000".parse()?)
    .known_peer("quic.saorsalabs.com:9000".parse()?)
    .known_peer("peer2.example.com:9000".parse()?)
    .max_connections(50)
    .connection_timeout(Duration::from_secs(45))
    .idle_timeout(Duration::from_secs(120))
    .build()?;
```

---

## NatConfig

NAT traversal configuration.

### Fields

```rust
pub struct NatConfig {
    pub max_candidates: usize,
    pub coordination_timeout: Duration,
    pub discovery_timeout: Duration,
    pub enable_symmetric_nat: bool,
    pub hole_punch_retries: u32,
}
```

### Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_candidates` | `usize` | `10` | Maximum address candidates |
| `coordination_timeout` | `Duration` | `15s` | Hole punch coordination timeout |
| `discovery_timeout` | `Duration` | `5s` | Candidate discovery timeout |
| `enable_symmetric_nat` | `bool` | `true` | Enable port prediction |
| `hole_punch_retries` | `u32` | `5` | Number of punch attempts |

### Example

```rust
let nat = NatConfig {
    max_candidates: 15,
    coordination_timeout: Duration::from_secs(20),
    discovery_timeout: Duration::from_secs(10),
    enable_symmetric_nat: true,
    hole_punch_retries: 10,
};
```

### Defaults

```rust
impl Default for NatConfig {
    fn default() -> Self {
        Self {
            max_candidates: 10,
            coordination_timeout: Duration::from_secs(15),
            discovery_timeout: Duration::from_secs(5),
            enable_symmetric_nat: true,
            hole_punch_retries: 5,
        }
    }
}
```

---

## PqcConfig

Post-quantum cryptography configuration.

**Important**: PQC cannot be disabled. These options tune PQC behavior.

### Builder Methods

```rust
let pqc = PqcConfig::builder()
    .ml_kem(true)                      // Enable ML-KEM-768
    .ml_dsa(true)                      // Enable ML-DSA-65
    .memory_pool_size(10)              // Reusable buffer count
    .handshake_timeout_multiplier(1.5) // Timeout adjustment
    .build()?;
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `ml_kem` | `bool` | `true` | Enable ML-KEM-768 key exchange |
| `ml_dsa` | `bool` | `true` | Enable ML-DSA-65 signatures |
| `memory_pool_size` | `usize` | `10` | Number of reusable buffers |
| `handshake_timeout_multiplier` | `f64` | `1.5` | Timeout multiplier for PQC |

### Example

```rust
let pqc = PqcConfig::builder()
    .ml_kem(true)
    .ml_dsa(true)
    .memory_pool_size(20)
    .handshake_timeout_multiplier(2.0)
    .build()?;
```

---

## MtuConfig

MTU (Maximum Transmission Unit) configuration.

### Fields

```rust
pub struct MtuConfig {
    pub initial: u16,
    pub min: u16,
    pub max: u16,
}
```

### Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `initial` | `u16` | `1200` | Initial MTU for new connections |
| `min` | `u16` | `1200` | Minimum MTU (QUIC minimum) |
| `max` | `u16` | `1500` | Maximum MTU after path validation |

### Example

```rust
let mtu = MtuConfig {
    initial: 1200,
    min: 1200,
    max: 1500,
};
```

### Considerations

- PQC handshakes are larger (~8KB total)
- Initial MTU affects handshake packet splitting
- Conservative settings improve compatibility
- Higher max MTU improves throughput after validation

---

## Environment Variables

Configuration can be influenced by environment variables:

| Variable | Effect |
|----------|--------|
| `RUST_LOG` | Logging level (debug, info, warn, error) |

### Logging Examples

```bash
# Full debug
RUST_LOG=ant_quic=debug

# Specific modules
RUST_LOG=ant_quic::nat_traversal=trace
RUST_LOG=ant_quic::crypto::pqc=debug
RUST_LOG=ant_quic::connection=info
```

---

## Complete Configuration Example

```rust
use ant_quic::{P2pConfig, NatConfig, PqcConfig, MtuConfig};
use std::time::Duration;

fn create_config() -> anyhow::Result<P2pConfig> {
    // NAT traversal tuning
    let nat = NatConfig {
        max_candidates: 15,
        coordination_timeout: Duration::from_secs(20),
        discovery_timeout: Duration::from_secs(10),
        enable_symmetric_nat: true,
        hole_punch_retries: 10,
    };

    // PQC tuning
    let pqc = PqcConfig::builder()
        .ml_kem(true)
        .ml_dsa(true)
        .memory_pool_size(20)
        .handshake_timeout_multiplier(2.0)
        .build()?;

    // MTU settings
    let mtu = MtuConfig {
        initial: 1200,
        min: 1200,
        max: 1500,
    };

    // Complete config
    let config = P2pConfig::builder()
        .bind_addr("0.0.0.0:9000".parse()?)
        .known_peer("quic.saorsalabs.com:9000".parse()?)
        .known_peer("peer2.example.com:9000".parse()?)
        .known_peer("peer3.example.com:9000".parse()?)
        .nat(nat)
        .pqc(pqc)
        .mtu(mtu)
        .max_connections(100)
        .connection_timeout(Duration::from_secs(45))
        .idle_timeout(Duration::from_secs(120))
        .build()?;

    Ok(config)
}
```

---

## Removed Configuration (v0.13.0)

The following options were **removed** in v0.13.0:

| Removed | Reason |
|---------|--------|
| `role` / `EndpointRole` | All nodes are symmetric |
| `bootstrap_nodes` | Use `known_peer()` instead |
| `enable_coordinator` | All nodes can coordinate |
| `PqcMode` | PQC always enabled |
| `HybridPreference` | No mode selection |
| `fallback_enabled` | No fallback to classical |
| `AuthConfig` | Raw Public Keys only |

### Migration

```rust
// OLD (v0.12 and earlier) - DO NOT USE
// let config = QuicNodeConfig {
//     role: EndpointRole::Client,
//     bootstrap_nodes: vec![...],
//     enable_coordinator: false,
//     ...
// };

// NEW (v0.13.0+)
let config = P2pConfig::builder()
    .known_peer("peer.example.com:9000".parse()?)
    .build()?;
```

## See Also

- [Configuration Guide](./configuration.md)
- [API Reference](./api-reference.md)
- [Troubleshooting](./troubleshooting.md)

