# Post-Quantum Cryptography Configuration Guide

This guide covers everything you need to know about configuring Post-Quantum Cryptography (PQC) in ant-quic.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Configuration Options](#configuration-options)
3. [Operating Modes](#operating-modes)
4. [Migration Strategies](#migration-strategies)
5. [Performance Tuning](#performance-tuning)
6. [Troubleshooting](#troubleshooting)
7. [Security Considerations](#security-considerations)

## Quick Start

The simplest way to enable PQC is to use the default configuration:

```rust
use ant_quic::{QuicP2PNode, Config};
use ant_quic::crypto::pqc::PqcMode;

// Enable hybrid PQC (recommended)
let config = Config::default()
    .with_pqc_mode(PqcMode::Hybrid);

let node = QuicP2PNode::with_config(config).await?;
```

This enables hybrid mode which combines classical and post-quantum algorithms for maximum compatibility and security.

## Configuration Options

### PqcConfig Builder

The `PqcConfig` struct provides fine-grained control over PQC behavior:

```rust
use ant_quic::crypto::pqc::{PqcConfig, PqcMode, HybridPreference};

let pqc_config = PqcConfig::builder()
    // Set the operating mode
    .mode(PqcMode::Hybrid)
    
    // Control hybrid algorithm preference
    .hybrid_preference(HybridPreference::PreferPqc)
    
    // Set migration period (days)
    .migration_period_days(30)
    
    // Enable compatibility warnings
    .enable_compatibility_warnings(true)
    
    // Build the configuration
    .build();
```

### Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `mode` | `PqcMode` | `Hybrid` | Operating mode (Disabled/Hybrid/Pure) |
| `hybrid_preference` | `HybridPreference` | `Balanced` | Algorithm selection preference |
| `migration_period_days` | `u32` | `90` | Grace period for migration |
| `compatibility_warnings` | `bool` | `true` | Log warnings for non-PQC peers |
| `fallback_enabled` | `bool` | `true` | Allow fallback to classical crypto |

## Operating Modes

### Disabled Mode

Completely disables PQC support:

```rust
let config = PqcConfig::disabled();
```

Use cases:
- Legacy systems that cannot be upgraded
- Testing classical cryptography paths
- Temporary compatibility requirements

### Hybrid Mode (Recommended)

Combines classical and post-quantum algorithms:

```rust
let config = PqcConfig::default(); // Hybrid is default
// or explicitly:
let config = PqcConfig::builder()
    .mode(PqcMode::Hybrid)
    .build();
```

Benefits:
- Protection against both classical and quantum attacks
- Maintains compatibility with non-PQC peers
- Smooth migration path
- ~8.7% performance overhead

Algorithm combinations:
- **Key Exchange**: X25519 + ML-KEM-768
- **Signatures**: Ed25519 + ML-DSA-65

### Pure Mode

Uses only post-quantum algorithms:

```rust
let config = PqcConfig::builder()
    .mode(PqcMode::Pure)
    .build();
```

Characteristics:
- Maximum quantum resistance
- Requires PQC support on both peers
- No fallback to classical algorithms
- Slightly higher performance overhead

## Migration Strategies

### Conservative Migration

Start with optional PQC and gradually increase requirements:

```rust
// Phase 1: Enable logging only
let phase1 = PqcConfig::builder()
    .mode(PqcMode::Disabled)
    .enable_compatibility_warnings(true)
    .build();

// Phase 2: Optional PQC
let phase2 = PqcConfig::builder()
    .mode(PqcMode::Hybrid)
    .hybrid_preference(HybridPreference::PreferClassical)
    .migration_period_days(90)
    .build();

// Phase 3: Prefer PQC
let phase3 = PqcConfig::builder()
    .mode(PqcMode::Hybrid)
    .hybrid_preference(HybridPreference::PreferPqc)
    .migration_period_days(30)
    .build();

// Phase 4: Require PQC
let phase4 = PqcConfig::builder()
    .mode(PqcMode::Pure)
    .build();
```

### Aggressive Migration

Quick transition for controlled environments:

```rust
// Immediate hybrid adoption
let config = PqcConfig::builder()
    .mode(PqcMode::Hybrid)
    .hybrid_preference(HybridPreference::PreferPqc)
    .migration_period_days(7)
    .fallback_enabled(false)
    .build();
```

### A/B Testing

Test PQC impact on a subset of connections:

```rust
use rand::Rng;

fn create_config(peer_id: &str) -> PqcConfig {
    let mut rng = rand::thread_rng();
    
    // Enable PQC for 50% of connections
    if rng.gen_bool(0.5) {
        PqcConfig::default()
    } else {
        PqcConfig::disabled()
    }
}
```

## Performance Tuning

### Connection Pooling

Reuse PQC handshake results:

```rust
// Enable connection pooling to amortize PQC overhead
let config = Config::default()
    .with_pqc_mode(PqcMode::Hybrid)
    .with_connection_pool_size(100)
    .with_idle_timeout(Duration::from_secs(300));
```

### Batch Operations

Process multiple connections together:

```rust
// Batch connection establishment
let futures: Vec<_> = addresses
    .iter()
    .map(|addr| node.connect(addr))
    .collect();

let connections = futures::future::join_all(futures).await;
```

### Resource Limits

Control memory usage:

```rust
let config = PqcConfig::builder()
    .mode(PqcMode::Hybrid)
    .max_cached_keys(1000)
    .key_cache_ttl(Duration::from_secs(3600))
    .build();
```

## Troubleshooting

### Common Issues

#### 1. Connection Failures with Legacy Peers

**Symptom**: Connections fail when PQC is enabled

**Solution**:
```rust
// Enable fallback for compatibility
let config = PqcConfig::builder()
    .mode(PqcMode::Hybrid)
    .fallback_enabled(true)
    .build();
```

#### 2. Performance Degradation

**Symptom**: High CPU usage during handshakes

**Solutions**:
- Use connection pooling
- Enable hardware acceleration if available
- Consider hybrid mode instead of pure PQC

#### 3. Memory Usage

**Symptom**: Increased memory consumption

**Solution**:
```rust
// Tune cache sizes
let config = PqcConfig::builder()
    .max_cached_keys(500)  // Reduce from default 1000
    .build();
```

### Debug Logging

Enable detailed PQC logging:

```bash
RUST_LOG=ant_quic::crypto::pqc=debug cargo run
```

Log categories:
- `pqc::negotiation` - Algorithm negotiation
- `pqc::handshake` - Handshake details
- `pqc::performance` - Performance metrics
- `pqc::compatibility` - Compatibility warnings

## Security Considerations

### Algorithm Selection

ant-quic uses NIST-standardized algorithms:

| Algorithm | Security Level | Use Case |
|-----------|---------------|----------|
| ML-KEM-768 | NIST Level 3 | Key exchange |
| ML-DSA-65 | NIST Level 3 | Digital signatures |
| X25519 | 128-bit classical | Hybrid key exchange |
| Ed25519 | 128-bit classical | Hybrid signatures |

### Side-Channel Protection

The implementation includes countermeasures against:
- Timing attacks
- Cache-timing attacks
- Power analysis (on supporting hardware)

### Key Management

Best practices:
1. Rotate keys regularly
2. Use unique keys per connection
3. Implement secure key storage
4. Monitor for quantum computing advances

### Compliance

Ensure your configuration meets regulatory requirements:

```rust
// FIPS-compliant configuration
let config = PqcConfig::builder()
    .mode(PqcMode::Hybrid)
    .fips_mode(true)
    .build();
```

## Examples

See the following examples for practical implementations:
- [`examples/pqc_basic.rs`](../../examples/pqc_basic.rs) - Simple PQC setup
- [`examples/pqc_hybrid_demo.rs`](../../examples/pqc_hybrid_demo.rs) - Hybrid mode demonstration
- [`examples/pqc_config_demo.rs`](../../examples/pqc_config_demo.rs) - Advanced configuration
- [`examples/pqc_migration_demo.rs`](../../examples/pqc_migration_demo.rs) - Migration strategies

## Further Reading

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [IETF PQUIC Working Group](https://datatracker.ietf.org/wg/pquic/about/)
- [ML-KEM Specification (FIPS 203)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
- [ML-DSA Specification (FIPS 204)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
EOF < /dev/null