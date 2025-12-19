# Post-Quantum Cryptography Configuration Guide

This guide covers everything you need to know about Post-Quantum Cryptography (PQC) in ant-quic v0.13.0+.

## Table of Contents

1. [Overview](#overview)
2. [Always-On PQC](#always-on-pqc)
3. [Configuration Options](#configuration-options)
4. [Performance Tuning](#performance-tuning)
5. [Troubleshooting](#troubleshooting)
6. [Security Considerations](#security-considerations)

## Overview

**In ant-quic v0.13.0+, Post-Quantum Cryptography is always enabled.** Every connection uses PQC algorithms - there is no classical-only mode and no way to disable PQC.

This provides maximum security against both current classical attacks and future quantum computer threats.

### Algorithms Used

| Algorithm | Standard | Security Level | Purpose |
|-----------|----------|---------------|---------|
| ML-KEM-768 | FIPS 203 | NIST Level 3 (192-bit) | Key Encapsulation |
| ML-DSA-65 | FIPS 204 | NIST Level 3 (192-bit) | Digital Signatures |

The hybrid approach combines:
- **Key Exchange**: X25519 + ML-KEM-768
- **Signatures**: Ed25519 + ML-DSA-65

**Security Property**: An attacker must break BOTH classical and post-quantum algorithms to compromise security.

## Always-On PQC

### Why Always-On?

In v0.13.0, we removed the ability to disable PQC because:

1. **"Harvest Now, Decrypt Later"**: Adversaries can record encrypted traffic today and decrypt it when quantum computers become available
2. **No Performance Excuse**: Modern implementations have minimal overhead (~8%)
3. **Simplicity**: No mode selection means fewer configuration errors
4. **Future-Proof**: All ant-quic networks are quantum-resistant by default

### What Changed from Earlier Versions

If you're upgrading from ant-quic < v0.13.0:

| Removed | Reason |
|---------|--------|
| `PqcMode::Disabled` | PQC cannot be disabled |
| `PqcMode::Hybrid` | Hybrid is now always used |
| `PqcMode::Pure` | Pure PQC mode removed |
| `HybridPreference` | No preference selection |
| `fallback_enabled` | No fallback to classical-only |
| `migration_period_days` | No migration period needed |

## Configuration Options

### Basic Usage

PQC is enabled by default with no configuration required:

```rust
use ant_quic::{P2pEndpoint, P2pConfig};

// PQC is automatically enabled
let config = P2pConfig::builder()
    .known_peer("peer.example.com:9000".parse()?)
    .build()?;

let endpoint = P2pEndpoint::new(config).await?;
```

### PqcConfig for Tuning

The `PqcConfig` struct allows tuning PQC behavior (but not disabling it):

```rust
use ant_quic::{P2pConfig, PqcConfig};

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

### Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `ml_kem` | `bool` | `true` | Enable ML-KEM-768 key encapsulation |
| `ml_dsa` | `bool` | `true` | Enable ML-DSA-65 signatures |
| `memory_pool_size` | `usize` | `10` | Pre-allocated key operation buffers |
| `handshake_timeout_multiplier` | `f64` | `1.0` | Multiplier for handshake timeouts |

**Note**: While `ml_kem` and `ml_dsa` can be set to `false`, at least one must remain `true`. PQC cannot be completely disabled.

## Performance Tuning

### Connection Pooling

Reuse connections to amortize PQC handshake overhead:

```rust
use ant_quic::{P2pConfig, ConnectionPoolConfig};

let config = P2pConfig::builder()
    .connection_pool(ConnectionPoolConfig {
        max_idle_connections: 100,
        idle_timeout: Duration::from_secs(300),
    })
    .build()?;
```

### Memory Optimization

For memory-constrained environments:

```rust
let pqc_config = PqcConfig::builder()
    .memory_pool_size(5)  // Reduce from default 10
    .build()?;
```

### Hardware Acceleration

ant-quic automatically uses hardware acceleration when available:
- **AVX2/AVX-512** on x86_64 for ML-KEM/ML-DSA operations
- **NEON** on ARM64 for vector operations

To verify hardware acceleration is active:

```bash
RUST_LOG=ant_quic::crypto::pqc=debug cargo run 2>&1 | grep -i "hardware\|accel"
```

### MTU Considerations

PQC increases handshake packet sizes. For networks with small MTUs:

```rust
use ant_quic::{P2pConfig, MtuConfig};

let config = P2pConfig::builder()
    .mtu(MtuConfig {
        initial: 1200,  // Conservative initial MTU
        min: 1200,      // Minimum MTU
        max: 1500,      // Maximum MTU
    })
    .build()?;
```

## Troubleshooting

### Common Issues

#### 1. Handshake Timeouts

**Symptom**: Connections fail with timeout errors

**Cause**: PQC operations take longer on slow hardware

**Solution**:
```rust
let pqc_config = PqcConfig::builder()
    .handshake_timeout_multiplier(2.0)  // Double the timeout
    .build()?;
```

#### 2. High Memory Usage

**Symptom**: Memory consumption increases during high connection rates

**Cause**: ML-KEM/ML-DSA require more memory per operation

**Solution**:
```rust
let pqc_config = PqcConfig::builder()
    .memory_pool_size(5)  // Reduce pre-allocation
    .build()?;
```

#### 3. Compatibility with Pre-v0.13.0 Peers

**Symptom**: Cannot connect to older ant-quic nodes

**Cause**: Pre-v0.13.0 nodes may have PQC disabled

**Solution**: Upgrade all peers to v0.13.0+. There is no backward compatibility mode - all nodes must support PQC.

### Debug Logging

Enable detailed PQC logging:

```bash
# Basic PQC logging
RUST_LOG=ant_quic::crypto::pqc=debug cargo run

# Detailed handshake logging
RUST_LOG=ant_quic::crypto::pqc=trace cargo run

# Performance metrics only
RUST_LOG=ant_quic::crypto::pqc::performance=info cargo run
```

Log categories:
- `pqc::negotiation` - Algorithm negotiation
- `pqc::handshake` - Handshake operations
- `pqc::performance` - Timing metrics
- `pqc::keygen` - Key generation events

## Security Considerations

### Algorithm Selection

ant-quic uses NIST-standardized algorithms chosen for their security and performance balance:

| Property | ML-KEM-768 | ML-DSA-65 |
|----------|------------|-----------|
| Standard | FIPS 203 | FIPS 204 |
| Security Level | NIST Level 3 | NIST Level 3 |
| Classical Security | 192 bits | 192 bits |
| Quantum Security | ~175 bits | ~175 bits |
| Public Key Size | 1,184 bytes | 1,952 bytes |
| Ciphertext/Signature | 1,088 bytes | 3,293 bytes |

### Side-Channel Protection

The implementation includes countermeasures against:
- Timing attacks (constant-time operations)
- Cache-timing attacks (memory access patterns)
- Power analysis (on supporting hardware)

### Key Management

Best practices:
1. **Unique Keys**: Each connection uses freshly generated keys
2. **Secure Deletion**: Key material is zeroized after use
3. **No Key Reuse**: Ephemeral keys prevent replay attacks

### Compliance

ant-quic's PQC implementation supports:
- **FIPS 203/204**: NIST post-quantum standards
- **SP 800-56C Rev. 2**: Key derivation methods
- **SP 800-90A Rev. 1**: Random number generation

## Examples

See working examples:
- [`examples/pqc_demo.rs`](../../examples/pqc_demo.rs) - Basic PQC setup
- [`examples/simple_chat.rs`](../../examples/simple_chat.rs) - Chat with PQC

## Further Reading

- [NIST FIPS 203 - ML-KEM](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
- [NIST FIPS 204 - ML-DSA](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
- [rfcs/fips-203-ml-kem.pdf](../../rfcs/fips-203-ml-kem.pdf) - Local reference
- [rfcs/fips-204-ml-dsa.pdf](../../rfcs/fips-204-ml-dsa.pdf) - Local reference
- [PQC Security Guide](./pqc-security.md) - Security deep dive
- [PQC Migration Guide](./pqc-migration.md) - Upgrading from older versions
