# Post-Quantum Cryptography Migration Guide

This guide provides a comprehensive roadmap for migrating your ant-quic applications to v0.13.0+ with always-on Post-Quantum Cryptography.

## Table of Contents

1. [Migration Overview](#migration-overview)
2. [What Changed in v0.13.0](#what-changed-in-v0130)
3. [Pre-Migration Checklist](#pre-migration-checklist)
4. [Migration Steps](#migration-steps)
5. [Code Changes Required](#code-changes-required)
6. [Network-Wide Migration](#network-wide-migration)
7. [Troubleshooting](#troubleshooting)
8. [Monitoring and Validation](#monitoring-and-validation)

## Migration Overview

### Why v0.13.0 Requires Migration

ant-quic v0.13.0 introduced **always-on Post-Quantum Cryptography**. This is a breaking change:

- **Before v0.13.0**: PQC was optional with `PqcMode::Disabled/Hybrid/Pure`
- **After v0.13.0**: PQC is always enabled, no way to disable

**All nodes in your network must be upgraded to v0.13.0+ simultaneously** or they will be unable to communicate with nodes running older versions that have PQC disabled.

### Why the Breaking Change?

1. **Security**: "Harvest now, decrypt later" attacks are a real threat
2. **Simplicity**: No mode confusion, consistent security everywhere
3. **Future-Proof**: All ant-quic networks are quantum-resistant by default
4. **Performance**: Modern hardware handles PQC with minimal overhead (~8%)

## What Changed in v0.13.0

### Removed Types and Methods

| Removed | Was Used For | v0.13.0 Equivalent |
|---------|--------------|-------------------|
| `PqcMode::Disabled` | Disable PQC | Not available - PQC always on |
| `PqcMode::Hybrid` | Enable hybrid mode | Default behavior (always hybrid) |
| `PqcMode::Pure` | PQC-only mode | Not available - always hybrid |
| `HybridPreference` | Algorithm priority | Not available |
| `.fallback_enabled(bool)` | Classical fallback | Not available |
| `.migration_period_days(u32)` | Transition period | Not available |
| `.with_pqc_mode(PqcMode)` | Set PQC mode | Not available |

### New Configuration

`PqcConfig` is now for tuning only:

```rust
// v0.13.0+: Tuning parameters only
let pqc_config = PqcConfig::builder()
    .ml_kem(true)                      // Enable ML-KEM-768 (default: true)
    .ml_dsa(true)                      // Enable ML-DSA-65 (default: true)
    .memory_pool_size(10)              // Key operation buffers
    .handshake_timeout_multiplier(1.5) // For slow hardware
    .build()?;
```

### New Primary API

v0.13.0 introduced `P2pEndpoint` as the primary API:

```rust
use ant_quic::{P2pEndpoint, P2pConfig};

let config = P2pConfig::builder()
    .known_peer("peer.example.com:9000".parse()?)
    .build()?;

let endpoint = P2pEndpoint::new(config).await?;
```

## Pre-Migration Checklist

Before starting migration:

- [ ] **Version Check**: Current ant-quic version < 0.13.0
- [ ] **Network Audit**: Identify all nodes that need upgrading
- [ ] **Coordination Plan**: Schedule coordinated network upgrade
- [ ] **Testing Environment**: Available for validation
- [ ] **Rollback Plan**: Document how to revert if needed
- [ ] **Performance Baseline**: Record current metrics for comparison
- [ ] **Hardware Assessment**: Verify hardware can handle PQC overhead

### Hardware Requirements

PQC requires more CPU and memory. Minimum recommendations:

| Resource | Requirement |
|----------|-------------|
| CPU | 1 GHz+ with AES-NI |
| RAM | 512 MB minimum, 1 GB+ recommended |
| Disk | No additional requirements |

## Migration Steps

### Step 1: Update Dependencies

Update `Cargo.toml`:

```toml
[dependencies]
ant-quic = "0.13.0"  # or later
```

Run:
```bash
cargo update
cargo check
```

### Step 2: Fix Compilation Errors

The compiler will identify all deprecated API usage. Common fixes:

#### Remove PqcMode References

```rust
// BEFORE (will not compile)
use ant_quic::crypto::pqc::{PqcConfig, PqcMode, HybridPreference};

let config = PqcConfig::builder()
    .mode(PqcMode::Hybrid)
    .hybrid_preference(HybridPreference::PreferPqc)
    .fallback_enabled(true)
    .build();

// AFTER
use ant_quic::PqcConfig;

let config = PqcConfig::builder()
    // Only tuning parameters available
    .ml_kem(true)
    .ml_dsa(true)
    .build()?;
```

#### Update Endpoint Creation

```rust
// BEFORE (will not compile)
use ant_quic::{QuicP2PNode, Config};

let config = Config::default()
    .with_pqc_mode(PqcMode::Hybrid);

let node = QuicP2PNode::with_config(config).await?;

// AFTER
use ant_quic::{P2pEndpoint, P2pConfig};

let config = P2pConfig::builder()
    .known_peer("peer.example.com:9000".parse()?)
    .build()?;

let endpoint = P2pEndpoint::new(config).await?;
```

### Step 3: Update Configuration Files

If you have external configuration (TOML, JSON, etc.), remove deprecated fields:

```toml
# BEFORE
[pqc]
mode = "hybrid"
hybrid_preference = "prefer_pqc"
fallback_enabled = true
migration_period_days = 90

# AFTER
[pqc]
ml_kem = true
ml_dsa = true
memory_pool_size = 10
```

### Step 4: Test Locally

```bash
# Build and test
cargo build --release
cargo test

# Test PQC specifically
cargo test pqc
cargo test ml_kem
cargo test ml_dsa

# Check for warnings
cargo clippy --all-targets -- -D warnings
```

### Step 5: Test in Staging

Deploy to a staging environment before production:

```bash
# Run with debug logging
RUST_LOG=ant_quic::crypto::pqc=debug ./target/release/ant-quic

# Verify PQC is active
# Look for: "PQC handshake completed with ML-KEM-768"
```

## Code Changes Required

### Common Patterns

#### Pattern 1: Simple Node

```rust
// BEFORE
let node = QuicP2PNode::new(addr).await?;

// AFTER
let config = P2pConfig::builder().build()?;
let endpoint = P2pEndpoint::new(config).await?;
```

#### Pattern 2: Node with Bootstrap

```rust
// BEFORE
let node = QuicP2PNode::with_bootstrap(addr, bootstrap_addrs).await?;

// AFTER
let mut builder = P2pConfig::builder();
for addr in bootstrap_addrs {
    builder = builder.known_peer(addr);
}
let config = builder.build()?;
let endpoint = P2pEndpoint::new(config).await?;
endpoint.connect_bootstrap().await?;
```

#### Pattern 3: Custom PQC Configuration

```rust
// BEFORE
let pqc = PqcConfig::builder()
    .mode(PqcMode::Hybrid)
    .hybrid_preference(HybridPreference::PreferPqc)
    .migration_period_days(30)
    .fallback_enabled(false)
    .build();

let config = Config::default().with_pqc_config(pqc);

// AFTER
let pqc = PqcConfig::builder()
    .ml_kem(true)
    .ml_dsa(true)
    .handshake_timeout_multiplier(1.5)
    .build()?;

let config = P2pConfig::builder()
    .pqc(pqc)
    .build()?;
```

#### Pattern 4: Conditional PQC (No Longer Possible)

```rust
// BEFORE - This pattern is NOT possible in v0.13.0+
fn create_config(enable_pqc: bool) -> Config {
    let mode = if enable_pqc {
        PqcMode::Hybrid
    } else {
        PqcMode::Disabled
    };
    Config::default().with_pqc_mode(mode)
}

// AFTER - PQC is always enabled
fn create_config() -> Result<P2pConfig> {
    P2pConfig::builder().build()
}
```

## Network-Wide Migration

### Coordinated Upgrade Strategy

Because v0.13.0 nodes cannot communicate with pre-v0.13.0 nodes that have PQC disabled:

1. **Audit**: Identify all nodes in your network
2. **Schedule**: Plan a maintenance window
3. **Upgrade All**: Update all nodes simultaneously
4. **Verify**: Test connectivity between all nodes

### Migration Timeline

```
Hour 0:     Begin maintenance window
Hour 0-1:   Upgrade all nodes to v0.13.0
Hour 1-2:   Restart all nodes
Hour 2-3:   Verify full network connectivity
Hour 3:     End maintenance window
```

### For Networks with Mixed Versions

If you cannot upgrade all nodes at once, there is **no migration path**. Options:

1. **Upgrade All**: The recommended approach
2. **Parallel Networks**: Run v0.12.x and v0.13.0 networks separately
3. **Gateway**: Custom bridge between networks (not recommended)

## Troubleshooting

### Build Errors

#### Error: `PqcMode` not found

```
error[E0433]: failed to resolve: use of undeclared type `PqcMode`
```

**Fix**: Remove all `PqcMode` usage. PQC is now always enabled.

#### Error: `with_pqc_mode` not found

```
error[E0599]: no method named `with_pqc_mode` found
```

**Fix**: Use `P2pConfig::builder()` instead of the old `Config` API.

### Runtime Errors

#### Connection Failures to Old Nodes

```
Error: PQC handshake failed: peer does not support PQC
```

**Fix**: Upgrade the peer to v0.13.0+.

#### Handshake Timeouts

```
Error: Connection timeout during PQC handshake
```

**Fix**: Increase timeout multiplier:
```rust
let pqc = PqcConfig::builder()
    .handshake_timeout_multiplier(2.0)
    .build()?;
```

## Monitoring and Validation

### Key Metrics to Monitor

After migration, verify:

1. **Connection Success Rate**
   ```bash
   # Should be > 99%
   grep "connection established" /var/log/ant-quic.log | wc -l
   ```

2. **Handshake Times**
   ```bash
   # Look for PQC timing
   RUST_LOG=ant_quic::crypto::pqc::performance=info ./ant-quic
   ```

3. **Memory Usage**
   ```bash
   # Monitor for increases
   ps aux | grep ant-quic
   ```

### Success Criteria

Migration is complete when:

- [ ] All nodes running v0.13.0+
- [ ] 100% connection success rate
- [ ] No PQC-related errors in logs
- [ ] Performance within acceptable bounds (~8% overhead)
- [ ] All tests passing

### Validation Commands

```bash
# Verify version
./ant-quic --version

# Check PQC is active
RUST_LOG=ant_quic::crypto::pqc=info ./ant-quic 2>&1 | grep -i "pqc\|ml-kem\|ml-dsa"

# Test connection
./ant-quic --known-peer peer.example.com:9000 --test-connection
```

## Additional Resources

- [PQC Configuration Guide](./pqc-configuration.md) - Detailed configuration options
- [PQC Security Guide](./pqc-security.md) - Security considerations
- [CHANGELOG](../../CHANGELOG.md) - Full v0.13.0 release notes
- [API Guide](../API_GUIDE.md) - Complete API reference

## Support

For migration support:
- GitHub Issues: [ant-quic/issues](https://github.com/dirvine/ant-quic/issues)
- Documentation: [docs.autonomi.org](https://docs.autonomi.org)

Remember: The move to always-on PQC is essential for long-term security. The short-term migration effort protects your network for decades to come.
