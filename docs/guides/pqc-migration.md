# Post-Quantum Cryptography Migration Guide

This guide provides a comprehensive roadmap for migrating your ant-quic applications to use Post-Quantum Cryptography.

## Table of Contents

1. [Migration Overview](#migration-overview)
2. [Pre-Migration Checklist](#pre-migration-checklist)
3. [Migration Phases](#migration-phases)
4. [Step-by-Step Instructions](#step-by-step-instructions)
5. [Troubleshooting](#troubleshooting)
6. [Rollback Procedures](#rollback-procedures)
7. [Monitoring and Validation](#monitoring-and-validation)

## Migration Overview

### Why Migrate?

- **Quantum Threat**: Quantum computers pose a future threat to current cryptography
- **Compliance**: Meeting regulatory requirements for quantum-safe cryptography
- **Future-Proofing**: Protecting data harvested today from future decryption
- **Best Practice**: Industry moving towards PQC adoption

### Migration Timeline

Typical migration timeline for production systems:

```
Week 1-2:   Assessment and Planning
Week 3-4:   Development Environment Testing
Week 5-8:   Staging Environment Rollout
Week 9-12:  Production Rollout (Phased)
Week 13-16: Monitoring and Optimization
```

## Pre-Migration Checklist

Before starting migration, ensure:

- [ ] Current ant-quic version >= 0.5.0
- [ ] All dependencies support PQC or have upgrade paths
- [ ] Performance testing environment available
- [ ] Rollback plan documented
- [ ] Monitoring infrastructure ready
- [ ] Team trained on PQC concepts

## Migration Phases

### Phase 1: Assessment (Weeks 1-2)

1. **Inventory Current Usage**
   ```bash
   # Find all QUIC connection points
   grep -r "QuicP2PNode\|Endpoint" src/
   ```

2. **Identify Dependencies**
   ```bash
   # Check for version constraints
   cargo tree | grep -i quic
   ```

3. **Performance Baseline**
   ```rust
   // Measure current performance
   let start = Instant::now();
   let connection = node.connect(addr).await?;
   let baseline_handshake = start.elapsed();
   ```

### Phase 2: Development Testing (Weeks 3-4)

1. **Enable PQC in Development**
   ```rust
   // Start with logging only
   let config = Config::default()
       .with_pqc_mode(PqcMode::Disabled)
       .with_pqc_logging(true);
   ```

2. **Test Compatibility**
   ```rust
   #[cfg(test)]
   mod pqc_tests {
       #[test]
       fn test_pqc_handshake() {
           // Test both PQC and non-PQC connections
       }
   }
   ```

### Phase 3: Staging Rollout (Weeks 5-8)

1. **Gradual Enablement**
   ```rust
   // Week 5-6: Optional PQC
   let config = PqcConfig::builder()
       .mode(PqcMode::Hybrid)
       .hybrid_preference(HybridPreference::PreferClassical)
       .build();
   
   // Week 7-8: Prefer PQC
   let config = PqcConfig::builder()
       .mode(PqcMode::Hybrid)
       .hybrid_preference(HybridPreference::PreferPqc)
       .build();
   ```

### Phase 4: Production Rollout (Weeks 9-12)

1. **Canary Deployment**
   ```rust
   // Enable for subset of nodes
   fn should_enable_pqc(node_id: &str) -> bool {
       // Start with 10% of nodes
       hash(node_id) % 10 == 0
   }
   ```

2. **Progressive Rollout**
   ```rust
   // Increase percentage weekly
   Week 9:  10% of connections
   Week 10: 25% of connections
   Week 11: 50% of connections
   Week 12: 100% of connections
   ```

## Step-by-Step Instructions

### Step 1: Update Dependencies

```toml
# Cargo.toml
[dependencies]
ant-quic = "0.5.0"  # Minimum version with PQC support
```

### Step 2: Modify Connection Code

**Before:**
```rust
use ant_quic::QuicP2PNode;

let node = QuicP2PNode::new(addr).await?;
```

**After:**
```rust
use ant_quic::{QuicP2PNode, Config};
use ant_quic::crypto::pqc::{PqcMode, PqcConfig};

let pqc_config = PqcConfig::default();  // Hybrid mode
let config = Config::default()
    .with_pqc_config(pqc_config);

let node = QuicP2PNode::with_config(config).await?;
```

### Step 3: Update Client Configuration

```rust
// Client with PQC support
impl MyClient {
    pub fn new_with_pqc() -> Result<Self> {
        let config = ClientConfig::builder()
            .with_pqc_mode(PqcMode::Hybrid)
            .build()?;
            
        Ok(Self { config })
    }
}
```

### Step 4: Update Server Configuration

```rust
// Server accepting both PQC and non-PQC
impl MyServer {
    pub fn new_with_pqc() -> Result<Self> {
        let config = ServerConfig::builder()
            .with_pqc_mode(PqcMode::Hybrid)
            .with_fallback_enabled(true)
            .build()?;
            
        Ok(Self { config })
    }
}
```

### Step 5: Add Monitoring

```rust
// Monitor PQC usage
#[derive(Default)]
struct PqcMetrics {
    total_connections: AtomicU64,
    pqc_connections: AtomicU64,
    classical_connections: AtomicU64,
    handshake_times: RwLock<Vec<Duration>>,
}

impl PqcMetrics {
    fn record_connection(&self, is_pqc: bool, handshake_time: Duration) {
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        
        if is_pqc {
            self.pqc_connections.fetch_add(1, Ordering::Relaxed);
        } else {
            self.classical_connections.fetch_add(1, Ordering::Relaxed);
        }
        
        self.handshake_times.write().unwrap().push(handshake_time);
    }
}
```

## Troubleshooting

### Common Issues and Solutions

#### 1. Connection Failures

**Symptom**: Connections fail after enabling PQC

**Solution**:
```rust
// Enable fallback
let config = PqcConfig::builder()
    .mode(PqcMode::Hybrid)
    .fallback_enabled(true)
    .build();
```

#### 2. Performance Degradation

**Symptom**: Handshake times increase significantly

**Solutions**:
```rust
// 1. Use connection pooling
let config = Config::default()
    .with_connection_pool_size(100);

// 2. Enable hardware acceleration
let config = PqcConfig::builder()
    .with_hardware_accel(true)
    .build();

// 3. Tune cache sizes
let config = PqcConfig::builder()
    .max_cached_keys(2000)
    .build();
```

#### 3. Memory Issues

**Symptom**: Increased memory usage

**Solution**:
```rust
// Reduce key cache
let config = PqcConfig::builder()
    .max_cached_keys(500)
    .key_cache_ttl(Duration::from_secs(1800))
    .build();
```

#### 4. Compatibility Issues

**Symptom**: Legacy clients cannot connect

**Solution**:
```rust
// Maintain compatibility period
let config = PqcConfig::builder()
    .mode(PqcMode::Hybrid)
    .migration_period_days(90)
    .compatibility_warnings(true)
    .build();
```

### Debug Commands

```bash
# Enable detailed PQC logging
RUST_LOG=ant_quic::crypto::pqc=debug cargo run

# Trace handshake details
RUST_LOG=ant_quic::crypto::pqc::negotiation=trace cargo run

# Monitor performance
RUST_LOG=ant_quic::crypto::pqc::performance=info cargo run
```

## Rollback Procedures

### Emergency Rollback

If critical issues arise:

1. **Immediate Rollback**
   ```rust
   // Disable PQC globally
   let config = PqcConfig::disabled();
   ```

2. **Gradual Rollback**
   ```rust
   // Reduce PQC usage progressively
   let config = PqcConfig::builder()
       .mode(PqcMode::Hybrid)
       .hybrid_preference(HybridPreference::PreferClassical)
       .pqc_probability(0.1)  // Only 10% use PQC
       .build();
   ```

### Rollback Checklist

- [ ] Document issue encountered
- [ ] Capture metrics before rollback
- [ ] Update configuration
- [ ] Verify connectivity restored
- [ ] Notify stakeholders
- [ ] Plan remediation

## Monitoring and Validation

### Key Metrics to Monitor

1. **Connection Success Rate**
   ```rust
   let success_rate = (successful_connections as f64 / total_attempts as f64) * 100.0;
   assert\!(success_rate > 99.0, "Success rate below threshold");
   ```

2. **Handshake Performance**
   ```rust
   let avg_handshake_time = handshake_times.iter().sum::<Duration>() / handshake_times.len() as u32;
   assert\!(avg_handshake_time < Duration::from_millis(150), "Handshake too slow");
   ```

3. **PQC Adoption Rate**
   ```rust
   let pqc_rate = (pqc_connections as f64 / total_connections as f64) * 100.0;
   info\!("PQC adoption: {:.1}%", pqc_rate);
   ```

### Validation Tests

```rust
#[cfg(test)]
mod migration_validation {
    #[test]
    fn validate_pqc_compatibility() {
        // Test PQC client → non-PQC server
        // Test non-PQC client → PQC server
        // Test PQC client → PQC server
    }
    
    #[test]
    fn validate_performance_targets() {
        // Ensure < 10% overhead
        // Ensure memory usage acceptable
    }
}
```

### Success Criteria

Migration is complete when:
- ✅ 100% of connections support PQC
- ✅ Performance overhead < 10%
- ✅ Zero PQC-related failures in 7 days
- ✅ All monitoring alerts configured
- ✅ Team trained on PQC operations

## Additional Resources

- [PQC Configuration Guide](./pqc-configuration.md)
- [PQC Security Considerations](./pqc-security.md)
- [Example: pqc_migration_demo.rs](../../examples/pqc_migration_demo.rs)
- [NIST PQC Standards](https://csrc.nist.gov/projects/post-quantum-cryptography)

## Support

For migration support:
- GitHub Issues: [ant-quic/issues](https://github.com/dirvine/ant-quic/issues)
- Documentation: [docs.autonomi.org](https://docs.autonomi.org)
- Community: [Discord/Forum]

Remember: Migration to PQC is a journey, not a destination. Plan carefully, test thoroughly, and monitor continuously.
ENDFILE < /dev/null