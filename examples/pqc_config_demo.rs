//! Example demonstrating Post-Quantum Cryptography configuration
//!
//! v0.13.0+: PQC is always enabled (100% PQC, no classical crypto).
//! This example shows various ways to configure PQC parameters.

use ant_quic::crypto::pqc::PqcConfig;
use ant_quic::{
    EndpointConfig,
    crypto::{CryptoError, HmacKey},
};
use std::error::Error;
use std::sync::Arc;

/// Dummy HMAC key for example
struct ExampleHmacKey;

impl HmacKey for ExampleHmacKey {
    fn sign(&self, data: &[u8], out: &mut [u8]) {
        let len = out.len().min(data.len());
        out[..len].copy_from_slice(&data[..len]);
    }

    fn signature_len(&self) -> usize {
        32
    }

    fn verify(&self, _data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        // Dummy verification for example
        if signature.len() >= self.signature_len() {
            Ok(())
        } else {
            Err(CryptoError)
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("=== Post-Quantum Cryptography Configuration Demo ===\n");
    println!("v0.13.0+: PQC is always enabled - all connections use ML-KEM-768\n");

    // Example 1: Default configuration (recommended for most users)
    default_configuration()?;

    // Example 2: Custom memory pool size
    custom_memory_pool()?;

    // Example 3: Adjusted timeout for slow networks
    adjusted_timeout()?;

    // Example 4: Full configuration
    full_configuration()?;

    Ok(())
}

fn default_configuration() -> Result<(), Box<dyn Error>> {
    println!("1. Default Configuration (Recommended)");
    println!("   - ML-KEM-768 for key exchange");
    println!("   - ML-DSA-65 for signatures");
    println!("   - Suitable for most deployments\n");

    // Use default PQC config
    let pqc_config = PqcConfig::default();

    // Create endpoint with PQC support
    let reset_key: Arc<dyn HmacKey> = Arc::new(ExampleHmacKey);
    let mut endpoint_config = EndpointConfig::new(reset_key);
    endpoint_config.pqc_config(pqc_config);

    println!("   Default config: ML-KEM enabled, ML-DSA enabled\n");

    Ok(())
}

fn custom_memory_pool() -> Result<(), Box<dyn Error>> {
    println!("2. Custom Memory Pool Size");
    println!("   - Larger pool for high-concurrency environments");
    println!("   - Useful for servers handling many connections\n");

    let pqc_config = PqcConfig::builder()
        .ml_kem(true)
        .ml_dsa(true)
        .memory_pool_size(100) // Large pool for many concurrent connections
        .build()?;

    let reset_key: Arc<dyn HmacKey> = Arc::new(ExampleHmacKey);
    let mut endpoint_config = EndpointConfig::new(reset_key);
    endpoint_config.pqc_config(pqc_config.clone());

    println!("   Memory pool size: {}", pqc_config.memory_pool_size);
    println!(
        "   Optimized for {} concurrent PQC operations\n",
        pqc_config.memory_pool_size
    );

    Ok(())
}

fn adjusted_timeout() -> Result<(), Box<dyn Error>> {
    println!("3. Adjusted Timeout Configuration");
    println!("   - Increased timeout for slow or high-latency networks");
    println!("   - PQC handshakes are larger and may need more time\n");

    let pqc_config = PqcConfig::builder()
        .ml_kem(true)
        .ml_dsa(true)
        .handshake_timeout_multiplier(3.0) // Allow extra time for PQC
        .build()?;

    let reset_key: Arc<dyn HmacKey> = Arc::new(ExampleHmacKey);
    let mut endpoint_config = EndpointConfig::new(reset_key);
    endpoint_config.pqc_config(pqc_config.clone());

    println!(
        "   Timeout multiplier: {}x\n",
        pqc_config.handshake_timeout_multiplier
    );

    Ok(())
}

fn full_configuration() -> Result<(), Box<dyn Error>> {
    println!("4. Full Configuration Example");
    println!("   - All PQC parameters customized\n");

    let pqc_config = PqcConfig::builder()
        .ml_kem(true)
        .ml_dsa(true)
        .memory_pool_size(50)
        .handshake_timeout_multiplier(2.0)
        .build()?;

    let reset_key: Arc<dyn HmacKey> = Arc::new(ExampleHmacKey);
    let mut endpoint_config = EndpointConfig::new(reset_key);
    endpoint_config.pqc_config(pqc_config.clone());

    println!("   ML-KEM enabled: {}", pqc_config.ml_kem_enabled);
    println!("   ML-DSA enabled: {}", pqc_config.ml_dsa_enabled);
    println!("   Memory pool size: {}", pqc_config.memory_pool_size);
    println!(
        "   Timeout multiplier: {}\n",
        pqc_config.handshake_timeout_multiplier
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_examples_compile() {
        assert!(default_configuration().is_ok());
        assert!(custom_memory_pool().is_ok());
        assert!(adjusted_timeout().is_ok());
        assert!(full_configuration().is_ok());
    }
}
