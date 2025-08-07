//! Example demonstrating Post-Quantum Cryptography configuration
//!
//! This example shows various ways to configure PQC support in ant-quic,
//! from conservative migration strategies to aggressive PQC-only deployments.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Post-Quantum Cryptography Configuration Demo ===\n");

    // Check if PQC features are enabled
    #[cfg(not(feature = "pqc"))]
    {
        println!("Error: This example requires the 'pqc' feature to be enabled.");
        println!("Run with: cargo run --example pqc_config_demo --features pqc");
        return Ok(());
    }

    #[cfg(feature = "pqc")]
    {
        run_pqc_config_demo()
    }
}

#[cfg(feature = "pqc")]
use ant_quic::crypto::pqc::{HybridPreference, PqcConfig, PqcMode};
#[cfg(feature = "pqc")]
use ant_quic::{
    EndpointConfig,
    crypto::{CryptoError, HmacKey},
};
#[cfg(feature = "pqc")]
use std::error::Error;
#[cfg(feature = "pqc")]
use std::sync::Arc;

#[cfg(feature = "pqc")]
/// Dummy HMAC key for example
struct ExampleHmacKey;

#[cfg(feature = "pqc")]
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

#[cfg(feature = "pqc")]
fn run_pqc_config_demo() -> Result<(), Box<dyn Error>> {
    println!("=== Post-Quantum Cryptography Configuration Examples ===\n");

    // Example 1: Default configuration (recommended for most users)
    default_configuration()?;

    // Example 2: Conservative migration approach
    conservative_migration()?;

    // Example 3: Aggressive PQC adoption
    aggressive_pqc()?;

    // Example 4: PQC-only for testing
    pqc_only_testing()?;

    // Example 5: Performance-optimized configuration
    performance_optimized()?;

    // Example 6: Custom hybrid preferences
    custom_hybrid_preferences()?;

    Ok(())
}

#[cfg(feature = "pqc")]
fn default_configuration() -> Result<(), Box<dyn Error>> {
    println!("1. Default Configuration (Recommended)");
    println!("   - Hybrid mode with balanced preferences");
    println!("   - Suitable for most deployments\n");

    // Use default PQC config
    let pqc_config = PqcConfig::default();

    // Create endpoint with PQC support
    let reset_key: Arc<dyn HmacKey> = Arc::new(ExampleHmacKey);
    let mut endpoint_config = EndpointConfig::new(reset_key);
    endpoint_config.pqc_config(pqc_config);

    println!("   Default config: {:?}\n", PqcConfig::default());

    Ok(())
}

#[cfg(feature = "pqc")]
fn conservative_migration() -> Result<(), Box<dyn Error>> {
    println!("2. Conservative Migration");
    println!("   - Hybrid mode preferring classical algorithms");
    println!("   - Good for gradual PQC adoption\n");

    let pqc_config = PqcConfig::builder()
        .mode(PqcMode::Hybrid)
        .hybrid_preference(HybridPreference::PreferClassical)
        .handshake_timeout_multiplier(3.0) // Allow extra time for PQC
        .build()?;

    let reset_key: Arc<dyn HmacKey> = Arc::new(ExampleHmacKey);
    let mut endpoint_config = EndpointConfig::new(reset_key);
    endpoint_config.pqc_config(pqc_config.clone());

    println!("   Mode: {:?}", pqc_config.mode);
    println!("   Preference: {:?}", pqc_config.hybrid_preference);
    println!(
        "   Timeout multiplier: {}\n",
        pqc_config.handshake_timeout_multiplier
    );

    Ok(())
}

#[cfg(feature = "pqc")]
fn aggressive_pqc() -> Result<(), Box<dyn Error>> {
    println!("3. Aggressive PQC Adoption");
    println!("   - Hybrid mode preferring PQC algorithms");
    println!("   - For organizations prioritizing quantum resistance\n");

    let pqc_config = PqcConfig::builder()
        .mode(PqcMode::Hybrid)
        .hybrid_preference(HybridPreference::PreferPqc)
        .memory_pool_size(50) // Larger pool for PQC operations
        .handshake_timeout_multiplier(2.5)
        .build()?;

    let reset_key: Arc<dyn HmacKey> = Arc::new(ExampleHmacKey);
    let mut endpoint_config = EndpointConfig::new(reset_key);
    endpoint_config.pqc_config(pqc_config.clone());

    println!("   Mode: {:?}", pqc_config.mode);
    println!("   Preference: {:?}", pqc_config.hybrid_preference);
    println!("   Memory pool size: {}\n", pqc_config.memory_pool_size);

    Ok(())
}

#[cfg(feature = "pqc")]
fn pqc_only_testing() -> Result<(), Box<dyn Error>> {
    println!("4. PQC-Only Testing Configuration");
    println!("   - Requires PQC algorithms only");
    println!("   - Useful for testing quantum-safe deployments\n");

    let pqc_config = PqcConfig::builder()
        .mode(PqcMode::PqcOnly)
        .ml_kem(true)
        .ml_dsa(true)
        .memory_pool_size(20)
        .handshake_timeout_multiplier(4.0) // PQC handshakes are larger
        .build()?;

    let reset_key: Arc<dyn HmacKey> = Arc::new(ExampleHmacKey);
    let mut endpoint_config = EndpointConfig::new(reset_key);
    endpoint_config.pqc_config(pqc_config.clone());

    println!("   Mode: {:?}", pqc_config.mode);
    println!("   ML-KEM enabled: {}", pqc_config.ml_kem_enabled);
    println!("   ML-DSA enabled: {}", pqc_config.ml_dsa_enabled);
    println!("   This configuration will reject non-PQC connections\n");

    Ok(())
}

#[cfg(feature = "pqc")]
fn performance_optimized() -> Result<(), Box<dyn Error>> {
    println!("5. Performance-Optimized Configuration");
    println!("   - Tuned for high-throughput environments");
    println!("   - Larger memory pools and adjusted timeouts\n");

    let pqc_config = PqcConfig::builder()
        .mode(PqcMode::Hybrid)
        .hybrid_preference(HybridPreference::Balanced)
        .memory_pool_size(100) // Large pool for many concurrent connections
        .handshake_timeout_multiplier(1.5) // Tighter timeout for performance
        .build()?;

    let reset_key: Arc<dyn HmacKey> = Arc::new(ExampleHmacKey);
    let mut endpoint_config = EndpointConfig::new(reset_key);
    endpoint_config.pqc_config(pqc_config.clone());

    println!("   Memory pool size: {}", pqc_config.memory_pool_size);
    println!(
        "   Timeout multiplier: {}",
        pqc_config.handshake_timeout_multiplier
    );
    println!(
        "   Optimized for {} concurrent PQC operations\n",
        pqc_config.memory_pool_size
    );

    Ok(())
}

#[cfg(feature = "pqc")]
fn custom_hybrid_preferences() -> Result<(), Box<dyn Error>> {
    println!("6. Custom Hybrid Preferences");
    println!("   - Fine-grained control over algorithm selection\n");

    // Example: Use PQC for key exchange but classical for signatures
    let pqc_config = PqcConfig::builder()
        .mode(PqcMode::Hybrid)
        .ml_kem(true) // Enable PQC key encapsulation
        .ml_dsa(false) // Disable PQC signatures (use classical)
        .hybrid_preference(HybridPreference::Balanced)
        .build()?;

    let reset_key: Arc<dyn HmacKey> = Arc::new(ExampleHmacKey);
    let mut endpoint_config = EndpointConfig::new(reset_key);
    endpoint_config.pqc_config(pqc_config.clone());

    println!("   ML-KEM (key exchange): {}", pqc_config.ml_kem_enabled);
    println!("   ML-DSA (signatures): {}", pqc_config.ml_dsa_enabled);
    println!("   This uses PQC for confidentiality but classical for authentication\n");

    Ok(())
}

#[cfg(all(test, feature = "pqc"))]
mod tests {
    use super::*;

    #[test]
    fn test_all_examples_compile() {
        assert!(default_configuration().is_ok());
        assert!(conservative_migration().is_ok());
        assert!(aggressive_pqc().is_ok());
        assert!(pqc_only_testing().is_ok());
        assert!(performance_optimized().is_ok());
        assert!(custom_hybrid_preferences().is_ok());
    }
}
