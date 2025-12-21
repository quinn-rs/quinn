//! Example demonstrating ML-KEM-768 usage with saorsa-pqc
//!
//! v0.2: Updated to use the simplified MlKem768 implementation backed by saorsa-pqc.

use ant_quic::crypto::pqc::{MlKem768, MlKemOperations};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== ML-KEM-768 Usage Example ===\n");

    // PQC is always enabled in ant-quic v0.12.0+
    run_ml_kem_demo()
}

fn run_ml_kem_demo() -> Result<(), Box<dyn std::error::Error>> {
    println!("ML-KEM-768 Example\n");

    // Create ML-KEM instance (v0.2: uses saorsa-pqc backend)
    let ml_kem = MlKem768::new();

    // Generate a keypair
    println!("1. Generating ML-KEM-768 keypair...");
    let (public_key, secret_key) = ml_kem.generate_keypair()?;
    println!(
        "   ✓ Public key size: {} bytes",
        public_key.as_bytes().len()
    );
    println!(
        "   ✓ Secret key size: {} bytes",
        secret_key.as_bytes().len()
    );

    // Demonstrate encapsulation (sender side)
    println!("\n2. Encapsulating shared secret...");
    let (ciphertext, shared_secret_sender) = ml_kem.encapsulate(&public_key)?;
    println!(
        "   ✓ Ciphertext size: {} bytes",
        ciphertext.as_bytes().len()
    );
    println!(
        "   ✓ Shared secret: {:?}",
        &shared_secret_sender.as_bytes()[..8]
    );

    // Demonstrate decapsulation (receiver side)
    println!("\n3. Decapsulating shared secret...");
    let shared_secret_receiver = ml_kem.decapsulate(&secret_key, &ciphertext)?;
    println!(
        "   ✓ Shared secret: {:?}",
        &shared_secret_receiver.as_bytes()[..8]
    );

    // Verify shared secrets match
    println!("\n4. Verifying shared secrets match...");
    if shared_secret_sender.as_bytes() == shared_secret_receiver.as_bytes() {
        println!("   ✓ Success! Shared secrets match");
    } else {
        println!("   ✗ Error: Shared secrets don't match");
        return Err("Key exchange failed".into());
    }

    // Note about the implementation
    println!("\n📝 Implementation Note:");
    println!("   v0.2: ML-KEM-768 is now backed by saorsa-pqc which provides");
    println!("   a clean FIPS 203 implementation with proper key serialization.");
    println!("   This is used in TLS 1.3 key exchange for post-quantum security.");

    Ok(())
}
