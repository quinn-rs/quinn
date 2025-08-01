//! Example demonstrating ML-KEM-768 usage with aws-lc-rs
//!
//! This example shows how the ML-KEM implementation works around the lack of
//! direct private key serialization in aws-lc-rs by using an in-memory cache.

use ant_quic::crypto::pqc::{MlKemOperations, ml_kem_impl::MlKem768Impl};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("ML-KEM-768 Example\n");

    // Create ML-KEM instance
    let ml_kem = MlKem768Impl::new();

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
    println!("   aws-lc-rs doesn't expose raw private key serialization for ML-KEM.");
    println!("   This implementation uses an in-memory cache to store DecapsulationKey");
    println!("   objects, indexed by the public key bytes.");
    println!("   For production use, consider implementing proper key storage using");
    println!("   PKCS#8 encoding or a secure key management system.");

    Ok(())
}
