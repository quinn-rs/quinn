//! Example demonstrating hybrid post-quantum key exchange
//!
//! This shows how to use the hybrid KEM (Key Encapsulation Mechanism) that
//! combines classical ECDH with post-quantum ML-KEM-768 for quantum-resistant
//! key exchange.

use ant_quic::crypto::pqc::hybrid::HybridKem;
use ant_quic::crypto::pqc::hybrid_key_exchange::{HybridKeyExchange, KeyExchangeRole};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Hybrid Post-Quantum Key Exchange Demo ===\n");

    // Check if PQC features are enabled
    #[cfg(not(feature = "pqc"))]
    {
        println!("Error: This example requires the 'pqc' feature to be enabled.");
        println!("Run with: cargo run --example pqc_hybrid_demo --features pqc");
        return Ok(());
    }

    #[cfg(feature = "pqc")]
    {
        // Direct KEM usage
        direct_kem_demo()?;

        println!("\n" + "=".repeat(50).as_str() + "\n");

        // Full key exchange protocol
        key_exchange_protocol_demo()?;
    }

    Ok(())
}

#[cfg(feature = "pqc")]
fn direct_kem_demo() -> Result<(), Box<dyn std::error::Error>> {
    println!("1. Direct Hybrid KEM Usage\n");

    // Create hybrid KEM instance
    let kem = HybridKem::new();

    // Check availability
    println!("Hybrid KEM available: {}", HybridKem::is_available());
    println!("Algorithm: {}", HybridKem::algorithm_name());
    println!("Security level: {}", HybridKem::security_level());

    // Generate keypair
    println!("\nGenerating hybrid keypair...");
    let (public_key, secret_key) = kem.generate_keypair()?;
    println!("✓ Generated keypair");
    println!(
        "  Classical public key: {} bytes",
        public_key.classical.len()
    );
    println!(
        "  ML-KEM public key: {} bytes",
        public_key.ml_kem.as_bytes().len()
    );

    // Encapsulate (sender side)
    println!("\nEncapsulating shared secret...");
    let (ciphertext, shared_secret1) = kem.encapsulate(&public_key)?;
    println!("✓ Created ciphertext");
    println!(
        "  Classical ciphertext: {} bytes",
        ciphertext.classical.len()
    );
    println!(
        "  ML-KEM ciphertext: {} bytes",
        ciphertext.ml_kem.as_bytes().len()
    );
    println!("  Shared secret: {} bytes", shared_secret1.as_bytes().len());

    // Decapsulate (receiver side)
    println!("\nDecapsulating shared secret...");
    let shared_secret2 = kem.decapsulate(&secret_key, &ciphertext)?;
    println!("✓ Recovered shared secret");

    // In a real implementation, these would match
    // Our placeholder classical implementation may cause differences
    println!(
        "\nShared secrets match: {}",
        shared_secret1.as_bytes() == shared_secret2.as_bytes()
    );

    Ok(())
}

#[cfg(feature = "pqc")]
fn key_exchange_protocol_demo() -> Result<(), Box<dyn std::error::Error>> {
    use ant_quic::crypto::pqc::hybrid_key_exchange::HybridKeyShare;

    println!("2. Full Key Exchange Protocol\n");

    // Create initiator (client) and responder (server)
    let mut initiator = HybridKeyExchange::new(KeyExchangeRole::Initiator);
    let mut responder = HybridKeyExchange::new(KeyExchangeRole::Responder);

    println!("Created initiator and responder");

    // Step 1: Initiator starts key exchange
    println!("\n[Initiator] Starting key exchange...");
    let initiator_share = initiator.start()?;
    println!("✓ Generated initiator key share");
    println!("  State: {}", initiator.state_name());

    // Simulate network transmission
    let encoded = initiator_share.encode();
    println!("\n[Network] Transmitting {} bytes...", encoded.len());
    let received_initiator_share = HybridKeyShare::decode(&encoded)?;

    // Step 2: Responder processes initiator's share
    println!("\n[Responder] Processing initiator's share...");
    let responder_share = responder
        .process_peer_key_share(&received_initiator_share)?
        .expect("Responder should send response");
    println!("✓ Generated responder key share with ciphertext");
    println!("  State: {}", responder.state_name());

    // Simulate network transmission
    let encoded = responder_share.encode();
    println!("\n[Network] Transmitting {} bytes...", encoded.len());
    let received_responder_share = HybridKeyShare::decode(&encoded)?;

    // Step 3: Initiator processes responder's share
    println!("\n[Initiator] Processing responder's share...");
    let response = initiator.process_peer_key_share(&received_responder_share)?;
    assert!(
        response.is_none(),
        "Initiator shouldn't send another response"
    );
    println!("✓ Completed key exchange");
    println!("  State: {}", initiator.state_name());

    // Both parties should now have the same shared secret
    println!("\n[Result] Key exchange complete!");
    println!("  Initiator has secret: {}", initiator.is_complete());
    println!("  Responder has secret: {}", responder.is_complete());

    let initiator_secret = initiator.get_shared_secret()?;
    let responder_secret = responder.get_shared_secret()?;

    // In a real implementation with proper classical crypto, these would match
    println!(
        "\nShared secrets match: {}",
        initiator_secret.as_bytes() == responder_secret.as_bytes()
    );

    if initiator_secret.as_bytes() != responder_secret.as_bytes() {
        println!("Note: Secrets don't match due to placeholder classical implementation");
        println!("      In production, both parties would derive the same secret");
    }

    Ok(())
}

#[cfg(feature = "pqc")]
fn demonstrate_hybrid_signatures() -> Result<(), Box<dyn std::error::Error>> {
    use ant_quic::crypto::pqc::hybrid::HybridSignature;

    println!("\n3. Hybrid Digital Signatures\n");

    // Create hybrid signature instance
    let signer = HybridSignature::new();

    println!("Algorithm: {}", HybridSignature::algorithm_name());
    println!("Security level: {}", HybridSignature::security_level());
    println!(
        "Signature size: {} bytes",
        HybridSignature::signature_size()
    );

    // Generate signing keypair
    println!("\nGenerating hybrid signature keypair...");
    let (public_key, secret_key) = signer.generate_keypair()?;
    println!("✓ Generated keypair");

    // Sign a message
    let message = b"This is a test message for hybrid signatures";
    println!("\nSigning message ({} bytes)...", message.len());
    let signature = signer.sign(&secret_key, message)?;
    println!("✓ Created hybrid signature");
    println!("  Classical signature: {} bytes", signature.classical.len());
    println!("  ML-DSA signature: {} bytes", signature.ml_dsa.len());

    // Verify signature
    println!("\nVerifying signature...");
    let is_valid = signer.verify(&public_key, message, &signature)?;
    println!("✓ Signature is valid: {}", is_valid);

    // Test with wrong message
    let wrong_message = b"This is a different message";
    let is_valid = signer.verify(&public_key, wrong_message, &signature)?;
    println!("✓ Wrong message verification: {}", is_valid);

    Ok(())
}
