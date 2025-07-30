//! Comprehensive security validation tests for PQC implementation

use ant_quic::crypto::pqc::{
    ml_dsa::{MlDsa, MlDsa65PublicKey, MlDsa65SecretKey, SecurityLevel as DsaSecurityLevel},
    ml_kem::{MlKem, MlKem768PublicKey, MlKem768SecretKey, SecurityLevel},
    security_validation::{EntropyQuality, SecurityValidator, Severity, run_security_validation},
    types::{PqcAlgorithm, PqcKeyPair},
};
use std::time::{Duration, Instant};

#[test]
fn test_basic_security_validation() {
    let report = run_security_validation();

    // Basic sanity checks
    assert!(report.security_score <= 100);
    assert!(report.nist_compliance.parameters_valid);
}

#[test]
fn test_timing_side_channel_ml_kem() {
    // Test that ML-KEM operations have consistent timing
    const ITERATIONS: usize = 100;
    let mut timings = Vec::new();

    for _ in 0..ITERATIONS {
        let ml_kem = MlKem::new(SecurityLevel::Level3);
        let (public_key, secret_key) = ml_kem.generate_keypair().unwrap();

        let start = Instant::now();
        // Perform encapsulation
        let (ciphertext, shared_secret1) = public_key.encapsulate();
        timings.push(start.elapsed());
    }

    // Calculate timing variance
    let mean = timings.iter().map(|d| d.as_nanos() as f64).sum::<f64>() / ITERATIONS as f64;
    let variance = timings
        .iter()
        .map(|d| {
            let diff = d.as_nanos() as f64 - mean;
            diff * diff
        })
        .sum::<f64>()
        / ITERATIONS as f64;

    let cv = (variance.sqrt() / mean) * 100.0;

    // Timing should be relatively consistent (< 10% CV)
    assert!(cv < 10.0, "ML-KEM timing variance too high: {:.2}%", cv);
}

#[test]
fn test_timing_side_channel_ml_dsa() {
    // Test that ML-DSA operations have consistent timing
    const ITERATIONS: usize = 100;
    let mut timings = Vec::new();

    let ml_dsa = MlDsa::new(DsaSecurityLevel::Level3);
    let (public_key, secret_key) = ml_dsa.generate_keypair().unwrap();
    let message = b"test message for signing";

    for _ in 0..ITERATIONS {
        let start = Instant::now();
        // Perform signing
        let signature = secret_key.sign(message);
        timings.push(start.elapsed());
    }

    // Calculate timing variance
    let mean = timings.iter().map(|d| d.as_nanos() as f64).sum::<f64>() / ITERATIONS as f64;
    let variance = timings
        .iter()
        .map(|d| {
            let diff = d.as_nanos() as f64 - mean;
            diff * diff
        })
        .sum::<f64>()
        / ITERATIONS as f64;

    let cv = (variance.sqrt() / mean) * 100.0;

    // Timing should be relatively consistent (< 10% CV)
    assert!(cv < 10.0, "ML-DSA timing variance too high: {:.2}%", cv);
}

#[test]
fn test_deterministic_signatures() {
    // ML-DSA should produce deterministic signatures
    let ml_dsa = MlDsa::new(DsaSecurityLevel::Level3);
    let (public_key, secret_key) = ml_dsa.generate_keypair().unwrap();
    let message = b"deterministic test message";

    // Sign the same message multiple times
    let sig1 = secret_key.sign(message);
    let sig2 = secret_key.sign(message);
    let sig3 = secret_key.sign(message);

    // All signatures should be identical
    assert_eq!(sig1, sig2, "Signatures not deterministic");
    assert_eq!(sig2, sig3, "Signatures not deterministic");

    // Different messages should produce different signatures
    let different_message = b"different message";
    let sig4 = secret_key.sign(different_message);
    assert_ne!(sig1, sig4, "Different messages produced same signature");
}

#[test]
fn test_key_independence() {
    // Keys generated independently should be different
    let ml_kem = MlKem::new(SecurityLevel::Level3);
    let (pub1, sec1) = ml_kem.generate_keypair().unwrap();
    let (pub2, sec2) = ml_kem.generate_keypair().unwrap();

    // Public keys should be different
    assert_ne!(
        pub1.as_bytes(),
        pub2.as_bytes(),
        "Public keys not independent"
    );

    // Secret keys should be different
    // Note: We can't directly compare secret keys, but we can test their behavior
    let (cipher1, ss1) = pub1.encapsulate();
    let (cipher2, ss2) = pub2.encapsulate();

    // Ciphertexts and shared secrets should be different
    assert_ne!(cipher1, cipher2, "Ciphertexts not independent");
    assert_ne!(ss1, ss2, "Shared secrets not independent");
}

#[test]
fn test_ciphertext_randomization() {
    // Each encapsulation should produce different ciphertexts
    let ml_kem = MlKem::new(SecurityLevel::Level3);
    let (public_key, _) = ml_kem.generate_keypair().unwrap();

    let (cipher1, ss1) = public_key.encapsulate();
    let (cipher2, ss2) = public_key.encapsulate();
    let (cipher3, ss3) = public_key.encapsulate();

    // All ciphertexts should be different
    assert_ne!(cipher1, cipher2, "Ciphertexts not randomized");
    assert_ne!(cipher2, cipher3, "Ciphertexts not randomized");
    assert_ne!(cipher1, cipher3, "Ciphertexts not randomized");

    // All shared secrets should be different
    assert_ne!(ss1, ss2, "Shared secrets not randomized");
    assert_ne!(ss2, ss3, "Shared secrets not randomized");
    assert_ne!(ss1, ss3, "Shared secrets not randomized");
}

#[test]
fn test_invalid_ciphertext_handling() {
    let ml_kem = MlKem::new(SecurityLevel::Level3);
    let (public_key, secret_key) = ml_kem.generate_keypair().unwrap();

    // Create invalid ciphertext
    let mut invalid_cipher = vec![0u8; 1088]; // ML-KEM-768 ciphertext size
    invalid_cipher[0] = 0xFF; // Make it invalid

    // Decapsulation should not panic or leak timing information
    let start = Instant::now();
    let result = secret_key.decapsulate(&invalid_cipher);
    let invalid_time = start.elapsed();

    // Valid decapsulation for timing comparison
    let (valid_cipher, _) = public_key.encapsulate();
    let start = Instant::now();
    let _ = secret_key.decapsulate(&valid_cipher);
    let valid_time = start.elapsed();

    // Timing should be similar (within 50% to account for variance)
    let ratio = invalid_time.as_nanos() as f64 / valid_time.as_nanos() as f64;
    assert!(
        ratio > 0.5 && ratio < 1.5,
        "Timing difference too large for invalid ciphertext: {:.2}x",
        ratio
    );
}

#[test]
fn test_signature_malleability() {
    let ml_dsa = MlDsa::new(DsaSecurityLevel::Level3);
    let (public_key, secret_key) = ml_dsa.generate_keypair().unwrap();
    let message = b"test message";

    let signature = secret_key.sign(message);

    // Verify original signature
    assert!(public_key.verify(message, &signature).is_ok());

    // Modify signature slightly
    let mut modified_sig = signature.clone();
    modified_sig[0] ^= 0x01; // Flip one bit

    // Modified signature should fail verification
    assert!(public_key.verify(message, &modified_sig).is_err());

    // Test message modification
    let modified_message = b"test message!";
    assert!(public_key.verify(modified_message, &signature).is_err());
}

#[test]
fn test_key_serialization_consistency() {
    // Test that keys can be serialized and deserialized consistently
    let ml_kem = MlKem::new(SecurityLevel::Level3);
    let (pub_key, sec_key) = ml_kem.generate_keypair().unwrap();

    // Serialize and deserialize public key
    let pub_bytes = pub_key.as_bytes();
    let pub_key2 =
        MlKem768PublicKey::from_bytes(pub_bytes).expect("Failed to deserialize public key");

    // Test that deserialized key works the same
    let (cipher1, ss1) = pub_key.encapsulate();
    let (cipher2, ss2) = pub_key2.encapsulate();

    // Both keys should be able to decrypt each other's ciphertexts
    let decrypted1 = sec_key.decapsulate(&cipher2).unwrap();
    let decrypted2 = sec_key.decapsulate(&cipher1).unwrap();

    // The decapsulated values should match the encapsulated shared secrets
    assert_eq!(ss1, decrypted2);
    assert_eq!(ss2, decrypted1);
}

#[test]
fn test_memory_zeroing_simulation() {
    // Simulate checking if sensitive memory is zeroed
    // In real implementation, this would use memory inspection tools

    let sensitive_data = vec![0xAA; 32]; // Simulated key material
    let ptr = sensitive_data.as_ptr();

    // Drop the data
    drop(sensitive_data);

    // In a real test, we would check if the memory at ptr is zeroed
    // This is a placeholder for the actual implementation
    // Real implementation would use:
    // - Custom allocator with tracking
    // - Memory inspection after drop
    // - Verification that Drop trait zeroes memory
}

#[test]
fn test_security_validator_comprehensive() {
    let mut validator = SecurityValidator::new();
    let report = validator.validate_all();

    // Check all report sections
    assert!(report.nist_compliance.parameters_valid);
    assert!(report.side_channel.memory_zeroing);
    assert_ne!(report.randomness.entropy_quality, EntropyQuality::Critical);
    assert!(report.key_management.hybrid_security);

    // No critical issues in basic validation
    let critical_count = report
        .critical_issues
        .iter()
        .filter(|issue| issue.severity == Severity::Critical)
        .count();
    assert_eq!(
        critical_count, 0,
        "Found {} critical issues",
        critical_count
    );
}

#[test]
#[ignore] // Expensive test
fn test_statistical_randomness() {
    // Run basic statistical tests on random output
    const SAMPLE_SIZE: usize = 10000;
    let mut random_bytes = vec![0u8; SAMPLE_SIZE];

    // Generate random data from key generation
    let ml_kem = MlKem::new(SecurityLevel::Level3);
    for i in 0..100 {
        let (pub_key, _) = ml_kem.generate_keypair().unwrap();
        let bytes = pub_key.as_bytes();
        for (j, &byte) in bytes.iter().enumerate().take(100) {
            if i * 100 + j < SAMPLE_SIZE {
                random_bytes[i * 100 + j] = byte;
            }
        }
    }

    // Basic frequency test
    let mut bit_count = 0;
    for &byte in &random_bytes {
        bit_count += byte.count_ones() as usize;
    }
    let total_bits = SAMPLE_SIZE * 8;
    let ratio = bit_count as f64 / total_bits as f64;

    // Should be close to 0.5 (within 1%)
    assert!(
        (ratio - 0.5).abs() < 0.01,
        "Bit frequency test failed: {:.4} (expected ~0.5)",
        ratio
    );

    // Basic byte distribution test
    let mut byte_counts = [0u32; 256];
    for &byte in &random_bytes {
        byte_counts[byte as usize] += 1;
    }

    let expected = SAMPLE_SIZE as f64 / 256.0;
    let mut chi_square = 0.0;
    for count in &byte_counts {
        let diff = *count as f64 - expected;
        chi_square += (diff * diff) / expected;
    }

    // Chi-square test with 255 degrees of freedom
    // Critical value at 0.05 significance is ~293
    assert!(
        chi_square < 293.0,
        "Byte distribution test failed: chi-square = {:.2}",
        chi_square
    );
}

// Performance benchmarks for security-critical operations
#[test]
#[ignore] // Benchmark test
fn bench_constant_time_operations() {
    const ITERATIONS: usize = 1000;

    println!("\nConstant-time operation benchmarks:");

    // Benchmark ML-KEM encapsulation
    let ml_kem = MlKem::new(SecurityLevel::Level3);
    let (pub_key, _) = ml_kem.generate_keypair().unwrap();
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = pub_key.encapsulate();
    }
    let ml_kem_time = start.elapsed();
    println!(
        "ML-KEM encapsulation: {:.2} µs/op",
        ml_kem_time.as_micros() as f64 / ITERATIONS as f64
    );

    // Benchmark ML-DSA signing
    let ml_dsa = MlDsa::new(DsaSecurityLevel::Level3);
    let (_, sec_key) = ml_dsa.generate_keypair().unwrap();
    let message = b"benchmark message";
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = sec_key.sign(message);
    }
    let ml_dsa_time = start.elapsed();
    println!(
        "ML-DSA signing: {:.2} µs/op",
        ml_dsa_time.as_micros() as f64 / ITERATIONS as f64
    );
}
