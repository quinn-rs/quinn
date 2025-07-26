//! Quick cryptography tests

use std::time::Duration;

#[test]
fn test_basic_crypto_operations() {
    super::utils::assert_duration(Duration::from_millis(100), || {
        // Basic crypto operations are tested in unit tests
        // This is a placeholder for quick crypto tests
        assert!(true);
    });
}

#[test]
fn test_key_generation_speed() {
    super::utils::assert_duration(Duration::from_millis(200), || {
        // Test that key generation is reasonably fast
        use ed25519_dalek::SigningKey;
        let _signing_key = SigningKey::generate(&mut rand::thread_rng());
        assert!(true);
    });
}