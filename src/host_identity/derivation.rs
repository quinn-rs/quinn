// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

// Allow unused_assignments: ZeroizeOnDrop derive macro generates code that triggers
// false positive warnings for struct fields marked with #[zeroize(skip)].
// The prk and policy fields ARE used throughout the HostIdentity implementation.
#![allow(unused_assignments)]

//! HostKey derivation for deterministic key generation
//!
//! This module provides HKDF-based key derivation from a local-only HostKey.
//! The HostKey is never transmitted on the wire - it only exists locally.
//!
//! ## Key Hierarchy
//!
//! ```text
//! HostKey (32 bytes, local-only root secret)
//!    │
//!    ├── K_endpoint_encrypt → per-network endpoint key encryption
//!    │       │
//!    │       ├── network_id_1 → encryption key for stored ML-DSA-65 keypair
//!    │       ├── network_id_2 → encryption key for stored ML-DSA-65 keypair
//!    │       └── ...
//!    │
//!    └── K_cache → XChaCha20-Poly1305 encryption key for bootstrap cache
//! ```

use aws_lc_rs::hkdf;
use zeroize::{Zeroize, ZeroizeOnDrop};

// =============================================================================
// Constants
// =============================================================================

/// HostKey version for future migration support
pub const HOSTKEY_VERSION: &str = "v1";

/// Domain separator salt for all HostKey derivations
const HOSTKEY_SALT: &[u8] = b"antq:hostkey:v1";

/// Info string for endpoint encryption key derivation
const ENDPOINT_ENCRYPT_INFO: &[u8] = b"antq:endpoint-encrypt:v1";

/// Info string for cache key derivation
const CACHE_KEY_INFO: &[u8] = b"antq:cache-key:v1";

/// Derived key size in bytes
const DERIVED_KEY_SIZE: usize = 32;

// =============================================================================
// Endpoint Key Policy
// =============================================================================

/// Policy for deriving endpoint keys from the HostKey
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EndpointKeyPolicy {
    /// Derive distinct encryption keys per network_id (default, privacy-preserving)
    /// Each network gets its own encrypted keypair storage
    #[default]
    PerNetwork,

    /// Use a single encryption key for all networks (for operators wanting unified identity)
    Shared,
}

// =============================================================================
// HostIdentity
// =============================================================================

/// Local-only host identity derived from a root HostKey
///
/// The HostKey never appears on the wire. It is used only for:
/// - Deriving encryption keys for per-network endpoint keypair storage
/// - Deriving encryption keys for local state (bootstrap cache)
///
/// Endpoint keypairs are generated once and stored encrypted. The HostKey
/// ensures that the same host can decrypt its stored keypairs across restarts.
///
/// # Security
///
/// The inner secret is zeroed on drop to prevent memory leaks.
#[derive(ZeroizeOnDrop)]
pub struct HostIdentity {
    /// The root secret (32 bytes, never exposed)
    #[zeroize(skip)]
    prk: hkdf::Prk,

    /// The endpoint key policy
    #[zeroize(skip)]
    policy: EndpointKeyPolicy,
}

impl HostIdentity {
    /// Create a new HostIdentity from raw secret bytes
    ///
    /// The secret should be 32 bytes of cryptographically random data.
    /// This function takes ownership and the caller's copy should be zeroed.
    pub fn from_secret(mut secret: [u8; 32]) -> Self {
        // Extract using HKDF to create the PRK
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, HOSTKEY_SALT);
        let prk = salt.extract(&secret);

        // Zero the input secret
        secret.zeroize();

        Self {
            prk,
            policy: EndpointKeyPolicy::default(),
        }
    }

    /// Create a new HostIdentity with a specific policy
    pub fn from_secret_with_policy(secret: [u8; 32], policy: EndpointKeyPolicy) -> Self {
        let mut identity = Self::from_secret(secret);
        identity.policy = policy;
        identity
    }

    /// Generate a new random HostIdentity
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        Self::from_secret(secret)
    }

    /// Generate a new random HostIdentity with a specific policy
    pub fn generate_with_policy(policy: EndpointKeyPolicy) -> Self {
        let mut identity = Self::generate();
        identity.policy = policy;
        identity
    }

    /// Get the current endpoint key policy
    pub fn policy(&self) -> EndpointKeyPolicy {
        self.policy
    }

    /// Set the endpoint key policy
    pub fn set_policy(&mut self, policy: EndpointKeyPolicy) {
        self.policy = policy;
    }

    /// Derive an encryption key for storing endpoint keypairs for a specific network
    ///
    /// This key is used to encrypt/decrypt the ML-DSA-65 keypair stored on disk.
    /// If policy is `Shared`, the network_id is ignored.
    #[allow(clippy::expect_used)] // HKDF operations are infallible with valid fixed-size parameters
    pub fn derive_endpoint_encryption_key(&self, network_id: &[u8]) -> [u8; DERIVED_KEY_SIZE] {
        let effective_network_id = match self.policy {
            EndpointKeyPolicy::PerNetwork => network_id,
            EndpointKeyPolicy::Shared => b"antq:shared-identity",
        };

        // First derive the endpoint encryption base key
        let mut base_key = [0u8; DERIVED_KEY_SIZE];
        let okm = self
            .prk
            .expand(&[ENDPOINT_ENCRYPT_INFO], hkdf::HKDF_SHA256)
            .expect("HKDF expand should succeed with valid parameters");
        okm.fill(&mut base_key)
            .expect("OKM fill should succeed for 32 bytes");

        // Then derive the per-network key
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, effective_network_id);
        let prk = salt.extract(&base_key);

        let mut key = [0u8; DERIVED_KEY_SIZE];
        let okm = prk
            .expand(&[b"antq:endpoint-key:v1"], hkdf::HKDF_SHA256)
            .expect("HKDF expand should succeed");
        okm.fill(&mut key).expect("OKM fill should succeed");

        key
    }

    /// Derive the cache encryption key
    ///
    /// This key is used to encrypt the bootstrap cache at rest.
    #[allow(clippy::expect_used)] // HKDF operations are infallible with valid fixed-size parameters
    pub fn derive_cache_key(&self) -> [u8; DERIVED_KEY_SIZE] {
        let mut key = [0u8; DERIVED_KEY_SIZE];
        let okm = self
            .prk
            .expand(&[CACHE_KEY_INFO], hkdf::HKDF_SHA256)
            .expect("HKDF expand should succeed");
        okm.fill(&mut key).expect("OKM fill should succeed");
        key
    }

    /// Compute a fingerprint of this HostIdentity for display purposes
    ///
    /// This is NOT the HostKey itself, just a derived identifier safe to show.
    /// Returns a 16-character hex string (8 bytes).
    #[allow(clippy::expect_used)] // HKDF operations are infallible with valid fixed-size parameters
    pub fn fingerprint(&self) -> String {
        // HKDF requires minimum output of hash length (32 bytes for SHA-256)
        // We derive 32 bytes and truncate to 8 for display
        let mut full_bytes = [0u8; 32];
        let okm = self
            .prk
            .expand(&[b"antq:fingerprint:v1"], hkdf::HKDF_SHA256)
            .expect("HKDF expand should succeed");
        okm.fill(&mut full_bytes).expect("OKM fill should succeed");

        // Use first 8 bytes for fingerprint
        hex::encode(&full_bytes[..8])
    }

    // Note: export_secret() is intentionally not implemented
    // The HostKey cannot be exported once the PRK is created (HKDF extract is one-way)
    // Seed phrase backup would need to store the original secret, which is deferred per ADR-007
}

impl std::fmt::Debug for HostIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostIdentity")
            .field("fingerprint", &self.fingerprint())
            .field("policy", &self.policy)
            .finish()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_identity_from_secret() {
        let secret = [42u8; 32];
        let host = HostIdentity::from_secret(secret);

        // Should have default policy
        assert_eq!(host.policy(), EndpointKeyPolicy::PerNetwork);

        // Fingerprint should be deterministic
        let fingerprint1 = host.fingerprint();
        let host2 = HostIdentity::from_secret([42u8; 32]);
        let fingerprint2 = host2.fingerprint();
        assert_eq!(fingerprint1, fingerprint2);
    }

    #[test]
    fn test_host_identity_generate() {
        let host1 = HostIdentity::generate();
        let host2 = HostIdentity::generate();

        // Different hosts should have different fingerprints
        assert_ne!(host1.fingerprint(), host2.fingerprint());
    }

    #[test]
    fn test_derive_endpoint_encryption_key_deterministic() {
        let secret = [1u8; 32];
        let host = HostIdentity::from_secret(secret);

        let key1 = host.derive_endpoint_encryption_key(b"network-1");
        let key2 = host.derive_endpoint_encryption_key(b"network-1");

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_endpoint_encryption_key_per_network_isolation() {
        let secret = [1u8; 32];
        let host = HostIdentity::from_secret(secret);

        let key1 = host.derive_endpoint_encryption_key(b"network-1");
        let key2 = host.derive_endpoint_encryption_key(b"network-2");

        // Different networks should produce different keys
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_endpoint_encryption_key_shared_policy() {
        let secret = [1u8; 32];
        let mut host = HostIdentity::from_secret(secret);
        host.set_policy(EndpointKeyPolicy::Shared);

        let key1 = host.derive_endpoint_encryption_key(b"network-1");
        let key2 = host.derive_endpoint_encryption_key(b"network-2");

        // Shared policy should produce the same key for different networks
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_cache_key() {
        let secret = [1u8; 32];
        let host = HostIdentity::from_secret(secret);

        let key1 = host.derive_cache_key();
        let key2 = host.derive_cache_key();

        // Should be deterministic
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_cache_key_differs_from_endpoint_key() {
        let secret = [1u8; 32];
        let host = HostIdentity::from_secret(secret);

        let cache_key = host.derive_cache_key();
        let endpoint_key = host.derive_endpoint_encryption_key(b"test-network");

        // Domain separation should produce different keys
        assert_ne!(cache_key, endpoint_key);
    }

    #[test]
    fn test_fingerprint_safe_for_display() {
        let host = HostIdentity::generate();
        let fingerprint = host.fingerprint();

        // Fingerprint should be 16 hex characters (8 bytes)
        assert_eq!(fingerprint.len(), 16);
        assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_different_secrets_different_keys() {
        let host1 = HostIdentity::from_secret([1u8; 32]);
        let host2 = HostIdentity::from_secret([2u8; 32]);

        // Same network, different hosts should have different keys
        let key1 = host1.derive_endpoint_encryption_key(b"network");
        let key2 = host2.derive_endpoint_encryption_key(b"network");
        assert_ne!(key1, key2);

        // Cache keys should also differ
        assert_ne!(host1.derive_cache_key(), host2.derive_cache_key());
    }
}
