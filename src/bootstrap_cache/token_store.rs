// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Token persistence integration with BootstrapCache.

use crate::bootstrap_cache::BootstrapCache;
use crate::nat_traversal_api::PeerId;
use crate::token::TokenStore;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::{debug, warn};

/// A TokenStore implementation that persists tokens to the BootstrapCache.
///
/// It maintains a local synchronous cache for `take` operations (required by `TokenStore` trait)
/// and asynchronously updates the `BootstrapCache` on `insert`.
#[derive(Debug)]
pub struct BootstrapTokenStore {
    /// Reference to the persistent cache
    cache: Arc<BootstrapCache>,
    /// Local synchronous cache: ServerName -> Token
    /// ServerName is expected to be a PeerId hex string or a specific IP Key.
    local_cache: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl BootstrapTokenStore {
    /// Create a new BootstrapTokenStore backed by the given cache.
    ///
    /// This will initialize the local memory cache with all tokens currently in the BootstrapCache.
    pub async fn new(cache: Arc<BootstrapCache>) -> Self {
        let tokens = cache.get_all_tokens().await;
        let mut local = HashMap::new();

        for (peer_id, token) in tokens {
            // Key by PeerId hex string
            let key = hex::encode(peer_id.0);
            local.insert(key, token);
        }

        debug!(
            "Initialized BootstrapTokenStore with {} tokens",
            local.len()
        );

        Self {
            cache,
            local_cache: Arc::new(RwLock::new(local)),
        }
    }
}

impl TokenStore for BootstrapTokenStore {
    fn insert(&self, server_name: &str, token: Bytes) {
        let token_vec = token.to_vec();

        // 1. Update local cache immediately
        if let Ok(mut local) = self.local_cache.write() {
            local.insert(server_name.to_string(), token_vec.clone());
        } else {
            warn!("Failed to acquire write lock on local token cache");
        }

        // 2. Try to parse server_name as PeerId and update persistent cache
        // server_name is expected to be hex-encoded PeerId
        if let Ok(bytes) = hex::decode(server_name) {
            if let Ok(arr) = <[u8; 32]>::try_from(bytes) {
                let peer_id = PeerId(arr);
                let cache = self.cache.clone();
                let token_clone = token_vec;

                // Spawn async task to update persistent cache
                tokio::spawn(async move {
                    cache.update_token(peer_id, token_clone).await;
                });
                return;
            }
        }

        // If server_name is not a PeerId (e.g. it's an IP), we can't persist it
        // to a specific Peer entry easily unless we do a reverse lookup.
        // For now, we only persist tokens if the SNI was the PeerId.
        debug!(
            "Received token for non-PeerId server name: {}, not persisting to disk",
            server_name
        );
    }

    fn take(&self, server_name: &str) -> Option<Bytes> {
        if let Ok(mut local) = self.local_cache.write() {
            local.remove(server_name).map(Bytes::from)
        } else {
            warn!("Failed to acquire write lock on local token cache");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap_cache::BootstrapCacheConfig;
    use tempfile::TempDir;

    async fn create_test_cache(temp_dir: &TempDir) -> Arc<BootstrapCache> {
        let config = BootstrapCacheConfig::builder()
            .cache_dir(temp_dir.path())
            .max_peers(100)
            .epsilon(0.0)
            .min_peers_to_save(1)
            .build();

        Arc::new(
            BootstrapCache::open(config)
                .await
                .expect("Failed to create cache"),
        )
    }

    #[tokio::test]
    async fn insert_and_take_valid_peer_id() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let cache = create_test_cache(&temp_dir).await;
        let store = BootstrapTokenStore::new(cache).await;

        // Valid PeerId hex string (32 bytes = 64 hex chars)
        let peer_id_hex = hex::encode([0xAB; 32]);
        let token = Bytes::from_static(b"test_token_data");

        // Insert token
        store.insert(&peer_id_hex, token.clone());

        // First take should return the token
        let taken = store.take(&peer_id_hex);
        assert!(taken.is_some(), "First take should return token");
        assert_eq!(taken.expect("should have token"), token);

        // Second take should return None (one-shot semantics)
        let taken_again = store.take(&peer_id_hex);
        assert!(
            taken_again.is_none(),
            "Second take should return None (one-shot)"
        );
    }

    #[tokio::test]
    async fn take_nonexistent_returns_none() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let cache = create_test_cache(&temp_dir).await;
        let store = BootstrapTokenStore::new(cache).await;

        let result = store.take("nonexistent_key");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn insert_non_peer_id_server_name() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let cache = create_test_cache(&temp_dir).await;
        let store = BootstrapTokenStore::new(cache).await;

        // Non-PeerId server names (IPs, hostnames)
        let test_cases = ["192.168.1.1:8000", "server.example.com", "localhost", "::1"];

        for server_name in test_cases {
            let token = Bytes::from(format!("token_for_{}", server_name));

            // Insert should succeed locally even for non-PeerId names
            store.insert(server_name, token.clone());

            // Take should work (local cache)
            let taken = store.take(server_name);
            assert!(
                taken.is_some(),
                "Should be able to take token for {}",
                server_name
            );
            assert_eq!(taken.expect("should have token"), token);
        }
    }

    #[tokio::test]
    async fn hex_decode_edge_cases() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let cache = create_test_cache(&temp_dir).await;
        let store = BootstrapTokenStore::new(cache).await;

        // Test various malformed hex strings - should still work via local cache
        let edge_cases = [
            "",                       // Empty string
            "abc",                    // Odd length (not valid hex length)
            "gggg",                   // Invalid hex chars
            "00112233",               // Valid hex but wrong length (4 bytes, not 32)
            &hex::encode([0xFF; 16]), // 16 bytes instead of 32
        ];

        for server_name in edge_cases {
            let token = Bytes::from_static(b"edge_case_token");

            // Insert should succeed (updates local cache)
            store.insert(server_name, token.clone());

            // Take should work from local cache
            let taken = store.take(server_name);
            assert!(
                taken.is_some(),
                "Should take token for edge case: '{}'",
                server_name
            );
        }
    }

    #[tokio::test]
    async fn multiple_tokens_different_peers() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let cache = create_test_cache(&temp_dir).await;
        let store = BootstrapTokenStore::new(cache).await;

        // Insert tokens for multiple peers
        let peer1 = hex::encode([0x11; 32]);
        let peer2 = hex::encode([0x22; 32]);
        let peer3 = hex::encode([0x33; 32]);

        store.insert(&peer1, Bytes::from_static(b"token1"));
        store.insert(&peer2, Bytes::from_static(b"token2"));
        store.insert(&peer3, Bytes::from_static(b"token3"));

        // Each peer should have their own token
        assert_eq!(store.take(&peer1), Some(Bytes::from_static(b"token1")));
        assert_eq!(store.take(&peer2), Some(Bytes::from_static(b"token2")));
        assert_eq!(store.take(&peer3), Some(Bytes::from_static(b"token3")));

        // All should be gone now
        assert!(store.take(&peer1).is_none());
        assert!(store.take(&peer2).is_none());
        assert!(store.take(&peer3).is_none());
    }

    #[tokio::test]
    async fn overwrite_token_for_same_peer() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let cache = create_test_cache(&temp_dir).await;
        let store = BootstrapTokenStore::new(cache).await;

        let peer_id = hex::encode([0xAA; 32]);

        // Insert first token
        store.insert(&peer_id, Bytes::from_static(b"first_token"));

        // Overwrite with second token
        store.insert(&peer_id, Bytes::from_static(b"second_token"));

        // Should get the second (newest) token
        let taken = store.take(&peer_id);
        assert_eq!(
            taken,
            Some(Bytes::from_static(b"second_token")),
            "Should return the most recently inserted token"
        );
    }
}
