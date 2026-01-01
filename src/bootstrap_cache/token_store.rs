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
use std::str::FromStr;
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

        debug!("Initialized BootstrapTokenStore with {} tokens", local.len());

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
        debug!("Received token for non-PeerId server name: {}, not persisting to disk", server_name);
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
