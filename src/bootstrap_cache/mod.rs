// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Greedy Bootstrap Cache
//!
//! Provides persistent peer caching with quality-based selection for network bootstrap.
//!
//! ## Features
//!
//! - **Large capacity**: 10,000-30,000 peer entries (configurable)
//! - **Quality scoring**: Success rate, RTT, age decay, capability bonuses
//! - **Epsilon-greedy selection**: Balances exploitation vs exploration
//! - **Multi-process safe**: Atomic writes with file locking (Unix)
//! - **Background maintenance**: Periodic save, cleanup, and quality updates
//!
//! ## Example
//!
//! ```rust,ignore
//! use ant_quic::bootstrap_cache::{BootstrapCache, BootstrapCacheConfig};
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = BootstrapCacheConfig::builder()
//!         .cache_dir("/var/lib/ant-quic")
//!         .max_peers(20_000)
//!         .epsilon(0.1)
//!         .build();
//!
//!     let cache = Arc::new(BootstrapCache::open(config).await?);
//!
//!     // Start background maintenance
//!     let _maintenance = cache.clone().start_maintenance();
//!
//!     // Get peers for bootstrap (epsilon-greedy selection)
//!     let peers = cache.select_peers(50).await;
//!
//!     // Record connection results
//!     for peer in &peers {
//!         // ... attempt connection ...
//!         cache.record_success(&peer.peer_id, 100).await; // or record_failure
//!     }
//!
//!     // Save periodically (also done by maintenance task)
//!     cache.save().await?;
//!
//!     Ok(())
//! }
//! ```

mod cache;
mod config;
mod entry;
mod persistence;
mod selection;
mod token_store;

pub use cache::{BootstrapCache, CacheEvent, CacheStats};
pub use config::{BootstrapCacheConfig, BootstrapCacheConfigBuilder, QualityWeights};
pub use entry::{
    CachedPeer, ConnectionOutcome, ConnectionStats, NatType, PeerCapabilities, PeerSource,
    RelayPathHint,
};
pub use persistence::EncryptedCachePersistence;
pub use selection::SelectionStrategy;
pub use token_store::BootstrapTokenStore;
