//! Main bootstrap cache implementation.

use super::config::BootstrapCacheConfig;
use super::entry::{CachedPeer, ConnectionOutcome, PeerCapabilities, PeerSource};
use super::persistence::{CacheData, CachePersistence};
use super::selection::select_epsilon_greedy;
use crate::nat_traversal_api::PeerId;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, info, warn};

/// Bootstrap cache event for notifications
#[derive(Debug, Clone)]
pub enum CacheEvent {
    /// Cache was updated (peers added/removed/modified)
    Updated {
        /// Current peer count
        peer_count: usize,
    },
    /// Cache was saved to disk
    Saved,
    /// Cache was merged from another source
    Merged {
        /// Number of peers added from merge
        added: usize,
    },
    /// Stale peers were cleaned up
    Cleaned {
        /// Number of peers removed
        removed: usize,
    },
}

/// Cache statistics
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Total number of cached peers
    pub total_peers: usize,
    /// Peers that support relay
    pub relay_peers: usize,
    /// Peers that support NAT coordination
    pub coordinator_peers: usize,
    /// Average quality score across all peers
    pub average_quality: f64,
    /// Number of untested peers
    pub untested_peers: usize,
}

/// Greedy bootstrap cache with quality-based peer selection.
///
/// This cache stores peer information with quality metrics and provides
/// epsilon-greedy selection to balance exploitation (using known-good peers)
/// with exploration (trying new peers to discover potentially better ones).
pub struct BootstrapCache {
    config: BootstrapCacheConfig,
    data: Arc<RwLock<CacheData>>,
    persistence: CachePersistence,
    event_tx: broadcast::Sender<CacheEvent>,
    last_save: Arc<RwLock<Instant>>,
    last_cleanup: Arc<RwLock<Instant>>,
}

impl BootstrapCache {
    /// Open or create a bootstrap cache.
    ///
    /// Loads existing cache data from disk if available, otherwise starts fresh.
    pub async fn open(config: BootstrapCacheConfig) -> std::io::Result<Self> {
        let persistence =
            CachePersistence::new(&config.cache_dir, config.enable_file_locking)?;
        let data = persistence.load()?;
        let (event_tx, _) = broadcast::channel(256);
        let now = Instant::now();

        info!(
            "Opened bootstrap cache with {} peers",
            data.peers.len()
        );

        Ok(Self {
            config,
            data: Arc::new(RwLock::new(data)),
            persistence,
            event_tx,
            last_save: Arc::new(RwLock::new(now)),
            last_cleanup: Arc::new(RwLock::new(now)),
        })
    }

    /// Subscribe to cache events
    pub fn subscribe(&self) -> broadcast::Receiver<CacheEvent> {
        self.event_tx.subscribe()
    }

    /// Get the number of cached peers
    pub async fn peer_count(&self) -> usize {
        self.data.read().await.peers.len()
    }

    /// Select peers for bootstrap using epsilon-greedy strategy.
    ///
    /// Returns up to `count` peers, balancing exploitation of known-good peers
    /// with exploration of untested peers based on the configured epsilon.
    pub async fn select_peers(&self, count: usize) -> Vec<CachedPeer> {
        let data = self.data.read().await;
        let peers: Vec<CachedPeer> = data.peers.values().cloned().collect();

        select_epsilon_greedy(&peers, count, self.config.epsilon)
            .into_iter()
            .cloned()
            .collect()
    }

    /// Select peers that support relay functionality.
    ///
    /// Returns peers sorted by quality score that have relay capability.
    pub async fn select_relay_peers(&self, count: usize) -> Vec<CachedPeer> {
        let data = self.data.read().await;
        let mut relays: Vec<CachedPeer> = data
            .peers
            .values()
            .filter(|p| p.capabilities.supports_relay)
            .cloned()
            .collect();

        relays.sort_by(|a, b| {
            b.quality_score
                .partial_cmp(&a.quality_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        relays.into_iter().take(count).collect()
    }

    /// Select peers that support NAT coordination.
    ///
    /// Returns peers sorted by quality score that have coordination capability.
    pub async fn select_coordinators(&self, count: usize) -> Vec<CachedPeer> {
        let data = self.data.read().await;
        let mut coordinators: Vec<CachedPeer> = data
            .peers
            .values()
            .filter(|p| p.capabilities.supports_coordination)
            .cloned()
            .collect();

        coordinators.sort_by(|a, b| {
            b.quality_score
                .partial_cmp(&a.quality_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        coordinators.into_iter().take(count).collect()
    }

    /// Add or update a peer in the cache.
    ///
    /// If the cache is at capacity, evicts the lowest quality peers.
    pub async fn upsert(&self, peer: CachedPeer) {
        let mut data = self.data.write().await;

        // Evict lowest quality if at capacity
        if data.peers.len() >= self.config.max_peers
            && !data.peers.contains_key(&peer.peer_id.0)
        {
            self.evict_lowest_quality(&mut data);
        }

        data.peers.insert(peer.peer_id.0, peer);

        let count = data.peers.len();
        drop(data);

        let _ = self.event_tx.send(CacheEvent::Updated { peer_count: count });
    }

    /// Add a seed peer (user-provided bootstrap node).
    pub async fn add_seed(&self, peer_id: PeerId, addresses: Vec<SocketAddr>) {
        let peer = CachedPeer::new(peer_id, addresses, PeerSource::Seed);
        self.upsert(peer).await;
    }

    /// Add a peer discovered from an active connection.
    pub async fn add_from_connection(
        &self,
        peer_id: PeerId,
        addresses: Vec<SocketAddr>,
        caps: Option<PeerCapabilities>,
    ) {
        let mut peer = CachedPeer::new(peer_id, addresses, PeerSource::Connection);
        if let Some(caps) = caps {
            peer.capabilities = caps;
        }
        self.upsert(peer).await;
    }

    /// Record a connection attempt result.
    pub async fn record_outcome(&self, peer_id: &PeerId, outcome: ConnectionOutcome) {
        let mut data = self.data.write().await;

        if let Some(peer) = data.peers.get_mut(&peer_id.0) {
            if outcome.success {
                peer.record_success(
                    outcome.rtt_ms.unwrap_or(100),
                    outcome.capabilities_discovered,
                );
            } else {
                peer.record_failure();
            }

            // Recalculate quality score
            peer.calculate_quality(&self.config.weights);
        }
    }

    /// Record successful connection.
    pub async fn record_success(&self, peer_id: &PeerId, rtt_ms: u32) {
        self.record_outcome(
            peer_id,
            ConnectionOutcome {
                success: true,
                rtt_ms: Some(rtt_ms),
                capabilities_discovered: None,
            },
        )
        .await;
    }

    /// Record failed connection.
    pub async fn record_failure(&self, peer_id: &PeerId) {
        self.record_outcome(
            peer_id,
            ConnectionOutcome {
                success: false,
                rtt_ms: None,
                capabilities_discovered: None,
            },
        )
        .await;
    }

    /// Update peer capabilities.
    pub async fn update_capabilities(&self, peer_id: &PeerId, caps: PeerCapabilities) {
        let mut data = self.data.write().await;

        if let Some(peer) = data.peers.get_mut(&peer_id.0) {
            peer.capabilities = caps;
            peer.calculate_quality(&self.config.weights);
        }
    }

    /// Get a specific peer.
    pub async fn get(&self, peer_id: &PeerId) -> Option<CachedPeer> {
        self.data.read().await.peers.get(&peer_id.0).cloned()
    }

    /// Check if peer exists in cache.
    pub async fn contains(&self, peer_id: &PeerId) -> bool {
        self.data.read().await.peers.contains_key(&peer_id.0)
    }

    /// Remove a peer from cache.
    pub async fn remove(&self, peer_id: &PeerId) -> Option<CachedPeer> {
        self.data.write().await.peers.remove(&peer_id.0)
    }

    /// Save cache to disk.
    pub async fn save(&self) -> std::io::Result<()> {
        let mut data = self.data.write().await;

        if data.peers.len() < self.config.min_peers_to_save {
            debug!(
                "Skipping save: only {} peers (min: {})",
                data.peers.len(),
                self.config.min_peers_to_save
            );
            return Ok(());
        }

        self.persistence.save(&mut data)?;

        drop(data);
        *self.last_save.write().await = Instant::now();
        let _ = self.event_tx.send(CacheEvent::Saved);

        Ok(())
    }

    /// Cleanup stale peers.
    ///
    /// Removes peers that haven't been seen within the stale threshold.
    /// Returns the number of peers removed.
    pub async fn cleanup_stale(&self) -> usize {
        let mut data = self.data.write().await;
        let initial_count = data.peers.len();

        data.peers
            .retain(|_, peer| !peer.is_stale(self.config.stale_threshold));

        let removed = initial_count - data.peers.len();

        if removed > 0 {
            info!("Cleaned up {} stale peers", removed);
            let _ = self.event_tx.send(CacheEvent::Cleaned { removed });
        }

        drop(data);
        *self.last_cleanup.write().await = Instant::now();

        removed
    }

    /// Recalculate quality scores for all peers.
    pub async fn recalculate_quality(&self) {
        let mut data = self.data.write().await;

        for peer in data.peers.values_mut() {
            peer.calculate_quality(&self.config.weights);
        }

        let count = data.peers.len();
        let _ = self.event_tx.send(CacheEvent::Updated { peer_count: count });
    }

    /// Get cache statistics.
    pub async fn stats(&self) -> CacheStats {
        let data = self.data.read().await;

        let relay_count = data
            .peers
            .values()
            .filter(|p| p.capabilities.supports_relay)
            .count();
        let coord_count = data
            .peers
            .values()
            .filter(|p| p.capabilities.supports_coordination)
            .count();
        let untested = data
            .peers
            .values()
            .filter(|p| p.stats.success_count + p.stats.failure_count == 0)
            .count();
        let avg_quality = if data.peers.is_empty() {
            0.0
        } else {
            data.peers.values().map(|p| p.quality_score).sum::<f64>() / data.peers.len() as f64
        };

        CacheStats {
            total_peers: data.peers.len(),
            relay_peers: relay_count,
            coordinator_peers: coord_count,
            average_quality: avg_quality,
            untested_peers: untested,
        }
    }

    /// Start background maintenance tasks.
    ///
    /// Spawns a task that periodically:
    /// - Saves the cache to disk
    /// - Cleans up stale peers
    /// - Recalculates quality scores
    ///
    /// Returns a handle that can be used to cancel the task.
    pub fn start_maintenance(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let cache = self;

        tokio::spawn(async move {
            let mut save_interval = tokio::time::interval(cache.config.save_interval);
            let mut cleanup_interval = tokio::time::interval(cache.config.cleanup_interval);
            let mut quality_interval =
                tokio::time::interval(cache.config.quality_update_interval);

            loop {
                tokio::select! {
                    _ = save_interval.tick() => {
                        if let Err(e) = cache.save().await {
                            warn!("Failed to save cache: {}", e);
                        }
                    }
                    _ = cleanup_interval.tick() => {
                        cache.cleanup_stale().await;
                    }
                    _ = quality_interval.tick() => {
                        cache.recalculate_quality().await;
                    }
                }
            }
        })
    }

    /// Get all cached peers (for export/debug).
    pub async fn all_peers(&self) -> Vec<CachedPeer> {
        self.data.read().await.peers.values().cloned().collect()
    }

    /// Get the configuration.
    pub fn config(&self) -> &BootstrapCacheConfig {
        &self.config
    }

    fn evict_lowest_quality(&self, data: &mut CacheData) {
        let evict_count = (self.config.max_peers / 20).max(1); // Evict ~5%

        let mut sorted: Vec<_> = data.peers.iter().collect();
        sorted.sort_by(|a, b| {
            a.1.quality_score
                .partial_cmp(&b.1.quality_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let to_remove: Vec<[u8; 32]> = sorted
            .into_iter()
            .take(evict_count)
            .map(|(id, _)| *id)
            .collect();

        for id in to_remove {
            data.peers.remove(&id);
        }

        debug!("Evicted {} lowest quality peers", evict_count);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn create_test_cache(temp_dir: &TempDir) -> BootstrapCache {
        let config = BootstrapCacheConfig::builder()
            .cache_dir(temp_dir.path())
            .max_peers(100)
            .epsilon(0.0) // Pure exploitation for predictable tests
            .min_peers_to_save(1)
            .build();

        BootstrapCache::open(config).await.unwrap()
    }

    #[tokio::test]
    async fn test_cache_creation() {
        let temp_dir = TempDir::new().unwrap();
        let cache = create_test_cache(&temp_dir).await;
        assert_eq!(cache.peer_count().await, 0);
    }

    #[tokio::test]
    async fn test_add_and_get() {
        let temp_dir = TempDir::new().unwrap();
        let cache = create_test_cache(&temp_dir).await;

        let peer_id = PeerId([1u8; 32]);
        cache
            .add_seed(peer_id, vec!["127.0.0.1:9000".parse().unwrap()])
            .await;

        assert_eq!(cache.peer_count().await, 1);
        assert!(cache.contains(&peer_id).await);

        let peer = cache.get(&peer_id).await.unwrap();
        assert_eq!(peer.addresses.len(), 1);
    }

    #[tokio::test]
    async fn test_select_peers() {
        let temp_dir = TempDir::new().unwrap();
        let cache = create_test_cache(&temp_dir).await;

        // Add peers with different quality
        for i in 0..10usize {
            let peer_id = PeerId([i as u8; 32]);
            let mut peer = CachedPeer::new(
                peer_id,
                vec![format!("127.0.0.1:{}", 9000 + i).parse().unwrap()],
                PeerSource::Seed,
            );
            peer.quality_score = i as f64 / 10.0;
            cache.upsert(peer).await;
        }

        // Select should return highest quality first (epsilon=0)
        let selected = cache.select_peers(5).await;
        assert_eq!(selected.len(), 5);
        assert!(selected[0].quality_score >= selected[4].quality_score);
    }

    #[tokio::test]
    async fn test_persistence() {
        let temp_dir = TempDir::new().unwrap();

        // Create and populate cache
        {
            let cache = create_test_cache(&temp_dir).await;
            cache
                .add_seed(PeerId([1; 32]), vec!["127.0.0.1:9000".parse().unwrap()])
                .await;
            cache.save().await.unwrap();
        }

        // Reopen and verify
        {
            let cache = create_test_cache(&temp_dir).await;
            assert_eq!(cache.peer_count().await, 1);
            assert!(cache.contains(&PeerId([1; 32])).await);
        }
    }

    #[tokio::test]
    async fn test_quality_scoring() {
        let temp_dir = TempDir::new().unwrap();
        let cache = create_test_cache(&temp_dir).await;

        let peer_id = PeerId([1; 32]);
        cache
            .add_seed(peer_id, vec!["127.0.0.1:9000".parse().unwrap()])
            .await;

        // Initial quality should be neutral
        let peer = cache.get(&peer_id).await.unwrap();
        let initial_quality = peer.quality_score;

        // Record successes - quality should improve
        for _ in 0..5 {
            cache.record_success(&peer_id, 50).await;
        }

        let peer = cache.get(&peer_id).await.unwrap();
        assert!(peer.quality_score > initial_quality);
        assert!(peer.success_rate() > 0.9);
    }

    #[tokio::test]
    async fn test_eviction() {
        let temp_dir = TempDir::new().unwrap();
        let config = BootstrapCacheConfig::builder()
            .cache_dir(temp_dir.path())
            .max_peers(10)
            .build();

        let cache = BootstrapCache::open(config).await.unwrap();

        // Add 15 peers
        for i in 0..15u8 {
            let peer_id = PeerId([i; 32]);
            let mut peer = CachedPeer::new(
                peer_id,
                vec![format!("127.0.0.1:{}", 9000 + i as u16)
                    .parse()
                    .unwrap()],
                PeerSource::Seed,
            );
            peer.quality_score = i as f64 / 15.0;
            cache.upsert(peer).await;
        }

        // Should have evicted some
        assert!(cache.peer_count().await <= 10);
    }

    #[tokio::test]
    async fn test_stats() {
        let temp_dir = TempDir::new().unwrap();
        let cache = create_test_cache(&temp_dir).await;

        // Add some peers with capabilities
        let mut peer1 = CachedPeer::new(
            PeerId([1; 32]),
            vec!["127.0.0.1:9001".parse().unwrap()],
            PeerSource::Seed,
        );
        peer1.capabilities.supports_relay = true;
        cache.upsert(peer1).await;

        let mut peer2 = CachedPeer::new(
            PeerId([2; 32]),
            vec!["127.0.0.1:9002".parse().unwrap()],
            PeerSource::Seed,
        );
        peer2.capabilities.supports_coordination = true;
        cache.upsert(peer2).await;

        cache
            .add_seed(PeerId([3; 32]), vec!["127.0.0.1:9003".parse().unwrap()])
            .await;

        let stats = cache.stats().await;
        assert_eq!(stats.total_peers, 3);
        assert_eq!(stats.relay_peers, 1);
        assert_eq!(stats.coordinator_peers, 1);
        assert_eq!(stats.untested_peers, 3);
    }

    #[tokio::test]
    async fn test_select_relay_peers() {
        let temp_dir = TempDir::new().unwrap();
        let cache = create_test_cache(&temp_dir).await;

        // Add mix of relay and non-relay peers
        for i in 0..10u8 {
            let mut peer = CachedPeer::new(
                PeerId([i; 32]),
                vec![format!("127.0.0.1:{}", 9000 + i as u16)
                    .parse()
                    .unwrap()],
                PeerSource::Seed,
            );
            peer.capabilities.supports_relay = i % 2 == 0;
            peer.quality_score = i as f64 / 10.0;
            cache.upsert(peer).await;
        }

        let relays = cache.select_relay_peers(10).await;
        assert_eq!(relays.len(), 5); // Only half support relay

        // All selected should support relay
        for peer in &relays {
            assert!(peer.capabilities.supports_relay);
        }
    }
}
