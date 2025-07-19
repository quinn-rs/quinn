//! Memory optimization components for ant-quic
//!
//! This module provides memory-efficient resource management including:
//! - Connection pooling for Quinn connections
//! - Candidate caching with TTL
//! - Automatic cleanup of expired sessions and state
//! - Frame batching for reduced packet overhead

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};

use tracing::{debug, info};

#[cfg(feature = "production-ready")]
use crate::{HighLevelConnection as QuinnConnection, Endpoint as QuinnEndpoint};

use crate::{
    nat_traversal_api::{CandidateAddress, PeerId},
    VarInt,
};

/// Connection pool for reusing Quinn connections
#[derive(Debug)]
pub struct ConnectionPool {
    /// Active connections by peer ID
    active_connections: Arc<RwLock<HashMap<PeerId, PooledConnection>>>,
    /// Connection pool configuration
    config: ConnectionPoolConfig,
    /// Pool statistics
    stats: Arc<Mutex<ConnectionPoolStats>>,
    /// Cleanup task handle
    cleanup_handle: Option<tokio::task::JoinHandle<()>>,
}

/// Configuration for connection pooling
#[derive(Debug, Clone)]
pub struct ConnectionPoolConfig {
    /// Maximum number of connections to pool
    pub max_connections: usize,
    /// Maximum idle time before connection cleanup
    pub max_idle_time: Duration,
    /// Cleanup interval for expired connections
    pub cleanup_interval: Duration,
    /// Enable connection reuse
    pub enable_reuse: bool,
    /// Maximum connection age before forced refresh
    pub max_connection_age: Duration,
}

/// A pooled connection with metadata
#[derive(Debug)]
struct PooledConnection {
    #[cfg(feature = "production-ready")]
    connection: Arc<QuinnConnection>,
    #[cfg(not(feature = "production-ready"))]
    _placeholder: (),
    peer_id: PeerId,
    remote_address: SocketAddr,
    created_at: Instant,
    last_used: Instant,
    use_count: u64,
    is_active: bool,
}

/// Statistics for connection pool
#[derive(Debug, Default, Clone)]
pub struct ConnectionPoolStats {
    /// Total connections created
    pub connections_created: u64,
    /// Total connections reused
    pub connections_reused: u64,
    /// Total connections expired
    pub connections_expired: u64,
    /// Current active connections
    pub active_connections: usize,
    /// Pool hit rate (reuse / total requests)
    pub hit_rate: f64,
    /// Average connection age
    pub avg_connection_age: Duration,
}

/// Candidate cache with TTL for efficient candidate management
#[derive(Debug)]
pub struct CandidateCache {
    /// Cached candidates by peer ID
    cache: Arc<RwLock<HashMap<PeerId, CachedCandidateSet>>>,
    /// Cache configuration
    config: CandidateCacheConfig,
    /// Cache statistics
    stats: Arc<Mutex<CandidateCacheStats>>,
    /// Cleanup task handle
    cleanup_handle: Option<tokio::task::JoinHandle<()>>,
}

/// Configuration for candidate caching
#[derive(Debug, Clone)]
pub struct CandidateCacheConfig {
    /// Default TTL for cached candidates
    pub default_ttl: Duration,
    /// Maximum number of candidate sets to cache
    pub max_cache_size: usize,
    /// Cleanup interval for expired entries
    pub cleanup_interval: Duration,
    /// Enable candidate validation caching
    pub enable_validation_cache: bool,
    /// TTL for validation results
    pub validation_ttl: Duration,
}

/// Cached candidate set with metadata
#[derive(Debug, Clone)]
struct CachedCandidateSet {
    candidates: Vec<CandidateAddress>,
    cached_at: Instant,
    ttl: Duration,
    access_count: u64,
    last_accessed: Instant,
    validation_results: HashMap<SocketAddr, ValidationCacheEntry>,
}

/// Cached validation result
#[derive(Debug, Clone)]
struct ValidationCacheEntry {
    is_valid: bool,
    rtt: Option<Duration>,
    cached_at: Instant,
    ttl: Duration,
}

/// Statistics for candidate cache
#[derive(Debug, Default, Clone)]
pub struct CandidateCacheStats {
    /// Total cache hits
    pub cache_hits: u64,
    /// Total cache misses
    pub cache_misses: u64,
    /// Total entries expired
    pub entries_expired: u64,
    /// Current cache size
    pub current_size: usize,
    /// Cache hit rate
    pub hit_rate: f64,
    /// Average entry age
    pub avg_entry_age: Duration,
}

/// Session state cleanup coordinator
#[derive(Debug)]
pub struct SessionCleanupCoordinator {
    /// Active sessions by peer ID
    active_sessions: Arc<RwLock<HashMap<PeerId, SessionState>>>,
    /// Cleanup configuration
    config: SessionCleanupConfig,
    /// Cleanup statistics
    stats: Arc<Mutex<SessionCleanupStats>>,
    /// Cleanup task handle
    cleanup_handle: Option<tokio::task::JoinHandle<()>>,
}

/// Configuration for session cleanup
#[derive(Debug, Clone)]
pub struct SessionCleanupConfig {
    /// Maximum session idle time
    pub max_idle_time: Duration,
    /// Maximum session age
    pub max_session_age: Duration,
    /// Cleanup interval
    pub cleanup_interval: Duration,
    /// Enable aggressive cleanup under memory pressure
    pub enable_aggressive_cleanup: bool,
    /// Memory pressure threshold (MB)
    pub memory_pressure_threshold: usize,
}

/// Session state for cleanup tracking
#[derive(Debug)]
struct SessionState {
    peer_id: PeerId,
    created_at: Instant,
    last_activity: Instant,
    memory_usage: usize,
    is_active: bool,
    cleanup_priority: CleanupPriority,
}

/// Priority for session cleanup
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CleanupPriority {
    Low,    // Keep as long as possible
    Normal, // Standard cleanup rules
    High,   // Clean up aggressively
}

/// Statistics for session cleanup
#[derive(Debug, Default, Clone)]
pub struct SessionCleanupStats {
    /// Total sessions cleaned up
    pub sessions_cleaned: u64,
    /// Memory freed (bytes)
    pub memory_freed: u64,
    /// Current active sessions
    pub active_sessions: usize,
    /// Average session lifetime
    pub avg_session_lifetime: Duration,
}

/// Frame batching coordinator for reduced packet overhead
#[derive(Debug)]
pub struct FrameBatchingCoordinator {
    /// Pending frames by destination
    pending_frames: Arc<Mutex<HashMap<SocketAddr, BatchedFrameSet>>>,
    /// Batching configuration
    config: FrameBatchingConfig,
    /// Batching statistics
    stats: Arc<Mutex<FrameBatchingStats>>,
    /// Flush task handle
    flush_handle: Option<tokio::task::JoinHandle<()>>,
}

/// Configuration for frame batching
#[derive(Debug, Clone)]
pub struct FrameBatchingConfig {
    /// Maximum batch size (bytes)
    pub max_batch_size: usize,
    /// Maximum batch delay
    pub max_batch_delay: Duration,
    /// Maximum frames per batch
    pub max_frames_per_batch: usize,
    /// Enable adaptive batching based on network conditions
    pub enable_adaptive_batching: bool,
    /// Minimum batch size for efficiency
    pub min_batch_size: usize,
}

/// Batched frame set
#[derive(Debug)]
struct BatchedFrameSet {
    frames: Vec<BatchedFrame>,
    total_size: usize,
    created_at: Instant,
    destination: SocketAddr,
    priority: BatchPriority,
}

/// Individual batched frame
#[derive(Debug)]
struct BatchedFrame {
    frame_type: u8,
    payload: Vec<u8>,
    size: usize,
    priority: FramePriority,
    created_at: Instant,
}

/// Priority for frame batching
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum BatchPriority {
    Low,    // Can wait for full batch
    Normal, // Standard batching rules
    High,   // Send quickly, minimal batching
}

/// Priority for individual frames
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FramePriority {
    Background, // Low priority, can be delayed
    Normal,     // Standard priority
    Urgent,     // High priority, minimal delay
}

/// Statistics for frame batching
#[derive(Debug, Default, Clone)]
pub struct FrameBatchingStats {
    /// Total frames batched
    pub frames_batched: u64,
    /// Total batches sent
    pub batches_sent: u64,
    /// Average batch size
    pub avg_batch_size: f64,
    /// Bytes saved through batching
    pub bytes_saved: u64,
    /// Batching efficiency (0.0 - 1.0)
    pub batching_efficiency: f64,
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 1000,
            max_idle_time: Duration::from_secs(300), // 5 minutes
            cleanup_interval: Duration::from_secs(60), // 1 minute
            enable_reuse: true,
            max_connection_age: Duration::from_secs(3600), // 1 hour
        }
    }
}

impl Default for CandidateCacheConfig {
    fn default() -> Self {
        Self {
            default_ttl: Duration::from_secs(300), // 5 minutes
            max_cache_size: 10000,
            cleanup_interval: Duration::from_secs(60), // 1 minute
            enable_validation_cache: true,
            validation_ttl: Duration::from_secs(60), // 1 minute
        }
    }
}

impl Default for SessionCleanupConfig {
    fn default() -> Self {
        Self {
            max_idle_time: Duration::from_secs(600), // 10 minutes
            max_session_age: Duration::from_secs(3600), // 1 hour
            cleanup_interval: Duration::from_secs(120), // 2 minutes
            enable_aggressive_cleanup: true,
            memory_pressure_threshold: 512, // 512 MB
        }
    }
}

impl Default for FrameBatchingConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 1200, // Just under typical MTU
            max_batch_delay: Duration::from_millis(10), // 10ms max delay
            max_frames_per_batch: 10,
            enable_adaptive_batching: true,
            min_batch_size: 200, // Minimum size for efficiency
        }
    }
}

impl ConnectionPool {
    /// Create a new connection pool
    pub fn new(config: ConnectionPoolConfig) -> Self {
        let pool = Self {
            active_connections: Arc::new(RwLock::new(HashMap::new())),
            config,
            stats: Arc::new(Mutex::new(ConnectionPoolStats::default())),
            cleanup_handle: None,
        };

        pool
    }

    /// Start the connection pool with cleanup task
    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let connections = Arc::clone(&self.active_connections);
        let stats = Arc::clone(&self.stats);
        let config = self.config.clone();

        let cleanup_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(config.cleanup_interval);
            
            loop {
                interval.tick().await;
                Self::cleanup_expired_connections(&connections, &stats, &config).await;
            }
        });

        self.cleanup_handle = Some(cleanup_handle);
        info!("Connection pool started with max_connections={}", self.config.max_connections);
        Ok(())
    }

    /// Get or create a connection for a peer
    #[cfg(feature = "production-ready")]
    pub async fn get_connection(
        &self,
        peer_id: PeerId,
        remote_address: SocketAddr,
        endpoint: &QuinnEndpoint,
    ) -> Result<Arc<QuinnConnection>, Box<dyn std::error::Error + Send + Sync>> {
        // Try to get existing connection
        if let Some(connection) = self.try_get_existing_connection(peer_id, remote_address).await {
            self.update_stats_hit().await;
            return Ok(connection);
        }

        // Create new connection
        let connection = self.create_new_connection(peer_id, remote_address, endpoint).await?;
        self.update_stats_miss().await;
        Ok(connection)
    }

    /// Try to get existing connection from pool
    #[cfg(feature = "production-ready")]
    async fn try_get_existing_connection(
        &self,
        peer_id: PeerId,
        remote_address: SocketAddr,
    ) -> Option<Arc<QuinnConnection>> {
        let mut connections = self.active_connections.write().unwrap();
        
        if let Some(pooled) = connections.get_mut(&peer_id) {
            if pooled.is_active && pooled.remote_address == remote_address {
                // Check if connection is still valid
                if pooled.connection.close_reason().is_none() {
                    pooled.last_used = Instant::now();
                    pooled.use_count += 1;
                    debug!("Reusing pooled connection for peer {:?}", peer_id);
                    return Some(Arc::clone(&pooled.connection));
                } else {
                    // Connection is closed, remove it
                    connections.remove(&peer_id);
                }
            }
        }

        None
    }

    /// Create a new connection and add to pool
    #[cfg(feature = "production-ready")]
    async fn create_new_connection(
        &self,
        peer_id: PeerId,
        remote_address: SocketAddr,
        endpoint: &QuinnEndpoint,
    ) -> Result<Arc<QuinnConnection>, Box<dyn std::error::Error + Send + Sync>> {
        // Check pool size limit
        {
            let connections = self.active_connections.read().unwrap();
            if connections.len() >= self.config.max_connections {
                // Pool is full, need to evict least recently used
                drop(connections);
                self.evict_lru_connection().await;
            }
        }

        // Create new connection
        let rustls_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        
        let client_crypto = crate::crypto::rustls::QuicClientConfig::try_from(rustls_config)
            .map_err(|e| format!("Failed to create QUIC client config: {}", e))?;
        
        let client_config = crate::ClientConfig::new(Arc::new(client_crypto));
        
        let connecting = endpoint.connect_with(client_config, remote_address, "ant-quic")
            .map_err(|e| format!("Failed to initiate connection: {}", e))?;
        
        // Wait for the connection to be established
        let connection = connecting.await
            .map_err(|e| format!("Connection failed: {}", e))?;

        let connection_arc = Arc::new(connection);
        
        let pooled = PooledConnection {
            connection: Arc::clone(&connection_arc),
            peer_id,
            remote_address,
            created_at: Instant::now(),
            last_used: Instant::now(),
            use_count: 1,
            is_active: true,
        };

        // Add to pool
        {
            let mut connections = self.active_connections.write().unwrap();
            connections.insert(peer_id, pooled);
        }

        // Update stats
        {
            let mut stats = self.stats.lock().unwrap();
            stats.connections_created += 1;
            stats.active_connections += 1;
        }

        info!("Created new pooled connection for peer {:?}", peer_id);
        Ok(connection_arc)
    }

    /// Evict least recently used connection
    async fn evict_lru_connection(&self) {
        let mut connections = self.active_connections.write().unwrap();
        
        if let Some((lru_peer_id, _)) = connections
            .iter()
            .min_by_key(|(_, pooled)| pooled.last_used)
            .map(|(peer_id, pooled)| (*peer_id, pooled.last_used))
        {
            connections.remove(&lru_peer_id);
            debug!("Evicted LRU connection for peer {:?}", lru_peer_id);
            
            // Update stats
            let mut stats = self.stats.lock().unwrap();
            stats.active_connections = stats.active_connections.saturating_sub(1);
        }
    }

    /// Update stats for cache hit
    async fn update_stats_hit(&self) {
        let mut stats = self.stats.lock().unwrap();
        stats.connections_reused += 1;
        let total_requests = stats.connections_created + stats.connections_reused;
        stats.hit_rate = stats.connections_reused as f64 / total_requests as f64;
    }

    /// Update stats for cache miss
    async fn update_stats_miss(&self) {
        let stats = self.stats.lock().unwrap();
        let total_requests = stats.connections_created + stats.connections_reused;
        drop(stats);
        
        let mut stats = self.stats.lock().unwrap();
        stats.hit_rate = stats.connections_reused as f64 / total_requests as f64;
    }

    /// Cleanup expired connections
    async fn cleanup_expired_connections(
        connections: &Arc<RwLock<HashMap<PeerId, PooledConnection>>>,
        stats: &Arc<Mutex<ConnectionPoolStats>>,
        config: &ConnectionPoolConfig,
    ) {
        let now = Instant::now();
        let mut to_remove = Vec::new();

        // Find expired connections
        {
            let connections_read = connections.read().unwrap();
            for (peer_id, pooled) in connections_read.iter() {
                let idle_time = now.duration_since(pooled.last_used);
                let age = now.duration_since(pooled.created_at);

                if idle_time > config.max_idle_time || age > config.max_connection_age {
                    to_remove.push(*peer_id);
                }

                #[cfg(feature = "production-ready")]
                {
                    // Also remove closed connections
                    if pooled.connection.close_reason().is_some() {
                        to_remove.push(*peer_id);
                    }
                }
            }
        }

        // Remove expired connections
        if !to_remove.is_empty() {
            let mut connections_write = connections.write().unwrap();
            for peer_id in &to_remove {
                connections_write.remove(peer_id);
            }

            // Update stats
            let mut stats_guard = stats.lock().unwrap();
            stats_guard.connections_expired += to_remove.len() as u64;
            stats_guard.active_connections = connections_write.len();

            debug!("Cleaned up {} expired connections", to_remove.len());
        }
    }

    /// Get connection pool statistics
    pub async fn get_stats(&self) -> ConnectionPoolStats {
        self.stats.lock().unwrap().clone()
    }

    /// Shutdown the connection pool
    pub async fn shutdown(&mut self) {
        if let Some(handle) = self.cleanup_handle.take() {
            handle.abort();
        }

        // Close all connections
        #[cfg(feature = "production-ready")]
        {
            let connections = self.active_connections.read().unwrap();
            for (_, pooled) in connections.iter() {
                pooled.connection.close(VarInt::from_u32(0), b"shutdown");
            }
        }

        info!("Connection pool shutdown complete");
    }
}

impl CandidateCache {
    /// Create a new candidate cache
    pub fn new(config: CandidateCacheConfig) -> Self {
        let cache = Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            config,
            stats: Arc::new(Mutex::new(CandidateCacheStats::default())),
            cleanup_handle: None,
        };

        cache
    }

    /// Start the candidate cache with cleanup task
    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let cache = Arc::clone(&self.cache);
        let stats = Arc::clone(&self.stats);
        let config = self.config.clone();

        let cleanup_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(config.cleanup_interval);
            
            loop {
                interval.tick().await;
                Self::cleanup_expired_entries(&cache, &stats, &config).await;
            }
        });

        self.cleanup_handle = Some(cleanup_handle);
        info!("Candidate cache started with max_size={}", self.config.max_cache_size);
        Ok(())
    }

    /// Get cached candidates for a peer
    pub async fn get_candidates(&self, peer_id: PeerId) -> Option<Vec<CandidateAddress>> {
        let (is_valid, candidates) = {
            let cache = self.cache.read().unwrap();
            
            if let Some(cached_set) = cache.get(&peer_id) {
                let now = Instant::now();
                
                // Check if entry is still valid
                if now.duration_since(cached_set.cached_at) <= cached_set.ttl {
                    (true, Some(cached_set.candidates.clone()))
                } else {
                    (false, None)
                }
            } else {
                (false, None)
            }
        };
        
        if is_valid {
            // Update access statistics
            self.update_access_stats(peer_id, true).await;
            
            if let Some(ref candidates) = candidates {
                debug!("Cache hit for peer {:?}, {} candidates", peer_id, candidates.len());
            }
            return candidates;
        }

        // Cache miss
        self.update_access_stats(peer_id, false).await;
        debug!("Cache miss for peer {:?}", peer_id);
        None
    }

    /// Cache candidates for a peer
    pub async fn cache_candidates(
        &self,
        peer_id: PeerId,
        candidates: Vec<CandidateAddress>,
        ttl: Option<Duration>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let ttl = ttl.unwrap_or(self.config.default_ttl);
        
        // Check cache size limit
        {
            let cache = self.cache.read().unwrap();
            if cache.len() >= self.config.max_cache_size {
                drop(cache);
                self.evict_lru_entry().await;
            }
        }

        let candidate_count = candidates.len();
        let cached_set = CachedCandidateSet {
            candidates,
            cached_at: Instant::now(),
            ttl,
            access_count: 0,
            last_accessed: Instant::now(),
            validation_results: HashMap::new(),
        };

        // Add to cache
        {
            let mut cache = self.cache.write().unwrap();
            cache.insert(peer_id, cached_set);
        }

        // Update stats
        {
            let mut stats = self.stats.lock().unwrap();
            stats.current_size += 1;
        }

        debug!("Cached {} candidates for peer {:?} with TTL {:?}", 
               candidate_count, peer_id, ttl);
        Ok(())
    }

    /// Cache validation result for a candidate
    pub async fn cache_validation_result(
        &self,
        peer_id: PeerId,
        address: SocketAddr,
        is_valid: bool,
        rtt: Option<Duration>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.config.enable_validation_cache {
            return Ok(());
        }

        let mut cache = self.cache.write().unwrap();
        
        if let Some(cached_set) = cache.get_mut(&peer_id) {
            let validation_entry = ValidationCacheEntry {
                is_valid,
                rtt,
                cached_at: Instant::now(),
                ttl: self.config.validation_ttl,
            };

            cached_set.validation_results.insert(address, validation_entry);
            debug!("Cached validation result for {}:{} -> {}", peer_id.0[0], address, is_valid);
        }

        Ok(())
    }

    /// Get cached validation result
    pub async fn get_validation_result(
        &self,
        peer_id: PeerId,
        address: SocketAddr,
    ) -> Option<(bool, Option<Duration>)> {
        if !self.config.enable_validation_cache {
            return None;
        }

        let cache = self.cache.read().unwrap();
        
        if let Some(cached_set) = cache.get(&peer_id) {
            if let Some(validation_entry) = cached_set.validation_results.get(&address) {
                let now = Instant::now();
                
                // Check if validation result is still valid
                if now.duration_since(validation_entry.cached_at) <= validation_entry.ttl {
                    return Some((validation_entry.is_valid, validation_entry.rtt));
                }
            }
        }

        None
    }

    /// Update access statistics
    async fn update_access_stats(&self, peer_id: PeerId, hit: bool) {
        // Update cache-level stats
        {
            let mut stats = self.stats.lock().unwrap();
            if hit {
                stats.cache_hits += 1;
            } else {
                stats.cache_misses += 1;
            }
            
            let total_accesses = stats.cache_hits + stats.cache_misses;
            stats.hit_rate = stats.cache_hits as f64 / total_accesses as f64;
        }

        // Update entry-level stats
        if hit {
            let mut cache = self.cache.write().unwrap();
            if let Some(cached_set) = cache.get_mut(&peer_id) {
                cached_set.access_count += 1;
                cached_set.last_accessed = Instant::now();
            }
        }
    }

    /// Evict least recently used entry
    async fn evict_lru_entry(&self) {
        let mut cache = self.cache.write().unwrap();
        
        if let Some((lru_peer_id, _)) = cache
            .iter()
            .min_by_key(|(_, cached_set)| cached_set.last_accessed)
            .map(|(peer_id, cached_set)| (*peer_id, cached_set.last_accessed))
        {
            cache.remove(&lru_peer_id);
            debug!("Evicted LRU cache entry for peer {:?}", lru_peer_id);
            
            // Update stats
            let mut stats = self.stats.lock().unwrap();
            stats.current_size = stats.current_size.saturating_sub(1);
        }
    }

    /// Cleanup expired cache entries
    async fn cleanup_expired_entries(
        cache: &Arc<RwLock<HashMap<PeerId, CachedCandidateSet>>>,
        stats: &Arc<Mutex<CandidateCacheStats>>,
        _config: &CandidateCacheConfig,
    ) {
        let now = Instant::now();
        let mut to_remove = Vec::new();

        // Find expired entries
        {
            let cache_read = cache.read().unwrap();
            for (peer_id, cached_set) in cache_read.iter() {
                let age = now.duration_since(cached_set.cached_at);
                if age > cached_set.ttl {
                    to_remove.push(*peer_id);
                }
            }
        }

        // Remove expired entries
        if !to_remove.is_empty() {
            let mut cache_write = cache.write().unwrap();
            for peer_id in &to_remove {
                cache_write.remove(peer_id);
            }

            // Update stats
            let mut stats_guard = stats.lock().unwrap();
            stats_guard.entries_expired += to_remove.len() as u64;
            stats_guard.current_size = cache_write.len();

            debug!("Cleaned up {} expired cache entries", to_remove.len());
        }

        // Also cleanup expired validation results
        {
            let mut cache_write = cache.write().unwrap();
            for cached_set in cache_write.values_mut() {
                cached_set.validation_results.retain(|_, validation_entry| {
                    now.duration_since(validation_entry.cached_at) <= validation_entry.ttl
                });
            }
        }
    }

    /// Get cache statistics
    pub async fn get_stats(&self) -> CandidateCacheStats {
        self.stats.lock().unwrap().clone()
    }

    /// Shutdown the candidate cache
    pub async fn shutdown(&mut self) {
        if let Some(handle) = self.cleanup_handle.take() {
            handle.abort();
        }

        // Clear cache
        {
            let mut cache = self.cache.write().unwrap();
            cache.clear();
        }

        info!("Candidate cache shutdown complete");
    }
}

impl SessionCleanupCoordinator {
    /// Create a new session cleanup coordinator
    pub fn new(config: SessionCleanupConfig) -> Self {
        Self {
            active_sessions: Arc::new(RwLock::new(HashMap::new())),
            config,
            stats: Arc::new(Mutex::new(SessionCleanupStats::default())),
            cleanup_handle: None,
        }
    }

    /// Start the session cleanup coordinator
    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let sessions = Arc::clone(&self.active_sessions);
        let stats = Arc::clone(&self.stats);
        let config = self.config.clone();

        let cleanup_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(config.cleanup_interval);
            
            loop {
                interval.tick().await;
                Self::cleanup_expired_sessions(&sessions, &stats, &config).await;
            }
        });

        self.cleanup_handle = Some(cleanup_handle);
        info!("Session cleanup coordinator started");
        Ok(())
    }

    /// Register a new session
    pub async fn register_session(
        &self,
        peer_id: PeerId,
        memory_usage: usize,
        priority: CleanupPriority,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let session_state = SessionState {
            peer_id,
            created_at: Instant::now(),
            last_activity: Instant::now(),
            memory_usage,
            is_active: true,
            cleanup_priority: priority,
        };

        {
            let mut sessions = self.active_sessions.write().unwrap();
            sessions.insert(peer_id, session_state);
        }

        // Update stats
        {
            let mut stats = self.stats.lock().unwrap();
            stats.active_sessions += 1;
        }

        debug!("Registered session for peer {:?} with {} bytes", peer_id, memory_usage);
        Ok(())
    }

    /// Update session activity
    pub async fn update_session_activity(&self, peer_id: PeerId) {
        let mut sessions = self.active_sessions.write().unwrap();
        if let Some(session) = sessions.get_mut(&peer_id) {
            session.last_activity = Instant::now();
        }
    }

    /// Cleanup expired sessions
    async fn cleanup_expired_sessions(
        sessions: &Arc<RwLock<HashMap<PeerId, SessionState>>>,
        stats: &Arc<Mutex<SessionCleanupStats>>,
        config: &SessionCleanupConfig,
    ) {
        let now = Instant::now();
        let mut to_remove = Vec::new();
        let mut memory_freed = 0u64;

        // Check for memory pressure
        let memory_pressure = Self::check_memory_pressure(config);

        // Find sessions to cleanup
        {
            let sessions_read = sessions.read().unwrap();
            for (peer_id, session) in sessions_read.iter() {
                let idle_time = now.duration_since(session.last_activity);
                let age = now.duration_since(session.created_at);

                let should_cleanup = if memory_pressure && config.enable_aggressive_cleanup {
                    // Aggressive cleanup under memory pressure
                    match session.cleanup_priority {
                        CleanupPriority::High => idle_time > Duration::from_secs(30),
                        CleanupPriority::Normal => idle_time > Duration::from_secs(60),
                        CleanupPriority::Low => idle_time > config.max_idle_time / 2,
                    }
                } else {
                    // Normal cleanup rules
                    idle_time > config.max_idle_time || age > config.max_session_age
                };

                if should_cleanup {
                    to_remove.push(*peer_id);
                    memory_freed += session.memory_usage as u64;
                }
            }
        }

        // Remove expired sessions
        if !to_remove.is_empty() {
            let mut sessions_write = sessions.write().unwrap();
            for peer_id in &to_remove {
                sessions_write.remove(peer_id);
            }

            // Update stats
            let mut stats_guard = stats.lock().unwrap();
            stats_guard.sessions_cleaned += to_remove.len() as u64;
            stats_guard.memory_freed += memory_freed;
            stats_guard.active_sessions = sessions_write.len();

            if memory_pressure {
                info!("Aggressive cleanup: removed {} sessions, freed {} bytes", 
                      to_remove.len(), memory_freed);
            } else {
                debug!("Regular cleanup: removed {} sessions, freed {} bytes", 
                       to_remove.len(), memory_freed);
            }
        }
    }

    /// Check if system is under memory pressure
    fn check_memory_pressure(config: &SessionCleanupConfig) -> bool {
        // Simplified memory pressure detection
        // In production, this would check actual system memory usage
        // For now, return false (no memory pressure)
        // This can be enhanced with system memory monitoring
        let _ = config.memory_pressure_threshold;
        false
    }

    /// Get session cleanup statistics
    pub async fn get_stats(&self) -> SessionCleanupStats {
        self.stats.lock().unwrap().clone()
    }

    /// Shutdown the session cleanup coordinator
    pub async fn shutdown(&mut self) {
        if let Some(handle) = self.cleanup_handle.take() {
            handle.abort();
        }

        // Clear sessions
        {
            let mut sessions = self.active_sessions.write().unwrap();
            sessions.clear();
        }

        info!("Session cleanup coordinator shutdown complete");
    }
}

impl FrameBatchingCoordinator {
    /// Create a new frame batching coordinator
    pub fn new(config: FrameBatchingConfig) -> Self {
        Self {
            pending_frames: Arc::new(Mutex::new(HashMap::new())),
            config,
            stats: Arc::new(Mutex::new(FrameBatchingStats::default())),
            flush_handle: None,
        }
    }

    /// Start the frame batching coordinator
    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let pending_frames = Arc::clone(&self.pending_frames);
        let stats = Arc::clone(&self.stats);
        let config = self.config.clone();

        let flush_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(config.max_batch_delay / 4);
            
            loop {
                interval.tick().await;
                Self::flush_expired_batches(&pending_frames, &stats, &config).await;
            }
        });

        self.flush_handle = Some(flush_handle);
        info!("Frame batching coordinator started");
        Ok(())
    }

    /// Add frame to batch
    pub async fn add_frame(
        &self,
        destination: SocketAddr,
        frame_type: u8,
        payload: Vec<u8>,
        priority: FramePriority,
    ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        let frame = BatchedFrame {
            frame_type,
            size: payload.len(),
            payload,
            priority,
            created_at: Instant::now(),
        };

        let mut pending = self.pending_frames.lock().unwrap();
        
        // Check if we need to flush
        let (should_flush, frames_count, total_size) = {
            let batch_set = pending.entry(destination).or_insert_with(|| {
                BatchedFrameSet {
                    frames: Vec::new(),
                    total_size: 0,
                    created_at: Instant::now(),
                    destination,
                    priority: BatchPriority::Normal,
                }
            });

            batch_set.frames.push(frame);
            batch_set.total_size += batch_set.frames.last().unwrap().size;
            
            // Update batch priority based on frame priority
            if priority == FramePriority::Urgent {
                batch_set.priority = BatchPriority::High;
            }

            // Check if batch should be flushed immediately
            let should_flush = self.should_flush_batch(batch_set);
            (should_flush, batch_set.frames.len(), batch_set.total_size)
        };
        
        if should_flush {
            // Remove and serialize the batch
            if let Some(batch_set) = pending.remove(&destination) {
                let batch_data = self.serialize_batch(&batch_set);
                
                // Update stats
                {
                    let mut stats = self.stats.lock().unwrap();
                    stats.batches_sent += 1;
                    stats.frames_batched += frames_count as u64;
                    stats.avg_batch_size = (stats.avg_batch_size * (stats.batches_sent - 1) as f64 + 
                                           total_size as f64) / stats.batches_sent as f64;
                }

                debug!("Flushed batch to {} with {} frames ({} bytes)", 
                       destination, frames_count, total_size);
                return Ok(Some(batch_data));
            }
        }

        Ok(None)
    }

    /// Check if batch should be flushed
    fn should_flush_batch(&self, batch_set: &BatchedFrameSet) -> bool {
        let now = Instant::now();
        let age = now.duration_since(batch_set.created_at);

        // Flush if batch is full, old, or high priority
        batch_set.total_size >= self.config.max_batch_size ||
        batch_set.frames.len() >= self.config.max_frames_per_batch ||
        age >= self.config.max_batch_delay ||
        batch_set.priority == BatchPriority::High
    }

    /// Serialize batch into packet data
    fn serialize_batch(&self, batch_set: &BatchedFrameSet) -> Vec<u8> {
        let mut data = Vec::with_capacity(batch_set.total_size + batch_set.frames.len() * 4);
        
        for frame in &batch_set.frames {
            // Add frame type and length
            data.push(frame.frame_type);
            data.extend_from_slice(&(frame.payload.len() as u16).to_be_bytes());
            // Add frame payload
            data.extend_from_slice(&frame.payload);
        }

        data
    }

    /// Flush expired batches
    async fn flush_expired_batches(
        pending_frames: &Arc<Mutex<HashMap<SocketAddr, BatchedFrameSet>>>,
        stats: &Arc<Mutex<FrameBatchingStats>>,
        config: &FrameBatchingConfig,
    ) {
        let now = Instant::now();
        let mut to_flush = Vec::new();

        // Find expired batches
        {
            let pending = pending_frames.lock().unwrap();
            for (destination, batch_set) in pending.iter() {
                let age = now.duration_since(batch_set.created_at);
                if age >= config.max_batch_delay {
                    to_flush.push((*destination, batch_set.frames.len(), batch_set.total_size));
                }
            }
        }

        // Flush expired batches
        if !to_flush.is_empty() {
            let mut pending = pending_frames.lock().unwrap();
            let flush_count = to_flush.len();
            for (destination, frame_count, total_size) in to_flush {
                pending.remove(&destination);
                
                // Update stats
                let mut stats_guard = stats.lock().unwrap();
                stats_guard.batches_sent += 1;
                stats_guard.frames_batched += frame_count as u64;
                stats_guard.avg_batch_size = (stats_guard.avg_batch_size * (stats_guard.batches_sent - 1) as f64 + 
                                             total_size as f64) / stats_guard.batches_sent as f64;
            }

            debug!("Flushed {} expired batches", flush_count);
        }
    }

    /// Get batching statistics
    pub async fn get_stats(&self) -> FrameBatchingStats {
        self.stats.lock().unwrap().clone()
    }

    /// Shutdown the frame batching coordinator
    pub async fn shutdown(&mut self) {
        if let Some(handle) = self.flush_handle.take() {
            handle.abort();
        }

        // Flush all pending batches
        {
            let mut pending = self.pending_frames.lock().unwrap();
            pending.clear();
        }

        info!("Frame batching coordinator shutdown complete");
    }
}

/// Memory optimization manager that coordinates all memory optimization components
#[derive(Debug)]
pub struct MemoryOptimizationManager {
    connection_pool: ConnectionPool,
    candidate_cache: CandidateCache,
    session_cleanup: SessionCleanupCoordinator,
    frame_batching: FrameBatchingCoordinator,
    is_running: bool,
}

impl MemoryOptimizationManager {
    /// Create a new memory optimization manager with default configurations
    pub fn new() -> Self {
        Self {
            connection_pool: ConnectionPool::new(ConnectionPoolConfig::default()),
            candidate_cache: CandidateCache::new(CandidateCacheConfig::default()),
            session_cleanup: SessionCleanupCoordinator::new(SessionCleanupConfig::default()),
            frame_batching: FrameBatchingCoordinator::new(FrameBatchingConfig::default()),
            is_running: false,
        }
    }

    /// Create a new memory optimization manager with custom configurations
    pub fn with_configs(
        pool_config: ConnectionPoolConfig,
        cache_config: CandidateCacheConfig,
        cleanup_config: SessionCleanupConfig,
        batching_config: FrameBatchingConfig,
    ) -> Self {
        Self {
            connection_pool: ConnectionPool::new(pool_config),
            candidate_cache: CandidateCache::new(cache_config),
            session_cleanup: SessionCleanupCoordinator::new(cleanup_config),
            frame_batching: FrameBatchingCoordinator::new(batching_config),
            is_running: false,
        }
    }

    /// Start all memory optimization components
    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.is_running {
            return Ok(());
        }

        self.connection_pool.start().await?;
        self.candidate_cache.start().await?;
        self.session_cleanup.start().await?;
        self.frame_batching.start().await?;

        self.is_running = true;
        info!("Memory optimization manager started");
        Ok(())
    }

    /// Get connection pool reference
    pub fn connection_pool(&self) -> &ConnectionPool {
        &self.connection_pool
    }

    /// Get candidate cache reference
    pub fn candidate_cache(&self) -> &CandidateCache {
        &self.candidate_cache
    }

    /// Get session cleanup coordinator reference
    pub fn session_cleanup(&self) -> &SessionCleanupCoordinator {
        &self.session_cleanup
    }

    /// Get frame batching coordinator reference
    pub fn frame_batching(&self) -> &FrameBatchingCoordinator {
        &self.frame_batching
    }

    /// Get comprehensive memory optimization statistics
    pub async fn get_comprehensive_stats(&self) -> MemoryOptimizationStats {
        MemoryOptimizationStats {
            connection_pool: self.connection_pool.get_stats().await,
            candidate_cache: self.candidate_cache.get_stats().await,
            session_cleanup: self.session_cleanup.get_stats().await,
            frame_batching: self.frame_batching.get_stats().await,
        }
    }

    /// Shutdown all memory optimization components
    pub async fn shutdown(&mut self) {
        if !self.is_running {
            return;
        }

        self.connection_pool.shutdown().await;
        self.candidate_cache.shutdown().await;
        self.session_cleanup.shutdown().await;
        self.frame_batching.shutdown().await;

        self.is_running = false;
        info!("Memory optimization manager shutdown complete");
    }
}

/// Comprehensive memory optimization statistics
#[derive(Debug, Clone)]
pub struct MemoryOptimizationStats {
    pub connection_pool: ConnectionPoolStats,
    pub candidate_cache: CandidateCacheStats,
    pub session_cleanup: SessionCleanupStats,
    pub frame_batching: FrameBatchingStats,
}

impl Default for MemoryOptimizationManager {
    fn default() -> Self {
        Self::new()
    }
}