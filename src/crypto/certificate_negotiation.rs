//! Certificate Type Negotiation Protocol Implementation
//!
//! This module implements the complete certificate type negotiation protocol
//! as defined in RFC 7250, including state management, caching, and integration
//! with both client and server sides of TLS connections.

use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};

use tracing::{Level, debug, info, span, warn};

use super::tls_extensions::{
    CertificateTypeList, CertificateTypePreferences, NegotiationResult, TlsExtensionError,
};

/// Negotiation state for a single TLS connection
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NegotiationState {
    /// Negotiation not yet started
    Pending,
    /// Extensions sent, waiting for response
    Waiting {
        sent_at: Instant,
        our_preferences: CertificateTypePreferences,
    },
    /// Negotiation completed successfully
    Completed {
        result: NegotiationResult,
        completed_at: Instant,
    },
    /// Negotiation failed
    Failed { error: String, failed_at: Instant },
    /// Timed out waiting for response
    TimedOut { timeout_at: Instant },
}

impl NegotiationState {
    /// Check if negotiation is complete (either succeeded or failed)
    pub fn is_complete(&self) -> bool {
        matches!(
            self,
            NegotiationState::Completed { .. }
                | NegotiationState::Failed { .. }
                | NegotiationState::TimedOut { .. }
        )
    }

    /// Check if negotiation succeeded
    pub fn is_successful(&self) -> bool {
        matches!(self, NegotiationState::Completed { .. })
    }

    /// Get the negotiation result if successful
    pub fn get_result(&self) -> Option<&NegotiationResult> {
        match self {
            NegotiationState::Completed { result, .. } => Some(result),
            _ => None,
        }
    }

    /// Get error message if failed
    pub fn get_error(&self) -> Option<&str> {
        match self {
            NegotiationState::Failed { error, .. } => Some(error),
            _ => None,
        }
    }
}

/// Configuration for certificate type negotiation
#[derive(Debug, Clone)]
pub struct NegotiationConfig {
    /// Timeout for waiting for negotiation response
    pub timeout: Duration,
    /// Whether to cache negotiation results
    pub enable_caching: bool,
    /// Maximum cache size
    pub max_cache_size: usize,
    /// Whether to allow fallback to X.509 if RPK negotiation fails
    pub allow_fallback: bool,
    /// Default preferences if none specified
    pub default_preferences: CertificateTypePreferences,
}

impl Default for NegotiationConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            enable_caching: true,
            max_cache_size: 1000,
            allow_fallback: true,
            default_preferences: CertificateTypePreferences::prefer_raw_public_key(),
        }
    }
}

/// Unique identifier for a negotiation session
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NegotiationId(u64);

impl NegotiationId {
    /// Generate a new unique negotiation ID
    pub fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    /// Get the raw ID value
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

/// Cache key for negotiation results
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    /// Our certificate type preferences
    local_preferences: String, // Serialized preferences for hashing
    /// Remote certificate type preferences  
    remote_preferences: String, // Serialized preferences for hashing
}

impl CacheKey {
    /// Create a cache key from preferences
    fn new(
        local: &CertificateTypePreferences,
        remote_client: Option<&CertificateTypeList>,
        remote_server: Option<&CertificateTypeList>,
    ) -> Self {
        use std::collections::hash_map::DefaultHasher;

        let mut hasher = DefaultHasher::new();
        local.hash(&mut hasher);
        let local_hash = hasher.finish();

        let mut hasher = DefaultHasher::new();
        if let Some(types) = remote_client {
            types.hash(&mut hasher);
        }
        if let Some(types) = remote_server {
            types.hash(&mut hasher);
        }
        let remote_hash = hasher.finish();

        Self {
            local_preferences: format!("{:x}", local_hash),
            remote_preferences: format!("{:x}", remote_hash),
        }
    }
}

/// Hash implementation for CertificateTypePreferences
impl Hash for CertificateTypePreferences {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.client_types.types.hash(state);
        self.server_types.types.hash(state);
        self.require_extensions.hash(state);
        self.fallback_client.hash(state);
        self.fallback_server.hash(state);
    }
}

/// Hash implementation for CertificateTypeList  
impl Hash for CertificateTypeList {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.types.hash(state);
    }
}

/// Certificate type negotiation manager
pub struct CertificateNegotiationManager {
    /// Configuration for negotiation behavior
    config: NegotiationConfig,
    /// Active negotiation sessions
    sessions: RwLock<HashMap<NegotiationId, NegotiationState>>,
    /// Result cache for performance optimization
    cache: Arc<Mutex<HashMap<CacheKey, (NegotiationResult, Instant)>>>,
    /// Negotiation statistics
    stats: Arc<Mutex<NegotiationStats>>,
}

/// Statistics for certificate type negotiation
#[derive(Debug, Default, Clone)]
pub struct NegotiationStats {
    /// Total number of negotiations attempted
    pub total_attempts: u64,
    /// Number of successful negotiations
    pub successful: u64,
    /// Number of failed negotiations
    pub failed: u64,
    /// Number of timed out negotiations
    pub timed_out: u64,
    /// Number of cache hits
    pub cache_hits: u64,
    /// Number of cache misses
    pub cache_misses: u64,
    /// Average negotiation time
    pub avg_negotiation_time: Duration,
}

impl CertificateNegotiationManager {
    /// Create a new negotiation manager
    pub fn new(config: NegotiationConfig) -> Self {
        Self {
            config,
            sessions: RwLock::new(HashMap::new()),
            cache: Arc::new(Mutex::new(HashMap::new())),
            stats: Arc::new(Mutex::new(NegotiationStats::default())),
        }
    }

    /// Start a new certificate type negotiation
    pub fn start_negotiation(&self, preferences: CertificateTypePreferences) -> NegotiationId {
        let id = NegotiationId::new();
        let state = NegotiationState::Waiting {
            sent_at: Instant::now(),
            our_preferences: preferences,
        };

        let mut sessions = self.sessions.write().unwrap();
        sessions.insert(id, state);

        let mut stats = self.stats.lock().unwrap();
        stats.total_attempts += 1;

        debug!("Started certificate type negotiation: {:?}", id);
        id
    }

    /// Complete a negotiation with remote preferences
    pub fn complete_negotiation(
        &self,
        id: NegotiationId,
        remote_client_types: Option<CertificateTypeList>,
        remote_server_types: Option<CertificateTypeList>,
    ) -> Result<NegotiationResult, TlsExtensionError> {
        let _span = span!(Level::DEBUG, "complete_negotiation", id = id.as_u64()).entered();

        let mut sessions = self.sessions.write().unwrap();
        let state = sessions.get(&id).ok_or_else(|| {
            TlsExtensionError::InvalidExtensionData(format!("Unknown negotiation ID: {:?}", id))
        })?;

        let our_preferences = match state {
            NegotiationState::Waiting {
                our_preferences, ..
            } => our_preferences.clone(),
            _ => {
                return Err(TlsExtensionError::InvalidExtensionData(
                    "Negotiation not in waiting state".to_string(),
                ));
            }
        };

        // Check cache first if enabled
        if self.config.enable_caching {
            let cache_key = CacheKey::new(
                &our_preferences,
                remote_client_types.as_ref(),
                remote_server_types.as_ref(),
            );

            let mut cache = self.cache.lock().unwrap();
            if let Some((cached_result, cached_at)) = cache.get(&cache_key) {
                // Check if cache entry is still valid (not expired)
                if cached_at.elapsed() < Duration::from_secs(300) {
                    // 5 minute cache
                    let mut stats = self.stats.lock().unwrap();
                    stats.cache_hits += 1;

                    // Update session state
                    sessions.insert(
                        id,
                        NegotiationState::Completed {
                            result: cached_result.clone(),
                            completed_at: Instant::now(),
                        },
                    );

                    debug!("Cache hit for negotiation: {:?}", id);
                    return Ok(cached_result.clone());
                } else {
                    // Remove expired entry
                    cache.remove(&cache_key);
                }
            }

            let mut stats = self.stats.lock().unwrap();
            stats.cache_misses += 1;
        }

        // Perform actual negotiation
        let negotiation_start = Instant::now();
        let result =
            our_preferences.negotiate(remote_client_types.as_ref(), remote_server_types.as_ref());

        match result {
            Ok(negotiation_result) => {
                let completed_at = Instant::now();
                let negotiation_time = negotiation_start.elapsed();

                // Update session state
                sessions.insert(
                    id,
                    NegotiationState::Completed {
                        result: negotiation_result.clone(),
                        completed_at,
                    },
                );

                // Update statistics
                let mut stats = self.stats.lock().unwrap();
                stats.successful += 1;

                // Update average negotiation time (simple moving average)
                let total_completed = stats.successful + stats.failed;
                stats.avg_negotiation_time = if total_completed == 1 {
                    negotiation_time
                } else {
                    Duration::from_nanos(
                        (stats.avg_negotiation_time.as_nanos() as u64 * (total_completed - 1)
                            + negotiation_time.as_nanos() as u64)
                            / total_completed,
                    )
                };

                // Cache the result if caching is enabled
                if self.config.enable_caching {
                    let cache_key = CacheKey::new(
                        &our_preferences,
                        remote_client_types.as_ref(),
                        remote_server_types.as_ref(),
                    );

                    let mut cache = self.cache.lock().unwrap();

                    // Evict old entries if cache is full
                    if cache.len() >= self.config.max_cache_size {
                        // Simple eviction: remove oldest entries
                        let mut entries: Vec<_> = cache
                            .iter()
                            .map(|(k, (_, t))| (k.clone(), t.clone()))
                            .collect();
                        entries.sort_by_key(|(_, timestamp)| *timestamp);

                        let to_remove = cache.len() - self.config.max_cache_size + 1;
                        let keys_to_remove: Vec<_> = entries
                            .iter()
                            .take(to_remove)
                            .map(|(key, _)| key.clone())
                            .collect();

                        for key in keys_to_remove {
                            cache.remove(&key);
                        }
                    }

                    cache.insert(cache_key, (negotiation_result.clone(), completed_at));
                }

                info!(
                    "Certificate type negotiation completed successfully: {:?} -> client={}, server={}",
                    id, negotiation_result.client_cert_type, negotiation_result.server_cert_type
                );

                Ok(negotiation_result)
            }
            Err(error) => {
                // Update session state
                sessions.insert(
                    id,
                    NegotiationState::Failed {
                        error: error.to_string(),
                        failed_at: Instant::now(),
                    },
                );

                // Update statistics
                let mut stats = self.stats.lock().unwrap();
                stats.failed += 1;

                warn!("Certificate type negotiation failed: {:?} -> {}", id, error);
                Err(error)
            }
        }
    }

    /// Fail a negotiation with an error
    pub fn fail_negotiation(&self, id: NegotiationId, error: String) {
        let mut sessions = self.sessions.write().unwrap();
        sessions.insert(
            id,
            NegotiationState::Failed {
                error,
                failed_at: Instant::now(),
            },
        );

        let mut stats = self.stats.lock().unwrap();
        stats.failed += 1;

        warn!("Certificate type negotiation failed: {:?}", id);
    }

    /// Get the current state of a negotiation
    pub fn get_negotiation_state(&self, id: NegotiationId) -> Option<NegotiationState> {
        let sessions = self.sessions.read().unwrap();
        sessions.get(&id).cloned()
    }

    /// Check for and handle timed out negotiations
    pub fn handle_timeouts(&self) {
        let mut sessions = self.sessions.write().unwrap();
        let mut timed_out_ids = Vec::new();

        for (id, state) in sessions.iter() {
            if let NegotiationState::Waiting { sent_at, .. } = state {
                if sent_at.elapsed() > self.config.timeout {
                    timed_out_ids.push(*id);
                }
            }
        }

        for id in timed_out_ids {
            sessions.insert(
                id,
                NegotiationState::TimedOut {
                    timeout_at: Instant::now(),
                },
            );

            let mut stats = self.stats.lock().unwrap();
            stats.timed_out += 1;

            warn!("Certificate type negotiation timed out: {:?}", id);
        }
    }

    /// Clean up completed negotiations older than the specified duration
    pub fn cleanup_old_sessions(&self, max_age: Duration) {
        let mut sessions = self.sessions.write().unwrap();
        let cutoff = Instant::now() - max_age;

        sessions.retain(|id, state| {
            let should_retain = match state {
                NegotiationState::Completed { completed_at, .. } => *completed_at > cutoff,
                NegotiationState::Failed { failed_at, .. } => *failed_at > cutoff,
                NegotiationState::TimedOut { timeout_at, .. } => *timeout_at > cutoff,
                _ => true, // Keep pending and waiting sessions
            };

            if !should_retain {
                debug!("Cleaned up old negotiation session: {:?}", id);
            }

            should_retain
        });
    }

    /// Get current negotiation statistics
    pub fn get_stats(&self) -> NegotiationStats {
        self.stats.lock().unwrap().clone()
    }

    /// Clear all cached results
    pub fn clear_cache(&self) {
        let mut cache = self.cache.lock().unwrap();
        cache.clear();
        debug!("Cleared certificate type negotiation cache");
    }

    /// Get cache statistics
    pub fn get_cache_stats(&self) -> (usize, usize) {
        let cache = self.cache.lock().unwrap();
        (cache.len(), self.config.max_cache_size)
    }
}

impl Default for CertificateNegotiationManager {
    fn default() -> Self {
        Self::new(NegotiationConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::super::tls_extensions::CertificateType;
    use super::*;

    #[test]
    fn test_negotiation_id_generation() {
        let id1 = NegotiationId::new();
        let id2 = NegotiationId::new();

        assert_ne!(id1, id2);
        assert!(id1.as_u64() > 0);
        assert!(id2.as_u64() > 0);
    }

    #[test]
    fn test_negotiation_state_checks() {
        let pending = NegotiationState::Pending;
        assert!(!pending.is_complete());
        assert!(!pending.is_successful());

        let completed = NegotiationState::Completed {
            result: NegotiationResult::new(CertificateType::RawPublicKey, CertificateType::X509),
            completed_at: Instant::now(),
        };
        assert!(completed.is_complete());
        assert!(completed.is_successful());
        assert!(completed.get_result().is_some());

        let failed = NegotiationState::Failed {
            error: "Test error".to_string(),
            failed_at: Instant::now(),
        };
        assert!(failed.is_complete());
        assert!(!failed.is_successful());
        assert_eq!(failed.get_error().unwrap(), "Test error");
    }

    #[test]
    fn test_negotiation_manager_basic_flow() {
        let manager = CertificateNegotiationManager::default();
        let preferences = CertificateTypePreferences::prefer_raw_public_key();

        // Start negotiation
        let id = manager.start_negotiation(preferences);

        let state = manager.get_negotiation_state(id).unwrap();
        assert!(matches!(state, NegotiationState::Waiting { .. }));

        // Complete negotiation
        let remote_types = CertificateTypeList::raw_public_key_only();
        let result = manager
            .complete_negotiation(id, Some(remote_types.clone()), Some(remote_types))
            .unwrap();

        assert_eq!(result.client_cert_type, CertificateType::RawPublicKey);
        assert_eq!(result.server_cert_type, CertificateType::RawPublicKey);

        let state = manager.get_negotiation_state(id).unwrap();
        assert!(state.is_successful());
    }

    #[test]
    fn test_negotiation_caching() {
        let config = NegotiationConfig {
            enable_caching: true,
            ..Default::default()
        };
        let manager = CertificateNegotiationManager::new(config);
        let preferences = CertificateTypePreferences::prefer_raw_public_key();

        // First negotiation
        let id1 = manager.start_negotiation(preferences.clone());
        let remote_types = CertificateTypeList::raw_public_key_only();
        let result1 = manager
            .complete_negotiation(id1, Some(remote_types.clone()), Some(remote_types.clone()))
            .unwrap();

        // Second negotiation with same preferences should hit cache
        let id2 = manager.start_negotiation(preferences);
        let result2 = manager
            .complete_negotiation(id2, Some(remote_types.clone()), Some(remote_types))
            .unwrap();

        assert_eq!(result1, result2);

        let stats = manager.get_stats();
        assert_eq!(stats.cache_hits, 1);
        assert_eq!(stats.cache_misses, 1);
    }

    #[test]
    fn test_negotiation_timeout_handling() {
        let config = NegotiationConfig {
            timeout: Duration::from_millis(1),
            ..Default::default()
        };
        let manager = CertificateNegotiationManager::new(config);
        let preferences = CertificateTypePreferences::prefer_raw_public_key();

        let id = manager.start_negotiation(preferences);

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(10));
        manager.handle_timeouts();

        let state = manager.get_negotiation_state(id).unwrap();
        assert!(matches!(state, NegotiationState::TimedOut { .. }));

        let stats = manager.get_stats();
        assert_eq!(stats.timed_out, 1);
    }
}
