//! Bootstrap cache configuration.

use std::path::PathBuf;
use std::time::Duration;

/// Configuration for the bootstrap cache
#[derive(Debug, Clone)]
pub struct BootstrapCacheConfig {
    /// Directory for cache files
    pub cache_dir: PathBuf,

    /// Maximum number of peers to cache (default: 20,000)
    pub max_peers: usize,

    /// Epsilon for exploration rate (default: 0.1 = 10%)
    /// Higher values = more exploration of unknown peers
    pub epsilon: f64,

    /// Time after which peers are considered stale (default: 7 days)
    pub stale_threshold: Duration,

    /// Interval between background save operations (default: 5 minutes)
    pub save_interval: Duration,

    /// Interval between quality score recalculations (default: 1 hour)
    pub quality_update_interval: Duration,

    /// Interval between stale peer cleanup (default: 6 hours)
    pub cleanup_interval: Duration,

    /// Minimum peers required before saving (prevents empty cache overwrite)
    pub min_peers_to_save: usize,

    /// Enable file locking for multi-process safety
    pub enable_file_locking: bool,

    /// Quality score weights
    pub weights: QualityWeights,
}

/// Weights for quality score calculation
#[derive(Debug, Clone)]
pub struct QualityWeights {
    /// Weight for success rate component (default: 0.4)
    pub success_rate: f64,
    /// Weight for RTT component (default: 0.25)
    pub rtt: f64,
    /// Weight for age/freshness component (default: 0.15)
    pub freshness: f64,
    /// Weight for capability bonuses (default: 0.2)
    pub capabilities: f64,
}

impl Default for BootstrapCacheConfig {
    fn default() -> Self {
        Self {
            cache_dir: default_cache_dir(),
            max_peers: 20_000,
            epsilon: 0.1,
            stale_threshold: Duration::from_secs(7 * 24 * 3600), // 7 days
            save_interval: Duration::from_secs(5 * 60),          // 5 minutes
            quality_update_interval: Duration::from_secs(3600),  // 1 hour
            cleanup_interval: Duration::from_secs(6 * 3600),     // 6 hours
            min_peers_to_save: 10,
            enable_file_locking: true,
            weights: QualityWeights::default(),
        }
    }
}

impl Default for QualityWeights {
    fn default() -> Self {
        Self {
            success_rate: 0.4,
            rtt: 0.25,
            freshness: 0.15,
            capabilities: 0.2,
        }
    }
}

impl BootstrapCacheConfig {
    /// Create a new configuration builder
    pub fn builder() -> BootstrapCacheConfigBuilder {
        BootstrapCacheConfigBuilder::default()
    }
}

/// Builder for BootstrapCacheConfig
#[derive(Default)]
pub struct BootstrapCacheConfigBuilder {
    config: BootstrapCacheConfig,
}

impl BootstrapCacheConfigBuilder {
    /// Set the cache directory
    pub fn cache_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.config.cache_dir = dir.into();
        self
    }

    /// Set maximum number of peers
    pub fn max_peers(mut self, max: usize) -> Self {
        self.config.max_peers = max;
        self
    }

    /// Set epsilon for exploration rate (clamped to 0.0-1.0)
    pub fn epsilon(mut self, epsilon: f64) -> Self {
        self.config.epsilon = epsilon.clamp(0.0, 1.0);
        self
    }

    /// Set stale threshold duration
    pub fn stale_threshold(mut self, duration: Duration) -> Self {
        self.config.stale_threshold = duration;
        self
    }

    /// Set save interval
    pub fn save_interval(mut self, duration: Duration) -> Self {
        self.config.save_interval = duration;
        self
    }

    /// Set quality update interval
    pub fn quality_update_interval(mut self, duration: Duration) -> Self {
        self.config.quality_update_interval = duration;
        self
    }

    /// Set cleanup interval
    pub fn cleanup_interval(mut self, duration: Duration) -> Self {
        self.config.cleanup_interval = duration;
        self
    }

    /// Set minimum peers required to save
    pub fn min_peers_to_save(mut self, min: usize) -> Self {
        self.config.min_peers_to_save = min;
        self
    }

    /// Enable or disable file locking
    pub fn enable_file_locking(mut self, enable: bool) -> Self {
        self.config.enable_file_locking = enable;
        self
    }

    /// Set quality weights
    pub fn weights(mut self, weights: QualityWeights) -> Self {
        self.config.weights = weights;
        self
    }

    /// Build the configuration
    pub fn build(self) -> BootstrapCacheConfig {
        self.config
    }
}

fn default_cache_dir() -> PathBuf {
    // Try platform-specific cache directory, fallback to current directory
    if let Some(cache_dir) = dirs::cache_dir() {
        cache_dir.join("ant-quic")
    } else if let Some(home) = dirs::home_dir() {
        home.join(".cache").join("ant-quic")
    } else {
        PathBuf::from(".ant-quic-cache")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = BootstrapCacheConfig::default();
        assert_eq!(config.max_peers, 20_000);
        assert!((config.epsilon - 0.1).abs() < f64::EPSILON);
        assert_eq!(config.stale_threshold, Duration::from_secs(7 * 24 * 3600));
    }

    #[test]
    fn test_builder() {
        let config = BootstrapCacheConfig::builder()
            .max_peers(10_000)
            .epsilon(0.2)
            .cache_dir("/tmp/test")
            .build();

        assert_eq!(config.max_peers, 10_000);
        assert!((config.epsilon - 0.2).abs() < f64::EPSILON);
        assert_eq!(config.cache_dir, PathBuf::from("/tmp/test"));
    }

    #[test]
    fn test_epsilon_clamping() {
        let config = BootstrapCacheConfig::builder().epsilon(1.5).build();
        assert!((config.epsilon - 1.0).abs() < f64::EPSILON);

        let config = BootstrapCacheConfig::builder().epsilon(-0.5).build();
        assert!(config.epsilon.abs() < f64::EPSILON);
    }
}
