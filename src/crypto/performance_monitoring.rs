//! Performance Monitoring and Optimization for Certificate Type Negotiation
//!
//! This module provides performance monitoring, optimization features, and
//! production hardening for the RFC 7250 certificate type negotiation system.

use std::{
    sync::{Arc, Mutex, atomic::{AtomicU64, AtomicBool, Ordering}},
    time::{Duration, Instant},
    collections::VecDeque,
};

use tracing::{info, warn, span, Level};

use super::{
    tls_extensions::NegotiationResult,
};

/// Performance metrics for certificate type negotiation
#[derive(Debug, Default)]
pub struct CertTypePerformanceMetrics {
    /// Total number of negotiations
    pub total_negotiations: AtomicU64,
    /// Successful negotiations
    pub successful_negotiations: AtomicU64,
    /// Failed negotiations
    pub failed_negotiations: AtomicU64,
    /// Cache hits
    pub cache_hits: AtomicU64,
    /// Cache misses
    pub cache_misses: AtomicU64,
    /// Total negotiation time in nanoseconds
    pub total_negotiation_time_ns: AtomicU64,
    /// Number of extension parsing operations
    pub extension_parsing_ops: AtomicU64,
    /// Total extension parsing time in nanoseconds
    pub extension_parsing_time_ns: AtomicU64,
    /// Raw Public Key connections
    pub rpk_connections: AtomicU64,
    /// X.509 connections
    pub x509_connections: AtomicU64,
    /// Mixed certificate type connections
    pub mixed_connections: AtomicU64,
}

impl CertTypePerformanceMetrics {
    /// Record a negotiation attempt
    pub fn record_negotiation(&self, duration: Duration, success: bool, result: Option<&NegotiationResult>) {
        self.total_negotiations.fetch_add(1, Ordering::Relaxed);
        self.total_negotiation_time_ns.fetch_add(duration.as_nanos() as u64, Ordering::Relaxed);

        if success {
            self.successful_negotiations.fetch_add(1, Ordering::Relaxed);
            
            if let Some(result) = result {
                if result.is_raw_public_key_only() {
                    self.rpk_connections.fetch_add(1, Ordering::Relaxed);
                } else if result.is_x509_only() {
                    self.x509_connections.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.mixed_connections.fetch_add(1, Ordering::Relaxed);
                }
            }
        } else {
            self.failed_negotiations.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record cache hit/miss
    pub fn record_cache_access(&self, hit: bool) {
        if hit {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.cache_misses.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record extension parsing operation
    pub fn record_extension_parsing(&self, duration: Duration) {
        self.extension_parsing_ops.fetch_add(1, Ordering::Relaxed);
        self.extension_parsing_time_ns.fetch_add(duration.as_nanos() as u64, Ordering::Relaxed);
    }

    /// Get average negotiation time
    pub fn avg_negotiation_time(&self) -> Duration {
        let total = self.total_negotiations.load(Ordering::Relaxed);
        if total > 0 {
            Duration::from_nanos(self.total_negotiation_time_ns.load(Ordering::Relaxed) / total)
        } else {
            Duration::ZERO
        }
    }

    /// Get cache hit rate
    pub fn cache_hit_rate(&self) -> f64 {
        let hits = self.cache_hits.load(Ordering::Relaxed) as f64;
        let misses = self.cache_misses.load(Ordering::Relaxed) as f64;
        let total = hits + misses;
        
        if total > 0.0 {
            hits / total
        } else {
            0.0
        }
    }

    /// Get success rate
    pub fn success_rate(&self) -> f64 {
        let total = self.total_negotiations.load(Ordering::Relaxed) as f64;
        let successful = self.successful_negotiations.load(Ordering::Relaxed) as f64;
        
        if total > 0.0 {
            successful / total
        } else {
            0.0
        }
    }

    /// Get Raw Public Key usage percentage
    pub fn rpk_usage_percentage(&self) -> f64 {
        let total = self.successful_negotiations.load(Ordering::Relaxed) as f64;
        let rpk = self.rpk_connections.load(Ordering::Relaxed) as f64;
        
        if total > 0.0 {
            (rpk / total) * 100.0
        } else {
            0.0
        }
    }

    /// Get average extension parsing time
    pub fn avg_extension_parsing_time(&self) -> Duration {
        let ops = self.extension_parsing_ops.load(Ordering::Relaxed);
        if ops > 0 {
            Duration::from_nanos(self.extension_parsing_time_ns.load(Ordering::Relaxed) / ops)
        } else {
            Duration::ZERO
        }
    }

    /// Reset all metrics
    pub fn reset(&self) {
        self.total_negotiations.store(0, Ordering::Relaxed);
        self.successful_negotiations.store(0, Ordering::Relaxed);
        self.failed_negotiations.store(0, Ordering::Relaxed);
        self.cache_hits.store(0, Ordering::Relaxed);
        self.cache_misses.store(0, Ordering::Relaxed);
        self.total_negotiation_time_ns.store(0, Ordering::Relaxed);
        self.extension_parsing_ops.store(0, Ordering::Relaxed);
        self.extension_parsing_time_ns.store(0, Ordering::Relaxed);
        self.rpk_connections.store(0, Ordering::Relaxed);
        self.x509_connections.store(0, Ordering::Relaxed);
        self.mixed_connections.store(0, Ordering::Relaxed);
    }
}

/// Real-time performance monitoring with sliding windows
#[derive(Debug)]
pub struct CertTypePerformanceMonitor {
    /// Global performance metrics
    metrics: Arc<CertTypePerformanceMetrics>,
    /// Sliding window for recent performance data
    recent_negotiations: Arc<Mutex<VecDeque<NegotiationSample>>>,
    /// Window size for recent data
    window_size: usize,
    /// Performance alerts
    alerts: Arc<Mutex<Vec<PerformanceAlert>>>,
    /// Alert thresholds
    thresholds: PerformanceThresholds,
    /// Whether monitoring is enabled
    enabled: AtomicBool,
}

/// Sample of a single negotiation for performance analysis
#[derive(Debug, Clone)]
struct NegotiationSample {
    timestamp: Instant,
    duration: Duration,
    success: bool,
    cert_type: Option<NegotiationResult>,
    cache_hit: bool,
}

/// Performance alert types
#[derive(Debug, Clone)]
pub enum PerformanceAlert {
    HighNegotiationLatency {
        avg_latency: Duration,
        threshold: Duration,
        timestamp: Instant,
    },
    LowSuccessRate {
        success_rate: f64,
        threshold: f64,
        timestamp: Instant,
    },
    LowCacheHitRate {
        hit_rate: f64,
        threshold: f64,
        timestamp: Instant,
    },
    HighErrorRate {
        error_rate: f64,
        threshold: f64,
        timestamp: Instant,
    },
}

/// Configurable performance thresholds
#[derive(Debug, Clone)]
pub struct PerformanceThresholds {
    /// Maximum acceptable average negotiation latency
    pub max_avg_latency: Duration,
    /// Minimum acceptable success rate
    pub min_success_rate: f64,
    /// Minimum acceptable cache hit rate
    pub min_cache_hit_rate: f64,
    /// Maximum acceptable error rate
    pub max_error_rate: f64,
}

impl Default for PerformanceThresholds {
    fn default() -> Self {
        Self {
            max_avg_latency: Duration::from_millis(100),
            min_success_rate: 0.95,
            min_cache_hit_rate: 0.80,
            max_error_rate: 0.05,
        }
    }
}

impl CertTypePerformanceMonitor {
    /// Create a new performance monitor
    pub fn new(window_size: usize, thresholds: PerformanceThresholds) -> Self {
        Self {
            metrics: Arc::new(CertTypePerformanceMetrics::default()),
            recent_negotiations: Arc::new(Mutex::new(VecDeque::with_capacity(window_size))),
            window_size,
            alerts: Arc::new(Mutex::new(Vec::new())),
            thresholds,
            enabled: AtomicBool::new(true),
        }
    }

    /// Enable or disable monitoring
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    /// Check if monitoring is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Record a negotiation attempt
    pub fn record_negotiation(
        &self,
        duration: Duration,
        success: bool,
        result: Option<NegotiationResult>,
        cache_hit: bool,
    ) {
        if !self.is_enabled() {
            return;
        }

        let _span = span!(Level::TRACE, "record_negotiation", 
                          duration_ms = duration.as_millis(), %success).entered();

        // Update global metrics
        self.metrics.record_negotiation(duration, success, result.as_ref());
        self.metrics.record_cache_access(cache_hit);

        // Add to sliding window
        let sample = NegotiationSample {
            timestamp: Instant::now(),
            duration,
            success,
            cert_type: result,
            cache_hit,
        };

        {
            let mut window = self.recent_negotiations.lock().unwrap();
            window.push_back(sample);
            
            // Maintain window size
            while window.len() > self.window_size {
                window.pop_front();
            }
        }

        // Check for performance issues
        self.check_performance_alerts();
    }

    /// Record extension parsing performance
    pub fn record_extension_parsing(&self, duration: Duration) {
        if self.is_enabled() {
            self.metrics.record_extension_parsing(duration);
        }
    }

    /// Get current performance metrics
    pub fn get_metrics(&self) -> Arc<CertTypePerformanceMetrics> {
        self.metrics.clone()
    }

    /// Get recent performance data
    pub fn get_recent_performance(&self, duration: Duration) -> RecentPerformanceData {
        let window = self.recent_negotiations.lock().unwrap();
        let cutoff = Instant::now() - duration;
        
        let recent_samples: Vec<_> = window.iter()
            .filter(|sample| sample.timestamp > cutoff)
            .cloned()
            .collect();

        if recent_samples.is_empty() {
            return RecentPerformanceData::default();
        }

        let total_samples = recent_samples.len();
        let successful_samples = recent_samples.iter().filter(|s| s.success).count();
        let cache_hits = recent_samples.iter().filter(|s| s.cache_hit).count();
        
        let total_duration: Duration = recent_samples.iter().map(|s| s.duration).sum();
        let avg_duration = total_duration / total_samples as u32;
        
        let success_rate = successful_samples as f64 / total_samples as f64;
        let cache_hit_rate = cache_hits as f64 / total_samples as f64;

        RecentPerformanceData {
            sample_count: total_samples,
            avg_duration,
            success_rate,
            cache_hit_rate,
            time_window: duration,
        }
    }

    /// Check for performance alerts
    fn check_performance_alerts(&self) {
        let recent = self.get_recent_performance(Duration::from_secs(60)); // Last minute
        
        if recent.sample_count < 10 {
            return; // Not enough data
        }

        let mut new_alerts = Vec::new();
        let now = Instant::now();

        // Check latency
        if recent.avg_duration > self.thresholds.max_avg_latency {
            new_alerts.push(PerformanceAlert::HighNegotiationLatency {
                avg_latency: recent.avg_duration,
                threshold: self.thresholds.max_avg_latency,
                timestamp: now,
            });
        }

        // Check success rate
        if recent.success_rate < self.thresholds.min_success_rate {
            new_alerts.push(PerformanceAlert::LowSuccessRate {
                success_rate: recent.success_rate,
                threshold: self.thresholds.min_success_rate,
                timestamp: now,
            });
        }

        // Check cache hit rate
        if recent.cache_hit_rate < self.thresholds.min_cache_hit_rate {
            new_alerts.push(PerformanceAlert::LowCacheHitRate {
                hit_rate: recent.cache_hit_rate,
                threshold: self.thresholds.min_cache_hit_rate,
                timestamp: now,
            });
        }

        // Check error rate
        let error_rate = 1.0 - recent.success_rate;
        if error_rate > self.thresholds.max_error_rate {
            new_alerts.push(PerformanceAlert::HighErrorRate {
                error_rate,
                threshold: self.thresholds.max_error_rate,
                timestamp: now,
            });
        }

        // Add new alerts
        if !new_alerts.is_empty() {
            let mut alerts = self.alerts.lock().unwrap();
            for alert in new_alerts {
                warn!("Performance alert: {:?}", alert);
                alerts.push(alert);
            }

            // Limit alert history size
            const MAX_ALERTS: usize = 100;
            while alerts.len() > MAX_ALERTS {
                alerts.remove(0);
            }
        }
    }

    /// Get recent performance alerts
    pub fn get_alerts(&self, max_age: Duration) -> Vec<PerformanceAlert> {
        let alerts = self.alerts.lock().unwrap();
        let cutoff = Instant::now() - max_age;
        
        alerts.iter()
            .filter(|alert| {
                let timestamp = match alert {
                    PerformanceAlert::HighNegotiationLatency { timestamp, .. } => *timestamp,
                    PerformanceAlert::LowSuccessRate { timestamp, .. } => *timestamp,
                    PerformanceAlert::LowCacheHitRate { timestamp, .. } => *timestamp,
                    PerformanceAlert::HighErrorRate { timestamp, .. } => *timestamp,
                };
                timestamp > cutoff
            })
            .cloned()
            .collect()
    }

    /// Clear old alerts
    pub fn clear_old_alerts(&self, max_age: Duration) {
        let mut alerts = self.alerts.lock().unwrap();
        let cutoff = Instant::now() - max_age;
        
        alerts.retain(|alert| {
            let timestamp = match alert {
                PerformanceAlert::HighNegotiationLatency { timestamp, .. } => *timestamp,
                PerformanceAlert::LowSuccessRate { timestamp, .. } => *timestamp,
                PerformanceAlert::LowCacheHitRate { timestamp, .. } => *timestamp,
                PerformanceAlert::HighErrorRate { timestamp, .. } => *timestamp,
            };
            timestamp > cutoff
        });
    }

    /// Get performance summary
    pub fn get_summary(&self) -> PerformanceSummary {
        let metrics = &self.metrics;
        let recent = self.get_recent_performance(Duration::from_secs(300)); // Last 5 minutes
        let alerts = self.get_alerts(Duration::from_secs(300));

        PerformanceSummary {
            total_negotiations: metrics.total_negotiations.load(Ordering::Relaxed),
            avg_negotiation_time: metrics.avg_negotiation_time(),
            success_rate: metrics.success_rate(),
            cache_hit_rate: metrics.cache_hit_rate(),
            rpk_usage_percentage: metrics.rpk_usage_percentage(),
            recent_performance: recent,
            active_alerts: alerts.len(),
            monitoring_enabled: self.is_enabled(),
        }
    }

    /// Reset all performance data
    pub fn reset(&self) {
        self.metrics.reset();
        self.recent_negotiations.lock().unwrap().clear();
        self.alerts.lock().unwrap().clear();
        info!("Performance monitoring data reset");
    }
}

/// Recent performance data over a time window
#[derive(Debug, Default, Clone)]
pub struct RecentPerformanceData {
    pub sample_count: usize,
    pub avg_duration: Duration,
    pub success_rate: f64,
    pub cache_hit_rate: f64,
    pub time_window: Duration,
}

/// Performance summary for reporting
#[derive(Debug, Clone)]
pub struct PerformanceSummary {
    pub total_negotiations: u64,
    pub avg_negotiation_time: Duration,
    pub success_rate: f64,
    pub cache_hit_rate: f64,
    pub rpk_usage_percentage: f64,
    pub recent_performance: RecentPerformanceData,
    pub active_alerts: usize,
    pub monitoring_enabled: bool,
}

/// Production hardening configuration
#[derive(Debug, Clone)]
pub struct ProductionHardeningConfig {
    /// Enable performance monitoring
    pub enable_monitoring: bool,
    /// Enable detailed tracing (may impact performance)
    pub enable_detailed_tracing: bool,
    /// Maximum negotiation timeout
    pub max_negotiation_timeout: Duration,
    /// Maximum cache size
    pub max_cache_size: usize,
    /// Enable automatic cache cleanup
    pub enable_cache_cleanup: bool,
    /// Cache cleanup interval
    pub cache_cleanup_interval: Duration,
    /// Enable rate limiting
    pub enable_rate_limiting: bool,
    /// Maximum negotiations per second
    pub max_negotiations_per_second: u64,
}

impl Default for ProductionHardeningConfig {
    fn default() -> Self {
        Self {
            enable_monitoring: true,
            enable_detailed_tracing: false,
            max_negotiation_timeout: Duration::from_secs(30),
            max_cache_size: 10000,
            enable_cache_cleanup: true,
            cache_cleanup_interval: Duration::from_secs(300), // 5 minutes
            enable_rate_limiting: true,
            max_negotiations_per_second: 1000,
        }
    }
}

/// Production-ready certificate type negotiation system
pub struct ProductionCertTypeSystem {
    /// Performance monitor
    monitor: Arc<CertTypePerformanceMonitor>,
    /// Production configuration
    config: ProductionHardeningConfig,
    /// Rate limiting state
    rate_limiter: Arc<Mutex<RateLimiter>>,
}

/// Simple rate limiter implementation
#[derive(Debug)]
struct RateLimiter {
    max_per_second: u64,
    current_count: u64,
    last_reset: Instant,
}

impl RateLimiter {
    fn new(max_per_second: u64) -> Self {
        Self {
            max_per_second,
            current_count: 0,
            last_reset: Instant::now(),
        }
    }

    fn check_and_increment(&mut self) -> bool {
        let now = Instant::now();
        
        // Reset counter every second
        if now.duration_since(self.last_reset) >= Duration::from_secs(1) {
            self.current_count = 0;
            self.last_reset = now;
        }

        if self.current_count < self.max_per_second {
            self.current_count += 1;
            true
        } else {
            false
        }
    }
}

impl ProductionCertTypeSystem {
    /// Create a new production system
    pub fn new(config: ProductionHardeningConfig) -> Self {
        let thresholds = PerformanceThresholds::default();
        let monitor = Arc::new(CertTypePerformanceMonitor::new(1000, thresholds));
        monitor.set_enabled(config.enable_monitoring);

        Self {
            monitor,
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(config.max_negotiations_per_second))),
            config,
        }
    }

    /// Check if a negotiation is allowed (rate limiting)
    pub fn check_negotiation_allowed(&self) -> bool {
        if !self.config.enable_rate_limiting {
            return true;
        }

        self.rate_limiter.lock().unwrap().check_and_increment()
    }

    /// Get performance monitor
    pub fn monitor(&self) -> &Arc<CertTypePerformanceMonitor> {
        &self.monitor
    }

    /// Get production configuration
    pub fn config(&self) -> &ProductionHardeningConfig {
        &self.config
    }

    /// Generate production health report
    pub fn health_report(&self) -> ProductionHealthReport {
        let summary = self.monitor.get_summary();
        let alerts = self.monitor.get_alerts(Duration::from_secs(300));
        
        let health_status = if alerts.is_empty() && 
                              summary.success_rate > 0.95 && 
                              summary.avg_negotiation_time < Duration::from_millis(100) {
            HealthStatus::Healthy
        } else if summary.success_rate > 0.90 {
            HealthStatus::Warning
        } else {
            HealthStatus::Critical
        };

        ProductionHealthReport {
            status: health_status,
            performance_summary: summary,
            recent_alerts: alerts,
            timestamp: Instant::now(),
        }
    }
}

/// Health status for production systems
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Warning,
    Critical,
}

/// Production health report
#[derive(Debug, Clone)]
pub struct ProductionHealthReport {
    pub status: HealthStatus,
    pub performance_summary: PerformanceSummary,
    pub recent_alerts: Vec<PerformanceAlert>,
    pub timestamp: Instant,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::tls_extensions::CertificateType;

    #[test]
    fn test_performance_metrics() {
        let metrics = CertTypePerformanceMetrics::default();
        
        let result = NegotiationResult::new(
            CertificateType::RawPublicKey,
            CertificateType::RawPublicKey,
        );
        
        metrics.record_negotiation(Duration::from_millis(50), true, Some(&result));
        metrics.record_cache_access(true);

        assert_eq!(metrics.total_negotiations.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.successful_negotiations.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.rpk_connections.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.cache_hits.load(Ordering::Relaxed), 1);
        
        assert!(metrics.avg_negotiation_time() > Duration::ZERO);
        assert_eq!(metrics.cache_hit_rate(), 1.0);
        assert_eq!(metrics.success_rate(), 1.0);
        assert_eq!(metrics.rpk_usage_percentage(), 100.0);
    }

    #[test]
    fn test_performance_monitor() {
        let monitor = CertTypePerformanceMonitor::new(10, PerformanceThresholds::default());
        
        let result = NegotiationResult::new(
            CertificateType::RawPublicKey,
            CertificateType::X509,
        );
        
        // Record some negotiations
        monitor.record_negotiation(Duration::from_millis(25), true, Some(result), true);
        monitor.record_negotiation(Duration::from_millis(30), true, None, false);
        monitor.record_negotiation(Duration::from_millis(35), false, None, false);

        let recent = monitor.get_recent_performance(Duration::from_secs(60));
        assert_eq!(recent.sample_count, 3);
        assert!(recent.success_rate > 0.6 && recent.success_rate < 0.7);
        assert!(recent.cache_hit_rate > 0.3 && recent.cache_hit_rate < 0.4);
    }

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new(5);
        
        // Should allow up to 5 requests
        for _ in 0..5 {
            assert!(limiter.check_and_increment());
        }
        
        // 6th request should be denied
        assert!(!limiter.check_and_increment());
        
        // Wait for reset (in real usage, would wait 1 second)
        limiter.last_reset = Instant::now() - Duration::from_secs(2);
        assert!(limiter.check_and_increment());
    }

    #[test]
    fn test_production_system() {
        let config = ProductionHardeningConfig::default();
        let system = ProductionCertTypeSystem::new(config);
        
        // Should allow negotiation by default
        assert!(system.check_negotiation_allowed());
        
        // Should generate health report
        let health = system.health_report();
        assert_eq!(health.status, HealthStatus::Healthy); // No traffic yet
    }
}