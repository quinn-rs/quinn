// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Comprehensive relay statistics collection and aggregation.
//!
//! This module provides statistics collection for the MASQUE relay infrastructure.
//! It tracks authentication, rate limiting, errors, and relay queue statistics.

use super::{
    AuthenticationStatistics, ConnectionStatistics, ErrorStatistics, RateLimitingStatistics,
    RelayStatistics, SessionStatistics,
};
use crate::endpoint::RelayStats;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Comprehensive relay statistics collector that aggregates stats from all relay components
#[derive(Debug)]
pub struct RelayStatisticsCollector {
    /// Basic relay queue statistics
    queue_stats: Arc<Mutex<RelayStats>>,

    /// Error tracking
    error_counts: Arc<Mutex<HashMap<String, u64>>>,

    /// Authentication tracking
    auth_stats: Arc<Mutex<AuthenticationStatistics>>,

    /// Rate limiting tracking
    rate_limit_stats: Arc<Mutex<RateLimitingStatistics>>,

    /// Collection start time for rate calculations
    start_time: Instant,

    /// Last statistics snapshot
    last_snapshot: Arc<Mutex<RelayStatistics>>,

    /// Active sessions count (updated externally)
    active_sessions: AtomicU32,

    /// Total sessions created (updated externally)
    total_sessions: AtomicU64,

    /// Active connections count (updated externally)
    active_connections: AtomicU32,

    /// Total bytes sent (updated externally)
    total_bytes_sent: AtomicU64,

    /// Total bytes received (updated externally)
    total_bytes_received: AtomicU64,
}

impl Clone for RelayStatisticsCollector {
    fn clone(&self) -> Self {
        Self {
            queue_stats: Arc::clone(&self.queue_stats),
            error_counts: Arc::clone(&self.error_counts),
            auth_stats: Arc::clone(&self.auth_stats),
            rate_limit_stats: Arc::clone(&self.rate_limit_stats),
            start_time: self.start_time,
            last_snapshot: Arc::clone(&self.last_snapshot),
            active_sessions: AtomicU32::new(self.active_sessions.load(Ordering::Relaxed)),
            total_sessions: AtomicU64::new(self.total_sessions.load(Ordering::Relaxed)),
            active_connections: AtomicU32::new(self.active_connections.load(Ordering::Relaxed)),
            total_bytes_sent: AtomicU64::new(self.total_bytes_sent.load(Ordering::Relaxed)),
            total_bytes_received: AtomicU64::new(self.total_bytes_received.load(Ordering::Relaxed)),
        }
    }
}

impl RelayStatisticsCollector {
    /// Create a new statistics collector
    pub fn new() -> Self {
        Self {
            queue_stats: Arc::new(Mutex::new(RelayStats::default())),
            error_counts: Arc::new(Mutex::new(HashMap::new())),
            auth_stats: Arc::new(Mutex::new(AuthenticationStatistics::default())),
            rate_limit_stats: Arc::new(Mutex::new(RateLimitingStatistics::default())),
            start_time: Instant::now(),
            last_snapshot: Arc::new(Mutex::new(RelayStatistics::default())),
            active_sessions: AtomicU32::new(0),
            total_sessions: AtomicU64::new(0),
            active_connections: AtomicU32::new(0),
            total_bytes_sent: AtomicU64::new(0),
            total_bytes_received: AtomicU64::new(0),
        }
    }

    /// Update session count (called by MASQUE relay server)
    pub fn update_session_count(&self, active: u32, total: u64) {
        self.active_sessions.store(active, Ordering::Relaxed);
        self.total_sessions.store(total, Ordering::Relaxed);
    }

    /// Update connection count (called by MASQUE relay components)
    pub fn update_connection_count(&self, active: u32) {
        self.active_connections.store(active, Ordering::Relaxed);
    }

    /// Update bytes transferred (called by MASQUE relay components)
    pub fn add_bytes_transferred(&self, sent: u64, received: u64) {
        self.total_bytes_sent.fetch_add(sent, Ordering::Relaxed);
        self.total_bytes_received
            .fetch_add(received, Ordering::Relaxed);
    }

    /// Update queue statistics (called from endpoint)
    #[allow(clippy::unwrap_used)]
    pub fn update_queue_stats(&self, stats: &RelayStats) {
        let mut queue_stats = self.queue_stats.lock().unwrap();
        *queue_stats = stats.clone();
    }

    /// Record an authentication attempt
    #[allow(clippy::unwrap_used)]
    pub fn record_auth_attempt(&self, success: bool, error: Option<&str>) {
        let mut auth_stats = self.auth_stats.lock().unwrap();
        auth_stats.total_auth_attempts += 1;

        if success {
            auth_stats.successful_auths += 1;
        } else {
            auth_stats.failed_auths += 1;

            if let Some(error_msg) = error {
                if error_msg.contains("replay") {
                    auth_stats.replay_attacks_blocked += 1;
                } else if error_msg.contains("signature") {
                    auth_stats.invalid_signatures += 1;
                } else if error_msg.contains("unknown") || error_msg.contains("trusted") {
                    auth_stats.unknown_peer_keys += 1;
                }
            }
        }

        // Update auth rate (auth attempts per second)
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            auth_stats.auth_rate = auth_stats.total_auth_attempts as f64 / elapsed;
        }
    }

    /// Record a rate limiting decision
    #[allow(clippy::unwrap_used)]
    pub fn record_rate_limit(&self, allowed: bool) {
        let mut rate_stats = self.rate_limit_stats.lock().unwrap();
        rate_stats.total_requests += 1;

        if allowed {
            rate_stats.requests_allowed += 1;
        } else {
            rate_stats.requests_blocked += 1;
        }

        // Update efficiency percentage
        if rate_stats.total_requests > 0 {
            rate_stats.efficiency_percentage =
                (rate_stats.requests_allowed as f64 / rate_stats.total_requests as f64) * 100.0;
        }
    }

    /// Record an error occurrence
    #[allow(clippy::unwrap_used)]
    pub fn record_error(&self, error_type: &str) {
        let mut error_counts = self.error_counts.lock().unwrap();
        *error_counts.entry(error_type.to_string()).or_insert(0) += 1;
    }

    /// Collect comprehensive statistics from all sources
    #[allow(clippy::unwrap_used)]
    pub fn collect_statistics(&self) -> RelayStatistics {
        let session_stats = self.collect_session_statistics();
        let connection_stats = self.collect_connection_statistics();
        let auth_stats = self.auth_stats.lock().unwrap().clone();
        let rate_limit_stats = self.rate_limit_stats.lock().unwrap().clone();
        let error_stats = self.collect_error_statistics();

        let stats = RelayStatistics {
            session_stats,
            connection_stats,
            auth_stats,
            rate_limit_stats,
            error_stats,
        };

        // Update last snapshot
        {
            let mut last_snapshot = self.last_snapshot.lock().unwrap();
            *last_snapshot = stats.clone();
        }

        stats
    }

    /// Get the last collected statistics snapshot
    #[allow(clippy::unwrap_used)]
    pub fn get_last_snapshot(&self) -> RelayStatistics {
        self.last_snapshot.lock().unwrap().clone()
    }

    /// Collect session statistics from atomic counters
    fn collect_session_statistics(&self) -> SessionStatistics {
        let active_sessions = self.active_sessions.load(Ordering::Relaxed);
        let total_sessions = self.total_sessions.load(Ordering::Relaxed);
        let total_bytes_sent = self.total_bytes_sent.load(Ordering::Relaxed);
        let total_bytes_received = self.total_bytes_received.load(Ordering::Relaxed);

        let mut stats = SessionStatistics::default();
        stats.active_sessions = active_sessions;
        stats.total_sessions_created = total_sessions;
        stats.total_bytes_forwarded = total_bytes_sent + total_bytes_received;

        // Calculate average session duration if we have historical data
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if total_sessions > 0 && elapsed > 0.0 {
            stats.avg_session_duration = elapsed / total_sessions as f64;
        }

        stats
    }

    /// Collect connection statistics from atomic counters
    fn collect_connection_statistics(&self) -> ConnectionStatistics {
        let active_connections = self.active_connections.load(Ordering::Relaxed);
        let total_bytes_sent = self.total_bytes_sent.load(Ordering::Relaxed);
        let total_bytes_received = self.total_bytes_received.load(Ordering::Relaxed);

        let mut stats = ConnectionStatistics::default();
        stats.active_connections = active_connections;
        stats.total_bytes_sent = total_bytes_sent;
        stats.total_bytes_received = total_bytes_received;

        // Calculate average bandwidth usage
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            let total_bytes = total_bytes_sent + total_bytes_received;
            stats.avg_bandwidth_usage = total_bytes as f64 / elapsed;
        }

        // Peak concurrent connections would need to be tracked over time
        stats.peak_concurrent_connections = active_connections;

        stats
    }

    /// Collect error statistics
    #[allow(clippy::unwrap_used)]
    fn collect_error_statistics(&self) -> ErrorStatistics {
        let error_counts = self.error_counts.lock().unwrap();
        let queue_stats = self.queue_stats.lock().unwrap();

        let mut error_stats = ErrorStatistics::default();
        error_stats.error_breakdown = error_counts.clone();

        // Categorize errors
        for (error_type, count) in error_counts.iter() {
            if error_type.contains("protocol") || error_type.contains("frame") {
                error_stats.protocol_errors += count;
            } else if error_type.contains("resource") || error_type.contains("exhausted") {
                error_stats.resource_exhausted += count;
            } else if error_type.contains("session") {
                error_stats.session_errors += count;
            } else if error_type.contains("auth") {
                error_stats.auth_failures += count;
            } else if error_type.contains("network") || error_type.contains("connection") {
                error_stats.network_errors += count;
            } else {
                error_stats.internal_errors += count;
            }
        }

        // Add queue-related failures
        error_stats.resource_exhausted += queue_stats.requests_dropped;
        error_stats.protocol_errors += queue_stats.requests_failed;

        // Calculate error rate
        let total_errors = error_stats.protocol_errors
            + error_stats.resource_exhausted
            + error_stats.session_errors
            + error_stats.auth_failures
            + error_stats.network_errors
            + error_stats.internal_errors;

        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            error_stats.error_rate = total_errors as f64 / elapsed;
        }

        error_stats
    }

    /// Reset all statistics (useful for testing)
    #[allow(clippy::unwrap_used)]
    pub fn reset(&self) {
        {
            let mut queue_stats = self.queue_stats.lock().unwrap();
            *queue_stats = RelayStats::default();
        }
        {
            let mut error_counts = self.error_counts.lock().unwrap();
            error_counts.clear();
        }
        {
            let mut auth_stats = self.auth_stats.lock().unwrap();
            *auth_stats = AuthenticationStatistics::default();
        }
        {
            let mut rate_limit_stats = self.rate_limit_stats.lock().unwrap();
            *rate_limit_stats = RateLimitingStatistics::default();
        }

        self.active_sessions.store(0, Ordering::Relaxed);
        self.total_sessions.store(0, Ordering::Relaxed);
        self.active_connections.store(0, Ordering::Relaxed);
        self.total_bytes_sent.store(0, Ordering::Relaxed);
        self.total_bytes_received.store(0, Ordering::Relaxed);
    }
}

impl Default for RelayStatisticsCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_statistics_collector_creation() {
        let collector = RelayStatisticsCollector::new();
        let stats = collector.collect_statistics();

        // Should start with empty statistics
        assert_eq!(stats.session_stats.active_sessions, 0);
        assert_eq!(stats.connection_stats.total_connections, 0);
        assert_eq!(stats.auth_stats.total_auth_attempts, 0);
        assert!(stats.is_healthy());
    }

    #[test]
    fn test_auth_tracking() {
        let collector = RelayStatisticsCollector::new();

        // Record some authentication attempts
        collector.record_auth_attempt(true, None);
        collector.record_auth_attempt(false, Some("signature verification failed"));
        collector.record_auth_attempt(false, Some("replay attack detected"));

        let stats = collector.collect_statistics();
        assert_eq!(stats.auth_stats.total_auth_attempts, 3);
        assert_eq!(stats.auth_stats.successful_auths, 1);
        assert_eq!(stats.auth_stats.failed_auths, 2);
        assert_eq!(stats.auth_stats.invalid_signatures, 1);
        assert_eq!(stats.auth_stats.replay_attacks_blocked, 1);
    }

    #[test]
    fn test_rate_limiting_tracking() {
        let collector = RelayStatisticsCollector::new();

        // Record some rate limiting decisions
        collector.record_rate_limit(true);
        collector.record_rate_limit(true);
        collector.record_rate_limit(false);
        collector.record_rate_limit(true);

        let stats = collector.collect_statistics();
        assert_eq!(stats.rate_limit_stats.total_requests, 4);
        assert_eq!(stats.rate_limit_stats.requests_allowed, 3);
        assert_eq!(stats.rate_limit_stats.requests_blocked, 1);
        assert_eq!(stats.rate_limit_stats.efficiency_percentage, 75.0);
    }

    #[test]
    fn test_error_tracking() {
        let collector = RelayStatisticsCollector::new();

        // Record various errors
        collector.record_error("protocol_error");
        collector.record_error("resource_exhausted");
        collector.record_error("session_timeout");
        collector.record_error("auth_failed");

        let stats = collector.collect_statistics();
        assert_eq!(stats.error_stats.protocol_errors, 1);
        assert_eq!(stats.error_stats.resource_exhausted, 1);
        assert_eq!(stats.error_stats.session_errors, 1);
        assert_eq!(stats.error_stats.auth_failures, 1);
        assert_eq!(stats.error_stats.error_breakdown.len(), 4);
    }

    #[test]
    fn test_session_count_updates() {
        let collector = RelayStatisticsCollector::new();

        // Update session counts
        collector.update_session_count(5, 100);

        let stats = collector.collect_statistics();
        assert_eq!(stats.session_stats.active_sessions, 5);
        assert_eq!(stats.session_stats.total_sessions_created, 100);
    }

    #[test]
    fn test_bytes_transferred() {
        let collector = RelayStatisticsCollector::new();

        // Add some bytes transferred
        collector.add_bytes_transferred(1000, 2000);
        collector.add_bytes_transferred(500, 500);

        let stats = collector.collect_statistics();
        assert_eq!(stats.connection_stats.total_bytes_sent, 1500);
        assert_eq!(stats.connection_stats.total_bytes_received, 2500);
        assert_eq!(stats.session_stats.total_bytes_forwarded, 4000);
    }

    #[test]
    fn test_success_rate_calculation() {
        let collector = RelayStatisticsCollector::new();

        // Record more successful operations to ensure > 50% success rate
        collector.record_auth_attempt(true, None);
        collector.record_auth_attempt(true, None);
        collector.record_auth_attempt(true, None);
        collector.record_auth_attempt(true, None);

        // Note: record_rate_limit doesn't affect the success_rate calculation
        // as it's not counted in total_ops
        collector.record_rate_limit(true);
        collector.record_rate_limit(true);

        // Record some failures (but less than successes)
        collector.record_auth_attempt(false, None);
        collector.record_error("protocol_error");

        let stats = collector.collect_statistics();

        // Should have a good success rate but not perfect due to failures
        let success_rate = stats.success_rate();
        assert!(success_rate > 0.5);
        assert!(success_rate < 1.0);
    }

    #[test]
    fn test_reset_functionality() {
        let collector = RelayStatisticsCollector::new();

        // Add some data
        collector.record_auth_attempt(true, None);
        collector.record_error("test_error");
        collector.record_rate_limit(false);
        collector.update_session_count(10, 50);
        collector.add_bytes_transferred(1000, 2000);

        // Verify data exists
        let stats_before = collector.collect_statistics();
        assert!(stats_before.auth_stats.total_auth_attempts > 0);
        assert_eq!(stats_before.session_stats.active_sessions, 10);

        // Reset and verify clean state
        collector.reset();
        let stats_after = collector.collect_statistics();
        assert_eq!(stats_after.auth_stats.total_auth_attempts, 0);
        assert_eq!(stats_after.rate_limit_stats.total_requests, 0);
        assert_eq!(stats_after.session_stats.active_sessions, 0);
        assert_eq!(stats_after.connection_stats.total_bytes_sent, 0);
    }
}
