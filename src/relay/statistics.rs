// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses


//! Comprehensive relay statistics collection and aggregation.

use super::{
    AuthenticationStatistics, ConnectionStatistics, ErrorStatistics, RateLimitingStatistics,
    RelayConnection, RelayStatistics, SessionManager, SessionStatistics,
};
use crate::endpoint::RelayStats;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Comprehensive relay statistics collector that aggregates stats from all relay components
#[derive(Debug, Clone)]
pub struct RelayStatisticsCollector {
    /// Basic relay queue statistics
    queue_stats: Arc<Mutex<RelayStats>>,

    /// Session managers being tracked
    session_managers: Arc<Mutex<Vec<Arc<SessionManager>>>>,

    /// Connection tracking
    connections: Arc<Mutex<HashMap<u32, Arc<RelayConnection>>>>,

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
}

impl RelayStatisticsCollector {
    /// Create a new statistics collector
    pub fn new() -> Self {
        Self {
            queue_stats: Arc::new(Mutex::new(RelayStats::default())),
            session_managers: Arc::new(Mutex::new(Vec::new())),
            connections: Arc::new(Mutex::new(HashMap::new())),
            error_counts: Arc::new(Mutex::new(HashMap::new())),
            auth_stats: Arc::new(Mutex::new(AuthenticationStatistics::default())),
            rate_limit_stats: Arc::new(Mutex::new(RateLimitingStatistics::default())),
            start_time: Instant::now(),
            last_snapshot: Arc::new(Mutex::new(RelayStatistics::default())),
        }
    }

    /// Register a session manager for statistics collection
    pub fn register_session_manager(&self, session_manager: Arc<SessionManager>) {
        let mut managers = self.session_managers.lock().unwrap();
        managers.push(session_manager);
    }

    /// Register a relay connection for statistics collection  
    pub fn register_connection(&self, session_id: u32, connection: Arc<RelayConnection>) {
        let mut connections = self.connections.lock().unwrap();
        connections.insert(session_id, connection);
    }

    /// Unregister a relay connection
    pub fn unregister_connection(&self, session_id: u32) {
        let mut connections = self.connections.lock().unwrap();
        connections.remove(&session_id);
    }

    /// Update queue statistics (called from endpoint)
    pub fn update_queue_stats(&self, stats: &RelayStats) {
        let mut queue_stats = self.queue_stats.lock().unwrap();
        *queue_stats = stats.clone();
    }

    /// Record an authentication attempt
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
    pub fn record_error(&self, error_type: &str) {
        let mut error_counts = self.error_counts.lock().unwrap();
        *error_counts.entry(error_type.to_string()).or_insert(0) += 1;
    }

    /// Collect comprehensive statistics from all sources
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
    pub fn get_last_snapshot(&self) -> RelayStatistics {
        self.last_snapshot.lock().unwrap().clone()
    }

    /// Collect session statistics from all registered session managers
    fn collect_session_statistics(&self) -> SessionStatistics {
        let managers = self.session_managers.lock().unwrap();
        let mut total_stats = SessionStatistics::default();

        for manager in managers.iter() {
            let mgr_stats = manager.get_statistics();

            // Aggregate session counts
            total_stats.active_sessions += mgr_stats.active_sessions as u32;
            total_stats.pending_sessions += mgr_stats.pending_sessions as u32;
            total_stats.total_bytes_forwarded +=
                mgr_stats.total_bytes_sent + mgr_stats.total_bytes_received;

            // For derived stats, we take the maximum or average as appropriate
            if mgr_stats.total_sessions > 0 {
                total_stats.total_sessions_created += mgr_stats.total_sessions as u64;
            }
        }

        // Calculate average session duration if we have historical data
        // This would need to be tracked over time in a real implementation
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if total_stats.total_sessions_created > 0 && elapsed > 0.0 {
            total_stats.avg_session_duration = elapsed / total_stats.total_sessions_created as f64;
        }

        total_stats
    }

    /// Collect connection statistics from all registered connections
    fn collect_connection_statistics(&self) -> ConnectionStatistics {
        let connections = self.connections.lock().unwrap();
        let mut total_stats = ConnectionStatistics::default();

        total_stats.total_connections = connections.len() as u64;

        for connection in connections.values() {
            let conn_stats = connection.get_stats();

            if conn_stats.is_active {
                total_stats.active_connections += 1;
            }

            total_stats.total_bytes_sent += conn_stats.bytes_sent;
            total_stats.total_bytes_received += conn_stats.bytes_received;
        }

        // Calculate average bandwidth usage
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            let total_bytes = total_stats.total_bytes_sent + total_stats.total_bytes_received;
            total_stats.avg_bandwidth_usage = total_bytes as f64 / elapsed;
        }

        // Peak concurrent connections would need to be tracked over time
        total_stats.peak_concurrent_connections = total_stats.active_connections;

        total_stats
    }

    /// Collect error statistics
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
    fn test_success_rate_calculation() {
        let collector = RelayStatisticsCollector::new();

        // Record some successful operations
        collector.record_auth_attempt(true, None);
        collector.record_auth_attempt(true, None);
        collector.record_rate_limit(true);
        collector.record_rate_limit(true);

        // Record some failures
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

        // Verify data exists
        let stats_before = collector.collect_statistics();
        assert!(stats_before.auth_stats.total_auth_attempts > 0);

        // Reset and verify clean state
        collector.reset();
        let stats_after = collector.collect_statistics();
        assert_eq!(stats_after.auth_stats.total_auth_attempts, 0);
        assert_eq!(stats_after.rate_limit_stats.total_requests, 0);
    }
}
