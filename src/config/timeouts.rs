// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses


//! Timeout configuration constants for ant-quic
//!
//! This module centralizes all timeout and duration constants used throughout
//! the codebase to improve maintainability and configurability.

use std::time::Duration;

/// NAT traversal related timeouts
pub mod nat_traversal {
    use super::*;

    /// Default timeout for coordination operations
    pub const COORDINATION_TIMEOUT: Duration = Duration::from_secs(10);

    /// Grace period for coordination synchronization
    pub const COORDINATION_GRACE_PERIOD: Duration = Duration::from_millis(500);

    /// Total timeout for NAT traversal attempts
    pub const TOTAL_TIMEOUT: Duration = Duration::from_secs(30);

    /// Timeout for individual hole punching attempts
    pub const HOLE_PUNCH_TIMEOUT: Duration = Duration::from_secs(5);

    /// Keep-alive interval for maintaining NAT bindings
    pub const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(5);

    /// Validation cache timeout
    pub const VALIDATION_CACHE_TIMEOUT: Duration = Duration::from_secs(300);

    /// Rate limiting window
    pub const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

    /// Session timeout for idle connections
    pub const SESSION_TIMEOUT: Duration = Duration::from_secs(300);

    /// Observation record timeout
    pub const OBSERVATION_TIMEOUT: Duration = Duration::from_secs(3600);

    /// Base timeout for adaptive timeouts
    pub const BASE_TIMEOUT: Duration = Duration::from_millis(1000);

    /// Minimum allowed timeout
    pub const MIN_TIMEOUT: Duration = Duration::from_millis(100);

    /// Maximum allowed timeout  
    pub const MAX_TIMEOUT: Duration = Duration::from_secs(30);
}

/// Discovery related timeouts
pub mod discovery {
    use super::*;

    /// Total discovery operation timeout
    pub const TOTAL_TIMEOUT: Duration = Duration::from_secs(30);

    /// Local interface scan timeout
    pub const LOCAL_SCAN_TIMEOUT: Duration = Duration::from_secs(2);

    /// Bootstrap query timeout
    pub const BOOTSTRAP_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

    /// Interface cache TTL
    pub const INTERFACE_CACHE_TTL: Duration = Duration::from_secs(60);

    /// Server reflexive address cache TTL
    pub const SERVER_REFLEXIVE_CACHE_TTL: Duration = Duration::from_secs(300);

    /// Long operation timeout
    pub const LONG_OPERATION_TIMEOUT: Duration = Duration::from_secs(10);

    /// Health check interval
    pub const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(30);
}

/// Connection related timeouts
pub mod connection {
    use super::*;

    /// Direct connection attempt timeout
    pub const DIRECT_CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

    /// General connection timeout
    pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

    /// Socket read timeout
    pub const SOCKET_READ_TIMEOUT: Duration = Duration::from_millis(100);

    /// Connection poll interval
    pub const POLL_INTERVAL: Duration = Duration::from_millis(10);

    /// Cleanup interval for stale connections
    pub const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

    /// Candidate timeout before removal
    pub const CANDIDATE_TIMEOUT: Duration = Duration::from_secs(300);

    /// Validation timeout
    pub const VALIDATION_TIMEOUT: Duration = Duration::from_secs(30);
}

/// Monitoring and metrics timeouts
pub mod monitoring {
    use super::*;

    /// Metrics cleanup interval
    pub const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

    /// Recovery timeout for failed operations
    pub const RECOVERY_TIMEOUT: Duration = Duration::from_secs(300);

    /// Health check interval
    pub const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(30);

    /// Metrics retention period
    pub const RETENTION_PERIOD: Duration = Duration::from_secs(3600);

    /// Metrics flush interval
    pub const FLUSH_INTERVAL: Duration = Duration::from_secs(60);

    /// Alert evaluation interval
    pub const EVALUATION_INTERVAL: Duration = Duration::from_secs(30);

    /// Alert deduplication window
    pub const DEDUPLICATION_WINDOW: Duration = Duration::from_secs(300);
}

/// Retry strategy timeouts
pub mod retry {
    use super::*;

    /// Initial retry delay
    pub const INITIAL_DELAY: Duration = Duration::from_millis(100);

    /// Standard retry delay
    pub const STANDARD_DELAY: Duration = Duration::from_millis(500);

    /// Maximum retry delay
    pub const MAX_DELAY: Duration = Duration::from_secs(30);

    /// Retry attempt timeout
    pub const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);
}

/// RTT (Round Trip Time) thresholds
pub mod rtt {
    use super::*;

    /// Excellent RTT threshold
    pub const EXCELLENT_THRESHOLD: Duration = Duration::from_millis(50);

    /// Good RTT threshold
    pub const GOOD_THRESHOLD: Duration = Duration::from_millis(100);

    /// Fair RTT threshold
    pub const FAIR_THRESHOLD: Duration = Duration::from_millis(200);

    /// Poor RTT threshold
    pub const POOR_THRESHOLD: Duration = Duration::from_millis(500);

    /// Default RTT estimate
    pub const DEFAULT_RTT: Duration = Duration::from_millis(100);

    /// Base grace period for RTT calculations
    pub const BASE_GRACE_PERIOD: Duration = Duration::from_millis(150);
}

/// Work limiter and batching timeouts
pub mod work_limiter {
    use super::*;

    /// Work cycle time
    pub const CYCLE_TIME: Duration = Duration::from_millis(500);

    /// Batch processing time
    pub const BATCH_TIME: Duration = Duration::from_millis(100);

    /// Lock contention threshold
    pub const LOCK_CONTENTION_THRESHOLD: Duration = Duration::from_millis(1);
}

/// Circuit breaker configuration
pub mod circuit_breaker {
    use super::*;

    /// Circuit breaker timeout
    pub const TIMEOUT: Duration = Duration::from_secs(60);

    /// Circuit breaker window size
    pub const WINDOW_SIZE: Duration = Duration::from_secs(300);
}

/// Escalation timeouts for monitoring
pub mod escalation {
    use super::*;

    /// Warning escalation time
    pub const WARNING_TIME: Duration = Duration::from_secs(60);

    /// Critical escalation time
    pub const CRITICAL_TIME: Duration = Duration::from_secs(300);

    /// Page escalation time
    pub const PAGE_TIME: Duration = Duration::from_secs(600);
}

/// Default workflow timeouts
pub mod workflow {
    use super::*;

    /// Default workflow timeout
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

    /// Step execution timeout
    pub const STEP_TIMEOUT: Duration = Duration::from_secs(10);

    /// Workflow poll interval
    pub const POLL_INTERVAL: Duration = Duration::from_secs(1);
}

/// Congestion control timeouts
pub mod congestion {
    use super::*;

    /// BBR probe RTT time
    pub const PROBE_RTT_TIME: Duration = Duration::from_millis(200);

    /// BBR cycle length
    pub const CYCLE_LENGTH: Duration = Duration::from_secs(10);
}

/// Helper functions for timeout configuration
pub mod helpers {
    use super::*;

    /// Get timeout from environment variable or use default
    pub fn from_env_or_default(env_var: &str, default: Duration) -> Duration {
        std::env::var(env_var)
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(default)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timeout_values_are_reasonable() {
        // Ensure minimum timeouts are less than maximum timeouts
        assert!(nat_traversal::MIN_TIMEOUT < nat_traversal::MAX_TIMEOUT);

        // Ensure RTT thresholds are in increasing order
        assert!(rtt::EXCELLENT_THRESHOLD < rtt::GOOD_THRESHOLD);
        assert!(rtt::GOOD_THRESHOLD < rtt::FAIR_THRESHOLD);
        assert!(rtt::FAIR_THRESHOLD < rtt::POOR_THRESHOLD);

        // Ensure retry delays are in reasonable order
        assert!(retry::INITIAL_DELAY < retry::STANDARD_DELAY);
        assert!(retry::STANDARD_DELAY < retry::MAX_DELAY);
    }
}
