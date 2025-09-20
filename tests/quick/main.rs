//! Quick tests - Execute in <30 seconds total
//!
//! This test suite contains fast unit and integration tests that provide
//! rapid feedback during development. These tests are run on every push.

// Re-export test modules
mod auth_tests;
mod auto_binding_integration;
mod binding_stream_tests;
mod connect_topologies;
mod connection_tests;
mod crypto_tests;
mod frame_tests;
mod pure_pq_rpk_tests;
mod token_binding_tests;
mod token_v2_server_side_tests;

// Quick test utilities
pub mod utils {
    use std::time::{Duration, Instant};

    /// Ensures a test completes within the specified duration
    pub fn assert_duration<F, R>(max_duration: Duration, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let start = Instant::now();
        let result = f();
        let elapsed = start.elapsed();

        assert!(
            elapsed <= max_duration,
            "Test exceeded time limit: {elapsed:?} > {max_duration:?}"
        );

        result
    }

    /// Maximum duration for a quick test
    pub const QUICK_TEST_TIMEOUT: Duration = Duration::from_secs(5);
}
