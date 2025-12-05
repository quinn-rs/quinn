//! Standard test suite for ant-quic
//! These tests run in < 5 minutes and include integration and protocol tests

#![allow(clippy::unwrap_used, clippy::expect_used)]

pub mod utils {
    use std::time::Duration;

    pub const STANDARD_TEST_TIMEOUT: Duration = Duration::from_secs(30);

    // Add common test utilities here
    pub fn setup_test_logger() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("ant_quic=debug,warn")
            .try_init();
    }
}

// Test modules
pub mod integration_tests;
pub mod nat_basic_tests;
pub mod protocol_tests;

// Re-export test utilities
pub use utils::*;
