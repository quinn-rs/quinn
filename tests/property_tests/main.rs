//! Property-based test runner for ant-quic
//!
//! This is the entry point for property-based tests using proptest.
//! Run with: cargo test --test property_tests

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod connection_properties;
mod crypto_properties;
mod frame_properties;
mod generators;
mod nat_properties;
mod transport_properties;

// Re-export config for use in tests
pub mod config {
    use proptest::prelude::*;

    /// Default number of test cases for property tests
    pub const DEFAULT_PROPTEST_CASES: u32 = 256;

    /// Extended number of test cases for thorough testing
    pub const EXTENDED_PROPTEST_CASES: u32 = 1024;

    /// Maximum shrinking iterations
    pub const MAX_SHRINK_ITERS: u32 = 10000;

    /// Get default proptest config
    pub fn default_config() -> ProptestConfig {
        ProptestConfig {
            cases: DEFAULT_PROPTEST_CASES,
            max_shrink_iters: MAX_SHRINK_ITERS,
            ..Default::default()
        }
    }

    /// Get extended proptest config for CI
    pub fn extended_config() -> ProptestConfig {
        ProptestConfig {
            cases: EXTENDED_PROPTEST_CASES,
            max_shrink_iters: MAX_SHRINK_ITERS,
            ..Default::default()
        }
    }
}
