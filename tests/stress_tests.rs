//! Stress tests for NAT traversal and connection management
//!
//! Run these tests with: cargo test --release --test stress_tests -- --ignored

// Re-export the stress test module
mod stress {
    pub mod connection_stress_tests;
}

// Import all stress tests
use stress::connection_stress_tests::*;
