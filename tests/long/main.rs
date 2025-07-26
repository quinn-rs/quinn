//! Long-running test suite for ant-quic
//! These tests take > 5 minutes and include stress, performance, and comprehensive tests

use std::time::Duration;

pub mod utils {
    use super::*;
    
    pub const LONG_TEST_TIMEOUT: Duration = Duration::from_secs(1800); // 30 minutes
    
    // Add common test utilities here
    pub fn setup_test_logger() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("ant_quic=debug,warn")  
            .try_init();
    }
}

// Test modules
pub mod stress_tests;
pub mod nat_comprehensive_tests;
pub mod performance_tests;

// Custom test runner for long tests
fn main() {
    println!("Running long tests...");
    
    // Set up logging
    utils::setup_test_logger();
    
    // Run test suites
    println!("Note: Long tests are typically run with --ignored flag");
    println!("Use: cargo test --test long -- --ignored");
}
