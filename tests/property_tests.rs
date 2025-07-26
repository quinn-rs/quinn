//! Property-based testing harness for ant-quic

#[cfg(test)]
mod property_tests;

// Re-export the test modules when running tests
#[cfg(test)]
pub use property_tests::*;