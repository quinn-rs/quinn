//! Platform-specific test harness

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "platform_specific/mod.rs"]
mod platform_specific;

// Re-export tests
#[allow(unused_imports)]
pub use platform_specific::*;
