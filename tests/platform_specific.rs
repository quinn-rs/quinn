//! Platform-specific test harness

#[cfg(feature = "platform-tests")]
mod platform_specific;

// Re-export tests when platform-tests feature is enabled
#[cfg(feature = "platform-tests")]
pub use platform_specific::*;