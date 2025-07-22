//! Network Interface Discovery
//!
//! This module provides platform-specific network interface discovery implementations
//! for Windows, Linux, and macOS. It is used to discover local network interfaces
//! and their addresses for NAT traversal.

use std::net::SocketAddr;

// Re-export public discovery API
pub use crate::candidate_discovery::{
    DiscoveryError, DiscoveryEvent, NetworkInterface, ValidatedCandidate,
};

/// Common trait for platform-specific network discovery implementations
pub trait NetworkDiscovery {
    /// Discover network interfaces on the system
    fn discover_interfaces(&self) -> Result<Vec<NetworkInterface>, DiscoveryError>;

    /// Get the default route for outgoing connections
    fn get_default_route(&self) -> Result<Option<SocketAddr>, DiscoveryError>;
}

// Platform-specific implementations
#[cfg(windows)]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

// Mock implementation for testing
#[cfg(test)]
pub mod mock;
