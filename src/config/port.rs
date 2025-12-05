// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Port configuration for QUIC endpoints
//!
//! This module provides flexible port binding strategies, dual-stack IPv4/IPv6 support,
//! and port discovery APIs to enable OS-assigned ports and avoid port conflicts.

use std::net::SocketAddr;
use thiserror::Error;

/// Port binding strategy for QUIC endpoints
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortBinding {
    /// Let OS assign random available port (port 0)
    ///
    /// This is the recommended default as it avoids conflicts and allows multiple
    /// instances to run on the same machine.
    ///
    /// # Example
    /// ```
    /// use ant_quic::config::PortBinding;
    ///
    /// let port = PortBinding::OsAssigned;
    /// ```
    OsAssigned,

    /// Bind to specific port
    ///
    /// # Example
    /// ```
    /// use ant_quic::config::PortBinding;
    ///
    /// let port = PortBinding::Explicit(9000);
    /// ```
    Explicit(u16),

    /// Try ports in range, use first available
    ///
    /// # Example
    /// ```
    /// use ant_quic::config::PortBinding;
    ///
    /// let port = PortBinding::Range(9000, 9010);
    /// ```
    Range(u16, u16),
}

impl Default for PortBinding {
    fn default() -> Self {
        Self::OsAssigned
    }
}

/// IP stack configuration for endpoint binding
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpMode {
    /// IPv4 only (bind to 0.0.0.0:port)
    ///
    /// This is the safest default as it:
    /// - Works on all platforms
    /// - Avoids dual-stack conflicts
    /// - Simplifies configuration
    IPv4Only,

    /// IPv6 only (bind to [::]:port)
    IPv6Only,

    /// Both IPv4 and IPv6 on same port
    ///
    /// Note: May fail on some platforms due to dual-stack binding conflicts.
    /// Use `DualStackSeparate` if this fails.
    DualStack,

    /// IPv4 and IPv6 on different ports
    ///
    /// This avoids dual-stack binding conflicts by using separate ports.
    DualStackSeparate {
        /// Port binding for IPv4
        ipv4_port: PortBinding,
        /// Port binding for IPv6
        ipv6_port: PortBinding,
    },
}

impl Default for IpMode {
    fn default() -> Self {
        Self::IPv4Only
    }
}

/// Socket-level options for endpoint binding
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SocketOptions {
    /// Send buffer size in bytes
    pub send_buffer_size: Option<usize>,
    /// Receive buffer size in bytes
    pub recv_buffer_size: Option<usize>,
    /// Enable SO_REUSEADDR
    pub reuse_address: bool,
    /// Enable SO_REUSEPORT (Linux/BSD only)
    pub reuse_port: bool,
}

/// Retry behavior on port binding failures
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PortRetryBehavior {
    /// Fail immediately if port unavailable
    #[default]
    FailFast,
    /// Fall back to OS-assigned port on conflict
    FallbackToOsAssigned,
    /// Try next port in range (only for Range binding)
    TryNext,
}

/// Configuration for endpoint port binding
///
/// This configuration allows flexible port binding strategies, dual-stack support,
/// and automatic port discovery.
///
/// # Examples
///
/// ## OS-assigned port (recommended)
/// ```
/// use ant_quic::config::EndpointPortConfig;
///
/// let config = EndpointPortConfig::default();
/// ```
///
/// ## Explicit port
/// ```
/// use ant_quic::config::{EndpointPortConfig, PortBinding};
///
/// let config = EndpointPortConfig {
///     port: PortBinding::Explicit(9000),
///     ..Default::default()
/// };
/// ```
///
/// ## Dual-stack with separate ports
/// ```
/// use ant_quic::config::{EndpointPortConfig, IpMode, PortBinding};
///
/// let config = EndpointPortConfig {
///     ip_mode: IpMode::DualStackSeparate {
///         ipv4_port: PortBinding::Explicit(9000),
///         ipv6_port: PortBinding::Explicit(9001),
///     },
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone)]
pub struct EndpointPortConfig {
    /// Port binding configuration
    pub port: PortBinding,
    /// IP stack mode
    pub ip_mode: IpMode,
    /// Socket options
    pub socket_options: SocketOptions,
    /// Retry behavior on port conflicts
    pub retry_behavior: PortRetryBehavior,
}

impl Default for EndpointPortConfig {
    fn default() -> Self {
        Self {
            // Use OS-assigned port to avoid conflicts
            port: PortBinding::OsAssigned,
            // Use IPv4-only to avoid dual-stack conflicts
            ip_mode: IpMode::IPv4Only,
            socket_options: SocketOptions::default(),
            retry_behavior: PortRetryBehavior::FailFast,
        }
    }
}

/// Errors related to endpoint port configuration and binding
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EndpointConfigError {
    /// Port is already in use
    #[error("Port {0} is already in use. Try using PortBinding::OsAssigned to let the OS choose.")]
    PortInUse(u16),

    /// Invalid port number
    #[error("Invalid port number: {0}. Port must be in range 0-65535.")]
    InvalidPort(u32),

    /// Cannot bind to privileged port
    #[error(
        "Cannot bind to privileged port {0}. Use port 1024 or higher, or run with appropriate permissions."
    )]
    PermissionDenied(u16),

    /// No available port in range
    #[error(
        "No available port in range {0}-{1}. Try a wider range or use PortBinding::OsAssigned."
    )]
    NoPortInRange(u16, u16),

    /// Dual-stack not supported on this platform
    #[error("Dual-stack not supported on this platform. Use IpMode::IPv4Only or IpMode::IPv6Only.")]
    DualStackNotSupported,

    /// IPv6 not available on this system
    #[error("IPv6 not available on this system. Use IpMode::IPv4Only.")]
    Ipv6NotAvailable,

    /// Failed to bind socket
    #[error("Failed to bind socket: {0}")]
    BindFailed(String),

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// IO error during socket operations
    #[error("IO error: {0}")]
    IoError(String),
}

impl From<std::io::Error> for EndpointConfigError {
    fn from(err: std::io::Error) -> Self {
        use std::io::ErrorKind;
        match err.kind() {
            ErrorKind::AddrInUse => {
                // Try to extract port from error message
                Self::BindFailed(err.to_string())
            }
            ErrorKind::PermissionDenied => Self::BindFailed(err.to_string()),
            ErrorKind::AddrNotAvailable => Self::Ipv6NotAvailable,
            _ => Self::IoError(err.to_string()),
        }
    }
}

/// Result type for port configuration operations
pub type PortConfigResult<T> = Result<T, EndpointConfigError>;

/// Bound socket information after successful binding
#[derive(Debug, Clone)]
pub struct BoundSocket {
    /// Socket addresses that were successfully bound
    pub addrs: Vec<SocketAddr>,
    /// The configuration that was used
    pub config: EndpointPortConfig,
}

impl BoundSocket {
    /// Get the primary bound address (first in the list)
    pub fn primary_addr(&self) -> Option<SocketAddr> {
        self.addrs.first().copied()
    }

    /// Get all bound addresses
    pub fn all_addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_binding_default() {
        let port = PortBinding::default();
        assert_eq!(port, PortBinding::OsAssigned);
    }

    #[test]
    fn test_port_binding_explicit() {
        let port = PortBinding::Explicit(9000);
        match port {
            PortBinding::Explicit(9000) => {}
            _ => panic!("Expected Explicit(9000)"),
        }
    }

    #[test]
    fn test_port_binding_range() {
        let port = PortBinding::Range(9000, 9010);
        match port {
            PortBinding::Range(9000, 9010) => {}
            _ => panic!("Expected Range(9000, 9010)"),
        }
    }

    #[test]
    fn test_ip_mode_default() {
        let mode = IpMode::default();
        assert_eq!(mode, IpMode::IPv4Only);
    }

    #[test]
    fn test_ip_mode_ipv4_only() {
        let mode = IpMode::IPv4Only;
        match mode {
            IpMode::IPv4Only => {}
            _ => panic!("Expected IPv4Only"),
        }
    }

    #[test]
    fn test_ip_mode_dual_stack_separate() {
        let mode = IpMode::DualStackSeparate {
            ipv4_port: PortBinding::Explicit(9000),
            ipv6_port: PortBinding::Explicit(9001),
        };
        match mode {
            IpMode::DualStackSeparate {
                ipv4_port,
                ipv6_port,
            } => {
                assert_eq!(ipv4_port, PortBinding::Explicit(9000));
                assert_eq!(ipv6_port, PortBinding::Explicit(9001));
            }
            _ => panic!("Expected DualStackSeparate"),
        }
    }

    #[test]
    fn test_socket_options_default() {
        let opts = SocketOptions::default();
        assert_eq!(opts.send_buffer_size, None);
        assert_eq!(opts.recv_buffer_size, None);
        assert!(!opts.reuse_address);
        assert!(!opts.reuse_port);
    }

    #[test]
    fn test_retry_behavior_default() {
        let behavior = PortRetryBehavior::default();
        assert_eq!(behavior, PortRetryBehavior::FailFast);
    }

    #[test]
    fn test_endpoint_port_config_default() {
        let config = EndpointPortConfig::default();
        assert_eq!(config.port, PortBinding::OsAssigned);
        assert_eq!(config.ip_mode, IpMode::IPv4Only);
        assert_eq!(config.retry_behavior, PortRetryBehavior::FailFast);
    }

    #[test]
    fn test_endpoint_config_error_display() {
        let err = EndpointConfigError::PortInUse(9000);
        assert!(err.to_string().contains("Port 9000 is already in use"));

        let err = EndpointConfigError::InvalidPort(70000);
        assert!(err.to_string().contains("Invalid port number"));

        let err = EndpointConfigError::PermissionDenied(80);
        assert!(err.to_string().contains("privileged port"));
    }

    #[test]
    fn test_bound_socket() {
        let config = EndpointPortConfig::default();
        let addrs = vec![
            "127.0.0.1:9000".parse().expect("valid address"),
            "127.0.0.1:9001".parse().expect("valid address"),
        ];
        let bound = BoundSocket {
            addrs: addrs.clone(),
            config,
        };

        assert_eq!(bound.primary_addr(), Some(addrs[0]));
        assert_eq!(bound.all_addrs(), &addrs[..]);
    }
}
