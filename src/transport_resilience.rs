//! Graceful transport degradation
//!
//! Provides resilient transport handling that gracefully degrades
//! when certain transports are unavailable or fail.

use std::fmt;
use std::net::SocketAddr;

/// Result of a transport operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportResult<T> {
    /// Operation completed successfully
    Success(T),
    /// Transport is not available for this destination
    Unsupported,
    /// Transport temporarily unavailable
    TemporarilyUnavailable,
    /// Transport failed with an error
    Failed(TransportError),
}

impl<T> TransportResult<T> {
    /// Check if the result is a success
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success(_))
    }

    /// Check if the transport is simply unsupported (not an error)
    pub fn is_unsupported(&self) -> bool {
        matches!(self, Self::Unsupported)
    }

    /// Check if we should retry
    pub fn should_retry(&self) -> bool {
        matches!(self, Self::TemporarilyUnavailable)
    }

    /// Convert to Option, treating Unsupported as None (not an error)
    pub fn into_option(self) -> Option<T> {
        match self {
            Self::Success(v) => Some(v),
            _ => None,
        }
    }

    /// Convert to Result, treating Unsupported as Ok(None)
    pub fn into_result(self) -> Result<Option<T>, TransportError> {
        match self {
            Self::Success(v) => Ok(Some(v)),
            Self::Unsupported => Ok(None),
            Self::TemporarilyUnavailable => Ok(None),
            Self::Failed(e) => Err(e),
        }
    }
}

/// Transport-level error
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportError {
    /// Error kind
    pub kind: TransportErrorKind,
    /// Error message
    pub message: String,
}

impl TransportError {
    /// Create a new transport error
    pub fn new(kind: TransportErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// Create a connection refused error
    pub fn connection_refused(addr: SocketAddr) -> Self {
        Self::new(
            TransportErrorKind::ConnectionRefused,
            format!("Connection refused to {}", addr),
        )
    }

    /// Create a timeout error
    pub fn timeout(addr: SocketAddr) -> Self {
        Self::new(
            TransportErrorKind::Timeout,
            format!("Connection to {} timed out", addr),
        )
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)
    }
}

impl std::error::Error for TransportError {}

/// Categories of transport errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportErrorKind {
    /// Connection was actively refused
    ConnectionRefused,
    /// Connection attempt timed out
    Timeout,
    /// Network is unreachable
    NetworkUnreachable,
    /// Host is unreachable
    HostUnreachable,
    /// Address not available
    AddressNotAvailable,
    /// Permission denied
    PermissionDenied,
    /// Protocol not supported
    ProtocolNotSupported,
    /// Other I/O error
    Io,
}

impl fmt::Display for TransportErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectionRefused => write!(f, "connection refused"),
            Self::Timeout => write!(f, "timeout"),
            Self::NetworkUnreachable => write!(f, "network unreachable"),
            Self::HostUnreachable => write!(f, "host unreachable"),
            Self::AddressNotAvailable => write!(f, "address not available"),
            Self::PermissionDenied => write!(f, "permission denied"),
            Self::ProtocolNotSupported => write!(f, "protocol not supported"),
            Self::Io => write!(f, "I/O error"),
        }
    }
}

/// Transport capability checker
#[derive(Debug, Clone)]
pub struct TransportCapabilities {
    /// Whether IPv4 is supported
    pub ipv4: bool,
    /// Whether IPv6 is supported
    pub ipv6: bool,
    /// Whether relay is available
    pub relay: bool,
    /// Whether direct UDP is available
    pub direct_udp: bool,
}

impl Default for TransportCapabilities {
    fn default() -> Self {
        Self {
            ipv4: true,
            ipv6: true,
            relay: false,
            direct_udp: true,
        }
    }
}

impl TransportCapabilities {
    /// Check if address is supported
    pub fn supports_address(&self, addr: &SocketAddr) -> bool {
        match addr {
            SocketAddr::V4(_) => self.ipv4,
            SocketAddr::V6(_) => self.ipv6,
        }
    }
}

/// Fallback strategy for transport failures
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackStrategy {
    /// Don't retry on failure
    NoRetry,
    /// Retry immediately once
    RetryOnce,
    /// Retry with exponential backoff
    ExponentialBackoff {
        /// Maximum number of retries
        max_retries: u32,
        /// Initial delay in milliseconds
        initial_delay_ms: u64,
    },
    /// Fall back to relay on direct failure
    FallbackToRelay,
}

impl Default for FallbackStrategy {
    fn default() -> Self {
        Self::FallbackToRelay
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_result_success() {
        let result: TransportResult<i32> = TransportResult::Success(42);
        assert!(result.is_success());
        assert!(!result.is_unsupported());
        assert!(!result.should_retry());
        assert_eq!(result.into_option(), Some(42));
    }

    #[test]
    fn test_transport_result_unsupported() {
        let result: TransportResult<i32> = TransportResult::Unsupported;
        assert!(!result.is_success());
        assert!(result.is_unsupported());
        assert!(!result.should_retry());
        assert_eq!(result.into_option(), None);
    }

    #[test]
    fn test_transport_result_temporarily_unavailable() {
        let result: TransportResult<i32> = TransportResult::TemporarilyUnavailable;
        assert!(!result.is_success());
        assert!(!result.is_unsupported());
        assert!(result.should_retry());
    }

    #[test]
    fn test_transport_result_into_result() {
        let success: TransportResult<i32> = TransportResult::Success(42);
        assert_eq!(success.into_result(), Ok(Some(42)));

        let unsupported: TransportResult<i32> = TransportResult::Unsupported;
        assert_eq!(unsupported.into_result(), Ok(None));

        let error = TransportError::new(TransportErrorKind::Timeout, "test");
        let failed: TransportResult<i32> = TransportResult::Failed(error.clone());
        assert_eq!(failed.into_result(), Err(error));
    }

    #[test]
    fn test_transport_error() {
        let error = TransportError::connection_refused("127.0.0.1:5000".parse().unwrap());
        assert_eq!(error.kind, TransportErrorKind::ConnectionRefused);
        assert!(error.message.contains("127.0.0.1:5000"));
    }

    #[test]
    fn test_transport_capabilities_default() {
        let caps = TransportCapabilities::default();
        assert!(caps.ipv4);
        assert!(caps.ipv6);
        assert!(!caps.relay);
        assert!(caps.direct_udp);
    }

    #[test]
    fn test_transport_capabilities_supports_address() {
        let caps = TransportCapabilities {
            ipv4: true,
            ipv6: false,
            relay: false,
            direct_udp: true,
        };

        let v4_addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let v6_addr: SocketAddr = "[::1]:5000".parse().unwrap();

        assert!(caps.supports_address(&v4_addr));
        assert!(!caps.supports_address(&v6_addr));
    }

    #[test]
    fn test_fallback_strategy_default() {
        let strategy = FallbackStrategy::default();
        assert_eq!(strategy, FallbackStrategy::FallbackToRelay);
    }

    #[test]
    fn test_transport_error_display() {
        let error = TransportError::timeout("192.168.1.1:9000".parse().unwrap());
        let display = format!("{}", error);
        assert!(display.contains("timeout"));
        assert!(display.contains("192.168.1.1:9000"));
    }
}
