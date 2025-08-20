// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Error types for the relay protocol implementation.

use std::fmt;

/// Result type alias for relay operations
pub type RelayResult<T> = Result<T, RelayError>;

/// Comprehensive error taxonomy for relay operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayError {
    /// Authentication failed due to invalid token or signature
    AuthenticationFailed { reason: String },

    /// Rate limiting triggered - too many requests
    RateLimitExceeded { retry_after_ms: u64 },

    /// Session-related errors
    SessionError {
        session_id: Option<u32>,
        kind: SessionErrorKind,
    },

    /// Network connectivity issues
    NetworkError { operation: String, source: String },

    /// Protocol-level errors
    ProtocolError { frame_type: u8, reason: String },

    /// Resource exhaustion (memory, bandwidth, etc.)
    ResourceExhausted {
        resource_type: String,
        current_usage: u64,
        limit: u64,
    },

    /// Configuration or setup errors
    ConfigurationError { parameter: String, reason: String },
}

/// Specific session error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionErrorKind {
    /// Session not found
    NotFound,
    /// Session already exists
    AlreadyExists,
    /// Session expired
    Expired,
    /// Session terminated
    Terminated,
    /// Invalid session state for operation
    InvalidState {
        current_state: String,
        expected_state: String,
    },
    /// Bandwidth limit exceeded for session
    BandwidthExceeded { used: u64, limit: u64 },
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelayError::AuthenticationFailed { reason } => {
                write!(f, "Authentication failed: {}", reason)
            }
            RelayError::RateLimitExceeded { retry_after_ms } => {
                write!(f, "Rate limit exceeded, retry after {} ms", retry_after_ms)
            }
            RelayError::SessionError { session_id, kind } => match session_id {
                Some(id) => write!(f, "Session {} error: {}", id, kind),
                None => write!(f, "Session error: {}", kind),
            },
            RelayError::NetworkError { operation, source } => {
                write!(f, "Network error during {}: {}", operation, source)
            }
            RelayError::ProtocolError { frame_type, reason } => {
                write!(
                    f,
                    "Protocol error in frame 0x{:02x}: {}",
                    frame_type, reason
                )
            }
            RelayError::ResourceExhausted {
                resource_type,
                current_usage,
                limit,
            } => {
                write!(
                    f,
                    "Resource exhausted: {} usage ({}) exceeds limit ({})",
                    resource_type, current_usage, limit
                )
            }
            RelayError::ConfigurationError { parameter, reason } => {
                write!(f, "Configuration error for {}: {}", parameter, reason)
            }
        }
    }
}

impl fmt::Display for SessionErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionErrorKind::NotFound => write!(f, "session not found"),
            SessionErrorKind::AlreadyExists => write!(f, "session already exists"),
            SessionErrorKind::Expired => write!(f, "session expired"),
            SessionErrorKind::Terminated => write!(f, "session terminated"),
            SessionErrorKind::InvalidState {
                current_state,
                expected_state,
            } => {
                write!(
                    f,
                    "invalid state '{}', expected '{}'",
                    current_state, expected_state
                )
            }
            SessionErrorKind::BandwidthExceeded { used, limit } => {
                write!(f, "bandwidth exceeded: {} > {}", used, limit)
            }
        }
    }
}

impl std::error::Error for RelayError {}

impl From<std::io::Error> for RelayError {
    fn from(error: std::io::Error) -> Self {
        RelayError::NetworkError {
            operation: "I/O operation".to_string(),
            source: error.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let auth_error = RelayError::AuthenticationFailed {
            reason: "Invalid signature".to_string(),
        };
        assert!(auth_error.to_string().contains("Authentication failed"));

        let rate_limit_error = RelayError::RateLimitExceeded {
            retry_after_ms: 1000,
        };
        assert!(rate_limit_error.to_string().contains("Rate limit exceeded"));

        let session_error = RelayError::SessionError {
            session_id: Some(123),
            kind: SessionErrorKind::NotFound,
        };
        assert!(session_error.to_string().contains("Session 123 error"));
    }

    #[test]
    fn test_session_error_kind_display() {
        let invalid_state = SessionErrorKind::InvalidState {
            current_state: "Connected".to_string(),
            expected_state: "Idle".to_string(),
        };
        assert!(invalid_state.to_string().contains("invalid state"));
        assert!(invalid_state.to_string().contains("Connected"));
        assert!(invalid_state.to_string().contains("Idle"));
    }

    #[test]
    fn test_error_conversion() {
        let io_error =
            std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "Connection refused");
        let relay_error: RelayError = io_error.into();

        match relay_error {
            RelayError::NetworkError { operation, source } => {
                assert_eq!(operation, "I/O operation");
                assert!(source.contains("Connection refused"));
            }
            _ => panic!("Expected NetworkError"),
        }
    }
}
