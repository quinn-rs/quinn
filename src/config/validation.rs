// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Configuration validation for production deployments
//!
//! This module provides comprehensive configuration validation to ensure
//! that all configuration parameters are valid and compatible with each other.
//! It includes detailed error messages and validation rules for production use.

use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;

/// Configuration validation errors with detailed context
#[derive(Error, Debug)]

pub(crate) enum ConfigValidationError {
    #[error("Invalid bootstrap node configuration: {0}")]
    InvalidBootstrapNode(String),

    #[error("Invalid role configuration: {0}")]
    InvalidRole(String),

    #[error("Incompatible configuration combination: {0}")]
    IncompatibleConfiguration(String),

    #[error("Missing required configuration: {0}")]
    MissingRequiredConfig(String),

    #[error("Configuration value out of range: {0}")]
    ValueOutOfRange(String),

    #[error("Invalid address format: {0}")]
    InvalidAddress(String),
}

/// Configuration validation result
pub(crate) type ValidationResult<T> = Result<T, ConfigValidationError>;

/// Trait for validating configuration objects
pub(crate) trait ConfigValidator {
    /// Validate the configuration and return detailed errors if invalid
    fn validate(&self) -> ValidationResult<()>;
}

/// Validate a socket address
pub(crate) fn validate_socket_addr(addr: &SocketAddr, context: &str) -> ValidationResult<()> {
    // Check for reserved/invalid addresses
    match addr.ip() {
        std::net::IpAddr::V4(ipv4) => {
            if ipv4.is_unspecified() {
                return Err(ConfigValidationError::InvalidAddress(format!(
                    "{context}: IPv4 address cannot be unspecified (0.0.0.0)"
                )));
            }
            if ipv4.is_broadcast() {
                return Err(ConfigValidationError::InvalidAddress(format!(
                    "{context}: IPv4 address cannot be broadcast (255.255.255.255)"
                )));
            }
            if ipv4.is_multicast() {
                return Err(ConfigValidationError::InvalidAddress(format!(
                    "{context}: IPv4 address cannot be multicast"
                )));
            }
        }
        std::net::IpAddr::V6(ipv6) => {
            if ipv6.is_unspecified() {
                return Err(ConfigValidationError::InvalidAddress(format!(
                    "{context}: IPv6 address cannot be unspecified (::)"
                )));
            }
            if ipv6.is_multicast() {
                return Err(ConfigValidationError::InvalidAddress(format!(
                    "{context}: IPv6 address cannot be multicast"
                )));
            }
        }
    }

    // Check port range
    if addr.port() == 0 {
        return Err(ConfigValidationError::InvalidAddress(format!(
            "{context}: port cannot be 0"
        )));
    }

    // Check for well-known ports in production
    if addr.port() < 1024 && !is_allowed_privileged_port(addr.port()) {
        return Err(ConfigValidationError::InvalidAddress(format!(
            "{}: port {} is a privileged port, ensure proper permissions",
            context,
            addr.port()
        )));
    }

    Ok(())
}

/// Check if a privileged port is allowed for QUIC use
fn is_allowed_privileged_port(port: u16) -> bool {
    // Common QUIC ports that might be used
    matches!(port, 443 | 80 | 853)
}

/// Validate a duration value
pub(crate) fn validate_duration(
    duration: Duration,
    min: Duration,
    max: Duration,
    context: &str,
) -> ValidationResult<()> {
    if duration < min {
        return Err(ConfigValidationError::ValueOutOfRange(format!(
            "{context}: duration {duration:?} is less than minimum {min:?}"
        )));
    }

    if duration > max {
        return Err(ConfigValidationError::ValueOutOfRange(format!(
            "{context}: duration {duration:?} is greater than maximum {max:?}"
        )));
    }

    Ok(())
}

/// Validate a numeric value within a range
pub(crate) fn validate_range<T>(value: T, min: T, max: T, context: &str) -> ValidationResult<()>
where
    T: PartialOrd + std::fmt::Display + Copy,
{
    if value < min {
        return Err(ConfigValidationError::ValueOutOfRange(format!(
            "{context}: value {value} is less than minimum {min}"
        )));
    }

    if value > max {
        return Err(ConfigValidationError::ValueOutOfRange(format!(
            "{context}: value {value} is greater than maximum {max}"
        )));
    }

    Ok(())
}

/// Validate bootstrap node addresses
pub(crate) fn validate_bootstrap_nodes(nodes: &[SocketAddr]) -> ValidationResult<()> {
    if nodes.is_empty() {
        return Err(ConfigValidationError::MissingRequiredConfig(
            "At least one bootstrap node is required for non-bootstrap endpoints".to_string(),
        ));
    }

    if nodes.len() > 100 {
        return Err(ConfigValidationError::InvalidBootstrapNode(
            "Too many bootstrap nodes (maximum 100)".to_string(),
        ));
    }

    // Check for duplicates
    let mut seen = std::collections::HashSet::new();
    for (i, node) in nodes.iter().enumerate() {
        if !seen.insert(node) {
            return Err(ConfigValidationError::InvalidBootstrapNode(format!(
                "Duplicate bootstrap node at index {i}: {node}"
            )));
        }

        validate_socket_addr(node, &format!("bootstrap node {i}"))?;
    }

    Ok(())
}

/// Validate Linux-specific network capabilities
#[cfg(target_os = "linux")]
#[allow(dead_code)]
fn validate_linux_network_capabilities() -> ValidationResult<()> {
    // Check if we can access network interfaces
    // This is a placeholder - in production, you'd check netlink access
    Ok(())
}

/// Validate Windows-specific network capabilities
#[cfg(target_os = "windows")]
fn validate_windows_network_capabilities() -> ValidationResult<()> {
    // Check if we can access IP Helper API
    // This is a placeholder - in production, you'd test IP Helper API access
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_validate_socket_addr() {
        let valid_addr = SocketAddr::new(IpAddr::V4([127, 0, 0, 1].into()), 8080);
        assert!(validate_socket_addr(&valid_addr, "test").is_ok());

        let invalid_addr = SocketAddr::new(IpAddr::V4([0, 0, 0, 0].into()), 8080);
        assert!(validate_socket_addr(&invalid_addr, "test").is_err());

        let zero_port = SocketAddr::new(IpAddr::V4([127, 0, 0, 1].into()), 0);
        assert!(validate_socket_addr(&zero_port, "test").is_err());
    }

    #[test]
    fn test_validate_duration() {
        let min = Duration::from_secs(1);
        let max = Duration::from_secs(60);

        assert!(validate_duration(Duration::from_secs(30), min, max, "test").is_ok());
        assert!(validate_duration(Duration::from_millis(500), min, max, "test").is_err());
        assert!(validate_duration(Duration::from_secs(120), min, max, "test").is_err());
    }

    #[test]
    fn test_validate_range() {
        assert!(validate_range(50, 1, 100, "test").is_ok());
        assert!(validate_range(0, 1, 100, "test").is_err());
        assert!(validate_range(150, 1, 100, "test").is_err());
    }

    #[test]
    fn test_validate_bootstrap_nodes() {
        let valid_nodes = vec![
            SocketAddr::new(IpAddr::V4([127, 0, 0, 1].into()), 8080),
            SocketAddr::new(IpAddr::V4([192, 168, 1, 1].into()), 8081),
        ];
        assert!(validate_bootstrap_nodes(&valid_nodes).is_ok());

        let empty_nodes = vec![];
        assert!(validate_bootstrap_nodes(&empty_nodes).is_err());

        let duplicate_nodes = vec![
            SocketAddr::new(IpAddr::V4([127, 0, 0, 1].into()), 8080),
            SocketAddr::new(IpAddr::V4([127, 0, 0, 1].into()), 8080),
        ];
        assert!(validate_bootstrap_nodes(&duplicate_nodes).is_err());
    }
}
