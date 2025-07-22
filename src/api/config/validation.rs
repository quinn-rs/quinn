//! Configuration validation module
//!
//! This module provides validation functions for P2P configuration options.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

use super::ConfigError;
use crate::nat_traversal::BootstrapNode;

/// Validate bootstrap nodes
///
/// Ensures that:
/// - There is at least one bootstrap node if NAT traversal is enabled
/// - There are no duplicate bootstrap nodes
/// - Each bootstrap node has a valid address
pub(crate) fn validate_bootstrap_nodes(
    nodes: &[BootstrapNode],
    nat_traversal_enabled: bool,
) -> Result<(), ConfigError> {
    // If NAT traversal is enabled, at least one bootstrap node is required
    if nat_traversal_enabled && nodes.is_empty() {
        return Err(ConfigError::MissingRequiredConfig(
            "At least one bootstrap node is required when NAT traversal is enabled".to_string(),
        ));
    }

    // Check for too many bootstrap nodes
    if nodes.len() > 100 {
        return Err(ConfigError::InvalidBootstrapNode(
            "Too many bootstrap nodes (maximum 100)".to_string(),
        ));
    }

    // Check for duplicates
    let mut seen = HashSet::new();
    for (i, node) in nodes.iter().enumerate() {
        if !seen.insert(node.address) {
            return Err(ConfigError::InvalidBootstrapNode(format!(
                "Duplicate bootstrap node at index {}: {}",
                i, node.address
            )));
        }

        validate_socket_addr(&node.address, &format!("bootstrap node {}", i))?;
    }

    Ok(())
}

/// Validate a socket address
///
/// Ensures that:
/// - The address is not unspecified (0.0.0.0)
/// - The address is not broadcast (255.255.255.255)
/// - The address is not multicast
/// - The port is not 0
pub(crate) fn validate_socket_addr(addr: &SocketAddr, context: &str) -> Result<(), ConfigError> {
    // Check for reserved/invalid addresses
    match addr.ip() {
        std::net::IpAddr::V4(ipv4) => {
            if ipv4.is_unspecified() && context != "listen address" {
                // Allow unspecified for listen address (0.0.0.0)
                return Err(ConfigError::InvalidAddress(format!(
                    "{}: IPv4 address cannot be unspecified (0.0.0.0)",
                    context
                )));
            }
            if ipv4.is_broadcast() {
                return Err(ConfigError::InvalidAddress(format!(
                    "{}: IPv4 address cannot be broadcast (255.255.255.255)",
                    context
                )));
            }
            if ipv4.is_multicast() {
                return Err(ConfigError::InvalidAddress(format!(
                    "{}: IPv4 address cannot be multicast",
                    context
                )));
            }
        }
        std::net::IpAddr::V6(ipv6) => {
            if ipv6.is_unspecified() && context != "listen address" {
                // Allow unspecified for listen address (::)
                return Err(ConfigError::InvalidAddress(format!(
                    "{}: IPv6 address cannot be unspecified (::)",
                    context
                )));
            }
            if ipv6.is_multicast() {
                return Err(ConfigError::InvalidAddress(format!(
                    "{}: IPv6 address cannot be multicast",
                    context
                )));
            }
        }
    }

    // Check port range
    if addr.port() == 0 && context != "listen address" {
        // Allow port 0 for listen address (system will assign a port)
        return Err(ConfigError::InvalidAddress(format!(
            "{}: port cannot be 0",
            context
        )));
    }

    Ok(())
}

/// Validate a duration value
///
/// Ensures that the duration is within the specified range.
pub(crate) fn validate_duration(
    duration: Duration,
    min: Duration,
    max: Duration,
    context: &str,
) -> Result<(), ConfigError> {
    if duration < min {
        return Err(ConfigError::ValueOutOfRange(format!(
            "{}: duration {:?} is less than minimum {:?}",
            context, duration, min
        )));
    }

    if duration > max {
        return Err(ConfigError::ValueOutOfRange(format!(
            "{}: duration {:?} is greater than maximum {:?}",
            context, duration, max
        )));
    }

    Ok(())
}

/// Validate a numeric value within a range
///
/// Ensures that the value is within the specified range.
pub(crate) fn validate_range<T>(value: T, min: T, max: T, context: &str) -> Result<(), ConfigError>
where
    T: PartialOrd + std::fmt::Display + Copy,
{
    if value < min {
        return Err(ConfigError::ValueOutOfRange(format!(
            "{}: value {} is less than minimum {}",
            context, value, min
        )));
    }

    if value > max {
        return Err(ConfigError::ValueOutOfRange(format!(
            "{}: value {} is greater than maximum {}",
            context, value, max
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_validate_socket_addr() {
        let valid_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        assert!(validate_socket_addr(&valid_addr, "test").is_ok());

        let invalid_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8080);
        assert!(validate_socket_addr(&invalid_addr, "test").is_err());

        // Unspecified address should be allowed for listen address
        let unspecified_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8080);
        assert!(validate_socket_addr(&unspecified_addr, "listen address").is_ok());

        let zero_port = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        assert!(validate_socket_addr(&zero_port, "test").is_err());

        // Port 0 should be allowed for listen address
        let zero_port_listen = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        assert!(validate_socket_addr(&zero_port_listen, "listen address").is_ok());
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
}
