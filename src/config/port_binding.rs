// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Socket binding implementation for port configuration
//!
//! This module handles the actual socket binding logic, including retry behavior,
//! dual-stack support, and port validation.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

use super::port::{
    BoundSocket, EndpointConfigError, EndpointPortConfig, IpMode, PortBinding, PortConfigResult,
    PortRetryBehavior, SocketOptions, buffer_defaults,
};

/// Validate port number
fn validate_port(port: u16) -> PortConfigResult<()> {
    if port < 1024 {
        return Err(EndpointConfigError::PermissionDenied(port));
    }
    Ok(())
}

/// Validate port range
fn validate_port_range(start: u16, end: u16) -> PortConfigResult<()> {
    if start >= end {
        return Err(EndpointConfigError::InvalidConfig(format!(
            "Invalid port range: start ({}) must be less than end ({})",
            start, end
        )));
    }
    if start < 1024 {
        return Err(EndpointConfigError::PermissionDenied(start));
    }
    Ok(())
}

/// Try to set send buffer size with graceful fallback
///
/// If the kernel rejects the requested size, tries progressively smaller sizes
/// until it succeeds or reaches the minimum buffer size.
fn try_set_send_buffer(socket: &socket2::Socket, requested: usize) -> std::io::Result<usize> {
    let mut size = requested;
    while size >= buffer_defaults::MIN_BUFFER_SIZE {
        if socket.set_send_buffer_size(size).is_ok() {
            // Return actual size that was set
            return socket.send_buffer_size();
        }
        // Try half the size
        size /= 2;
        tracing::debug!(
            "Send buffer size {} rejected, trying {} bytes",
            size * 2,
            size
        );
    }
    // Last resort: try minimum size
    if socket
        .set_send_buffer_size(buffer_defaults::MIN_BUFFER_SIZE)
        .is_ok()
    {
        return socket.send_buffer_size();
    }
    // Accept whatever the OS gives us
    socket.send_buffer_size()
}

/// Try to set receive buffer size with graceful fallback
///
/// If the kernel rejects the requested size, tries progressively smaller sizes
/// until it succeeds or reaches the minimum buffer size.
fn try_set_recv_buffer(socket: &socket2::Socket, requested: usize) -> std::io::Result<usize> {
    let mut size = requested;
    while size >= buffer_defaults::MIN_BUFFER_SIZE {
        if socket.set_recv_buffer_size(size).is_ok() {
            // Return actual size that was set
            return socket.recv_buffer_size();
        }
        // Try half the size
        size /= 2;
        tracing::debug!(
            "Recv buffer size {} rejected, trying {} bytes",
            size * 2,
            size
        );
    }
    // Last resort: try minimum size
    if socket
        .set_recv_buffer_size(buffer_defaults::MIN_BUFFER_SIZE)
        .is_ok()
    {
        return socket.recv_buffer_size();
    }
    // Accept whatever the OS gives us
    socket.recv_buffer_size()
}

/// Create a socket with specified options
fn create_socket(addr: &SocketAddr, opts: &SocketOptions) -> PortConfigResult<UdpSocket> {
    let socket = socket2::Socket::new(
        if addr.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        },
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .map_err(|e| EndpointConfigError::BindFailed(e.to_string()))?;

    // Set socket to non-blocking mode
    socket
        .set_nonblocking(true)
        .map_err(|e| EndpointConfigError::BindFailed(e.to_string()))?;

    // Apply socket options
    if opts.reuse_address {
        socket
            .set_reuse_address(true)
            .map_err(|e| EndpointConfigError::BindFailed(e.to_string()))?;
    }

    // SO_REUSEPORT support is platform-specific and optional
    // We'll skip it for now to ensure cross-platform compatibility
    #[allow(clippy::collapsible_if)]
    if opts.reuse_port {
        #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
        {
            // On supported Unix platforms, try to set SO_REUSEPORT
            // This is a best-effort attempt - failure is not critical
            tracing::debug!("SO_REUSEPORT requested but skipped for compatibility");
        }
    }

    // Apply buffer sizes with graceful fallback
    // If the kernel rejects the requested size, try progressively smaller sizes
    if let Some(size) = opts.send_buffer_size {
        if let Err(e) = try_set_send_buffer(&socket, size) {
            tracing::warn!(
                "Failed to set send buffer to {} bytes: {}. Using OS default.",
                size,
                e
            );
        }
    }

    if let Some(size) = opts.recv_buffer_size {
        if let Err(e) = try_set_recv_buffer(&socket, size) {
            tracing::warn!(
                "Failed to set recv buffer to {} bytes: {}. Using OS default.",
                size,
                e
            );
        }
    }

    // Bind the socket
    socket.bind(&socket2::SockAddr::from(*addr)).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AddrInUse {
            EndpointConfigError::PortInUse(addr.port())
        } else if e.kind() == std::io::ErrorKind::PermissionDenied {
            EndpointConfigError::PermissionDenied(addr.port())
        } else {
            EndpointConfigError::BindFailed(e.to_string())
        }
    })?;

    // Convert to std::net::UdpSocket
    let std_socket: UdpSocket = socket.into();
    Ok(std_socket)
}

/// Bind a single socket to the given port and IP mode
fn bind_single_socket(
    port: u16,
    ip_mode: &IpMode,
    socket_opts: &SocketOptions,
) -> PortConfigResult<Vec<SocketAddr>> {
    match ip_mode {
        IpMode::IPv4Only => {
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
            let socket = create_socket(&addr, socket_opts)?;
            let local_addr = socket
                .local_addr()
                .map_err(|e| EndpointConfigError::BindFailed(e.to_string()))?;
            // Keep socket alive by forgetting it (in production, we'd store it)
            std::mem::forget(socket);
            Ok(vec![local_addr])
        }
        IpMode::IPv6Only => {
            let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
            let socket = create_socket(&addr, socket_opts)?;
            let local_addr = socket
                .local_addr()
                .map_err(|e| EndpointConfigError::BindFailed(e.to_string()))?;
            std::mem::forget(socket);
            Ok(vec![local_addr])
        }
        IpMode::DualStack => {
            // Try binding both stacks to same port
            let v4_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
            let v6_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);

            let v4_socket = create_socket(&v4_addr, socket_opts)?;
            let v4_local = v4_socket
                .local_addr()
                .map_err(|e| EndpointConfigError::BindFailed(e.to_string()))?;

            let v6_socket = create_socket(&v6_addr, socket_opts)
                .map_err(|_| EndpointConfigError::DualStackNotSupported)?;
            let v6_local = v6_socket
                .local_addr()
                .map_err(|e| EndpointConfigError::BindFailed(e.to_string()))?;

            std::mem::forget(v4_socket);
            std::mem::forget(v6_socket);
            Ok(vec![v4_local, v6_local])
        }
        IpMode::DualStackSeparate {
            ipv4_port,
            ipv6_port,
        } => {
            // Recursively bind each stack with its own port
            let mut addrs = Vec::new();

            // Bind IPv4
            let v4_addrs = bind_with_port_binding(ipv4_port, &IpMode::IPv4Only, socket_opts)?;
            addrs.extend(v4_addrs);

            // Bind IPv6
            let v6_addrs = bind_with_port_binding(ipv6_port, &IpMode::IPv6Only, socket_opts)?;
            addrs.extend(v6_addrs);

            Ok(addrs)
        }
    }
}

/// Bind with port binding strategy
fn bind_with_port_binding(
    port_binding: &PortBinding,
    ip_mode: &IpMode,
    socket_opts: &SocketOptions,
) -> PortConfigResult<Vec<SocketAddr>> {
    match port_binding {
        PortBinding::OsAssigned => bind_single_socket(0, ip_mode, socket_opts),
        PortBinding::Explicit(port) => {
            validate_port(*port)?;
            bind_single_socket(*port, ip_mode, socket_opts)
        }
        PortBinding::Range(start, end) => {
            validate_port_range(*start, *end)?;

            for port in *start..=*end {
                match bind_single_socket(port, ip_mode, socket_opts) {
                    Ok(addrs) => return Ok(addrs),
                    Err(EndpointConfigError::PortInUse(_)) => continue,
                    Err(e) => return Err(e),
                }
            }

            Err(EndpointConfigError::NoPortInRange(*start, *end))
        }
    }
}

/// Bind endpoint with configuration
pub fn bind_endpoint(config: &EndpointPortConfig) -> PortConfigResult<BoundSocket> {
    let addrs = match &config.port {
        PortBinding::OsAssigned => bind_single_socket(0, &config.ip_mode, &config.socket_options)?,
        PortBinding::Explicit(port) => {
            validate_port(*port)?;
            match bind_single_socket(*port, &config.ip_mode, &config.socket_options) {
                Ok(addrs) => addrs,
                Err(EndpointConfigError::PortInUse(_)) => match config.retry_behavior {
                    PortRetryBehavior::FailFast => {
                        return Err(EndpointConfigError::PortInUse(*port));
                    }
                    PortRetryBehavior::FallbackToOsAssigned => {
                        tracing::warn!("Port {} in use, falling back to OS-assigned", port);
                        bind_single_socket(0, &config.ip_mode, &config.socket_options)?
                    }
                    PortRetryBehavior::TryNext => {
                        return Err(EndpointConfigError::PortInUse(*port));
                    }
                },
                Err(e) => return Err(e),
            }
        }
        PortBinding::Range(start, end) => {
            validate_port_range(*start, *end)?;
            bind_with_port_binding(&config.port, &config.ip_mode, &config.socket_options)?
        }
    };

    Ok(BoundSocket {
        addrs,
        config: config.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_port_privileged() {
        assert!(matches!(
            validate_port(80),
            Err(EndpointConfigError::PermissionDenied(80))
        ));
        assert!(matches!(
            validate_port(443),
            Err(EndpointConfigError::PermissionDenied(443))
        ));
        assert!(matches!(
            validate_port(1023),
            Err(EndpointConfigError::PermissionDenied(1023))
        ));
    }

    #[test]
    fn test_validate_port_valid() {
        assert!(validate_port(1024).is_ok());
        assert!(validate_port(9000).is_ok());
        assert!(validate_port(65535).is_ok());
    }

    #[test]
    fn test_validate_port_range_invalid() {
        assert!(validate_port_range(9000, 9000).is_err());
        assert!(validate_port_range(9010, 9000).is_err());
        assert!(validate_port_range(80, 90).is_err());
    }

    #[test]
    fn test_validate_port_range_valid() {
        assert!(validate_port_range(9000, 9010).is_ok());
        assert!(validate_port_range(1024, 2048).is_ok());
    }

    #[test]
    fn test_bind_os_assigned_ipv4() {
        let config = EndpointPortConfig {
            port: PortBinding::OsAssigned,
            ip_mode: IpMode::IPv4Only,
            ..Default::default()
        };

        let result = bind_endpoint(&config);
        assert!(result.is_ok());

        let bound = result.expect("bind_endpoint should succeed");
        assert_eq!(bound.addrs.len(), 1);
        assert!(bound.addrs[0].is_ipv4());
        assert_ne!(bound.addrs[0].port(), 0); // OS assigned a port
    }

    #[test]
    fn test_bind_explicit_port() {
        let config = EndpointPortConfig {
            port: PortBinding::Explicit(12345),
            ip_mode: IpMode::IPv4Only,
            ..Default::default()
        };

        let result = bind_endpoint(&config);
        assert!(result.is_ok());

        let bound = result.expect("bind_endpoint should succeed");
        assert_eq!(bound.addrs.len(), 1);
        assert_eq!(bound.addrs[0].port(), 12345);
    }

    #[test]
    fn test_bind_privileged_port_fails() {
        let config = EndpointPortConfig {
            port: PortBinding::Explicit(80),
            ip_mode: IpMode::IPv4Only,
            ..Default::default()
        };

        let result = bind_endpoint(&config);
        assert!(matches!(
            result,
            Err(EndpointConfigError::PermissionDenied(80))
        ));
    }

    #[test]
    fn test_bind_port_conflict() {
        // First binding succeeds
        let config1 = EndpointPortConfig {
            port: PortBinding::Explicit(23456),
            ip_mode: IpMode::IPv4Only,
            retry_behavior: PortRetryBehavior::FailFast,
            ..Default::default()
        };

        let _bound1 = bind_endpoint(&config1).expect("First bind should succeed");

        // Second binding to same port should fail
        let config2 = EndpointPortConfig {
            port: PortBinding::Explicit(23456),
            ip_mode: IpMode::IPv4Only,
            retry_behavior: PortRetryBehavior::FailFast,
            ..Default::default()
        };

        let result2 = bind_endpoint(&config2);
        assert!(matches!(
            result2,
            Err(EndpointConfigError::PortInUse(23456))
        ));
    }

    #[test]
    fn test_bind_fallback_to_os_assigned() {
        // First binding
        let config1 = EndpointPortConfig {
            port: PortBinding::Explicit(34567),
            ip_mode: IpMode::IPv4Only,
            ..Default::default()
        };

        let _bound1 = bind_endpoint(&config1).expect("First bind should succeed");

        // Second binding with fallback
        let config2 = EndpointPortConfig {
            port: PortBinding::Explicit(34567),
            ip_mode: IpMode::IPv4Only,
            retry_behavior: PortRetryBehavior::FallbackToOsAssigned,
            ..Default::default()
        };

        let result2 = bind_endpoint(&config2);
        assert!(result2.is_ok());

        let bound2 = result2.expect("bind_endpoint with fallback should succeed");
        assert_ne!(bound2.addrs[0].port(), 34567); // Should get different port
    }

    #[test]
    fn test_bind_port_range() {
        let config = EndpointPortConfig {
            port: PortBinding::Range(45000, 45010),
            ip_mode: IpMode::IPv4Only,
            ..Default::default()
        };

        let result = bind_endpoint(&config);
        assert!(result.is_ok());

        let bound = result.expect("bind_endpoint should succeed");
        let port = bound.addrs[0].port();
        assert!((45000..=45010).contains(&port));
    }

    #[test]
    fn test_bound_socket_primary_addr() {
        let config = EndpointPortConfig::default();
        let bound = bind_endpoint(&config).expect("bind_endpoint should succeed");

        assert!(bound.primary_addr().is_some());
        assert_eq!(bound.primary_addr(), bound.addrs.first().copied());
    }

    #[test]
    fn test_bound_socket_all_addrs() {
        let config = EndpointPortConfig::default();
        let bound = bind_endpoint(&config).expect("bind_endpoint should succeed");

        assert!(!bound.all_addrs().is_empty());
        assert_eq!(bound.all_addrs(), &bound.addrs[..]);
    }
}
