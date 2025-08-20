// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses


//! Metrics collection and export system
//!
//! This module provides metrics collection and export capabilities for ant-quic.
//! It includes both internal metrics collection (always available) and optional
//! Prometheus export functionality.
//!
//! ## Feature Gates
//!
//! - **Basic metrics**: Always available (no feature flag required)
//! - **Prometheus export**: Requires the `prometheus` feature flag
//!
//! ## Example
//!
//! ```rust
//! use ant_quic::metrics::MetricsConfig;
//!
//! // Basic metrics config (always available)
//! let config = MetricsConfig::default();
//! assert!(!config.enabled);
//!
//! #[cfg(feature = "prometheus")]
//! {
//!     // Prometheus-specific functionality only available with feature flag
//!     use ant_quic::metrics::{PrometheusExporter, MetricsServer};
//! }
//! ```

pub use crate::logging::metrics::*;

#[cfg(feature = "prometheus")]
pub mod prometheus;

#[cfg(feature = "prometheus")]
pub mod http_server;

#[cfg(feature = "prometheus")]
pub use self::prometheus::PrometheusExporter;

#[cfg(feature = "prometheus")]
pub use self::http_server::MetricsServer;

/// Configuration for metrics collection and export
#[derive(Debug, Clone)]
pub struct MetricsConfig {
    /// Whether to enable metrics collection
    pub enabled: bool,
    /// Port for the metrics HTTP server (only used when prometheus feature is enabled)
    pub port: u16,
    /// Address to bind the metrics server to
    pub bind_address: std::net::IpAddr,
    /// Update interval for metrics collection
    pub update_interval: std::time::Duration,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 9090,
            bind_address: std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            update_interval: std::time::Duration::from_secs(30),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_config_default() {
        let config = MetricsConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.port, 9090);
        assert_eq!(
            config.bind_address,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))
        );
        assert_eq!(config.update_interval, std::time::Duration::from_secs(30));
    }
}
