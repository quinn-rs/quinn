// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Configurable timeouts for NAT traversal operations

use crate::Duration;
use serde::{Deserialize, Serialize};

/// Configuration for NAT traversal timeouts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatTraversalTimeouts {
    /// Timeout for hole punching coordination
    pub coordination_timeout: Duration,

    /// Overall timeout for establishing a connection through NAT
    pub connection_establishment_timeout: Duration,

    /// Timeout for individual probe attempts
    pub probe_timeout: Duration,

    /// Interval between retry attempts
    pub retry_interval: Duration,

    /// Timeout for bootstrap node queries
    pub bootstrap_query_timeout: Duration,

    /// Time to wait for path migration to complete
    pub migration_timeout: Duration,

    /// Time to wait for session state transitions
    pub session_timeout: Duration,
}

impl Default for NatTraversalTimeouts {
    fn default() -> Self {
        Self {
            coordination_timeout: Duration::from_secs(10),
            connection_establishment_timeout: Duration::from_secs(30),
            probe_timeout: Duration::from_secs(5),
            retry_interval: Duration::from_secs(1),
            bootstrap_query_timeout: Duration::from_secs(5),
            migration_timeout: Duration::from_secs(60),
            session_timeout: Duration::from_secs(5),
        }
    }
}

impl NatTraversalTimeouts {
    /// Create timeouts optimized for fast local networks
    pub fn fast() -> Self {
        Self {
            coordination_timeout: Duration::from_secs(5),
            connection_establishment_timeout: Duration::from_secs(15),
            probe_timeout: Duration::from_secs(2),
            retry_interval: Duration::from_millis(500),
            bootstrap_query_timeout: Duration::from_secs(2),
            migration_timeout: Duration::from_secs(30),
            session_timeout: Duration::from_secs(2),
        }
    }

    /// Create timeouts optimized for slow or unreliable networks
    pub fn conservative() -> Self {
        Self {
            coordination_timeout: Duration::from_secs(20),
            connection_establishment_timeout: Duration::from_secs(60),
            probe_timeout: Duration::from_secs(10),
            retry_interval: Duration::from_secs(2),
            bootstrap_query_timeout: Duration::from_secs(10),
            migration_timeout: Duration::from_secs(120),
            session_timeout: Duration::from_secs(10),
        }
    }
}

/// Configuration for discovery operation timeouts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryTimeouts {
    /// Total timeout for the entire discovery process
    pub total_timeout: Duration,

    /// Timeout for scanning local network interfaces
    pub local_scan_timeout: Duration,

    /// Time to cache network interface information
    pub interface_cache_ttl: Duration,

    /// Time to cache server reflexive addresses
    pub server_reflexive_cache_ttl: Duration,

    /// Interval between health checks for bootstrap nodes
    pub health_check_interval: Duration,
}

impl Default for DiscoveryTimeouts {
    fn default() -> Self {
        Self {
            total_timeout: Duration::from_secs(30),
            local_scan_timeout: Duration::from_secs(2),
            interface_cache_ttl: Duration::from_secs(60),
            server_reflexive_cache_ttl: Duration::from_secs(300),
            health_check_interval: Duration::from_secs(30),
        }
    }
}

/// Configuration for relay-related timeouts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayTimeouts {
    /// Timeout for relay request operations
    pub request_timeout: Duration,

    /// Interval between retry attempts
    pub retry_interval: Duration,

    /// Time window for rate limiting
    pub rate_limit_window: Duration,
}

impl Default for RelayTimeouts {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(30),
            retry_interval: Duration::from_millis(500),
            rate_limit_window: Duration::from_secs(60),
        }
    }
}

/// Master timeout configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TimeoutConfig {
    /// NAT traversal timeouts
    pub nat_traversal: NatTraversalTimeouts,

    /// Discovery timeouts
    pub discovery: DiscoveryTimeouts,

    /// Relay timeouts
    pub relay: RelayTimeouts,
}

impl TimeoutConfig {
    /// Create a configuration optimized for fast networks
    pub fn fast() -> Self {
        Self {
            nat_traversal: NatTraversalTimeouts::fast(),
            discovery: DiscoveryTimeouts::default(), // Keep default for discovery
            relay: RelayTimeouts::default(),
        }
    }

    /// Create a configuration optimized for slow networks
    pub fn conservative() -> Self {
        Self {
            nat_traversal: NatTraversalTimeouts::conservative(),
            discovery: DiscoveryTimeouts::default(),
            relay: RelayTimeouts::default(),
        }
    }
}
