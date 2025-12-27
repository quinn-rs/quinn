// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Connection strategy state machine for progressive NAT traversal fallback.
//!
//! This module implements a state machine that attempts connections using
//! progressively more aggressive NAT traversal techniques:
//!
//! 1. **Direct IPv4** - Simple direct connection (fastest when both peers have public IPv4)
//! 2. **Direct IPv6** - Many ISPs have native IPv6 even behind CGNAT
//! 3. **Hole-Punch** - Coordinated NAT traversal via a common peer
//! 4. **Relay** - MASQUE CONNECT-UDP relay (guaranteed connectivity)
//!
//! # Example
//!
//! ```rust,ignore
//! let config = StrategyConfig::default();
//! let mut strategy = ConnectionStrategy::new(config);
//!
//! loop {
//!     match strategy.current_stage() {
//!         ConnectionStage::DirectIPv4 { .. } => {
//!             // Try direct IPv4 connection
//!         }
//!         ConnectionStage::DirectIPv6 { .. } => {
//!             // Try direct IPv6 connection
//!         }
//!         ConnectionStage::HolePunching { .. } => {
//!             // Coordinate hole-punching via common peer
//!         }
//!         ConnectionStage::Relay { .. } => {
//!             // Connect via MASQUE relay
//!         }
//!         ConnectionStage::Connected { via } => {
//!             println!("Connected via {:?}", via);
//!             break;
//!         }
//!         ConnectionStage::Failed { errors } => {
//!             eprintln!("All strategies failed: {:?}", errors);
//!             break;
//!         }
//!     }
//! }
//! ```

use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// How a connection was established
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionMethod {
    /// Direct IPv4 connection succeeded
    DirectIPv4,
    /// Direct IPv6 connection succeeded (NAT bypassed)
    DirectIPv6,
    /// Connection established via coordinated hole-punching
    HolePunched {
        /// The coordinator peer that helped with hole-punching
        coordinator: SocketAddr,
    },
    /// Connection established via relay
    Relayed {
        /// The relay server address
        relay: SocketAddr,
    },
}

impl std::fmt::Display for ConnectionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionMethod::DirectIPv4 => write!(f, "Direct IPv4"),
            ConnectionMethod::DirectIPv6 => write!(f, "Direct IPv6"),
            ConnectionMethod::HolePunched { coordinator } => {
                write!(f, "Hole-punched via {}", coordinator)
            }
            ConnectionMethod::Relayed { relay } => write!(f, "Relayed via {}", relay),
        }
    }
}

/// Error that occurred during a connection attempt
#[derive(Debug, Clone)]
pub struct ConnectionAttemptError {
    /// The method that was attempted
    pub method: AttemptedMethod,
    /// Description of the error
    pub error: String,
    /// When the attempt was made
    pub timestamp: Instant,
}

/// Which method was attempted
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptedMethod {
    /// Direct IPv4 connection
    DirectIPv4,
    /// Direct IPv6 connection
    DirectIPv6,
    /// Hole-punching with specified round
    HolePunch {
        /// The round number
        round: u32,
    },
    /// Relay connection
    Relay,
}

/// Current stage of the connection strategy
#[derive(Debug, Clone)]
pub enum ConnectionStage {
    /// Attempting direct IPv4 connection
    DirectIPv4 {
        /// When this stage started
        started: Instant,
    },
    /// Attempting direct IPv6 connection
    DirectIPv6 {
        /// When this stage started
        started: Instant,
    },
    /// Attempting hole-punching via a coordinator
    HolePunching {
        /// The coordinator peer address
        coordinator: SocketAddr,
        /// Current hole-punch round (starts at 1)
        round: u32,
        /// When this stage started
        started: Instant,
    },
    /// Attempting relay connection
    Relay {
        /// The relay server address
        relay_addr: SocketAddr,
        /// When this stage started
        started: Instant,
    },
    /// Successfully connected
    Connected {
        /// How the connection was established
        via: ConnectionMethod,
    },
    /// All methods failed
    Failed {
        /// Errors from all attempted methods
        errors: Vec<ConnectionAttemptError>,
    },
}

/// Configuration for connection strategy timeouts and behavior
#[derive(Debug, Clone)]
pub struct StrategyConfig {
    /// Timeout for direct IPv4 connection attempts
    pub ipv4_timeout: Duration,
    /// Timeout for direct IPv6 connection attempts
    pub ipv6_timeout: Duration,
    /// Timeout for each hole-punch round
    pub holepunch_timeout: Duration,
    /// Timeout for relay connection
    pub relay_timeout: Duration,
    /// Maximum number of hole-punch rounds before falling back to relay
    pub max_holepunch_rounds: u32,
    /// Whether to attempt IPv6 connections
    pub ipv6_enabled: bool,
    /// Whether to attempt relay connections as final fallback
    pub relay_enabled: bool,
    /// Optional coordinator address for hole-punching
    pub coordinator: Option<SocketAddr>,
    /// Optional relay server address
    pub relay_addr: Option<SocketAddr>,
}

impl Default for StrategyConfig {
    fn default() -> Self {
        Self {
            ipv4_timeout: Duration::from_secs(5),
            ipv6_timeout: Duration::from_secs(5),
            holepunch_timeout: Duration::from_secs(15),
            relay_timeout: Duration::from_secs(30),
            max_holepunch_rounds: 3,
            ipv6_enabled: true,
            relay_enabled: true,
            coordinator: None,
            relay_addr: None,
        }
    }
}

impl StrategyConfig {
    /// Create a new strategy config with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the IPv4 timeout
    pub fn with_ipv4_timeout(mut self, timeout: Duration) -> Self {
        self.ipv4_timeout = timeout;
        self
    }

    /// Set the IPv6 timeout
    pub fn with_ipv6_timeout(mut self, timeout: Duration) -> Self {
        self.ipv6_timeout = timeout;
        self
    }

    /// Set the hole-punch timeout
    pub fn with_holepunch_timeout(mut self, timeout: Duration) -> Self {
        self.holepunch_timeout = timeout;
        self
    }

    /// Set the relay timeout
    pub fn with_relay_timeout(mut self, timeout: Duration) -> Self {
        self.relay_timeout = timeout;
        self
    }

    /// Set the maximum number of hole-punch rounds
    pub fn with_max_holepunch_rounds(mut self, rounds: u32) -> Self {
        self.max_holepunch_rounds = rounds;
        self
    }

    /// Enable or disable IPv6 attempts
    pub fn with_ipv6_enabled(mut self, enabled: bool) -> Self {
        self.ipv6_enabled = enabled;
        self
    }

    /// Enable or disable relay fallback
    pub fn with_relay_enabled(mut self, enabled: bool) -> Self {
        self.relay_enabled = enabled;
        self
    }

    /// Set the coordinator address for hole-punching
    pub fn with_coordinator(mut self, addr: SocketAddr) -> Self {
        self.coordinator = Some(addr);
        self
    }

    /// Set the relay server address
    pub fn with_relay(mut self, addr: SocketAddr) -> Self {
        self.relay_addr = Some(addr);
        self
    }
}

/// Connection strategy state machine
///
/// Manages the progression through connection methods from fastest (direct)
/// to most reliable (relay).
#[derive(Debug)]
pub struct ConnectionStrategy {
    stage: ConnectionStage,
    config: StrategyConfig,
    errors: Vec<ConnectionAttemptError>,
}

impl ConnectionStrategy {
    /// Create a new connection strategy with the given configuration
    pub fn new(config: StrategyConfig) -> Self {
        Self {
            stage: ConnectionStage::DirectIPv4 {
                started: Instant::now(),
            },
            config,
            errors: Vec::new(),
        }
    }

    /// Get the current stage
    pub fn current_stage(&self) -> &ConnectionStage {
        &self.stage
    }

    /// Get the configuration
    pub fn config(&self) -> &StrategyConfig {
        &self.config
    }

    /// Get the IPv4 timeout
    pub fn ipv4_timeout(&self) -> Duration {
        self.config.ipv4_timeout
    }

    /// Get the IPv6 timeout
    pub fn ipv6_timeout(&self) -> Duration {
        self.config.ipv6_timeout
    }

    /// Get the hole-punch timeout
    pub fn holepunch_timeout(&self) -> Duration {
        self.config.holepunch_timeout
    }

    /// Get the relay timeout
    pub fn relay_timeout(&self) -> Duration {
        self.config.relay_timeout
    }

    /// Record an error and transition to IPv6 stage
    pub fn transition_to_ipv6(&mut self, error: impl Into<String>) {
        self.errors.push(ConnectionAttemptError {
            method: AttemptedMethod::DirectIPv4,
            error: error.into(),
            timestamp: Instant::now(),
        });

        if self.config.ipv6_enabled {
            self.stage = ConnectionStage::DirectIPv6 {
                started: Instant::now(),
            };
        } else {
            self.transition_to_holepunch_internal();
        }
    }

    /// Record an error and transition to hole-punching stage
    pub fn transition_to_holepunch(&mut self, error: impl Into<String>) {
        self.errors.push(ConnectionAttemptError {
            method: AttemptedMethod::DirectIPv6,
            error: error.into(),
            timestamp: Instant::now(),
        });
        self.transition_to_holepunch_internal();
    }

    fn transition_to_holepunch_internal(&mut self) {
        if let Some(coordinator) = self.config.coordinator {
            self.stage = ConnectionStage::HolePunching {
                coordinator,
                round: 1,
                started: Instant::now(),
            };
        } else {
            // No coordinator available, skip to relay
            self.transition_to_relay_internal();
        }
    }

    /// Record a hole-punch error and either retry or transition to relay
    pub fn record_holepunch_error(&mut self, round: u32, error: impl Into<String>) {
        self.errors.push(ConnectionAttemptError {
            method: AttemptedMethod::HolePunch { round },
            error: error.into(),
            timestamp: Instant::now(),
        });
    }

    /// Check if we should retry hole-punching
    pub fn should_retry_holepunch(&self) -> bool {
        if let ConnectionStage::HolePunching { round, .. } = &self.stage {
            *round < self.config.max_holepunch_rounds
        } else {
            false
        }
    }

    /// Increment the hole-punch round
    pub fn increment_round(&mut self) {
        if let ConnectionStage::HolePunching {
            coordinator, round, ..
        } = &self.stage
        {
            self.stage = ConnectionStage::HolePunching {
                coordinator: *coordinator,
                round: round + 1,
                started: Instant::now(),
            };
        }
    }

    /// Transition to relay stage
    pub fn transition_to_relay(&mut self, error: impl Into<String>) {
        if let ConnectionStage::HolePunching { round, .. } = &self.stage {
            self.errors.push(ConnectionAttemptError {
                method: AttemptedMethod::HolePunch { round: *round },
                error: error.into(),
                timestamp: Instant::now(),
            });
        }
        self.transition_to_relay_internal();
    }

    fn transition_to_relay_internal(&mut self) {
        if self.config.relay_enabled {
            if let Some(relay_addr) = self.config.relay_addr {
                self.stage = ConnectionStage::Relay {
                    relay_addr,
                    started: Instant::now(),
                };
            } else {
                // No relay available
                self.transition_to_failed("No relay server configured");
            }
        } else {
            self.transition_to_failed("Relay disabled and all other methods failed");
        }
    }

    /// Transition to failed state
    pub fn transition_to_failed(&mut self, error: impl Into<String>) {
        // Record the final error if we came from relay stage
        if let ConnectionStage::Relay { .. } = &self.stage {
            self.errors.push(ConnectionAttemptError {
                method: AttemptedMethod::Relay,
                error: error.into(),
                timestamp: Instant::now(),
            });
        }

        self.stage = ConnectionStage::Failed {
            errors: std::mem::take(&mut self.errors),
        };
    }

    /// Mark connection as successful via the specified method
    pub fn mark_connected(&mut self, method: ConnectionMethod) {
        self.stage = ConnectionStage::Connected { via: method };
    }

    /// Check if the strategy has reached a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.stage,
            ConnectionStage::Connected { .. } | ConnectionStage::Failed { .. }
        )
    }

    /// Get all recorded errors
    pub fn errors(&self) -> &[ConnectionAttemptError] {
        &self.errors
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = StrategyConfig::default();
        assert_eq!(config.ipv4_timeout, Duration::from_secs(5));
        assert_eq!(config.ipv6_timeout, Duration::from_secs(5));
        assert_eq!(config.holepunch_timeout, Duration::from_secs(15));
        assert_eq!(config.relay_timeout, Duration::from_secs(30));
        assert_eq!(config.max_holepunch_rounds, 3);
        assert!(config.ipv6_enabled);
        assert!(config.relay_enabled);
    }

    #[test]
    fn test_config_builder() {
        let config = StrategyConfig::new()
            .with_ipv4_timeout(Duration::from_secs(3))
            .with_ipv6_timeout(Duration::from_secs(3))
            .with_max_holepunch_rounds(5)
            .with_ipv6_enabled(false);

        assert_eq!(config.ipv4_timeout, Duration::from_secs(3));
        assert_eq!(config.max_holepunch_rounds, 5);
        assert!(!config.ipv6_enabled);
    }

    #[test]
    fn test_initial_stage() {
        let strategy = ConnectionStrategy::new(StrategyConfig::default());
        assert!(matches!(
            strategy.current_stage(),
            ConnectionStage::DirectIPv4 { .. }
        ));
    }

    #[test]
    fn test_transition_ipv4_to_ipv6() {
        let mut strategy = ConnectionStrategy::new(StrategyConfig::default());

        strategy.transition_to_ipv6("Connection refused");

        assert!(matches!(
            strategy.current_stage(),
            ConnectionStage::DirectIPv6 { .. }
        ));
        assert_eq!(strategy.errors().len(), 1);
        assert!(matches!(
            strategy.errors()[0].method,
            AttemptedMethod::DirectIPv4
        ));
    }

    #[test]
    fn test_skip_ipv6_when_disabled() {
        let config = StrategyConfig::new()
            .with_ipv6_enabled(false)
            .with_coordinator("127.0.0.1:9000".parse().unwrap());
        let mut strategy = ConnectionStrategy::new(config);

        strategy.transition_to_ipv6("Connection refused");

        // Should skip directly to hole-punching
        assert!(matches!(
            strategy.current_stage(),
            ConnectionStage::HolePunching { round: 1, .. }
        ));
    }

    #[test]
    fn test_transition_to_holepunch() {
        let config = StrategyConfig::new().with_coordinator("127.0.0.1:9000".parse().unwrap());
        let mut strategy = ConnectionStrategy::new(config);

        strategy.transition_to_ipv6("IPv4 failed");
        strategy.transition_to_holepunch("IPv6 failed");

        assert!(matches!(
            strategy.current_stage(),
            ConnectionStage::HolePunching {
                round: 1,
                coordinator,
                ..
            } if coordinator.port() == 9000
        ));
    }

    #[test]
    fn test_holepunch_rounds() {
        let config = StrategyConfig::new()
            .with_coordinator("127.0.0.1:9000".parse().unwrap())
            .with_max_holepunch_rounds(3);
        let mut strategy = ConnectionStrategy::new(config);

        // Get to holepunch stage
        strategy.transition_to_ipv6("IPv4 failed");
        strategy.transition_to_holepunch("IPv6 failed");

        // Round 1
        assert!(strategy.should_retry_holepunch());
        strategy.record_holepunch_error(1, "Round 1 failed");
        strategy.increment_round();

        // Round 2
        if let ConnectionStage::HolePunching { round, .. } = strategy.current_stage() {
            assert_eq!(*round, 2);
        } else {
            panic!("Expected HolePunching stage");
        }
        assert!(strategy.should_retry_holepunch());
        strategy.record_holepunch_error(2, "Round 2 failed");
        strategy.increment_round();

        // Round 3 - last round
        if let ConnectionStage::HolePunching { round, .. } = strategy.current_stage() {
            assert_eq!(*round, 3);
        } else {
            panic!("Expected HolePunching stage");
        }
        assert!(!strategy.should_retry_holepunch());
    }

    #[test]
    fn test_transition_to_relay() {
        let config = StrategyConfig::new()
            .with_coordinator("127.0.0.1:9000".parse().unwrap())
            .with_relay("127.0.0.1:9001".parse().unwrap());
        let mut strategy = ConnectionStrategy::new(config);

        strategy.transition_to_ipv6("IPv4 failed");
        strategy.transition_to_holepunch("IPv6 failed");
        strategy.transition_to_relay("Holepunch failed");

        if let ConnectionStage::Relay { relay_addr, .. } = strategy.current_stage() {
            assert_eq!(relay_addr.port(), 9001);
        } else {
            panic!("Expected Relay stage");
        }
    }

    #[test]
    fn test_transition_to_failed() {
        let config = StrategyConfig::new()
            .with_coordinator("127.0.0.1:9000".parse().unwrap())
            .with_relay("127.0.0.1:9001".parse().unwrap());
        let mut strategy = ConnectionStrategy::new(config);

        strategy.transition_to_ipv6("IPv4 failed");
        strategy.transition_to_holepunch("IPv6 failed");
        strategy.transition_to_relay("Holepunch failed");
        strategy.transition_to_failed("Relay failed");

        if let ConnectionStage::Failed { errors } = strategy.current_stage() {
            assert_eq!(errors.len(), 4);
        } else {
            panic!("Expected Failed stage");
        }
    }

    #[test]
    fn test_mark_connected() {
        let mut strategy = ConnectionStrategy::new(StrategyConfig::default());

        strategy.mark_connected(ConnectionMethod::DirectIPv4);

        if let ConnectionStage::Connected { via } = strategy.current_stage() {
            assert_eq!(*via, ConnectionMethod::DirectIPv4);
        } else {
            panic!("Expected Connected stage");
        }
        assert!(strategy.is_terminal());
    }

    #[test]
    fn test_connection_method_display() {
        assert_eq!(format!("{}", ConnectionMethod::DirectIPv4), "Direct IPv4");
        assert_eq!(format!("{}", ConnectionMethod::DirectIPv6), "Direct IPv6");
        assert_eq!(
            format!(
                "{}",
                ConnectionMethod::HolePunched {
                    coordinator: "1.2.3.4:9000".parse().unwrap()
                }
            ),
            "Hole-punched via 1.2.3.4:9000"
        );
        assert_eq!(
            format!(
                "{}",
                ConnectionMethod::Relayed {
                    relay: "5.6.7.8:9001".parse().unwrap()
                }
            ),
            "Relayed via 5.6.7.8:9001"
        );
    }

    #[test]
    fn test_no_coordinator_skips_to_relay() {
        let config = StrategyConfig::new().with_relay("127.0.0.1:9001".parse().unwrap());
        // No coordinator set
        let mut strategy = ConnectionStrategy::new(config);

        strategy.transition_to_ipv6("IPv4 failed");
        strategy.transition_to_holepunch("IPv6 failed");

        // Should skip hole-punching and go to relay
        assert!(matches!(
            strategy.current_stage(),
            ConnectionStage::Relay { .. }
        ));
    }

    #[test]
    fn test_no_relay_fails() {
        let config = StrategyConfig::new()
            .with_coordinator("127.0.0.1:9000".parse().unwrap())
            .with_relay_enabled(false);
        let mut strategy = ConnectionStrategy::new(config);

        strategy.transition_to_ipv6("IPv4 failed");
        strategy.transition_to_holepunch("IPv6 failed");
        strategy.transition_to_relay("Holepunch failed");

        // Should fail since relay is disabled
        assert!(matches!(
            strategy.current_stage(),
            ConnectionStage::Failed { .. }
        ));
    }
}
