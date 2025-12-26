//! TUI type definitions for the network test interface.
//!
//! This module defines the data structures used by the terminal UI
//! to display network state and peer connections.

use crate::registry::{ConnectionDirection, ConnectionMethod, ConnectivityMatrix, NatType};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Connection quality indicator (5 levels).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionQuality {
    /// Excellent connection (< 50ms RTT)
    Excellent,
    /// Good connection (50-100ms RTT)
    Good,
    /// Fair connection (100-200ms RTT)
    Fair,
    /// Poor connection (200-500ms RTT)
    Poor,
    /// Very poor connection (> 500ms RTT)
    VeryPoor,
}

impl ConnectionQuality {
    /// Create quality indicator from RTT measurement.
    pub fn from_rtt(rtt: Duration) -> Self {
        let ms = rtt.as_millis();
        if ms < 50 {
            Self::Excellent
        } else if ms < 100 {
            Self::Good
        } else if ms < 200 {
            Self::Fair
        } else if ms < 500 {
            Self::Poor
        } else {
            Self::VeryPoor
        }
    }

    /// Get the quality bar representation (5 dots).
    pub fn as_bar(&self) -> &'static str {
        match self {
            Self::Excellent => "●●●●●",
            Self::Good => "●●●●○",
            Self::Fair => "●●●○○",
            Self::Poor => "●●○○○",
            Self::VeryPoor => "●○○○○",
        }
    }
}

/// Traffic direction indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficDirection {
    /// Sending data
    Sending,
    /// Receiving data
    Receiving,
    /// Idle
    Idle,
}

/// Information about a connected peer for display.
#[derive(Debug, Clone)]
pub struct ConnectedPeer {
    /// Short peer ID (first 8 chars)
    pub short_id: String,
    /// Full peer ID
    pub full_id: String,
    /// Country code with flag emoji
    pub location: String,
    /// Connection method used
    pub method: ConnectionMethod,
    /// Connection direction (who initiated)
    pub direction: ConnectionDirection,
    /// Current RTT measurement
    pub rtt: Option<Duration>,
    /// Connection quality
    pub quality: ConnectionQuality,
    /// TX traffic indicator
    pub tx_active: bool,
    /// RX traffic indicator
    pub rx_active: bool,
    /// Packets sent
    pub packets_sent: u64,
    /// Packets received
    pub packets_received: u64,
    /// Connection established time
    pub connected_at: Instant,
    /// Remote addresses
    pub addresses: Vec<SocketAddr>,
    /// Connectivity matrix showing all tested paths
    pub connectivity: ConnectivityMatrix,
}

impl ConnectedPeer {
    /// Create a new connected peer.
    pub fn new(peer_id: &str, method: ConnectionMethod) -> Self {
        Self::with_direction(peer_id, method, ConnectionDirection::Outbound)
    }

    /// Create a new connected peer with explicit direction.
    pub fn with_direction(
        peer_id: &str,
        method: ConnectionMethod,
        direction: ConnectionDirection,
    ) -> Self {
        let short_id = if peer_id.len() > 8 {
            peer_id[..8].to_string()
        } else {
            peer_id.to_string()
        };

        Self {
            short_id,
            full_id: peer_id.to_string(),
            location: "??".to_string(),
            method,
            direction,
            rtt: None,
            quality: ConnectionQuality::Fair,
            tx_active: false,
            rx_active: false,
            packets_sent: 0,
            packets_received: 0,
            connected_at: Instant::now(),
            addresses: Vec::new(),
            connectivity: ConnectivityMatrix::default(),
        }
    }

    /// Update RTT measurement.
    pub fn update_rtt(&mut self, rtt: Duration) {
        self.rtt = Some(rtt);
        self.quality = ConnectionQuality::from_rtt(rtt);
    }

    /// Get formatted RTT string.
    pub fn rtt_string(&self) -> String {
        match self.rtt {
            Some(rtt) => format!("{}ms", rtt.as_millis()),
            None => "---".to_string(),
        }
    }

    /// Get TX/RX indicator string.
    pub fn traffic_indicator(&self) -> String {
        let tx = if self.tx_active { ">>" } else { "  " };
        let rx = if self.rx_active { "<<" } else { "  " };
        format!("[{}] [{}]", tx, rx)
    }

    /// Get connectivity summary string.
    pub fn connectivity_summary(&self) -> String {
        self.connectivity.summary()
    }

    /// Update connectivity matrix from test results.
    pub fn update_connectivity(&mut self, matrix: ConnectivityMatrix) {
        self.connectivity = matrix;
    }
}

/// Local node information for display.
#[derive(Debug, Clone)]
pub struct LocalNodeInfo {
    /// Peer ID (full)
    pub peer_id: String,
    /// Short peer ID (first 8 chars)
    pub short_id: String,
    /// Detected NAT type
    pub nat_type: NatType,
    /// Local IPv4 address
    pub local_ipv4: Option<SocketAddr>,
    /// External IPv4 address (discovered)
    pub external_ipv4: Option<SocketAddr>,
    /// Local IPv6 address
    pub local_ipv6: Option<SocketAddr>,
    /// External IPv6 address (discovered)
    pub external_ipv6: Option<SocketAddr>,
    /// Whether registered with central registry
    pub registered: bool,
    /// Time until registration expires
    pub registration_expires_in: Option<Duration>,
    /// Last heartbeat sent
    pub last_heartbeat: Option<Instant>,
}

impl Default for LocalNodeInfo {
    fn default() -> Self {
        Self {
            peer_id: String::new(),
            short_id: String::new(),
            nat_type: NatType::Unknown,
            local_ipv4: None,
            external_ipv4: None,
            local_ipv6: None,
            external_ipv6: None,
            registered: false,
            registration_expires_in: None,
            last_heartbeat: None,
        }
    }
}

impl LocalNodeInfo {
    /// Set the peer ID.
    pub fn set_peer_id(&mut self, peer_id: &str) {
        self.peer_id = peer_id.to_string();
        self.short_id = if peer_id.len() > 8 {
            peer_id[..8].to_string()
        } else {
            peer_id.to_string()
        };
    }

    /// Get registration status string.
    pub fn registration_status(&self) -> &'static str {
        if self.registered { "✓" } else { "✗" }
    }

    /// Get last heartbeat string.
    pub fn heartbeat_status(&self) -> String {
        match self.last_heartbeat {
            Some(instant) => {
                let elapsed = instant.elapsed().as_secs();
                format!("{}s ago", elapsed)
            }
            None => "Never".to_string(),
        }
    }
}

/// Network-wide statistics for display.
#[derive(Debug, Clone, Default)]
pub struct NetworkStatistics {
    /// Total connection attempts
    pub connection_attempts: u64,
    /// Successful connections
    pub connection_successes: u64,
    /// Failed connections
    pub connection_failures: u64,
    /// Direct connections
    pub direct_connections: u64,
    /// Hole-punched connections
    pub hole_punched_connections: u64,
    /// Relayed connections
    pub relayed_connections: u64,
    /// Inbound connections (they connected to us - proves NAT traversal works!)
    pub inbound_connections: u64,
    /// Outbound connections (we connected to them)
    pub outbound_connections: u64,
    /// Test packets sent
    pub packets_sent: u64,
    /// Test packets received
    pub packets_received: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Node start time
    pub started_at: Option<Instant>,
    /// Total registered nodes in network
    pub total_registered_nodes: usize,
}

impl NetworkStatistics {
    /// Get connection success rate as percentage.
    pub fn success_rate(&self) -> f64 {
        if self.connection_attempts == 0 {
            0.0
        } else {
            (self.connection_successes as f64 / self.connection_attempts as f64) * 100.0
        }
    }

    /// Get uptime string.
    pub fn uptime(&self) -> String {
        match self.started_at {
            Some(started) => {
                let elapsed = started.elapsed();
                let hours = elapsed.as_secs() / 3600;
                let minutes = (elapsed.as_secs() % 3600) / 60;
                let seconds = elapsed.as_secs() % 60;
                format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
            }
            None => "00:00:00".to_string(),
        }
    }

    /// Get formatted bytes sent.
    pub fn bytes_sent_formatted(&self) -> String {
        format_bytes(self.bytes_sent)
    }

    /// Get formatted bytes received.
    pub fn bytes_received_formatted(&self) -> String {
        format_bytes(self.bytes_received)
    }
}

/// Format bytes into human-readable string.
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Country code to flag emoji mapping.
pub fn country_flag(country_code: &str) -> &'static str {
    match country_code.to_uppercase().as_str() {
        "US" => "🇺🇸",
        "GB" | "UK" => "🇬🇧",
        "DE" => "🇩🇪",
        "FR" => "🇫🇷",
        "JP" => "🇯🇵",
        "CN" => "🇨🇳",
        "KR" => "🇰🇷",
        "AU" => "🇦🇺",
        "CA" => "🇨🇦",
        "BR" => "🇧🇷",
        "IN" => "🇮🇳",
        "RU" => "🇷🇺",
        "IT" => "🇮🇹",
        "ES" => "🇪🇸",
        "NL" => "🇳🇱",
        "SE" => "🇸🇪",
        "NO" => "🇳🇴",
        "FI" => "🇫🇮",
        "DK" => "🇩🇰",
        "PL" => "🇵🇱",
        "CH" => "🇨🇭",
        "AT" => "🇦🇹",
        "BE" => "🇧🇪",
        "IE" => "🇮🇪",
        "SG" => "🇸🇬",
        "HK" => "🇭🇰",
        "NZ" => "🇳🇿",
        "ZA" => "🇿🇦",
        "MX" => "🇲🇽",
        "AR" => "🇦🇷",
        _ => "🌍",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_quality_from_rtt() {
        assert_eq!(
            ConnectionQuality::from_rtt(Duration::from_millis(10)),
            ConnectionQuality::Excellent
        );
        assert_eq!(
            ConnectionQuality::from_rtt(Duration::from_millis(75)),
            ConnectionQuality::Good
        );
        assert_eq!(
            ConnectionQuality::from_rtt(Duration::from_millis(150)),
            ConnectionQuality::Fair
        );
        assert_eq!(
            ConnectionQuality::from_rtt(Duration::from_millis(300)),
            ConnectionQuality::Poor
        );
        assert_eq!(
            ConnectionQuality::from_rtt(Duration::from_millis(1000)),
            ConnectionQuality::VeryPoor
        );
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1500), "1.5 KB");
        assert_eq!(format_bytes(1_500_000), "1.4 MB");
        assert_eq!(format_bytes(1_500_000_000), "1.4 GB");
    }

    #[test]
    fn test_country_flag() {
        assert_eq!(country_flag("US"), "🇺🇸");
        assert_eq!(country_flag("GB"), "🇬🇧");
        assert_eq!(country_flag("XX"), "🌍");
    }
}
