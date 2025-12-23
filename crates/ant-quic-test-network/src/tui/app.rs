//! TUI application state and event handling.
//!
//! This module manages the terminal UI state, handles user input,
//! and coordinates updates from the network layer.

use crate::tui::types::{ConnectedPeer, LocalNodeInfo, NetworkStatistics};
use std::collections::HashMap;
use std::time::Instant;

/// Application running state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppState {
    /// Application is running normally
    Running,
    /// Application is shutting down
    Quitting,
}

/// Main TUI application state.
#[derive(Debug)]
pub struct App {
    /// Current application state
    pub state: AppState,
    /// Local node information
    pub local_node: LocalNodeInfo,
    /// Connected peers (peer_id -> peer info)
    pub connected_peers: HashMap<String, ConnectedPeer>,
    /// Network statistics
    pub stats: NetworkStatistics,
    /// Auto-connect enabled
    pub auto_connecting: bool,
    /// Total registered nodes in network
    pub total_registered_nodes: usize,
    /// Registry URL
    pub registry_url: String,
    /// Dashboard URL (for display)
    pub dashboard_url: String,
    /// Last UI refresh time
    pub last_refresh: Instant,
    /// Error message to display (if any)
    pub error_message: Option<String>,
    /// Info message to display (if any)
    pub info_message: Option<String>,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    /// Create a new application instance.
    pub fn new() -> Self {
        Self {
            state: AppState::Running,
            local_node: LocalNodeInfo::default(),
            connected_peers: HashMap::new(),
            stats: NetworkStatistics {
                started_at: Some(Instant::now()),
                ..Default::default()
            },
            auto_connecting: true,
            total_registered_nodes: 0,
            registry_url: "https://quic.saorsalabs.com".to_string(),
            dashboard_url: "https://quic.saorsalabs.com".to_string(),
            last_refresh: Instant::now(),
            error_message: None,
            info_message: None,
        }
    }

    /// Check if the application should quit.
    pub fn should_quit(&self) -> bool {
        self.state == AppState::Quitting
    }

    /// Request application quit.
    pub fn quit(&mut self) {
        self.state = AppState::Quitting;
    }

    /// Add or update a connected peer.
    pub fn update_peer(&mut self, peer: ConnectedPeer) {
        self.connected_peers.insert(peer.full_id.clone(), peer);
    }

    /// Remove a disconnected peer.
    pub fn remove_peer(&mut self, peer_id: &str) {
        self.connected_peers.remove(peer_id);
    }

    /// Get the number of connected peers.
    pub fn connected_count(&self) -> usize {
        self.connected_peers.len()
    }

    /// Mark that we sent a packet to a peer.
    pub fn packet_sent(&mut self, peer_id: &str) {
        self.stats.packets_sent += 1;
        self.stats.bytes_sent += 5120; // 5KB test packet

        if let Some(peer) = self.connected_peers.get_mut(peer_id) {
            peer.packets_sent += 1;
            peer.tx_active = true;
        }
    }

    /// Mark that we received a packet from a peer.
    pub fn packet_received(&mut self, peer_id: &str) {
        self.stats.packets_received += 1;
        self.stats.bytes_received += 5120; // 5KB test packet

        if let Some(peer) = self.connected_peers.get_mut(peer_id) {
            peer.packets_received += 1;
            peer.rx_active = true;
        }
    }

    /// Clear traffic indicators (call periodically).
    pub fn clear_traffic_indicators(&mut self) {
        for peer in self.connected_peers.values_mut() {
            peer.tx_active = false;
            peer.rx_active = false;
        }
    }

    /// Record a connection attempt.
    pub fn connection_attempted(&mut self) {
        self.stats.connection_attempts += 1;
    }

    /// Record a successful connection.
    pub fn connection_succeeded(&mut self, method: crate::registry::ConnectionMethod) {
        self.stats.connection_successes += 1;
        match method {
            crate::registry::ConnectionMethod::Direct => {
                self.stats.direct_connections += 1;
            }
            crate::registry::ConnectionMethod::HolePunched => {
                self.stats.hole_punched_connections += 1;
            }
            crate::registry::ConnectionMethod::Relayed => {
                self.stats.relayed_connections += 1;
            }
        }
    }

    /// Record a failed connection.
    pub fn connection_failed(&mut self) {
        self.stats.connection_failures += 1;
    }

    /// Set an error message.
    pub fn set_error(&mut self, message: &str) {
        self.error_message = Some(message.to_string());
    }

    /// Clear the error message.
    pub fn clear_error(&mut self) {
        self.error_message = None;
    }

    /// Set an info message.
    pub fn set_info(&mut self, message: &str) {
        self.info_message = Some(message.to_string());
    }

    /// Clear the info message.
    pub fn clear_info(&mut self) {
        self.info_message = None;
    }

    /// Update node registration status.
    pub fn set_registered(&mut self, registered: bool) {
        self.local_node.registered = registered;
        if registered {
            self.local_node.last_heartbeat = Some(Instant::now());
        }
    }

    /// Update heartbeat timestamp.
    pub fn heartbeat_sent(&mut self) {
        self.local_node.last_heartbeat = Some(Instant::now());
    }

    /// Update RTT measurement for a peer.
    pub fn update_peer_rtt(&mut self, peer_id: &str, rtt: std::time::Duration) {
        if let Some(peer) = self.connected_peers.get_mut(peer_id) {
            peer.update_rtt(rtt);
        }
    }

    /// Get sorted list of connected peers for display.
    pub fn peers_sorted(&self) -> Vec<&ConnectedPeer> {
        let mut peers: Vec<_> = self.connected_peers.values().collect();
        // Sort by RTT (fastest first), then by connection time
        peers.sort_by(|a, b| match (a.rtt, b.rtt) {
            (Some(a_rtt), Some(b_rtt)) => a_rtt.cmp(&b_rtt),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.connected_at.cmp(&b.connected_at),
        });
        peers
    }
}

/// Input event from the terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputEvent {
    /// Quit the application
    Quit,
    /// Toggle auto-connect
    ToggleAutoConnect,
    /// Force refresh display
    Refresh,
    /// Unknown/ignored key
    Unknown,
}

impl InputEvent {
    /// Parse a key event into an input event.
    pub fn from_key(key: crossterm::event::KeyCode) -> Self {
        use crossterm::event::KeyCode;

        match key {
            KeyCode::Char('q') | KeyCode::Char('Q') => Self::Quit,
            KeyCode::Char('a') | KeyCode::Char('A') => Self::ToggleAutoConnect,
            KeyCode::Char('r') | KeyCode::Char('R') => Self::Refresh,
            KeyCode::Esc => Self::Quit,
            _ => Self::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::ConnectionMethod;

    #[test]
    fn test_app_creation() {
        let app = App::new();
        assert_eq!(app.state, AppState::Running);
        assert!(app.connected_peers.is_empty());
        assert!(app.auto_connecting);
    }

    #[test]
    fn test_connection_stats() {
        let mut app = App::new();

        app.connection_attempted();
        app.connection_succeeded(ConnectionMethod::Direct);
        app.connection_attempted();
        app.connection_failed();

        assert_eq!(app.stats.connection_attempts, 2);
        assert_eq!(app.stats.connection_successes, 1);
        assert_eq!(app.stats.connection_failures, 1);
        assert_eq!(app.stats.direct_connections, 1);
        assert!((app.stats.success_rate() - 50.0).abs() < 0.001);
    }

    #[test]
    fn test_peer_management() {
        let mut app = App::new();

        let peer = ConnectedPeer::new("test_peer_id_12345", ConnectionMethod::HolePunched);
        app.update_peer(peer);

        assert_eq!(app.connected_count(), 1);
        assert!(app.connected_peers.contains_key("test_peer_id_12345"));

        app.remove_peer("test_peer_id_12345");
        assert_eq!(app.connected_count(), 0);
    }

    #[test]
    fn test_input_events() {
        use crossterm::event::KeyCode;

        assert_eq!(InputEvent::from_key(KeyCode::Char('q')), InputEvent::Quit);
        assert_eq!(InputEvent::from_key(KeyCode::Char('Q')), InputEvent::Quit);
        assert_eq!(InputEvent::from_key(KeyCode::Esc), InputEvent::Quit);
        assert_eq!(
            InputEvent::from_key(KeyCode::Char('a')),
            InputEvent::ToggleAutoConnect
        );
        assert_eq!(
            InputEvent::from_key(KeyCode::Char('x')),
            InputEvent::Unknown
        );
    }
}
