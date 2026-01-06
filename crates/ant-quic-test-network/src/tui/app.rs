//! TUI application state and event handling.
//!
//! This module manages the terminal UI state, handles user input,
//! and coordinates updates from the network layer.

use crate::tui::types::{
    CacheHealth, ConnectedPeer, ConnectionHistoryEntry, ConnectionStatus, ConnectivityTestResults,
    FrameDirection, GeographicDistribution, LocalNodeInfo, NatTraversalPhase, NatTypeAnalytics,
    NetworkStatistics, ProtocolFrame, TestConnectivityMethod, TrafficType,
};
use ratatui::widgets::TableState;
use std::collections::{HashMap, HashSet};
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
    /// Connection history (peer_id -> history entry) - persists after disconnection
    pub connection_history: HashMap<String, ConnectionHistoryEntry>,
    /// Network statistics
    pub stats: NetworkStatistics,
    /// Auto-connect enabled
    pub auto_connecting: bool,
    /// Total registered nodes in network (from registry)
    pub total_registered_nodes: usize,
    /// Peers we've actually communicated with (seen alive)
    pub peers_seen: HashSet<String>,
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
    /// Protocol frame log (last 20 frames)
    pub protocol_frames: Vec<ProtocolFrame>,
    /// Bootstrap cache health information
    pub cache_health: Option<CacheHealth>,
    /// NAT type analytics for connection success rates
    pub nat_analytics: Option<NatTypeAnalytics>,
    /// Geographic distribution of peers for network diversity
    pub geographic_distribution: Option<GeographicDistribution>,
    /// Connectivity test results (inbound/outbound test matrix)
    pub connectivity_test: ConnectivityTestResults,
    /// Scroll state for the connections table
    pub connections_table_state: TableState,
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
            connection_history: HashMap::new(),
            stats: NetworkStatistics {
                started_at: Some(Instant::now()),
                ..Default::default()
            },
            auto_connecting: true,
            total_registered_nodes: 0,
            peers_seen: HashSet::new(),
            registry_url: "https://saorsa-1.saorsalabs.com".to_string(),
            dashboard_url: "https://saorsa-1.saorsalabs.com".to_string(),
            last_refresh: Instant::now(),
            error_message: None,
            info_message: None,
            protocol_frames: Vec::new(),
            cache_health: None,
            nat_analytics: None,
            geographic_distribution: None,
            connectivity_test: ConnectivityTestResults::new(),
            connections_table_state: TableState::default(),
        }
    }

    /// Mark a peer as seen (we've communicated with them).
    pub fn peer_seen(&mut self, peer_id: &str) {
        self.peers_seen.insert(peer_id.to_string());
    }

    /// Get count of peers we've actually seen.
    pub fn peers_seen_count(&self) -> usize {
        self.peers_seen.len()
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
        let peer_id = peer.full_id.clone();

        if let Some(history) = self.connection_history.get_mut(&peer_id) {
            history.update_from_peer(&peer);
        } else {
            self.connection_history.insert(
                peer_id.clone(),
                ConnectionHistoryEntry::from_connected_peer(&peer),
            );
        }

        self.connected_peers.insert(peer_id, peer);
    }

    /// Remove a disconnected peer.
    pub fn remove_peer(&mut self, peer_id: &str) {
        if let Some(history) = self.connection_history.get_mut(peer_id) {
            history.mark_disconnected();
        }
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
        peers.sort_by(|a, b| match (a.rtt, b.rtt) {
            (Some(a_rtt), Some(b_rtt)) => a_rtt.cmp(&b_rtt),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.connected_at.cmp(&b.connected_at),
        });
        peers
    }

    /// Get sorted connection history for display (connected first, then by last_seen).
    pub fn history_sorted(&self) -> Vec<&ConnectionHistoryEntry> {
        let mut history: Vec<_> = self.connection_history.values().collect();
        history.sort_by(|a, b| match (&a.status, &b.status) {
            (ConnectionStatus::Connected, ConnectionStatus::Connected) => {
                b.last_seen.cmp(&a.last_seen)
            }
            (ConnectionStatus::Connected, _) => std::cmp::Ordering::Less,
            (_, ConnectionStatus::Connected) => std::cmp::Ordering::Greater,
            _ => b.last_seen.cmp(&a.last_seen),
        });
        history
    }

    /// Get count of currently connected peers in history.
    pub fn history_connected_count(&self) -> usize {
        self.connection_history
            .values()
            .filter(|h| h.status == ConnectionStatus::Connected)
            .count()
    }

    /// Get count of disconnected peers in history.
    pub fn history_disconnected_count(&self) -> usize {
        self.connection_history
            .values()
            .filter(|h| h.status == ConnectionStatus::Disconnected)
            .count()
    }

    pub fn add_protocol_frame(&mut self, frame: ProtocolFrame) {
        self.protocol_frames.push(frame);
        if self.protocol_frames.len() > 200 {
            self.protocol_frames
                .drain(0..self.protocol_frames.len() - 200);
        }
    }

    /// Update NAT traversal phase for a peer
    pub fn update_nat_phase(
        &mut self,
        peer_id: &str,
        phase: NatTraversalPhase,
        coordinator_id: Option<String>,
    ) {
        if let Some(peer) = self.connected_peers.get_mut(peer_id) {
            peer.nat_phase = phase;
            peer.coordinator_id = coordinator_id;
        }
    }

    /// Update traffic type for a peer
    pub fn update_traffic_type(
        &mut self,
        peer_id: &str,
        traffic_type: TrafficType,
        direction: FrameDirection,
    ) {
        if let Some(peer) = self.connected_peers.get_mut(peer_id) {
            match traffic_type {
                TrafficType::Protocol => {
                    peer.protocol_tx = direction == FrameDirection::Sent;
                    peer.protocol_rx = direction == FrameDirection::Received;
                }
                TrafficType::TestData => {
                    peer.data_tx = direction == FrameDirection::Sent;
                    peer.data_rx = direction == FrameDirection::Received;
                }
                TrafficType::Relay => {
                    // Relay traffic counts as both TX and RX for visibility
                    if direction == FrameDirection::Sent {
                        peer.protocol_tx = true;
                    } else {
                        peer.protocol_rx = true;
                    }
                }
            }
        }
    }

    /// Update cache health information
    pub fn update_cache_health(&mut self, health: CacheHealth) {
        self.cache_health = Some(health);
    }

    /// Update NAT type analytics
    pub fn update_nat_analytics(&mut self, analytics: NatTypeAnalytics) {
        self.nat_analytics = Some(analytics);
    }

    pub fn update_peer_nat_test_state(
        &mut self,
        peer_id: &str,
        state: crate::tui::types::PeerNatTestState,
    ) {
        if let Some(peer) = self.connected_peers.get_mut(peer_id) {
            peer.nat_test_state = state;
        }
    }

    pub fn update_geographic_distribution(&mut self, distribution: GeographicDistribution) {
        self.geographic_distribution = Some(distribution);
    }

    pub fn start_connectivity_test(&mut self) {
        self.connectivity_test.start();
    }

    pub fn connectivity_test_inbound_phase(&mut self) {
        self.connectivity_test.start_inbound_phase();
    }

    pub fn record_inbound_connection(
        &mut self,
        peer_id: &str,
        method: TestConnectivityMethod,
        success: bool,
        rtt_ms: Option<u32>,
    ) {
        self.connectivity_test
            .record_inbound(peer_id, method, success, rtt_ms, None);
    }

    pub fn record_outbound_connection(
        &mut self,
        peer_id: &str,
        method: TestConnectivityMethod,
        success: bool,
        rtt_ms: Option<u32>,
    ) {
        self.connectivity_test
            .record_outbound(peer_id, method, success, rtt_ms, None);
    }

    pub fn connectivity_countdown(&self) -> u32 {
        self.connectivity_test.countdown_seconds()
    }

    pub fn connectivity_countdown_complete(&self) -> bool {
        self.connectivity_test.countdown_complete()
    }

    pub fn scroll_connections_up(&mut self) {
        let i = match self.connections_table_state.selected() {
            Some(i) => i.saturating_sub(1),
            None => 0,
        };
        self.connections_table_state.select(Some(i));
    }

    pub fn scroll_connections_down(&mut self) {
        let len = self.connected_peers.len();
        if len == 0 {
            return;
        }
        let i = match self.connections_table_state.selected() {
            Some(i) => (i + 1).min(len - 1),
            None => 0,
        };
        self.connections_table_state.select(Some(i));
    }

    pub fn scroll_connections_page_up(&mut self) {
        let i = match self.connections_table_state.selected() {
            Some(i) => i.saturating_sub(10),
            None => 0,
        };
        self.connections_table_state.select(Some(i));
    }

    pub fn scroll_connections_page_down(&mut self) {
        let len = self.connected_peers.len();
        if len == 0 {
            return;
        }
        let i = match self.connections_table_state.selected() {
            Some(i) => (i + 10).min(len - 1),
            None => 0,
        };
        self.connections_table_state.select(Some(i));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputEvent {
    Quit,
    ToggleAutoConnect,
    Refresh,
    ResetConnectivityTest,
    ScrollUp,
    ScrollDown,
    PageUp,
    PageDown,
    Unknown,
}

impl InputEvent {
    pub fn from_key(key: crossterm::event::KeyCode) -> Self {
        use crossterm::event::KeyCode;

        match key {
            KeyCode::Char('q') | KeyCode::Char('Q') => Self::Quit,
            KeyCode::Char('a') | KeyCode::Char('A') => Self::ToggleAutoConnect,
            KeyCode::Char('r') | KeyCode::Char('R') => Self::Refresh,
            KeyCode::Char('t') | KeyCode::Char('T') => Self::ResetConnectivityTest,
            KeyCode::Up | KeyCode::Char('k') => Self::ScrollUp,
            KeyCode::Down | KeyCode::Char('j') => Self::ScrollDown,
            KeyCode::PageUp => Self::PageUp,
            KeyCode::PageDown => Self::PageDown,
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
