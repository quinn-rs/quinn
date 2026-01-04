//! Terminal User Interface Module
//!
//! This module provides an interactive terminal UI for the ant-quic network
//! test infrastructure. Users see real-time network status, connected peers,
//! and traffic statistics.
//!
//! # Architecture
//!
//! ```text
//! ╔══════════════════════════════════════════════════════════════════════════════╗
//! ║                          ant-quic Network Test                               ║
//! ║                         "We will be legion!!"                                ║
//! ╠══════════════════════════════════════════════════════════════════════════════╣
//! ║  YOUR NODE                                                                   ║
//! ╟──────────────────────────────────────────────────────────────────────────────╢
//! ║  Peer ID: a3b7c9d2...    NAT Type: Port Restricted    Registered: ✓         ║
//! ╠══════════════════════════════════════════════════════════════════════════════╣
//! ║  CONNECTED PEERS (3 of 142 registered)                      [Auto-connecting]║
//! ╟──────────────────────────────────────────────────────────────────────────────╢
//! ║  Peer         Location    Method        RTT      TX/RX       Status          ║
//! ╠══════════════════════════════════════════════════════════════════════════════╣
//! ║  NETWORK STATS                                                               ║
//! ╠══════════════════════════════════════════════════════════════════════════════╣
//! ║  [Q] Quit    Dashboard: https://saorsa-1.saorsalabs.com  ML-KEM-768 | ML-DSA-65║
//! ╚══════════════════════════════════════════════════════════════════════════════╝
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use ant_quic::tui::{App, run_tui};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let app = App::new();
//!     run_tui(app).await
//! }
//! ```

mod app;
mod types;
mod ui;

pub use app::{App, AppState, InputEvent};
pub use types::{
    CacheHealth, ConnectedPeer, ConnectionQuality, FrameDirection, GeographicDistribution,
    LocalNodeInfo, NatTraversalPhase, NatTypeAnalytics, NetworkStatistics, ProtocolFrame,
    TrafficDirection, TrafficType, country_flag,
};

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::io;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::warn;

/// Send a TUI event, logging if the channel is full.
///
/// This is a helper to replace bare `try_send()` calls that silently drop events.
/// Critical events like `PeerConnected` should use this function.
pub fn send_tui_event(tx: &mpsc::Sender<TuiEvent>, event: TuiEvent) {
    if let Err(e) = tx.try_send(event) {
        match e {
            mpsc::error::TrySendError::Full(ev) => {
                warn!(
                    "TUI event channel full, dropping event: {:?}",
                    event_name(&ev)
                );
            }
            mpsc::error::TrySendError::Closed(ev) => {
                warn!(
                    "TUI event channel closed, dropping event: {:?}",
                    event_name(&ev)
                );
            }
        }
    }
}

/// Get a short name for the event type (for logging).
fn event_name(event: &TuiEvent) -> &'static str {
    match event {
        TuiEvent::UpdateLocalNode(_) => "UpdateLocalNode",
        TuiEvent::UpdatePeer(_) => "UpdatePeer",
        TuiEvent::RemovePeer(_) => "RemovePeer",
        TuiEvent::UpdateRegisteredCount(_) => "UpdateRegisteredCount",
        TuiEvent::PacketSent(_) => "PacketSent",
        TuiEvent::PacketReceived(_) => "PacketReceived",
        TuiEvent::RegistrationUpdated(_) => "RegistrationUpdated",
        TuiEvent::HeartbeatSent => "HeartbeatSent",
        TuiEvent::Error(_) => "Error",
        TuiEvent::Info(_) => "Info",
        TuiEvent::ClearMessages => "ClearMessages",
        TuiEvent::Quit => "Quit",
        TuiEvent::RegistrationComplete => "RegistrationComplete",
        TuiEvent::PeerConnected(_) => "PeerConnected",
        TuiEvent::TestPacketResult { .. } => "TestPacketResult",
        TuiEvent::ConnectionFailed => "ConnectionFailed",
        TuiEvent::ConnectionAttempted => "ConnectionAttempted",
        TuiEvent::InboundConnection => "InboundConnection",
        TuiEvent::OutboundConnection => "OutboundConnection",
        TuiEvent::Ipv4Connection => "Ipv4Connection",
        TuiEvent::Ipv6Connection => "Ipv6Connection",
        TuiEvent::GossipPeerDiscovered { .. } => "GossipPeerDiscovered",
        TuiEvent::GossipRelayDiscovered { .. } => "GossipRelayDiscovered",
        TuiEvent::PeerSeen(_) => "PeerSeen",
        TuiEvent::SwimLivenessUpdate { .. } => "SwimLivenessUpdate",
        TuiEvent::ProtocolFrame(_) => "ProtocolFrame",
        TuiEvent::NatPhaseUpdate { .. } => "NatPhaseUpdate",
        TuiEvent::TrafficTypeUpdate { .. } => "TrafficTypeUpdate",
        TuiEvent::CacheHealthUpdate(_) => "CacheHealthUpdate",
        TuiEvent::NatAnalyticsUpdate(_) => "NatAnalyticsUpdate",
        TuiEvent::GeographicDistributionUpdate(_) => "GeographicDistributionUpdate",
    }
}

/// Events that can be sent to the TUI from other parts of the application.
#[derive(Debug, Clone)]
pub enum TuiEvent {
    /// Update local node information
    UpdateLocalNode(LocalNodeInfo),
    /// Add or update a connected peer
    UpdatePeer(ConnectedPeer),
    /// Remove a disconnected peer
    RemovePeer(String),
    /// Update total registered nodes count
    UpdateRegisteredCount(usize),
    /// Record packet sent
    PacketSent(String),
    /// Record packet received
    PacketReceived(String),
    /// Update registration status
    RegistrationUpdated(bool),
    /// Heartbeat sent
    HeartbeatSent,
    /// Set error message
    Error(String),
    /// Set info message
    Info(String),
    /// Clear messages
    ClearMessages,
    /// Force quit
    Quit,
    /// Registration with registry completed successfully
    RegistrationComplete,
    /// A new peer connected (from TestNode)
    PeerConnected(ConnectedPeer),
    /// Test packet exchange result
    TestPacketResult {
        /// The peer ID the test was with
        peer_id: String,
        /// Whether the test succeeded
        success: bool,
        /// Round-trip time if successful
        rtt: Option<std::time::Duration>,
    },
    /// Connection attempt failed
    ConnectionFailed,
    /// Connection attempt started
    ConnectionAttempted,
    /// Inbound connection received (they connected to us - proves NAT traversal works!)
    InboundConnection,
    /// Outbound connection established (we connected to them)
    OutboundConnection,
    /// IPv4 connection established
    Ipv4Connection,
    /// IPv6 connection established
    Ipv6Connection,
    /// Gossip: peer discovered via gossip network
    GossipPeerDiscovered {
        /// Peer ID of discovered peer
        peer_id: String,
        /// Addresses reported by the peer
        addresses: Vec<String>,
        /// Whether the peer is publicly reachable
        is_public: bool,
    },
    /// Gossip: relay discovered via gossip network
    GossipRelayDiscovered {
        /// Peer ID of the relay
        peer_id: String,
        /// Addresses where relay can be reached
        addresses: Vec<String>,
        /// Current load (active connections)
        load: u32,
    },
    /// A peer was seen/communicated with (for tracking "nodes known alive")
    PeerSeen(String),
    /// SWIM liveness update from saorsa-gossip
    SwimLivenessUpdate {
        /// Peers marked alive by SWIM
        alive: usize,
        /// Peers marked suspect by SWIM
        suspect: usize,
        /// Peers marked dead by SWIM
        dead: usize,
        /// HyParView active view size
        active: usize,
        /// HyParView passive view size
        passive: usize,
    },
    /// Protocol frame logged
    ProtocolFrame(ProtocolFrame),
    /// NAT traversal phase updated for a peer
    NatPhaseUpdate {
        /// Peer ID
        peer_id: String,
        /// New phase
        phase: NatTraversalPhase,
        /// Optional coordinator ID
        coordinator_id: Option<String>,
    },
    /// Traffic type updated for a peer
    TrafficTypeUpdate {
        /// Peer ID
        peer_id: String,
        /// Traffic type
        traffic_type: TrafficType,
        /// Direction
        direction: FrameDirection,
    },
    /// Bootstrap cache health updated
    CacheHealthUpdate(CacheHealth),
    /// NAT type analytics updated
    NatAnalyticsUpdate(NatTypeAnalytics),
    /// Geographic distribution updated
    GeographicDistributionUpdate(GeographicDistribution),
}

/// Configuration for the TUI.
#[derive(Debug, Clone)]
pub struct TuiConfig {
    /// Tick rate for UI updates
    pub tick_rate: Duration,
    /// Registry URL to display
    pub registry_url: String,
    /// Dashboard URL to display
    pub dashboard_url: String,
}

impl Default for TuiConfig {
    fn default() -> Self {
        Self {
            tick_rate: Duration::from_millis(250),
            registry_url: "https://saorsa-1.saorsalabs.com".to_string(),
            dashboard_url: "https://saorsa-1.saorsalabs.com".to_string(),
        }
    }
}

/// Run the terminal UI with the given application state.
///
/// Returns when the user quits (Q key or Esc).
pub async fn run_tui(mut app: App, mut event_rx: mpsc::Receiver<TuiEvent>) -> anyhow::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Clear terminal
    terminal.clear()?;

    let tick_rate = Duration::from_millis(250);
    let mut last_tick = std::time::Instant::now();

    // Process any pending events BEFORE first draw
    // This ensures local node info is displayed immediately
    while let Ok(event) = event_rx.try_recv() {
        handle_tui_event(&mut app, event);
    }

    loop {
        // Draw UI
        terminal.draw(|frame| ui::draw(frame, &app))?;

        // Calculate timeout for event polling
        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_millis(0));

        // Poll for terminal events with timeout
        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                // Only handle key press events (not release)
                if key.kind == KeyEventKind::Press {
                    match InputEvent::from_key(key.code) {
                        InputEvent::Quit => {
                            app.quit();
                        }
                        InputEvent::ToggleAutoConnect => {
                            app.auto_connecting = !app.auto_connecting;
                        }
                        InputEvent::Refresh => {
                            // Force redraw on next loop
                            terminal.clear()?;
                        }
                        InputEvent::Unknown => {}
                    }
                }
            }
        }

        // Check for application events (non-blocking)
        while let Ok(event) = event_rx.try_recv() {
            handle_tui_event(&mut app, event);
        }

        // Handle tick
        if last_tick.elapsed() >= tick_rate {
            // Clear traffic indicators periodically
            app.clear_traffic_indicators();
            last_tick = std::time::Instant::now();
        }

        // Check if we should quit
        if app.should_quit() {
            break;
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

/// Handle a TUI event.
fn handle_tui_event(app: &mut App, event: TuiEvent) {
    match event {
        TuiEvent::UpdateLocalNode(node_info) => {
            app.local_node = node_info;
        }
        TuiEvent::UpdatePeer(peer) => {
            app.update_peer(peer);
        }
        TuiEvent::RemovePeer(peer_id) => {
            app.remove_peer(&peer_id);
        }
        TuiEvent::UpdateRegisteredCount(count) => {
            app.total_registered_nodes = count;
        }
        TuiEvent::PacketSent(peer_id) => {
            app.packet_sent(&peer_id);
        }
        TuiEvent::PacketReceived(peer_id) => {
            app.packet_received(&peer_id);
        }
        TuiEvent::RegistrationUpdated(registered) => {
            app.set_registered(registered);
        }
        TuiEvent::HeartbeatSent => {
            app.heartbeat_sent();
        }
        TuiEvent::Error(msg) => {
            app.set_error(&msg);
        }
        TuiEvent::Info(msg) => {
            app.set_info(&msg);
        }
        TuiEvent::ClearMessages => {
            app.clear_error();
            app.clear_info();
        }
        TuiEvent::Quit => {
            app.quit();
        }
        TuiEvent::RegistrationComplete => {
            app.set_registered(true);
            app.set_info("Registered with network registry");
        }
        TuiEvent::PeerConnected(peer) => {
            app.peer_seen(&peer.full_id);
            let method_str = match peer.method {
                crate::registry::ConnectionMethod::Direct => {
                    app.stats.direct_connections += 1;
                    "DIRECT"
                }
                crate::registry::ConnectionMethod::HolePunched => {
                    app.stats.hole_punched_connections += 1;
                    "PUNCHED"
                }
                crate::registry::ConnectionMethod::Relayed => {
                    app.stats.relayed_connections += 1;
                    "RELAYED"
                }
            };
            app.add_protocol_frame(ProtocolFrame {
                peer_id: peer.full_id.clone(),
                frame_type: "CONNECTED".to_string(),
                direction: FrameDirection::Received,
                timestamp: std::time::Instant::now(),
                context: Some(method_str.to_string()),
            });
            app.update_peer(peer);
            app.stats.connection_successes += 1;
            app.stats.connection_attempts += 1;
        }
        TuiEvent::ConnectionFailed => {
            app.stats.connection_failures += 1;
            app.stats.connection_attempts += 1;
        }
        TuiEvent::ConnectionAttempted => {
            app.stats.connection_attempts += 1;
        }
        TuiEvent::TestPacketResult {
            peer_id,
            success,
            rtt,
        } => {
            if success {
                // Mark peer as seen (successful communication)
                app.peer_seen(&peer_id);
                app.packet_sent(&peer_id);
                app.packet_received(&peer_id);
                if let Some(rtt) = rtt {
                    app.update_peer_rtt(&peer_id, rtt);
                }
            }
        }
        TuiEvent::InboundConnection => {
            app.stats.inbound_connections += 1;
        }
        TuiEvent::OutboundConnection => {
            app.stats.outbound_connections += 1;
        }
        TuiEvent::Ipv4Connection => {
            app.stats.ipv4_connections += 1;
        }
        TuiEvent::Ipv6Connection => {
            app.stats.ipv6_connections += 1;
        }
        TuiEvent::GossipPeerDiscovered {
            peer_id,
            addresses,
            is_public,
        } => {
            // Log gossip peer discovery - could track in stats later
            tracing::debug!(
                "Gossip discovered peer {} ({} addresses, public={})",
                &peer_id[..16.min(peer_id.len())],
                addresses.len(),
                is_public
            );
            app.stats.gossip_peers_discovered += 1;
            // Mark peer as seen (we received gossip from them)
            app.peer_seen(&peer_id);
        }
        TuiEvent::GossipRelayDiscovered {
            peer_id,
            addresses,
            load,
        } => {
            // Log gossip relay discovery - could track in stats later
            tracing::debug!(
                "Gossip discovered relay {} ({} addresses, load={})",
                &peer_id[..16.min(peer_id.len())],
                addresses.len(),
                load
            );
            app.stats.gossip_relays_discovered += 1;
            // Also mark relay as seen
            app.peer_seen(&peer_id);
        }
        TuiEvent::PeerSeen(peer_id) => {
            app.peer_seen(&peer_id);
        }
        TuiEvent::SwimLivenessUpdate {
            alive,
            suspect,
            dead,
            active,
            passive,
        } => {
            app.stats.swim_alive = alive;
            app.stats.swim_suspect = suspect;
            app.stats.swim_dead = dead;
            app.stats.hyparview_active = active;
            app.stats.hyparview_passive = passive;
        }
        TuiEvent::ProtocolFrame(frame) => {
            app.add_protocol_frame(frame);
        }
        TuiEvent::NatPhaseUpdate {
            peer_id,
            phase,
            coordinator_id,
        } => {
            app.update_nat_phase(&peer_id, phase, coordinator_id);
        }
        TuiEvent::TrafficTypeUpdate {
            peer_id,
            traffic_type,
            direction,
        } => {
            app.update_traffic_type(&peer_id, traffic_type, direction);
        }
        TuiEvent::CacheHealthUpdate(health) => {
            app.update_cache_health(health);
        }
        TuiEvent::NatAnalyticsUpdate(analytics) => {
            app.update_nat_analytics(analytics);
        }
        TuiEvent::GeographicDistributionUpdate(distribution) => {
            app.update_geographic_distribution(distribution);
        }
    }
}

/// Create a standalone TUI for visual testing and development.
///
/// Creates the TUI with an empty event channel (no TestNode backend).
pub async fn run_standalone() -> anyhow::Result<()> {
    let app = App::new();
    let (_tx, rx) = mpsc::channel(100);
    run_tui(app, rx).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tui_config_default() {
        let config = TuiConfig::default();
        assert_eq!(config.tick_rate, Duration::from_millis(250));
        assert!(config.registry_url.contains("saorsalabs"));
    }

    #[test]
    fn test_tui_event_variants() {
        // Just verify all variants can be created
        let _ = TuiEvent::UpdateLocalNode(LocalNodeInfo::default());
        let _ = TuiEvent::UpdatePeer(ConnectedPeer::new(
            "test",
            crate::registry::ConnectionMethod::Direct,
        ));
        let _ = TuiEvent::RemovePeer("test".to_string());
        let _ = TuiEvent::UpdateRegisteredCount(10);
        let _ = TuiEvent::PacketSent("test".to_string());
        let _ = TuiEvent::PacketReceived("test".to_string());
        let _ = TuiEvent::RegistrationUpdated(true);
        let _ = TuiEvent::HeartbeatSent;
        let _ = TuiEvent::Error("error".to_string());
        let _ = TuiEvent::Info("info".to_string());
        let _ = TuiEvent::ClearMessages;
        let _ = TuiEvent::Quit;
        let _ = TuiEvent::SwimLivenessUpdate {
            alive: 5,
            suspect: 1,
            dead: 0,
            active: 4,
            passive: 20,
        };
        // Test new Phase 1 events
        let _ = TuiEvent::ProtocolFrame(ProtocolFrame {
            peer_id: "test_peer".to_string(),
            frame_type: "ADD_ADDRESS".to_string(),
            direction: FrameDirection::Sent,
            timestamp: std::time::Instant::now(),
            context: Some("test context".to_string()),
        });
        let _ = TuiEvent::NatPhaseUpdate {
            peer_id: "test_peer".to_string(),
            phase: crate::tui::types::NatTraversalPhase::Punching,
            coordinator_id: Some("coordinator".to_string()),
        };
        let _ = TuiEvent::TrafficTypeUpdate {
            peer_id: "test_peer".to_string(),
            traffic_type: crate::tui::types::TrafficType::TestData,
            direction: FrameDirection::Sent,
        };
        let _ = TuiEvent::CacheHealthUpdate(CacheHealth {
            total_peers: 100,
            valid_peers: 80,
            public_peers: 20,
            average_quality: 0.75,
            cache_age: std::time::Duration::from_secs(3600),
            last_updated: Some(std::time::Instant::now()),
            cache_hits: 800,
            cache_misses: 200,
            fresh_peers: 70,
            stale_peers: 30,
            private_peers: 80,
            public_quality: 0.85,
            private_quality: 0.65,
        });
    }

    #[test]
    fn test_handle_tui_event() {
        let mut app = App::new();

        // Test registration update
        handle_tui_event(&mut app, TuiEvent::RegistrationUpdated(true));
        assert!(app.local_node.registered);

        // Test packet events
        let peer = ConnectedPeer::new("test_peer", crate::registry::ConnectionMethod::Direct);
        handle_tui_event(&mut app, TuiEvent::UpdatePeer(peer));
        handle_tui_event(&mut app, TuiEvent::PacketSent("test_peer".to_string()));
        assert_eq!(app.stats.packets_sent, 1);

        // Test quit
        handle_tui_event(&mut app, TuiEvent::Quit);
        assert!(app.should_quit());
    }

    #[test]
    fn test_swim_liveness_update() {
        let mut app = App::new();

        // Test SWIM liveness stats update
        handle_tui_event(
            &mut app,
            TuiEvent::SwimLivenessUpdate {
                alive: 7,
                suspect: 2,
                dead: 1,
                active: 5,
                passive: 30,
            },
        );

        assert_eq!(app.stats.swim_alive, 7);
        assert_eq!(app.stats.swim_suspect, 2);
        assert_eq!(app.stats.swim_dead, 1);
        assert_eq!(app.stats.hyparview_active, 5);
        assert_eq!(app.stats.hyparview_passive, 30);
    }
}
