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
//! ║  [Q] Quit    Dashboard: https://quic.saorsalabs.com    ML-KEM-768 | ML-DSA-65║
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
    ConnectedPeer, ConnectionQuality, LocalNodeInfo, NetworkStatistics, TrafficDirection,
    country_flag,
};

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
use std::time::Duration;
use tokio::sync::mpsc;

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
            registry_url: "https://quic.saorsalabs.com".to_string(),
            dashboard_url: "https://quic.saorsalabs.com".to_string(),
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
            app.update_peer(peer);
            app.stats.connection_successes += 1;
        }
        TuiEvent::TestPacketResult {
            peer_id,
            success,
            rtt,
        } => {
            if success {
                app.packet_sent(&peer_id);
                app.packet_received(&peer_id);
                if let Some(rtt) = rtt {
                    app.update_peer_rtt(&peer_id, rtt);
                }
            }
        }
    }
}

/// Create a simple standalone TUI for testing.
///
/// This creates the TUI with a dummy event channel.
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
}
