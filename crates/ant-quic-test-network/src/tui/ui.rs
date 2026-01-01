//! TUI rendering using ratatui.
//!
//! This module handles the visual rendering of the terminal UI,
//! drawing the various sections showing network status.
//!
//! ## Traffic Light Color Scheme
//! - 🟢 Green: Direct connections (best - fully connectable)
//! - 🟠 Orange: NAT Traversed / Hole-punched (great - NAT was bypassed!)
//! - 🔴 Red: Relayed connections (works but slower - last resort)

use crate::registry::ConnectionMethod;
use crate::tui::app::App;
use crate::tui::types::country_flag;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};

/// Traffic light colors for connection methods
const COLOR_DIRECT: Color = Color::Green; // Best: Direct connection
const COLOR_HOLEPUNCHED: Color = Color::Yellow; // Great: NAT traversed
const COLOR_RELAYED: Color = Color::Red; // Works: But slower

/// Get color for connection method (traffic light approach)
fn method_color(method: &ConnectionMethod) -> Color {
    match method {
        ConnectionMethod::Direct => COLOR_DIRECT,
        ConnectionMethod::HolePunched => COLOR_HOLEPUNCHED,
        ConnectionMethod::Relayed => COLOR_RELAYED,
    }
}

/// Get emoji for connection method
fn method_emoji(method: &ConnectionMethod) -> &'static str {
    match method {
        ConnectionMethod::Direct => "🟢",
        ConnectionMethod::HolePunched => "🟠",
        ConnectionMethod::Relayed => "🔴",
    }
}

/// Main UI rendering function.
pub fn draw(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Length(4), // Connection Overview (traffic lights)
            Constraint::Length(5), // Your Node (reduced)
            Constraint::Min(6),    // Connected Peers
            Constraint::Length(5), // Network Stats (reduced)
            Constraint::Length(3), // Messages (errors/info)
            Constraint::Length(3), // Footer
        ])
        .split(frame.area());

    draw_header(frame, chunks[0]);
    draw_connection_overview(frame, app, chunks[1]);
    draw_node_info(frame, app, chunks[2]);
    draw_peers(frame, app, chunks[3]);
    draw_stats(frame, app, chunks[4]);
    draw_messages(frame, app, chunks[5]);
    draw_footer(frame, app, chunks[6]);
}

/// Draw the header with title and version.
fn draw_header(frame: &mut Frame, area: Rect) {
    let version = env!("CARGO_PKG_VERSION");
    let title = vec![Line::from(vec![
        Span::styled(
            "ant-quic Network Test",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled(
            format!("v{}", version),
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("                    "),
        Span::styled(
            "\"We will be legion!!\"",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::ITALIC),
        ),
    ])];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let paragraph = Paragraph::new(title).block(block);
    frame.render_widget(paragraph, area);
}

/// Draw connection overview with traffic light summary.
/// Shows at a glance how well we're connecting to the network.
fn draw_connection_overview(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(" CONNECTION OVERVIEW ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::White));

    // Count connections by method
    let mut direct = 0usize;
    let mut holepunched = 0usize;
    let mut relayed = 0usize;
    let mut inbound = 0usize;
    let mut outbound = 0usize;

    for peer in app.connected_peers.values() {
        match peer.method {
            ConnectionMethod::Direct => direct += 1,
            ConnectionMethod::HolePunched => holepunched += 1,
            ConnectionMethod::Relayed => relayed += 1,
        }
        match peer.direction {
            crate::registry::ConnectionDirection::Inbound => inbound += 1,
            crate::registry::ConnectionDirection::Outbound => outbound += 1,
        }
    }

    let total = app.connected_peers.len();

    // Build visual bar representation
    let bar_width = 30usize;
    let direct_bar = if total > 0 {
        (direct * bar_width) / total.max(1)
    } else {
        0
    };
    let holepunched_bar = if total > 0 {
        (holepunched * bar_width) / total.max(1)
    } else {
        0
    };
    let relayed_bar = if total > 0 {
        (relayed * bar_width) / total.max(1)
    } else {
        0
    };

    // Traffic activity indicator
    let tx_active = app.connected_peers.values().any(|p| p.tx_active);
    let rx_active = app.connected_peers.values().any(|p| p.rx_active);
    let traffic_indicator = match (tx_active, rx_active) {
        (true, true) => "◀▶",
        (true, false) => "▶▶",
        (false, true) => "◀◀",
        (false, false) => "  ",
    };

    let line1 = Line::from(vec![
        Span::raw("  "),
        Span::styled(
            "🟢 Direct: ",
            Style::default()
                .fg(COLOR_DIRECT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!("{:3}", direct), Style::default().fg(COLOR_DIRECT)),
        Span::raw(" "),
        Span::styled("█".repeat(direct_bar), Style::default().fg(COLOR_DIRECT)),
        Span::raw("  "),
        Span::styled(
            "🟠 NAT Traversed: ",
            Style::default()
                .fg(COLOR_HOLEPUNCHED)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("{:3}", holepunched),
            Style::default().fg(COLOR_HOLEPUNCHED),
        ),
        Span::raw(" "),
        Span::styled(
            "█".repeat(holepunched_bar),
            Style::default().fg(COLOR_HOLEPUNCHED),
        ),
        Span::raw("  "),
        Span::styled(
            "🔴 Relay: ",
            Style::default()
                .fg(COLOR_RELAYED)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!("{:3}", relayed), Style::default().fg(COLOR_RELAYED)),
        Span::raw(" "),
        Span::styled("█".repeat(relayed_bar), Style::default().fg(COLOR_RELAYED)),
    ]);

    // Inbound connections are VERY important - they prove NAT traversal works!
    let inbound_style = if inbound > 0 {
        Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let line2 = Line::from(vec![
        Span::raw("  "),
        Span::styled(format!("← {} INBOUND", inbound), inbound_style),
        Span::styled(
            " (they connected to YOU!)",
            Style::default().fg(Color::DarkGray),
        ),
        Span::raw("    "),
        Span::styled(
            format!("→ {} OUTBOUND", outbound),
            Style::default().fg(Color::Cyan),
        ),
        Span::raw("    "),
        Span::styled(
            format!("TOTAL: {}", total),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("    Traffic: "),
        Span::styled(
            traffic_indicator,
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
    ]);

    let paragraph = Paragraph::new(vec![line1, line2]).block(block);
    frame.render_widget(paragraph, area);
}

/// Draw local node information (compact).
fn draw_node_info(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(" YOUR NODE ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green));

    // Build node info lines
    let peer_id_display = if app.local_node.peer_id.is_empty() {
        "Generating...".to_string()
    } else {
        format!("{}...", app.local_node.short_id)
    };

    let registration_icon = if app.local_node.registered {
        Span::styled("✓ Registered", Style::default().fg(Color::Green))
    } else {
        Span::styled("✗ Not Registered", Style::default().fg(Color::Red))
    };

    let nat_type = format!("{}", app.local_node.nat_type);

    // IPv4 info
    let ipv4_external = app
        .local_node
        .external_ipv4
        .map(|a| a.to_string())
        .unwrap_or_else(|| "discovering...".to_string());

    // IPv6 info
    let ipv6_info = if app.local_node.local_ipv6.is_some() {
        Span::styled("IPv6: ✓", Style::default().fg(Color::Green))
    } else {
        Span::styled("IPv6: ✗", Style::default().fg(Color::DarkGray))
    };

    let line1 = Line::from(vec![
        Span::raw("  ID: "),
        Span::styled(peer_id_display, Style::default().fg(Color::White)),
        Span::raw("  NAT: "),
        Span::styled(nat_type, Style::default().fg(Color::Yellow)),
        Span::raw("  "),
        registration_icon,
    ]);

    let line2 = Line::from(vec![
        Span::raw("  External: "),
        Span::styled(ipv4_external, Style::default().fg(Color::Cyan)),
        Span::raw("    "),
        ipv6_info,
        Span::raw("    Heartbeat: "),
        Span::styled(
            app.local_node.heartbeat_status(),
            Style::default().fg(Color::Green),
        ),
    ]);

    let text = vec![line1, line2];
    let paragraph = Paragraph::new(text).block(block);
    frame.render_widget(paragraph, area);
}

/// Draw connected peers table with traffic light colors.
fn draw_peers(frame: &mut Frame, app: &App, area: Rect) {
    let auto_status = if app.auto_connecting {
        Span::styled("[Auto-connecting]", Style::default().fg(Color::Green))
    } else {
        Span::styled("[Paused]", Style::default().fg(Color::Yellow))
    };

    let title = Line::from(vec![
        Span::raw(format!(" LIVE CONNECTIONS ({}) ", app.connected_count(),)),
        auto_status,
        Span::raw("  "),
        Span::styled("🟢=Direct ", Style::default().fg(COLOR_DIRECT)),
        Span::styled("🟠=NAT ", Style::default().fg(COLOR_HOLEPUNCHED)),
        Span::styled("🔴=Relay", Style::default().fg(COLOR_RELAYED)),
    ]);

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue));

    // Table header with traffic column
    let header = Row::new(vec![
        Cell::from("").style(Style::default().add_modifier(Modifier::BOLD)), // Traffic light
        Cell::from("Peer").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Location").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Dir").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Traffic").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("RTT").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Quality").style(Style::default().add_modifier(Modifier::BOLD)),
    ])
    .height(1)
    .style(Style::default().fg(Color::White));

    // Table rows with traffic light colors
    let rows: Vec<Row> = app
        .peers_sorted()
        .iter()
        .map(|peer| {
            // Traffic light emoji based on connection method
            let method_indicator = method_emoji(&peer.method);
            let row_color = method_color(&peer.method);

            // Direction with emphasis on inbound (proves NAT traversal!)
            let (direction_str, direction_style) = match peer.direction {
                crate::registry::ConnectionDirection::Outbound => {
                    ("→Out", Style::default().fg(Color::Cyan))
                }
                crate::registry::ConnectionDirection::Inbound => (
                    "←IN!",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
            };

            // Get country flag
            let location = if peer.location.len() == 2 {
                format!("{} {}", country_flag(&peer.location), peer.location)
            } else {
                peer.location.clone()
            };

            // Visual traffic indicator with animation-like effect
            let traffic = match (peer.tx_active, peer.rx_active) {
                (true, true) => "◀━▶",
                (true, false) => "  ▶",
                (false, true) => "◀  ",
                (false, false) => "   ",
            };
            let traffic_style = if peer.tx_active || peer.rx_active {
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::DarkGray)
            };

            // Quality bar based on RTT
            let quality = peer.quality.as_bar();

            Row::new(vec![
                Cell::from(method_indicator).style(Style::default().fg(row_color)),
                Cell::from(peer.short_id.clone()).style(Style::default().fg(row_color)),
                Cell::from(location),
                Cell::from(direction_str).style(direction_style),
                Cell::from(traffic).style(traffic_style),
                Cell::from(peer.rtt_string()),
                Cell::from(quality).style(Style::default().fg(row_color)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(2),  // Traffic light emoji
            Constraint::Length(10), // Peer ID
            Constraint::Length(8),  // Location
            Constraint::Length(5),  // Direction (Out/In)
            Constraint::Length(4),  // Traffic indicator
            Constraint::Length(7),  // RTT
            Constraint::Min(6),     // Quality bar (●●●●●)
        ],
    )
    .header(header)
    .block(block)
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    frame.render_widget(table, area);
}

/// Draw network statistics (compact version).
fn draw_stats(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(" GOSSIP NETWORK ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta));

    // SWIM liveness from saorsa-gossip (authoritative peer health data)
    let alive = app.stats.swim_alive;
    let suspect = app.stats.swim_suspect;
    let dead = app.stats.swim_dead;
    let total_known = alive + suspect + dead;

    // Line 1: SWIM status and HyParView
    let line1 = Line::from(vec![
        Span::raw("  SWIM: "),
        Span::styled(format!("{}", alive), Style::default().fg(Color::Green)),
        Span::styled(" alive ", Style::default().fg(Color::DarkGray)),
        Span::styled(format!("{}", suspect), Style::default().fg(Color::Yellow)),
        Span::styled(" suspect ", Style::default().fg(Color::DarkGray)),
        Span::styled(format!("{}", dead), Style::default().fg(Color::Red)),
        Span::styled(" dead", Style::default().fg(Color::DarkGray)),
        Span::raw("    HyParView: "),
        Span::styled(
            format!("{}", app.stats.hyparview_active),
            Style::default().fg(Color::Cyan),
        ),
        Span::styled("/", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{}", app.stats.hyparview_passive),
            Style::default().fg(Color::Blue),
        ),
        Span::raw("    Known: "),
        Span::styled(
            format!("{}", total_known),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
    ]);

    // Line 2: Packets and uptime
    let line2 = Line::from(vec![
        Span::raw("  Packets: "),
        Span::styled(
            format!("{}↑", app.stats.packets_sent),
            Style::default().fg(Color::Cyan),
        ),
        Span::raw(" "),
        Span::styled(
            format!("{}↓", app.stats.packets_received),
            Style::default().fg(Color::Green),
        ),
        Span::raw("  Bytes: "),
        Span::styled(
            app.stats.bytes_sent_formatted(),
            Style::default().fg(Color::White),
        ),
        Span::raw("/"),
        Span::styled(
            app.stats.bytes_received_formatted(),
            Style::default().fg(Color::White),
        ),
        Span::raw("    Uptime: "),
        Span::styled(
            app.stats.uptime(),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
    ]);

    let text = vec![line1, line2];
    let paragraph = Paragraph::new(text).block(block);
    frame.render_widget(paragraph, area);
}

/// Draw messages panel (errors and info).
fn draw_messages(frame: &mut Frame, app: &App, area: Rect) {
    let (border_color, message) = if let Some(ref err) = app.error_message {
        (Color::Red, format!("❌ ERROR: {}", err))
    } else if let Some(ref info) = app.info_message {
        (Color::Green, format!("ℹ️  {}", info))
    } else {
        (Color::DarkGray, "No messages".to_string())
    };

    let block = Block::default()
        .title(" MESSAGES ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));

    let paragraph = Paragraph::new(Line::from(vec![
        Span::raw("  "),
        Span::styled(message, Style::default().fg(border_color)),
    ]))
    .block(block);

    frame.render_widget(paragraph, area);
}

/// Draw footer with controls and info.
fn draw_footer(frame: &mut Frame, _app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let line = Line::from(vec![
        Span::styled("  [Q]", Style::default().fg(Color::Yellow)),
        Span::raw(" Quit    "),
        Span::styled(
            "🔐 ML-KEM-768 + ML-DSA-65",
            Style::default().fg(Color::Green),
        ),
        Span::raw("    "),
        Span::styled(
            "\"We will be legion!!\"",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
    ]);

    let paragraph = Paragraph::new(line).block(block);
    frame.render_widget(paragraph, area);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_draw_functions_exist() {
        // Verify all drawing functions are defined
        let _ = draw as fn(&mut Frame, &App);
        let _ = draw_header as fn(&mut Frame, Rect);
        let _ = draw_connection_overview as fn(&mut Frame, &App, Rect);
        let _ = draw_node_info as fn(&mut Frame, &App, Rect);
        let _ = draw_peers as fn(&mut Frame, &App, Rect);
        let _ = draw_stats as fn(&mut Frame, &App, Rect);
        let _ = draw_footer as fn(&mut Frame, &App, Rect);
    }

    #[test]
    fn test_method_color() {
        assert_eq!(method_color(&ConnectionMethod::Direct), COLOR_DIRECT);
        assert_eq!(
            method_color(&ConnectionMethod::HolePunched),
            COLOR_HOLEPUNCHED
        );
        assert_eq!(method_color(&ConnectionMethod::Relayed), COLOR_RELAYED);
    }

    #[test]
    fn test_method_emoji() {
        assert_eq!(method_emoji(&ConnectionMethod::Direct), "🟢");
        assert_eq!(method_emoji(&ConnectionMethod::HolePunched), "🟠");
        assert_eq!(method_emoji(&ConnectionMethod::Relayed), "🔴");
    }
}
