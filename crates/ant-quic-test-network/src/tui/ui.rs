//! TUI rendering using ratatui.
//!
//! This module handles the visual rendering of the terminal UI,
//! drawing the various sections showing network status.

use crate::tui::app::App;
use crate::tui::types::country_flag;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};

/// Main UI rendering function.
pub fn draw(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Length(6), // Your Node
            Constraint::Min(6),    // Connected Peers
            Constraint::Length(5), // Network Stats
            Constraint::Length(3), // Messages (errors/info)
            Constraint::Length(4), // Footer (2 lines)
        ])
        .split(frame.area());

    draw_header(frame, chunks[0]);
    draw_node_info(frame, app, chunks[1]);
    draw_peers(frame, app, chunks[2]);
    draw_stats(frame, app, chunks[3]);
    draw_messages(frame, app, chunks[4]);
    draw_footer(frame, app, chunks[5]);
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

/// Draw local node information.
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
        Span::styled("✓", Style::default().fg(Color::Green))
    } else {
        Span::styled("✗", Style::default().fg(Color::Red))
    };

    let nat_type = format!("{}", app.local_node.nat_type);

    let line1 = Line::from(vec![
        Span::raw("  Peer ID: "),
        Span::styled(peer_id_display, Style::default().fg(Color::White)),
        Span::raw("    NAT Type: "),
        Span::styled(nat_type, Style::default().fg(Color::Yellow)),
        Span::raw("    Registered: "),
        registration_icon,
    ]);

    // IPv4 line
    let ipv4_local = app
        .local_node
        .local_ipv4
        .map(|a| a.to_string())
        .unwrap_or_else(|| "Not bound".to_string());
    let ipv4_external = app
        .local_node
        .external_ipv4
        .map(|a| a.to_string())
        .unwrap_or_else(|| "Not discovered".to_string());

    let line2 = Line::from(vec![
        Span::raw("  IPv4: "),
        Span::styled(ipv4_local, Style::default().fg(Color::White)),
        Span::raw(" → "),
        Span::styled(
            format!("{} (External)", ipv4_external),
            Style::default().fg(Color::Cyan),
        ),
    ]);

    // IPv6 line - Note: IPv6 is typically not NATted, so local = global
    let ipv6_display = if let Some(addr) = app.local_node.local_ipv6 {
        Line::from(vec![
            Span::raw("  IPv6: "),
            Span::styled(addr.to_string(), Style::default().fg(Color::White)),
            Span::styled(" (global - no NAT)", Style::default().fg(Color::DarkGray)),
        ])
    } else {
        Line::from(vec![
            Span::raw("  IPv6: "),
            Span::styled("Not available", Style::default().fg(Color::DarkGray)),
        ])
    };

    let line3 = ipv6_display;

    let text = vec![line1, line2, line3];
    let paragraph = Paragraph::new(text).block(block);
    frame.render_widget(paragraph, area);
}

/// Draw connected peers table.
fn draw_peers(frame: &mut Frame, app: &App, area: Rect) {
    let auto_status = if app.auto_connecting {
        Span::styled("[Auto-connecting]", Style::default().fg(Color::Green))
    } else {
        Span::styled("[Paused]", Style::default().fg(Color::Yellow))
    };

    let title = Line::from(vec![
        Span::raw(format!(
            " CONNECTED PEERS ({} of {} seen) ",
            app.connected_count(),
            app.peers_seen_count()
        )),
        auto_status,
    ]);

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue));

    // Table header
    let header = Row::new(vec![
        Cell::from("Peer").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Location").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Dir").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("RTT").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Connectivity").style(Style::default().add_modifier(Modifier::BOLD)),
    ])
    .height(1)
    .style(Style::default().fg(Color::White));

    // Table rows
    let rows: Vec<Row> = app
        .peers_sorted()
        .iter()
        .map(|peer| {
            // Show connection direction: Out = we dialed them, In = they dialed us
            let (direction_str, direction_style) = match peer.direction {
                crate::registry::ConnectionDirection::Outbound => {
                    ("→ Out", Style::default().fg(Color::Cyan))
                }
                crate::registry::ConnectionDirection::Inbound => {
                    ("← In", Style::default().fg(Color::Green))
                }
            };

            // Get country flag
            let location = if peer.location.len() == 2 {
                format!("{} {}", country_flag(&peer.location), peer.location)
            } else {
                peer.location.clone()
            };

            // Get connectivity matrix summary (shows which paths tested and results)
            let connectivity = peer.connectivity_summary();

            Row::new(vec![
                Cell::from(peer.short_id.clone()),
                Cell::from(location),
                Cell::from(direction_str).style(direction_style),
                Cell::from(peer.rtt_string()),
                Cell::from(connectivity),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(12), // Peer ID
            Constraint::Length(10), // Location
            Constraint::Length(6),  // Direction (Out/In)
            Constraint::Length(8),  // RTT
            Constraint::Min(30),    // Connectivity matrix (e.g., "IPv4:✓ IPv6:✗ NAT:✓ Relay:✗")
        ],
    )
    .header(header)
    .block(block)
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    frame.render_widget(table, area);
}

/// Draw network statistics.
fn draw_stats(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(" NETWORK STATS ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta));

    // Current reachability: connected peers / (peers seen)
    // This is more meaningful than registry count since it shows nodes we've actually communicated with
    let connected_peers = app.connected_peers.len();
    let peers_seen = app.peers_seen_count().max(1);
    let reachability = if peers_seen > 0 {
        (connected_peers as f64 / peers_seen as f64) * 100.0
    } else {
        0.0
    };

    let success_color = if reachability >= 80.0 {
        Color::Green
    } else if reachability >= 50.0 {
        Color::Yellow
    } else {
        Color::Red
    };

    let line1 = Line::from(vec![
        Span::raw("  Connected: "),
        Span::styled(
            format!("{}", connected_peers),
            Style::default().fg(Color::Green),
        ),
        Span::raw(" / "),
        Span::styled(
            format!("{} seen", peers_seen),
            Style::default().fg(Color::Cyan),
        ),
        Span::raw(" ("),
        Span::styled(
            format!("{:.0}%", reachability),
            Style::default().fg(success_color),
        ),
        Span::raw(" reach)  Inbound: "),
        Span::styled(
            format!("{}", app.stats.inbound_connections),
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  Outbound: "),
        Span::styled(
            format!("{}", app.stats.outbound_connections),
            Style::default().fg(Color::Cyan),
        ),
    ]);

    let line2 = Line::from(vec![
        Span::raw("  Test Packets: "),
        Span::styled(
            format!("{} sent", app.stats.packets_sent),
            Style::default().fg(Color::Cyan),
        ),
        Span::raw(" / "),
        Span::styled(
            format!("{} received", app.stats.packets_received),
            Style::default().fg(Color::Cyan),
        ),
        Span::raw("     Bytes: "),
        Span::styled(
            app.stats.bytes_sent_formatted(),
            Style::default().fg(Color::White),
        ),
        Span::raw(" / "),
        Span::styled(
            app.stats.bytes_received_formatted(),
            Style::default().fg(Color::White),
        ),
    ]);

    let heartbeat_status = app.local_node.heartbeat_status();
    let line3 = Line::from(vec![
        Span::raw("  Uptime: "),
        Span::styled(app.stats.uptime(), Style::default().fg(Color::White)),
        Span::raw("                         Registry heartbeat: "),
        Span::styled(heartbeat_status, Style::default().fg(Color::Green)),
    ]);

    let text = vec![line1, line2, line3];
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
fn draw_footer(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let line1 = Line::from(vec![
        Span::styled("  [Q]", Style::default().fg(Color::Yellow)),
        Span::raw(" Quit "),
        Span::styled(
            "(please leave running as long as you can for this test!)",
            Style::default().fg(Color::Magenta),
        ),
        Span::raw("    "),
        Span::styled("ML-KEM-768", Style::default().fg(Color::Green)),
        Span::raw(" | "),
        Span::styled("ML-DSA-65", Style::default().fg(Color::Green)),
    ]);

    let line2 = Line::from(vec![
        Span::raw("  Dashboard: "),
        Span::styled(
            app.dashboard_url.clone(),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::UNDERLINED),
        ),
        Span::raw("                                        "),
        Span::styled(
            "We will be legion!!",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
    ]);

    let paragraph = Paragraph::new(vec![line1, line2]).block(block);
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
        let _ = draw_node_info as fn(&mut Frame, &App, Rect);
        let _ = draw_peers as fn(&mut Frame, &App, Rect);
        let _ = draw_stats as fn(&mut Frame, &App, Rect);
        let _ = draw_footer as fn(&mut Frame, &App, Rect);
    }
}
