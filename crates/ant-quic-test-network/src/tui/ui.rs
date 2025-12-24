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
            Constraint::Min(8),    // Connected Peers
            Constraint::Length(5), // Network Stats
            Constraint::Length(4), // Footer (2 lines)
        ])
        .split(frame.area());

    draw_header(frame, chunks[0]);
    draw_node_info(frame, app, chunks[1]);
    draw_peers(frame, app, chunks[2]);
    draw_stats(frame, app, chunks[3]);
    draw_footer(frame, app, chunks[4]);
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

    // IPv6 line
    let ipv6_local = app
        .local_node
        .local_ipv6
        .map(|a| a.to_string())
        .unwrap_or_else(|| "Not available".to_string());
    let ipv6_external = app
        .local_node
        .external_ipv6
        .map(|a| a.to_string())
        .unwrap_or_else(|| "Not discovered".to_string());

    // Only show IPv6 line if we have local IPv6 or it's just informational
    let ipv6_color = if app.local_node.local_ipv6.is_some() {
        Color::White
    } else {
        Color::DarkGray
    };

    let line3 = Line::from(vec![
        Span::raw("  IPv6: "),
        Span::styled(ipv6_local, Style::default().fg(ipv6_color)),
        Span::raw(" → "),
        Span::styled(ipv6_external, Style::default().fg(Color::Cyan)),
    ]);

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
            " CONNECTED PEERS ({} of {} registered) ",
            app.connected_count(),
            app.total_registered_nodes
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
        Cell::from("Method").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("RTT").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("TX/RX").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Status").style(Style::default().add_modifier(Modifier::BOLD)),
    ])
    .height(1)
    .style(Style::default().fg(Color::White));

    // Table rows
    let rows: Vec<Row> = app
        .peers_sorted()
        .iter()
        .map(|peer| {
            let method_style = match peer.method {
                crate::registry::ConnectionMethod::Direct => Style::default().fg(Color::Green),
                crate::registry::ConnectionMethod::HolePunched => {
                    Style::default().fg(Color::Yellow)
                }
                crate::registry::ConnectionMethod::Relayed => Style::default().fg(Color::Red),
            };

            let method_str = format!("{}", peer.method);

            // Get country flag
            let location = if peer.location.len() == 2 {
                format!("{} {}", country_flag(&peer.location), peer.location)
            } else {
                peer.location.clone()
            };

            // Status indicator with clear separation
            let status_indicator = match peer.quality {
                crate::tui::types::ConnectionQuality::Excellent => "●",
                crate::tui::types::ConnectionQuality::Good => "●",
                crate::tui::types::ConnectionQuality::Fair => "●",
                crate::tui::types::ConnectionQuality::Poor => "●",
                crate::tui::types::ConnectionQuality::VeryPoor => "○",
            };
            let status_color = match peer.quality {
                crate::tui::types::ConnectionQuality::Excellent => Color::Green,
                crate::tui::types::ConnectionQuality::Good => Color::LightGreen,
                crate::tui::types::ConnectionQuality::Fair => Color::Yellow,
                crate::tui::types::ConnectionQuality::Poor => Color::LightRed,
                crate::tui::types::ConnectionQuality::VeryPoor => Color::Red,
            };

            Row::new(vec![
                Cell::from(peer.short_id.clone()),
                Cell::from(location),
                Cell::from(method_str).style(method_style),
                Cell::from(peer.rtt_string()),
                Cell::from(peer.traffic_indicator()),
                Cell::from(Span::styled(
                    format!("{} OK", status_indicator),
                    Style::default().fg(status_color),
                )),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(12), // Peer ID
            Constraint::Length(10), // Location
            Constraint::Length(12), // Method
            Constraint::Length(8),  // RTT
            Constraint::Length(12), // TX/RX
            Constraint::Length(8),  // Status (simplified)
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

    let success_rate = app.stats.success_rate();
    let success_color = if success_rate >= 90.0 {
        Color::Green
    } else if success_rate >= 70.0 {
        Color::Yellow
    } else {
        Color::Red
    };

    let line1 = Line::from(vec![
        Span::raw("  Connections: "),
        Span::styled(
            format!("{} success", app.stats.connection_successes),
            Style::default().fg(Color::Green),
        ),
        Span::raw(" / "),
        Span::styled(
            format!("{} failed", app.stats.connection_failures),
            Style::default().fg(Color::Red),
        ),
        Span::raw(" ("),
        Span::styled(
            format!("{:.1}%", success_rate),
            Style::default().fg(success_color),
        ),
        Span::raw(")    Direct: "),
        Span::styled(
            format!("{}", app.stats.direct_connections),
            Style::default().fg(Color::Green),
        ),
        Span::raw("  Punched: "),
        Span::styled(
            format!("{}", app.stats.hole_punched_connections),
            Style::default().fg(Color::Yellow),
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
        Span::raw("                              Last heartbeat: "),
        Span::styled(heartbeat_status, Style::default().fg(Color::Green)),
    ]);

    let text = vec![line1, line2, line3];
    let paragraph = Paragraph::new(text).block(block);
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
