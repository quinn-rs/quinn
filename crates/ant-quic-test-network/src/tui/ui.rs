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
use crate::tui::types::{ConnectivityTestPhase, country_flag};
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

#[allow(dead_code)]
fn method_emoji(method: &ConnectionMethod) -> &'static str {
    match method {
        ConnectionMethod::Direct => "🟢",
        ConnectionMethod::HolePunched => "🟠",
        ConnectionMethod::Relayed => "🔴",
    }
}

#[allow(dead_code)]
fn format_connectivity_matrix(matrix: &crate::registry::ConnectivityMatrix) -> Vec<Span<'static>> {
    let mut spans = Vec::with_capacity(8);

    // IPv4 Direct
    let (v4_char, v4_color) = if matrix.ipv4_direct_tested {
        if matrix.ipv4_direct_success {
            ("✓", Color::Green)
        } else {
            ("✗", Color::Red)
        }
    } else {
        ("·", Color::DarkGray)
    };
    spans.push(Span::styled("4", Style::default().fg(Color::Yellow)));
    spans.push(Span::styled(
        v4_char.to_string(),
        Style::default().fg(v4_color),
    ));
    spans.push(Span::raw(" "));

    // IPv6 Direct
    let (v6_char, v6_color) = if matrix.ipv6_direct_tested {
        if matrix.ipv6_direct_success {
            ("✓", Color::Green)
        } else {
            ("✗", Color::Red)
        }
    } else {
        ("·", Color::DarkGray)
    };
    spans.push(Span::styled("6", Style::default().fg(Color::Magenta)));
    spans.push(Span::styled(
        v6_char.to_string(),
        Style::default().fg(v6_color),
    ));
    spans.push(Span::raw(" "));

    // NAT Traversal
    let (nat_char, nat_color) = if matrix.nat_traversal_tested {
        if matrix.nat_traversal_success {
            ("✓", Color::Green)
        } else {
            ("✗", Color::Red)
        }
    } else {
        ("·", Color::DarkGray)
    };
    spans.push(Span::styled("N", Style::default().fg(Color::Cyan)));
    spans.push(Span::styled(
        nat_char.to_string(),
        Style::default().fg(nat_color),
    ));
    spans.push(Span::raw(" "));

    // Relay
    let (relay_char, relay_color) = if matrix.relay_tested {
        if matrix.relay_success {
            ("✓", Color::Green)
        } else {
            ("✗", Color::Red)
        }
    } else {
        ("·", Color::DarkGray)
    };
    spans.push(Span::styled("R", Style::default().fg(Color::Red)));
    spans.push(Span::styled(
        relay_char.to_string(),
        Style::default().fg(relay_color),
    ));

    spans
}

pub fn draw(frame: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),  // Header
            Constraint::Length(6),  // Network Stats (comprehensive counts)
            Constraint::Length(4),  // Your Node
            Constraint::Min(6),     // Connected Peers
            Constraint::Length(10), // Cache Health + NAT Analytics + ACTIVITY LOG
            Constraint::Length(3),  // Messages
            Constraint::Length(3),  // Footer
        ])
        .split(frame.area());

    draw_header(frame, chunks[0]);
    draw_network_stats(frame, app, chunks[1]);
    draw_node_info(frame, app, chunks[2]);
    draw_peers(frame, app, chunks[3]);
    draw_enhanced_analytics(frame, app, chunks[4]);
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

fn draw_network_stats(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(" NETWORK STATS ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let mut direct = 0usize;
    let mut holepunched = 0usize;
    let mut relayed = 0usize;
    let mut inbound = 0usize;
    let mut outbound = 0usize;
    let mut ipv4 = 0usize;
    let mut ipv6 = 0usize;
    let mut nat_verified = 0usize;

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
        for addr in &peer.addresses {
            if addr.is_ipv4() {
                ipv4 += 1;
            } else {
                ipv6 += 1;
            }
        }
        if peer.is_nat_verified() {
            nat_verified += 1;
        }
    }

    let total = app.connected_peers.len();
    let history_total = app.connection_history.len();
    let history_disconnected = app.history_disconnected_count();

    let tx_active = app.connected_peers.values().any(|p| p.tx_active);
    let rx_active = app.connected_peers.values().any(|p| p.rx_active);
    let traffic = match (tx_active, rx_active) {
        (true, true) => "◀▶",
        (true, false) => "▶▶",
        (false, true) => "◀◀",
        (false, false) => "··",
    };

    let line1 = Line::from(vec![
        Span::raw("  LIVE: "),
        Span::styled(
            format!("{}", total),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  │  "),
        Span::styled("🟢", Style::default().fg(COLOR_DIRECT)),
        Span::styled(format!("{}", direct), Style::default().fg(COLOR_DIRECT)),
        Span::raw(" "),
        Span::styled("🟠", Style::default().fg(COLOR_HOLEPUNCHED)),
        Span::styled(
            format!("{}", holepunched),
            Style::default().fg(COLOR_HOLEPUNCHED),
        ),
        Span::raw(" "),
        Span::styled("🔴", Style::default().fg(COLOR_RELAYED)),
        Span::styled(format!("{}", relayed), Style::default().fg(COLOR_RELAYED)),
        Span::raw("  │  "),
        Span::styled(
            format!("←{}", inbound),
            Style::default()
                .fg(if inbound > 0 {
                    Color::Green
                } else {
                    Color::DarkGray
                })
                .add_modifier(if inbound > 0 {
                    Modifier::BOLD
                } else {
                    Modifier::empty()
                }),
        ),
        Span::raw(" "),
        Span::styled(format!("→{}", outbound), Style::default().fg(Color::Cyan)),
        Span::raw("  │  "),
        Span::styled(format!("v4:{}", ipv4), Style::default().fg(Color::Yellow)),
        Span::raw(" "),
        Span::styled(format!("v6:{}", ipv6), Style::default().fg(Color::Magenta)),
        Span::raw("  │  "),
        Span::styled(
            format!("NAT✓{}", nat_verified),
            Style::default().fg(Color::Green),
        ),
        Span::raw("  "),
        Span::styled(
            traffic,
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
    ]);

    let hyparview_active = app.stats.hyparview_active;
    let hyparview_passive = app.stats.hyparview_passive;
    let swim_alive = app.stats.swim_alive;
    let swim_suspect = app.stats.swim_suspect;
    let swim_dead = app.stats.swim_dead;

    let hyparview_color = if hyparview_active >= 6 {
        Color::Green
    } else if hyparview_active >= 3 {
        Color::Yellow
    } else {
        Color::Red
    };

    let line2 = Line::from(vec![
        Span::raw("  GOSSIP: HyPar "),
        Span::styled(
            format!("{}", hyparview_active),
            Style::default()
                .fg(hyparview_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("/"),
        Span::styled(
            format!("{}", hyparview_passive),
            Style::default().fg(Color::DarkGray),
        ),
        Span::raw("  SWIM "),
        Span::styled(format!("{}", swim_alive), Style::default().fg(Color::Green)),
        Span::raw("/"),
        Span::styled(
            format!("{}", swim_suspect),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw("/"),
        Span::styled(format!("{}", swim_dead), Style::default().fg(Color::Red)),
        Span::raw("  │  HISTORY: "),
        Span::styled(
            format!("{}", history_total),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" ("),
        Span::styled(
            format!("{}○", history_disconnected),
            Style::default().fg(Color::DarkGray),
        ),
        Span::raw(")  │  SEEN: "),
        Span::styled(
            format!("{}", app.peers_seen_count()),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        connectivity_test_status_span(app),
    ]);

    let (connected, attempted) = app.stats.unique_peer_counts();
    let success_rate = app.stats.success_rate();
    let success_color = if success_rate >= 90.0 {
        Color::Green
    } else if success_rate >= 70.0 {
        Color::Yellow
    } else {
        Color::Red
    };

    let line3 = Line::from(vec![
        Span::raw("  SUCCESS: "),
        Span::styled(
            format!("{:.0}%", success_rate),
            Style::default()
                .fg(success_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" ("),
        Span::styled(format!("{}", connected), Style::default().fg(Color::Green)),
        Span::raw("/"),
        Span::styled(format!("{}", attempted), Style::default().fg(Color::White)),
        Span::raw(")  │  PKTS: "),
        Span::styled(
            format!("{}↑", app.stats.packets_sent),
            Style::default().fg(Color::Cyan),
        ),
        Span::raw(" "),
        Span::styled(
            format!("{}↓", app.stats.packets_received),
            Style::default().fg(Color::Green),
        ),
        Span::raw("  │  UP: "),
        Span::styled(
            app.stats.uptime(),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  │  REG: "),
        Span::styled(
            format!("{}", app.total_registered_nodes),
            Style::default().fg(Color::Yellow),
        ),
    ]);

    let paragraph = Paragraph::new(vec![line1, line2, line3]).block(block);
    frame.render_widget(paragraph, area);
}

fn connectivity_test_status_span(app: &App) -> Span<'static> {
    match app.connectivity_test.phase {
        ConnectivityTestPhase::Registering => {
            if app.local_node.registered {
                Span::styled(
                    "  🔄 Connecting...",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::raw("")
            }
        }
        ConnectivityTestPhase::WaitingForInbound => {
            let countdown = app.connectivity_countdown();
            Span::styled(
                format!("  🔄 TEST: Waiting {}s", countdown),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
        }
        ConnectivityTestPhase::WaitingCountdown { seconds_remaining } => Span::styled(
            format!("  ⏱️ Countdown: {}s", seconds_remaining),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        ConnectivityTestPhase::TestingOutbound { tested, total } => Span::styled(
            format!("  🔄 Testing: {}/{}", tested, total),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        ConnectivityTestPhase::Complete => {
            let rate = app.connectivity_test.inbound_success_rate();
            let color = if rate >= 80.0 {
                Color::Green
            } else if rate >= 50.0 {
                Color::Yellow
            } else {
                Color::Red
            };
            Span::styled(
                format!("  ✅ Test: {:.0}% success", rate),
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            )
        }
    }
}

/// Draw local node information (compact).
fn draw_node_info(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(" YOUR NODE ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green));

    // Build node info lines - use peer_id directly for robustness
    let peer_id_display = if app.local_node.peer_id.is_empty() {
        "Generating...".to_string()
    } else {
        // Extract first 8 chars from peer_id directly (short_id should match but this is safer)
        let short = if app.local_node.peer_id.len() > 8 {
            &app.local_node.peer_id[..8]
        } else {
            &app.local_node.peer_id
        };
        format!("{}...", short)
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

fn draw_peers(frame: &mut Frame, app: &mut App, area: Rect) {
    let auto_status = if app.auto_connecting {
        Span::styled("[Auto-connecting]", Style::default().fg(Color::Green))
    } else {
        Span::styled("[Paused]", Style::default().fg(Color::Yellow))
    };

    let scroll_hint = Span::styled(
        " [↑/↓/PgUp/PgDn to scroll]",
        Style::default().fg(Color::DarkGray),
    );
    let history_total = app.connection_history.len();
    let history_live = app.history_connected_count();
    let title = Line::from(vec![
        Span::raw(format!(
            " ALL CONNECTIONS ({} live / {} total) ",
            history_live, history_total
        )),
        auto_status,
        scroll_hint,
        Span::raw("  "),
        Span::styled("D/N/R", Style::default().fg(Color::DarkGray)),
        Span::raw(" "),
        Span::styled("✓×·", Style::default().fg(Color::DarkGray)),
    ]);

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue));

    let header = Row::new(vec![
        Cell::from("").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Peer").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Loc").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Out").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("In").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("IP").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("RTT").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Seen").style(Style::default().add_modifier(Modifier::BOLD)),
    ])
    .height(1)
    .style(Style::default().fg(Color::White));

    // Table rows with traffic light colors
    let rows: Vec<Row> = app
        .history_sorted()
        .iter()
        .map(|entry| {
            let status_color = match entry.status {
                crate::tui::types::ConnectionStatus::Connected => Color::Green,
                crate::tui::types::ConnectionStatus::Disconnected => Color::DarkGray,
                crate::tui::types::ConnectionStatus::Failed => Color::Red,
                crate::tui::types::ConnectionStatus::Coordinating => Color::Yellow,
            };

            let row_color = match entry.status {
                crate::tui::types::ConnectionStatus::Connected => entry
                    .method
                    .as_ref()
                    .map(method_color)
                    .unwrap_or(Color::Green),
                crate::tui::types::ConnectionStatus::Disconnected => Color::DarkGray,
                crate::tui::types::ConnectionStatus::Failed => Color::Red,
                crate::tui::types::ConnectionStatus::Coordinating => Color::Yellow,
            };

            let location = if entry.location.len() == 2 {
                format!("{} {}", country_flag(&entry.location), entry.location)
            } else {
                entry.location.clone()
            };

            let outbound_summary = entry.outbound.summary_compact();
            let inbound_summary = entry.inbound.summary_compact();

            Row::new(vec![
                Cell::from(entry.status.emoji()).style(Style::default().fg(status_color)),
                Cell::from(entry.short_id.clone()).style(Style::default().fg(row_color)),
                Cell::from(location),
                Cell::from(outbound_summary),
                Cell::from(inbound_summary),
                Cell::from(entry.ip_version_indicator()).style(Style::default().fg(Color::Cyan)),
                Cell::from(entry.rtt_string()).style(Style::default().fg(Color::Yellow)),
                Cell::from(entry.time_since_seen()).style(Style::default().fg(Color::DarkGray)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(2), // Status
            Constraint::Length(9), // Peer ID
            Constraint::Length(5), // Location
            Constraint::Length(7), // Outbound summary
            Constraint::Length(7), // Inbound summary
            Constraint::Length(4), // IP version
            Constraint::Length(6), // RTT
            Constraint::Min(4),    // Last seen
        ],
    )
    .header(header)
    .block(block)
    .row_highlight_style(
        Style::default()
            .add_modifier(Modifier::REVERSED)
            .fg(Color::Cyan),
    );

    frame.render_stateful_widget(table, area, &mut app.connections_table_state);
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
        Span::raw(" Quit  "),
        Span::styled("[T]", Style::default().fg(Color::Yellow)),
        Span::raw(" Test    "),
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

fn draw_enhanced_analytics(frame: &mut Frame, app: &App, area: Rect) {
    draw_activity_log(frame, app, area);
}

fn draw_activity_log(frame: &mut Frame, app: &App, area: Rect) {
    if !app.connectivity_test.peer_results.is_empty() {
        draw_connectivity_results(frame, app, area);
        return;
    }

    let stats = &app.stats;
    let title = format!(
        " ACTIVITY LOG  In:{} Out:{} Direct:{} NAT:{} Relay:{} ",
        stats.inbound_connections,
        stats
            .connection_successes
            .saturating_sub(stats.inbound_connections),
        stats.direct_connections,
        stats.hole_punched_connections,
        stats.relayed_connections,
    );

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let mut lines: Vec<Line> = Vec::new();
    let now = std::time::Instant::now();
    let max_lines = (area.height as usize).saturating_sub(2);

    for pf in app.protocol_frames.iter().rev().take(max_lines) {
        let age = now.duration_since(pf.timestamp);
        let age_str = if age.as_secs() < 60 {
            format!("{:>2}s", age.as_secs())
        } else if age.as_secs() < 3600 {
            format!("{:>2}m", age.as_secs() / 60)
        } else {
            format!("{:>2}h", age.as_secs() / 3600)
        };

        let (dir_arrow, dir_color) = match pf.direction {
            crate::tui::types::FrameDirection::Sent => ("→", Color::Cyan),
            crate::tui::types::FrameDirection::Received => ("←", Color::Green),
        };

        let peer_short = if pf.peer_id.len() > 8 {
            &pf.peer_id[..8]
        } else {
            &pf.peer_id
        };

        let frame_color = match pf.frame_type.as_str() {
            "CONNECTED" => Color::Green,
            "DISCONNECTED" => Color::Red,
            "DIRECT" | "Direct" => Color::Green,
            "PUNCHED" | "HolePunched" => Color::Yellow,
            "RELAYED" | "Relayed" => Color::Magenta,
            "CONNECT" => Color::Cyan,
            "NAT_TRAVERSE" => Color::Yellow,
            _ => Color::White,
        };

        let detail = pf.context.as_deref().unwrap_or("");

        lines.push(Line::from(vec![
            Span::styled(
                format!("{} ", age_str),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(dir_arrow, Style::default().fg(dir_color)),
            Span::raw(" "),
            Span::styled(peer_short, Style::default().fg(Color::White)),
            Span::raw(" "),
            Span::styled(
                format!("{:<12}", &pf.frame_type),
                Style::default().fg(frame_color),
            ),
            Span::styled(detail, Style::default().fg(Color::DarkGray)),
        ]));
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "  Waiting for activity...",
            Style::default().fg(Color::DarkGray),
        )));
    }

    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, area);
}

fn draw_connectivity_results(frame: &mut Frame, app: &App, area: Rect) {
    let inbound_count = app.connectivity_test.peer_results.len();
    let success_rate = app.connectivity_test.inbound_success_rate();
    let title = format!(
        " CONNECTIVITY TEST ({} peers, {:.0}% success) ",
        inbound_count, success_rate
    );

    let title_color = if success_rate >= 80.0 {
        Color::Green
    } else if success_rate >= 50.0 {
        Color::Yellow
    } else {
        Color::Red
    };

    let block = Block::default()
        .title(Span::styled(title, Style::default().fg(title_color)))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let mut lines: Vec<Line> = Vec::new();

    for result in app.connectivity_test.sorted_results().iter().take(8) {
        let inbound_icon = if result.inbound_success() {
            Span::styled("✓", Style::default().fg(Color::Green))
        } else {
            Span::styled("✗", Style::default().fg(Color::Red))
        };

        let outbound_icon = if result.outbound_success() {
            Span::styled("✓", Style::default().fg(Color::Green))
        } else if result.outbound_attempts.is_empty() {
            Span::styled("-", Style::default().fg(Color::DarkGray))
        } else {
            Span::styled("✗", Style::default().fg(Color::Red))
        };

        let method_str = if let Some(attempt) = result.inbound_attempts.first() {
            attempt.method.display_name()
        } else {
            "N/A"
        };

        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(&result.peer_id, Style::default().fg(Color::White)),
            Span::raw(" In:"),
            inbound_icon,
            Span::raw(" Out:"),
            outbound_icon,
            Span::raw(" via "),
            Span::styled(method_str, Style::default().fg(Color::Cyan)),
        ]));
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "  Waiting for test connections...",
            Style::default().fg(Color::DarkGray),
        )));
    }

    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, area);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_draw_functions_exist() {
        let _ = draw as fn(&mut Frame, &mut App);
        let _ = draw_header as fn(&mut Frame, Rect);
        let _ = draw_network_stats as fn(&mut Frame, &App, Rect);
        let _ = draw_node_info as fn(&mut Frame, &App, Rect);
        let _ = draw_peers as fn(&mut Frame, &mut App, Rect);
        let _ = draw_enhanced_analytics as fn(&mut Frame, &App, Rect);
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

    #[test]
    fn test_format_connectivity_matrix() {
        use crate::registry::ConnectivityMatrix;

        let mut matrix = ConnectivityMatrix::default();
        let spans = format_connectivity_matrix(&matrix);
        let text: String = spans.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(text, "4· 6· N· R·");

        matrix.ipv4_direct_tested = true;
        matrix.ipv4_direct_success = true;
        matrix.ipv6_direct_tested = true;
        matrix.ipv6_direct_success = false;
        matrix.nat_traversal_tested = true;
        matrix.nat_traversal_success = true;

        let spans = format_connectivity_matrix(&matrix);
        let text: String = spans.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(text, "4✓ 6✗ N✓ R·");
    }
}
