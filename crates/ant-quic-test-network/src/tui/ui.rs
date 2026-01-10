//! TUI rendering using ratatui.
//!
//! This module handles the visual rendering of the terminal UI,
//! drawing the various sections showing network status.
//!
//! ## Traffic Light Color Scheme
//! - 🟢 Green: Direct connections (best - fully connectable)
//! - 🟠 Orange: NAT Traversed / Hole-punched (great - NAT was bypassed!)
//! - 🔴 Red: Relayed connections (works but slower - last resort)
//!
//! ## Tab Navigation
//! - [1] Overview - Main dashboard (default)
//! - [2] Gossip Health - Detailed stats for all 9 saorsa-gossip crates
//! - [3] Connectivity Matrix - N×N peer-to-peer connectivity test results
//! - [4] Protocol Log - Real-time message flow visualization

use crate::gossip_tests::TestStatus;
use crate::registry::ConnectionMethod;
use crate::tui::app::{App, Tab};
use crate::tui::types::{ConnectivityTestPhase, country_flag};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Tabs},
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
    // Main layout: tabs at top, content in middle, footer at bottom
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), // Tab bar
            Constraint::Min(10),   // Main content area
            Constraint::Length(3), // Messages
            Constraint::Length(3), // Footer with controls
        ])
        .split(frame.area());

    // Draw tab bar
    draw_tab_bar(frame, app, main_chunks[0]);

    // Draw content based on active tab
    match app.active_tab {
        Tab::Overview => draw_overview_tab(frame, app, main_chunks[1]),
        Tab::GossipHealth => draw_gossip_health_tab(frame, app, main_chunks[1]),
        Tab::ConnectivityMatrix => draw_connectivity_matrix_tab(frame, app, main_chunks[1]),
        Tab::ProtocolLog => draw_protocol_log_tab(frame, app, main_chunks[1]),
    }

    draw_messages(frame, app, main_chunks[2]);
    draw_footer(frame, app, main_chunks[3]);
}

/// Draw the tab bar for navigation.
fn draw_tab_bar(frame: &mut Frame, app: &App, area: Rect) {
    let tab_titles = vec![
        "[1] Overview",
        "[2] Gossip Health",
        "[3] Connectivity Matrix",
        "[4] Protocol Log",
    ];
    let selected_idx = match app.active_tab {
        Tab::Overview => 0,
        Tab::GossipHealth => 1,
        Tab::ConnectivityMatrix => 2,
        Tab::ProtocolLog => 3,
    };

    let tabs = Tabs::new(tab_titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(" ant-quic Network Test - Tab/Shift+Tab to navigate "),
        )
        .select(selected_idx)
        .style(Style::default().fg(Color::White))
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        )
        .divider(" │ ");

    frame.render_widget(tabs, area);
}

/// Draw the Overview tab (original layout).
fn draw_overview_tab(frame: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6),  // Network Stats (comprehensive counts)
            Constraint::Length(4),  // Your Node
            Constraint::Length(3),  // Gossip Crate Status (compact)
            Constraint::Min(6),     // Connected Peers
            Constraint::Length(10), // Cache Health + NAT Analytics + ACTIVITY LOG
        ])
        .split(area);

    draw_network_stats(frame, app, chunks[0]);
    draw_node_info(frame, app, chunks[1]);
    draw_gossip_status(frame, app, chunks[2]);
    draw_peers(frame, app, chunks[3]);
    draw_enhanced_analytics(frame, app, chunks[4]);
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

/// Draw gossip crate test status (compact single-line format).
/// Shows status of all 9 saorsa-gossip crates: types, identity, transport,
/// membership, pubsub, crdt-sync, groups, coordinator, rendezvous.
fn draw_gossip_status(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(" SAORSA-GOSSIP CRATES (9) — Press [G] to test ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta));

    let mut spans: Vec<Span> = vec![Span::raw(" ")];

    if app.gossip_tests_running {
        spans.push(Span::styled(
            "🔄 Running tests...",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ));
    } else if let Some(ref results) = app.gossip_test_results {
        // All 9 crates with full names for clarity
        let crates = [
            ("types", &results.types),
            ("identity", &results.identity),
            ("transport", &results.transport),
            ("membership", &results.membership),
            ("pubsub", &results.pubsub),
            ("crdt-sync", &results.crdt_sync),
            ("groups", &results.groups),
            ("coordinator", &results.coordinator),
            ("rendezvous", &results.rendezvous),
        ];

        for (i, (name, result)) in crates.iter().enumerate() {
            if i > 0 {
                spans.push(Span::raw(" │ "));
            }

            let (icon, color) = match result.status {
                TestStatus::Passed => ("✓", Color::Green),
                TestStatus::Failed => ("✗", Color::Red),
                TestStatus::Running => ("◐", Color::Yellow),
                TestStatus::Skipped => ("−", Color::DarkGray),
                TestStatus::Pending => ("·", Color::DarkGray),
            };

            // Color-code the crate name based on status
            spans.push(Span::styled(icon, Style::default().fg(color)));
            spans.push(Span::styled(
                name.to_string(),
                Style::default().fg(color),
            ));
        }

        // Summary at the end
        let passed = crates
            .iter()
            .filter(|(_, r)| r.status == TestStatus::Passed)
            .count();
        let total = crates.len();
        let summary_color = if passed == total {
            Color::Green
        } else if passed >= 7 {
            Color::Yellow
        } else {
            Color::Red
        };
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            format!("[{}/{}]", passed, total),
            Style::default()
                .fg(summary_color)
                .add_modifier(Modifier::BOLD),
        ));
    } else {
        // No test results yet - show what crates will be tested
        spans.push(Span::styled(
            "types│identity│transport│membership│pubsub│crdt-sync│groups│coordinator│rendezvous",
            Style::default().fg(Color::DarkGray),
        ));
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            "[not tested]",
            Style::default().fg(Color::Yellow),
        ));
    }

    let line = Line::from(spans);
    let paragraph = Paragraph::new(vec![line]).block(block);
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
    // Legend: D=Direct, N=NAT traversal, R=Relay | ✓=ok, ✗=fail, ·=untested
    let title = Line::from(vec![
        Span::raw(format!(
            " CONNECTIONS ({} live / {} total) ",
            history_live, history_total
        )),
        auto_status,
        scroll_hint,
        Span::raw(" "),
        Span::styled("D", Style::default().fg(Color::Green)),
        Span::styled("irect/", Style::default().fg(Color::DarkGray)),
        Span::styled("N", Style::default().fg(Color::Yellow)),
        Span::styled("AT/", Style::default().fg(Color::DarkGray)),
        Span::styled("R", Style::default().fg(Color::Red)),
        Span::styled("elay ", Style::default().fg(Color::DarkGray)),
        Span::styled("✓", Style::default().fg(Color::Green)),
        Span::styled("ok ", Style::default().fg(Color::DarkGray)),
        Span::styled("✗", Style::default().fg(Color::Red)),
        Span::styled("fail ", Style::default().fg(Color::DarkGray)),
        Span::styled("·", Style::default().fg(Color::DarkGray)),
        Span::styled("untested", Style::default().fg(Color::DarkGray)),
    ]);

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue));

    // Column headers with explanatory abbreviations
    // D=Direct, N=NAT hole-punch, R=Relay
    // ✓=success, ·=untested, ✗=failed
    let header = Row::new(vec![
        Cell::from("St").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Peer ID").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Loc").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("→ D·N·R").style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan)),
        Cell::from("← D·N·R").style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Magenta)),
        Cell::from("IPv").style(Style::default().add_modifier(Modifier::BOLD)),
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

            // Display location with country flag if available
            let location = if entry.location.len() == 2 {
                format!("{} {}", country_flag(&entry.location), entry.location)
            } else if entry.location == "---" || entry.location == "??" {
                "🌍 ?".to_string()  // Globe icon for unknown location
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
        Span::raw(" Test  "),
        Span::styled("[G]", Style::default().fg(Color::Magenta)),
        Span::raw(" Gossip    "),
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

/// Draw the Gossip Health tab - detailed stats for all 9 saorsa-gossip crates.
fn draw_gossip_health_tab(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8), // Transport + Identity
            Constraint::Length(8), // Membership (HyParView + SWIM)
            Constraint::Length(8), // Pubsub (Plumtree)
            Constraint::Min(8),    // CRDT + Coordinator + Groups + Rendezvous
        ])
        .split(area);

    draw_transport_identity_panel(frame, app, chunks[0]);
    draw_membership_panel(frame, app, chunks[1]);
    draw_pubsub_panel(frame, app, chunks[2]);
    draw_extended_gossip_panel(frame, app, chunks[3]);
}

/// Draw transport and identity stats panel.
fn draw_transport_identity_panel(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Transport panel
    let transport_block = Block::default()
        .title(" saorsa-gossip-transport ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let transport_lines = if let Some(ref stats) = app.gossip_stats {
        vec![
            Line::from(vec![
                Span::raw("  Packets Sent: "),
                Span::styled(
                    format!("{}", stats.transport_packets_sent),
                    Style::default().fg(Color::Cyan),
                ),
            ]),
            Line::from(vec![
                Span::raw("  Packets Recv: "),
                Span::styled(
                    format!("{}", stats.transport_packets_received),
                    Style::default().fg(Color::Green),
                ),
            ]),
            Line::from(vec![
                Span::raw("  Bytes Sent: "),
                Span::styled(
                    format_bytes_short(stats.transport_bytes_sent),
                    Style::default().fg(Color::Cyan),
                ),
            ]),
            Line::from(vec![
                Span::raw("  Bytes Recv: "),
                Span::styled(
                    format_bytes_short(stats.transport_bytes_received),
                    Style::default().fg(Color::Green),
                ),
            ]),
        ]
    } else {
        vec![Line::from(Span::styled(
            "  No data available",
            Style::default().fg(Color::DarkGray),
        ))]
    };

    frame.render_widget(
        Paragraph::new(transport_lines).block(transport_block),
        chunks[0],
    );

    // Identity panel
    let identity_block = Block::default()
        .title(" saorsa-gossip-identity ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta));

    let identity_lines = if let Some(ref stats) = app.gossip_stats {
        vec![
            Line::from(vec![
                Span::raw("  Known Peers: "),
                Span::styled(
                    format!("{}", stats.identity_known_peers),
                    Style::default().fg(Color::Yellow),
                ),
            ]),
            Line::from(vec![
                Span::raw("  Verifications: "),
                Span::styled(
                    format!("{}", stats.identity_verifications),
                    Style::default().fg(Color::Green),
                ),
            ]),
        ]
    } else {
        vec![Line::from(Span::styled(
            "  No data available",
            Style::default().fg(Color::DarkGray),
        ))]
    };

    frame.render_widget(
        Paragraph::new(identity_lines).block(identity_block),
        chunks[1],
    );
}

/// Draw membership (HyParView + SWIM) stats panel.
fn draw_membership_panel(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // HyParView panel
    let hyparview_block = Block::default()
        .title(" HyParView Membership ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue));

    let hyparview_lines = if let Some(ref stats) = app.gossip_stats {
        let active_color = if stats.hyparview_active >= 6 {
            Color::Green
        } else if stats.hyparview_active >= 3 {
            Color::Yellow
        } else {
            Color::Red
        };
        vec![
            Line::from(vec![
                Span::raw("  Active View: "),
                Span::styled(
                    format!("{}", stats.hyparview_active),
                    Style::default()
                        .fg(active_color)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::raw("  Passive View: "),
                Span::styled(
                    format!("{}", stats.hyparview_passive),
                    Style::default().fg(Color::DarkGray),
                ),
            ]),
            Line::from(vec![
                Span::raw("  Shuffles: "),
                Span::styled(
                    format!("{}", stats.hyparview_shuffles),
                    Style::default().fg(Color::Cyan),
                ),
            ]),
            Line::from(vec![
                Span::raw("  Joins: "),
                Span::styled(
                    format!("{}", stats.hyparview_joins),
                    Style::default().fg(Color::Green),
                ),
            ]),
            Line::from(vec![
                Span::raw("  Forward Joins: "),
                Span::styled(
                    format!("{}", stats.hyparview_forward_joins),
                    Style::default().fg(Color::Yellow),
                ),
            ]),
        ]
    } else {
        vec![Line::from(Span::styled(
            "  No data available",
            Style::default().fg(Color::DarkGray),
        ))]
    };

    frame.render_widget(
        Paragraph::new(hyparview_lines).block(hyparview_block),
        chunks[0],
    );

    // SWIM panel
    let swim_block = Block::default()
        .title(" SWIM Failure Detection ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));

    let swim_lines = if let Some(ref stats) = app.gossip_stats {
        vec![
            Line::from(vec![
                Span::styled("  Alive: ", Style::default().fg(Color::Green)),
                Span::styled(
                    format!("{}", stats.swim_alive),
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("  "),
                Span::styled("Suspect: ", Style::default().fg(Color::Yellow)),
                Span::styled(
                    format!("{}", stats.swim_suspect),
                    Style::default().fg(Color::Yellow),
                ),
                Span::raw("  "),
                Span::styled("Dead: ", Style::default().fg(Color::Red)),
                Span::styled(
                    format!("{}", stats.swim_dead),
                    Style::default().fg(Color::Red),
                ),
            ]),
            Line::from(vec![
                Span::raw("  Pings Sent: "),
                Span::styled(
                    format!("{}", stats.swim_pings_sent),
                    Style::default().fg(Color::Cyan),
                ),
            ]),
            Line::from(vec![
                Span::raw("  Pings Recv: "),
                Span::styled(
                    format!("{}", stats.swim_pings_received),
                    Style::default().fg(Color::Green),
                ),
            ]),
            Line::from(vec![
                Span::raw("  Ping-Req Sent: "),
                Span::styled(
                    format!("{}", stats.swim_ping_req_sent),
                    Style::default().fg(Color::Yellow),
                ),
            ]),
            Line::from(vec![
                Span::raw("  ACKs Received: "),
                Span::styled(
                    format!("{}", stats.swim_acks_received),
                    Style::default().fg(Color::Green),
                ),
            ]),
        ]
    } else {
        vec![Line::from(Span::styled(
            "  No data available",
            Style::default().fg(Color::DarkGray),
        ))]
    };

    frame.render_widget(Paragraph::new(swim_lines).block(swim_block), chunks[1]);
}

/// Draw pubsub (Plumtree) stats panel.
fn draw_pubsub_panel(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(" Plumtree Epidemic Broadcast ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green));

    let lines = if let Some(ref stats) = app.gossip_stats {
        vec![
            Line::from(vec![
                Span::raw("  Eager Peers: "),
                Span::styled(
                    format!("{}", stats.plumtree_eager),
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("    Lazy Peers: "),
                Span::styled(
                    format!("{}", stats.plumtree_lazy),
                    Style::default().fg(Color::Yellow),
                ),
            ]),
            Line::from(vec![
                Span::raw("  Messages Sent: "),
                Span::styled(
                    format!("{}", stats.plumtree_sent),
                    Style::default().fg(Color::Cyan),
                ),
                Span::raw("    Messages Recv: "),
                Span::styled(
                    format!("{}", stats.plumtree_received),
                    Style::default().fg(Color::Green),
                ),
            ]),
            Line::from(vec![
                Span::raw("  Broadcasts: "),
                Span::styled(
                    format!("{}", stats.plumtree_broadcasts),
                    Style::default().fg(Color::Yellow),
                ),
            ]),
            Line::from(vec![
                Span::raw("  IHAVEs Sent: "),
                Span::styled(
                    format!("{}", stats.plumtree_ihaves_sent),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw("    IHAVEs Recv: "),
                Span::styled(
                    format!("{}", stats.plumtree_ihaves_received),
                    Style::default().fg(Color::DarkGray),
                ),
            ]),
            Line::from(vec![
                Span::raw("  GRAFTs Sent: "),
                Span::styled(
                    format!("{}", stats.plumtree_grafts_sent),
                    Style::default().fg(Color::Magenta),
                ),
                Span::raw("    PRUNEs Sent: "),
                Span::styled(
                    format!("{}", stats.plumtree_prunes_sent),
                    Style::default().fg(Color::Red),
                ),
            ]),
        ]
    } else {
        vec![Line::from(Span::styled(
            "  No data available",
            Style::default().fg(Color::DarkGray),
        ))]
    };

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

/// Draw extended gossip stats (CRDT, Coordinator, Groups, Rendezvous).
fn draw_extended_gossip_panel(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(area);

    // CRDT-sync panel
    let crdt_block = Block::default()
        .title(" CRDT Sync ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta));

    let crdt_lines = if let Some(ref stats) = app.gossip_stats {
        vec![
            Line::from(vec![
                Span::raw(" Entries: "),
                Span::styled(
                    format!("{}", stats.crdt_entries),
                    Style::default().fg(Color::Yellow),
                ),
            ]),
            Line::from(vec![
                Span::raw(" Merges: "),
                Span::styled(
                    format!("{}", stats.crdt_merges),
                    Style::default().fg(Color::Green),
                ),
            ]),
            Line::from(vec![
                Span::raw(" VClock: "),
                Span::styled(
                    format!("{}", stats.crdt_vector_clock_len),
                    Style::default().fg(Color::Cyan),
                ),
            ]),
            Line::from(vec![
                Span::raw(" Rounds: "),
                Span::styled(
                    format!("{}", stats.crdt_sync_rounds),
                    Style::default().fg(Color::White),
                ),
            ]),
        ]
    } else {
        vec![Line::from(Span::styled(
            " N/A",
            Style::default().fg(Color::DarkGray),
        ))]
    };

    frame.render_widget(Paragraph::new(crdt_lines).block(crdt_block), chunks[0]);

    // Coordinator panel
    let coord_block = Block::default()
        .title(" Coordinator ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));

    let coord_lines = if let Some(ref stats) = app.gossip_stats {
        vec![
            Line::from(vec![
                Span::raw(" Active: "),
                Span::styled(
                    format!("{}", stats.coordinator_active),
                    Style::default().fg(Color::Yellow),
                ),
            ]),
            Line::from(vec![
                Span::raw(" Success: "),
                Span::styled(
                    format!("{}", stats.coordinator_success),
                    Style::default().fg(Color::Green),
                ),
            ]),
            Line::from(vec![
                Span::raw(" Failed: "),
                Span::styled(
                    format!("{}", stats.coordinator_failed),
                    Style::default().fg(Color::Red),
                ),
            ]),
            Line::from(vec![
                Span::raw(" Requests: "),
                Span::styled(
                    format!("{}", stats.coordinator_requests),
                    Style::default().fg(Color::Cyan),
                ),
            ]),
        ]
    } else {
        vec![Line::from(Span::styled(
            " N/A",
            Style::default().fg(Color::DarkGray),
        ))]
    };

    frame.render_widget(Paragraph::new(coord_lines).block(coord_block), chunks[1]);

    // Groups panel
    let groups_block = Block::default()
        .title(" Groups ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue));

    let groups_lines = if let Some(ref stats) = app.gossip_stats {
        vec![
            Line::from(vec![
                Span::raw(" Count: "),
                Span::styled(
                    format!("{}", stats.groups_count),
                    Style::default().fg(Color::Cyan),
                ),
            ]),
            Line::from(vec![
                Span::raw(" Members: "),
                Span::styled(
                    format!("{}", stats.groups_total_members),
                    Style::default().fg(Color::Yellow),
                ),
            ]),
            Line::from(vec![
                Span::raw(" Joins: "),
                Span::styled(
                    format!("{}", stats.groups_joins),
                    Style::default().fg(Color::Green),
                ),
            ]),
            Line::from(vec![
                Span::raw(" Leaves: "),
                Span::styled(
                    format!("{}", stats.groups_leaves),
                    Style::default().fg(Color::Red),
                ),
            ]),
        ]
    } else {
        vec![Line::from(Span::styled(
            " N/A",
            Style::default().fg(Color::DarkGray),
        ))]
    };

    frame.render_widget(Paragraph::new(groups_lines).block(groups_block), chunks[2]);

    // Rendezvous panel
    let rdv_block = Block::default()
        .title(" Rendezvous ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green));

    let rdv_lines = if let Some(ref stats) = app.gossip_stats {
        vec![
            Line::from(vec![
                Span::raw(" Points: "),
                Span::styled(
                    format!("{}", stats.rendezvous_points),
                    Style::default().fg(Color::Yellow),
                ),
            ]),
            Line::from(vec![
                Span::raw(" Regs: "),
                Span::styled(
                    format!("{}", stats.rendezvous_registrations),
                    Style::default().fg(Color::Green),
                ),
            ]),
            Line::from(vec![
                Span::raw(" Discover: "),
                Span::styled(
                    format!("{}", stats.rendezvous_discoveries),
                    Style::default().fg(Color::Cyan),
                ),
            ]),
            Line::from(vec![
                Span::raw(" Queries: "),
                Span::styled(
                    format!("{}", stats.rendezvous_queries),
                    Style::default().fg(Color::White),
                ),
            ]),
        ]
    } else {
        vec![Line::from(Span::styled(
            " N/A",
            Style::default().fg(Color::DarkGray),
        ))]
    };

    frame.render_widget(Paragraph::new(rdv_lines).block(rdv_block), chunks[3]);
}

/// Draw the Connectivity Matrix tab - N×N peer connectivity results.
fn draw_connectivity_matrix_tab(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Summary header
            Constraint::Min(10),   // Matrix table
        ])
        .split(area);

    // Summary header
    let total_peers = app.connection_history.len();
    let connected = app.connected_peers.len();
    let tested = app.connectivity_test.peer_results.len();

    let header_block = Block::default()
        .title(" CONNECTIVITY MATRIX ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let header_line = Line::from(vec![
        Span::raw("  Total Peers: "),
        Span::styled(
            format!("{}", total_peers),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  │  Connected: "),
        Span::styled(format!("{}", connected), Style::default().fg(Color::Green)),
        Span::raw("  │  Tested: "),
        Span::styled(format!("{}", tested), Style::default().fg(Color::Yellow)),
        Span::raw("  │  Press [T] to run connectivity test"),
    ]);

    frame.render_widget(
        Paragraph::new(vec![header_line]).block(header_block),
        chunks[0],
    );

    // Matrix table showing per-peer connectivity
    let matrix_block = Block::default()
        .title(" Per-Peer Connectivity (D=Direct, N=NAT, R=Relay) ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue));

    let header = Row::new(vec![
        Cell::from("Peer").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Status").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Out D4").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Out D6").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Out N").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Out R").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("In D4").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("In D6").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("In N").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("In R").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("RTT").style(Style::default().add_modifier(Modifier::BOLD)),
    ])
    .height(1)
    .style(Style::default().fg(Color::White));

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

            // Helper for outcome cell - accepts MethodOutcome by value (it's Copy)
            let outcome_cell = |outcome: crate::tui::types::MethodOutcome| -> Cell {
                let (text, color) = match outcome {
                    crate::tui::types::MethodOutcome::Success => ("✓", Color::Green),
                    crate::tui::types::MethodOutcome::Failed => ("✗", Color::Red),
                    crate::tui::types::MethodOutcome::Unknown => ("·", Color::DarkGray),
                };
                Cell::from(text).style(Style::default().fg(color))
            };

            Row::new(vec![
                Cell::from(entry.short_id.clone()).style(Style::default().fg(status_color)),
                Cell::from(entry.status.emoji()).style(Style::default().fg(status_color)),
                outcome_cell(entry.outbound.direct_ipv4),  // Out D4
                outcome_cell(entry.outbound.direct_ipv6),  // Out D6
                outcome_cell(entry.outbound.nat_best()),   // Out N (best of v4/v6)
                outcome_cell(entry.outbound.relay_best()), // Out R (best of v4/v6)
                outcome_cell(entry.inbound.direct_ipv4),   // In D4
                outcome_cell(entry.inbound.direct_ipv6),   // In D6
                outcome_cell(entry.inbound.nat_best()),    // In N (best of v4/v6)
                outcome_cell(entry.inbound.relay_best()),  // In R (best of v4/v6)
                Cell::from(entry.rtt_string()).style(Style::default().fg(Color::Yellow)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(9), // Peer
            Constraint::Length(6), // Status
            Constraint::Length(6), // Out D4
            Constraint::Length(6), // Out D6
            Constraint::Length(6), // Out N
            Constraint::Length(6), // Out R
            Constraint::Length(6), // In D4
            Constraint::Length(6), // In D6
            Constraint::Length(6), // In N
            Constraint::Length(6), // In R
            Constraint::Min(6),    // RTT
        ],
    )
    .header(header)
    .block(matrix_block);

    frame.render_widget(table, chunks[1]);
}

/// Draw the Protocol Log tab - real-time message flow visualization.
fn draw_protocol_log_tab(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(format!(
            " PROTOCOL LOG ({} frames) - Real-time Message Flow ",
            app.protocol_frames.len()
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let mut lines: Vec<Line> = Vec::new();
    let now = std::time::Instant::now();
    let max_lines = (area.height as usize).saturating_sub(2);

    // Header line
    lines.push(Line::from(vec![
        Span::styled(
            " Time  ",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "Dir ",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "Peer     ",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "Frame Type   ",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "Details",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        ),
    ]));

    lines.push(Line::from(Span::styled(
        "─".repeat(80),
        Style::default().fg(Color::DarkGray),
    )));

    for pf in app
        .protocol_frames
        .iter()
        .rev()
        .take(max_lines.saturating_sub(2))
    {
        let age = now.duration_since(pf.timestamp);
        let age_str = if age.as_secs() < 60 {
            format!("{:>3}s", age.as_secs())
        } else if age.as_secs() < 3600 {
            format!("{:>2}m{:02}s", age.as_secs() / 60, age.as_secs() % 60)
        } else {
            format!(
                "{:>2}h{:02}m",
                age.as_secs() / 3600,
                (age.as_secs() % 3600) / 60
            )
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
            "ADD_ADDRESS" => Color::Blue,
            "PUNCH_ME_NOW" => Color::Yellow,
            "OBSERVED_ADDRESS" => Color::Magenta,
            _ => Color::White,
        };

        let detail = pf.context.as_deref().unwrap_or("");

        lines.push(Line::from(vec![
            Span::styled(
                format!(" {} ", age_str),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(format!(" {} ", dir_arrow), Style::default().fg(dir_color)),
            Span::styled(
                format!("{:<8} ", peer_short),
                Style::default().fg(Color::White),
            ),
            Span::styled(
                format!("{:<12} ", &pf.frame_type),
                Style::default().fg(frame_color),
            ),
            Span::styled(detail, Style::default().fg(Color::DarkGray)),
        ]));
    }

    if app.protocol_frames.is_empty() {
        lines.push(Line::from(Span::styled(
            "  Waiting for protocol frames...",
            Style::default().fg(Color::DarkGray),
        )));
    }

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

/// Format bytes into short string.
fn format_bytes_short(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1}G", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1}M", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1}K", bytes as f64 / KB as f64)
    } else {
        format!("{}B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_draw_functions_exist() {
        let _ = draw as fn(&mut Frame, &mut App);
        let _ = draw_tab_bar as fn(&mut Frame, &App, Rect);
        let _ = draw_overview_tab as fn(&mut Frame, &mut App, Rect);
        let _ = draw_gossip_health_tab as fn(&mut Frame, &App, Rect);
        let _ = draw_connectivity_matrix_tab as fn(&mut Frame, &App, Rect);
        let _ = draw_protocol_log_tab as fn(&mut Frame, &App, Rect);
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
