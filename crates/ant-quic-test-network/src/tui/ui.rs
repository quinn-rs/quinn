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
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Frame,
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
            Constraint::Length(8), // Enhanced: Protocol Frame + Cache Health + NAT Analytics
            Constraint::Length(6), // Network Stats + Geographic Distribution
            Constraint::Length(3), // Messages (errors/info)
            Constraint::Length(3), // Footer
        ])
        .split(frame.area());

    draw_header(frame, chunks[0]);
    draw_connection_overview(frame, app, chunks[1]);
    draw_node_info(frame, app, chunks[2]);
    draw_peers(frame, app, chunks[3]);
    draw_enhanced_analytics(frame, app, chunks[4]);
    draw_stats_and_geography(frame, app, chunks[5]);
    draw_messages(frame, app, chunks[6]);
    draw_footer(frame, app, chunks[7]);
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
        Span::styled("█".repeat(direct_bar), Style::default().fg(COLOR_DIRECT)),
        Span::raw("  "),
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

    // Table header with enhanced columns
    let header = Row::new(vec![
        Cell::from("").style(Style::default().add_modifier(Modifier::BOLD)), // Traffic light
        Cell::from("Peer").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Location").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Dir").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("NAT").style(Style::default().add_modifier(Modifier::BOLD)), // NAT verification status
        Cell::from("Phase").style(Style::default().add_modifier(Modifier::BOLD)), // NAT traversal phase
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

            // Enhanced traffic indicators with type differentiation
            let protocol_indicator = if peer.protocol_tx || peer.protocol_rx {
                "🔄"
            } else {
                "  "
            };
            let data_indicator = if peer.data_tx || peer.data_rx {
                "📦"
            } else {
                "  "
            };
            let traffic_indicator = if peer.tx_active || peer.rx_active {
                "◀━▶"
            } else {
                "   "
            };

            let traffic_spans = [
                Span::styled(protocol_indicator, Style::default().fg(Color::Blue)),
                Span::styled(data_indicator, Style::default().fg(Color::Green)),
                Span::styled(
                    traffic_indicator,
                    Style::default()
                        .fg(Color::Magenta)
                        .add_modifier(Modifier::BOLD),
                ),
            ];

            let traffic_style = if peer.tx_active
                || peer.rx_active
                || peer.protocol_tx
                || peer.protocol_rx
                || peer.data_tx
                || peer.data_rx
            {
                Style::default().add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::DarkGray)
            };

            // Quality bar based on RTT
            let quality = peer.quality.as_bar();

            // NAT verification status: shows bidirectional connectivity
            // ✓✓ = full bidirectional (both outbound and inbound verified)
            // ✓• = outbound only (we connected to them)
            // •✓ = inbound only (they connected to us)
            // •• = neither verified yet
            let (nat_status, nat_style) = match (peer.outbound_verified, peer.inbound_verified) {
                (true, true) => (
                    "✓✓",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                (true, false) => ("✓•", Style::default().fg(Color::Cyan)),
                (false, true) => ("•✓", Style::default().fg(Color::Yellow)),
                (false, false) => ("••", Style::default().fg(Color::DarkGray)),
            };

            // NAT traversal phase with emoji
            let phase_display =
                format!("{}{}", peer.nat_phase.emoji(), peer.nat_phase.color_name());
            let phase_style = Style::default().fg(match peer.nat_phase.color_name() {
                "blue" => Color::Blue,
                "yellow" => Color::Yellow,
                "orange" => Color::LightYellow,
                "green" => Color::Green,
                "red" => Color::Red,
                _ => Color::White,
            });

            Row::new(vec![
                Cell::from(method_indicator).style(Style::default().fg(row_color)),
                Cell::from(peer.short_id.clone()).style(Style::default().fg(row_color)),
                Cell::from(location),
                Cell::from(direction_str).style(direction_style),
                Cell::from(nat_status).style(nat_style),
                Cell::from(phase_display).style(phase_style),
                Cell::from(
                    traffic_spans
                        .iter()
                        .map(|s| s.content.clone())
                        .collect::<String>(),
                )
                .style(traffic_style),
                Cell::from(peer.rtt_string()),
                Cell::from(quality).style(Style::default().fg(row_color)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(2),  // Traffic light emoji
            Constraint::Length(9),  // Peer ID (reduced)
            Constraint::Length(8),  // Location
            Constraint::Length(4),  // Direction (Out/In)
            Constraint::Length(3),  // NAT verification status
            Constraint::Length(10), // NAT traversal phase
            Constraint::Length(5),  // Traffic indicator
            Constraint::Length(7),  // RTT
            Constraint::Min(6),     // Quality bar (●●●●●●)
        ],
    )
    .header(header)
    .block(block)
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    frame.render_widget(table, area);
}

fn draw_stats(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(" ENHANCED NETWORK STATISTICS ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta));

    // Phase 2: NAT type distribution in connected peers
    let mut nat_distribution = std::collections::HashMap::new();
    for peer in app.connected_peers.values() {
        *nat_distribution
            .entry(format!("{}", peer.method))
            .or_insert(0) += 1;
    }

    // SWIM liveness from saorsa-gossip
    let alive = app.stats.swim_alive;
    let suspect = app.stats.swim_suspect;
    let dead = app.stats.swim_dead;
    let total_known = alive + suspect + dead;

    // Cache effectiveness metrics
    let cache_effectiveness = if let Some(ref health) = app.cache_health {
        format!("{:.1}%", health.cache_hit_rate())
    } else {
        "N/A".to_string()
    };

    let cache_color = if let Some(ref health) = app.cache_health {
        let rate = health.cache_hit_rate();
        if rate >= 80.0 {
            Color::Green
        } else if rate >= 60.0 {
            Color::Yellow
        } else {
            Color::Red
        }
    } else {
        Color::DarkGray
    };

    let line1 = Line::from(vec![
        Span::raw("  SWIM: "),
        Span::styled(format!("{}", alive), Style::default().fg(Color::Green)),
        Span::styled(" alive ", Style::default().fg(Color::DarkGray)),
        Span::styled(format!("{}", suspect), Style::default().fg(Color::Yellow)),
        Span::styled(" suspect ", Style::default().fg(Color::DarkGray)),
        Span::styled(format!("{}", dead), Style::default().fg(Color::Red)),
        Span::styled(" dead", Style::default().fg(Color::DarkGray)),
        Span::raw("  Cache: "),
        Span::styled(
            cache_effectiveness,
            Style::default()
                .fg(cache_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  Known: "),
        Span::styled(
            format!("{}", total_known),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
    ]);

    let success_rate = app.stats.success_rate();
    let success_color = if success_rate >= 90.0 {
        Color::Green
    } else if success_rate >= 70.0 {
        Color::Yellow
    } else {
        Color::Red
    };

    let line2 = Line::from(vec![
        Span::raw("  Protocol Eff: "),
        Span::styled(
            format!("{:.1}%", app.stats.protocol_efficiency()),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  Success: "),
        Span::styled(
            format!("{:.1}%", success_rate),
            Style::default()
                .fg(success_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  In/Out: "),
        Span::styled(
            format!(
                "{}/{}",
                app.stats.inbound_connections, app.stats.outbound_connections
            ),
            Style::default().fg(Color::White),
        ),
    ]);

    let line3 = Line::from(vec![
        Span::raw("  Geo Diversity: "),
        Span::styled(
            if let Some(ref geo) = app.geographic_distribution {
                if geo.is_diverse() {
                    "✓"
                } else {
                    "✗"
                }
            } else {
                "?"
            },
            Style::default().fg(Color::Green),
        ),
        Span::raw("  Packets: "),
        Span::styled(
            format!(
                "{}↑ {}↓",
                app.stats.packets_sent, app.stats.packets_received
            ),
            Style::default().fg(Color::White),
        ),
        Span::raw("  Uptime: "),
        Span::styled(
            app.stats.uptime(),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
    ]);

    let text = vec![line1, line2, line3];
    let paragraph = Paragraph::new(text).block(block);
    frame.render_widget(paragraph, area);
}

// Helper method for protocol efficiency calculation
trait NetworkStatsExt {
    fn protocol_efficiency(&self) -> f64;
}

impl NetworkStatsExt for crate::tui::types::NetworkStatistics {
    fn protocol_efficiency(&self) -> f64 {
        if self.bytes_sent == 0 && self.bytes_received == 0 {
            0.0
        } else {
            // Calculate efficiency based on success rates and connection methods
            let total_connections = self.connection_attempts;
            if total_connections == 0 {
                return 0.0;
            }

            let success_weight = 0.6;
            let method_weight = 0.4;

            let success_bonus = (self.success_rate() / 100.0) * success_weight;

            // Direct connections are most efficient, relayed are least
            let method_score = if total_connections > 0 {
                let direct_ratio = self.direct_connections as f64 / total_connections as f64;
                let hole_punched_ratio =
                    self.hole_punched_connections as f64 / total_connections as f64;
                let relayed_ratio = self.relayed_connections as f64 / total_connections as f64;

                (direct_ratio * 1.0 + hole_punched_ratio * 0.8 + relayed_ratio * 0.5)
                    * method_weight
            } else {
                0.0
            };

            (success_bonus + method_score) * 100.0
        }
    }
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

/// Draw enhanced analytics panel combining cache health, NAT analytics, and protocol frames
fn draw_enhanced_analytics(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    draw_cache_health_panel(frame, app, chunks[0]);
    draw_nat_analytics_panel(frame, app, chunks[1]);
}

fn draw_cache_health_panel(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(" BOOTSTRAP CACHE HEALTH ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta));

    if let Some(ref health) = app.cache_health {
        let validity = health.validity_percentage();
        let validity_color = if validity >= 80.0 {
            Color::Green
        } else if validity >= 60.0 {
            Color::Yellow
        } else {
            Color::Red
        };

        let hit_rate = health.cache_hit_rate();
        let hit_rate_color = if hit_rate >= 80.0 {
            Color::Green
        } else if hit_rate >= 60.0 {
            Color::Yellow
        } else {
            Color::Red
        };

        let freshness = health.freshness_percentage();
        let freshness_color = if freshness >= 70.0 {
            Color::Green
        } else if freshness >= 40.0 {
            Color::Yellow
        } else {
            Color::Red
        };

        let health_score = health.health_score();
        let health_color = if health_score >= 0.8 {
            Color::Green
        } else if health_score >= 0.6 {
            Color::Yellow
        } else {
            Color::Red
        };

        let validity_bar = "█".repeat((validity / 10.0) as usize);
        let validity_bg = "░".repeat(10usize.saturating_sub((validity / 10.0) as usize));

        let lines = vec![
            Line::from(vec![
                Span::raw("  Total: "),
                Span::styled(
                    format!("{}", health.total_peers),
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("  Valid: "),
                Span::styled(
                    format!("{:.1}%", validity),
                    Style::default()
                        .fg(validity_color)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("  Hit Rate: "),
                Span::styled(
                    format!("{:.1}%", hit_rate),
                    Style::default()
                        .fg(hit_rate_color)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("  Score: "),
                Span::styled(
                    format!("{:.2}", health_score),
                    Style::default()
                        .fg(health_color)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::raw("  Fresh: "),
                Span::styled(
                    format!("{:.1}%", freshness),
                    Style::default()
                        .fg(freshness_color)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("  Public: "),
                Span::styled(
                    format!("{:.1}%", health.public_percentage()),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("  Private: "),
                Span::styled(
                    format!("{:.1}%", health.private_percentage()),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::raw("  Validity: ["),
                Span::styled(validity_bg, Style::default().fg(Color::DarkGray)),
                Span::styled(validity_bar, Style::default().fg(validity_color)),
                Span::raw("]  "),
                Span::styled(
                    if health.fresh_peers > health.stale_peers {
                        "🟢 Fresh > Stale"
                    } else if health.fresh_peers == health.stale_peers {
                        "🟡 Fresh = Stale"
                    } else {
                        "🔴 Fresh < Stale"
                    },
                    Style::default().add_modifier(Modifier::BOLD),
                ),
            ]),
        ];

        let paragraph = Paragraph::new(lines).block(block);
        frame.render_widget(paragraph, area);
    } else {
        let paragraph = Paragraph::new("  No cache health data available").block(block);
        frame.render_widget(paragraph, area);
    }
}

fn draw_nat_analytics_panel(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(" NAT TYPE SUCCESS RATE ANALYTICS ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));

    if let Some(ref analytics) = app.nat_analytics {
        fn success_bar(rate: f64) -> String {
            let filled = (rate / 10.0) as usize;
            let empty = 10usize.saturating_sub(filled);
            let bar_char = if rate >= 90.0 {
                "█"
            } else if rate >= 70.0 {
                "▓"
            } else if rate >= 50.0 {
                "▒"
            } else {
                "░"
            };
            format!("{}{}", bar_char.repeat(filled), "░".repeat(empty))
        }

        let fc_rate = analytics.full_cone.success_rate();
        let rc_rate = analytics.restricted_cone.success_rate();
        let pr_rate = analytics.port_restricted.success_rate();
        let sym_rate = analytics.symmetric.success_rate();
        let cgnat_rate = analytics.cgnat.success_rate();

        let lines = vec![
            Line::from(vec![
                Span::styled("FullCone :", Style::default().fg(Color::Green)),
                Span::raw(" "),
                Span::styled(
                    format!("{:5.1}%", fc_rate),
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" "),
                Span::styled(success_bar(fc_rate), Style::default().fg(Color::Green)),
            ]),
            Line::from(vec![
                Span::styled("RestCone :", Style::default().fg(Color::Blue)),
                Span::raw(" "),
                Span::styled(
                    format!("{:5.1}%", rc_rate),
                    Style::default()
                        .fg(Color::Blue)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" "),
                Span::styled(success_bar(rc_rate), Style::default().fg(Color::Blue)),
            ]),
            Line::from(vec![
                Span::styled("PortRest :", Style::default().fg(Color::Cyan)),
                Span::raw(" "),
                Span::styled(
                    format!("{:5.1}%", pr_rate),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" "),
                Span::styled(success_bar(pr_rate), Style::default().fg(Color::Cyan)),
            ]),
            Line::from(vec![
                Span::styled("Symmetric:", Style::default().fg(Color::LightYellow)),
                Span::raw(" "),
                Span::styled(
                    format!("{:5.1}%", sym_rate),
                    Style::default()
                        .fg(Color::LightYellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" "),
                Span::styled(
                    success_bar(sym_rate),
                    Style::default().fg(Color::LightYellow),
                ),
            ]),
            Line::from(vec![
                Span::styled("CGNAT    :", Style::default().fg(Color::Red)),
                Span::raw(" "),
                Span::styled(
                    format!("{:5.1}%", cgnat_rate),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Span::raw(" "),
                Span::styled(success_bar(cgnat_rate), Style::default().fg(Color::Red)),
            ]),
            Line::from(vec![
                Span::raw("  Overall: "),
                Span::styled(
                    format!("{:.1}%", analytics.overall_success_rate()),
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("  Total: "),
                Span::styled(
                    format!("{}", analytics.total_attempts()),
                    Style::default().fg(Color::Cyan),
                ),
                Span::raw(" attempts"),
            ]),
        ];

        let paragraph = Paragraph::new(lines).block(block);
        frame.render_widget(paragraph, area);
    } else {
        let paragraph = Paragraph::new("  No NAT analytics data available").block(block);
        frame.render_widget(paragraph, area);
    }
}

/// Draw stats and geographic distribution panel
fn draw_stats_and_geography(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    draw_stats(frame, app, chunks[0]);
    draw_geographic_distribution(frame, app, chunks[1]);
}

/// Draw geographic distribution panel showing network diversity
fn draw_geographic_distribution(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(" GEOGRAPHIC DIVERSITY ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green));

    if let Some(ref distribution) = app.geographic_distribution {
        let top_regions = distribution.top_regions(5);
        let diversity_score = distribution.diversity_score();

        let diversity_color = if diversity_score >= 0.8 {
            Color::Green
        } else if diversity_score >= 0.5 {
            Color::Yellow
        } else {
            Color::Red
        };

        let mut lines = vec![Line::from(vec![
            Span::raw("  Regions: "),
            Span::styled(
                format!("{}", distribution.regions.len()),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(
                "Diverse",
                Style::default()
                    .fg(if distribution.is_diverse() {
                        Color::Green
                    } else {
                        Color::Yellow
                    })
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  Score: "),
            Span::styled(
                format!("{:.2}", diversity_score),
                Style::default()
                    .fg(diversity_color)
                    .add_modifier(Modifier::BOLD),
            ),
        ])];

        for (region, count) in top_regions {
            let flag = country_flag(region);
            let percentage = distribution.region_percentage(region);
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(flag, Style::default().fg(Color::White)),
                Span::raw(" "),
                Span::styled(region, Style::default().fg(Color::Cyan)),
                Span::raw(": "),
                Span::styled(
                    format!("{}", count),
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" ("),
                Span::styled(
                    format!("{:.1}%", percentage),
                    Style::default().fg(Color::Yellow),
                ),
                Span::raw(")"),
            ]));
        }

        let paragraph = Paragraph::new(lines).block(block);
        frame.render_widget(paragraph, area);
    } else {
        let paragraph = Paragraph::new("  No geographic data available").block(block);
        frame.render_widget(paragraph, area);
    }
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
