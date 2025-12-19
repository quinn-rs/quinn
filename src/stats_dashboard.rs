// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Connection Statistics Dashboard
//!
//! This module provides a real-time dashboard for monitoring connection
//! statistics, NAT traversal performance, and network health metrics.

use crate::{
    nat_traversal_api::{NatTraversalEvent, NatTraversalStatistics, PeerId},
    terminal_ui,
};

/// Node statistics for dashboard display
#[derive(Debug, Clone, Default)]
pub struct NodeStats {
    /// Number of currently active connections
    pub active_connections: usize,
    /// Total number of successful connections since startup
    pub successful_connections: usize,
    /// Total number of failed connections since startup
    pub failed_connections: usize,
}
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

/// Box drawing style
#[derive(Debug, Clone, Copy)]
pub enum BoxStyle {
    /// Single line borders
    Single,
    /// Double line borders
    Double,
    /// Rounded corners
    Rounded,
}

/// Draw a box with title and content
fn draw_box(title: &str, content: &str, _style: BoxStyle, width: usize) -> String {
    let mut result = String::new();

    // Top border with title
    let padding = width.saturating_sub(title.len() + 4);
    let left_pad = padding / 2;
    let right_pad = padding - left_pad;

    result.push_str(&format!(
        "╭{} {} {}╮\n",
        "─".repeat(left_pad),
        title,
        "─".repeat(right_pad)
    ));

    // Content lines
    for line in content.lines() {
        let line_len = line.chars().count();
        let padding = width.saturating_sub(line_len + 2);
        result.push_str(&format!("│ {}{} │\n", line, " ".repeat(padding)));
    }

    // Bottom border
    result.push_str(&format!("╰{}╯", "─".repeat(width - 2)));

    result
}

/// Dashboard configuration
#[derive(Debug, Clone)]
pub struct DashboardConfig {
    /// Update interval for the dashboard
    pub update_interval: Duration,
    /// Maximum number of historical data points
    pub history_size: usize,
    /// Enable detailed connection tracking
    pub detailed_tracking: bool,
    /// Enable performance graphs
    pub show_graphs: bool,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            update_interval: Duration::from_secs(1),
            history_size: 60, // 1 minute of second-by-second data
            detailed_tracking: true,
            show_graphs: true,
        }
    }
}

/// Connection information
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Peer identifier
    pub peer_id: PeerId,
    /// Remote socket address
    pub remote_address: SocketAddr,
    /// Timestamp when the connection was established
    pub connected_at: Instant,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Timestamp of last activity
    pub last_activity: Instant,
    /// Measured round trip time
    pub rtt: Option<Duration>,
    /// Packet loss ratio [0.0-1.0]
    pub packet_loss: f64,
    /// NAT type inferred for the peer
    pub nat_type: String,
}

/// Historical data point
#[derive(Debug, Clone)]
struct DataPoint {
    #[allow(dead_code)]
    timestamp: Instant,
    active_connections: usize,
    nat_success_rate: f64,
    #[allow(dead_code)]
    bytes_per_second: u64,
    #[allow(dead_code)]
    avg_rtt: Duration,
}

/// Statistics dashboard
pub struct StatsDashboard {
    config: DashboardConfig,
    /// Current node statistics
    node_stats: Arc<RwLock<NodeStats>>,
    /// NAT traversal statistics
    nat_stats: Arc<RwLock<NatTraversalStatistics>>,
    /// Active connections
    connections: Arc<RwLock<HashMap<PeerId, ConnectionInfo>>>,
    /// Historical data
    #[allow(dead_code)]
    history: Arc<RwLock<VecDeque<DataPoint>>>,
    /// Dashboard start time
    start_time: Instant,
    /// Last update time
    last_update: Arc<RwLock<Instant>>,
}

impl StatsDashboard {
    /// Create new statistics dashboard
    pub fn new(config: DashboardConfig) -> Self {
        let history_size = config.history_size;
        Self {
            config,
            node_stats: Arc::new(RwLock::new(NodeStats::default())),
            nat_stats: Arc::new(RwLock::new(NatTraversalStatistics::default())),
            connections: Arc::new(RwLock::new(HashMap::new())),
            history: Arc::new(RwLock::new(VecDeque::with_capacity(history_size))),
            start_time: Instant::now(),
            last_update: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Get the dashboard configuration
    pub fn config(&self) -> &DashboardConfig {
        &self.config
    }

    /// Update node statistics
    pub async fn update_node_stats(&self, stats: NodeStats) {
        *self.node_stats.write().await = stats;
    }

    /// Update NAT traversal statistics
    pub async fn update_nat_stats(&self, stats: NatTraversalStatistics) {
        *self.nat_stats.write().await = stats;
    }

    /// Handle NAT traversal event
    pub async fn handle_nat_event(&self, event: &NatTraversalEvent) {
        match event {
            NatTraversalEvent::ConnectionEstablished {
                peer_id,
                remote_address,
            } => {
                let mut connections = self.connections.write().await;
                connections.insert(
                    *peer_id,
                    ConnectionInfo {
                        peer_id: *peer_id,
                        remote_address: *remote_address,
                        connected_at: Instant::now(),
                        bytes_sent: 0,
                        bytes_received: 0,
                        last_activity: Instant::now(),
                        rtt: None,
                        packet_loss: 0.0,
                        nat_type: "Unknown".to_string(),
                    },
                );
            }
            NatTraversalEvent::TraversalFailed { peer_id, .. } => {
                let mut connections = self.connections.write().await;
                connections.remove(peer_id);
            }
            _ => {}
        }
    }

    /// Update connection metrics
    pub async fn update_connection_metrics(
        &self,
        peer_id: PeerId,
        bytes_sent: u64,
        bytes_received: u64,
        rtt: Option<Duration>,
    ) {
        let mut connections = self.connections.write().await;
        if let Some(conn) = connections.get_mut(&peer_id) {
            conn.bytes_sent = bytes_sent;
            conn.bytes_received = bytes_received;
            conn.rtt = rtt;
            conn.last_activity = Instant::now();
        }
    }

    /// Record historical data point
    async fn record_data_point(&self) {
        let _node_stats = self.node_stats.read().await;
        let nat_stats = self.nat_stats.read().await;
        let connections = self.connections.read().await;

        let success_rate = if nat_stats.total_attempts > 0 {
            nat_stats.successful_connections as f64 / nat_stats.total_attempts as f64
        } else {
            0.0
        };

        let total_bytes: u64 = connections
            .values()
            .map(|c| c.bytes_sent + c.bytes_received)
            .sum();

        let avg_rtt = if connections.is_empty() {
            Duration::from_millis(0)
        } else {
            let total_rtt: Duration = connections.values().filter_map(|c| c.rtt).sum();
            let count = connections.values().filter(|c| c.rtt.is_some()).count();
            if count > 0 {
                total_rtt / count as u32
            } else {
                Duration::from_millis(0)
            }
        };

        let data_point = DataPoint {
            timestamp: Instant::now(),
            active_connections: connections.len(),
            nat_success_rate: success_rate,
            bytes_per_second: total_bytes,
            avg_rtt,
        };

        let mut history = self.history.write().await;
        if history.len() >= self.config.history_size {
            history.pop_front();
        }
        history.push_back(data_point);
    }

    /// Render the dashboard
    pub async fn render(&self) -> String {
        // Record current data point
        self.record_data_point().await;

        let mut output = String::new();

        // Clear screen and move to top
        output.push_str("\x1B[2J\x1B[H");

        // Title
        output.push_str(&format!(
            "{}🚀 ant-quic Connection Statistics Dashboard\n\n{}",
            terminal_ui::colors::BOLD,
            terminal_ui::colors::RESET
        ));

        // System uptime
        let uptime = self.start_time.elapsed();
        output.push_str(&format!("⏱️  Uptime: {}\n\n", format_duration(uptime)));

        // Render sections
        output.push_str(&self.render_overview_section().await);
        output.push_str(&self.render_nat_section().await);
        output.push_str(&self.render_connections_section().await);

        if self.config.show_graphs {
            output.push_str(&self.render_graphs_section().await);
        }

        output.push_str(&self.render_footer().await);

        output
    }

    /// Render overview section
    async fn render_overview_section(&self) -> String {
        let node_stats = self.node_stats.read().await;
        let _connections = self.connections.read().await;

        let mut section = String::new();

        section.push_str(&draw_box(
            "📊 Overview",
            &format!(
                "Active Connections: {}\n\
                 Total Successful: {}\n\
                 Total Failed: {}\n\
                 Success Rate: {:.1}%",
                format!(
                    "{}{}{}",
                    terminal_ui::colors::GREEN,
                    node_stats.active_connections,
                    terminal_ui::colors::RESET
                ),
                node_stats.successful_connections,
                node_stats.failed_connections,
                if node_stats.successful_connections + node_stats.failed_connections > 0 {
                    (node_stats.successful_connections as f64
                        / (node_stats.successful_connections + node_stats.failed_connections)
                            as f64)
                        * 100.0
                } else {
                    0.0
                }
            ),
            BoxStyle::Single,
            50,
        ));

        section.push('\n');
        section
    }

    /// Render NAT traversal section
    async fn render_nat_section(&self) -> String {
        let nat_stats = self.nat_stats.read().await;

        let mut section = String::new();

        section.push_str(&draw_box(
            "🌐 NAT Traversal",
            &format!(
                "Total Attempts: {}\n\
                 Successful: {} ({:.1}%)\n\
                 Direct Connections: {}\n\
                 Relayed: {}\n\
                 Average Time: {:?}\n\
                 Active Sessions: {}",
                nat_stats.total_attempts,
                nat_stats.successful_connections,
                if nat_stats.total_attempts > 0 {
                    (nat_stats.successful_connections as f64 / nat_stats.total_attempts as f64)
                        * 100.0
                } else {
                    0.0
                },
                nat_stats.direct_connections,
                nat_stats.relayed_connections,
                nat_stats.average_coordination_time,
                nat_stats.active_sessions,
            ),
            BoxStyle::Single,
            50,
        ));

        section.push('\n');
        section
    }

    /// Render connections section
    async fn render_connections_section(&self) -> String {
        let connections = self.connections.read().await;

        let mut section = String::new();

        if connections.is_empty() {
            section.push_str(&draw_box(
                "🔗 Active Connections",
                "No active connections",
                BoxStyle::Single,
                50,
            ));
        } else {
            let mut content = String::new();
            for (i, (peer_id, conn)) in connections.iter().enumerate() {
                if i > 0 {
                    content.push_str("\n─────────────────────────────────────────────\n");
                }

                content.push_str(&format!(
                    "Peer: {}\n\
                     Address: {}\n\
                     Duration: {}\n\
                     Sent: {} | Received: {}\n\
                     RTT: {} | Loss: {:.1}%",
                    format!(
                        "{}{}{}",
                        terminal_ui::colors::DIM,
                        hex::encode(&peer_id.0[..8]),
                        terminal_ui::colors::RESET
                    ),
                    conn.remote_address,
                    format_duration(conn.connected_at.elapsed()),
                    format_bytes(conn.bytes_sent),
                    format_bytes(conn.bytes_received),
                    conn.rtt
                        .map(|d| format!("{d:?}"))
                        .unwrap_or_else(|| "N/A".to_string()),
                    conn.packet_loss * 100.0,
                ));
            }

            section.push_str(&draw_box(
                &format!("🔗 Active Connections ({})", connections.len()),
                &content,
                BoxStyle::Single,
                50,
            ));
        }

        section.push('\n');
        section
    }

    /// Render graphs section
    async fn render_graphs_section(&self) -> String {
        let history = self.history.read().await;

        if history.len() < 2 {
            return String::new();
        }

        let mut section = String::new();

        // Connection count graph
        let conn_data: Vec<usize> = history.iter().map(|d| d.active_connections).collect();

        section.push_str(&draw_box(
            "📈 Connection History",
            &render_mini_graph(&conn_data, 20, 50),
            BoxStyle::Single,
            50,
        ));
        section.push('\n');

        // Success rate graph
        let success_data: Vec<f64> = history.iter().map(|d| d.nat_success_rate * 100.0).collect();

        section.push_str(&draw_box(
            "📈 NAT Success Rate %",
            &render_mini_graph_float(&success_data, 20, 50),
            BoxStyle::Single,
            50,
        ));
        section.push('\n');

        section
    }

    /// Render footer
    async fn render_footer(&self) -> String {
        let last_update = *self.last_update.read().await;

        format!(
            "\n{}\n{}",
            format!(
                "{}Last updated: {:?} ago{}",
                terminal_ui::colors::DIM,
                last_update.elapsed(),
                terminal_ui::colors::RESET
            ),
            format!(
                "{}Press Ctrl+C to exit{}",
                terminal_ui::colors::DIM,
                terminal_ui::colors::RESET
            ),
        )
    }
}

/// Format duration in human-readable format
fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs();
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}

/// Format bytes in human-readable format
fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    format!("{:.2} {}", size, UNITS[unit_index])
}

/// Render a simple ASCII graph
fn render_mini_graph(data: &[usize], height: usize, width: usize) -> String {
    if data.is_empty() {
        return "No data".to_string();
    }

    let max_val = *data.iter().max().unwrap_or(&1).max(&1) as f64;
    let step = data.len().max(1) / width.min(data.len()).max(1);

    let mut graph = vec![vec![' '; width]; height];

    for (i, chunk) in data.chunks(step).enumerate() {
        if i >= width {
            break;
        }

        let avg = chunk.iter().sum::<usize>() as f64 / chunk.len() as f64;
        let normalized = (avg / max_val * (height - 1) as f64).round() as usize;

        for y in 0..=normalized {
            let row = height - 1 - y;
            graph[row][i] = '█';
        }
    }

    let mut output = String::new();
    for row in graph {
        output.push_str(&row.iter().collect::<String>());
        output.push('\n');
    }

    output.push_str(&format!(
        "Max: {} | Latest: {}",
        data.iter().max().unwrap_or(&0),
        data.last().unwrap_or(&0)
    ));

    output
}

/// Render a simple ASCII graph for float values
fn render_mini_graph_float(data: &[f64], height: usize, width: usize) -> String {
    if data.is_empty() {
        return "No data".to_string();
    }

    let max_val = data
        .iter()
        .cloned()
        .fold(f64::NEG_INFINITY, f64::max)
        .max(1.0);
    let step = data.len().max(1) / width.min(data.len()).max(1);

    let mut graph = vec![vec![' '; width]; height];

    for (i, chunk) in data.chunks(step).enumerate() {
        if i >= width {
            break;
        }

        let avg = chunk.iter().sum::<f64>() / chunk.len() as f64;
        let normalized = (avg / max_val * (height - 1) as f64).round() as usize;

        for y in 0..=normalized {
            let row = height - 1 - y;
            graph[row][i] = '█';
        }
    }

    let mut output = String::new();
    for row in graph {
        output.push_str(&row.iter().collect::<String>());
        output.push('\n');
    }

    output.push_str(&format!(
        "Max: {:.1}% | Latest: {:.1}%",
        data.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
        data.last().unwrap_or(&0.0)
    ));

    output
}
