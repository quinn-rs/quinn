// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! E2E Dashboard - Real-time monitoring for ant-quic test nodes
//!
//! This dashboard receives metrics from test nodes via HTTP POST and displays
//! them in a web interface with real-time updates via WebSocket.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use clap::Parser;
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tracing::{debug, info};
use warp::ws::{Message, WebSocket};
use warp::Filter;

/// Dashboard CLI arguments
#[derive(Parser, Debug)]
#[command(name = "e2e-dashboard")]
#[command(author, version, about = "E2E test dashboard for ant-quic")]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value = "8080")]
    port: u16,

    /// Address to bind to
    #[arg(short, long, default_value = "0.0.0.0")]
    bind: String,
}

/// Peer information from a node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: String,
    pub remote_addr: String,
    pub connected_at: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connection_type: String,
}

/// Metrics report received from nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeMetricsReport {
    pub node_id: String,
    pub location: String,
    pub timestamp: u64,
    pub uptime_secs: u64,
    pub active_connections: usize,
    pub bytes_sent_total: u64,
    pub bytes_received_total: u64,
    pub current_throughput_mbps: f64,
    pub nat_traversal_successes: u64,
    pub nat_traversal_failures: u64,
    pub direct_connections: u64,
    pub relayed_connections: u64,
    pub data_chunks_sent: u64,
    pub data_chunks_verified: u64,
    pub data_verification_failures: u64,
    pub external_addresses: Vec<String>,
    pub connected_peers: Vec<PeerInfo>,
    pub local_addr: String,
}

/// Node state tracked by dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeState {
    pub node_id: String,
    pub location: String,
    pub last_seen: u64,
    pub first_seen: u64,
    pub uptime_secs: u64,
    pub active_connections: usize,
    pub bytes_sent_total: u64,
    pub bytes_received_total: u64,
    pub current_throughput_mbps: f64,
    pub nat_traversal_successes: u64,
    pub nat_traversal_failures: u64,
    pub direct_connections: u64,
    pub relayed_connections: u64,
    pub data_chunks_sent: u64,
    pub data_chunks_verified: u64,
    pub data_verification_failures: u64,
    pub external_addresses: Vec<String>,
    pub connected_peers: Vec<PeerInfo>,
    pub local_addr: String,
    pub status: NodeStatus,
}

/// Node status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum NodeStatus {
    Online,
    Warning,
    Offline,
}

/// Network summary statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSummary {
    pub total_nodes: usize,
    pub online_nodes: usize,
    pub total_connections: usize,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub average_throughput_mbps: f64,
    pub total_nat_successes: u64,
    pub total_nat_failures: u64,
    pub nat_success_rate: f64,
    pub total_chunks_verified: u64,
    pub total_verification_failures: u64,
    pub test_duration_secs: u64,
}

/// Connection between two nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub from_node: String,
    pub to_node: String,
    pub connection_type: String,
    pub bytes_transferred: u64,
}

/// Network topology for visualization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTopology {
    pub nodes: Vec<TopologyNode>,
    pub connections: Vec<ConnectionInfo>,
}

/// Node in topology view
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyNode {
    pub id: String,
    pub location: String,
    pub status: NodeStatus,
    pub connection_count: usize,
}

/// WebSocket update message
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WsUpdate {
    NodeUpdate { node: NodeState },
    NetworkSummary { summary: NetworkSummary },
    Topology { topology: NetworkTopology },
}

/// Dashboard application state
pub struct DashboardState {
    nodes: DashMap<String, NodeState>,
    start_time: Instant,
    ws_tx: broadcast::Sender<WsUpdate>,
}

impl DashboardState {
    pub fn new() -> Self {
        let (ws_tx, _) = broadcast::channel(100);
        Self {
            nodes: DashMap::new(),
            start_time: Instant::now(),
            ws_tx,
        }
    }

    /// Update node metrics from a report
    pub fn update_node(&self, report: NodeMetricsReport) {
        let now = now_timestamp();
        let is_new = !self.nodes.contains_key(&report.node_id);

        let state = NodeState {
            node_id: report.node_id.clone(),
            location: report.location,
            last_seen: now,
            first_seen: self
                .nodes
                .get(&report.node_id)
                .map(|n| n.first_seen)
                .unwrap_or(now),
            uptime_secs: report.uptime_secs,
            active_connections: report.active_connections,
            bytes_sent_total: report.bytes_sent_total,
            bytes_received_total: report.bytes_received_total,
            current_throughput_mbps: report.current_throughput_mbps,
            nat_traversal_successes: report.nat_traversal_successes,
            nat_traversal_failures: report.nat_traversal_failures,
            direct_connections: report.direct_connections,
            relayed_connections: report.relayed_connections,
            data_chunks_sent: report.data_chunks_sent,
            data_chunks_verified: report.data_chunks_verified,
            data_verification_failures: report.data_verification_failures,
            external_addresses: report.external_addresses,
            connected_peers: report.connected_peers,
            local_addr: report.local_addr,
            status: NodeStatus::Online,
        };

        self.nodes.insert(report.node_id.clone(), state.clone());

        // Broadcast update to WebSocket clients
        let _ = self.ws_tx.send(WsUpdate::NodeUpdate { node: state });
        let _ = self
            .ws_tx
            .send(WsUpdate::NetworkSummary { summary: self.network_summary() });
        let _ = self.ws_tx.send(WsUpdate::Topology { topology: self.topology() });

        if is_new {
            info!("New node registered: {}", report.node_id);
        }
    }

    /// Get all nodes
    pub fn all_nodes(&self) -> Vec<NodeState> {
        self.nodes.iter().map(|r| r.value().clone()).collect()
    }

    /// Get a specific node
    pub fn get_node(&self, id: &str) -> Option<NodeState> {
        self.nodes.get(id).map(|r| r.value().clone())
    }

    /// Calculate network summary
    pub fn network_summary(&self) -> NetworkSummary {
        let nodes: Vec<_> = self.nodes.iter().map(|r| r.value().clone()).collect();
        let online_nodes = nodes
            .iter()
            .filter(|n| n.status == NodeStatus::Online)
            .count();
        let total_connections: usize = nodes.iter().map(|n| n.active_connections).sum();
        let total_bytes_sent: u64 = nodes.iter().map(|n| n.bytes_sent_total).sum();
        let total_bytes_received: u64 = nodes.iter().map(|n| n.bytes_received_total).sum();
        let total_throughput: f64 = nodes.iter().map(|n| n.current_throughput_mbps).sum();
        let total_nat_successes: u64 = nodes.iter().map(|n| n.nat_traversal_successes).sum();
        let total_nat_failures: u64 = nodes.iter().map(|n| n.nat_traversal_failures).sum();
        let total_chunks_verified: u64 = nodes.iter().map(|n| n.data_chunks_verified).sum();
        let total_verification_failures: u64 =
            nodes.iter().map(|n| n.data_verification_failures).sum();

        let nat_success_rate = if total_nat_successes + total_nat_failures > 0 {
            total_nat_successes as f64 / (total_nat_successes + total_nat_failures) as f64 * 100.0
        } else {
            100.0
        };

        NetworkSummary {
            total_nodes: nodes.len(),
            online_nodes,
            total_connections,
            total_bytes_sent,
            total_bytes_received,
            average_throughput_mbps: if online_nodes > 0 {
                total_throughput / online_nodes as f64
            } else {
                0.0
            },
            total_nat_successes,
            total_nat_failures,
            nat_success_rate,
            total_chunks_verified,
            total_verification_failures,
            test_duration_secs: self.start_time.elapsed().as_secs(),
        }
    }

    /// Get network topology
    pub fn topology(&self) -> NetworkTopology {
        let nodes: Vec<_> = self.nodes.iter().map(|r| r.value().clone()).collect();

        let topology_nodes: Vec<TopologyNode> = nodes
            .iter()
            .map(|n| TopologyNode {
                id: n.node_id.clone(),
                location: n.location.clone(),
                status: n.status,
                connection_count: n.active_connections,
            })
            .collect();

        // Extract connections from peer info
        let mut connections = Vec::new();
        for node in &nodes {
            for peer in &node.connected_peers {
                connections.push(ConnectionInfo {
                    from_node: node.node_id.clone(),
                    to_node: peer.peer_id.clone(),
                    connection_type: peer.connection_type.clone(),
                    bytes_transferred: peer.bytes_sent + peer.bytes_received,
                });
            }
        }

        NetworkTopology {
            nodes: topology_nodes,
            connections,
        }
    }

    /// Subscribe to WebSocket updates
    pub fn subscribe(&self) -> broadcast::Receiver<WsUpdate> {
        self.ws_tx.subscribe()
    }
}

impl Default for DashboardState {
    fn default() -> Self {
        Self::new()
    }
}

fn now_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Handle WebSocket connection
async fn handle_websocket(ws: WebSocket, state: Arc<DashboardState>) {
    let (mut tx, mut rx) = ws.split();
    let mut updates = state.subscribe();

    // Send initial state
    let initial_summary = state.network_summary();
    let initial_topology = state.topology();
    let initial_nodes = state.all_nodes();

    if let Ok(msg) = serde_json::to_string(&WsUpdate::NetworkSummary { summary: initial_summary }) {
        let _ = tx.send(Message::text(msg)).await;
    }
    if let Ok(msg) = serde_json::to_string(&WsUpdate::Topology { topology: initial_topology }) {
        let _ = tx.send(Message::text(msg)).await;
    }
    for node in initial_nodes {
        if let Ok(msg) = serde_json::to_string(&WsUpdate::NodeUpdate { node }) {
            let _ = tx.send(Message::text(msg)).await;
        }
    }

    // Forward updates to WebSocket
    let forward_task = tokio::spawn(async move {
        while let Ok(update) = updates.recv().await {
            if let Ok(msg) = serde_json::to_string(&update) {
                if tx.send(Message::text(msg)).await.is_err() {
                    break;
                }
            }
        }
    });

    // Keep connection alive
    while let Some(result) = rx.next().await {
        match result {
            Ok(msg) => {
                if msg.is_close() {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    forward_task.abort();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter("e2e_dashboard=info")
        .init();

    let state = Arc::new(DashboardState::new());

    // API routes
    let state_metrics = state.clone();
    let metrics_route = warp::path!("api" / "metrics")
        .and(warp::post())
        .and(warp::body::json())
        .map(move |report: NodeMetricsReport| {
            debug!("Received metrics from node: {}", report.node_id);
            state_metrics.update_node(report);
            warp::reply::json(&serde_json::json!({"status": "ok"}))
        });

    let state_nodes = state.clone();
    let nodes_route = warp::path!("api" / "nodes")
        .and(warp::get())
        .map(move || warp::reply::json(&state_nodes.all_nodes()));

    let state_node = state.clone();
    let node_route = warp::path!("api" / "nodes" / String)
        .and(warp::get())
        .map(move |id: String| match state_node.get_node(&id) {
            Some(node) => warp::reply::with_status(
                warp::reply::json(&node),
                warp::http::StatusCode::OK,
            ),
            None => warp::reply::with_status(
                warp::reply::json(&serde_json::json!({"error": "Node not found"})),
                warp::http::StatusCode::NOT_FOUND,
            ),
        });

    let state_summary = state.clone();
    let summary_route = warp::path!("api" / "network" / "summary")
        .and(warp::get())
        .map(move || warp::reply::json(&state_summary.network_summary()));

    let state_topology = state.clone();
    let topology_route = warp::path!("api" / "network" / "topology")
        .and(warp::get())
        .map(move || warp::reply::json(&state_topology.topology()));

    let state_ws = state.clone();
    let ws_route = warp::path!("ws" / "live")
        .and(warp::ws())
        .map(move |ws: warp::ws::Ws| {
            let state = state_ws.clone();
            ws.on_upgrade(move |socket| handle_websocket(socket, state))
        });

    // Static files
    let static_route = warp::path("static").and(warp::fs::dir("static"));

    // Dashboard HTML
    let index_route = warp::path::end().map(|| {
        warp::reply::html(DASHBOARD_HTML)
    });

    let routes = metrics_route
        .or(nodes_route)
        .or(node_route)
        .or(summary_route)
        .or(topology_route)
        .or(ws_route)
        .or(static_route)
        .or(index_route)
        .with(warp::log("e2e_dashboard"));

    let addr: SocketAddr = format!("{}:{}", args.bind, args.port).parse()?;

    info!("═══════════════════════════════════════════════════════════════");
    info!("                E2E DASHBOARD SERVER");
    info!("═══════════════════════════════════════════════════════════════");
    info!("Listening on: http://{}", addr);
    info!("WebSocket: ws://{}/ws/live", addr);
    info!("API endpoints:");
    info!("  POST /api/metrics       - Receive node metrics");
    info!("  GET  /api/nodes         - List all nodes");
    info!("  GET  /api/nodes/:id     - Get specific node");
    info!("  GET  /api/network/summary - Network summary");
    info!("  GET  /api/network/topology - Network topology");
    info!("═══════════════════════════════════════════════════════════════");

    warp::serve(routes).run(addr).await;

    Ok(())
}

/// Embedded dashboard HTML
const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ant-quic E2E Dashboard</title>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent-green: #3fb950;
            --accent-yellow: #d29922;
            --accent-red: #f85149;
            --accent-blue: #58a6ff;
            --border-color: #30363d;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
        }

        .header {
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            padding: 16px 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .header h1 {
            font-size: 20px;
            font-weight: 600;
        }

        .header .status {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .status-indicator {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: var(--accent-green);
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 24px;
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }

        .card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px;
        }

        .card h3 {
            font-size: 14px;
            font-weight: 500;
            color: var(--text-secondary);
            margin-bottom: 8px;
        }

        .card .value {
            font-size: 32px;
            font-weight: 600;
        }

        .card .unit {
            font-size: 14px;
            color: var(--text-secondary);
        }

        .card.success .value { color: var(--accent-green); }
        .card.warning .value { color: var(--accent-yellow); }
        .card.error .value { color: var(--accent-red); }
        .card.info .value { color: var(--accent-blue); }

        .nodes-table {
            width: 100%;
            border-collapse: collapse;
        }

        .nodes-table th,
        .nodes-table td {
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }

        .nodes-table th {
            background: var(--bg-tertiary);
            font-weight: 500;
            font-size: 12px;
            text-transform: uppercase;
            color: var(--text-secondary);
        }

        .nodes-table tr:hover {
            background: var(--bg-tertiary);
        }

        .status-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 500;
        }

        .status-badge.online {
            background: rgba(63, 185, 80, 0.2);
            color: var(--accent-green);
        }

        .status-badge.warning {
            background: rgba(210, 153, 34, 0.2);
            color: var(--accent-yellow);
        }

        .status-badge.offline {
            background: rgba(248, 81, 73, 0.2);
            color: var(--accent-red);
        }

        .section {
            margin-bottom: 32px;
        }

        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
        }

        .section-header h2 {
            font-size: 16px;
            font-weight: 600;
        }

        .no-data {
            text-align: center;
            padding: 48px;
            color: var(--text-secondary);
        }

        .footer {
            text-align: center;
            padding: 24px;
            color: var(--text-secondary);
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>ant-quic E2E Dashboard</h1>
        <div class="status">
            <div class="status-indicator" id="wsStatus"></div>
            <span id="wsStatusText">Connecting...</span>
        </div>
    </div>

    <div class="container">
        <div class="grid" id="summaryGrid">
            <div class="card info">
                <h3>Total Nodes</h3>
                <div class="value" id="totalNodes">0</div>
            </div>
            <div class="card success">
                <h3>Online Nodes</h3>
                <div class="value" id="onlineNodes">0</div>
            </div>
            <div class="card info">
                <h3>Total Connections</h3>
                <div class="value" id="totalConnections">0</div>
            </div>
            <div class="card info">
                <h3>Data Transferred</h3>
                <div class="value" id="dataTransferred">0</div>
                <div class="unit">total</div>
            </div>
            <div class="card success">
                <h3>Avg Throughput</h3>
                <div class="value" id="avgThroughput">0</div>
                <div class="unit">Mbps</div>
            </div>
            <div class="card success">
                <h3>NAT Success Rate</h3>
                <div class="value" id="natSuccessRate">100</div>
                <div class="unit">%</div>
            </div>
            <div class="card success">
                <h3>Chunks Verified</h3>
                <div class="value" id="chunksVerified">0</div>
            </div>
            <div class="card info">
                <h3>Test Duration</h3>
                <div class="value" id="testDuration">0</div>
                <div class="unit">seconds</div>
            </div>
        </div>

        <div class="section">
            <div class="section-header">
                <h2>Active Nodes</h2>
            </div>
            <div class="card">
                <table class="nodes-table">
                    <thead>
                        <tr>
                            <th>Node ID</th>
                            <th>Location</th>
                            <th>Status</th>
                            <th>Connections</th>
                            <th>Sent</th>
                            <th>Received</th>
                            <th>Throughput</th>
                            <th>NAT Success</th>
                        </tr>
                    </thead>
                    <tbody id="nodesTable">
                        <tr>
                            <td colspan="8" class="no-data">Waiting for nodes to connect...</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <div class="footer">
        ant-quic E2E Testing Dashboard | Real-time monitoring via WebSocket
    </div>

    <script>
        const nodes = {};
        let ws = null;

        function formatBytes(bytes) {
            if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(2) + ' GB';
            if (bytes >= 1048576) return (bytes / 1048576).toFixed(2) + ' MB';
            if (bytes >= 1024) return (bytes / 1024).toFixed(2) + ' KB';
            return bytes + ' B';
        }

        function formatDuration(secs) {
            if (secs >= 3600) {
                const h = Math.floor(secs / 3600);
                const m = Math.floor((secs % 3600) / 60);
                return h + 'h ' + m + 'm';
            }
            if (secs >= 60) {
                const m = Math.floor(secs / 60);
                const s = secs % 60;
                return m + 'm ' + s + 's';
            }
            return secs + 's';
        }

        function updateSummary(summary) {
            document.getElementById('totalNodes').textContent = summary.total_nodes;
            document.getElementById('onlineNodes').textContent = summary.online_nodes;
            document.getElementById('totalConnections').textContent = summary.total_connections;
            document.getElementById('dataTransferred').textContent =
                formatBytes(summary.total_bytes_sent + summary.total_bytes_received);
            document.getElementById('avgThroughput').textContent =
                summary.average_throughput_mbps.toFixed(2);
            document.getElementById('natSuccessRate').textContent =
                summary.nat_success_rate.toFixed(1);
            document.getElementById('chunksVerified').textContent = summary.total_chunks_verified;
            document.getElementById('testDuration').textContent = summary.test_duration_secs;
        }

        function updateNodesTable() {
            const tbody = document.getElementById('nodesTable');
            const nodeList = Object.values(nodes);

            if (nodeList.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" class="no-data">Waiting for nodes to connect...</td></tr>';
                return;
            }

            tbody.innerHTML = nodeList.map(node => {
                const statusClass = node.status === 'Online' ? 'online' :
                                   node.status === 'Warning' ? 'warning' : 'offline';
                return `
                    <tr>
                        <td>${node.node_id}</td>
                        <td>${node.location}</td>
                        <td><span class="status-badge ${statusClass}">${node.status}</span></td>
                        <td>${node.active_connections}</td>
                        <td>${formatBytes(node.bytes_sent_total)}</td>
                        <td>${formatBytes(node.bytes_received_total)}</td>
                        <td>${node.current_throughput_mbps.toFixed(2)} Mbps</td>
                        <td>${node.nat_traversal_successes}/${node.nat_traversal_successes + node.nat_traversal_failures}</td>
                    </tr>
                `;
            }).join('');
        }

        function connectWebSocket() {
            const wsUrl = `ws://${window.location.host}/ws/live`;
            ws = new WebSocket(wsUrl);

            ws.onopen = function() {
                document.getElementById('wsStatus').style.background = 'var(--accent-green)';
                document.getElementById('wsStatusText').textContent = 'Connected';
            };

            ws.onclose = function() {
                document.getElementById('wsStatus').style.background = 'var(--accent-red)';
                document.getElementById('wsStatusText').textContent = 'Disconnected';
                setTimeout(connectWebSocket, 3000);
            };

            ws.onerror = function() {
                document.getElementById('wsStatus').style.background = 'var(--accent-yellow)';
                document.getElementById('wsStatusText').textContent = 'Error';
            };

            ws.onmessage = function(event) {
                try {
                    const update = JSON.parse(event.data);

                    switch (update.type) {
                        case 'NodeUpdate':
                            nodes[update.node.node_id] = update.node;
                            updateNodesTable();
                            break;
                        case 'NetworkSummary':
                            updateSummary(update.summary);
                            break;
                        case 'Topology':
                            // Could add topology visualization here
                            break;
                    }
                } catch (e) {
                    console.error('Failed to parse update:', e);
                }
            };
        }

        // Initial connection
        connectWebSocket();

        // Periodic refresh of summary via API (backup)
        setInterval(async () => {
            try {
                const resp = await fetch('/api/network/summary');
                const summary = await resp.json();
                updateSummary(summary);
            } catch (e) {
                console.error('Failed to fetch summary:', e);
            }
        }, 5000);
    </script>
</body>
</html>
"#;
