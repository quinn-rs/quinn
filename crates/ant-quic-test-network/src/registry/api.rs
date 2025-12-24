//! HTTP API endpoints for the peer registry.
//!
//! Provides REST endpoints for node registration, heartbeat, peer discovery,
//! and network statistics. Also includes WebSocket support for real-time updates.
//!
//! # Persistent Storage
//!
//! All experiment data is persisted to JSON files in the data directory:
//! - `experiment_summary.json` - Complete experiment data
//! - `nodes.json` - All nodes (active and historical)
//! - `connections.json` - All connection records
//! - `events.jsonl` - Append-only event log
//! - `stats_snapshots.json` - Periodic statistics snapshots

use crate::dashboard::dashboard_routes;
use crate::registry::persistence::{PersistenceConfig, PersistentStorage};
use crate::registry::store::PeerStore;
use crate::registry::types::{
    ConnectionReport, NetworkEvent, NetworkStats, NodeHeartbeat, NodeRegistration, PeerInfo,
    RegistrationResponse,
};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use warp::{Filter, Rejection, Reply};

/// Extract the real client IP from proxy headers or remote address.
///
/// Priority order:
/// 1. X-Forwarded-For header (first IP in chain)
/// 2. X-Real-IP header
/// 3. Direct remote address
fn extract_client_ip(
    x_forwarded_for: Option<String>,
    x_real_ip: Option<String>,
    remote_addr: Option<SocketAddr>,
) -> Option<IpAddr> {
    // Try X-Forwarded-For first (nginx adds this)
    if let Some(xff) = x_forwarded_for {
        // X-Forwarded-For can be a comma-separated list; take the first (original client)
        if let Some(first_ip) = xff.split(',').next() {
            if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }

    // Try X-Real-IP
    if let Some(xri) = x_real_ip {
        if let Ok(ip) = xri.trim().parse::<IpAddr>() {
            return Some(ip);
        }
    }

    // Fall back to remote address
    remote_addr.map(|addr| addr.ip())
}

/// Registry API server configuration.
#[derive(Debug, Clone)]
pub struct RegistryConfig {
    /// HTTP server bind address
    pub bind_addr: SocketAddr,
    /// Registration TTL in seconds
    pub ttl_secs: u64,
    /// Cleanup interval for expired entries
    pub cleanup_interval_secs: u64,
    /// Data directory for persistent storage
    pub data_dir: PathBuf,
    /// Whether to enable persistent storage
    pub persistence_enabled: bool,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:8080".parse().expect("valid default address"),
            ttl_secs: 120,
            cleanup_interval_secs: 30,
            data_dir: PathBuf::from("./data"),
            persistence_enabled: true,
        }
    }
}

/// Start the registry HTTP server.
pub async fn start_registry_server(config: RegistryConfig) -> anyhow::Result<()> {
    let store = PeerStore::with_ttl(config.ttl_secs);

    // Initialize persistent storage
    let persistence_config = PersistenceConfig {
        data_dir: config.data_dir.clone(),
        enabled: config.persistence_enabled,
        ..Default::default()
    };
    let persistence = PersistentStorage::new(persistence_config);
    if let Err(e) = persistence.initialize().await {
        tracing::warn!("Failed to initialize persistence: {}", e);
    } else if persistence.is_enabled() {
        tracing::info!("Persistent storage enabled at {:?}", config.data_dir);
    }

    // Clone for cleanup task before moving into filter
    let cleanup_store = Arc::clone(&store);
    let save_store = Arc::clone(&store);
    let snapshot_store = Arc::clone(&store);
    let event_store = Arc::clone(&store);

    let store_filter = warp::any().map(move || Arc::clone(&store));
    let persistence_filter = {
        let p = Arc::clone(&persistence);
        warp::any().map(move || Arc::clone(&p))
    };

    // POST /api/register - Node registration with client IP extraction
    let register = warp::path!("api" / "register")
        .and(warp::post())
        .and(warp::body::json())
        .and(store_filter.clone())
        .and(warp::header::optional::<String>("X-Forwarded-For"))
        .and(warp::header::optional::<String>("X-Real-IP"))
        .and(warp::addr::remote())
        .and_then(handle_register);

    // POST /api/heartbeat - Node heartbeat
    let heartbeat = warp::path!("api" / "heartbeat")
        .and(warp::post())
        .and(warp::body::json())
        .and(store_filter.clone())
        .and_then(handle_heartbeat);

    // GET /api/peers - Get peer list
    let peers = warp::path!("api" / "peers")
        .and(warp::get())
        .and(store_filter.clone())
        .and_then(handle_get_peers);

    // GET /api/stats - Get network statistics
    let stats = warp::path!("api" / "stats")
        .and(warp::get())
        .and(store_filter.clone())
        .and_then(handle_get_stats);

    // GET /api/node/:peer_id - Get detailed node info
    let node_detail = warp::path!("api" / "node" / String)
        .and(warp::get())
        .and(store_filter.clone())
        .and_then(handle_get_node_detail);

    // GET /api/peers/all - Get all peers including historical
    let all_peers = warp::path!("api" / "peers" / "all")
        .and(warp::get())
        .and(store_filter.clone())
        .and_then(handle_get_all_peers);

    // GET /api/results - Get experiment results
    let results = warp::path!("api" / "results")
        .and(warp::get())
        .and(store_filter.clone())
        .and_then(handle_get_results);

    // POST /api/connection - Report a connection
    let connection = warp::path!("api" / "connection")
        .and(warp::post())
        .and(warp::body::json())
        .and(store_filter.clone())
        .and_then(handle_connection_report);

    // GET /api/export - Export all persisted data
    let export = warp::path!("api" / "export")
        .and(warp::get())
        .and(persistence_filter.clone())
        .and_then(handle_export_data);

    // GET /api/events - Get event log
    let events = warp::path!("api" / "events")
        .and(warp::get())
        .and(persistence_filter.clone())
        .and_then(handle_get_events);

    // GET /ws/live - WebSocket for real-time updates
    let websocket = warp::path!("ws" / "live")
        .and(warp::ws())
        .and(store_filter.clone())
        .map(|ws: warp::ws::Ws, store: Arc<PeerStore>| {
            ws.on_upgrade(move |socket| handle_websocket(socket, store))
        });

    // GET /health - Health check
    let health = warp::path!("health")
        .and(warp::get())
        .map(|| warp::reply::json(&serde_json::json!({"status": "ok"})));

    // Dashboard routes (serves Three.js globe UI)
    let dashboard = dashboard_routes(Arc::clone(&cleanup_store));

    // Combine all routes
    // Note: Dashboard routes are first so "/" serves index.html
    // all_peers must come before peers to match the more specific path first
    let routes = dashboard
        .or(register)
        .or(heartbeat)
        .or(connection)
        .or(all_peers)
        .or(peers)
        .or(stats)
        .or(results)
        .or(export)
        .or(events)
        .or(node_detail)
        .or(websocket)
        .or(health)
        .with(warp::cors().allow_any_origin())
        .with(warp::log("registry"));

    // Start cleanup task
    let cleanup_interval = Duration::from_secs(config.cleanup_interval_secs);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(cleanup_interval);
        loop {
            interval.tick().await;
            let removed = cleanup_store.cleanup_expired();
            if removed > 0 {
                tracing::info!("Cleaned up {} expired registrations", removed);
            }
        }
    });

    // Start periodic save task
    let save_persistence = Arc::clone(&persistence);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            // Update persistence with current state
            let all_peers = save_store.get_all_peers_with_historical();
            save_persistence.update_nodes(all_peers).await;

            let results = save_store.get_experiment_results().await;
            save_persistence
                .update_connections(results.connections)
                .await;
            save_persistence.update_nat_stats(results.nat_stats).await;

            // Save to disk
            if let Err(e) = save_persistence.save().await {
                tracing::warn!("Failed to save persistence data: {}", e);
            } else {
                tracing::debug!("Persisted experiment data to disk");
            }
        }
    });

    // Start periodic stats snapshot task
    let snapshot_persistence = Arc::clone(&persistence);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes
        loop {
            interval.tick().await;
            let stats = snapshot_store.get_stats();
            snapshot_persistence.add_stats_snapshot(stats).await;
            tracing::debug!("Created statistics snapshot");
        }
    });

    // Start event logging task
    let event_persistence = Arc::clone(&persistence);
    tokio::spawn(async move {
        let mut event_rx = event_store.subscribe();
        while let Ok(event) = event_rx.recv().await {
            event_persistence.log_event(event).await;
        }
    });

    tracing::info!("Starting registry server on {}", config.bind_addr);
    tracing::info!("Experiment data will be saved to {:?}", config.data_dir);
    warp::serve(routes).run(config.bind_addr).await;

    Ok(())
}

/// Handle export of all persisted data.
async fn handle_export_data(persistence: Arc<PersistentStorage>) -> Result<impl Reply, Rejection> {
    let data = persistence.get_data().await;
    Ok(warp::reply::json(&data))
}

/// Handle get events from event log.
async fn handle_get_events(persistence: Arc<PersistentStorage>) -> Result<impl Reply, Rejection> {
    match persistence.read_events() {
        Ok(events) => Ok(warp::reply::json(&events)),
        Err(e) => Ok(warp::reply::json(&serde_json::json!({
            "error": e,
            "events": []
        }))),
    }
}

/// Handle node registration.
async fn handle_register(
    registration: NodeRegistration,
    store: Arc<PeerStore>,
    x_forwarded_for: Option<String>,
    x_real_ip: Option<String>,
    remote_addr: Option<SocketAddr>,
) -> Result<impl Reply, Rejection> {
    // Extract the real client IP from headers or remote address
    let client_ip = extract_client_ip(x_forwarded_for, x_real_ip, remote_addr);

    tracing::info!(
        "Registration from peer {} ({}) client_ip={:?}",
        &registration.peer_id[..8.min(registration.peer_id.len())],
        registration.version,
        client_ip
    );

    match store.register_with_client_ip(registration, client_ip) {
        Ok(peers) => {
            let response = RegistrationResponse {
                success: true,
                error: None,
                peers,
                expires_in_secs: 120, // 2 minutes
            };
            Ok(warp::reply::json(&response))
        }
        Err(e) => {
            let response = RegistrationResponse {
                success: false,
                error: Some(e),
                peers: vec![],
                expires_in_secs: 0,
            };
            Ok(warp::reply::json(&response))
        }
    }
}

/// Handle node heartbeat.
async fn handle_heartbeat(
    heartbeat: NodeHeartbeat,
    store: Arc<PeerStore>,
) -> Result<impl Reply, Rejection> {
    match store.heartbeat(heartbeat) {
        Ok(()) => Ok(warp::reply::with_status(
            warp::reply::json(&serde_json::json!({"success": true})),
            warp::http::StatusCode::OK,
        )),
        Err(e) => {
            tracing::warn!("Heartbeat failed: {}", e);
            Ok(warp::reply::with_status(
                warp::reply::json(&serde_json::json!({"success": false, "error": e})),
                warp::http::StatusCode::NOT_FOUND,
            ))
        }
    }
}

/// Handle get peers request.
async fn handle_get_peers(store: Arc<PeerStore>) -> Result<impl Reply, Rejection> {
    let peers = store.get_all_peers();
    Ok(warp::reply::json(&peers))
}

/// Handle get stats request.
async fn handle_get_stats(store: Arc<PeerStore>) -> Result<impl Reply, Rejection> {
    let stats = store.get_stats();
    Ok(warp::reply::json(&stats))
}

/// Handle get all peers including historical.
async fn handle_get_all_peers(store: Arc<PeerStore>) -> Result<impl Reply, Rejection> {
    let peers = store.get_all_peers_with_historical();
    Ok(warp::reply::json(&peers))
}

/// Handle get experiment results.
async fn handle_get_results(store: Arc<PeerStore>) -> Result<impl Reply, Rejection> {
    let results = store.get_experiment_results().await;
    Ok(warp::reply::json(&results))
}

/// Handle connection report from nodes.
async fn handle_connection_report(
    report: ConnectionReport,
    store: Arc<PeerStore>,
) -> Result<impl Reply, Rejection> {
    tracing::debug!(
        "Connection report: {} -> {} via {:?}",
        &report.from_peer[..8.min(report.from_peer.len())],
        &report.to_peer[..8.min(report.to_peer.len())],
        report.method
    );

    store
        .record_connection(
            report.from_peer,
            report.to_peer,
            report.method,
            report.is_ipv6,
            report.rtt_ms,
        )
        .await;

    Ok(warp::reply::json(&serde_json::json!({"success": true})))
}

/// Detailed node information for the dashboard.
#[derive(Debug, Clone, serde::Serialize)]
struct NodeDetailResponse {
    /// Basic peer info
    #[serde(flatten)]
    peer: PeerInfo,
    /// NAT traversal statistics
    nat_stats: NodeNatStats,
    /// Connection statistics
    connection_stats: NodeConnectionStats,
    /// Network connectivity summary
    connectivity: ConnectivitySummary,
}

/// NAT statistics for a node.
#[derive(Debug, Clone, serde::Serialize)]
struct NodeNatStats {
    /// Total connection attempts
    attempts: u64,
    /// Successful direct connections
    direct_success: u64,
    /// Successful hole-punched connections
    hole_punch_success: u64,
    /// Successful relayed connections
    relay_success: u64,
    /// Failed connection attempts
    failures: u64,
    /// Overall success rate percentage
    success_rate_percent: f64,
}

/// Connection statistics for a node.
#[derive(Debug, Clone, serde::Serialize)]
struct NodeConnectionStats {
    /// Currently connected peers
    connected_peers: usize,
    /// Total bytes sent
    bytes_sent: u64,
    /// Total bytes received
    bytes_received: u64,
    /// Formatted bytes sent
    bytes_sent_formatted: String,
    /// Formatted bytes received
    bytes_received_formatted: String,
}

/// Connectivity assessment summary.
#[derive(Debug, Clone, serde::Serialize)]
struct ConnectivitySummary {
    /// Overall connectivity score (0-100)
    score: u8,
    /// Human-readable connectivity rating
    rating: String,
    /// Assessment message
    message: String,
    /// Whether 100% connectivity is achievable
    full_connectivity_possible: bool,
}

/// Handle get node detail request.
async fn handle_get_node_detail(
    peer_id: String,
    store: Arc<PeerStore>,
) -> Result<impl Reply, Rejection> {
    // Check both active and historical peers
    let peers = store.get_all_peers_with_historical();
    let peer = peers.iter().find(|p| p.peer_id.starts_with(&peer_id));

    match peer {
        Some(peer) => {
            // Get the detailed entry from store
            let nat_stats = store.get_node_nat_stats(&peer.peer_id);
            let conn_stats = store.get_node_connection_stats(&peer.peer_id);

            let total_attempts = nat_stats.attempts.max(1);
            let total_success =
                nat_stats.direct_success + nat_stats.hole_punch_success + nat_stats.relay_success;
            let success_rate = (total_success as f64 / total_attempts as f64) * 100.0;

            // Calculate connectivity score
            let (score, rating, message, full_connectivity) =
                assess_connectivity(&peer.capabilities, peer.nat_type, success_rate);

            let response = NodeDetailResponse {
                peer: peer.clone(),
                nat_stats: NodeNatStats {
                    attempts: nat_stats.attempts,
                    direct_success: nat_stats.direct_success,
                    hole_punch_success: nat_stats.hole_punch_success,
                    relay_success: nat_stats.relay_success,
                    failures: nat_stats.failures,
                    success_rate_percent: success_rate,
                },
                connection_stats: NodeConnectionStats {
                    connected_peers: conn_stats.0,
                    bytes_sent: conn_stats.1,
                    bytes_received: conn_stats.2,
                    bytes_sent_formatted: format_bytes(conn_stats.1),
                    bytes_received_formatted: format_bytes(conn_stats.2),
                },
                connectivity: ConnectivitySummary {
                    score,
                    rating,
                    message,
                    full_connectivity_possible: full_connectivity,
                },
            };
            Ok(warp::reply::json(&response))
        }
        None => Ok(warp::reply::json(&serde_json::json!({
            "error": "Node not found",
            "peer_id": peer_id
        }))),
    }
}

/// Assess connectivity based on capabilities and NAT type.
fn assess_connectivity(
    capabilities: &crate::registry::types::NodeCapabilities,
    nat_type: crate::registry::types::NatType,
    success_rate: f64,
) -> (u8, String, String, bool) {
    use crate::registry::types::NatType;

    let mut score: u8 = 50; // Base score
    let mut factors = Vec::new();

    // PQC support (required for ant-quic)
    if capabilities.pqc {
        score = score.saturating_add(10);
        factors.push("Quantum-safe (ML-KEM-768)");
    }

    // IPv4 support
    if capabilities.ipv4 {
        score = score.saturating_add(15);
        factors.push("IPv4 enabled");
    }

    // IPv6 support (bonus)
    if capabilities.ipv6 {
        score = score.saturating_add(10);
        factors.push("IPv6 enabled (dual-stack)");
    }

    // NAT traversal capability
    if capabilities.nat_traversal {
        score = score.saturating_add(10);
    }

    // NAT type assessment
    let (nat_bonus, nat_msg) = match nat_type {
        NatType::None => (15, "Direct public IP - optimal connectivity"),
        NatType::FullCone => (12, "Full cone NAT - excellent connectivity"),
        NatType::AddressRestricted => (8, "Address restricted NAT - good connectivity"),
        NatType::PortRestricted => (5, "Port restricted NAT - moderate connectivity"),
        NatType::Symmetric => (0, "Symmetric NAT - requires relay for some peers"),
        NatType::Unknown => (3, "NAT type unknown - connectivity assessment pending"),
    };
    score = score.saturating_add(nat_bonus);

    // Success rate bonus
    if success_rate >= 90.0 {
        score = score.saturating_add(5);
    } else if success_rate >= 75.0 {
        score = score.saturating_add(3);
    }

    // Cap at 100
    score = score.min(100);

    let rating = match score {
        90..=100 => "Excellent".to_string(),
        75..=89 => "Very Good".to_string(),
        60..=74 => "Good".to_string(),
        40..=59 => "Moderate".to_string(),
        _ => "Limited".to_string(),
    };

    // Full connectivity assessment
    let full_connectivity = matches!(
        nat_type,
        NatType::None | NatType::FullCone | NatType::AddressRestricted | NatType::PortRestricted
    ) && capabilities.nat_traversal;

    let message = if full_connectivity {
        format!(
            "{}. This node can achieve 100% peer-to-peer connectivity!",
            nat_msg
        )
    } else {
        format!(
            "{}. Some connections may require relay assistance.",
            nat_msg
        )
    };

    (score, rating, message, full_connectivity)
}

/// Format bytes into human-readable string.
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Handle WebSocket connection for real-time updates.
async fn handle_websocket(ws: warp::ws::WebSocket, store: Arc<PeerStore>) {
    use futures_util::{SinkExt, StreamExt};

    let (mut tx, mut rx) = ws.split();
    let mut event_rx = store.subscribe();

    // Send initial stats
    let initial_stats = store.get_stats();
    let initial_msg = NetworkEvent::StatsUpdate(initial_stats);
    if let Ok(json) = serde_json::to_string(&initial_msg) {
        let _ = tx.send(warp::ws::Message::text(json)).await;
    }

    // Forward events to WebSocket
    let send_task = tokio::spawn(async move {
        while let Ok(event) = event_rx.recv().await {
            if let Ok(json) = serde_json::to_string(&event) {
                if tx.send(warp::ws::Message::text(json)).await.is_err() {
                    break;
                }
            }
        }
    });

    // Handle incoming messages (ping/pong)
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

    send_task.abort();
}

/// Client for connecting to the registry from nodes.
pub struct RegistryClient {
    base_url: String,
    client: reqwest::Client,
}

impl RegistryClient {
    /// Create a new registry client.
    pub fn new(registry_url: &str) -> Self {
        Self {
            base_url: registry_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("failed to create HTTP client"),
        }
    }

    /// Register this node with the registry.
    pub async fn register(
        &self,
        registration: &NodeRegistration,
    ) -> anyhow::Result<RegistrationResponse> {
        let url = format!("{}/api/register", self.base_url);
        let response = self
            .client
            .post(&url)
            .json(registration)
            .send()
            .await?
            .json()
            .await?;
        Ok(response)
    }

    /// Send heartbeat to registry.
    pub async fn heartbeat(&self, heartbeat: &NodeHeartbeat) -> anyhow::Result<()> {
        let url = format!("{}/api/heartbeat", self.base_url);
        let response = self.client.post(&url).json(heartbeat).send().await?;
        // Check for HTTP error status (including 404 for unknown peer)
        response.error_for_status()?;
        Ok(())
    }

    /// Get list of peers from registry.
    pub async fn get_peers(&self) -> anyhow::Result<Vec<PeerInfo>> {
        let url = format!("{}/api/peers", self.base_url);
        let peers = self.client.get(&url).send().await?.json().await?;
        Ok(peers)
    }

    /// Get network statistics from registry.
    pub async fn get_stats(&self) -> anyhow::Result<NetworkStats> {
        let url = format!("{}/api/stats", self.base_url);
        let stats = self.client.get(&url).send().await?.json().await?;
        Ok(stats)
    }

    /// Report a connection to the registry.
    pub async fn report_connection(&self, report: &ConnectionReport) -> anyhow::Result<()> {
        let url = format!("{}/api/connection", self.base_url);
        self.client.post(&url).json(report).send().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_registration_response_serialization() {
        let response = RegistrationResponse {
            success: true,
            error: None,
            peers: vec![],
            expires_in_secs: 120,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"success\":true"));
    }

    #[test]
    fn test_registry_client_creation() {
        let client = RegistryClient::new("https://saorsa-1.saorsalabs.com");
        assert_eq!(client.base_url, "https://saorsa-1.saorsalabs.com");

        // Test trailing slash handling
        let client2 = RegistryClient::new("https://saorsa-1.saorsalabs.com/");
        assert_eq!(client2.base_url, "https://saorsa-1.saorsalabs.com");
    }
}
