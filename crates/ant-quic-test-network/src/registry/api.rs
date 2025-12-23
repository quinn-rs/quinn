//! HTTP API endpoints for the peer registry.
//!
//! Provides REST endpoints for node registration, heartbeat, peer discovery,
//! and network statistics. Also includes WebSocket support for real-time updates.

use crate::dashboard::dashboard_routes;
use crate::registry::store::PeerStore;
use crate::registry::types::{
    NetworkEvent, NetworkStats, NodeHeartbeat, NodeRegistration, PeerInfo, RegistrationResponse,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use warp::{Filter, Rejection, Reply};

/// Registry API server configuration.
#[derive(Debug, Clone)]
pub struct RegistryConfig {
    /// HTTP server bind address
    pub bind_addr: SocketAddr,
    /// Registration TTL in seconds
    pub ttl_secs: u64,
    /// Cleanup interval for expired entries
    pub cleanup_interval_secs: u64,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:8080".parse().expect("valid default address"),
            ttl_secs: 120,
            cleanup_interval_secs: 30,
        }
    }
}

/// Start the registry HTTP server.
pub async fn start_registry_server(config: RegistryConfig) -> anyhow::Result<()> {
    let store = PeerStore::with_ttl(config.ttl_secs);

    // Clone for cleanup task before moving into filter
    let cleanup_store = Arc::clone(&store);

    let store_filter = warp::any().map(move || Arc::clone(&store));

    // POST /api/register - Node registration
    let register = warp::path!("api" / "register")
        .and(warp::post())
        .and(warp::body::json())
        .and(store_filter.clone())
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
    let routes = dashboard
        .or(register)
        .or(heartbeat)
        .or(peers)
        .or(stats)
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

    tracing::info!("Starting registry server on {}", config.bind_addr);
    warp::serve(routes).run(config.bind_addr).await;

    Ok(())
}

/// Handle node registration.
async fn handle_register(
    registration: NodeRegistration,
    store: Arc<PeerStore>,
) -> Result<impl Reply, Rejection> {
    tracing::info!(
        "Registration from peer {} ({})",
        &registration.peer_id[..8.min(registration.peer_id.len())],
        registration.version
    );

    match store.register(registration) {
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
        Ok(()) => Ok(warp::reply::json(&serde_json::json!({"success": true}))),
        Err(e) => Ok(warp::reply::json(
            &serde_json::json!({"success": false, "error": e}),
        )),
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
        self.client.post(&url).json(heartbeat).send().await?;
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
        let client = RegistryClient::new("https://quic.saorsalabs.com");
        assert_eq!(client.base_url, "https://quic.saorsalabs.com");

        // Test trailing slash handling
        let client2 = RegistryClient::new("https://quic.saorsalabs.com/");
        assert_eq!(client2.base_url, "https://quic.saorsalabs.com");
    }
}
