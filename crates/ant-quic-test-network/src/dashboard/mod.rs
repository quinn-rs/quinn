//! Web dashboard for the ant-quic test network.
//!
//! Provides a Three.js globe visualization and real-time statistics.

use rust_embed::Embed;
use std::sync::Arc;
use warp::Filter;

use crate::registry::PeerStore;

/// Embedded static files from the static/ directory.
#[derive(Embed)]
#[folder = "static/"]
struct StaticFiles;

/// Create dashboard routes.
pub fn dashboard_routes(
    store: Arc<PeerStore>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let index = warp::path::end().and_then(serve_index);

    let static_files = warp::path("static")
        .and(warp::path::tail())
        .and_then(serve_static);

    let api_stats = warp::path!("api" / "stats")
        .and(warp::get())
        .and(with_store(store.clone()))
        .and_then(get_stats);

    let api_peers = warp::path!("api" / "peers")
        .and(warp::get())
        .and(with_store(store.clone()))
        .and_then(get_peers);

    let ws_live = warp::path!("ws" / "live")
        .and(warp::ws())
        .and(with_store(store))
        .map(|ws: warp::ws::Ws, store: Arc<PeerStore>| {
            ws.on_upgrade(move |socket| handle_websocket(socket, store))
        });

    index
        .or(static_files)
        .or(api_stats)
        .or(api_peers)
        .or(ws_live)
}

fn with_store(
    store: Arc<PeerStore>,
) -> impl Filter<Extract = (Arc<PeerStore>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || store.clone())
}

async fn serve_index() -> Result<impl warp::Reply, warp::Rejection> {
    match StaticFiles::get("index.html") {
        Some(content) => Ok(warp::reply::html(
            String::from_utf8_lossy(content.data.as_ref()).to_string(),
        )),
        None => Err(warp::reject::not_found()),
    }
}

async fn serve_static(path: warp::path::Tail) -> Result<impl warp::Reply, warp::Rejection> {
    let path = path.as_str();
    match StaticFiles::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            Ok(warp::reply::with_header(
                content.data.to_vec(),
                "Content-Type",
                mime.as_ref(),
            ))
        }
        None => Err(warp::reject::not_found()),
    }
}

async fn get_stats(store: Arc<PeerStore>) -> Result<impl warp::Reply, warp::Rejection> {
    let stats = store.get_stats();
    Ok(warp::reply::json(&stats))
}

async fn get_peers(store: Arc<PeerStore>) -> Result<impl warp::Reply, warp::Rejection> {
    let peers = store.get_all_peers();
    Ok(warp::reply::json(&peers))
}

async fn handle_websocket(ws: warp::ws::WebSocket, store: Arc<PeerStore>) {
    use futures_util::{SinkExt, StreamExt};
    use tokio::time::{Duration, interval};

    let (mut tx, mut rx) = ws.split();

    // Send initial full state
    let initial_state = serde_json::json!({
        "type": "full_state",
        "nodes": store.get_all_peers(),
        "stats": store.get_stats(),
    });

    if tx
        .send(warp::ws::Message::text(initial_state.to_string()))
        .await
        .is_err()
    {
        return;
    }

    let mut event_rx = store.subscribe();

    // Spawn task to forward events to WebSocket
    let forward_task = tokio::spawn(async move {
        while let Ok(event) = event_rx.recv().await {
            let msg = match event {
                crate::registry::NetworkEvent::NodeRegistered {
                    peer_id,
                    country_code,
                    latitude,
                    longitude,
                } => serde_json::json!({
                    "type": "node_registered",
                    "peer_id": peer_id,
                    "country_code": country_code,
                    "latitude": latitude,
                    "longitude": longitude,
                }),
                crate::registry::NetworkEvent::NodeOffline { peer_id } => serde_json::json!({
                    "type": "node_offline",
                    "peer_id": peer_id,
                }),
                crate::registry::NetworkEvent::ConnectionEstablished {
                    from_peer,
                    to_peer,
                    method,
                    rtt_ms,
                } => serde_json::json!({
                    "type": "connection_established",
                    "from_peer": from_peer,
                    "to_peer": to_peer,
                    "method": format!("{:?}", method).to_lowercase(),
                    "rtt_ms": rtt_ms,
                }),
                crate::registry::NetworkEvent::StatsUpdate(stats) => serde_json::json!({
                    "type": "stats_update",
                    "stats": stats,
                }),
                crate::registry::NetworkEvent::ConnectivityTestRequest {
                    peer_id,
                    addresses,
                    relay_addr,
                    timestamp_ms,
                } => serde_json::json!({
                    "type": "connectivity_test_request",
                    "peer_id": peer_id,
                    "addresses": addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
                    "relay_addr": relay_addr.map(|a| a.to_string()),
                    "timestamp_ms": timestamp_ms,
                }),
            };

            if tx
                .send(warp::ws::Message::text(msg.to_string()))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    // Keep connection alive with pings and handle incoming messages
    let mut ping_interval = interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            _ = ping_interval.tick() => {
                // Ping is handled by warp internally
            }
            msg = rx.next() => {
                match msg {
                    Some(Ok(msg)) => {
                        if msg.is_close() {
                            break;
                        }
                    }
                    Some(Err(_)) | None => break,
                }
            }
        }
    }

    forward_task.abort();
}
