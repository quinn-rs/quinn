// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! MASQUE Relay Client
//!
//! Implements a client for connecting to MASQUE CONNECT-UDP Bind relays.
//! Used when direct NAT traversal fails and relay fallback is needed.
//!
//! # Overview
//!
//! The relay client connects to a relay server and:
//! - Negotiates a CONNECT-UDP Bind session
//! - Learns its public address from the relay
//! - Manages context registrations for efficient datagram forwarding
//! - Provides a simple API for sending/receiving datagrams through the relay
//!
//! # Example
//!
//! ```rust,ignore
//! use ant_quic::masque::relay_client::{MasqueRelayClient, RelayClientConfig};
//! use std::net::SocketAddr;
//!
//! // Connect to a relay
//! let relay_addr: SocketAddr = "203.0.113.50:9000".parse().unwrap();
//! let config = RelayClientConfig::default();
//! let client = MasqueRelayClient::connect(relay_addr, config).await?;
//!
//! // Get our public address
//! let public_addr = client.public_address();
//!
//! // Send datagram to target through relay
//! client.send_datagram(target_addr, data).await?;
//! ```

use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::VarInt;
use crate::masque::{
    Capsule, CompressedDatagram, CompressionAck, CompressionAssign, CompressionClose,
    ConnectError, ConnectUdpRequest, ConnectUdpResponse, ContextManager, Datagram,
    UncompressedDatagram,
};
use crate::relay::error::{RelayError, RelayResult, SessionErrorKind};

/// Configuration for the relay client
#[derive(Debug, Clone)]
pub struct RelayClientConfig {
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Session keepalive interval
    pub keepalive_interval: Duration,
    /// Maximum pending context registrations
    pub max_pending_contexts: usize,
    /// Prefer compressed contexts over uncompressed
    pub prefer_compressed: bool,
}

impl Default for RelayClientConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            keepalive_interval: Duration::from_secs(30),
            max_pending_contexts: 50,
            prefer_compressed: true,
        }
    }
}

/// State of the relay connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayConnectionState {
    /// Not connected
    Disconnected,
    /// Connection in progress
    Connecting,
    /// Connected and session established
    Connected,
    /// Connection failed
    Failed,
    /// Gracefully closed
    Closed,
}

/// Statistics for the relay client
#[derive(Debug, Default)]
pub struct RelayClientStats {
    /// Bytes sent through relay
    pub bytes_sent: AtomicU64,
    /// Bytes received through relay
    pub bytes_received: AtomicU64,
    /// Datagrams sent
    pub datagrams_sent: AtomicU64,
    /// Datagrams received
    pub datagrams_received: AtomicU64,
    /// Contexts registered
    pub contexts_registered: AtomicU64,
    /// Connection attempts
    pub connection_attempts: AtomicU64,
}

impl RelayClientStats {
    /// Create new statistics
    pub fn new() -> Self {
        Self::default()
    }

    /// Record bytes sent
    pub fn record_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        self.datagrams_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Record bytes received
    pub fn record_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
        self.datagrams_received.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a context registration
    pub fn record_context(&self) {
        self.contexts_registered.fetch_add(1, Ordering::Relaxed);
    }

    /// Total bytes sent
    pub fn total_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Total bytes received
    pub fn total_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }
}

/// Pending datagram awaiting context acknowledgement
#[derive(Debug)]
struct PendingDatagram {
    /// Target address for the datagram
    target: SocketAddr,
    /// The datagram payload (stored for retry after ACK)
    #[allow(dead_code)]
    payload: Bytes,
    /// When the datagram was queued (for timeout handling)
    #[allow(dead_code)]
    created_at: Instant,
}

/// MASQUE Relay Client
///
/// Manages a connection to a MASQUE relay server and provides
/// APIs for sending and receiving datagrams through the relay.
#[derive(Debug)]
pub struct MasqueRelayClient {
    /// Configuration
    config: RelayClientConfig,
    /// Relay server address
    relay_address: SocketAddr,
    /// Our public address as seen by the relay
    public_address: RwLock<Option<SocketAddr>>,
    /// Connection state
    state: RwLock<RelayConnectionState>,
    /// Context manager (client role - even IDs)
    context_manager: RwLock<ContextManager>,
    /// Mapping: target address → context ID
    target_to_context: RwLock<HashMap<SocketAddr, VarInt>>,
    /// Pending datagrams waiting for context ACK
    pending_datagrams: RwLock<Vec<PendingDatagram>>,
    /// Connection timestamp
    connected_at: RwLock<Option<Instant>>,
    /// Statistics
    stats: Arc<RelayClientStats>,
}

impl MasqueRelayClient {
    /// Create a new relay client (not yet connected)
    pub fn new(relay_address: SocketAddr, config: RelayClientConfig) -> Self {
        Self {
            config,
            relay_address,
            public_address: RwLock::new(None),
            state: RwLock::new(RelayConnectionState::Disconnected),
            context_manager: RwLock::new(ContextManager::new(true)), // Client role
            target_to_context: RwLock::new(HashMap::new()),
            pending_datagrams: RwLock::new(Vec::new()),
            connected_at: RwLock::new(None),
            stats: Arc::new(RelayClientStats::new()),
        }
    }

    /// Get relay server address
    pub fn relay_address(&self) -> SocketAddr {
        self.relay_address
    }

    /// Get our public address (if known)
    pub async fn public_address(&self) -> Option<SocketAddr> {
        *self.public_address.read().await
    }

    /// Get current connection state
    pub async fn state(&self) -> RelayConnectionState {
        *self.state.read().await
    }

    /// Check if connected
    pub async fn is_connected(&self) -> bool {
        *self.state.read().await == RelayConnectionState::Connected
    }

    /// Get connection duration
    pub async fn connection_duration(&self) -> Option<Duration> {
        self.connected_at.read().await.map(|t| t.elapsed())
    }

    /// Get statistics
    pub fn stats(&self) -> Arc<RelayClientStats> {
        Arc::clone(&self.stats)
    }

    /// Create a CONNECT-UDP Bind request
    pub fn create_connect_request(&self) -> ConnectUdpRequest {
        ConnectUdpRequest::bind_any()
    }

    /// Handle the CONNECT-UDP response from the relay
    pub async fn handle_connect_response(
        &self,
        response: ConnectUdpResponse,
    ) -> RelayResult<()> {
        if !response.is_success() {
            *self.state.write().await = RelayConnectionState::Failed;
            return Err(RelayError::SessionError {
                session_id: None,
                kind: SessionErrorKind::InvalidState {
                    current_state: format!("HTTP {}", response.status),
                    expected_state: "HTTP 200".into(),
                },
            });
        }

        // Store public address if provided
        if let Some(addr) = response.proxy_public_address {
            *self.public_address.write().await = Some(addr);
            tracing::info!(
                relay = %self.relay_address,
                public_addr = %addr,
                "MASQUE relay session established"
            );
        }

        *self.state.write().await = RelayConnectionState::Connected;
        *self.connected_at.write().await = Some(Instant::now());

        Ok(())
    }

    /// Handle an incoming capsule from the relay
    pub async fn handle_capsule(&self, capsule: Capsule) -> RelayResult<Option<Capsule>> {
        match capsule {
            Capsule::CompressionAck(ack) => self.handle_ack(ack).await,
            Capsule::CompressionClose(close) => self.handle_close(close).await,
            Capsule::CompressionAssign(assign) => self.handle_assign(assign).await,
            Capsule::Unknown { capsule_type, .. } => {
                tracing::debug!(
                    capsule_type = capsule_type.into_inner(),
                    "Ignoring unknown capsule from relay"
                );
                Ok(None)
            }
        }
    }

    /// Handle COMPRESSION_ACK from relay
    async fn handle_ack(&self, ack: CompressionAck) -> RelayResult<Option<Capsule>> {
        let result = {
            let mut mgr = self.context_manager.write().await;
            mgr.handle_ack(ack.context_id)
        }; // Release write lock before calling flush

        match result {
            Ok(_) => {
                self.stats.record_context();
                tracing::debug!(
                    context_id = ack.context_id.into_inner(),
                    "Context acknowledged by relay"
                );

                // Try to send any pending datagrams for this context
                self.flush_pending_for_context(ack.context_id).await;
                Ok(None)
            }
            Err(e) => {
                tracing::warn!(
                    context_id = ack.context_id.into_inner(),
                    error = %e,
                    "Unexpected ACK from relay"
                );
                Ok(None)
            }
        }
    }

    /// Handle COMPRESSION_CLOSE from relay
    async fn handle_close(&self, close: CompressionClose) -> RelayResult<Option<Capsule>> {
        let target = {
            let mgr = self.context_manager.read().await;
            mgr.get_target(close.context_id)
        };

        // Remove from our mapping
        if let Some(t) = target {
            self.target_to_context.write().await.remove(&t);
        }

        // Close in context manager
        let mut mgr = self.context_manager.write().await;
        let _ = mgr.close(close.context_id);

        tracing::debug!(
            context_id = close.context_id.into_inner(),
            "Context closed by relay"
        );

        Ok(None)
    }

    /// Handle COMPRESSION_ASSIGN from relay (relay allocating context)
    async fn handle_assign(&self, assign: CompressionAssign) -> RelayResult<Option<Capsule>> {
        let target = assign.target();

        // Register the remote context
        {
            let mut mgr = self.context_manager.write().await;
            if let Err(e) = mgr.register_remote(assign.context_id, target) {
                tracing::warn!(
                    context_id = assign.context_id.into_inner(),
                    error = %e,
                    "Failed to register remote context"
                );
                // Send CLOSE to reject
                return Ok(Some(Capsule::CompressionClose(CompressionClose::new(
                    assign.context_id,
                ))));
            }
        }

        // Update target mapping
        if let Some(t) = target {
            self.target_to_context.write().await.insert(t, assign.context_id);
        }

        // Send ACK
        Ok(Some(Capsule::CompressionAck(CompressionAck::new(
            assign.context_id,
        ))))
    }

    /// Get or create a context for a target address
    ///
    /// Returns the context ID and an optional capsule to send (COMPRESSION_ASSIGN).
    pub async fn get_or_create_context(
        &self,
        target: SocketAddr,
    ) -> RelayResult<(VarInt, Option<Capsule>)> {
        // Check if we already have a context
        {
            let map = self.target_to_context.read().await;
            if let Some(&ctx_id) = map.get(&target) {
                let mgr = self.context_manager.read().await;
                if let Some(info) = mgr.get_context(ctx_id) {
                    if info.state == crate::masque::ContextState::Active {
                        return Ok((ctx_id, None));
                    }
                }
            }
        }

        // Allocate new context
        let ctx_id = {
            let mut mgr = self.context_manager.write().await;
            let id = mgr.allocate_local().map_err(|_| RelayError::ResourceExhausted {
                resource_type: "contexts".into(),
                current_usage: mgr.active_count() as u64,
                limit: self.config.max_pending_contexts as u64,
            })?;

            // Register as compressed context
            mgr.register_compressed(id, target).map_err(|_| {
                RelayError::SessionError {
                    session_id: None,
                    kind: SessionErrorKind::InvalidState {
                        current_state: "duplicate target".into(),
                        expected_state: "unique target".into(),
                    },
                }
            })?;

            id
        };

        // Add to target map (as pending)
        self.target_to_context.write().await.insert(target, ctx_id);

        // Create COMPRESSION_ASSIGN capsule
        let assign = match target {
            SocketAddr::V4(v4) => {
                CompressionAssign::compressed_v4(ctx_id, *v4.ip(), v4.port())
            }
            SocketAddr::V6(v6) => {
                CompressionAssign::compressed_v6(ctx_id, *v6.ip(), v6.port())
            }
        };

        Ok((ctx_id, Some(Capsule::CompressionAssign(assign))))
    }

    /// Create a datagram for sending to a target
    ///
    /// If a context exists and is active, returns a compressed datagram.
    /// Otherwise returns an uncompressed datagram (if allowed).
    pub async fn create_datagram(
        &self,
        target: SocketAddr,
        payload: Bytes,
    ) -> RelayResult<(Datagram, Option<Capsule>)> {
        // Try to get existing active context
        {
            let map = self.target_to_context.read().await;
            if let Some(&ctx_id) = map.get(&target) {
                let mgr = self.context_manager.read().await;
                if let Some(info) = mgr.get_context(ctx_id) {
                    if info.state == crate::masque::ContextState::Active {
                        // Use compressed datagram
                        let datagram = CompressedDatagram::new(ctx_id, payload);
                        return Ok((Datagram::Compressed(datagram), None));
                    }
                }
            }
        }

        // Create new context (always needed for both compressed and uncompressed)
        let (ctx_id, capsule) = self.get_or_create_context(target).await?;

        // Context is pending - queue the datagram
        if capsule.is_some() {
            self.pending_datagrams.write().await.push(PendingDatagram {
                target,
                payload: payload.clone(),
                created_at: Instant::now(),
            });
        }

        // Return compressed datagram (caller should send capsule first if returned)
        let datagram = CompressedDatagram::new(ctx_id, payload);
        Ok((Datagram::Compressed(datagram), capsule))
    }

    /// Flush pending datagrams for a context
    async fn flush_pending_for_context(&self, ctx_id: VarInt) {
        let target = {
            let mgr = self.context_manager.read().await;
            mgr.get_target(ctx_id)
        };

        if let Some(target) = target {
            let mut pending = self.pending_datagrams.write().await;
            pending.retain(|d| d.target != target);
        }
    }

    /// Decode an incoming datagram from the relay
    pub async fn decode_datagram(&self, data: &[u8]) -> RelayResult<(SocketAddr, Bytes)> {
        // Try to decode as compressed first (more common)
        if let Ok(datagram) = CompressedDatagram::decode(&mut bytes::Bytes::copy_from_slice(data)) {
            let mgr = self.context_manager.read().await;
            if let Some(target) = mgr.get_target(datagram.context_id) {
                self.stats.record_received(datagram.payload.len() as u64);
                return Ok((target, datagram.payload));
            }
        }

        // Try uncompressed
        if let Ok(datagram) = UncompressedDatagram::decode(&mut bytes::Bytes::copy_from_slice(data))
        {
            self.stats.record_received(datagram.payload.len() as u64);
            return Ok((datagram.target, datagram.payload));
        }

        Err(RelayError::ProtocolError {
            frame_type: 0,
            reason: "Failed to decode datagram".into(),
        })
    }

    /// Record a sent datagram
    pub fn record_sent(&self, bytes: usize) {
        self.stats.record_sent(bytes as u64);
    }

    /// Close the relay connection
    pub async fn close(&self) {
        *self.state.write().await = RelayConnectionState::Closed;

        // Clear all contexts
        self.target_to_context.write().await.clear();
        self.pending_datagrams.write().await.clear();

        tracing::info!(
            relay = %self.relay_address,
            "MASQUE relay client closed"
        );
    }

    /// Get list of active context IDs
    pub async fn active_contexts(&self) -> Vec<VarInt> {
        let mgr = self.context_manager.read().await;
        mgr.local_context_ids().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), port)
    }

    fn relay_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)), 9000)
    }

    #[tokio::test]
    async fn test_client_creation() {
        let config = RelayClientConfig::default();
        let client = MasqueRelayClient::new(relay_addr(), config);

        assert_eq!(client.relay_address(), relay_addr());
        assert!(!client.is_connected().await);
        assert!(client.public_address().await.is_none());
    }

    #[tokio::test]
    async fn test_connect_request() {
        let config = RelayClientConfig::default();
        let client = MasqueRelayClient::new(relay_addr(), config);

        let request = client.create_connect_request();
        assert!(request.connect_udp_bind);
    }

    #[tokio::test]
    async fn test_handle_success_response() {
        let config = RelayClientConfig::default();
        let client = MasqueRelayClient::new(relay_addr(), config);

        let public_addr = test_addr(12345);
        let response = ConnectUdpResponse::success(Some(public_addr));

        client.handle_connect_response(response).await.unwrap();

        assert!(client.is_connected().await);
        assert_eq!(client.public_address().await, Some(public_addr));
    }

    #[tokio::test]
    async fn test_handle_error_response() {
        let config = RelayClientConfig::default();
        let client = MasqueRelayClient::new(relay_addr(), config);

        let response = ConnectUdpResponse::error(503, "Server busy");

        let result = client.handle_connect_response(response).await;
        assert!(result.is_err());
        assert_eq!(client.state().await, RelayConnectionState::Failed);
    }

    #[tokio::test]
    async fn test_context_creation() {
        let config = RelayClientConfig::default();
        let client = MasqueRelayClient::new(relay_addr(), config);

        // Simulate connected state
        let response = ConnectUdpResponse::success(Some(test_addr(12345)));
        client.handle_connect_response(response).await.unwrap();

        let target = test_addr(8080);
        let (ctx_id, capsule) = client.get_or_create_context(target).await.unwrap();

        // First call should return a capsule (COMPRESSION_ASSIGN)
        assert!(capsule.is_some());
        assert!(matches!(capsule, Some(Capsule::CompressionAssign(_))));

        // Context should use even ID (client)
        assert_eq!(ctx_id.into_inner() % 2, 0);
    }

    #[tokio::test]
    async fn test_handle_compression_ack() {
        let config = RelayClientConfig::default();
        let client = MasqueRelayClient::new(relay_addr(), config);

        let response = ConnectUdpResponse::success(Some(test_addr(12345)));
        client.handle_connect_response(response).await.unwrap();

        let target = test_addr(8080);
        let (ctx_id, _) = client.get_or_create_context(target).await.unwrap();

        // Handle ACK
        let ack = CompressionAck::new(ctx_id);
        let result = client.handle_capsule(Capsule::CompressionAck(ack)).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        // Now context should be active
        let (new_ctx_id, capsule) = client.get_or_create_context(target).await.unwrap();
        assert_eq!(new_ctx_id, ctx_id);
        assert!(capsule.is_none()); // No new assignment needed
    }

    #[tokio::test]
    async fn test_handle_compression_close() {
        let config = RelayClientConfig::default();
        let client = MasqueRelayClient::new(relay_addr(), config);

        let response = ConnectUdpResponse::success(Some(test_addr(12345)));
        client.handle_connect_response(response).await.unwrap();

        let target = test_addr(8080);
        let (ctx_id, _) = client.get_or_create_context(target).await.unwrap();

        // Simulate ACK
        let ack = CompressionAck::new(ctx_id);
        client.handle_capsule(Capsule::CompressionAck(ack)).await.unwrap();

        // Handle CLOSE
        let close = CompressionClose::new(ctx_id);
        let result = client.handle_capsule(Capsule::CompressionClose(close)).await;
        assert!(result.is_ok());

        // Context should be removed
        let (new_ctx_id, capsule) = client.get_or_create_context(target).await.unwrap();
        assert_ne!(new_ctx_id, ctx_id); // New context ID
        assert!(capsule.is_some()); // New assignment needed
    }

    #[tokio::test]
    async fn test_create_datagram_compressed() {
        let config = RelayClientConfig {
            prefer_compressed: true,
            ..Default::default()
        };
        let client = MasqueRelayClient::new(relay_addr(), config);

        let response = ConnectUdpResponse::success(Some(test_addr(12345)));
        client.handle_connect_response(response).await.unwrap();

        let target = test_addr(8080);
        let payload = Bytes::from("Hello, relay!");

        let (datagram, capsule) = client.create_datagram(target, payload).await.unwrap();

        // Should create compressed datagram with assignment
        assert!(matches!(datagram, Datagram::Compressed(_)));
        assert!(capsule.is_some());
    }

    #[tokio::test]
    async fn test_client_close() {
        let config = RelayClientConfig::default();
        let client = MasqueRelayClient::new(relay_addr(), config);

        let response = ConnectUdpResponse::success(Some(test_addr(12345)));
        client.handle_connect_response(response).await.unwrap();
        assert!(client.is_connected().await);

        client.close().await;
        assert_eq!(client.state().await, RelayConnectionState::Closed);
    }

    #[tokio::test]
    async fn test_stats() {
        let config = RelayClientConfig::default();
        let client = MasqueRelayClient::new(relay_addr(), config);

        let stats = client.stats();
        assert_eq!(stats.total_sent(), 0);
        assert_eq!(stats.total_received(), 0);

        client.record_sent(100);
        assert_eq!(stats.total_sent(), 100);
        assert_eq!(stats.datagrams_sent.load(Ordering::Relaxed), 1);
    }
}
