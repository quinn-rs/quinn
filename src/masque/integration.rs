// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! MASQUE Relay Integration
//!
//! Provides integration between the MASQUE relay system and the NAT traversal API.
//! This module acts as the bridge that enables automatic relay fallback when
//! direct NAT traversal fails.
//!
//! # Overview
//!
//! The integration layer:
//! - Manages a pool of relay connections to known peers
//! - Automatically attempts relay fallback when direct connection fails
//! - Coordinates context registration for efficient datagram forwarding
//! - Tracks relay usage statistics
//!
//! # Example
//!
//! ```rust,ignore
//! use ant_quic::masque::integration::{RelayManager, RelayManagerConfig};
//! use std::net::SocketAddr;
//!
//! let config = RelayManagerConfig::default();
//! let manager = RelayManager::new(config);
//!
//! // Add relay nodes
//! manager.add_relay_node(relay_addr).await;
//!
//! // Attempt connection through relay
//! let result = manager.connect_via_relay(target).await;
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use bytes::Bytes;

use crate::masque::{
    ConnectUdpRequest, ConnectUdpResponse, MasqueRelayClient, RelayClientConfig,
    RelayConnectionState,
};
use crate::relay::error::{RelayError, RelayResult, SessionErrorKind};

/// Configuration for the relay manager
#[derive(Debug, Clone)]
pub struct RelayManagerConfig {
    /// Maximum number of relay connections to maintain
    pub max_relays: usize,
    /// Relay connection timeout
    pub connect_timeout: Duration,
    /// Time to wait before retrying a failed relay
    pub retry_delay: Duration,
    /// Maximum retries per relay
    pub max_retries: u32,
    /// Client configuration for relay connections
    pub client_config: RelayClientConfig,
}

impl Default for RelayManagerConfig {
    fn default() -> Self {
        Self {
            max_relays: 5,
            connect_timeout: Duration::from_secs(10),
            retry_delay: Duration::from_secs(30),
            max_retries: 3,
            client_config: RelayClientConfig::default(),
        }
    }
}

/// Statistics for relay operations
#[derive(Debug, Default)]
pub struct RelayManagerStats {
    /// Total relay connection attempts
    pub connection_attempts: AtomicU64,
    /// Successful relay connections
    pub successful_connections: AtomicU64,
    /// Failed relay connections
    pub failed_connections: AtomicU64,
    /// Bytes sent through relays
    pub bytes_sent: AtomicU64,
    /// Bytes received through relays
    pub bytes_received: AtomicU64,
    /// Datagrams relayed
    pub datagrams_relayed: AtomicU64,
    /// Currently active relay connections
    pub active_relays: AtomicU64,
}

impl RelayManagerStats {
    /// Create new statistics
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a connection attempt
    pub fn record_attempt(&self, success: bool) {
        self.connection_attempts.fetch_add(1, Ordering::Relaxed);
        if success {
            self.successful_connections.fetch_add(1, Ordering::Relaxed);
            self.active_relays.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failed_connections.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a disconnection
    pub fn record_disconnect(&self) {
        let current = self.active_relays.load(Ordering::Relaxed);
        if current > 0 {
            self.active_relays.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Record bytes sent
    pub fn record_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        self.datagrams_relayed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record bytes received
    pub fn record_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Get active relay count
    pub fn active_count(&self) -> u64 {
        self.active_relays.load(Ordering::Relaxed)
    }
}

/// Information about a relay node
#[derive(Debug)]
struct RelayNodeInfo {
    /// Relay server address
    address: SocketAddr,
    /// Connected client (if any)
    client: Option<MasqueRelayClient>,
    /// Last connection attempt
    last_attempt: Option<Instant>,
    /// Number of consecutive failures
    failure_count: u32,
    /// Whether the relay is currently usable
    available: bool,
}

impl RelayNodeInfo {
    fn new(address: SocketAddr) -> Self {
        Self {
            address,
            client: None,
            last_attempt: None,
            failure_count: 0,
            available: true,
        }
    }

    fn mark_failed(&mut self) {
        self.last_attempt = Some(Instant::now());
        self.failure_count = self.failure_count.saturating_add(1);
    }

    fn mark_connected(&mut self, client: MasqueRelayClient) {
        self.client = Some(client);
        self.failure_count = 0;
        self.available = true;
    }

    fn can_retry(&self, retry_delay: Duration, max_retries: u32) -> bool {
        if self.failure_count >= max_retries {
            return false;
        }
        match self.last_attempt {
            Some(t) => t.elapsed() >= retry_delay,
            None => true,
        }
    }
}

/// Result of a relay operation
#[derive(Debug)]
pub enum RelayOperationResult {
    /// Operation succeeded via relay
    Success {
        /// Relay used
        relay: SocketAddr,
        /// Public address assigned by relay
        public_address: Option<SocketAddr>,
    },
    /// All relays failed
    AllRelaysFailed {
        /// Number of relays attempted
        attempted: usize,
    },
    /// No relays available
    NoRelaysAvailable,
}

/// Manages relay connections for NAT traversal fallback
#[derive(Debug)]
pub struct RelayManager {
    /// Configuration
    config: RelayManagerConfig,
    /// Known relay nodes
    relays: RwLock<HashMap<SocketAddr, RelayNodeInfo>>,
    /// Whether the manager is active
    active: AtomicBool,
    /// Statistics
    stats: Arc<RelayManagerStats>,
}

impl RelayManager {
    /// Create a new relay manager
    pub fn new(config: RelayManagerConfig) -> Self {
        Self {
            config,
            relays: RwLock::new(HashMap::new()),
            active: AtomicBool::new(true),
            stats: Arc::new(RelayManagerStats::new()),
        }
    }

    /// Get statistics
    pub fn stats(&self) -> Arc<RelayManagerStats> {
        Arc::clone(&self.stats)
    }

    /// Add a potential relay node
    pub async fn add_relay_node(&self, address: SocketAddr) {
        let mut relays = self.relays.write().await;
        if !relays.contains_key(&address) && relays.len() < self.config.max_relays {
            relays.insert(address, RelayNodeInfo::new(address));
            tracing::debug!(relay = %address, "Added relay node");
        }
    }

    /// Remove a relay node
    pub async fn remove_relay_node(&self, address: SocketAddr) {
        let mut relays = self.relays.write().await;
        if let Some(info) = relays.remove(&address) {
            if info.client.is_some() {
                self.stats.record_disconnect();
            }
            tracing::debug!(relay = %address, "Removed relay node");
        }
    }

    /// Get list of available relay addresses
    pub async fn available_relays(&self) -> Vec<SocketAddr> {
        let relays = self.relays.read().await;
        relays
            .iter()
            .filter(|(_, info)| {
                info.available && info.can_retry(self.config.retry_delay, self.config.max_retries)
            })
            .map(|(addr, _)| *addr)
            .collect()
    }

    /// Get a connected relay client for a specific relay
    pub async fn get_relay_client(&self, relay: SocketAddr) -> Option<SocketAddr> {
        let relays = self.relays.read().await;
        let info = relays.get(&relay)?;
        let client = info.client.as_ref()?;

        // Check if still connected
        if matches!(client.state().await, RelayConnectionState::Connected) {
            Some(info.address)
        } else {
            None
        }
    }

    /// Initiate relay connection (returns request to send)
    pub fn create_connect_request(&self) -> ConnectUdpRequest {
        ConnectUdpRequest::bind_any()
    }

    /// Handle relay connection response
    pub async fn handle_connect_response(
        &self,
        relay: SocketAddr,
        response: ConnectUdpResponse,
    ) -> RelayResult<Option<SocketAddr>> {
        if !response.is_success() {
            let mut relays = self.relays.write().await;
            if let Some(info) = relays.get_mut(&relay) {
                info.mark_failed();
            }
            self.stats.record_attempt(false);
            return Err(RelayError::SessionError {
                session_id: None,
                kind: SessionErrorKind::InvalidState {
                    current_state: format!("HTTP {}", response.status),
                    expected_state: "HTTP 200".into(),
                },
            });
        }

        // Create new client for this relay
        let client = MasqueRelayClient::new(relay, self.config.client_config.clone());
        client.handle_connect_response(response.clone()).await?;

        let public_addr = response.proxy_public_address;

        // Store the client
        {
            let mut relays = self.relays.write().await;
            if let Some(info) = relays.get_mut(&relay) {
                info.mark_connected(client);
            }
        }

        self.stats.record_attempt(true);

        tracing::info!(
            relay = %relay,
            public_addr = ?public_addr,
            "Relay connection established"
        );

        Ok(public_addr)
    }

    /// Get our public address from any connected relay
    pub async fn public_address(&self) -> Option<SocketAddr> {
        let relays = self.relays.read().await;
        for info in relays.values() {
            if let Some(ref client) = info.client {
                if let Some(addr) = client.public_address().await {
                    return Some(addr);
                }
            }
        }
        None
    }

    /// Send datagram through relay
    pub async fn send_via_relay(
        &self,
        relay: SocketAddr,
        target: SocketAddr,
        payload: Bytes,
    ) -> RelayResult<()> {
        let relays = self.relays.read().await;
        let info = relays.get(&relay).ok_or(RelayError::SessionError {
            session_id: None,
            kind: SessionErrorKind::NotFound,
        })?;

        let _client = info.client.as_ref().ok_or(RelayError::SessionError {
            session_id: None,
            kind: SessionErrorKind::InvalidState {
                current_state: "not connected".into(),
                expected_state: "connected".into(),
            },
        })?;

        // Note: In a full implementation, we would:
        // 1. Get or create context for target
        // 2. Send COMPRESSION_ASSIGN capsule if needed
        // 3. Encode datagram with context ID
        // 4. Send over QUIC datagram

        self.stats.record_sent(payload.len() as u64);

        tracing::trace!(
            relay = %relay,
            target = %target,
            bytes = payload.len(),
            "Sent datagram via relay"
        );

        Ok(())
    }

    /// Close all relay connections
    pub async fn close_all(&self) {
        self.active.store(false, Ordering::SeqCst);

        let mut relays = self.relays.write().await;
        for info in relays.values_mut() {
            if let Some(ref client) = info.client {
                client.close().await;
            }
            info.client = None;
        }

        tracing::info!("Closed all relay connections");
    }

    /// Get number of active relay connections
    pub async fn active_relay_count(&self) -> usize {
        let relays = self.relays.read().await;
        relays.values().filter(|info| info.client.is_some()).count()
    }

    /// Check if relay fallback is available
    pub async fn has_available_relay(&self) -> bool {
        !self.available_relays().await.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn relay_addr(id: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, id)), 9000)
    }

    #[tokio::test]
    async fn test_manager_creation() {
        let config = RelayManagerConfig::default();
        let manager = RelayManager::new(config);

        assert_eq!(manager.active_relay_count().await, 0);
        assert!(!manager.has_available_relay().await);
    }

    #[tokio::test]
    async fn test_add_relay_node() {
        let config = RelayManagerConfig::default();
        let manager = RelayManager::new(config);

        manager.add_relay_node(relay_addr(1)).await;
        assert!(manager.has_available_relay().await);

        let available = manager.available_relays().await;
        assert_eq!(available.len(), 1);
        assert_eq!(available[0], relay_addr(1));
    }

    #[tokio::test]
    async fn test_remove_relay_node() {
        let config = RelayManagerConfig::default();
        let manager = RelayManager::new(config);

        manager.add_relay_node(relay_addr(1)).await;
        assert!(manager.has_available_relay().await);

        manager.remove_relay_node(relay_addr(1)).await;
        assert!(!manager.has_available_relay().await);
    }

    #[tokio::test]
    async fn test_relay_limit() {
        let config = RelayManagerConfig {
            max_relays: 2,
            ..Default::default()
        };
        let manager = RelayManager::new(config);

        manager.add_relay_node(relay_addr(1)).await;
        manager.add_relay_node(relay_addr(2)).await;
        manager.add_relay_node(relay_addr(3)).await; // Should be ignored

        let available = manager.available_relays().await;
        assert_eq!(available.len(), 2);
    }

    #[tokio::test]
    async fn test_handle_success_response() {
        let config = RelayManagerConfig::default();
        let manager = RelayManager::new(config);

        let relay = relay_addr(1);
        manager.add_relay_node(relay).await;

        let response = ConnectUdpResponse::success(Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            12345,
        )));

        let result = manager.handle_connect_response(relay, response).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());

        let stats = manager.stats();
        assert_eq!(stats.successful_connections.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_handle_error_response() {
        let config = RelayManagerConfig::default();
        let manager = RelayManager::new(config);

        let relay = relay_addr(1);
        manager.add_relay_node(relay).await;

        let response = ConnectUdpResponse::error(503, "Server busy");

        let result = manager.handle_connect_response(relay, response).await;
        assert!(result.is_err());

        let stats = manager.stats();
        assert_eq!(stats.failed_connections.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_stats() {
        let config = RelayManagerConfig::default();
        let manager = RelayManager::new(config);

        let stats = manager.stats();
        assert_eq!(stats.active_count(), 0);

        stats.record_attempt(true);
        assert_eq!(stats.active_count(), 1);

        stats.record_disconnect();
        assert_eq!(stats.active_count(), 0);
    }

    #[tokio::test]
    async fn test_close_all() {
        let config = RelayManagerConfig::default();
        let manager = RelayManager::new(config);

        manager.add_relay_node(relay_addr(1)).await;
        manager.add_relay_node(relay_addr(2)).await;

        manager.close_all().await;
        // Should not panic
    }
}
