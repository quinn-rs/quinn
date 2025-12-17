// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! QUIC-based P2P node with NAT traversal
//!
//! This module provides a QUIC-based implementation of the P2P node
//! that integrates with the NAT traversal protocol.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use tracing::{debug, error, info};

use crate::{
    auth::{AuthConfig, AuthManager, AuthMessage, AuthProtocol},
    crypto::raw_public_keys::key_utils::{
        derive_peer_id_from_public_key, generate_ed25519_keypair,
    },
    nat_traversal_api::{
        EndpointRole, NatTraversalConfig, NatTraversalEndpoint, NatTraversalError,
        NatTraversalEvent, NatTraversalStatistics, PeerId,
    },
};

/// QUIC-based P2P node with NAT traversal
#[derive(Clone, Debug)]
pub struct QuicP2PNode {
    /// NAT traversal endpoint
    nat_endpoint: Arc<NatTraversalEndpoint>,
    /// Active peer connections (maps peer ID to their socket address)
    connected_peers: Arc<tokio::sync::RwLock<HashMap<PeerId, SocketAddr>>>,
    /// Node statistics
    stats: Arc<tokio::sync::Mutex<NodeStats>>,
    /// Node configuration
    config: QuicNodeConfig,
    /// Authentication manager
    auth_manager: Arc<AuthManager>,
    /// Our peer ID
    peer_id: PeerId,
    /// Shutdown signal for graceful termination
    shutdown: Arc<AtomicBool>,
}

/// Configuration for QUIC P2P node
#[derive(Debug, Clone)]
pub struct QuicNodeConfig {
    /// Role of this node
    pub role: EndpointRole,
    /// Bootstrap nodes
    pub bootstrap_nodes: Vec<SocketAddr>,
    /// Enable coordinator services
    pub enable_coordinator: bool,
    /// Max concurrent connections
    pub max_connections: usize,
    /// Connection timeout
    pub connection_timeout: Duration,
    /// Statistics interval
    pub stats_interval: Duration,
    /// Authentication configuration
    pub auth_config: AuthConfig,
    /// Bind address for the node
    pub bind_addr: Option<SocketAddr>,
}

impl Default for QuicNodeConfig {
    fn default() -> Self {
        Self {
            role: EndpointRole::Client,
            bootstrap_nodes: Vec::new(),
            enable_coordinator: false,
            max_connections: 100,
            connection_timeout: Duration::from_secs(30),
            stats_interval: Duration::from_secs(30),
            auth_config: AuthConfig::default(),
            bind_addr: None,
        }
    }
}

/// Basic per-connection performance metrics
#[derive(Debug, Clone)]
pub struct ConnectionMetrics {
    /// Bytes sent to this peer
    pub bytes_sent: u64,
    /// Bytes received from this peer
    pub bytes_received: u64,
    /// Round-trip time
    pub rtt: Option<Duration>,
    /// Packet loss rate (0.0 to 1.0)
    pub packet_loss: f64,
}

/// Aggregate node statistics for monitoring and telemetry
#[derive(Debug, Clone)]
pub struct NodeStats {
    /// Number of active connections
    pub active_connections: usize,
    /// Total successful connections
    pub successful_connections: u64,
    /// Total failed connections
    pub failed_connections: u64,
    /// NAT traversal attempts
    pub nat_traversal_attempts: u64,
    /// Successful NAT traversals
    pub nat_traversal_successes: u64,
    /// Node start time
    pub start_time: Instant,
}

impl Default for NodeStats {
    fn default() -> Self {
        Self {
            active_connections: 0,
            successful_connections: 0,
            failed_connections: 0,
            nat_traversal_attempts: 0,
            nat_traversal_successes: 0,
            start_time: Instant::now(),
        }
    }
}

impl QuicP2PNode {
    /// Create a new QUIC P2P node
    pub async fn new(
        config: QuicNodeConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Generate Ed25519 keypair for authentication
        let (secret_key, public_key) = generate_ed25519_keypair();
        let peer_id = derive_peer_id_from_public_key(&public_key);

        info!("Creating QUIC P2P node with peer ID: {:?}", peer_id);

        // Create authentication manager
        let auth_manager = Arc::new(AuthManager::new(secret_key, config.auth_config.clone()));

        // Create NAT traversal configuration
        let nat_config = NatTraversalConfig {
            role: config.role,
            bootstrap_nodes: config.bootstrap_nodes.clone(),
            max_candidates: 50,
            coordination_timeout: Duration::from_secs(10),
            enable_symmetric_nat: true,
            // Bootstrap nodes should not enable relay fallback
            enable_relay_fallback: !matches!(config.role, EndpointRole::Bootstrap),
            max_concurrent_attempts: 5,
            bind_addr: config.bind_addr,
            prefer_rfc_nat_traversal: true, // Default to RFC format for standards compliance
            timeouts: crate::config::nat_timeouts::TimeoutConfig::default(),
        };

        // Create event callback for NAT traversal events
        let stats_clone = Arc::new(tokio::sync::Mutex::new(NodeStats {
            start_time: Instant::now(),
            ..Default::default()
        }));
        let stats_for_callback = Arc::clone(&stats_clone);

        let event_callback = Box::new(move |event: NatTraversalEvent| {
            let stats = stats_for_callback.clone();
            tokio::spawn(async move {
                let mut stats = stats.lock().await;
                match event {
                    NatTraversalEvent::CoordinationRequested { .. } => {
                        stats.nat_traversal_attempts += 1;
                    }
                    NatTraversalEvent::ConnectionEstablished { .. } => {
                        stats.nat_traversal_successes += 1;
                    }
                    _ => {}
                }
            });
        });

        // Create NAT traversal endpoint
        let nat_endpoint =
            Arc::new(NatTraversalEndpoint::new(nat_config, Some(event_callback)).await?);

        // Initialize shutdown signal
        let shutdown = Arc::new(AtomicBool::new(false));

        // Create the node
        let node = Self {
            nat_endpoint,
            connected_peers: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            stats: stats_clone,
            config,
            auth_manager,
            peer_id,
            shutdown: shutdown.clone(),
        };

        Ok(node)
    }

    /// Get the node configuration
    pub fn get_config(&self) -> &QuicNodeConfig {
        &self.config
    }

    /// Connect directly to a bootstrap node
    pub async fn connect_to_bootstrap(
        &self,
        bootstrap_addr: SocketAddr,
    ) -> Result<PeerId, NatTraversalError> {
        info!("Connecting to bootstrap node at {}", bootstrap_addr);

        // Get the quinn endpoint from NAT traversal endpoint
        let endpoint = self.nat_endpoint.get_quinn_endpoint().ok_or_else(|| {
            NatTraversalError::ConfigError("Quinn endpoint not available".to_string())
        })?;

        // Connect using the QUIC endpoint directly
        match endpoint.connect(bootstrap_addr, "bootstrap-node") {
            Ok(connecting) => {
                match connecting.await {
                    Ok(connection) => {
                        // Extract peer ID from the connection
                        // For now, we'll generate a temporary peer ID based on the address
                        // In a real implementation, we'd exchange peer IDs during the handshake
                        let peer_id = self.derive_peer_id_from_address(bootstrap_addr);

                        // Spawn the NAT traversal handler loop so connection lifecycle events are processed
                        let handler_connection = connection.clone();

                        // Store the connection in NAT endpoint
                        self.nat_endpoint.add_connection(peer_id, connection)?;

                        self.nat_endpoint
                            .spawn_connection_handler(peer_id, handler_connection)?;

                        // Store the peer address mapping
                        self.connected_peers
                            .write()
                            .await
                            .insert(peer_id, bootstrap_addr);

                        // Update stats
                        {
                            let mut stats = self.stats.lock().await;
                            stats.active_connections += 1;
                            stats.successful_connections += 1;
                        }

                        // Fire connection established event
                        if let Some(ref callback) = self.nat_endpoint.get_event_callback() {
                            callback(NatTraversalEvent::ConnectionEstablished {
                                peer_id,
                                remote_address: bootstrap_addr,
                            });
                        }

                        info!(
                            "Successfully connected to bootstrap node {} with peer ID {:?}",
                            bootstrap_addr, peer_id
                        );
                        Ok(peer_id)
                    }
                    Err(e) => {
                        error!(
                            "Failed to establish connection to bootstrap node {}: {}",
                            bootstrap_addr, e
                        );
                        {
                            let mut stats = self.stats.lock().await;
                            stats.failed_connections += 1;
                        }
                        Err(NatTraversalError::NetworkError(format!(
                            "Connection failed: {e}"
                        )))
                    }
                }
            }
            Err(e) => {
                error!(
                    "Failed to initiate connection to bootstrap node {}: {}",
                    bootstrap_addr, e
                );
                {
                    let mut stats = self.stats.lock().await;
                    stats.failed_connections += 1;
                }
                Err(NatTraversalError::NetworkError(format!(
                    "Connect error: {e}"
                )))
            }
        }
    }

    /// Derive a peer ID from a socket address (temporary solution)
    fn derive_peer_id_from_address(&self, addr: SocketAddr) -> PeerId {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        addr.hash(&mut hasher);
        let hash = hasher.finish();

        let mut peer_id_bytes = [0u8; 32];
        peer_id_bytes[..8].copy_from_slice(&hash.to_le_bytes());
        let port_bytes = addr.port().to_le_bytes();
        peer_id_bytes[8..10].copy_from_slice(&port_bytes);

        PeerId(peer_id_bytes)
    }

    /// Connect to a peer using NAT traversal
    pub async fn connect_to_peer(
        &self,
        peer_id: PeerId,
        coordinator: SocketAddr,
    ) -> Result<SocketAddr, NatTraversalError> {
        info!(
            "Initiating connection to peer {:?} via coordinator {}",
            peer_id, coordinator
        );

        // Update stats
        {
            let mut stats = self.stats.lock().await;
            stats.nat_traversal_attempts += 1;
        }

        // Initiate NAT traversal
        self.nat_endpoint
            .initiate_nat_traversal(peer_id, coordinator)?;

        // Poll for completion (in production, this would be event-driven)
        let start = Instant::now();
        let timeout = self.config.connection_timeout;

        while start.elapsed() < timeout {
            let events = self.nat_endpoint.poll(Instant::now())?;

            for event in events {
                match event {
                    NatTraversalEvent::ConnectionEstablished {
                        peer_id: evt_peer,
                        remote_address,
                    } => {
                        if evt_peer == peer_id {
                            // Store peer connection
                            {
                                let mut peers = self.connected_peers.write().await;
                                peers.insert(peer_id, remote_address);
                            }

                            // Update stats
                            {
                                let mut stats = self.stats.lock().await;
                                stats.successful_connections += 1;
                                stats.active_connections += 1;
                                stats.nat_traversal_successes += 1;
                            }

                            info!(
                                "Successfully connected to peer {:?} at {}",
                                peer_id, remote_address
                            );

                            // Perform authentication if required
                            if self.config.auth_config.require_authentication {
                                match self.authenticate_as_initiator(&peer_id).await {
                                    Ok(_) => {
                                        info!("Authentication successful with peer {:?}", peer_id);
                                    }
                                    Err(e) => {
                                        error!(
                                            "Authentication failed with peer {:?}: {}",
                                            peer_id, e
                                        );
                                        // Remove from connected peers
                                        self.connected_peers.write().await.remove(&peer_id);
                                        // Update stats
                                        let mut stats = self.stats.lock().await;
                                        stats.active_connections =
                                            stats.active_connections.saturating_sub(1);
                                        stats.failed_connections += 1;
                                        return Err(NatTraversalError::ConfigError(format!(
                                            "Authentication failed: {e}"
                                        )));
                                    }
                                }
                            }

                            return Ok(remote_address);
                        }
                    }
                    NatTraversalEvent::TraversalFailed {
                        peer_id: evt_peer,
                        error,
                        fallback_available: _,
                    } => {
                        if evt_peer == peer_id {
                            // Update stats
                            {
                                let mut stats = self.stats.lock().await;
                                stats.failed_connections += 1;
                            }

                            error!("NAT traversal failed for peer {:?}: {}", peer_id, error);
                            return Err(error);
                        }
                    }
                    _ => {
                        debug!("Received event: {:?}", event);
                    }
                }
            }

            // Brief sleep to avoid busy waiting
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Timeout
        {
            let mut stats = self.stats.lock().await;
            stats.failed_connections += 1;
        }

        Err(NatTraversalError::Timeout)
    }

    /// Accept incoming connections
    pub async fn accept(
        &self,
    ) -> Result<(SocketAddr, PeerId), Box<dyn std::error::Error + Send + Sync>> {
        info!("Waiting for incoming connection...");

        // Accept connection through the NAT traversal endpoint
        match self.nat_endpoint.accept_connection().await {
            Ok((peer_id, connection)) => {
                let remote_addr = connection.remote_address();

                // Spawn connection handler to monitor the connection
                if let Err(e) = self
                    .nat_endpoint
                    .spawn_connection_handler(peer_id, connection)
                {
                    error!(
                        "Failed to spawn connection handler for peer {:?}: {}",
                        peer_id, e
                    );
                    return Err(Box::new(e));
                }

                // Store the connection
                {
                    let mut peers = self.connected_peers.write().await;
                    peers.insert(peer_id, remote_addr);
                }

                // Update stats
                {
                    let mut stats = self.stats.lock().await;
                    stats.successful_connections += 1;
                    stats.active_connections += 1;
                }

                info!(
                    "Accepted connection from peer {:?} at {}",
                    peer_id, remote_addr
                );

                // Handle authentication if required
                if self.config.auth_config.require_authentication {
                    // Start a task to handle incoming authentication
                    let self_clone = self.clone();
                    let auth_peer_id = peer_id;
                    tokio::spawn(async move {
                        if let Err(e) = self_clone.handle_incoming_auth(auth_peer_id).await {
                            error!(
                                "Failed to handle authentication for peer {:?}: {}",
                                auth_peer_id, e
                            );
                            // Remove the peer if auth fails
                            self_clone
                                .connected_peers
                                .write()
                                .await
                                .remove(&auth_peer_id);
                            let mut stats = self_clone.stats.lock().await;
                            stats.active_connections = stats.active_connections.saturating_sub(1);
                        }
                    });
                }

                Ok((remote_addr, peer_id))
            }
            Err(e) => {
                // Update stats
                {
                    let mut stats = self.stats.lock().await;
                    stats.failed_connections += 1;
                }

                error!("Failed to accept connection: {}", e);
                Err(Box::new(e))
            }
        }
    }

    /// Send data to a peer
    pub async fn send_to_peer(
        &self,
        peer_id: &PeerId,
        data: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        debug!(
            "Attempting to send {} bytes to peer {:?}",
            data.len(),
            peer_id
        );

        let peers = self.connected_peers.read().await;

        if let Some(remote_addr) = peers.get(peer_id) {
            debug!("Found peer {:?} at {}", peer_id, remote_addr);

            // Get the Quinn connection for this peer from the NAT traversal endpoint
            match self.nat_endpoint.get_connection(peer_id) {
                Ok(Some(connection)) => {
                    // Open a unidirectional stream for data transmission
                    let mut send_stream = connection
                        .open_uni()
                        .await
                        .map_err(|e| format!("Failed to open unidirectional stream: {e}"))?;

                    // Send the data
                    send_stream
                        .write_all(data)
                        .await
                        .map_err(|e| format!("Failed to write data: {e}"))?;

                    // Finish the stream
                    send_stream
                        .finish()
                        .map_err(|e| format!("Failed to finish stream: {e}"))?;

                    debug!(
                        "Successfully sent {} bytes to peer {:?}",
                        data.len(),
                        peer_id
                    );
                    Ok(())
                }
                Ok(None) => {
                    error!("No active connection found for peer {:?}", peer_id);
                    Err("No active connection".into())
                }
                Err(e) => {
                    error!("Failed to get connection for peer {:?}: {}", peer_id, e);
                    Err(Box::new(e))
                }
            }
        } else {
            error!("Peer {:?} not connected", peer_id);
            Err("Peer not connected".into())
        }
    }

    /// Receive data from peers
    pub async fn receive(
        &self,
    ) -> Result<(PeerId, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
        debug!("Waiting to receive data from any connected peer...");

        // Get all connected peers
        let peers = {
            let peers_guard = self.connected_peers.read().await;
            peers_guard.clone()
        };

        if peers.is_empty() {
            return Err("No connected peers".into());
        }

        // Try to receive data from any connected peer
        // In a real implementation, this would use a more sophisticated approach
        // like select! over multiple connection streams
        for (peer_id, _remote_addr) in peers.iter() {
            match self.nat_endpoint.get_connection(peer_id) {
                Ok(Some(connection)) => {
                    // Try to accept incoming unidirectional streams
                    match tokio::time::timeout(Duration::from_millis(100), connection.accept_uni())
                        .await
                    {
                        Ok(Ok(mut recv_stream)) => {
                            debug!(
                                "Receiving data from unidirectional stream from peer {:?}",
                                peer_id
                            );

                            // Read all data from the stream
                            match recv_stream.read_to_end(1024 * 1024).await {
                                // 1MB limit
                                Ok(buffer) => {
                                    if !buffer.is_empty() {
                                        debug!(
                                            "Received {} bytes from peer {:?}",
                                            buffer.len(),
                                            peer_id
                                        );
                                        return Ok((*peer_id, buffer));
                                    }
                                }
                                Err(e) => {
                                    debug!(
                                        "Failed to read from stream for peer {:?}: {}",
                                        peer_id, e
                                    );
                                }
                            }
                        }
                        Ok(Err(e)) => {
                            debug!("Failed to accept uni stream from peer {:?}: {}", peer_id, e);
                        }
                        Err(_) => {
                            // Timeout - try bidirectional streams
                        }
                    }

                    // Also try to accept bidirectional streams
                    match tokio::time::timeout(Duration::from_millis(100), connection.accept_bi())
                        .await
                    {
                        Ok(Ok((_send_stream, mut recv_stream))) => {
                            debug!(
                                "Receiving data from bidirectional stream from peer {:?}",
                                peer_id
                            );

                            // Read all data from the receive side
                            match recv_stream.read_to_end(1024 * 1024).await {
                                // 1MB limit
                                Ok(buffer) => {
                                    if !buffer.is_empty() {
                                        debug!(
                                            "Received {} bytes from peer {:?} via bidirectional stream",
                                            buffer.len(),
                                            peer_id
                                        );
                                        return Ok((*peer_id, buffer));
                                    }
                                }
                                Err(e) => {
                                    debug!(
                                        "Failed to read from bidirectional stream for peer {:?}: {}",
                                        peer_id, e
                                    );
                                }
                            }
                        }
                        Ok(Err(e)) => {
                            debug!(
                                "Failed to accept bidirectional stream from peer {:?}: {}",
                                peer_id, e
                            );
                        }
                        Err(_) => {
                            // Timeout - continue to next peer
                        }
                    }
                }
                Ok(None) => {
                    debug!("No active connection for peer {:?}", peer_id);
                }
                Err(e) => {
                    debug!("Failed to get connection for peer {:?}: {}", peer_id, e);
                }
            }
        }

        // If we get here, no data was received from any peer
        Err("No data available from any connected peer".into())
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> NodeStats {
        self.stats.lock().await.clone()
    }

    /// Get access to the NAT traversal endpoint
    pub fn get_nat_endpoint(
        &self,
    ) -> Result<&NatTraversalEndpoint, Box<dyn std::error::Error + Send + Sync>> {
        Ok(&*self.nat_endpoint)
    }

    /// Start periodic statistics reporting
    pub fn start_stats_task(&self) -> tokio::task::JoinHandle<()> {
        let stats = Arc::clone(&self.stats);
        let interval_duration = self.config.stats_interval;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(interval_duration);

            loop {
                interval.tick().await;

                let stats_snapshot = stats.lock().await.clone();

                info!(
                    "Node statistics - Connections: {}/{}, NAT traversal: {}/{}",
                    stats_snapshot.active_connections,
                    stats_snapshot.successful_connections,
                    stats_snapshot.nat_traversal_successes,
                    stats_snapshot.nat_traversal_attempts
                );
            }
        })
    }

    /// Get NAT traversal statistics
    pub async fn get_nat_stats(
        &self,
    ) -> Result<NatTraversalStatistics, Box<dyn std::error::Error + Send + Sync>> {
        self.nat_endpoint.get_nat_stats()
    }

    /// Get the external/reflexive address as observed by remote peers
    ///
    /// This returns the public address of this endpoint as seen by other peers,
    /// discovered via OBSERVED_ADDRESS frames during QUIC connections.
    ///
    /// Returns `None` if:
    /// - No connections are active
    /// - No OBSERVED_ADDRESS frame has been received from any peer
    pub fn get_observed_external_address(
        &self,
    ) -> Result<Option<std::net::SocketAddr>, Box<dyn std::error::Error + Send + Sync>> {
        self.nat_endpoint
            .get_observed_external_address()
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }

    // OBSERVED_ADDRESS integration is handled within the connection; manual injection removed

    /// Get connection metrics for a specific peer
    pub async fn get_connection_metrics(
        &self,
        peer_id: &PeerId,
    ) -> Result<ConnectionMetrics, Box<dyn std::error::Error + Send + Sync>> {
        match self.nat_endpoint.get_connection(peer_id) {
            Ok(Some(connection)) => {
                // Get basic RTT from the connection
                let rtt = connection.rtt();

                // Get congestion window and other stats
                let stats = connection.stats();

                Ok(ConnectionMetrics {
                    bytes_sent: stats.udp_tx.bytes,
                    bytes_received: stats.udp_rx.bytes,
                    rtt: Some(rtt),
                    packet_loss: stats.path.lost_packets as f64
                        / (stats.path.sent_packets + stats.path.lost_packets).max(1) as f64,
                })
            }
            Ok(None) => Err("Connection not found".into()),
            Err(e) => Err(format!("Failed to get connection: {e}").into()),
        }
    }

    /// Get this node's peer ID
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Get this node's public key bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.auth_manager.public_key_bytes()
    }

    /// Send an authentication message to a peer
    async fn send_auth_message(
        &self,
        peer_id: &PeerId,
        message: AuthMessage,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let data = AuthManager::serialize_message(&message)?;
        self.send_to_peer(peer_id, &data).await
    }

    /// Perform authentication handshake as initiator
    async fn authenticate_as_initiator(
        &self,
        peer_id: &PeerId,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Starting authentication with peer {:?}", peer_id);

        // Send authentication request
        let auth_request = self.auth_manager.create_auth_request();
        self.send_auth_message(peer_id, auth_request).await?;

        // Wait for challenge
        let timeout_duration = self.config.auth_config.auth_timeout;
        let start = Instant::now();

        while start.elapsed() < timeout_duration {
            match tokio::time::timeout(Duration::from_secs(1), self.receive()).await {
                Ok(Ok((recv_peer_id, data))) => {
                    if recv_peer_id == *peer_id {
                        match AuthManager::deserialize_message(&data) {
                            Ok(AuthMessage::Challenge { nonce, .. }) => {
                                // Create and send challenge response
                                let response =
                                    self.auth_manager.create_challenge_response(nonce)?;
                                self.send_auth_message(peer_id, response).await?;
                            }
                            Ok(AuthMessage::AuthSuccess { .. }) => {
                                info!("Authentication successful with peer {:?}", peer_id);
                                return Ok(());
                            }
                            Ok(AuthMessage::AuthFailure { reason }) => {
                                return Err(format!("Authentication failed: {reason}").into());
                            }
                            _ => continue,
                        }
                    }
                }
                _ => continue,
            }
        }

        Err("Authentication timeout".into())
    }

    /// Handle incoming authentication messages
    async fn handle_auth_message(
        &self,
        peer_id: PeerId,
        message: AuthMessage,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let auth_protocol = AuthProtocol::new(Arc::clone(&self.auth_manager));

        match auth_protocol.handle_message(peer_id, message).await {
            Ok(Some(response)) => {
                self.send_auth_message(&peer_id, response).await?;
            }
            Ok(None) => {
                // No response needed
            }
            Err(e) => {
                error!("Authentication error: {}", e);
                let failure = AuthMessage::AuthFailure {
                    reason: e.to_string(),
                };
                self.send_auth_message(&peer_id, failure).await?;
                return Err(Box::new(e));
            }
        }

        Ok(())
    }

    /// Check if a peer is authenticated
    pub async fn is_peer_authenticated(&self, peer_id: &PeerId) -> bool {
        self.auth_manager.is_authenticated(peer_id).await
    }

    /// Get list of authenticated peers
    pub async fn list_authenticated_peers(&self) -> Vec<PeerId> {
        self.auth_manager.list_authenticated_peers().await
    }

    /// Handle incoming authentication from a peer
    async fn handle_incoming_auth(
        &self,
        peer_id: PeerId,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Handling incoming authentication from peer {:?}", peer_id);

        let timeout_duration = self.config.auth_config.auth_timeout;
        let start = Instant::now();

        while start.elapsed() < timeout_duration {
            match tokio::time::timeout(Duration::from_secs(1), self.receive()).await {
                Ok(Ok((recv_peer_id, data))) => {
                    if recv_peer_id == peer_id {
                        match AuthManager::deserialize_message(&data) {
                            Ok(auth_msg) => {
                                self.handle_auth_message(peer_id, auth_msg).await?;

                                // Check if authentication is complete
                                if self.auth_manager.is_authenticated(&peer_id).await {
                                    info!("Peer {:?} successfully authenticated", peer_id);
                                    return Ok(());
                                }
                            }
                            Err(_) => {
                                // Not an auth message, ignore
                                continue;
                            }
                        }
                    }
                }
                _ => continue,
            }
        }

        Err("Authentication timeout waiting for peer".into())
    }

    /// Get the metrics collector for Prometheus export
    pub fn get_metrics_collector(
        &self,
    ) -> Result<Arc<crate::logging::MetricsCollector>, &'static str> {
        // For now, create a new metrics collector
        // In a full implementation, this would be a field in the struct
        // and properly wired up to collect actual metrics
        Ok(Arc::new(crate::logging::MetricsCollector::new()))
    }

    /// Gracefully shutdown the node and close all connections
    pub fn shutdown(&self) {
        info!("Shutting down QuicP2PNode");
        self.shutdown.store(true, Ordering::SeqCst);

        // Close the Quinn endpoint to terminate all connections
        if let Some(endpoint) = self.nat_endpoint.get_quinn_endpoint() {
            endpoint.close(0u32.into(), b"node shutdown");
        }
    }
}

/// Automatic cleanup when QuicP2PNode is dropped
impl Drop for QuicP2PNode {
    fn drop(&mut self) {
        self.shutdown();
    }
}
