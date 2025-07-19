//! QUIC-based P2P node with NAT traversal
//!
//! This module provides a QUIC-based implementation of the P2P node
//! that integrates with the NAT traversal protocol.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use tracing::{debug, info, error};

use crate::{
    nat_traversal_api::{
        NatTraversalEndpoint, NatTraversalConfig, NatTraversalEvent,
        EndpointRole, PeerId, NatTraversalError,
    },
};

/// QUIC-based P2P node with NAT traversal
pub struct QuicP2PNode {
    /// NAT traversal endpoint
    nat_endpoint: Arc<NatTraversalEndpoint>,
    /// Active peer connections (maps peer ID to their socket address)
    connected_peers: Arc<tokio::sync::RwLock<HashMap<PeerId, SocketAddr>>>,
    /// Node statistics
    stats: Arc<tokio::sync::Mutex<NodeStats>>,
    /// Node configuration
    config: QuicNodeConfig,
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
        }
    }
}

/// Node statistics
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
    pub async fn new(config: QuicNodeConfig) -> Result<Self, Box<dyn std::error::Error>> {
        // Create NAT traversal configuration
        let nat_config = NatTraversalConfig {
            role: config.role,
            bootstrap_nodes: config.bootstrap_nodes.clone(),
            max_candidates: 50,
            coordination_timeout: Duration::from_secs(10),
            enable_symmetric_nat: true,
            enable_relay_fallback: true,
            max_concurrent_attempts: 5,
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
        let nat_endpoint = Arc::new(
            NatTraversalEndpoint::new(nat_config, Some(event_callback)).await?
        );

        Ok(Self {
            nat_endpoint,
            connected_peers: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            stats: stats_clone,
            config,
        })
    }

    /// Connect to a peer using NAT traversal
    pub async fn connect_to_peer(
        &self,
        peer_id: PeerId,
        coordinator: SocketAddr,
    ) -> Result<SocketAddr, NatTraversalError> {
        info!("Initiating connection to peer {:?} via coordinator {}", peer_id, coordinator);
        
        // Update stats
        {
            let mut stats = self.stats.lock().await;
            stats.nat_traversal_attempts += 1;
        }

        // Initiate NAT traversal
        self.nat_endpoint.initiate_nat_traversal(peer_id, coordinator)?;

        // Poll for completion (in production, this would be event-driven)
        let start = Instant::now();
        let timeout = self.config.connection_timeout;
        
        while start.elapsed() < timeout {
            let events = self.nat_endpoint.poll(Instant::now())?;
            
            for event in events {
                match event {
                    NatTraversalEvent::ConnectionEstablished { peer_id: evt_peer, remote_address } => {
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
                            
                            info!("Successfully connected to peer {:?} at {}", peer_id, remote_address);
                            return Ok(remote_address);
                        }
                    }
                    NatTraversalEvent::TraversalFailed { peer_id: evt_peer, error, fallback_available: _ } => {
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
    pub async fn accept(&self) -> Result<(SocketAddr, PeerId), Box<dyn std::error::Error>> {
        info!("Waiting for incoming connection...");
        
        // Accept connection through the NAT traversal endpoint
        match self.nat_endpoint.accept_connection().await {
            Ok((peer_id, connection)) => {
                let remote_addr = connection.remote_address();
                
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
                
                info!("Accepted connection from peer {:?} at {}", peer_id, remote_addr);
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
    ) -> Result<(), Box<dyn std::error::Error>> {
        let peers = self.connected_peers.read().await;
        
        if let Some(remote_addr) = peers.get(peer_id) {
            debug!("Sending {} bytes to peer {:?} at {}", data.len(), peer_id, remote_addr);
            
            // Get the Quinn connection for this peer from the NAT traversal endpoint
            match self.nat_endpoint.get_connection(peer_id) {
                Ok(Some(connection)) => {
                    // Open a unidirectional stream for data transmission
                    let mut send_stream = connection.open_uni().await
                        .map_err(|e| format!("Failed to open unidirectional stream: {}", e))?;
                    
                    // Send the data
                    send_stream.write_all(data).await
                        .map_err(|e| format!("Failed to write data: {}", e))?;
                    
                    // Finish the stream
                    send_stream.finish().map_err(|e| format!("Failed to finish stream: {}", e))?;
                    
                    debug!("Successfully sent {} bytes to peer {:?}", data.len(), peer_id);
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
    pub async fn receive(&self) -> Result<(PeerId, Vec<u8>), Box<dyn std::error::Error>> {
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
                    match tokio::time::timeout(Duration::from_millis(100), connection.accept_uni()).await {
                        Ok(Ok(mut recv_stream)) => {
                            debug!("Receiving data from unidirectional stream from peer {:?}", peer_id);
                            
                            // Read all data from the stream
                            match recv_stream.read_to_end(1024 * 1024).await { // 1MB limit
                                Ok(buffer) => {
                                    if !buffer.is_empty() {
                                        debug!("Received {} bytes from peer {:?}", buffer.len(), peer_id);
                                        return Ok((*peer_id, buffer));
                                    }
                                }
                                Err(e) => {
                                    debug!("Failed to read from stream for peer {:?}: {}", peer_id, e);
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
                    match tokio::time::timeout(Duration::from_millis(100), connection.accept_bi()).await {
                        Ok(Ok((_send_stream, mut recv_stream))) => {
                            debug!("Receiving data from bidirectional stream from peer {:?}", peer_id);
                            
                            // Read all data from the receive side
                            match recv_stream.read_to_end(1024 * 1024).await { // 1MB limit
                                Ok(buffer) => {
                                    if !buffer.is_empty() {
                                        debug!("Received {} bytes from peer {:?} via bidirectional stream", buffer.len(), peer_id);
                                        return Ok((*peer_id, buffer));
                                    }
                                }
                                Err(e) => {
                                    debug!("Failed to read from bidirectional stream for peer {:?}: {}", peer_id, e);
                                }
                            }
                        }
                        Ok(Err(e)) => {
                            debug!("Failed to accept bidirectional stream from peer {:?}: {}", peer_id, e);
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
    pub fn get_nat_endpoint(&self) -> Result<&NatTraversalEndpoint, Box<dyn std::error::Error + Send + Sync>> {
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
}

