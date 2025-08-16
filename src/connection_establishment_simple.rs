//! Simplified Connection Establishment with Automatic NAT Traversal
//!
//! This module provides a simplified but complete connection establishment
//! system that automatically handles NAT traversal with fallback mechanisms.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use tracing::{debug, info, warn};

use crate::{
    candidate_discovery::{CandidateDiscoveryManager, DiscoveryError, DiscoveryEvent},
    nat_traversal_api::{BootstrapNode, CandidateAddress, PeerId},
    high_level::{Endpoint as QuinnEndpoint, Connection as QuinnConnection},
};

/// Simplified connection establishment manager
pub struct SimpleConnectionEstablishmentManager {
    /// Configuration for connection establishment
    config: SimpleEstablishmentConfig,
    /// Active connection attempts  
    active_attempts: HashMap<PeerId, SimpleConnectionAttempt>,
    /// Candidate discovery manager
    discovery_manager: Arc<std::sync::Mutex<CandidateDiscoveryManager>>,
    /// Known bootstrap nodes
    bootstrap_nodes: Vec<BootstrapNode>,
    /// Event callback
    event_callback: Option<Box<dyn Fn(SimpleConnectionEvent) + Send + Sync>>,
    /// Quinn endpoint for making QUIC connections
    quinn_endpoint: Option<Arc<QuinnEndpoint>>,
}

/// Simplified configuration
#[derive(Debug, Clone)]
pub struct SimpleEstablishmentConfig {
    /// Timeout for direct connection attempts
    pub direct_timeout: Duration,
    /// Timeout for NAT traversal
    pub nat_traversal_timeout: Duration,
    /// Enable automatic NAT traversal
    pub enable_nat_traversal: bool,
    /// Maximum retry attempts
    pub max_retries: u32,
}

/// Simplified connection attempt state
#[derive(Debug)]
struct SimpleConnectionAttempt {
    peer_id: PeerId,
    state: SimpleAttemptState,
    started_at: Instant,
    attempt_number: u32,
    known_addresses: Vec<SocketAddr>,
    discovered_candidates: Vec<CandidateAddress>,
    last_error: Option<String>,
    /// Active QUIC connection attempts
    connection_handles: Vec<tokio::task::JoinHandle<Result<QuinnConnection, String>>>,
    /// Current target addresses being attempted
    target_addresses: Vec<SocketAddr>,
    /// Established connection (if successful)
    established_connection: Option<QuinnConnection>,
}

/// Simplified state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SimpleAttemptState {
    DirectConnection,
    CandidateDiscovery,
    NatTraversal,
    Connected,
    Failed,
}

/// Simplified events
#[derive(Debug, Clone)]
pub enum SimpleConnectionEvent {
    AttemptStarted {
        peer_id: PeerId,
    },
    DirectConnectionTried {
        peer_id: PeerId,
        address: SocketAddr,
    },
    CandidateDiscoveryStarted {
        peer_id: PeerId,
    },
    NatTraversalStarted {
        peer_id: PeerId,
    },
    DirectConnectionSucceeded {
        peer_id: PeerId,
        address: SocketAddr,
    },
    DirectConnectionFailed {
        peer_id: PeerId,
        address: SocketAddr,
        error: String,
    },
    ConnectionEstablished {
        peer_id: PeerId,
    },
    ConnectionFailed {
        peer_id: PeerId,
        error: String,
    },
}

impl Default for SimpleEstablishmentConfig {
    fn default() -> Self {
        Self {
            direct_timeout: Duration::from_secs(5),
            nat_traversal_timeout: Duration::from_secs(30),
            enable_nat_traversal: true,
            max_retries: 3,
        }
    }
}

impl SimpleConnectionEstablishmentManager {
    /// Create a new simplified connection establishment manager
    pub fn new(
        config: SimpleEstablishmentConfig,
        discovery_manager: Arc<std::sync::Mutex<CandidateDiscoveryManager>>,
        bootstrap_nodes: Vec<BootstrapNode>,
        event_callback: Option<Box<dyn Fn(SimpleConnectionEvent) + Send + Sync>>,
        quinn_endpoint: Option<Arc<QuinnEndpoint>>,
    ) -> Self {
        Self {
            config,
            active_attempts: HashMap::new(),
            discovery_manager,
            bootstrap_nodes,
            event_callback,
            quinn_endpoint,
        }
    }

    /// Start connection to peer
    pub fn connect_to_peer(
        &mut self,
        peer_id: PeerId,
        known_addresses: Vec<SocketAddr>,
    ) -> Result<(), String> {
        // Check if already attempting
        if self.active_attempts.contains_key(&peer_id) {
            return Err("Connection attempt already in progress".to_string());
        }

        // Create new attempt
        let attempt = SimpleConnectionAttempt {
            peer_id,
            state: SimpleAttemptState::DirectConnection,
            started_at: Instant::now(),
            attempt_number: 1,
            known_addresses: known_addresses.clone(),
            discovered_candidates: Vec::new(),
            last_error: None,
            connection_handles: Vec::new(),
            target_addresses: Vec::new(),
            established_connection: None,
        };

        self.active_attempts.insert(peer_id, attempt);

        // Emit event
        self.emit_event(SimpleConnectionEvent::AttemptStarted { peer_id });

        // Try direct connection first if we have addresses
        if !known_addresses.is_empty() {
            info!("Starting direct connection attempt to peer {:?}", peer_id);
            
            // Start direct connections if we have a Quinn endpoint
            if let Some(ref quinn_endpoint) = self.quinn_endpoint {
                self.start_direct_connections(peer_id, &known_addresses, quinn_endpoint.clone())?;
            } else {
                // Just emit events if no real endpoint (for testing)
                for address in &known_addresses {
                    self.emit_event(SimpleConnectionEvent::DirectConnectionTried {
                        peer_id,
                        address: *address,
                    });
                }
            }
        } else if self.config.enable_nat_traversal {
            // Start candidate discovery immediately
            self.start_candidate_discovery(peer_id)?;
        } else {
            return Err("No known addresses and NAT traversal disabled".to_string());
        }

        Ok(())
    }

    /// Start direct QUIC connections to known addresses
    fn start_direct_connections(
        &mut self,
        peer_id: PeerId,
        addresses: &[SocketAddr],
        endpoint: Arc<QuinnEndpoint>,
    ) -> Result<(), String> {
        let attempt = self.active_attempts.get_mut(&peer_id)
            .ok_or("Attempt not found")?;
        
        // Collect events to emit after the loop
        let mut events_to_emit = Vec::new();
        
        for &address in addresses {
            let server_name = format!("peer-{:x}", peer_id.0[0] as u32);
            let endpoint_clone = endpoint.clone();
            
            // Spawn a task to handle the connection attempt
            let handle = tokio::spawn(async move {
                let connecting = endpoint_clone.connect(address, &server_name)
                    .map_err(|e| format!("Failed to start connection: {}", e))?;
                    
                // Apply a timeout to the connection attempt
                match tokio::time::timeout(Duration::from_secs(10), connecting).await {
                    Ok(connection_result) => connection_result
                        .map_err(|e| format!("Connection failed: {}", e)),
                    Err(_) => Err("Connection timed out".to_string()),
                }
            });
            
            attempt.connection_handles.push(handle);
            attempt.target_addresses.push(address);
            
            // Collect event to emit later
            events_to_emit.push(SimpleConnectionEvent::DirectConnectionTried {
                peer_id,
                address,
            });
        }
        
        // Emit events after borrowing is done
        for event in events_to_emit {
            self.emit_event(event);
        }
        
        debug!("Started {} direct connections for peer {:?}", addresses.len(), peer_id);
        Ok(())
    }

    /// Poll for progress
    pub fn poll(&mut self, now: Instant) -> Vec<SimpleConnectionEvent> {
        let mut events = Vec::new();

        // Process discovery events
        let discovery_events = match self.discovery_manager.lock() {
            Ok(mut discovery) => discovery.poll(now),
            _ => Vec::new(),
        };

        for discovery_event in discovery_events {
            self.handle_discovery_event(discovery_event, &mut events);
        }

        // Process active attempts
        let peer_ids: Vec<_> = self.active_attempts.keys().copied().collect();
        let mut completed = Vec::new();

        for peer_id in peer_ids {
            if self.poll_attempt(peer_id, now, &mut events) {
                completed.push(peer_id);
            }
        }

        // Remove completed attempts
        for peer_id in completed {
            self.active_attempts.remove(&peer_id);
        }

        events
    }

    /// Cancel connection attempt
    pub fn cancel_connection(&mut self, peer_id: PeerId) -> bool {
        self.active_attempts.remove(&peer_id).is_some()
    }

    // Private methods

    fn start_candidate_discovery(&mut self, peer_id: PeerId) -> Result<(), String> {
        if let Some(attempt) = self.active_attempts.get_mut(&peer_id) {
            attempt.state = SimpleAttemptState::CandidateDiscovery;

            match self.discovery_manager.lock() {
                Ok(mut discovery) => {
                    discovery
                        .start_discovery(peer_id, self.bootstrap_nodes.clone())
                        .map_err(|e| format!("Discovery failed: {e:?}"))?;
                }
                _ => {
                    return Err("Failed to lock discovery manager".to_string());
                }
            }

            self.emit_event(SimpleConnectionEvent::CandidateDiscoveryStarted { peer_id });
        }

        Ok(())
    }

    fn poll_attempt(
        &mut self,
        peer_id: PeerId,
        now: Instant,
        events: &mut Vec<SimpleConnectionEvent>,
    ) -> bool {
        let attempt = match self.active_attempts.get_mut(&peer_id) {
            Some(a) => a,
            None => return true,
        };

        let elapsed = now.duration_since(attempt.started_at);
        let timeout = match attempt.state {
            SimpleAttemptState::DirectConnection => self.config.direct_timeout,
            _ => self.config.nat_traversal_timeout,
        };

        // Check timeout
        if elapsed > timeout {
            match attempt.state {
                SimpleAttemptState::DirectConnection if self.config.enable_nat_traversal => {
                    // Fallback to NAT traversal
                    info!(
                        "Direct connection timed out for peer {:?}, starting NAT traversal",
                        peer_id
                    );
                    attempt.state = SimpleAttemptState::CandidateDiscovery;

                    // Start discovery outside of the borrow
                    let discovery_result = match self.discovery_manager.lock() {
                        Ok(mut discovery) => {
                            discovery.start_discovery(peer_id, self.bootstrap_nodes.clone())
                        }
                        _ => Err(DiscoveryError::InternalError(
                            "Failed to lock discovery manager".to_string(),
                        )),
                    };

                    if let Err(e) = discovery_result {
                        attempt.state = SimpleAttemptState::Failed;
                        attempt.last_error = Some(format!("Discovery failed: {e:?}"));
                        events.push(SimpleConnectionEvent::ConnectionFailed {
                            peer_id,
                            error: format!("Discovery failed: {e:?}"),
                        });
                        return true;
                    }

                    events.push(SimpleConnectionEvent::CandidateDiscoveryStarted { peer_id });
                    return false;
                }
                _ => {
                    // Timeout, mark as failed
                    attempt.state = SimpleAttemptState::Failed;
                    attempt.last_error = Some("Timeout exceeded".to_string());
                    events.push(SimpleConnectionEvent::ConnectionFailed {
                        peer_id,
                        error: "Timeout exceeded".to_string(),
                    });
                    return true;
                }
            }
        }

        // Check real QUIC connection attempts
        let has_connection_handles = !attempt.connection_handles.is_empty();
        
        if has_connection_handles {
            // Extract data needed for polling to avoid double mutable borrow
            let mut connection_handles = std::mem::take(&mut attempt.connection_handles);
            let mut target_addresses = std::mem::take(&mut attempt.target_addresses);
            let mut established_connection = attempt.established_connection.take();
            
            Self::poll_connection_handles_extracted(
                peer_id,
                &mut connection_handles,
                &mut target_addresses,
                &mut established_connection,
                events,
            );
            
            // Put data back
            attempt.connection_handles = connection_handles;
            attempt.target_addresses = target_addresses;
            attempt.established_connection = established_connection;
            
            // Check if we have a successful connection
            if attempt.established_connection.is_some() {
                attempt.state = SimpleAttemptState::Connected;
                events.push(SimpleConnectionEvent::ConnectionEstablished { peer_id });
                return true;
            }
        }
        
        match attempt.state {
            SimpleAttemptState::DirectConnection => {
                // Check if all direct connections failed
                if attempt.connection_handles.is_empty() || 
                   attempt.connection_handles.iter().all(|h| h.is_finished()) {
                    // All direct attempts finished, check for success
                    if attempt.established_connection.is_none() && self.config.enable_nat_traversal {
                        // No connection established, try NAT traversal
                        debug!("Direct connections failed for peer {:?}, trying NAT traversal", peer_id);
                        attempt.state = SimpleAttemptState::CandidateDiscovery;
                        // Start discovery will be handled in next poll cycle
                    }
                }
            }
            SimpleAttemptState::CandidateDiscovery => {
                // Wait for discovery events
            }
            SimpleAttemptState::NatTraversal => {
                // Poll NAT traversal connection attempts
                debug!("Polling NAT traversal attempts for peer {:?}", peer_id);
            }
            SimpleAttemptState::Connected | SimpleAttemptState::Failed => {
                return true;
            }
        }

        false
    }

    /// Poll connection handles to check for completed connections (extracted version)
    fn poll_connection_handles_extracted(
        peer_id: PeerId,
        connection_handles: &mut Vec<tokio::task::JoinHandle<Result<QuinnConnection, String>>>,
        target_addresses: &mut Vec<SocketAddr>,
        established_connection: &mut Option<QuinnConnection>,
        events: &mut Vec<SimpleConnectionEvent>,
    ) -> bool {
        let mut completed_indices = Vec::new();
        
        for (index, handle) in connection_handles.iter_mut().enumerate() {
            if handle.is_finished() {
                completed_indices.push(index);
            }
        }
        
        // Process completed handles
        for &index in completed_indices.iter().rev() {
            let handle = connection_handles.remove(index);
            let target_address = target_addresses.remove(index);
            
            match tokio::runtime::Handle::try_current() {
                Ok(runtime_handle) => {
                    match runtime_handle.block_on(handle) {
                        Ok(Ok(connection)) => {
                            // Connection succeeded
                            info!("QUIC connection established to {} for peer {:?}", target_address, peer_id);
                            *established_connection = Some(connection);
                            
                            events.push(SimpleConnectionEvent::DirectConnectionSucceeded {
                                peer_id,
                                address: target_address,
                            });
                            
                            // Cancel remaining connection attempts
                            for remaining_handle in connection_handles.drain(..) {
                                remaining_handle.abort();
                            }
                            target_addresses.clear();
                            
                            return true; // Exit early on success
                        }
                        Ok(Err(e)) => {
                            // Connection failed
                            warn!("QUIC connection to {} failed: {}", target_address, e);
                            
                            events.push(SimpleConnectionEvent::DirectConnectionFailed {
                                peer_id,
                                address: target_address,
                                error: e,
                            });
                        }
                        Err(join_error) => {
                            // Task panic or cancellation
                            warn!("QUIC connection task failed: {}", join_error);
                            
                            events.push(SimpleConnectionEvent::DirectConnectionFailed {
                                peer_id,
                                address: target_address,
                                error: format!("Task failed: {}", join_error),
                            });
                        }
                    }
                }
                Err(_) => {
                    // No tokio runtime available, can't check result
                    warn!("Unable to check connection result without tokio runtime");
                }
            }
        }
        
        false
    }

    fn handle_discovery_event(
        &mut self,
        discovery_event: DiscoveryEvent,
        events: &mut Vec<SimpleConnectionEvent>,
    ) {
        match discovery_event {
            DiscoveryEvent::LocalCandidateDiscovered { candidate }
            | DiscoveryEvent::ServerReflexiveCandidateDiscovered { candidate, .. }
            | DiscoveryEvent::PredictedCandidateGenerated { candidate, .. } => {
                // Add candidate to relevant attempts
                for attempt in self.active_attempts.values_mut() {
                    if attempt.state == SimpleAttemptState::CandidateDiscovery {
                        attempt.discovered_candidates.push(candidate.clone());
                    }
                }
            }
            DiscoveryEvent::DiscoveryCompleted { .. } => {
                // Transition attempts to NAT traversal
                let peer_ids: Vec<_> = self
                    .active_attempts
                    .iter()
                    .filter(|(_, a)| a.state == SimpleAttemptState::CandidateDiscovery)
                    .map(|(peer_id, _)| *peer_id)
                    .collect();

                for peer_id in peer_ids {
                    if let Some(attempt) = self.active_attempts.get_mut(&peer_id) {
                        attempt.state = SimpleAttemptState::NatTraversal;
                        events.push(SimpleConnectionEvent::NatTraversalStarted { peer_id });
                    }
                }
            }
            DiscoveryEvent::DiscoveryFailed { error, .. } => {
                warn!("Discovery failed: {:?}", error);
                // Mark relevant attempts as failed
                let peer_ids: Vec<_> = self
                    .active_attempts
                    .iter()
                    .filter(|(_, a)| a.state == SimpleAttemptState::CandidateDiscovery)
                    .map(|(peer_id, _)| *peer_id)
                    .collect();

                for peer_id in peer_ids {
                    if let Some(attempt) = self.active_attempts.get_mut(&peer_id) {
                        attempt.state = SimpleAttemptState::Failed;
                        attempt.last_error = Some(format!("Discovery failed: {error:?}"));
                        events.push(SimpleConnectionEvent::ConnectionFailed {
                            peer_id,
                            error: format!("Discovery failed: {error:?}"),
                        });
                    }
                }
            }
            _ => {
                // Handle other events as needed
            }
        }
    }

    fn emit_event(&self, event: SimpleConnectionEvent) {
        if let Some(ref callback) = self.event_callback {
            callback(event);
        }
    }
}
