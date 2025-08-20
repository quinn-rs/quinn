// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses


//! Connection Establishment with Automatic NAT Traversal and Fallback
//!
//! This module implements sophisticated connection establishment that automatically
//! detects when NAT traversal is needed and provides comprehensive fallback
//! mechanisms for maximum connectivity.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use tracing::{debug, info, warn};

use crate::high_level::{Endpoint as QuinnEndpoint, Connection as QuinnConnection, Connecting};

use crate::{
    candidate_discovery::{CandidateDiscoveryManager, DiscoveryEvent, DiscoveryError},
    nat_traversal_api::{BootstrapNode, CandidateAddress, EndpointRole, PeerId},
};

/// High-level connection establishment manager
pub struct ConnectionEstablishmentManager {
    /// Configuration for connection establishment behavior
    config: EstablishmentConfig,
    /// Active connection attempts
    active_attempts: HashMap<PeerId, ConnectionAttempt>,
    /// Candidate discovery manager
    discovery_manager: Arc<std::sync::Mutex<CandidateDiscoveryManager>>,
    /// Known bootstrap nodes for coordination
    bootstrap_nodes: Vec<BootstrapNode>,
    /// Our role in the network
    endpoint_role: EndpointRole,
    /// Event callback for monitoring
    event_callback: Option<Box<dyn Fn(ConnectionEstablishmentEvent) + Send + Sync>>,
    /// Quinn endpoint for making QUIC connections
    quinn_endpoint: Option<Arc<QuinnEndpoint>>,
}

/// Configuration for connection establishment behavior
#[derive(Debug, Clone)]
pub struct EstablishmentConfig {
    /// Timeout for direct connection attempts
    pub direct_connection_timeout: Duration,
    /// Timeout for NAT traversal completion
    pub nat_traversal_timeout: Duration,
    /// Maximum number of simultaneous connection attempts
    pub max_concurrent_attempts: usize,
    /// Enable automatic NAT traversal detection
    pub enable_auto_nat_traversal: bool,
    /// Enable relay fallback as last resort
    pub enable_relay_fallback: bool,
    /// Retry configuration
    pub retry_config: RetryConfig,
    /// Candidate selection strategy
    pub candidate_strategy: CandidateSelectionStrategy,
}

/// Retry configuration for failed connections
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Initial retry delay
    pub initial_delay: Duration,
    /// Maximum retry delay
    pub max_delay: Duration,
    /// Backoff multiplier (exponential backoff)
    pub backoff_multiplier: f64,
    /// Enable jitter to avoid thundering herd
    pub enable_jitter: bool,
}

/// Strategy for selecting and ordering connection candidates
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateSelectionStrategy {
    /// Try highest priority candidates first
    PriorityFirst,
    /// Try multiple candidates in parallel
    Parallel,
    /// Adaptive strategy based on network conditions
    Adaptive,
    /// Conservative approach - try direct first, then NAT traversal
    Conservative,
}

/// State of a single connection attempt to a peer
#[derive(Debug)]
struct ConnectionAttempt {
    /// Target peer we're connecting to
    peer_id: PeerId,
    /// Current state of this attempt
    state: AttemptState,
    /// When this attempt started
    started_at: Instant,
    /// Current attempt number (for retries)
    attempt_number: u32,
    /// Strategy being used for this attempt
    strategy: ConnectionStrategy,
    /// Discovered candidates for this peer
    candidates: Vec<CandidateAddress>,
    /// Active connection sub-attempts
    sub_attempts: Vec<SubAttempt>,
    /// Last known error
    last_error: Option<ConnectionError>,
    /// Bootstrap node being used for coordination
    coordinator: Option<SocketAddr>,
    /// Established connection (if successful)
    established_connection: Option<QuinnConnection>,
}

/// State machine for connection attempts
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttemptState {
    /// Initializing the connection attempt
    Initializing,
    /// Trying direct connection
    DirectConnection,
    /// Discovering address candidates
    CandidateDiscovery,
    /// Performing NAT traversal coordination
    NatTraversalCoordination,
    /// Active hole punching in progress
    HolePunching,
    /// Validating established connections
    PathValidation,
    /// Connection established successfully
    Connected,
    /// Attempt failed, may retry
    Failed,
    /// Attempt cancelled
    Cancelled,
}

/// Strategy for this specific connection attempt
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionStrategy {
    /// Try direct connection only
    DirectOnly,
    /// Use full NAT traversal
    NatTraversal,
    /// Try direct first, then NAT traversal
    Progressive,
    /// Use relay as fallback
    RelayFallback,
}

/// Individual sub-attempt within a connection attempt
struct SubAttempt {
    /// Method being used for this sub-attempt
    method: ConnectionMethod,
    /// Target address for this attempt
    target_address: SocketAddr,
    /// When this sub-attempt started
    started_at: Instant,
    /// Current state
    state: SubAttemptState,
    /// Associated candidate information
    candidate: Option<CandidateAddress>,
    /// Active QUIC connection attempt
    connection_handle: Option<tokio::task::JoinHandle<Result<QuinnConnection, crate::ConnectionError>>>,
    /// Established connection (if successful)
    established_connection: Option<QuinnConnection>,
}

/// Connection method being attempted
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionMethod {
    /// Direct connection to known address
    Direct,
    /// Connection via discovered local candidate
    LocalCandidate,
    /// Connection via server reflexive candidate
    ServerReflexive,
    /// Connection via predicted candidate
    Predicted,
    /// Connection via relay server
    Relay,
}

/// State of a sub-attempt
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubAttemptState {
    /// Starting the attempt
    Starting,
    /// Sending connection packets
    Connecting,
    /// Validating the connection
    Validating,
    /// Successfully connected
    Connected,
    /// Failed to connect
    Failed,
    /// Cancelled due to success elsewhere
    Cancelled,
}

/// Events generated during connection establishment
#[derive(Debug, Clone)]
pub enum ConnectionEstablishmentEvent {
    /// Connection attempt started
    AttemptStarted {
        peer_id: PeerId,
        strategy: ConnectionStrategy,
        attempt_number: u32,
    },
    /// Direct connection attempt initiated
    DirectConnectionStarted {
        peer_id: PeerId,
        target_address: SocketAddr,
    },
    /// Candidate discovery started
    CandidateDiscoveryStarted {
        peer_id: PeerId,
        bootstrap_count: usize,
    },
    /// NAT traversal coordination initiated
    NatTraversalCoordinationStarted {
        peer_id: PeerId,
        coordinator: SocketAddr,
        candidate_count: usize,
    },
    /// Hole punching started
    HolePunchingStarted {
        peer_id: PeerId,
        target_candidates: Vec<SocketAddr>,
    },
    /// Connection method succeeded
    ConnectionMethodSucceeded {
        peer_id: PeerId,
        method: ConnectionMethod,
        target_address: SocketAddr,
        establishment_time: Duration,
    },
    /// Connection method failed
    ConnectionMethodFailed {
        peer_id: PeerId,
        method: ConnectionMethod,
        target_address: SocketAddr,
        error: ConnectionError,
    },
    /// Connection fully established
    ConnectionEstablished {
        peer_id: PeerId,
        final_address: SocketAddr,
        method: ConnectionMethod,
        total_time: Duration,
        fallback_used: bool,
    },
    /// Connection attempt failed
    AttemptFailed {
        peer_id: PeerId,
        error: ConnectionError,
        will_retry: bool,
        next_retry_in: Option<Duration>,
    },
    /// All connection attempts exhausted
    ConnectionFailed {
        peer_id: PeerId,
        final_error: ConnectionError,
        total_attempts: u32,
        total_time: Duration,
    },
}

/// Errors that can occur during connection establishment
#[derive(Debug, Clone)]
pub enum ConnectionError {
    /// Direct connection failed
    DirectConnectionFailed(String),
    /// Candidate discovery failed
    CandidateDiscoveryFailed(DiscoveryError),
    /// NAT traversal coordination failed
    NatTraversalCoordinationFailed(String),
    /// Hole punching failed
    HolePunchingFailed(String),
    /// Path validation failed
    PathValidationFailed(String),
    /// All connection methods failed
    AllMethodsFailed,
    /// Configuration error
    ConfigurationError(String),
    /// Timeout exceeded
    TimeoutExceeded,
    /// Connection cancelled by user
    Cancelled,
    /// Network error
    NetworkError(String),
    /// Resource exhaustion
    ResourceExhausted,
    /// Connection failed
    ConnectionFailed(String),
    /// Timed out
    TimedOut,
}

impl Default for EstablishmentConfig {
    fn default() -> Self {
        Self {
            direct_connection_timeout: Duration::from_secs(5),
            nat_traversal_timeout: Duration::from_secs(30),
            max_concurrent_attempts: 3,
            enable_auto_nat_traversal: true,
            enable_relay_fallback: true,
            retry_config: RetryConfig::default(),
            candidate_strategy: CandidateSelectionStrategy::Adaptive,
        }
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(10),
            backoff_multiplier: 2.0,
            enable_jitter: true,
        }
    }
}

impl ConnectionEstablishmentManager {
    /// Create a new connection establishment manager
    pub fn new(
        config: EstablishmentConfig,
        discovery_manager: Arc<std::sync::Mutex<CandidateDiscoveryManager>>,
        bootstrap_nodes: Vec<BootstrapNode>,
        endpoint_role: EndpointRole,
        event_callback: Option<Box<dyn Fn(ConnectionEstablishmentEvent) + Send + Sync>>,
        quinn_endpoint: Option<Arc<QuinnEndpoint>>,
    ) -> Self {
        Self {
            config,
            active_attempts: HashMap::new(),
            discovery_manager,
            bootstrap_nodes,
            endpoint_role,
            event_callback,
            quinn_endpoint,
        }
    }

    /// Initiate connection establishment to a peer
    pub fn connect_to_peer(
        &mut self,
        peer_id: PeerId,
        known_addresses: Vec<SocketAddr>,
        coordinator: Option<SocketAddr>,
    ) -> Result<(), ConnectionError> {
        info!("Initiating connection to peer {:?}", peer_id);

        // Check if we already have an active attempt
        if let Some(existing) = self.active_attempts.get(&peer_id) {
            warn!("Connection attempt to {:?} already in progress (state: {:?})", peer_id, existing.state);
            return Ok(());
        }

        // Determine connection strategy based on configuration and available information
        let strategy = self.determine_connection_strategy(&known_addresses, coordinator.is_some());

        // Create new connection attempt
        let attempt = ConnectionAttempt {
            peer_id,
            state: AttemptState::Initializing,
            started_at: Instant::now(),
            attempt_number: 1,
            strategy,
            candidates: Vec::new(),
            sub_attempts: Vec::new(),
            last_error: None,
            coordinator,
            established_connection: None,
        };

        self.active_attempts.insert(peer_id, attempt);

        // Emit event
        self.emit_event(ConnectionEstablishmentEvent::AttemptStarted {
            peer_id,
            strategy,
            attempt_number: 1,
        });

        // Start the connection attempt
        self.start_connection_attempt(peer_id, known_addresses)?;

        Ok(())
    }

    /// Poll for connection establishment progress
    pub fn poll(&mut self, now: Instant) -> Vec<ConnectionEstablishmentEvent> {
        let mut events = Vec::new();

        // Process each active attempt
        let mut completed_attempts = Vec::new();
        
        for (peer_id, attempt) in &mut self.active_attempts {
            let peer_id = *peer_id;
            if self.poll_connection_attempt(peer_id, attempt, now, &mut events) {
                completed_attempts.push(peer_id);
            }
        }

        // Remove completed attempts
        for peer_id in completed_attempts {
            self.active_attempts.remove(&peer_id);
        }

        // Poll discovery manager for candidate updates
        let discovery_events = if let Ok(mut discovery) = self.discovery_manager.lock() {
            discovery.poll(now)
        } else {
            Vec::new()
        };
        
        for discovery_event in discovery_events {
            self.handle_discovery_event(discovery_event, &mut events);
        }

        events
    }

    /// Cancel a connection attempt
    pub fn cancel_connection(&mut self, peer_id: PeerId) -> bool {
        if let Some(attempt) = self.active_attempts.get_mut(&peer_id) {
            attempt.state = AttemptState::Cancelled;
            info!("Cancelled connection attempt to peer {:?}", peer_id);
            true
        } else {
            false
        }
    }

    /// Get statistics about connection establishment
    pub fn get_statistics(&self) -> ConnectionEstablishmentStatistics {
        let active_attempts = self.active_attempts.len();
        let mut direct_attempts = 0;
        let mut nat_traversal_attempts = 0;
        let mut relay_attempts = 0;

        for attempt in self.active_attempts.values() {
            match attempt.strategy {
                ConnectionStrategy::DirectOnly => direct_attempts += 1,
                ConnectionStrategy::NatTraversal | ConnectionStrategy::Progressive => nat_traversal_attempts += 1,
                ConnectionStrategy::RelayFallback => relay_attempts += 1,
            }
        }

        ConnectionEstablishmentStatistics {
            active_attempts,
            direct_attempts,
            nat_traversal_attempts,
            relay_attempts,
            total_bootstrap_nodes: self.bootstrap_nodes.len(),
        }
    }

    // Private implementation methods

    fn determine_connection_strategy(
        &self,
        known_addresses: &[SocketAddr],
        has_coordinator: bool,
    ) -> ConnectionStrategy {
        match self.config.candidate_strategy {
            CandidateSelectionStrategy::Conservative => {
                if !known_addresses.is_empty() {
                    ConnectionStrategy::Progressive
                } else if has_coordinator {
                    ConnectionStrategy::NatTraversal
                } else {
                    ConnectionStrategy::DirectOnly
                }
            }
            CandidateSelectionStrategy::PriorityFirst | 
            CandidateSelectionStrategy::Parallel |
            CandidateSelectionStrategy::Adaptive => {
                if self.config.enable_auto_nat_traversal && (known_addresses.is_empty() || has_coordinator) {
                    ConnectionStrategy::NatTraversal
                } else {
                    ConnectionStrategy::Progressive
                }
            }
        }
    }

    fn start_connection_attempt(
        &mut self,
        peer_id: PeerId,
        known_addresses: Vec<SocketAddr>,
    ) -> Result<(), ConnectionError> {
        let attempt = self.active_attempts.get_mut(&peer_id)
            .ok_or(ConnectionError::ConfigurationError("Attempt not found".to_string()))?;

        match attempt.strategy {
            ConnectionStrategy::DirectOnly => {
                self.start_direct_connection(peer_id, known_addresses)
            }
            ConnectionStrategy::Progressive => {
                if !known_addresses.is_empty() {
                    self.start_direct_connection(peer_id, known_addresses)
                } else {
                    self.start_candidate_discovery(peer_id)
                }
            }
            ConnectionStrategy::NatTraversal => {
                self.start_candidate_discovery(peer_id)
            }
            ConnectionStrategy::RelayFallback => {
                self.start_relay_connection(peer_id)
            }
        }
    }

    fn start_direct_connection(
        &mut self,
        peer_id: PeerId,
        addresses: Vec<SocketAddr>,
    ) -> Result<(), ConnectionError> {
        let attempt = self.active_attempts.get_mut(&peer_id)
            .ok_or(ConnectionError::ConfigurationError("Attempt not found".to_string()))?;

        attempt.state = AttemptState::DirectConnection;

        // Create sub-attempts for each known address and collect events
        let mut new_events = Vec::new();
        for address in addresses {
            let sub_attempt = SubAttempt {
                method: ConnectionMethod::Direct,
                target_address: address,
                started_at: Instant::now(),
                state: SubAttemptState::Starting,
                candidate: None,
                connection_handle: None,
                established_connection: None,
            };

            attempt.sub_attempts.push(sub_attempt);

            new_events.push(ConnectionEstablishmentEvent::DirectConnectionStarted {
                peer_id,
                target_address: address,
            });
        }
        
        // Emit all events
        for event in new_events {
            self.emit_event(event);
        }

        // Now initiate actual QUIC connections for each sub-attempt
        if let Some(ref quinn_endpoint) = self.quinn_endpoint {
            let attempt = self.active_attempts.get_mut(&peer_id)
                .ok_or(ConnectionError::ConfigurationError("Attempt not found".to_string()))?;
            
            for sub_attempt in &mut attempt.sub_attempts {
                if sub_attempt.state == SubAttemptState::Starting {
                    // Start the actual QUIC connection
                    self.initiate_quic_connection(peer_id, sub_attempt, quinn_endpoint.clone())?;
                    sub_attempt.state = SubAttemptState::Connecting;
                }
            }
        }
        
        debug!("Started direct connection attempts to {} addresses for peer {:?}", 
               attempt.sub_attempts.len(), peer_id);

        Ok(())
    }

    fn start_candidate_discovery(&mut self, peer_id: PeerId) -> Result<(), ConnectionError> {
        let attempt = self.active_attempts.get_mut(&peer_id)
            .ok_or(ConnectionError::ConfigurationError("Attempt not found".to_string()))?;

        attempt.state = AttemptState::CandidateDiscovery;

        // Start discovery using the discovery manager
        {
            let mut discovery = self.discovery_manager.lock()
                .map_err(|_| ConnectionError::ConfigurationError("Discovery manager lock failed".to_string()))?;

            discovery.start_discovery(peer_id, self.bootstrap_nodes.clone())
                .map_err(|e| ConnectionError::CandidateDiscoveryFailed(e))?;
        }

        self.emit_event(ConnectionEstablishmentEvent::CandidateDiscoveryStarted {
            peer_id,
            bootstrap_count: self.bootstrap_nodes.len(),
        });

        debug!("Started candidate discovery for peer {:?}", peer_id);

        Ok(())
    }

    fn start_relay_connection(&mut self, peer_id: PeerId) -> Result<(), ConnectionError> {
        debug!("Starting relay connection for peer {:?}", peer_id);
        
        let attempt = self.active_attempts.get_mut(&peer_id)
            .ok_or(ConnectionError::ConfigurationError("Attempt not found".to_string()))?;

        // Select an appropriate relay server from bootstrap nodes
        let relay_server = self.select_relay_server()
            .ok_or(ConnectionError::ConfigurationError("No relay servers available".to_string()))?;

        debug!("Selected relay server {} for peer {:?}", relay_server, peer_id);

        // Update attempt state
        attempt.state = AttemptState::NatTraversalCoordination;
        attempt.coordinator = Some(relay_server);

        // Create relay connection sub-attempt
        let relay_sub_attempt = SubAttempt {
            method: ConnectionMethod::Relay,
            target_address: relay_server,
            started_at: Instant::now(),
            state: SubAttemptState::Starting,
            candidate: None,
            connection_handle: None,
            established_connection: None,
        };

        attempt.sub_attempts.push(relay_sub_attempt);

        // Start establishing connection to relay server
        self.establish_relay_connection(peer_id, relay_server)?;

        debug!("Relay connection initiated for peer {:?} via {}", peer_id, relay_server);
        Ok(())
    }

    /// Select the best available relay server from bootstrap nodes
    fn select_relay_server(&self) -> Option<SocketAddr> {
        // Filter bootstrap nodes that can act as relays
        let relay_capable_nodes: Vec<_> = self.bootstrap_nodes.iter()
            .filter(|node| {
                // Check if this bootstrap node supports relay functionality
                match node.role {
                    crate::nat_traversal_api::BootstrapRole::Relay => true,
                    crate::nat_traversal_api::BootstrapRole::Coordinator => true, // Coordinators can also relay
                    _ => false,
                }
            })
            .collect();

        if relay_capable_nodes.is_empty() {
            warn!("No relay-capable bootstrap nodes available");
            return None;
        }

        // Simple selection strategy: choose the first available relay
        // In a production system, this could be enhanced with:
        // - Load balancing based on current connections
        // - Geographic proximity
        // - Historical performance metrics
        // - Health checks
        
        let selected = relay_capable_nodes[0];
        Some(selected.address)
    }

    /// Establish connection to relay server
    fn establish_relay_connection(&mut self, peer_id: PeerId, relay_address: SocketAddr) -> Result<(), ConnectionError> {
        debug!("Establishing connection to relay server {} for peer {:?}", relay_address, peer_id);

        // In a real implementation, this would:
        // 1. Create a QUIC connection to the relay server
        // 2. Authenticate with the relay server
        // 3. Request relay service for the target peer
        // 4. Handle relay server responses and state management

        // For now, we'll simulate the relay connection establishment
        // This would be replaced with actual Quinn connection logic

        // Update the sub-attempt state to indicate connection is in progress
        if let Some(attempt) = self.active_attempts.get_mut(&peer_id) {
            for sub_attempt in &mut attempt.sub_attempts {
                if sub_attempt.method == ConnectionMethod::Relay && 
                   sub_attempt.target_address == relay_address {
                    sub_attempt.state = SubAttemptState::Connecting;
                    break;
                }
            }
        }

        debug!("Relay connection establishment initiated for peer {:?}", peer_id);
        Ok(())
    }

    /// Initiate a real QUIC connection for a sub-attempt
    fn initiate_quic_connection(
        &self,
        peer_id: PeerId,
        sub_attempt: &mut SubAttempt,
        endpoint: Arc<QuinnEndpoint>,
    ) -> Result<(), ConnectionError> {
        let target_address = sub_attempt.target_address;
        let server_name = format!("peer-{:x}", peer_id.0[0] as u32);
        
        // Spawn a task to handle the connection attempt
        let handle = tokio::spawn(async move {
            let connecting = endpoint.connect(target_address, &server_name)
                .map_err(|e| ConnectionError::ConnectionFailed(format!("Failed to start connection: {}", e)))?;
                
            // Apply a timeout to the connection attempt
            match tokio::time::timeout(Duration::from_secs(10), connecting).await {
                Ok(connection_result) => connection_result
                    .map_err(|e| ConnectionError::ConnectionFailed(format!("Connection failed: {}", e))),
                Err(_) => Err(ConnectionError::TimedOut),
            }
        });
        
        // Store the connection handle for polling
        sub_attempt.connection_handle = Some(handle);
        
        debug!("Initiated QUIC connection to {} for peer {:?}", target_address, peer_id);
        Ok(())
    }
    
    /// Handle relay connection state management
    fn handle_relay_connection_state(
        &mut self,
        peer_id: PeerId,
        relay_address: SocketAddr,
        now: Instant,
        events: &mut Vec<ConnectionEstablishmentEvent>,
    ) -> Result<bool, ConnectionError> {
        let attempt = self.active_attempts.get_mut(&peer_id)
            .ok_or(ConnectionError::ConfigurationError("Attempt not found".to_string()))?;

        // Find the relay sub-attempt
        let relay_sub_attempt = attempt.sub_attempts.iter_mut()
            .find(|sub| sub.method == ConnectionMethod::Relay && sub.target_address == relay_address);

        if let Some(sub_attempt) = relay_sub_attempt {
            match sub_attempt.state {
                SubAttemptState::Connecting => {
                    // Check if relay connection has been established
                    let elapsed = now.duration_since(sub_attempt.started_at);
                    
                    // Simulate relay connection establishment (replace with real logic)
                    if elapsed > Duration::from_secs(2) {
                        // Simulate successful relay connection
                        sub_attempt.state = SubAttemptState::Connected;
                        
                        events.push(ConnectionEstablishmentEvent::ConnectionMethodSucceeded {
                            peer_id,
                            method: ConnectionMethod::Relay,
                            target_address: relay_address,
                            establishment_time: elapsed,
                        });

                        // Now request relay to target peer
                        self.request_peer_relay(peer_id, relay_address)?;
                        
                        debug!("Relay connection established for peer {:?} via {}", peer_id, relay_address);
                        return Ok(false); // Continue processing, not fully connected yet
                    }
                }
                SubAttemptState::Validating => {
                    // Check if peer-to-peer connection through relay is established
                    let elapsed = now.duration_since(sub_attempt.started_at);
                    
                    // Simulate peer connection validation through relay
                    if elapsed > Duration::from_secs(5) {
                        sub_attempt.state = SubAttemptState::Connected;
                        attempt.state = AttemptState::Connected;
                        
                        events.push(ConnectionEstablishmentEvent::ConnectionEstablished {
                            peer_id,
                            final_address: relay_address,
                            method: ConnectionMethod::Relay,
                            total_time: now.duration_since(attempt.started_at),
                            fallback_used: true,
                        });

                        info!("Peer-to-peer connection established via relay {} for peer {:?}", 
                              relay_address, peer_id);
                        return Ok(true); // Connection fully established
                    }
                }
                SubAttemptState::Connected => {
                    return Ok(true); // Already connected
                }
                SubAttemptState::Failed => {
                    return Err(ConnectionError::NetworkError(
                        format!("Relay connection to {} failed", relay_address)
                    ));
                }
                _ => {
                    // Continue processing
                }
            }
        }

        Ok(false)
    }

    /// Request relay service for target peer
    fn request_peer_relay(&mut self, peer_id: PeerId, relay_address: SocketAddr) -> Result<(), ConnectionError> {
        debug!("Requesting relay service for peer {:?} via {}", peer_id, relay_address);

        // In a real implementation, this would:
        // 1. Send a relay request frame to the relay server
        // 2. Include the target peer ID and connection parameters
        // 3. Handle relay server acknowledgment
        // 4. Set up bidirectional relay for data forwarding

        // Update the relay sub-attempt to validation state
        if let Some(attempt) = self.active_attempts.get_mut(&peer_id) {
            for sub_attempt in &mut attempt.sub_attempts {
                if sub_attempt.method == ConnectionMethod::Relay && 
                   sub_attempt.target_address == relay_address {
                    sub_attempt.state = SubAttemptState::Validating;
                    break;
                }
            }
        }

        debug!("Relay service requested for peer {:?}", peer_id);
        Ok(())
    }

    fn poll_connection_attempt(
        &mut self,
        peer_id: PeerId,
        attempt: &mut ConnectionAttempt,
        now: Instant,
        events: &mut Vec<ConnectionEstablishmentEvent>,
    ) -> bool {
        // Check for overall timeout
        let elapsed = now.duration_since(attempt.started_at);
        let timeout = match attempt.strategy {
            ConnectionStrategy::DirectOnly => self.config.direct_connection_timeout,
            _ => self.config.nat_traversal_timeout,
        };

        if elapsed > timeout {
            attempt.state = AttemptState::Failed;
            attempt.last_error = Some(ConnectionError::TimeoutExceeded);
            
            if self.should_retry_attempt(attempt) {
                self.schedule_retry(peer_id, attempt, events);
                return false;
            } else {
                events.push(ConnectionEstablishmentEvent::ConnectionFailed {
                    peer_id,
                    final_error: ConnectionError::TimeoutExceeded,
                    total_attempts: attempt.attempt_number,
                    total_time: elapsed,
                });
                return true;
            }
        }

        // Poll sub-attempts
        self.poll_sub_attempts(peer_id, attempt, now, events);

        // Handle relay connections if present
        if let Some(coordinator) = attempt.coordinator {
            if attempt.sub_attempts.iter().any(|sub| sub.method == ConnectionMethod::Relay) {
                match self.handle_relay_connection_state(peer_id, coordinator, now, events) {
                    Ok(true) => return true, // Relay connection completed
                    Ok(false) => {}, // Continue processing
                    Err(e) => {
                        attempt.state = AttemptState::Failed;
                        attempt.last_error = Some(e.clone());
                        events.push(ConnectionEstablishmentEvent::AttemptFailed {
                            peer_id,
                            error: e,
                            will_retry: self.should_retry_attempt(attempt),
                            next_retry_in: self.calculate_retry_delay(attempt),
                        });
                        return self.should_retry_attempt(attempt);
                    }
                }
            }
        }

        // State machine progression
        match attempt.state {
            AttemptState::DirectConnection => {
                self.handle_direct_connection_state(peer_id, attempt, now, events)
            }
            AttemptState::CandidateDiscovery => {
                self.handle_candidate_discovery_state(peer_id, attempt, now, events)
            }
            AttemptState::NatTraversalCoordination => {
                self.handle_nat_traversal_coordination_state(peer_id, attempt, now, events)
            }
            AttemptState::HolePunching => {
                self.handle_hole_punching_state(peer_id, attempt, now, events)
            }
            AttemptState::PathValidation => {
                self.handle_path_validation_state(peer_id, attempt, now, events)
            }
            AttemptState::Connected | AttemptState::Failed | AttemptState::Cancelled => {
                true // Attempt is complete
            }
            _ => false,
        }
    }

    fn poll_sub_attempts(
        &mut self,
        peer_id: PeerId,
        attempt: &mut ConnectionAttempt,
        now: Instant,
        events: &mut Vec<ConnectionEstablishmentEvent>,
    ) {
        for sub_attempt in &mut attempt.sub_attempts {
            if sub_attempt.state == SubAttemptState::Connecting {
                {
                    // Check actual QUIC connection status
                    if let Some(ref mut handle) = sub_attempt.connection_handle {
                        if handle.is_finished() {
                            // Take the handle and check the result
                            let handle = sub_attempt.connection_handle.take().unwrap();
                            match tokio::runtime::Handle::try_current() {
                                Ok(runtime_handle) => {
                                    match runtime_handle.block_on(handle) {
                                        Ok(Ok(connection)) => {
                                            // Connection succeeded
                                            sub_attempt.state = SubAttemptState::Connected;
                                            sub_attempt.established_connection = Some(connection.clone());
                                            let elapsed = now.duration_since(sub_attempt.started_at);
                                            
                                            events.push(ConnectionEstablishmentEvent::ConnectionMethodSucceeded {
                                                peer_id,
                                                method: sub_attempt.method,
                                                target_address: sub_attempt.target_address,
                                                establishment_time: elapsed,
                                            });

                                            // Mark attempt as connected
                                            attempt.state = AttemptState::Connected;
                                            attempt.established_connection = Some(connection);
                                            
                                            events.push(ConnectionEstablishmentEvent::ConnectionEstablished {
                                                peer_id,
                                                final_address: sub_attempt.target_address,
                                                method: sub_attempt.method,
                                                total_time: now.duration_since(attempt.started_at),
                                                fallback_used: false,
                                            });
                                            
                                            info!("QUIC connection established to {} for peer {:?}", sub_attempt.target_address, peer_id);
                                        }
                                        Ok(Err(e)) => {
                                            // Connection failed
                                            sub_attempt.state = SubAttemptState::Failed;
                                            warn!("QUIC connection to {} failed: {}", sub_attempt.target_address, e);
                                            
                                            events.push(ConnectionEstablishmentEvent::ConnectionMethodFailed {
                                                peer_id,
                                                method: sub_attempt.method,
                                                target_address: sub_attempt.target_address,
                                                error: e,
                                            });
                                        }
                                        Err(join_error) => {
                                            // Task panic or cancellation
                                            sub_attempt.state = SubAttemptState::Failed;
                                            warn!("QUIC connection task failed: {}", join_error);
                                        }
                                    }
                                }
                                Err(_) => {
                                    // No tokio runtime available, can't check result
                                    warn!("Unable to check connection result without tokio runtime");
                                }
                            }
                        }
                    }
                }
                
            }
        }
    }

    fn handle_direct_connection_state(
        &mut self,
        peer_id: PeerId,
        attempt: &mut ConnectionAttempt,
        _now: Instant,
        events: &mut Vec<ConnectionEstablishmentEvent>,
    ) -> bool {
        // Check if any direct connection succeeded
        let has_success = attempt.sub_attempts.iter()
            .any(|sub| sub.state == SubAttemptState::Connected);

        if has_success {
            return true; // Connection established
        }

        // Check if all direct attempts failed
        let all_failed = attempt.sub_attempts.iter()
            .all(|sub| matches!(sub.state, SubAttemptState::Failed | SubAttemptState::Cancelled));

        if all_failed && attempt.strategy == ConnectionStrategy::Progressive {
            // Fall back to NAT traversal
            debug!("Direct connection failed for peer {:?}, falling back to NAT traversal", peer_id);
            
            if let Err(e) = self.start_candidate_discovery(peer_id) {
                attempt.state = AttemptState::Failed;
                attempt.last_error = Some(e.clone());
                
                events.push(ConnectionEstablishmentEvent::AttemptFailed {
                    peer_id,
                    error: e,
                    will_retry: self.should_retry_attempt(attempt),
                    next_retry_in: self.calculate_retry_delay(attempt),
                });
                
                return self.should_retry_attempt(attempt);
            }
        } else if all_failed {
            attempt.state = AttemptState::Failed;
            attempt.last_error = Some(ConnectionError::DirectConnectionFailed(
                "All direct connection attempts failed".to_string()
            ));
            
            return self.should_retry_attempt(attempt);
        }

        false
    }

    fn handle_candidate_discovery_state(
        &mut self,
        _peer_id: PeerId,
        _attempt: &mut ConnectionAttempt,
        _now: Instant,
        _events: &mut Vec<ConnectionEstablishmentEvent>,
    ) -> bool {
        // Discovery state is handled by discovery events
        // This will transition to coordination when candidates are found
        false
    }

    fn handle_coordination_state(
        &mut self,
        peer_id: PeerId,
        attempt: &mut ConnectionAttempt,
        now: Instant,
        events: &mut Vec<ConnectionEstablishmentEvent>,
    ) -> bool {
        debug!("Handling coordination state for peer {:?}", peer_id);

        // Check if we have a coordinator (bootstrap node) assigned
        let coordinator = match attempt.coordinator {
            Some(addr) => addr,
            None => {
                // Try to assign a coordinator from available bootstrap nodes
                if let Some(bootstrap_addr) = self.select_coordinator() {
                    attempt.coordinator = Some(bootstrap_addr);
                    bootstrap_addr
                } else {
                    // No coordinators available, fail the attempt
                    attempt.state = AttemptState::Failed;
                    attempt.last_error = Some(ConnectionError::NatTraversalCoordinationFailed(
                        "No bootstrap coordinators available".to_string()
                    ));
                    
                    events.push(ConnectionEstablishmentEvent::AttemptFailed {
                        peer_id,
                        error: ConnectionError::NatTraversalCoordinationFailed(
                            "No bootstrap coordinators available".to_string()
                        ),
                        will_retry: self.should_retry_attempt(attempt),
                        next_retry_in: self.calculate_retry_delay(attempt),
                    });
                    
                    return self.should_retry_attempt(attempt);
                }
            }
        };

        // Check if we have discovered candidates
        if attempt.candidates.is_empty() {
            // Still waiting for candidate discovery to complete
            let elapsed = now.duration_since(attempt.started_at);
            if elapsed > Duration::from_secs(10) {
                // Candidate discovery is taking too long, fail
                attempt.state = AttemptState::Failed;
                attempt.last_error = Some(ConnectionError::CandidateDiscoveryFailed(
                    crate::candidate_discovery::DiscoveryError::Timeout
                ));
                
                events.push(ConnectionEstablishmentEvent::AttemptFailed {
                    peer_id,
                    error: ConnectionError::CandidateDiscoveryFailed(
                        crate::candidate_discovery::DiscoveryError::Timeout
                    ),
                    will_retry: self.should_retry_attempt(attempt),
                    next_retry_in: self.calculate_retry_delay(attempt),
                });
                
                return self.should_retry_attempt(attempt);
            }
            return false; // Continue waiting
        }

        // Start coordination with bootstrap node
        match self.initiate_coordination_with_bootstrap(peer_id, coordinator, &attempt.candidates) {
            Ok(()) => {
                // Coordination initiated successfully, transition to hole punching
                attempt.state = AttemptState::HolePunching;
                
                let target_candidates: Vec<SocketAddr> = attempt.candidates.iter()
                    .map(|c| c.address)
                    .collect();
                
                events.push(ConnectionEstablishmentEvent::HolePunchingStarted {
                    peer_id,
                    target_candidates,
                });
                
                debug!("Transitioned to hole punching state for peer {:?}", peer_id);
                false // Continue processing
            }
            Err(e) => {
                // Coordination failed
                attempt.state = AttemptState::Failed;
                attempt.last_error = Some(e.clone());
                
                events.push(ConnectionEstablishmentEvent::AttemptFailed {
                    peer_id,
                    error: e,
                    will_retry: self.should_retry_attempt(attempt),
                    next_retry_in: self.calculate_retry_delay(attempt),
                });
                
                self.should_retry_attempt(attempt)
            }
        }
    }

    fn handle_nat_traversal_coordination_state(
        &mut self,
        peer_id: PeerId,
        attempt: &mut ConnectionAttempt,
        now: Instant,
        events: &mut Vec<ConnectionEstablishmentEvent>,
    ) -> bool {
        // Delegate to the main coordination handler
        self.handle_coordination_state(peer_id, attempt, now, events)
    }

    fn handle_hole_punching_state(
        &mut self,
        peer_id: PeerId,
        attempt: &mut ConnectionAttempt,
        now: Instant,
        events: &mut Vec<ConnectionEstablishmentEvent>,
    ) -> bool {
        debug!("Handling hole punching state for peer {:?}", peer_id);

        // Check if we have candidates to punch holes to
        if attempt.candidates.is_empty() {
            attempt.state = AttemptState::Failed;
            attempt.last_error = Some(ConnectionError::HolePunchingFailed(
                "No candidates available for hole punching".to_string()
            ));
            
            events.push(ConnectionEstablishmentEvent::AttemptFailed {
                peer_id,
                error: ConnectionError::HolePunchingFailed(
                    "No candidates available for hole punching".to_string()
                ),
                will_retry: self.should_retry_attempt(attempt),
                next_retry_in: self.calculate_retry_delay(attempt),
            });
            
            return self.should_retry_attempt(attempt);
        }

        // Create hole punching sub-attempts if not already created
        if attempt.sub_attempts.is_empty() || 
           !attempt.sub_attempts.iter().any(|sub| matches!(sub.method, 
               ConnectionMethod::LocalCandidate | ConnectionMethod::ServerReflexive | ConnectionMethod::Predicted)) {
            
            self.create_hole_punching_sub_attempts(peer_id, attempt);
        }

        // Check progress of hole punching attempts
        let mut any_connected = false;
        let mut all_failed = true;
        
        for sub_attempt in &mut attempt.sub_attempts {
            match sub_attempt.method {
                ConnectionMethod::LocalCandidate | 
                ConnectionMethod::ServerReflexive | 
                ConnectionMethod::Predicted => {
                    
                    match sub_attempt.state {
                        SubAttemptState::Starting => {
                            // Start the hole punching attempt
                            sub_attempt.state = SubAttemptState::Connecting;
                            self.initiate_hole_punch(peer_id, sub_attempt, now);
                            all_failed = false;
                        }
                        SubAttemptState::Connecting => {
                            // Check if hole punching succeeded
                            let elapsed = now.duration_since(sub_attempt.started_at);
                            
                            // Simulate hole punching attempts with different success rates
                            let success_probability = match sub_attempt.method {
                                ConnectionMethod::LocalCandidate => 0.9,  // High success for local
                                ConnectionMethod::ServerReflexive => 0.7, // Medium for server reflexive
                                ConnectionMethod::Predicted => 0.4,       // Lower for predicted
                                _ => 0.0,
                            };
                            
                            if elapsed > Duration::from_secs(3) {
                                // Simulate success/failure based on probability
                                let success = (elapsed.as_millis() % 100) as f64 / 100.0 < success_probability;
                                
                                if success {
                                    sub_attempt.state = SubAttemptState::Connected;
                                    any_connected = true;
                                    
                                    events.push(ConnectionEstablishmentEvent::ConnectionMethodSucceeded {
                                        peer_id,
                                        method: sub_attempt.method,
                                        target_address: sub_attempt.target_address,
                                        establishment_time: elapsed,
                                    });
                                    
                                    debug!("Hole punching succeeded for peer {:?} via {:?} to {}", 
                                           peer_id, sub_attempt.method, sub_attempt.target_address);
                                } else {
                                    sub_attempt.state = SubAttemptState::Failed;
                                    debug!("Hole punching failed for peer {:?} via {:?} to {}", 
                                           peer_id, sub_attempt.method, sub_attempt.target_address);
                                }
                            } else {
                                all_failed = false; // Still in progress
                            }
                        }
                        SubAttemptState::Connected => {
                            any_connected = true;
                            all_failed = false;
                        }
                        SubAttemptState::Failed => {
                            // This attempt failed, but others might succeed
                        }
                        _ => {
                            all_failed = false;
                        }
                    }
                }
                _ => {
                    // Non-hole-punching attempts
                    if !matches!(sub_attempt.state, SubAttemptState::Failed) {
                        all_failed = false;
                    }
                }
            }
        }

        if any_connected {
            // At least one hole punching attempt succeeded, transition to path validation
            attempt.state = AttemptState::PathValidation;
            debug!("Hole punching succeeded for peer {:?}, transitioning to path validation", peer_id);
            return false; // Continue to path validation
        } else if all_failed {
            // All hole punching attempts failed
            if self.config.enable_relay_fallback {
                // Try relay as fallback
                debug!("Hole punching failed for peer {:?}, falling back to relay", peer_id);
                match self.start_relay_connection(peer_id) {
                    Ok(()) => {
                        return false; // Continue with relay attempt
                    }
                    Err(e) => {
                        attempt.state = AttemptState::Failed;
                        attempt.last_error = Some(e.clone());
                        
                        events.push(ConnectionEstablishmentEvent::AttemptFailed {
                            peer_id,
                            error: e,
                            will_retry: self.should_retry_attempt(attempt),
                            next_retry_in: self.calculate_retry_delay(attempt),
                        });
                        
                        return self.should_retry_attempt(attempt);
                    }
                }
            } else {
                // No relay fallback, mark as failed
                attempt.state = AttemptState::Failed;
                attempt.last_error = Some(ConnectionError::HolePunchingFailed(
                    "All hole punching attempts failed".to_string()
                ));
                
                events.push(ConnectionEstablishmentEvent::AttemptFailed {
                    peer_id,
                    error: ConnectionError::HolePunchingFailed(
                        "All hole punching attempts failed".to_string()
                    ),
                    will_retry: self.should_retry_attempt(attempt),
                    next_retry_in: self.calculate_retry_delay(attempt),
                });
                
                return self.should_retry_attempt(attempt);
            }
        }

        false // Continue processing
    }

    fn handle_path_validation_state(
        &mut self,
        peer_id: PeerId,
        attempt: &mut ConnectionAttempt,
        now: Instant,
        events: &mut Vec<ConnectionEstablishmentEvent>,
    ) -> bool {
        debug!("Handling path validation state for peer {:?}", peer_id);

        // Find connected sub-attempts that need validation
        let mut validated_connections = Vec::new();
        let mut validation_failed = false;

        for sub_attempt in &mut attempt.sub_attempts {
            if sub_attempt.state == SubAttemptState::Connected {
                // Perform path validation for this connection
                let elapsed = now.duration_since(sub_attempt.started_at);
                
                // Simulate path validation process
                // In a real implementation, this would involve:
                // 1. Sending QUIC PATH_CHALLENGE frames
                // 2. Waiting for PATH_RESPONSE frames
                // 3. Verifying bidirectional connectivity
                // 4. Measuring RTT and path characteristics
                
                if elapsed > Duration::from_secs(1) {
                    // Simulate validation success/failure
                    let validation_success = match sub_attempt.method {
                        ConnectionMethod::Direct => true,           // Direct connections usually validate
                        ConnectionMethod::LocalCandidate => true,  // Local candidates are reliable
                        ConnectionMethod::ServerReflexive => true, // Server reflexive usually works
                        ConnectionMethod::Predicted => elapsed.as_millis() % 3 != 0, // 66% success rate
                        ConnectionMethod::Relay => true,           // Relay connections are pre-validated
                    };

                    if validation_success {
                        sub_attempt.state = SubAttemptState::Validating; // Mark as validated
                        validated_connections.push((sub_attempt.method, sub_attempt.target_address));
                        
                        debug!("Path validation succeeded for peer {:?} via {:?} to {}", 
                               peer_id, sub_attempt.method, sub_attempt.target_address);
                    } else {
                        sub_attempt.state = SubAttemptState::Failed;
                        validation_failed = true;
                        
                        debug!("Path validation failed for peer {:?} via {:?} to {}", 
                               peer_id, sub_attempt.method, sub_attempt.target_address);
                    }
                }
            }
        }

        // Check if we have at least one validated connection
        if !validated_connections.is_empty() {
            // Select the best validated connection
            let (best_method, best_address) = self.select_best_validated_connection(&validated_connections);
            
            // Mark attempt as successfully connected
            attempt.state = AttemptState::Connected;
            
            // Determine if fallback was used
            let fallback_used = match best_method {
                ConnectionMethod::Direct => false,
                _ => true, // Any non-direct method is considered fallback
            };
            
            events.push(ConnectionEstablishmentEvent::ConnectionEstablished {
                peer_id,
                final_address: best_address,
                method: best_method,
                total_time: now.duration_since(attempt.started_at),
                fallback_used,
            });

            info!("Connection established to peer {:?} via {:?} at {} (fallback: {})", 
                  peer_id, best_method, best_address, fallback_used);
            
            return true; // Connection fully established
        }

        // Check if all validation attempts have failed
        let all_validation_failed = attempt.sub_attempts.iter()
            .filter(|sub| matches!(sub.state, SubAttemptState::Connected | SubAttemptState::Validating))
            .all(|sub| sub.state == SubAttemptState::Failed);

        if all_validation_failed && validation_failed {
            // All path validation attempts failed
            attempt.state = AttemptState::Failed;
            attempt.last_error = Some(ConnectionError::PathValidationFailed(
                "All path validation attempts failed".to_string()
            ));
            
            events.push(ConnectionEstablishmentEvent::AttemptFailed {
                peer_id,
                error: ConnectionError::PathValidationFailed(
                    "All path validation attempts failed".to_string()
                ),
                will_retry: self.should_retry_attempt(attempt),
                next_retry_in: self.calculate_retry_delay(attempt),
            });
            
            return self.should_retry_attempt(attempt);
        }

        false // Continue validation process
    }

    /// Select the best validated connection from available options
    fn select_best_validated_connection(
        &self,
        validated_connections: &[(ConnectionMethod, SocketAddr)],
    ) -> (ConnectionMethod, SocketAddr) {
        // Priority order for connection methods (best to worst)
        let method_priority = |method: ConnectionMethod| -> u8 {
            match method {
                ConnectionMethod::Direct => 0,           // Highest priority
                ConnectionMethod::LocalCandidate => 1,  // Second best
                ConnectionMethod::ServerReflexive => 2, // Third
                ConnectionMethod::Predicted => 3,       // Fourth
                ConnectionMethod::Relay => 4,           // Lowest priority (but still valid)
            }
        };

        // Find the connection with the highest priority (lowest priority number)
        validated_connections.iter()
            .min_by_key(|(method, _)| method_priority(*method))
            .copied()
            .unwrap_or_else(|| {
                // Fallback to first connection if priority logic fails
                validated_connections[0]
            })
    }

    /// Select a coordinator from available bootstrap nodes
    fn select_coordinator(&self) -> Option<SocketAddr> {
        // Filter bootstrap nodes that can act as coordinators
        let coordinator_nodes: Vec<_> = self.bootstrap_nodes.iter()
            .filter(|node| {
                match node.role {
                    crate::nat_traversal_api::BootstrapRole::Coordinator => true,
                    crate::nat_traversal_api::BootstrapRole::Relay => true, // Relays can also coordinate
                    _ => false,
                }
            })
            .collect();

        if coordinator_nodes.is_empty() {
            return None;
        }

        // Simple selection: choose first available coordinator
        // In production, this could consider load balancing, proximity, etc.
        Some(coordinator_nodes[0].address)
    }

    /// Initiate coordination with bootstrap node
    fn initiate_coordination_with_bootstrap(
        &mut self,
        peer_id: PeerId,
        coordinator: SocketAddr,
        candidates: &[CandidateAddress],
    ) -> Result<(), ConnectionError> {
        debug!("Initiating coordination with bootstrap {} for peer {:?}", coordinator, peer_id);

        // In a real implementation, this would:
        // 1. Send coordination request to bootstrap node
        // 2. Include our candidates and target peer ID
        // 3. Wait for coordination response with peer's candidates
        // 4. Set up synchronized hole punching

        // For now, simulate successful coordination initiation
        debug!("Coordination initiated with {} candidates for peer {:?}", candidates.len(), peer_id);
        Ok(())
    }

    /// Create hole punching sub-attempts for discovered candidates
    fn create_hole_punching_sub_attempts(&mut self, peer_id: PeerId, attempt: &mut ConnectionAttempt) {
        debug!("Creating hole punching sub-attempts for peer {:?}", peer_id);

        // Sort candidates by priority (highest first)
        let mut sorted_candidates = attempt.candidates.clone();
        sorted_candidates.sort_by(|a, b| b.priority.cmp(&a.priority));

        // Create sub-attempts for each candidate type
        for candidate in sorted_candidates {
            let method = match candidate.candidate_type {
                crate::nat_traversal_api::CandidateType::Host => ConnectionMethod::LocalCandidate,
                crate::nat_traversal_api::CandidateType::ServerReflexive => ConnectionMethod::ServerReflexive,
                crate::nat_traversal_api::CandidateType::PeerReflexive => ConnectionMethod::Predicted,
                crate::nat_traversal_api::CandidateType::Relay => ConnectionMethod::Relay,
            };

            let sub_attempt = SubAttempt {
                method,
                target_address: candidate.address,
                started_at: Instant::now(),
                state: SubAttemptState::Starting,
                candidate: Some(candidate.clone()),
                connection_handle: None,
                established_connection: None,
            };

            attempt.sub_attempts.push(sub_attempt);
        }

        debug!("Created {} hole punching sub-attempts for peer {:?}", 
               attempt.sub_attempts.len(), peer_id);
    }

    /// Initiate hole punching for a specific sub-attempt
    fn initiate_hole_punch(&mut self, peer_id: PeerId, sub_attempt: &mut SubAttempt, now: Instant) {
        debug!("Initiating hole punch for peer {:?} via {:?} to {}", 
               peer_id, sub_attempt.method, sub_attempt.target_address);

        // In a real implementation, this would:
        // 1. Send coordinated packets to the target address
        // 2. Use QUIC connection establishment with NAT traversal frames
        // 3. Handle simultaneous connection attempts from both sides
        // 4. Manage timing and synchronization with the peer

        // Update the start time for this specific attempt
        sub_attempt.started_at = now;
        
        debug!("Hole punch initiated for peer {:?} to {}", peer_id, sub_attempt.target_address);
    }


    fn handle_discovery_event(
        &mut self,
        discovery_event: DiscoveryEvent,
        events: &mut Vec<ConnectionEstablishmentEvent>,
    ) {
        match discovery_event {
            DiscoveryEvent::LocalCandidateDiscovered { candidate } => {
                self.handle_candidate_discovered(candidate, events);
            }
            DiscoveryEvent::ServerReflexiveCandidateDiscovered { candidate, bootstrap_node: _ } => {
                self.handle_candidate_discovered(candidate, events);
            }
            DiscoveryEvent::PredictedCandidateGenerated { candidate, confidence: _ } => {
                self.handle_candidate_discovered(candidate, events);
            }
            DiscoveryEvent::DiscoveryCompleted { candidate_count, total_duration: _, success_rate: _ } => {
                debug!("Candidate discovery completed with {} candidates", candidate_count);
                self.transition_to_coordination(events);
            }
            DiscoveryEvent::DiscoveryFailed { error, partial_results } => {
                warn!("Candidate discovery failed: {:?}", error);
                self.handle_discovery_failure(error, partial_results, events);
            }
            _ => {
                // Handle other discovery events as needed
            }
        }
    }

    fn handle_candidate_discovered(
        &mut self,
        candidate: CandidateAddress,
        _events: &mut Vec<ConnectionEstablishmentEvent>,
    ) {
        debug!("Discovered candidate: {:?}", candidate);
        
        // Add candidate to relevant active attempts
        for attempt in self.active_attempts.values_mut() {
            if attempt.state == AttemptState::CandidateDiscovery {
                attempt.candidates.push(candidate.clone());
            }
        }
    }

    fn transition_to_coordination(&mut self, events: &mut Vec<ConnectionEstablishmentEvent>) {
        for (peer_id, attempt) in &mut self.active_attempts {
            if attempt.state == AttemptState::CandidateDiscovery {
                attempt.state = AttemptState::NatTraversalCoordination;
                
                if let Some(coordinator) = attempt.coordinator {
                    events.push(ConnectionEstablishmentEvent::NatTraversalCoordinationStarted {
                        peer_id: *peer_id,
                        coordinator,
                        candidate_count: attempt.candidates.len(),
                    });
                }
            }
        }
    }

    fn handle_discovery_failure(
        &mut self,
        error: DiscoveryError,
        _partial_results: Vec<CandidateAddress>,
        events: &mut Vec<ConnectionEstablishmentEvent>,
    ) {
        let peer_ids: Vec<_> = self.active_attempts.keys().copied().collect();
        for peer_id in peer_ids {
            if let Some(attempt) = self.active_attempts.get_mut(&peer_id) {
                if attempt.state == AttemptState::CandidateDiscovery {
                    attempt.state = AttemptState::Failed;
                    attempt.last_error = Some(ConnectionError::CandidateDiscoveryFailed(error.clone()));
                    
                    let will_retry = self.should_retry_attempt(attempt);
                    let next_retry_in = self.calculate_retry_delay(attempt);
                    
                    events.push(ConnectionEstablishmentEvent::AttemptFailed {
                        peer_id,
                        error: ConnectionError::CandidateDiscoveryFailed(error.clone()),
                        will_retry,
                        next_retry_in,
                    });
                }
            }
        }
    }

    fn should_retry_attempt(&self, attempt: &ConnectionAttempt) -> bool {
        attempt.attempt_number < self.config.retry_config.max_retries
    }

    fn calculate_retry_delay(&self, attempt: &ConnectionAttempt) -> Option<Duration> {
        if !self.should_retry_attempt(attempt) {
            return None;
        }

        let base_delay = self.config.retry_config.initial_delay;
        let multiplier = self.config.retry_config.backoff_multiplier;
        let max_delay = self.config.retry_config.max_delay;

        let mut delay = base_delay.mul_f64(multiplier.powi(attempt.attempt_number as i32 - 1));
        
        if delay > max_delay {
            delay = max_delay;
        }

        if self.config.retry_config.enable_jitter {
            // Add up to 25% jitter
            let jitter = delay.mul_f64(0.25 * rand::random::<f64>());
            delay = delay + jitter;
        }

        Some(delay)
    }

    fn schedule_retry(
        &mut self,
        peer_id: PeerId,
        attempt: &mut ConnectionAttempt,
        events: &mut Vec<ConnectionEstablishmentEvent>,
    ) {
        if let Some(delay) = self.calculate_retry_delay(attempt) {
            attempt.attempt_number += 1;
            attempt.state = AttemptState::Initializing;
            attempt.started_at = Instant::now() + delay;
            attempt.sub_attempts.clear();
            
            events.push(ConnectionEstablishmentEvent::AttemptFailed {
                peer_id,
                error: attempt.last_error.clone().unwrap_or(ConnectionError::AllMethodsFailed),
                will_retry: true,
                next_retry_in: Some(delay),
            });
            
            info!("Scheduled retry #{} for peer {:?} in {:?}", 
                  attempt.attempt_number, peer_id, delay);
        }
    }

    fn emit_event(&self, event: ConnectionEstablishmentEvent) {
        if let Some(ref callback) = self.event_callback {
            callback(event);
        }
    }

    /// Get the established connection for a peer
    pub fn get_connection(&self, peer_id: &PeerId) -> Option<QuinnConnection> {
        self.active_attempts
            .get(peer_id)
            .and_then(|attempt| attempt.established_connection.clone())
    }

    /// Take the established connection for a peer (removes it from the manager)
    pub fn take_connection(&mut self, peer_id: &PeerId) -> Option<QuinnConnection> {
        self.active_attempts
            .get_mut(peer_id)
            .and_then(|attempt| attempt.established_connection.take())
    }

    /// Check if a connection is established
    pub fn is_connected(&self, peer_id: &PeerId) -> bool {
        self.active_attempts
            .get(peer_id)
            .map(|attempt| attempt.state == AttemptState::Connected && attempt.established_connection.is_some())
            .unwrap_or(false)
    }

    /// Get all established connections
    pub fn get_all_connections(&self) -> HashMap<PeerId, QuinnConnection> {
        self.active_attempts
            .iter()
            .filter_map(|(peer_id, attempt)| {
                attempt.established_connection
                    .as_ref()
                    .map(|conn| (*peer_id, conn.clone()))
            })
            .collect()
    }

    /// Remove a connection (disconnect)
    pub fn remove_connection(&mut self, peer_id: &PeerId) -> bool {
        if let Some(attempt) = self.active_attempts.get_mut(peer_id) {
            attempt.established_connection = None;
            attempt.state = AttemptState::Failed;
            true
        } else {
            false
        }
    }
}

/// Statistics about connection establishment
#[derive(Debug, Clone)]
pub struct ConnectionEstablishmentStatistics {
    /// Number of active connection attempts
    pub active_attempts: usize,
    /// Number of direct connection attempts
    pub direct_attempts: usize,
    /// Number of NAT traversal attempts
    pub nat_traversal_attempts: usize,
    /// Number of relay connection attempts
    pub relay_attempts: usize,
    /// Total number of available bootstrap nodes
    pub total_bootstrap_nodes: usize,
}

impl std::fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DirectConnectionFailed(msg) => write!(f, "direct connection failed: {}", msg),
            Self::CandidateDiscoveryFailed(err) => write!(f, "candidate discovery failed: {:?}", err),
            Self::NatTraversalCoordinationFailed(msg) => write!(f, "NAT traversal coordination failed: {}", msg),
            Self::HolePunchingFailed(msg) => write!(f, "hole punching failed: {}", msg),
            Self::PathValidationFailed(msg) => write!(f, "path validation failed: {}", msg),
            Self::AllMethodsFailed => write!(f, "all connection methods failed"),
            Self::ConfigurationError(msg) => write!(f, "configuration error: {}", msg),
            Self::TimeoutExceeded => write!(f, "timeout exceeded"),
            Self::Cancelled => write!(f, "connection cancelled"),
            Self::NetworkError(msg) => write!(f, "network error: {}", msg),
            Self::ResourceExhausted => write!(f, "resource exhausted"),
            Self::ConnectionFailed(msg) => write!(f, "connection failed: {}", msg),
            Self::TimedOut => write!(f, "timed out"),
        }
    }
}

impl std::error::Error for ConnectionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_establishment_config_default() {
        let config = EstablishmentConfig::default();
        assert_eq!(config.direct_connection_timeout, Duration::from_secs(5));
        assert_eq!(config.nat_traversal_timeout, Duration::from_secs(30));
        assert_eq!(config.max_concurrent_attempts, 3);
        assert!(config.enable_auto_nat_traversal);
        assert!(config.enable_relay_fallback);
    }

    #[test]
    fn test_retry_config_default() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_delay, Duration::from_millis(500));
        assert_eq!(config.max_delay, Duration::from_secs(10));
        assert_eq!(config.backoff_multiplier, 2.0);
        assert!(config.enable_jitter);
    }

    #[test]
    fn test_connection_strategy_determination() {
        let config = EstablishmentConfig {
            candidate_strategy: CandidateSelectionStrategy::Conservative,
            ..EstablishmentConfig::default()
        };

        let manager = ConnectionEstablishmentManager::new(
            config,
            Arc::new(std::sync::Mutex::new(
                crate::candidate_discovery::CandidateDiscoveryManager::new(
                    crate::candidate_discovery::DiscoveryConfig::default(),
                    crate::connection::nat_traversal::NatTraversalRole::Client,
                )
            )),
            Vec::new(),
            EndpointRole::Client,
            None,
            None, // Quinn endpoint
        );

        // Test with known addresses
        let strategy = manager.determine_connection_strategy(
            &[SocketAddr::from(([127, 0, 0, 1], 8080))],
            false
        );
        assert_eq!(strategy, ConnectionStrategy::Progressive);

        // Test without known addresses but with coordinator
        let strategy = manager.determine_connection_strategy(&[], true);
        assert_eq!(strategy, ConnectionStrategy::NatTraversal);

        // Test without anything
        let strategy = manager.determine_connection_strategy(&[], false);
        assert_eq!(strategy, ConnectionStrategy::DirectOnly);
    }
}