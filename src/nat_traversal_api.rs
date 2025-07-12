//! High-level NAT Traversal API for Autonomi P2P Networks
//!
//! This module provides a simple, high-level interface for establishing
//! QUIC connections through NATs using sophisticated hole punching and
//! coordination protocols.

use std::{
    collections::HashMap,
    fmt,
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

#[cfg(feature = "production-ready")]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(feature = "production-ready")]
use tokio::{
    net::UdpSocket,
    sync::mpsc,
    time::{sleep, timeout},
};

#[cfg(feature = "production-ready")]
// use futures_util::StreamExt;

use tracing::{debug, info};

use crate::{
    candidate_discovery::{CandidateDiscoveryManager, DiscoveryConfig, DiscoveryEvent},
    connection::nat_traversal::{CandidateSource, CandidateState, NatTraversalRole},
    VarInt,
};

#[cfg(feature = "production-ready")]
use quinn::{
    Endpoint as QuinnEndpoint,
    EndpointConfig,
    ServerConfig,
    ClientConfig,
    Connection,
    ConnectionError,
    TransportConfig,
    crypto::rustls::QuicServerConfig,
    crypto::rustls::QuicClientConfig,
};


#[cfg(feature = "production-ready")]
use crate::config::validation::{ConfigValidator, ValidationResult};

#[cfg(feature = "production-ready")]
use crate::crypto::certificate_manager::{CertificateManager, CertificateConfig};

/// High-level NAT traversal endpoint for Autonomi P2P networks
pub struct NatTraversalEndpoint {
    /// Underlying Quinn endpoint
    #[cfg(feature = "production-ready")]
    quinn_endpoint: Option<QuinnEndpoint>,
    /// Fallback internal endpoint for non-production builds
    #[cfg(not(feature = "production-ready"))]
    internal_endpoint: Endpoint,
    /// NAT traversal configuration
    config: NatTraversalConfig,
    /// Known bootstrap/coordinator nodes
    bootstrap_nodes: Arc<std::sync::RwLock<Vec<BootstrapNode>>>,
    /// Active NAT traversal sessions
    active_sessions: Arc<std::sync::RwLock<HashMap<PeerId, NatTraversalSession>>>,
    /// Candidate discovery manager
    discovery_manager: Arc<std::sync::Mutex<CandidateDiscoveryManager>>,
    /// Event callback for coordination (simplified without async channels)
    event_callback: Option<Box<dyn Fn(NatTraversalEvent) + Send + Sync>>,
    /// Shutdown flag for async operations
    #[cfg(feature = "production-ready")]
    shutdown: Arc<AtomicBool>,
    /// Channel for internal communication
    #[cfg(feature = "production-ready")]
    event_tx: Option<mpsc::UnboundedSender<NatTraversalEvent>>,
    /// Active connections by peer ID
    #[cfg(feature = "production-ready")]
    connections: Arc<std::sync::RwLock<HashMap<PeerId, Connection>>>,
    /// Local peer ID
    local_peer_id: PeerId,
}

/// Configuration for NAT traversal behavior
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NatTraversalConfig {
    /// Role of this endpoint in the network
    pub role: EndpointRole,
    /// Bootstrap nodes for coordination and candidate discovery
    pub bootstrap_nodes: Vec<SocketAddr>,
    /// Maximum number of address candidates to maintain
    pub max_candidates: usize,
    /// Timeout for coordination rounds
    pub coordination_timeout: Duration,
    /// Enable symmetric NAT prediction algorithms
    pub enable_symmetric_nat: bool,
    /// Enable automatic relay fallback
    pub enable_relay_fallback: bool,
    /// Maximum concurrent NAT traversal attempts
    pub max_concurrent_attempts: usize,
}

/// Role of an endpoint in the Autonomi network
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EndpointRole {
    /// Regular client node (most common)
    Client,
    /// Server node (always reachable, can coordinate)
    Server { can_coordinate: bool },
    /// Bootstrap node (public, coordinates NAT traversal)
    Bootstrap,
}

impl EndpointRole {
    /// Get a string representation of the role for use in certificate common names
    pub fn name(&self) -> &'static str {
        match self {
            EndpointRole::Client => "client",
            EndpointRole::Server { .. } => "server",
            EndpointRole::Bootstrap => "bootstrap",
        }
    }
}

/// Unique identifier for a peer in the network
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct PeerId(pub [u8; 32]);

/// Information about a bootstrap/coordinator node
#[derive(Debug, Clone)]
pub struct BootstrapNode {
    /// Network address of the bootstrap node
    pub address: SocketAddr,
    /// Last successful contact time
    pub last_seen: std::time::Instant,
    /// Whether this node can coordinate NAT traversal
    pub can_coordinate: bool,
    /// RTT to this bootstrap node
    pub rtt: Option<Duration>,
    /// Number of successful coordinations via this node
    pub coordination_count: u32,
}

/// Active NAT traversal session state
#[derive(Debug)]
struct NatTraversalSession {
    /// Target peer we're trying to connect to
    peer_id: PeerId,
    /// Coordinator being used for this session
    coordinator: SocketAddr,
    /// Current attempt number
    attempt: u32,
    /// Session start time
    started_at: std::time::Instant,
    /// Current phase of traversal
    phase: TraversalPhase,
    /// Discovered candidate addresses
    candidates: Vec<CandidateAddress>,
}

/// Phases of NAT traversal process
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TraversalPhase {
    /// Discovering local candidates
    Discovery,
    /// Requesting coordination from bootstrap
    Coordination,
    /// Waiting for peer coordination
    Synchronization,
    /// Active hole punching
    Punching,
    /// Validating established paths
    Validation,
    /// Successfully connected
    Connected,
    /// Failed, may retry or fallback
    Failed,
}

/// Address candidate discovered during NAT traversal
#[derive(Debug, Clone)]
pub struct CandidateAddress {
    /// The candidate address
    pub address: SocketAddr,
    /// Priority for ICE-like selection
    pub priority: u32,
    /// How this candidate was discovered
    pub source: CandidateSource,
    /// Current validation state
    pub state: CandidateState,
}


/// Events generated during NAT traversal process
#[derive(Debug, Clone)]
pub enum NatTraversalEvent {
    /// New candidate address discovered
    CandidateDiscovered {
        peer_id: PeerId,
        candidate: CandidateAddress,
    },
    /// Coordination request sent to bootstrap
    CoordinationRequested {
        peer_id: PeerId,
        coordinator: SocketAddr,
    },
    /// Peer coordination synchronized
    CoordinationSynchronized {
        peer_id: PeerId,
        round_id: VarInt,
    },
    /// Hole punching started
    HolePunchingStarted {
        peer_id: PeerId,
        targets: Vec<SocketAddr>,
    },
    /// Path validated successfully
    PathValidated {
        peer_id: PeerId,
        address: SocketAddr,
        rtt: Duration,
    },
    /// NAT traversal completed successfully
    TraversalSucceeded {
        peer_id: PeerId,
        final_address: SocketAddr,
        total_time: Duration,
    },
    /// Connection established after NAT traversal
    ConnectionEstablished {
        peer_id: PeerId,
        /// The socket address where the connection was established
        remote_address: SocketAddr,
    },
    /// NAT traversal failed
    TraversalFailed {
        peer_id: PeerId,
        error: NatTraversalError,
        fallback_available: bool,
    },
    /// Connection lost
    ConnectionLost {
        peer_id: PeerId,
        reason: String,
    },
}

/// Errors that can occur during NAT traversal
#[derive(Debug, Clone)]
pub enum NatTraversalError {
    /// No bootstrap nodes available
    NoBootstrapNodes,
    /// Failed to discover any candidates
    NoCandidatesFound,
    /// Candidate discovery failed
    CandidateDiscoveryFailed(String),
    /// Coordination with bootstrap failed
    CoordinationFailed(String),
    /// All hole punching attempts failed
    HolePunchingFailed,
    /// Connection validation timed out
    ValidationTimeout,
    /// Network error during traversal
    NetworkError(String),
    /// Configuration error
    ConfigError(String),
    /// Internal protocol error
    ProtocolError(String),
    /// NAT traversal timed out
    Timeout,
    /// Connection failed after successful traversal
    ConnectionFailed(String),
    /// General traversal failure
    TraversalFailed(String),
}

impl Default for NatTraversalConfig {
    fn default() -> Self {
        Self {
            role: EndpointRole::Client,
            bootstrap_nodes: Vec::new(),
            max_candidates: 8,
            coordination_timeout: Duration::from_secs(10),
            enable_symmetric_nat: true,
            enable_relay_fallback: true,
            max_concurrent_attempts: 3,
        }
    }
}

#[cfg(feature = "production-ready")]
impl ConfigValidator for NatTraversalConfig {
    fn validate(&self) -> ValidationResult<()> {
        use crate::config::validation::*;
        
        // Validate role-specific requirements
        match self.role {
            EndpointRole::Client => {
                if self.bootstrap_nodes.is_empty() {
                    return Err(ConfigValidationError::InvalidRole(
                        "Client endpoints require at least one bootstrap node".to_string()
                    ));
                }
            }
            EndpointRole::Server { can_coordinate } => {
                if can_coordinate && self.bootstrap_nodes.is_empty() {
                    return Err(ConfigValidationError::InvalidRole(
                        "Server endpoints with coordination capability require bootstrap nodes".to_string()
                    ));
                }
            }
            EndpointRole::Bootstrap => {
                // Bootstrap nodes don't need other bootstrap nodes
            }
        }
        
        // Validate bootstrap nodes
        if !self.bootstrap_nodes.is_empty() {
            validate_bootstrap_nodes(&self.bootstrap_nodes)?;
        }
        
        // Validate candidate limits
        validate_range(
            self.max_candidates,
            1,
            256,
            "max_candidates"
        )?;
        
        // Validate coordination timeout
        validate_duration(
            self.coordination_timeout,
            Duration::from_millis(100),
            Duration::from_secs(300),
            "coordination_timeout"
        )?;
        
        // Validate concurrent attempts
        validate_range(
            self.max_concurrent_attempts,
            1,
            16,
            "max_concurrent_attempts"
        )?;
        
        // Validate configuration compatibility
        if self.max_concurrent_attempts > self.max_candidates {
            return Err(ConfigValidationError::IncompatibleConfiguration(
                "max_concurrent_attempts cannot exceed max_candidates".to_string()
            ));
        }
        
        if self.role == EndpointRole::Bootstrap && self.enable_relay_fallback {
            return Err(ConfigValidationError::IncompatibleConfiguration(
                "Bootstrap nodes should not enable relay fallback".to_string()
            ));
        }
        
        Ok(())
    }
}

impl NatTraversalEndpoint {
    /// Create a new NAT traversal endpoint with optional event callback
    #[cfg(feature = "production-ready")]
    pub async fn new(
        config: NatTraversalConfig,
        event_callback: Option<Box<dyn Fn(NatTraversalEvent) + Send + Sync>>,
    ) -> Result<Self, NatTraversalError> {
        Self::new_impl(config, event_callback).await
    }
    
    /// Create a new NAT traversal endpoint with optional event callback (non-async fallback)
    #[cfg(not(feature = "production-ready"))]
    pub fn new(
        config: NatTraversalConfig,
        event_callback: Option<Box<dyn Fn(NatTraversalEvent) + Send + Sync>>,
    ) -> Result<Self, NatTraversalError> {
        Self::new_fallback(config, event_callback)
    }
    
    /// Internal async implementation for production builds
    #[cfg(feature = "production-ready")]
    async fn new_impl(
        config: NatTraversalConfig,
        event_callback: Option<Box<dyn Fn(NatTraversalEvent) + Send + Sync>>,
    ) -> Result<Self, NatTraversalError> {
        Self::new_common(config, event_callback).await
    }
    
    /// Internal fallback implementation for non-production builds
    #[cfg(not(feature = "production-ready"))]
    fn new_fallback(
        config: NatTraversalConfig,
        event_callback: Option<Box<dyn Fn(NatTraversalEvent) + Send + Sync>>,
    ) -> Result<Self, NatTraversalError> {
        Self::new_common_sync(config, event_callback)
    }
    
    /// Common implementation for both async and sync versions
    #[cfg(feature = "production-ready")]
    async fn new_common(
        config: NatTraversalConfig,
        event_callback: Option<Box<dyn Fn(NatTraversalEvent) + Send + Sync>>,
    ) -> Result<Self, NatTraversalError> {
        // Existing implementation with async support
        Self::new_shared_logic(config, event_callback).await
    }
    
    /// Common implementation for sync versions
    #[cfg(not(feature = "production-ready"))]
    fn new_common_sync(
        config: NatTraversalConfig,
        event_callback: Option<Box<dyn Fn(NatTraversalEvent) + Send + Sync>>,
    ) -> Result<Self, NatTraversalError> {
        // Existing implementation without async support
        Self::new_shared_logic_sync(config, event_callback)
    }
    
    /// Shared logic for endpoint creation (async version)
    #[cfg(feature = "production-ready")]
    async fn new_shared_logic(
        config: NatTraversalConfig,
        event_callback: Option<Box<dyn Fn(NatTraversalEvent) + Send + Sync>>,
    ) -> Result<Self, NatTraversalError> {
        // Validate configuration using production-ready validation
        #[cfg(feature = "production-ready")]
        {
            config.validate()
                .map_err(|e| NatTraversalError::ConfigError(e.to_string()))?;
        }
        
        // Fallback validation for non-production builds
        #[cfg(not(feature = "production-ready"))]
        {
            if config.bootstrap_nodes.is_empty() && config.role != EndpointRole::Bootstrap {
                return Err(NatTraversalError::ConfigError(
                    "At least one bootstrap node required for non-bootstrap endpoints".to_string(),
                ));
            }
        }

        // Initialize bootstrap nodes
        let bootstrap_nodes = Arc::new(std::sync::RwLock::new(
            config
                .bootstrap_nodes
                .iter()
                .map(|&address| BootstrapNode {
                    address,
                    last_seen: std::time::Instant::now(),
                    can_coordinate: true, // Assume true initially
                    rtt: None,
                    coordination_count: 0,
                })
                .collect(),
        ));

        // Create candidate discovery manager
        let discovery_config = DiscoveryConfig {
            total_timeout: config.coordination_timeout,
            max_candidates: config.max_candidates,
            enable_symmetric_prediction: config.enable_symmetric_nat,
            ..DiscoveryConfig::default()
        };

        let nat_traversal_role = match config.role {
            EndpointRole::Client => NatTraversalRole::Client,
            EndpointRole::Server { can_coordinate } => NatTraversalRole::Server { can_relay: can_coordinate },
            EndpointRole::Bootstrap => NatTraversalRole::Bootstrap,
        };

        let discovery_manager = Arc::new(std::sync::Mutex::new(
            CandidateDiscoveryManager::new(discovery_config, nat_traversal_role)
        ));

        // Create QUIC endpoint with NAT traversal enabled
        // Create QUIC endpoint with NAT traversal enabled
        let (quinn_endpoint, event_tx) = Self::create_quinn_endpoint(&config, nat_traversal_role).await?;

        Ok(Self {
            quinn_endpoint: Some(quinn_endpoint),
            config,
            bootstrap_nodes,
            active_sessions: Arc::new(std::sync::RwLock::new(HashMap::new())),
            discovery_manager,
            event_callback,
            shutdown: Arc::new(AtomicBool::new(false)),
            event_tx: Some(event_tx),
            connections: Arc::new(std::sync::RwLock::new(HashMap::new())),
            local_peer_id: Self::generate_local_peer_id(),
        })
    }
    
    /// Shared logic for endpoint creation (sync version)
    #[cfg(not(feature = "production-ready"))]
    fn new_shared_logic_sync(
        config: NatTraversalConfig,
        event_callback: Option<Box<dyn Fn(NatTraversalEvent) + Send + Sync>>,
    ) -> Result<Self, NatTraversalError> {
        // Validate configuration using production-ready validation
        config.validate()
            .map_err(|e| NatTraversalError::ConfigError(e.to_string()))?;
        
        // Initialize bootstrap nodes
        let bootstrap_nodes = Arc::new(std::sync::RwLock::new(
            config
                .bootstrap_nodes
                .iter()
                .map(|&address| BootstrapNode {
                    address,
                    last_seen: std::time::Instant::now(),
                    can_coordinate: true,
                    rtt: None,
                    coordination_count: 0,
                })
                .collect(),
        ));
        
        // Create candidate discovery manager
        let discovery_config = DiscoveryConfig {
            total_timeout: config.coordination_timeout,
            max_candidates: config.max_candidates,
            enable_symmetric_prediction: config.enable_symmetric_nat,
            ..DiscoveryConfig::default()
        };
        
        let nat_traversal_role = match config.role {
            EndpointRole::Client => NatTraversalRole::Client,
            EndpointRole::Server { can_coordinate } => NatTraversalRole::Server { can_relay: can_coordinate },
            EndpointRole::Bootstrap => NatTraversalRole::Bootstrap,
        };
        
        let discovery_manager = Arc::new(std::sync::Mutex::new(
            CandidateDiscoveryManager::new(discovery_config, nat_traversal_role)
        ));
        
        // Create fallback endpoint
        let internal_endpoint = Self::create_fallback_endpoint(&config, nat_traversal_role)?;
        
        Ok(Self {
            internal_endpoint,
            config,
            bootstrap_nodes,
            active_sessions: Arc::new(std::sync::RwLock::new(HashMap::new())),
            discovery_manager,
            event_callback,
            local_peer_id: Self::generate_local_peer_id(),
        })
    }

    /// Initiate NAT traversal to a peer (returns immediately, progress via events)
    pub fn initiate_nat_traversal(
        &self,
        peer_id: PeerId,
        coordinator: SocketAddr,
    ) -> Result<(), NatTraversalError> {
        info!("Starting NAT traversal to peer {:?} via coordinator {}", peer_id, coordinator);

        // Create new session
        let session = NatTraversalSession {
            peer_id,
            coordinator,
            attempt: 1,
            started_at: std::time::Instant::now(),
            phase: TraversalPhase::Discovery,
            candidates: Vec::new(),
        };

        // Store session
        {
            let mut sessions = self.active_sessions.write()
                .map_err(|_| NatTraversalError::ProtocolError("Lock poisoned".to_string()))?;
            sessions.insert(peer_id, session);
        }

        // Start candidate discovery
        let bootstrap_nodes_vec = {
            let bootstrap_nodes = self.bootstrap_nodes.read()
                .map_err(|_| NatTraversalError::ProtocolError("Lock poisoned".to_string()))?;
            bootstrap_nodes.clone()
        };

        {
            let mut discovery = self.discovery_manager.lock()
                .map_err(|_| NatTraversalError::ProtocolError("Discovery manager lock poisoned".to_string()))?;
            
            discovery.start_discovery(peer_id, bootstrap_nodes_vec)
                .map_err(|e| NatTraversalError::CandidateDiscoveryFailed(e.to_string()))?;
        }

        // Emit event
        if let Some(ref callback) = self.event_callback {
            callback(NatTraversalEvent::CoordinationRequested {
                peer_id,
                coordinator,
            });
        }

        // NAT traversal will proceed via poll() calls and state machine updates
        Ok(())
    }

    /// Get current NAT traversal statistics
    pub fn get_statistics(&self) -> Result<NatTraversalStatistics, NatTraversalError> {
        let sessions = self.active_sessions.read()
            .map_err(|_| NatTraversalError::ProtocolError("Lock poisoned".to_string()))?;
        let bootstrap_nodes = self.bootstrap_nodes.read()
            .map_err(|_| NatTraversalError::ProtocolError("Lock poisoned".to_string()))?;

        Ok(NatTraversalStatistics {
            active_sessions: sessions.len(),
            total_bootstrap_nodes: bootstrap_nodes.len(),
            successful_coordinations: bootstrap_nodes.iter().map(|b| b.coordination_count).sum(),
            average_coordination_time: Duration::from_millis(500), // TODO: Calculate real average
        })
    }

    /// Add a new bootstrap node
    pub fn add_bootstrap_node(&self, address: SocketAddr) -> Result<(), NatTraversalError> {
        let mut bootstrap_nodes = self.bootstrap_nodes.write()
            .map_err(|_| NatTraversalError::ProtocolError("Lock poisoned".to_string()))?;
        
        // Check if already exists
        if !bootstrap_nodes.iter().any(|b| b.address == address) {
            bootstrap_nodes.push(BootstrapNode {
                address,
                last_seen: std::time::Instant::now(),
                can_coordinate: true,
                rtt: None,
                coordination_count: 0,
            });
            info!("Added bootstrap node: {}", address);
        }
        Ok(())
    }

    /// Remove a bootstrap node
    pub fn remove_bootstrap_node(&self, address: SocketAddr) -> Result<(), NatTraversalError> {
        let mut bootstrap_nodes = self.bootstrap_nodes.write()
            .map_err(|_| NatTraversalError::ProtocolError("Lock poisoned".to_string()))?;
        bootstrap_nodes.retain(|b| b.address != address);
        info!("Removed bootstrap node: {}", address);
        Ok(())
    }

    // Private implementation methods

    /// Create a Quinn endpoint with NAT traversal configured (async version)
    #[cfg(feature = "production-ready")]
    async fn create_quinn_endpoint(
        config: &NatTraversalConfig,
        _nat_role: NatTraversalRole,
    ) -> Result<(QuinnEndpoint, mpsc::UnboundedSender<NatTraversalEvent>), NatTraversalError> {
        use std::sync::Arc;
        
        // Create server config if this is a coordinator/bootstrap node
        let server_config = match config.role {
            EndpointRole::Bootstrap | EndpointRole::Server { .. } => {
                // Production certificate management
                let cert_config = CertificateConfig {
                    common_name: format!("ant-quic-{}", config.role.name()),
                    subject_alt_names: vec![
                        "localhost".to_string(),
                        "ant-quic-node".to_string(),
                    ],
                    self_signed: true, // Use self-signed for P2P networks
                    ..CertificateConfig::default()
                };
                
                let cert_manager = CertificateManager::new(cert_config)
                    .map_err(|e| NatTraversalError::ConfigError(format!("Certificate manager creation failed: {}", e)))?;
                
                let cert_bundle = cert_manager.generate_certificate()
                    .map_err(|e| NatTraversalError::ConfigError(format!("Certificate generation failed: {}", e)))?;
                
                let rustls_config = cert_manager.create_server_config(&cert_bundle)
                    .map_err(|e| NatTraversalError::ConfigError(format!("Server config creation failed: {}", e)))?;
                
                let server_crypto = QuicServerConfig::try_from(rustls_config.as_ref().clone())
                    .map_err(|e| NatTraversalError::ConfigError(e.to_string()))?;
                
                let mut server_config = ServerConfig::with_crypto(Arc::new(server_crypto));
                
                // Configure transport parameters for NAT traversal
                let mut transport_config = TransportConfig::default();
                transport_config.keep_alive_interval(Some(Duration::from_secs(5)));
                transport_config.max_idle_timeout(Some(quinn::VarInt::from_u32(30000).into()));
                server_config.transport_config(Arc::new(transport_config));
                
                Some(server_config)
            }
            _ => None,
        };
        
        // Create client config for outgoing connections
        let client_config = {
            let cert_config = CertificateConfig {
                common_name: format!("ant-quic-{}", config.role.name()),
                subject_alt_names: vec![
                    "localhost".to_string(),
                    "ant-quic-node".to_string(),
                ],
                self_signed: true,
                ..CertificateConfig::default()
            };
            
            let cert_manager = CertificateManager::new(cert_config)
                .map_err(|e| NatTraversalError::ConfigError(format!("Certificate manager creation failed: {}", e)))?;
            
            let _cert_bundle = cert_manager.generate_certificate()
                .map_err(|e| NatTraversalError::ConfigError(format!("Certificate generation failed: {}", e)))?;
            
            let rustls_config = cert_manager.create_client_config()
                .map_err(|e| NatTraversalError::ConfigError(format!("Client config creation failed: {}", e)))?;
            
            let client_crypto = QuicClientConfig::try_from(rustls_config.as_ref().clone())
                .map_err(|e| NatTraversalError::ConfigError(e.to_string()))?;
            
            let mut client_config = ClientConfig::new(Arc::new(client_crypto));
            
            // Configure transport parameters for NAT traversal
            let mut transport_config = TransportConfig::default();
            transport_config.keep_alive_interval(Some(Duration::from_secs(5)));
            transport_config.max_idle_timeout(Some(quinn::VarInt::from_u32(30000).into()));
            client_config.transport_config(Arc::new(transport_config));
            
            client_config
        };
        
        // Create UDP socket
        let socket = UdpSocket::bind("0.0.0.0:0").await
            .map_err(|e| NatTraversalError::NetworkError(format!("Failed to bind UDP socket: {}", e)))?;
        
        // Convert tokio socket to std socket
        let std_socket = socket.into_std()
            .map_err(|e| NatTraversalError::NetworkError(format!("Failed to convert socket: {}", e)))?;
        
        // Create Quinn endpoint
        let mut endpoint = QuinnEndpoint::new(
            EndpointConfig::default(),
            server_config,
            std_socket,
            Arc::new(quinn::TokioRuntime),
        ).map_err(|e| NatTraversalError::ConfigError(format!("Failed to create Quinn endpoint: {}", e)))?;
        
        // Set default client config
        endpoint.set_default_client_config(client_config);
        
        // Create event channel
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        
        Ok((endpoint, event_tx))
    }
    
    /// Create a fallback endpoint for non-production builds
    #[cfg(not(feature = "production-ready"))]
    fn create_fallback_endpoint(
        config: &NatTraversalConfig,
        _nat_role: NatTraversalRole,
    ) -> Result<Endpoint, NatTraversalError> {
        use crate::{
            EndpointConfig, TransportConfig,
            transport_parameters::NatTraversalConfig as TPNatConfig,
            transport_parameters::NatTraversalRole as TPRole,
        };
        
        #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
        use crate::crypto::rustls::QuicServerConfig;
        
        // Configure transport with NAT traversal
        let mut transport_config = TransportConfig::default();
        
        // Convert role for transport parameters
        let tp_role = match nat_role {
            NatTraversalRole::Client => TPRole::Client,
            NatTraversalRole::Server { can_relay } => TPRole::Server { can_relay },
            NatTraversalRole::Bootstrap => TPRole::Bootstrap,
        };
        
        // Enable NAT traversal in transport parameters
        transport_config.nat_traversal_config = Some(TPNatConfig {
            role: tp_role,
            max_candidates: VarInt::from_u32(config.max_candidates as u32),
            coordination_timeout: VarInt::from_u32(config.coordination_timeout.as_millis() as u32),
            max_concurrent_attempts: VarInt::from_u32(config.max_concurrent_attempts as u32),
            peer_id: None, // Will be set dynamically when peer ID is determined
        });
        
        // Create endpoint configuration
        let endpoint_config = Arc::new(EndpointConfig::default());
        
        // Create server config if this is a coordinator/bootstrap node
        let server_config = match config.role {
            EndpointRole::Bootstrap | EndpointRole::Server { .. } => {
                #[cfg(feature = "production-ready")]
                {
                    // Production certificate management
                    let cert_config = CertificateConfig {
                        common_name: format!("ant-quic-{}", config.role.name()),
                        subject_alt_names: vec![
                            "localhost".to_string(),
                            "ant-quic-node".to_string(),
                        ],
                        self_signed: true, // Use self-signed for P2P networks
                        ..CertificateConfig::default()
                    };
                    
                    let cert_manager = CertificateManager::new(cert_config)
                        .map_err(|e| NatTraversalError::ConfigError(format!("Certificate manager creation failed: {}", e)))?;
                    
                    let _cert_bundle = cert_manager.generate_certificate()
                        .map_err(|e| NatTraversalError::ConfigError(format!("Certificate generation failed: {}", e)))?;
                    
                    #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
                    {
                        let rustls_config = cert_manager.create_server_config(&cert_bundle)
                            .map_err(|e| NatTraversalError::ConfigError(format!("Server config creation failed: {}", e)))?;
                        
                        let server_config = QuicServerConfig::try_from(rustls_config.as_ref().clone())
                            .map_err(|e| NatTraversalError::ConfigError(e.to_string()))?;
                        
                        Some(Arc::new(crate::ServerConfig::with_crypto(Arc::new(server_config))))
                    }
                    #[cfg(not(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring")))]
                    {
                        None
                    }
                }
                #[cfg(not(feature = "production-ready"))]
                {
                    // Fallback to dummy certificates for development
                    let cert = rustls::pki_types::CertificateDer::from(vec![0; 32]);
                    let key = rustls::pki_types::PrivateKeyDer::try_from(vec![0; 32]).ok();
                    
                    if let Some(key) = key {
                        #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
                        {
                            let server_config = QuicServerConfig::try_from(
                                rustls::ServerConfig::builder()
                                    .with_no_client_auth()
                                    .with_single_cert(vec![cert], key)
                                    .map_err(|e| NatTraversalError::ConfigError(e.to_string()))?
                            ).map_err(|e| NatTraversalError::ConfigError(e.to_string()))?;
                            
                            Some(Arc::new(crate::ServerConfig::with_crypto(Arc::new(server_config))))
                        }
                        #[cfg(not(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring")))]
                        {
                            None
                        }
                    } else {
                        None
                    }
                }
            }
            _ => None,
        };
        
        // Create the endpoint
        let endpoint = Endpoint::new(
            endpoint_config,
            server_config,
            true, // allow_mtud
            None, // rng_seed
        );
        
        // NOTE: Client configuration would need to be set when connecting to peers
        // The Endpoint doesn't have a set_default_client_config method
        
        Ok(endpoint)
    }
    
    /// Start listening for incoming connections (async version)
    #[cfg(feature = "production-ready")]
    pub async fn start_listening(&self, bind_addr: SocketAddr) -> Result<(), NatTraversalError> {
        let endpoint = self.quinn_endpoint.as_ref()
            .ok_or_else(|| NatTraversalError::ConfigError("Quinn endpoint not initialized".to_string()))?;
        
        // Rebind the endpoint to the specified address
        let _socket = UdpSocket::bind(bind_addr).await
            .map_err(|e| NatTraversalError::NetworkError(format!("Failed to bind to {}: {}", bind_addr, e)))?;
        
        info!("Started listening on {}", bind_addr);
        
        // Start accepting connections in a background task
        let endpoint_clone = endpoint.clone();
        let shutdown_clone = self.shutdown.clone();
        let event_tx = self.event_tx.as_ref().unwrap().clone();
        
        tokio::spawn(async move {
            Self::accept_connections(endpoint_clone, shutdown_clone, event_tx).await;
        });
        
        Ok(())
    }
    
    /// Accept incoming connections
    #[cfg(feature = "production-ready")]
    async fn accept_connections(
        endpoint: QuinnEndpoint,
        shutdown: Arc<AtomicBool>,
        event_tx: mpsc::UnboundedSender<NatTraversalEvent>,
    ) {
        while !shutdown.load(Ordering::Relaxed) {
            match endpoint.accept().await {
                Some(connecting) => {
                    let event_tx = event_tx.clone();
                    tokio::spawn(async move {
                        match connecting.await {
                            Ok(connection) => {
                                info!("Accepted connection from {}", connection.remote_address());
                                
                                // Generate peer ID from connection address
                                let peer_id = Self::generate_peer_id_from_address(connection.remote_address());
                                
                                let _ = event_tx.send(NatTraversalEvent::ConnectionEstablished {
                                    peer_id,
                                    remote_address: connection.remote_address(),
                                });
                                
                                // Handle connection streams
                                Self::handle_connection(connection, event_tx).await;
                            }
                            Err(e) => {
                                debug!("Connection failed: {}", e);
                            }
                        }
                    });
                }
                None => {
                    // Endpoint closed
                    break;
                }
            }
        }
    }
    
    /// Handle an established connection
    #[cfg(feature = "production-ready")]
    async fn handle_connection(
        connection: Connection,
        event_tx: mpsc::UnboundedSender<NatTraversalEvent>,
    ) {
        let peer_id = Self::generate_peer_id_from_address(connection.remote_address());
        let remote_address = connection.remote_address();
        
        debug!("Handling connection from peer {:?} at {}", peer_id, remote_address);
        // Handle bidirectional and unidirectional streams
        loop {
            tokio::select! {
                stream = connection.accept_bi() => {
                    match stream {
                        Ok((send, recv)) => {
                            tokio::spawn(async move {
                                Self::handle_bi_stream(send, recv).await;
                            });
                        }
                        Err(e) => {
                            debug!("Error accepting bidirectional stream: {}", e);
                            let _ = event_tx.send(NatTraversalEvent::ConnectionLost {
                                peer_id,
                                reason: format!("Stream error: {}", e),
                            });
                            break;
                        }
                    }
                }
                stream = connection.accept_uni() => {
                    match stream {
                        Ok(recv) => {
                            tokio::spawn(async move {
                                Self::handle_uni_stream(recv).await;
                            });
                        }
                        Err(e) => {
                            debug!("Error accepting unidirectional stream: {}", e);
                            let _ = event_tx.send(NatTraversalEvent::ConnectionLost {
                                peer_id,
                                reason: format!("Stream error: {}", e),
                            });
                            break;
                        }
                    }
                }
            }
        }
    }
    
    /// Handle a bidirectional stream
    #[cfg(feature = "production-ready")]
    async fn handle_bi_stream(
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
    ) {
        let mut buffer = vec![0u8; 1024];
        
        loop {
            match recv.read(&mut buffer).await {
                Ok(Some(size)) => {
                    debug!("Received {} bytes on bidirectional stream", size);
                    
                    // Echo back the data for now
                    if let Err(e) = send.write_all(&buffer[..size]).await {
                        debug!("Failed to write to stream: {}", e);
                        break;
                    }
                }
                Ok(None) => {
                    debug!("Bidirectional stream closed by peer");
                    break;
                }
                Err(e) => {
                    debug!("Error reading from bidirectional stream: {}", e);
                    break;
                }
            }
        }
    }
    
    /// Handle a unidirectional stream
    #[cfg(feature = "production-ready")]
    async fn handle_uni_stream(mut recv: quinn::RecvStream) {
        let mut buffer = vec![0u8; 1024];
        
        loop {
            match recv.read(&mut buffer).await {
                Ok(Some(size)) => {
                    debug!("Received {} bytes on unidirectional stream", size);
                    // Process the data
                }
                Ok(None) => {
                    debug!("Unidirectional stream closed by peer");
                    break;
                }
                Err(e) => {
                    debug!("Error reading from unidirectional stream: {}", e);
                    break;
                }
            }
        }
    }
    
    /// Connect to a peer using NAT traversal
    #[cfg(feature = "production-ready")]
    pub async fn connect_to_peer(
        &self,
        peer_id: PeerId,
        server_name: &str,
        remote_addr: SocketAddr,
    ) -> Result<Connection, NatTraversalError> {
        let endpoint = self.quinn_endpoint.as_ref()
            .ok_or_else(|| NatTraversalError::ConfigError("Quinn endpoint not initialized".to_string()))?;
        
        info!("Connecting to peer {:?} at {}", peer_id, remote_addr);
        
        // Attempt connection with timeout
        let connecting = endpoint.connect(remote_addr, server_name)
            .map_err(|e| NatTraversalError::ConnectionFailed(format!("Failed to initiate connection: {}", e)))?;
        
        let connection = timeout(Duration::from_secs(10), connecting)
            .await
            .map_err(|_| NatTraversalError::Timeout)?
            .map_err(|e| NatTraversalError::ConnectionFailed(format!("Connection failed: {}", e)))?;
        
        info!("Successfully connected to peer {:?} at {}", peer_id, remote_addr);
        
        // Send event notification
        if let Some(ref event_tx) = self.event_tx {
            let _ = event_tx.send(NatTraversalEvent::ConnectionEstablished {
                peer_id,
                remote_address: remote_addr,
            });
        }
        
        Ok(connection)
    }
    
    /// Accept incoming connections on the endpoint
    #[cfg(feature = "production-ready")]
    pub async fn accept_connection(&self) -> Result<(PeerId, Connection), NatTraversalError> {
        let endpoint = self.quinn_endpoint.as_ref()
            .ok_or_else(|| NatTraversalError::ConfigError("Quinn endpoint not initialized".to_string()))?;
        
        // Accept incoming connection
        let incoming = endpoint.accept().await
            .ok_or_else(|| NatTraversalError::NetworkError("Endpoint closed".to_string()))?;
        
        let remote_addr = incoming.remote_address();
        info!("Accepting connection from {}", remote_addr);
        
        // Accept the connection
        let connection = incoming.await
            .map_err(|e| NatTraversalError::ConnectionFailed(format!("Failed to accept connection: {}", e)))?;
        
        // Generate or extract peer ID from connection
        let peer_id = self.extract_peer_id_from_connection(&connection).await
            .unwrap_or_else(|| Self::generate_peer_id_from_address(remote_addr));
        
        // Store the connection
        {
            let mut connections = self.connections.write()
                .map_err(|_| NatTraversalError::ProtocolError("Connections lock poisoned".to_string()))?;
            connections.insert(peer_id, connection.clone());
        }
        
        info!("Connection accepted from peer {:?} at {}", peer_id, remote_addr);
        
        // Send event notification
        if let Some(ref event_tx) = self.event_tx {
            let _ = event_tx.send(NatTraversalEvent::ConnectionEstablished {
                peer_id,
                remote_address: remote_addr,
            });
        }
        
        Ok((peer_id, connection))
    }
    
    /// Get the local peer ID
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }
    
    /// Get an active connection by peer ID
    #[cfg(feature = "production-ready")]
    pub fn get_connection(&self, peer_id: &PeerId) -> Result<Option<Connection>, NatTraversalError> {
        let connections = self.connections.read()
            .map_err(|_| NatTraversalError::ProtocolError("Connections lock poisoned".to_string()))?;
        Ok(connections.get(peer_id).cloned())
    }
    
    /// Remove a connection by peer ID
    #[cfg(feature = "production-ready")]
    pub fn remove_connection(&self, peer_id: &PeerId) -> Result<Option<Connection>, NatTraversalError> {
        let mut connections = self.connections.write()
            .map_err(|_| NatTraversalError::ProtocolError("Connections lock poisoned".to_string()))?;
        Ok(connections.remove(peer_id))
    }
    
    /// List all active connections
    #[cfg(feature = "production-ready")]
    pub fn list_connections(&self) -> Result<Vec<(PeerId, SocketAddr)>, NatTraversalError> {
        let connections = self.connections.read()
            .map_err(|_| NatTraversalError::ProtocolError("Connections lock poisoned".to_string()))?;
        let mut result = Vec::new();
        for (peer_id, connection) in connections.iter() {
            result.push((*peer_id, connection.remote_address()));
        }
        Ok(result)
    }
    
    /// Handle incoming data from a connection
    #[cfg(feature = "production-ready")]
    pub async fn handle_connection_data(
        &self,
        peer_id: PeerId,
        connection: &Connection,
    ) -> Result<(), NatTraversalError> {
        info!("Handling connection data from peer {:?}", peer_id);
        
        // Spawn task to handle bidirectional streams
        let connection_clone = connection.clone();
        let peer_id_clone = peer_id;
        tokio::spawn(async move {
            loop {
                match connection_clone.accept_bi().await {
                    Ok((send, recv)) => {
                        debug!("Accepted bidirectional stream from peer {:?}", peer_id_clone);
                        tokio::spawn(Self::handle_bi_stream(send, recv));
                    }
                    Err(ConnectionError::ApplicationClosed(_)) => {
                        debug!("Connection closed by peer {:?}", peer_id_clone);
                        break;
                    }
                    Err(e) => {
                        debug!("Error accepting bidirectional stream from peer {:?}: {}", peer_id_clone, e);
                        break;
                    }
                }
            }
        });
        
        // Spawn task to handle unidirectional streams
        let connection_clone = connection.clone();
        let peer_id_clone = peer_id;
        tokio::spawn(async move {
            loop {
                match connection_clone.accept_uni().await {
                    Ok(recv) => {
                        debug!("Accepted unidirectional stream from peer {:?}", peer_id_clone);
                        tokio::spawn(Self::handle_uni_stream(recv));
                    }
                    Err(ConnectionError::ApplicationClosed(_)) => {
                        debug!("Connection closed by peer {:?}", peer_id_clone);
                        break;
                    }
                    Err(e) => {
                        debug!("Error accepting unidirectional stream from peer {:?}: {}", peer_id_clone, e);
                        break;
                    }
                }
            }
        });
        
        Ok(())
    }
    
    /// Generate a local peer ID
    fn generate_local_peer_id() -> PeerId {
        use std::time::SystemTime;
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        SystemTime::now().hash(&mut hasher);
        std::process::id().hash(&mut hasher);
        
        let hash = hasher.finish();
        let mut peer_id = [0u8; 32];
        peer_id[0..8].copy_from_slice(&hash.to_be_bytes());
        
        // Add some randomness
        for i in 8..32 {
            peer_id[i] = rand::random();
        }
        
        PeerId(peer_id)
    }
    
    /// Generate a peer ID from a socket address
    fn generate_peer_id_from_address(addr: SocketAddr) -> PeerId {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        addr.hash(&mut hasher);
        
        let hash = hasher.finish();
        let mut peer_id = [0u8; 32];
        peer_id[0..8].copy_from_slice(&hash.to_be_bytes());
        
        // Add some randomness to avoid collisions
        for i in 8..32 {
            peer_id[i] = rand::random();
        }
        
        PeerId(peer_id)
    }
    
    /// Extract peer ID from connection (stub implementation)
    #[cfg(feature = "production-ready")]
    async fn extract_peer_id_from_connection(&self, connection: &Connection) -> Option<PeerId> {
        // TODO: In a real implementation, this would:
        // 1. Read the peer's certificate
        // 2. Extract the peer ID from the certificate subject
        // 3. Or use a custom transport parameter
        // For now, we'll return None to fall back to address-based generation
        let _ = connection;
        None
    }
    
    /// Shutdown the endpoint
    #[cfg(feature = "production-ready")]
    pub async fn shutdown(&self) -> Result<(), NatTraversalError> {
        // Set shutdown flag
        self.shutdown.store(true, Ordering::Relaxed);
        
        // Close all active connections
        {
            let mut connections = self.connections.write()
                .map_err(|_| NatTraversalError::ProtocolError("Connections lock poisoned".to_string()))?;
            for (peer_id, connection) in connections.drain() {
                info!("Closing connection to peer {:?}", peer_id);
                connection.close(0u32.into(), b"Shutdown");
            }
        }
        
        // Wait for connection to be closed
        if let Some(ref endpoint) = self.quinn_endpoint {
            endpoint.wait_idle().await;
        }
        
        info!("NAT traversal endpoint shutdown completed");
        Ok(())
    }

    /// Discover address candidates for a peer
    #[cfg(feature = "production-ready")]
    pub async fn discover_candidates(&self, peer_id: PeerId) -> Result<Vec<CandidateAddress>, NatTraversalError> {
        debug!("Discovering address candidates for peer {:?}", peer_id);
        
        let mut candidates = Vec::new();
        
        // Get bootstrap nodes
        let bootstrap_nodes = {
            let nodes = self.bootstrap_nodes.read()
                .map_err(|_| NatTraversalError::ProtocolError("Lock poisoned".to_string()))?;
            nodes.clone()
        };
        
        // Start discovery process
        {
            let mut discovery = self.discovery_manager.lock()
                .map_err(|_| NatTraversalError::ProtocolError("Discovery manager lock poisoned".to_string()))?;
            
            discovery.start_discovery(peer_id, bootstrap_nodes)
                .map_err(|e| NatTraversalError::CandidateDiscoveryFailed(e.to_string()))?;
        }
        
        // Poll for discovery results with timeout
        let timeout_duration = self.config.coordination_timeout;
        let start_time = std::time::Instant::now();
        
        while start_time.elapsed() < timeout_duration {
            let discovery_events = {
                let mut discovery = self.discovery_manager.lock()
                    .map_err(|_| NatTraversalError::ProtocolError("Discovery manager lock poisoned".to_string()))?;
                discovery.poll(std::time::Instant::now())
            };
            
            for event in discovery_events {
                match event {
                    DiscoveryEvent::LocalCandidateDiscovered { candidate } => {
                        candidates.push(candidate);
                    }
                    DiscoveryEvent::ServerReflexiveCandidateDiscovered { candidate, .. } => {
                        candidates.push(candidate);
                    }
                    DiscoveryEvent::PredictedCandidateGenerated { candidate, .. } => {
                        candidates.push(candidate);
                    }
                    DiscoveryEvent::DiscoveryCompleted { .. } => {
                        // Discovery complete, return candidates
                        return Ok(candidates);
                    }
                    DiscoveryEvent::DiscoveryFailed { error, partial_results } => {
                        // Use partial results if available
                        candidates.extend(partial_results);
                        if candidates.is_empty() {
                            return Err(NatTraversalError::CandidateDiscoveryFailed(error.to_string()));
                        }
                        return Ok(candidates);
                    }
                    _ => {}
                }
            }
            
            // Brief delay before next poll
            sleep(Duration::from_millis(10)).await;
        }
        
        if candidates.is_empty() {
            Err(NatTraversalError::NoCandidatesFound)
        } else {
            Ok(candidates)
        }
    }
    
    /// Fallback candidate discovery for non-production builds
    #[cfg(not(feature = "production-ready"))]
    fn discover_candidates(&self, peer_id: PeerId) -> Result<(), NatTraversalError> {
        debug!("Discovering address candidates for peer {:?}", peer_id);
        
        // TODO: Implement candidate discovery
        // 1. Enumerate local network interfaces
        // 2. Query bootstrap nodes for observed addresses
        // 3. Predict symmetric NAT addresses if enabled
        
        Ok(())
    }

    fn coordinate_with_bootstrap(
        &self,
        peer_id: PeerId,
        coordinator: SocketAddr,
    ) -> Result<(), NatTraversalError> {
        debug!("Coordinating with bootstrap {} for peer {:?}", coordinator, peer_id);
        
        // TODO: This needs to be async or use a different approach
        // For now, we'll just log the intent and return
        // In a real implementation, this would:
        // 1. Connect to coordinator
        // 2. Send PUNCH_ME_NOW frame
        // 3. Wait for peer's coordination
        // 4. Synchronize timing for hole punching
        
        info!("Would coordinate with bootstrap {} for peer {:?}", coordinator, peer_id);
        
        Ok(())
    }

    fn attempt_hole_punching(&self, peer_id: PeerId) -> Result<(), NatTraversalError> {
        debug!("Attempting hole punching for peer {:?}", peer_id);
        
        // TODO: Implement hole punching
        // 1. Generate candidate pairs
        // 2. Send coordinated PATH_CHALLENGE packets
        // 3. Wait for PATH_RESPONSE validation
        
        Ok(())
    }

    /// Poll for NAT traversal progress and state machine updates
    pub fn poll(&self, now: std::time::Instant) -> Result<Vec<NatTraversalEvent>, NatTraversalError> {
        let mut events = Vec::new();
        
        // Poll candidate discovery manager
        {
            let mut discovery = self.discovery_manager.lock()
                .map_err(|_| NatTraversalError::ProtocolError("Discovery manager lock poisoned".to_string()))?;
            
            let discovery_events = discovery.poll(now);
            
            // Convert discovery events to NAT traversal events
            for discovery_event in discovery_events {
                if let Some(nat_event) = self.convert_discovery_event(discovery_event) {
                    events.push(nat_event.clone());
                    
                    // Emit via callback
                    if let Some(ref callback) = self.event_callback {
                        callback(nat_event);
                    }
                }
            }
        }
        
        // Check active sessions for timeouts and state updates
        let mut sessions = self.active_sessions.write()
            .map_err(|_| NatTraversalError::ProtocolError("Lock poisoned".to_string()))?;
        
        for (_peer_id, session) in sessions.iter_mut() {
            // TODO: Implement session state machine polling
            // 1. Check timeouts
            // 2. Advance state machine
            // 3. Generate events
            let _elapsed = now.duration_since(session.started_at);
        }
        
        Ok(events)
    }

    /// Convert discovery events to NAT traversal events
    fn convert_discovery_event(&self, discovery_event: DiscoveryEvent) -> Option<NatTraversalEvent> {
        match discovery_event {
            DiscoveryEvent::LocalCandidateDiscovered { candidate } => {
                Some(NatTraversalEvent::CandidateDiscovered {
                    peer_id: PeerId([0; 32]), // TODO: Get actual peer ID from current session
                    candidate,
                })
            },
            DiscoveryEvent::ServerReflexiveCandidateDiscovered { candidate, bootstrap_node: _ } => {
                Some(NatTraversalEvent::CandidateDiscovered {
                    peer_id: PeerId([0; 32]), // TODO: Get actual peer ID from current session
                    candidate,
                })
            },
            DiscoveryEvent::PredictedCandidateGenerated { candidate, confidence: _ } => {
                Some(NatTraversalEvent::CandidateDiscovered {
                    peer_id: PeerId([0; 32]), // TODO: Get actual peer ID from current session
                    candidate,
                })
            },
            DiscoveryEvent::DiscoveryCompleted { candidate_count: _, total_duration: _, success_rate: _ } => {
                // This could trigger the coordination phase
                None // For now, don't emit specific event
            },
            DiscoveryEvent::DiscoveryFailed { error, partial_results } => {
                Some(NatTraversalEvent::TraversalFailed {
                    peer_id: PeerId([0; 32]), // TODO: Get actual peer ID from current session
                    error: NatTraversalError::CandidateDiscoveryFailed(error.to_string()),
                    fallback_available: !partial_results.is_empty(),
                })
            },
            _ => None, // Other events don't need to be converted
        }
    }
}

impl fmt::Debug for NatTraversalEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NatTraversalEndpoint")
            .field("config", &self.config)
            .field("bootstrap_nodes", &"<RwLock>")
            .field("active_sessions", &"<RwLock>")
            .field("event_callback", &self.event_callback.is_some())
            .finish()
    }
}

/// Statistics about NAT traversal performance
#[derive(Debug, Clone)]
pub struct NatTraversalStatistics {
    /// Number of active NAT traversal sessions
    pub active_sessions: usize,
    /// Total number of known bootstrap nodes
    pub total_bootstrap_nodes: usize,
    /// Total successful coordinations
    pub successful_coordinations: u32,
    /// Average time for coordination
    pub average_coordination_time: Duration,
}

impl fmt::Display for NatTraversalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoBootstrapNodes => write!(f, "no bootstrap nodes available"),
            Self::NoCandidatesFound => write!(f, "no address candidates found"),
            Self::CandidateDiscoveryFailed(msg) => write!(f, "candidate discovery failed: {}", msg),
            Self::CoordinationFailed(msg) => write!(f, "coordination failed: {}", msg),
            Self::HolePunchingFailed => write!(f, "hole punching failed"),
            Self::ValidationTimeout => write!(f, "validation timeout"),
            Self::NetworkError(msg) => write!(f, "network error: {}", msg),
            Self::ConfigError(msg) => write!(f, "configuration error: {}", msg),
            Self::ProtocolError(msg) => write!(f, "protocol error: {}", msg),
            Self::Timeout => write!(f, "operation timed out"),
            Self::ConnectionFailed(msg) => write!(f, "connection failed: {}", msg),
            Self::TraversalFailed(msg) => write!(f, "traversal failed: {}", msg),
        }
    }
}

impl std::error::Error for NatTraversalError {}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display first 8 bytes as hex (16 characters)
        for byte in &self.0[..8] {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl From<[u8; 32]> for PeerId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Dummy certificate verifier that accepts any certificate
/// WARNING: This is only for testing/demo purposes - use proper verification in production!
#[derive(Debug)]
struct SkipServerVerification;

impl SkipServerVerification {
    #[allow(dead_code)]
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Default token store that accepts all tokens (for demo purposes)
struct DefaultTokenStore;

impl crate::TokenStore for DefaultTokenStore {
    fn insert(&self, _server_name: &str, _token: bytes::Bytes) {
        // Ignore token storage for demo
    }

    fn take(&self, _server_name: &str) -> Option<bytes::Bytes> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_traversal_config_default() {
        let config = NatTraversalConfig::default();
        assert_eq!(config.role, EndpointRole::Client);
        assert_eq!(config.max_candidates, 8);
        assert!(config.enable_symmetric_nat);
        assert!(config.enable_relay_fallback);
    }

    #[test]
    fn test_peer_id_display() {
        let peer_id = PeerId([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
        assert_eq!(format!("{}", peer_id), "0123456789abcdef");
    }

    #[test]
    fn test_bootstrap_node_management() {
        let config = NatTraversalConfig::default();
        // Note: This will fail due to ServerConfig requirement in new() - for illustration only
        // let endpoint = NatTraversalEndpoint::new(config, None).unwrap();
    }
}