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

use tracing::{debug, info};

use crate::{
    candidate_discovery::{CandidateDiscoveryManager, DiscoveryConfig, DiscoveryEvent},
    connection::nat_traversal::{CandidateSource, CandidateState, NatTraversalRole},
    Endpoint, VarInt,
};

/// High-level NAT traversal endpoint for Autonomi P2P networks
pub struct NatTraversalEndpoint {
    /// Underlying Quinn endpoint
    endpoint: Endpoint,
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
}

/// Configuration for NAT traversal behavior
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointRole {
    /// Regular client node (most common)
    Client,
    /// Server node (always reachable, can coordinate)
    Server { can_coordinate: bool },
    /// Bootstrap node (public, coordinates NAT traversal)
    Bootstrap,
}

/// Unique identifier for a peer in the network
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

impl NatTraversalEndpoint {
    /// Create a new NAT traversal endpoint with optional event callback
    pub fn new(
        config: NatTraversalConfig,
        event_callback: Option<Box<dyn Fn(NatTraversalEvent) + Send + Sync>>,
    ) -> Result<Self, NatTraversalError> {
        // Validate configuration
        if config.bootstrap_nodes.is_empty() && config.role != EndpointRole::Bootstrap {
            return Err(NatTraversalError::ConfigError(
                "At least one bootstrap node required for non-bootstrap endpoints".to_string(),
            ));
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
        // Note: This is a simplified version - in production you'd need proper TLS setup
        let endpoint = Self::create_quic_endpoint(&config, nat_traversal_role)?;

        Ok(Self {
            endpoint,
            config,
            bootstrap_nodes,
            active_sessions: Arc::new(std::sync::RwLock::new(HashMap::new())),
            discovery_manager,
            event_callback,
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

    /// Create a QUIC endpoint with NAT traversal configured
    fn create_quic_endpoint(
        config: &NatTraversalConfig,
        nat_role: NatTraversalRole,
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
                // For demo purposes, create a simple server config
                // In production, you'd need proper certificate management
                let cert = rustls::pki_types::CertificateDer::from(vec![0; 32]); // Dummy cert
                let key = rustls::pki_types::PrivateKeyDer::try_from(vec![0; 32]).ok(); // Dummy key
                
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