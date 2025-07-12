//! Bootstrap Node Certificate Type Support
//!
//! This module provides certificate type advertisement, discovery, and
//! compatibility checking for bootstrap nodes in mixed P2P deployments
//! where different peers may support different certificate types.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
    time::{Duration, Instant},
    net::SocketAddr,
};

use serde::{Serialize, Deserialize};
use tracing::{debug, info, error, span, Level};

use super::{
    tls_extensions::{
        CertificateType, CertificateTypeList, CertificateTypePreferences,
        TlsExtensionError,
    },
    certificate_negotiation::{CertificateNegotiationManager, NegotiationConfig},
};

use crate::nat_traversal_api::{PeerId, EndpointRole};

/// Certificate type capabilities advertisement for bootstrap nodes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificateTypeCapabilities {
    /// Certificate types supported for client authentication
    pub client_types: Vec<CertificateType>,
    /// Certificate types supported for server authentication
    pub server_types: Vec<CertificateType>,
    /// Whether this node requires certificate type extensions
    pub requires_extensions: bool,
    /// Preferred certificate types (most preferred first)
    pub preferences: Vec<CertificateType>,
    /// Bootstrap node role and capabilities
    pub endpoint_role: EndpointRole,
    /// Timestamp when capabilities were last updated
    pub last_updated: u64,
}

impl CertificateTypeCapabilities {
    /// Create capabilities from certificate type preferences
    pub fn from_preferences(
        preferences: &CertificateTypePreferences,
        role: EndpointRole,
    ) -> Self {
        Self {
            client_types: preferences.client_types.types.clone(),
            server_types: preferences.server_types.types.clone(),
            requires_extensions: preferences.require_extensions,
            preferences: preferences.server_types.types.clone(), // Use server types as general preference
            endpoint_role: role,
            last_updated: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Convert to certificate type preferences
    pub fn to_preferences(&self) -> Result<CertificateTypePreferences, TlsExtensionError> {
        let client_types = CertificateTypeList::new(self.client_types.clone())?;
        let server_types = CertificateTypeList::new(self.server_types.clone())?;
        
        Ok(CertificateTypePreferences {
            client_types,
            server_types,
            require_extensions: self.requires_extensions,
            fallback_client: CertificateType::X509,
            fallback_server: CertificateType::X509,
        })
    }

    /// Check if this node supports Raw Public Keys
    pub fn supports_raw_public_key(&self) -> bool {
        self.client_types.contains(&CertificateType::RawPublicKey) ||
        self.server_types.contains(&CertificateType::RawPublicKey)
    }

    /// Check if this node supports X.509 certificates
    pub fn supports_x509(&self) -> bool {
        self.client_types.contains(&CertificateType::X509) ||
        self.server_types.contains(&CertificateType::X509)
    }

    /// Check compatibility with another node's capabilities
    pub fn is_compatible_with(&self, other: &CertificateTypeCapabilities) -> bool {
        // Check if there's at least one common certificate type for both client and server auth
        let common_client_types: HashSet<_> = self.client_types.iter()
            .filter(|t| other.client_types.contains(t))
            .collect();
        
        let common_server_types: HashSet<_> = self.server_types.iter()
            .filter(|t| other.server_types.contains(t))
            .collect();

        !common_client_types.is_empty() && !common_server_types.is_empty()
    }

    /// Get the best common certificate type for communication
    pub fn negotiate_with(&self, other: &CertificateTypeCapabilities) -> Option<(CertificateType, CertificateType)> {
        // Find the best common client certificate type
        let client_type = self.preferences.iter()
            .find(|&t| other.client_types.contains(t) && self.client_types.contains(t))
            .copied();

        // Find the best common server certificate type
        let server_type = self.preferences.iter()
            .find(|&t| other.server_types.contains(t) && self.server_types.contains(t))
            .copied();

        match (client_type, server_type) {
            (Some(c), Some(s)) => Some((c, s)),
            _ => None,
        }
    }

    /// Check if capabilities are expired
    pub fn is_expired(&self, max_age: Duration) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        now - self.last_updated > max_age.as_secs()
    }

    /// Update the last updated timestamp
    pub fn refresh(&mut self) {
        self.last_updated = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
}

/// Peer information with certificate type capabilities
#[derive(Debug, Clone)]
pub struct CertTypePeerInfo {
    /// Peer ID
    pub peer_id: PeerId,
    /// Peer's network address
    pub address: SocketAddr,
    /// Certificate type capabilities
    pub capabilities: CertificateTypeCapabilities,
    /// When this peer info was discovered
    pub discovered_at: Instant,
    /// Last successful connection time
    pub last_connected: Option<Instant>,
    /// Connection success rate (0.0 to 1.0)
    pub success_rate: f64,
    /// Number of connection attempts
    pub connection_attempts: u64,
    /// Number of successful connections
    pub successful_connections: u64,
}

impl CertTypePeerInfo {
    /// Create new peer info
    pub fn new(
        peer_id: PeerId,
        address: SocketAddr,
        capabilities: CertificateTypeCapabilities,
    ) -> Self {
        Self {
            peer_id,
            address,
            capabilities,
            discovered_at: Instant::now(),
            last_connected: None,
            success_rate: 0.0,
            connection_attempts: 0,
            successful_connections: 0,
        }
    }

    /// Record a connection attempt
    pub fn record_connection_attempt(&mut self, success: bool) {
        self.connection_attempts += 1;
        if success {
            self.successful_connections += 1;
            self.last_connected = Some(Instant::now());
        }
        
        self.success_rate = if self.connection_attempts > 0 {
            self.successful_connections as f64 / self.connection_attempts as f64
        } else {
            0.0
        };
    }

    /// Check if peer info is stale
    pub fn is_stale(&self, max_age: Duration) -> bool {
        self.discovered_at.elapsed() > max_age
    }

    /// Get peer quality score (0.0 to 1.0)
    pub fn quality_score(&self) -> f64 {
        let recency_factor = {
            let age = self.discovered_at.elapsed().as_secs() as f64;
            let max_age = 3600.0; // 1 hour
            (max_age - age.min(max_age)) / max_age
        };

        let success_factor = self.success_rate;
        
        let activity_factor = if self.connection_attempts > 0 {
            (self.connection_attempts as f64).log10().min(2.0) / 2.0
        } else {
            0.0
        };

        (recency_factor * 0.3 + success_factor * 0.5 + activity_factor * 0.2).min(1.0)
    }
}

/// Bootstrap node certificate type registry
pub struct CertTypeBootstrapRegistry {
    /// Known peers with their certificate type capabilities
    peers: Arc<RwLock<HashMap<PeerId, CertTypePeerInfo>>>,
    /// Our own capabilities
    local_capabilities: CertificateTypeCapabilities,
    /// Certificate type negotiation manager
    negotiation_manager: Arc<CertificateNegotiationManager>,
    /// Registry configuration
    config: BootstrapRegistryConfig,
}

/// Configuration for the bootstrap registry
#[derive(Debug, Clone)]
pub struct BootstrapRegistryConfig {
    /// Maximum age for peer information before it's considered stale
    pub max_peer_age: Duration,
    /// Maximum age for certificate type capabilities
    pub max_capabilities_age: Duration,
    /// Maximum number of peers to track
    pub max_peers: usize,
    /// Minimum quality score for peer inclusion
    pub min_quality_score: f64,
}

impl Default for BootstrapRegistryConfig {
    fn default() -> Self {
        Self {
            max_peer_age: Duration::from_secs(3600), // 1 hour
            max_capabilities_age: Duration::from_secs(300), // 5 minutes
            max_peers: 1000,
            min_quality_score: 0.1,
        }
    }
}

impl CertTypeBootstrapRegistry {
    /// Create a new bootstrap registry
    pub fn new(
        local_capabilities: CertificateTypeCapabilities,
        negotiation_config: NegotiationConfig,
        config: BootstrapRegistryConfig,
    ) -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
            local_capabilities,
            negotiation_manager: Arc::new(CertificateNegotiationManager::new(negotiation_config)),
            config,
        }
    }

    /// Register a peer with their certificate type capabilities
    pub fn register_peer(
        &self,
        peer_id: PeerId,
        address: SocketAddr,
        capabilities: CertificateTypeCapabilities,
    ) -> Result<(), BootstrapError> {
        let _span = span!(Level::DEBUG, "register_peer", peer_id = ?peer_id, address = %address).entered();

        // Validate capabilities
        if capabilities.is_expired(self.config.max_capabilities_age) {
            return Err(BootstrapError::ExpiredCapabilities);
        }

        let mut peers = self.peers.write().unwrap();
        
        // Check if we're at capacity
        if peers.len() >= self.config.max_peers && !peers.contains_key(&peer_id) {
            // Remove the lowest quality peer to make room
            if let Some((worst_peer_id, _)) = peers.iter()
                .min_by(|a, b| a.1.quality_score().partial_cmp(&b.1.quality_score()).unwrap())
                .map(|(id, peer)| (*id, peer.quality_score()))
            {
                if worst_peer_id != peer_id {
                    peers.remove(&worst_peer_id);
                    debug!("Removed low-quality peer to make room: {:?}", worst_peer_id);
                }
            }
        }

        let peer_info = CertTypePeerInfo::new(peer_id, address, capabilities);
        peers.insert(peer_id, peer_info);

        debug!("Registered peer with certificate type capabilities: {:?}", peer_id);
        Ok(())
    }

    /// Get compatible peers for the given certificate type preferences
    pub fn get_compatible_peers(
        &self,
        preferences: &CertificateTypePreferences,
    ) -> Vec<CertTypePeerInfo> {
        let peers = self.peers.read().unwrap();
        let local_caps = CertificateTypeCapabilities::from_preferences(preferences, EndpointRole::Client);

        peers.values()
            .filter(|peer| {
                // Check compatibility
                local_caps.is_compatible_with(&peer.capabilities) &&
                // Check quality score
                peer.quality_score() >= self.config.min_quality_score &&
                // Check staleness
                !peer.is_stale(self.config.max_peer_age)
            })
            .cloned()
            .collect()
    }

    /// Get the best peer for connection based on certificate type compatibility
    pub fn get_best_peer(
        &self,
        preferences: &CertificateTypePreferences,
    ) -> Option<CertTypePeerInfo> {
        let compatible_peers = self.get_compatible_peers(preferences);
        
        compatible_peers.into_iter()
            .max_by(|a, b| a.quality_score().partial_cmp(&b.quality_score()).unwrap())
    }

    /// Get peers that support Raw Public Keys
    pub fn get_rpk_peers(&self) -> Vec<CertTypePeerInfo> {
        let peers = self.peers.read().unwrap();
        
        peers.values()
            .filter(|peer| {
                peer.capabilities.supports_raw_public_key() &&
                peer.quality_score() >= self.config.min_quality_score &&
                !peer.is_stale(self.config.max_peer_age)
            })
            .cloned()
            .collect()
    }

    /// Get peers that support X.509 certificates
    pub fn get_x509_peers(&self) -> Vec<CertTypePeerInfo> {
        let peers = self.peers.read().unwrap();
        
        peers.values()
            .filter(|peer| {
                peer.capabilities.supports_x509() &&
                peer.quality_score() >= self.config.min_quality_score &&
                !peer.is_stale(self.config.max_peer_age)
            })
            .cloned()
            .collect()
    }

    /// Record a connection attempt to a peer
    pub fn record_connection_attempt(&self, peer_id: PeerId, success: bool) {
        let mut peers = self.peers.write().unwrap();
        if let Some(peer) = peers.get_mut(&peer_id) {
            peer.record_connection_attempt(success);
            debug!("Recorded connection attempt for peer {:?}: success={}, rate={:.2}",
                   peer_id, success, peer.success_rate);
        }
    }

    /// Update capabilities for a peer
    pub fn update_peer_capabilities(
        &self,
        peer_id: PeerId,
        capabilities: CertificateTypeCapabilities,
    ) -> Result<(), BootstrapError> {
        if capabilities.is_expired(self.config.max_capabilities_age) {
            return Err(BootstrapError::ExpiredCapabilities);
        }

        let mut peers = self.peers.write().unwrap();
        if let Some(peer) = peers.get_mut(&peer_id) {
            peer.capabilities = capabilities;
            debug!("Updated capabilities for peer: {:?}", peer_id);
            Ok(())
        } else {
            Err(BootstrapError::PeerNotFound)
        }
    }

    /// Remove a peer from the registry
    pub fn remove_peer(&self, peer_id: PeerId) -> bool {
        let mut peers = self.peers.write().unwrap();
        let removed = peers.remove(&peer_id).is_some();
        if removed {
            debug!("Removed peer from registry: {:?}", peer_id);
        }
        removed
    }

    /// Clean up stale peers and expired capabilities
    pub fn cleanup_stale_entries(&self) {
        let mut peers = self.peers.write().unwrap();
        let mut removed_count = 0;

        peers.retain(|peer_id, peer| {
            let should_retain = !peer.is_stale(self.config.max_peer_age) &&
                              !peer.capabilities.is_expired(self.config.max_capabilities_age) &&
                              peer.quality_score() >= self.config.min_quality_score;
            
            if !should_retain {
                removed_count += 1;
                debug!("Removed stale peer: {:?}", peer_id);
            }
            
            should_retain
        });

        if removed_count > 0 {
            info!("Cleaned up {} stale peers from registry", removed_count);
        }
    }

    /// Get registry statistics
    pub fn get_stats(&self) -> BootstrapRegistryStats {
        let peers = self.peers.read().unwrap();
        
        let total_peers = peers.len();
        let rpk_peers = peers.values().filter(|p| p.capabilities.supports_raw_public_key()).count();
        let x509_peers = peers.values().filter(|p| p.capabilities.supports_x509()).count();
        let mixed_peers = peers.values().filter(|p| 
            p.capabilities.supports_raw_public_key() && p.capabilities.supports_x509()
        ).count();

        let avg_quality = if total_peers > 0 {
            peers.values().map(|p| p.quality_score()).sum::<f64>() / total_peers as f64
        } else {
            0.0
        };

        let avg_success_rate = if total_peers > 0 {
            peers.values().map(|p| p.success_rate).sum::<f64>() / total_peers as f64
        } else {
            0.0
        };

        BootstrapRegistryStats {
            total_peers,
            rpk_peers,
            x509_peers,
            mixed_peers,
            avg_quality_score: avg_quality,
            avg_success_rate,
        }
    }

    /// Get our local capabilities
    pub fn local_capabilities(&self) -> &CertificateTypeCapabilities {
        &self.local_capabilities
    }

    /// Update our local capabilities
    pub fn update_local_capabilities(&mut self, capabilities: CertificateTypeCapabilities) {
        self.local_capabilities = capabilities;
        info!("Updated local certificate type capabilities");
    }
}

/// Statistics for the bootstrap registry
#[derive(Debug, Clone)]
pub struct BootstrapRegistryStats {
    /// Total number of peers
    pub total_peers: usize,
    /// Peers supporting Raw Public Keys
    pub rpk_peers: usize,
    /// Peers supporting X.509 certificates
    pub x509_peers: usize,
    /// Peers supporting both certificate types
    pub mixed_peers: usize,
    /// Average quality score
    pub avg_quality_score: f64,
    /// Average connection success rate
    pub avg_success_rate: f64,
}

/// Errors that can occur in bootstrap operations
#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error("Peer not found in registry")]
    PeerNotFound,
    
    #[error("Certificate type capabilities are expired")]
    ExpiredCapabilities,
    
    #[error("Registry is at maximum capacity")]
    RegistryFull,
    
    #[error("Invalid certificate type capabilities: {0}")]
    InvalidCapabilities(#[from] TlsExtensionError),
    
    #[error("Peer is incompatible with local capabilities")]
    IncompatiblePeer,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn create_test_capabilities(
        client_types: Vec<CertificateType>,
        server_types: Vec<CertificateType>,
    ) -> CertificateTypeCapabilities {
        CertificateTypeCapabilities {
            client_types,
            server_types,
            requires_extensions: false,
            preferences: vec![CertificateType::RawPublicKey, CertificateType::X509],
            endpoint_role: EndpointRole::Client,
            last_updated: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    #[test]
    fn test_capabilities_compatibility() {
        let rpk_caps = create_test_capabilities(
            vec![CertificateType::RawPublicKey],
            vec![CertificateType::RawPublicKey],
        );

        let mixed_caps = create_test_capabilities(
            vec![CertificateType::RawPublicKey, CertificateType::X509],
            vec![CertificateType::RawPublicKey, CertificateType::X509],
        );

        let x509_caps = create_test_capabilities(
            vec![CertificateType::X509],
            vec![CertificateType::X509],
        );

        // RPK should be compatible with mixed
        assert!(rpk_caps.is_compatible_with(&mixed_caps));
        assert!(mixed_caps.is_compatible_with(&rpk_caps));

        // X509 should be compatible with mixed
        assert!(x509_caps.is_compatible_with(&mixed_caps));
        assert!(mixed_caps.is_compatible_with(&x509_caps));

        // RPK and X509 should not be compatible
        assert!(!rpk_caps.is_compatible_with(&x509_caps));
        assert!(!x509_caps.is_compatible_with(&rpk_caps));
    }

    #[test]
    fn test_capabilities_negotiation() {
        let mixed_caps = create_test_capabilities(
            vec![CertificateType::RawPublicKey, CertificateType::X509],
            vec![CertificateType::RawPublicKey, CertificateType::X509],
        );

        let rpk_caps = create_test_capabilities(
            vec![CertificateType::RawPublicKey],
            vec![CertificateType::RawPublicKey],
        );

        let result = mixed_caps.negotiate_with(&rpk_caps);
        assert_eq!(result, Some((CertificateType::RawPublicKey, CertificateType::RawPublicKey)));
    }

    #[test]
    fn test_peer_info_quality_score() {
        let caps = create_test_capabilities(
            vec![CertificateType::RawPublicKey],
            vec![CertificateType::RawPublicKey],
        );

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let mut peer = CertTypePeerInfo::new(PeerId([1; 32]), addr, caps);

        let initial_score = peer.quality_score();

        // Record successful connections
        peer.record_connection_attempt(true);
        peer.record_connection_attempt(true);
        peer.record_connection_attempt(false);

        let updated_score = peer.quality_score();
        
        assert!(peer.success_rate > 0.0);
        assert!(peer.connection_attempts > 0);
        // Score should be influenced by success rate
    }

    #[test]
    fn test_bootstrap_registry_basic_operations() {
        let local_caps = create_test_capabilities(
            vec![CertificateType::RawPublicKey, CertificateType::X509],
            vec![CertificateType::RawPublicKey, CertificateType::X509],
        );

        let registry = CertTypeBootstrapRegistry::new(
            local_caps,
            NegotiationConfig::default(),
            BootstrapRegistryConfig::default(),
        );

        let peer_id = PeerId([1; 32]);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let peer_caps = create_test_capabilities(
            vec![CertificateType::RawPublicKey],
            vec![CertificateType::RawPublicKey],
        );

        // Register peer
        assert!(registry.register_peer(peer_id, addr, peer_caps).is_ok());

        // Check that peer is registered
        let stats = registry.get_stats();
        assert_eq!(stats.total_peers, 1);
        assert_eq!(stats.rpk_peers, 1);

        // Record connection attempts
        registry.record_connection_attempt(peer_id, true);
        registry.record_connection_attempt(peer_id, false);

        // Remove peer
        assert!(registry.remove_peer(peer_id));
        let stats = registry.get_stats();
        assert_eq!(stats.total_peers, 0);
    }

    #[test]
    fn test_bootstrap_registry_compatibility_filtering() {
        let local_caps = create_test_capabilities(
            vec![CertificateType::RawPublicKey],
            vec![CertificateType::RawPublicKey],
        );

        let registry = CertTypeBootstrapRegistry::new(
            local_caps.clone(),
            NegotiationConfig::default(),
            BootstrapRegistryConfig::default(),
        );

        // Add compatible peer
        let peer1_id = PeerId([1; 32]);
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081);
        let peer1_caps = create_test_capabilities(
            vec![CertificateType::RawPublicKey],
            vec![CertificateType::RawPublicKey],
        );
        registry.register_peer(peer1_id, addr1, peer1_caps).unwrap();

        // Add incompatible peer
        let peer2_id = PeerId([2; 32]);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8082);
        let peer2_caps = create_test_capabilities(
            vec![CertificateType::X509],
            vec![CertificateType::X509],
        );
        registry.register_peer(peer2_id, addr2, peer2_caps).unwrap();

        // Get compatible peers
        let preferences = local_caps.to_preferences().unwrap();
        let compatible = registry.get_compatible_peers(&preferences);
        
        assert_eq!(compatible.len(), 1);
        assert_eq!(compatible[0].peer_id, peer1_id);
    }
}