//! Distributed Peer Discovery with Certificate Type Awareness
//!
//! This module implements a distributed peer discovery system that includes
//! certificate type capabilities in peer announcements, enabling efficient
//! discovery of compatible peers in P2P networks.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, Instant, SystemTime},
    net::SocketAddr,
};

use serde::{Serialize, Deserialize};
use tokio::sync::{mpsc, broadcast};
use tracing::{debug, info, error, instrument};

use crate::nat_traversal_api::{PeerId, EndpointRole};
use super::{
    tls_extensions::{CertificateType, CertificateTypePreferences},
    bootstrap_support::{CertificateTypeCapabilities, CertTypePeerInfo},
};

/// Peer announcement with certificate type capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAnnouncement {
    /// Peer identifier
    pub peer_id: PeerId,
    /// Network addresses
    pub addresses: Vec<SocketAddr>,
    /// Certificate type capabilities
    pub cert_capabilities: CertificateTypeCapabilities,
    /// Service metadata
    pub services: Vec<String>,
    /// Announcement timestamp
    pub timestamp: u64,
    /// Time-to-live in seconds
    pub ttl: u32,
    /// Signature for authenticity
    pub signature: Vec<u8>,
}

impl PeerAnnouncement {
    /// Create a new peer announcement
    pub fn new(
        peer_id: PeerId,
        addresses: Vec<SocketAddr>,
        cert_capabilities: CertificateTypeCapabilities,
        services: Vec<String>,
        ttl: u32,
    ) -> Self {
        Self {
            peer_id,
            addresses,
            cert_capabilities,
            services,
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            ttl,
            signature: Vec::new(), // Would be signed with peer's private key
        }
    }

    /// Check if announcement is still valid
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        now < self.timestamp.saturating_add(self.ttl as u64)
    }

    /// Get announcement age
    pub fn age(&self) -> Duration {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Duration::from_secs(now.saturating_sub(self.timestamp))
    }
}

/// DHT-based peer discovery with certificate type support
pub struct CertTypeDht {
    /// Local peer ID
    local_peer_id: PeerId,
    /// Local certificate capabilities
    local_capabilities: CertificateTypeCapabilities,
    /// Routing table organized by XOR distance
    routing_table: Arc<RwLock<DhtRoutingTable>>,
    /// Stored peer announcements
    peer_store: Arc<RwLock<HashMap<PeerId, PeerAnnouncement>>>,
    /// Event channel for DHT events
    event_tx: mpsc::UnboundedSender<DhtEvent>,
    /// Configuration
    config: DhtConfig,
}

/// DHT routing table using Kademlia-style buckets
struct DhtRoutingTable {
    /// K-buckets organized by distance
    buckets: Vec<KBucket>,
    /// Local peer ID for distance calculations
    local_id: PeerId,
}

impl DhtRoutingTable {
    fn new(local_id: PeerId, bucket_size: usize) -> Self {
        let mut buckets = Vec::with_capacity(256);
        for _ in 0..256 {
            buckets.push(KBucket::new(bucket_size));
        }
        
        Self { buckets, local_id }
    }

    /// Find the bucket index for a peer
    fn bucket_index(&self, peer_id: &PeerId) -> usize {
        let distance = xor_distance(&self.local_id.0, &peer_id.0);
        leading_zeros(&distance).min(255) as usize
    }

    /// Add a peer to the routing table
    fn add_peer(&mut self, info: CertTypePeerInfo) -> bool {
        let bucket_idx = self.bucket_index(&info.peer_id);
        self.buckets[bucket_idx].add_peer(info)
    }

    /// Find closest peers to a target
    fn find_closest(&self, target: &PeerId, count: usize) -> Vec<CertTypePeerInfo> {
        let mut candidates: Vec<(PeerId, CertTypePeerInfo)> = Vec::new();
        
        for bucket in &self.buckets {
            for peer in &bucket.peers {
                let distance = xor_distance(&target.0, &peer.peer_id.0);
                candidates.push((PeerId(distance), peer.clone()));
            }
        }
        
        candidates.sort_by_key(|(distance, _)| *distance);
        candidates.into_iter()
            .take(count)
            .map(|(_, info)| info)
            .collect()
    }

    /// Get peers with specific certificate type capabilities
    fn find_by_cert_type(&self, cert_type: CertificateType) -> Vec<CertTypePeerInfo> {
        let mut results = Vec::new();
        
        for bucket in &self.buckets {
            for peer in &bucket.peers {
                if peer.capabilities.supports_cert_type(cert_type) {
                    results.push(peer.clone());
                }
            }
        }
        
        results
    }
}

/// K-bucket for storing peers at similar distances
struct KBucket {
    /// Maximum number of peers in bucket
    capacity: usize,
    /// Peers in this bucket
    peers: Vec<CertTypePeerInfo>,
    /// Last activity time
    last_updated: Instant,
}

impl KBucket {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            peers: Vec::with_capacity(capacity),
            last_updated: Instant::now(),
        }
    }

    fn add_peer(&mut self, info: CertTypePeerInfo) -> bool {
        self.last_updated = Instant::now();
        
        // Check if peer already exists
        if let Some(existing) = self.peers.iter_mut().find(|p| p.peer_id == info.peer_id) {
            // Update existing peer info
            *existing = info;
            return true;
        }
        
        // Add new peer if space available
        if self.peers.len() < self.capacity {
            self.peers.push(info);
            true
        } else {
            // Bucket is full - in real implementation would check for stale peers
            false
        }
    }
}

/// Configuration for DHT
#[derive(Debug, Clone)]
pub struct DhtConfig {
    /// K-bucket size
    pub bucket_size: usize,
    /// Replication factor
    pub replication_factor: usize,
    /// Lookup parallelism
    pub alpha: usize,
    /// Announcement interval
    pub announce_interval: Duration,
    /// Cleanup interval
    pub cleanup_interval: Duration,
    /// Request timeout
    pub request_timeout: Duration,
}

impl Default for DhtConfig {
    fn default() -> Self {
        Self {
            bucket_size: 20,
            replication_factor: 20,
            alpha: 3,
            announce_interval: Duration::from_secs(300),
            cleanup_interval: Duration::from_secs(600),
            request_timeout: Duration::from_secs(10),
        }
    }
}

/// DHT events
#[derive(Debug)]
pub enum DhtEvent {
    /// New peer discovered
    PeerDiscovered(CertTypePeerInfo),
    /// Peer capabilities updated
    PeerUpdated(PeerId, CertificateTypeCapabilities),
    /// Peer removed
    PeerRemoved(PeerId),
    /// Lookup completed
    LookupCompleted {
        target: PeerId,
        results: Vec<CertTypePeerInfo>,
    },
}

impl CertTypeDht {
    /// Create a new DHT instance
    pub fn new(
        local_peer_id: PeerId,
        local_capabilities: CertificateTypeCapabilities,
        config: DhtConfig,
    ) -> (Self, mpsc::UnboundedReceiver<DhtEvent>) {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        
        let dht = Self {
            local_peer_id,
            local_capabilities,
            routing_table: Arc::new(RwLock::new(DhtRoutingTable::new(
                local_peer_id,
                config.bucket_size,
            ))),
            peer_store: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            config,
        };
        
        (dht, event_rx)
    }

    /// Announce ourselves to the network
    #[instrument(skip(self))]
    pub async fn announce(&self, services: Vec<String>) -> Result<(), DhtError> {
        let announcement = PeerAnnouncement::new(
            self.local_peer_id,
            vec![], // Would include actual addresses
            self.local_capabilities.clone(),
            services,
            self.config.announce_interval.as_secs() as u32 * 2,
        );

        // Find nodes to announce to
        let routing_table = self.routing_table.read().unwrap();
        let targets = routing_table.find_closest(&self.local_peer_id, self.config.replication_factor);
        drop(routing_table);

        // Send announcements (simplified - would use actual network)
        for target in targets {
            debug!("Announcing {:?} to peer {:?}", announcement.peer_id, target.peer_id);
            // In real implementation, would send announcement over network
        }

        info!("DHT announcement completed");
        Ok(())
    }

    /// Lookup peers with specific certificate type capabilities
    #[instrument(skip(self))]
    pub async fn lookup_by_cert_type(
        &self,
        cert_type: CertificateType,
    ) -> Result<Vec<CertTypePeerInfo>, DhtError> {
        let routing_table = self.routing_table.read().unwrap();
        let results = routing_table.find_by_cert_type(cert_type);
        
        info!("Found {} peers supporting {:?}", results.len(), cert_type);
        Ok(results)
    }

    /// Find peers compatible with our certificate preferences
    pub async fn find_compatible_peers(
        &self,
        preferences: &CertificateTypePreferences,
    ) -> Result<Vec<CertTypePeerInfo>, DhtError> {
        let peer_store = self.peer_store.read().unwrap();
        let local_caps = CertificateTypeCapabilities::from_preferences(preferences, EndpointRole::Client);
        
        let compatible: Vec<_> = peer_store.values()
            .filter_map(|announcement| {
                if announcement.is_valid() && local_caps.is_compatible_with(&announcement.cert_capabilities) {
                    Some(CertTypePeerInfo::new(
                        announcement.peer_id,
                        announcement.addresses.first().copied()?,
                        announcement.cert_capabilities.clone(),
                    ))
                } else {
                    None
                }
            })
            .collect();

        Ok(compatible)
    }

    /// Store a peer announcement
    pub fn store_announcement(&self, announcement: PeerAnnouncement) -> Result<(), DhtError> {
        if !announcement.is_valid() {
            return Err(DhtError::InvalidAnnouncement);
        }

        let peer_info = CertTypePeerInfo::new(
            announcement.peer_id,
            announcement.addresses.first().copied()
                .ok_or(DhtError::NoAddresses)?,
            announcement.cert_capabilities.clone(),
        );

        // Add to routing table
        let mut routing_table = self.routing_table.write().unwrap();
        routing_table.add_peer(peer_info.clone());
        drop(routing_table);

        // Store announcement
        self.peer_store.write().unwrap()
            .insert(announcement.peer_id, announcement);

        // Emit event
        let _ = self.event_tx.send(DhtEvent::PeerDiscovered(peer_info));

        Ok(())
    }

    /// Clean up expired entries
    pub fn cleanup(&self) {
        let mut peer_store = self.peer_store.write().unwrap();
        let removed: Vec<_> = peer_store
            .iter()
            .filter(|(_, ann)| !ann.is_valid())
            .map(|(id, _)| *id)
            .collect();

        for peer_id in removed {
            peer_store.remove(&peer_id);
            let _ = self.event_tx.send(DhtEvent::PeerRemoved(peer_id));
        }
    }
}

/// Gossip protocol for peer discovery
pub struct CertTypeGossip {
    /// Local peer information
    local_peer_id: PeerId,
    local_capabilities: CertificateTypeCapabilities,
    /// Known peers and their views
    peer_views: Arc<RwLock<HashMap<PeerId, GossipView>>>,
    /// Gossip configuration
    config: GossipConfig,
    /// Event channel
    event_tx: broadcast::Sender<GossipEvent>,
}

/// Gossip view from a peer's perspective
#[derive(Debug, Clone)]
struct GossipView {
    /// Peers known to this peer
    known_peers: HashMap<PeerId, GossipPeerInfo>,
    /// Last update time
    last_updated: Instant,
    /// View version for conflict resolution
    version: u64,
}

/// Peer information in gossip protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipPeerInfo {
    pub peer_id: PeerId,
    pub addresses: Vec<SocketAddr>,
    pub cert_capabilities: CertificateTypeCapabilities,
    pub heartbeat: u64,
    pub services: Vec<String>,
}

/// Gossip protocol configuration
#[derive(Debug, Clone)]
pub struct GossipConfig {
    /// Gossip interval
    pub gossip_interval: Duration,
    /// Number of peers to gossip with each round
    pub fanout: usize,
    /// Maximum peers to track
    pub max_peers: usize,
    /// Heartbeat timeout
    pub heartbeat_timeout: Duration,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            gossip_interval: Duration::from_secs(10),
            fanout: 3,
            max_peers: 1000,
            heartbeat_timeout: Duration::from_secs(60),
        }
    }
}

/// Gossip protocol events
#[derive(Debug, Clone)]
pub enum GossipEvent {
    /// New peer discovered through gossip
    PeerDiscovered(GossipPeerInfo),
    /// Peer information updated
    PeerUpdated(PeerId, CertificateTypeCapabilities),
    /// Peer considered offline
    PeerOffline(PeerId),
}

impl CertTypeGossip {
    /// Create a new gossip protocol instance
    pub fn new(
        local_peer_id: PeerId,
        local_capabilities: CertificateTypeCapabilities,
        config: GossipConfig,
    ) -> (Self, broadcast::Receiver<GossipEvent>) {
        let (event_tx, event_rx) = broadcast::channel(100);
        
        let gossip = Self {
            local_peer_id,
            local_capabilities,
            peer_views: Arc::new(RwLock::new(HashMap::new())),
            config,
            event_tx,
        };
        
        (gossip, event_rx)
    }

    /// Process incoming gossip message
    #[instrument(skip(self, message))]
    pub async fn handle_gossip(&self, from: PeerId, message: GossipMessage) -> Result<(), DhtError> {
        match message {
            GossipMessage::PeerUpdate { peers, version } => {
                self.handle_peer_update(from, peers, version).await?;
            }
            GossipMessage::Heartbeat { capabilities } => {
                self.handle_heartbeat(from, capabilities).await?;
            }
            GossipMessage::Request => {
                // Would send our view to the requester
            }
        }
        
        Ok(())
    }

    /// Handle peer update from gossip
    async fn handle_peer_update(
        &self,
        from: PeerId,
        peers: Vec<GossipPeerInfo>,
        version: u64,
    ) -> Result<(), DhtError> {
        let mut views = self.peer_views.write().unwrap();
        
        // Update or create view for this peer
        let view = views.entry(from).or_insert_with(|| GossipView {
            known_peers: HashMap::new(),
            last_updated: Instant::now(),
            version: 0,
        });

        // Only update if version is newer
        if version > view.version {
            view.version = version;
            view.last_updated = Instant::now();
            
            // Process peer updates
            for peer_info in peers {
                if peer_info.peer_id != self.local_peer_id {
                    // Check if this is new information
                    if !view.known_peers.contains_key(&peer_info.peer_id) {
                        let _ = self.event_tx.send(GossipEvent::PeerDiscovered(peer_info.clone()));
                    }
                    
                    view.known_peers.insert(peer_info.peer_id, peer_info);
                }
            }
        }
        
        Ok(())
    }

    /// Handle heartbeat message
    async fn handle_heartbeat(
        &self,
        from: PeerId,
        capabilities: CertificateTypeCapabilities,
    ) -> Result<(), DhtError> {
        let _ = self.event_tx.send(GossipEvent::PeerUpdated(from, capabilities));
        Ok(())
    }

    /// Select random peers for gossip
    pub fn select_gossip_targets(&self) -> Vec<PeerId> {
        use rand::seq::SliceRandom;
        
        let views = self.peer_views.read().unwrap();
        let mut peers: Vec<_> = views.keys().copied().collect();
        
        let mut rng = rand::rng();
        peers.shuffle(&mut rng);
        
        peers.into_iter().take(self.config.fanout).collect()
    }

    /// Get merged view of all known peers
    pub fn get_network_view(&self) -> Vec<GossipPeerInfo> {
        let views = self.peer_views.read().unwrap();
        let mut merged: HashMap<PeerId, GossipPeerInfo> = HashMap::new();
        
        // Merge all views, keeping the most recent information
        for view in views.values() {
            for (peer_id, info) in &view.known_peers {
                match merged.get(peer_id) {
                    Some(existing) if existing.heartbeat >= info.heartbeat => continue,
                    _ => {
                        merged.insert(*peer_id, info.clone());
                    }
                }
            }
        }
        
        merged.into_values().collect()
    }

    /// Find peers supporting specific certificate types
    pub fn find_by_cert_type(&self, cert_type: CertificateType) -> Vec<GossipPeerInfo> {
        self.get_network_view()
            .into_iter()
            .filter(|peer| peer.cert_capabilities.supports_cert_type(cert_type))
            .collect()
    }
}

/// Messages for gossip protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipMessage {
    /// Share known peers
    PeerUpdate {
        peers: Vec<GossipPeerInfo>,
        version: u64,
    },
    /// Heartbeat to indicate liveness
    Heartbeat {
        capabilities: CertificateTypeCapabilities,
    },
    /// Request current view
    Request,
}

/// Helper trait for certificate type support checking
trait CertTypeSupportChecker {
    fn supports_cert_type(&self, cert_type: CertificateType) -> bool;
}

impl CertTypeSupportChecker for CertificateTypeCapabilities {
    fn supports_cert_type(&self, cert_type: CertificateType) -> bool {
        self.client_types.contains(&cert_type) || self.server_types.contains(&cert_type)
    }
}

/// Calculate XOR distance between two peer IDs
fn xor_distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = a[i] ^ b[i];
    }
    result
}

/// Count leading zeros in a byte array
fn leading_zeros(bytes: &[u8; 32]) -> u32 {
    let mut zeros = 0;
    for byte in bytes {
        if *byte == 0 {
            zeros += 8;
        } else {
            zeros += byte.leading_zeros();
            break;
        }
    }
    zeros
}

/// Errors for DHT operations
#[derive(Debug, thiserror::Error)]
pub enum DhtError {
    #[error("Invalid announcement")]
    InvalidAnnouncement,
    
    #[error("No addresses in announcement")]
    NoAddresses,
    
    #[error("Lookup timeout")]
    LookupTimeout,
    
    #[error("Network error: {0}")]
    NetworkError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_distance() {
        let a = PeerId([0xFF; 32]);
        let b = PeerId([0x00; 32]);
        let distance = xor_distance(&a.0, &b.0);
        assert_eq!(distance, [0xFF; 32]);
        
        let zeros = leading_zeros(&[0x00; 32]);
        assert_eq!(zeros, 256);
    }

    #[test]
    fn test_routing_table() {
        let local_id = PeerId([1; 32]);
        let mut table = DhtRoutingTable::new(local_id, 20);
        
        let peer1 = CertTypePeerInfo::new(
            PeerId([2; 32]),
            SocketAddr::from(([127, 0, 0, 1], 8080)),
            CertificateTypeCapabilities::from_preferences(
                &CertificateTypePreferences::prefer_raw_public_key(),
                EndpointRole::Client,
            ),
        );
        
        assert!(table.add_peer(peer1.clone()));
        
        let closest = table.find_closest(&PeerId([3; 32]), 10);
        assert_eq!(closest.len(), 1);
        assert_eq!(closest[0].peer_id, peer1.peer_id);
    }

    #[test]
    fn test_peer_announcement() {
        let peer_id = PeerId([1; 32]);
        let caps = CertificateTypeCapabilities::from_preferences(
            &CertificateTypePreferences::raw_public_key_only(),
            EndpointRole::Client,
        );
        
        let announcement = PeerAnnouncement::new(
            peer_id,
            vec![SocketAddr::from(([127, 0, 0, 1], 8080))],
            caps,
            vec!["storage".to_string()],
            3600,
        );
        
        assert!(announcement.is_valid());
        assert_eq!(announcement.ttl, 3600);
    }

    #[tokio::test]
    async fn test_dht_basic_operations() {
        let peer_id = PeerId([1; 32]);
        let caps = CertificateTypeCapabilities::from_preferences(
            &CertificateTypePreferences::prefer_raw_public_key(),
            EndpointRole::Client,
        );
        
        let (dht, mut events) = CertTypeDht::new(peer_id, caps.clone(), DhtConfig::default());
        
        // Store an announcement
        let announcement = PeerAnnouncement::new(
            PeerId([2; 32]),
            vec![SocketAddr::from(([127, 0, 0, 1], 8081))],
            caps,
            vec![],
            3600,
        );
        
        dht.store_announcement(announcement).unwrap();
        
        // Should receive discovery event
        if let Ok(event) = events.try_recv() {
            match event {
                DhtEvent::PeerDiscovered(info) => {
                    assert_eq!(info.peer_id, PeerId([2; 32]));
                }
                _ => panic!("Unexpected event"),
            }
        }
    }
}