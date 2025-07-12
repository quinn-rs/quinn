//! Advanced 0-RTT Optimization for Raw Public Keys
//!
//! This module implements secure session resumption and 0-RTT support specifically
//! optimized for Raw Public Key authentication, avoiding the overhead of certificate
//! chain validation during resumption.

use std::{
    sync::{Arc, RwLock},
    collections::{HashMap, VecDeque},
    time::{Duration, Instant, SystemTime},
};

use rustls::{
    Error as TlsError,
};

use ed25519_dalek::{VerifyingKey as Ed25519PublicKey};
use serde::{Serialize, Deserialize};
use tracing::{debug, info, warn, instrument};

use crate::nat_traversal_api::PeerId;
use super::{
    tls_extensions::NegotiationResult,
};

/// 0-RTT session ticket for Raw Public Keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpkSessionTicket {
    /// Session ID for tracking
    pub session_id: Vec<u8>,
    /// Peer's Raw Public Key identity
    pub peer_public_key: Vec<u8>,
    /// Negotiated certificate types
    pub cert_types: NegotiationResult,
    /// Application-layer protocol negotiated
    pub alpn: Option<Vec<u8>>,
    /// Timestamp when ticket was issued
    pub issued_at: u64,
    /// Maximum age in seconds
    pub lifetime: u32,
    /// Age add value for anti-replay
    pub age_add: u32,
    /// Resumption secret
    pub resumption_secret: Vec<u8>,
    /// Server name indication
    pub sni: Option<String>,
}

impl RpkSessionTicket {
    /// Create a new session ticket
    pub fn new(
        peer_public_key: &Ed25519PublicKey,
        cert_types: NegotiationResult,
        alpn: Option<Vec<u8>>,
        lifetime: u32,
        resumption_secret: Vec<u8>,
        sni: Option<String>,
    ) -> Self {
        use rand::Rng;
        
        let mut rng = rand::rng();
        let mut session_id = vec![0u8; 32];
        rng.fill(&mut session_id[..]);
        
        Self {
            session_id,
            peer_public_key: peer_public_key.as_bytes().to_vec(),
            cert_types,
            alpn,
            issued_at: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            lifetime,
            age_add: rng.random(),
            resumption_secret,
            sni,
        }
    }

    /// Check if ticket is still valid
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        now < self.issued_at.saturating_add(self.lifetime as u64)
    }

    /// Get ticket age in milliseconds
    pub fn age_millis(&self) -> u32 {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        
        let issued_millis = self.issued_at * 1000;
        ((now - issued_millis) as u32).wrapping_add(self.age_add)
    }

    /// Verify the ticket matches expected parameters
    pub fn verify_match(
        &self,
        peer_key: &Ed25519PublicKey,
        sni: Option<&str>,
    ) -> bool {
        self.peer_public_key == peer_key.as_bytes() &&
        self.sni.as_deref() == sni &&
        self.is_valid()
    }
}

/// Cache for 0-RTT session tickets
pub struct RpkSessionCache {
    /// Maximum number of tickets to cache
    max_tickets: usize,
    /// Tickets indexed by peer ID
    tickets_by_peer: RwLock<HashMap<PeerId, VecDeque<RpkSessionTicket>>>,
    /// Tickets indexed by SNI
    tickets_by_sni: RwLock<HashMap<String, VecDeque<RpkSessionTicket>>>,
    /// Global ticket order for LRU eviction
    ticket_order: RwLock<VecDeque<(PeerId, SystemTime)>>,
}

impl RpkSessionCache {
    /// Create a new session cache
    pub fn new(max_tickets: usize) -> Self {
        Self {
            max_tickets,
            tickets_by_peer: RwLock::new(HashMap::new()),
            tickets_by_sni: RwLock::new(HashMap::new()),
            ticket_order: RwLock::new(VecDeque::new()),
        }
    }

    /// Store a session ticket
    #[instrument(skip(self, ticket))]
    pub fn store_ticket(&self, peer_id: PeerId, ticket: RpkSessionTicket) {
        let mut tickets_by_peer = self.tickets_by_peer.write().unwrap();
        let mut tickets_by_sni = self.tickets_by_sni.write().unwrap();
        let mut ticket_order = self.ticket_order.write().unwrap();

        // Enforce cache size limit
        while ticket_order.len() >= self.max_tickets {
            if let Some((old_peer_id, _)) = ticket_order.pop_front() {
                // Remove oldest ticket
                if let Some(peer_tickets) = tickets_by_peer.get_mut(&old_peer_id) {
                    if let Some(old_ticket) = peer_tickets.pop_front() {
                        // Also remove from SNI index
                        if let Some(sni) = &old_ticket.sni {
                            if let Some(sni_tickets) = tickets_by_sni.get_mut(sni) {
                                sni_tickets.retain(|t| t.session_id != old_ticket.session_id);
                            }
                        }
                    }
                }
            }
        }

        // Store by peer ID
        tickets_by_peer
            .entry(peer_id)
            .or_insert_with(VecDeque::new)
            .push_back(ticket.clone());

        // Store by SNI if present
        if let Some(sni) = &ticket.sni {
            tickets_by_sni
                .entry(sni.clone())
                .or_insert_with(VecDeque::new)
                .push_back(ticket);
        }

        // Track in global order
        ticket_order.push_back((peer_id, SystemTime::now()));

        debug!("Stored 0-RTT ticket for peer {:?}", peer_id);
    }

    /// Retrieve tickets for a peer
    pub fn get_tickets(&self, peer_id: &PeerId) -> Vec<RpkSessionTicket> {
        let tickets = self.tickets_by_peer.read().unwrap();
        tickets
            .get(peer_id)
            .map(|deque| deque.iter().filter(|t| t.is_valid()).cloned().collect())
            .unwrap_or_default()
    }

    /// Retrieve tickets by SNI
    pub fn get_tickets_by_sni(&self, sni: &str) -> Vec<RpkSessionTicket> {
        let tickets = self.tickets_by_sni.read().unwrap();
        tickets
            .get(sni)
            .map(|deque| deque.iter().filter(|t| t.is_valid()).cloned().collect())
            .unwrap_or_default()
    }

    /// Find a suitable ticket for resumption
    pub fn find_resumption_ticket(
        &self,
        peer_id: &PeerId,
        sni: Option<&str>,
    ) -> Option<RpkSessionTicket> {
        let tickets = self.get_tickets(peer_id);
        
        tickets.into_iter()
            .find(|ticket| {
                ticket.is_valid() && 
                (sni.is_none() || ticket.sni.as_deref() == sni)
            })
    }

    /// Clean up expired tickets
    pub fn cleanup_expired(&self) {
        let mut tickets_by_peer = self.tickets_by_peer.write().unwrap();
        let mut tickets_by_sni = self.tickets_by_sni.write().unwrap();

        // Clean peer tickets
        tickets_by_peer.retain(|_, tickets| {
            tickets.retain(|t| t.is_valid());
            !tickets.is_empty()
        });

        // Clean SNI tickets
        tickets_by_sni.retain(|_, tickets| {
            tickets.retain(|t| t.is_valid());
            !tickets.is_empty()
        });

        debug!("Cleaned up expired 0-RTT tickets");
    }

    /// Get cache statistics
    pub fn stats(&self) -> SessionCacheStats {
        let tickets_by_peer = self.tickets_by_peer.read().unwrap();
        let total_tickets: usize = tickets_by_peer.values().map(|v| v.len()).sum();
        let unique_peers = tickets_by_peer.len();

        SessionCacheStats {
            total_tickets,
            unique_peers,
            max_tickets: self.max_tickets,
        }
    }
}

/// Statistics for session cache
#[derive(Debug, Clone)]
pub struct SessionCacheStats {
    pub total_tickets: usize,
    pub unique_peers: usize,
    pub max_tickets: usize,
}

/// 0-RTT data protection for early data
pub struct ZeroRttProtection {
    /// Key derivation function
    kdf: ring::hkdf::Prk,
    /// Anti-replay cache
    anti_replay: Arc<RwLock<AntiReplayCache>>,
}

impl ZeroRttProtection {
    /// Create new 0-RTT protection
    pub fn new(resumption_secret: &[u8]) -> Result<Self, TlsError> {
        let kdf = ring::hkdf::Prk::new_less_safe(
            ring::hkdf::HKDF_SHA256,
            resumption_secret,
        );

        Ok(Self {
            kdf,
            anti_replay: Arc::new(RwLock::new(AntiReplayCache::new(10000))),
        })
    }

    /// Derive early data keys
    pub fn derive_early_data_keys(&self) -> Result<EarlyDataKeys, TlsError> {
        let mut client_key = vec![0u8; 32];
        let mut server_key = vec![0u8; 32];

        self.kdf
            .expand(&[b"early_client"], ring::hkdf::HKDF_SHA256)
            .map_err(|_| TlsError::General("Failed to derive client early data key".into()))?
            .fill(&mut client_key)
            .map_err(|_| TlsError::General("Failed to fill client key".into()))?;

        self.kdf
            .expand(&[b"early_server"], ring::hkdf::HKDF_SHA256)
            .map_err(|_| TlsError::General("Failed to derive server early data key".into()))?
            .fill(&mut server_key)
            .map_err(|_| TlsError::General("Failed to fill server key".into()))?;

        Ok(EarlyDataKeys {
            client_key,
            server_key,
        })
    }

    /// Check anti-replay for early data
    pub fn check_anti_replay(&self, ticket_age: u32, nonce: &[u8]) -> bool {
        let mut cache = self.anti_replay.write().unwrap();
        cache.check_and_insert(ticket_age, nonce)
    }
}

/// Keys for protecting early data
#[derive(Debug)]
pub struct EarlyDataKeys {
    pub client_key: Vec<u8>,
    pub server_key: Vec<u8>,
}

/// Anti-replay cache for 0-RTT
struct AntiReplayCache {
    max_entries: usize,
    entries: HashMap<Vec<u8>, Instant>,
    window: Duration,
}

impl AntiReplayCache {
    fn new(max_entries: usize) -> Self {
        Self {
            max_entries,
            entries: HashMap::new(),
            window: Duration::from_secs(5), // 5 second window
        }
    }

    fn check_and_insert(&mut self, ticket_age: u32, nonce: &[u8]) -> bool {
        let now = Instant::now();
        
        // Clean old entries
        self.entries.retain(|_, time| now.duration_since(*time) < self.window);

        // Check if nonce was already seen
        let key = [&ticket_age.to_be_bytes()[..], nonce].concat();
        if self.entries.contains_key(&key) {
            return false; // Replay detected
        }

        // Enforce size limit
        if self.entries.len() >= self.max_entries {
            // Remove oldest entry
            if let Some((oldest_key, _)) = self.entries.iter()
                .min_by_key(|(_, time)| *time)
                .map(|(k, v)| (k.clone(), *v))
            {
                self.entries.remove(&oldest_key);
            }
        }

        // Insert new entry
        self.entries.insert(key, now);
        true
    }
}

/// Configuration for 0-RTT with Raw Public Keys
#[derive(Debug, Clone)]
pub struct ZeroRttRpkConfig {
    /// Enable 0-RTT for client
    pub enable_client: bool,
    /// Enable 0-RTT for server
    pub enable_server: bool,
    /// Maximum early data size
    pub max_early_data_size: u32,
    /// Session ticket lifetime in seconds
    pub ticket_lifetime: u32,
    /// Maximum number of tickets to issue
    pub max_tickets: usize,
    /// Enable anti-replay protection
    pub enable_anti_replay: bool,
}

impl Default for ZeroRttRpkConfig {
    fn default() -> Self {
        Self {
            enable_client: true,
            enable_server: true,
            max_early_data_size: 16384, // 16KB
            ticket_lifetime: 7200, // 2 hours
            max_tickets: 5,
            enable_anti_replay: true,
        }
    }
}

/// Manager for 0-RTT sessions with Raw Public Keys
pub struct ZeroRttRpkManager {
    /// Configuration
    config: ZeroRttRpkConfig,
    /// Session cache
    cache: Arc<RpkSessionCache>,
    /// Active 0-RTT protections by session ID
    protections: Arc<RwLock<HashMap<Vec<u8>, Arc<ZeroRttProtection>>>>,
}

impl ZeroRttRpkManager {
    /// Create a new 0-RTT manager
    pub fn new(config: ZeroRttRpkConfig) -> Self {
        Self {
            cache: Arc::new(RpkSessionCache::new(config.max_tickets * 100)),
            protections: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Create a session ticket for resumption
    #[instrument(skip(self, peer_key, resumption_secret))]
    pub fn create_session_ticket(
        &self,
        peer_id: PeerId,
        peer_key: &Ed25519PublicKey,
        cert_types: NegotiationResult,
        alpn: Option<Vec<u8>>,
        resumption_secret: Vec<u8>,
        sni: Option<String>,
    ) -> Result<RpkSessionTicket, TlsError> {
        let ticket = RpkSessionTicket::new(
            peer_key,
            cert_types,
            alpn,
            self.config.ticket_lifetime,
            resumption_secret.clone(),
            sni,
        );

        // Create protection for this session
        let protection = Arc::new(ZeroRttProtection::new(&resumption_secret)?);
        self.protections.write().unwrap()
            .insert(ticket.session_id.clone(), protection);

        // Store in cache
        self.cache.store_ticket(peer_id, ticket.clone());

        info!("Created 0-RTT session ticket for peer {:?}", peer_id);
        Ok(ticket)
    }

    /// Find a ticket for resumption
    pub fn find_resumption_ticket(
        &self,
        peer_id: &PeerId,
        sni: Option<&str>,
    ) -> Option<(RpkSessionTicket, Arc<ZeroRttProtection>)> {
        let ticket = self.cache.find_resumption_ticket(peer_id, sni)?;
        
        let protections = self.protections.read().unwrap();
        let protection = protections.get(&ticket.session_id)?.clone();

        Some((ticket, protection))
    }

    /// Validate early data
    pub fn validate_early_data(
        &self,
        ticket: &RpkSessionTicket,
        ticket_age: u32,
        nonce: &[u8],
    ) -> Result<bool, TlsError> {
        if !self.config.enable_anti_replay {
            return Ok(true);
        }

        let protections = self.protections.read().unwrap();
        let protection = protections.get(&ticket.session_id)
            .ok_or_else(|| TlsError::General("No protection found for session".into()))?;

        Ok(protection.check_anti_replay(ticket_age, nonce))
    }

    /// Clean up expired sessions
    pub fn cleanup(&self) {
        self.cache.cleanup_expired();
        
        // Clean up protections for expired sessions
        let mut protections = self.protections.write().unwrap();
        let tickets_by_peer = self.cache.tickets_by_peer.read().unwrap();
        
        let valid_session_ids: std::collections::HashSet<_> = tickets_by_peer
            .values()
            .flat_map(|tickets| tickets.iter().map(|t| t.session_id.clone()))
            .collect();

        protections.retain(|session_id, _| valid_session_ids.contains(session_id));
    }

    /// Get manager statistics
    pub fn stats(&self) -> ZeroRttStats {
        let cache_stats = self.cache.stats();
        let num_protections = self.protections.read().unwrap().len();

        ZeroRttStats {
            cache_stats,
            active_protections: num_protections,
            config: self.config.clone(),
        }
    }
}

/// Statistics for 0-RTT manager
#[derive(Debug, Clone)]
pub struct ZeroRttStats {
    pub cache_stats: SessionCacheStats,
    pub active_protections: usize,
    pub config: ZeroRttRpkConfig,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::tls_extensions::CertificateType;
    use crate::crypto::raw_public_keys::utils;

    #[test]
    fn test_session_ticket_creation() {
        let (private_key, public_key) = utils::generate_ed25519_keypair();
        let cert_types = NegotiationResult::new(
            CertificateType::RawPublicKey,
            CertificateType::RawPublicKey,
        );
        
        let ticket = RpkSessionTicket::new(
            &public_key,
            cert_types,
            Some(b"h3".to_vec()),
            3600,
            vec![0u8; 32],
            Some("example.com".to_string()),
        );

        assert_eq!(ticket.peer_public_key, public_key.as_bytes());
        assert!(ticket.is_valid());
        assert_eq!(ticket.lifetime, 3600);
    }

    #[test]
    fn test_session_cache() {
        let cache = RpkSessionCache::new(100);
        let peer_id = PeerId([1; 32]);
        
        let (_, public_key) = utils::generate_ed25519_keypair();
        let cert_types = NegotiationResult::new(
            CertificateType::RawPublicKey,
            CertificateType::RawPublicKey,
        );
        
        let ticket = RpkSessionTicket::new(
            &public_key,
            cert_types,
            None,
            3600,
            vec![0u8; 32],
            Some("example.com".to_string()),
        );

        cache.store_ticket(peer_id, ticket.clone());
        
        let retrieved = cache.get_tickets(&peer_id);
        assert_eq!(retrieved.len(), 1);
        assert_eq!(retrieved[0].session_id, ticket.session_id);

        let by_sni = cache.get_tickets_by_sni("example.com");
        assert_eq!(by_sni.len(), 1);
    }

    #[test]
    fn test_anti_replay_cache() {
        let mut cache = AntiReplayCache::new(10);
        let nonce = b"test_nonce";
        
        // First check should succeed
        assert!(cache.check_and_insert(12345, nonce));
        
        // Replay should be detected
        assert!(!cache.check_and_insert(12345, nonce));
        
        // Different nonce should succeed
        assert!(cache.check_and_insert(12345, b"different_nonce"));
    }

    #[test]
    fn test_zero_rtt_manager() {
        let config = ZeroRttRpkConfig::default();
        let manager = ZeroRttRpkManager::new(config);
        
        let peer_id = PeerId([1; 32]);
        let (_, public_key) = utils::generate_ed25519_keypair();
        let cert_types = NegotiationResult::new(
            CertificateType::RawPublicKey,
            CertificateType::RawPublicKey,
        );
        
        let ticket = manager.create_session_ticket(
            peer_id,
            &public_key,
            cert_types,
            None,
            vec![0u8; 32],
            Some("example.com".to_string()),
        ).unwrap();

        // Should be able to find the ticket
        let found = manager.find_resumption_ticket(&peer_id, Some("example.com"));
        assert!(found.is_some());
        
        let (found_ticket, _protection) = found.unwrap();
        assert_eq!(found_ticket.session_id, ticket.session_id);
    }
}