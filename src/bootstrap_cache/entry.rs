//! Cached peer entry types.

use crate::nat_traversal_api::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

/// A cached peer entry with quality metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedPeer {
    /// Unique peer identifier (serialized as bytes)
    #[serde(with = "peer_id_serde")]
    pub peer_id: PeerId,

    /// Known socket addresses for this peer
    pub addresses: Vec<SocketAddr>,

    /// Peer capabilities and features
    pub capabilities: PeerCapabilities,

    /// When we first discovered this peer
    pub first_seen: SystemTime,

    /// When we last successfully communicated with this peer
    pub last_seen: SystemTime,

    /// When we last attempted to connect (success or failure)
    pub last_attempt: Option<SystemTime>,

    /// Connection statistics
    pub stats: ConnectionStats,

    /// Computed quality score (0.0 to 1.0)
    #[serde(default = "default_quality_score")]
    pub quality_score: f64,

    /// Source that added this peer
    pub source: PeerSource,
}

fn default_quality_score() -> f64 {
    0.5
}

/// Peer capabilities and features
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerCapabilities {
    /// Peer supports relay traffic
    pub supports_relay: bool,

    /// Peer supports NAT traversal coordination
    pub supports_coordination: bool,

    /// Protocol identifiers advertised by this peer (as hex strings for serialization)
    #[serde(default)]
    pub protocols: HashSet<String>,

    /// Observed NAT type hint
    pub nat_type: Option<NatType>,

    /// External addresses reported by peer
    #[serde(default)]
    pub external_addresses: Vec<SocketAddr>,
}

/// NAT type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NatType {
    /// No NAT (public IP)
    None,
    /// Full cone NAT (easiest to traverse)
    FullCone,
    /// Address-restricted cone NAT
    AddressRestrictedCone,
    /// Port-restricted cone NAT
    PortRestrictedCone,
    /// Symmetric NAT (hardest to traverse)
    Symmetric,
    /// Unknown NAT type
    Unknown,
}

/// Connection statistics for quality scoring
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectionStats {
    /// Total successful connections
    pub success_count: u32,

    /// Total failed connection attempts
    pub failure_count: u32,

    /// Exponential moving average RTT in milliseconds
    pub avg_rtt_ms: u32,

    /// Minimum observed RTT
    pub min_rtt_ms: u32,

    /// Maximum observed RTT
    pub max_rtt_ms: u32,

    /// Total bytes relayed through this peer (if relay)
    pub bytes_relayed: u64,

    /// Number of NAT traversals coordinated (if coordinator)
    pub coordinations_completed: u32,
}

/// How we discovered this peer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerSource {
    /// User-provided bootstrap seed
    Seed,
    /// Discovered via active connection
    Connection,
    /// Discovered via relay traffic
    Relay,
    /// Discovered via NAT coordination
    Coordination,
    /// Merged from another cache instance
    Merge,
    /// Unknown source (legacy entries)
    Unknown,
}

impl Default for PeerSource {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Result of a connection attempt
#[derive(Debug, Clone)]
pub struct ConnectionOutcome {
    /// Whether the connection succeeded
    pub success: bool,
    /// RTT in milliseconds if available
    pub rtt_ms: Option<u32>,
    /// Capabilities discovered during connection
    pub capabilities_discovered: Option<PeerCapabilities>,
}

impl CachedPeer {
    /// Create a new peer entry
    pub fn new(peer_id: PeerId, addresses: Vec<SocketAddr>, source: PeerSource) -> Self {
        let now = SystemTime::now();
        Self {
            peer_id,
            addresses,
            capabilities: PeerCapabilities::default(),
            first_seen: now,
            last_seen: now,
            last_attempt: None,
            stats: ConnectionStats::default(),
            quality_score: 0.5, // Neutral starting score
            source,
        }
    }

    /// Record a successful connection
    pub fn record_success(&mut self, rtt_ms: u32, caps: Option<PeerCapabilities>) {
        self.last_seen = SystemTime::now();
        self.last_attempt = Some(SystemTime::now());
        self.stats.success_count = self.stats.success_count.saturating_add(1);

        // Update RTT with exponential moving average (alpha = 0.125)
        if self.stats.avg_rtt_ms == 0 {
            self.stats.avg_rtt_ms = rtt_ms;
            self.stats.min_rtt_ms = rtt_ms;
            self.stats.max_rtt_ms = rtt_ms;
        } else {
            self.stats.avg_rtt_ms = (self.stats.avg_rtt_ms * 7 + rtt_ms) / 8;
            self.stats.min_rtt_ms = self.stats.min_rtt_ms.min(rtt_ms);
            self.stats.max_rtt_ms = self.stats.max_rtt_ms.max(rtt_ms);
        }

        if let Some(caps) = caps {
            self.capabilities = caps;
        }
    }

    /// Record a failed connection attempt
    pub fn record_failure(&mut self) {
        self.last_attempt = Some(SystemTime::now());
        self.stats.failure_count = self.stats.failure_count.saturating_add(1);
    }

    /// Calculate quality score based on metrics
    pub fn calculate_quality(&mut self, weights: &super::config::QualityWeights) {
        let total_attempts = self.stats.success_count + self.stats.failure_count;

        // Success rate component (0.0 to 1.0)
        let success_rate = if total_attempts > 0 {
            self.stats.success_count as f64 / total_attempts as f64
        } else {
            0.5 // Neutral for untested peers
        };

        // RTT component (lower is better, normalized to 0.0-1.0)
        // 50ms = 1.0, 500ms = 0.5, 1000ms+ = 0.0
        let rtt_score = if self.stats.avg_rtt_ms > 0 {
            1.0 - (self.stats.avg_rtt_ms as f64 / 1000.0).min(1.0)
        } else {
            0.5 // Neutral for unknown RTT
        };

        // Freshness component (exponential decay with 24-hour half-life)
        let age_secs = self
            .last_seen
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .and_then(|last_seen_epoch| {
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .ok()
                    .map(|now_epoch| now_epoch.as_secs().saturating_sub(last_seen_epoch.as_secs()))
            })
            .unwrap_or(0) as f64;

        // Half-life of 24 hours = decay constant ln(2)/86400
        let freshness = (-age_secs * 0.693 / 86400.0).exp();

        // Capability bonuses
        let mut cap_bonus: f64 = 0.0;
        if self.capabilities.supports_relay {
            cap_bonus += 0.3;
        }
        if self.capabilities.supports_coordination {
            cap_bonus += 0.3;
        }
        if matches!(
            self.capabilities.nat_type,
            Some(NatType::None) | Some(NatType::FullCone)
        ) {
            cap_bonus += 0.4; // Easy to connect
        }
        let cap_score = cap_bonus.min(1.0);

        // Weighted combination
        self.quality_score = (success_rate * weights.success_rate
            + rtt_score * weights.rtt
            + freshness * weights.freshness
            + cap_score * weights.capabilities)
            .clamp(0.0, 1.0);
    }

    /// Check if this peer is stale
    pub fn is_stale(&self, threshold: Duration) -> bool {
        self.last_seen
            .elapsed()
            .map(|age| age > threshold)
            .unwrap_or(true)
    }

    /// Get success rate
    pub fn success_rate(&self) -> f64 {
        let total = self.stats.success_count + self.stats.failure_count;
        if total == 0 {
            0.5
        } else {
            self.stats.success_count as f64 / total as f64
        }
    }

    /// Merge addresses from another peer entry
    pub fn merge_addresses(&mut self, other: &CachedPeer) {
        for addr in &other.addresses {
            if !self.addresses.contains(addr) {
                self.addresses.push(*addr);
            }
        }
        // Keep reasonable limit
        if self.addresses.len() > 10 {
            self.addresses.truncate(10);
        }
    }
}

/// Serde helper for PeerId serialization
mod peer_id_serde {
    use super::PeerId;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(peer_id: &PeerId, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        hex::encode(peer_id.0).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PeerId, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("PeerId must be 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(PeerId(arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cached_peer_new() {
        let peer_id = PeerId([1u8; 32]);
        let peer = CachedPeer::new(
            peer_id,
            vec!["127.0.0.1:9000".parse().unwrap()],
            PeerSource::Seed,
        );

        assert_eq!(peer.peer_id, peer_id);
        assert_eq!(peer.addresses.len(), 1);
        assert_eq!(peer.source, PeerSource::Seed);
        assert!((peer.quality_score - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_record_success() {
        let mut peer = CachedPeer::new(
            PeerId([1u8; 32]),
            vec!["127.0.0.1:9000".parse().unwrap()],
            PeerSource::Seed,
        );

        peer.record_success(100, None);
        assert_eq!(peer.stats.success_count, 1);
        assert_eq!(peer.stats.avg_rtt_ms, 100);
        assert_eq!(peer.stats.min_rtt_ms, 100);
        assert_eq!(peer.stats.max_rtt_ms, 100);

        peer.record_success(200, None);
        assert_eq!(peer.stats.success_count, 2);
        // EMA: (100*7 + 200) / 8 = 112
        assert_eq!(peer.stats.avg_rtt_ms, 112);
        assert_eq!(peer.stats.min_rtt_ms, 100);
        assert_eq!(peer.stats.max_rtt_ms, 200);
    }

    #[test]
    fn test_record_failure() {
        let mut peer = CachedPeer::new(
            PeerId([1u8; 32]),
            vec!["127.0.0.1:9000".parse().unwrap()],
            PeerSource::Seed,
        );

        peer.record_failure();
        assert_eq!(peer.stats.failure_count, 1);
        assert!(peer.last_attempt.is_some());
    }

    #[test]
    fn test_success_rate() {
        let mut peer = CachedPeer::new(
            PeerId([1u8; 32]),
            vec!["127.0.0.1:9000".parse().unwrap()],
            PeerSource::Seed,
        );

        // No attempts = 0.5
        assert!((peer.success_rate() - 0.5).abs() < f64::EPSILON);

        peer.record_success(100, None);
        assert!((peer.success_rate() - 1.0).abs() < f64::EPSILON);

        peer.record_failure();
        assert!((peer.success_rate() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_quality_calculation() {
        let weights = super::super::config::QualityWeights::default();
        let mut peer = CachedPeer::new(
            PeerId([1u8; 32]),
            vec!["127.0.0.1:9000".parse().unwrap()],
            PeerSource::Seed,
        );

        // Initial quality should be moderate (untested peer)
        peer.calculate_quality(&weights);
        assert!(peer.quality_score > 0.3 && peer.quality_score < 0.7);

        // Good performance should increase quality
        for _ in 0..5 {
            peer.record_success(50, None); // Low RTT
        }
        peer.calculate_quality(&weights);
        assert!(peer.quality_score > 0.6);
    }

    #[test]
    fn test_peer_serialization() {
        let peer = CachedPeer::new(
            PeerId([0xab; 32]),
            vec!["127.0.0.1:9000".parse().unwrap()],
            PeerSource::Seed,
        );

        let json = serde_json::to_string(&peer).unwrap();
        let deserialized: CachedPeer = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.peer_id, peer.peer_id);
        assert_eq!(deserialized.addresses, peer.addresses);
        assert_eq!(deserialized.source, peer.source);
    }
}
