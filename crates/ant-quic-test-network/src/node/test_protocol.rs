//! Test packet protocol for measuring connectivity.
//!
//! Implements a simple 5KB test packet exchange protocol to verify
//! connectivity and measure round-trip times.
//!
//! Also includes relay discovery protocol for NAT traversal:
//! - CAN_YOU_REACH: Ask a peer if they can connect to a target
//! - REACH_RESPONSE: Reply with reachability status
//! - RELAY_PUNCH_ME_NOW: Forward PUNCH_ME_NOW via relay
//! - RELAY_ACK: Acknowledge relay request

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Size of test packet payload (approximately 5KB total with headers).
pub const TEST_PAYLOAD_SIZE: usize = 5000;

/// Magic bytes to identify test packets.
pub const TEST_PACKET_MAGIC: [u8; 4] = *b"TEST";

/// Test packet type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PacketType {
    /// Ping request - sender expects a pong response.
    Ping = 0,
    /// Pong response - acknowledges a ping.
    Pong = 1,
}

/// A 5KB test packet for connectivity verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestPacket {
    /// Magic bytes to identify test packets.
    pub magic: [u8; 4],
    /// Packet type (ping/pong).
    pub packet_type: PacketType,
    /// Sequence number for ordering.
    pub sequence: u64,
    /// Timestamp in nanoseconds since epoch.
    pub timestamp_ns: u64,
    /// Sender's peer ID (32 bytes).
    pub sender_id: [u8; 32],
    /// Random payload to reach ~5KB.
    pub payload: Vec<u8>,
    /// SHA-256 checksum of the packet contents.
    pub checksum: [u8; 32],
}

impl TestPacket {
    /// Create a new ping packet.
    pub fn new_ping(sender_id: [u8; 32], sequence: u64) -> Self {
        let mut packet = Self {
            magic: TEST_PACKET_MAGIC,
            packet_type: PacketType::Ping,
            sequence,
            timestamp_ns: current_timestamp_ns(),
            sender_id,
            payload: generate_random_payload(),
            checksum: [0u8; 32],
        };
        packet.checksum = packet.calculate_checksum();
        packet
    }

    /// Create a pong response from a ping.
    pub fn create_pong(&self, sender_id: [u8; 32]) -> Self {
        let mut packet = Self {
            magic: TEST_PACKET_MAGIC,
            packet_type: PacketType::Pong,
            sequence: self.sequence,
            timestamp_ns: current_timestamp_ns(),
            sender_id,
            payload: generate_random_payload(),
            checksum: [0u8; 32],
        };
        packet.checksum = packet.calculate_checksum();
        packet
    }

    /// Calculate the checksum for this packet.
    fn calculate_checksum(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.magic);
        hasher.update([self.packet_type as u8]);
        hasher.update(self.sequence.to_le_bytes());
        hasher.update(self.timestamp_ns.to_le_bytes());
        hasher.update(self.sender_id);
        hasher.update(&self.payload);
        hasher.finalize().into()
    }

    /// Verify the packet checksum.
    pub fn verify_checksum(&self) -> bool {
        self.checksum == self.calculate_checksum()
    }

    /// Get the packet size in bytes.
    pub fn size(&self) -> usize {
        // Approximate: 4 (magic) + 1 (type) + 8 (seq) + 8 (ts) + 32 (id) + payload + 32 (checksum)
        4 + 1 + 8 + 8 + 32 + self.payload.len() + 32
    }

    /// Serialize to bytes for transmission.
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }
}

/// Result of a test packet exchange.
#[derive(Debug, Clone)]
pub struct TestResult {
    /// Sequence number of the test.
    pub sequence: u64,
    /// Round-trip time.
    pub rtt: Duration,
    /// Whether the test was successful.
    pub success: bool,
    /// Error message if failed.
    pub error: Option<String>,
    /// Timestamp when the test was performed.
    pub timestamp: Instant,
}

impl TestResult {
    /// Create a successful test result.
    pub fn success(sequence: u64, rtt: Duration) -> Self {
        Self {
            sequence,
            rtt,
            success: true,
            error: None,
            timestamp: Instant::now(),
        }
    }

    /// Create a failed test result.
    pub fn failure(sequence: u64, error: String) -> Self {
        Self {
            sequence,
            rtt: Duration::ZERO,
            success: false,
            error: Some(error),
            timestamp: Instant::now(),
        }
    }
}

/// Generate random payload data.
fn generate_random_payload() -> Vec<u8> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..TEST_PAYLOAD_SIZE).map(|_| rng.r#gen()).collect()
}

/// Get current timestamp in nanoseconds.
fn current_timestamp_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

// ============================================================================
// Relay Discovery Protocol
// ============================================================================
//
// This protocol enables NAT traversal when direct connection and hole-punching
// fail. It works by discovering a relay peer that can reach the target, then
// using that relay to forward PUNCH_ME_NOW frames for coordinated hole-punching.
//
// Flow:
// 1. A wants to connect to B but cannot (NAT blocks)
// 2. A asks connected peers: "Can you reach B?"
// 3. First peer (R) that says "yes" becomes the relay
// 4. A sends RELAY_PUNCH_ME_NOW to R, R forwards to B
// 5. A and B attempt simultaneous hole-punch
// 6. If successful, migrate off relay; if not, keep relay for traffic

/// Magic bytes to identify relay protocol messages.
pub const RELAY_MAGIC: [u8; 4] = *b"RLAY";

/// Relay protocol message types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RelayMessage {
    /// Request: Ask if peer can reach a target.
    CanYouReach(CanYouReachRequest),

    /// Response: Reply with reachability status.
    ReachResponse(ReachResponse),

    /// Request: Forward PUNCH_ME_NOW to target via relay.
    RelayPunchMeNow(RelayPunchMeNowRequest),

    /// Response: Acknowledge relay request.
    RelayAck(RelayAckResponse),

    /// Request: Forward data to target via relay (when hole-punch fails).
    RelayData(RelayDataRequest),

    /// Response: Data forwarded from relay.
    RelayedData(RelayedDataResponse),
}

/// Request to check if peer can reach a target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanYouReachRequest {
    /// Magic bytes for protocol identification.
    pub magic: [u8; 4],
    /// Request ID for correlation.
    pub request_id: u64,
    /// Target peer ID we want to reach.
    pub target_peer_id: [u8; 32],
    /// Our peer ID (requester).
    pub requester_peer_id: [u8; 32],
}

impl CanYouReachRequest {
    /// Create a new CAN_YOU_REACH request.
    pub fn new(target_peer_id: [u8; 32], requester_peer_id: [u8; 32]) -> Self {
        Self {
            magic: RELAY_MAGIC,
            request_id: current_timestamp_ns(),
            target_peer_id,
            requester_peer_id,
        }
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&RelayMessage::CanYouReach(self.clone()))
    }
}

/// Response to CAN_YOU_REACH request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachResponse {
    /// Magic bytes for protocol identification.
    pub magic: [u8; 4],
    /// Request ID this responds to.
    pub request_id: u64,
    /// Target peer ID that was queried.
    pub target_peer_id: [u8; 32],
    /// Whether we can reach the target.
    pub reachable: bool,
    /// If reachable, the addresses we have for the target.
    pub target_addresses: Vec<SocketAddr>,
    /// Whether we're currently connected to the target.
    pub currently_connected: bool,
    /// Whether we appear to be a public node (external == local address).
    pub is_public_node: bool,
}

impl ReachResponse {
    /// Create a positive response (we can reach the target).
    pub fn reachable(
        request_id: u64,
        target_peer_id: [u8; 32],
        target_addresses: Vec<SocketAddr>,
        currently_connected: bool,
        is_public_node: bool,
    ) -> Self {
        Self {
            magic: RELAY_MAGIC,
            request_id,
            target_peer_id,
            reachable: true,
            target_addresses,
            currently_connected,
            is_public_node,
        }
    }

    /// Create a negative response (we cannot reach the target).
    pub fn unreachable(request_id: u64, target_peer_id: [u8; 32], is_public_node: bool) -> Self {
        Self {
            magic: RELAY_MAGIC,
            request_id,
            target_peer_id,
            reachable: false,
            target_addresses: Vec::new(),
            currently_connected: false,
            is_public_node,
        }
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&RelayMessage::ReachResponse(self.clone()))
    }
}

/// Request to relay a PUNCH_ME_NOW frame to target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayPunchMeNowRequest {
    /// Magic bytes for protocol identification.
    pub magic: [u8; 4],
    /// Request ID for correlation.
    pub request_id: u64,
    /// Target peer ID to relay to.
    pub target_peer_id: [u8; 32],
    /// Requester's peer ID.
    pub requester_peer_id: [u8; 32],
    /// Requester's address candidates for hole-punching.
    pub requester_addresses: Vec<SocketAddr>,
    /// Round number for NAT traversal coordination.
    pub round: u64,
    /// Sequence number of the address to pair with.
    pub paired_with_sequence: u64,
}

impl RelayPunchMeNowRequest {
    /// Create a new RELAY_PUNCH_ME_NOW request.
    pub fn new(
        target_peer_id: [u8; 32],
        requester_peer_id: [u8; 32],
        requester_addresses: Vec<SocketAddr>,
        round: u64,
        paired_with_sequence: u64,
    ) -> Self {
        Self {
            magic: RELAY_MAGIC,
            request_id: current_timestamp_ns(),
            target_peer_id,
            requester_peer_id,
            requester_addresses,
            round,
            paired_with_sequence,
        }
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&RelayMessage::RelayPunchMeNow(self.clone()))
    }
}

/// Acknowledge relay request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayAckResponse {
    /// Magic bytes for protocol identification.
    pub magic: [u8; 4],
    /// Request ID this acknowledges.
    pub request_id: u64,
    /// Whether the relay was successful.
    pub success: bool,
    /// Error message if relay failed.
    pub error: Option<String>,
}

impl RelayAckResponse {
    /// Create a success acknowledgment.
    pub fn success(request_id: u64) -> Self {
        Self {
            magic: RELAY_MAGIC,
            request_id,
            success: true,
            error: None,
        }
    }

    /// Create a failure acknowledgment.
    pub fn failure(request_id: u64, error: String) -> Self {
        Self {
            magic: RELAY_MAGIC,
            request_id,
            success: false,
            error: Some(error),
        }
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&RelayMessage::RelayAck(self.clone()))
    }
}

/// Request to relay data to target (when hole-punch fails, keep relay for traffic).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayDataRequest {
    /// Magic bytes for protocol identification.
    pub magic: [u8; 4],
    /// Target peer ID to relay to.
    pub target_peer_id: [u8; 32],
    /// Source peer ID.
    pub source_peer_id: [u8; 32],
    /// Data payload to relay.
    pub data: Vec<u8>,
}

impl RelayDataRequest {
    /// Create a new relay data request.
    pub fn new(target_peer_id: [u8; 32], source_peer_id: [u8; 32], data: Vec<u8>) -> Self {
        Self {
            magic: RELAY_MAGIC,
            target_peer_id,
            source_peer_id,
            data,
        }
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&RelayMessage::RelayData(self.clone()))
    }
}

/// Data relayed from another peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayedDataResponse {
    /// Magic bytes for protocol identification.
    pub magic: [u8; 4],
    /// Source peer ID (who sent the original data).
    pub source_peer_id: [u8; 32],
    /// Relay peer ID (who forwarded the data).
    pub relay_peer_id: [u8; 32],
    /// Data payload.
    pub data: Vec<u8>,
}

impl RelayedDataResponse {
    /// Create a new relayed data response.
    pub fn new(source_peer_id: [u8; 32], relay_peer_id: [u8; 32], data: Vec<u8>) -> Self {
        Self {
            magic: RELAY_MAGIC,
            source_peer_id,
            relay_peer_id,
            data,
        }
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&RelayMessage::RelayedData(self.clone()))
    }
}

impl RelayMessage {
    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }

    /// Check if bytes look like a relay message (check magic).
    pub fn is_relay_message(data: &[u8]) -> bool {
        // JSON-encoded, so we look for the magic in the content
        if data.len() < 10 {
            return false;
        }
        // Quick heuristic: relay messages contain "RLAY" magic
        data.windows(4).any(|w| w == RELAY_MAGIC)
    }
}

/// Information about a potential relay peer.
#[derive(Debug, Clone)]
pub struct RelayCandidate {
    /// Peer ID of the relay candidate.
    pub peer_id: [u8; 32],
    /// Whether this peer appears to be public on any IP family (backward compat).
    pub is_public: bool,
    /// Whether this peer is public on IPv4.
    pub is_public_ipv4: bool,
    /// Whether this peer is public on IPv6.
    pub is_public_ipv6: bool,
    /// Whether we're currently connected to this peer.
    pub is_connected: bool,
    /// Addresses of this peer.
    pub addresses: Vec<SocketAddr>,
}

impl RelayCandidate {
    /// Priority score for relay selection.
    /// Higher is better.
    ///
    /// Dual-stack public nodes (public on both IPv4 and IPv6) are highest priority
    /// because they can relay traffic for any peer regardless of IP family.
    pub fn priority(&self) -> u32 {
        let mut score = 0;

        // Dual-stack public nodes are best (can relay any traffic)
        if self.is_public_ipv4 && self.is_public_ipv6 {
            score += 150;
        } else if self.is_public_ipv4 {
            // IPv4-only public: good for most traffic (IPv4 still dominant)
            score += 100;
        } else if self.is_public_ipv6 {
            // IPv6-only public: useful for IPv6-capable peers
            score += 80;
        }

        // Currently connected is better (no connection overhead)
        if self.is_connected {
            score += 50;
        }

        // Prefer nodes with both IPv4 and IPv6 addresses available
        let has_ipv4 = self.addresses.iter().any(|a| a.ip().is_ipv4());
        let has_ipv6 = self.addresses.iter().any(|a| a.ip().is_ipv6());
        if has_ipv4 && has_ipv6 {
            score += 20;
        }

        // More addresses = more reachable
        score += self.addresses.len() as u32;

        score
    }

    /// Check if this relay can handle traffic for a given IP family.
    pub fn can_relay_ipv4(&self) -> bool {
        self.is_public_ipv4 && self.addresses.iter().any(|a| a.ip().is_ipv4())
    }

    /// Check if this relay can handle IPv6 traffic.
    pub fn can_relay_ipv6(&self) -> bool {
        self.is_public_ipv6 && self.addresses.iter().any(|a| a.ip().is_ipv6())
    }
}

// ============================================================================
// Public Node Detection
// ============================================================================
//
// A node is considered "public" if its external address equals its local address,
// meaning it's not behind NAT and can be directly reached from anywhere.
// These nodes are ideal relay candidates because:
// 1. They can accept incoming connections from any peer
// 2. No NAT traversal needed to reach them
// 3. They can coordinate hole-punching between NATted peers

/// Information about a peer's network visibility.
#[derive(Debug, Clone)]
pub struct PeerNetworkInfo {
    /// Peer ID (32 bytes).
    pub peer_id: [u8; 32],
    /// Local addresses reported by the peer.
    pub local_addresses: Vec<SocketAddr>,
    /// External addresses observed for the peer.
    pub external_addresses: Vec<SocketAddr>,
    /// Whether this peer appears to be public (external == local for any IP family).
    /// This is the union of `is_public_ipv4 || is_public_ipv6` for backward compatibility.
    pub is_public: bool,
    /// Whether this peer is public on IPv4 (external IPv4 == local IPv4).
    /// A peer can be public on IPv4 but NATted on IPv6, or vice versa.
    pub is_public_ipv4: bool,
    /// Whether this peer is public on IPv6 (external IPv6 == local IPv6).
    /// IPv6 is typically globally routable, so this is usually true if IPv6 is available.
    pub is_public_ipv6: bool,
    /// Whether we're currently connected to this peer.
    pub is_connected: bool,
    /// When we last confirmed connectivity.
    pub last_seen: std::time::Instant,
}

impl PeerNetworkInfo {
    /// Create new peer network info.
    pub fn new(peer_id: [u8; 32]) -> Self {
        Self {
            peer_id,
            local_addresses: Vec::new(),
            external_addresses: Vec::new(),
            is_public: false,
            is_public_ipv4: false,
            is_public_ipv6: false,
            is_connected: false,
            last_seen: std::time::Instant::now(),
        }
    }

    /// Determine if this peer is public by comparing addresses per IP family.
    ///
    /// A peer is public on a given IP family if the external address IP matches
    /// the local address IP for that family. This means the peer is not behind NAT
    /// for that address family.
    ///
    /// # Dual-Stack Behavior
    ///
    /// IPv4 and IPv6 are evaluated independently because:
    /// - A node may be NATted on IPv4 but have global IPv6 (common with ISPs)
    /// - A node may have public IPv4 but no IPv6 at all
    /// - A node may be NATted on both (rare, usually carrier-grade NAT)
    ///
    /// The combined `is_public` is true if the node is public on either family,
    /// which maintains backward compatibility.
    pub fn compute_is_public(&mut self) {
        // Reset both family statuses
        self.is_public_ipv4 = false;
        self.is_public_ipv6 = false;

        if self.external_addresses.is_empty() || self.local_addresses.is_empty() {
            self.is_public = false;
            return;
        }

        // Separate addresses by IP family
        let (local_ipv4, local_ipv6): (Vec<_>, Vec<_>) =
            self.local_addresses.iter().partition(|a| a.ip().is_ipv4());
        let (external_ipv4, external_ipv6): (Vec<_>, Vec<_>) = self
            .external_addresses
            .iter()
            .partition(|a| a.ip().is_ipv4());

        // Check IPv4: external IPv4 IP matches any local IPv4 IP
        if !local_ipv4.is_empty() && !external_ipv4.is_empty() {
            let local_ipv4_ips: std::collections::HashSet<std::net::IpAddr> =
                local_ipv4.iter().map(|a: &&SocketAddr| a.ip()).collect();
            let external_ipv4_ips: std::collections::HashSet<std::net::IpAddr> =
                external_ipv4.iter().map(|a: &&SocketAddr| a.ip()).collect();
            self.is_public_ipv4 = external_ipv4_ips
                .intersection(&local_ipv4_ips)
                .next()
                .is_some();
        }

        // Check IPv6: external IPv6 IP matches any local IPv6 IP
        // Note: IPv6 global addresses are typically not NATted, so if we have
        // a global IPv6 address (not fe80:: link-local or fd00::/8 ULA),
        // we're likely public on IPv6.
        if !local_ipv6.is_empty() && !external_ipv6.is_empty() {
            let local_ipv6_ips: std::collections::HashSet<std::net::IpAddr> =
                local_ipv6.iter().map(|a: &&SocketAddr| a.ip()).collect();
            let external_ipv6_ips: std::collections::HashSet<std::net::IpAddr> =
                external_ipv6.iter().map(|a: &&SocketAddr| a.ip()).collect();
            self.is_public_ipv6 = external_ipv6_ips
                .intersection(&local_ipv6_ips)
                .next()
                .is_some();
        }

        // Combined status for backward compatibility
        self.is_public = self.is_public_ipv4 || self.is_public_ipv6;
    }

    /// Convert to a RelayCandidate for relay selection.
    pub fn to_relay_candidate(&self) -> RelayCandidate {
        RelayCandidate {
            peer_id: self.peer_id,
            is_public: self.is_public,
            is_public_ipv4: self.is_public_ipv4,
            is_public_ipv6: self.is_public_ipv6,
            is_connected: self.is_connected,
            addresses: self.external_addresses.clone(),
        }
    }
}

// ============================================================================
// Relay State Tracking
// ============================================================================

/// State for managing relay discovery and forwarding.
#[derive(Debug)]
pub struct RelayState {
    /// Known peers and their network info (for public node detection).
    pub known_peers: std::collections::HashMap<[u8; 32], PeerNetworkInfo>,
    /// Pending CAN_YOU_REACH requests (request_id -> target_peer_id).
    pub pending_reach_requests: std::collections::HashMap<u64, [u8; 32]>,
    /// Active relay connections: target_peer_id -> relay_peer_id.
    /// When we can't reach a target directly, we use the relay to forward.
    pub active_relays: std::collections::HashMap<[u8; 32], [u8; 32]>,
    /// Our own peer ID.
    pub our_peer_id: [u8; 32],
    /// Our external addresses (for public node self-detection).
    pub our_external_addresses: Vec<SocketAddr>,
    /// Our local addresses.
    pub our_local_addresses: Vec<SocketAddr>,
}

impl RelayState {
    /// Create new relay state.
    pub fn new(our_peer_id: [u8; 32]) -> Self {
        Self {
            known_peers: std::collections::HashMap::new(),
            pending_reach_requests: std::collections::HashMap::new(),
            active_relays: std::collections::HashMap::new(),
            our_peer_id,
            our_external_addresses: Vec::new(),
            our_local_addresses: Vec::new(),
        }
    }

    /// Check if we appear to be a public node (on any IP family).
    /// This is `are_we_public_ipv4() || are_we_public_ipv6()`.
    pub fn are_we_public(&self) -> bool {
        self.are_we_public_ipv4() || self.are_we_public_ipv6()
    }

    /// Check if we appear to be a public node on IPv4.
    ///
    /// A node is public on IPv4 if any external IPv4 address matches any local IPv4 address.
    pub fn are_we_public_ipv4(&self) -> bool {
        if self.our_external_addresses.is_empty() || self.our_local_addresses.is_empty() {
            return false;
        }

        // Filter to IPv4 only
        let external_ipv4: Vec<_> = self
            .our_external_addresses
            .iter()
            .filter(|a| a.ip().is_ipv4())
            .collect();
        let local_ipv4: Vec<_> = self
            .our_local_addresses
            .iter()
            .filter(|a| a.ip().is_ipv4())
            .collect();

        if external_ipv4.is_empty() || local_ipv4.is_empty() {
            return false;
        }

        let external_ips: std::collections::HashSet<_> =
            external_ipv4.iter().map(|a| a.ip()).collect();
        let local_ips: std::collections::HashSet<_> = local_ipv4.iter().map(|a| a.ip()).collect();

        external_ips.intersection(&local_ips).next().is_some()
    }

    /// Check if we appear to be a public node on IPv6.
    ///
    /// A node is public on IPv6 if any external IPv6 address matches any local IPv6 address.
    /// Note: IPv6 global addresses are typically not NATted.
    pub fn are_we_public_ipv6(&self) -> bool {
        if self.our_external_addresses.is_empty() || self.our_local_addresses.is_empty() {
            return false;
        }

        // Filter to IPv6 only (excluding link-local fe80::)
        let external_ipv6: Vec<_> = self
            .our_external_addresses
            .iter()
            .filter(|a| {
                if let std::net::IpAddr::V6(v6) = a.ip() {
                    // Exclude link-local addresses (fe80::/10)
                    let segments = v6.segments();
                    (segments[0] & 0xffc0) != 0xfe80
                } else {
                    false
                }
            })
            .collect();
        let local_ipv6: Vec<_> = self
            .our_local_addresses
            .iter()
            .filter(|a| {
                if let std::net::IpAddr::V6(v6) = a.ip() {
                    // Exclude link-local addresses (fe80::/10)
                    let segments = v6.segments();
                    (segments[0] & 0xffc0) != 0xfe80
                } else {
                    false
                }
            })
            .collect();

        if external_ipv6.is_empty() || local_ipv6.is_empty() {
            return false;
        }

        let external_ips: std::collections::HashSet<_> =
            external_ipv6.iter().map(|a| a.ip()).collect();
        let local_ips: std::collections::HashSet<_> = local_ipv6.iter().map(|a| a.ip()).collect();

        external_ips.intersection(&local_ips).next().is_some()
    }

    /// Get our public status per IP family.
    ///
    /// Returns (is_public, is_public_ipv4, is_public_ipv6).
    pub fn get_public_status(&self) -> (bool, bool, bool) {
        let ipv4 = self.are_we_public_ipv4();
        let ipv6 = self.are_we_public_ipv6();
        (ipv4 || ipv6, ipv4, ipv6)
    }

    /// Update peer network info.
    pub fn update_peer(
        &mut self,
        peer_id: [u8; 32],
        local_addresses: Vec<SocketAddr>,
        external_addresses: Vec<SocketAddr>,
        is_connected: bool,
    ) {
        let entry = self
            .known_peers
            .entry(peer_id)
            .or_insert_with(|| PeerNetworkInfo::new(peer_id));

        entry.local_addresses = local_addresses;
        entry.external_addresses = external_addresses;
        entry.is_connected = is_connected;
        entry.last_seen = std::time::Instant::now();
        entry.compute_is_public();
    }

    /// Mark a peer as connected/disconnected.
    pub fn set_peer_connected(&mut self, peer_id: [u8; 32], connected: bool) {
        if let Some(peer) = self.known_peers.get_mut(&peer_id) {
            peer.is_connected = connected;
            if connected {
                peer.last_seen = std::time::Instant::now();
            }
        }
    }

    /// Get all public nodes (sorted by priority).
    pub fn get_public_nodes(&self) -> Vec<&PeerNetworkInfo> {
        let mut public: Vec<_> = self
            .known_peers
            .values()
            .filter(|p| p.is_public && p.is_connected)
            .collect();

        // Sort by address count (more addresses = more likely reachable)
        public.sort_by(|a, b| b.external_addresses.len().cmp(&a.external_addresses.len()));
        public
    }

    /// Get all connected peers as relay candidates (sorted by priority).
    pub fn get_relay_candidates(&self) -> Vec<RelayCandidate> {
        let mut candidates: Vec<_> = self
            .known_peers
            .values()
            .filter(|p| p.is_connected)
            .map(|p| p.to_relay_candidate())
            .collect();

        // Sort by priority (highest first)
        candidates.sort_by_key(|c| std::cmp::Reverse(c.priority()));
        candidates
    }

    /// Check if we can reach a target through any relay.
    pub fn get_relay_for(&self, target_peer_id: &[u8; 32]) -> Option<[u8; 32]> {
        self.active_relays.get(target_peer_id).copied()
    }

    /// Set an active relay for a target.
    pub fn set_relay_for(&mut self, target_peer_id: [u8; 32], relay_peer_id: [u8; 32]) {
        self.active_relays.insert(target_peer_id, relay_peer_id);
    }

    /// Remove relay for a target (e.g., when direct connection succeeds).
    pub fn remove_relay_for(&mut self, target_peer_id: &[u8; 32]) {
        self.active_relays.remove(target_peer_id);
    }
}

// ============================================================================
// Gossip Protocol for Peer List Exchange
// ============================================================================
//
// This protocol enables decentralized peer discovery by exchanging peer lists
// between connected peers. When two nodes connect, they exchange their known
// peer lists, enabling new nodes to discover the network without relying
// solely on the registry.
//
// Flow:
// 1. A connects to B
// 2. Both A and B send their peer list to each other
// 3. Each node tries to connect to new peers discovered
// 4. When a new peer is discovered, broadcast to all connected peers

/// Magic bytes to identify gossip protocol messages.
pub const GOSSIP_MAGIC: [u8; 4] = *b"GOSP";

/// Gossip protocol message types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipMessage {
    /// Peer list exchange - share known peers.
    PeerList(PeerListMessage),
    /// Single peer announcement - notify about a new peer.
    PeerAnnouncement(GossipPeerAnnouncement),
    /// Request a peer to connect back to us (for NAT traversal verification).
    ConnectBackRequest(ConnectBackRequest),
    /// Response to a connect-back request.
    ConnectBackResponse(ConnectBackResponse),
    /// Request peer to disconnect and connect back after 30s (fresh NAT test).
    DisconnectAndConnectBack(DisconnectAndConnectBack),
    /// Delta update: peer added or updated (epoch-based).
    PeerUpsert(PeerUpsert),
    /// Delta update: peer removed/dead (epoch-based tombstone).
    PeerTombstone(PeerTombstone),
}

/// A list of known peers to share via gossip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerListMessage {
    /// Magic bytes for protocol identification.
    pub magic: [u8; 4],
    /// Sender's peer ID (32 bytes hex).
    pub sender_id: String,
    /// List of known peers.
    pub peers: Vec<GossipPeerInfo>,
    /// Timestamp when this message was created.
    pub timestamp_ms: u64,
}

/// Information about a peer shared via gossip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipPeerInfo {
    /// Hex-encoded peer ID.
    pub peer_id: String,
    /// Known addresses for this peer.
    pub addresses: Vec<SocketAddr>,
    /// Whether this peer is publicly reachable.
    pub is_public: bool,
    /// Whether we're currently connected to this peer.
    pub is_connected: bool,
    /// Last time we successfully communicated with this peer.
    pub last_seen_ms: u64,
}

/// Single peer announcement broadcast to all connected peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipPeerAnnouncement {
    /// Magic bytes for protocol identification.
    pub magic: [u8; 4],
    /// The peer being announced.
    pub peer: GossipPeerInfo,
    /// Announcer's peer ID.
    pub announcer_id: String,
    /// Timestamp when this announcement was created.
    pub timestamp_ms: u64,
    /// TTL - how many more hops this announcement should propagate (prevents infinite loops).
    pub ttl: u8,
}

impl PeerListMessage {
    /// Create a new peer list message.
    pub fn new(sender_id: String, peers: Vec<GossipPeerInfo>) -> Self {
        Self {
            magic: GOSSIP_MAGIC,
            sender_id,
            peers,
            timestamp_ms: current_timestamp_ns() / 1_000_000,
        }
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&GossipMessage::PeerList(self.clone()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        let msg: GossipMessage = serde_json::from_slice(bytes)?;
        match msg {
            GossipMessage::PeerList(list) => Ok(list),
            _ => Err(serde::de::Error::custom("Expected PeerList")),
        }
    }
}

#[allow(dead_code)] // Will be used for gossip broadcast on discovery
impl GossipPeerAnnouncement {
    /// Create a new peer announcement.
    pub fn new(peer: GossipPeerInfo, announcer_id: String, ttl: u8) -> Self {
        Self {
            magic: GOSSIP_MAGIC,
            peer,
            announcer_id,
            timestamp_ms: current_timestamp_ns() / 1_000_000,
            ttl,
        }
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&GossipMessage::PeerAnnouncement(self.clone()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        let msg: GossipMessage = serde_json::from_slice(bytes)?;
        match msg {
            GossipMessage::PeerAnnouncement(announcement) => Ok(announcement),
            _ => Err(serde::de::Error::custom("Expected PeerAnnouncement")),
        }
    }

    /// Create a copy with decremented TTL for forwarding.
    pub fn forward(&self) -> Option<Self> {
        if self.ttl == 0 {
            return None;
        }
        Some(Self {
            magic: self.magic,
            peer: self.peer.clone(),
            announcer_id: self.announcer_id.clone(),
            timestamp_ms: self.timestamp_ms,
            ttl: self.ttl - 1,
        })
    }
}

/// Delta gossip: peer added or updated. Accept only if epoch > local epoch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerUpsert {
    pub magic: [u8; 4],
    pub peer_id: String,
    pub epoch: u64,
    pub addresses: Vec<SocketAddr>,
    pub is_public: bool,
    pub expires_at_ms: u64,
    pub announcer_id: String,
}

impl PeerUpsert {
    pub fn new(
        peer_id: String,
        epoch: u64,
        addresses: Vec<SocketAddr>,
        is_public: bool,
        ttl_secs: u64,
        announcer_id: String,
    ) -> Self {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Self {
            magic: GOSSIP_MAGIC,
            peer_id,
            epoch,
            addresses,
            is_public,
            expires_at_ms: now_ms + (ttl_secs * 1000),
            announcer_id,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&GossipMessage::PeerUpsert(self.clone()))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        let msg: GossipMessage = serde_json::from_slice(bytes)?;
        match msg {
            GossipMessage::PeerUpsert(upsert) => Ok(upsert),
            _ => Err(serde::de::Error::custom("Expected PeerUpsert")),
        }
    }

    pub fn is_expired(&self) -> bool {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        now_ms > self.expires_at_ms
    }
}

/// Delta gossip: peer removed/dead (tombstone). Accept only if epoch > local epoch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerTombstone {
    pub magic: [u8; 4],
    pub peer_id: String,
    pub epoch: u64,
    pub reason: TombstoneReason,
    pub tombstone_expires_at_ms: u64,
    pub announcer_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TombstoneReason {
    SwimDead,
    Timeout,
    Unregistered,
    Manual,
}

impl PeerTombstone {
    pub fn new(
        peer_id: String,
        epoch: u64,
        reason: TombstoneReason,
        ttl_secs: u64,
        announcer_id: String,
    ) -> Self {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Self {
            magic: GOSSIP_MAGIC,
            peer_id,
            epoch,
            reason,
            tombstone_expires_at_ms: now_ms + (ttl_secs * 1000),
            announcer_id,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&GossipMessage::PeerTombstone(self.clone()))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        let msg: GossipMessage = serde_json::from_slice(bytes)?;
        match msg {
            GossipMessage::PeerTombstone(tombstone) => Ok(tombstone),
            _ => Err(serde::de::Error::custom("Expected PeerTombstone")),
        }
    }

    pub fn is_expired(&self) -> bool {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        now_ms > self.tombstone_expires_at_ms
    }
}

// ============================================================================
// Connect-Back Protocol for NAT Traversal Verification
// ============================================================================
//
// This protocol enables bidirectional NAT traversal testing. When node A wants
// to verify that other nodes can connect BACK to it (proving NAT hole is open),
// it sends a ConnectBackRequest via gossip. The receiving node attempts to
// establish a QUIC connection to the requester's addresses.
//
// The 30-second rule: Only send connect-back requests to peers that haven't
// had a connection (in either direction) for at least 30 seconds. This ensures
// we're testing a fresh NAT traversal rather than reusing an existing hole.
//
// Flow:
// 1. A hasn't had any connection with B for 30+ seconds
// 2. A sends ConnectBackRequest to B via gossip (includes A's external addresses)
// 3. B attempts to connect to A's addresses
// 4. B sends ConnectBackResponse with the result
// 5. If successful, A's inbound NAT traversal is verified!

/// Request a peer to connect back to us for NAT traversal verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectBackRequest {
    /// Magic bytes for protocol identification.
    pub magic: [u8; 4],
    /// Unique request ID for correlation.
    pub request_id: u64,
    /// Requester's peer ID (hex-encoded).
    pub requester_peer_id: String,
    /// Requester's external addresses to connect to.
    pub requester_addresses: Vec<SocketAddr>,
    /// Timestamp when this request was created.
    pub timestamp_ms: u64,
}

impl ConnectBackRequest {
    /// Create a new connect-back request.
    pub fn new(requester_peer_id: String, requester_addresses: Vec<SocketAddr>) -> Self {
        Self {
            magic: GOSSIP_MAGIC,
            request_id: current_timestamp_ns(),
            requester_peer_id,
            requester_addresses,
            timestamp_ms: current_timestamp_ns() / 1_000_000,
        }
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&GossipMessage::ConnectBackRequest(self.clone()))
    }
}

/// Response to a connect-back request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectBackResponse {
    /// Magic bytes for protocol identification.
    pub magic: [u8; 4],
    /// Request ID this responds to.
    pub request_id: u64,
    /// Responder's peer ID (hex-encoded).
    pub responder_peer_id: String,
    /// Whether the connect-back attempt succeeded.
    pub success: bool,
    /// The address we successfully connected to (if success).
    pub connected_address: Option<SocketAddr>,
    /// Error message if connect-back failed.
    pub error: Option<String>,
    /// Timestamp when this response was created.
    pub timestamp_ms: u64,
}

impl ConnectBackResponse {
    /// Create a successful connect-back response.
    pub fn success(
        request_id: u64,
        responder_peer_id: String,
        connected_address: SocketAddr,
    ) -> Self {
        Self {
            magic: GOSSIP_MAGIC,
            request_id,
            responder_peer_id,
            success: true,
            connected_address: Some(connected_address),
            error: None,
            timestamp_ms: current_timestamp_ns() / 1_000_000,
        }
    }

    /// Create a failed connect-back response.
    pub fn failure(request_id: u64, responder_peer_id: String, error: String) -> Self {
        Self {
            magic: GOSSIP_MAGIC,
            request_id,
            responder_peer_id,
            success: false,
            connected_address: None,
            error: Some(error),
            timestamp_ms: current_timestamp_ns() / 1_000_000,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&GossipMessage::ConnectBackResponse(self.clone()))
    }
}

/// Request peer to disconnect, wait 30s for NAT hole to expire, then connect back.
/// This tests fresh NAT traversal rather than reusing existing holes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisconnectAndConnectBack {
    pub magic: [u8; 4],
    pub request_id: u64,
    pub requester_peer_id: String,
    pub requester_addresses: Vec<SocketAddr>,
    pub requester_ipv4_addresses: Vec<SocketAddr>,
    pub requester_ipv6_addresses: Vec<SocketAddr>,
    pub delay_seconds: u32,
    pub timestamp_ms: u64,
}

impl DisconnectAndConnectBack {
    pub fn new(
        requester_peer_id: String,
        requester_addresses: Vec<SocketAddr>,
        delay_seconds: u32,
    ) -> Self {
        let ipv4: Vec<SocketAddr> = requester_addresses
            .iter()
            .filter(|a| a.is_ipv4())
            .copied()
            .collect();
        let ipv6: Vec<SocketAddr> = requester_addresses
            .iter()
            .filter(|a| a.is_ipv6())
            .copied()
            .collect();
        Self {
            magic: GOSSIP_MAGIC,
            request_id: current_timestamp_ns(),
            requester_peer_id,
            requester_addresses,
            requester_ipv4_addresses: ipv4,
            requester_ipv6_addresses: ipv6,
            delay_seconds,
            timestamp_ms: current_timestamp_ns() / 1_000_000,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&GossipMessage::DisconnectAndConnectBack(self.clone()))
    }
}

#[allow(dead_code)]
impl GossipMessage {
    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }

    /// Check if bytes look like a gossip message (check magic).
    pub fn is_gossip_message(data: &[u8]) -> bool {
        if data.len() < 10 {
            return false;
        }
        // JSON-encoded, so we look for the magic in the content
        data.windows(4).any(|w| w == GOSSIP_MAGIC)
    }
}

// ============================================================================
// Connectivity Test Protocol
// ============================================================================
//
// This protocol implements the coordinated connectivity test flow:
// 1. TUI app registers with dashboard
// 2. Dashboard gossips NEW_PEER_TEST to all nodes
// 3. All nodes connect TO the TUI app, trying IPv4/IPv6/NAT/Relay
// 4. TUI records incoming connections
// 5. After 30s, TUI connects BACK to everyone
// 6. Results show bidirectional connectivity matrix

#[allow(dead_code)]
pub mod connectivity_test {
    use super::*;

    pub const MAGIC: [u8; 4] = *b"CNTV";

    /// How a connection was established.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub enum ConnectivityMethod {
        /// Direct IPv4 connection (no NAT traversal needed)
        DirectIpv4,
        /// Direct IPv6 connection
        DirectIpv6,
        /// NAT traversal via hole punching (IPv4)
        NatTraversalIpv4,
        /// NAT traversal via hole punching (IPv6)
        NatTraversalIpv6,
        /// Relayed via MASQUE (IPv4)
        RelayedIpv4,
        /// Relayed via MASQUE (IPv6)
        RelayedIpv6,
    }

    impl ConnectivityMethod {
        pub fn is_ipv4(&self) -> bool {
            matches!(
                self,
                ConnectivityMethod::DirectIpv4
                    | ConnectivityMethod::NatTraversalIpv4
                    | ConnectivityMethod::RelayedIpv4
            )
        }

        pub fn is_ipv6(&self) -> bool {
            matches!(
                self,
                ConnectivityMethod::DirectIpv6
                    | ConnectivityMethod::NatTraversalIpv6
                    | ConnectivityMethod::RelayedIpv6
            )
        }

        pub fn is_direct(&self) -> bool {
            matches!(
                self,
                ConnectivityMethod::DirectIpv4 | ConnectivityMethod::DirectIpv6
            )
        }

        pub fn is_nat_traversal(&self) -> bool {
            matches!(
                self,
                ConnectivityMethod::NatTraversalIpv4 | ConnectivityMethod::NatTraversalIpv6
            )
        }

        pub fn is_relayed(&self) -> bool {
            matches!(
                self,
                ConnectivityMethod::RelayedIpv4 | ConnectivityMethod::RelayedIpv6
            )
        }

        pub fn display_name(&self) -> &'static str {
            match self {
                ConnectivityMethod::DirectIpv4 => "Direct IPv4",
                ConnectivityMethod::DirectIpv6 => "Direct IPv6",
                ConnectivityMethod::NatTraversalIpv4 => "NAT IPv4",
                ConnectivityMethod::NatTraversalIpv6 => "NAT IPv6",
                ConnectivityMethod::RelayedIpv4 => "Relay IPv4",
                ConnectivityMethod::RelayedIpv6 => "Relay IPv6",
            }
        }
    }

    /// Test phase in the connectivity test flow.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ConnectivityTestPhase {
        /// Registering with dashboard
        Registering,
        /// Waiting for inbound connections from network
        WaitingForInbound,
        /// Received inbound connections, waiting before outbound test
        WaitingCountdown { seconds_remaining: u32 },
        /// Performing outbound connection tests
        TestingOutbound { tested: u32, total: u32 },
        /// Test complete, showing results
        Complete,
    }

    /// Result of a single connection attempt.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ConnectionAttemptResult {
        /// Method attempted
        pub method: ConnectivityMethod,
        /// Whether this attempt succeeded
        pub success: bool,
        /// RTT if successful (milliseconds)
        pub rtt_ms: Option<u32>,
        /// Error message if failed
        pub error: Option<String>,
        /// Timestamp of attempt (unix millis)
        pub timestamp_ms: u64,
    }

    /// Results for a single peer in the connectivity test.
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct PeerConnectivityResult {
        /// Peer ID (hex string, first 8 chars for display)
        pub peer_id: String,
        /// Full peer ID
        pub peer_id_full: String,
        /// Peer name (e.g., "saorsa-1" or "user-abc")
        pub peer_name: Option<String>,
        /// Peer's addresses
        pub addresses: Vec<SocketAddr>,

        /// Inbound test results (them connecting to us)
        pub inbound_ipv4_direct: Option<bool>,
        pub inbound_ipv6_direct: Option<bool>,
        pub inbound_nat_traversal: Option<bool>,
        pub inbound_relay: Option<bool>,
        /// All inbound attempts with details
        pub inbound_attempts: Vec<ConnectionAttemptResult>,

        /// Outbound test results (us connecting to them)
        pub outbound_ipv4_direct: Option<bool>,
        pub outbound_ipv6_direct: Option<bool>,
        pub outbound_nat_traversal: Option<bool>,
        pub outbound_relay: Option<bool>,
        /// All outbound attempts with details
        pub outbound_attempts: Vec<ConnectionAttemptResult>,
    }

    impl PeerConnectivityResult {
        pub fn new(peer_id: String, peer_id_full: String) -> Self {
            Self {
                peer_id,
                peer_id_full,
                ..Default::default()
            }
        }

        /// Record an inbound connection attempt.
        pub fn record_inbound(
            &mut self,
            method: ConnectivityMethod,
            success: bool,
            rtt_ms: Option<u32>,
            error: Option<String>,
        ) {
            let attempt = ConnectionAttemptResult {
                method,
                success,
                rtt_ms,
                error,
                timestamp_ms: current_timestamp_ns() / 1_000_000,
            };
            self.inbound_attempts.push(attempt);

            match method {
                ConnectivityMethod::DirectIpv4 => self.inbound_ipv4_direct = Some(success),
                ConnectivityMethod::DirectIpv6 => self.inbound_ipv6_direct = Some(success),
                ConnectivityMethod::NatTraversalIpv4 | ConnectivityMethod::NatTraversalIpv6 => {
                    if self.inbound_nat_traversal.is_none() || success {
                        self.inbound_nat_traversal = Some(success);
                    }
                }
                ConnectivityMethod::RelayedIpv4 | ConnectivityMethod::RelayedIpv6 => {
                    if self.inbound_relay.is_none() || success {
                        self.inbound_relay = Some(success);
                    }
                }
            }
        }

        /// Record an outbound connection attempt.
        pub fn record_outbound(
            &mut self,
            method: ConnectivityMethod,
            success: bool,
            rtt_ms: Option<u32>,
            error: Option<String>,
        ) {
            let attempt = ConnectionAttemptResult {
                method,
                success,
                rtt_ms,
                error,
                timestamp_ms: current_timestamp_ns() / 1_000_000,
            };
            self.outbound_attempts.push(attempt);

            match method {
                ConnectivityMethod::DirectIpv4 => self.outbound_ipv4_direct = Some(success),
                ConnectivityMethod::DirectIpv6 => self.outbound_ipv6_direct = Some(success),
                ConnectivityMethod::NatTraversalIpv4 | ConnectivityMethod::NatTraversalIpv6 => {
                    if self.outbound_nat_traversal.is_none() || success {
                        self.outbound_nat_traversal = Some(success);
                    }
                }
                ConnectivityMethod::RelayedIpv4 | ConnectivityMethod::RelayedIpv6 => {
                    if self.outbound_relay.is_none() || success {
                        self.outbound_relay = Some(success);
                    }
                }
            }
        }

        /// Check if inbound IPv4 succeeded (any method).
        pub fn inbound_ipv4_success(&self) -> bool {
            self.inbound_ipv4_direct == Some(true)
                || self.inbound_nat_traversal == Some(true)
                || self.inbound_relay == Some(true)
        }

        /// Check if inbound IPv6 succeeded.
        pub fn inbound_ipv6_success(&self) -> bool {
            self.inbound_ipv6_direct == Some(true)
        }

        /// Check if outbound IPv4 succeeded (any method).
        pub fn outbound_ipv4_success(&self) -> bool {
            self.outbound_ipv4_direct == Some(true)
                || self.outbound_nat_traversal == Some(true)
                || self.outbound_relay == Some(true)
        }

        /// Check if outbound IPv6 succeeded.
        pub fn outbound_ipv6_success(&self) -> bool {
            self.outbound_ipv6_direct == Some(true)
        }

        /// Overall inbound success (any method worked).
        pub fn inbound_success(&self) -> bool {
            self.inbound_ipv4_success() || self.inbound_ipv6_success()
        }

        /// Overall outbound success (any method worked).
        pub fn outbound_success(&self) -> bool {
            self.outbound_ipv4_success() || self.outbound_ipv6_success()
        }
    }

    /// Message sent when a new peer registers and wants connectivity testing.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct NewPeerTestRequest {
        /// Magic bytes for protocol identification.
        pub magic: [u8; 4],
        /// Peer ID of the new peer to test.
        pub peer_id: [u8; 32],
        /// Addresses where the peer can be reached.
        pub addresses: Vec<SocketAddr>,
        /// Request timestamp.
        pub timestamp_ms: u64,
        /// Relay address to use if direct connection fails.
        pub relay_addr: Option<SocketAddr>,
    }

    impl NewPeerTestRequest {
        pub fn new(
            peer_id: [u8; 32],
            addresses: Vec<SocketAddr>,
            relay_addr: Option<SocketAddr>,
        ) -> Self {
            Self {
                magic: MAGIC,
                peer_id,
                addresses,
                timestamp_ms: current_timestamp_ns() / 1_000_000,
                relay_addr,
            }
        }

        pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
            serde_json::to_vec(self)
        }

        pub fn from_bytes(data: &[u8]) -> Result<Self, serde_json::Error> {
            serde_json::from_slice(data)
        }
    }

    /// Message sent to test connectivity (includes proof data).
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ConnectivityTestProbe {
        /// Magic bytes for protocol identification.
        pub magic: [u8; 4],
        /// Sender's peer ID.
        pub sender_peer_id: [u8; 32],
        /// Sender's name (e.g., "saorsa-1").
        pub sender_name: Option<String>,
        /// How the connection was made.
        pub method: ConnectivityMethod,
        /// Test data payload (5KB to verify real connectivity).
        pub payload: Vec<u8>,
        /// Checksum of payload.
        pub checksum: [u8; 32],
        /// Timestamp when sent.
        pub timestamp_ms: u64,
    }

    impl ConnectivityTestProbe {
        pub fn new(
            sender_peer_id: [u8; 32],
            sender_name: Option<String>,
            method: ConnectivityMethod,
        ) -> Self {
            let payload = generate_random_payload();
            let checksum = {
                let mut hasher = Sha256::new();
                hasher.update(&payload);
                hasher.finalize().into()
            };
            Self {
                magic: MAGIC,
                sender_peer_id,
                sender_name,
                method,
                payload,
                checksum,
                timestamp_ms: current_timestamp_ns() / 1_000_000,
            }
        }

        pub fn verify(&self) -> bool {
            let mut hasher = Sha256::new();
            hasher.update(&self.payload);
            let calculated: [u8; 32] = hasher.finalize().into();
            calculated == self.checksum
        }

        pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
            serde_json::to_vec(self)
        }

        pub fn from_bytes(data: &[u8]) -> Result<Self, serde_json::Error> {
            serde_json::from_slice(data)
        }
    }

    /// Acknowledgment of connectivity test probe.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ConnectivityTestAck {
        /// Magic bytes for protocol identification.
        pub magic: [u8; 4],
        /// Responder's peer ID.
        pub responder_peer_id: [u8; 32],
        /// Original sender's peer ID.
        pub sender_peer_id: [u8; 32],
        /// Method that was used.
        pub method: ConnectivityMethod,
        /// Whether the probe was valid.
        pub valid: bool,
        /// Response timestamp.
        pub timestamp_ms: u64,
    }

    impl ConnectivityTestAck {
        pub fn new(
            responder_peer_id: [u8; 32],
            sender_peer_id: [u8; 32],
            method: ConnectivityMethod,
            valid: bool,
        ) -> Self {
            Self {
                magic: MAGIC,
                responder_peer_id,
                sender_peer_id,
                method,
                valid,
                timestamp_ms: current_timestamp_ns() / 1_000_000,
            }
        }

        pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
            serde_json::to_vec(self)
        }

        pub fn from_bytes(data: &[u8]) -> Result<Self, serde_json::Error> {
            serde_json::from_slice(data)
        }
    }

    #[allow(dead_code)]
    pub mod connectivity_timeouts {
        use std::time::Duration;

        /// Timeout for direct IPv4 connection attempt.
        pub const DIRECT_IPV4: Duration = Duration::from_secs(5);
        /// Timeout for direct IPv6 connection attempt.
        pub const DIRECT_IPV6: Duration = Duration::from_secs(5);
        /// Timeout for NAT traversal attempt.
        pub const NAT_TRAVERSAL: Duration = Duration::from_secs(10);
        /// Timeout for relay connection attempt.
        pub const RELAY: Duration = Duration::from_secs(10);
        /// Total timeout for all attempts to a single peer.
        pub const TOTAL_PER_PEER: Duration = Duration::from_secs(35);
        /// Wait time between inbound and outbound phases.
        pub const WAIT_BEFORE_OUTBOUND: Duration = Duration::from_secs(30);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ping_packet_creation() {
        let sender_id = [42u8; 32];
        let packet = TestPacket::new_ping(sender_id, 1);

        assert_eq!(packet.magic, TEST_PACKET_MAGIC);
        assert_eq!(packet.packet_type, PacketType::Ping);
        assert_eq!(packet.sequence, 1);
        assert_eq!(packet.sender_id, sender_id);
        assert!(packet.verify_checksum());
    }

    #[test]
    fn test_pong_response() {
        let sender_a = [1u8; 32];
        let sender_b = [2u8; 32];
        let ping = TestPacket::new_ping(sender_a, 1);
        let pong = ping.create_pong(sender_b);

        assert_eq!(pong.packet_type, PacketType::Pong);
        assert_eq!(pong.sequence, ping.sequence);
        assert_eq!(pong.sender_id, sender_b);
        assert!(pong.verify_checksum());
    }

    #[test]
    fn test_packet_size() {
        let sender_id = [0u8; 32];
        let packet = TestPacket::new_ping(sender_id, 0);
        // Should be approximately 5KB
        assert!(packet.size() > 5000);
        assert!(packet.size() < 6000);
    }

    #[test]
    fn test_serialization() {
        let sender_id = [42u8; 32];
        let packet = TestPacket::new_ping(sender_id, 100);
        let bytes = packet.to_bytes().expect("serialization failed");
        let restored = TestPacket::from_bytes(&bytes).expect("deserialization failed");

        assert_eq!(restored.sequence, packet.sequence);
        assert_eq!(restored.sender_id, sender_id);
        assert!(restored.verify_checksum());
    }
}
