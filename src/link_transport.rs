// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! # Link Transport Abstraction Layer
//!
//! This module provides the [`LinkTransport`] and [`LinkConn`] traits that abstract
//! the transport layer for overlay networks like saorsa-core. This enables:
//!
//! - **Version decoupling**: Overlays can compile against a stable trait interface
//!   while ant-quic evolves underneath
//! - **Testing**: Mock transports for unit testing overlay logic
//! - **Alternative transports**: Future support for WebRTC, TCP fallback, etc.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      saorsa-core (overlay)                       │
//! │  DHT routing │ Record storage │ Greedy routing │ Naming         │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    LinkTransport trait                          │
//! │  local_peer() │ peer_table() │ dial() │ accept() │ subscribe()  │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                  ant-quic P2pEndpoint                            │
//! │  QUIC transport │ NAT traversal │ PQC │ Connection management   │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Example: Implementing an Overlay
//!
//! ```rust,ignore
//! use ant_quic::link_transport::{LinkTransport, LinkConn, LinkEvent, ProtocolId, LinkError};
//! use std::sync::Arc;
//! use futures_util::StreamExt;
//!
//! // Define your overlay's protocol identifier
//! const DHT_PROTOCOL: ProtocolId = ProtocolId::from_static(b"saorsa-dht/1.0.0");
//!
//! async fn run_overlay<T: LinkTransport>(transport: Arc<T>) -> anyhow::Result<()> {
//!     // Register our protocol so peers know we support it
//!     transport.register_protocol(DHT_PROTOCOL);
//!
//!     // Subscribe to transport events for connection lifecycle
//!     let mut events = transport.subscribe();
//!     tokio::spawn(async move {
//!         while let Ok(event) = events.recv().await {
//!             match event {
//!                 LinkEvent::PeerConnected { peer, caps } => {
//!                     println!("New peer: {:?}, relay: {}", peer, caps.supports_relay);
//!                 }
//!                 LinkEvent::PeerDisconnected { peer, reason } => {
//!                     println!("Lost peer: {:?}, reason: {:?}", peer, reason);
//!                 }
//!                 _ => {}
//!             }
//!         }
//!     });
//!
//!     // Accept incoming connections in a background task
//!     let transport_clone = transport.clone();
//!     tokio::spawn(async move {
//!         let mut incoming = transport_clone.accept(DHT_PROTOCOL);
//!         while let Some(result) = incoming.next().await {
//!             match result {
//!                 Ok(conn) => {
//!                     println!("Accepted connection from {:?}", conn.peer());
//!                     // Handle connection...
//!                 }
//!                 Err(e) => eprintln!("Accept error: {}", e),
//!             }
//!         }
//!     });
//!
//!     // Dial a peer using their PeerId (NAT traversal handled automatically)
//!     let peers = transport.peer_table();
//!     if let Some((peer_id, caps)) = peers.first() {
//!         match transport.dial(*peer_id, DHT_PROTOCOL).await {
//!             Ok(conn) => {
//!                 // Open a bidirectional stream for request/response
//!                 let (mut send, mut recv) = conn.open_bi().await?;
//!                 send.write_all(b"PING").await?;
//!                 send.finish()?;
//!
//!                 let response = recv.read_to_end(1024).await?;
//!                 println!("Response: {:?}", response);
//!             }
//!             Err(LinkError::PeerNotFound(_)) => {
//!                 println!("Peer not in table - need to bootstrap");
//!             }
//!             Err(e) => eprintln!("Dial failed: {}", e),
//!         }
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Choosing Stream Types
//!
//! - **Bidirectional (`open_bi`)**: Use for request/response patterns where both
//!   sides send and receive. Example: RPC calls, file transfers with acknowledgment.
//!
//! - **Unidirectional (`open_uni`)**: Use for one-way messages where no response
//!   is needed. Example: event notifications, log streaming, pub/sub.
//!
//! - **Datagrams (`send_datagram`)**: Use for small, unreliable messages where
//!   latency matters more than reliability. Example: heartbeats, real-time metrics.
//!
//! ## Error Handling Patterns
//!
//! ```rust,ignore
//! use ant_quic::link_transport::{LinkError, LinkResult};
//!
//! async fn connect_with_retry<T: LinkTransport>(
//!     transport: &T,
//!     peer: PeerId,
//!     proto: ProtocolId,
//! ) -> LinkResult<T::Conn> {
//!     for attempt in 1..=3 {
//!         match transport.dial(peer, proto).await {
//!             Ok(conn) => return Ok(conn),
//!             Err(LinkError::PeerNotFound(_)) => {
//!                 // Peer not in table - can't retry, need bootstrap
//!                 return Err(LinkError::PeerNotFound(format!("{:?}", peer)));
//!             }
//!             Err(LinkError::ConnectionFailed(msg)) if attempt < 3 => {
//!                 // Transient failure - retry after delay
//!                 tokio::time::sleep(Duration::from_millis(100 * attempt as u64)).await;
//!                 continue;
//!             }
//!             Err(LinkError::Timeout) if attempt < 3 => {
//!                 // NAT traversal may need multiple attempts
//!                 continue;
//!             }
//!             Err(e) => return Err(e),
//!         }
//!     }
//!     Err(LinkError::ConnectionFailed("max retries exceeded".into()))
//! }
//! ```

use std::collections::HashSet;
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::broadcast;

use crate::nat_traversal_api::PeerId;

// ============================================================================
// Stream Type Registry (Protocol Multiplexing)
// ============================================================================

/// Stream type identifier - the first byte of each QUIC stream.
///
/// This enum provides a hardcoded registry of protocol types for multiplexing
/// multiple protocols over a single QUIC connection. Each stream's first byte
/// identifies its protocol type.
///
/// # Protocol Ranges
///
/// | Range | Protocol Family | Types |
/// |-------|-----------------|-------|
/// | 0x00-0x0F | Gossip | Membership, PubSub, Bulk |
/// | 0x10-0x1F | DHT | Query, Store, Witness, Replication |
/// | 0x20-0x2F | WebRTC | Signal, Media, Data |
/// | 0xF0-0xFF | Reserved | Future use |
///
/// # Example
///
/// ```rust
/// use ant_quic::link_transport::StreamType;
///
/// // Check if a byte is a valid stream type
/// let stream_type = StreamType::from_byte(0x10);
/// assert_eq!(stream_type, Some(StreamType::DhtQuery));
///
/// // Get all gossip types
/// for st in StreamType::gossip_types() {
///     println!("Gossip type: {}", st);
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum StreamType {
    // =========================================================================
    // Gossip Protocols (0x00-0x0F)
    // =========================================================================
    /// Membership protocol messages (HyParView, SWIM).
    Membership = 0x00,

    /// PubSub protocol messages (Plumtree).
    PubSub = 0x01,

    /// Bulk gossip data transfer (CRDT deltas, large payloads).
    GossipBulk = 0x02,

    // =========================================================================
    // DHT Protocols (0x10-0x1F)
    // =========================================================================
    /// DHT query operations (GET, FIND_NODE, FIND_VALUE).
    DhtQuery = 0x10,

    /// DHT store operations (PUT, STORE).
    DhtStore = 0x11,

    /// DHT witness operations (Byzantine fault tolerance).
    DhtWitness = 0x12,

    /// DHT replication operations (background repair).
    DhtReplication = 0x13,

    // =========================================================================
    // WebRTC Protocols (0x20-0x2F)
    // =========================================================================
    /// WebRTC signaling (SDP, ICE candidates via QUIC).
    WebRtcSignal = 0x20,

    /// WebRTC media streams (audio/video RTP).
    WebRtcMedia = 0x21,

    /// WebRTC data channels.
    WebRtcData = 0x22,

    // =========================================================================
    // Reserved (0xF0-0xFF)
    // =========================================================================
    /// Reserved for future protocols.
    Reserved = 0xF0,
}

impl StreamType {
    /// Parse a stream type from its byte value.
    ///
    /// Returns `None` for unknown/unassigned values.
    #[inline]
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(Self::Membership),
            0x01 => Some(Self::PubSub),
            0x02 => Some(Self::GossipBulk),
            0x10 => Some(Self::DhtQuery),
            0x11 => Some(Self::DhtStore),
            0x12 => Some(Self::DhtWitness),
            0x13 => Some(Self::DhtReplication),
            0x20 => Some(Self::WebRtcSignal),
            0x21 => Some(Self::WebRtcMedia),
            0x22 => Some(Self::WebRtcData),
            0xF0 => Some(Self::Reserved),
            _ => None,
        }
    }

    /// Get the byte value for this stream type.
    #[inline]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    /// Get the protocol family for this stream type.
    #[inline]
    pub const fn family(self) -> StreamTypeFamily {
        match self as u8 {
            0x00..=0x0F => StreamTypeFamily::Gossip,
            0x10..=0x1F => StreamTypeFamily::Dht,
            0x20..=0x2F => StreamTypeFamily::WebRtc,
            _ => StreamTypeFamily::Reserved,
        }
    }

    /// Check if this is a gossip protocol type.
    #[inline]
    pub const fn is_gossip(self) -> bool {
        matches!(self.family(), StreamTypeFamily::Gossip)
    }

    /// Check if this is a DHT protocol type.
    #[inline]
    pub const fn is_dht(self) -> bool {
        matches!(self.family(), StreamTypeFamily::Dht)
    }

    /// Check if this is a WebRTC protocol type.
    #[inline]
    pub const fn is_webrtc(self) -> bool {
        matches!(self.family(), StreamTypeFamily::WebRtc)
    }

    /// Get all gossip stream types.
    pub const fn gossip_types() -> &'static [StreamType] {
        &[Self::Membership, Self::PubSub, Self::GossipBulk]
    }

    /// Get all DHT stream types.
    pub const fn dht_types() -> &'static [StreamType] {
        &[
            Self::DhtQuery,
            Self::DhtStore,
            Self::DhtWitness,
            Self::DhtReplication,
        ]
    }

    /// Get all WebRTC stream types.
    pub const fn webrtc_types() -> &'static [StreamType] {
        &[Self::WebRtcSignal, Self::WebRtcMedia, Self::WebRtcData]
    }

    /// Get all defined stream types.
    pub const fn all_types() -> &'static [StreamType] {
        &[
            Self::Membership,
            Self::PubSub,
            Self::GossipBulk,
            Self::DhtQuery,
            Self::DhtStore,
            Self::DhtWitness,
            Self::DhtReplication,
            Self::WebRtcSignal,
            Self::WebRtcMedia,
            Self::WebRtcData,
            Self::Reserved,
        ]
    }
}

impl fmt::Display for StreamType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Membership => write!(f, "Membership"),
            Self::PubSub => write!(f, "PubSub"),
            Self::GossipBulk => write!(f, "GossipBulk"),
            Self::DhtQuery => write!(f, "DhtQuery"),
            Self::DhtStore => write!(f, "DhtStore"),
            Self::DhtWitness => write!(f, "DhtWitness"),
            Self::DhtReplication => write!(f, "DhtReplication"),
            Self::WebRtcSignal => write!(f, "WebRtcSignal"),
            Self::WebRtcMedia => write!(f, "WebRtcMedia"),
            Self::WebRtcData => write!(f, "WebRtcData"),
            Self::Reserved => write!(f, "Reserved"),
        }
    }
}

impl From<StreamType> for u8 {
    fn from(st: StreamType) -> Self {
        st as u8
    }
}

impl TryFrom<u8> for StreamType {
    type Error = LinkError;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        Self::from_byte(byte).ok_or(LinkError::InvalidStreamType(byte))
    }
}

/// Protocol family for stream types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamTypeFamily {
    /// Gossip protocols (0x00-0x0F).
    Gossip,
    /// DHT protocols (0x10-0x1F).
    Dht,
    /// WebRTC protocols (0x20-0x2F).
    WebRtc,
    /// Reserved (0xF0-0xFF).
    Reserved,
}

impl StreamTypeFamily {
    /// Get the byte range for this protocol family.
    pub const fn byte_range(self) -> (u8, u8) {
        match self {
            Self::Gossip => (0x00, 0x0F),
            Self::Dht => (0x10, 0x1F),
            Self::WebRtc => (0x20, 0x2F),
            Self::Reserved => (0xF0, 0xFF),
        }
    }

    /// Check if a byte is in this family's range.
    pub const fn contains(self, byte: u8) -> bool {
        let (start, end) = self.byte_range();
        byte >= start && byte <= end
    }
}

/// A filter for accepting specific stream types.
///
/// Use this with `accept_bi_typed` and `accept_uni_typed` to filter
/// incoming streams by protocol type.
///
/// # Example
///
/// ```rust
/// use ant_quic::link_transport::{StreamFilter, StreamType};
///
/// // Accept only DHT streams
/// let filter = StreamFilter::new()
///     .with_types(StreamType::dht_types());
///
/// // Accept gossip and DHT
/// let filter = StreamFilter::new()
///     .with_type(StreamType::Membership)
///     .with_type(StreamType::DhtQuery);
/// ```
#[derive(Debug, Clone, Default)]
pub struct StreamFilter {
    /// Allowed stream types. Empty means accept all.
    allowed: HashSet<StreamType>,
}

impl StreamFilter {
    /// Create a new empty filter (accepts all types).
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a filter that accepts all stream types.
    pub fn accept_all() -> Self {
        let mut filter = Self::new();
        for st in StreamType::all_types() {
            filter.allowed.insert(*st);
        }
        filter
    }

    /// Create a filter for gossip streams only.
    pub fn gossip_only() -> Self {
        Self::new().with_types(StreamType::gossip_types())
    }

    /// Create a filter for DHT streams only.
    pub fn dht_only() -> Self {
        Self::new().with_types(StreamType::dht_types())
    }

    /// Create a filter for WebRTC streams only.
    pub fn webrtc_only() -> Self {
        Self::new().with_types(StreamType::webrtc_types())
    }

    /// Add a single stream type to the filter.
    pub fn with_type(mut self, stream_type: StreamType) -> Self {
        self.allowed.insert(stream_type);
        self
    }

    /// Add multiple stream types to the filter.
    pub fn with_types(mut self, stream_types: &[StreamType]) -> Self {
        for st in stream_types {
            self.allowed.insert(*st);
        }
        self
    }

    /// Check if a stream type is accepted by this filter.
    pub fn accepts(&self, stream_type: StreamType) -> bool {
        self.allowed.is_empty() || self.allowed.contains(&stream_type)
    }

    /// Check if this filter accepts any type (is empty).
    pub fn accepts_all(&self) -> bool {
        self.allowed.is_empty()
    }

    /// Get the set of allowed types.
    pub fn allowed_types(&self) -> &HashSet<StreamType> {
        &self.allowed
    }
}

// ============================================================================
// Protocol Identifier
// ============================================================================

/// Protocol identifier for multiplexing multiple overlays on a single transport.
///
/// Protocols are identified by a 16-byte value, allowing efficient binary comparison
/// while supporting human-readable names during debugging.
///
/// # Examples
///
/// ```rust
/// use ant_quic::link_transport::ProtocolId;
///
/// // From a static string (padded/truncated to 16 bytes)
/// const DHT: ProtocolId = ProtocolId::from_static(b"saorsa-dht/1.0.0");
///
/// // From bytes
/// let proto = ProtocolId::new([0x73, 0x61, 0x6f, 0x72, 0x73, 0x61, 0x2d, 0x64,
///                              0x68, 0x74, 0x2f, 0x31, 0x2e, 0x30, 0x2e, 0x30]);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProtocolId(pub [u8; 16]);

impl ProtocolId {
    /// Create a new protocol ID from raw bytes.
    #[inline]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Create a protocol ID from a static byte string.
    ///
    /// The string is padded with zeros if shorter than 16 bytes,
    /// or truncated if longer.
    #[inline]
    pub const fn from_static(s: &[u8]) -> Self {
        let mut bytes = [0u8; 16];
        let len = if s.len() < 16 { s.len() } else { 16 };
        let mut i = 0;
        while i < len {
            bytes[i] = s[i];
            i += 1;
        }
        Self(bytes)
    }

    /// Get the raw bytes of this protocol ID.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// The default protocol for connections without explicit protocol negotiation.
    pub const DEFAULT: Self = Self::from_static(b"ant-quic/default");

    /// Protocol ID for NAT traversal coordination messages.
    pub const NAT_TRAVERSAL: Self = Self::from_static(b"ant-quic/nat");

    /// Protocol ID for relay traffic.
    pub const RELAY: Self = Self::from_static(b"ant-quic/relay");
}

impl Default for ProtocolId {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl fmt::Debug for ProtocolId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Try to display as UTF-8 string, trimming null bytes
        let end = self.0.iter().position(|&b| b == 0).unwrap_or(16);
        if let Ok(s) = std::str::from_utf8(&self.0[..end]) {
            write!(f, "ProtocolId({:?})", s)
        } else {
            write!(f, "ProtocolId({:?})", hex::encode(self.0))
        }
    }
}

impl fmt::Display for ProtocolId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let end = self.0.iter().position(|&b| b == 0).unwrap_or(16);
        if let Ok(s) = std::str::from_utf8(&self.0[..end]) {
            write!(f, "{}", s)
        } else {
            write!(f, "{}", hex::encode(self.0))
        }
    }
}

impl From<&str> for ProtocolId {
    fn from(s: &str) -> Self {
        Self::from_static(s.as_bytes())
    }
}

impl From<[u8; 16]> for ProtocolId {
    fn from(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

// ============================================================================
// Peer Capabilities
// ============================================================================

/// NAT type classification hint for connection strategy selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum NatHint {
    /// No NAT detected (public IP, direct connectivity)
    None,
    /// Full cone NAT (easiest to traverse)
    FullCone,
    /// Address-restricted cone NAT
    AddressRestrictedCone,
    /// Port-restricted cone NAT
    PortRestrictedCone,
    /// Symmetric NAT (hardest to traverse, may require relay)
    Symmetric,
    /// Unknown NAT type
    #[default]
    Unknown,
}

/// Capabilities and quality metrics for a connected peer.
///
/// This struct captures both static capabilities (what the peer can do)
/// and dynamic metrics (how well the peer is performing).
#[derive(Debug, Clone)]
pub struct Capabilities {
    /// Whether this peer can relay traffic for NAT traversal.
    pub supports_relay: bool,

    /// Whether this peer can coordinate NAT hole-punching.
    pub supports_coordination: bool,

    /// Observed external addresses for this peer.
    pub observed_addrs: Vec<SocketAddr>,

    /// Protocols this peer advertises support for.
    pub protocols: Vec<ProtocolId>,

    /// Last time we successfully communicated with this peer.
    pub last_seen: SystemTime,

    /// Median round-trip time in milliseconds (p50).
    pub rtt_ms_p50: u32,

    /// Estimated RTT jitter in milliseconds.
    pub rtt_jitter_ms: u32,

    /// Packet loss rate (0.0 to 1.0).
    pub packet_loss: f32,

    /// Inferred NAT type for connection strategy hints.
    pub nat_type_hint: Option<NatHint>,

    /// Peer's advertised bandwidth limit (bytes/sec), if any.
    pub bandwidth_limit: Option<u64>,

    /// Number of successful connections to this peer.
    pub successful_connections: u32,

    /// Number of failed connection attempts to this peer.
    pub failed_connections: u32,

    /// Whether this peer is currently connected.
    pub is_connected: bool,
}

impl Default for Capabilities {
    fn default() -> Self {
        Self {
            supports_relay: false,
            supports_coordination: false,
            observed_addrs: Vec::new(),
            protocols: Vec::new(),
            last_seen: SystemTime::UNIX_EPOCH,
            rtt_ms_p50: 0,
            rtt_jitter_ms: 0,
            packet_loss: 0.0,
            nat_type_hint: None,
            bandwidth_limit: None,
            successful_connections: 0,
            failed_connections: 0,
            is_connected: false,
        }
    }
}

impl Capabilities {
    /// Create capabilities for a newly connected peer.
    pub fn new_connected(addr: SocketAddr) -> Self {
        Self {
            observed_addrs: vec![addr],
            last_seen: SystemTime::now(),
            is_connected: true,
            ..Default::default()
        }
    }

    /// Calculate a quality score for peer selection (0.0 to 1.0).
    ///
    /// Higher scores indicate better peers for connection.
    pub fn quality_score(&self) -> f32 {
        let mut score = 0.5; // Base score

        // RTT component (lower is better, max 300ms considered)
        let rtt_score = 1.0 - (self.rtt_ms_p50 as f32 / 300.0).min(1.0);
        score += rtt_score * 0.3;

        // Packet loss component
        let loss_score = 1.0 - self.packet_loss;
        score += loss_score * 0.2;

        // Connection success rate
        let total = self.successful_connections + self.failed_connections;
        if total > 0 {
            let success_rate = self.successful_connections as f32 / total as f32;
            score += success_rate * 0.2;
        }

        // Capability bonus
        if self.supports_relay {
            score += 0.05;
        }
        if self.supports_coordination {
            score += 0.05;
        }

        // NAT type penalty
        if let Some(nat) = self.nat_type_hint {
            match nat {
                NatHint::None | NatHint::FullCone => {}
                NatHint::AddressRestrictedCone | NatHint::PortRestrictedCone => {
                    score -= 0.05;
                }
                NatHint::Symmetric => {
                    score -= 0.15;
                }
                NatHint::Unknown => {
                    score -= 0.02;
                }
            }
        }

        score.clamp(0.0, 1.0)
    }

    /// Check if this peer supports a specific protocol.
    pub fn supports_protocol(&self, proto: &ProtocolId) -> bool {
        self.protocols.contains(proto)
    }
}

// ============================================================================
// Link Events
// ============================================================================

/// Reason for peer disconnection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisconnectReason {
    /// Clean shutdown initiated by local side.
    LocalClose,
    /// Clean shutdown initiated by remote side.
    RemoteClose,
    /// Connection timed out.
    Timeout,
    /// Transport error occurred.
    TransportError(String),
    /// Application-level error code.
    ApplicationError(u64),
    /// Connection was reset.
    Reset,
}

/// Events emitted by the link transport layer.
///
/// These events notify the overlay about significant transport-level changes.
#[derive(Debug, Clone)]
pub enum LinkEvent {
    /// A new peer has connected.
    PeerConnected {
        /// The connected peer's ID.
        peer: PeerId,
        /// Initial capabilities (may be updated later).
        caps: Capabilities,
    },

    /// A peer has disconnected.
    PeerDisconnected {
        /// The disconnected peer's ID.
        peer: PeerId,
        /// Reason for disconnection.
        reason: DisconnectReason,
    },

    /// Our observed external address has been updated.
    ExternalAddressUpdated {
        /// The new external address.
        addr: SocketAddr,
    },

    /// A peer's capabilities have been updated.
    CapabilityUpdated {
        /// The peer whose capabilities changed.
        peer: PeerId,
        /// Updated capabilities.
        caps: Capabilities,
    },

    /// A relay request has been received.
    RelayRequest {
        /// Peer requesting the relay.
        from: PeerId,
        /// Target peer for the relay.
        to: PeerId,
        /// Bytes remaining in relay budget.
        budget_bytes: u64,
    },

    /// A NAT traversal coordination request has been received.
    CoordinationRequest {
        /// First peer in the coordination.
        peer_a: PeerId,
        /// Second peer in the coordination.
        peer_b: PeerId,
        /// Coordination round number.
        round: u64,
    },

    /// The bootstrap cache has been updated.
    BootstrapCacheUpdated {
        /// Number of peers in the cache.
        peer_count: usize,
    },
}

// ============================================================================
// Link Transport Errors
// ============================================================================

/// Errors that can occur during link transport operations.
#[derive(Debug, Error, Clone)]
pub enum LinkError {
    /// The connection was closed.
    #[error("connection closed")]
    ConnectionClosed,

    /// Failed to establish connection.
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    /// The peer is not known/reachable.
    #[error("peer not found: {0}")]
    PeerNotFound(String),

    /// Protocol negotiation failed.
    #[error("protocol not supported: {0}")]
    ProtocolNotSupported(ProtocolId),

    /// A timeout occurred.
    #[error("operation timed out")]
    Timeout,

    /// The stream was reset by the peer.
    #[error("stream reset: error code {0}")]
    StreamReset(u64),

    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    Io(String),

    /// The transport is shutting down.
    #[error("transport shutdown")]
    Shutdown,

    /// Rate limit exceeded.
    #[error("rate limit exceeded")]
    RateLimited,

    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),

    /// Invalid stream type byte.
    #[error("invalid stream type byte: 0x{0:02x}")]
    InvalidStreamType(u8),

    /// Stream type not accepted by filter.
    #[error("stream type {0} not accepted")]
    StreamTypeFiltered(StreamType),
}

impl From<std::io::Error> for LinkError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

/// Result type for link transport operations.
pub type LinkResult<T> = Result<T, LinkError>;

// ============================================================================
// Link Connection Trait
// ============================================================================

/// A boxed future for async operations.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A boxed stream for async iteration.
pub type BoxStream<'a, T> = Pin<Box<dyn futures_util::Stream<Item = T> + Send + 'a>>;

/// A connection to a remote peer.
///
/// This trait abstracts a single QUIC connection, providing methods to
/// open streams and send/receive datagrams. Connections are obtained via
/// [`LinkTransport::dial`] or [`LinkTransport::accept`].
///
/// # Stream Types
///
/// - **Bidirectional streams** (`open_bi`): Both endpoints can send and receive.
///   Use for request/response patterns.
/// - **Unidirectional streams** (`open_uni`): Only the opener can send.
///   Use for notifications or one-way data transfer.
/// - **Datagrams** (`send_datagram`): Unreliable, unordered messages.
///   Use for real-time data where latency > reliability.
///
/// # Connection Lifecycle
///
/// 1. Connection established (via dial or accept)
/// 2. Open streams as needed
/// 3. Close gracefully with `close()` or let it drop
pub trait LinkConn: Send + Sync {
    /// Get the remote peer's cryptographic identity.
    ///
    /// This is stable across reconnections and network changes.
    fn peer(&self) -> PeerId;

    /// Get the remote peer's current network address.
    ///
    /// Note: This may change during the connection lifetime due to
    /// NAT rebinding or connection migration.
    fn remote_addr(&self) -> SocketAddr;

    /// Open a unidirectional stream (send only).
    ///
    /// The remote peer will receive this stream via their `accept_uni()`.
    /// Use for one-way messages like notifications or log streams.
    ///
    /// # Example
    /// ```rust,ignore
    /// let mut stream = conn.open_uni().await?;
    /// stream.write_all(b"notification").await?;
    /// stream.finish()?; // Signal end of stream
    /// ```
    fn open_uni(&self) -> BoxFuture<'_, LinkResult<Box<dyn LinkSendStream>>>;

    /// Open a bidirectional stream for request/response communication.
    ///
    /// Returns a (send, recv) pair. Both sides can write and read.
    /// Use for RPC, file transfers, or any interactive protocol.
    ///
    /// # Example
    /// ```rust,ignore
    /// let (mut send, mut recv) = conn.open_bi().await?;
    /// send.write_all(b"request").await?;
    /// send.finish()?;
    /// let response = recv.read_to_end(4096).await?;
    /// ```
    fn open_bi(
        &self,
    ) -> BoxFuture<'_, LinkResult<(Box<dyn LinkSendStream>, Box<dyn LinkRecvStream>)>>;

    /// Open a typed unidirectional stream.
    ///
    /// The stream type byte is automatically prepended to the stream.
    /// The remote peer should use `accept_uni_typed` to receive.
    ///
    /// # Example
    /// ```rust,ignore
    /// let mut stream = conn.open_uni_typed(StreamType::Membership).await?;
    /// stream.write_all(b"membership update").await?;
    /// stream.finish()?;
    /// ```
    fn open_uni_typed(
        &self,
        stream_type: StreamType,
    ) -> BoxFuture<'_, LinkResult<Box<dyn LinkSendStream>>>;

    /// Open a typed bidirectional stream.
    ///
    /// The stream type byte is automatically prepended to the stream.
    /// The remote peer should use `accept_bi_typed` to receive.
    ///
    /// # Example
    /// ```rust,ignore
    /// let (mut send, mut recv) = conn.open_bi_typed(StreamType::DhtQuery).await?;
    /// send.write_all(b"query request").await?;
    /// send.finish()?;
    /// let response = recv.read_to_end(4096).await?;
    /// ```
    fn open_bi_typed(
        &self,
        stream_type: StreamType,
    ) -> BoxFuture<'_, LinkResult<(Box<dyn LinkSendStream>, Box<dyn LinkRecvStream>)>>;

    /// Accept incoming unidirectional streams with type filtering.
    ///
    /// Returns a stream of (type, recv_stream) pairs for streams
    /// matching the filter. Use `StreamFilter::new()` to accept all types.
    ///
    /// # Example
    /// ```rust,ignore
    /// let filter = StreamFilter::gossip_only();
    /// let mut incoming = conn.accept_uni_typed(filter);
    /// while let Some(result) = incoming.next().await {
    ///     let (stream_type, recv) = result?;
    ///     println!("Got {} stream", stream_type);
    /// }
    /// ```
    fn accept_uni_typed(
        &self,
        filter: StreamFilter,
    ) -> BoxStream<'_, LinkResult<(StreamType, Box<dyn LinkRecvStream>)>>;

    /// Accept incoming bidirectional streams with type filtering.
    ///
    /// Returns a stream of (type, send_stream, recv_stream) tuples for
    /// streams matching the filter. Use `StreamFilter::new()` to accept all types.
    ///
    /// # Example
    /// ```rust,ignore
    /// let filter = StreamFilter::dht_only();
    /// let mut incoming = conn.accept_bi_typed(filter);
    /// while let Some(result) = incoming.next().await {
    ///     let (stream_type, send, recv) = result?;
    ///     // Handle DHT request/response
    /// }
    /// ```
    fn accept_bi_typed(
        &self,
        filter: StreamFilter,
    ) -> BoxStream<
        '_,
        LinkResult<(
            StreamType,
            Box<dyn LinkSendStream>,
            Box<dyn LinkRecvStream>,
        )>,
    >;

    /// Send an unreliable datagram to the peer.
    ///
    /// Datagrams are:
    /// - **Unreliable**: May be dropped without notification
    /// - **Unordered**: May arrive out of order
    /// - **Size-limited**: Must fit in a single QUIC packet (~1200 bytes)
    ///
    /// Use for heartbeats, metrics, or real-time data where occasional
    /// loss is acceptable.
    fn send_datagram(&self, data: Bytes) -> LinkResult<()>;

    /// Receive datagrams from the peer.
    ///
    /// Returns a stream of datagrams. Each datagram is delivered as-is
    /// (no framing). The stream ends when the connection closes.
    fn recv_datagrams(&self) -> BoxStream<'_, Bytes>;

    /// Close the connection gracefully.
    ///
    /// # Parameters
    /// - `error_code`: Application-defined error code (0 = normal close)
    /// - `reason`: Human-readable reason for debugging
    fn close(&self, error_code: u64, reason: &str);

    /// Check if the connection is still open.
    ///
    /// Returns false after the connection has been closed (locally or remotely)
    /// or if a fatal error occurred.
    fn is_open(&self) -> bool;

    /// Get current connection statistics.
    ///
    /// Useful for monitoring connection health and debugging performance.
    fn stats(&self) -> ConnectionStats;
}

/// Statistics for a connection.
///
/// Updated in real-time as the connection handles data. Use for:
/// - Monitoring connection health
/// - Detecting congestion (high RTT, packet loss)
/// - Debugging performance issues
///
/// # Typical Values
///
/// | Metric | Good | Concerning | Critical |
/// |--------|------|------------|----------|
/// | RTT | <50ms | 50-200ms | >500ms |
/// | Packet loss | <0.1% | 0.1-1% | >5% |
///
/// # Example
/// ```rust,ignore
/// let stats = conn.stats();
/// if stats.rtt > Duration::from_millis(200) {
///     log::warn!("High latency: {:?}", stats.rtt);
/// }
/// if stats.packets_lost > stats.bytes_sent / 100 {
///     log::warn!("Significant packet loss detected");
/// }
/// ```
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    /// Total bytes sent on this connection (including retransmits).
    pub bytes_sent: u64,
    /// Total bytes received on this connection.
    pub bytes_received: u64,
    /// Current smoothed round-trip time estimate.
    /// Calculated using QUIC's RTT estimation algorithm.
    pub rtt: Duration,
    /// How long this connection has been established.
    pub connected_duration: Duration,
    /// Total number of streams opened (bidirectional + unidirectional).
    pub streams_opened: u64,
    /// Estimated packets lost during transmission.
    /// High values indicate congestion or poor network conditions.
    pub packets_lost: u64,
}

/// A send stream for writing data to a peer.
pub trait LinkSendStream: Send + Sync {
    /// Write data to the stream.
    fn write<'a>(&'a mut self, data: &'a [u8]) -> BoxFuture<'a, LinkResult<usize>>;

    /// Write all data to the stream.
    fn write_all<'a>(&'a mut self, data: &'a [u8]) -> BoxFuture<'a, LinkResult<()>>;

    /// Finish the stream (signal end of data).
    fn finish(&mut self) -> LinkResult<()>;

    /// Reset the stream with an error code.
    fn reset(&mut self, error_code: u64) -> LinkResult<()>;

    /// Get the stream ID.
    fn id(&self) -> u64;
}

/// A receive stream for reading data from a peer.
pub trait LinkRecvStream: Send + Sync {
    /// Read data from the stream.
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, LinkResult<Option<usize>>>;

    /// Read all data until the stream ends.
    fn read_to_end(&mut self, size_limit: usize) -> BoxFuture<'_, LinkResult<Vec<u8>>>;

    /// Stop receiving data (signal we don't want more).
    fn stop(&mut self, error_code: u64) -> LinkResult<()>;

    /// Get the stream ID.
    fn id(&self) -> u64;
}

// ============================================================================
// Link Transport Trait
// ============================================================================

/// Incoming connection stream.
pub type Incoming<C> = BoxStream<'static, LinkResult<C>>;

/// The primary transport abstraction for overlay networks.
///
/// This trait provides everything an overlay needs to establish connections,
/// send/receive data, and monitor the transport layer.
///
/// # Implementation Notes
///
/// Implementors should:
/// - Handle NAT traversal transparently
/// - Maintain a peer table with capabilities
/// - Emit events for connection state changes
/// - Support protocol multiplexing
///
/// # Example Implementation
///
/// The default implementation wraps `P2pEndpoint`:
///
/// ```rust,ignore
/// let config = P2pConfig::builder()
///     .bind_addr("0.0.0.0:0".parse()?)
///     .build()?;
/// let endpoint = P2pEndpoint::new(config).await?;
/// let transport: Arc<dyn LinkTransport<Conn = P2pLinkConn>> = Arc::new(endpoint);
/// ```
pub trait LinkTransport: Send + Sync + 'static {
    /// The connection type returned by this transport.
    type Conn: LinkConn + 'static;

    /// Get our local peer identity.
    ///
    /// This is our stable cryptographic identity, derived from our key pair.
    /// It remains constant across restarts and network changes.
    fn local_peer(&self) -> PeerId;

    /// Get our externally observed address, if known.
    ///
    /// Returns the address other peers see when we connect to them.
    /// This is discovered via:
    /// - OBSERVED_ADDRESS frames from connected peers
    /// - NAT traversal address discovery
    ///
    /// Returns `None` if we haven't connected to any peers yet or
    /// if we're behind a symmetric NAT that changes our external port.
    fn external_address(&self) -> Option<SocketAddr>;

    /// Get all known peers with their capabilities.
    ///
    /// Includes:
    /// - Currently connected peers (`caps.is_connected = true`)
    /// - Previously connected peers still in bootstrap cache
    /// - Peers learned from relay/coordination traffic
    ///
    /// Use `Capabilities::quality_score()` to rank peers for selection.
    fn peer_table(&self) -> Vec<(PeerId, Capabilities)>;

    /// Get capabilities for a specific peer.
    ///
    /// Returns `None` if the peer is not known.
    fn peer_capabilities(&self, peer: &PeerId) -> Option<Capabilities>;

    /// Subscribe to transport-level events.
    ///
    /// Events include peer connections/disconnections, address changes,
    /// and capability updates. Use for maintaining overlay state.
    ///
    /// Multiple subscribers are supported via broadcast channel.
    fn subscribe(&self) -> broadcast::Receiver<LinkEvent>;

    /// Accept incoming connections for a specific protocol.
    ///
    /// Returns a stream of connections from peers that want to speak
    /// the specified protocol. Register your protocol first with
    /// `register_protocol()`.
    ///
    /// # Example
    /// ```rust,ignore
    /// let mut incoming = transport.accept(MY_PROTOCOL);
    /// while let Some(result) = incoming.next().await {
    ///     if let Ok(conn) = result {
    ///         tokio::spawn(handle_connection(conn));
    ///     }
    /// }
    /// ```
    fn accept(&self, proto: ProtocolId) -> Incoming<Self::Conn>;

    /// Dial a peer by their PeerId (preferred method).
    ///
    /// Uses the peer table to find known addresses for this peer.
    /// NAT traversal is handled automatically - if direct connection
    /// fails, coordination and hole-punching are attempted.
    ///
    /// # Errors
    /// - `PeerNotFound`: Peer not in table (need to bootstrap)
    /// - `ConnectionFailed`: Network error (may be transient)
    /// - `Timeout`: NAT traversal timed out (retry may succeed)
    fn dial(&self, peer: PeerId, proto: ProtocolId) -> BoxFuture<'_, LinkResult<Self::Conn>>;

    /// Dial a peer by direct address (for bootstrapping).
    ///
    /// Use when you don't know the peer's ID yet, such as when
    /// connecting to a known seed address to join the network.
    ///
    /// After connection, the peer's ID will be available via
    /// `conn.peer()`.
    fn dial_addr(
        &self,
        addr: SocketAddr,
        proto: ProtocolId,
    ) -> BoxFuture<'_, LinkResult<Self::Conn>>;

    /// Get protocols we advertise as supported.
    fn supported_protocols(&self) -> Vec<ProtocolId>;

    /// Register a protocol as supported.
    ///
    /// Call this before `accept()` to receive connections for the protocol.
    /// Registered protocols are advertised to connected peers.
    fn register_protocol(&self, proto: ProtocolId);

    /// Unregister a protocol.
    ///
    /// Stops accepting new connections for this protocol. Existing
    /// connections are not affected.
    fn unregister_protocol(&self, proto: ProtocolId);

    /// Check if we have an active connection to a peer.
    fn is_connected(&self, peer: &PeerId) -> bool;

    /// Get the count of active connections.
    fn active_connections(&self) -> usize;

    /// Gracefully shutdown the transport.
    ///
    /// Closes all connections, stops accepting new ones, and flushes
    /// the bootstrap cache to disk. Pending operations will complete
    /// or error.
    ///
    /// Call this before exiting to ensure clean shutdown.
    fn shutdown(&self) -> BoxFuture<'_, ()>;
}

// ============================================================================
// P2pEndpoint Implementation
// ============================================================================

// The implementation of LinkTransport for P2pEndpoint is in a separate file
// to keep this module focused on the trait definitions.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_id_from_string() {
        let proto = ProtocolId::from("saorsa-dht/1.0");
        assert_eq!(&proto.0[..14], b"saorsa-dht/1.0");
        assert_eq!(proto.0[14], 0);
        assert_eq!(proto.0[15], 0);
    }

    #[test]
    fn test_protocol_id_truncation() {
        let proto = ProtocolId::from("this-is-a-very-long-protocol-name");
        assert_eq!(&proto.0, b"this-is-a-very-l");
    }

    #[test]
    fn test_protocol_id_display() {
        let proto = ProtocolId::from("test/1.0");
        assert_eq!(format!("{}", proto), "test/1.0");
    }

    #[test]
    fn test_capabilities_quality_score() {
        let mut caps = Capabilities::default();

        // Default has perfect RTT (0ms) and no packet loss, so score should be high
        // Score = 0.5 (base) + 0.3 (RTT: 1.0*0.3) + 0.2 (loss: 1.0*0.2) = 1.0
        let base_score = caps.quality_score();
        assert!(
            (0.9..=1.0).contains(&base_score),
            "base_score = {}",
            base_score
        );

        // Worse RTT should reduce score
        caps.rtt_ms_p50 = 150; // 50% of max
        let worse_rtt_score = caps.quality_score();
        assert!(
            worse_rtt_score < base_score,
            "worse RTT should reduce score"
        );

        // Very bad RTT should reduce score more
        caps.rtt_ms_p50 = 500;
        let bad_rtt_score = caps.quality_score();
        assert!(
            bad_rtt_score < worse_rtt_score,
            "bad RTT should reduce score more"
        );

        // Symmetric NAT should reduce score
        caps.rtt_ms_p50 = 50;
        caps.nat_type_hint = Some(NatHint::Symmetric);
        let nat_score = caps.quality_score();
        // Reset RTT for fair comparison
        caps.nat_type_hint = None;
        caps.rtt_ms_p50 = 50;
        let no_nat_score = caps.quality_score();
        assert!(
            nat_score < no_nat_score,
            "symmetric NAT should reduce score"
        );
    }

    #[test]
    fn test_capabilities_supports_protocol() {
        let mut caps = Capabilities::default();
        let dht = ProtocolId::from("dht/1.0");
        let gossip = ProtocolId::from("gossip/1.0");

        caps.protocols.push(dht);

        assert!(caps.supports_protocol(&dht));
        assert!(!caps.supports_protocol(&gossip));
    }

    // =========================================================================
    // Stream Type Tests
    // =========================================================================

    #[test]
    fn test_stream_type_bytes() {
        assert_eq!(StreamType::Membership.as_byte(), 0x00);
        assert_eq!(StreamType::PubSub.as_byte(), 0x01);
        assert_eq!(StreamType::GossipBulk.as_byte(), 0x02);
        assert_eq!(StreamType::DhtQuery.as_byte(), 0x10);
        assert_eq!(StreamType::DhtStore.as_byte(), 0x11);
        assert_eq!(StreamType::DhtWitness.as_byte(), 0x12);
        assert_eq!(StreamType::DhtReplication.as_byte(), 0x13);
        assert_eq!(StreamType::WebRtcSignal.as_byte(), 0x20);
        assert_eq!(StreamType::WebRtcMedia.as_byte(), 0x21);
        assert_eq!(StreamType::WebRtcData.as_byte(), 0x22);
        assert_eq!(StreamType::Reserved.as_byte(), 0xF0);
    }

    #[test]
    fn test_stream_type_from_byte() {
        assert_eq!(StreamType::from_byte(0x00), Some(StreamType::Membership));
        assert_eq!(StreamType::from_byte(0x10), Some(StreamType::DhtQuery));
        assert_eq!(StreamType::from_byte(0x20), Some(StreamType::WebRtcSignal));
        assert_eq!(StreamType::from_byte(0xF0), Some(StreamType::Reserved));
        assert_eq!(StreamType::from_byte(0x99), None); // Unassigned
        assert_eq!(StreamType::from_byte(0xFF), None); // Unassigned
    }

    #[test]
    fn test_stream_type_families() {
        assert!(StreamType::Membership.is_gossip());
        assert!(StreamType::PubSub.is_gossip());
        assert!(StreamType::GossipBulk.is_gossip());

        assert!(StreamType::DhtQuery.is_dht());
        assert!(StreamType::DhtStore.is_dht());
        assert!(StreamType::DhtWitness.is_dht());
        assert!(StreamType::DhtReplication.is_dht());

        assert!(StreamType::WebRtcSignal.is_webrtc());
        assert!(StreamType::WebRtcMedia.is_webrtc());
        assert!(StreamType::WebRtcData.is_webrtc());
    }

    #[test]
    fn test_stream_type_family_ranges() {
        assert!(StreamTypeFamily::Gossip.contains(0x00));
        assert!(StreamTypeFamily::Gossip.contains(0x0F));
        assert!(!StreamTypeFamily::Gossip.contains(0x10));

        assert!(StreamTypeFamily::Dht.contains(0x10));
        assert!(StreamTypeFamily::Dht.contains(0x1F));
        assert!(!StreamTypeFamily::Dht.contains(0x20));

        assert!(StreamTypeFamily::WebRtc.contains(0x20));
        assert!(StreamTypeFamily::WebRtc.contains(0x2F));
        assert!(!StreamTypeFamily::WebRtc.contains(0x30));
    }

    #[test]
    fn test_stream_filter_accepts() {
        let filter = StreamFilter::new()
            .with_type(StreamType::Membership)
            .with_type(StreamType::DhtQuery);

        assert!(filter.accepts(StreamType::Membership));
        assert!(filter.accepts(StreamType::DhtQuery));
        assert!(!filter.accepts(StreamType::PubSub));
        assert!(!filter.accepts(StreamType::WebRtcMedia));
    }

    #[test]
    fn test_stream_filter_empty_accepts_all() {
        let filter = StreamFilter::new();
        assert!(filter.accepts_all());
        assert!(filter.accepts(StreamType::Membership));
        assert!(filter.accepts(StreamType::DhtQuery));
        assert!(filter.accepts(StreamType::WebRtcMedia));
    }

    #[test]
    fn test_stream_filter_presets() {
        let gossip = StreamFilter::gossip_only();
        assert!(gossip.accepts(StreamType::Membership));
        assert!(gossip.accepts(StreamType::PubSub));
        assert!(gossip.accepts(StreamType::GossipBulk));
        assert!(!gossip.accepts(StreamType::DhtQuery));

        let dht = StreamFilter::dht_only();
        assert!(dht.accepts(StreamType::DhtQuery));
        assert!(dht.accepts(StreamType::DhtStore));
        assert!(!dht.accepts(StreamType::Membership));

        let webrtc = StreamFilter::webrtc_only();
        assert!(webrtc.accepts(StreamType::WebRtcSignal));
        assert!(webrtc.accepts(StreamType::WebRtcMedia));
        assert!(!webrtc.accepts(StreamType::DhtQuery));
    }

    #[test]
    fn test_stream_type_display() {
        assert_eq!(format!("{}", StreamType::Membership), "Membership");
        assert_eq!(format!("{}", StreamType::DhtQuery), "DhtQuery");
        assert_eq!(format!("{}", StreamType::WebRtcMedia), "WebRtcMedia");
    }
}
