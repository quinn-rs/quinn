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
//! ## Example
//!
//! ```rust,ignore
//! use ant_quic::link_transport::{LinkTransport, LinkConn, ProtocolId};
//!
//! // Define your overlay's protocol
//! const DHT_PROTOCOL: ProtocolId = ProtocolId::from_static(b"saorsa-dht/1.0.0");
//!
//! async fn run_overlay<T: LinkTransport>(transport: T) -> anyhow::Result<()> {
//!     // Accept incoming connections for our protocol
//!     let mut incoming = transport.accept(DHT_PROTOCOL);
//!     
//!     // Dial a peer
//!     let peer_id = /* ... */;
//!     let conn = transport.dial(peer_id, DHT_PROTOCOL).await?;
//!     
//!     // Open a bidirectional stream
//!     let (send, recv) = conn.open_bi().await?;
//!     
//!     Ok(())
//! }
//! ```

use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use thiserror::Error;
use tokio::sync::broadcast;

use crate::nat_traversal_api::PeerId;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    Unknown,
}

impl Default for NatHint {
    fn default() -> Self {
        Self::Unknown
    }
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
/// open streams and send/receive datagrams.
pub trait LinkConn: Send + Sync {
    /// Get the remote peer's ID.
    fn peer(&self) -> PeerId;

    /// Get the remote peer's address.
    fn remote_addr(&self) -> SocketAddr;

    /// Open a unidirectional stream (send only).
    fn open_uni(&self) -> BoxFuture<'_, LinkResult<Box<dyn LinkSendStream>>>;

    /// Open a bidirectional stream.
    fn open_bi(&self) -> BoxFuture<'_, LinkResult<(Box<dyn LinkSendStream>, Box<dyn LinkRecvStream>)>>;

    /// Send an unreliable datagram to the peer.
    fn send_datagram(&self, data: Bytes) -> LinkResult<()>;

    /// Receive datagrams from the peer.
    fn recv_datagrams(&self) -> BoxStream<'_, Bytes>;

    /// Close the connection with an error code.
    fn close(&self, error_code: u64, reason: &str);

    /// Check if the connection is still open.
    fn is_open(&self) -> bool;

    /// Get connection statistics.
    fn stats(&self) -> ConnectionStats;
}

/// Statistics for a connection.
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    /// Bytes sent on this connection.
    pub bytes_sent: u64,
    /// Bytes received on this connection.
    pub bytes_received: u64,
    /// Current round-trip time estimate.
    pub rtt: Duration,
    /// Connection uptime.
    pub connected_duration: Duration,
    /// Number of streams opened.
    pub streams_opened: u64,
    /// Packets lost (estimated).
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
/// The default implementation wraps [`P2pEndpoint`]:
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

    /// Get our local peer ID.
    fn local_peer(&self) -> PeerId;

    /// Get our observed external address (if known).
    fn external_address(&self) -> Option<SocketAddr>;

    /// Get the current peer table with capabilities.
    ///
    /// This returns all known peers, including disconnected ones
    /// that are still in the bootstrap cache.
    fn peer_table(&self) -> Vec<(PeerId, Capabilities)>;

    /// Get capabilities for a specific peer.
    fn peer_capabilities(&self, peer: &PeerId) -> Option<Capabilities>;

    /// Subscribe to transport events.
    fn subscribe(&self) -> broadcast::Receiver<LinkEvent>;

    /// Accept incoming connections for a specific protocol.
    fn accept(&self, proto: ProtocolId) -> Incoming<Self::Conn>;

    /// Dial a peer to establish a connection.
    ///
    /// This may involve NAT traversal, which is handled transparently.
    fn dial(&self, peer: PeerId, proto: ProtocolId) -> BoxFuture<'_, LinkResult<Self::Conn>>;

    /// Dial a peer by address (for bootstrap).
    fn dial_addr(&self, addr: SocketAddr, proto: ProtocolId) -> BoxFuture<'_, LinkResult<Self::Conn>>;

    /// Get the list of protocols we support.
    fn supported_protocols(&self) -> Vec<ProtocolId>;

    /// Register a protocol as supported.
    fn register_protocol(&self, proto: ProtocolId);

    /// Unregister a protocol.
    fn unregister_protocol(&self, proto: ProtocolId);

    /// Check if we're connected to a peer.
    fn is_connected(&self, peer: &PeerId) -> bool;

    /// Get the number of active connections.
    fn active_connections(&self) -> usize;

    /// Gracefully shutdown the transport.
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
        assert!((0.9..=1.0).contains(&base_score), "base_score = {}", base_score);

        // Worse RTT should reduce score
        caps.rtt_ms_p50 = 150; // 50% of max
        let worse_rtt_score = caps.quality_score();
        assert!(worse_rtt_score < base_score, "worse RTT should reduce score");

        // Very bad RTT should reduce score more
        caps.rtt_ms_p50 = 500;
        let bad_rtt_score = caps.quality_score();
        assert!(bad_rtt_score < worse_rtt_score, "bad RTT should reduce score more");

        // Symmetric NAT should reduce score
        caps.rtt_ms_p50 = 50;
        caps.nat_type_hint = Some(NatHint::Symmetric);
        let nat_score = caps.quality_score();
        // Reset RTT for fair comparison
        caps.nat_type_hint = None;
        caps.rtt_ms_p50 = 50;
        let no_nat_score = caps.quality_score();
        assert!(nat_score < no_nat_score, "symmetric NAT should reduce score");
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
}
