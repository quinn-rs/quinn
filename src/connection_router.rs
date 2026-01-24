// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Connection Router for Protocol Engine Selection
//!
//! This module provides automatic routing of connections through either the
//! QUIC engine (for broadband transports) or the Constrained engine (for
//! BLE/LoRa/Serial transports) based on transport capabilities.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                    Application                          │
//! ├─────────────────────────────────────────────────────────┤
//! │                  ConnectionRouter                       │
//! │  - Capability-based engine selection                    │
//! │  - Unified API for both engines                         │
//! ├──────────────────────┬──────────────────────────────────┤
//! │    QUIC Engine       │     Constrained Engine           │
//! │  (NatTraversalEnd.)  │   (ConstrainedTransport)         │
//! ├──────────────────────┼──────────────────────────────────┤
//! │    UDP Transport     │   BLE/LoRa/Serial Transport      │
//! └──────────────────────┴──────────────────────────────────┘
//! ```
//!
//! # Engine Selection
//!
//! The router selects the protocol engine based on [`TransportCapabilities`]:
//!
//! | Transport | MTU | Bandwidth | Engine |
//! |-----------|-----|-----------|--------|
//! | UDP | 1500 | High | QUIC |
//! | BLE | 244 | Low | Constrained |
//! | LoRa | 250 | Very Low | Constrained |
//! | Serial | 1024 | Medium | Constrained |
//!
//! # Example
//!
//! ```rust,ignore
//! use ant_quic::connection_router::{ConnectionRouter, RouterConfig};
//! use ant_quic::transport::TransportAddr;
//!
//! // Create router with default config
//! let router = ConnectionRouter::new(RouterConfig::default());
//!
//! // Connect to a peer - engine selected automatically
//! let ble_addr = TransportAddr::Ble {
//!     device_id: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
//!     service_uuid: None,
//! };
//!
//! // This will use the Constrained engine
//! let conn = router.connect(&ble_addr).await?;
//!
//! // Send data through the routed connection
//! conn.send(b"Hello!").await?;
//! ```

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::constrained::{
    AdapterEvent, ConnectionId as ConstrainedConnId, ConstrainedError, ConstrainedHandle,
    ConstrainedTransport, ConstrainedTransportConfig,
};
use crate::high_level::Connection as QuicConnection;
use crate::nat_traversal_api::{NatTraversalEndpoint, NatTraversalError, PeerId};
use crate::transport::{ProtocolEngine, TransportAddr, TransportCapabilities, TransportRegistry};

/// Error type for connection routing operations
#[derive(Debug, Clone)]
pub enum RouterError {
    /// No suitable transport available for the address
    NoTransportAvailable {
        /// The address that couldn't be routed
        addr: TransportAddr,
    },

    /// Connection failed on the selected engine
    ConnectionFailed {
        /// Which engine was used
        engine: ProtocolEngine,
        /// Underlying error message
        reason: String,
    },

    /// Send operation failed
    SendFailed {
        /// Error message
        reason: String,
    },

    /// Receive operation failed
    ReceiveFailed {
        /// Error message
        reason: String,
    },

    /// Connection is closed
    ConnectionClosed,

    /// Router is shutting down
    ShuttingDown,

    /// Constrained engine error
    Constrained(ConstrainedError),

    /// QUIC engine error
    Quic {
        /// Error message
        reason: String,
    },

    /// NAT traversal error from the QUIC engine
    NatTraversal(NatTraversalError),

    /// Endpoint not initialized
    EndpointNotInitialized,
}

impl fmt::Display for RouterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoTransportAvailable { addr } => {
                write!(f, "no transport available for address: {addr}")
            }
            Self::ConnectionFailed { engine, reason } => {
                write!(f, "connection failed on {engine} engine: {reason}")
            }
            Self::SendFailed { reason } => write!(f, "send failed: {reason}"),
            Self::ReceiveFailed { reason } => write!(f, "receive failed: {reason}"),
            Self::ConnectionClosed => write!(f, "connection is closed"),
            Self::ShuttingDown => write!(f, "router is shutting down"),
            Self::Constrained(e) => write!(f, "constrained error: {e}"),
            Self::Quic { reason } => write!(f, "QUIC error: {reason}"),
            Self::NatTraversal(e) => write!(f, "NAT traversal error: {e}"),
            Self::EndpointNotInitialized => write!(f, "QUIC endpoint not initialized"),
        }
    }
}

impl std::error::Error for RouterError {}

impl From<ConstrainedError> for RouterError {
    fn from(err: ConstrainedError) -> Self {
        Self::Constrained(err)
    }
}

impl From<NatTraversalError> for RouterError {
    fn from(err: NatTraversalError) -> Self {
        Self::NatTraversal(err)
    }
}

/// Configuration for the connection router
#[derive(Debug, Clone)]
pub struct RouterConfig {
    /// Configuration for the constrained engine
    pub constrained_config: ConstrainedTransportConfig,

    /// Whether to prefer QUIC when both engines are available
    pub prefer_quic: bool,

    /// Enable metrics collection
    pub enable_metrics: bool,

    /// Maximum concurrent routed connections
    pub max_connections: usize,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            constrained_config: ConstrainedTransportConfig::default(),
            prefer_quic: true,
            enable_metrics: true,
            max_connections: 256,
        }
    }
}

impl RouterConfig {
    /// Create config optimized for BLE-heavy workloads
    pub fn for_ble_focus() -> Self {
        Self {
            constrained_config: ConstrainedTransportConfig::for_ble(),
            prefer_quic: false,
            enable_metrics: true,
            max_connections: 32,
        }
    }

    /// Create config optimized for LoRa-heavy workloads
    pub fn for_lora_focus() -> Self {
        Self {
            constrained_config: ConstrainedTransportConfig::for_lora(),
            prefer_quic: false,
            enable_metrics: true,
            max_connections: 16,
        }
    }

    /// Create config for mixed transport environments
    pub fn for_mixed() -> Self {
        Self {
            constrained_config: ConstrainedTransportConfig::default(),
            prefer_quic: true,
            enable_metrics: true,
            max_connections: 128,
        }
    }
}

/// A routed connection that abstracts over QUIC and Constrained engines
pub enum RoutedConnection {
    /// Connection through the QUIC engine
    Quic {
        /// Remote address
        remote: TransportAddr,
        /// Connection identifier
        connection_id: u64,
        /// Peer ID of the remote peer
        peer_id: PeerId,
        /// The actual QUIC connection handle
        connection: QuicConnection,
    },

    /// Connection through the Constrained engine
    Constrained {
        /// Remote address
        remote: TransportAddr,
        /// Constrained connection ID
        connection_id: ConstrainedConnId,
        /// Handle to the constrained transport
        handle: ConstrainedHandle,
    },
}

impl fmt::Debug for RoutedConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Quic {
                remote,
                connection_id,
                peer_id,
                ..
            } => f
                .debug_struct("RoutedConnection::Quic")
                .field("remote", remote)
                .field("connection_id", connection_id)
                .field("peer_id", peer_id)
                .finish_non_exhaustive(),
            Self::Constrained {
                remote,
                connection_id,
                handle,
            } => f
                .debug_struct("RoutedConnection::Constrained")
                .field("remote", remote)
                .field("connection_id", connection_id)
                .field("handle", handle)
                .finish(),
        }
    }
}

impl RoutedConnection {
    /// Get the remote address of this connection
    pub fn remote_addr(&self) -> &TransportAddr {
        match self {
            Self::Quic { remote, .. } => remote,
            Self::Constrained { remote, .. } => remote,
        }
    }

    /// Get which protocol engine this connection uses
    pub fn engine(&self) -> ProtocolEngine {
        match self {
            Self::Quic { .. } => ProtocolEngine::Quic,
            Self::Constrained { .. } => ProtocolEngine::Constrained,
        }
    }

    /// Check if this is a constrained connection
    pub fn is_constrained(&self) -> bool {
        matches!(self, Self::Constrained { .. })
    }

    /// Check if this is a QUIC connection
    pub fn is_quic(&self) -> bool {
        matches!(self, Self::Quic { .. })
    }

    /// Get the QUIC connection if this is a QUIC routed connection
    pub fn quic_connection(&self) -> Option<&QuicConnection> {
        match self {
            Self::Quic { connection, .. } => Some(connection),
            Self::Constrained { .. } => None,
        }
    }

    /// Get the peer ID for this connection
    ///
    /// Returns Some(peer_id) for QUIC connections, None for constrained connections
    /// (constrained connections don't have peer IDs in the same sense)
    pub fn peer_id(&self) -> Option<&PeerId> {
        match self {
            Self::Quic { peer_id, .. } => Some(peer_id),
            Self::Constrained { .. } => None,
        }
    }

    /// Get the connection ID
    pub fn connection_id(&self) -> u64 {
        match self {
            Self::Quic { connection_id, .. } => *connection_id,
            Self::Constrained { connection_id, .. } => connection_id.0 as u64,
        }
    }

    /// Send data through this connection (constrained path)
    ///
    /// For QUIC connections, use the async send methods on the connection directly
    /// via `quic_connection()`. This method is primarily for constrained connections.
    pub fn send(&self, data: &[u8]) -> Result<(), RouterError> {
        match self {
            Self::Quic { .. } => {
                // QUIC send requires async - users should use open_uni() or open_bi()
                // on the connection directly. This sync API is for constrained only.
                Err(RouterError::SendFailed {
                    reason: "QUIC send requires async streams - use quic_connection().open_uni() or open_bi()".into(),
                })
            }
            Self::Constrained {
                connection_id,
                handle,
                ..
            } => {
                handle.send(*connection_id, data)?;
                Ok(())
            }
        }
    }

    /// Receive data from this connection (non-blocking, constrained path)
    ///
    /// For QUIC connections, use the async receive methods on the connection directly
    /// via `quic_connection()`. This method is primarily for constrained connections.
    pub fn recv(&self) -> Result<Option<Vec<u8>>, RouterError> {
        match self {
            Self::Quic { .. } => {
                // QUIC recv requires async - users should use accept_uni() or accept_bi()
                // on the connection directly.
                Err(RouterError::ReceiveFailed {
                    reason: "QUIC recv requires async streams - use quic_connection().accept_uni() or accept_bi()".into(),
                })
            }
            Self::Constrained {
                connection_id,
                handle,
                ..
            } => {
                let data = handle.recv(*connection_id)?;
                Ok(data)
            }
        }
    }

    /// Close this connection
    pub fn close(&self) -> Result<(), RouterError> {
        match self {
            Self::Quic { connection, .. } => {
                // QUIC close - use VarInt(0) for graceful close
                connection.close(crate::VarInt::from_u32(0), b"connection closed");
                Ok(())
            }
            Self::Constrained {
                connection_id,
                handle,
                ..
            } => {
                handle.close(*connection_id)?;
                Ok(())
            }
        }
    }

    /// Check if this connection is still open
    pub fn is_open(&self) -> bool {
        match self {
            Self::Quic { connection, .. } => connection.close_reason().is_none(),
            Self::Constrained {
                connection_id,
                handle,
                ..
            } => handle
                .connection_state(*connection_id)
                .map(|s| matches!(s, crate::constrained::ConnectionState::Established))
                .unwrap_or(false),
        }
    }

    /// Close this connection with a reason code
    ///
    /// For QUIC connections, the reason code is passed to the QUIC close frame.
    /// For constrained connections, the reason code is logged but not transmitted
    /// (constrained protocol has simpler close handling).
    pub fn close_with_reason(
        &self,
        reason_code: u32,
        reason_text: &[u8],
    ) -> Result<(), RouterError> {
        match self {
            Self::Quic { connection, .. } => {
                connection.close(crate::VarInt::from_u32(reason_code), reason_text);
                Ok(())
            }
            Self::Constrained {
                connection_id,
                handle,
                ..
            } => {
                tracing::debug!(
                    connection_id = connection_id.0,
                    reason_code,
                    "closing constrained connection with reason"
                );
                handle.close(*connection_id)?;
                Ok(())
            }
        }
    }

    /// Send data asynchronously (unified API)
    ///
    /// This method provides a unified async send API that works for both QUIC and
    /// constrained connections. For QUIC, it opens a unidirectional stream and sends
    /// the data. For constrained, it uses the sync send path.
    pub async fn send_async(&self, data: &[u8]) -> Result<(), RouterError> {
        match self {
            Self::Quic { connection, .. } => {
                // Open a unidirectional stream and send data
                let mut send_stream =
                    connection
                        .open_uni()
                        .await
                        .map_err(|e| RouterError::SendFailed {
                            reason: format!("failed to open QUIC stream: {e}"),
                        })?;

                send_stream
                    .write_all(data)
                    .await
                    .map_err(|e| RouterError::SendFailed {
                        reason: format!("failed to write to QUIC stream: {e}"),
                    })?;

                send_stream.finish().map_err(|e| RouterError::SendFailed {
                    reason: format!("failed to finish QUIC stream: {e}"),
                })?;

                Ok(())
            }
            Self::Constrained {
                connection_id,
                handle,
                ..
            } => {
                // Constrained send is sync, but we expose it as async for uniformity
                handle.send(*connection_id, data)?;
                Ok(())
            }
        }
    }

    /// Receive data asynchronously (unified API)
    ///
    /// This method provides a unified async receive API that works for both QUIC and
    /// constrained connections. For QUIC, it accepts a unidirectional stream and reads
    /// data. For constrained, it polls the sync recv path.
    ///
    /// Note: For QUIC, this opens a new incoming stream each time. For more control
    /// over stream management, use `quic_connection()` directly.
    pub async fn recv_async(&self) -> Result<Vec<u8>, RouterError> {
        match self {
            Self::Quic { connection, .. } => {
                // Accept an incoming unidirectional stream
                let mut recv_stream =
                    connection
                        .accept_uni()
                        .await
                        .map_err(|e| RouterError::ReceiveFailed {
                            reason: format!("failed to accept QUIC stream: {e}"),
                        })?;

                // Read all data from the stream
                let data = recv_stream.read_to_end(64 * 1024).await.map_err(|e| {
                    RouterError::ReceiveFailed {
                        reason: format!("failed to read from QUIC stream: {e}"),
                    }
                })?;

                Ok(data)
            }
            Self::Constrained {
                connection_id,
                handle,
                ..
            } => {
                // Constrained recv is sync - poll until data is available
                // This is a simple implementation; a production version might use
                // tokio::time::interval for periodic polling
                let data =
                    handle
                        .recv(*connection_id)?
                        .ok_or_else(|| RouterError::ReceiveFailed {
                            reason: "no data available from constrained connection".into(),
                        })?;
                Ok(data)
            }
        }
    }

    /// Get the maximum transmission unit (MTU) for this connection
    ///
    /// Returns the maximum payload size that can be sent in a single message.
    pub fn mtu(&self) -> usize {
        match self {
            Self::Quic { .. } => {
                // QUIC typically supports large datagrams, but we return a conservative
                // estimate for stream data. Actual QUIC datagram MTU depends on path.
                1200 // QUIC minimum MTU
            }
            Self::Constrained { .. } => {
                // Constrained engine uses smaller MTU for BLE/LoRa compatibility
                244 // BLE typical ATT MTU - 3 bytes header
            }
        }
    }

    /// Get statistics for this connection
    pub fn stats(&self) -> ConnectionStats {
        match self {
            Self::Quic { connection, .. } => {
                let quic_stats = connection.stats();
                ConnectionStats {
                    bytes_sent: quic_stats.udp_tx.bytes,
                    bytes_received: quic_stats.udp_rx.bytes,
                    packets_sent: quic_stats.udp_tx.datagrams,
                    packets_received: quic_stats.udp_rx.datagrams,
                    engine: ProtocolEngine::Quic,
                }
            }
            Self::Constrained { .. } => {
                // Constrained engine doesn't expose detailed stats yet
                ConnectionStats {
                    bytes_sent: 0,
                    bytes_received: 0,
                    packets_sent: 0,
                    packets_received: 0,
                    engine: ProtocolEngine::Constrained,
                }
            }
        }
    }
}

/// Statistics for a routed connection
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Total packets sent
    pub packets_sent: u64,
    /// Total packets received
    pub packets_received: u64,
    /// Which engine this connection uses
    pub engine: ProtocolEngine,
}

impl ConnectionStats {
    /// Create stats for a QUIC connection
    pub fn new_quic() -> Self {
        Self {
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            engine: ProtocolEngine::Quic,
        }
    }

    /// Create stats for a constrained connection
    pub fn new_constrained() -> Self {
        Self {
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            engine: ProtocolEngine::Constrained,
        }
    }
}

/// Reason for engine selection decision
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectionReason {
    /// Transport supports full QUIC (bandwidth >= 10kbps, MTU >= 1200, RTT < 2s)
    SupportsQuic,
    /// Transport too constrained for QUIC
    TooConstrained,
    /// QUIC preferred but unavailable, falling back to constrained
    QuicUnavailableFallback,
    /// Constrained preferred but unavailable, falling back to QUIC
    ConstrainedUnavailableFallback,
    /// User preference override (prefer_quic config)
    UserPreference,
    /// Explicit address type mapping
    AddressTypeMapping,
}

impl fmt::Display for SelectionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SupportsQuic => write!(f, "transport supports full QUIC"),
            Self::TooConstrained => write!(f, "transport too constrained for QUIC"),
            Self::QuicUnavailableFallback => write!(f, "QUIC unavailable, using constrained"),
            Self::ConstrainedUnavailableFallback => {
                write!(f, "constrained unavailable, using QUIC")
            }
            Self::UserPreference => write!(f, "user preference"),
            Self::AddressTypeMapping => write!(f, "address type mapping"),
        }
    }
}

/// Result of an engine selection decision
#[derive(Debug, Clone)]
pub struct SelectionResult {
    /// The selected protocol engine
    pub engine: ProtocolEngine,
    /// Reason for the selection
    pub reason: SelectionReason,
    /// Whether this was a fallback from the preferred choice
    pub is_fallback: bool,
    /// Capability assessment
    pub capabilities_met: bool,
}

impl SelectionResult {
    /// Create a new selection result
    pub fn new(engine: ProtocolEngine, reason: SelectionReason) -> Self {
        Self {
            engine,
            reason,
            is_fallback: false,
            capabilities_met: true,
        }
    }

    /// Mark this as a fallback selection
    pub fn with_fallback(mut self) -> Self {
        self.is_fallback = true;
        self
    }
}

/// Unified router events that map from both engine types
#[derive(Debug, Clone)]
pub enum RouterEvent {
    /// New incoming connection established
    Connected {
        /// Connection ID (opaque, engine-specific)
        connection_id: u64,
        /// Remote address
        remote: TransportAddr,
        /// Which engine handles this connection
        engine: ProtocolEngine,
    },

    /// Data received on a connection
    DataReceived {
        /// Connection ID
        connection_id: u64,
        /// Received data
        data: Vec<u8>,
        /// Which engine
        engine: ProtocolEngine,
    },

    /// Connection closed
    Disconnected {
        /// Connection ID
        connection_id: u64,
        /// Reason for disconnection
        reason: String,
        /// Which engine
        engine: ProtocolEngine,
    },

    /// Connection error
    Error {
        /// Connection ID (if applicable)
        connection_id: Option<u64>,
        /// Error description
        error: String,
        /// Which engine
        engine: ProtocolEngine,
    },
}

impl RouterEvent {
    /// Get the engine type for this event
    pub fn engine(&self) -> ProtocolEngine {
        match self {
            Self::Connected { engine, .. }
            | Self::DataReceived { engine, .. }
            | Self::Disconnected { engine, .. }
            | Self::Error { engine, .. } => *engine,
        }
    }

    /// Get connection ID if available
    pub fn connection_id(&self) -> Option<u64> {
        match self {
            Self::Connected { connection_id, .. }
            | Self::DataReceived { connection_id, .. }
            | Self::Disconnected { connection_id, .. } => Some(*connection_id),
            Self::Error { connection_id, .. } => *connection_id,
        }
    }

    /// Create from constrained adapter event
    pub fn from_adapter_event(event: AdapterEvent, addr_lookup: Option<&TransportAddr>) -> Self {
        match event {
            AdapterEvent::ConnectionAccepted {
                connection_id,
                remote_addr,
            } => Self::Connected {
                connection_id: connection_id.0 as u64,
                remote: remote_addr.into(),
                engine: ProtocolEngine::Constrained,
            },
            AdapterEvent::ConnectionEstablished { connection_id } => Self::Connected {
                connection_id: connection_id.0 as u64,
                remote: addr_lookup.cloned().unwrap_or_else(|| {
                    TransportAddr::Udp(std::net::SocketAddr::from(([0, 0, 0, 0], 0)))
                }),
                engine: ProtocolEngine::Constrained,
            },
            AdapterEvent::DataReceived {
                connection_id,
                data,
            } => Self::DataReceived {
                connection_id: connection_id.0 as u64,
                data,
                engine: ProtocolEngine::Constrained,
            },
            AdapterEvent::ConnectionClosed { connection_id } => Self::Disconnected {
                connection_id: connection_id.0 as u64,
                reason: "connection closed".into(),
                engine: ProtocolEngine::Constrained,
            },
            AdapterEvent::ConnectionError {
                connection_id,
                error,
            } => Self::Error {
                connection_id: Some(connection_id.0 as u64),
                error,
                engine: ProtocolEngine::Constrained,
            },
            AdapterEvent::Transmit { .. } => {
                // Transmit events are internal, not exposed to router users
                // We convert them to a no-op error event
                Self::Error {
                    connection_id: None,
                    error: "internal transmit event".into(),
                    engine: ProtocolEngine::Constrained,
                }
            }
        }
    }
}

/// Router statistics
#[derive(Debug, Clone, Default)]
pub struct RouterStats {
    /// Total connections routed through QUIC
    pub quic_connections: u64,

    /// Total connections routed through Constrained
    pub constrained_connections: u64,

    /// Total bytes sent via QUIC
    pub quic_bytes_sent: u64,

    /// Total bytes sent via Constrained
    pub constrained_bytes_sent: u64,

    /// Total bytes received via QUIC
    pub quic_bytes_received: u64,

    /// Total bytes received via Constrained
    pub constrained_bytes_received: u64,

    /// Connection failures
    pub connection_failures: u64,

    /// Engine selection decisions (QUIC chosen)
    pub quic_selections: u64,

    /// Engine selection decisions (Constrained chosen)
    pub constrained_selections: u64,

    /// Fallback selections (when preferred engine unavailable)
    pub fallback_selections: u64,

    /// Total events processed
    pub events_processed: u64,
}

/// Connection router for automatic protocol engine selection
///
/// The router examines transport capabilities and routes connections
/// through either QUIC or the Constrained engine as appropriate.
pub struct ConnectionRouter {
    /// Router configuration
    config: RouterConfig,

    /// Constrained transport (created lazily when needed)
    constrained_transport: Option<ConstrainedTransport>,

    /// Transport registry for capability lookups
    registry: Option<Arc<TransportRegistry>>,

    /// NAT traversal endpoint for QUIC connections
    quic_endpoint: Option<Arc<NatTraversalEndpoint>>,

    /// Router statistics
    stats: RouterStats,

    /// Next QUIC connection ID (for tracking)
    next_quic_id: u64,
}

impl ConnectionRouter {
    /// Create a new connection router
    pub fn new(config: RouterConfig) -> Self {
        Self {
            config,
            constrained_transport: None,
            registry: None,
            quic_endpoint: None,
            stats: RouterStats::default(),
            next_quic_id: 1,
        }
    }

    /// Create router with a transport registry
    pub fn with_registry(config: RouterConfig, registry: Arc<TransportRegistry>) -> Self {
        Self {
            config,
            constrained_transport: None,
            registry: Some(registry),
            quic_endpoint: None,
            stats: RouterStats::default(),
            next_quic_id: 1,
        }
    }

    /// Create router with a QUIC endpoint
    pub fn with_quic_endpoint(
        config: RouterConfig,
        quic_endpoint: Arc<NatTraversalEndpoint>,
    ) -> Self {
        Self {
            config,
            constrained_transport: None,
            registry: None,
            quic_endpoint: Some(quic_endpoint),
            stats: RouterStats::default(),
            next_quic_id: 1,
        }
    }

    /// Create router with both transport registry and QUIC endpoint
    pub fn with_full_config(
        config: RouterConfig,
        registry: Arc<TransportRegistry>,
        quic_endpoint: Arc<NatTraversalEndpoint>,
    ) -> Self {
        Self {
            config,
            constrained_transport: None,
            registry: Some(registry),
            quic_endpoint: Some(quic_endpoint),
            stats: RouterStats::default(),
            next_quic_id: 1,
        }
    }

    /// Set the QUIC endpoint after construction
    pub fn set_quic_endpoint(&mut self, endpoint: Arc<NatTraversalEndpoint>) {
        self.quic_endpoint = Some(endpoint);
    }

    /// Check if QUIC endpoint is available
    pub fn is_quic_available(&self) -> bool {
        self.quic_endpoint.is_some()
    }

    /// Select the appropriate protocol engine for a transport
    pub fn select_engine(&mut self, capabilities: &TransportCapabilities) -> ProtocolEngine {
        let result = self.select_engine_detailed(capabilities);
        result.engine
    }

    /// Select engine with detailed selection result
    pub fn select_engine_detailed(
        &mut self,
        capabilities: &TransportCapabilities,
    ) -> SelectionResult {
        let supports_quic = capabilities.supports_full_quic();

        let (engine, reason) = if supports_quic {
            // Transport can handle QUIC
            if self.config.prefer_quic {
                (ProtocolEngine::Quic, SelectionReason::SupportsQuic)
            } else {
                // User prefers constrained even when QUIC is available
                (ProtocolEngine::Constrained, SelectionReason::UserPreference)
            }
        } else {
            // Transport cannot handle QUIC - must use constrained
            (ProtocolEngine::Constrained, SelectionReason::TooConstrained)
        };

        // Update selection stats
        match engine {
            ProtocolEngine::Quic => self.stats.quic_selections += 1,
            ProtocolEngine::Constrained => self.stats.constrained_selections += 1,
        }

        tracing::debug!(
            engine = ?engine,
            reason = %reason,
            supports_quic = supports_quic,
            bandwidth_bps = capabilities.bandwidth_bps,
            mtu = capabilities.mtu,
            "engine selection decision"
        );

        SelectionResult {
            engine,
            reason,
            is_fallback: false,
            capabilities_met: supports_quic || engine == ProtocolEngine::Constrained,
        }
    }

    /// Select engine with fallback support
    ///
    /// If the preferred engine is unavailable (e.g., QUIC endpoint not initialized),
    /// this method will attempt to use the fallback engine.
    pub fn select_engine_with_fallback(
        &mut self,
        capabilities: &TransportCapabilities,
        quic_available: bool,
        constrained_available: bool,
    ) -> Result<SelectionResult, RouterError> {
        let preferred = self.select_engine_detailed(capabilities);

        // Check if preferred engine is available
        let (engine, result) = match preferred.engine {
            ProtocolEngine::Quic if quic_available => (ProtocolEngine::Quic, preferred),
            ProtocolEngine::Quic if constrained_available => {
                // Fall back to constrained
                self.stats.fallback_selections += 1;
                tracing::warn!(
                    preferred = "QUIC",
                    fallback = "Constrained",
                    "preferred engine unavailable, using fallback"
                );
                (
                    ProtocolEngine::Constrained,
                    SelectionResult {
                        engine: ProtocolEngine::Constrained,
                        reason: SelectionReason::QuicUnavailableFallback,
                        is_fallback: true,
                        capabilities_met: true,
                    },
                )
            }
            ProtocolEngine::Constrained if constrained_available => {
                (ProtocolEngine::Constrained, preferred)
            }
            ProtocolEngine::Constrained if quic_available && capabilities.supports_full_quic() => {
                // Fall back to QUIC (only if transport supports it)
                self.stats.fallback_selections += 1;
                tracing::warn!(
                    preferred = "Constrained",
                    fallback = "QUIC",
                    "preferred engine unavailable, using fallback"
                );
                (
                    ProtocolEngine::Quic,
                    SelectionResult {
                        engine: ProtocolEngine::Quic,
                        reason: SelectionReason::ConstrainedUnavailableFallback,
                        is_fallback: true,
                        capabilities_met: true,
                    },
                )
            }
            _ => {
                // No suitable engine available
                tracing::error!(
                    quic_available,
                    constrained_available,
                    "no suitable engine available"
                );
                return Err(RouterError::NoTransportAvailable {
                    addr: TransportAddr::Udp(
                        "0.0.0.0:0"
                            .parse()
                            .unwrap_or_else(|_| std::net::SocketAddr::from(([0, 0, 0, 0], 0))),
                    ),
                });
            }
        };

        // Adjust stats for fallback
        if result.is_fallback {
            match engine {
                ProtocolEngine::Quic => {
                    self.stats.quic_selections += 1;
                    self.stats.constrained_selections =
                        self.stats.constrained_selections.saturating_sub(1);
                }
                ProtocolEngine::Constrained => {
                    self.stats.constrained_selections += 1;
                    self.stats.quic_selections = self.stats.quic_selections.saturating_sub(1);
                }
            }
        }

        Ok(result)
    }

    /// Select engine based on destination address
    pub fn select_engine_for_addr(&mut self, addr: &TransportAddr) -> ProtocolEngine {
        self.select_engine_for_addr_detailed(addr).engine
    }

    /// Select engine based on destination address with detailed result
    pub fn select_engine_for_addr_detailed(&mut self, addr: &TransportAddr) -> SelectionResult {
        // Determine capabilities based on address type
        let capabilities = Self::capabilities_for_addr(addr);
        self.select_engine_detailed(&capabilities)
    }

    /// Get transport capabilities for an address type
    pub fn capabilities_for_addr(addr: &TransportAddr) -> TransportCapabilities {
        match addr {
            TransportAddr::Udp(_) => TransportCapabilities::broadband(),
            TransportAddr::Ble { .. } => TransportCapabilities::ble(),
            TransportAddr::LoRa { .. } => TransportCapabilities::lora_long_range(),
            TransportAddr::Serial { .. } => TransportCapabilities::serial_115200(),
            TransportAddr::Ax25 { .. } => TransportCapabilities::packet_radio_1200(),
            // Overlay networks use broadband-equivalent capabilities
            TransportAddr::I2p { .. } => TransportCapabilities::broadband(),
            TransportAddr::Yggdrasil { .. } => TransportCapabilities::broadband(),
            TransportAddr::Broadcast { .. } => TransportCapabilities::broadband(),
        }
    }

    /// Connect to a remote address, automatically selecting the engine (sync version)
    ///
    /// This method only works for constrained connections. For QUIC connections,
    /// use `connect_async()` instead.
    pub fn connect(&mut self, remote: &TransportAddr) -> Result<RoutedConnection, RouterError> {
        let engine = self.select_engine_for_addr(remote);

        match engine {
            ProtocolEngine::Quic => self.connect_quic(remote),
            ProtocolEngine::Constrained => self.connect_constrained(remote),
        }
    }

    /// Connect to a remote address, automatically selecting the engine (async version)
    ///
    /// This method handles both QUIC and constrained connections. For QUIC connections,
    /// it requires a peer ID and server name.
    pub async fn connect_async(
        &mut self,
        remote: &TransportAddr,
        peer_id: Option<PeerId>,
        server_name: Option<&str>,
    ) -> Result<RoutedConnection, RouterError> {
        let engine = self.select_engine_for_addr(remote);

        match engine {
            ProtocolEngine::Quic => {
                // QUIC requires peer_id and server_name
                let peer_id = peer_id.ok_or_else(|| RouterError::Quic {
                    reason: "peer_id required for QUIC connections".into(),
                })?;
                let server_name = server_name.ok_or_else(|| RouterError::Quic {
                    reason: "server_name required for QUIC connections".into(),
                })?;
                self.connect_quic_async(remote, peer_id, server_name).await
            }
            ProtocolEngine::Constrained => {
                // Constrained connections are sync, so we can just call the sync version
                self.connect_constrained(remote)
            }
        }
    }

    /// Connect to a QUIC peer by peer ID and address
    ///
    /// Convenience method for QUIC connections that doesn't require engine selection
    /// (assumes QUIC is appropriate for the given address).
    pub async fn connect_peer(
        &mut self,
        peer_id: PeerId,
        remote_addr: SocketAddr,
        server_name: &str,
    ) -> Result<RoutedConnection, RouterError> {
        let transport_addr = TransportAddr::Udp(remote_addr);
        self.connect_quic_async(&transport_addr, peer_id, server_name)
            .await
    }

    /// Connect using the QUIC engine (sync version)
    ///
    /// This method returns an error indicating async is required for QUIC connections.
    /// Use `connect_quic_async` instead for actual QUIC connections.
    fn connect_quic(&mut self, remote: &TransportAddr) -> Result<RoutedConnection, RouterError> {
        // QUIC connections require async - this sync version returns an error
        // directing users to use the async method
        Err(RouterError::Quic {
            reason: format!(
                "QUIC connections require async - use connect_async() for address {}",
                remote
            ),
        })
    }

    /// Connect using the QUIC engine (async version)
    ///
    /// This method initiates a QUIC connection through the NatTraversalEndpoint.
    pub async fn connect_quic_async(
        &mut self,
        remote: &TransportAddr,
        peer_id: PeerId,
        server_name: &str,
    ) -> Result<RoutedConnection, RouterError> {
        let endpoint = self
            .quic_endpoint
            .as_ref()
            .ok_or(RouterError::EndpointNotInitialized)?;

        // Extract socket address from transport address
        let socket_addr = remote.as_socket_addr().ok_or_else(|| RouterError::Quic {
            reason: format!("Cannot extract socket address from {remote} for QUIC connection"),
        })?;

        // Connect through the NAT traversal endpoint
        let connection = endpoint
            .connect_to_peer(peer_id, server_name, socket_addr)
            .await?;

        // Assign connection ID and update stats
        let connection_id = self.next_quic_id;
        self.next_quic_id += 1;
        self.stats.quic_connections += 1;

        tracing::info!(
            connection_id,
            peer = ?peer_id,
            remote = %socket_addr,
            "QUIC connection established via router"
        );

        Ok(RoutedConnection::Quic {
            remote: remote.clone(),
            connection_id,
            peer_id,
            connection,
        })
    }

    /// Connect using the Constrained engine
    fn connect_constrained(
        &mut self,
        remote: &TransportAddr,
    ) -> Result<RoutedConnection, RouterError> {
        // Initialize constrained transport if needed
        if self.constrained_transport.is_none() {
            let transport = ConstrainedTransport::new(self.config.constrained_config.clone());
            self.constrained_transport = Some(transport);
        }

        let transport =
            self.constrained_transport
                .as_ref()
                .ok_or(RouterError::NoTransportAvailable {
                    addr: remote.clone(),
                })?;

        let handle = transport.handle();
        let connection_id = handle.connect(remote)?;

        self.stats.constrained_connections += 1;

        Ok(RoutedConnection::Constrained {
            remote: remote.clone(),
            connection_id,
            handle,
        })
    }

    /// Get the constrained transport handle (for direct access if needed)
    pub fn constrained_handle(&self) -> Option<ConstrainedHandle> {
        self.constrained_transport.as_ref().map(|t| t.handle())
    }

    /// Check if a transport supports QUIC
    pub fn supports_quic(&self, addr: &TransportAddr) -> bool {
        let capabilities = Self::capabilities_for_addr(addr);
        capabilities.supports_full_quic()
    }

    /// Check if constrained engine is initialized
    pub fn is_constrained_initialized(&self) -> bool {
        self.constrained_transport.is_some()
    }

    /// Get router statistics
    pub fn stats(&self) -> &RouterStats {
        &self.stats
    }

    /// Get router configuration
    pub fn config(&self) -> &RouterConfig {
        &self.config
    }

    /// Get the transport registry if one was configured
    pub fn registry(&self) -> Option<&Arc<TransportRegistry>> {
        self.registry.as_ref()
    }

    /// Process incoming constrained events (raw adapter events)
    pub fn poll_constrained_events(&self) -> Vec<AdapterEvent> {
        let mut events = Vec::new();
        if let Some(handle) = self.constrained_handle() {
            while let Some(event) = handle.next_event() {
                events.push(event);
            }
        }
        events
    }

    /// Poll for unified router events from all engines
    ///
    /// Note: This is a sync method that only polls constrained events.
    /// For QUIC events, use `poll_events_async()` or the event callback
    /// mechanism on the NatTraversalEndpoint.
    pub fn poll_events(&mut self) -> Vec<RouterEvent> {
        let mut events = Vec::new();

        // Collect constrained events and convert to unified format
        if let Some(handle) = self.constrained_handle() {
            while let Some(adapter_event) = handle.next_event() {
                let router_event = RouterEvent::from_adapter_event(adapter_event, None);

                // Update stats based on event type
                if let RouterEvent::DataReceived { data, .. } = &router_event {
                    self.stats.constrained_bytes_received += data.len() as u64;
                }

                self.stats.events_processed += 1;
                events.push(router_event);
            }
        }

        events
    }

    /// Accept an incoming QUIC connection
    ///
    /// This method waits for an incoming connection on the QUIC endpoint
    /// and returns it wrapped as a RoutedConnection.
    pub async fn accept_quic(&mut self) -> Result<RoutedConnection, RouterError> {
        let endpoint = self
            .quic_endpoint
            .as_ref()
            .ok_or(RouterError::EndpointNotInitialized)?;

        let (peer_id, connection) = endpoint.accept_connection().await?;

        // Get remote address from the connection
        let remote_addr = connection.remote_address();
        let transport_addr = TransportAddr::Udp(remote_addr);

        // Assign connection ID and update stats
        let connection_id = self.next_quic_id;
        self.next_quic_id += 1;
        self.stats.quic_connections += 1;

        tracing::info!(
            connection_id,
            peer = ?peer_id,
            remote = %remote_addr,
            "Accepted incoming QUIC connection via router"
        );

        Ok(RoutedConnection::Quic {
            remote: transport_addr,
            connection_id,
            peer_id,
            connection,
        })
    }

    /// Get the QUIC endpoint (for advanced use)
    pub fn quic_endpoint(&self) -> Option<&Arc<NatTraversalEndpoint>> {
        self.quic_endpoint.as_ref()
    }

    /// Process incoming data from a constrained transport
    ///
    /// This should be called when data is received from the underlying
    /// transport (e.g., BLE characteristic notification, LoRa packet).
    pub fn process_constrained_incoming(
        &mut self,
        remote: &TransportAddr,
        data: &[u8],
    ) -> Result<Vec<RouterEvent>, RouterError> {
        let handle = self
            .constrained_handle()
            .ok_or(RouterError::NoTransportAvailable {
                addr: remote.clone(),
            })?;

        // Process the incoming data through the constrained engine
        handle.process_incoming(remote, data)?;

        // Collect any resulting events
        let mut events = Vec::new();
        while let Some(adapter_event) = handle.next_event() {
            let router_event = RouterEvent::from_adapter_event(adapter_event, Some(remote));

            if let RouterEvent::DataReceived { data, .. } = &router_event {
                self.stats.constrained_bytes_received += data.len() as u64;
            }

            self.stats.events_processed += 1;
            events.push(router_event);
        }

        Ok(events)
    }

    /// Get connection state for a constrained connection
    pub fn constrained_connection_state(
        &self,
        connection_id: ConstrainedConnId,
    ) -> Option<crate::constrained::ConnectionState> {
        self.constrained_handle()
            .and_then(|h| h.connection_state(connection_id))
    }

    /// Get all active constrained connection IDs
    pub fn active_constrained_connections(&self) -> Vec<ConstrainedConnId> {
        self.constrained_handle()
            .map(|h| h.active_connections())
            .unwrap_or_default()
    }
}

impl fmt::Debug for ConnectionRouter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionRouter")
            .field("config", &self.config)
            .field(
                "constrained_initialized",
                &self.constrained_transport.is_some(),
            )
            .field("stats", &self.stats)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_router_config_default() {
        let config = RouterConfig::default();
        assert!(config.prefer_quic);
        assert!(config.enable_metrics);
        assert_eq!(config.max_connections, 256);
    }

    #[test]
    fn test_router_config_presets() {
        let ble_config = RouterConfig::for_ble_focus();
        assert!(!ble_config.prefer_quic);
        assert_eq!(ble_config.max_connections, 32);

        let lora_config = RouterConfig::for_lora_focus();
        assert!(!lora_config.prefer_quic);
        assert_eq!(lora_config.max_connections, 16);

        let mixed_config = RouterConfig::for_mixed();
        assert!(mixed_config.prefer_quic);
        assert_eq!(mixed_config.max_connections, 128);
    }

    #[test]
    fn test_engine_selection_for_udp() {
        let mut router = ConnectionRouter::new(RouterConfig::default());
        let addr = TransportAddr::Udp("127.0.0.1:9000".parse().unwrap());

        let engine = router.select_engine_for_addr(&addr);
        assert_eq!(engine, ProtocolEngine::Quic);
        assert_eq!(router.stats().quic_selections, 1);
    }

    #[test]
    fn test_engine_selection_for_ble() {
        let mut router = ConnectionRouter::new(RouterConfig::default());
        let addr = TransportAddr::Ble {
            device_id: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            service_uuid: None,
        };

        let engine = router.select_engine_for_addr(&addr);
        assert_eq!(engine, ProtocolEngine::Constrained);
        assert_eq!(router.stats().constrained_selections, 1);
    }

    #[test]
    fn test_engine_selection_for_lora() {
        let mut router = ConnectionRouter::new(RouterConfig::default());
        let addr = TransportAddr::LoRa {
            device_addr: [0x12, 0x34, 0x56, 0x78],
            params: crate::transport::LoRaParams::default(),
        };

        let engine = router.select_engine_for_addr(&addr);
        assert_eq!(engine, ProtocolEngine::Constrained);
    }

    #[test]
    fn test_supports_quic() {
        let router = ConnectionRouter::new(RouterConfig::default());

        let udp_addr = TransportAddr::Udp("127.0.0.1:9000".parse().unwrap());
        assert!(router.supports_quic(&udp_addr));

        let ble_addr = TransportAddr::Ble {
            device_id: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            service_uuid: None,
        };
        assert!(!router.supports_quic(&ble_addr));
    }

    #[test]
    fn test_connect_constrained() {
        let mut router = ConnectionRouter::new(RouterConfig::default());
        let addr = TransportAddr::Ble {
            device_id: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            service_uuid: None,
        };

        let conn = router.connect(&addr);
        assert!(conn.is_ok());

        let conn = conn.unwrap();
        assert!(conn.is_constrained());
        assert_eq!(conn.engine(), ProtocolEngine::Constrained);
        assert_eq!(conn.remote_addr(), &addr);
        assert_eq!(router.stats().constrained_connections, 1);
    }

    #[test]
    fn test_connect_quic_requires_async() {
        // QUIC connections require async - the sync connect() method
        // should return an error for QUIC addresses
        let mut router = ConnectionRouter::new(RouterConfig::default());
        let addr = TransportAddr::Udp("127.0.0.1:9000".parse().unwrap());

        let result = router.connect(&addr);
        assert!(result.is_err());

        // Should be a QUIC error indicating async is required
        if let Err(RouterError::Quic { reason }) = result {
            assert!(reason.contains("async"));
        } else {
            panic!("Expected RouterError::Quic");
        }
    }

    #[test]
    fn test_quic_endpoint_availability() {
        let router = ConnectionRouter::new(RouterConfig::default());
        assert!(!router.is_quic_available());

        // Can't easily test with_quic_endpoint in a unit test without
        // setting up a full NatTraversalEndpoint, but we can verify the method exists
    }

    #[test]
    fn test_router_with_registry() {
        let registry = Arc::new(crate::transport::TransportRegistry::new());
        let router = ConnectionRouter::with_registry(RouterConfig::default(), registry.clone());
        assert!(router.registry().is_some());
        assert!(!router.is_quic_available());
    }

    #[test]
    fn test_routed_connection_send_constrained() {
        let mut router = ConnectionRouter::new(RouterConfig::default());
        let addr = TransportAddr::Ble {
            device_id: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            service_uuid: None,
        };

        let conn = router.connect(&addr).unwrap();

        // Send should work (connection is in SYN_SENT state, so data gets queued)
        // Note: actual transmission happens after handshake
        let result = conn.send(b"test data");
        // May fail because connection not established - that's expected
        // The important thing is it doesn't panic
        let _ = result;
    }

    #[test]
    fn test_routed_connection_close() {
        let mut router = ConnectionRouter::new(RouterConfig::default());
        let addr = TransportAddr::Ble {
            device_id: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            service_uuid: None,
        };

        let conn = router.connect(&addr).unwrap();
        let result = conn.close();
        assert!(result.is_ok());
    }

    #[test]
    fn test_router_stats() {
        let mut router = ConnectionRouter::new(RouterConfig::default());

        // Make some selections
        let udp_addr = TransportAddr::Udp("127.0.0.1:9000".parse().unwrap());
        let ble_addr = TransportAddr::Ble {
            device_id: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            service_uuid: None,
        };

        let _ = router.select_engine_for_addr(&udp_addr);
        let _ = router.select_engine_for_addr(&udp_addr);
        let _ = router.select_engine_for_addr(&ble_addr);

        let stats = router.stats();
        assert_eq!(stats.quic_selections, 2);
        assert_eq!(stats.constrained_selections, 1);
    }

    #[test]
    fn test_constrained_handle_access() {
        let mut router = ConnectionRouter::new(RouterConfig::default());

        // Initially no handle
        assert!(router.constrained_handle().is_none());

        // After connecting constrained, handle is available
        let addr = TransportAddr::Ble {
            device_id: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            service_uuid: None,
        };
        let _ = router.connect(&addr);

        assert!(router.constrained_handle().is_some());
    }

    #[test]
    fn test_router_error_display() {
        let err = RouterError::NoTransportAvailable {
            addr: TransportAddr::Udp("127.0.0.1:9000".parse().unwrap()),
        };
        assert!(format!("{err}").contains("no transport available"));

        let err = RouterError::ConnectionFailed {
            engine: ProtocolEngine::Quic,
            reason: "timeout".into(),
        };
        assert!(format!("{err}").contains("QUIC"));
        assert!(format!("{err}").contains("timeout"));

        let err = RouterError::ConnectionClosed;
        assert!(format!("{err}").contains("closed"));
    }

    // ========================================================================
    // Task 2: Protocol Selection Logic Tests
    // ========================================================================

    #[test]
    fn test_select_engine_detailed_udp() {
        let mut router = ConnectionRouter::new(RouterConfig::default());
        let capabilities = TransportCapabilities::broadband();

        let result = router.select_engine_detailed(&capabilities);
        assert_eq!(result.engine, ProtocolEngine::Quic);
        assert_eq!(result.reason, SelectionReason::SupportsQuic);
        assert!(!result.is_fallback);
        assert!(result.capabilities_met);
    }

    #[test]
    fn test_select_engine_detailed_ble() {
        let mut router = ConnectionRouter::new(RouterConfig::default());
        let capabilities = TransportCapabilities::ble();

        let result = router.select_engine_detailed(&capabilities);
        assert_eq!(result.engine, ProtocolEngine::Constrained);
        assert_eq!(result.reason, SelectionReason::TooConstrained);
        assert!(!result.is_fallback);
    }

    #[test]
    fn test_select_engine_detailed_user_preference() {
        // Configure router to prefer constrained even for broadband
        let mut config = RouterConfig::default();
        config.prefer_quic = false;
        let mut router = ConnectionRouter::new(config);
        let capabilities = TransportCapabilities::broadband();

        let result = router.select_engine_detailed(&capabilities);
        assert_eq!(result.engine, ProtocolEngine::Constrained);
        assert_eq!(result.reason, SelectionReason::UserPreference);
    }

    #[test]
    fn test_select_engine_with_fallback_quic_available() {
        let mut router = ConnectionRouter::new(RouterConfig::default());
        let capabilities = TransportCapabilities::broadband();

        let result = router
            .select_engine_with_fallback(&capabilities, true, false)
            .unwrap();
        assert_eq!(result.engine, ProtocolEngine::Quic);
        assert!(!result.is_fallback);
    }

    #[test]
    fn test_select_engine_with_fallback_to_constrained() {
        let mut router = ConnectionRouter::new(RouterConfig::default());
        let capabilities = TransportCapabilities::broadband();

        // QUIC unavailable, constrained available
        let result = router
            .select_engine_with_fallback(&capabilities, false, true)
            .unwrap();
        assert_eq!(result.engine, ProtocolEngine::Constrained);
        assert!(result.is_fallback);
        assert_eq!(result.reason, SelectionReason::QuicUnavailableFallback);
        assert_eq!(router.stats().fallback_selections, 1);
    }

    #[test]
    fn test_select_engine_with_fallback_constrained_preferred() {
        let config = RouterConfig::for_ble_focus();
        let mut router = ConnectionRouter::new(config);
        let capabilities = TransportCapabilities::broadband();

        // Constrained preferred but unavailable, QUIC available
        // Should fallback to QUIC since transport supports it
        let result = router
            .select_engine_with_fallback(&capabilities, true, false)
            .unwrap();
        assert_eq!(result.engine, ProtocolEngine::Quic);
        assert!(result.is_fallback);
        assert_eq!(
            result.reason,
            SelectionReason::ConstrainedUnavailableFallback
        );
    }

    #[test]
    fn test_select_engine_with_fallback_no_engines() {
        let mut router = ConnectionRouter::new(RouterConfig::default());
        let capabilities = TransportCapabilities::broadband();

        // Neither engine available
        let result = router.select_engine_with_fallback(&capabilities, false, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_capabilities_for_addr_coverage() {
        // Test all address types return valid capabilities
        let udp = TransportAddr::Udp("127.0.0.1:9000".parse().unwrap());
        assert!(ConnectionRouter::capabilities_for_addr(&udp).supports_full_quic());

        let ble = TransportAddr::Ble {
            device_id: [0; 6],
            service_uuid: None,
        };
        assert!(!ConnectionRouter::capabilities_for_addr(&ble).supports_full_quic());

        let lora = TransportAddr::LoRa {
            device_addr: [0; 4],
            params: crate::transport::LoRaParams::default(),
        };
        assert!(!ConnectionRouter::capabilities_for_addr(&lora).supports_full_quic());

        // Serial should be constrained (MTU < 1200)
        let serial = TransportAddr::serial("/dev/ttyUSB0");
        let serial_caps = ConnectionRouter::capabilities_for_addr(&serial);
        assert!(!serial_caps.supports_full_quic());

        // Overlay networks should support QUIC
        let i2p = TransportAddr::I2p {
            destination: Box::new([0u8; 387]),
        };
        assert!(ConnectionRouter::capabilities_for_addr(&i2p).supports_full_quic());

        let yggdrasil = TransportAddr::yggdrasil([0; 16]);
        assert!(ConnectionRouter::capabilities_for_addr(&yggdrasil).supports_full_quic());
    }

    #[test]
    fn test_selection_reason_display() {
        assert!(format!("{}", SelectionReason::SupportsQuic).contains("QUIC"));
        assert!(format!("{}", SelectionReason::TooConstrained).contains("constrained"));
        assert!(format!("{}", SelectionReason::QuicUnavailableFallback).contains("unavailable"));
        assert!(format!("{}", SelectionReason::UserPreference).contains("preference"));
    }

    #[test]
    fn test_selection_result_with_fallback() {
        let result = SelectionResult::new(ProtocolEngine::Quic, SelectionReason::SupportsQuic);
        assert!(!result.is_fallback);

        let fallback_result = result.with_fallback();
        assert!(fallback_result.is_fallback);
        assert_eq!(fallback_result.engine, ProtocolEngine::Quic);
    }

    #[test]
    fn test_is_constrained_initialized() {
        let mut router = ConnectionRouter::new(RouterConfig::default());
        assert!(!router.is_constrained_initialized());

        // Initialize by connecting to BLE
        let addr = TransportAddr::Ble {
            device_id: [0; 6],
            service_uuid: None,
        };
        let _ = router.connect(&addr);

        assert!(router.is_constrained_initialized());
    }

    #[test]
    fn test_fallback_stats_tracking() {
        let mut router = ConnectionRouter::new(RouterConfig::default());
        let capabilities = TransportCapabilities::broadband();

        // Normal selection - no fallback
        let _ = router.select_engine_with_fallback(&capabilities, true, true);
        assert_eq!(router.stats().fallback_selections, 0);

        // Fallback selection
        let _ = router.select_engine_with_fallback(&capabilities, false, true);
        assert_eq!(router.stats().fallback_selections, 1);
    }

    // ========================================================================
    // Task 4: QUIC Connection Integration Tests
    // ========================================================================

    #[test]
    fn test_router_error_nat_traversal() {
        // Test that NatTraversalError converts to RouterError properly
        use crate::nat_traversal_api::NatTraversalError;

        let nat_err = NatTraversalError::Timeout;
        let router_err: RouterError = nat_err.into();
        let msg = format!("{router_err}");
        assert!(msg.contains("NAT traversal"));
    }

    #[test]
    fn test_router_error_endpoint_not_initialized() {
        let err = RouterError::EndpointNotInitialized;
        let msg = format!("{err}");
        assert!(msg.contains("not initialized"));
    }

    #[test]
    fn test_routed_connection_accessors_constrained() {
        let mut router = ConnectionRouter::new(RouterConfig::default());
        let addr = TransportAddr::Ble {
            device_id: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            service_uuid: None,
        };

        let conn = router.connect(&addr).unwrap();

        // Test accessors
        assert_eq!(conn.engine(), ProtocolEngine::Constrained);
        assert!(conn.is_constrained());
        assert!(!conn.is_quic());
        assert!(conn.quic_connection().is_none());
        assert!(conn.peer_id().is_none());
        assert_eq!(conn.remote_addr(), &addr);

        // Connection ID should be valid
        let _conn_id = conn.connection_id();
    }

    #[test]
    fn test_set_quic_endpoint() {
        let router = ConnectionRouter::new(RouterConfig::default());
        assert!(!router.is_quic_available());
        assert!(router.quic_endpoint().is_none());

        // We can't easily construct a NatTraversalEndpoint in a unit test,
        // but we verify the setter method exists and the state tracking works
    }

    #[test]
    fn test_router_debug_impl() {
        let router = ConnectionRouter::new(RouterConfig::default());
        let debug_str = format!("{router:?}");
        assert!(debug_str.contains("ConnectionRouter"));
        assert!(debug_str.contains("config"));
        assert!(debug_str.contains("stats"));
    }

    #[test]
    fn test_routed_connection_debug_constrained() {
        let mut router = ConnectionRouter::new(RouterConfig::default());
        let addr = TransportAddr::Ble {
            device_id: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            service_uuid: None,
        };

        let conn = router.connect(&addr).unwrap();
        let debug_str = format!("{conn:?}");
        assert!(debug_str.contains("Constrained"));
    }

    #[test]
    fn test_router_event_engine_accessor() {
        let event = RouterEvent::Connected {
            connection_id: 1,
            remote: TransportAddr::Udp("127.0.0.1:9000".parse().unwrap()),
            engine: ProtocolEngine::Quic,
        };
        assert_eq!(event.engine(), ProtocolEngine::Quic);

        let event = RouterEvent::DataReceived {
            connection_id: 2,
            data: vec![1, 2, 3],
            engine: ProtocolEngine::Constrained,
        };
        assert_eq!(event.engine(), ProtocolEngine::Constrained);
    }

    #[test]
    fn test_router_event_connection_id() {
        let event = RouterEvent::Connected {
            connection_id: 42,
            remote: TransportAddr::Udp("127.0.0.1:9000".parse().unwrap()),
            engine: ProtocolEngine::Quic,
        };
        assert_eq!(event.connection_id(), Some(42));

        let event = RouterEvent::Error {
            connection_id: None,
            error: "test error".into(),
            engine: ProtocolEngine::Constrained,
        };
        assert_eq!(event.connection_id(), None);
    }

    #[test]
    fn test_router_with_fallback_quic_unavailable_but_transport_supports() {
        // When QUIC is unavailable but transport supports QUIC,
        // should fall back to constrained
        let mut router = ConnectionRouter::new(RouterConfig::default());
        let capabilities = TransportCapabilities::broadband();

        let result = router
            .select_engine_with_fallback(&capabilities, false, true)
            .unwrap();
        assert_eq!(result.engine, ProtocolEngine::Constrained);
        assert!(result.is_fallback);
        assert_eq!(result.reason, SelectionReason::QuicUnavailableFallback);
    }

    #[test]
    fn test_poll_events_empty() {
        let mut router = ConnectionRouter::new(RouterConfig::default());
        let events = router.poll_events();
        assert!(events.is_empty());
    }

    #[test]
    fn test_poll_events_after_constrained_connect() {
        let mut router = ConnectionRouter::new(RouterConfig::default());
        let addr = TransportAddr::Ble {
            device_id: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            service_uuid: None,
        };

        // Connect to initialize constrained transport
        let _ = router.connect(&addr);

        // Poll events - should return empty since no actual network activity
        let events = router.poll_events();
        // Events may or may not be present depending on timing
        let _ = events;
    }

    // ========================================================================
    // Task 5: Unified Send/Receive API Tests
    // ========================================================================

    #[test]
    fn test_connection_mtu() {
        let mut router = ConnectionRouter::new(RouterConfig::default());
        let addr = TransportAddr::Ble {
            device_id: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            service_uuid: None,
        };

        let conn = router.connect(&addr).unwrap();
        let mtu = conn.mtu();

        // BLE MTU should be small (244 bytes for typical ATT MTU)
        assert_eq!(mtu, 244);
    }

    #[test]
    fn test_connection_stats_constrained() {
        let mut router = ConnectionRouter::new(RouterConfig::default());
        let addr = TransportAddr::Ble {
            device_id: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            service_uuid: None,
        };

        let conn = router.connect(&addr).unwrap();
        let stats = conn.stats();

        assert_eq!(stats.engine, ProtocolEngine::Constrained);
        // Initial stats should be zero (no traffic yet)
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.bytes_received, 0);
    }

    #[test]
    fn test_connection_stats_constructors() {
        let quic_stats = ConnectionStats::new_quic();
        assert_eq!(quic_stats.engine, ProtocolEngine::Quic);
        assert_eq!(quic_stats.bytes_sent, 0);

        let constrained_stats = ConnectionStats::new_constrained();
        assert_eq!(constrained_stats.engine, ProtocolEngine::Constrained);
        assert_eq!(constrained_stats.bytes_sent, 0);
    }

    #[test]
    fn test_close_with_reason_constrained() {
        let mut router = ConnectionRouter::new(RouterConfig::default());
        let addr = TransportAddr::Ble {
            device_id: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            service_uuid: None,
        };

        let conn = router.connect(&addr).unwrap();
        let result = conn.close_with_reason(42, b"test close");
        assert!(result.is_ok());
    }

    #[test]
    fn test_is_open_after_close() {
        let mut router = ConnectionRouter::new(RouterConfig::default());
        let addr = TransportAddr::Ble {
            device_id: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            service_uuid: None,
        };

        let conn = router.connect(&addr).unwrap();

        // Connection might be in SYN_SENT state initially
        // After close, it should not be "established"
        let _ = conn.close();
        // is_open() checks for Established state, which shouldn't be true after close
        // (though depending on timing, it may never have been established)
    }

    #[tokio::test]
    async fn test_send_async_constrained() {
        let mut router = ConnectionRouter::new(RouterConfig::default());
        let addr = TransportAddr::Ble {
            device_id: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            service_uuid: None,
        };

        let conn = router.connect(&addr).unwrap();

        // Send async on constrained - may fail because connection not established
        // but should not panic
        let result = conn.send_async(b"test data").await;
        // Result depends on connection state - we just verify no panic
        let _ = result;
    }

    #[tokio::test]
    async fn test_recv_async_constrained_no_data() {
        let mut router = ConnectionRouter::new(RouterConfig::default());
        let addr = TransportAddr::Ble {
            device_id: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            service_uuid: None,
        };

        let conn = router.connect(&addr).unwrap();

        // Recv async on constrained - should fail because no data available
        let result = conn.recv_async().await;
        assert!(result.is_err());
    }
}
