// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! # P2pEndpoint LinkTransport Implementation
//!
//! This module provides the concrete implementation of [`LinkTransport`] and [`LinkConn`]
//! for [`P2pEndpoint`], bridging the high-level P2P API with the transport abstraction layer.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use ant_quic::{P2pConfig, P2pLinkTransport};
//! use ant_quic::link_transport::{LinkTransport, ProtocolId};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = P2pConfig::builder()
//!         .bind_addr("0.0.0.0:0".parse()?)
//!         .build()?;
//!
//!     let transport = P2pLinkTransport::new(config).await?;
//!
//!     // Use as LinkTransport
//!     let local_peer = transport.local_peer();
//!     let peers = transport.peer_table();
//!
//!     // Dial with protocol
//!     let proto = ProtocolId::from("my-app/1.0");
//!     let conn = transport.dial_addr("127.0.0.1:9000".parse()?, proto).await?;
//!
//!     Ok(())
//! }
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use bytes::Bytes;
use futures_util::StreamExt;
use tokio::sync::{RwLock as TokioRwLock, broadcast};
use tracing::{debug, error, info, warn};

use crate::high_level::{
    Connection as HighLevelConnection, RecvStream as HighLevelRecvStream,
    SendStream as HighLevelSendStream,
};
use crate::link_transport::{
    BoxFuture, BoxStream, Capabilities, ConnectionStats, DisconnectReason, Incoming, LinkConn,
    LinkError, LinkEvent, LinkRecvStream, LinkResult, LinkSendStream, LinkTransport, ProtocolId,
    StreamFilter, StreamType,
};
use crate::nat_traversal_api::PeerId;
use crate::p2p_endpoint::{P2pEndpoint, P2pEvent};
use crate::unified_config::P2pConfig;

// ============================================================================
// P2pLinkConn - Connection wrapper
// ============================================================================

/// A [`LinkConn`] implementation wrapping a high-level QUIC connection.
pub struct P2pLinkConn {
    /// The underlying QUIC connection.
    inner: HighLevelConnection,
    /// Remote peer ID.
    peer_id: PeerId,
    /// Remote address.
    remote_addr: SocketAddr,
    /// Connection start time.
    connected_at: std::time::Instant,
}

impl P2pLinkConn {
    /// Create a new connection wrapper.
    pub fn new(inner: HighLevelConnection, peer_id: PeerId, remote_addr: SocketAddr) -> Self {
        Self {
            inner,
            peer_id,
            remote_addr,
            connected_at: std::time::Instant::now(),
        }
    }

    /// Get the underlying connection.
    pub fn inner(&self) -> &HighLevelConnection {
        &self.inner
    }
}

impl LinkConn for P2pLinkConn {
    fn peer(&self) -> PeerId {
        self.peer_id
    }

    fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    fn open_uni(&self) -> BoxFuture<'_, LinkResult<Box<dyn LinkSendStream>>> {
        Box::pin(async move {
            let stream = self
                .inner
                .open_uni()
                .await
                .map_err(|e| LinkError::ConnectionFailed(e.to_string()))?;
            Ok(Box::new(P2pSendStream::new(stream)) as Box<dyn LinkSendStream>)
        })
    }

    fn open_bi(
        &self,
    ) -> BoxFuture<'_, LinkResult<(Box<dyn LinkSendStream>, Box<dyn LinkRecvStream>)>> {
        Box::pin(async move {
            let (send, recv) = self
                .inner
                .open_bi()
                .await
                .map_err(|e| LinkError::ConnectionFailed(e.to_string()))?;
            Ok((
                Box::new(P2pSendStream::new(send)) as Box<dyn LinkSendStream>,
                Box::new(P2pRecvStream::new(recv)) as Box<dyn LinkRecvStream>,
            ))
        })
    }

    fn send_datagram(&self, data: Bytes) -> LinkResult<()> {
        self.inner
            .send_datagram(data)
            .map_err(|e| LinkError::Io(e.to_string()))
    }

    fn recv_datagrams(&self) -> BoxStream<'_, Bytes> {
        // Create a stream that polls for datagrams
        let conn = self.inner.clone();
        Box::pin(futures_util::stream::unfold(conn, |conn| async move {
            match conn.read_datagram().await {
                Ok(data) => Some((data, conn)),
                Err(_) => None,
            }
        }))
    }

    fn close(&self, error_code: u64, reason: &str) {
        self.inner.close(
            crate::VarInt::from_u64(error_code).unwrap_or(crate::VarInt::MAX),
            reason.as_bytes(),
        );
    }

    fn is_open(&self) -> bool {
        // Check if connection is still alive by examining the close reason
        self.inner.close_reason().is_none()
    }

    fn stats(&self) -> ConnectionStats {
        let quic_stats = self.inner.stats();
        ConnectionStats {
            bytes_sent: quic_stats.udp_tx.bytes,
            bytes_received: quic_stats.udp_rx.bytes,
            rtt: quic_stats.path.rtt,
            connected_duration: self.connected_at.elapsed(),
            streams_opened: 0, // Would need to track this separately
            packets_lost: quic_stats.path.lost_packets,
        }
    }

    fn open_uni_typed(
        &self,
        stream_type: StreamType,
    ) -> BoxFuture<'_, LinkResult<Box<dyn LinkSendStream>>> {
        Box::pin(async move {
            let mut stream = self
                .inner
                .open_uni()
                .await
                .map_err(|e| LinkError::ConnectionFailed(e.to_string()))?;

            // Write the stream type byte first
            stream
                .write_all(&[stream_type.as_byte()])
                .await
                .map_err(|e| LinkError::Io(e.to_string()))?;

            Ok(Box::new(P2pSendStream::new(stream)) as Box<dyn LinkSendStream>)
        })
    }

    fn open_bi_typed(
        &self,
        stream_type: StreamType,
    ) -> BoxFuture<'_, LinkResult<(Box<dyn LinkSendStream>, Box<dyn LinkRecvStream>)>> {
        Box::pin(async move {
            let (mut send, recv) = self
                .inner
                .open_bi()
                .await
                .map_err(|e| LinkError::ConnectionFailed(e.to_string()))?;

            // Write the stream type byte first
            send.write_all(&[stream_type.as_byte()])
                .await
                .map_err(|e| LinkError::Io(e.to_string()))?;

            Ok((
                Box::new(P2pSendStream::new(send)) as Box<dyn LinkSendStream>,
                Box::new(P2pRecvStream::new(recv)) as Box<dyn LinkRecvStream>,
            ))
        })
    }

    fn accept_uni_typed(
        &self,
        filter: StreamFilter,
    ) -> BoxStream<'_, LinkResult<(StreamType, Box<dyn LinkRecvStream>)>> {
        let conn = self.inner.clone();
        Box::pin(futures_util::stream::unfold(
            (conn, filter),
            |(conn, filter): (HighLevelConnection, StreamFilter)| async move {
                loop {
                    // Accept incoming unidirectional stream
                    let mut recv: HighLevelRecvStream = match conn.accept_uni().await {
                        Ok(r) => r,
                        Err(_) => return None,
                    };

                    // Read the first byte to determine stream type
                    let mut type_buf = [0u8; 1];
                    if recv.read_exact(&mut type_buf).await.is_err() {
                        // Failed to read type byte, skip this stream
                        continue;
                    }

                    // Parse stream type
                    let stream_type = match StreamType::from_byte(type_buf[0]) {
                        Some(st) => st,
                        None => {
                            // Unknown stream type, return error
                            return Some((
                                Err(LinkError::InvalidStreamType(type_buf[0])),
                                (conn, filter),
                            ));
                        }
                    };

                    // Check if filter accepts this type
                    if !filter.accepts(stream_type) {
                        // Not accepted, skip
                        continue;
                    }

                    // Return the typed stream
                    let recv_stream = Box::new(P2pRecvStream::new(recv)) as Box<dyn LinkRecvStream>;
                    return Some((Ok((stream_type, recv_stream)), (conn, filter)));
                }
            },
        ))
    }

    fn accept_bi_typed(
        &self,
        filter: StreamFilter,
    ) -> BoxStream<'_, LinkResult<(StreamType, Box<dyn LinkSendStream>, Box<dyn LinkRecvStream>)>>
    {
        let conn = self.inner.clone();
        Box::pin(futures_util::stream::unfold(
            (conn, filter),
            |(conn, filter): (HighLevelConnection, StreamFilter)| async move {
                loop {
                    // Accept incoming bidirectional stream
                    let (send, mut recv): (HighLevelSendStream, HighLevelRecvStream) =
                        match conn.accept_bi().await {
                            Ok((s, r)) => (s, r),
                            Err(_) => return None,
                        };

                    // Read the first byte to determine stream type
                    let mut type_buf = [0u8; 1];
                    if recv.read_exact(&mut type_buf).await.is_err() {
                        // Failed to read type byte, skip this stream
                        continue;
                    }

                    // Parse stream type
                    let stream_type = match StreamType::from_byte(type_buf[0]) {
                        Some(st) => st,
                        None => {
                            // Unknown stream type, return error
                            return Some((
                                Err(LinkError::InvalidStreamType(type_buf[0])),
                                (conn, filter),
                            ));
                        }
                    };

                    // Check if filter accepts this type
                    if !filter.accepts(stream_type) {
                        // Not accepted, skip
                        continue;
                    }

                    // Return the typed streams
                    let send_stream = Box::new(P2pSendStream::new(send)) as Box<dyn LinkSendStream>;
                    let recv_stream = Box::new(P2pRecvStream::new(recv)) as Box<dyn LinkRecvStream>;
                    return Some((Ok((stream_type, send_stream, recv_stream)), (conn, filter)));
                }
            },
        ))
    }
}

// ============================================================================
// P2pSendStream - Send stream wrapper
// ============================================================================

/// A [`LinkSendStream`] implementation wrapping a high-level send stream.
pub struct P2pSendStream {
    inner: HighLevelSendStream,
}

impl P2pSendStream {
    /// Create a new send stream wrapper.
    pub fn new(inner: HighLevelSendStream) -> Self {
        Self { inner }
    }
}

impl LinkSendStream for P2pSendStream {
    fn write<'a>(&'a mut self, data: &'a [u8]) -> BoxFuture<'a, LinkResult<usize>> {
        Box::pin(async move {
            self.inner
                .write(data)
                .await
                .map_err(|e| LinkError::Io(e.to_string()))
        })
    }

    fn write_all<'a>(&'a mut self, data: &'a [u8]) -> BoxFuture<'a, LinkResult<()>> {
        Box::pin(async move {
            self.inner
                .write_all(data)
                .await
                .map_err(|e| LinkError::Io(e.to_string()))
        })
    }

    fn finish(&mut self) -> LinkResult<()> {
        self.inner.finish().map_err(|_| LinkError::ConnectionClosed)
    }

    fn reset(&mut self, error_code: u64) -> LinkResult<()> {
        let code = crate::VarInt::from_u64(error_code).unwrap_or(crate::VarInt::MAX);
        self.inner
            .reset(code)
            .map_err(|_| LinkError::ConnectionClosed)
    }

    fn id(&self) -> u64 {
        self.inner.id().into()
    }
}

// ============================================================================
// P2pRecvStream - Receive stream wrapper
// ============================================================================

/// A [`LinkRecvStream`] implementation wrapping a high-level receive stream.
pub struct P2pRecvStream {
    inner: HighLevelRecvStream,
}

impl P2pRecvStream {
    /// Create a new receive stream wrapper.
    pub fn new(inner: HighLevelRecvStream) -> Self {
        Self { inner }
    }
}

impl LinkRecvStream for P2pRecvStream {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, LinkResult<Option<usize>>> {
        Box::pin(async move {
            self.inner
                .read(buf)
                .await
                .map_err(|e| LinkError::Io(e.to_string()))
        })
    }

    fn read_to_end(&mut self, size_limit: usize) -> BoxFuture<'_, LinkResult<Vec<u8>>> {
        Box::pin(async move {
            self.inner
                .read_to_end(size_limit)
                .await
                .map_err(|e| LinkError::Io(e.to_string()))
        })
    }

    fn stop(&mut self, error_code: u64) -> LinkResult<()> {
        let code = crate::VarInt::from_u64(error_code).unwrap_or(crate::VarInt::MAX);
        self.inner
            .stop(code)
            .map_err(|_| LinkError::ConnectionClosed)
    }

    fn id(&self) -> u64 {
        self.inner.id().into()
    }
}

// ============================================================================
// P2pLinkTransport - LinkTransport Implementation
// ============================================================================

/// Internal state for the LinkTransport implementation.
struct LinkTransportState {
    /// Registered protocols.
    protocols: Vec<ProtocolId>,
    /// Peer capabilities cache.
    capabilities: HashMap<PeerId, Capabilities>,
    /// Event broadcaster for LinkEvents.
    event_tx: broadcast::Sender<LinkEvent>,
}

impl Default for LinkTransportState {
    fn default() -> Self {
        let (event_tx, _) = broadcast::channel(256);
        Self {
            protocols: vec![ProtocolId::DEFAULT],
            capabilities: HashMap::new(),
            event_tx,
        }
    }
}

/// A [`LinkTransport`] implementation wrapping [`P2pEndpoint`].
///
/// This provides a stable abstraction layer for overlay networks to use,
/// decoupling them from specific ant-quic versions.
pub struct P2pLinkTransport {
    /// The underlying P2pEndpoint.
    endpoint: Arc<P2pEndpoint>,
    /// Additional state for LinkTransport.
    state: Arc<RwLock<LinkTransportState>>,
}

impl P2pLinkTransport {
    /// Create a new LinkTransport from a P2pConfig.
    pub async fn new(config: P2pConfig) -> Result<Self, crate::p2p_endpoint::EndpointError> {
        let endpoint = Arc::new(P2pEndpoint::new(config).await?);
        let state = Arc::new(RwLock::new(LinkTransportState::default()));

        // Spawn event forwarder
        let endpoint_clone = endpoint.clone();
        let state_clone = state.clone();
        tokio::spawn(async move {
            Self::event_forwarder(endpoint_clone, state_clone).await;
        });

        Ok(Self { endpoint, state })
    }

    /// Create from an existing P2pEndpoint.
    pub fn from_endpoint(endpoint: Arc<P2pEndpoint>) -> Self {
        let state = Arc::new(RwLock::new(LinkTransportState::default()));

        // Spawn event forwarder
        let endpoint_clone = endpoint.clone();
        let state_clone = state.clone();
        tokio::spawn(async move {
            Self::event_forwarder(endpoint_clone, state_clone).await;
        });

        Self { endpoint, state }
    }

    /// Forward P2pEvents to LinkEvents.
    async fn event_forwarder(endpoint: Arc<P2pEndpoint>, state: Arc<RwLock<LinkTransportState>>) {
        let mut rx = endpoint.subscribe();
        loop {
            match rx.recv().await {
                Ok(event) => {
                    let link_event = match event {
                        P2pEvent::PeerConnected {
                            peer_id,
                            addr,
                            side: _,
                        } => {
                            // Extract SocketAddr for Capabilities (currently UDP-only)
                            let socket_addr = addr.as_socket_addr().unwrap_or_else(|| {
                                // Fallback for non-UDP transports - use unspecified address
                                SocketAddr::from(([0, 0, 0, 0], 0))
                            });
                            let caps = Capabilities::new_connected(socket_addr);
                            // Update capabilities cache
                            if let Ok(mut state) = state.write() {
                                state.capabilities.insert(peer_id, caps.clone());
                            }
                            Some(LinkEvent::PeerConnected {
                                peer: peer_id,
                                caps,
                            })
                        }
                        P2pEvent::PeerDisconnected { peer_id, reason } => {
                            let disconnect_reason = match reason {
                                crate::p2p_endpoint::DisconnectReason::Normal => {
                                    DisconnectReason::LocalClose
                                }
                                crate::p2p_endpoint::DisconnectReason::RemoteClosed => {
                                    DisconnectReason::RemoteClose
                                }
                                crate::p2p_endpoint::DisconnectReason::Timeout => {
                                    DisconnectReason::Timeout
                                }
                                crate::p2p_endpoint::DisconnectReason::ProtocolError(msg) => {
                                    DisconnectReason::TransportError(msg)
                                }
                                crate::p2p_endpoint::DisconnectReason::AuthenticationFailed => {
                                    DisconnectReason::TransportError(
                                        "Authentication failed".to_string(),
                                    )
                                }
                                crate::p2p_endpoint::DisconnectReason::ConnectionLost => {
                                    DisconnectReason::Reset
                                }
                            };
                            // Update capabilities cache
                            if let Ok(mut state) = state.write() {
                                if let Some(caps) = state.capabilities.get_mut(&peer_id) {
                                    caps.is_connected = false;
                                }
                            }
                            Some(LinkEvent::PeerDisconnected {
                                peer: peer_id,
                                reason: disconnect_reason,
                            })
                        }
                        P2pEvent::ExternalAddressDiscovered { addr } => {
                            Some(LinkEvent::ExternalAddressUpdated { addr })
                        }
                        _ => None,
                    };

                    if let Some(event) = link_event {
                        if let Ok(state) = state.read() {
                            let _ = state.event_tx.send(event);
                        }
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!("Event forwarder lagged by {} events", n);
                }
                Err(broadcast::error::RecvError::Closed) => {
                    debug!("Event forwarder channel closed");
                    break;
                }
            }
        }
    }

    /// Get the underlying P2pEndpoint.
    pub fn endpoint(&self) -> &P2pEndpoint {
        &self.endpoint
    }
}

impl LinkTransport for P2pLinkTransport {
    type Conn = P2pLinkConn;

    fn local_peer(&self) -> PeerId {
        self.endpoint.peer_id()
    }

    fn external_address(&self) -> Option<SocketAddr> {
        self.endpoint.external_addr()
    }

    fn peer_table(&self) -> Vec<(PeerId, Capabilities)> {
        self.state
            .read()
            .map(|state| {
                state
                    .capabilities
                    .iter()
                    .map(|(k, v)| (*k, v.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn peer_capabilities(&self, peer: &PeerId) -> Option<Capabilities> {
        self.state
            .read()
            .ok()
            .and_then(|state| state.capabilities.get(peer).cloned())
    }

    fn subscribe(&self) -> broadcast::Receiver<LinkEvent> {
        self.state
            .read()
            .map(|state| state.event_tx.subscribe())
            .unwrap_or_else(|_| {
                let (tx, rx) = broadcast::channel(1);
                drop(tx);
                rx
            })
    }

    fn accept(&self, _proto: ProtocolId) -> Incoming<Self::Conn> {
        // TODO: Implement protocol-based accept filtering
        // For now, accept all incoming connections
        let endpoint = self.endpoint.clone();

        Box::pin(futures_util::stream::unfold(
            endpoint,
            |endpoint| async move {
                // Wait for an incoming connection
                if let Some(peer_conn) = endpoint.accept().await {
                    // Get the underlying QUIC connection
                    if let Some(conn) = endpoint
                        .get_quic_connection(&peer_conn.peer_id)
                        .ok()
                        .flatten()
                    {
                        // Extract SocketAddr from TransportAddr for LinkConn trait compatibility
                        let socket_addr = peer_conn
                            .remote_addr
                            .as_socket_addr()
                            .unwrap_or_else(|| conn.remote_address());
                        let link_conn = P2pLinkConn::new(conn, peer_conn.peer_id, socket_addr);
                        Some((Ok(link_conn), endpoint))
                    } else {
                        // Connection not found, try again
                        Some((
                            Err(LinkError::ConnectionFailed(
                                "Connection not found".to_string(),
                            )),
                            endpoint,
                        ))
                    }
                } else {
                    // Endpoint is shutting down
                    None
                }
            },
        ))
    }

    fn dial(&self, peer: PeerId, _proto: ProtocolId) -> BoxFuture<'_, LinkResult<Self::Conn>> {
        Box::pin(async move {
            // Look up peer address from capabilities
            let addr = self.state.read().ok().and_then(|state| {
                state
                    .capabilities
                    .get(&peer)
                    .and_then(|caps| caps.observed_addrs.first().copied())
            });

            match addr {
                Some(addr) => {
                    // Connect through P2pEndpoint
                    let peer_conn = self
                        .endpoint
                        .connect(addr)
                        .await
                        .map_err(|e| LinkError::ConnectionFailed(e.to_string()))?;

                    // Get the underlying QUIC connection
                    let conn = self
                        .endpoint
                        .get_quic_connection(&peer_conn.peer_id)
                        .map_err(|e| LinkError::ConnectionFailed(e.to_string()))?
                        .ok_or_else(|| {
                            LinkError::ConnectionFailed("Connection not found".to_string())
                        })?;

                    Ok(P2pLinkConn::new(conn, peer_conn.peer_id, addr))
                }
                None => Err(LinkError::PeerNotFound(format!("{:?}", peer))),
            }
        })
    }

    fn dial_addr(
        &self,
        addr: SocketAddr,
        _proto: ProtocolId,
    ) -> BoxFuture<'_, LinkResult<Self::Conn>> {
        Box::pin(async move {
            // Connect through P2pEndpoint
            let peer_conn = self
                .endpoint
                .connect(addr)
                .await
                .map_err(|e| LinkError::ConnectionFailed(e.to_string()))?;

            // Get the underlying QUIC connection
            let conn = self
                .endpoint
                .get_quic_connection(&peer_conn.peer_id)
                .map_err(|e| LinkError::ConnectionFailed(e.to_string()))?
                .ok_or_else(|| LinkError::ConnectionFailed("Connection not found".to_string()))?;

            Ok(P2pLinkConn::new(conn, peer_conn.peer_id, addr))
        })
    }

    fn supported_protocols(&self) -> Vec<ProtocolId> {
        self.state
            .read()
            .map(|state| state.protocols.clone())
            .unwrap_or_default()
    }

    fn register_protocol(&self, proto: ProtocolId) {
        if let Ok(mut state) = self.state.write() {
            if !state.protocols.contains(&proto) {
                state.protocols.push(proto);
            }
        }
    }

    fn unregister_protocol(&self, proto: ProtocolId) {
        if let Ok(mut state) = self.state.write() {
            state.protocols.retain(|p| p != &proto);
        }
    }

    fn is_connected(&self, peer: &PeerId) -> bool {
        self.state
            .read()
            .ok()
            .and_then(|state| state.capabilities.get(peer).map(|caps| caps.is_connected))
            .unwrap_or(false)
    }

    fn active_connections(&self) -> usize {
        self.state
            .read()
            .map(|state| {
                state
                    .capabilities
                    .values()
                    .filter(|caps| caps.is_connected)
                    .count()
            })
            .unwrap_or(0)
    }

    fn shutdown(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.endpoint.shutdown().await;
        })
    }
}

// ============================================================================
// SharedTransport - Protocol Multiplexer
// ============================================================================

/// Transport state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportState {
    /// Transport created but not started.
    Created,
    /// Transport is running and accepting connections.
    Running,
    /// Transport is shutting down.
    ShuttingDown,
    /// Transport has stopped.
    Stopped,
}

/// Peer connection state tracking.
#[allow(dead_code)]
struct PeerState {
    /// Remote socket address.
    remote_addr: Option<SocketAddr>,
    /// When the peer connected.
    connected_at: std::time::Instant,
    /// Messages sent to this peer.
    messages_sent: u64,
    /// Messages received from this peer.
    messages_received: u64,
    /// Last activity time.
    last_activity: std::time::Instant,
}

#[allow(dead_code)]
impl PeerState {
    fn new() -> Self {
        let now = std::time::Instant::now();
        Self {
            remote_addr: None,
            connected_at: now,
            messages_sent: 0,
            messages_received: 0,
            last_activity: now,
        }
    }

    fn with_addr(addr: SocketAddr) -> Self {
        let mut state = Self::new();
        state.remote_addr = Some(addr);
        state
    }
}

use crate::link_transport::BoxedHandler;

/// Shared transport that multiplexes protocols over a single connection per peer.
///
/// [`SharedTransport`] wraps any [`LinkTransport`] implementation and provides:
/// - Handler registration for different [`StreamType`]s
/// - Automatic stream routing to appropriate handlers
/// - Connection lifecycle management
/// - Peer state tracking
///
/// # Example
///
/// ```rust,ignore
/// use ant_quic::{SharedTransport, P2pLinkTransport, ProtocolHandler, StreamType};
///
/// let quic_transport = P2pLinkTransport::new(config).await?;
/// let transport = SharedTransport::new(quic_transport);
///
/// transport.register_handler(my_gossip_handler.boxed()).await?;
/// transport.register_handler(my_dht_handler.boxed()).await?;
///
/// transport.run().await?;
/// ```
pub struct SharedTransport<T: LinkTransport> {
    /// The underlying link transport.
    transport: Arc<T>,
    /// Registered protocol handlers, keyed by stream type.
    handlers: Arc<TokioRwLock<HashMap<StreamType, Arc<BoxedHandler>>>>,
    /// Connected peers with their connections.
    connections: Arc<TokioRwLock<HashMap<PeerId, Arc<T::Conn>>>>,
    /// Peer state tracking.
    peers: Arc<TokioRwLock<HashMap<PeerId, PeerState>>>,
    /// Transport state machine.
    state: TokioRwLock<TransportState>,
    /// Shutdown signal sender.
    shutdown_tx: broadcast::Sender<()>,
}

impl<T: LinkTransport> SharedTransport<T>
where
    T::Conn: Send + Sync + 'static,
{
    /// Create a new shared transport.
    pub fn new(transport: T) -> Self {
        let (shutdown_tx, _) = broadcast::channel(16);
        Self {
            transport: Arc::new(transport),
            handlers: Arc::new(TokioRwLock::new(HashMap::new())),
            connections: Arc::new(TokioRwLock::new(HashMap::new())),
            peers: Arc::new(TokioRwLock::new(HashMap::new())),
            state: TokioRwLock::new(TransportState::Created),
            shutdown_tx,
        }
    }

    /// Create from an existing Arc-wrapped transport.
    #[allow(dead_code)]
    pub fn from_arc(transport: Arc<T>) -> Self {
        let (shutdown_tx, _) = broadcast::channel(16);
        Self {
            transport,
            handlers: Arc::new(TokioRwLock::new(HashMap::new())),
            connections: Arc::new(TokioRwLock::new(HashMap::new())),
            peers: Arc::new(TokioRwLock::new(HashMap::new())),
            state: TokioRwLock::new(TransportState::Created),
            shutdown_tx,
        }
    }

    /// Get the local peer ID.
    pub fn local_peer(&self) -> PeerId {
        self.transport.local_peer()
    }

    /// Get the underlying transport.
    #[allow(dead_code)]
    pub fn transport(&self) -> &Arc<T> {
        &self.transport
    }

    /// Register a protocol handler.
    ///
    /// Each handler declares which stream types it handles. When streams arrive
    /// matching those types, they are dispatched to the handler.
    ///
    /// # Errors
    ///
    /// Returns [`LinkError::HandlerExists`] if a handler is already registered
    /// for any of the stream types.
    pub async fn register_handler(&self, handler: BoxedHandler) -> LinkResult<()> {
        let mut handlers = self.handlers.write().await;
        let handler = Arc::new(handler);

        // Check for conflicts first
        for &stream_type in handler.stream_types() {
            if handlers.contains_key(&stream_type) {
                return Err(LinkError::HandlerExists(stream_type));
            }
        }

        // Register for all stream types
        for &stream_type in handler.stream_types() {
            handlers.insert(stream_type, Arc::clone(&handler));
        }

        debug!(
            handler = %handler.name(),
            types = ?handler.stream_types(),
            "Registered protocol handler"
        );

        Ok(())
    }

    /// Unregister handler by stream types.
    ///
    /// Removes the handler registered for the given stream types.
    /// If this was the last reference to the handler, calls `shutdown()` on it.
    pub async fn unregister_handler(&self, stream_types: &[StreamType]) -> LinkResult<()> {
        let mut handlers = self.handlers.write().await;
        let mut seen_handlers = std::collections::HashSet::new();

        for &stream_type in stream_types {
            if let Some(handler) = handlers.remove(&stream_type) {
                let ptr = Arc::as_ptr(&handler) as usize;
                // Remove all stream types for this handler
                if seen_handlers.insert(ptr) {
                    // Remove other stream types registered by same handler
                    let handler_types: Vec<_> = handler.stream_types().to_vec();
                    for &ht in &handler_types {
                        handlers.remove(&ht);
                    }

                    // If this was the last reference, call shutdown
                    if Arc::strong_count(&handler) == 1 {
                        debug!(handler = %handler.name(), "Shutting down handler");
                        let _ = handler.shutdown().await;
                    }
                }
            }
        }

        Ok(())
    }

    /// Check if a handler is registered for a stream type.
    pub async fn has_handler(&self, stream_type: StreamType) -> bool {
        self.handlers.read().await.contains_key(&stream_type)
    }

    /// Get the handler for a stream type.
    pub async fn get_handler(&self, stream_type: StreamType) -> Option<Arc<BoxedHandler>> {
        self.handlers.read().await.get(&stream_type).cloned()
    }

    /// Get all registered stream types.
    pub async fn registered_types(&self) -> Vec<StreamType> {
        self.handlers.read().await.keys().copied().collect()
    }

    /// Build a stream filter from all registered handler types.
    pub async fn build_stream_filter(&self) -> StreamFilter {
        let handlers = self.handlers.read().await;
        let mut filter = StreamFilter::new();
        for &stream_type in handlers.keys() {
            filter = filter.with_type(stream_type);
        }
        filter
    }

    /// Check if transport is running.
    pub async fn is_running(&self) -> bool {
        *self.state.read().await == TransportState::Running
    }

    /// Start the transport.
    ///
    /// # Errors
    ///
    /// Returns [`LinkError::AlreadyRunning`] if the transport is already running.
    pub async fn start(&self) -> LinkResult<()> {
        let mut state = self.state.write().await;
        match *state {
            TransportState::Created | TransportState::Stopped => {
                *state = TransportState::Running;
                info!("SharedTransport started");
                Ok(())
            }
            TransportState::Running => Err(LinkError::AlreadyRunning),
            TransportState::ShuttingDown => Err(LinkError::NotRunning),
        }
    }

    /// Stop the transport gracefully.
    ///
    /// Shuts down all handlers and closes all connections.
    pub async fn stop(&self) -> LinkResult<()> {
        let mut state = self.state.write().await;
        if *state == TransportState::Stopped {
            return Ok(());
        }

        *state = TransportState::ShuttingDown;
        info!("SharedTransport shutting down");

        // Broadcast shutdown signal to all loops
        let _ = self.shutdown_tx.send(());

        // Shutdown handlers (avoid duplicates)
        {
            let handlers = self.handlers.read().await;
            let mut seen = std::collections::HashSet::new();

            for (stream_type, handler) in handlers.iter() {
                let ptr = Arc::as_ptr(handler) as usize;
                if seen.insert(ptr) {
                    if let Err(e) = handler.shutdown().await {
                        error!(
                            handler = %handler.name(),
                            stream_type = %stream_type,
                            error = %e,
                            "Handler shutdown error"
                        );
                    }
                }
            }
        }

        // Close all connections
        {
            let connections = self.connections.read().await;
            for (peer, conn) in connections.iter() {
                conn.close(0, "transport shutdown");
                debug!(peer = ?peer, "Closed connection");
            }
        }

        self.connections.write().await.clear();
        self.peers.write().await.clear();

        self.transport.shutdown().await;

        *state = TransportState::Stopped;
        info!("SharedTransport stopped");

        Ok(())
    }

    /// Get number of connected peers.
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    /// Get all connected peer IDs.
    pub async fn connected_peers(&self) -> Vec<PeerId> {
        self.peers.read().await.keys().copied().collect()
    }

    /// Check if a peer is connected.
    #[allow(dead_code)]
    pub async fn is_peer_connected(&self, peer: &PeerId) -> bool {
        self.peers.read().await.contains_key(peer)
    }

    /// Add a connection (for incoming connections).
    #[allow(dead_code)]
    pub async fn add_connection(&self, peer: PeerId, conn: T::Conn, addr: SocketAddr) {
        {
            let mut connections = self.connections.write().await;
            connections.insert(peer, Arc::new(conn));
        }
        {
            let mut peers = self.peers.write().await;
            peers.insert(peer, PeerState::with_addr(addr));
        }
        debug!(peer = ?peer, addr = %addr, "Added connection");
    }

    /// Remove a peer connection.
    #[allow(dead_code)]
    pub async fn remove_peer(&self, peer: &PeerId) {
        self.connections.write().await.remove(peer);
        self.peers.write().await.remove(peer);
        debug!(peer = ?peer, "Removed peer");
    }

    /// Connect to a peer by address.
    #[allow(dead_code)]
    pub async fn connect(&self, addr: SocketAddr) -> LinkResult<PeerId> {
        let conn = self.transport.dial_addr(addr, ProtocolId::DEFAULT).await?;
        let peer = conn.peer();
        self.add_connection(peer, conn, addr).await;
        Ok(peer)
    }

    /// Send data to a peer on a bidirectional stream, receive response.
    #[allow(dead_code)]
    pub async fn send(
        &self,
        peer: PeerId,
        stream_type: StreamType,
        data: Bytes,
    ) -> LinkResult<Option<Bytes>> {
        let conn = {
            let connections = self.connections.read().await;
            connections.get(&peer).cloned()
        };

        let conn = conn.ok_or_else(|| LinkError::PeerNotFound(format!("{:?}", peer)))?;

        let (mut send, mut recv) = conn.open_bi_typed(stream_type).await?;
        send.write_all(&data).await?;
        send.finish()?;

        // Update stats
        {
            let mut peers = self.peers.write().await;
            if let Some(state) = peers.get_mut(&peer) {
                state.messages_sent += 1;
                state.last_activity = std::time::Instant::now();
            }
        }

        // Read response
        let response = recv.read_to_end(1024 * 1024).await?;
        if response.is_empty() {
            Ok(None)
        } else {
            Ok(Some(Bytes::from(response)))
        }
    }

    /// Send data on a unidirectional stream.
    #[allow(dead_code)]
    pub async fn send_uni(
        &self,
        peer: PeerId,
        stream_type: StreamType,
        data: Bytes,
    ) -> LinkResult<()> {
        let conn = {
            let connections = self.connections.read().await;
            connections.get(&peer).cloned()
        };

        let conn = conn.ok_or_else(|| LinkError::PeerNotFound(format!("{:?}", peer)))?;

        let mut send = conn.open_uni_typed(stream_type).await?;
        send.write_all(&data).await?;
        send.finish()?;

        // Update stats
        {
            let mut peers = self.peers.write().await;
            if let Some(state) = peers.get_mut(&peer) {
                state.messages_sent += 1;
                state.last_activity = std::time::Instant::now();
            }
        }

        Ok(())
    }

    /// Run the transport, accepting incoming connections.
    ///
    /// This method blocks until the transport is stopped.
    #[allow(dead_code)]
    pub async fn run(&self) -> LinkResult<()> {
        self.start().await?;

        let mut incoming = self.transport.accept(ProtocolId::DEFAULT);
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("SharedTransport received shutdown signal");
                    break;
                }
                result = incoming.next() => {
                    match result {
                        Some(Ok(conn)) => {
                            let peer = conn.peer();
                            let remote_addr = conn.remote_addr();

                            info!(peer = ?peer, addr = %remote_addr, "Accepted connection");
                            self.add_connection(peer, conn, remote_addr).await;

                            // Spawn connection handler loop
                            let handlers = Arc::clone(&self.handlers);
                            let peers = Arc::clone(&self.peers);
                            let connections = Arc::clone(&self.connections);
                            let conn_shutdown_rx = self.shutdown_tx.subscribe();

                            tokio::spawn(async move {
                                Self::run_connection_accept(
                                    peer,
                                    handlers,
                                    peers,
                                    connections,
                                    conn_shutdown_rx,
                                ).await;
                            });
                        }
                        Some(Err(e)) => {
                            warn!(error = %e, "Error accepting connection");
                        }
                        None => {
                            debug!("Incoming connection stream ended");
                            break;
                        }
                    }
                }
            }
        }

        self.stop().await
    }

    /// Run the accept loop for a single connection.
    #[allow(dead_code)]
    async fn run_connection_accept(
        peer: PeerId,
        handlers: Arc<TokioRwLock<HashMap<StreamType, Arc<BoxedHandler>>>>,
        peers: Arc<TokioRwLock<HashMap<PeerId, PeerState>>>,
        connections: Arc<TokioRwLock<HashMap<PeerId, Arc<T::Conn>>>>,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) {
        let conn = {
            let connections = connections.read().await;
            connections.get(&peer).cloned()
        };

        let conn = match conn {
            Some(c) => c,
            None => {
                warn!(peer = ?peer, "Connection not found for accept loop");
                return;
            }
        };

        // Build filter from registered handlers
        let filter = {
            let handlers = handlers.read().await;
            let mut filter = StreamFilter::new();
            for &st in handlers.keys() {
                filter = filter.with_type(st);
            }
            filter
        };

        let mut stream = conn.accept_bi_typed(filter);

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    debug!(peer = ?peer, "Connection accept loop shutting down");
                    break;
                }
                result = stream.next() => {
                    match result {
                        Some(Ok((stream_type, send, recv))) => {
                            let handlers_clone = Arc::clone(&handlers);
                            let peers_clone = Arc::clone(&peers);
                            tokio::spawn(async move {
                                Self::handle_bi_stream(
                                    handlers_clone,
                                    peers_clone,
                                    peer,
                                    stream_type,
                                    send,
                                    recv,
                                ).await;
                            });
                        }
                        Some(Err(e)) => {
                            warn!(peer = ?peer, error = %e, "Error accepting stream");
                        }
                        None => {
                            debug!(peer = ?peer, "Connection closed");
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Handle an incoming bidirectional stream.
    #[allow(dead_code)]
    async fn handle_bi_stream(
        handlers: Arc<TokioRwLock<HashMap<StreamType, Arc<BoxedHandler>>>>,
        peers: Arc<TokioRwLock<HashMap<PeerId, PeerState>>>,
        peer: PeerId,
        stream_type: StreamType,
        mut send: Box<dyn LinkSendStream>,
        mut recv: Box<dyn LinkRecvStream>,
    ) {
        // Update peer stats
        {
            let mut peers_guard = peers.write().await;
            if let Some(state) = peers_guard.get_mut(&peer) {
                state.messages_received += 1;
                state.last_activity = std::time::Instant::now();
            }
        }

        // Read incoming data
        let data = match recv.read_to_end(1024 * 1024).await {
            Ok(data) => Bytes::from(data),
            Err(e) => {
                warn!(peer = ?peer, error = %e, "Failed to read stream");
                return;
            }
        };

        // Lookup handler
        let handler = {
            let handlers_guard = handlers.read().await;
            handlers_guard.get(&stream_type).cloned()
        };

        let handler = match handler {
            Some(h) => h,
            None => {
                warn!(peer = ?peer, stream_type = %stream_type, "No handler for stream type");
                return;
            }
        };

        // Dispatch to handler
        match handler.handle_stream(peer, stream_type, data).await {
            Ok(Some(response)) => {
                if let Err(e) = send.write_all(&response).await {
                    warn!(peer = ?peer, error = %e, "Failed to send response");
                }
                let _ = send.finish();
            }
            Ok(None) => {
                let _ = send.finish();
            }
            Err(e) => {
                error!(peer = ?peer, error = %e, "Handler error");
                let _ = send.finish();
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_id_constants() {
        assert_eq!(ProtocolId::DEFAULT.to_string(), "ant-quic/default");
        assert_eq!(ProtocolId::NAT_TRAVERSAL.to_string(), "ant-quic/nat");
        assert_eq!(ProtocolId::RELAY.to_string(), "ant-quic/relay");
    }

    #[test]
    fn test_capabilities_connected() {
        let addr: SocketAddr = "127.0.0.1:9000".parse().expect("valid addr");
        let caps = Capabilities::new_connected(addr);

        assert!(caps.is_connected);
        assert_eq!(caps.observed_addrs.len(), 1);
        assert_eq!(caps.observed_addrs[0], addr);
    }

    #[test]
    fn test_connection_stats_default() {
        let stats = ConnectionStats::default();
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.bytes_received, 0);
    }

    #[test]
    fn test_link_transport_state_default() {
        let state = LinkTransportState::default();
        assert_eq!(state.protocols.len(), 1);
        assert_eq!(state.protocols[0], ProtocolId::DEFAULT);
        assert!(state.capabilities.is_empty());
    }

    // =========================================================================
    // Phase 3: SharedTransport Tests
    // =========================================================================

    mod shared_transport_tests {
        use super::*;
        use crate::link_transport::ProtocolHandlerExt;
        use async_trait::async_trait;
        use std::sync::atomic::{AtomicUsize, Ordering};

        // === Mock Infrastructure ===

        struct MockConn {
            peer: PeerId,
            addr: SocketAddr,
        }

        impl LinkConn for MockConn {
            fn peer(&self) -> PeerId {
                self.peer
            }
            fn remote_addr(&self) -> SocketAddr {
                self.addr
            }
            fn open_uni(&self) -> BoxFuture<'_, LinkResult<Box<dyn LinkSendStream>>> {
                Box::pin(async { Err(LinkError::ConnectionClosed) })
            }
            fn open_bi(
                &self,
            ) -> BoxFuture<'_, LinkResult<(Box<dyn LinkSendStream>, Box<dyn LinkRecvStream>)>>
            {
                Box::pin(async { Err(LinkError::ConnectionClosed) })
            }
            fn send_datagram(&self, _: Bytes) -> LinkResult<()> {
                Ok(())
            }
            fn recv_datagrams(&self) -> BoxStream<'_, Bytes> {
                Box::pin(futures_util::stream::empty())
            }
            fn close(&self, _: u64, _: &str) {}
            fn is_open(&self) -> bool {
                true
            }
            fn stats(&self) -> ConnectionStats {
                ConnectionStats::default()
            }
            fn open_uni_typed(
                &self,
                _: StreamType,
            ) -> BoxFuture<'_, LinkResult<Box<dyn LinkSendStream>>> {
                Box::pin(async { Err(LinkError::ConnectionClosed) })
            }
            fn open_bi_typed(
                &self,
                _: StreamType,
            ) -> BoxFuture<'_, LinkResult<(Box<dyn LinkSendStream>, Box<dyn LinkRecvStream>)>>
            {
                Box::pin(async { Err(LinkError::ConnectionClosed) })
            }
            fn accept_uni_typed(
                &self,
                _: StreamFilter,
            ) -> BoxStream<'_, LinkResult<(StreamType, Box<dyn LinkRecvStream>)>> {
                Box::pin(futures_util::stream::empty())
            }
            fn accept_bi_typed(
                &self,
                _: StreamFilter,
            ) -> BoxStream<
                '_,
                LinkResult<(StreamType, Box<dyn LinkSendStream>, Box<dyn LinkRecvStream>)>,
            > {
                Box::pin(futures_util::stream::empty())
            }
        }

        struct MockTransport {
            local: PeerId,
        }

        impl LinkTransport for MockTransport {
            type Conn = MockConn;

            fn local_peer(&self) -> PeerId {
                self.local
            }
            fn external_address(&self) -> Option<SocketAddr> {
                None
            }
            fn peer_table(&self) -> Vec<(PeerId, Capabilities)> {
                vec![]
            }
            fn peer_capabilities(&self, _: &PeerId) -> Option<Capabilities> {
                None
            }
            fn subscribe(&self) -> broadcast::Receiver<LinkEvent> {
                let (tx, rx) = broadcast::channel(1);
                drop(tx);
                rx
            }
            fn accept(&self, _: ProtocolId) -> Incoming<Self::Conn> {
                Box::pin(futures_util::stream::empty())
            }
            fn dial(&self, _: PeerId, _: ProtocolId) -> BoxFuture<'_, LinkResult<Self::Conn>> {
                Box::pin(async { Err(LinkError::PeerNotFound("mock".into())) })
            }
            fn dial_addr(
                &self,
                addr: SocketAddr,
                _: ProtocolId,
            ) -> BoxFuture<'_, LinkResult<Self::Conn>> {
                let local = self.local;
                Box::pin(async move { Ok(MockConn { peer: local, addr }) })
            }
            fn supported_protocols(&self) -> Vec<ProtocolId> {
                vec![ProtocolId::DEFAULT]
            }
            fn register_protocol(&self, _: ProtocolId) {}
            fn unregister_protocol(&self, _: ProtocolId) {}
            fn is_connected(&self, _: &PeerId) -> bool {
                false
            }
            fn active_connections(&self) -> usize {
                0
            }
            fn shutdown(&self) -> BoxFuture<'_, ()> {
                Box::pin(async {})
            }
        }

        struct MockHandler {
            types: Vec<StreamType>,
            call_count: Arc<AtomicUsize>,
        }

        impl MockHandler {
            fn new(types: Vec<StreamType>) -> Self {
                Self {
                    types,
                    call_count: Arc::new(AtomicUsize::new(0)),
                }
            }
        }

        #[async_trait]
        impl crate::link_transport::ProtocolHandler for MockHandler {
            fn stream_types(&self) -> &[StreamType] {
                &self.types
            }

            async fn handle_stream(
                &self,
                _: PeerId,
                _: StreamType,
                _: Bytes,
            ) -> LinkResult<Option<Bytes>> {
                self.call_count.fetch_add(1, Ordering::SeqCst);
                Ok(Some(Bytes::from_static(b"response")))
            }

            fn name(&self) -> &str {
                "MockHandler"
            }
        }

        // === Tests ===

        #[test]
        fn test_shared_transport_creation() {
            let transport = SharedTransport::new(MockTransport {
                local: PeerId::from([1u8; 32]),
            });
            assert_eq!(transport.local_peer(), PeerId::from([1u8; 32]));
        }

        #[tokio::test]
        async fn test_register_handler() {
            let transport = SharedTransport::new(MockTransport {
                local: PeerId::from([1u8; 32]),
            });
            let handler = MockHandler::new(vec![StreamType::Membership, StreamType::PubSub]);

            transport.register_handler(handler.boxed()).await.unwrap();

            assert!(transport.has_handler(StreamType::Membership).await);
            assert!(transport.has_handler(StreamType::PubSub).await);
            assert!(!transport.has_handler(StreamType::DhtQuery).await);
        }

        #[tokio::test]
        async fn test_duplicate_handler_error() {
            let transport = SharedTransport::new(MockTransport {
                local: PeerId::from([1u8; 32]),
            });

            let handler1 = MockHandler::new(vec![StreamType::Membership]);
            let handler2 = MockHandler::new(vec![StreamType::Membership]);

            transport.register_handler(handler1.boxed()).await.unwrap();
            let result = transport.register_handler(handler2.boxed()).await;

            assert!(matches!(
                result,
                Err(LinkError::HandlerExists(StreamType::Membership))
            ));
        }

        #[tokio::test]
        async fn test_transport_lifecycle() {
            let transport = SharedTransport::new(MockTransport {
                local: PeerId::from([1u8; 32]),
            });

            assert!(!transport.is_running().await);

            transport.start().await.unwrap();
            assert!(transport.is_running().await);

            // Double start should error
            assert!(matches!(
                transport.start().await,
                Err(LinkError::AlreadyRunning)
            ));

            transport.stop().await.unwrap();
            assert!(!transport.is_running().await);
        }

        #[tokio::test]
        async fn test_build_stream_filter() {
            let transport = SharedTransport::new(MockTransport {
                local: PeerId::from([1u8; 32]),
            });

            let handler1 = MockHandler::new(vec![StreamType::Membership, StreamType::PubSub]);
            let handler2 = MockHandler::new(vec![StreamType::DhtQuery]);

            transport.register_handler(handler1.boxed()).await.unwrap();
            transport.register_handler(handler2.boxed()).await.unwrap();

            let filter = transport.build_stream_filter().await;
            assert!(filter.accepts(StreamType::Membership));
            assert!(filter.accepts(StreamType::PubSub));
            assert!(filter.accepts(StreamType::DhtQuery));
            assert!(!filter.accepts(StreamType::WebRtcSignal));
        }

        #[tokio::test]
        async fn test_registered_types() {
            let transport = SharedTransport::new(MockTransport {
                local: PeerId::from([1u8; 32]),
            });

            let handler = MockHandler::new(vec![StreamType::Membership, StreamType::DhtQuery]);
            transport.register_handler(handler.boxed()).await.unwrap();

            let types = transport.registered_types().await;
            assert_eq!(types.len(), 2);
            assert!(types.contains(&StreamType::Membership));
            assert!(types.contains(&StreamType::DhtQuery));
        }

        #[tokio::test]
        async fn test_get_handler() {
            let transport = SharedTransport::new(MockTransport {
                local: PeerId::from([1u8; 32]),
            });
            let handler = MockHandler::new(vec![StreamType::DhtStore]);

            transport.register_handler(handler.boxed()).await.unwrap();

            let h = transport.get_handler(StreamType::DhtStore).await;
            assert!(h.is_some());
            assert_eq!(h.unwrap().name(), "MockHandler");

            let h2 = transport.get_handler(StreamType::WebRtcSignal).await;
            assert!(h2.is_none());
        }

        #[tokio::test]
        async fn test_peer_count() {
            let transport = SharedTransport::new(MockTransport {
                local: PeerId::from([1u8; 32]),
            });
            transport.start().await.unwrap();

            assert_eq!(transport.peer_count().await, 0);
            assert!(transport.connected_peers().await.is_empty());
        }

        #[tokio::test]
        async fn test_unregister_handler() {
            let transport = SharedTransport::new(MockTransport {
                local: PeerId::from([1u8; 32]),
            });
            let handler = MockHandler::new(vec![StreamType::Membership, StreamType::PubSub]);

            transport.register_handler(handler.boxed()).await.unwrap();
            assert!(transport.has_handler(StreamType::Membership).await);
            assert!(transport.has_handler(StreamType::PubSub).await);

            transport
                .unregister_handler(&[StreamType::Membership])
                .await
                .unwrap();
            // Both should be gone since they were from the same handler
            assert!(!transport.has_handler(StreamType::Membership).await);
            assert!(!transport.has_handler(StreamType::PubSub).await);
        }
    }
}
