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
use std::time::Duration;

use bytes::Bytes;
use futures_util::StreamExt;
use tokio::sync::broadcast;
use tracing::{debug, warn};

use crate::high_level::{
    Connection as HighLevelConnection, RecvStream as HighLevelRecvStream,
    SendStream as HighLevelSendStream,
};
use crate::link_transport::{
    BoxFuture, BoxStream, Capabilities, ConnectionStats, DisconnectReason, Incoming, LinkConn,
    LinkError, LinkEvent, LinkRecvStream, LinkResult, LinkSendStream, LinkTransport, ProtocolId,
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
        self.inner
            .finish()
            .map_err(|_| LinkError::ConnectionClosed)
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
    async fn event_forwarder(
        endpoint: Arc<P2pEndpoint>,
        state: Arc<RwLock<LinkTransportState>>,
    ) {
        let mut rx = endpoint.subscribe();
        loop {
            match rx.recv().await {
                Ok(event) => {
                    let link_event = match event {
                        P2pEvent::PeerConnected { peer_id, addr } => {
                            let caps = Capabilities::new_connected(addr);
                            // Update capabilities cache
                            if let Ok(mut state) = state.write() {
                                state.capabilities.insert(peer_id, caps.clone());
                            }
                            Some(LinkEvent::PeerConnected { peer: peer_id, caps })
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

        Box::pin(futures_util::stream::unfold(endpoint, |endpoint| async move {
            // Wait for an incoming connection
            if let Some(peer_conn) = endpoint.accept().await {
                // Get the underlying QUIC connection
                if let Some(conn) = endpoint
                    .get_quic_connection(&peer_conn.peer_id)
                    .ok()
                    .flatten()
                {
                    let link_conn =
                        P2pLinkConn::new(conn, peer_conn.peer_id, peer_conn.remote_addr);
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
        }))
    }

    fn dial(&self, peer: PeerId, _proto: ProtocolId) -> BoxFuture<'_, LinkResult<Self::Conn>> {
        Box::pin(async move {
            // Look up peer address from capabilities
            let addr = self
                .state
                .read()
                .ok()
                .and_then(|state| {
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
}
