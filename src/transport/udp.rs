// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! UDP transport provider implementation
//!
//! This module implements the [`TransportProvider`] trait for UDP/IP sockets,
//! providing high-bandwidth, low-latency transport for standard Internet connectivity.
//!
//! The UDP transport is the default and most capable transport, supporting:
//! - Full QUIC protocol
//! - IPv4 and IPv6 dual-stack
//! - Broadcast on local networks
//! - No link-layer acknowledgements (QUIC handles reliability)

use async_trait::async_trait;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use super::addr::{TransportAddr, TransportType};
use super::capabilities::TransportCapabilities;
use super::provider::{
    InboundDatagram, LinkQuality, TransportError, TransportProvider, TransportStats,
};

/// UDP transport provider for standard Internet connectivity
///
/// This is the primary transport for ant-quic, providing high-bandwidth,
/// low-latency connectivity over UDP/IP.
pub struct UdpTransport {
    socket: Arc<UdpSocket>,
    capabilities: TransportCapabilities,
    local_addr: SocketAddr,
    online: AtomicBool,
    stats: UdpTransportStats,
    inbound_tx: mpsc::Sender<InboundDatagram>,
    shutdown_tx: mpsc::Sender<()>,
}

struct UdpTransportStats {
    datagrams_sent: AtomicU64,
    datagrams_received: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    send_errors: AtomicU64,
    receive_errors: AtomicU64,
}

impl Default for UdpTransportStats {
    fn default() -> Self {
        Self {
            datagrams_sent: AtomicU64::new(0),
            datagrams_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            send_errors: AtomicU64::new(0),
            receive_errors: AtomicU64::new(0),
        }
    }
}

impl UdpTransport {
    /// Bind a new UDP transport to the specified address
    ///
    /// # Arguments
    ///
    /// * `addr` - The socket address to bind to. Use `0.0.0.0:0` for automatic port selection.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket cannot be bound.
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        let local_addr = socket.local_addr()?;
        let socket = Arc::new(socket);

        let (inbound_tx, _) = mpsc::channel(1024);
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        let transport = Self {
            socket: socket.clone(),
            capabilities: TransportCapabilities::broadband(),
            local_addr,
            online: AtomicBool::new(true),
            stats: UdpTransportStats::default(),
            inbound_tx,
            shutdown_tx,
        };

        // Spawn receive loop
        transport.spawn_recv_loop(socket, shutdown_rx);

        Ok(transport)
    }

    /// Create a UDP transport from an existing socket
    ///
    /// This is useful when you want to share a socket with other components.
    pub fn from_socket(socket: Arc<UdpSocket>, local_addr: SocketAddr) -> Self {
        let (inbound_tx, _) = mpsc::channel(1024);
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        let transport = Self {
            socket: socket.clone(),
            capabilities: TransportCapabilities::broadband(),
            local_addr,
            online: AtomicBool::new(true),
            stats: UdpTransportStats::default(),
            inbound_tx,
            shutdown_tx,
        };

        transport.spawn_recv_loop(socket, shutdown_rx);
        transport
    }

    fn spawn_recv_loop(&self, socket: Arc<UdpSocket>, mut shutdown_rx: mpsc::Receiver<()>) {
        let inbound_tx = self.inbound_tx.clone();
        let online = self.online.load(Ordering::SeqCst);

        if !online {
            return;
        }

        // Note: This is a simplified receive loop for the transport abstraction.
        // In practice, the actual packet reception is handled by the QUIC endpoint's
        // polling mechanism, not this transport directly.
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];

            loop {
                tokio::select! {
                    result = socket.recv_from(&mut buf) => {
                        match result {
                            Ok((len, source)) => {
                                let datagram = InboundDatagram {
                                    data: buf[..len].to_vec(),
                                    source: TransportAddr::Udp(source),
                                    received_at: Instant::now(),
                                    link_quality: None,
                                };

                                // Best-effort send; drop if channel is full
                                let _ = inbound_tx.try_send(datagram);
                            }
                            Err(_) => {
                                // Receive error, but continue trying
                                continue;
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        break;
                    }
                }
            }
        });
    }

    /// Get the underlying UDP socket
    pub fn socket(&self) -> &Arc<UdpSocket> {
        &self.socket
    }
}

#[async_trait]
impl TransportProvider for UdpTransport {
    fn name(&self) -> &str {
        "UDP"
    }

    fn transport_type(&self) -> TransportType {
        TransportType::Udp
    }

    fn capabilities(&self) -> &TransportCapabilities {
        &self.capabilities
    }

    fn local_addr(&self) -> Option<TransportAddr> {
        Some(TransportAddr::Udp(self.local_addr))
    }

    async fn send(&self, data: &[u8], dest: &TransportAddr) -> Result<(), TransportError> {
        if !self.online.load(Ordering::SeqCst) {
            return Err(TransportError::Offline);
        }

        let socket_addr = match dest {
            TransportAddr::Udp(addr) => *addr,
            _ => {
                return Err(TransportError::AddressMismatch {
                    expected: TransportType::Udp,
                    actual: dest.transport_type(),
                });
            }
        };

        if data.len() > self.capabilities.mtu {
            return Err(TransportError::MessageTooLarge {
                size: data.len(),
                mtu: self.capabilities.mtu,
            });
        }

        match self.socket.send_to(data, socket_addr).await {
            Ok(sent) => {
                self.stats.datagrams_sent.fetch_add(1, Ordering::Relaxed);
                self.stats
                    .bytes_sent
                    .fetch_add(sent as u64, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                self.stats.send_errors.fetch_add(1, Ordering::Relaxed);
                Err(TransportError::SendFailed {
                    reason: e.to_string(),
                })
            }
        }
    }

    fn inbound(&self) -> mpsc::Receiver<InboundDatagram> {
        // Create a new receiver from the same channel
        // Note: In a real implementation, you might want to use a broadcast channel
        // or have the endpoint subscribe to the transport's inbound stream.
        let (_, rx) = mpsc::channel(1024);
        rx
    }

    fn is_online(&self) -> bool {
        self.online.load(Ordering::SeqCst)
    }

    async fn shutdown(&self) -> Result<(), TransportError> {
        self.online.store(false, Ordering::SeqCst);
        let _ = self.shutdown_tx.send(()).await;
        Ok(())
    }

    async fn broadcast(&self, data: &[u8]) -> Result<(), TransportError> {
        // UDP supports broadcast
        if !self.capabilities.broadcast {
            return Err(TransportError::BroadcastNotSupported);
        }

        // Broadcast to 255.255.255.255 on the same port
        let broadcast_addr = SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::BROADCAST),
            self.local_addr.port(),
        );

        self.send(data, &TransportAddr::Udp(broadcast_addr)).await
    }

    async fn link_quality(&self, _peer: &TransportAddr) -> Option<LinkQuality> {
        // UDP doesn't provide link quality metrics directly
        None
    }

    fn stats(&self) -> TransportStats {
        TransportStats {
            datagrams_sent: self.stats.datagrams_sent.load(Ordering::Relaxed),
            datagrams_received: self.stats.datagrams_received.load(Ordering::Relaxed),
            bytes_sent: self.stats.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.stats.bytes_received.load(Ordering::Relaxed),
            send_errors: self.stats.send_errors.load(Ordering::Relaxed),
            receive_errors: self.stats.receive_errors.load(Ordering::Relaxed),
            current_rtt: None,
        }
    }

    fn socket(&self) -> Option<&Arc<UdpSocket>> {
        Some(&self.socket)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_udp_transport_bind() {
        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        assert!(transport.is_online());
        assert_eq!(transport.transport_type(), TransportType::Udp);
        assert!(transport.capabilities().supports_full_quic());

        let local_addr = transport.local_addr();
        assert!(local_addr.is_some());
        if let Some(TransportAddr::Udp(addr)) = local_addr {
            assert_eq!(
                addr.ip(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
            );
            assert_ne!(addr.port(), 0);
        }
    }

    #[tokio::test]
    async fn test_udp_transport_send() {
        let transport1 = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let transport2 = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        let dest = transport2.local_addr().unwrap();
        let result = transport1.send(b"hello", &dest).await;
        assert!(result.is_ok());

        let stats = transport1.stats();
        assert_eq!(stats.datagrams_sent, 1);
        assert_eq!(stats.bytes_sent, 5);
    }

    #[tokio::test]
    async fn test_udp_transport_address_mismatch() {
        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        let ble_addr = TransportAddr::ble([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], None);
        let result = transport.send(b"hello", &ble_addr).await;

        match result {
            Err(TransportError::AddressMismatch { expected, actual }) => {
                assert_eq!(expected, TransportType::Udp);
                assert_eq!(actual, TransportType::Ble);
            }
            _ => panic!("expected AddressMismatch error"),
        }
    }

    #[tokio::test]
    async fn test_udp_transport_shutdown() {
        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        assert!(transport.is_online());
        transport.shutdown().await.unwrap();
        assert!(!transport.is_online());

        // Sending after shutdown should fail
        let dest = TransportAddr::Udp("127.0.0.1:9000".parse().unwrap());
        let result = transport.send(b"hello", &dest).await;
        assert!(matches!(result, Err(TransportError::Offline)));
    }

    #[test]
    fn test_udp_capabilities() {
        let caps = TransportCapabilities::broadband();

        assert!(caps.supports_full_quic());
        assert!(!caps.half_duplex);
        assert!(caps.broadcast);
        assert!(!caps.metered);
        assert!(!caps.power_constrained);
    }

    #[tokio::test]
    async fn test_udp_transport_socket_accessor() {
        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        // Test the inherent socket() method
        let socket_ref = transport.socket();
        assert!(socket_ref.local_addr().is_ok());

        // Test the trait method via TransportProvider
        let provider: &dyn TransportProvider = &transport;
        let socket_opt = provider.socket();
        assert!(socket_opt.is_some());
        assert!(socket_opt.unwrap().local_addr().is_ok());
    }
}
