// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Transport provider trait for pluggable transport implementations
//!
//! This module defines the [`TransportProvider`] trait, which abstracts the details
//! of physical transports (UDP, BLE, LoRa, etc.) behind a common interface.
//!
//! # Design
//!
//! The transport abstraction enables ant-quic to operate over any medium that can
//! deliver datagrams. Higher layers (protocol engines, routing) are unaware of
//! the underlying transport characteristics.
//!
//! Each transport implementation must:
//! 1. Describe its capabilities via [`TransportCapabilities`]
//! 2. Provide send/receive operations for datagrams
//! 3. Report its local address and online status
//!
//! # Protocol Engine Selection
//!
//! Based on transport capabilities, ant-quic selects the appropriate protocol engine:
//! - **QUIC Engine**: Full RFC 9000 for capable transports
//! - **Constrained Engine**: Minimal protocol for limited transports
//!
//! The [`ProtocolEngine`] enum represents this selection.

use async_trait::async_trait;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

use super::addr::{TransportAddr, TransportType};
use super::capabilities::TransportCapabilities;

/// Error type for transport operations
#[derive(Debug, Clone)]
pub enum TransportError {
    /// Transport address type mismatch
    AddressMismatch {
        /// Expected transport type
        expected: TransportType,
        /// Actual transport type received
        actual: TransportType,
    },

    /// Message exceeds transport MTU
    MessageTooLarge {
        /// Size of the message attempted
        size: usize,
        /// Maximum allowed size
        mtu: usize,
    },

    /// Transport is offline or disconnected
    Offline,

    /// Transport is shutting down
    ShuttingDown,

    /// Send operation failed
    SendFailed {
        /// Underlying error message
        reason: String,
    },

    /// Receive operation failed
    ReceiveFailed {
        /// Underlying error message
        reason: String,
    },

    /// Broadcast not supported by this transport
    BroadcastNotSupported,

    /// Transport-specific error
    Other {
        /// Error message
        message: String,
    },
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AddressMismatch { expected, actual } => {
                write!(
                    f,
                    "address type mismatch: expected {expected}, got {actual}"
                )
            }
            Self::MessageTooLarge { size, mtu } => {
                write!(f, "message too large: {size} bytes exceeds MTU of {mtu}")
            }
            Self::Offline => write!(f, "transport is offline"),
            Self::ShuttingDown => write!(f, "transport is shutting down"),
            Self::SendFailed { reason } => write!(f, "send failed: {reason}"),
            Self::ReceiveFailed { reason } => write!(f, "receive failed: {reason}"),
            Self::BroadcastNotSupported => write!(f, "broadcast not supported"),
            Self::Other { message } => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for TransportError {}

/// An inbound datagram received from a transport
#[derive(Debug, Clone)]
pub struct InboundDatagram {
    /// The data payload
    pub data: Vec<u8>,

    /// Source address of the sender
    pub source: TransportAddr,

    /// Timestamp when received (monotonic clock)
    pub received_at: std::time::Instant,

    /// Optional link quality metrics from the transport
    pub link_quality: Option<LinkQuality>,
}

/// Link quality metrics from the transport layer
#[derive(Debug, Clone, Default)]
pub struct LinkQuality {
    /// Received Signal Strength Indicator in dBm (radio transports)
    pub rssi: Option<i16>,

    /// Signal-to-Noise Ratio in dB (radio transports)
    pub snr: Option<f32>,

    /// Number of hops (overlay networks)
    pub hop_count: Option<u8>,

    /// Measured round-trip time to peer
    pub rtt: Option<Duration>,
}

/// Transport provider statistics
#[derive(Debug, Clone, Default)]
pub struct TransportStats {
    /// Total datagrams sent
    pub datagrams_sent: u64,

    /// Total datagrams received
    pub datagrams_received: u64,

    /// Total bytes sent
    pub bytes_sent: u64,

    /// Total bytes received
    pub bytes_received: u64,

    /// Send errors
    pub send_errors: u64,

    /// Receive errors
    pub receive_errors: u64,

    /// Current RTT estimate (if available)
    pub current_rtt: Option<Duration>,
}

/// Protocol engine selection based on transport capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolEngine {
    /// Full QUIC protocol (RFC 9000)
    ///
    /// Used for transports with:
    /// - Bandwidth >= 10 kbps
    /// - MTU >= 1200 bytes
    /// - RTT < 2 seconds
    Quic,

    /// Constrained protocol for limited transports
    ///
    /// Used for transports that don't meet QUIC requirements:
    /// - Minimal headers (4-8 bytes)
    /// - No congestion control
    /// - ARQ for reliability
    /// - Session key caching
    Constrained,
}

impl ProtocolEngine {
    /// Select protocol engine based on transport capabilities
    pub fn for_transport(caps: &TransportCapabilities) -> Self {
        if caps.supports_full_quic() {
            Self::Quic
        } else {
            Self::Constrained
        }
    }
}

impl fmt::Display for ProtocolEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Quic => write!(f, "QUIC"),
            Self::Constrained => write!(f, "Constrained"),
        }
    }
}

/// Core transport abstraction trait
///
/// Implement this trait to add support for a new transport medium.
/// All transports present the same interface to higher layers.
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` to allow concurrent access
/// from multiple async tasks.
///
/// # Example
///
/// ```rust,ignore
/// struct MyTransport {
///     // transport-specific state
/// }
///
/// #[async_trait]
/// impl TransportProvider for MyTransport {
///     fn name(&self) -> &str { "MyTransport" }
///     fn transport_type(&self) -> TransportType { TransportType::Serial }
///     fn capabilities(&self) -> &TransportCapabilities { &self.caps }
///     // ... implement remaining methods
/// }
/// ```
#[async_trait]
pub trait TransportProvider: Send + Sync + 'static {
    /// Human-readable name for this transport instance
    fn name(&self) -> &str;

    /// Transport type identifier for routing
    fn transport_type(&self) -> TransportType;

    /// Transport capabilities for protocol selection
    fn capabilities(&self) -> &TransportCapabilities;

    /// Our local address on this transport, if available
    fn local_addr(&self) -> Option<TransportAddr>;

    /// Send a datagram to a destination address
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The destination address type doesn't match this transport
    /// - The message exceeds the transport MTU
    /// - The transport is offline
    /// - The send operation fails
    async fn send(&self, data: &[u8], dest: &TransportAddr) -> Result<(), TransportError>;

    /// Get a receiver for inbound datagrams
    ///
    /// The receiver is connected to an internal channel that receives
    /// all datagrams arriving on this transport. Multiple calls return
    /// clones of the same receiver (or a new one if the transport supports it).
    fn inbound(&self) -> mpsc::Receiver<InboundDatagram>;

    /// Check if this transport is currently online and operational
    fn is_online(&self) -> bool;

    /// Gracefully shut down the transport
    ///
    /// This should:
    /// 1. Stop accepting new operations
    /// 2. Complete any pending sends
    /// 3. Close underlying resources
    async fn shutdown(&self) -> Result<(), TransportError>;

    /// Broadcast a datagram to all reachable peers (if supported)
    ///
    /// # Errors
    ///
    /// Returns `TransportError::BroadcastNotSupported` if this transport
    /// doesn't support broadcast.
    async fn broadcast(&self, _data: &[u8]) -> Result<(), TransportError> {
        if !self.capabilities().broadcast {
            return Err(TransportError::BroadcastNotSupported);
        }
        // Default implementation: not supported
        Err(TransportError::BroadcastNotSupported)
    }

    /// Get current link quality to a specific peer (if measurable)
    ///
    /// Returns `None` if link quality cannot be determined or is not
    /// applicable for this transport.
    async fn link_quality(&self, _peer: &TransportAddr) -> Option<LinkQuality> {
        None
    }

    /// Get transport statistics
    fn stats(&self) -> TransportStats {
        TransportStats::default()
    }

    /// Get the appropriate protocol engine for this transport
    fn protocol_engine(&self) -> ProtocolEngine {
        ProtocolEngine::for_transport(self.capabilities())
    }
}

/// Transport diagnostics for path selection and monitoring
#[derive(Debug, Clone)]
pub struct TransportDiagnostics {
    /// Transport name
    pub name: String,

    /// Transport type
    pub transport_type: TransportType,

    /// Selected protocol engine
    pub protocol_engine: ProtocolEngine,

    /// Bandwidth classification
    pub bandwidth_class: super::capabilities::BandwidthClass,

    /// Current RTT (if available)
    pub current_rtt: Option<Duration>,

    /// Whether transport is online
    pub is_online: bool,

    /// Transport statistics
    pub stats: TransportStats,

    /// Local address (if available)
    pub local_addr: Option<TransportAddr>,
}

impl TransportDiagnostics {
    /// Create diagnostics from a transport provider
    pub fn from_provider(provider: &dyn TransportProvider) -> Self {
        let caps = provider.capabilities();
        Self {
            name: provider.name().to_string(),
            transport_type: provider.transport_type(),
            protocol_engine: provider.protocol_engine(),
            bandwidth_class: caps.bandwidth_class(),
            current_rtt: provider.stats().current_rtt,
            is_online: provider.is_online(),
            stats: provider.stats(),
            local_addr: provider.local_addr(),
        }
    }
}

/// A collection of transport providers with registry functionality
#[derive(Default, Clone)]
pub struct TransportRegistry {
    providers: Vec<Arc<dyn TransportProvider>>,
}

impl TransportRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a transport provider
    pub fn register(&mut self, provider: Arc<dyn TransportProvider>) {
        self.providers.push(provider);
    }

    /// Get all registered providers
    pub fn providers(&self) -> &[Arc<dyn TransportProvider>] {
        &self.providers
    }

    /// Get providers of a specific transport type
    pub fn providers_by_type(
        &self,
        transport_type: TransportType,
    ) -> Vec<Arc<dyn TransportProvider>> {
        self.providers
            .iter()
            .filter(|p| p.transport_type() == transport_type)
            .cloned()
            .collect()
    }

    /// Get the first provider that can handle a destination address
    pub fn provider_for_addr(&self, addr: &TransportAddr) -> Option<Arc<dyn TransportProvider>> {
        let target_type = addr.transport_type();
        self.providers
            .iter()
            .find(|p| p.transport_type() == target_type && p.is_online())
            .cloned()
    }

    /// Get all online providers
    pub fn online_providers(&self) -> Vec<Arc<dyn TransportProvider>> {
        self.providers
            .iter()
            .filter(|p| p.is_online())
            .cloned()
            .collect()
    }

    /// Get diagnostics for all transports
    pub fn diagnostics(&self) -> Vec<TransportDiagnostics> {
        self.providers
            .iter()
            .map(|p| TransportDiagnostics::from_provider(p.as_ref()))
            .collect()
    }

    /// Check if any transport supports full QUIC
    pub fn has_quic_capable_transport(&self) -> bool {
        self.providers
            .iter()
            .any(|p| p.is_online() && p.capabilities().supports_full_quic())
    }

    /// Get the number of registered providers
    pub fn len(&self) -> usize {
        self.providers.len()
    }

    /// Check if the registry is empty
    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }
}

impl fmt::Debug for TransportRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransportRegistry")
            .field("providers", &self.providers.len())
            .field("online", &self.online_providers().len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Mock transport for testing
    #[allow(dead_code)]
    struct MockTransport {
        name: String,
        transport_type: TransportType,
        capabilities: TransportCapabilities,
        online: AtomicBool,
        local_addr: Option<TransportAddr>,
        inbound_rx: tokio::sync::Mutex<Option<mpsc::Receiver<InboundDatagram>>>,
    }

    impl MockTransport {
        fn new_udp() -> Self {
            let (_, rx) = mpsc::channel(16);
            Self {
                name: "MockUDP".to_string(),
                transport_type: TransportType::Udp,
                capabilities: TransportCapabilities::broadband(),
                online: AtomicBool::new(true),
                local_addr: Some(TransportAddr::Udp("127.0.0.1:9000".parse().unwrap())),
                inbound_rx: tokio::sync::Mutex::new(Some(rx)),
            }
        }

        fn new_ble() -> Self {
            let (_, rx) = mpsc::channel(16);
            Self {
                name: "MockBLE".to_string(),
                transport_type: TransportType::Ble,
                capabilities: TransportCapabilities::ble(),
                online: AtomicBool::new(true),
                local_addr: Some(TransportAddr::ble(
                    [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
                    None,
                )),
                inbound_rx: tokio::sync::Mutex::new(Some(rx)),
            }
        }
    }

    #[async_trait]
    impl TransportProvider for MockTransport {
        fn name(&self) -> &str {
            &self.name
        }

        fn transport_type(&self) -> TransportType {
            self.transport_type
        }

        fn capabilities(&self) -> &TransportCapabilities {
            &self.capabilities
        }

        fn local_addr(&self) -> Option<TransportAddr> {
            self.local_addr.clone()
        }

        async fn send(&self, data: &[u8], dest: &TransportAddr) -> Result<(), TransportError> {
            if !self.online.load(Ordering::SeqCst) {
                return Err(TransportError::Offline);
            }

            if dest.transport_type() != self.transport_type {
                return Err(TransportError::AddressMismatch {
                    expected: self.transport_type,
                    actual: dest.transport_type(),
                });
            }

            if data.len() > self.capabilities.mtu {
                return Err(TransportError::MessageTooLarge {
                    size: data.len(),
                    mtu: self.capabilities.mtu,
                });
            }

            Ok(())
        }

        fn inbound(&self) -> mpsc::Receiver<InboundDatagram> {
            // For testing, just create a new channel
            let (_, rx) = mpsc::channel(16);
            rx
        }

        fn is_online(&self) -> bool {
            self.online.load(Ordering::SeqCst)
        }

        async fn shutdown(&self) -> Result<(), TransportError> {
            self.online.store(false, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn test_protocol_engine_selection() {
        let broadband = TransportCapabilities::broadband();
        assert_eq!(
            ProtocolEngine::for_transport(&broadband),
            ProtocolEngine::Quic
        );

        let ble = TransportCapabilities::ble();
        assert_eq!(
            ProtocolEngine::for_transport(&ble),
            ProtocolEngine::Constrained
        );

        let lora = TransportCapabilities::lora_long_range();
        assert_eq!(
            ProtocolEngine::for_transport(&lora),
            ProtocolEngine::Constrained
        );
    }

    #[tokio::test]
    async fn test_mock_transport_send() {
        let transport = MockTransport::new_udp();

        let dest: SocketAddr = "192.168.1.1:9000".parse().unwrap();
        let result = transport.send(b"hello", &TransportAddr::Udp(dest)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_transport_address_mismatch() {
        let transport = MockTransport::new_udp();

        let dest = TransportAddr::ble([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], None);
        let result = transport.send(b"hello", &dest).await;

        match result {
            Err(TransportError::AddressMismatch { expected, actual }) => {
                assert_eq!(expected, TransportType::Udp);
                assert_eq!(actual, TransportType::Ble);
            }
            _ => panic!("expected AddressMismatch error"),
        }
    }

    #[tokio::test]
    async fn test_message_too_large() {
        let transport = MockTransport::new_ble();
        let large_data = vec![0u8; 500]; // Larger than BLE MTU of 244

        let dest = TransportAddr::ble([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], None);
        let result = transport.send(&large_data, &dest).await;

        match result {
            Err(TransportError::MessageTooLarge { size, mtu }) => {
                assert_eq!(size, 500);
                assert_eq!(mtu, 244);
            }
            _ => panic!("expected MessageTooLarge error"),
        }
    }

    #[tokio::test]
    async fn test_offline_transport() {
        let transport = MockTransport::new_udp();
        transport.shutdown().await.unwrap();

        let dest: SocketAddr = "192.168.1.1:9000".parse().unwrap();
        let result = transport.send(b"hello", &TransportAddr::Udp(dest)).await;

        assert!(matches!(result, Err(TransportError::Offline)));
        assert!(!transport.is_online());
    }

    #[test]
    fn test_transport_registry() {
        let mut registry = TransportRegistry::new();
        assert!(registry.is_empty());

        registry.register(Arc::new(MockTransport::new_udp()));
        registry.register(Arc::new(MockTransport::new_ble()));

        assert_eq!(registry.len(), 2);
        assert!(!registry.is_empty());

        // Get by type
        let udp_providers = registry.providers_by_type(TransportType::Udp);
        assert_eq!(udp_providers.len(), 1);

        let ble_providers = registry.providers_by_type(TransportType::Ble);
        assert_eq!(ble_providers.len(), 1);

        // No LoRa providers
        let lora_providers = registry.providers_by_type(TransportType::LoRa);
        assert!(lora_providers.is_empty());
    }

    #[test]
    fn test_provider_for_addr() {
        let mut registry = TransportRegistry::new();
        registry.register(Arc::new(MockTransport::new_udp()));
        registry.register(Arc::new(MockTransport::new_ble()));

        // Can find UDP provider
        let udp_addr: SocketAddr = "192.168.1.1:9000".parse().unwrap();
        let provider = registry.provider_for_addr(&TransportAddr::Udp(udp_addr));
        assert!(provider.is_some());
        assert_eq!(provider.unwrap().transport_type(), TransportType::Udp);

        // Can find BLE provider
        let ble_addr = TransportAddr::ble([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], None);
        let provider = registry.provider_for_addr(&ble_addr);
        assert!(provider.is_some());
        assert_eq!(provider.unwrap().transport_type(), TransportType::Ble);

        // No LoRa provider
        let lora_addr = TransportAddr::lora([0xDE, 0xAD, 0xBE, 0xEF]);
        let provider = registry.provider_for_addr(&lora_addr);
        assert!(provider.is_none());
    }

    #[test]
    fn test_quic_capable_check() {
        let mut registry = TransportRegistry::new();
        registry.register(Arc::new(MockTransport::new_udp()));

        assert!(registry.has_quic_capable_transport());

        // BLE-only registry doesn't have QUIC capability
        let mut ble_only = TransportRegistry::new();
        ble_only.register(Arc::new(MockTransport::new_ble()));
        assert!(!ble_only.has_quic_capable_transport());
    }

    #[test]
    fn test_transport_diagnostics() {
        let transport = MockTransport::new_udp();
        let diag = TransportDiagnostics::from_provider(&transport);

        assert_eq!(diag.name, "MockUDP");
        assert_eq!(diag.transport_type, TransportType::Udp);
        assert_eq!(diag.protocol_engine, ProtocolEngine::Quic);
        assert!(diag.is_online);
        assert!(diag.local_addr.is_some());
    }

    #[test]
    fn test_transport_error_display() {
        let err = TransportError::AddressMismatch {
            expected: TransportType::Udp,
            actual: TransportType::Ble,
        };
        assert!(format!("{err}").contains("UDP"));
        assert!(format!("{err}").contains("BLE"));

        let err = TransportError::MessageTooLarge {
            size: 1000,
            mtu: 500,
        };
        assert!(format!("{err}").contains("1000"));
        assert!(format!("{err}").contains("500"));
    }

    #[test]
    fn test_link_quality_default() {
        let quality = LinkQuality::default();
        assert!(quality.rssi.is_none());
        assert!(quality.snr.is_none());
        assert!(quality.hop_count.is_none());
        assert!(quality.rtt.is_none());
    }
}
