// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Multi-transport abstraction layer for ant-quic
//!
//! This module provides a transport abstraction that enables ant-quic to operate
//! over multiple physical mediums beyond UDP/IP. The design is based on the
//! multi-transport architecture described in `docs/research/CONSTRAINED_TRANSPORTS.md`.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                            APPLICATION                                   │
//! │                    (Node, P2pEndpoint, higher layers)                   │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                        PROTOCOL ENGINES                                  │
//! │   ┌─────────────────────┐     ┌─────────────────────────────────────┐   │
//! │   │    QUIC Engine      │     │      Constrained Engine             │   │
//! │   │  • Full RFC 9000    │     │  • Minimal headers (4-8 bytes)      │   │
//! │   │  • Quinn-based      │     │  • ARQ reliability                  │   │
//! │   └─────────────────────┘     └─────────────────────────────────────┘   │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                      TRANSPORT ABSTRACTION                               │
//! │                      (TransportProvider trait)                           │
//! │   ┌───────┬───────┬────────┬───────┬───────────────────────────────┐    │
//! │   │  UDP  │ BLE   │ Serial │ LoRa  │  Future Transports...         │    │
//! │   └───────┴───────┴────────┴───────┴───────────────────────────────┘    │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Key Types
//!
//! - [`TransportAddr`]: Unified addressing for all transport types
//! - [`TransportCapabilities`]: Describes what a transport can do
//! - [`TransportProvider`]: Trait for pluggable transport implementations
//! - [`TransportRegistry`]: Collection of available transports
//! - [`ProtocolEngine`]: Selector between QUIC and Constrained engines
//!
//! # Protocol Engine Selection
//!
//! The protocol engine is selected based on transport capabilities:
//!
//! | Criteria | QUIC Engine | Constrained Engine |
//! |----------|-------------|-------------------|
//! | Bandwidth | >= 10 kbps | < 10 kbps |
//! | MTU | >= 1200 bytes | < 1200 bytes |
//! | RTT | < 2 seconds | >= 2 seconds |
//!
//! # Example
//!
//! ```rust
//! use ant_quic::transport::{
//!     TransportAddr, TransportCapabilities, TransportType, ProtocolEngine,
//! };
//! use std::net::SocketAddr;
//!
//! // Create a UDP address
//! let addr = TransportAddr::Udp("192.168.1.1:9000".parse().unwrap());
//! assert_eq!(addr.transport_type(), TransportType::Udp);
//!
//! // Check capabilities
//! let caps = TransportCapabilities::broadband();
//! assert!(caps.supports_full_quic());
//! assert_eq!(ProtocolEngine::for_transport(&caps), ProtocolEngine::Quic);
//!
//! // Constrained transport uses different engine
//! let ble_caps = TransportCapabilities::ble();
//! assert!(!ble_caps.supports_full_quic());
//! assert_eq!(ProtocolEngine::for_transport(&ble_caps), ProtocolEngine::Constrained);
//! ```

// Sub-modules
mod addr;
mod capabilities;
mod provider;

// Transport provider implementations
mod udp;

#[cfg(feature = "ble")]
mod ble;

// Re-export core QUIC types for backward compatibility
pub use crate::connection::{
    Connection as QuicConnection, ConnectionError, ConnectionStats, Event as ConnectionEvent,
    FinishError, PathStats, ReadError, RecvStream, SendStream, ShouldTransmit, StreamEvent,
    Streams, WriteError,
};

pub use crate::endpoint::{
    AcceptError, ConnectError, ConnectionHandle, Endpoint as QuicEndpoint, Incoming,
};

pub use crate::shared::{ConnectionId, EcnCodepoint};
pub use crate::transport_error::{Code as TransportErrorCode, Error as TransportError};
pub use crate::transport_parameters;

// Re-export transport abstraction types
pub use addr::{LoRaParams, TransportAddr, TransportType};
pub use capabilities::{BandwidthClass, TransportCapabilities, TransportCapabilitiesBuilder};
pub use provider::{
    InboundDatagram, LinkQuality, ProtocolEngine, TransportDiagnostics,
    TransportError as ProviderError, TransportProvider, TransportRegistry, TransportStats,
};

// Re-export UDP transport provider
pub use udp::UdpTransport;

// Re-export BLE transport provider when feature is enabled
#[cfg(feature = "ble")]
pub use ble::BleTransport;

/// Create a default transport registry with UDP support
///
/// This is the standard starting point for most applications.
/// Additional transports can be added via feature flags or manual registration.
///
/// # Example
///
/// ```rust,ignore
/// use ant_quic::transport::default_registry;
///
/// let registry = default_registry("0.0.0.0:0").await?;
/// assert!(registry.has_quic_capable_transport());
/// ```
pub async fn default_registry(bind_addr: &str) -> Result<TransportRegistry, std::io::Error> {
    use std::sync::Arc;

    let mut registry = TransportRegistry::new();

    // Add UDP transport (always available)
    let udp = UdpTransport::bind(bind_addr.parse().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid address: {e}"),
        )
    })?)
    .await?;
    registry.register(Arc::new(udp));

    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn test_transport_addr_creation() {
        // UDP address
        let udp_addr: SocketAddr = "192.168.1.1:9000".parse().unwrap();
        let addr = TransportAddr::Udp(udp_addr);
        assert_eq!(addr.transport_type(), TransportType::Udp);

        // BLE address
        let ble_addr = TransportAddr::ble([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], None);
        assert_eq!(ble_addr.transport_type(), TransportType::Ble);

        // LoRa address
        let lora_addr = TransportAddr::lora([0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(lora_addr.transport_type(), TransportType::LoRa);
    }

    #[test]
    fn test_protocol_engine_selection() {
        // Broadband should use QUIC
        let broadband = TransportCapabilities::broadband();
        assert_eq!(
            ProtocolEngine::for_transport(&broadband),
            ProtocolEngine::Quic
        );

        // BLE should use Constrained (MTU too small)
        let ble = TransportCapabilities::ble();
        assert_eq!(
            ProtocolEngine::for_transport(&ble),
            ProtocolEngine::Constrained
        );

        // LoRa should use Constrained (all criteria fail)
        let lora = TransportCapabilities::lora_long_range();
        assert_eq!(
            ProtocolEngine::for_transport(&lora),
            ProtocolEngine::Constrained
        );
    }

    #[test]
    fn test_capability_profiles() {
        // Broadband supports QUIC
        let broadband = TransportCapabilities::broadband();
        assert!(broadband.supports_full_quic());
        assert_eq!(broadband.bandwidth_class(), BandwidthClass::High);

        // BLE doesn't support QUIC (MTU too small)
        let ble = TransportCapabilities::ble();
        assert!(!ble.supports_full_quic());
        assert!(ble.link_layer_acks);
        assert!(ble.power_constrained);

        // LoRa long-range doesn't support QUIC
        let lora = TransportCapabilities::lora_long_range();
        assert!(!lora.supports_full_quic());
        assert!(lora.half_duplex);
        assert!(lora.broadcast);

        // I2P overlay - high RTT (2s) means it's at the QUIC boundary
        // RTT must be < 2s for QUIC, I2P has typical_rtt = 2s so it's borderline
        let i2p = TransportCapabilities::i2p();
        // With RTT exactly at 2s, it doesn't support QUIC (requires < 2s)
        assert!(!i2p.supports_full_quic());

        // Yggdrasil supports QUIC (lower RTT)
        let yggdrasil = TransportCapabilities::yggdrasil();
        assert!(yggdrasil.supports_full_quic());
    }

    #[test]
    fn test_transport_registry_empty() {
        let registry = TransportRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
        assert!(!registry.has_quic_capable_transport());
    }

    #[test]
    fn test_bandwidth_estimation() {
        let lora = TransportCapabilities::lora_long_range();
        let time = lora.estimate_transmission_time(222);
        // 222 bytes * 8 bits / 293 bps ≈ 6 seconds
        assert!(time.as_secs() >= 5);
        assert!(time.as_secs() <= 7);
    }
}
