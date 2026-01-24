// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! NAT Traversal Protocol Implementation
//!
//! This module implements the QUIC-native NAT traversal approach based on
//! draft-seemann-quic-nat-traversal-01. It focuses exclusively on the three
//! required QUIC extension frames and implements a clean state machine for
//! NAT traversal lifecycle.
//!
//! IMPORTANT: This implementation uses ONLY the QUIC-native approach and does NOT
//! include any STUN, ICE, or other external NAT traversal protocols. All NAT traversal
//! functionality is implemented as QUIC protocol extensions using custom frames and
//! transport parameters as defined in the draft specification.
//!
//! # Multi-Transport Support (v0.19.0+)
//!
//! The ADD_ADDRESS frame has been extended to support multiple transport types beyond
//! UDP/IP. This enables advertising addresses on alternative transports such as:
//!
//! - **BLE** (Bluetooth Low Energy)
//! - **LoRa** (Long Range radio)
//! - **Serial** (Direct serial connections)
//! - **AX.25** (Packet radio)
//! - **I2P** (Anonymous overlay)
//! - **Yggdrasil** (Mesh networking)
//!
//! The wire format includes a transport type indicator and optional capability flags
//! that summarize transport characteristics (bandwidth, latency, MTU tiers).
//!
//! ## Key Types
//!
//! - [`CapabilityFlags`]: Compact 16-bit summary of transport capabilities
//! - [`frames::AddAddress`]: Extended ADD_ADDRESS frame with transport type
//! - [`NatTraversalEndpoint::advertise_transport_address`]: Multi-transport advertising
//!
//! ## Example
//!
//! ```ignore
//! use ant_quic::nat_traversal::CapabilityFlags;
//! use ant_quic::transport::TransportAddr;
//!
//! // Advertise a BLE address with capability flags
//! endpoint.advertise_transport_address(
//!     TransportAddr::Ble {
//!         device_id: [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC],
//!         service_uuid: None,
//!     },
//!     50,
//!     Some(CapabilityFlags::ble()),
//! );
//! ```

// Re-export public NAT traversal API
pub use crate::nat_traversal_api::{
    BootstrapNode,
    CandidateAddress,
    NatTraversalConfig,
    NatTraversalEndpoint,
    NatTraversalError,
    NatTraversalEvent,
    NatTraversalStatistics,
    PeerId,
    // Multi-transport support
    TransportCandidate,
};

// Re-export capability flags for multi-transport advertisements
pub use frames::CapabilityFlags;

// Re-export NAT traversal types from connection module
// v0.13.0: NatTraversalRole removed - all nodes are symmetric P2P nodes
pub use crate::connection::nat_traversal::{CandidateSource, CandidateState};

// Submodules
pub mod frames;
pub mod rfc_migration;

// Note: rfc_compliant_frames.rs is not included as it has compile errors
// and duplicates functionality in frames.rs

// Module-private imports
// Note: The actual NAT traversal implementation is in src/connection/nat_traversal.rs
// This module only contains protocol-level types and RFC migration utilities
