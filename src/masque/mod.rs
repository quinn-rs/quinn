// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! MASQUE CONNECT-UDP Bind Protocol Implementation
//!
//! This module implements the MASQUE relay mechanism per
//! draft-ietf-masque-connect-udp-listen-10 for enabling
//! fully connectable P2P nodes.
//!
//! # Overview
//!
//! MASQUE (Multiplexed Application Substrate over QUIC Encryption) provides
//! a standardized mechanism for proxying UDP traffic over QUIC connections.
//! The CONNECT-UDP Bind extension allows nodes behind NATs to receive
//! inbound connections through a relay server.
//!
//! # Protocol Components
//!
//! ## Capsules
//!
//! HTTP Capsules are used for control plane operations:
//!
//! - **COMPRESSION_ASSIGN** (0x11): Register a Context ID for header compression
//! - **COMPRESSION_ACK** (0x12): Acknowledge context registration
//! - **COMPRESSION_CLOSE** (0x13): Close or reject a context
//!
//! ## Context IDs
//!
//! Context IDs enable header compression:
//!
//! - Clients allocate even Context IDs (starting at 2)
//! - Servers allocate odd Context IDs (starting at 1)
//! - Context ID 0 is reserved
//! - Only one uncompressed context is allowed per direction
//!
//! ## Datagrams
//!
//! Two datagram formats are supported:
//!
//! 1. **Uncompressed**: Includes full target address in each datagram
//! 2. **Compressed**: Target address is implicit from context registration
//!
//! # Example
//!
//! ```rust
//! use ant_quic::masque::{ContextManager, CompressionAssign, CompressedDatagram};
//! use ant_quic::VarInt;
//! use bytes::Bytes;
//! use std::net::{SocketAddr, IpAddr, Ipv4Addr};
//!
//! // Create a context manager for a client
//! let mut mgr = ContextManager::new(true);
//!
//! // Allocate a context ID for a specific target
//! let context_id = mgr.allocate_local().unwrap();
//! let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8080);
//!
//! // Register the compressed context
//! mgr.register_compressed(context_id, target).unwrap();
//!
//! // Create a COMPRESSION_ASSIGN capsule to send to the relay
//! let assign = CompressionAssign::compressed_v4(
//!     context_id,
//!     Ipv4Addr::new(192, 168, 1, 100),
//!     8080
//! );
//!
//! // After receiving COMPRESSION_ACK, the context is active
//! mgr.handle_ack(context_id).unwrap();
//!
//! // Now we can send compressed datagrams
//! let datagram = CompressedDatagram::new(context_id, Bytes::from("Hello!"));
//! let encoded = datagram.encode();
//! ```
//!
//! # Security Considerations
//!
//! - All relay operations use ML-KEM-768 and ML-DSA-65 for authentication
//! - Rate limiting prevents abuse of relay resources
//! - Context IDs are validated to prevent spoofing
//! - Anti-replay protection is enforced on control messages
//!
//! # References
//!
//! - [draft-ietf-masque-connect-udp-listen-10](https://datatracker.ietf.org/doc/draft-ietf-masque-connect-udp-listen/)
//! - [RFC 9298 - CONNECT-UDP](https://datatracker.ietf.org/doc/rfc9298/)
//! - [RFC 9297 - HTTP Datagrams](https://datatracker.ietf.org/doc/rfc9297/)

pub mod capsule;
pub mod context;
pub mod datagram;

// Re-export primary types for convenience
pub use capsule::{
    CAPSULE_COMPRESSION_ACK, CAPSULE_COMPRESSION_ASSIGN, CAPSULE_COMPRESSION_CLOSE, Capsule,
    CompressionAck, CompressionAssign, CompressionClose,
};
pub use context::{ContextError, ContextInfo, ContextManager, ContextState};
pub use datagram::{CompressedDatagram, Datagram, UncompressedDatagram};
