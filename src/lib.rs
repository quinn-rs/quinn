// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! ant-quic: QUIC transport protocol with advanced NAT traversal for P2P networks
#![allow(elided_lifetimes_in_paths)]
#![allow(missing_debug_implementations)]
//!
//! This library provides a clean, modular implementation of QUIC-native NAT traversal
//! using raw public keys for authentication. It is designed to be minimal, focused,
//! and highly testable, with exceptional cross-platform support.
//!
//! The library is organized into the following main modules:
//! - `transport`: Core QUIC transport functionality
//! - `nat_traversal`: QUIC-native NAT traversal protocol
//! - `discovery`: Platform-specific network interface discovery
//! - `crypto`: Raw public key authentication
//! - `trust`: Trust management with TOFU pinning and channel binding

// Documentation warnings enabled - all public APIs must be documented
#![cfg_attr(not(fuzzing), warn(missing_docs))]
#![allow(unreachable_pub)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::use_self)]
// Dead code warnings enabled - remove unused code
#![warn(dead_code)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::module_inception)]
#![allow(clippy::useless_vec)]
#![allow(private_interfaces)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::type_complexity)]
#![allow(clippy::manual_clamp)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::borrowed_box)]
#![allow(clippy::manual_strip)]
#![allow(clippy::if_same_then_else)]
#![allow(clippy::ptr_arg)]
#![allow(clippy::incompatible_msrv)]
#![allow(clippy::await_holding_lock)]
#![allow(clippy::single_match)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::let_underscore_must_use)]
#![allow(clippy::let_underscore_untyped)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::result_large_err)]
#![allow(clippy::enum_glob_use)]
#![allow(clippy::match_like_matches_macro)]
#![allow(clippy::struct_field_names)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::similar_names)]
#![allow(clippy::new_without_default)]
#![allow(clippy::unwrap_or_default)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::redundant_field_names)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::redundant_pattern_matching)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::trivially_copy_pass_by_ref)]
#![allow(clippy::len_without_is_empty)]
#![allow(clippy::explicit_auto_deref)]
#![allow(clippy::blocks_in_conditions)]
#![allow(clippy::collapsible_else_if)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::needless_bool)]
#![allow(clippy::needless_borrow)]
#![allow(clippy::redundant_static_lifetimes)]
#![allow(clippy::match_ref_pats)]
#![allow(clippy::should_implement_trait)]
#![allow(clippy::wildcard_imports)]
#![warn(unused_must_use)]
#![allow(improper_ctypes)]
#![allow(improper_ctypes_definitions)]
#![allow(non_upper_case_globals)]
#![allow(clippy::wrong_self_convention)]
#![allow(clippy::vec_init_then_push)]
#![allow(clippy::format_in_format_args)]
#![allow(clippy::from_over_into)]
#![allow(clippy::useless_conversion)]
#![allow(clippy::never_loop)]
#![allow(dropping_references)]
#![allow(non_snake_case)]
#![allow(clippy::unnecessary_literal_unwrap)]
#![allow(clippy::assertions_on_constants)]
#![allow(unused_imports)]

use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    ops,
};

// Core modules
mod cid_queue;
pub mod coding;
mod constant_time;
mod range_set;
pub mod transport_parameters;
mod varint;

pub use varint::{VarInt, VarIntBoundsExceeded};

// Removed optional bloom module

// Core implementation modules
/// Configuration structures and validation
pub mod config;
/// QUIC connection state machine and management
pub mod connection;
/// QUIC endpoint for accepting and initiating connections
pub mod endpoint;
/// QUIC frame types and encoding/decoding
pub mod frame;
/// QUIC packet structures and processing
pub mod packet;
/// Shared types and utilities
pub mod shared;
/// Transport error types and codes
pub mod transport_error;
// Simplified congestion control
/// Network candidate discovery and management
pub mod candidate_discovery;
/// Connection ID generation strategies
pub mod cid_generator;
mod congestion;
mod protocol_violations;
#[cfg(test)]
mod protocol_violations_tests;

// Zero-cost tracing system
/// High-level NAT traversal API
pub mod nat_traversal_api;
mod token;
mod token_memory_cache;
/// Zero-cost tracing and event logging system
pub mod tracing;

// Public modules with new structure
/// Cryptographic operations and raw public key support
pub mod crypto;
/// Platform-specific network interface discovery
pub mod discovery;
/// NAT traversal protocol implementation
pub mod nat_traversal;
/// Transport-level protocol implementation
pub mod transport;

// Additional modules
/// Peer authentication system
pub mod auth;
/// Secure chat protocol implementation
pub mod chat;
// Performance optimization utilities are deprecated; remove module to eliminate dead code
// pub mod optimization;

// ============================================================================
// P2P API
// ============================================================================

/// P2P endpoint - the primary API for ant-quic
///
/// This module provides the main API for P2P networking with NAT traversal,
/// connection management, and secure communication.
pub mod p2p_endpoint;

/// P2P configuration system
///
/// This module provides `P2pConfig` with builder pattern support for
/// configuring endpoints, NAT traversal, MTU, PQC, and other settings.
pub mod unified_config;

/// Real-time statistics dashboard
pub mod stats_dashboard;
/// Terminal user interface components
pub mod terminal_ui;

// Compliance validation framework
/// IETF compliance validation tools
pub mod compliance_validator;

// Comprehensive logging system
/// Structured logging and diagnostics
pub mod logging;

/// Metrics collection and export system (basic metrics always available)
pub mod metrics;

/// TURN-style relay protocol for NAT traversal fallback
pub mod relay;

/// Transport trust module (TOFU, rotations, channel binding surfaces)
pub mod trust;

/// Address-validation tokens bound to (PeerId||CID||nonce)
#[cfg(feature = "aws-lc-rs")]
pub mod token_v2;

// High-level async API modules (ported from quinn crate)
pub mod high_level;

// Re-export high-level API types for easier usage
pub use high_level::{
    Accept, Connecting, Connection as HighLevelConnection, Endpoint,
    RecvStream as HighLevelRecvStream, SendStream as HighLevelSendStream,
};

// Re-export crypto utilities for peer ID management
pub use crypto::raw_public_keys::key_utils::{
    derive_peer_id_from_key_bytes, derive_peer_id_from_public_key, generate_ed25519_keypair,
    public_key_from_bytes, public_key_to_bytes, verify_peer_id,
};

// Re-export key types for backward compatibility
pub use candidate_discovery::{
    CandidateDiscoveryManager, DiscoveryConfig, DiscoveryError, DiscoveryEvent, NetworkInterface,
    ValidatedCandidate,
};
// v0.13.0: NatTraversalRole removed - all nodes are symmetric P2P nodes
pub use connection::nat_traversal::{CandidateSource, CandidateState};
pub use connection::{
    Chunk, Chunks, ClosedStream, Connection, ConnectionError, ConnectionStats, Datagrams, Event,
    FinishError, ReadError, ReadableError, RecvStream, SendDatagramError, SendStream, StreamEvent,
    Streams, WriteError, Written,
};
pub use endpoint::{
    AcceptError, ConnectError, ConnectionHandle, DatagramEvent, Endpoint as LowLevelEndpoint,
    Incoming,
};
pub use nat_traversal_api::{
    BootstrapNode, CandidateAddress, NatTraversalConfig, NatTraversalEndpoint,
    NatTraversalError, NatTraversalEvent, NatTraversalStatistics, PeerId,
};

// ============================================================================
// P2P API EXPORTS
// ============================================================================

/// P2P endpoint - the primary entry point for applications
pub use p2p_endpoint::{
    ConnectionMetrics, DisconnectReason, EndpointError, EndpointStats, P2pEndpoint, P2pEvent,
    PeerConnection, TraversalPhase,
};

/// P2P configuration with builder pattern
pub use unified_config::{ConfigError, MtuConfig, NatConfig, P2pConfig, P2pConfigBuilder};

pub use relay::{
    AuthToken, RelayAction, RelayAuthenticator, RelayConnection, RelayConnectionConfig, RelayError,
    RelayEvent, RelayResult, SessionId, SessionManager, SessionState,
};
pub use shared::{ConnectionId, EcnCodepoint, EndpointEvent};
pub use transport_error::{Code as TransportErrorCode, Error as TransportError};

// #[cfg(fuzzing)]
// pub mod fuzzing; // Module not implemented yet

/// The QUIC protocol version implemented.
///
/// Simplified to include only the essential versions:
/// - 0x00000001: QUIC v1 (RFC 9000)
/// - 0xff00_001d: Draft 29
pub const DEFAULT_SUPPORTED_VERSIONS: &[u32] = &[
    0x00000001,  // QUIC v1 (RFC 9000)
    0xff00_001d, // Draft 29
];

/// Whether an endpoint was the initiator of a connection
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Side {
    /// The initiator of a connection
    Client = 0,
    /// The acceptor of a connection
    Server = 1,
}

impl Side {
    #[inline]
    /// Shorthand for `self == Side::Client`
    pub fn is_client(self) -> bool {
        self == Self::Client
    }

    #[inline]
    /// Shorthand for `self == Side::Server`
    pub fn is_server(self) -> bool {
        self == Self::Server
    }
}

impl ops::Not for Side {
    type Output = Self;
    fn not(self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }
}

/// Whether a stream communicates data in both directions or only from the initiator
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Dir {
    /// Data flows in both directions
    Bi = 0,
    /// Data flows only from the stream's initiator
    Uni = 1,
}

impl Dir {
    fn iter() -> impl Iterator<Item = Self> {
        [Self::Bi, Self::Uni].iter().cloned()
    }
}

impl fmt::Display for Dir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Dir::*;
        f.pad(match *self {
            Bi => "bidirectional",
            Uni => "unidirectional",
        })
    }
}

/// Identifier for a stream within a particular connection
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct StreamId(u64);

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let initiator = match self.initiator() {
            Side::Client => "client",
            Side::Server => "server",
        };
        let dir = match self.dir() {
            Dir::Uni => "uni",
            Dir::Bi => "bi",
        };
        write!(
            f,
            "{} {}directional stream {}",
            initiator,
            dir,
            self.index()
        )
    }
}

impl StreamId {
    /// Create a new StreamId
    pub fn new(initiator: Side, dir: Dir, index: u64) -> Self {
        Self((index << 2) | ((dir as u64) << 1) | initiator as u64)
    }
    /// Which side of a connection initiated the stream
    pub fn initiator(self) -> Side {
        if self.0 & 0x1 == 0 {
            Side::Client
        } else {
            Side::Server
        }
    }
    /// Which directions data flows in
    pub fn dir(self) -> Dir {
        if self.0 & 0x2 == 0 { Dir::Bi } else { Dir::Uni }
    }
    /// Distinguishes streams of the same initiator and directionality
    pub fn index(self) -> u64 {
        self.0 >> 2
    }
}

impl From<StreamId> for VarInt {
    fn from(x: StreamId) -> Self {
        unsafe { Self::from_u64_unchecked(x.0) }
    }
}

impl From<VarInt> for StreamId {
    fn from(v: VarInt) -> Self {
        Self(v.0)
    }
}

impl From<StreamId> for u64 {
    fn from(x: StreamId) -> Self {
        x.0
    }
}

impl coding::Codec for StreamId {
    fn decode<B: bytes::Buf>(buf: &mut B) -> coding::Result<Self> {
        VarInt::decode(buf).map(|x| Self(x.into_inner()))
    }
    fn encode<B: bytes::BufMut>(&self, buf: &mut B) {
        // StreamId values should always be valid VarInt values, but handle the error case
        match VarInt::from_u64(self.0) {
            Ok(varint) => varint.encode(buf),
            Err(_) => {
                // This should never happen for valid StreamIds, but use a safe fallback
                VarInt::MAX.encode(buf);
            }
        }
    }
}

/// An outgoing packet
#[derive(Debug)]
#[must_use]
pub struct Transmit {
    /// The socket this datagram should be sent to
    pub destination: SocketAddr,
    /// Explicit congestion notification bits to set on the packet
    pub ecn: Option<EcnCodepoint>,
    /// Amount of data written to the caller-supplied buffer
    pub size: usize,
    /// The segment size if this transmission contains multiple datagrams.
    /// This is `None` if the transmit only contains a single datagram
    pub segment_size: Option<usize>,
    /// Optional source IP address for the datagram
    pub src_ip: Option<IpAddr>,
}

// Deal with time
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub(crate) use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
pub(crate) use web_time::{Duration, Instant, SystemTime, UNIX_EPOCH};

//
// Useful internal constants
//

/// The maximum number of CIDs we bother to issue per connection
pub(crate) const LOC_CID_COUNT: u64 = 8;
pub(crate) const RESET_TOKEN_SIZE: usize = 16;
pub(crate) const MAX_CID_SIZE: usize = 20;
pub(crate) const MIN_INITIAL_SIZE: u16 = 1200;
/// <https://www.rfc-editor.org/rfc/rfc9000.html#name-datagram-size>
pub(crate) const INITIAL_MTU: u16 = 1200;
pub(crate) const MAX_UDP_PAYLOAD: u16 = 65527;
pub(crate) const TIMER_GRANULARITY: Duration = Duration::from_millis(1);
/// Maximum number of streams that can be tracked per connection
pub(crate) const MAX_STREAM_COUNT: u64 = 1 << 60;

// Internal type re-exports for crate modules
pub use cid_generator::RandomConnectionIdGenerator;
pub use config::{
    AckFrequencyConfig, ClientConfig, EndpointConfig, MtuDiscoveryConfig, ServerConfig,
    TransportConfig,
};

// Post-Quantum Cryptography (PQC) re-exports - always available
pub use crypto::pqc::{
    HybridKem, HybridSignature, MlDsa65, MlKem768, PqcConfig, PqcConfigBuilder, PqcError, PqcResult,
};
pub(crate) use frame::Frame;
pub use token::TokenStore;
pub(crate) use token::{NoneTokenLog, ResetToken, TokenLog};
pub(crate) use token_memory_cache::TokenMemoryCache;
