//! ant-quic: QUIC transport protocol with advanced NAT traversal for P2P networks
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
//! - `api`: High-level P2P networking API

#![cfg_attr(not(fuzzing), warn(missing_docs))]
#![cfg_attr(test, allow(dead_code))]
#![warn(unreachable_pub)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::too_many_arguments)]
#![warn(clippy::use_self)]

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
pub mod config;
pub mod connection;
pub mod endpoint;
pub mod frame;
pub mod packet;
pub mod shared;
pub mod transport_error;
// Simplified congestion control
pub mod candidate_discovery;
pub mod cid_generator;
mod congestion;

// Zero-cost tracing system
pub mod tracing;
mod connection_establishment_simple;
pub mod nat_traversal_api;
mod token;
mod token_memory_cache;

// Public modules with new structure
pub mod api;
pub mod crypto;
pub mod discovery;
pub mod nat_traversal;
pub mod transport;

// Additional modules
pub mod auth;
pub mod chat;
pub mod optimization;
pub mod quic_node;
pub mod stats_dashboard;
pub mod terminal_ui;

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
pub use connection::nat_traversal::{CandidateSource, CandidateState, NatTraversalRole};
pub use connection::{
    Chunk, Chunks, ClosedStream, Connection, ConnectionError, ConnectionStats, Datagrams, Event,
    FinishError, ReadError, ReadableError, RecvStream, SendDatagramError, SendStream, StreamEvent,
    Streams, WriteError, Written,
};
pub use connection_establishment_simple::{
    SimpleConnectionEstablishmentManager, SimpleConnectionEvent, SimpleEstablishmentConfig,
};
pub use endpoint::{
    AcceptError, ConnectError, ConnectionHandle, DatagramEvent, Endpoint as LowLevelEndpoint,
    Incoming,
};
pub use nat_traversal_api::{
    BootstrapNode, CandidateAddress, EndpointRole, NatTraversalConfig, NatTraversalEndpoint,
    NatTraversalError, NatTraversalEvent, NatTraversalStatistics, PeerId,
};
pub use quic_node::{NodeStats as QuicNodeStats, QuicNodeConfig, QuicP2PNode};
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
        VarInt::from_u64(self.0).unwrap().encode(buf);
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
pub(crate) use frame::Frame;
pub(crate) use token::{NoneTokenLog, ResetToken, TokenLog, TokenStore};
pub(crate) use token_memory_cache::TokenMemoryCache;
