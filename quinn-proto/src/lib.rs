//! Low-level protocol logic for the QUIC protoocol
//!
//! quinn-proto contains a fully deterministic implementation of QUIC protocol logic. It contains
//! no networking code and does not get any relevant timestamps from the operating system. Most
//! users may want to use the futures-based quinn API instead.
//!
//! The quinn-proto API might be of interest if you want to use it from a C or C++ project
//! through C bindings or if you want to use a different event loop than the one tokio provides.
//!
//! The most important types are `Endpoint`, which conceptually represents the protocol state for
//! a single socket and mostly manages configuration and dispatches incoming datagrams to the
//! related `Connection`. `Connection` types contain the bulk of the protocol logic related to
//! managing a single connection and all the related state (such as streams).

#![warn(missing_docs)]
#[cfg(test)]
#[macro_use]
extern crate assert_matches;
#[cfg(test)]
#[macro_use]
extern crate hex_literal;
#[cfg(test)]
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate slog;

use std::fmt;
use std::net::SocketAddr;
use std::ops;
use std::time::Duration;

mod assembler;
#[doc(hidden)]
pub mod coding;
mod packet;
mod range_set;
mod spaces;
#[cfg(test)]
mod tests;
mod transport_parameters;
#[doc(hidden)]
pub mod varint;

mod connection;
pub use crate::connection::{Connection, ConnectionError, Event, Timer, TimerSetting, TimerUpdate};

mod crypto;
pub use crate::crypto::{ClientConfig as CryptoClientConfig, TokenKey};

mod frame;
use crate::frame::Frame;
pub use crate::frame::{ApplicationClose, ConnectionClose};

mod endpoint;
pub use crate::endpoint::{ClientConfig, ConnectError, ConnectionHandle, DatagramEvent, Endpoint};

mod shared;
pub use crate::shared::{
    ConfigError, ConnectionEvent, ConnectionId, EcnCodepoint, EndpointConfig, EndpointEvent,
    ServerConfig, TransportConfig,
};

mod streams;
pub use crate::streams::{FinishError, ReadError, WriteError};

mod transport_error;
pub use crate::transport_error::{Code as TransportErrorCode, Error as TransportError};

/// The QUIC protocol version implemented
pub const VERSION: u32 = 0xff00_0014;

/// TLS ALPN value for HTTP over QUIC
pub const ALPN_QUIC_HTTP: &[u8] = b"hq-20";

/// TLS ALPN value for H3
pub const ALPN_QUIC_H3: &[u8] = b"h3-20";

/// Whether an endpoint was the initiator of a connection
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
        self == Side::Client
    }

    #[inline]
    /// Shorthand for `self == Side::Server`
    pub fn is_server(self) -> bool {
        self == Side::Server
    }
}

impl ops::Not for Side {
    type Output = Side;
    fn not(self) -> Side {
        match self {
            Side::Client => Side::Server,
            Side::Server => Side::Client,
        }
    }
}

impl slog::Value for Side {
    fn serialize(
        &self,
        _: &slog::Record<'_>,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_arguments(key, &format_args!("{:?}", self))
    }
}

/// Whether a stream communicates data in both directions or only from the initiator
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Directionality {
    /// Data flows in both directions
    Bi = 0,
    /// Data flows only from the stream's initiator
    Uni = 1,
}

impl Directionality {
    fn iter() -> impl Iterator<Item = Self> {
        [Directionality::Bi, Directionality::Uni].iter().cloned()
    }
}

impl fmt::Display for Directionality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use self::Directionality::*;
        f.pad(match *self {
            Bi => "bidirectional",
            Uni => "unidirectional",
        })
    }
}

impl slog::Value for Directionality {
    fn serialize(
        &self,
        _: &slog::Record<'_>,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_arguments(key, &format_args!("{:?}", self))
    }
}

/// Identifier for a stream within a particular connection
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct StreamId(#[doc(hidden)] pub u64);

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let initiator = match self.initiator() {
            Side::Client => "client",
            Side::Server => "server",
        };
        let directionality = match self.directionality() {
            Directionality::Uni => "uni",
            Directionality::Bi => "bi",
        };
        write!(
            f,
            "{} {}directional stream {}",
            initiator,
            directionality,
            self.index()
        )
    }
}

impl slog::Value for StreamId {
    fn serialize(
        &self,
        _: &slog::Record<'_>,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_arguments(key, &format_args!("{:?}", self))
    }
}

impl StreamId {
    pub(crate) fn new(initiator: Side, dir: Directionality, index: u64) -> Self {
        StreamId(index << 2 | (dir as u64) << 1 | initiator as u64)
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
    pub fn directionality(self) -> Directionality {
        if self.0 & 0x2 == 0 {
            Directionality::Bi
        } else {
            Directionality::Uni
        }
    }
    /// Distinguishes streams of the same initiator and directionality
    pub fn index(self) -> u64 {
        self.0 >> 2
    }
}

impl coding::Codec for StreamId {
    fn decode<B: bytes::Buf>(buf: &mut B) -> coding::Result<StreamId> {
        varint::read(buf).map(StreamId).ok_or(coding::UnexpectedEnd)
    }
    fn encode<B: bytes::BufMut>(&self, buf: &mut B) {
        varint::write(self.0, buf).unwrap()
    }
}

/// An outgoing packet
#[derive(Debug)]
pub struct Transmit {
    /// The socket this datagram should be sent to
    pub destination: SocketAddr,
    /// Explicit congestion notification bits to set on the packet
    pub ecn: Option<EcnCodepoint>,
    /// Contents of the datagram
    pub contents: Box<[u8]>,
}

//
// Useful internal constants
//

/// Draft 17 §5.1.1: endpoints SHOULD provide and maintain at least eight
/// connection IDs
const LOC_CID_COUNT: usize = 8;
const RESET_TOKEN_SIZE: usize = 16;
const MAX_CID_SIZE: usize = 18;
const MIN_CID_SIZE: usize = 4;
const MIN_INITIAL_SIZE: usize = 1200;
const MIN_MTU: u16 = 1232;
const TIMER_GRANULARITY: Duration = Duration::from_millis(1);
/// Maximum number of streams that can be uniquely identified by a stream ID
const MAX_STREAM_COUNT: u64 = 1 << 60;
