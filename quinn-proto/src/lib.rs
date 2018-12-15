#[cfg(test)]
#[macro_use]
extern crate assert_matches;
#[macro_use]
extern crate failure;
#[cfg(test)]
#[macro_use]
extern crate hex_literal;
#[cfg(test)]
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate slog;

use std::fmt;
use std::ops;

mod coding;
mod dedup;
mod range_set;
#[cfg(test)]
mod tests;
mod transport_parameters;
mod varint;

mod connection;
pub use crate::connection::{ConnectionError, ConnectionHandle};

mod crypto;
pub use crate::crypto::{ClientConfig, ConnectError, TokenKey};

mod frame;
use crate::frame::Frame;
pub use crate::frame::{ApplicationClose, ConnectionClose};

mod endpoint;
pub use crate::endpoint::{Config, Endpoint, EndpointError, Event, Io, ServerConfig, Timer};

mod packet;
pub use crate::packet::{ConnectionId, EcnCodepoint};

mod stream;
pub use crate::stream::{ReadError, WriteError};

mod transport_error;
pub use crate::transport_error::Error as TransportError;

/// The QUIC protocol version implemented
pub const VERSION: u32 = 0xff00_000f;

/// TLS ALPN value for HTTP over QUIC
pub const ALPN_QUIC_HTTP: &[u8] = b"hq-11";

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
    fn is_client(self) -> bool {
        self == Side::Client
    }

    #[inline]
    fn is_server(self) -> bool {
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

/// Identifier for a stream within a particular connection
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct StreamId(pub(crate) u64);

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
    pub(crate) fn new(initiator: Side, directionality: Directionality, index: u64) -> Self {
        StreamId(index << 2 | (directionality as u64) << 1 | initiator as u64)
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

//
// Useful internal constants
//

const RESET_TOKEN_SIZE: usize = 16;
const MAX_CID_SIZE: usize = 18;
const MIN_CID_SIZE: usize = 4;
const MIN_INITIAL_SIZE: usize = 1200;
const MIN_MTU: u16 = 1232;
