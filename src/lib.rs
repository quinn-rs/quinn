extern crate bytes;
extern crate byteorder;
extern crate rand;
extern crate openssl;
extern crate slab;
#[macro_use]
extern crate failure;
extern crate digest;
extern crate blake2;
extern crate constant_time_eq;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate slog;
#[cfg(test)]
#[macro_use]
extern crate assert_matches;
#[cfg(test)]
#[macro_use]
extern crate hex_literal;
extern crate arrayvec;
extern crate fnv;

use std::fmt;

mod varint;
mod memory_stream;
mod transport_parameters;
mod coding;
mod hkdf;
mod range_set;
mod stream;

mod frame;
use frame::Frame;
pub use frame::{ApplicationClose, ConnectionClose};

mod endpoint;
pub use endpoint::{Endpoint, Config, PersistentState, ListenConfig, ConnectionHandle, Event, Io, Timer, ConnectionError, ReadError, WriteError};

mod transport_error;
pub use transport_error::Error as TransportError;


/// The QUIC protocol version implemented
pub const VERSION: u32 = 0xff00000B;

/// Whether an endpoint was the initiator of a connection
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Side {
    /// The initiator of a connection
    Client = 0,
    /// The acceptor of a connection
    Server = 1,
}

impl ::std::ops::Not for Side {
    type Output = Side;
    fn not(self) -> Side { match self { Side::Client => Side::Server, Side::Server => Side::Client } }
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
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let initiator = match self.initiator() { Side::Client => "client", Side::Server => "server" };
        let directionality = match self.directionality() { Directionality::Uni => "uni", Directionality::Bi => "bi" };
        write!(f, "{} {}directional stream {}", initiator, directionality, self.index())
    }
}

impl StreamId {
    pub(crate) fn new(initiator: Side, directionality: Directionality, index: u64) -> Self {
        StreamId(index << 2 | (directionality as u64) << 1 | initiator as u64)
    }
    /// Which side of a connection initiated the stream
    pub fn initiator(&self) -> Side { if self.0 & 0x1 == 0 { Side::Client } else { Side::Server } }
    /// Which directions data flows in
    pub fn directionality(&self) -> Directionality { if self.0 & 0x2 == 0 { Directionality::Bi } else { Directionality::Uni } }
    /// Distinguishes streams of the same initiator and directionality
    pub fn index(&self) -> u64 { self.0 >> 2 }
}

impl coding::Value for StreamId {
    fn decode<B: bytes::Buf>(buf: &mut B) -> coding::Result<StreamId> {
        varint::read(buf).map(StreamId).ok_or(coding::UnexpectedEnd)
    }
    fn encode<B: bytes::BufMut>(&self, buf: &mut B) {
        varint::write(self.0, buf).unwrap()
    }
}
