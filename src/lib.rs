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
extern crate bincode;
extern crate serde;
#[macro_use]
extern crate serde_derive;
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

mod frame;
use frame::Frame;
pub use frame::{ApplicationClose, ConnectionClose};

mod from_bytes;
use from_bytes::{FromBytes};

mod endpoint;
pub use endpoint::{Endpoint, Config, PersistentState, ListenConfig, ConnectionHandle, Event, Io, Timer, ConnectionError};


mod transport_error;
pub use transport_error::Error as TransportError;


pub const VERSION: u32 = 0xff00000B;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Side { Client = 0, Server = 1 }

impl ::std::ops::Not for Side {
    type Output = Side;
    fn not(self) -> Side { match self { Side::Client => Side::Server, Side::Server => Side::Client } }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Directionality { Bi = 0, Uni = 1 }

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
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
    pub fn initiator(&self) -> Side { if self.0 & 0x1 == 0 { Side::Client } else { Side::Server } }
    pub fn directionality(&self) -> Directionality { if self.0 & 0x2 == 0 { Directionality::Bi } else { Directionality::Uni } }
    pub fn index(&self) -> u64 { self.0 >> 2 }
}

impl From<u64> for StreamId { fn from(x: u64) -> Self { StreamId(x) } }
