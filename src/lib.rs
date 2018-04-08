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
