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
#![cfg_attr(test, allow(dead_code))]
// Fixes welcome:
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::too_many_arguments)]

use std::{fmt, net::SocketAddr, ops, time::Duration};

mod assembler;
mod cid_queue;
#[doc(hidden)]
pub mod coding;
mod constant_time;
mod packet;
mod range_set;
mod send_buffer;
mod spaces;
#[cfg(all(test, feature = "rustls"))]
mod tests;
mod timer;
pub mod transport_parameters;
mod varint;

pub use varint::{VarInt, VarIntBoundsExceeded};

mod connection;
pub use crate::connection::{ConnectionError, Event, SendDatagramError};

pub mod crypto;
#[cfg(feature = "rustls")]
pub use crypto::{rustls::AuthenticationData, types::*};

mod frame;
use crate::frame::Frame;
pub use crate::frame::{ApplicationClose, ConnectionClose, Datagram};

mod endpoint;
pub use crate::endpoint::{ConnectError, ConnectionHandle, DatagramEvent};

mod shared;
pub use crate::shared::{
    ConfigError, ConnectionEvent, ConnectionId, EcnCodepoint, EndpointEvent, TransportConfig,
};

mod streams;
pub use crate::streams::{FinishError, ReadError, UnknownStream, WriteError};

mod transport_error;
pub use crate::transport_error::{Code as TransportErrorCode, Error as TransportError};

/// Types that are generic over the crypto protocol implementation
pub mod generic {
    pub use crate::{
        connection::Connection,
        endpoint::Endpoint,
        shared::{ClientConfig, EndpointConfig, ServerConfig},
    };
}

#[cfg(feature = "rustls")]
mod rustls_impls {
    use crate::{crypto, generic};

    /// A `Connection` using rustls for the cryptography protocol
    pub type Connection = generic::Connection<crypto::rustls::TlsSession>;
    /// A `ClientConfig` containing client-side rustls configuration
    pub type ClientConfig = generic::ClientConfig<crypto::rustls::TlsSession>;
    /// An `Endpoint` using rustls for the cryptography protocol
    pub type Endpoint = generic::Endpoint<crypto::rustls::TlsSession>;
    /// A `ServerConfig` containing server-side rustls configuration
    pub type ServerConfig = generic::ServerConfig<crypto::rustls::TlsSession>;
    /// A `EndpointConfig` using rustls keys
    pub type EndpointConfig = generic::EndpointConfig<crypto::rustls::TlsSession>;
}

#[cfg(feature = "rustls")]
pub use crate::rustls_impls::*;

/// The QUIC protocol version implemented
const VERSION: u32 = 0xff00_001b;

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

/// Whether a stream communicates data in both directions or only from the initiator
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Dir {
    /// Data flows in both directions
    Bi = 0,
    /// Data flows only from the stream's initiator
    Uni = 1,
}

impl Dir {
    fn iter() -> impl Iterator<Item = Self> {
        [Dir::Bi, Dir::Uni].iter().cloned()
    }
}

impl fmt::Display for Dir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use self::Dir::*;
        f.pad(match *self {
            Bi => "bidirectional",
            Uni => "unidirectional",
        })
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
    pub(crate) fn new(initiator: Side, dir: Dir, index: u64) -> Self {
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
    pub fn dir(self) -> Dir {
        if self.0 & 0x2 == 0 {
            Dir::Bi
        } else {
            Dir::Uni
        }
    }
    /// Distinguishes streams of the same initiator and directionality
    pub fn index(self) -> u64 {
        self.0 >> 2
    }
}

impl coding::Codec for StreamId {
    fn decode<B: bytes::Buf>(buf: &mut B) -> coding::Result<StreamId> {
        VarInt::decode(buf).map(|x| StreamId(x.into_inner()))
    }
    fn encode<B: bytes::BufMut>(&self, buf: &mut B) {
        VarInt::from_u64(self.0).unwrap().encode(buf);
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

/// The maximum number of CIDs we bother to issue per connection
const LOC_CID_COUNT: u64 = 8;
const RESET_TOKEN_SIZE: usize = 16;
const MAX_CID_SIZE: usize = 20;
const MIN_INITIAL_SIZE: usize = 1200;
const MIN_MTU: u16 = 1232;
const TIMER_GRANULARITY: Duration = Duration::from_millis(1);
/// Maximum number of streams that can be uniquely identified by a stream ID
const MAX_STREAM_COUNT: u64 = 1 << 60;
