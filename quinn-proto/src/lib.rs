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

#![cfg_attr(not(fuzzing), warn(missing_docs))]
#![cfg_attr(test, allow(dead_code))]
// Fixes welcome:
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::too_many_arguments)]

use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    ops,
    time::Duration,
};

mod cid_queue;
#[doc(hidden)]
pub mod coding;
mod constant_time;
mod packet;
mod range_set;
#[cfg(all(test, feature = "rustls"))]
mod tests;
pub mod transport_parameters;
mod varint;

pub use varint::{VarInt, VarIntBoundsExceeded};

mod connection;
pub use crate::connection::{
    BytesSource, Chunk, Chunks, Connection, ConnectionError, ConnectionStats, Datagrams, Event,
    FinishError, ReadError, ReadableError, RecvStream, RttEstimator, SendDatagramError, SendStream,
    StreamEvent, Streams, UnknownStream, WriteError, Written,
};

mod config;
pub use config::{
    ClientConfig, ConfigError, EndpointConfig, IdleTimeout, ServerConfig, TransportConfig,
};

pub mod crypto;

mod frame;
use crate::frame::Frame;
pub use crate::frame::{ApplicationClose, ConnectionClose, Datagram};

mod endpoint;
pub use crate::endpoint::{ConnectError, ConnectionHandle, DatagramEvent, Endpoint};

mod shared;
pub use crate::shared::{ConnectionEvent, ConnectionId, EcnCodepoint, EndpointEvent};

mod transport_error;
pub use crate::transport_error::{Code as TransportErrorCode, Error as TransportError};

pub mod congestion;

mod cid_generator;
pub use crate::cid_generator::{ConnectionIdGenerator, RandomConnectionIdGenerator};

mod token;
use token::{ResetToken, RetryToken};

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;

#[doc(hidden)]
#[cfg(fuzzing)]
pub mod fuzzing {
    pub use crate::connection::{
        FinishError, Retransmits, SendStream, State as ConnectionState, Streams, StreamsState,
    };
    pub use crate::frame::ResetStream;
    pub use crate::packet::PartialDecode;
    pub use crate::transport_parameters::TransportParameters;
    use crate::MAX_CID_SIZE;
    use arbitrary::{Arbitrary, Result, Unstructured};
    pub use bytes::{BufMut, BytesMut};

    impl<'arbitrary> Arbitrary<'arbitrary> for TransportParameters {
        fn arbitrary(u: &mut Unstructured<'arbitrary>) -> Result<Self> {
            Ok(TransportParameters {
                initial_max_streams_bidi: u.arbitrary()?,
                initial_max_streams_uni: u.arbitrary()?,
                ack_delay_exponent: u.arbitrary()?,
                max_udp_payload_size: u.arbitrary()?,
                ..TransportParameters::default()
            })
        }
    }

    #[derive(Debug)]
    pub struct PacketParams {
        pub local_cid_len: usize,
        pub buf: BytesMut,
        pub grease_quic_bit: bool,
    }

    impl<'arbitrary> Arbitrary<'arbitrary> for PacketParams {
        fn arbitrary(u: &mut Unstructured<'arbitrary>) -> Result<Self> {
            let local_cid_len: usize = u.int_in_range(0..=MAX_CID_SIZE)?;
            let bytes: Vec<u8> = Vec::arbitrary(u)?;
            let mut buf = BytesMut::new();
            buf.put_slice(&bytes[..]);
            Ok(PacketParams {
                local_cid_len,
                buf,
                grease_quic_bit: bool::arbitrary(u)?,
            })
        }
    }
}

/// The QUIC protocol version implemented.
pub const DEFAULT_SUPPORTED_VERSIONS: &[u32] = &[
    0x00000001,
    0xff00_001d,
    0xff00_001e,
    0xff00_001f,
    0xff00_0020,
    0xff00_0021,
    0xff00_0022,
];

/// Whether an endpoint was the initiator of a connection
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
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
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
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
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
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
    /// Create a new StreamId
    pub fn new(initiator: Side, dir: Dir, index: u64) -> Self {
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

impl From<StreamId> for VarInt {
    fn from(x: StreamId) -> VarInt {
        unsafe { VarInt::from_u64_unchecked(x.0) }
    }
}

impl From<VarInt> for StreamId {
    fn from(v: VarInt) -> Self {
        Self(v.0)
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
    pub contents: Vec<u8>,
    /// The segment size if this transmission contains multiple datagrams.
    /// This is `None` if the transmit only contains a single datagram
    pub segment_size: Option<usize>,
    /// Optional source IP address for the datagram
    pub src_ip: Option<IpAddr>,
}

//
// Useful internal constants
//

/// The maximum number of CIDs we bother to issue per connection
const LOC_CID_COUNT: u64 = 8;
const RESET_TOKEN_SIZE: usize = 16;
const MAX_CID_SIZE: usize = 20;
const MIN_INITIAL_SIZE: u16 = 1200;
const INITIAL_MAX_UDP_PAYLOAD_SIZE: u16 = 1200;
const TIMER_GRANULARITY: Duration = Duration::from_millis(1);
/// Maximum number of streams that can be uniquely identified by a stream ID
const MAX_STREAM_COUNT: u64 = 1 << 60;
