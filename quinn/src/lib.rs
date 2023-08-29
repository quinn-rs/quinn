//! QUIC transport protocol implementation
//!
//! [QUIC](https://en.wikipedia.org/wiki/QUIC) is a modern transport protocol addressing
//! shortcomings of TCP, such as head-of-line blocking, poor security, slow handshakes, and
//! inefficient congestion control. This crate provides a portable userspace implementation. It
//! builds on top of quinn-proto, which implements protocol logic independent of any particular
//! runtime.
//!
//! The entry point of this crate is the [`Endpoint`].
//!
//! # About QUIC
//!
//! A QUIC connection is an association between two endpoints. The endpoint which initiates the
//! connection is termed the client, and the endpoint which accepts it is termed the server. A
//! single endpoint may function as both client and server for different connections, for example
//! in a peer-to-peer application. To communicate application data, each endpoint may open streams
//! up to a limit dictated by its peer. Typically, that limit is increased as old streams are
//! finished.
//!
//! Streams may be unidirectional or bidirectional, and are cheap to create and disposable. For
//! example, a traditionally datagram-oriented application could use a new stream for every
//! message it wants to send, no longer needing to worry about MTUs. Bidirectional streams behave
//! much like a traditional TCP connection, and are useful for sending messages that have an
//! immediate response, such as an HTTP request. Stream data is delivered reliably, and there is no
//! ordering enforced between data on different streams.
//!
//! By avoiding head-of-line blocking and providing unified congestion control across all streams
//! of a connection, QUIC is able to provide higher throughput and lower latency than one or
//! multiple TCP connections between the same two hosts, while providing more useful behavior than
//! raw UDP sockets.
//!
//! Quinn also exposes unreliable datagrams, which are a low-level primitive preferred when
//! automatic fragmentation and retransmission of certain data is not desired.
//!
//! QUIC uses encryption and identity verification built directly on TLS 1.3. Just as with a TLS
//! server, it is useful for a QUIC server to be identified by a certificate signed by a trusted
//! authority. If this is infeasible--for example, if servers are short-lived or not associated
//! with a domain name--then as with TLS, self-signed certificates can be used to provide
//! encryption alone.
#![warn(missing_docs)]
#![warn(unreachable_pub)]
#![warn(clippy::use_self)]

use std::time::Duration;

macro_rules! ready {
    ($e:expr $(,)?) => {
        match $e {
            std::task::Poll::Ready(t) => t,
            std::task::Poll::Pending => return std::task::Poll::Pending,
        }
    };
}

mod connection;
mod endpoint;
mod mutex;
mod recv_stream;
mod runtime;
mod send_stream;
mod work_limiter;

pub use proto::{
    congestion, crypto, AckFrequencyConfig, ApplicationClose, Chunk, ClientConfig, ConfigError,
    ConnectError, ConnectionClose, ConnectionError, EndpointConfig, IdleTimeout,
    MtuDiscoveryConfig, ServerConfig, StreamId, Transmit, TransportConfig, VarInt,
};
#[cfg(feature = "tls-rustls")]
pub use rustls;
pub use udp;

pub use crate::connection::{
    AcceptBi, AcceptUni, Connecting, Connection, OpenBi, OpenUni, ReadDatagram, SendDatagramError,
    UnknownStream, ZeroRttAccepted,
};
pub use crate::endpoint::{Accept, Endpoint};
pub use crate::recv_stream::{ReadError, ReadExactError, ReadToEndError, RecvStream};
#[cfg(feature = "runtime-async-std")]
pub use crate::runtime::AsyncStdRuntime;
#[cfg(feature = "runtime-tokio")]
pub use crate::runtime::TokioRuntime;
pub use crate::runtime::{default_runtime, AsyncTimer, AsyncUdpSocket, Runtime};
pub use crate::send_stream::{SendStream, StoppedError, WriteError};

#[cfg(test)]
mod tests;

#[derive(Debug)]
enum ConnectionEvent {
    Close {
        error_code: VarInt,
        reason: bytes::Bytes,
    },
    Proto(proto::ConnectionEvent),
    Ping,
}

#[derive(Debug)]
enum EndpointEvent {
    Proto(proto::EndpointEvent),
    Transmit(proto::Transmit),
}

/// Maximum number of datagrams processed in send/recv calls to make before moving on to other processing
///
/// This helps ensure we don't starve anything when the CPU is slower than the link.
/// Value is selected by picking a low number which didn't degrade throughput in benchmarks.
const IO_LOOP_BOUND: usize = 160;

/// The maximum amount of time that should be spent in `recvmsg()` calls per endpoint iteration
///
/// 50us are chosen so that an endpoint iteration with a 50us sendmsg limit blocks
/// the runtime for a maximum of about 100us.
/// Going much lower does not yield any noticeable difference, since a single `recvmmsg`
/// batch of size 32 was observed to take 30us on some systems.
const RECV_TIME_BOUND: Duration = Duration::from_micros(50);

/// The maximum amount of time that should be spent in `sendmsg()` calls per endpoint iteration
const SEND_TIME_BOUND: Duration = Duration::from_micros(50);

/// The maximum size of content length of packets in the outgoing transmit queue. Transmit packets
/// generated from the endpoint (retry or initial close) can be dropped when this limit is being execeeded.
/// Chose to represent 100 MB of data.
const MAX_TRANSMIT_QUEUE_CONTENTS_LEN: usize = 100_000_000;
