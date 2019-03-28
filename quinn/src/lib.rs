//! QUIC transport protocol support for Tokio
//!
//! [QUIC](https://en.wikipedia.org/wiki/QUIC) is a modern transport protocol addressing
//! shortcomings of TCP, such as head-of-line blocking, poor security, slow handshakes, and
//! inefficient congestion control. This crate provides a portable userspace implementation.
//!
//! The entry point of this crate is the [`Endpoint`](struct.Endpoint.html).
//!
//! The futures and streams defined in this crate are not `Send` because they necessarily share
//! state with each other. As a result, they must be spawned on a single-threaded tokio runtime.
//!
//! ```
//! # extern crate tokio;
//! # extern crate quinn;
//! # extern crate futures;
//! # use futures::Future;
//! # fn main() {
//! let mut runtime = tokio::runtime::current_thread::Runtime::new().unwrap();
//! let mut builder = quinn::Endpoint::new();
//! // <configure builder>
//! let (endpoint, driver, _) = builder.bind("[::]:0").unwrap();
//! runtime.spawn(driver.map_err(|e| panic!("IO error: {}", e)));
//! // ...
//! # }
//! ```
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
//! QUIC uses encryption and identity verification built directly on TLS 1.3. Just as with a TLS
//! server, it is useful for a QUIC server to be identified by a certificate signed by a trusted
//! authority. If this is infeasible--for example, if servers are short-lived or not associated
//! with a domain name--then as with TLS, self-signed certificates can be used to provide
//! encryption alone.
#![warn(missing_docs)]

#[macro_use]
extern crate slog;

mod builders;
mod platform;
pub mod tls;
mod udp;

use quinn_proto as quinn;

pub use crate::quinn::{
    ConnectError, ConnectionError, ConnectionId, DatagramEvent, ServerConfig, Transmit,
    TransportConfig, ALPN_QUIC_H3, ALPN_QUIC_HTTP,
};
pub use crate::tls::{Certificate, CertificateChain, PrivateKey};

pub use crate::builders::{
    ClientConfig, ClientConfigBuilder, EndpointBuilder, EndpointError, ServerConfigBuilder,
};

mod connection;
pub use connection::{
    read_to_end, BiStream, ConnectingFuture, Connection, ConnectionDriver, IncomingStreams,
    NewConnection, NewStream, Read, ReadError, ReadToEnd, RecvStream, SendStream, Write,
    WriteError,
};

mod endpoint;
pub use endpoint::{Driver, Endpoint, Incoming};

#[cfg(test)]
mod tests;

enum ConnectionEvent {
    DriverLost,
    Proto(quinn::ConnectionEvent),
}

enum EndpointEvent {
    Proto(quinn::EndpointEvent),
    Transmit(quinn::Transmit),
}

/// Maximum number of send/recv calls to make before moving on to other processing
///
/// This helps ensure we don't starve anything when the CPU is slower than the link. Value selected
/// more or less arbitrarily.
const IO_LOOP_BOUND: usize = 10;
