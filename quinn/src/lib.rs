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
//!
//! # Feature flags
//!
//! ### TLS provider features
//!
//! These features control which TLS providers quinn will use. Currently rustls is the only one baked into this crate.
//! See [quinn-boring](https://github.com/quinn-rs/quinn-boring/) for an example of integrating another crypto provider.
//!
//! - `rustls`: Enable rustls as the TLS provider for quinn.
//!
//! ### Cryptographic provider features
//!
//! These features control which libraries quinn will use for cryptographic functions.
//!
//! - `ring`: Use the ring library for cryptographic functions. Should not be combined with the `aws-lc-rs` feature as only one library or the other will be used.
//! - `aws-lc-rs`: Use the aws-lc-rs library for crytographic functions. Should not be combined with the `ring` feature as only one library or another can be used.
//! - `aws-lc-rs-fips`: Enable the fips feature for the aws-lc-rs library.
//!
//! ### rustls features
//!
//! These features control which library and features rustls will use for cryptographic functions.
//!
//! - `rustls-ring`: Tell rustls to use the `ring` library for cryptograhic functions.
//! - `rustls-aws-lc-rs`: Tell rustls to use the `aws-lc-rs` library for cryptographic functions.
//! - `rustls-aws-lc-rs-fips`: Tell rustls to use the `aws-lc-rs` library for cryptographic functions, and enable the fips feature of that library.
//!
//! ### Miscellaneous features
//!
//! - `bloom`: Enabled by default. Enables `BloomTokenLog`, and uses it by default.
//! - `platform-verifier`: Enabled by default. Provides `ClientConfig::with_platform_verifier()` convenience method.
//! - `futures-io`: Enables `futures::io::{AsyncRead, AsyncWrite}` support for streams.
//!
//! ### Logging features
//!
//! This will cause a dependency on the `log` crate and will cause logs to be emitted at
//! various log levels, for code in quinn or its dependencies.
//!
//! - `qlog`: Enabled QUIC logs in the [qlog format](https://quicwg.org/qlog/draft-ietf-quic-qlog-main-schema.html).
//! - `rustls-log`: Enables logging in the rustls create.
//! - `lock_tracking`: Records how long locks are held, and warns if they are held >= 1ms.
//! - `tracing-log`: Configure `tracing` to log events via `log` if no `tracing` subscriber exists.
//!
//! ### Runtime features
//!
//! These features will integrate quinn with different async runtimes.
//! The convenience functions `Endpoint::server` and `Endpoint::client` will only work with the tokio or
//! smol runtime features enabled. If you're using a different or custom runtime you'll need to use `Endpoint::new` and
//! pass in a `Arc<dyn Runtime>` directly.
//!
//! - `runtime-tokio`: Enable integration with the tokio async runtime.
//! - `runtime-smol`: Enable integration with the smol runtime.
//! - `smol`: Also enable integration with the smol runtime.
//! - `async-io`: Also required to enable integration with the smol runtime.
#![warn(missing_docs)]
#![warn(unreachable_pub)]
#![warn(clippy::use_self)]

use std::pin::Pin;

mod connection;
mod endpoint;
mod incoming;
mod mutex;
mod recv_stream;
mod runtime;
mod send_stream;
mod work_limiter;

#[cfg(not(wasm_browser))]
pub(crate) use std::time::{Duration, Instant};
#[cfg(wasm_browser)]
pub(crate) use web_time::{Duration, Instant};

#[cfg(feature = "bloom")]
pub use proto::BloomTokenLog;
pub use proto::{
    AckFrequencyConfig, ApplicationClose, Chunk, ClientConfig, ClosedStream, ConfigError,
    ConnectError, ConnectionClose, ConnectionError, ConnectionId, ConnectionIdGenerator,
    ConnectionStats, Dir, EcnCodepoint, EndpointConfig, FrameStats, FrameType, IdleTimeout,
    MtuDiscoveryConfig, NoneTokenLog, NoneTokenStore, PathStats, ServerConfig, Side, StdSystemTime,
    StreamId, TimeSource, TokenLog, TokenMemoryCache, TokenReuseError, TokenStore, Transmit,
    TransportConfig, TransportErrorCode, UdpStats, ValidationTokenConfig, VarInt,
    VarIntBoundsExceeded, Written, congestion, crypto,
};
#[cfg(feature = "qlog")]
pub use proto::{QlogConfig, QlogStream};
#[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
pub use rustls;
pub use udp;

pub use crate::connection::{
    AcceptBi, AcceptUni, Connecting, Connection, OpenBi, OpenUni, ReadDatagram, SendDatagram,
    SendDatagramError, ZeroRttAccepted,
};
pub use crate::endpoint::{Accept, Endpoint, EndpointStats};
pub use crate::incoming::{Incoming, IncomingFuture, RetryError};
pub use crate::recv_stream::{ReadError, ReadExactError, ReadToEndError, RecvStream, ResetError};
#[cfg(feature = "runtime-smol")]
pub use crate::runtime::SmolRuntime;
#[cfg(feature = "runtime-tokio")]
pub use crate::runtime::TokioRuntime;
pub use crate::runtime::{AsyncTimer, AsyncUdpSocket, Runtime, UdpSender, default_runtime};
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
    Rebind(Pin<Box<dyn UdpSender>>),
}

fn udp_transmit<'a>(t: &proto::Transmit, buffer: &'a [u8]) -> udp::Transmit<'a> {
    udp::Transmit {
        destination: t.destination,
        ecn: t.ecn.map(udp_ecn),
        contents: buffer,
        segment_size: t.segment_size,
        src_ip: t.src_ip,
    }
}

fn udp_ecn(ecn: proto::EcnCodepoint) -> udp::EcnCodepoint {
    match ecn {
        proto::EcnCodepoint::Ect0 => udp::EcnCodepoint::Ect0,
        proto::EcnCodepoint::Ect1 => udp::EcnCodepoint::Ect1,
        proto::EcnCodepoint::Ce => udp::EcnCodepoint::Ce,
    }
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
