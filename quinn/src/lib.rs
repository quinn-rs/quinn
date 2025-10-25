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
//! ### Essential features
//!
//! Usage without these features is not currently supported. TODO: If quinn can be used without rustls then
//! the exact mechanism of that should be documented, because from the code it's unclear how rustls could
//! be possibly pulled out.
//!
//! - `rustls`: Currently this must be enabled. In the future other SSL libraries may be supported.
//!
//! ### Miscellaneous features
//!
//! Miscellaneous optional features.
//!
//! - `bloom`: Enabled by default. Enables `BloomTokenLog`, and uses it by default.
//! - `platform-verifier`: Enabled by default. Provides `ClientConfig::with_platform_verifier()` convenience method.
//! - `async-io`: TODO: What does this do? Seems to be related to smol?
//! - `futures-io`: Enables `futures::io::{AsyncRead, AsyncWrite}` support for streams.
//!
//! ### Logging features
//!
//! This will cause a dependency on the `log` crate and will cause logs to be emitted at
//! various log levels, for code in quinn or its dependencies.
//!
//! - `log`: Globally enables and disables logs. TODO: Is this true?
//! - `qlog`: Enables logging in the quinn crates.
//! - `rustls-log`: Enables logging in the rustls create.
//! - `lock_tracking`: Enables logging of mutex locks in quinn. TODO: Does this enable lock tracking in deps?
//!
//! ### Crypto features
//!
//! The three supported cyrpto backends are rustls+ring, rustls+aws-lc-rs and rustls+aws-lc-rs-fips.
//! Note the feature defaults for rustls is to use aws-lc-rs and the default for quinn is to use ring.
//! So you'll get "Could not automatically determine the process-level CryptoProvider from Rustls crate features"
//! To fix this you'll need to `default-features = false` for rustls or quinn and line things up.
//! TODO: Can these be consolidated until non rustls crypto backends are supported?
//! TODO: Make aws-ls-rs the default, to match with rustls's opinion?
//!
//! - `rustls-ring`: Enables ring crypto backend for quinn and rustls. Requires the `ring` feature.
//! - `ring`: Will enable ring for quinn only. Generally used with `rustls-ring`.
//! - `rustls-aws-lc-rs`: Enables aws-lc-rs crypto backend for quinn and rustls. Requires the `aws-lc-rs` feature.
//! - `aws-lc-rs`: Enables aws-lc-rs crypto backend for quinn only. Generally used with `rustls-aws-lc-rs`.
//! - `rustls-aws-lc-rs-fips`: Enables aws-lc-rs-fips crypto backend for quinn and rustls. Requires the aws-lc-rs-fips feature.
//! - `aws-lc-rs-fips`: Enables aws-lc-rs-fips for quinn only. Generally used with `rustls-aws-lc-rs-fips`.
//!
//! ### Runtime features
//!
//! These features will integrate quinn with different async runtimes.
//! The convenience functions `Endpoint::server` and `Endpoint::client` will only work with the tokio or
//! smol runtime features enabled. If you're using a different or custom runtime you'll need to use `Endpoint::new` and
//! pass in a `Arc<dyn Runtime>` directly.
//!
//! - `runtime-tokio` - Enable integration with the tokio async runtime.
//! - `runtime-smol` - Enable integration with the smol runtime.
//! - `smol` - Also enable integrationw ith the smol runtime. TODO: Why is this a seperate feature flag from runtime-smol?
//! - `async-std` - Enable integration with the async-std async runtime. NOTE: This runtime is unmaintained.
//! - `runtime-async-std` - Also enable integration with the async-std runtime. TODO: Why is this a seperate flag?
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
