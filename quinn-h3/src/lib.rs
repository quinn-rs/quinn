//! HTTP/3 support for tokio.
//!
//! This library is an asynchronous implementation of the [HTTP/3] protocol, part of the [`quinn`]
//! project: a [QUIC] transport protocol implementation.
//!
//! This crate is built to integrate well into the rust `async` and [`tokio`] ecosystem. It is heavily
//! inspired by the [`h2`] crate's API, with the hope of making integration easier for downstream projects.
//!
//! # About HTTP/3
//!
//! HTTP/3 is the upcoming third major version of the Hypertext Transfer Protocol. It's built on top
//! of a new transport protocol over UDP: [QUIC]. It addresses the shortcomings that [HTTP/2]
//! suffers from being built on top of TCP, such as [Head-Of-Line blocking] and handshake latencies.
//! Thanks to QUIC streams multiplexing features over UDP, requests are made independent from each other
//! at the data transmissionlevel.
//!
//! Unlike HTTP/1, it exchanges headers in binary format, and compresses them with [QPACK].
//!
//! It also offers Server Push features similar to HTTP/2.
//!
//! The HTTP/3 specification has not yet been stabilized. The version currently implemented by this
//! crate is [draft-27].
//!
//! # Crate overview
//!
//! This crate is split into two main [`client`] and [`server`] modules.
//!
//! It makes extensive use of hyperium's [`http`] crate, which helps constructing [`Request`]s and
//! [`Response`]s,  compatible with all the HTTP versions out there. As well as [`http_body`] that
//! enables to stream bodies and handle trailers.
//!
//! On the sending side, the crate provides a convenience [`SimpleBody`] that is very limited,
//! you'll have to implement your own if you want more power. For the receive side, body can be
//! handled using [`RecvBody`].
//!
//! # Crate status
//!
//! This crate is in an experimental state. For now, it has multiple improvement vectors:
//!
//! * Though having been tested as compatible with a majority of other HTTP/3 implementations,
//!   `quinn-h3` does not implement all interoperability tests for the moment.
//! * The CONNECT method and associated proxy features are not implemented.
//! * Server PUSH is not implemented.
//!
//! # Getting started
//!
//! Give the examples a try:
//!
//! ```sh
//! cargo run --example h3_server &
//! cargo run --example h3_client
//! ```
//!
//! [HTTP/3]: https://en.wikipedia.org/wiki/HTTP/3
//! [`quinn`]: https://docs.rs/quinn
//! [`tokio`]: https://docs.rs/tokio
//! [`h2`]: https://docs.rs/h2
//! [QUIC]: https://en.wikipedia.org/wiki/QUIC
//! [HTTP/2]: https://en.wikipedia.org/wiki/HTTP/2
//! [Head-Of-Line blocking]: https://en.wikipedia.org/wiki/Head-of-line_blocking
//! [QPACK]: https://datatracker.ietf.org/doc/draft-ietf-quic-qpack/
//! [draft-27]: https://tools.ietf.org/html/draft-ietf-quic-http-27
//! [Server Push]: https://en.wikipedia.org/wiki/HTTP/2_Server_Push
//! [`client`]: client/index.html
//! [`server`]: server/index.html
//! [`http`]: https://docs.rs/http/*/http/index.html
//! [`Request`]: https://docs.rs/http/*/http/request/index.html
//! [`Response`]: https://docs.rs/http/*/http/response/index.html
//! [`http_body`]: https://docs.rs/http-body/*/http_body/index.html
//! [`SimpleBody`]: struct.SimpleBody.html
//! [`RecvBody`]: struct.RecvBody.html

#![warn(missing_docs)]
#![allow(clippy::identity_op)]

#[macro_use]
extern crate lazy_static;

#[cfg(test)]
#[macro_use]
extern crate proptest;

#[cfg(test)]
#[macro_use]
extern crate assert_matches;

#[cfg(test)]
mod tests;

pub use body::{Body, RecvBody};
pub use data::SendData;
pub use proto::settings::Settings;

pub mod client;
pub mod server;

mod body;
mod connection;
mod data;
mod frame;
mod headers;
mod proto;
mod streams;

#[cfg(not(feature = "interop-test-accessors"))]
mod qpack;
#[cfg(feature = "interop-test-accessors")]
#[allow(missing_docs)]
#[doc(hidden)]
pub mod qpack;

use err_derive::Error;
use quinn::{ApplicationClose, ConnectionError, ReadError, WriteError};
use std::{error::Error as StdError, io::ErrorKind};

use proto::ErrorCode;

/// A future that resolves when the handshake ends durinng a 0-RTT exchange
pub type ZeroRttAccepted = quinn::ZeroRttAccepted;

/// General error enum for this crate
#[derive(Debug, Error)]
pub enum Error {
    /// Cannot make a new request, bescause the connection is closing
    #[error(display = "Connection is closing, resquest aborted")]
    Aborted,
    /// Protocol violation detected by the internal HTTP/3 protocol state machine
    #[error(display = "H3 protocol error: {:?}", _0)]
    Proto(proto::connection::Error),
    /// Error occurred at the `QUIC` level
    #[error(display = "QUIC protocol error: {}", _0)]
    Quic(quinn::ConnectionError),
    /// A `QUIC`-specific read error occurred
    #[error(display = "QUIC read error: {}", _0)]
    Read(ReadError),
    /// A `QUIC`-specific write error occurred
    #[error(display = "QUIC write error: {}", _0)]
    Write(WriteError),
    /// Programming error within the crate's code
    #[error(display = "Internal error: {}", _0)]
    Internal(String),
    /// The peer's behavior was detected as incorrect or malicious
    #[error(display = "Incorrect peer behavior: {}", _0)]
    Peer(String),
    /// The peer tried to open an unidirectional stream with an unknown type code
    #[error(display = "unknown stream type {}", _0)]
    UnknownStream(u64),
    /// An IO error occurred
    #[error(display = "IO error: {}", _0)]
    Io(std::io::Error),
    /// An overflow occurred into the `QPACK` decoder
    #[error(display = "Overflow max data size")]
    Overflow,
    /// A future has been polled after it was already finished
    #[error(display = "Polled after finished")]
    Poll,
    /// The peer issued an HTTP/3 error code and an optional text description
    #[error(display = "Http error: {:?}", _0)]
    Http(HttpError, Option<String>),
    /// Polling the issued body data yielded an error
    #[error(display = "Polling body error: {}", _0)]
    Body(Box<dyn StdError + Send + Sync>),
}

impl Error {
    pub(crate) fn peer<T: Into<String>>(msg: T) -> Self {
        Error::Peer(msg.into())
    }

    pub(crate) fn internal<T: Into<String>>(msg: T) -> Self {
        Error::Internal(msg.into())
    }

    pub(crate) fn try_into_quic(&self) -> Option<&quinn_proto::ConnectionError> {
        match self {
            Error::Quic(e) => Some(e),
            Error::Write(quinn::WriteError::ConnectionClosed(e)) => Some(e),
            Error::Io(e) => e
                .get_ref()
                .and_then(|e| e.downcast_ref::<quinn_proto::ConnectionError>()),
            _ => None,
        }
    }

    pub(crate) fn body(e: Box<dyn StdError + Send + Sync>) -> Self {
        Self::Body(e)
    }

    /// Get the error reason if it's an `HttpError`
    pub fn reason(&self) -> Option<HttpError> {
        match self {
            Error::Http(http, _) => Some((*http).clone()),
            _ => None,
        }
    }
}

impl From<proto::connection::Error> for Error {
    fn from(err: proto::connection::Error) -> Error {
        Error::Proto(err)
    }
}

impl From<quinn::ConnectionError> for Error {
    fn from(err: quinn::ConnectionError) -> Error {
        Error::Quic(err)
    }
}

impl From<ErrorCode> for Error {
    fn from(code: ErrorCode) -> Self {
        Error::Http(code.into(), None)
    }
}

impl From<ReadError> for Error {
    fn from(err: ReadError) -> Error {
        match err {
            ReadError::Reset(c) => ErrorCode::from(c).into(),
            _ => Error::Read(err),
        }
    }
}

impl From<WriteError> for Error {
    fn from(err: WriteError) -> Error {
        match err {
            WriteError::Stopped(c) => ErrorCode::from(c).into(),
            WriteError::ConnectionClosed(ConnectionError::ApplicationClosed(
                ApplicationClose {
                    error_code,
                    ref reason,
                },
            )) => Error::Http(
                ErrorCode::from(error_code).into(),
                Some(String::from_utf8_lossy(reason).to_string()),
            ),
            _ => Error::Write(err),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        if err.kind() == ErrorKind::ConnectionReset && err.get_ref().is_some() {
            let err = err.into_inner().unwrap();
            let e = match err.downcast::<ReadError>() {
                Ok(e) => return (*e).into(),
                Err(e) => e,
            };
            return Error::Io(std::io::Error::new(ErrorKind::ConnectionReset, e));
        }
        Error::Io(err)
    }
}

impl From<frame::Error> for Error {
    fn from(err: frame::Error) -> Error {
        match err {
            frame::Error::Io(e) => e.into(),
            e => Error::Peer(format!("received an invalid frame: {:?}", e)),
        }
    }
}

impl From<proto::headers::Error> for Error {
    fn from(err: proto::headers::Error) -> Error {
        Error::Peer(format!("invalid headers: {:?}", err))
    }
}

/// Errors defined by the HTTP/3 protocol
///
/// Read the [HTTP/3 specification] for more details.
///
/// [HTTP/3 specification]: https://quicwg.org/base-drafts/draft-ietf-quic-http.html#name-http-3-error-codes
#[derive(Clone, Debug)]
pub enum HttpError {
    /// This is used when the connection or stream needs to be closed, but there is no error to signal
    NoError,
    /// Peer violated protocol requirements in a way which doesn't match a more specific error code, or endpoint declines to use the more specific error code
    GeneralProtocolError,
    /// An internal error has occurred in the HTTP stack
    InternalError,
    /// The endpoint detected that its peer created a stream that it will not accept
    StreamCreationError,
    /// A stream required by the connection was closed or reset
    ClosedCriticalStream,
    /// A frame was received which was not permitted in the current state or on the current stream
    FrameUnexpected,
    /// A frame that fails to satisfy layout requirements or with an invalid size was received
    FrameError,
    /// The endpoint detected that its peer is exhibiting a behavior that might be generating excessive load
    ExcessiveLoad,
    /// A Stream ID or Push ID was used incorrectly, such as exceeding a limit, reducing a limit, or being reused
    IdError,
    /// An endpoint detected an error in the payload of a SETTINGS frame
    SettingsError,
    /// No SETTINGS frame was received at the beginning of the control stream
    MissingSettings,
    /// A server rejected a request without performing any application processing
    RequestRejected,
    /// The request or its response (including pushed response) is cancelled
    RequestCancelled,
    /// The client's stream terminated without containing a fully-formed request
    RequestIncomplete,
    /// The connection established in response to a CONNECT request was reset or abnormally closed
    ConnectError,
    /// The requested operation cannot be served over HTTP/3. The peer should retry over HTTP/1.1
    VersionFallback,
    /// Decompression of a header block failed
    QpackDecompressionFailed,
    /// Error on the encoder stream
    QpackEncoderStreamError,
    /// Error on the decoder stream
    QpackDecoderStreamError,
    /// Unknown error code
    Unknown(u32),
}

impl From<ErrorCode> for HttpError {
    fn from(code: ErrorCode) -> Self {
        match code {
            ErrorCode::NO_ERROR => HttpError::NoError,
            ErrorCode::GENERAL_PROTOCOL_ERROR => HttpError::GeneralProtocolError,
            ErrorCode::INTERNAL_ERROR => HttpError::InternalError,
            ErrorCode::STREAM_CREATION_ERROR => HttpError::StreamCreationError,
            ErrorCode::CLOSED_CRITICAL_STREAM => HttpError::ClosedCriticalStream,
            ErrorCode::FRAME_UNEXPECTED => HttpError::FrameUnexpected,
            ErrorCode::FRAME_ERROR => HttpError::FrameError,
            ErrorCode::EXCESSIVE_LOAD => HttpError::ExcessiveLoad,
            ErrorCode::ID_ERROR => HttpError::IdError,
            ErrorCode::SETTINGS_ERROR => HttpError::SettingsError,
            ErrorCode::MISSING_SETTINGS => HttpError::MissingSettings,
            ErrorCode::REQUEST_REJECTED => HttpError::RequestRejected,
            ErrorCode::REQUEST_CANCELLED => HttpError::RequestCancelled,
            ErrorCode::REQUEST_INCOMPLETE => HttpError::RequestIncomplete,
            ErrorCode::CONNECT_ERROR => HttpError::ConnectError,
            ErrorCode::VERSION_FALLBACK => HttpError::VersionFallback,
            ErrorCode::QPACK_DECOMPRESSION_FAILED => HttpError::QpackDecompressionFailed,
            ErrorCode::QPACK_ENCODER_STREAM_ERROR => HttpError::QpackEncoderStreamError,
            ErrorCode::QPACK_DECODER_STREAM_ERROR => HttpError::QpackDecoderStreamError,
            _ => HttpError::Unknown(code.0),
        }
    }
}

/// TLS ALPN value for the HTTP/3 protocol
pub const ALPN: &[u8] = b"h3-28";

impl From<frame::Error> for (ErrorCode, String, Error) {
    fn from(err: frame::Error) -> Self {
        match err {
            frame::Error::Io(e) => (
                ErrorCode::GENERAL_PROTOCOL_ERROR,
                format!("IO Error: {:?}", e),
                Error::Io(e),
            ),
            frame::Error::Proto(e) => {
                let msg = format!("Parse frame error: {:?}", e);
                (ErrorCode::FRAME_ERROR, msg.clone(), Error::Peer(msg))
            }
        }
    }
}
