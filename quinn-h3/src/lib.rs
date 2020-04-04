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

pub use body::{Body, BodyReader, BodyWriter};
pub use proto::settings::Settings;

pub mod client;
pub mod server;

mod body;
mod connection;
mod frame;
mod headers;
mod proto;
mod qpack;
mod streams;

use err_derive::Error;
use quinn::{ApplicationClose, ConnectionError, ReadError, WriteError};
use std::io::ErrorKind;

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
/// Read the [`HTTP/3 specification`] for more details.
///
/// [`HTTP/3 specification`]: https://quicwg.org/base-drafts/draft-ietf-quic-http.html#name-http-3-error-codes
#[derive(Debug)]
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
pub const ALPN: &[u8] = b"h3-27";

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
