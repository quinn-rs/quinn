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

pub type ZeroRttAccepted = quinn::ZeroRttAccepted;

#[derive(Debug, Error)]
pub enum Error {
    #[error(display = "Connection is closing, resquest aborted")]
    Aborted,
    #[error(display = "H3 protocol error: {:?}", _0)]
    Proto(proto::connection::Error),
    #[error(display = "QUIC protocol error: {}", _0)]
    Quic(quinn::ConnectionError),
    #[error(display = "QUIC read error: {}", _0)]
    Read(ReadError),
    #[error(display = "QUIC write error: {}", _0)]
    Write(WriteError),
    #[error(display = "Internal error: {}", _0)]
    Internal(String),
    #[error(display = "Incorrect peer behavior: {}", _0)]
    Peer(String),
    #[error(display = "unknown stream type {}", _0)]
    UnknownStream(u64),
    #[error(display = "IO error: {}", _0)]
    Io(std::io::Error),
    #[error(display = "Overflow max data size")]
    Overflow,
    #[error(display = "Polled after finished")]
    Poll,
    #[error(display = "Http error: {:?}", _0)]
    Http(HttpError, Option<String>),
}

impl Error {
    pub fn peer<T: Into<String>>(msg: T) -> Self {
        Error::Peer(msg.into())
    }

    pub fn internal<T: Into<String>>(msg: T) -> Self {
        Error::Internal(msg.into())
    }

    pub fn try_into_quic(&self) -> Option<&quinn_proto::ConnectionError> {
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

#[derive(Debug)]
pub enum HttpError {
    NoError,
    GeneralProtocolError,
    InternalError,
    StreamCreationError,
    ClosedCriticalStream,
    FrameUnexpected,
    FrameError,
    ExcessiveLoad,
    IdError,
    SettingsError,
    MissingSettings,
    RequestRejected,
    RequestCancelled,
    RequestIncomplete,
    EarlyResponse,
    ConnectError,
    VersionFallback,
    QpackDecompressionFailed,
    QpackEncoderStreamError,
    QpackDecoderStreamError,
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
            ErrorCode::EARLY_RESPONSE => HttpError::EarlyResponse,
            ErrorCode::CONNECT_ERROR => HttpError::ConnectError,
            ErrorCode::VERSION_FALLBACK => HttpError::VersionFallback,
            ErrorCode::QPACK_DECOMPRESSION_FAILED => HttpError::QpackDecompressionFailed,
            ErrorCode::QPACK_ENCODER_STREAM_ERROR => HttpError::QpackEncoderStreamError,
            ErrorCode::QPACK_DECODER_STREAM_ERROR => HttpError::QpackDecoderStreamError,
            _ => HttpError::Unknown(code.0),
        }
    }
}

fn try_take<T>(item: &mut Option<T>, msg: &'static str) -> Result<T, Error> {
    item.take().ok_or_else(|| Error::internal(msg))
}

/// TLS ALPN value for H3
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
