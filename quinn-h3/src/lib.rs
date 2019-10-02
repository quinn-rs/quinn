#[macro_use]
extern crate lazy_static;

#[cfg(test)]
#[macro_use]
extern crate proptest;

#[cfg(test)]
#[macro_use]
extern crate assert_matches;

pub use body::Body;

pub mod body;
pub mod client;
pub mod connection;
pub mod headers;
pub mod proto;
pub mod qpack;
pub mod server;

mod frame;
mod streams;

use err_derive::Error;
use quinn::VarInt;

use proto::frame::SettingsFrame;

pub type Settings = SettingsFrame;

#[derive(Debug, Error)]
pub enum Error {
    #[error(display = "H3 protocol error: {:?}", _0)]
    Proto(proto::connection::Error),
    #[error(display = "QUIC protocol error: {}", _0)]
    Quic(quinn::ConnectionError),
    #[error(display = "QUIC write error: {}", _0)] // TODO to be refined
    Write(quinn::WriteError),
    #[error(display = "Internal error: {}", _0)]
    Internal(&'static str),
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
}

impl Error {
    pub fn peer<T: Into<String>>(msg: T) -> Self {
        Error::Peer(msg.into())
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

impl From<quinn::WriteError> for Error {
    fn from(err: quinn::WriteError) -> Error {
        Error::Write(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::Io(err)
    }
}

impl From<frame::Error> for Error {
    fn from(err: frame::Error) -> Error {
        match err {
            frame::Error::Io(e) => Error::Io(e),
            e => Error::Peer(format!("received an invalid frame: {:?}", e)),
        }
    }
}

impl From<proto::headers::Error> for Error {
    fn from(err: proto::headers::Error) -> Error {
        Error::Peer(format!("invalid headers: {:?}", err))
    }
}

fn try_take<T>(item: &mut Option<T>, msg: &'static str) -> Result<T, Error> {
    item.take().ok_or_else(|| Error::Internal(msg))
}

/// TLS ALPN value for H3
pub const ALPN: &[u8] = b"h3-20";

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct ErrorCode(u32);

macro_rules! error_codes {
    {$($name:ident = $val:expr,)*} => {
        impl ErrorCode {
            $(pub const $name: ErrorCode = ErrorCode($val);)*
        }
    }
}

error_codes! {
    NO_ERROR = 0x100,
    GENERAL_PROTOCOL_ERROR = 0x101,
    INTERNAL_ERROR = 0x102,
    STREAM_CREATION_ERROR = 0x103,
    CLOSED_CRITICAL_STREAM = 0x104,
    FRAME_UNEXPECTED = 0x105,
    FRAME_ERROR = 0x106,
    EXCESSIVE_LOAD = 0x107,
    ID_ERROR = 0x108,
    SETTINGS_ERROR = 0x109,
    MISSING_SETTINGS = 0x10A,
    REQUEST_REJECTED = 0x10B,
    REQUEST_CANCELLED = 0x10C,
    REQUEST_INCOMPLETE = 0x10D,
    EARLY_RESPONSE = 0x10E,
    CONNECT_ERROR = 0x10F,
    VERSION_FALLBACK = 0x110,
}

impl From<ErrorCode> for VarInt {
    fn from(error: ErrorCode) -> VarInt {
        error.0.into()
    }
}

impl From<frame::Error> for (ErrorCode, String) {
    fn from(err: frame::Error) -> Self {
        match err {
            frame::Error::Io(e) => (
                ErrorCode::GENERAL_PROTOCOL_ERROR,
                format!("IO Error: {:?}", e),
            ),
            frame::Error::Proto(e) => (
                ErrorCode::FRAME_ERROR,
                format!("Parse frame error: {:?}", e),
            ),
        }
    }
}
