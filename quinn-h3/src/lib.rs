#[macro_use]
extern crate lazy_static;

#[cfg(test)]
#[macro_use]
extern crate proptest;

#[cfg(test)]
#[macro_use]
extern crate assert_matches;

pub use body::Body;

pub mod client;
pub mod connection;
pub mod proto;
pub mod qpack;
pub mod server;

mod body;
mod frame;

use std::mem;

use err_derive::Error;

#[derive(Clone)]
pub struct Settings {
    pub max_header_list_size: u64,
    pub num_placeholders: u64,
    pub qpack_max_table_capacity: u64,
    pub qpack_blocked_streams: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            max_header_list_size: u64::max_value(),
            num_placeholders: 0,
            qpack_max_table_capacity: 0,
            qpack_blocked_streams: 0,
        }
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error(display = "H3 protocol error: {:?}", _0)]
    Proto(proto::connection::Error),
    #[error(display = "QUIC protocol error: {}", _0)]
    Quic(quinn::ConnectionError),
    #[error(display = "Internal error: {}", _0)]
    Internal(&'static str),
    #[error(display = "Incorrect peer behavior: {}", _0)]
    Peer(String),
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
    mem::replace(item, None).ok_or(Error::Internal(msg))
}
