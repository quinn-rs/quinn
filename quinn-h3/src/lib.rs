#[macro_use]
extern crate lazy_static;

#[cfg(test)]
#[macro_use]
extern crate proptest;

#[cfg(test)]
#[macro_use]
extern crate assert_matches;

pub mod client;
pub mod connection;
mod frame;
pub mod proto;
pub mod qpack;
pub mod server;

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
