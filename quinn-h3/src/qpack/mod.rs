/*
 *QUIC                                                           C. Krasic
 *Internet-Draft                                               Google, Inc
 *Intended status: Standards Track                               M. Bishop
 *Expires: November 24, 2018                           Akamai Technologies
 *                                                        A. Frindell, Ed.
 *                                                                Facebook
 *                                                            May 23, 2018
 *
 *
 *              QPACK: Header Compression for HTTP over QUIC
 *                        draft-ietf-quic-qpack-00
 */

#[allow(dead_code)]
pub const QPACK_VERSION: &'static str = "0.0.0~draft";
#[allow(dead_code)]
pub const QPACK_VERSION_DATE: &'static str = "23-may-2018";

pub use self::decoder::{decode_header, on_encoder_recv, Error as DecoderError};
pub use self::dynamic::{
    DynamicTable, DynamicTableDecoder, DynamicTableEncoder, DynamicTableInserter,
    Error as DynamicTableError,
};
pub use self::encoder::{encode, on_decoder_recv, set_dynamic_table_size};
pub use self::field::HeaderField;

mod bloc;
mod dynamic;
mod field;
mod static_;
mod stream;
mod vas;

mod decoder;
mod encoder;

mod prefix_int;
mod prefix_string;

#[cfg(test)]
mod tests;

#[derive(Debug, PartialEq)]
pub(self) enum ParseError {
    InvalidInteger(prefix_int::Error),
    InvalidString(prefix_string::Error),
    InvalidPrefix(u8),
    InvalidBase(isize),
}

impl From<prefix_int::Error> for ParseError {
    fn from(e: prefix_int::Error) -> Self {
        match e {
            e => ParseError::InvalidInteger(e),
        }
    }
}

impl From<prefix_string::Error> for ParseError {
    fn from(e: prefix_string::Error) -> Self {
        match e {
            e => ParseError::InvalidString(e),
        }
    }
}
