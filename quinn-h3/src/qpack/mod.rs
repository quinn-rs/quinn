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
pub use self::encoder::{encode, on_decoder_recv};
pub use self::table::HeaderField;
pub use self::table::{
    DynamicTable, DynamicTableDecoder, DynamicTableEncoder, DynamicTableError, DynamicTableInserter,
};

mod bloc;
mod stream;
mod table;
mod vas;

mod decoder;
mod encoder;

mod prefix_int;
mod prefix_string;

#[cfg(test)]
mod tests;

#[derive(Debug, PartialEq)]
pub enum ParseError {
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
