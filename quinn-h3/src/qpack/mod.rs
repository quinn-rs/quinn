pub use self::decoder::{
    ack_header, decode_header, on_encoder_recv, stream_canceled, Error as DecoderError,
};
pub use self::dynamic::{
    DynamicTable, DynamicTableDecoder, DynamicTableEncoder, DynamicTableInserter,
    Error as DynamicTableError,
};
pub use self::encoder::{encode, on_decoder_recv, set_dynamic_table_size, Error as EncoderError};
pub use self::field::HeaderField;

mod block;
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
