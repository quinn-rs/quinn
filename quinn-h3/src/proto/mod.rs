use bytes::{Buf, BufMut, Bytes, BytesMut};
use quinn_proto::{
    coding::{BufExt, BufMutExt, UnexpectedEnd},
    VarInt,
};
use std::fmt;

pub mod connection;
pub mod frame;
pub mod headers;
pub mod settings;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct StreamType(pub u64);

macro_rules! stream_types {
    {$($name:ident = $val:expr,)*} => {
        impl StreamType {
            $(pub const $name: StreamType = StreamType($val);)*
        }
    }
}

stream_types! {
    CONTROL = 0x00,
    PUSH = 0x01,
    ENCODER = 0x02,
    DECODER = 0x03,
}

impl StreamType {
    pub fn encode<W: BufMut>(&self, buf: &mut W) {
        buf.write_var(self.0);
    }

    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, UnexpectedEnd> {
        Ok(StreamType(buf.get_var()?))
    }

    pub fn encoded(&self) -> Bytes {
        let var_int = VarInt::from(self.0 as u32);
        let mut buf = BytesMut::with_capacity(var_int.size());
        self.encode(&mut buf);
        buf.freeze()
    }
}

impl fmt::Display for StreamType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            &StreamType::CONTROL => write!(f, "Control"),
            &StreamType::ENCODER => write!(f, "Encoder"),
            &StreamType::DECODER => write!(f, "Decoder"),
            x => write!(f, "StreamType({})", x.0),
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct ErrorCode(pub(super) u32);

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
    QPACK_DECOMPRESSION_FAILED = 0x200,
    QPACK_ENCODER_STREAM_ERROR = 0x201,
    QPACK_DECODER_STREAM_ERROR = 0x202,
}

impl From<ErrorCode> for VarInt {
    fn from(error: ErrorCode) -> VarInt {
        error.0.into()
    }
}

impl From<VarInt> for ErrorCode {
    fn from(error: VarInt) -> ErrorCode {
        ErrorCode(error.into_inner() as u32)
    }
}
