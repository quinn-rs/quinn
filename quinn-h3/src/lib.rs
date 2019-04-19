#[macro_use]
extern crate lazy_static;

#[cfg(test)]
#[macro_use]
extern crate proptest;

#[cfg(test)]
#[macro_use]
extern crate assert_matches;

extern crate quinn_proto;
pub mod connection;
pub mod frame;
pub mod qpack;

use bytes::{Buf, BufMut};
use quinn_proto::coding::{BufExt, BufMutExt, Codec, UnexpectedEnd};

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct StreamType(u64);

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
    pub fn decode<T: Buf>(buf: &mut T) -> Result<Self, UnexpectedEnd> {
        Ok(StreamType(buf.get_var()?))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ErrorCodeError {
    UnexpectedEnd,
    UnknownCode(u16),
}

#[derive(Debug, Eq, PartialEq)]
pub enum ErrorCode {
    NoError,
    WrongSettingDirection,
    PushRefused,
    InternalError,
    PushAlreadyInCache,
    RequestCancelled,
    IncompleteRequest,
    ConnectError,
    ExcessiveLoad,
    VersionFallback,
    WrongStream,
    LimitExceeded,
    DuplicatePush,
    UnknownStreamType,
    WrongStreamCount,
    ClosedCriticalStream,
    WrongStreamDirection,
    EarlyResponse,
    MissingSettings,
    UnexpectedFrame,
    RequestRejected,
    GeneralProtocolError,
    MalformedFrame(frame::Type),
    QpackDecompressionFailed,
    QpackEncoderStreamError,
    QpackDecoderStreamError,
}

impl ErrorCode {
    pub fn encode<W: BufMut>(&self, buf: &mut W) {
        let val: u16 = match *self {
            ErrorCode::NoError => ErrorCodeValue::NO_ERROR.0,
            ErrorCode::WrongSettingDirection => ErrorCodeValue::WRONG_SETTING_DIRECTION.0,
            ErrorCode::PushRefused => ErrorCodeValue::PUSH_REFUSED.0,
            ErrorCode::InternalError => ErrorCodeValue::INTERNAL_ERROR.0,
            ErrorCode::PushAlreadyInCache => ErrorCodeValue::PUSH_ALREADY_IN_CACHE.0,
            ErrorCode::RequestCancelled => ErrorCodeValue::REQUEST_CANCELLED.0,
            ErrorCode::IncompleteRequest => ErrorCodeValue::INCOMPLETE_REQUEST.0,
            ErrorCode::ConnectError => ErrorCodeValue::CONNECT_ERROR.0,
            ErrorCode::ExcessiveLoad => ErrorCodeValue::EXCESSIVE_LOAD.0,
            ErrorCode::VersionFallback => ErrorCodeValue::VERSION_FALLBACK.0,
            ErrorCode::WrongStream => ErrorCodeValue::WRONG_STREAM.0,
            ErrorCode::LimitExceeded => ErrorCodeValue::LIMIT_EXCEEDED.0,
            ErrorCode::DuplicatePush => ErrorCodeValue::DUPLICATE_PUSH.0,
            ErrorCode::UnknownStreamType => ErrorCodeValue::UNKNOWN_STREAM_TYPE.0,
            ErrorCode::WrongStreamCount => ErrorCodeValue::WRONG_STREAM_COUNT.0,
            ErrorCode::ClosedCriticalStream => ErrorCodeValue::CLOSED_CRITICAL_STREAM.0,
            ErrorCode::WrongStreamDirection => ErrorCodeValue::WRONG_STREAM_DIRECTION.0,
            ErrorCode::EarlyResponse => ErrorCodeValue::EARLY_RESPONSE.0,
            ErrorCode::MissingSettings => ErrorCodeValue::MISSING_SETTINGS.0,
            ErrorCode::UnexpectedFrame => ErrorCodeValue::UNEXPECTED_FRAME.0,
            ErrorCode::RequestRejected => ErrorCodeValue::REQUEST_REJECTED.0,
            ErrorCode::GeneralProtocolError => ErrorCodeValue::GENERAL_PROTOCOL_ERROR.0,
            ErrorCode::MalformedFrame(f) if f.0 < 0xff => {
                ErrorCodeValue::MALFORMED_FRAME.0 | f.0 as u16
            }
            ErrorCode::MalformedFrame(_) => ErrorCodeValue::MALFORMED_FRAME.0 | 0xff,
            ErrorCode::QpackDecompressionFailed => ErrorCodeValue::QPACK_DECOMPRESSION_FAILED.0,
            ErrorCode::QpackEncoderStreamError => ErrorCodeValue::QPACK_ENCODER_STREAM_ERROR.0,
            ErrorCode::QpackDecoderStreamError => ErrorCodeValue::QPACK_DECODER_STREAM_ERROR.0,
        };
        val.encode(buf);
    }

    pub fn decode<T: Buf>(buf: &mut T) -> Result<Self, ErrorCodeError> {
        let value = match u16::decode(buf) {
            Ok(v) => v,
            Err(_) => return Err(ErrorCodeError::UnexpectedEnd),
        };

        if value & 0xff00 == ErrorCodeValue::MALFORMED_FRAME.0 {
            return Ok(ErrorCode::MalformedFrame(frame::Type(value as u64 & 0xff)));
        }

        match ErrorCodeValue(value) {
            ErrorCodeValue::NO_ERROR => Ok(ErrorCode::NoError),
            ErrorCodeValue::WRONG_SETTING_DIRECTION => Ok(ErrorCode::WrongSettingDirection),
            ErrorCodeValue::PUSH_REFUSED => Ok(ErrorCode::PushRefused),
            ErrorCodeValue::INTERNAL_ERROR => Ok(ErrorCode::InternalError),
            ErrorCodeValue::PUSH_ALREADY_IN_CACHE => Ok(ErrorCode::PushAlreadyInCache),
            ErrorCodeValue::REQUEST_CANCELLED => Ok(ErrorCode::RequestCancelled),
            ErrorCodeValue::INCOMPLETE_REQUEST => Ok(ErrorCode::IncompleteRequest),
            ErrorCodeValue::CONNECT_ERROR => Ok(ErrorCode::ConnectError),
            ErrorCodeValue::EXCESSIVE_LOAD => Ok(ErrorCode::ExcessiveLoad),
            ErrorCodeValue::VERSION_FALLBACK => Ok(ErrorCode::VersionFallback),
            ErrorCodeValue::WRONG_STREAM => Ok(ErrorCode::WrongStream),
            ErrorCodeValue::LIMIT_EXCEEDED => Ok(ErrorCode::LimitExceeded),
            ErrorCodeValue::DUPLICATE_PUSH => Ok(ErrorCode::DuplicatePush),
            ErrorCodeValue::UNKNOWN_STREAM_TYPE => Ok(ErrorCode::UnknownStreamType),
            ErrorCodeValue::WRONG_STREAM_COUNT => Ok(ErrorCode::WrongStreamCount),
            ErrorCodeValue::CLOSED_CRITICAL_STREAM => Ok(ErrorCode::ClosedCriticalStream),
            ErrorCodeValue::WRONG_STREAM_DIRECTION => Ok(ErrorCode::WrongStreamDirection),
            ErrorCodeValue::EARLY_RESPONSE => Ok(ErrorCode::EarlyResponse),
            ErrorCodeValue::MISSING_SETTINGS => Ok(ErrorCode::MissingSettings),
            ErrorCodeValue::UNEXPECTED_FRAME => Ok(ErrorCode::UnexpectedFrame),
            ErrorCodeValue::REQUEST_REJECTED => Ok(ErrorCode::RequestRejected),
            ErrorCodeValue::GENERAL_PROTOCOL_ERROR => Ok(ErrorCode::GeneralProtocolError),
            ErrorCodeValue::QPACK_DECOMPRESSION_FAILED => Ok(ErrorCode::QpackDecompressionFailed),
            ErrorCodeValue::QPACK_ENCODER_STREAM_ERROR => Ok(ErrorCode::QpackEncoderStreamError),
            ErrorCodeValue::QPACK_DECODER_STREAM_ERROR => Ok(ErrorCode::QpackDecoderStreamError),
            _ => Err(ErrorCodeError::UnknownCode(value)),
        }
    }
}

#[derive(PartialEq, Eq)]
pub struct ErrorCodeValue(u16);

macro_rules! error_codes {
    {$($name:ident = $val:expr,)*} => {
        impl ErrorCodeValue {
            $(pub const $name: ErrorCodeValue = ErrorCodeValue($val);)*
        }
    }
}

error_codes! {
    NO_ERROR = 0x00,
    WRONG_SETTING_DIRECTION = 0x01,
    PUSH_REFUSED = 0x02,
    INTERNAL_ERROR = 0x03,
    PUSH_ALREADY_IN_CACHE = 0x04,
    REQUEST_CANCELLED = 0x05,
    INCOMPLETE_REQUEST = 0x06,
    CONNECT_ERROR = 0x07,
    EXCESSIVE_LOAD = 0x08,
    VERSION_FALLBACK = 0x09,
    WRONG_STREAM = 0x0A,
    LIMIT_EXCEEDED = 0x0B,
    DUPLICATE_PUSH = 0x0C,
    UNKNOWN_STREAM_TYPE = 0x0D,
    WRONG_STREAM_COUNT = 0x0E,
    CLOSED_CRITICAL_STREAM = 0x0F,
    WRONG_STREAM_DIRECTION = 0x010,
    EARLY_RESPONSE = 0x011,
    MISSING_SETTINGS = 0x012,
    UNEXPECTED_FRAME = 0x013,
    REQUEST_REJECTED = 0x014,
    GENERAL_PROTOCOL_ERROR = 0x0FF,
    MALFORMED_FRAME = 0x100,
    QPACK_DECOMPRESSION_FAILED = 0x200,
    QPACK_ENCODER_STREAM_ERROR = 0x201,
    QPACK_DECODER_STREAM_ERROR = 0x202,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn error_code_simple() {
        let error = ErrorCode::GeneralProtocolError;
        let mut buf = Vec::new();
        error.encode(&mut buf);
        assert_eq!(&buf, b"\x00\xff");
        assert_eq!(
            ErrorCode::decode(&mut Cursor::new(&buf)),
            Ok(ErrorCode::GeneralProtocolError)
        );
    }

    #[test]
    fn error_code_malformed_frame() {
        let error = ErrorCode::MalformedFrame(frame::Type::GOAWAY);
        let mut buf = Vec::new();
        error.encode(&mut buf);
        assert_eq!(&buf, b"\x01\x07");
        assert_eq!(
            ErrorCode::decode(&mut Cursor::new(&buf)),
            Ok(ErrorCode::MalformedFrame(frame::Type::GOAWAY))
        );
    }

    #[test]
    fn error_code_malformed_frame_unknown_type() {
        assert_eq!(
            ErrorCode::decode(&mut Cursor::new(&[0x1, 0xff])),
            Ok(ErrorCode::MalformedFrame(frame::Type(0xff)))
        );
    }

    #[test]
    fn error_code_unknown() {
        assert_eq!(
            ErrorCode::decode(&mut Cursor::new(&[0x3, 0])),
            Err(ErrorCodeError::UnknownCode(0x300))
        );
    }
}
