use std::fmt;

use bytes::{Buf, BufMut, Bytes};
use quinn_proto::{
    coding::{BufExt, BufMutExt, Codec, UnexpectedEnd},
    VarInt,
};
use tracing::trace;

use super::settings::{Error as SettingsError, SettingId, SettingsFrame};

#[derive(Debug, PartialEq)]
pub enum Error {
    Malformed,
    UnsupportedFrame(u64), // Known frames that should generate an error
    UnknownFrame(u64),     // Unknown frames that should be ignored
    UnexpectedEnd,
    InvalidFrameValue,
    InvalidSettingId(u64),
    InvalidSettingValue(SettingId, u64),
    SettingRepeated(SettingId),
    SettingsExceeded,
    Incomplete(usize),
    IncompleteData,
    Settings(String),
}

#[derive(Debug, PartialEq)]
pub enum HttpFrame {
    Data(DataFrame<Bytes>),
    Headers(HeadersFrame),
    CancelPush(u64),
    Settings(SettingsFrame),
    PushPromise(PushPromiseFrame),
    Goaway(u64),
    MaxPushId(u64),
    DuplicatePush(u64),
    Reserved,
}

impl HttpFrame {
    pub fn encode<T: BufMut>(&self, buf: &mut T) {
        match self {
            HttpFrame::Data(f) => f.encode(buf),
            HttpFrame::Headers(f) => f.encode(buf),
            HttpFrame::Settings(f) => f.encode(buf),
            HttpFrame::CancelPush(id) => simple_frame_encode(Type::CANCEL_PUSH, *id, buf),
            HttpFrame::PushPromise(f) => f.encode(buf),
            HttpFrame::Goaway(id) => simple_frame_encode(Type::GOAWAY, *id, buf),
            HttpFrame::MaxPushId(id) => simple_frame_encode(Type::MAX_PUSH_ID, *id, buf),
            HttpFrame::DuplicatePush(id) => simple_frame_encode(Type::DUPLICATE_PUSH, *id, buf),
            HttpFrame::Reserved => (),
        }
    }

    pub fn decode<T: Buf>(buf: &mut T) -> Result<Self, Error> {
        let remaining = buf.remaining();
        let ty = Type::decode(buf).map_err(|_| Error::Incomplete(remaining + 1))?;
        let len = buf
            .get_var()
            .map_err(|_| Error::Incomplete(remaining + 1))?;

        if buf.remaining() < len as usize {
            if ty == Type::DATA {
                return Err(Error::IncompleteData);
            }
            return Err(Error::Incomplete(2 + len as usize));
        }

        let mut payload = buf.take(len as usize);
        let frame = match ty {
            Type::DATA => Ok(HttpFrame::Data(DataFrame {
                payload: payload.copy_to_bytes(payload.remaining()),
            })),
            Type::HEADERS => Ok(HttpFrame::Headers(HeadersFrame::decode(&mut payload)?)),
            Type::SETTINGS => Ok(HttpFrame::Settings(SettingsFrame::decode(&mut payload)?)),
            Type::CANCEL_PUSH => Ok(HttpFrame::CancelPush(payload.get_var()?)),
            Type::PUSH_PROMISE => Ok(HttpFrame::PushPromise(PushPromiseFrame::decode(
                &mut payload,
            )?)),
            Type::GOAWAY => Ok(HttpFrame::Goaway(payload.get_var()?)),
            Type::MAX_PUSH_ID => Ok(HttpFrame::MaxPushId(payload.get_var()?)),
            Type::DUPLICATE_PUSH => Ok(HttpFrame::DuplicatePush(payload.get_var()?)),
            Type::H2_PRIORITY | Type::H2_PING | Type::H2_WINDOW_UPDATE | Type::H2_CONTINUATION => {
                Err(Error::UnsupportedFrame(ty.0))
            }
            t if t.0 > 0x21 && (t.0 - 0x21) % 0x1f == 0 => {
                buf.advance(len as usize);
                Ok(HttpFrame::Reserved)
            }
            _ => {
                buf.advance(len as usize);
                Err(Error::UnknownFrame(ty.0))
            }
        };
        if let Ok(frame) = &frame {
            trace!(
                "got frame {}, len: {}, remaining: {}",
                frame,
                len,
                buf.remaining()
            );
        }
        frame
    }
}

impl fmt::Display for HttpFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpFrame::Data(frame) => write!(f, "Data({} bytes)", frame.len()),
            HttpFrame::Headers(frame) => write!(f, "Headers({} entries)", frame.len()),
            HttpFrame::Settings(_) => write!(f, "Settings"),
            HttpFrame::CancelPush(id) => write!(f, "CancelPush({})", id),
            HttpFrame::PushPromise(frame) => write!(f, "PushPromise({})", frame.id),
            HttpFrame::Goaway(id) => write!(f, "GoAway({})", id),
            HttpFrame::MaxPushId(id) => write!(f, "MaxPushId({})", id),
            HttpFrame::DuplicatePush(id) => write!(f, "DuplicatePush({})", id),
            HttpFrame::Reserved => write!(f, "Reserved"),
        }
    }
}
macro_rules! frame_types {
    {$($name:ident = $val:expr,)*} => {
        impl Type {
            $(pub const $name: Type = Type($val);)*
        }
    }
}

frame_types! {
    DATA = 0x0,
    HEADERS = 0x1,
    H2_PRIORITY = 0x2,
    CANCEL_PUSH = 0x3,
    SETTINGS = 0x4,
    PUSH_PROMISE = 0x5,
    H2_PING = 0x6,
    GOAWAY = 0x7,
    H2_WINDOW_UPDATE = 0x8,
    H2_CONTINUATION = 0x9,
    MAX_PUSH_ID = 0xD,
    DUPLICATE_PUSH = 0xE,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub(crate) struct Type(u64);

impl Codec for Type {
    fn decode<B: Buf>(buf: &mut B) -> Result<Self, UnexpectedEnd> {
        Ok(Type(buf.get_var()?))
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.write_var(self.0);
    }
}

pub(crate) trait FrameHeader {
    fn len(&self) -> usize;
    const TYPE: Type;
    fn encode_header<T: BufMut>(&self, buf: &mut T) {
        Self::TYPE.encode(buf);
        buf.write_var(self.len() as u64);
    }
}

pub(crate) trait IntoPayload {
    fn into_payload(&mut self) -> &mut dyn Buf;
}

#[derive(Debug, PartialEq)]
pub struct DataFrame<P> {
    pub payload: P,
}

impl<P> DataFrame<P>
where
    P: Buf,
{
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        self.encode_header(buf);
        buf.put(self.payload.chunk());
    }
}

impl<P> FrameHeader for DataFrame<P>
where
    P: Buf,
{
    const TYPE: Type = Type::DATA;
    fn len(&self) -> usize {
        self.payload.remaining()
    }
}

impl<P> IntoPayload for DataFrame<P>
where
    P: Buf,
{
    fn into_payload(&mut self) -> &mut dyn Buf {
        &mut self.payload
    }
}

pub struct PartialData {
    remaining: usize,
}

impl PartialData {
    pub fn decode<B: Buf>(buf: &mut B) -> Result<(Self, DataFrame<Bytes>), Error> {
        if Type::DATA != Type::decode(buf)? {
            panic!("can only decode Data frames");
        }

        let len = buf.get_var()? as usize;
        let payload = buf.copy_to_bytes(buf.remaining());

        Ok((
            Self {
                remaining: len - payload.len(),
            },
            DataFrame { payload },
        ))
    }

    pub fn decode_data<B: Buf>(&mut self, buf: &mut B) -> DataFrame<Bytes> {
        let payload = buf.copy_to_bytes(self.remaining);
        self.remaining -= payload.len();
        DataFrame { payload }
    }

    pub fn remaining(&self) -> usize {
        self.remaining
    }
}

#[derive(Debug, PartialEq)]
pub struct HeadersFrame {
    pub encoded: Bytes,
}

impl FrameHeader for HeadersFrame {
    const TYPE: Type = Type::HEADERS;
    fn len(&self) -> usize {
        self.encoded.as_ref().len()
    }
}

impl HeadersFrame {
    fn decode<B: Buf>(buf: &mut B) -> Result<Self, UnexpectedEnd> {
        Ok(HeadersFrame {
            encoded: buf.copy_to_bytes(buf.remaining()),
        })
    }

    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        self.encode_header(buf);
        buf.put(self.encoded.clone());
    }
}

impl IntoPayload for HeadersFrame {
    fn into_payload(&mut self) -> &mut dyn Buf {
        &mut self.encoded
    }
}

#[derive(Debug, PartialEq)]
pub struct PushPromiseFrame {
    id: u64,
    encoded: Bytes,
}

impl FrameHeader for PushPromiseFrame {
    const TYPE: Type = Type::PUSH_PROMISE;
    fn len(&self) -> usize {
        VarInt::from_u64(self.id).unwrap().size() + self.encoded.as_ref().len()
    }
}

impl PushPromiseFrame {
    fn decode<B: Buf>(buf: &mut B) -> Result<Self, UnexpectedEnd> {
        Ok(PushPromiseFrame {
            id: buf.get_var()?,
            encoded: buf.copy_to_bytes(buf.remaining()),
        })
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        self.encode_header(buf);
        buf.write_var(self.id);
        buf.put(self.encoded.clone());
    }
}

fn simple_frame_encode<B: BufMut>(ty: Type, id: u64, buf: &mut B) {
    ty.encode(buf);
    buf.write_var(1);
    buf.write_var(id);
}

impl From<UnexpectedEnd> for Error {
    fn from(_: UnexpectedEnd) -> Self {
        Error::UnexpectedEnd
    }
}

impl From<SettingsError> for Error {
    fn from(e: SettingsError) -> Self {
        match e {
            SettingsError::Exceeded => Error::SettingsExceeded,
            SettingsError::Malformed => Error::Malformed,
            SettingsError::Repeated(i) => Error::SettingRepeated(i),
            SettingsError::InvalidSettingId(i) => Error::InvalidSettingId(i),
            SettingsError::InvalidSettingValue(i, v) => Error::InvalidSettingValue(i, v),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::settings::Settings;
    use std::io::Cursor;

    #[test]
    fn unknown_frame_type() {
        let mut buf = Cursor::new(&[22, 4, 0, 255, 128, 0, 3, 1, 2]);
        assert_eq!(HttpFrame::decode(&mut buf), Err(Error::UnknownFrame(22)));
        assert_eq!(HttpFrame::decode(&mut buf), Ok(HttpFrame::CancelPush(2)));
    }

    #[test]
    fn len_unexpected_end() {
        let mut buf = Cursor::new(&[0, 255]);
        let decoded = HttpFrame::decode(&mut buf);
        assert_eq!(decoded, Err(Error::Incomplete(3)));
    }

    #[test]
    fn type_unexpected_end() {
        let mut buf = Cursor::new(&[255]);
        let decoded = HttpFrame::decode(&mut buf);
        assert_eq!(decoded, Err(Error::Incomplete(2)));
    }

    #[test]
    fn buffer_too_short() {
        let mut buf = Cursor::new(&[4, 4, 0, 255, 128]);
        let decoded = HttpFrame::decode(&mut buf);
        assert_eq!(decoded, Err(Error::Incomplete(6)));
    }

    fn codec_frame_check(frame: HttpFrame, wire: &[u8]) {
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        println!("buf: {:?}", buf);
        assert_eq!(&buf, &wire);

        let mut read = Cursor::new(&buf);
        let decoded = HttpFrame::decode(&mut read).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn settings_frame() {
        let mut settings = Settings::new();
        settings.set_max_header_list_size(0xfad1).unwrap();
        settings.set_qpack_max_table_capacity(0xfad2).unwrap();
        settings.set_qpack_max_blocked_streams(0xfad3).unwrap();
        codec_frame_check(
            HttpFrame::Settings(settings.to_frame()),
            &[
                4, 15, 6, 128, 0, 250, 209, 1, 128, 0, 250, 210, 7, 128, 0, 250, 211,
            ],
        );
    }

    #[test]
    fn settings_frame_emtpy() {
        codec_frame_check(HttpFrame::Settings(Settings::default().to_frame()), &[4, 0]);
    }

    #[test]
    fn data_frame() {
        codec_frame_check(
            HttpFrame::Data(DataFrame {
                payload: Bytes::from("foo bar"),
            }),
            &[0, 7, 102, 111, 111, 32, 98, 97, 114],
        );
    }

    #[test]
    fn simple_frames() {
        codec_frame_check(HttpFrame::CancelPush(2), &[3, 1, 2]);
        codec_frame_check(HttpFrame::Goaway(2), &[7, 1, 2]);
        codec_frame_check(HttpFrame::MaxPushId(2), &[13, 1, 2]);
        codec_frame_check(HttpFrame::DuplicatePush(2), &[14, 1, 2]);
    }

    #[test]
    fn headers_frames() {
        codec_frame_check(
            HttpFrame::Headers(HeadersFrame {
                encoded: Bytes::from("TODO QPACK"),
            }),
            &[1, 10, 84, 79, 68, 79, 32, 81, 80, 65, 67, 75],
        );
        codec_frame_check(
            HttpFrame::PushPromise(PushPromiseFrame {
                id: 134,
                encoded: Bytes::from("TODO QPACK"),
            }),
            &[5, 12, 64, 134, 84, 79, 68, 79, 32, 81, 80, 65, 67, 75],
        );
    }

    #[test]
    fn reserved_frame() {
        let mut raw = vec![];
        VarInt::from_u32(0x21 + 2 * 0x1f).encode(&mut raw);
        raw.extend(&[6, 0, 255, 128, 0, 250, 218]);
        let mut buf = Cursor::new(&raw);
        let decoded = HttpFrame::decode(&mut buf);
        assert_eq!(decoded, Ok(HttpFrame::Reserved));
    }
}
