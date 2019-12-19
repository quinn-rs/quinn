use std::fmt;

use bytes::{buf::ext::BufExt as _, Buf, BufMut, Bytes};
use quinn_proto::{
    coding::{BufExt, BufMutExt, Codec, UnexpectedEnd},
    VarInt,
};
use std::collections::HashSet;
use tracing::trace;

#[derive(Debug, PartialEq)]
pub enum Error {
    Malformed,
    UnsupportedFrame,
    UnexpectedEnd,
    InvalidFrameValue,
    Incomplete(usize),
    IncompleteData,
    Settings(String),
}

#[derive(Debug, PartialEq)]
pub enum HttpFrame {
    Data(DataFrame),
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
        let ty = Type::decode(buf)?;
        let len = buf.get_var()?;

        if buf.remaining() < len as usize {
            if ty == Type::DATA {
                return Err(Error::IncompleteData);
            }
            return Err(Error::Incomplete(2 + len as usize));
        }

        let mut payload = buf.take(len as usize);
        let frame = match ty {
            Type::DATA => Ok(HttpFrame::Data(DataFrame {
                payload: payload.to_bytes(),
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
                Err(Error::UnsupportedFrame)
            }
            t if t.0 > 0x21 && (t.0 - 0x21) % 0x1f == 0 => {
                buf.advance(len as usize);
                Ok(HttpFrame::Reserved)
            }
            _ => Err(Error::UnsupportedFrame),
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
    fn into_payload(self) -> Bytes;
}

#[derive(Debug, PartialEq)]
pub struct DataFrame {
    pub payload: Bytes,
}

impl DataFrame {
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        self.encode_header(buf);
        buf.put(self.payload.clone());
    }
}

impl FrameHeader for DataFrame {
    const TYPE: Type = Type::DATA;
    fn len(&self) -> usize {
        self.payload.as_ref().len()
    }
}

impl IntoPayload for DataFrame {
    fn into_payload(self) -> Bytes {
        self.payload
    }
}

pub struct PartialData {
    remaining: usize,
}

impl PartialData {
    pub fn decode<B: Buf>(buf: &mut B) -> Result<(Self, DataFrame), Error> {
        if Type::DATA != Type::decode(buf)? {
            panic!("can only decode Data frames");
        }

        let len = buf.get_var()? as usize;
        let payload = buf.to_bytes();

        Ok((
            Self {
                remaining: len - payload.len(),
            },
            DataFrame { payload },
        ))
    }

    pub fn decode_data<B: Buf>(&mut self, buf: &mut B) -> DataFrame {
        let payload = buf.take(self.remaining).to_bytes();
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
            encoded: buf.to_bytes(),
        })
    }

    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        self.encode_header(buf);
        buf.put(self.encoded.clone());
    }
}

impl IntoPayload for HeadersFrame {
    fn into_payload(self) -> Bytes {
        self.encoded
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
            encoded: buf.to_bytes(),
        })
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        self.encode_header(buf);
        buf.write_var(self.id);
        buf.put(self.encoded.clone());
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct SettingsFrame {
    pub num_placeholders: u64,
    pub max_header_list_size: u64,
    pub qpack_max_table_capacity: u64,
    pub qpack_blocked_streams: u64,
}

impl Default for SettingsFrame {
    fn default() -> SettingsFrame {
        SettingsFrame {
            num_placeholders: DEFAULT_NUM_PLACE_HOLDER,
            max_header_list_size: DEFAULT_MAX_HEADER_LIST_SIZE,
            qpack_max_table_capacity: DEFAULT_QPACK_MAX_TABLE_CAPACITY,
            qpack_blocked_streams: DEFAULT_QPACK_BLOCKED_STREAMS,
        }
    }
}

const DEFAULT_NUM_PLACE_HOLDER: u64 = 16;
const DEFAULT_MAX_HEADER_LIST_SIZE: u64 = 6;
const DEFAULT_QPACK_MAX_TABLE_CAPACITY: u64 = 4096;
const DEFAULT_QPACK_BLOCKED_STREAMS: u64 = 129;

impl SettingsFrame {
    pub fn encode<T: BufMut>(&self, buf: &mut T) {
        self.encode_header(buf);
        SettingId::NUM_PLACEHOLDERS.encode(buf);
        buf.write_var(self.num_placeholders);
        SettingId::MAX_HEADER_LIST_SIZE.encode(buf);
        buf.write_var(self.max_header_list_size);
        SettingId::QPACK_MAX_TABLE_CAPACITY.encode(buf);
        buf.write_var(self.qpack_max_table_capacity);
        SettingId::QPACK_BLOCKED_STREAMS.encode(buf);
        buf.write_var(self.qpack_blocked_streams);
    }

    fn decode<T: Buf>(buf: &mut T) -> Result<SettingsFrame, Error> {
        let mut settings = SettingsFrame::default();
        let mut received = HashSet::with_capacity(4);
        while buf.has_remaining() {
            if buf.remaining() < 2 {
                // remains less than 2 * minimum-size varint
                return Err(Error::Malformed);
            }
            let identifier = SettingId::decode(buf).map_err(|_| Error::Malformed)?;
            let value = buf.get_var().map_err(|_| Error::InvalidFrameValue)?;

            if !received.insert(identifier) {
                return Err(Error::Settings(format!(
                    "Recieved setting '0x{:X}' twice",
                    identifier.0
                )));
            }

            match identifier {
                t if t.0 > 0x21 && (t.0 - 0x21) % 0x1f == 0 => continue,
                SettingId::NUM_PLACEHOLDERS => {
                    settings.num_placeholders = value;
                }
                SettingId::MAX_HEADER_LIST_SIZE => {
                    settings.max_header_list_size = value;
                }
                SettingId::QPACK_MAX_TABLE_CAPACITY => {
                    settings.qpack_max_table_capacity = value;
                }
                SettingId::QPACK_BLOCKED_STREAMS => {
                    settings.qpack_blocked_streams = value;
                }
                _ => continue,
            }
        }
        Ok(settings)
    }
}

impl FrameHeader for SettingsFrame {
    const TYPE: Type = Type::SETTINGS;
    fn len(&self) -> usize {
        fn sz(x: u64) -> usize {
            VarInt::from_u64(x).unwrap().size()
        }
        sz(SettingId::NUM_PLACEHOLDERS.0)
            + sz(self.num_placeholders)
            + sz(SettingId::MAX_HEADER_LIST_SIZE.0)
            + sz(self.max_header_list_size)
            + sz(SettingId::QPACK_MAX_TABLE_CAPACITY.0)
            + sz(self.qpack_max_table_capacity)
            + sz(SettingId::QPACK_BLOCKED_STREAMS.0)
            + sz(self.qpack_blocked_streams)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
struct SettingId(u64);

impl Codec for SettingId {
    fn decode<B: Buf>(buf: &mut B) -> Result<Self, UnexpectedEnd> {
        Ok(SettingId(buf.get_var()?))
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.write_var(self.0);
    }
}

macro_rules! setting_identifiers {
    {$($name:ident = $val:expr,)*} => {
        impl SettingId {
            $(pub const $name: SettingId = SettingId($val);)*
        }
    }
}

setting_identifiers! {
    QPACK_MAX_TABLE_CAPACITY = 0x1,
    QPACK_BLOCKED_STREAMS = 0x7,
    NUM_PLACEHOLDERS = 0x8,
    MAX_HEADER_LIST_SIZE = 0x6,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn unknown_frame_type() {
        let mut buf = Cursor::new(&[0x2f, 4, 0, 255, 128, 0]);
        let decoded = HttpFrame::decode(&mut buf);
        assert_eq!(decoded, Err(Error::UnsupportedFrame));
    }

    #[test]
    fn buffer_too_short() {
        let mut buf = Cursor::new(&[4, 4, 0, 255, 128]);
        let decoded = HttpFrame::decode(&mut buf);
        assert_eq!(decoded, Err(Error::Incomplete(6)));
    }

    #[test]
    fn settings_frame_ignores_0x_a_a() {
        let mut buf = vec![4, 16, 8, 128, 0, 250, 218];
        buf.write_var(0x1a2a);
        buf.extend(&[128, 0, 250, 218, 6, 128, 0, 250, 218]);

        let mut cur = Cursor::new(&buf);
        let decoded = HttpFrame::decode(&mut cur).unwrap();
        assert_matches!(
            decoded,
            HttpFrame::Settings(SettingsFrame {
                num_placeholders: 0xfada,
                max_header_list_size: 0xfada,
                ..
            })
        );
    }

    #[test]
    fn settings_frame_invalid_value() {
        let mut buf = Cursor::new(&[4, 6, 0, 255, 128, 0, 250, 218]);
        let decoded = HttpFrame::decode(&mut buf);
        assert_eq!(decoded, Err(Error::InvalidFrameValue));
    }

    #[test]
    fn settings_frame_invalid_len() {
        let mut buf = Cursor::new(&[4, 8, 0x1a, 0x2a, 128, 0, 250, 218, 0, 3]);
        let decoded = HttpFrame::decode(&mut buf);
        assert_eq!(decoded, Err(Error::Malformed));
    }

    #[test]
    fn settings_frame_identifier_twice() {
        let mut buf = Cursor::new(&[4, 10, 6, 128, 0, 250, 218, 6, 128, 0, 250, 218]);
        let decoded = HttpFrame::decode(&mut buf);
        assert_eq!(
            decoded,
            Err(Error::Settings("Recieved setting '0x6' twice".to_string()))
        );
    }

    #[test]
    fn settings_frame_ignores_unknown_id() {
        let mut buf = Cursor::new(&[4, 10, 0xA, 128, 0, 250, 218, 6, 128, 0, 250, 218]);
        let decoded = HttpFrame::decode(&mut buf);
        assert_matches!(
            decoded,
            Ok(HttpFrame::Settings(SettingsFrame {
                num_placeholders: 16,
                max_header_list_size: 0xFADA,
                ..
            }))
        );
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
        codec_frame_check(
            HttpFrame::Settings(SettingsFrame {
                num_placeholders: 0xfada,
                max_header_list_size: 0xfad1,
                qpack_max_table_capacity: 0xfad2,
                qpack_blocked_streams: 0xfad3,
            }),
            &[
                4, 20, 8, 128, 0, 250, 218, 6, 128, 0, 250, 209, 1, 128, 0, 250, 210, 7, 128, 0,
                250, 211,
            ],
        );
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
