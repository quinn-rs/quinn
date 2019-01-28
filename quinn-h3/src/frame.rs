use std::mem::size_of;

use bytes::{Buf, BufMut, Bytes};

use quinn_proto::coding::{BufExt, BufMutExt, Codec, UnexpectedEnd};
use quinn_proto::varint;

#[derive(Debug, PartialEq)]
pub enum Error {
    Malformed,
    UnsupportedFrame,
    InvalidFrameValue,
}

#[derive(Debug, PartialEq)]
pub enum HttpFrame {
    Data(DataFrame),
    Headers(HeadersFrame),
    Priority(PriorityFrame),
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
            HttpFrame::Priority(f) => f.encode(buf),
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
        let len = buf.get_var()?;
        let ty = buf.get::<Type>()?;

        if buf.remaining() < len as usize {
            return Err(Error::Malformed);
        }

        let mut payload = buf.take(len as usize);
        match ty {
            Type::DATA => Ok(HttpFrame::Data(DataFrame {
                payload: payload.collect(),
            })),
            Type::HEADERS => Ok(HttpFrame::Headers(HeadersFrame::decode(&mut payload)?)),
            Type::PRIORITY => Ok(HttpFrame::Priority(PriorityFrame::decode(&mut payload)?)),
            Type::SETTINGS => Ok(HttpFrame::Settings(SettingsFrame::decode(&mut payload)?)),
            Type::CANCEL_PUSH => Ok(HttpFrame::CancelPush(payload.get_var()?)),
            Type::PUSH_PROMISE => Ok(HttpFrame::PushPromise(PushPromiseFrame::decode(
                &mut payload,
            )?)),
            Type::GOAWAY => Ok(HttpFrame::Goaway(payload.get_var()?)),
            Type::MAX_PUSH_ID => Ok(HttpFrame::MaxPushId(payload.get_var()?)),
            Type::DUPLICATE_PUSH => Ok(HttpFrame::DuplicatePush(payload.get_var()?)),
            t if (t.0 - 0xb) % 0x1f == 0 => Ok(HttpFrame::Reserved),
            _ => Err(Error::UnsupportedFrame),
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
    PRIORITY = 0x2,
    CANCEL_PUSH = 0x3,
    SETTINGS = 0x4,
    PUSH_PROMISE = 0x5,
    GOAWAY = 0x7,
    MAX_PUSH_ID = 0xD,
    DUPLICATE_PUSH = 0xE,
}

#[derive(Copy, Clone, Eq, PartialEq)]
struct Type(u8);

impl Codec for Type {
    fn decode<B: Buf>(buf: &mut B) -> Result<Self, UnexpectedEnd> {
        Ok(Type(buf.get_u8()))
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.write(self.0);
    }
}

trait FrameHeader {
    fn len(&self) -> usize;
    const TYPE: Type;
    fn encode_header<T: BufMut>(&self, buf: &mut T) {
        buf.write_var(self.len() as u64);
        buf.put_u8(Self::TYPE.0);
    }
}

#[derive(Debug, PartialEq)]
pub struct DataFrame {
    pub payload: Bytes,
}

impl DataFrame {
    fn encode<B: BufMut>(&self, buf: &mut B) {
        self.encode_header(buf);
        buf.put(&self.payload);
    }
}

impl FrameHeader for DataFrame {
    const TYPE: Type = Type::DATA;
    fn len(&self) -> usize {
        self.payload.as_ref().len()
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
            encoded: buf.collect(),
        })
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        self.encode_header(buf);
        buf.put(&self.encoded);
    }
}

#[derive(Debug, PartialEq)]
pub struct PushPromiseFrame {
    push_id: u64,
    encoded: Bytes,
}

impl FrameHeader for PushPromiseFrame {
    const TYPE: Type = Type::PUSH_PROMISE;
    fn len(&self) -> usize {
        varint::size(self.push_id).unwrap() + self.encoded.as_ref().len()
    }
}

impl PushPromiseFrame {
    fn decode<B: Buf>(buf: &mut B) -> Result<Self, UnexpectedEnd> {
        Ok(PushPromiseFrame {
            push_id: buf.get_var()?,
            encoded: buf.collect(),
        })
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        self.encode_header(buf);
        buf.write_var(self.push_id);
        buf.put(&self.encoded);
    }
}

#[derive(Debug, PartialEq)]
pub enum Priority {
    RequestStream(u64),
    PushStream(u64),
    Placeholder(u64),
    CurrentStream,
    TreeRoot,
}

#[derive(Debug, PartialEq)]
pub struct PriorityFrame {
    prioritized: Priority,
    dependency: Priority,
    weight: u8,
}

impl Codec for PriorityFrame {
    fn decode<B: Buf>(buf: &mut B) -> Result<Self, UnexpectedEnd> {
        let first = buf.get_u8();
        let pt = (0b11000000 & first) >> 6;
        let dt = (0b00110000 & first) >> 4;

        let prioritized = match pt {
            0b00 => Priority::RequestStream(buf.get_var()?),
            0b01 => Priority::PushStream(buf.get_var()?),
            0b10 => Priority::Placeholder(buf.get_var()?),
            0b11 => Priority::CurrentStream,
            _ => unreachable!(),
        };

        let dependency = match dt {
            0b00 => Priority::RequestStream(buf.get_var()?),
            0b01 => Priority::PushStream(buf.get_var()?),
            0b10 => Priority::Placeholder(buf.get_var()?),
            0b11 => Priority::TreeRoot,
            _ => unreachable!(),
        };

        Ok(PriorityFrame {
            prioritized,
            dependency,
            weight: buf.get_u8(),
        })
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        let (pt, prioritized) = match self.prioritized {
            Priority::RequestStream(id) => (0b00, Some(id)),
            Priority::PushStream(id) => (0b01, Some(id)),
            Priority::Placeholder(id) => (0b10, Some(id)),
            Priority::CurrentStream => (0b11, None),
            _ => unreachable!(),
        };

        let (dt, dependency) = match self.dependency {
            Priority::RequestStream(id) => (0b00, Some(id)),
            Priority::PushStream(id) => (0b01, Some(id)),
            Priority::Placeholder(id) => (0b10, Some(id)),
            Priority::CurrentStream => (0b11, None),
            _ => unreachable!(),
        };

        let first: u8 = (pt << 6) | (dt << 4);

        self.encode_header(buf);
        buf.write(first);
        if let Some(prioritized) = prioritized {
            buf.write_var(prioritized)
        }
        if let Some(dependency) = dependency {
            buf.write_var(dependency)
        }
        buf.write(self.weight);
    }
}

impl FrameHeader for PriorityFrame {
    const TYPE: Type = Type::PRIORITY;
    fn len(&self) -> usize {
        let mut size = size_of::<u8>() * 2;

        size += match self.prioritized {
            Priority::RequestStream(id) | Priority::PushStream(id) | Priority::Placeholder(id) => {
                varint::size(id).unwrap()
            }
            _ => 0,
        };
        size += match self.dependency {
            Priority::RequestStream(id) | Priority::PushStream(id) | Priority::Placeholder(id) => {
                varint::size(id).unwrap()
            }
            _ => 0,
        };

        size
    }
}

#[derive(Debug, PartialEq)]
pub struct SettingsFrame {
    pub num_placeholders: u64,
    pub max_header_list_size: u64,
}

impl Default for SettingsFrame {
    fn default() -> SettingsFrame {
        SettingsFrame {
            num_placeholders: 16,
            max_header_list_size: 65536,
        }
    }
}

impl SettingsFrame {
    fn encode<T: BufMut>(&self, buf: &mut T) {
        self.encode_header(buf);
        SettingId::NUM_PLACEHOLDERS.encode(buf);
        buf.write_var(self.num_placeholders);
        SettingId::MAX_HEADER_LIST_SIZE.encode(buf);
        buf.write_var(self.max_header_list_size);
    }

    fn decode<T: Buf>(buf: &mut T) -> Result<SettingsFrame, Error> {
        let mut settings = SettingsFrame::default();
        while buf.has_remaining() {
            if buf.remaining() < 3 {
                // remains less than id + minimum-size varint
                return Err(Error::Malformed);
            }
            let identifier = buf.get::<SettingId>()?;
            let value = buf.get_var()?;
            println!("frame value: {:x}", identifier.0);
            match identifier {
                id if id.0 & 0x0f0f == 0x0a0a => continue,
                SettingId::NUM_PLACEHOLDERS => {
                    settings.num_placeholders = value;
                }
                SettingId::MAX_HEADER_LIST_SIZE => {
                    settings.max_header_list_size = value;
                }
                _ => {
                    return Err(Error::InvalidFrameValue);
                }
            }
        }
        Ok(settings)
    }
}

impl FrameHeader for SettingsFrame {
    const TYPE: Type = Type::SETTINGS;
    fn len(&self) -> usize {
        size_of::<u16>() * 2
            + varint::size(self.num_placeholders).unwrap()
            + varint::size(self.max_header_list_size).unwrap()
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
struct SettingId(u16);

impl Codec for SettingId {
    fn decode<B: Buf>(buf: &mut B) -> Result<Self, UnexpectedEnd> {
        Ok(SettingId(u16::decode(buf)?))
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.write(self.0);
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
    NUM_PLACEHOLDERS = 0x8,
    MAX_HEADER_LIST_SIZE = 0x6,
}

fn simple_frame_encode<B: BufMut>(ty: Type, id: u64, buf: &mut B) {
    buf.write_var(1);
    buf.put_u8(ty.0);
    buf.write_var(id);
}

impl From<UnexpectedEnd> for Error {
    fn from(_: UnexpectedEnd) -> Self {
        Error::Malformed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn unknown_frame_type() {
        let mut buf = Cursor::new(&[04, 0xff, 0, 255, 128, 0]);
        let decoded = HttpFrame::decode(&mut buf);
        assert_eq!(decoded, Err(Error::UnsupportedFrame));
    }

    #[test]
    fn buffer_too_short() {
        let mut buf = Cursor::new(&[04, 0x4, 0, 255, 128]);
        let decoded = HttpFrame::decode(&mut buf);
        assert_eq!(decoded, Err(Error::Malformed));
    }

    #[test]
    fn settings_frame_ignores_0x_a_a() {
        let settings = SettingsFrame {
            num_placeholders: 0xfada,
            max_header_list_size: 0xfada,
        };

        let mut buf = Cursor::new(&[
            18, 4, 0, 8, 128, 0, 250, 218, 0x1a, 0x2a, 128, 0, 250, 218, 0, 6, 128, 0, 250, 218,
        ]);
        let decoded = HttpFrame::decode(&mut buf).unwrap();
        assert_eq!(decoded, HttpFrame::Settings(settings));
    }

    #[test]
    fn settings_frame_ivalid_value() {
        let mut buf = Cursor::new(&[06, 4, 0, 255, 128, 0, 250, 218]);
        let decoded = HttpFrame::decode(&mut buf);
        assert_eq!(decoded, Err(Error::InvalidFrameValue));
    }

    #[test]
    fn settings_frame_ivalid_len() {
        let mut buf = Cursor::new(&[08, 4, 0x1a, 0x2a, 128, 0, 250, 218, 0, 3]);
        let decoded = HttpFrame::decode(&mut buf);
        assert_eq!(decoded, Err(Error::Malformed));
    }

    fn codec_frame_check(frame: HttpFrame, wire: &[u8]) {
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        assert_eq!(&buf, &wire);

        let mut read = Cursor::new(&buf);
        let decoded = HttpFrame::decode(&mut read).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn settings_frame() {
        codec_frame_check(
            HttpFrame::Settings(SettingsFrame {
                num_placeholders: 0xFADA,
                max_header_list_size: 0xFADA,
            }),
            &[12, 4, 0, 8, 128, 0, 250, 218, 0, 6, 128, 0, 250, 218],
        );
    }

    #[test]
    fn data_frame() {
        codec_frame_check(
            HttpFrame::Data(DataFrame {
                payload: Bytes::from("foo bar"),
            }),
            &[7, 0, 102, 111, 111, 32, 98, 97, 114],
        );
    }

    #[test]
    fn priority_frame() {
        codec_frame_check(
            HttpFrame::Priority(PriorityFrame {
                prioritized: Priority::PushStream(21),
                dependency: Priority::RequestStream(42),
                weight: 2,
            }),
            &[4, 2, 64, 21, 42, 2],
        );
    }

    #[test]
    fn simple_frames() {
        codec_frame_check(HttpFrame::CancelPush(2), &[1, 3, 2]);
        codec_frame_check(HttpFrame::Goaway(2), &[1, 7, 2]);
        codec_frame_check(HttpFrame::MaxPushId(2), &[1, 13, 2]);
        codec_frame_check(HttpFrame::DuplicatePush(2), &[1, 14, 2]);
    }

    #[test]
    fn headers_frames() {
        codec_frame_check(
            HttpFrame::Headers(HeadersFrame {
                encoded: Bytes::from("TODO QPACK"),
            }),
            &[10, 1, 84, 79, 68, 79, 32, 81, 80, 65, 67, 75],
        );
        codec_frame_check(
            HttpFrame::PushPromise(PushPromiseFrame {
                push_id: 134,
                encoded: Bytes::from("TODO QPACK"),
            }),
            &[12, 5, 64, 134, 84, 79, 68, 79, 32, 81, 80, 65, 67, 75],
        );
    }

    #[test]
    fn reserved_frame() {
        let mut buf = Cursor::new(&[6, 0xb + 2 * 0x1f, 0, 255, 128, 0, 250, 218]);
        let decoded = HttpFrame::decode(&mut buf);
        assert_eq!(decoded, Ok(HttpFrame::Reserved));
    }

}
