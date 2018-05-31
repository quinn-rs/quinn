use bytes::{Buf, BufMut};

use codec::{BufLen, Codec, VarLen};
use {QuicError, QuicResult};

// On the wire:
// len: VarLen
// ptype: u8
// flags: u8
// payload: [u8]
#[derive(Debug, PartialEq)]
enum HttpFrame {
    Settings(SettingsFrame),
}

impl Codec for HttpFrame {
    fn encode<T: BufMut>(&self, buf: &mut T) {
        match self {
            HttpFrame::Settings(f) => {
                f.len().encode(buf);
                buf.put_u8(0x4);
                f.encode(buf);
            }
        }
    }

    fn decode<T: Buf>(buf: &mut T) -> QuicResult<Self> {
        let len = VarLen::decode(buf)?.0 as usize;
        match buf.get_u8() {
            0x4 => Ok(HttpFrame::Settings(SettingsFrame::decode(
                &mut buf.take(1 + len),
            )?)),
            v => Err(QuicError::DecodeError(format!(
                "unsupported HTTP frame type {}",
                v
            ))),
        }
    }
}

#[derive(Debug, PartialEq)]
struct SettingsFrame(Settings);

impl Codec for SettingsFrame {
    fn encode<T: BufMut>(&self, buf: &mut T) {
        buf.put_u8(0);
        buf.put_u16_be(0x1);
        let encoded = VarLen(u64::from(self.0.header_table_size));
        let encoded_len = encoded.buf_len();
        debug_assert!(encoded_len < 64);
        VarLen(encoded_len as u64).encode(buf);
        encoded.encode(buf);

        buf.put_u16_be(0x6);
        let encoded = VarLen(u64::from(self.0.max_header_list_size));
        let encoded_len = encoded.buf_len();
        debug_assert!(encoded_len < 64);
        VarLen(encoded_len as u64).encode(buf);
        encoded.encode(buf);
    }

    fn decode<T: Buf>(buf: &mut T) -> QuicResult<SettingsFrame> {
        if buf.get_u8() != 0 {
            return Err(QuicError::DecodeError("unsupported flags".into()));
        }
        let mut settings = Settings::default();
        while buf.has_remaining() {
            let tag = buf.get_u16_be();
            if tag != 0x1 && tag != 0x6 {
                return Err(QuicError::DecodeError("unsupported tag".into()));
            }
            VarLen::decode(buf)?;
            let val = VarLen::decode(buf)?;
            if tag == 0x1 {
                settings.header_table_size = val.0 as u32;
            } else if tag == 0x6 {
                settings.max_header_list_size = val.0 as u32;
            }
        }
        Ok(SettingsFrame(settings))
    }
}

impl FrameHeader for SettingsFrame {
    fn len(&self) -> VarLen {
        VarLen(
            (6 + VarLen(u64::from(self.0.header_table_size)).buf_len()
                + VarLen(u64::from(self.0.max_header_list_size)).buf_len()) as u64,
        )
    }
    fn flags(&self) -> u8 {
        0
    }
    fn ftype(&self) -> u8 {
        0x4
    }
}

impl<T> BufLen for T
where
    T: FrameHeader,
{
    fn buf_len(&self) -> usize {
        let len = self.len();
        2 + VarLen(len.0).buf_len() + (len.0 as usize)
    }
}

pub trait FrameHeader {
    fn len(&self) -> VarLen;
    fn flags(&self) -> u8;
    fn ftype(&self) -> u8;
    fn encode_header<T: BufMut>(&self, buf: &mut T) {
        self.len().encode(buf);
        buf.put_u8(self.ftype());
        buf.put_u8(self.flags());
    }
}

#[derive(Debug, PartialEq)]
pub struct Settings {
    header_table_size: u32,
    max_header_list_size: u32,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings {
            header_table_size: 65536,
            max_header_list_size: 65536,
        }
    }
}

#[cfg(test)]
mod tests {
    use codec::Codec;
    use std::io::Cursor;

    #[test]
    fn test_settings_frame() {
        let settings = super::Settings {
            header_table_size: 131072,
            max_header_list_size: 65536,
        };

        let frame = super::HttpFrame::Settings(super::SettingsFrame(settings));
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        assert_eq!(
            &buf,
            &[14, 4, 0, 0, 1, 4, 128, 2, 0, 0, 0, 6, 4, 128, 1, 0, 0]
        );

        let mut read = Cursor::new(&buf);
        let decoded = super::HttpFrame::decode(&mut read).unwrap();
        assert_eq!(decoded, frame);
    }
}
