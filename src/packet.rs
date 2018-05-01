use bytes::{BigEndian, Buf, BufMut};

use codec::{BufLen, Codec, VarLen};
use frame::{Frame, PaddingFrame};
use crypto::PacketKey;

use std::io::Cursor;

#[derive(Debug, PartialEq)]
pub struct Packet {
    pub header: Header,
    pub payload: Vec<Frame>,
}

impl Packet {
    pub fn ptype(&self) -> Option<LongType> {
        self.header.ptype()
    }

    pub fn conn_id(&self) -> Option<u64> {
        self.header.conn_id()
    }

    pub fn number(&self) -> u32 {
        self.header.number()
    }

    pub fn encode(&self, key: &PacketKey, buf: &mut Vec<u8>) {
        let unpadded_len = self.buf_len() + key.algorithm().tag_len();
        let len = if self.ptype() == Some(LongType::Initial) && unpadded_len < 1200 {
            1200
        } else {
            unpadded_len
        };

        if len > buf.capacity() {
            let diff = len - buf.capacity();
            buf.reserve(diff);
        }

        buf.resize(len, 0);
        let (payload_start, buf) = {
            let mut write = Cursor::new(buf);
            self.header.encode(&mut write);
            let payload_start = write.position() as usize;
            debug_assert_eq!(payload_start, self.header.buf_len());

            let mut expected = payload_start;
            for frame in self.payload.iter() {
                frame.encode(&mut write);
                expected += frame.buf_len();
            }
            debug_assert_eq!(expected, write.position() as usize);

            if unpadded_len < len {
                let padding = Frame::Padding(PaddingFrame(len - unpadded_len));
                padding.encode(&mut write);
            }
            (payload_start, write.into_inner())
        };

        let out_len = {
            let suffix_capacity = key.algorithm().tag_len();
            let (header_buf, mut payload) = buf.split_at_mut(payload_start);
            key.encrypt(
                self.header.number(),
                &header_buf,
                &mut payload,
                suffix_capacity,
            )
        };
        buf.truncate(payload_start + out_len);
    }

    pub fn start_decode(buf: &mut [u8]) -> PartialDecode {
        let (header, header_len) = {
            let mut read = Cursor::new(&buf);
            let header = Header::decode(&mut read);
            (header, read.position() as usize)
        };
        PartialDecode {
            header,
            header_len,
            buf,
        }
    }
}

pub struct PartialDecode<'a> {
    pub(crate) header: Header,
    header_len: usize,
    buf: &'a mut [u8],
}

impl<'a> PartialDecode<'a> {
    pub fn conn_id(&self) -> Option<u64> {
        self.header.conn_id()
    }

    pub fn finish(self, key: &PacketKey) -> Packet {
        let PartialDecode {
            header,
            header_len,
            buf,
        } = self;
        let (header_buf, payload_buf) = buf.split_at_mut(header_len);
        let decrypted = key.decrypt(header.number(), &header_buf, payload_buf);
        let mut read = Cursor::new(decrypted);

        let mut payload = Vec::new();
        while read.has_remaining() {
            let frame = Frame::decode(&mut read);
            payload.push(frame);
        }

        Packet { header, payload }
    }
}

impl BufLen for Packet {
    fn buf_len(&self) -> usize {
        let payload_len: usize = self.payload.iter().map(|f| f.buf_len()).sum();
        self.header.buf_len() + payload_len
    }
}

#[derive(Debug, PartialEq)]
pub enum Header {
    Short {
        ptype: ShortType,
        conn_id: Option<u64>,
        key_phase: bool,
        number: u32,
    },
    Long {
        ptype: LongType,
        conn_id: u64,
        version: u32,
        number: u32,
    },
}

impl Header {
    pub fn ptype(&self) -> Option<LongType> {
        match *self {
            Header::Short { .. } => None,
            Header::Long { ptype, .. } => Some(ptype),
        }
    }

    fn conn_id(&self) -> Option<u64> {
        match *self {
            Header::Short { conn_id, .. } => conn_id,
            Header::Long { conn_id, .. } => Some(conn_id),
        }
    }

    fn number(&self) -> u32 {
        match *self {
            Header::Short { number, .. } => number,
            Header::Long { number, .. } => number,
        }
    }
}

impl BufLen for Header {
    fn buf_len(&self) -> usize {
        match *self {
            Header::Short {
                ref ptype,
                ref conn_id,
                number,
                ..
            } => {
                1 + if conn_id.is_some() { 8 } else { 0 } + ptype.buf_len()
                    + VarLen(number as u64).buf_len()
            }
            Header::Long { .. } => 17,
        }
    }
}

impl Codec for Header {
    fn encode<T: BufMut>(&self, buf: &mut T) {
        match *self {
            Header::Long {
                ptype,
                conn_id,
                version,
                number,
            } => {
                buf.put_u8(128 | ptype.to_byte());
                buf.put_u64::<BigEndian>(conn_id);
                buf.put_u32::<BigEndian>(version);
                buf.put_u32::<BigEndian>(number);
            }
            Header::Short {
                ptype,
                conn_id,
                key_phase,
                number,
            } => {
                let omit_conn_id = if conn_id.is_some() { 0x40 } else { 0 };
                let key_phase_bit = if key_phase { 0x20 } else { 0 };
                buf.put_u8(omit_conn_id | key_phase_bit | 0x10 | ptype.to_byte());
                if let Some(cid) = conn_id {
                    buf.put_u64::<BigEndian>(cid);
                }
                VarLen(number as u64).encode(buf);
            }
        }
    }

    fn decode<T: Buf>(buf: &mut T) -> Self {
        let first = buf.get_u8();
        if first & 128 == 128 {
            Header::Long {
                ptype: LongType::from_byte(first ^ 128),
                conn_id: buf.get_u64::<BigEndian>(),
                version: buf.get_u32::<BigEndian>(),
                number: buf.get_u32::<BigEndian>(),
            }
        } else {
            let ptype = ShortType::from_byte(first & 7);
            let conn_id = if first & 0x40 == 0x40 {
                Some(buf.get_u64::<BigEndian>())
            } else {
                None
            };

            let size = ptype.buf_len();
            let number = if size == 1 {
                buf.get_u8() as u32
            } else if size == 2 {
                buf.get_u16::<BigEndian>() as u32
            } else {
                buf.get_u32::<BigEndian>()
            };

            Header::Short {
                ptype,
                conn_id,
                key_phase: first & 0x20 == 0x20,
                number,
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum LongType {
    Initial = 0x7f,
    Retry = 0x7e,
    Handshake = 0x7d,
    Protected = 0x7c,
}

impl Copy for LongType {}

impl LongType {
    pub fn to_byte(&self) -> u8 {
        use self::LongType::*;
        match *self {
            Initial => 0x7f,
            Retry => 0x7e,
            Handshake => 0x7d,
            Protected => 0x7c,
        }
    }
    pub fn from_byte(v: u8) -> Self {
        use self::LongType::*;
        match v {
            0x7f => Initial,
            0x7e => Retry,
            0x7d => Handshake,
            0x7c => Protected,
            _ => panic!("invalid long packet type {}", v),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ShortType {
    One = 0x0,
    Two = 0x1,
    Four = 0x2,
}

impl Copy for ShortType {}

impl BufLen for ShortType {
    fn buf_len(&self) -> usize {
        use self::ShortType::*;
        match *self {
            One => 1,
            Two => 2,
            Four => 4,
        }
    }
}

impl ShortType {
    pub fn to_byte(&self) -> u8 {
        use self::ShortType::*;
        match *self {
            One => 1,
            Two => 2,
            Four => 4,
        }
    }
    pub fn from_byte(v: u8) -> Self {
        use self::ShortType::*;
        match v {
            0 => One,
            1 => Two,
            2 => Four,
            _ => panic!("invalid short packet type {}", v),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Header, LongType, Packet};
    use types::DRAFT_10;
    use frame::{Frame, StreamFrame};
    use tls::{Secret, Side};

    #[test]
    fn test_roundtrip() {
        let mut buf = vec![0u8; 65536];
        let bytes = b"\x00\x01\x02\x03";
        let packet = Packet {
            header: Header::Long {
                ptype: LongType::Initial,
                conn_id: 123456789,
                version: DRAFT_10,
                number: 987654321,
            },
            payload: vec![
                Frame::Stream(StreamFrame {
                    id: 0,
                    fin: false,
                    offset: 0,
                    len: Some(bytes.len() as u64),
                    data: bytes.to_vec(),
                }),
            ],
        };

        let key = Secret::Handshake(123456789).build_key(Side::Client);
        packet.encode(&key, &mut buf);
        let mut decoded = Packet::start_decode(&mut buf).finish(&key);

        decoded.payload.retain(|f| {
            if let Frame::Padding(_) = *f {
                false
            } else {
                true
            }
        });
        assert_eq!(packet, decoded);
    }
}
