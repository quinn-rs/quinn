use bytes::{BigEndian, BufMut};

use codec::{BufLen, Codec, VarLen};
use frame::{Frame, PaddingFrame};
use crypto::PacketKey;

use std::io::Cursor;

pub struct Packet {
    pub header: Header,
    pub payload: Vec<Frame>,
}

impl Packet {
    pub fn encode(&self, key: &PacketKey, buf: &mut Vec<u8>) {
        let unpadded_len = self.buf_len() + key.algorithm().tag_len();
        let len = if unpadded_len < 1200 {
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
            let (header, mut payload) = buf.split_at_mut(payload_start);
            key.encrypt(&header, &mut payload, suffix_capacity)
        };
        buf.truncate(payload_start + out_len);
    }
}

impl BufLen for Packet {
    fn buf_len(&self) -> usize {
        let payload_len: usize = self.payload.iter().map(|f| f.buf_len()).sum();
        self.header.buf_len() + payload_len
    }
}

#[derive(Debug)]
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

impl BufLen for Header {
    fn buf_len(&self) -> usize {
        match *self {
            Header::Short { ref ptype, ref conn_id, number, .. } => {
                1 + if conn_id.is_some() {
                    8
                } else {
                    0
                } + ptype.buf_len() + VarLen::new(number as u64).buf_len()
            },
            Header::Long { .. } => 17,
        }
    }
}

impl Codec for Header {
    fn encode<T: BufMut>(&self, buf: &mut T) {
        match *self {
            Header::Long { ptype, conn_id, version, number } => {
                buf.put_u8(128 | ptype.to_byte());
                buf.put_u64::<BigEndian>(conn_id);
                buf.put_u32::<BigEndian>(version);
                buf.put_u32::<BigEndian>(number);
            },
            Header::Short { ptype, conn_id, key_phase, number } => {
                let omit_conn_id = if conn_id.is_some() {
                    0x40
                } else {
                    0
                };
                let key_phase_bit = if key_phase {
                    0x20
                } else {
                    0
                };
                buf.put_u8(omit_conn_id | key_phase_bit | 0x10 | ptype.to_byte());
                if let Some(cid) = conn_id {
                    buf.put_u64::<BigEndian>(cid);
                }
                VarLen::new(number as u64).encode(buf);
            },
        }
    }
}

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
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

pub const DRAFT_10: u32 = 0xff00000a;
