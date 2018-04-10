use bytes::{BigEndian, BufMut};

use codec::{BufLen, Codec, VarLen};
use frame::Frame;

pub struct Packet {
    pub header: Header,
    pub number: u32,
    pub payload: Vec<Frame>,
}

impl BufLen for Packet {
    fn buf_len(&self) -> usize {
        let payload_len: usize = self.payload.iter().map(|f| f.buf_len()).sum();
        self.header.buf_len() + 4 + payload_len
    }
}

impl Codec for Packet {
    fn encode<T: BufMut>(&self, buf: &mut T) {
        self.header.encode(buf);
        match self.header {
            Header::Long { .. } => buf.put_u32::<BigEndian>(self.number),
            Header::Short { .. } => VarLen::new(self.number as u64).encode(buf),
        }
        for frame in self.payload.iter() {
            frame.encode(buf);
        }
    }
}

pub enum Header {
    Short {
        ptype: ShortType,
        conn_id: Option<u64>,
        key_phase: bool,
    },
    Long {
        ptype: LongType,
        conn_id: u64,
        version: u32,
    },
}

impl BufLen for Header {
    fn buf_len(&self) -> usize {
        match *self {
            Header::Short { ref ptype, ref conn_id, .. } => {
                1 + if conn_id.is_some() {
                    8
                } else {
                    0
                } + ptype.buf_len()
            },
            Header::Long { .. } => 17,
        }
    }
}

impl Codec for Header {
    fn encode<T: BufMut>(&self, buf: &mut T) {
        match *self {
            Header::Long { ptype, conn_id, version } => {
                buf.put_u8(128 | ptype.to_byte());
                buf.put_u64::<BigEndian>(conn_id);
                buf.put_u32::<BigEndian>(version);
            },
            Header::Short { ptype, conn_id, key_phase } => {
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
            },
        }
    }
}

#[derive(Clone)]
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

#[derive(Clone)]
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
