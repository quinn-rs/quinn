use bytes::{BigEndian, BufMut, BytesMut};

use std::io;

use tokio_io::codec::{Decoder, Encoder};

pub struct QuicCodec {}

impl Decoder for QuicCodec {
    type Item = Packet;
    type Error = io::Error;
    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, io::Error> {
        let first = buf[0];
        let (header, number, offset) = if first & 128 == 128 {

            let h = Header::Long {
                ptype: LongType::from_byte(first ^ 128),
                conn_id: bytes_to_u64(&buf[1..9]),
                version: bytes_to_u32(&buf[9..13]),
            };
            let number = bytes_to_u32(&buf[13..17]);
            (h, number, 17)

        } else {

            let ptype = ShortType::from_byte(first & 7);
            let conn_id = if first & 0x40 == 0x40 {
                Some(bytes_to_u64(&buf[1..9]))
            } else {
                None
            };
            let h = Header::Short {
                ptype,
                conn_id,
                key_phase: first & 0x20 == 0x20,
            };

            let offset = if conn_id.is_some() { 9 } else { 1 };
            let size = match h {
                Header::Short { ref ptype, .. } => ptype.buf_len(),
                _ => panic!("must be a short header"),
            };
            let number = if size == 1 {
                buf[offset] as u32
            } else if size == 2 {
                (buf[offset] as u32) << 8 | (buf[offset + 1] as u32)
            } else {
                bytes_to_u32(&buf[offset..offset + 4])
            };
            (h, number, offset + size)

        };
        Ok(Some(Packet {
            header,
            number,
            payload: Vec::new(),
        }))
    }
}

impl Encoder for QuicCodec {
    type Item = Packet;
    type Error = io::Error;
    fn encode(&mut self, msg: Self::Item, dst: &mut BytesMut) -> Result<(), io::Error> {
        let required = msg.buf_len();
        let cur_size = dst.remaining_mut();
        if cur_size < required {
            dst.reserve(required - cur_size);
        }
        Ok(())
    }
}

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
    fn to_byte(&self) -> u8 {
        use self::LongType::*;
        match *self {
            Initial => 0x7f,
            Retry => 0x7e,
            Handshake => 0x7d,
            Protected => 0x7c,
        }
    }
    fn from_byte(v: u8) -> Self {
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
    fn to_byte(&self) -> u8 {
        use self::ShortType::*;
        match *self {
            One => 1,
            Two => 2,
            Four => 4,
        }
    }
    fn from_byte(v: u8) -> Self {
        use self::ShortType::*;
        match v {
            0 => One,
            1 => Two,
            2 => Four,
            _ => panic!("invalid short packet type {}", v),
        }
    }
}

pub enum Frame {
    Padding(PaddingFrame),
    Stream(StreamFrame),
}

impl BufLen for Frame {
    fn buf_len(&self) -> usize {
        match *self {
            Frame::Padding(ref f) => f.buf_len(),
            Frame::Stream(ref f) => f.buf_len(),
        }
    }
}

impl Codec for Frame {
    fn encode<T: BufMut>(&self, buf: &mut T) {
        match *self {
            Frame::Padding(ref f) => f.encode(buf),
            Frame::Stream(ref f) => f.encode(buf),
        }
    }
}

pub struct StreamFrame {
    pub id: u64,
    pub fin: bool,
    pub offset: Option<u64>,
    pub len: Option<u64>,
    pub data: Vec<u8>,
}

impl BufLen for StreamFrame {
    fn buf_len(&self) -> usize {
        1 +
            self.offset.map(VarLen::new).buf_len() +
            self.len.map(VarLen::new).buf_len() +
            self.data.len()
    }
}

impl Codec for StreamFrame {
    fn encode<T: BufMut>(&self, buf: &mut T) {
        let has_offset = if self.offset.is_some() {
            0x04
        } else {
            0
        };
        let has_len = if self.len.is_some() {
            0x02
        } else {
            0
        };
        let is_fin = if self.fin {
            0x01
        } else {
            0
        };
        buf.put_u8(0x10 | has_offset | has_len | is_fin);
        if let Some(offset) = self.offset {
            VarLen::new(offset).encode(buf);
        }
        if let Some(len) = self.len {
            VarLen::new(len).encode(buf);
        }
        buf.put_slice(&self.data);
    }
}

pub struct PaddingFrame(pub usize);

impl BufLen for PaddingFrame {
    fn buf_len(&self) -> usize {
        self.0
    }
}

impl Codec for PaddingFrame {
    fn encode<T: BufMut>(&self, buf: &mut T) {
        let padding = vec![0; self.0];
        buf.put_slice(&padding);
    }
}

pub enum FrameType {
    Padding = 0x0,
    ResetStream = 0x1,
    ConnectionClose = 0x2,
    ApplicationClose = 0x3,
    MaxData = 0x4,
    MaxStreamData = 0x5,
    MaxStreamId = 0x6,
    Ping = 0x7,
    Blocked = 0x8,
    StreamBlocked = 0x9,
    StreamIdBlocked = 0xa,
    NewConnectionId = 0xb,
    StopSending = 0xc,
    Ack = 0xd,
    PathChallenge = 0xe,
    PathResponse = 0xf,
    Stream = 0x10,
    StreamFin = 0x11,
    StreamLen = 0x12,
    StreamLenFin = 0x13,
    StreamOff = 0x14,
    StreamOffFin = 0x15,
    StreamOffLen = 0x16,
    StreamOffLenFin = 0x17,
}

struct VarLen {
    val: u64,
}

impl VarLen {
    fn new(val: u64) -> VarLen {
        VarLen { val }
    }
}

impl BufLen for VarLen {
    fn buf_len(&self) -> usize {
        match self.val {
            v if v <= 63 => 1,
            v if v <= 16_383 => 2,
            v if v <= 1_073_741_823 => 4,
            v if v <= 4_611_686_018_427_387_903 => 8,
            v => panic!("too large for variable-length encoding: {}", v),
        }
    }
}

impl Codec for VarLen {
    fn encode<T: BufMut>(&self, buf: &mut T) {
        match self.buf_len() {
            1 => buf.put_u8(self.val as u8),
            2 => buf.put_u16::<BigEndian>(self.val as u16 | 16384),
            4 => buf.put_u32::<BigEndian>(self.val as u32 | 2_147_483_648),
            8 => buf.put_u64::<BigEndian>(self.val | 13_835_058_055_282_163_712),
            _ => panic!("impossible variable-length encoding"),
        }
    }
}

fn bytes_to_u64(bytes: &[u8]) -> u64 {
    debug_assert_eq!(bytes.len(), 8);
    ((bytes[0] as u64) << 56 |
        (bytes[1] as u64) << 48 |
        (bytes[2] as u64) << 40 |
        (bytes[3] as u64) << 32 |
        (bytes[4] as u64) << 24 |
        (bytes[5] as u64) << 16 |
        (bytes[6] as u64) << 8 |
        (bytes[7] as u64))
}

fn bytes_to_u32(bytes: &[u8]) -> u32 {
    debug_assert_eq!(bytes.len(), 4);
    ((bytes[0] as u32) << 24 |
        (bytes[1] as u32) << 16 |
        (bytes[2] as u32) << 8 |
        (bytes[3] as u32))
}

pub trait BufLen {
    fn buf_len(&self) -> usize;
}

impl<T> BufLen for Option<T> where T: BufLen {
    fn buf_len(&self) -> usize {
        match *self {
            Some(ref v) => v.buf_len(),
            None => 0,
        }
    }
}

pub trait Codec {
    fn encode<T: BufMut>(&self, buf: &mut T);
}

pub const DRAFT_10: u32 = 0xff00000a;

#[cfg(test)]
mod tests {
    use super::{Codec, VarLen};
    #[test]
    fn test_var_len_encoding_8() {
        let num = 151_288_809_941_952_652;
        let bytes = b"\xc2\x19\x7c\x5e\xff\x14\xe8\x8c";
        let mut buf = Vec::new();
        VarLen::new(num).encode(&mut buf);
        assert_eq!(bytes[..], *buf);
    }
    #[test]
    fn test_var_len_encoding_4() {
        let num = 494_878_333;
        let bytes = b"\x9d\x7f\x3e\x7d";
        let mut buf = Vec::new();
        VarLen::new(num).encode(&mut buf);
        assert_eq!(bytes[..], *buf);
    }
    #[test]
    fn test_var_len_encoding_2() {
        let num = 15_293;
        let bytes = b"\x7b\xbd";
        let mut buf = Vec::new();
        VarLen::new(num).encode(&mut buf);
        assert_eq!(bytes[..], *buf);
    }
    #[test]
    fn test_var_len_encoding_1_short() {
        let num = 37;
        let bytes = b"\x25";
        let mut buf = Vec::new();
        VarLen::new(num).encode(&mut buf);
        assert_eq!(bytes[..], *buf);
    }
}
