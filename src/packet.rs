use bytes::{BigEndian, Buf, BufMut};

use codec::{BufLen, Codec, VarLen};
use crypto::PacketKey;
use frame::Frame;
use types::ConnectionId;

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

    pub fn dst_cid(&self) -> ConnectionId {
        self.header.dst_cid()
    }

    pub fn number(&self) -> u32 {
        self.header.number()
    }

    pub fn encode(&self, key: &PacketKey, buf: &mut Vec<u8>) {
        let tag_len = key.algorithm().tag_len();
        let len = self.buf_len() + tag_len;
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
            (payload_start, write.into_inner())
        };

        let out_len = {
            let (header_buf, mut payload) = buf.split_at_mut(payload_start);
            key.encrypt(self.header.number(), &header_buf, &mut payload, tag_len)
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
    pub fn dst_cid(&self) -> ConnectionId {
        self.header.dst_cid()
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
        self.header.buf_len() + self.payload.buf_len()
    }
}

#[derive(Debug, PartialEq)]
pub enum Header {
    Long {
        ptype: LongType,
        version: u32,
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
        len: u64,
        number: u32,
    },
}

impl Header {
    pub fn ptype(&self) -> Option<LongType> {
        match *self {
            Header::Long { ptype, .. } => Some(ptype),
        }
    }

    fn dst_cid(&self) -> ConnectionId {
        match *self {
            Header::Long { dst_cid, .. } => dst_cid,
        }
    }

    fn number(&self) -> u32 {
        match *self {
            Header::Long { number, .. } => number,
        }
    }
}

impl BufLen for Header {
    fn buf_len(&self) -> usize {
        match *self {
            Header::Long {
                dst_cid,
                src_cid,
                len,
                ..
            } => 10 + (dst_cid.len as usize + src_cid.len as usize) + VarLen(len).buf_len(),
        }
    }
}

impl Codec for Header {
    fn encode<T: BufMut>(&self, buf: &mut T) {
        match *self {
            Header::Long {
                ptype,
                version,
                dst_cid,
                src_cid,
                len,
                number,
            } => {
                buf.put_u8(128 | ptype.to_byte());
                buf.put_u32::<BigEndian>(version);
                buf.put_u8((dst_cid.cil() << 4) | src_cid.cil());
                buf.put_slice(&dst_cid);
                buf.put_slice(&src_cid);
                VarLen(len).encode(buf);
                buf.put_u32::<BigEndian>(number);
            }
        }
    }

    fn decode<T: Buf>(buf: &mut T) -> Self {
        let first = buf.get_u8();
        if first & 128 == 128 {
            let version = buf.get_u32::<BigEndian>();
            let cils = buf.get_u8();

            let (dst_cid, src_cid, used) = {
                let (mut dcil, mut scil) = ((cils >> 4) as usize, (cils & 15) as usize);
                if dcil > 0 {
                    dcil += 3;
                }
                if scil > 0 {
                    scil += 3;
                }

                let bytes = buf.bytes();
                let dst_cid = ConnectionId::new(&bytes[..dcil]);
                let src_cid = ConnectionId::new(&bytes[dcil..dcil + scil]);
                (dst_cid, src_cid, dcil + scil)
            };

            buf.advance(used);
            Header::Long {
                ptype: LongType::from_byte(first ^ 128),
                version,
                dst_cid,
                src_cid,
                len: VarLen::decode(buf).0,
                number: buf.get_u32::<BigEndian>(),
            }
        } else {
            panic!("short headers not implemented yet");
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
