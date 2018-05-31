use bytes::{Buf, BufMut};

use super::QuicResult;
use codec::{BufLen, Codec, VarLen};
use frame::Frame;
use types::{ConnectionId, GENERATED_CID_LENGTH};

use rand::{thread_rng, Rng};

use std::io::Cursor;

#[derive(Debug, PartialEq)]
pub struct Packet {
    pub header: Header,
    pub payload: Vec<Frame>,
}

impl Packet {
    pub fn start_decode(buf: &mut [u8]) -> QuicResult<PartialDecode> {
        let (header, header_len) = {
            let mut read = Cursor::new(&buf);
            let header = Header::decode(&mut read)?;
            (header, read.position() as usize)
        };
        Ok(PartialDecode {
            header,
            header_len,
            buf,
        })
    }
}

pub struct PartialDecode<'a> {
    pub header: Header,
    pub header_len: usize,
    pub buf: &'a mut [u8],
}

impl<'a> PartialDecode<'a> {
    pub fn dst_cid(&self) -> ConnectionId {
        self.header.dst_cid()
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
    Short {
        key_phase: bool,
        ptype: ShortType,
        dst_cid: ConnectionId,
        number: u32,
    },
    Negotiation {
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
        supported_versions: Vec<u32>,
    },
}

impl Header {
    pub fn ptype(&self) -> Option<LongType> {
        match *self {
            Header::Long { ptype, .. } => Some(ptype),
            Header::Short { .. } => None,
            Header::Negotiation { .. } => None,
        }
    }

    fn dst_cid(&self) -> ConnectionId {
        match *self {
            Header::Long { dst_cid, .. } => dst_cid,
            Header::Short { dst_cid, .. } => dst_cid,
            Header::Negotiation { dst_cid, .. } => dst_cid,
        }
    }
}

impl BufLen for Header {
    fn buf_len(&self) -> usize {
        match self {
            Header::Long {
                dst_cid,
                src_cid,
                len,
                ..
            } => 10 + (dst_cid.len as usize + src_cid.len as usize) + VarLen(*len).buf_len(),
            Header::Short { ptype, dst_cid, .. } => 1 + (dst_cid.len as usize) + ptype.buf_len(),
            Header::Negotiation {
                dst_cid,
                src_cid,
                supported_versions,
            } => 6 + (dst_cid.len as usize + src_cid.len as usize) + 4 * supported_versions.len(),
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
                buf.put_u32_be(version);
                buf.put_u8((dst_cid.cil() << 4) | src_cid.cil());
                buf.put_slice(&dst_cid);
                buf.put_slice(&src_cid);
                VarLen(len).encode(buf);
                buf.put_u32_be(number);
            }
            Header::Short {
                key_phase,
                ptype,
                dst_cid,
                number,
            } => {
                let key_phase_bit = if key_phase { 0x40 } else { 0 };
                buf.put_u8(key_phase_bit | 0x20 | 0x10 | ptype.to_byte());
                buf.put_slice(&dst_cid);
                debug_assert_eq!(ptype, ShortType::Two);
                buf.put_u16_be(number as u16);
            }
            Header::Negotiation {
                dst_cid,
                src_cid,
                ref supported_versions,
            } => {
                buf.put_u8(thread_rng().gen::<u8>() | 128);
                buf.put_u32_be(0);
                buf.put_u8((dst_cid.cil() << 4) | src_cid.cil());
                buf.put_slice(&dst_cid);
                buf.put_slice(&src_cid);
                for v in supported_versions {
                    buf.put_u32_be(*v);
                }
            }
        }
    }

    fn decode<T: Buf>(buf: &mut T) -> QuicResult<Self> {
        let first = buf.get_u8();
        if first & 128 == 128 {
            let version = buf.get_u32_be();
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
            if version == 0 {
                let mut supported_versions = vec![];
                while buf.has_remaining() {
                    supported_versions.push(buf.get_u32_be());
                }
                Ok(Header::Negotiation {
                    dst_cid,
                    src_cid,
                    supported_versions,
                })
            } else {
                Ok(Header::Long {
                    ptype: LongType::from_byte(first ^ 128),
                    version,
                    dst_cid,
                    src_cid,
                    len: VarLen::decode(buf)?.0,
                    number: buf.get_u32_be(),
                })
            }
        } else {
            let key_phase = first & 0x40 == 0x40;
            let dst_cid = {
                let bytes = buf.bytes();
                ConnectionId::new(&bytes[..GENERATED_CID_LENGTH as usize])
            };
            buf.advance(GENERATED_CID_LENGTH as usize);

            let ptype = ShortType::from_byte(first & 3);
            let number = match ptype {
                ShortType::One => u32::from(buf.get_u8()),
                ShortType::Two => u32::from(buf.get_u16_be()),
                ShortType::Four => buf.get_u32_be(),
            };

            Ok(Header::Short {
                key_phase,
                ptype,
                dst_cid,
                number,
            })
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
        match self {
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
        match self {
            One => 1,
            Two => 2,
            Four => 4,
        }
    }
}

impl ShortType {
    pub fn to_byte(&self) -> u8 {
        use self::ShortType::*;
        match self {
            One => 0,
            Two => 1,
            Four => 2,
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
