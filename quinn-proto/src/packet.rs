use std::{fmt, io, str};

use bytes::{BigEndian, Buf, BufMut, ByteOrder, Bytes, BytesMut};
use rand::Rng;
use slog;

use coding::{self, BufExt, BufMutExt};
use {MAX_CID_SIZE, MIN_CID_SIZE, VERSION};

pub struct Packet {
    pub header: Header,
    pub header_data: Bytes,
    pub payload: BytesMut,
}

impl Packet {
    pub fn decode(
        mut packet: BytesMut,
        dest_id_len: usize,
    ) -> Result<(Self, BytesMut), HeaderError> {
        let (header_len, payload_len, header) = Header::decode(&mut packet, dest_id_len)?;
        let header_data = packet.split_to(header_len).freeze();
        let payload = packet.split_to(payload_len);
        Ok((
            Packet {
                header,
                header_data,
                payload,
            },
            packet,
        ))
    }
}

#[derive(Debug, Clone)]
pub enum Header {
    Long {
        ty: u8,
        source_id: ConnectionId,
        destination_id: ConnectionId,
        number: u32,
    },
    Short {
        id: ConnectionId,
        number: PacketNumber,
        key_phase: bool,
    },
    VersionNegotiate {
        ty: u8,
        source_id: ConnectionId,
        destination_id: ConnectionId,
    },
}

impl Header {
    pub fn destination_id(&self) -> ConnectionId {
        use self::Header::*;
        match self {
            Long { destination_id, .. } => *destination_id,
            Short { id, .. } => *id,
            VersionNegotiate { destination_id, .. } => *destination_id,
        }
    }

    pub fn key_phase(&self) -> bool {
        match *self {
            Header::Short { key_phase, .. } => key_phase,
            _ => false,
        }
    }

    fn decode(
        packet: &mut BytesMut,
        dest_id_len: usize,
    ) -> Result<(usize, usize, Self), HeaderError> {
        let mut buf = io::Cursor::new(&packet[..]);
        let ty = buf.get::<u8>()?;
        let long = ty & 0x80 != 0;
        let ty = ty & !0x80;
        let mut cid_stage = [0; MAX_CID_SIZE];
        if long {
            let version = buf.get::<u32>()?;
            let ci_lengths = buf.get::<u8>()?;
            let mut dcil = ci_lengths >> 4;
            if dcil > 0 {
                dcil += 3
            };
            let mut scil = ci_lengths & 0xF;
            if scil > 0 {
                scil += 3
            };
            if buf.remaining() < (dcil + scil) as usize {
                return Err(HeaderError::InvalidHeader(
                    "connection IDs longer than packet",
                ));
            }
            buf.copy_to_slice(&mut cid_stage[0..dcil as usize]);
            let destination_id = ConnectionId::new(&cid_stage[..dcil as usize]);
            buf.copy_to_slice(&mut cid_stage[0..scil as usize]);
            let source_id = ConnectionId::new(&cid_stage[..scil as usize]);
            match version {
                0 => Ok((
                    buf.position() as usize,
                    packet.len() - buf.position() as usize,
                    Header::VersionNegotiate {
                        ty,
                        source_id,
                        destination_id,
                    },
                )),
                VERSION => {
                    let len = buf.get_var()?;
                    let number = buf.get()?;
                    let header_len = buf.position() as usize;
                    if buf.position() + len > packet.len() as u64 {
                        return Err(HeaderError::InvalidHeader("payload longer than packet"));
                    }
                    Ok((
                        header_len,
                        len as usize,
                        Header::Long {
                            ty,
                            source_id,
                            destination_id,
                            number,
                        },
                    ))
                }
                _ => {
                    return Err(HeaderError::UnsupportedVersion {
                        source: source_id,
                        destination: destination_id,
                    })
                }
            }
        } else {
            if buf.remaining() < dest_id_len {
                return Err(HeaderError::InvalidHeader(
                    "destination connection ID longer than packet",
                ));
            }
            buf.copy_to_slice(&mut cid_stage[..dest_id_len]);
            let id = ConnectionId::new(&cid_stage[..dest_id_len]);
            let key_phase = ty & KEY_PHASE_BIT != 0;
            let number = match ty & 0b11 {
                0x0 => PacketNumber::U8(buf.get()?),
                0x1 => PacketNumber::U16(buf.get()?),
                0x2 => PacketNumber::U32(buf.get()?),
                _ => {
                    return Err(HeaderError::InvalidHeader("unknown packet type"));
                }
            };
            Ok((
                buf.position() as usize,
                packet.len() - buf.position() as usize,
                Header::Short {
                    id,
                    number,
                    key_phase,
                },
            ))
        }
    }

    pub fn encode<W: BufMut>(&self, w: &mut W) {
        use self::Header::*;
        match *self {
            Long {
                ty,
                ref source_id,
                ref destination_id,
                number,
            } => {
                w.write(0b1000_0000 | ty);
                w.write(VERSION);
                let mut dcil = destination_id.len() as u8;
                if dcil > 0 {
                    dcil -= 3;
                }
                let mut scil = source_id.len() as u8;
                if scil > 0 {
                    scil -= 3;
                }
                w.write(dcil << 4 | scil);
                w.put_slice(destination_id);
                w.put_slice(source_id);
                w.write::<u16>(0); // Placeholder for payload length; see `set_payload_length`
                w.write(number);
            }
            Short {
                ref id,
                number,
                key_phase,
            } => {
                let ty = number.ty() | 0x30 | if key_phase { KEY_PHASE_BIT } else { 0 };
                w.write(ty);
                w.put_slice(id);
                number.encode(w);
            }
            VersionNegotiate {
                ty,
                ref source_id,
                ref destination_id,
            } => {
                w.write(0x80 | ty);
                w.write::<u32>(0);
                let mut dcil = destination_id.len() as u8;
                if dcil > 0 {
                    dcil -= 3;
                }
                let mut scil = source_id.len() as u8;
                if scil > 0 {
                    scil -= 3;
                }
                w.write(dcil << 4 | scil);
                w.put_slice(destination_id);
                w.put_slice(source_id);
            }
        }
    }
}

// An encoded packet number
#[derive(Debug, Copy, Clone)]
pub enum PacketNumber {
    U8(u8),
    U16(u16),
    U32(u32),
}

impl PacketNumber {
    pub fn new(n: u64, largest_acked: u64) -> Self {
        if largest_acked == 0 {
            return PacketNumber::U32(n as u32);
        }
        let range = (n - largest_acked) / 2;
        if range < 1 << 8 {
            PacketNumber::U8(n as u8)
        } else if range < 1 << 16 {
            PacketNumber::U16(n as u16)
        } else if range < 1 << 32 {
            PacketNumber::U32(n as u32)
        } else {
            panic!("packet number too large to encode")
        }
    }

    fn ty(self) -> u8 {
        use self::PacketNumber::*;
        match self {
            U8(_) => 0x00,
            U16(_) => 0x01,
            U32(_) => 0x02,
        }
    }

    pub fn encode<W: BufMut>(self, w: &mut W) {
        use self::PacketNumber::*;
        match self {
            U8(x) => w.write(x),
            U16(x) => w.write(x),
            U32(x) => w.write(x),
        }
    }

    pub fn expand(self, prev: u64) -> u64 {
        use self::PacketNumber::*;
        let t = prev + 1;
        // Compute missing bits that minimize the difference from expected
        let d = match self {
            U8(_) => 1 << 8,
            U16(_) => 1 << 16,
            U32(_) => 1 << 32,
        };
        let x = match self {
            U8(x) => x as u64,
            U16(x) => x as u64,
            U32(x) => x as u64,
        };
        if t > d / 2 {
            x + d * ((t + d / 2 - x) / d)
        } else {
            x % d
        }
    }
}

#[derive(Debug, Fail, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum HeaderError {
    #[fail(display = "unsupported version")]
    UnsupportedVersion {
        source: ConnectionId,
        destination: ConnectionId,
    },
    #[fail(display = "invalid header: {}", _0)]
    InvalidHeader(&'static str),
}

impl From<coding::UnexpectedEnd> for HeaderError {
    fn from(_: coding::UnexpectedEnd) -> Self {
        HeaderError::InvalidHeader("unexpected end of packet")
    }
}

/// Protocol-level identifier for a connection.
///
/// Mainly useful for identifying this connection's packets on the wire with tools like Wireshark.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ConnectionId {
    pub len: u8,
    pub bytes: [u8; MAX_CID_SIZE],
}

impl ConnectionId {
    pub fn new(bytes: &[u8]) -> Self {
        debug_assert!(
            bytes.is_empty() || (bytes.len() >= MIN_CID_SIZE && bytes.len() <= MAX_CID_SIZE)
        );
        let mut res = Self {
            len: bytes.len() as u8,
            bytes: [0; MAX_CID_SIZE],
        };
        res.bytes[..bytes.len()].clone_from_slice(&bytes);
        res
    }

    pub fn random<R: Rng>(rng: &mut R, len: u8) -> Self {
        debug_assert!(len as usize <= MAX_CID_SIZE);
        let mut res = Self {
            len: len as u8,
            bytes: [0; MAX_CID_SIZE],
        };
        let mut rng_bytes = [0; MAX_CID_SIZE];
        rng.fill_bytes(&mut rng_bytes);
        res.bytes[..len as usize].clone_from_slice(&rng_bytes[..len as usize]);
        res
    }
}

impl ::std::ops::Deref for ConnectionId {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes[0..self.len as usize]
    }
}

impl ::std::ops::DerefMut for ConnectionId {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[0..self.len as usize]
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.iter() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl slog::Value for ConnectionId {
    fn serialize(
        &self,
        _: &slog::Record,
        key: slog::Key,
        serializer: &mut slog::Serializer,
    ) -> slog::Result {
        serializer.emit_arguments(key, &format_args!("{}", self))
    }
}

pub fn set_payload_length(packet: &mut [u8], header_len: usize) {
    let len = packet.len() - header_len + AEAD_TAG_SIZE;
    assert!(len < 2usize.pow(14)); // Fits in reserved space
    BigEndian::write_u16(&mut packet[header_len - 6..], len as u16 | 0b01 << 14);
}

pub const AEAD_TAG_SIZE: usize = 16;
const KEY_PHASE_BIT: u8 = 0x40;

pub mod types {
    pub const INITIAL: u8 = 0x7F;
    pub const RETRY: u8 = 0x7E;
    //pub const ZERO_RTT: u8 = 0x7C;
    pub const HANDSHAKE: u8 = 0x7D;
}
