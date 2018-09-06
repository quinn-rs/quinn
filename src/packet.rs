use std::{fmt, io, str};

use arrayvec::ArrayVec;
use bytes::{Buf, BufMut, Bytes};
use rand::Rng;
use slog;

use coding::{self, BufExt, BufMutExt};
use {MAX_CID_SIZE, VERSION};

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
    pub fn destination_id(&self) -> &ConnectionId {
        use self::Header::*;
        match *self {
            Long {
                ref destination_id, ..
            } => destination_id,
            Short { ref id, .. } => id,
            VersionNegotiate {
                ref destination_id, ..
            } => destination_id,
        }
    }

    pub fn key_phase(&self) -> bool {
        match *self {
            Header::Short { key_phase, .. } => key_phase,
            _ => false,
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

    fn ty(&self) -> u8 {
        use self::PacketNumber::*;
        match *self {
            U8(_) => 0x00,
            U16(_) => 0x01,
            U32(_) => 0x02,
        }
    }

    pub fn encode<W: BufMut>(&self, w: &mut W) {
        use self::PacketNumber::*;
        match *self {
            U8(x) => w.write(x),
            U16(x) => w.write(x),
            U32(x) => w.write(x),
        }
    }

    pub fn expand(&self, prev: u64) -> u64 {
        use self::PacketNumber::*;
        let t = prev + 1;
        // Compute missing bits that minimize the difference from expected
        let d = match *self {
            U8(_) => 1 << 8,
            U16(_) => 1 << 16,
            U32(_) => 1 << 32,
        };
        let x = match *self {
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

const KEY_PHASE_BIT: u8 = 0x40;

impl Header {
    pub fn encode<W: BufMut>(&self, w: &mut W) {
        use self::Header::*;
        match *self {
            Long {
                ty,
                ref source_id,
                ref destination_id,
                number,
            } => {
                w.write(0b10000000 | ty);
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

pub struct Packet {
    pub header: Header,
    pub header_data: Bytes,
    pub payload: Bytes,
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

impl Packet {
    pub fn decode(packet: &Bytes, dest_id_len: usize) -> Result<(Self, Bytes), HeaderError> {
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
            let destination_id = ConnectionId::new(cid_stage, dcil as usize);
            buf.copy_to_slice(&mut cid_stage[0..scil as usize]);
            let source_id = ConnectionId::new(cid_stage, scil as usize);
            Ok(match version {
                0 => {
                    let header_data = packet.slice(0, buf.position() as usize);
                    let payload = packet.slice(buf.position() as usize, packet.len());
                    (
                        Packet {
                            header: Header::VersionNegotiate {
                                ty,
                                source_id,
                                destination_id,
                            },
                            header_data,
                            payload,
                        },
                        Bytes::new(),
                    )
                }
                VERSION => {
                    let len = buf.get_var()?;
                    let number = buf.get()?;
                    let header_data = packet.slice(0, buf.position() as usize);
                    if buf.position() + len > packet.len() as u64 {
                        return Err(HeaderError::InvalidHeader("payload longer than packet"));
                    }
                    let payload = if len == 0 {
                        Bytes::new()
                    } else {
                        packet.slice(buf.position() as usize, (buf.position() + len) as usize)
                    };
                    (
                        Packet {
                            header: Header::Long {
                                ty,
                                source_id,
                                destination_id,
                                number,
                            },
                            header_data,
                            payload,
                        },
                        packet.slice((buf.position() + len) as usize, packet.len()),
                    )
                }
                _ => {
                    return Err(HeaderError::UnsupportedVersion {
                        source: source_id,
                        destination: destination_id,
                    })
                }
            })
        } else {
            if buf.remaining() < dest_id_len {
                return Err(HeaderError::InvalidHeader(
                    "destination connection ID longer than packet",
                ));
            }
            buf.copy_to_slice(&mut cid_stage[0..dest_id_len]);
            let id = ConnectionId::new(cid_stage, dest_id_len);
            let key_phase = ty & KEY_PHASE_BIT != 0;
            let number = match ty & 0b11 {
                0x0 => PacketNumber::U8(buf.get()?),
                0x1 => PacketNumber::U16(buf.get()?),
                0x2 => PacketNumber::U32(buf.get()?),
                _ => {
                    return Err(HeaderError::InvalidHeader("unknown packet type"));
                }
            };
            let header_data = packet.slice(0, buf.position() as usize);
            let payload = packet.slice(buf.position() as usize, packet.len());
            Ok((
                Packet {
                    header: Header::Short {
                        id,
                        number,
                        key_phase,
                    },
                    header_data,
                    payload,
                },
                Bytes::new(),
            ))
        }
    }
}

/// Protocol-level identifier for a connection.
///
/// Mainly useful for identifying this connection's packets on the wire with tools like Wireshark.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ConnectionId(pub(crate) ArrayVec<[u8; MAX_CID_SIZE]>);

impl ::std::ops::Deref for ConnectionId {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl ::std::ops::DerefMut for ConnectionId {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl ConnectionId {
    pub fn new(data: [u8; MAX_CID_SIZE], len: usize) -> Self {
        let mut x = ConnectionId(data.into());
        x.0.truncate(len);
        x
    }

    pub fn random<R: Rng>(rng: &mut R, len: u8) -> Self {
        debug_assert!(len as usize <= MAX_CID_SIZE);
        let mut v = ArrayVec::from([0; MAX_CID_SIZE]);
        rng.fill_bytes(&mut v[0..len as usize]);
        v.truncate(len as usize);
        ConnectionId(v)
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in &self.0 {
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

pub mod types {
    pub const INITIAL: u8 = 0x7F;
    pub const RETRY: u8 = 0x7E;
    pub const ZERO_RTT: u8 = 0x7C;
    pub const HANDSHAKE: u8 = 0x7D;
}
