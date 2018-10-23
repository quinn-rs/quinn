use std::{fmt, io, str};

use bytes::{BigEndian, Buf, BufMut, ByteOrder, Bytes, BytesMut};
use rand::Rng;
use slog;

use coding::{self, BufExt, BufMutExt};
use {LOCAL_ID_LEN, MAX_CID_SIZE, MIN_CID_SIZE, VERSION};

// Due to packet number encryption, it is impossible to fully decode a header
// (which includes a variable-length packet number) without crypto context.
// The crypto context (represented by the `Crypto` type in Quinn) is usually
// part of the `Connection`, or can be derived from the destination CID for
// Initial packets.
//
// To cope with this, we decode the invariant header (which should be stable
// across QUIC versions), which gives us the destination CID and allows us
// to inspect the version and packet type (which depends on the version).
// This information allows us to fully decode and decrypt the packet.
pub struct PartialDecode {
    invariant_header: InvariantHeader,
    buf: io::Cursor<BytesMut>,
}

impl PartialDecode {
    pub fn new(bytes: BytesMut) -> Result<Self, PacketDecodeError> {
        let mut buf = io::Cursor::new(bytes);
        let invariant_header = InvariantHeader::decode(&mut buf)?;
        Ok(Self {
            invariant_header,
            buf,
        })
    }

    pub fn has_long_header(&self) -> bool {
        use self::InvariantHeader::*;
        match self.invariant_header {
            Long { .. } => true,
            Short { .. } => false,
        }
    }

    pub fn is_initial(&self) -> bool {
        use self::InvariantHeader::*;
        match self.invariant_header {
            Long {
                version: VERSION,
                first,
                ..
            } => LongType::from_byte(first) == Ok(LongType::Initial),
            Long { .. } | Short { .. } => false,
        }
    }

    pub fn dst_cid(&self) -> ConnectionId {
        self.invariant_header.dst_cid()
    }

    pub fn finish(self) -> Result<(Packet, Option<BytesMut>), PacketDecodeError> {
        let Self {
            invariant_header,
            mut buf,
        } = self;
        let (header_len, payload_len, header, allow_coalesced) = match invariant_header {
            InvariantHeader::Short { first, dst_cid } => {
                let key_phase = first & KEY_PHASE_BIT != 0;
                let number = match first & 0b11 {
                    0x0 => PacketNumber::U8(buf.get()?),
                    0x1 => PacketNumber::U16(buf.get()?),
                    0x2 => PacketNumber::U32(buf.get()?),
                    _ => {
                        return Err(PacketDecodeError::InvalidHeader("unknown packet type"));
                    }
                };
                (
                    buf.position() as usize,
                    buf.remaining(),
                    Header::Short {
                        dst_cid,
                        number,
                        key_phase,
                    },
                    false,
                )
            }
            InvariantHeader::Long {
                first,
                version,
                dst_cid,
                src_cid,
            } => {
                if version == 0 {
                    (
                        buf.position() as usize,
                        buf.remaining(),
                        Header::VersionNegotiate { src_cid, dst_cid },
                        false,
                    )
                } else {
                    debug_assert_eq!(version, VERSION);
                    let ty = LongType::from_byte(first)?;
                    if let LongType::Retry = ty {
                        let odcil = buf.get::<u8>()? as usize;
                        let mut odci_stage = [0; 18];
                        buf.copy_to_slice(&mut odci_stage[0..odcil]);
                        let orig_dst_cid = ConnectionId::new(&odci_stage[..odcil]);
                        (
                            buf.position() as usize,
                            buf.remaining(),
                            Header::Retry {
                                src_cid,
                                dst_cid,
                                orig_dst_cid,
                            },
                            false,
                        )
                    } else {
                        let len = buf.get_var()?;
                        let number = buf.get()?;
                        let header_len = buf.position() as usize;
                        if len > buf.remaining() as u64 {
                            return Err(PacketDecodeError::InvalidHeader(
                                "payload longer than packet",
                            ));
                        }
                        (
                            header_len,
                            len as usize,
                            Header::Long {
                                ty,
                                src_cid,
                                dst_cid,
                                number,
                            },
                            true,
                        )
                    }
                }
            }
        };

        let mut bytes = buf.into_inner();
        let header_data = bytes.split_to(header_len).freeze();
        let payload = bytes.split_to(payload_len);
        Ok((
            Packet {
                header,
                header_data,
                payload,
            },
            if allow_coalesced { Some(bytes) } else { None },
        ))
    }
}

pub struct Packet {
    pub header: Header,
    pub header_data: Bytes,
    pub payload: BytesMut,
}

#[derive(Debug, Clone)]
pub enum Header {
    Long {
        ty: LongType,
        src_cid: ConnectionId,
        dst_cid: ConnectionId,
        number: u32,
    },
    Retry {
        src_cid: ConnectionId,
        dst_cid: ConnectionId,
        orig_dst_cid: ConnectionId,
    },
    Short {
        dst_cid: ConnectionId,
        number: PacketNumber,
        key_phase: bool,
    },
    VersionNegotiate {
        src_cid: ConnectionId,
        dst_cid: ConnectionId,
    },
}

impl Header {
    pub fn encode<W: BufMut>(&self, w: &mut W) {
        use self::Header::*;
        match *self {
            Long {
                ty,
                ref src_cid,
                ref dst_cid,
                number,
            } => {
                w.write(u8::from(ty));
                w.write(VERSION);
                Self::encode_cids(w, dst_cid, src_cid);
                w.write::<u16>(0); // Placeholder for payload length; see `set_payload_length`
                w.write(number);
            }
            Retry {
                ref src_cid,
                ref dst_cid,
                ref orig_dst_cid,
            } => {
                w.write(u8::from(LongType::Retry));
                w.write(VERSION);
                Self::encode_cids(w, dst_cid, src_cid);
                w.write(orig_dst_cid.len() as u8);
                w.put_slice(orig_dst_cid);
            }
            Short {
                ref dst_cid,
                number,
                key_phase,
            } => {
                let ty = number.ty() | 0x30 | if key_phase { KEY_PHASE_BIT } else { 0 };
                w.write(ty);
                w.put_slice(dst_cid);
                number.encode(w);
            }
            VersionNegotiate {
                ref src_cid,
                ref dst_cid,
            } => {
                w.write(0x80u8);
                w.write::<u32>(0);
                Self::encode_cids(w, dst_cid, src_cid);
            }
        }
    }

    fn encode_cids<W: BufMut>(w: &mut W, dst_cid: &ConnectionId, src_cid: &ConnectionId) {
        let mut dcil = dst_cid.len() as u8;
        if dcil > 0 {
            dcil -= 3;
        }
        let mut scil = src_cid.len() as u8;
        if scil > 0 {
            scil -= 3;
        }
        w.write(dcil << 4 | scil);
        w.put_slice(dst_cid);
        w.put_slice(src_cid);
    }
}

pub enum InvariantHeader {
    Long {
        first: u8,
        version: u32,
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
    },
    Short {
        first: u8,
        dst_cid: ConnectionId,
    },
}

impl InvariantHeader {
    fn dst_cid(&self) -> ConnectionId {
        use self::InvariantHeader::*;
        match self {
            Long { dst_cid, .. } => *dst_cid,
            Short { dst_cid, .. } => *dst_cid,
        }
    }

    fn decode<R: Buf>(buf: &mut R) -> Result<Self, PacketDecodeError> {
        let first = buf.get::<u8>()?;
        let mut cid_stage = [0; MAX_CID_SIZE];

        if first & LONG_HEADER_FORM == 0 {
            if buf.remaining() < LOCAL_ID_LEN {
                return Err(PacketDecodeError::InvalidHeader(
                    "destination connection ID longer than packet",
                ));
            }
            buf.copy_to_slice(&mut cid_stage[..LOCAL_ID_LEN]);
            let dst_cid = ConnectionId::new(&cid_stage[..LOCAL_ID_LEN]);
            Ok(InvariantHeader::Short { first, dst_cid })
        } else {
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
                return Err(PacketDecodeError::InvalidHeader(
                    "connection IDs longer than packet",
                ));
            }

            buf.copy_to_slice(&mut cid_stage[0..dcil as usize]);
            let dst_cid = ConnectionId::new(&cid_stage[..dcil as usize]);
            buf.copy_to_slice(&mut cid_stage[0..scil as usize]);
            let src_cid = ConnectionId::new(&cid_stage[..scil as usize]);

            if version > 0 && version != VERSION {
                return Err(PacketDecodeError::UnsupportedVersion {
                    source: src_cid,
                    destination: dst_cid,
                });
            }

            Ok(InvariantHeader::Long {
                first,
                version,
                dst_cid,
                src_cid,
            })
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

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum LongType {
    Initial,
    Retry,
    Handshake,
    ZeroRtt,
}

impl LongType {
    fn from_byte(b: u8) -> Result<Self, PacketDecodeError> {
        use self::LongType::*;
        debug_assert_eq!(b & LONG_HEADER_FORM, LONG_HEADER_FORM);
        match b ^ LONG_HEADER_FORM {
            0x7f => Ok(Initial),
            0x7e => Ok(Retry),
            0x7d => Ok(Handshake),
            0x7c => Ok(ZeroRtt),
            _ => Err(PacketDecodeError::InvalidLongHeaderType(b)),
        }
    }
}

impl From<LongType> for u8 {
    fn from(ty: LongType) -> u8 {
        use self::LongType::*;
        LONG_HEADER_FORM | match ty {
            Initial => 0x7f,
            Retry => 0x7e,
            Handshake => 0x7d,
            ZeroRtt => 0x7c,
        }
    }
}

impl slog::Value for LongType {
    fn serialize(
        &self,
        _: &slog::Record,
        key: slog::Key,
        serializer: &mut slog::Serializer,
    ) -> slog::Result {
        serializer.emit_arguments(key, &format_args!("{:?}", self))
    }
}

#[derive(Debug, Fail, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum PacketDecodeError {
    #[fail(display = "unsupported version")]
    UnsupportedVersion {
        source: ConnectionId,
        destination: ConnectionId,
    },
    #[fail(display = "invalid header: {}", _0)]
    InvalidHeader(&'static str),
    #[fail(display = "invalid long header type: {:02x}", _0)]
    InvalidLongHeaderType(u8),
}

impl From<coding::UnexpectedEnd> for PacketDecodeError {
    fn from(_: coding::UnexpectedEnd) -> Self {
        PacketDecodeError::InvalidHeader("unexpected end of packet")
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
const LONG_HEADER_FORM: u8 = 0x80;
const KEY_PHASE_BIT: u8 = 0x40;
