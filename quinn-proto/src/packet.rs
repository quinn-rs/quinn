use std::{cmp::Ordering, fmt, io, ops::Range, str};

use bytes::{BigEndian, Buf, BufMut, ByteOrder, Bytes, BytesMut};
use err_derive::Error;
use rand::Rng;
use slog;

use crate::coding::{self, BufExt, BufMutExt};
use crate::crypto::{HeaderCrypto, RingHeaderCrypto};
use crate::varint;
use crate::{MAX_CID_SIZE, MIN_CID_SIZE, VERSION};

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
    plain_header: PlainHeader,
    buf: io::Cursor<BytesMut>,
}

impl PartialDecode {
    pub fn new(
        bytes: BytesMut,
        local_cid_len: usize,
    ) -> Result<(Self, Option<BytesMut>), PacketDecodeError> {
        let mut buf = io::Cursor::new(bytes);
        let plain_header = PlainHeader::decode(&mut buf, local_cid_len)?;
        let dgram_len = buf.get_ref().len();
        let packet_len = plain_header
            .payload_len()
            .map(|len| (buf.position() + len) as usize)
            .unwrap_or(dgram_len);
        match dgram_len.cmp(&packet_len) {
            Ordering::Equal => Ok((Self { plain_header, buf }, None)),
            Ordering::Less => Err(PacketDecodeError::InvalidHeader(
                "packet too short to contain payload length",
            )),
            Ordering::Greater => {
                let rest = Some(buf.get_mut().split_off(packet_len));
                Ok((Self { plain_header, buf }, rest))
            }
        }
    }

    pub fn has_long_header(&self) -> bool {
        use self::PlainHeader::*;
        match self.plain_header {
            Short { .. } => false,
            _ => true,
        }
    }

    pub fn is_initial(&self) -> bool {
        self.space() == Some(SpaceId::Initial)
    }

    pub fn space(&self) -> Option<SpaceId> {
        use self::PlainHeader::*;
        match self.plain_header {
            Initial { .. } => Some(SpaceId::Initial),
            Long {
                ty: LongType::Handshake,
                ..
            } => Some(SpaceId::Handshake),
            Long {
                ty: LongType::ZeroRtt,
                ..
            } => Some(SpaceId::Data),
            Short { .. } => Some(SpaceId::Data),
            _ => None,
        }
    }

    pub fn is_0rtt(&self) -> bool {
        match self.plain_header {
            PlainHeader::Long { ty, .. } => ty == LongType::ZeroRtt,
            _ => false,
        }
    }

    pub fn dst_cid(&self) -> ConnectionId {
        self.plain_header.dst_cid()
    }

    /// Length of data being decoded
    ///
    /// May account for multiple packets.
    pub fn len(&self) -> usize {
        self.buf.get_ref().len()
    }

    pub fn finish(
        self,
        header_crypto: Option<&RingHeaderCrypto>,
    ) -> Result<Packet, PacketDecodeError> {
        use self::PlainHeader::*;
        let Self {
            plain_header,
            mut buf,
        } = self;

        if let Initial {
            dst_cid,
            src_cid,
            token_pos,
            ..
        } = plain_header
        {
            let number = Self::decrypt_header(&mut buf, header_crypto.unwrap())?;
            let header_len = buf.position() as usize;
            let mut bytes = buf.into_inner();

            let header_data = bytes.split_to(header_len).freeze();
            let token = header_data.slice(token_pos.start, token_pos.end);
            return Ok(Packet {
                header: Header::Initial {
                    dst_cid,
                    src_cid,
                    token,
                    number,
                },
                header_data,
                payload: bytes,
            });
        }

        let header = match plain_header {
            Long {
                ty,
                dst_cid,
                src_cid,
                ..
            } => Header::Long {
                ty,
                dst_cid,
                src_cid,
                number: Self::decrypt_header(&mut buf, header_crypto.unwrap())?,
            },
            Retry {
                dst_cid,
                src_cid,
                orig_dst_cid,
            } => Header::Retry {
                dst_cid,
                src_cid,
                orig_dst_cid,
            },
            Short { spin, dst_cid, .. } => {
                let number = Self::decrypt_header(&mut buf, header_crypto.unwrap())?;
                let key_phase = buf.get_ref()[0] & KEY_PHASE_BIT != 0;
                Header::Short {
                    spin,
                    key_phase,
                    dst_cid,
                    number,
                }
            }
            VersionNegotiate {
                random,
                dst_cid,
                src_cid,
            } => Header::VersionNegotiate {
                random,
                dst_cid,
                src_cid,
            },
            Initial { .. } => unreachable!(),
        };

        let header_len = buf.position() as usize;
        let mut bytes = buf.into_inner();
        Ok(Packet {
            header,
            header_data: bytes.split_to(header_len).freeze(),
            payload: bytes,
        })
    }

    fn decrypt_header(
        buf: &mut io::Cursor<BytesMut>,
        header_crypto: &RingHeaderCrypto,
    ) -> Result<PacketNumber, PacketDecodeError> {
        let packet_length = buf.get_ref().len();
        let pn_offset = buf.position() as usize;
        if packet_length < pn_offset + 4 + header_crypto.sample_size() {
            return Err(PacketDecodeError::InvalidHeader(
                "packet too short to extract header protection sample",
            ));
        }

        header_crypto.decrypt(pn_offset, buf.get_mut());

        let len = PacketNumber::decode_len(buf.get_ref()[0]);
        PacketNumber::decode(len, buf)
    }
}

pub struct Packet {
    pub header: Header,
    pub header_data: Bytes,
    pub payload: BytesMut,
}

#[derive(Debug, Clone)]
pub enum Header {
    Initial {
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
        token: Bytes,
        number: PacketNumber,
    },
    Long {
        ty: LongType,
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
        number: PacketNumber,
    },
    Retry {
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
        orig_dst_cid: ConnectionId,
    },
    Short {
        spin: bool,
        key_phase: bool,
        dst_cid: ConnectionId,
        number: PacketNumber,
    },
    VersionNegotiate {
        random: u8,
        src_cid: ConnectionId,
        dst_cid: ConnectionId,
    },
}

impl Header {
    pub fn encode<W: BufMut>(&self, w: &mut W) -> PartialEncode {
        use self::Header::*;
        match *self {
            Initial {
                ref dst_cid,
                ref src_cid,
                ref token,
                number,
            } => {
                w.write(u8::from(LongHeaderType::Initial) | number.tag());
                w.write(VERSION);
                Self::encode_cids(w, dst_cid, src_cid);
                w.write_var(token.len() as u64);
                w.put_slice(token);
                w.write::<u16>(0); // Placeholder for payload length; see `set_payload_length`
                number.encode(w);
                let pn_pos = 8
                    + dst_cid.len()
                    + src_cid.len()
                    + varint::size(token.len() as u64).unwrap()
                    + token.len();
                PartialEncode { pn: Some(pn_pos) }
            }
            Long {
                ty,
                ref dst_cid,
                ref src_cid,
                number,
            } => {
                w.write(u8::from(LongHeaderType::Standard(ty)) | number.tag());
                w.write(VERSION);
                Self::encode_cids(w, dst_cid, src_cid);
                w.write::<u16>(0); // Placeholder for payload length; see `set_payload_length`
                number.encode(w);
                let pn_pos = 8 + dst_cid.len() + src_cid.len();
                PartialEncode { pn: Some(pn_pos) }
            }
            Retry {
                ref dst_cid,
                ref src_cid,
                ref orig_dst_cid,
            } => {
                let odcil = if orig_dst_cid.len() == 0 {
                    0
                } else {
                    orig_dst_cid.len() as u8 - 3
                };
                w.write(u8::from(LongHeaderType::Retry) | odcil);
                w.write(VERSION);
                Self::encode_cids(w, dst_cid, src_cid);
                w.put_slice(orig_dst_cid);
                PartialEncode { pn: None }
            }
            Short {
                spin,
                key_phase,
                ref dst_cid,
                number,
            } => {
                w.write(
                    FIXED_BIT
                        | if key_phase { KEY_PHASE_BIT } else { 0 }
                        | if spin { SPIN_BIT } else { 0 }
                        | number.tag(),
                );
                w.put_slice(dst_cid);
                number.encode(w);
                PartialEncode {
                    pn: Some(1 + dst_cid.len()),
                }
            }
            VersionNegotiate {
                ref random,
                ref dst_cid,
                ref src_cid,
            } => {
                w.write(0x80u8 | random);
                w.write::<u32>(0);
                Self::encode_cids(w, dst_cid, src_cid);
                PartialEncode { pn: None }
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

    pub fn is_retry(&self) -> bool {
        match *self {
            Header::Retry { .. } => true,
            _ => false,
        }
    }

    pub fn number(&self) -> Option<PacketNumber> {
        use self::Header::*;
        Some(match *self {
            Initial { number, .. } => number,
            Long { number, .. } => number,
            Short { number, .. } => number,
            _ => {
                return None;
            }
        })
    }

    pub fn space(&self) -> SpaceId {
        use self::Header::*;
        match *self {
            Short { .. } => SpaceId::Data,
            Long {
                ty: LongType::ZeroRtt,
                ..
            } => SpaceId::Data,
            Long {
                ty: LongType::Handshake,
                ..
            } => SpaceId::Handshake,
            _ => SpaceId::Initial,
        }
    }

    pub fn key_phase(&self) -> bool {
        match *self {
            Header::Short { key_phase, .. } => key_phase,
            _ => false,
        }
    }

    pub fn is_short(&self) -> bool {
        match *self {
            Header::Short { .. } => true,
            _ => false,
        }
    }

    pub fn is_0rtt(&self) -> bool {
        match *self {
            Header::Long {
                ty: LongType::ZeroRtt,
                ..
            } => true,
            _ => false,
        }
    }

    pub fn dst_cid(&self) -> &ConnectionId {
        use self::Header::*;
        match *self {
            Initial { ref dst_cid, .. } => dst_cid,
            Long { ref dst_cid, .. } => dst_cid,
            Retry { ref dst_cid, .. } => dst_cid,
            Short { ref dst_cid, .. } => dst_cid,
            VersionNegotiate { ref dst_cid, .. } => dst_cid,
        }
    }
}

pub struct PartialEncode {
    pn: Option<usize>,
}

impl PartialEncode {
    pub fn finish(self, buf: &mut [u8], header_crypto: &RingHeaderCrypto) {
        let PartialEncode { pn, .. } = self;
        let pn_pos = if let Some(pn) = pn {
            pn
        } else {
            return;
        };

        debug_assert!(
            pn_pos + 4 + header_crypto.sample_size() <= buf.len(),
            "packet must be padded to at least {} bytes for header protection sampling",
            pn_pos + 4 + header_crypto.sample_size()
        );

        header_crypto.encrypt(pn_pos, buf);
    }
}

pub enum PlainHeader {
    Initial {
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
        token_pos: Range<usize>,
        len: u64,
    },
    Long {
        ty: LongType,
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
        len: u64,
    },
    Retry {
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
        orig_dst_cid: ConnectionId,
    },
    Short {
        first: u8,
        spin: bool,
        dst_cid: ConnectionId,
    },
    VersionNegotiate {
        random: u8,
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
    },
}

impl PlainHeader {
    fn dst_cid(&self) -> ConnectionId {
        use self::PlainHeader::*;
        match self {
            Initial { dst_cid, .. } => *dst_cid,
            Long { dst_cid, .. } => *dst_cid,
            Retry { dst_cid, .. } => *dst_cid,
            Short { dst_cid, .. } => *dst_cid,
            VersionNegotiate { dst_cid, .. } => *dst_cid,
        }
    }

    fn payload_len(&self) -> Option<u64> {
        use self::PlainHeader::*;
        match self {
            Initial { len, .. } | Long { len, .. } => Some(*len),
            _ => None,
        }
    }

    fn decode(
        buf: &mut io::Cursor<BytesMut>,
        local_cid_len: usize,
    ) -> Result<Self, PacketDecodeError> {
        let first = buf.get::<u8>()?;
        if first & LONG_HEADER_FORM == 0 {
            let spin = first & SPIN_BIT != 0;

            if buf.remaining() < local_cid_len {
                return Err(PacketDecodeError::InvalidHeader(
                    "destination connection ID longer than packet",
                ));
            }
            let dst_cid = Self::get_cid(buf, local_cid_len);

            Ok(PlainHeader::Short {
                first,
                spin,
                dst_cid,
            })
        } else {
            let version = buf.get::<u32>()?;
            let ci_lengths = buf.get::<u8>()?;
            let mut dcil = (ci_lengths >> 4) as usize;
            if dcil > 0 {
                dcil += 3
            };
            let mut scil = (ci_lengths & 0xF) as usize;
            if scil > 0 {
                scil += 3
            };
            if buf.remaining() < (dcil + scil) as usize {
                return Err(PacketDecodeError::InvalidHeader(
                    "connection IDs longer than packet",
                ));
            }

            let dst_cid = Self::get_cid(buf, dcil);
            let src_cid = Self::get_cid(buf, scil);

            if version == 0 {
                let random = first & !LONG_HEADER_FORM;
                return Ok(PlainHeader::VersionNegotiate {
                    random,
                    dst_cid,
                    src_cid,
                });
            }

            if version != VERSION {
                return Err(PacketDecodeError::UnsupportedVersion {
                    source: src_cid,
                    destination: dst_cid,
                });
            }

            match LongHeaderType::from_byte(first)? {
                LongHeaderType::Initial => {
                    let token_len = buf.get_var()? as usize;
                    let token_start = buf.position() as usize;
                    buf.advance(token_len);

                    let len = buf.get_var()?;
                    Ok(PlainHeader::Initial {
                        dst_cid,
                        src_cid,
                        token_pos: token_start..token_start + token_len,
                        len,
                    })
                }
                LongHeaderType::Retry => {
                    let odcil = first & 0xf;
                    let odcil = if odcil == 0 { 0 } else { (odcil + 3) as usize };
                    let orig_dst_cid = Self::get_cid(buf, odcil);

                    Ok(PlainHeader::Retry {
                        dst_cid,
                        src_cid,
                        orig_dst_cid,
                    })
                }
                LongHeaderType::Standard(ty) => Ok(PlainHeader::Long {
                    ty,
                    dst_cid,
                    src_cid,
                    len: buf.get_var()?,
                }),
            }
        }
    }

    fn get_cid<R: Buf>(buf: &mut R, len: usize) -> ConnectionId {
        let cid = ConnectionId::new(&buf.bytes()[..len]);
        buf.advance(len);
        cid
    }
}

// An encoded packet number
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PacketNumber {
    U8(u8),
    U16(u16),
    U24(u32),
    U32(u32),
}

impl PacketNumber {
    pub fn new(n: u64, largest_acked: u64) -> Self {
        let range = (n - largest_acked) * 2;
        if range < 1 << 8 {
            PacketNumber::U8(n as u8)
        } else if range < 1 << 16 {
            PacketNumber::U16(n as u16)
        } else if range < 1 << 24 {
            PacketNumber::U24(n as u32)
        } else if range < 1 << 32 {
            PacketNumber::U32(n as u32)
        } else {
            panic!("packet number too large to encode")
        }
    }

    pub fn len(self) -> usize {
        use self::PacketNumber::*;
        match self {
            U8(_) => 1,
            U16(_) => 2,
            U24(_) => 3,
            U32(_) => 4,
        }
    }

    pub fn encode<W: BufMut>(self, w: &mut W) {
        use self::PacketNumber::*;
        match self {
            U8(x) => w.write(x),
            U16(x) => w.write(x),
            U24(x) => w.put_uint_be(x as u64, 3),
            U32(x) => w.write(x),
        }
    }

    pub fn decode<R: Buf>(len: usize, r: &mut R) -> Result<PacketNumber, PacketDecodeError> {
        use self::PacketNumber::*;
        let pn = match len {
            1 => U8(r.get()?),
            2 => U16(r.get()?),
            3 => U24(r.get_uint_be(3) as u32),
            4 => U32(r.get()?),
            _ => unreachable!(),
        };
        Ok(pn)
    }

    pub fn decode_len(tag: u8) -> usize {
        1 + (tag & 0x03) as usize
    }

    fn tag(self) -> u8 {
        use self::PacketNumber::*;
        match self {
            U8(_) => 0b00,
            U16(_) => 0b01,
            U24(_) => 0b10,
            U32(_) => 0b11,
        }
    }

    pub fn expand(self, expected: u64) -> u64 {
        // From Appendix A
        use self::PacketNumber::*;
        let truncated = match self {
            U8(x) => x as u64,
            U16(x) => x as u64,
            U24(x) => x as u64,
            U32(x) => x as u64,
        };
        let nbits = self.len() * 8;
        let win = 1 << nbits;
        let hwin = win / 2;
        let mask = win - 1;
        // The incoming packet number should be greater than expected - hwin and less than or equal
        // to expected + hwin
        //
        // This means we can't just strip the trailing bits from expected and add the truncated
        // because that might yield a value outside the window.
        //
        // The following code calculates a candidate value and makes sure it's within the packet
        // number window.
        let candidate = (expected & !mask) | truncated;
        if expected.checked_sub(hwin).map_or(false, |x| candidate <= x) {
            candidate + win
        } else if candidate > expected + hwin && candidate > win {
            candidate - win
        } else {
            candidate
        }
    }
}

/// Long packet type including non-uniform cases
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LongHeaderType {
    Initial,
    Retry,
    Standard(LongType),
}

impl LongHeaderType {
    fn from_byte(b: u8) -> Result<Self, PacketDecodeError> {
        use self::{LongHeaderType::*, LongType::*};
        if b & FIXED_BIT == 0 {
            return Err(PacketDecodeError::InvalidHeader("fixed bit unset"));
        }
        debug_assert!(b & LONG_HEADER_FORM != 0, "not a long packet");
        Ok(match (b & 0x30) >> 4 {
            0x0 => Initial,
            0x1 => Standard(ZeroRtt),
            0x2 => Standard(Handshake),
            0x3 => Retry,
            _ => unreachable!(),
        })
    }
}

impl From<LongHeaderType> for u8 {
    fn from(ty: LongHeaderType) -> u8 {
        use self::{LongHeaderType::*, LongType::*};
        match ty {
            Initial => LONG_HEADER_FORM | FIXED_BIT,
            Standard(ZeroRtt) => LONG_HEADER_FORM | FIXED_BIT | (0x1 << 4),
            Standard(Handshake) => LONG_HEADER_FORM | FIXED_BIT | (0x2 << 4),
            Retry => LONG_HEADER_FORM | FIXED_BIT | (0x3 << 4),
        }
    }
}

impl slog::Value for LongHeaderType {
    fn serialize(
        &self,
        _: &slog::Record<'_>,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_arguments(key, &format_args!("{:?}", self))
    }
}

/// Long packet types with uniform header structure
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LongType {
    Handshake,
    ZeroRtt,
}

impl slog::Value for LongType {
    fn serialize(
        &self,
        _: &slog::Record<'_>,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_arguments(key, &format_args!("{:?}", self))
    }
}

#[derive(Debug, Error, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum PacketDecodeError {
    #[error(display = "unsupported version")]
    UnsupportedVersion {
        source: ConnectionId,
        destination: ConnectionId,
    },
    #[error(display = "invalid header: {}", _0)]
    InvalidHeader(&'static str),
}

impl From<coding::UnexpectedEnd> for PacketDecodeError {
    fn from(_: coding::UnexpectedEnd) -> Self {
        PacketDecodeError::InvalidHeader("unexpected end of packet")
    }
}

/// Protocol-level identifier for a connection.
///
/// Mainly useful for identifying this connection's packets on the wire with tools like Wireshark.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
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

    pub fn random<R: Rng>(rng: &mut R, len: usize) -> Self {
        debug_assert!(len <= MAX_CID_SIZE);
        let mut res = Self {
            len: len as u8,
            bytes: [0; MAX_CID_SIZE],
        };
        let mut rng_bytes = [0; MAX_CID_SIZE];
        rng.fill_bytes(&mut rng_bytes);
        res.bytes[..len].clone_from_slice(&rng_bytes[..len]);
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

impl fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.bytes[0..self.len as usize].fmt(f)
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.iter() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl slog::Value for ConnectionId {
    fn serialize(
        &self,
        _: &slog::Record<'_>,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_arguments(key, &format_args!("{}", self))
    }
}

pub fn set_payload_length(packet: &mut [u8], header_len: usize, pn_len: usize, tag_len: usize) {
    let len = packet.len() - header_len + pn_len + tag_len;
    assert!(len < 2usize.pow(14)); // Fits in reserved space
    BigEndian::write_u16(
        &mut packet[header_len - pn_len - 2..],
        len as u16 | 0b01 << 14,
    );
}

pub const LONG_HEADER_FORM: u8 = 0x80;
const FIXED_BIT: u8 = 0x40;
pub const SPIN_BIT: u8 = 0x20;
pub const SHORT_RESERVED_BITS: u8 = 0x18;
pub const LONG_RESERVED_BITS: u8 = 0x0c;
const KEY_PHASE_BIT: u8 = 0x04;

/// Explicit congestion notification codepoint
#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum EcnCodepoint {
    ECT0 = 0b10,
    ECT1 = 0b01,
    CE = 0b11,
}

impl EcnCodepoint {
    pub fn from_bits(x: u8) -> Option<Self> {
        use self::EcnCodepoint::*;
        Some(match x & 0b11 {
            0b10 => ECT0,
            0b01 => ECT1,
            0b11 => CE,
            _ => {
                return None;
            }
        })
    }

    pub fn bits(self) -> u8 {
        self as u8
    }
}

/// Packet number space identifiers
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum SpaceId {
    /// Unprotected packets, used to bootstrap the handshake
    Initial = 0,
    Handshake = 1,
    /// Application data space, used for 0-RTT and post-handshake/1-RTT packets
    Data = 2,
}

impl SpaceId {
    pub const VALUES: [Self; 3] = [SpaceId::Initial, SpaceId::Handshake, SpaceId::Data];
}

impl slog::Value for SpaceId {
    fn serialize(
        &self,
        _: &slog::Record<'_>,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_arguments(key, &format_args!("{:?}", self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto::Crypto, Side};
    use std::io;

    fn check_pn(typed: PacketNumber, encoded: &[u8]) {
        let mut buf = Vec::new();
        typed.encode(&mut buf);
        assert_eq!(&buf[..], encoded);
        let decoded = PacketNumber::decode(typed.len(), &mut io::Cursor::new(&buf)).unwrap();
        assert_eq!(typed, decoded);
    }

    #[test]
    fn roundtrip_packet_numbers() {
        check_pn(PacketNumber::U8(0x7f), &[0x7f]);
        check_pn(PacketNumber::U16(0x80), &[0x00, 0x80]);
        check_pn(PacketNumber::U16(0x3fff), &[0x3f, 0xff]);
        check_pn(PacketNumber::U32(0x00004000), &[0x00, 0x00, 0x40, 0x00]);
        check_pn(PacketNumber::U32(0xffffffff), &[0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn pn_encode() {
        check_pn(PacketNumber::new(0x10, 0), &[0x10]);
        check_pn(PacketNumber::new(0x100, 0), &[0x01, 0x00]);
        check_pn(PacketNumber::new(0x10000, 0), &[0x01, 0x00, 0x00]);
    }

    #[test]
    fn pn_expand_roundtrip() {
        for expected in 0..1024 {
            for actual in expected..1024 {
                assert_eq!(actual, PacketNumber::new(actual, expected).expand(expected));
            }
        }
    }

    #[test]
    fn header_encoding() {
        let dcid = ConnectionId::new(&hex!("06b858ec6f80452b"));
        let client_crypto = Crypto::new_initial(&dcid, Side::Client);
        let client_header_crypto = client_crypto.header_crypto();
        let mut buf = Vec::new();
        let header = Header::Initial {
            number: PacketNumber::U8(0),
            src_cid: ConnectionId::new(&[]),
            dst_cid: dcid,
            token: Bytes::new(),
        };
        let encode = header.encode(&mut buf);
        let header_len = buf.len();
        buf.resize(header_len + 16, 0);
        set_payload_length(&mut buf, header_len, 1, client_crypto.tag_len());
        assert_eq!(
            buf[..],
            hex!("c0ff0000125006b858ec6f80452b00402100 00000000000000000000000000000000")[..]
        );

        client_crypto.encrypt(0, &mut buf, header_len);
        encode.finish(&mut buf, &client_header_crypto);
        assert_eq!(
            buf[..],
            hex!(
                "ceff0000125006b858ec6f80452b004021b6
                 f037a410591e943c31d1eefad0927b97cbc32ece77d2881aa8f1b0c51ec425b0"
            )[..]
        );

        let server_crypto = Crypto::new_initial(&dcid, Side::Server);
        let server_header_crypto = server_crypto.header_crypto();
        let decode = PartialDecode::new(buf.clone().into(), 0).unwrap().0;
        let mut packet = decode.finish(Some(&server_header_crypto)).unwrap();
        assert_eq!(
            packet.header_data[..],
            hex!("c0ff0000125006b858ec6f80452b00402100")[..]
        );
        server_crypto
            .decrypt(0, &packet.header_data, &mut packet.payload)
            .unwrap();
        assert_eq!(packet.payload[..], [0; 16]);
        match packet.header {
            Header::Initial {
                number: PacketNumber::U8(0),
                ..
            } => {}
            _ => {
                panic!("unexpected header {:?}", packet.header);
            }
        }
    }
}
