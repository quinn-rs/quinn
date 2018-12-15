use std::{fmt, io, str};

use bytes::{BigEndian, Buf, BufMut, ByteOrder, Bytes, BytesMut};
use rand::Rng;
use slog;

use crate::coding::{self, BufExt, BufMutExt, Codec};
use crate::crypto::PacketNumberKey;
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
    invariant_header: InvariantHeader,
    buf: io::Cursor<BytesMut>,
}

impl PartialDecode {
    pub fn new(bytes: BytesMut, local_cid_len: usize) -> Result<Self, PacketDecodeError> {
        let mut buf = io::Cursor::new(bytes);
        let invariant_header = InvariantHeader::decode(&mut buf, local_cid_len)?;
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
            } => PacketType::from_byte(first) == Ok(PacketType::Initial),
            Long { .. } | Short { .. } => false,
        }
    }

    pub fn is_handshake(&self) -> bool {
        match self.invariant_header {
            InvariantHeader::Long {
                version: VERSION,
                first,
                ..
            } => match PacketType::from_byte(first).unwrap() {
                PacketType::Initial => true,
                PacketType::Retry => true,
                PacketType::Long(LongType::Handshake) => true,
                _ => false,
            },
            InvariantHeader::Long { .. } => false,
            InvariantHeader::Short { .. } => false,
        }
    }

    pub fn dst_cid(&self) -> ConnectionId {
        self.invariant_header.dst_cid()
    }

    pub fn key_phase(&self) -> bool {
        match self.invariant_header {
            InvariantHeader::Short { first, .. } => (first & KEY_PHASE_BIT) != 0,
            _ => false,
        }
    }

    pub fn finish(
        self,
        pn_key: &PacketNumberKey,
    ) -> Result<(Packet, Option<BytesMut>), PacketDecodeError> {
        let Self {
            invariant_header,
            mut buf,
        } = self;
        let (payload_len, header, allow_coalesced) = match invariant_header {
            InvariantHeader::Short { first, dst_cid } => {
                let key_phase = first & KEY_PHASE_BIT != 0;
                if !buf.has_remaining() {
                    return Err(PacketDecodeError::InvalidHeader(
                        "header ends before packet number",
                    ));
                }

                let sample_offset = 1 + dst_cid.len() + 4;
                let number = Self::get_packet_number(&mut buf, pn_key, sample_offset)?;
                (
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
                version: 0,
                dst_cid,
                src_cid,
                ..
            } => (
                buf.remaining(),
                Header::VersionNegotiate {
                    random: first & !LONG_HEADER_FORM,
                    src_cid,
                    dst_cid,
                },
                false,
            ),
            InvariantHeader::Long {
                first,
                version: VERSION,
                dst_cid,
                src_cid,
            } => match PacketType::from_byte(first)? {
                PacketType::Retry => {
                    let odcil = buf.get::<u8>()? as usize;
                    let mut odci_stage = [0; 18];
                    buf.copy_to_slice(&mut odci_stage[0..odcil]);
                    let orig_dst_cid = ConnectionId::new(&odci_stage[..odcil]);
                    (
                        buf.remaining(),
                        Header::Retry {
                            src_cid,
                            dst_cid,
                            orig_dst_cid,
                        },
                        false,
                    )
                }
                PacketType::Initial => {
                    let token_length = buf.get_var()? as usize;
                    // Could we avoid this alloc/copy somehow?
                    let mut token = BytesMut::with_capacity(token_length);
                    token.extend_from_slice(&buf.bytes()[..token_length]);
                    let token = token.freeze();
                    buf.advance(token_length);

                    let len = buf.get_var()?;
                    let sample_offset = 10
                        + dst_cid.len()
                        + src_cid.len()
                        + varint::size(len).unwrap()
                        + varint::size(token_length as u64).unwrap()
                        + token.len();

                    let number = Self::get_packet_number(&mut buf, pn_key, sample_offset)?;
                    (
                        (len as usize) - number.len(),
                        Header::Initial {
                            src_cid,
                            dst_cid,
                            token,
                            number,
                        },
                        true,
                    )
                }
                PacketType::Long(ty) => {
                    let len = buf.get_var()?;
                    let sample_offset =
                        10 + dst_cid.len() + src_cid.len() + varint::size(len).unwrap();
                    let number = Self::get_packet_number(&mut buf, pn_key, sample_offset)?;
                    (
                        (len as usize) - number.len(),
                        Header::Long {
                            ty,
                            src_cid,
                            dst_cid,
                            number,
                        },
                        true,
                    )
                }
                // InvariantHeader should be Short variant for Short packet type
                PacketType::Short { .. } => unreachable!(),
            },
            // InvariantHeader decode checks for unsupported versions
            InvariantHeader::Long { .. } => unreachable!(),
        };

        let header_len = buf.position() as usize;
        let mut bytes = buf.into_inner();
        if bytes.len() < header_len + payload_len {
            return Err(PacketDecodeError::InvalidHeader(
                "payload longer than packet",
            ));
        }

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

    fn get_packet_number(
        buf: &mut io::Cursor<BytesMut>,
        pn_key: &PacketNumberKey,
        mut sample_offset: usize,
    ) -> Result<PacketNumber, PacketDecodeError> {
        let packet_length = buf.get_ref().len();
        if sample_offset + pn_key.sample_size() > packet_length {
            sample_offset = packet_length
                .checked_sub(pn_key.sample_size())
                .ok_or_else(|| {
                    PacketDecodeError::InvalidHeader("packet too short to decode packet number")
                })?;
        }
        if packet_length < sample_offset + pn_key.sample_size() {
            return Err(PacketDecodeError::InvalidHeader(
                "packet too short to extract packet number encryption sample",
            ));
        }

        let mut first = [buf.bytes()[0]; 1];
        let mut sample = [0; 16];
        debug_assert!(pn_key.sample_size() <= 16);
        sample.copy_from_slice(&buf.get_ref()[sample_offset..sample_offset + pn_key.sample_size()]);

        pn_key.decrypt(&sample, &mut first);
        let len = PacketNumber::decode_len(first[0]);
        let pos = buf.position() as usize;
        pn_key.decrypt(&sample, &mut buf.get_mut()[pos..pos + len]);
        PacketNumber::decode(buf)
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
        src_cid: ConnectionId,
        dst_cid: ConnectionId,
        token: Bytes,
        number: PacketNumber,
    },
    Long {
        ty: LongType,
        src_cid: ConnectionId,
        dst_cid: ConnectionId,
        number: PacketNumber,
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
        random: u8,
        src_cid: ConnectionId,
        dst_cid: ConnectionId,
    },
}

impl Header {
    pub fn encode<W: BufMut>(&self, w: &mut W) -> PartialEncode<'_> {
        use self::Header::*;
        match *self {
            Initial {
                ref src_cid,
                ref dst_cid,
                ref token,
                number,
            } => {
                w.write(u8::from(PacketType::Initial));
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
                PartialEncode {
                    header: self,
                    pn: Some((pn_pos, number.len())),
                }
            }
            Long {
                ty,
                ref src_cid,
                ref dst_cid,
                number,
            } => {
                w.write(u8::from(PacketType::Long(ty)));
                w.write(VERSION);
                Self::encode_cids(w, dst_cid, src_cid);
                w.write::<u16>(0); // Placeholder for payload length; see `set_payload_length`
                number.encode(w);
                let pn_pos = 8 + dst_cid.len() + src_cid.len();
                PartialEncode {
                    header: self,
                    pn: Some((pn_pos, number.len())),
                }
            }
            Retry {
                ref src_cid,
                ref dst_cid,
                ref orig_dst_cid,
            } => {
                w.write(u8::from(PacketType::Retry));
                w.write(VERSION);
                Self::encode_cids(w, dst_cid, src_cid);
                w.write(orig_dst_cid.len() as u8);
                w.put_slice(orig_dst_cid);
                PartialEncode {
                    header: self,
                    pn: None,
                }
            }
            Short {
                ref dst_cid,
                number,
                key_phase,
            } => {
                w.write(0x30 | if key_phase { KEY_PHASE_BIT } else { 0 });
                w.put_slice(dst_cid);
                number.encode(w);
                PartialEncode {
                    header: self,
                    pn: Some((1 + dst_cid.len(), number.len())),
                }
            }
            VersionNegotiate {
                ref random,
                ref src_cid,
                ref dst_cid,
            } => {
                w.write(0x80u8 | random);
                w.write::<u32>(0);
                Self::encode_cids(w, dst_cid, src_cid);
                PartialEncode {
                    header: self,
                    pn: None,
                }
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
}

pub struct PartialEncode<'a> {
    header: &'a Header,
    pn: Option<(usize, usize)>,
}

impl<'a> PartialEncode<'a> {
    pub fn finish(self, buf: &mut [u8], pn_key: &PacketNumberKey, header_len: usize) {
        let PartialEncode { header, pn } = self;
        let payload_len = (buf.len() - header_len) as u64;
        let (mut sample_offset, pn_pos, pn_len) = match header {
            Header::Short { dst_cid, .. } => {
                let sample_offset = 1 + dst_cid.len() + 4;
                let (pn_pos, pn_len) = pn.unwrap();
                (sample_offset, pn_pos, pn_len)
            }
            Header::Initial {
                dst_cid,
                src_cid,
                token,
                ..
            } => {
                let sample_offset = 10
                    + dst_cid.len()
                    + src_cid.len()
                    + varint::size(payload_len).unwrap()
                    + varint::size(token.len() as u64).unwrap()
                    + token.len();
                let (pn_pos, pn_len) = pn.unwrap();
                (sample_offset, pn_pos, pn_len)
            }
            Header::Long {
                dst_cid, src_cid, ..
            } => {
                let sample_offset =
                    10 + dst_cid.len() + src_cid.len() + varint::size(payload_len).unwrap();
                let (pn_pos, pn_len) = pn.unwrap();
                (sample_offset, pn_pos, pn_len)
            }
            _ => {
                return;
            }
        };

        let packet_length = buf.len();
        if sample_offset + pn_key.sample_size() > packet_length {
            sample_offset = packet_length - pn_key.sample_size();
        }

        debug_assert!(pn_key.sample_size() <= 16);
        let sample = {
            let mut sample = [0; 16];
            sample.copy_from_slice(&buf[sample_offset..sample_offset + pn_key.sample_size()]);
            sample
        };

        pn_key.encrypt(&sample, &mut buf[pn_pos..pn_pos + pn_len]);
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

    fn decode<R: Buf>(buf: &mut R, local_cid_len: usize) -> Result<Self, PacketDecodeError> {
        let first = buf.get::<u8>()?;
        if first & LONG_HEADER_FORM == 0 {
            if buf.remaining() < local_cid_len {
                return Err(PacketDecodeError::InvalidHeader(
                    "destination connection ID longer than packet",
                ));
            }
            let dst_cid = Self::get_cid(buf, local_cid_len);
            Ok(InvariantHeader::Short { first, dst_cid })
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
    U32(u32),
}

impl PacketNumber {
    pub fn new(n: u64, largest_acked: u64) -> Self {
        let range = (n - largest_acked) * 2;
        if range < 1 << 7 {
            PacketNumber::U8(n as u8)
        } else if range < 1 << 14 {
            PacketNumber::U16(n as u16)
        } else if range < 1 << 30 {
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
            U32(_) => 4,
        }
    }

    pub fn encode<W: BufMut>(self, w: &mut W) {
        use self::PacketNumber::*;
        match self {
            U8(x) => {
                debug_assert!(x < 128);
                w.write(x)
            }
            U16(x) => {
                debug_assert!(x < 16384);
                w.write(x | 0x8000)
            }
            U32(x) => {
                debug_assert!(x < 1073741824);
                w.write(x | 0xc0000000)
            }
        }
    }

    pub fn decode<R: Buf>(r: &mut R) -> Result<PacketNumber, PacketDecodeError> {
        use self::PacketNumber::*;
        if r.remaining() < 1 {
            return Err(coding::UnexpectedEnd.into());
        }

        let len = Self::decode_len(r.bytes()[0]);
        if r.remaining() < len {
            return Err(coding::UnexpectedEnd.into());
        }

        match len {
            1 => Ok(U8(r.get()?)),
            2 => Ok(U16(u16::decode(r)? & PACKET_NUMBER_16_MASK)),
            4 => Ok(U32(u32::decode(r)? & PACKET_NUMBER_32_MASK)),
            _ => Err(PacketDecodeError::InvalidHeader(
                "unable to decode packet number",
            )),
        }
    }

    fn decode_len(b: u8) -> usize {
        if b < 0x80 {
            1
        } else if b < 0xc0 {
            2
        } else {
            4
        }
    }

    pub fn expand(self, expected: u64) -> u64 {
        // From Appendix A
        use self::PacketNumber::*;
        let truncated = match self {
            U8(x) => x as u64,
            U16(x) => x as u64,
            U32(x) => x as u64,
        };
        let nbits = match self {
            U8(_) => 7,
            U16(_) => 14,
            U32(_) => 30,
        };
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketType {
    Initial,
    Long(LongType),
    Retry,
    Short { key_phase: bool },
}

impl PacketType {
    fn from_byte(b: u8) -> Result<Self, PacketDecodeError> {
        use self::{LongType::*, PacketType::*};
        match b {
            0xff => Ok(Initial),
            0xfe => Ok(Retry),
            0xfd => Ok(Long(Handshake)),
            0xfc => Ok(Long(ZeroRtt)),
            b if b & LONG_HEADER_FORM == 0 => Ok(Short {
                key_phase: b & KEY_PHASE_BIT > 0,
            }),
            _ => Err(PacketDecodeError::InvalidLongHeaderType(b)),
        }
    }
}

impl From<PacketType> for u8 {
    fn from(ty: PacketType) -> u8 {
        use self::{LongType::*, PacketType::*};
        match ty {
            Initial => LONG_HEADER_FORM | 0x7f,
            Long(Handshake) => LONG_HEADER_FORM | 0x7d,
            Long(ZeroRtt) => LONG_HEADER_FORM | 0x7c,
            Retry => LONG_HEADER_FORM | 0x7e,
            Short { key_phase } => {
                if key_phase {
                    KEY_PHASE_BIT
                } else {
                    0
                }
            }
        }
    }
}

impl slog::Value for PacketType {
    fn serialize(
        &self,
        _: &slog::Record<'_>,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_arguments(key, &format_args!("{:?}", self))
    }
}

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

pub fn set_payload_length(packet: &mut [u8], header_len: usize, pn_len: usize) {
    let len = packet.len() - header_len + pn_len + AEAD_TAG_SIZE;
    assert!(len < 2usize.pow(14)); // Fits in reserved space
    BigEndian::write_u16(
        &mut packet[header_len - pn_len - 2..],
        len as u16 | 0b01 << 14,
    );
}

pub const AEAD_TAG_SIZE: usize = 16;
pub const PACKET_NUMBER_16_MASK: u16 = 0x3fff;
pub const PACKET_NUMBER_32_MASK: u32 = 0x3fffffff;

const LONG_HEADER_FORM: u8 = 0x80;
const KEY_PHASE_BIT: u8 = 0x40;

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

#[cfg(test)]
mod tests {
    use super::{
        ConnectionId, Header, PacketNumber, PacketNumberKey, PartialDecode, PartialEncode,
    };
    use std::io;

    fn check_pn(typed: PacketNumber, encoded: &[u8]) {
        let mut buf = Vec::new();
        typed.encode(&mut buf);
        assert_eq!(&buf[..], encoded);
        let decoded = PacketNumber::decode(&mut io::Cursor::new(&buf)).unwrap();
        assert_eq!(typed, decoded);
    }

    #[test]
    fn roundtrip_packet_numbers() {
        check_pn(PacketNumber::U8(127), &[0x7f]);
        check_pn(PacketNumber::U16(128), &[0x80, 0x80]);
        check_pn(PacketNumber::U16(16383), &[0xbf, 0xff]);
        check_pn(PacketNumber::U32(16384), &[0xc0, 0x00, 0x40, 0x00]);
        check_pn(PacketNumber::U32(1073741823), &[0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn pn_encode() {
        check_pn(PacketNumber::new(63, 0), &[0x3f]);
        check_pn(PacketNumber::new(64, 0), &[0x80, 0x40]);
        check_pn(PacketNumber::new(8191, 0), &[0x9f, 0xff]);
        check_pn(PacketNumber::new(8192, 0), &[0xc0, 0x00, 0x20, 0x00]);
    }

    #[test]
    fn pn_expand_roundtrip() {
        for expected in 0..1024 {
            for actual in expected..1024 {
                assert_eq!(actual, PacketNumber::new(actual, expected).expand(expected));
            }
        }
    }

    // https://github.com/quicwg/base-drafts/wiki/Test-vector-for-AES-packet-number-encryption
    #[test]
    fn pne_test_vector() {
        let key = PacketNumberKey::AesCtr128([
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ]);

        let received = vec![
            0x30, 0x80, 0x6d, 0xbb, 0xb5, 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9,
            0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0x20, 0x3f, 0xbe, 0x2e, 0x32, 0x17, 0xfc,
            0x5b, 0x88, 0x55,
        ];
        let partial_decode = PartialDecode::new(received.into(), 0).unwrap();
        let packet = partial_decode.finish(&key).unwrap().0;
        match packet.header {
            Header::Short {
                number: PacketNumber::U16(15034),
                ..
            } => {}
            _ => unreachable!(),
        }

        let mut sending = vec![
            0x30, 0xba, 0xba, 0xbb, 0xb5, 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9,
            0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0x20, 0x3f, 0xbe, 0x2e, 0x32, 0x17, 0xfc,
            0x5b, 0x88, 0x55,
        ];
        let header = Header::Short {
            dst_cid: ConnectionId::new(&[]),
            number: PacketNumber::U16(15034),
            key_phase: false,
        };
        PartialEncode {
            header: &header,
            pn: Some((1, 2)),
        }
        .finish(&mut sending, &key, 3);
        assert_eq!(&sending[1..3], [0x80, 0x6d]);
    }

    #[test]
    fn pne_test_chacha20() {
        let key = PacketNumberKey::ChaCha20([
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c, 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c,
        ]);

        let received = vec![
            0x30, 0xa9, 0x0e, 0xbb, 0xb5, 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9,
            0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0x20, 0x3f, 0xbe, 0x2e, 0x32, 0x17, 0xfc,
            0x5b, 0x88, 0x55,
        ];
        let partial_decode = PartialDecode::new(received.into(), 0).unwrap();
        let packet = partial_decode.finish(&key).unwrap().0;
        match packet.header {
            Header::Short {
                number: PacketNumber::U16(15034),
                ..
            } => {}
            _ => unreachable!(),
        }

        let mut sending = vec![
            0x30, 0xba, 0xba, 0xbb, 0xb5, 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9,
            0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0x20, 0x3f, 0xbe, 0x2e, 0x32, 0x17, 0xfc,
            0x5b, 0x88, 0x55,
        ];
        let header = Header::Short {
            dst_cid: ConnectionId::new(&[]),
            number: PacketNumber::U16(15034),
            key_phase: false,
        };
        PartialEncode {
            header: &header,
            pn: Some((1, 2)),
        }
        .finish(&mut sending, &key, 3);
        assert_eq!(&sending[1..3], [0xa9, 0x0e]);
    }
}
