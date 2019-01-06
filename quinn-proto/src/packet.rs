use std::{fmt, io, str};

use bytes::{BigEndian, Buf, BufMut, ByteOrder, Bytes, BytesMut};
use rand::Rng;
use slog;

use crate::coding::{self, BufExt, BufMutExt};
use crate::crypto::HeaderCrypto;
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
        self.space() == Some(SpaceId::Initial)
    }

    pub fn space(&self) -> Option<SpaceId> {
        use self::InvariantHeader::*;
        match self.invariant_header {
            Short { .. } => Some(SpaceId::Data),
            Long {
                version: VERSION,
                first,
                ..
            } => match LongHeaderType::from_byte(first).ok()? {
                LongHeaderType::Retry => None,
                LongHeaderType::Initial => Some(SpaceId::Initial),
                LongHeaderType::Standard(LongType::Handshake) => Some(SpaceId::Handshake),
                LongHeaderType::Standard(LongType::ZeroRtt) => Some(SpaceId::Data),
            },
            _ => None,
        }
    }

    pub fn is_0rtt(&self) -> bool {
        match self.invariant_header {
            InvariantHeader::Long {
                version: VERSION,
                first,
                ..
            } => {
                LongHeaderType::from_byte(first) == Ok(LongHeaderType::Standard(LongType::ZeroRtt))
            }
            _ => false,
        }
    }

    pub fn dst_cid(&self) -> ConnectionId {
        self.invariant_header.dst_cid()
    }

    /// Length of data being decoded
    ///
    /// May account for multiple packets.
    pub fn len(&self) -> usize {
        self.buf.get_ref().len()
    }

    pub fn finish(
        self,
        header_crypto: Option<&HeaderCrypto>,
    ) -> Result<(Packet, Option<BytesMut>), PacketDecodeError> {
        let Self {
            invariant_header,
            mut buf,
        } = self;
        let (payload_len, header, allow_coalesced) = match invariant_header {
            InvariantHeader::Short { dst_cid, .. } => {
                if !buf.has_remaining() {
                    return Err(PacketDecodeError::InvalidHeader(
                        "header ends before packet number",
                    ));
                }

                let number = Self::decrypt_header(&mut buf, header_crypto.unwrap())?;
                let spin = buf.get_ref()[0] & SPIN_BIT != 0;
                let key_phase = buf.get_ref()[0] & KEY_PHASE_BIT != 0;
                (
                    buf.remaining(),
                    Header::Short {
                        dst_cid,
                        number,
                        spin,
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
            } => match LongHeaderType::from_byte(first)? {
                LongHeaderType::Retry => {
                    let odcil = first & 0xf;
                    let odcil = if odcil == 0 { 0 } else { (odcil + 3) as usize };
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
                LongHeaderType::Initial => {
                    let token_length = buf.get_var()? as usize;
                    // Could we avoid this alloc/copy somehow?
                    let mut token = BytesMut::with_capacity(token_length);
                    token.extend_from_slice(&buf.bytes()[..token_length]);
                    let token = token.freeze();
                    buf.advance(token_length);

                    let len = buf.get_var()?;
                    let number = Self::decrypt_header(&mut buf, header_crypto.unwrap())?;
                    if len < number.len() as u64 {
                        return Err(PacketDecodeError::InvalidHeader(
                            "packet number longer than packet",
                        ));
                    }
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
                LongHeaderType::Standard(ty) => {
                    let len = buf.get_var()?;
                    let number = Self::decrypt_header(&mut buf, header_crypto.unwrap())?;
                    if len < number.len() as u64 {
                        return Err(PacketDecodeError::InvalidHeader(
                            "packet number longer than packet",
                        ));
                    }
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

    fn decrypt_header(
        buf: &mut io::Cursor<BytesMut>,
        header_crypto: &HeaderCrypto,
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
        spin: bool,
        key_phase: bool,
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
                ref src_cid,
                ref dst_cid,
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
                ref src_cid,
                ref dst_cid,
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
                ref src_cid,
                ref dst_cid,
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
                ref dst_cid,
                number,
                spin,
                key_phase,
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
                ref src_cid,
                ref dst_cid,
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
}

pub struct PartialEncode {
    pn: Option<usize>,
}

impl PartialEncode {
    pub fn finish(self, buf: &mut [u8], header_crypto: &HeaderCrypto) {
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

#[derive(Debug, Fail, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum PacketDecodeError {
    #[fail(display = "unsupported version")]
    UnsupportedVersion {
        source: ConnectionId,
        destination: ConnectionId,
    },
    #[fail(display = "invalid header: {}", _0)]
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
            hex!("c0ff0000115006b858ec6f80452b00402100 00000000000000000000000000000000")[..]
        );

        client_crypto.encrypt(0, &mut buf, header_len);
        encode.finish(&mut buf, &client_header_crypto);
        assert_eq!(
            buf[..],
            hex!(
                "c8ff0000115006b858ec6f80452b004021a7
                 f037a410591e943c31d1eefad0927b97e620160d59c776720c7118b9699a15b3"
            )[..]
        );

        let server_crypto = Crypto::new_initial(&dcid, Side::Server);
        let server_header_crypto = server_crypto.header_crypto();
        let decode = PartialDecode::new(buf.clone().into(), 0).unwrap();
        let mut packet = decode.finish(Some(&server_header_crypto)).unwrap().0;
        assert_eq!(
            packet.header_data[..],
            hex!("c0ff0000115006b858ec6f80452b00402100")[..]
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
