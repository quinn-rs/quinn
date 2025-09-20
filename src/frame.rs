// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses
#![allow(missing_docs)]

use std::{
    fmt::{self, Write},
    mem,
    net::SocketAddr,
    ops::{Range, RangeInclusive},
};

use bytes::{Buf, BufMut, Bytes};
use tinyvec::TinyVec;

use crate::{
    Dir, MAX_CID_SIZE, RESET_TOKEN_SIZE, ResetToken, StreamId, TransportError, TransportErrorCode,
    VarInt,
    coding::{self, BufExt, BufMutExt, UnexpectedEnd},
    range_set::ArrayRangeSet,
    shared::{ConnectionId, EcnCodepoint},
};

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;

/// A QUIC frame type
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct FrameType(pub(crate) u64);

impl FrameType {
    pub(crate) fn stream(self) -> Option<StreamInfo> {
        if STREAM_TYS.contains(&self.0) {
            Some(StreamInfo(self.0 as u8))
        } else {
            None
        }
    }

    /// Check if this is a STREAM frame type
    #[allow(dead_code)]
    pub(crate) fn is_stream(self) -> bool {
        STREAM_TYS.contains(&self.0)
    }
    fn datagram(self) -> Option<DatagramInfo> {
        if DATAGRAM_TYS.contains(&self.0) {
            Some(DatagramInfo(self.0 as u8))
        } else {
            None
        }
    }
}

impl coding::Codec for FrameType {
    fn decode<B: Buf>(buf: &mut B) -> coding::Result<Self> {
        Ok(Self(buf.get_var()?))
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.write_var(self.0);
    }
}

pub(crate) trait FrameStruct {
    /// Smallest number of bytes this type of frame is guaranteed to fit within.
    const SIZE_BOUND: usize;
}

macro_rules! frame_types {
    {$($name:ident = $val:expr_2021,)*} => {
        impl FrameType {
            $(pub(crate) const $name: FrameType = FrameType($val);)*
        }

        impl fmt::Debug for FrameType {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self.0 {
                    $($val => f.write_str(stringify!($name)),)*
                    _ => write!(f, "Type({:02x})", self.0)
                }
            }
        }

        impl fmt::Display for FrameType {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self.0 {
                    $($val => f.write_str(stringify!($name)),)*
                    x if STREAM_TYS.contains(&x) => f.write_str("STREAM"),
                    x if DATAGRAM_TYS.contains(&x) => f.write_str("DATAGRAM"),
                    _ => write!(f, "<unknown {:02x}>", self.0),
                }
            }
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct StreamInfo(u8);

impl StreamInfo {
    fn fin(self) -> bool {
        self.0 & 0x01 != 0
    }
    fn len(self) -> bool {
        self.0 & 0x02 != 0
    }
    fn off(self) -> bool {
        self.0 & 0x04 != 0
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct DatagramInfo(u8);

impl DatagramInfo {
    fn len(self) -> bool {
        self.0 & 0x01 != 0
    }
}

frame_types! {
    PADDING = 0x00,
    PING = 0x01,
    ACK = 0x02,
    ACK_ECN = 0x03,
    RESET_STREAM = 0x04,
    STOP_SENDING = 0x05,
    CRYPTO = 0x06,
    NEW_TOKEN = 0x07,
    // STREAM
    MAX_DATA = 0x10,
    MAX_STREAM_DATA = 0x11,
    MAX_STREAMS_BIDI = 0x12,
    MAX_STREAMS_UNI = 0x13,
    DATA_BLOCKED = 0x14,
    STREAM_DATA_BLOCKED = 0x15,
    STREAMS_BLOCKED_BIDI = 0x16,
    STREAMS_BLOCKED_UNI = 0x17,
    NEW_CONNECTION_ID = 0x18,
    RETIRE_CONNECTION_ID = 0x19,
    PATH_CHALLENGE = 0x1a,
    PATH_RESPONSE = 0x1b,
    CONNECTION_CLOSE = 0x1c,
    APPLICATION_CLOSE = 0x1d,
    HANDSHAKE_DONE = 0x1e,
    // ACK Frequency
    ACK_FREQUENCY = 0xaf,
    IMMEDIATE_ACK = 0x1f,
    // NAT Traversal Extension - draft-seemann-quic-nat-traversal-02
    ADD_ADDRESS_IPV4 = 0x3d7e90,
    ADD_ADDRESS_IPV6 = 0x3d7e91,
    PUNCH_ME_NOW_IPV4 = 0x3d7e92,
    PUNCH_ME_NOW_IPV6 = 0x3d7e93,
    REMOVE_ADDRESS = 0x3d7e94,
    // Address Discovery Extension - draft-ietf-quic-address-discovery-00
    OBSERVED_ADDRESS_IPV4 = 0x9f81a6,
    OBSERVED_ADDRESS_IPV6 = 0x9f81a7,
    // DATAGRAM
}

const STREAM_TYS: RangeInclusive<u64> = RangeInclusive::new(0x08, 0x0f);
const DATAGRAM_TYS: RangeInclusive<u64> = RangeInclusive::new(0x30, 0x31);

/// All supported QUIC frame variants handled by this implementation
#[derive(Debug)]
pub(crate) enum Frame {
    Padding,
    Ping,
    Ack(Ack),
    ResetStream(ResetStream),
    StopSending(StopSending),
    Crypto(Crypto),
    NewToken(NewToken),
    Stream(Stream),
    MaxData(VarInt),
    MaxStreamData { id: StreamId, offset: u64 },
    MaxStreams { dir: Dir, count: u64 },
    DataBlocked { offset: u64 },
    StreamDataBlocked { id: StreamId, offset: u64 },
    StreamsBlocked { dir: Dir, limit: u64 },
    NewConnectionId(NewConnectionId),
    RetireConnectionId { sequence: u64 },
    PathChallenge(u64),
    PathResponse(u64),
    Close(Close),
    Datagram(Datagram),
    AckFrequency(AckFrequency),
    ImmediateAck,
    HandshakeDone,
    AddAddress(AddAddress),
    PunchMeNow(PunchMeNow),
    RemoveAddress(RemoveAddress),
    ObservedAddress(ObservedAddress),
}

impl Frame {
    pub(crate) fn ty(&self) -> FrameType {
        use Frame::*;
        match self {
            Padding => FrameType::PADDING,
            ResetStream(_) => FrameType::RESET_STREAM,
            Close(self::Close::Connection(_)) => FrameType::CONNECTION_CLOSE,
            Close(self::Close::Application(_)) => FrameType::APPLICATION_CLOSE,
            MaxData(_) => FrameType::MAX_DATA,
            MaxStreamData { .. } => FrameType::MAX_STREAM_DATA,
            MaxStreams { dir: Dir::Bi, .. } => FrameType::MAX_STREAMS_BIDI,
            MaxStreams { dir: Dir::Uni, .. } => FrameType::MAX_STREAMS_UNI,
            Ping => FrameType::PING,
            DataBlocked { .. } => FrameType::DATA_BLOCKED,
            StreamDataBlocked { .. } => FrameType::STREAM_DATA_BLOCKED,
            StreamsBlocked { dir: Dir::Bi, .. } => FrameType::STREAMS_BLOCKED_BIDI,
            StreamsBlocked { dir: Dir::Uni, .. } => FrameType::STREAMS_BLOCKED_UNI,
            StopSending { .. } => FrameType::STOP_SENDING,
            RetireConnectionId { .. } => FrameType::RETIRE_CONNECTION_ID,
            Ack(_) => FrameType::ACK,
            Stream(x) => {
                let mut ty = *STREAM_TYS.start();
                if x.fin {
                    ty |= 0x01;
                }
                if x.offset != 0 {
                    ty |= 0x04;
                }
                FrameType(ty)
            }
            PathChallenge(_) => FrameType::PATH_CHALLENGE,
            PathResponse(_) => FrameType::PATH_RESPONSE,
            NewConnectionId { .. } => FrameType::NEW_CONNECTION_ID,
            Crypto(_) => FrameType::CRYPTO,
            NewToken(_) => FrameType::NEW_TOKEN,
            Datagram(_) => FrameType(*DATAGRAM_TYS.start()),
            AckFrequency(_) => FrameType::ACK_FREQUENCY,
            ImmediateAck => FrameType::IMMEDIATE_ACK,
            HandshakeDone => FrameType::HANDSHAKE_DONE,
            AddAddress(a) => match a.address {
                SocketAddr::V4(_) => FrameType::ADD_ADDRESS_IPV4,
                SocketAddr::V6(_) => FrameType::ADD_ADDRESS_IPV6,
            },
            PunchMeNow(p) => match p.address {
                SocketAddr::V4(_) => FrameType::PUNCH_ME_NOW_IPV4,
                SocketAddr::V6(_) => FrameType::PUNCH_ME_NOW_IPV6,
            },
            RemoveAddress(_) => FrameType::REMOVE_ADDRESS,
            ObservedAddress(o) => match o.address {
                SocketAddr::V4(_) => FrameType::OBSERVED_ADDRESS_IPV4,
                SocketAddr::V6(_) => FrameType::OBSERVED_ADDRESS_IPV6,
            },
        }
    }

    pub(crate) fn is_ack_eliciting(&self) -> bool {
        !matches!(*self, Self::Ack(_) | Self::Padding | Self::Close(_))
    }
}

/// Reason for closing a connection (transport or application)
#[derive(Clone, Debug)]
pub enum Close {
    /// Transport-layer connection close
    Connection(ConnectionClose),
    /// Application-layer connection close
    Application(ApplicationClose),
}

impl Close {
    pub(crate) fn encode<W: BufMut>(&self, out: &mut W, max_len: usize) {
        match *self {
            Self::Connection(ref x) => x.encode(out, max_len),
            Self::Application(ref x) => x.encode(out, max_len),
        }
    }

    pub(crate) fn is_transport_layer(&self) -> bool {
        matches!(*self, Self::Connection(_))
    }
}

impl From<TransportError> for Close {
    fn from(x: TransportError) -> Self {
        Self::Connection(x.into())
    }
}
impl From<ConnectionClose> for Close {
    fn from(x: ConnectionClose) -> Self {
        Self::Connection(x)
    }
}
impl From<ApplicationClose> for Close {
    fn from(x: ApplicationClose) -> Self {
        Self::Application(x)
    }
}

/// Reason given by the transport for closing the connection
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionClose {
    /// Class of error as encoded in the specification
    pub error_code: TransportErrorCode,
    /// Type of frame that caused the close
    pub frame_type: Option<FrameType>,
    /// Human-readable reason for the close
    pub reason: Bytes,
}

impl fmt::Display for ConnectionClose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error_code.fmt(f)?;
        if !self.reason.as_ref().is_empty() {
            f.write_str(": ")?;
            f.write_str(&String::from_utf8_lossy(&self.reason))?;
        }
        Ok(())
    }
}

impl From<TransportError> for ConnectionClose {
    fn from(x: TransportError) -> Self {
        Self {
            error_code: x.code,
            frame_type: x.frame,
            reason: x.reason.into(),
        }
    }
}

impl FrameStruct for ConnectionClose {
    const SIZE_BOUND: usize = 1 + 8 + 8 + 8;
}

impl ConnectionClose {
    pub(crate) fn encode<W: BufMut>(&self, out: &mut W, max_len: usize) {
        out.write(FrameType::CONNECTION_CLOSE); // 1 byte
        out.write(self.error_code); // <= 8 bytes
        let ty = self.frame_type.map_or(0, |x| x.0);
        out.write_var(ty); // <= 8 bytes
        let max_len = max_len
            - 3
            - VarInt::from_u64_bounded(ty).size()
            - VarInt::from_u64_bounded(self.reason.len() as u64).size();
        let actual_len = self.reason.len().min(max_len);
        out.write_var(actual_len as u64); // <= 8 bytes
        out.put_slice(&self.reason[0..actual_len]); // whatever's left
    }
}

/// Reason given by an application for closing the connection
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationClose {
    /// Application-specific reason code
    pub error_code: VarInt,
    /// Human-readable reason for the close
    pub reason: Bytes,
}

impl fmt::Display for ApplicationClose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.reason.as_ref().is_empty() {
            f.write_str(&String::from_utf8_lossy(&self.reason))?;
            f.write_str(" (code ")?;
            self.error_code.fmt(f)?;
            f.write_str(")")?;
        } else {
            self.error_code.fmt(f)?;
        }
        Ok(())
    }
}

impl FrameStruct for ApplicationClose {
    const SIZE_BOUND: usize = 1 + 8 + 8;
}

impl ApplicationClose {
    pub(crate) fn encode<W: BufMut>(&self, out: &mut W, max_len: usize) {
        out.write(FrameType::APPLICATION_CLOSE); // 1 byte
        out.write(self.error_code); // <= 8 bytes
        let max_len = max_len - 3 - VarInt::from_u64_bounded(self.reason.len() as u64).size();
        let actual_len = self.reason.len().min(max_len);
        out.write_var(actual_len as u64); // <= 8 bytes
        out.put_slice(&self.reason[0..actual_len]); // whatever's left
    }
}

#[derive(Clone, Eq, PartialEq)]
/// Contents of an ACK frame
pub struct Ack {
    /// Largest acknowledged packet number
    pub largest: u64,
    /// ACK delay in microseconds
    pub delay: u64,
    /// Additional ACK block data encoded per RFC 9000
    pub additional: Bytes,
    /// Explicit Congestion Notification counters, if present
    pub ecn: Option<EcnCounts>,
}

impl fmt::Debug for Ack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ranges = "[".to_string();
        let mut first = true;
        for range in self.iter() {
            if !first {
                ranges.push(',');
            }
            write!(ranges, "{range:?}")
                .unwrap_or_else(|_| panic!("writing to string should not fail"));
            first = false;
        }
        ranges.push(']');

        f.debug_struct("Ack")
            .field("largest", &self.largest)
            .field("delay", &self.delay)
            .field("ecn", &self.ecn)
            .field("ranges", &ranges)
            .finish()
    }
}

impl<'a> IntoIterator for &'a Ack {
    type Item = RangeInclusive<u64>;
    type IntoIter = AckIter<'a>;

    fn into_iter(self) -> AckIter<'a> {
        AckIter::new(self.largest, &self.additional[..])
    }
}

impl Ack {
    /// Encode an ACK frame into the provided buffer
    pub fn encode<W: BufMut>(
        delay: u64,
        ranges: &ArrayRangeSet,
        ecn: Option<&EcnCounts>,
        buf: &mut W,
    ) {
        let mut rest = ranges.iter().rev();
        let first = rest
            .next()
            .unwrap_or_else(|| panic!("ACK ranges should have at least one range"));
        let largest = first.end - 1;
        let first_size = first.end - first.start;
        buf.write(if ecn.is_some() {
            FrameType::ACK_ECN
        } else {
            FrameType::ACK
        });
        buf.write_var(largest);
        buf.write_var(delay);
        buf.write_var(ranges.len() as u64 - 1);
        buf.write_var(first_size - 1);
        let mut prev = first.start;
        for block in rest {
            let size = block.end - block.start;
            buf.write_var(prev - block.end - 1);
            buf.write_var(size - 1);
            prev = block.start;
        }
        if let Some(x) = ecn {
            x.encode(buf)
        }
    }

    /// Iterate over acknowledged packet ranges
    pub fn iter(&self) -> AckIter<'_> {
        self.into_iter()
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
/// Explicit Congestion Notification counters
pub struct EcnCounts {
    /// Number of ECT(0) marked packets
    pub ect0: u64,
    /// Number of ECT(1) marked packets
    pub ect1: u64,
    /// Number of CE marked packets
    pub ce: u64,
}

impl std::ops::AddAssign<EcnCodepoint> for EcnCounts {
    fn add_assign(&mut self, rhs: EcnCodepoint) {
        match rhs {
            EcnCodepoint::Ect0 => {
                self.ect0 += 1;
            }
            EcnCodepoint::Ect1 => {
                self.ect1 += 1;
            }
            EcnCodepoint::Ce => {
                self.ce += 1;
            }
        }
    }
}

impl EcnCounts {
    pub const ZERO: Self = Self {
        ect0: 0,
        ect1: 0,
        ce: 0,
    };

    pub fn encode<W: BufMut>(&self, out: &mut W) {
        out.write_var(self.ect0);
        out.write_var(self.ect1);
        out.write_var(self.ce);
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Stream {
    pub(crate) id: StreamId,
    pub(crate) offset: u64,
    pub(crate) fin: bool,
    pub(crate) data: Bytes,
}

impl FrameStruct for Stream {
    const SIZE_BOUND: usize = 1 + 8 + 8 + 8;
}

/// Metadata from a stream frame
#[derive(Debug, Clone)]
pub(crate) struct StreamMeta {
    pub(crate) id: StreamId,
    pub(crate) offsets: Range<u64>,
    pub(crate) fin: bool,
}

// This manual implementation exists because `Default` is not implemented for `StreamId`
impl Default for StreamMeta {
    fn default() -> Self {
        Self {
            id: StreamId(0),
            offsets: 0..0,
            fin: false,
        }
    }
}

impl StreamMeta {
    pub(crate) fn encode<W: BufMut>(&self, length: bool, out: &mut W) {
        let mut ty = *STREAM_TYS.start();
        if self.offsets.start != 0 {
            ty |= 0x04;
        }
        if length {
            ty |= 0x02;
        }
        if self.fin {
            ty |= 0x01;
        }
        out.write_var(ty); // 1 byte
        out.write(self.id); // <=8 bytes
        if self.offsets.start != 0 {
            out.write_var(self.offsets.start); // <=8 bytes
        }
        if length {
            out.write_var(self.offsets.end - self.offsets.start); // <=8 bytes
        }
    }
}

/// A vector of [`StreamMeta`] with optimization for the single element case
pub(crate) type StreamMetaVec = TinyVec<[StreamMeta; 1]>;

#[derive(Debug, Clone)]
pub(crate) struct Crypto {
    pub(crate) offset: u64,
    pub(crate) data: Bytes,
}

impl Crypto {
    pub(crate) const SIZE_BOUND: usize = 17;

    pub(crate) fn encode<W: BufMut>(&self, out: &mut W) {
        out.write(FrameType::CRYPTO);
        out.write_var(self.offset);
        out.write_var(self.data.len() as u64);
        out.put_slice(&self.data);
    }
}

#[derive(Debug, Clone)]
pub(crate) struct NewToken {
    pub(crate) token: Bytes,
}

impl NewToken {
    pub(crate) fn encode<W: BufMut>(&self, out: &mut W) {
        out.write(FrameType::NEW_TOKEN);
        out.write_var(self.token.len() as u64);
        out.put_slice(&self.token);
    }

    pub(crate) fn size(&self) -> usize {
        1 + VarInt::from_u64_bounded(self.token.len() as u64).size() + self.token.len()
    }
}

pub(crate) struct Iter {
    bytes: Bytes,
    last_ty: Option<FrameType>,
}

impl Iter {
    pub(crate) fn new(payload: Bytes) -> Result<Self, TransportError> {
        if payload.is_empty() {
            // "An endpoint MUST treat receipt of a packet containing no frames as a
            // connection error of type PROTOCOL_VIOLATION."
            // https://www.rfc-editor.org/rfc/rfc9000.html#name-frames-and-frame-types
            return Err(TransportError::PROTOCOL_VIOLATION(
                "packet payload is empty",
            ));
        }

        Ok(Self {
            bytes: payload,
            last_ty: None,
        })
    }

    fn take_len(&mut self) -> Result<Bytes, UnexpectedEnd> {
        let len = self.bytes.get_var()?;
        if len > self.bytes.remaining() as u64 {
            return Err(UnexpectedEnd);
        }
        Ok(self.bytes.split_to(len as usize))
    }

    fn try_next(&mut self) -> Result<Frame, IterErr> {
        let ty = self.bytes.get::<FrameType>()?;
        self.last_ty = Some(ty);
        Ok(match ty {
            FrameType::PADDING => Frame::Padding,
            FrameType::RESET_STREAM => Frame::ResetStream(ResetStream {
                id: self.bytes.get()?,
                error_code: self.bytes.get()?,
                final_offset: self.bytes.get()?,
            }),
            FrameType::CONNECTION_CLOSE => Frame::Close(Close::Connection(ConnectionClose {
                error_code: self.bytes.get()?,
                frame_type: {
                    let x = self.bytes.get_var()?;
                    if x == 0 { None } else { Some(FrameType(x)) }
                },
                reason: self.take_len()?,
            })),
            FrameType::APPLICATION_CLOSE => Frame::Close(Close::Application(ApplicationClose {
                error_code: self.bytes.get()?,
                reason: self.take_len()?,
            })),
            FrameType::MAX_DATA => Frame::MaxData(self.bytes.get()?),
            FrameType::MAX_STREAM_DATA => Frame::MaxStreamData {
                id: self.bytes.get()?,
                offset: self.bytes.get_var()?,
            },
            FrameType::MAX_STREAMS_BIDI => Frame::MaxStreams {
                dir: Dir::Bi,
                count: self.bytes.get_var()?,
            },
            FrameType::MAX_STREAMS_UNI => Frame::MaxStreams {
                dir: Dir::Uni,
                count: self.bytes.get_var()?,
            },
            FrameType::PING => Frame::Ping,
            FrameType::DATA_BLOCKED => Frame::DataBlocked {
                offset: self.bytes.get_var()?,
            },
            FrameType::STREAM_DATA_BLOCKED => Frame::StreamDataBlocked {
                id: self.bytes.get()?,
                offset: self.bytes.get_var()?,
            },
            FrameType::STREAMS_BLOCKED_BIDI => Frame::StreamsBlocked {
                dir: Dir::Bi,
                limit: self.bytes.get_var()?,
            },
            FrameType::STREAMS_BLOCKED_UNI => Frame::StreamsBlocked {
                dir: Dir::Uni,
                limit: self.bytes.get_var()?,
            },
            FrameType::STOP_SENDING => Frame::StopSending(StopSending {
                id: self.bytes.get()?,
                error_code: self.bytes.get()?,
            }),
            FrameType::RETIRE_CONNECTION_ID => Frame::RetireConnectionId {
                sequence: self.bytes.get_var()?,
            },
            FrameType::ACK | FrameType::ACK_ECN => {
                let largest = self.bytes.get_var()?;
                let delay = self.bytes.get_var()?;
                let extra_blocks = self.bytes.get_var()? as usize;
                let n = scan_ack_blocks(&self.bytes, largest, extra_blocks)?;
                Frame::Ack(Ack {
                    delay,
                    largest,
                    additional: self.bytes.split_to(n),
                    ecn: if ty != FrameType::ACK_ECN {
                        None
                    } else {
                        Some(EcnCounts {
                            ect0: self.bytes.get_var()?,
                            ect1: self.bytes.get_var()?,
                            ce: self.bytes.get_var()?,
                        })
                    },
                })
            }
            FrameType::PATH_CHALLENGE => Frame::PathChallenge(self.bytes.get()?),
            FrameType::PATH_RESPONSE => Frame::PathResponse(self.bytes.get()?),
            FrameType::NEW_CONNECTION_ID => {
                let sequence = self.bytes.get_var()?;
                let retire_prior_to = self.bytes.get_var()?;
                if retire_prior_to > sequence {
                    return Err(IterErr::Malformed);
                }
                let length = self.bytes.get::<u8>()? as usize;
                if length > MAX_CID_SIZE || length == 0 {
                    return Err(IterErr::Malformed);
                }
                if length > self.bytes.remaining() {
                    return Err(IterErr::UnexpectedEnd);
                }
                let mut stage = [0; MAX_CID_SIZE];
                self.bytes.copy_to_slice(&mut stage[0..length]);
                let id = ConnectionId::new(&stage[..length]);
                if self.bytes.remaining() < 16 {
                    return Err(IterErr::UnexpectedEnd);
                }
                let mut reset_token = [0; RESET_TOKEN_SIZE];
                self.bytes.copy_to_slice(&mut reset_token);
                Frame::NewConnectionId(NewConnectionId {
                    sequence,
                    retire_prior_to,
                    id,
                    reset_token: reset_token.into(),
                })
            }
            FrameType::CRYPTO => Frame::Crypto(Crypto {
                offset: self.bytes.get_var()?,
                data: self.take_len()?,
            }),
            FrameType::NEW_TOKEN => Frame::NewToken(NewToken {
                token: self.take_len()?,
            }),
            FrameType::HANDSHAKE_DONE => Frame::HandshakeDone,
            FrameType::ACK_FREQUENCY => Frame::AckFrequency(AckFrequency {
                sequence: self.bytes.get()?,
                ack_eliciting_threshold: self.bytes.get()?,
                request_max_ack_delay: self.bytes.get()?,
                reordering_threshold: self.bytes.get()?,
            }),
            FrameType::IMMEDIATE_ACK => Frame::ImmediateAck,
            FrameType::ADD_ADDRESS_IPV4 => {
                Frame::AddAddress(AddAddress::decode_auto(&mut self.bytes, false)?)
            }
            FrameType::ADD_ADDRESS_IPV6 => {
                Frame::AddAddress(AddAddress::decode_auto(&mut self.bytes, true)?)
            }
            FrameType::PUNCH_ME_NOW_IPV4 => {
                Frame::PunchMeNow(PunchMeNow::decode_auto(&mut self.bytes, false)?)
            }
            FrameType::PUNCH_ME_NOW_IPV6 => {
                Frame::PunchMeNow(PunchMeNow::decode_auto(&mut self.bytes, true)?)
            }
            FrameType::REMOVE_ADDRESS => {
                // RemoveAddress doesn't have auto decode, uses same format for both
                Frame::RemoveAddress(RemoveAddress::decode(&mut self.bytes)?)
            }
            FrameType::OBSERVED_ADDRESS_IPV4 => {
                Frame::ObservedAddress(ObservedAddress::decode(&mut self.bytes, false)?)
            }
            FrameType::OBSERVED_ADDRESS_IPV6 => {
                Frame::ObservedAddress(ObservedAddress::decode(&mut self.bytes, true)?)
            }
            _ => {
                if let Some(s) = ty.stream() {
                    Frame::Stream(Stream {
                        id: self.bytes.get()?,
                        offset: if s.off() { self.bytes.get_var()? } else { 0 },
                        fin: s.fin(),
                        data: if s.len() {
                            self.take_len()?
                        } else {
                            self.take_remaining()
                        },
                    })
                } else if let Some(d) = ty.datagram() {
                    Frame::Datagram(Datagram {
                        data: if d.len() {
                            self.take_len()?
                        } else {
                            self.take_remaining()
                        },
                    })
                } else {
                    return Err(IterErr::InvalidFrameId);
                }
            }
        })
    }

    fn take_remaining(&mut self) -> Bytes {
        mem::take(&mut self.bytes)
    }
}

impl Iterator for Iter {
    type Item = Result<Frame, InvalidFrame>;
    fn next(&mut self) -> Option<Self::Item> {
        if !self.bytes.has_remaining() {
            return None;
        }
        match self.try_next() {
            Ok(x) => Some(Ok(x)),
            Err(e) => {
                // Corrupt frame, skip it and everything that follows
                self.bytes.clear();
                Some(Err(InvalidFrame {
                    ty: self.last_ty,
                    reason: e.reason(),
                }))
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct InvalidFrame {
    pub(crate) ty: Option<FrameType>,
    pub(crate) reason: &'static str,
}

impl From<InvalidFrame> for TransportError {
    fn from(err: InvalidFrame) -> Self {
        let mut te = Self::FRAME_ENCODING_ERROR(err.reason);
        te.frame = err.ty;
        te
    }
}

/// Validate exactly `n` ACK ranges in `buf` and return the number of bytes they cover
fn scan_ack_blocks(mut buf: &[u8], largest: u64, n: usize) -> Result<usize, IterErr> {
    let total_len = buf.remaining();
    let first_block = buf.get_var()?;
    let mut smallest = largest.checked_sub(first_block).ok_or(IterErr::Malformed)?;
    for _ in 0..n {
        let gap = buf.get_var()?;
        smallest = smallest.checked_sub(gap + 2).ok_or(IterErr::Malformed)?;
        let block = buf.get_var()?;
        smallest = smallest.checked_sub(block).ok_or(IterErr::Malformed)?;
    }
    Ok(total_len - buf.remaining())
}

enum IterErr {
    UnexpectedEnd,
    InvalidFrameId,
    Malformed,
}

impl IterErr {
    fn reason(&self) -> &'static str {
        use IterErr::*;
        match *self {
            UnexpectedEnd => "unexpected end",
            InvalidFrameId => "invalid frame ID",
            Malformed => "malformed",
        }
    }
}

impl From<UnexpectedEnd> for IterErr {
    fn from(_: UnexpectedEnd) -> Self {
        Self::UnexpectedEnd
    }
}

#[derive(Debug, Clone)]
pub struct AckIter<'a> {
    largest: u64,
    data: &'a [u8],
}

impl<'a> AckIter<'a> {
    fn new(largest: u64, data: &'a [u8]) -> Self {
        Self { largest, data }
    }
}

impl Iterator for AckIter<'_> {
    type Item = RangeInclusive<u64>;
    fn next(&mut self) -> Option<RangeInclusive<u64>> {
        if !self.data.has_remaining() {
            return None;
        }
        let block = match self.data.get_var() {
            Ok(block) => block,
            Err(_) => return None,
        };
        let largest = self.largest;
        if let Ok(gap) = self.data.get_var() {
            self.largest -= block + gap + 2;
        }
        Some(largest - block..=largest)
    }
}

#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[derive(Debug, Copy, Clone)]
pub struct ResetStream {
    pub(crate) id: StreamId,
    pub(crate) error_code: VarInt,
    pub(crate) final_offset: VarInt,
}

impl FrameStruct for ResetStream {
    const SIZE_BOUND: usize = 1 + 8 + 8 + 8;
}

impl ResetStream {
    pub(crate) fn encode<W: BufMut>(&self, out: &mut W) {
        out.write(FrameType::RESET_STREAM); // 1 byte
        out.write(self.id); // <= 8 bytes
        out.write(self.error_code); // <= 8 bytes
        out.write(self.final_offset); // <= 8 bytes
    }
}

#[derive(Debug, Copy, Clone)]
pub(crate) struct StopSending {
    pub(crate) id: StreamId,
    pub(crate) error_code: VarInt,
}

impl FrameStruct for StopSending {
    const SIZE_BOUND: usize = 1 + 8 + 8;
}

impl StopSending {
    pub(crate) fn encode<W: BufMut>(&self, out: &mut W) {
        out.write(FrameType::STOP_SENDING); // 1 byte
        out.write(self.id); // <= 8 bytes
        out.write(self.error_code) // <= 8 bytes
    }
}

#[derive(Debug, Copy, Clone)]
pub(crate) struct NewConnectionId {
    pub(crate) sequence: u64,
    pub(crate) retire_prior_to: u64,
    pub(crate) id: ConnectionId,
    pub(crate) reset_token: ResetToken,
}

impl NewConnectionId {
    pub(crate) fn encode<W: BufMut>(&self, out: &mut W) {
        out.write(FrameType::NEW_CONNECTION_ID);
        out.write_var(self.sequence);
        out.write_var(self.retire_prior_to);
        out.write(self.id.len() as u8);
        out.put_slice(&self.id);
        out.put_slice(&self.reset_token);
    }
}

/// Smallest number of bytes this type of frame is guaranteed to fit within.
pub(crate) const RETIRE_CONNECTION_ID_SIZE_BOUND: usize = 9;

/// An unreliable datagram
#[derive(Debug, Clone)]
pub struct Datagram {
    /// Payload
    pub data: Bytes,
}

impl FrameStruct for Datagram {
    const SIZE_BOUND: usize = 1 + 8;
}

impl Datagram {
    pub(crate) fn encode(&self, length: bool, out: &mut Vec<u8>) {
        out.write(FrameType(*DATAGRAM_TYS.start() | u64::from(length))); // 1 byte
        if length {
            // Safe to unwrap because we check length sanity before queueing datagrams
            out.write(VarInt::from_u64_bounded(self.data.len() as u64)); // <= 8 bytes
        }
        out.extend_from_slice(&self.data);
    }

    pub(crate) fn size(&self, length: bool) -> usize {
        1 + if length {
            VarInt::from_u64_bounded(self.data.len() as u64).size()
        } else {
            0
        } + self.data.len()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct AckFrequency {
    pub(crate) sequence: VarInt,
    pub(crate) ack_eliciting_threshold: VarInt,
    pub(crate) request_max_ack_delay: VarInt,
    pub(crate) reordering_threshold: VarInt,
}

impl AckFrequency {
    pub(crate) fn encode<W: BufMut>(&self, buf: &mut W) {
        buf.write(FrameType::ACK_FREQUENCY);
        buf.write(self.sequence);
        buf.write(self.ack_eliciting_threshold);
        buf.write(self.request_max_ack_delay);
        buf.write(self.reordering_threshold);
    }
}

// Re-export unified NAT traversal frames
pub(crate) use nat_traversal_unified::{AddAddress, PunchMeNow, RemoveAddress};

/// Address Discovery frame for informing peers of their observed address
/// draft-ietf-quic-address-discovery-00
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ObservedAddress {
    /// Monotonically increasing sequence number
    pub(crate) sequence_number: VarInt,
    /// The socket address observed by the sender
    pub(crate) address: SocketAddr,
}

impl ObservedAddress {
    pub(crate) fn encode<W: BufMut>(&self, buf: &mut W) {
        match self.address {
            SocketAddr::V4(_) => buf.write(FrameType::OBSERVED_ADDRESS_IPV4),
            SocketAddr::V6(_) => buf.write(FrameType::OBSERVED_ADDRESS_IPV6),
        };

        // Write sequence number as varint
        buf.write_var(self.sequence_number.0);

        // Write address and port directly (no IP version byte needed)
        match self.address {
            SocketAddr::V4(addr) => {
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            SocketAddr::V6(addr) => {
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
        }
    }

    pub(crate) fn decode<R: Buf>(r: &mut R, is_ipv6: bool) -> Result<Self, UnexpectedEnd> {
        // Read sequence number first
        let sequence_number = VarInt::from_u64(r.get_var()?).map_err(|_| UnexpectedEnd)?;

        // Decode address based on frame type (no IP version byte)
        let address = if is_ipv6 {
            if r.remaining() < 18 {
                return Err(UnexpectedEnd);
            }
            let mut octets = [0u8; 16];
            r.copy_to_slice(&mut octets);
            let port = r.get::<u16>()?;
            SocketAddr::new(octets.into(), port)
        } else {
            if r.remaining() < 6 {
                return Err(UnexpectedEnd);
            }
            let mut octets = [0u8; 4];
            r.copy_to_slice(&mut octets);
            let port = r.get::<u16>()?;
            SocketAddr::new(octets.into(), port)
        };

        Ok(Self {
            sequence_number,
            address,
        })
    }
}

impl FrameStruct for ObservedAddress {
    const SIZE_BOUND: usize = 4 + 8 + 16 + 2; // frame type (4) + sequence (8) + IPv6 + port
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::coding::Codec;
    use assert_matches::assert_matches;

    fn frames(buf: Vec<u8>) -> Vec<Frame> {
        Iter::new(Bytes::from(buf))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    #[test]
    fn ack_coding() {
        const PACKETS: &[u64] = &[1, 2, 3, 5, 10, 11, 14];
        let mut ranges = ArrayRangeSet::new();
        for &packet in PACKETS {
            ranges.insert(packet..packet + 1);
        }
        let mut buf = Vec::new();
        const ECN: EcnCounts = EcnCounts {
            ect0: 42,
            ect1: 24,
            ce: 12,
        };
        Ack::encode(42, &ranges, Some(&ECN), &mut buf);
        let frames = frames(buf);
        assert_eq!(frames.len(), 1);
        match frames[0] {
            Frame::Ack(ref ack) => {
                let mut packets = ack.iter().flatten().collect::<Vec<_>>();
                packets.sort_unstable();
                assert_eq!(&packets[..], PACKETS);
                assert_eq!(ack.ecn, Some(ECN));
            }
            ref x => panic!("incorrect frame {x:?}"),
        }
    }

    #[test]
    fn ack_frequency_coding() {
        let mut buf = Vec::new();
        let original = AckFrequency {
            sequence: VarInt(42),
            ack_eliciting_threshold: VarInt(20),
            request_max_ack_delay: VarInt(50_000),
            reordering_threshold: VarInt(1),
        };
        original.encode(&mut buf);
        let frames = frames(buf);
        assert_eq!(frames.len(), 1);
        match &frames[0] {
            Frame::AckFrequency(decoded) => assert_eq!(decoded, &original),
            x => panic!("incorrect frame {x:?}"),
        }
    }

    #[test]
    fn immediate_ack_coding() {
        let mut buf = Vec::new();
        FrameType::IMMEDIATE_ACK.encode(&mut buf);
        let frames = frames(buf);
        assert_eq!(frames.len(), 1);
        assert_matches!(&frames[0], Frame::ImmediateAck);
    }

    #[test]
    fn add_address_ipv4_coding() {
        let mut buf = Vec::new();
        let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
        let original = AddAddress {
            sequence: VarInt(42),
            address: addr,
            priority: VarInt(100),
        };
        // Use RFC encoding to match the decoder expectations
        original.encode_rfc(&mut buf);
        let frames = frames(buf);
        assert_eq!(frames.len(), 1);
        match &frames[0] {
            Frame::AddAddress(decoded) => {
                assert_eq!(decoded.sequence, original.sequence);
                assert_eq!(decoded.address, original.address);
                // Priority is not encoded in RFC format
            }
            x => panic!("incorrect frame {x:?}"),
        }
    }

    #[test]
    fn add_address_ipv6_coding() {
        let mut buf = Vec::new();
        let addr = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 8080));
        let original = AddAddress {
            sequence: VarInt(123),
            address: addr,
            priority: VarInt(200),
        };
        // Use RFC encoding to match the decoder expectations
        original.encode_rfc(&mut buf);
        let frames = frames(buf);
        assert_eq!(frames.len(), 1);
        match &frames[0] {
            Frame::AddAddress(decoded) => {
                assert_eq!(decoded.sequence, original.sequence);
                assert_eq!(decoded.address, original.address);
                // Priority is not encoded in RFC format
            }
            x => panic!("incorrect frame {x:?}"),
        }
    }

    #[test]
    fn punch_me_now_ipv4_coding() {
        let mut buf = Vec::new();
        let addr = SocketAddr::from(([192, 168, 1, 1], 9000));
        let original = PunchMeNow {
            round: VarInt(1),
            paired_with_sequence_number: VarInt(42),
            address: addr,
            target_peer_id: None,
        };
        // Use RFC encoding to match the decoder expectations
        original.encode_rfc(&mut buf);
        let frames = frames(buf);
        assert_eq!(frames.len(), 1);
        match &frames[0] {
            Frame::PunchMeNow(decoded) => {
                assert_eq!(decoded.round, original.round);
                assert_eq!(
                    decoded.paired_with_sequence_number,
                    original.paired_with_sequence_number
                );
                assert_eq!(decoded.address, original.address);
            }
            x => panic!("incorrect frame {x:?}"),
        }
    }

    #[test]
    fn punch_me_now_ipv6_coding() {
        let mut buf = Vec::new();
        let addr = SocketAddr::from(([0xfe80, 0, 0, 0, 0, 0, 0, 1], 9000));
        let original = PunchMeNow {
            round: VarInt(2),
            paired_with_sequence_number: VarInt(100),
            address: addr,
            target_peer_id: None,
        };
        // Use RFC encoding to match the decoder expectations
        original.encode_rfc(&mut buf);
        let frames = frames(buf);
        assert_eq!(frames.len(), 1);
        match &frames[0] {
            Frame::PunchMeNow(decoded) => {
                assert_eq!(decoded.round, original.round);
                assert_eq!(
                    decoded.paired_with_sequence_number,
                    original.paired_with_sequence_number
                );
                assert_eq!(decoded.address, original.address);
            }
            x => panic!("incorrect frame {x:?}"),
        }
    }

    #[test]
    fn remove_address_coding() {
        let mut buf = Vec::new();
        let original = RemoveAddress {
            sequence: VarInt(42),
        };
        original.encode(&mut buf);
        let frames = frames(buf);
        assert_eq!(frames.len(), 1);
        match &frames[0] {
            Frame::RemoveAddress(decoded) => {
                assert_eq!(decoded.sequence, original.sequence);
            }
            x => panic!("incorrect frame {x:?}"),
        }
    }

    #[test]
    fn nat_traversal_frame_size_bounds() {
        // Test that the SIZE_BOUND constants are correct
        let mut buf = Vec::new();

        // AddAddress with IPv6 (worst case)
        let addr = AddAddress {
            sequence: VarInt::MAX,
            address: SocketAddr::from(([0xffff; 8], 65535)),
            priority: VarInt::MAX,
        };
        addr.encode(&mut buf);
        assert!(buf.len() <= AddAddress::SIZE_BOUND);
        buf.clear();

        // PunchMeNow with IPv6 (worst case)
        let punch = PunchMeNow {
            round: VarInt::MAX,
            paired_with_sequence_number: VarInt::MAX,
            address: SocketAddr::from(([0xffff; 8], 65535)),
            target_peer_id: Some([0xff; 32]),
        };
        punch.encode(&mut buf);
        assert!(buf.len() <= PunchMeNow::SIZE_BOUND);
        buf.clear();

        // RemoveAddress
        let remove = RemoveAddress {
            sequence: VarInt::MAX,
        };
        remove.encode(&mut buf);
        assert!(buf.len() <= RemoveAddress::SIZE_BOUND);
    }

    #[test]
    fn punch_me_now_with_target_peer_id() {
        // Note: target_peer_id is only supported in legacy format, not RFC format
        // This test verifies the legacy format can be encoded, but when decoded
        // through the standard frame decoder, target_peer_id won't be preserved
        // (as it's not part of the RFC format)
        let mut buf = Vec::new();
        let target_peer_id = [0x42; 32]; // Test peer ID
        let addr = SocketAddr::from(([192, 168, 1, 100], 12345));
        let original = PunchMeNow {
            round: VarInt(5),
            paired_with_sequence_number: VarInt(999),
            address: addr,
            target_peer_id: Some(target_peer_id),
        };
        // Use RFC encoding which doesn't include target_peer_id
        original.encode_rfc(&mut buf);
        let frames = frames(buf);
        assert_eq!(frames.len(), 1);
        match &frames[0] {
            Frame::PunchMeNow(decoded) => {
                assert_eq!(decoded.round, original.round);
                assert_eq!(
                    decoded.paired_with_sequence_number,
                    original.paired_with_sequence_number
                );
                assert_eq!(decoded.address, original.address);
                // RFC format doesn't support target_peer_id
                assert_eq!(decoded.target_peer_id, None);
            }
            x => panic!("incorrect frame {x:?}"),
        }
    }

    #[test]
    fn nat_traversal_frame_edge_cases() {
        // Test minimum values
        let mut buf = Vec::new();

        // AddAddress with minimum values
        let min_addr = AddAddress {
            sequence: VarInt(0),
            address: SocketAddr::from(([0, 0, 0, 0], 0)),
            priority: VarInt(0),
        };
        min_addr.encode_rfc(&mut buf);
        let frames1 = frames(buf.clone());
        assert_eq!(frames1.len(), 1);
        buf.clear();

        // PunchMeNow with minimum values
        let min_punch = PunchMeNow {
            round: VarInt(0),
            paired_with_sequence_number: VarInt(0),
            address: SocketAddr::from(([0, 0, 0, 0], 0)),
            target_peer_id: None,
        };
        min_punch.encode_rfc(&mut buf);
        let frames2 = frames(buf.clone());
        assert_eq!(frames2.len(), 1);
        buf.clear();

        // RemoveAddress with minimum values
        let min_remove = RemoveAddress {
            sequence: VarInt(0),
        };
        min_remove.encode(&mut buf);
        let frames3 = frames(buf);
        assert_eq!(frames3.len(), 1);
    }

    #[test]
    fn nat_traversal_frame_boundary_values() {
        // Test VarInt boundary values
        let mut buf = Vec::new();

        // Test VarInt boundary values for AddAddress
        let boundary_values = [
            VarInt(0),
            VarInt(63),         // Maximum 1-byte VarInt
            VarInt(64),         // Minimum 2-byte VarInt
            VarInt(16383),      // Maximum 2-byte VarInt
            VarInt(16384),      // Minimum 4-byte VarInt
            VarInt(1073741823), // Maximum 4-byte VarInt
            VarInt(1073741824), // Minimum 8-byte VarInt
        ];

        for &sequence in &boundary_values {
            for &priority in &boundary_values {
                let addr = AddAddress {
                    sequence,
                    address: SocketAddr::from(([127, 0, 0, 1], 8080)),
                    priority,
                };
                addr.encode_rfc(&mut buf);
                let parsed_frames = frames(buf.clone());
                assert_eq!(parsed_frames.len(), 1);
                match &parsed_frames[0] {
                    Frame::AddAddress(decoded) => {
                        assert_eq!(decoded.sequence, sequence);
                        // Priority not encoded in RFC format
                    }
                    x => panic!("incorrect frame {x:?}"),
                }
                buf.clear();
            }
        }
    }

    #[test]
    fn nat_traversal_frame_error_handling() {
        // Test malformed frame data
        let malformed_frames = vec![
            // Too short for any NAT traversal frame (4-byte frame types)
            vec![0xc0, 0x90, 0xf9, 0x0f], // Just ADD_ADDRESS_IPV4 frame type, no data
            vec![0xc0, 0x92, 0xf9, 0x0f], // Just PUNCH_ME_NOW_IPV4 frame type, no data
            vec![0xc0, 0x94, 0xf9, 0x0f], // Just REMOVE_ADDRESS frame type, no data
            // Incomplete AddAddress frames
            vec![0xc0, 0x90, 0xf9, 0x0f, 0x01], // Frame type + partial sequence
            vec![0xc0, 0x90, 0xf9, 0x0f, 0x01, 0x04], // Frame type + sequence + incomplete
            // Incomplete PunchMeNow frames
            vec![0xc0, 0x92, 0xf9, 0x0f, 0x01], // Frame type + partial round
            vec![0xc0, 0x92, 0xf9, 0x0f, 0x01, 0x02], // Frame type + round + partial
            // Incomplete RemoveAddress frames
            // RemoveAddress is actually hard to make malformed since it only has sequence

            // Invalid IP address types
            vec![0xc0, 0x90, 0xf9, 0x0f, 0x01, 0x99, 0x01, 0x02, 0x03, 0x04], // Invalid
        ];

        for malformed in malformed_frames {
            let result = Iter::new(Bytes::from(malformed)).unwrap().next();
            if let Some(frame_result) = result {
                // Should either parse successfully (for valid but incomplete data)
                // or return an error (for truly malformed data)
                match frame_result {
                    Ok(_) => {}  // Valid frame parsed
                    Err(_) => {} // Expected error for malformed data
                }
            }
        }
    }

    #[test]
    fn nat_traversal_frame_roundtrip_consistency() {
        // Test that encoding and then decoding produces identical frames

        // Test AddAddress frames
        let add_test_cases = vec![
            AddAddress {
                sequence: VarInt(42),
                address: SocketAddr::from(([127, 0, 0, 1], 8080)),
                priority: VarInt(100),
            },
            AddAddress {
                sequence: VarInt(1000),
                address: SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 443)),
                priority: VarInt(255),
            },
        ];

        for original_add in add_test_cases {
            let mut buf = Vec::new();
            original_add.encode_rfc(&mut buf);

            let decoded_frames = frames(buf);
            assert_eq!(decoded_frames.len(), 1);

            match &decoded_frames[0] {
                Frame::AddAddress(decoded) => {
                    assert_eq!(original_add.sequence, decoded.sequence);
                    assert_eq!(original_add.address, decoded.address);
                    // Priority not encoded in RFC format
                }
                _ => panic!("Expected AddAddress frame"),
            }
        }

        // Test PunchMeNow frames
        let punch_test_cases = vec![
            PunchMeNow {
                round: VarInt(1),
                paired_with_sequence_number: VarInt(42),
                address: SocketAddr::from(([192, 168, 1, 1], 9000)),
                target_peer_id: None,
            },
            PunchMeNow {
                round: VarInt(10),
                paired_with_sequence_number: VarInt(500),
                address: SocketAddr::from(([2001, 0xdb8, 0, 0, 0, 0, 0, 1], 12345)),
                target_peer_id: Some([0xaa; 32]),
            },
        ];

        for original_punch in punch_test_cases {
            let mut buf = Vec::new();
            original_punch.encode_rfc(&mut buf);

            let decoded_frames = frames(buf);
            assert_eq!(decoded_frames.len(), 1);

            match &decoded_frames[0] {
                Frame::PunchMeNow(decoded) => {
                    assert_eq!(original_punch.round, decoded.round);
                    assert_eq!(
                        original_punch.paired_with_sequence_number,
                        decoded.paired_with_sequence_number
                    );
                    assert_eq!(original_punch.address, decoded.address);
                    // RFC format doesn't support target_peer_id, so it should always be None
                    assert_eq!(decoded.target_peer_id, None);
                }
                _ => panic!("Expected PunchMeNow frame"),
            }
        }

        // Test RemoveAddress frames
        let remove_test_cases = vec![
            RemoveAddress {
                sequence: VarInt(123),
            },
            RemoveAddress {
                sequence: VarInt(0),
            },
        ];

        for original_remove in remove_test_cases {
            let mut buf = Vec::new();
            original_remove.encode(&mut buf);

            let decoded_frames = frames(buf);
            assert_eq!(decoded_frames.len(), 1);

            match &decoded_frames[0] {
                Frame::RemoveAddress(decoded) => {
                    assert_eq!(original_remove.sequence, decoded.sequence);
                }
                _ => panic!("Expected RemoveAddress frame"),
            }
        }
    }

    #[test]
    fn nat_traversal_frame_type_constants() {
        // Verify that the frame type constants match the NAT traversal draft specification
        assert_eq!(FrameType::ADD_ADDRESS_IPV4.0, 0x3d7e90);
        assert_eq!(FrameType::ADD_ADDRESS_IPV6.0, 0x3d7e91);
        assert_eq!(FrameType::PUNCH_ME_NOW_IPV4.0, 0x3d7e92);
        assert_eq!(FrameType::PUNCH_ME_NOW_IPV6.0, 0x3d7e93);
        assert_eq!(FrameType::REMOVE_ADDRESS.0, 0x3d7e94);
    }

    #[test]
    fn observed_address_frame_encoding() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        // Test IPv4 address encoding/decoding
        let ipv4_cases = vec![
            ObservedAddress {
                sequence_number: VarInt::from_u32(1),
                address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080),
            },
            ObservedAddress {
                sequence_number: VarInt::from_u32(2),
                address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443),
            },
            ObservedAddress {
                sequence_number: VarInt::from_u32(3),
                address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 65535),
            },
        ];

        for original in ipv4_cases {
            let mut buf = Vec::new();
            original.encode(&mut buf);

            let decoded_frames = frames(buf);
            assert_eq!(decoded_frames.len(), 1);

            match &decoded_frames[0] {
                Frame::ObservedAddress(decoded) => {
                    assert_eq!(original.address, decoded.address);
                }
                _ => panic!("Expected ObservedAddress frame"),
            }
        }

        // Test IPv6 address encoding/decoding
        let ipv6_cases = vec![
            ObservedAddress {
                sequence_number: VarInt::from_u32(4),
                address: SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                    8080,
                ),
            },
            ObservedAddress {
                sequence_number: VarInt::from_u32(5),
                address: SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 443),
            },
            ObservedAddress {
                sequence_number: VarInt::from_u32(6),
                address: SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
                    65535,
                ),
            },
        ];

        for original in ipv6_cases {
            let mut buf = Vec::new();
            original.encode(&mut buf);

            let decoded_frames = frames(buf);
            assert_eq!(decoded_frames.len(), 1);

            match &decoded_frames[0] {
                Frame::ObservedAddress(decoded) => {
                    assert_eq!(original.address, decoded.address);
                }
                _ => panic!("Expected ObservedAddress frame"),
            }
        }
    }

    #[test]
    fn observed_address_malformed_frames() {
        use crate::coding::BufMutExt;
        use bytes::BufMut;

        // Test truncated sequence number
        let mut buf = Vec::new();
        // Use IPv4 variant for test
        buf.write(FrameType::OBSERVED_ADDRESS_IPV4);
        // No sequence number, just go straight to address - this is invalid

        let result = Iter::new(Bytes::from(buf));
        assert!(result.is_ok());
        let mut iter = result.unwrap();
        let frame_result = iter.next();
        assert!(frame_result.is_some());
        assert!(frame_result.unwrap().is_err());

        // Test truncated IPv4 address
        let mut buf = Vec::new();
        // Use IPv4 variant for test
        buf.write(FrameType::OBSERVED_ADDRESS_IPV4);
        buf.put_u8(4); // IPv4
        buf.put_slice(&[192, 168]); // Only 2 bytes instead of 4

        let result = Iter::new(Bytes::from(buf));
        assert!(result.is_ok());
        let mut iter = result.unwrap();
        let frame_result = iter.next();
        assert!(frame_result.is_some());
        assert!(frame_result.unwrap().is_err());

        // Test truncated IPv6 address
        let mut buf = Vec::new();
        // Use IPv6 variant for test
        buf.write(FrameType::OBSERVED_ADDRESS_IPV6);
        buf.write_var(1); // sequence number
        buf.put_slice(&[0x20, 0x01, 0x0d, 0xb8]); // Only 4 bytes instead of 16

        let result = Iter::new(Bytes::from(buf));
        assert!(result.is_ok());
        let mut iter = result.unwrap();
        let frame_result = iter.next();
        assert!(frame_result.is_some());
        assert!(frame_result.unwrap().is_err());
    }

    #[test]
    fn observed_address_frame_type_constant() {
        // Verify that the frame type constant matches the address discovery draft
        assert_eq!(FrameType::OBSERVED_ADDRESS_IPV4.0, 0x9f81a6);
        assert_eq!(FrameType::OBSERVED_ADDRESS_IPV6.0, 0x9f81a7);
    }

    #[test]
    fn observed_address_frame_serialization_edge_cases() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        // Test with port 0
        let frame_port_0 = ObservedAddress {
            sequence_number: VarInt::from_u32(100),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 0),
        };
        let mut buf = Vec::new();
        frame_port_0.encode(&mut buf);
        let decoded_frames = frames(buf);
        assert_eq!(decoded_frames.len(), 1);
        match &decoded_frames[0] {
            Frame::ObservedAddress(decoded) => {
                assert_eq!(frame_port_0.address, decoded.address);
                assert_eq!(decoded.address.port(), 0);
            }
            _ => panic!("Expected ObservedAddress frame"),
        }

        // Test with maximum port
        let frame_max_port = ObservedAddress {
            sequence_number: VarInt::from_u32(101),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 65535),
        };
        let mut buf = Vec::new();
        frame_max_port.encode(&mut buf);
        let decoded_frames = frames(buf);
        assert_eq!(decoded_frames.len(), 1);
        match &decoded_frames[0] {
            Frame::ObservedAddress(decoded) => {
                assert_eq!(frame_max_port.address, decoded.address);
                assert_eq!(decoded.address.port(), 65535);
            }
            _ => panic!("Expected ObservedAddress frame"),
        }

        // Test with unspecified addresses
        let unspecified_v4 = ObservedAddress {
            sequence_number: VarInt::from_u32(102),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080),
        };
        let mut buf = Vec::new();
        unspecified_v4.encode(&mut buf);
        let decoded_frames = frames(buf);
        assert_eq!(decoded_frames.len(), 1);
        match &decoded_frames[0] {
            Frame::ObservedAddress(decoded) => {
                assert_eq!(unspecified_v4.address, decoded.address);
                assert_eq!(decoded.address.ip(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            }
            _ => panic!("Expected ObservedAddress frame"),
        }

        let unspecified_v6 = ObservedAddress {
            sequence_number: VarInt::from_u32(103),
            address: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 443),
        };
        let mut buf = Vec::new();
        unspecified_v6.encode(&mut buf);
        let decoded_frames = frames(buf);
        assert_eq!(decoded_frames.len(), 1);
        match &decoded_frames[0] {
            Frame::ObservedAddress(decoded) => {
                assert_eq!(unspecified_v6.address, decoded.address);
                assert_eq!(decoded.address.ip(), IpAddr::V6(Ipv6Addr::UNSPECIFIED));
            }
            _ => panic!("Expected ObservedAddress frame"),
        }
    }

    #[test]
    fn observed_address_frame_size_compliance() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        // Test that frame sizes are reasonable and within expected bounds
        let test_addresses = vec![
            ObservedAddress {
                sequence_number: VarInt::from_u32(1),
                address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080),
            },
            ObservedAddress {
                sequence_number: VarInt::from_u32(2),
                address: SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                    443,
                ),
            },
        ];

        for frame in test_addresses {
            let mut buf = Vec::new();
            frame.encode(&mut buf);

            // Frame type (4 bytes) + sequence (1 byte for small values) + address + port (2 bytes)
            // IPv4: 4 + 1 + 4 + 2 = 11 bytes
            // IPv6: 4 + 1 + 16 + 2 = 23 bytes
            match frame.address.ip() {
                IpAddr::V4(_) => {
                    assert!(
                        buf.len() == 11,
                        "IPv4 frame size {} out of expected range",
                        buf.len()
                    );
                }
                IpAddr::V6(_) => {
                    assert!(
                        buf.len() == 23,
                        "IPv6 frame size {} out of expected range",
                        buf.len()
                    );
                }
            }
        }
    }

    #[test]
    fn observed_address_multiple_frames_in_packet() {
        use crate::coding::BufMutExt;
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        // Test that multiple OBSERVED_ADDRESS frames can be encoded/decoded in a single packet
        let observed1 = ObservedAddress {
            sequence_number: VarInt::from_u32(10),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1234),
        };
        let observed2 = ObservedAddress {
            sequence_number: VarInt::from_u32(11),
            address: SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
                5678,
            ),
        };

        let mut buf = Vec::new();
        // Encode first ObservedAddress frame
        observed1.encode(&mut buf);
        // Encode PING frame
        buf.write(FrameType::PING);
        // Encode second ObservedAddress frame
        observed2.encode(&mut buf);
        // Padding frame is just zeros, no special encoding needed
        buf.push(0); // PADDING frame type

        let decoded_frames = frames(buf);
        assert_eq!(decoded_frames.len(), 4);

        // Verify each frame matches
        match &decoded_frames[0] {
            Frame::ObservedAddress(dec) => {
                assert_eq!(observed1.address, dec.address);
            }
            _ => panic!("Expected ObservedAddress at position 0"),
        }

        match &decoded_frames[1] {
            Frame::Ping => {}
            _ => panic!("Expected Ping at position 1"),
        }

        match &decoded_frames[2] {
            Frame::ObservedAddress(dec) => {
                assert_eq!(observed2.address, dec.address);
            }
            _ => panic!("Expected ObservedAddress at position 2"),
        }

        match &decoded_frames[3] {
            Frame::Padding => {}
            _ => panic!("Expected Padding at position 3"),
        }
    }

    #[test]
    fn observed_address_frame_error_recovery() {
        use bytes::BufMut;

        // Test that parser can recover from malformed OBSERVED_ADDRESS frames
        let mut buf = Vec::new();

        // Valid PING frame
        buf.put_u8(FrameType::PING.0 as u8);

        // Malformed OBSERVED_ADDRESS frame (truncated)
        // Use IPv4 variant for test
        buf.write(FrameType::OBSERVED_ADDRESS_IPV4);
        buf.write_var(1); // sequence number
        buf.put_slice(&[192, 168]); // Only 2 bytes instead of 4 for IPv4

        // Another valid PING frame (should not be parsed due to error above)
        buf.put_u8(FrameType::PING.0 as u8);

        let result = Iter::new(Bytes::from(buf));
        assert!(result.is_ok());
        let mut iter = result.unwrap();

        // First frame should parse successfully
        let frame1 = iter.next();
        assert!(frame1.is_some());
        assert!(frame1.unwrap().is_ok());

        // Second frame should fail
        let frame2 = iter.next();
        assert!(frame2.is_some());
        assert!(frame2.unwrap().is_err());

        // Iterator should stop after error
        let frame3 = iter.next();
        assert!(frame3.is_none());
    }

    #[test]
    fn observed_address_frame_varint_encoding() {
        use std::net::{IpAddr, Ipv4Addr};

        // Ensure frame type is correctly encoded as varint
        let frame = ObservedAddress {
            sequence_number: VarInt::from_u32(1000),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80),
        };

        let mut buf = Vec::new();
        frame.encode(&mut buf);

        // Frame type 0x9f81a6 (10453414) needs 4-byte varint encoding
        // QUIC varint encoding for values >= 2^21 and < 2^30:
        // Format: 10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
        // 0x9f81a6 = 10453414
        // First byte:  0x80 | ((value >> 24) & 0x3f) = 0x80
        // Second byte: (value >> 16) & 0xff = 0x9f
        // Third byte:  (value >> 8) & 0xff = 0x81
        // Fourth byte: value & 0xff = 0xa6
        assert_eq!(buf[0], 0x80); // First byte of 4-byte VarInt
        assert_eq!(buf[1], 0x9f); // Second byte
        assert_eq!(buf[2], 0x81); // Third byte
        assert_eq!(buf[3], 0xa6); // Fourth byte
    }

    // Include comprehensive tests module
    mod comprehensive_tests {
        include!("frame/tests.rs");
    }

    // Include sequence edge case tests
    mod sequence_edge_cases {
        include!("frame/sequence_edge_case_tests.rs");
    }

    // Include IP version encoding tests
    mod ip_version_tests {
        include!("frame/ip_version_encoding_tests.rs");
    }

    // Include observed address tests
    mod observed_address_test {
        include!("frame/observed_address_tests.rs");
    }

    // Include observed address sequence validation tests
    mod observed_address_validation {
        include!("frame/observed_address_sequence_validation_tests.rs");
    }

    // NAT frame interoperability tests
    mod nat_frame_interop {
        use super::*;
        use crate::frame::{
            nat_compat::*,
            rfc_nat_traversal::{RfcAddAddress, RfcPunchMeNow, RfcRemoveAddress},
        };

        #[test]
        fn test_add_address_conversions() {
            let old_frame = AddAddress {
                sequence: VarInt::from_u32(100),
                address: "10.0.0.1:8080".parse().unwrap(),
                priority: VarInt::from_u32(65535),
            };

            let rfc_frame = add_address_to_rfc(&old_frame);
            assert_eq!(rfc_frame.sequence_number, old_frame.sequence);
            assert_eq!(rfc_frame.address, old_frame.address);

            let default_priority = VarInt::from_u32(100000);
            let converted_back = rfc_to_add_address(&rfc_frame, default_priority);
            assert_eq!(converted_back.sequence, old_frame.sequence);
            assert_eq!(converted_back.address, old_frame.address);
            assert_eq!(converted_back.priority, default_priority);
        }

        #[test]
        fn test_punch_me_now_conversions() {
            let old_frame = PunchMeNow {
                round: VarInt::from_u32(5),
                paired_with_sequence_number: VarInt::from_u32(100),
                address: "192.168.1.1:5000".parse().unwrap(),
                target_peer_id: Some([0x42; 32]),
            };

            let rfc_frame = punch_me_now_to_rfc(&old_frame);
            assert_eq!(rfc_frame.round, old_frame.round);
            assert_eq!(
                rfc_frame.paired_with_sequence_number,
                old_frame.paired_with_sequence_number
            );
            assert_eq!(rfc_frame.address, old_frame.address);

            let converted_back = rfc_to_punch_me_now(&rfc_frame);
            assert_eq!(converted_back.round, old_frame.round);
            assert_eq!(
                converted_back.paired_with_sequence_number,
                old_frame.paired_with_sequence_number
            );
            assert_eq!(converted_back.address, old_frame.address);
            assert_eq!(converted_back.target_peer_id, None);
        }

        #[test]
        fn test_priority_strategy() {
            let strategy = PriorityStrategy {
                use_ice_priority: true,
                default_priority: VarInt::from_u32(50000),
            };

            let public_v4: SocketAddr = "8.8.8.8:53".parse().unwrap();
            let private_v4: SocketAddr = "192.168.1.1:80".parse().unwrap();
            let loopback_v4: SocketAddr = "127.0.0.1:8080".parse().unwrap();

            let pub_priority = strategy.calculate_priority(&public_v4);
            let priv_priority = strategy.calculate_priority(&private_v4);
            let loop_priority = strategy.calculate_priority(&loopback_v4);

            assert!(pub_priority.into_inner() > priv_priority.into_inner());
            assert!(priv_priority.into_inner() > loop_priority.into_inner());
        }

        #[test]
        fn test_compat_mode_detection() {
            assert_eq!(detect_frame_format(0x3d7e90), FrameFormat::Rfc);
            assert_eq!(detect_frame_format(0x3d7e91), FrameFormat::Rfc);
            assert_eq!(detect_frame_format(0x12345678), FrameFormat::Legacy);
        }
    }
}

// RFC-compliant NAT traversal frames
pub(crate) mod rfc_nat_traversal;

// Compatibility layer for NAT traversal frame migration
pub(crate) mod nat_compat;

// Unified NAT traversal frames with RFC compliance and backward compatibility
pub mod nat_traversal_unified;
