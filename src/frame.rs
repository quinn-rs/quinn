use bytes::{Buf, BufMut};

use codec::{BufLen, Codec, VarLen};

#[derive(Debug, PartialEq)]
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

    fn decode<T: Buf>(buf: &mut T) -> Self {
        match buf.bytes()[0] {
            v if v >= 0x10 => Frame::Stream(StreamFrame::decode(buf)),
            0 => Frame::Padding(PaddingFrame::decode(buf)),
            v => panic!("unimplemented decoding for frame type {}", v),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct StreamFrame {
    pub id: u64,
    pub fin: bool,
    pub offset: u64,
    pub len: Option<u64>,
    pub data: Vec<u8>,
}

impl BufLen for StreamFrame {
    fn buf_len(&self) -> usize {
        1 + VarLen(self.id).buf_len() + if self.offset > 0 {
            VarLen(self.offset).buf_len()
        } else {
            0
        } + self.len.map(VarLen).buf_len() + self.data.len()
    }
}

impl Codec for StreamFrame {
    fn encode<T: BufMut>(&self, buf: &mut T) {
        let has_offset = if self.offset > 0 { 0x04 } else { 0 };
        let has_len = if self.len.is_some() { 0x02 } else { 0 };
        let is_fin = if self.fin { 0x01 } else { 0 };
        buf.put_u8(0x10 | has_offset | has_len | is_fin);
        VarLen(self.id).encode(buf);
        if self.offset > 0 {
            VarLen(self.offset).encode(buf);
        }
        if let Some(len) = self.len {
            VarLen(len).encode(buf);
        }
        buf.put_slice(&self.data);
    }

    fn decode<T: Buf>(buf: &mut T) -> Self {
        let first = buf.get_u8();
        let id = VarLen::decode(buf).0;
        let offset = if first & 0x04 > 0 {
            VarLen::decode(buf).0
        } else {
            0
        };

        let len = if first & 0x02 > 0 {
            VarLen::decode(buf).0
        } else {
            buf.remaining() as u64
        };
        let mut data = vec![0u8; len as usize];
        buf.copy_to_slice(&mut data);

        StreamFrame {
            id: id,
            fin: first & 0x01 > 0,
            offset,
            len: if first & 0x02 > 0 { Some(len) } else { None },
            data,
        }
    }
}

#[derive(Debug, PartialEq)]
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

    fn decode<T: Buf>(buf: &mut T) -> Self {
        let size = buf.remaining();
        buf.advance(size);
        PaddingFrame(size)
    }
}

enum FrameType {
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
