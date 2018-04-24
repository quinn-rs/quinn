use bytes::{Buf, BufMut};

use codec::{BufLen, Codec, VarLen};

#[derive(Debug, PartialEq)]
pub enum Frame {
    Ack(AckFrame),
    Padding(PaddingFrame),
    Stream(StreamFrame),
}

impl BufLen for Frame {
    fn buf_len(&self) -> usize {
        match *self {
            Frame::Ack(ref f) => f.buf_len(),
            Frame::Padding(ref f) => f.buf_len(),
            Frame::Stream(ref f) => f.buf_len(),
        }
    }
}

impl Codec for Frame {
    fn encode<T: BufMut>(&self, buf: &mut T) {
        match *self {
            Frame::Ack(ref f) => f.encode(buf),
            Frame::Padding(ref f) => f.encode(buf),
            Frame::Stream(ref f) => f.encode(buf),
        }
    }

    fn decode<T: Buf>(buf: &mut T) -> Self {
        match buf.bytes()[0] {
            v if v >= 0x10 => Frame::Stream(StreamFrame::decode(buf)),
            0x0d => Frame::Ack(AckFrame::decode(buf)),
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
pub struct AckFrame {
    pub largest: u32,
    pub ack_delay: u64,
    pub blocks: Vec<Ack>,
}

impl BufLen for AckFrame {
    fn buf_len(&self) -> usize {
        1 + VarLen(self.largest as u64).buf_len() + VarLen(self.ack_delay).buf_len()
            + VarLen((self.blocks.len() - 1) as u64).buf_len()
            + self.blocks
                .iter()
                .map(|v| VarLen(v.value()).buf_len())
                .sum::<usize>()
    }
}

impl Codec for AckFrame {
    fn encode<T: BufMut>(&self, buf: &mut T) {
        buf.put_u8(0x0d);
        VarLen(self.largest as u64).encode(buf);
        VarLen(self.ack_delay).encode(buf);
        VarLen((self.blocks.len() - 1) as u64).encode(buf);
        for ack in self.blocks.iter() {
            VarLen(ack.value()).encode(buf);
        }
    }

    fn decode<T: Buf>(buf: &mut T) -> Self {
        let _ = buf.get_u8();
        let largest = VarLen::decode(buf).0 as u32;
        let ack_delay = VarLen::decode(buf).0;
        let count = VarLen::decode(buf).0;
        debug_assert_eq!(count % 2, 0);

        let mut blocks = vec![];
        for i in 0..count + 1 {
            blocks.push(if i % 2 == 0 {
                Ack::Ack(VarLen::decode(buf).0)
            } else {
                Ack::Gap(VarLen::decode(buf).0)
            });
        }

        AckFrame {
            largest,
            ack_delay,
            blocks,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Ack {
    Ack(u64),
    Gap(u64),
}

impl Ack {
    fn value(&self) -> u64 {
        match *self {
            Ack::Ack(v) => v,
            Ack::Gap(v) => v,
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

#[cfg(test)]
mod tests {
    use codec::{BufLen, Codec};
    use std::io::Cursor;

    #[test]
    fn test_ack_round_trip() {
        let obj = super::Frame::Ack(super::AckFrame {
            largest: 485971334,
            ack_delay: 0,
            blocks: vec![super::Ack::Ack(0)],
        });
        let bytes = b"\x0d\x9c\xf7\x55\x86\x00\x00\x00";
        assert_eq!(obj.buf_len(), bytes.len());

        let mut buf = Vec::with_capacity(64);
        obj.encode(&mut buf);
        assert_eq!(&buf, bytes);

        let mut read = Cursor::new(bytes);
        let decoded = super::Frame::decode(&mut read);
        assert_eq!(decoded, obj);
    }
}
