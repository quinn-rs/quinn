use std::{mem, fmt, io};
use std::collections::BTreeMap;

use bytes::{Bytes, BufMut};

use {varint, FromBytes, TransportError};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Type(u8);

impl From<u8> for Type { fn from(x: u8) -> Self { Type(x) } }
impl From<Type> for u8 { fn from(x: Type) -> Self { x.0 } }

impl Type {
    fn stream(&self) -> Option<StreamInfo> {
        if self.0 >= 0x10 && self.0 <= 0x17 { Some(StreamInfo(self.0)) } else { None }
    }
}

macro_rules! frame_types {
    {$($name:ident = $val:expr,)*} => {
        impl Type {
            $(pub const $name: Type = Type($val);)*
        }

        impl fmt::Display for Type {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                let x = match self.0 {
                    $($val => stringify!($name),)*
                    x if x >= 0x10 && x <= 0x17 => "STREAM",
                    _ => "<unknown>",
                };
                f.write_str(x)
            }
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct StreamInfo(u8);

impl StreamInfo {
    fn fin(&self) -> bool { self.0 & 0x01 != 0 }
    fn len(&self) -> bool { self.0 & 0x02 != 0 }
    fn off(&self) -> bool { self.0 & 0x04 != 0 }
}

frame_types!{
    PADDING = 0x00,
    RST_STREAM = 0x01,
    CONNECTION_CLOSE = 0x02,
    STOP_SENDING = 0x0c,
    ACK = 0x0d,
}

#[derive(Debug)]
pub enum Frame {
    Padding,
    RstStream {
        id: StreamId,
        app_error_code: u16,
        final_offset: u64,
    },
    ConnectionClose {
        error_code: TransportError,
        reason: Bytes,
    },
    Ack(Ack),
    Stream(Stream),
    Invalid,
}

#[derive(Debug, Clone)]
pub struct Ack {
    pub delay: u64,
    pub largest: u64,
    pub packets: AckIter
}

#[derive(Debug, Clone)]
pub struct Stream<T = Bytes> {
    pub id: StreamId,
    pub offset: u64,
    pub fin: bool,
    pub data: T,
}

impl<T> Stream<T>
    where T: AsRef<[u8]>
{
    pub fn encode<W: BufMut>(&self, length: bool, out: &mut W) {
        let mut ty = 0x10;
        if self.offset != 0 { ty |= 0x04; }
        if length { ty |= 0x02; }
        if self.fin { ty |= 0x01; }
        out.put_u8(ty);
        varint::write(self.id.0, out).unwrap();
        if self.offset != 0 { varint::write(self.offset, out).unwrap(); }
        if length { varint::write(self.data.as_ref().len() as u64, out).unwrap(); }
        out.put_slice(self.data.as_ref());
    }
}

pub struct Iter(Bytes);

impl Iter {
    pub fn new(payload: Bytes) -> Self { Iter(payload) }

    fn get_var(&mut self) -> Option<u64> {
        let (x, advance) = {
            let mut buf = io::Cursor::new(&self.0[..]);
            (varint::read(&mut buf)?, buf.position())
        };
        self.0.advance(advance as usize);
        Some(x)
    }

    fn take_len(&mut self) -> Option<Bytes> {
        let len = self.get_var()?;
        if len > self.0.len() as u64 { return None; }
        Some(self.0.split_to(len as usize))
    }

    fn get<T: FromBytes>(&mut self) -> Option<T> { T::from(&mut self.0) }

    fn try_next(&mut self) -> Option<Frame> {
        let ty = Type(self.0[0]);
        self.0.advance(1);
        Some(match ty {
            Type::PADDING => Frame::Padding,
            Type::RST_STREAM => Frame::RstStream {
                id: self.get_var()?.into(),
                app_error_code: self.get()?,
                final_offset: self.get_var()?,
            },
            Type::CONNECTION_CLOSE => Frame::ConnectionClose {
                error_code: self.get::<u16>()?.into(),
                reason: self.take_len()?,
            },
            Type::ACK => {
                let largest = self.get_var()?;
                let delay = self.get_var()?;
                Frame::Ack(Ack {
                    delay, largest,
                    packets: AckIter::new(largest, self)?,
                })
            }
            _ => match ty.stream() {
                Some(s) => Frame::Stream(Stream {
                    id: self.get_var()?.into(),
                    offset: if s.off() { self.get_var()? } else { 0 },
                    fin: s.fin(),
                    data: if s.len() { self.take_len()? } else { mem::replace(&mut self.0, Bytes::new()) }
                }),
                None => return None,
            }
        })
    }
}

impl Iterator for Iter {
    type Item = Frame;
    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() { return None; }
        match self.try_next() {
            x@Some(_) => x,
            None => {
                // Corrupt frame, skip it and everything that follows
                self.0 = Bytes::new();
                Some(Frame::Invalid)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct AckIter {
    next: u64,
    block_size: u64,
    data: Bytes,
}

impl AckIter {
    fn new(largest: u64, packet: &mut Iter) -> Option<Self> {
        let extra_blocks = packet.get_var()? + 1;
        let first_block = packet.get_var()?;
        let len = {
            let mut buf = io::Cursor::new(&packet.0[..]);
            for i in 0..extra_blocks {
                varint::read(&mut buf)?; // gap
                varint::read(&mut buf)?; // block
            }
            buf.position()
        };
        
        Some(Self {
            next: largest,
            block_size: first_block + 1,
            data: packet.0.slice(0, len as usize),
        })
    }

    pub fn peek(&self) -> Option<u64> {
        if self.block_size == 0 { None } else { Some(self.next) }
    }
}

impl Iterator for AckIter {
    type Item = u64;
    fn next(&mut self) -> Option<u64> {
        if self.block_size == 0 { return None; }
        let result = self.next;
        self.next -= 1;
        self.block_size -= 1;
        if self.block_size == 0 && !self.data.is_empty() {
            let advance = {
                let mut buf = io::Cursor::new(&self.data[..]);
                self.next -= varint::read(&mut buf).unwrap() + 1;
                self.block_size = varint::read(&mut buf).unwrap() + 1;
                buf.position()
            };
            self.data.advance(advance as usize);
        }
        Some(result)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct StreamId(pub u64);

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Side { Client, Server }

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Directionality { Uni, Bi }

impl StreamId {
    pub fn initiator(&self) -> Side { if self.0 & 0x1 == 0 { Side::Client } else { Side::Server } }
    pub fn directionality(&self) -> Directionality { if self.0 & 0x2 == 0 { Directionality::Bi } else { Directionality::Uni } }
}

impl From<u64> for StreamId { fn from(x: u64) -> Self { StreamId(x) } }

#[derive(Debug)]
pub struct StreamAssembler {
    offset: u64,
    /// (offset, data)
    segments: BTreeMap<u64, Bytes>,
}

impl StreamAssembler {
    pub fn new() -> Self { Self::with_offset(0) }
    pub fn with_offset(x: u64) -> Self { Self { offset: x, segments: BTreeMap::new() } }
    pub fn is_empty(&self) -> bool { self.segments.is_empty() }
    
    pub fn next(&mut self) -> Option<Bytes> {
        if let Some(data) = self.segments.remove(&self.offset) {
            self.offset += data.len() as u64;
            Some(data)
        } else { None }
    }

    pub fn insert(&mut self, mut offset: u64, mut data: Bytes) {
        let end_offset = if let Some((&prev_off, prev_data)) = self.segments.range(..offset).rev().next() {
            prev_off + prev_data.len() as u64
        } else {
            self.offset
        };
        if let Some(relative) = end_offset.checked_sub(offset) {
            if relative >= data.len() as u64 { return; }
            offset += relative;
            data.advance(relative as usize);
        }
        if let Some((&next_off, next_data)) = self.segments.range(offset..).next() {
            if offset == next_off { return; }
            data.truncate((next_off - offset) as usize);
        }
        self.segments.insert(offset, data);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn assemble_ordered() {
        let mut x = StreamAssembler::new();
        assert_matches!(x.next(), None);
        x.insert(0, (&b"123"[..]).into());
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"123");
        x.insert(3, (&b"456"[..]).into());
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"456");
        x.insert(6, (&b"789"[..]).into());
        x.insert(9, (&b"10"[..]).into());
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"789");
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"10");
    }

    #[test]
    fn assemble_unordered() {
        let mut x = StreamAssembler::new();
        x.insert(3, (&b"456"[..]).into());
        assert_matches!(x.next(), None);
        x.insert(0, (&b"123"[..]).into());
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"123");
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"456");
    }
}
