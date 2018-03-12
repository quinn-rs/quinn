use std::{mem, fmt, io};
use std::collections::{BTreeMap, BinaryHeap};

use bytes::{Bytes, Buf, BufMut, BigEndian};

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
    APPLICATION_CLOSE = 0x03,
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
    ConnectionClose(ConnectionClose),
    ApplicationClose(ApplicationClose),
    Ack(Ack),
    Stream(Stream),
    Invalid,
}

#[derive(Debug, Clone)]
pub struct ConnectionClose<T = Bytes> {
    pub error_code: TransportError,
    pub reason: T,
}

impl<T> fmt::Display for ConnectionClose<T>
    where T: AsRef<[u8]>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.error_code.fmt(f)?;
        if !self.reason.as_ref().is_empty() {
            f.write_str(": ")?;
            f.write_str(&String::from_utf8_lossy(self.reason.as_ref()))?;
        }
        Ok(())
    }
}

impl From<TransportError> for ConnectionClose {
    fn from(x: TransportError) -> Self { ConnectionClose { error_code: x, reason: Bytes::new() } }
}

impl<T> ConnectionClose<T>
    where T: AsRef<[u8]>
{
    pub fn encode<W: BufMut>(&self, out: &mut W) {
        out.put_u8(Type::CONNECTION_CLOSE.into());
        out.put_u16::<BigEndian>(self.error_code.into());
        varint::write(self.reason.as_ref().len() as u64, out).unwrap();
        out.put_slice(self.reason.as_ref());
    }
}

#[derive(Debug, Clone)]
pub struct ApplicationClose<T = Bytes> {
    pub error_code: u16,
    pub reason: T,
}

impl<T> fmt::Display for ApplicationClose<T>
    where T: AsRef<[u8]>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.error_code.fmt(f)?;
        if !self.reason.as_ref().is_empty() {
            f.write_str(": ")?;
            f.write_str(&String::from_utf8_lossy(self.reason.as_ref()))?;
        }
        Ok(())
    }
}

impl<T> ApplicationClose<T>
    where T: AsRef<[u8]>
{
    pub fn encode<W: BufMut>(&self, out: &mut W) {
        out.put_u8(Type::APPLICATION_CLOSE.into());
        out.put_u16::<BigEndian>(self.error_code.into());
        varint::write(self.reason.as_ref().len() as u64, out).unwrap();
        out.put_slice(self.reason.as_ref());
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Ack {
    pub largest: u64,
    pub delay: u64,
    pub additional: Bytes,
}

impl<'a> IntoIterator for &'a Ack {
    type Item = u64;
    type IntoIter = AckIter<'a>;

    fn into_iter(self) -> AckIter<'a> {
        AckIter::new(self.largest, &self.additional[..])
    }
}

impl Ack {
    pub fn new<T>(delay: u64, packets: T) -> Option<Self>
        where T: IntoIterator<Item = u64>
    {
        let mut heap = packets.into_iter().collect::<BinaryHeap<u64>>();
        let largest = heap.pop()?;
        let mut buf = Vec::new();
        Self::write_additional(largest, heap, &mut buf);
        Some(Self { largest, delay, additional: buf.into() })
    }

    pub fn encode<W: BufMut>(&self, buf: &mut W) {
        buf.put_u8(Type::ACK.into());
        varint::write(self.largest, buf).unwrap();
        varint::write(self.delay, buf).unwrap();
        let mut count = 0;
        let mut cursor = io::Cursor::new(&self.additional[..]);
        varint::read(&mut cursor).unwrap();
        while cursor.has_remaining() {
            varint::read(&mut cursor).unwrap();
            varint::read(&mut cursor).unwrap();
            count += 1;
        }
        varint::write(count, buf).unwrap();
        buf.put_slice(&self.additional[..]);
    }

    pub fn direct_encode<W, T>(delay: u64, packets: T, buf: &mut W) -> bool
        where W: BufMut, T: IntoIterator<Item = u64>
    {
        buf.put_u8(Type::ACK.into());
        let mut heap = packets.into_iter().collect::<BinaryHeap<u64>>();
        let largest = if let Some(x) = heap.pop() { x } else { return false; };
        varint::write(largest, buf).unwrap();
        varint::write(delay, buf).unwrap();
        varint::write(heap.len() as u64, buf).unwrap();
        Self::write_additional(largest, heap, buf);
        true
    }

    fn write_additional<W: BufMut>(largest: u64, packets: BinaryHeap<u64>, buf: &mut W) {
        let mut prev = largest;
        let mut block_size = 0;
        let packets = packets.into_sorted_vec();
        for packet in packets.into_iter().rev() {
            if prev - packet > 1 {
                varint::write(block_size, buf).unwrap(); // block
                varint::write(prev - packet - 1, buf).unwrap(); // gap
                block_size = 0;
            } else {
                block_size += 1;
            }
            prev = packet;
        }
        varint::write(block_size, buf).unwrap(); // block
    }

    pub fn iter(&self) -> AckIter { self.into_iter() }
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

    pub fn len(&self, length: bool) -> usize {
        let mut result = varint::size(self.id.0).unwrap();
        if self.offset != 0 { result += varint::size(self.offset).unwrap(); }
        if length { result += varint::size(self.data.as_ref().len() as u64).unwrap(); }
        result += self.data.as_ref().len();
        result
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
            Type::CONNECTION_CLOSE => Frame::ConnectionClose(ConnectionClose {
                error_code: self.get::<u16>()?.into(),
                reason: self.take_len()?,
            }),
            Type::APPLICATION_CLOSE => Frame::ApplicationClose(ApplicationClose {
                error_code: self.get::<u16>()?,
                reason: self.take_len()?,
            }),
            Type::ACK => {
                let largest = self.get_var()?;
                let delay = self.get_var()?;
                let extra_blocks = self.get_var()? as usize;
                let len = scan_ack_blocks(&self.0[..], extra_blocks)?;
                Frame::Ack(Ack {
                    delay, largest,
                    additional: self.0.split_to(len),
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

fn scan_ack_blocks(packet: &[u8], n: usize) -> Option<usize> {
    let mut buf = io::Cursor::new(packet);
    let _first_block = varint::read(&mut buf)?;
    for _ in 0..n {
        varint::read(&mut buf)?; // gap
        varint::read(&mut buf)?; // block
    }
    Some(buf.position() as usize)
}

#[derive(Debug, Clone)]
pub struct AckIter<'a> {
    next: u64,
    block_size: u64,
    data: io::Cursor<&'a [u8]>,
}

impl<'a> AckIter<'a> {
    fn new(largest: u64, payload: &'a [u8]) -> Self {
        let mut data = io::Cursor::new(payload);
        let first_block = varint::read(&mut data).unwrap();
        Self {
            next: largest,
            block_size: first_block + 1,
            data,
        }
    }

    pub fn peek(&self) -> Option<u64> {
        if self.block_size == 0 { None } else { Some(self.next) }
    }
}

impl<'a> Iterator for AckIter<'a> {
    type Item = u64;
    fn next(&mut self) -> Option<u64> {
        if self.block_size == 0 { return None; }
        let result = self.next;
        self.next -= 1;
        self.block_size -= 1;
        if self.block_size == 0 && self.data.has_remaining() {
            self.next -= varint::read(&mut self.data).unwrap();
            self.block_size = varint::read(&mut self.data).unwrap() + 1;
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
        let prev_end = if let Some((&prev_off, prev_data)) = self.segments.range(..offset).rev().next() {
            prev_off + prev_data.len() as u64
        } else {
            self.offset
        };
        if let Some(relative) = prev_end.checked_sub(offset) {
            if relative >= data.len() as u64 { return; }
            offset += relative;
            data.advance(relative as usize);
        }

        // For every segment we overlap:
        // - if the segment extends past our end, truncate ourselves and finish
        // - if we meet or extend past the segment's end, drop it
        // This ensures our data remains roughly as contiguous as possible.
        let mut to_drop = Vec::new();
        for (&next_off, next_data) in self.segments.range(offset..) {
            let end = offset + data.len() as u64;
            let next_end = next_off + next_data.len() as u64;
            if next_off >= end {
                // There's a gap here, so we're finished.
                break;
            } else if next_end < end {
                // The existing segment is a subset of us; discard it
                to_drop.push(next_off);
            } else if next_off == offset {
                // We are wholly contained by the existing segment; bail out.
                // Note that this can only happen on the first iteration, so to_drop is necessarily empty, so skipping
                // the cleanup is fine.
                return;
            } else {
                // We partially overlap the existing segment; truncate and finish.
                data.truncate((next_off - offset) as usize);
                break;
            }
        }
        for x in to_drop { self.segments.remove(&x); }
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
        assert_matches!(x.next(), None);
    }

    #[test]
    fn assemble_unordered() {
        let mut x = StreamAssembler::new();
        x.insert(3, (&b"456"[..]).into());
        assert_matches!(x.next(), None);
        x.insert(0, (&b"123"[..]).into());
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"123");
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"456");
        assert_matches!(x.next(), None);
    }

    #[test]
    fn assemble_duplicate() {
        let mut x = StreamAssembler::new();
        x.insert(0, (&b"123"[..]).into());
        x.insert(0, (&b"123"[..]).into());
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"123");
        assert_matches!(x.next(), None);
    }

    #[test]
    fn assemble_contained() {
        let mut x = StreamAssembler::new();
        x.insert(0, (&b"12345"[..]).into());
        x.insert(1, (&b"234"[..]).into());
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"12345");
        assert_matches!(x.next(), None);
    }

    #[test]
    fn assemble_contains() {
        let mut x = StreamAssembler::new();
        x.insert(1, (&b"234"[..]).into());
        x.insert(0, (&b"12345"[..]).into());
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"12345");
        assert_matches!(x.next(), None);
    }

    #[test]
    fn assemble_overlapping() {
        let mut x = StreamAssembler::new();
        x.insert(0, (&b"123"[..]).into());
        x.insert(1, (&b"234"[..]).into());
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"123");
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"4");
        assert_matches!(x.next(), None);
    }

    #[test]
    fn assemble_complex() {
        let mut x = StreamAssembler::new();
        x.insert(0, (&b"1"[..]).into());
        x.insert(2, (&b"3"[..]).into());
        x.insert(4, (&b"5"[..]).into());
        x.insert(0, (&b"123456"[..]).into());
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"123456");
        assert_matches!(x.next(), None);
    }

    #[test]
    fn ack() {
        let packets = [1, 2, 3, 5, 10, 11, 14];
        let ack = Ack::new(42, packets.iter().cloned()).unwrap();
        assert_eq!(&ack.additional[..], &[0, 2, 1, 4, 0, 1, 2]);
        assert_eq!(&ack.iter().collect::<BinaryHeap<u64>>().into_sorted_vec(), &packets);
        let mut buf = Vec::new();
        ack.encode(&mut buf);
        let frames = Iter::new(Bytes::from(buf)).collect::<Vec<_>>();
        assert_matches!(frames[0], Frame::Ack(ref x));
        if let Frame::Ack(ref x) = frames[0] {
            assert_eq!(x, &ack);
        }
    }
}
