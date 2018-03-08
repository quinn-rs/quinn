use std::{mem, fmt, io};

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
pub struct Stream {
    pub id: StreamId,
    pub offset: u64,
    pub fin: bool,
    pub data: Bytes,
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

pub fn stream(out: &mut Vec<u8>, id: StreamId, offset: Option<u64>, length: bool, fin: bool, data: &[u8]) {
    let mut ty = 0x10;
    if offset.is_some() { ty |= 0x04; }
    if length { ty |= 0x02; }
    if fin { ty |= 0x01; }
    out.put_u8(ty);
    varint::write(id.0, out).unwrap();
    if let Some(o) = offset { varint::write(o, out).unwrap(); }
    if length { varint::write(data.len() as u64, out).unwrap(); }
    out.extend_from_slice(data);
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
