use std::{mem, fmt};

use bytes::{Bytes, IntoBuf, BufMut};

use {varint, FromBytes};

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
}

#[derive(Debug)]
pub enum Frame {
    Padding,
    RstStream {
        id: u64,
        app_error_code: u16,
        final_offset: u64,
    },
    ConnectionClose {
        error_code: u16,
        reason: Bytes,
    },
    Stream {
        id: u64,
        offset: Option<u64>,
        fin: bool,
        data: Bytes,
    },
    Invalid,
}

pub struct Iter(Bytes);

impl Iter {
    pub fn new(payload: Bytes) -> Self { Iter(payload) }

    fn get_var(&mut self) -> Option<u64> {
        let mut buf = self.0.clone().into_buf();
        let x: u64 = varint::read(&mut buf)?;
        self.0.advance(buf.position() as usize);
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
                id: self.get_var()?,
                app_error_code: self.get()?,
                final_offset: self.get_var()?,
            },
            Type::CONNECTION_CLOSE => Frame::ConnectionClose {
                error_code: self.get()?,
                reason: self.take_len()?,
            },
            _ => match ty.stream() {
                Some(s) => Frame::Stream {
                    id: self.get_var()?,
                    offset: if s.off() { Some(self.get_var()?) } else { None },
                    fin: s.fin(),
                    data: if s.len() { self.take_len()? } else { mem::replace(&mut self.0, Bytes::new()) }
                },
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

pub fn stream(out: &mut Vec<u8>, id: u64, offset: Option<u64>, length: bool, fin: bool, data: &[u8]) {
    let mut ty = 0x10;
    if offset.is_some() { ty |= 0x04; }
    if length { ty |= 0x02; }
    if fin { ty |= 0x01; }
    out.put_u8(ty);
    varint::write(id, out).unwrap();
    if let Some(o) = offset { varint::write(o, out).unwrap(); }
    if length { varint::write(data.len() as u64, out).unwrap(); }
    out.extend_from_slice(data);
}
