use bytes::Bytes;

use byteorder::{ByteOrder, BigEndian};

pub trait FromBytes {
    fn from(x: &mut Bytes) -> Option<Self>
        where Self: Sized;
}

impl FromBytes for u8 {
    fn from(bytes: &mut Bytes) -> Option<u8> {
        if bytes.len() < 1 { return None; }
        let x = bytes[0];
        bytes.advance(1);
        Some(x)
    }
}

impl FromBytes for u16 {
    fn from(bytes: &mut Bytes) -> Option<u16> {
        if bytes.len() < 2 { return None; }
        let x = BigEndian::read_u16(&bytes[0..2]);
        bytes.advance(2);
        Some(x)
    }
}

impl FromBytes for u32 {
    fn from(bytes: &mut Bytes) -> Option<u32> {
        if bytes.len() < 4 { return None; }
        let x = BigEndian::read_u32(&bytes[0..4]);
        bytes.advance(4);
        Some(x)
    }
}

impl FromBytes for u64 {
    fn from(bytes: &mut Bytes) -> Option<u64> {
        if bytes.len() < 8 { return None; }
        let x = BigEndian::read_u64(&bytes[0..8]);
        bytes.advance(8);
        Some(x)
    }
}

#[derive(Fail, Debug, Copy, Clone, Eq, PartialEq)]
#[fail(display = "too short")]
pub struct TooShort;

pub trait BytesExt {
    fn take<T: FromBytes>(&mut self) -> Result<T, TooShort>;
}

impl BytesExt for Bytes {
    fn take<T: FromBytes>(&mut self) -> Result<T, TooShort> {
        T::from(self).ok_or(TooShort)
    }
}
