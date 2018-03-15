use bytes::{Buf, BufMut, BigEndian};

#[derive(Fail, Debug, Copy, Clone, Eq, PartialEq)]
#[fail(display = "unexpected end of buffer")]
pub struct UnexpectedEnd;

pub type Result<T> = ::std::result::Result<T, UnexpectedEnd>;

pub trait Value: Sized {
    fn decode<B: Buf>(buf: &mut B) -> Result<Self>;
    fn encode<B: BufMut>(&self, buf: &mut B);
}

impl Value for u8 {
    fn decode<B: Buf>(buf: &mut B) -> Result<u8> {
        if buf.remaining() < 1 { return Err(UnexpectedEnd); }
        Ok(buf.get_u8())
    }
    fn encode<B: BufMut>(&self, buf: &mut B) { buf.put_u8(*self); }
}

impl Value for u16 {
    fn decode<B: Buf>(buf: &mut B) -> Result<u16> {
        if buf.remaining() < 2 { return Err(UnexpectedEnd); }
        Ok(buf.get_u16::<BigEndian>())
    }
    fn encode<B: BufMut>(&self, buf: &mut B) { buf.put_u16::<BigEndian>(*self); }
}

impl Value for u32 {
    fn decode<B: Buf>(buf: &mut B) -> Result<u32> {
        if buf.remaining() < 4 { return Err(UnexpectedEnd); }
        Ok(buf.get_u32::<BigEndian>())
    }
    fn encode<B: BufMut>(&self, buf: &mut B) { buf.put_u32::<BigEndian>(*self); }
}

impl Value for u64 {
    fn decode<B: Buf>(buf: &mut B) -> Result<u64> {
        if buf.remaining() < 8 { return Err(UnexpectedEnd); }
        Ok(buf.get_u64::<BigEndian>())
    }
    fn encode<B: BufMut>(&self, buf: &mut B) { buf.put_u64::<BigEndian>(*self); }
}

pub trait BufExt {
    fn get<T: Value>(&mut self) -> Result<T>;
}

impl<T: Buf> BufExt for T {
    fn get<U: Value>(&mut self) -> Result<U> {
        U::decode(self)
    }
}
