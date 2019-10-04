use bytes::{Buf, BufMut, Bytes, BytesMut};
use quinn_proto::{
    coding::{BufExt, BufMutExt, UnexpectedEnd},
    VarInt,
};

pub mod connection;
pub mod frame;
pub mod headers;

#[derive(Debug, PartialEq, Eq)]
pub struct StreamType(pub u64);

macro_rules! stream_types {
    {$($name:ident = $val:expr,)*} => {
        impl StreamType {
            $(pub const $name: StreamType = StreamType($val);)*
        }
    }
}

stream_types! {
    CONTROL = 0x00,
    PUSH = 0x01,
    ENCODER = 0x02,
    DECODER = 0x03,
}

impl StreamType {
    pub fn encode<W: BufMut>(&self, buf: &mut W) {
        buf.write_var(self.0);
    }

    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, UnexpectedEnd> {
        Ok(StreamType(buf.get_var()?))
    }

    pub fn encoded(&self) -> Bytes {
        let var_int = VarInt::from(self.0 as u32);
        let mut buf = BytesMut::with_capacity(var_int.size());
        self.encode(&mut buf);
        buf.freeze()
    }
}
