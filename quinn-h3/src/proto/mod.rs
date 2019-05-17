use bytes::BufMut;
use quinn_proto::coding::BufMutExt;

pub mod connection;
pub mod frame;
pub mod headers;

pub struct StreamType(u64);

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
}
