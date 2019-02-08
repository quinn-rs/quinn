#[macro_use]
extern crate lazy_static;

#[cfg(test)]
#[macro_use]
extern crate proptest;

#[cfg(test)]
#[macro_use]
extern crate assert_matches;

extern crate quinn_proto;
pub mod frame;
pub mod qpack;

use bytes::BufMut;
use quinn_proto::coding::Codec;

pub struct StreamType(u8);

macro_rules! stream_types {
    {$($name:ident = $val:expr,)*} => {
        impl StreamType {
            $(pub const $name: StreamType = StreamType($val);)*
        }
    }
}

stream_types! {
    CONTROL = b'C',
    PUSH = b'P',
    ENCODER = b'H',
    DECODER = b'h',
}

impl StreamType {
    pub fn encode<W: BufMut>(&self, buf: &mut W) {
        self.0.encode(buf);
    }
}
