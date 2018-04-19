use bytes::{BigEndian, Buf, BufMut, BytesMut};

use proto::{Header, LongType, Packet, ShortType};

use std::io;

use tokio_io::codec::{Decoder, Encoder};

struct QuicCodec {}

impl Decoder for QuicCodec {
    type Item = Packet;
    type Error = io::Error;
    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, io::Error> {
        let first = buf[0];
        let (header, _) = if first & 128 == 128 {

            let h = Header::Long {
                ptype: LongType::from_byte(first ^ 128),
                conn_id: bytes_to_u64(&buf[1..9]),
                version: bytes_to_u32(&buf[9..13]),
                number: bytes_to_u32(&buf[13..17]),
            };
            (h, 17)

        } else {

            let ptype = ShortType::from_byte(first & 7);
            let conn_id = if first & 0x40 == 0x40 {
                Some(bytes_to_u64(&buf[1..9]))
            } else {
                None
            };

            let offset = if conn_id.is_some() { 9 } else { 1 };
            let size = ptype.buf_len();
            let number = if size == 1 {
                buf[offset] as u32
            } else if size == 2 {
                (buf[offset] as u32) << 8 | (buf[offset + 1] as u32)
            } else {
                bytes_to_u32(&buf[offset..offset + 4])
            };
            let h = Header::Short {
                ptype,
                conn_id,
                key_phase: first & 0x20 == 0x20,
                number,
            };
            (h, offset + size)

        };
        Ok(Some(Packet {
            header,
            payload: Vec::new(),
        }))
    }
}

impl Encoder for QuicCodec {
    type Item = Packet;
    type Error = io::Error;
    fn encode(&mut self, msg: Self::Item, dst: &mut BytesMut) -> Result<(), io::Error> {
        let required = msg.buf_len();
        let cur_size = dst.remaining_mut();
        if cur_size < required {
            dst.reserve(required - cur_size);
        }
        Ok(())
    }
}

pub struct VarLen {
    pub val: u64,
}

impl VarLen {
    pub fn new(val: u64) -> VarLen {
        VarLen { val }
    }
}

impl BufLen for VarLen {
    fn buf_len(&self) -> usize {
        match self.val {
            v if v <= 63 => 1,
            v if v <= 16_383 => 2,
            v if v <= 1_073_741_823 => 4,
            v if v <= 4_611_686_018_427_387_903 => 8,
            v => panic!("too large for variable-length encoding: {}", v),
        }
    }
}

impl Codec for VarLen {
    fn encode<T: BufMut>(&self, buf: &mut T) {
        match self.buf_len() {
            1 => buf.put_u8(self.val as u8),
            2 => buf.put_u16::<BigEndian>(self.val as u16 | 16384),
            4 => buf.put_u32::<BigEndian>(self.val as u32 | 2_147_483_648),
            8 => buf.put_u64::<BigEndian>(self.val | 13_835_058_055_282_163_712),
            _ => panic!("impossible variable-length encoding"),
        }
    }

    fn decode<T: Buf>(buf: &mut T) -> Self {
        let first = buf.get_u8();
        let be_val = first & 0x3f;
        let val = match first >> 6 {
            0 => be_val as u64,
            1 => (be_val as u64) << 8 | (buf.get_u8() as u64),
            2 => {
                (be_val as u64) << 24 |
                (buf.get_u8() as u64) << 16 |
                (buf.get_u16::<BigEndian>() as u64)
            },
            3 => {
                (be_val as u64) << 56 |
                (buf.get_u8() as u64) << 48 |
                (buf.get_u16::<BigEndian>() as u64) << 32 |
                (buf.get_u32::<BigEndian>() as u64)
            },
            v => panic!("impossible variable length encoding: {}", v),
        };
        VarLen { val }
    }
}

fn bytes_to_u64(bytes: &[u8]) -> u64 {
    debug_assert_eq!(bytes.len(), 8);
    ((bytes[0] as u64) << 56 |
        (bytes[1] as u64) << 48 |
        (bytes[2] as u64) << 40 |
        (bytes[3] as u64) << 32 |
        (bytes[4] as u64) << 24 |
        (bytes[5] as u64) << 16 |
        (bytes[6] as u64) << 8 |
        (bytes[7] as u64))
}

fn bytes_to_u32(bytes: &[u8]) -> u32 {
    debug_assert_eq!(bytes.len(), 4);
    ((bytes[0] as u32) << 24 |
        (bytes[1] as u32) << 16 |
        (bytes[2] as u32) << 8 |
        (bytes[3] as u32))
}

pub trait BufLen {
    fn buf_len(&self) -> usize;
}

impl<T> BufLen for Option<T> where T: BufLen {
    fn buf_len(&self) -> usize {
        match *self {
            Some(ref v) => v.buf_len(),
            None => 0,
        }
    }
}

pub trait Codec {
    fn encode<T: BufMut>(&self, buf: &mut T);
    fn decode<T: Buf>(buf: &mut T) -> Self;
}

#[cfg(test)]
mod tests {
    use super::{Codec, VarLen};
    use std::io::Cursor;
    #[test]
    fn test_var_len_encoding_8() {
        let num = 151_288_809_941_952_652;
        let bytes = b"\xc2\x19\x7c\x5e\xff\x14\xe8\x8c";

        let mut buf = Vec::new();
        VarLen::new(num).encode(&mut buf);
        assert_eq!(bytes[..], *buf);

        let mut read = Cursor::new(bytes);
        assert_eq!(VarLen::decode(&mut read).val, num);
    }
    #[test]
    fn test_var_len_encoding_4() {
        let num = 494_878_333;
        let bytes = b"\x9d\x7f\x3e\x7d";

        let mut buf = Vec::new();
        VarLen::new(num).encode(&mut buf);
        assert_eq!(bytes[..], *buf);

        let mut read = Cursor::new(bytes);
        assert_eq!(VarLen::decode(&mut read).val, num);
    }
    #[test]
    fn test_var_len_encoding_2() {
        let num = 15_293;
        let bytes = b"\x7b\xbd";

        let mut buf = Vec::new();
        VarLen::new(num).encode(&mut buf);
        assert_eq!(bytes[..], *buf);

        let mut read = Cursor::new(bytes);
        assert_eq!(VarLen::decode(&mut read).val, num);
    }
    #[test]
    fn test_var_len_encoding_1_short() {
        let num = 37;
        let bytes = b"\x25";

        let mut buf = Vec::new();
        VarLen::new(num).encode(&mut buf);
        assert_eq!(bytes[..], *buf);

        let mut read = Cursor::new(bytes);
        assert_eq!(VarLen::decode(&mut read).val, num);
    }
}
