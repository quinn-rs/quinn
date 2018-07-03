use super::{QuicError, QuicResult};
use bytes::{Buf, BufMut};

pub struct VarLen(pub u64);

impl BufLen for VarLen {
    fn buf_len(&self) -> usize {
        match self.0 {
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
            1 => buf.put_u8(self.0 as u8),
            2 => buf.put_u16_be(self.0 as u16 | 16384),
            4 => buf.put_u32_be(self.0 as u32 | 2_147_483_648),
            8 => buf.put_u64_be(self.0 | 13_835_058_055_282_163_712),
            _ => panic!("impossible variable-length encoding"),
        }
    }

    fn decode<T: Buf>(buf: &mut T) -> QuicResult<Self> {
        let first = buf.get_u8();
        let be_val = first & 0x3f;
        let val = match first >> 6 {
            0 => u64::from(be_val),
            1 => u64::from(be_val) << 8 | u64::from(buf.get_u8()),
            2 => {
                u64::from(be_val) << 24
                    | u64::from(buf.get_u8()) << 16
                    | u64::from(buf.get_u16_be())
            }
            3 => {
                u64::from(be_val) << 56
                    | u64::from(buf.get_u8()) << 48
                    | u64::from(buf.get_u16_be()) << 32
                    | u64::from(buf.get_u32_be())
            }
            v => {
                return Err(QuicError::DecodeError(format!(
                    "impossible variable length encoding: {}",
                    v
                )))
            }
        };
        Ok(VarLen(val))
    }
}

pub trait BufLen {
    fn buf_len(&self) -> usize;
}

impl<T> BufLen for Option<T>
where
    T: BufLen,
{
    fn buf_len(&self) -> usize {
        match self {
            Some(v) => v.buf_len(),
            None => 0,
        }
    }
}

impl<T> BufLen for Vec<T>
where
    T: BufLen,
{
    fn buf_len(&self) -> usize {
        self.iter().map(|i| i.buf_len()).sum()
    }
}

pub trait Codec: Sized {
    // TODO q on add sized
    fn encode<T: BufMut>(&self, buf: &mut T);
    fn decode<T: Buf>(buf: &mut T) -> QuicResult<Self>;
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
        VarLen(num).encode(&mut buf);
        assert_eq!(bytes[..], *buf);

        let mut read = Cursor::new(bytes);
        assert_eq!(VarLen::decode(&mut read).expect("Invalid VarLen").0, num);
    }
    #[test]
    fn test_var_len_encoding_4() {
        let num = 494_878_333;
        let bytes = b"\x9d\x7f\x3e\x7d";

        let mut buf = Vec::new();
        VarLen(num).encode(&mut buf);
        assert_eq!(bytes[..], *buf);

        let mut read = Cursor::new(bytes);
        assert_eq!(VarLen::decode(&mut read).expect("Invalid VarLen").0, num);
    }
    #[test]
    fn test_var_len_encoding_2() {
        let num = 15_293;
        let bytes = b"\x7b\xbd";

        let mut buf = Vec::new();
        VarLen(num).encode(&mut buf);
        assert_eq!(bytes[..], *buf);

        let mut read = Cursor::new(bytes);
        assert_eq!(VarLen::decode(&mut read).expect("Invalid VarLen").0, num);
    }
    #[test]
    fn test_var_len_encoding_1_short() {
        let num = 37;
        let bytes = b"\x25";

        let mut buf = Vec::new();
        VarLen(num).encode(&mut buf);
        assert_eq!(bytes[..], *buf);

        let mut read = Cursor::new(bytes);
        assert_eq!(VarLen::decode(&mut read).expect("Invalid VarLen").0, num);
    }
}
