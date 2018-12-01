use bytes::{Buf, BufMut};

use byteorder::{BigEndian, ByteOrder};

pub fn size(x: u64) -> Option<usize> {
    if x < 2u64.pow(6) {
        Some(1)
    } else if x < 2u64.pow(14) {
        Some(2)
    } else if x < 2u64.pow(30) {
        Some(4)
    } else if x < 2u64.pow(62) {
        Some(8)
    } else {
        None
    }
}

pub fn read<R: Buf>(r: &mut R) -> Option<u64> {
    if !r.has_remaining() {
        return None;
    }
    let mut buf = [0; 8];
    buf[0] = r.get_u8();
    let tag = buf[0] >> 6;
    buf[0] &= 0b0011_1111;
    Some(match tag {
        0b00 => buf[0] as u64,
        0b01 => {
            if r.remaining() < 1 {
                return None;
            }
            r.copy_to_slice(&mut buf[1..2]);
            BigEndian::read_u16(&buf) as u64
        }
        0b10 => {
            if r.remaining() < 3 {
                return None;
            }
            r.copy_to_slice(&mut buf[1..4]);
            BigEndian::read_u32(&buf) as u64
        }
        0b11 => {
            if r.remaining() < 7 {
                return None;
            }
            r.copy_to_slice(&mut buf[1..8]);
            BigEndian::read_u64(&buf) as u64
        }
        _ => unreachable!(),
    })
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Fail)]
pub enum WriteError {
    #[fail(display = "insufficient space to encode value")]
    InsufficientSpace,
    #[fail(display = "value too large for varint encoding")]
    OversizedValue,
}

pub fn write<W: BufMut>(x: u64, w: &mut W) -> Result<(), WriteError> {
    if x < 2u64.pow(6) {
        if w.remaining_mut() < 1 {
            return Err(WriteError::InsufficientSpace);
        }
        w.put_u8(x as u8);
    } else if x < 2u64.pow(14) {
        if w.remaining_mut() < 2 {
            return Err(WriteError::InsufficientSpace);
        }
        w.put_u16_be(0b01 << 14 | x as u16);
    } else if x < 2u64.pow(30) {
        if w.remaining_mut() < 4 {
            return Err(WriteError::InsufficientSpace);
        }
        w.put_u32_be(0b10 << 30 | x as u32);
    } else if x < 2u64.pow(62) {
        if w.remaining_mut() < 8 {
            return Err(WriteError::InsufficientSpace);
        }
        w.put_u64_be(0b11 << 62 | x);
    } else {
        return Err(WriteError::OversizedValue);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io;
    use std::u64;

    #[test]
    fn sizes() {
        assert_eq!(size(0), Some(1));
        assert_eq!(size(63), Some(1));

        assert_eq!(size(64), Some(2));
        assert_eq!(size(16383), Some(2));

        assert_eq!(size(16384), Some(4));
        assert_eq!(size(1_073_741_823), Some(4));

        assert_eq!(size(1_073_741_824), Some(8));
        assert_eq!(size(4_611_686_018_427_387_903), Some(8));

        assert_eq!(size(4_611_686_018_427_387_904), None);
        assert_eq!(size(u64::MAX), None);
    }

    /// Encodes the `$num` argument into a big-endian byte slice and verifies it reads correctly.
    macro_rules! assert_read_good {
        ($num:expr, $tag:expr) => {
            let mut buf = $num.to_be_bytes();
            buf[0] |= $tag;
            let mut buf = io::Cursor::new(buf);
            assert_eq!(read(&mut buf), Some(u64::from($num)));
        };
        ($num:expr => one octet) => {
            assert_read_good!(u8::from($num), 0b0000_0000)
        };
        ($num:expr => two octets) => {
            assert_read_good!(u16::from($num), 0b0100_0000)
        };
        ($num:expr => four octets) => {
            assert_read_good!(u32::from($num), 0b1000_0000)
        };
        ($num:expr => eight octets) => {
            assert_read_good!(u64::from($num), 0b1100_0000)
        };
    }

    /// Encodes the `$num` argument into a big-endian byte slice and verifies it doesn't read
    /// correctly from a partial byte slice.
    macro_rules! assert_read_bad {
        ($num:expr, $tag:expr, $range:expr) => {
            let mut buf = $num.to_be_bytes();
            buf[0] |= $tag;
            let mut buf = io::Cursor::new(&buf[$range]);
            assert_eq!(read(&mut buf), None);
        };
        ($num:expr => two octets) => {
            assert_read_bad!(u16::from($num), 0b0100_0000, ..1)
        };
        ($num:expr => four octets) => {
            assert_read_bad!(u32::from($num), 0b1000_0000, ..3)
        };
        ($num:expr => eight octets) => {
            assert_read_bad!(u64::from($num), 0b1100_0000, ..7)
        };
    }

    macro_rules! assert_read {
        ($num:expr => one octet) => {
            assert_read_good!($num => one octet);
        };
        ($num:expr => two octets) => {
            assert_read_good!($num => two octets);
            assert_read_bad!($num => two octets);
        };
        ($num:expr => four octets) => {
            assert_read_good!($num => four octets);
            assert_read_bad!($num => four octets);
        };
        ($num:expr => eight octets) => {
            assert_read_good!($num => eight octets);
            assert_read_bad!($num => eight octets);
        };
    }

    #[test]
    #[allow(clippy::cyclomatic_complexity)]
    fn reads() {
        assert_read!(0_u8 => one octet);
        assert_read!(1_u8 => one octet);
        assert_read!(63_u8 => one octet);

        assert_read!(0_u8 => two octets);
        assert_read!(1_u8 => two octets);
        assert_read!(63_u8 => two octets);
        assert_read!(64_u8 => two octets);
        assert_read!(255_u8 => two octets);
        assert_read!(256_u16 => two octets);
        assert_read!(16383_u16 => two octets);

        assert_read!(0_u8 => four octets);
        assert_read!(1_u8 => four octets);
        assert_read!(63_u8 => four octets);
        assert_read!(64_u8 => four octets);
        assert_read!(255_u8 => four octets);
        assert_read!(256_u16 => four octets);
        assert_read!(16383_u16 => four octets);
        assert_read!(16384_u16 => four octets);
        assert_read!(65535_u16 => four octets);
        assert_read!(65536_u32 => four octets);
        assert_read!(1_073_741_823_u32 => four octets);

        assert_read!(0_u8 => eight octets);
        assert_read!(1_u8 => eight octets);
        assert_read!(63_u8 => eight octets);
        assert_read!(64_u8 => eight octets);
        assert_read!(255_u8 => eight octets);
        assert_read!(256_u16 => eight octets);
        assert_read!(16383_u16 => eight octets);
        assert_read!(16384_u16 => eight octets);
        assert_read!(65535_u16 => eight octets);
        assert_read!(65536_u32 => eight octets);
        assert_read!(1_073_741_823_u32 => eight octets);
        assert_read!(1_073_741_824_u32 => eight octets);
        assert_read!(0xFFFF_FFFF_u32 => eight octets);
        assert_read!(0x1_0000_0000_u64 => eight octets);
        assert_read!(0x3FFF_FFFF_FFFF_FFFF_u64 => eight octets);
    }
}
