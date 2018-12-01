use bytes::{Buf, BufMut};

//  +------+--------+-------------+-----------------------+
//  | 2Bit | Length | Usable Bits | Range                 |
//  +------+--------+-------------+-----------------------+
//  | 00   | 1      | 6           | 0-63                  |
//  |      |        |             |                       |
//  | 01   | 2      | 14          | 0-16383               |
//  |      |        |             |                       |
//  | 10   | 4      | 30          | 0-1073741823          |
//  |      |        |             |                       |
//  | 11   | 8      | 62          | 0-4611686018427387903 |
//  +------+--------+-------------+-----------------------+

const ONE_OCTET_MAX: u64 = 63;
const TWO_OCTETS_MIN: u64 = ONE_OCTET_MAX + 1;
const TWO_OCTETS_MAX: u64 = 16383;
const FOUR_OCTETS_MIN: u64 = TWO_OCTETS_MAX + 1;
const FOUR_OCTETS_MAX: u64 = 1_073_741_823;
const EIGHT_OCTETS_MIN: u64 = FOUR_OCTETS_MAX + 1;
const EIGHT_OCTETS_MAX: u64 = 4_611_686_018_427_387_903;

const TAG_MASK: u8 = 0b1100_0000;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Tag {
    One = 0b0000_0000,
    Two = 0b0100_0000,
    Four = 0b1000_0000,
    Eight = 0b1100_0000,
}

impl From<Tag> for u8 {
    fn from(tag: Tag) -> Self {
        tag as Self
    }
}

impl From<Tag> for u16 {
    fn from(tag: Tag) -> Self {
        (tag as Self) << 8
    }
}

impl From<Tag> for u32 {
    fn from(tag: Tag) -> Self {
        (tag as Self) << 24
    }
}

impl From<Tag> for u64 {
    fn from(tag: Tag) -> Self {
        (tag as Self) << 56
    }
}

impl From<u8> for Tag {
    fn from(raw: u8) -> Self {
        match raw & TAG_MASK {
            0b0000_0000 => Tag::One,
            0b0100_0000 => Tag::Two,
            0b1000_0000 => Tag::Four,
            0b1100_0000 => Tag::Eight,
            _ => unreachable!(),
        }
    }
}

pub fn size(x: u64) -> Option<usize> {
    match x {
        0...ONE_OCTET_MAX => Some(1),
        TWO_OCTETS_MIN...TWO_OCTETS_MAX => Some(2),
        FOUR_OCTETS_MIN...FOUR_OCTETS_MAX => Some(4),
        EIGHT_OCTETS_MIN...EIGHT_OCTETS_MAX => Some(8),
        _ => None,
    }
}

pub fn read<R: Buf>(r: &mut R) -> Option<u64> {
    if !r.has_remaining() {
        return None;
    }

    let tag = r.bytes()[0].into();
    match tag {
        Tag::One => Some(r.get_u8() as u64),
        Tag::Two if r.remaining() >= 2 => Some((r.get_u16_be() as u64) & TWO_OCTETS_MAX),
        Tag::Four if r.remaining() >= 4 => Some((r.get_u32_be() as u64) & FOUR_OCTETS_MAX),
        Tag::Eight if r.remaining() >= 8 => Some(r.get_u64_be() & EIGHT_OCTETS_MAX),
        _ => None,
    }
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

    macro_rules! assert_write {
        ($num:expr) => {
            let mut buf = [0_u8; 8];
            let mut buf = io::Cursor::new(&mut buf);
            write($num, &mut buf).expect("Successful write");
            buf.set_position(0);
            assert_eq!(read(&mut buf), Some($num));
        };
    }

    #[test]
    fn writes() {
        assert_write!(0);
        assert_write!(1);
        assert_write!(63);
        assert_write!(64);
        assert_write!(255);
        assert_write!(256);
        assert_write!(16383);
        assert_write!(16384);
        assert_write!(65535);
        assert_write!(65536);
        assert_write!(1_073_741_823);
        assert_write!(1_073_741_824);
        assert_write!(0xFFFF_FFFF);
        assert_write!(0x1_0000_0000);
        assert_write!(0x3FFF_FFFF_FFFF_FFFF);
    }

    #[test]
    fn insufficient_space() {
        let mut buf = io::Cursor::new([0_u8; 1]);
        let err = write(100, &mut buf).unwrap_err();
        assert_eq!(err, WriteError::InsufficientSpace);
    }

    #[test]
    fn oversized_value() {
        let mut buf = io::Cursor::new([0_u8; 8]);
        let err = write(0x4000_0000_0000_0000, &mut buf).unwrap_err();
        assert_eq!(err, WriteError::OversizedValue);
    }
}
