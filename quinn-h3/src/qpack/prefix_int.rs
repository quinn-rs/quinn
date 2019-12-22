use bytes::{Buf, BufMut};

use quinn_proto::coding::{self, BufExt, BufMutExt};

#[derive(Debug, PartialEq)]
pub enum Error {
    Overflow,
    UnexpectedEnd,
}

pub fn decode<B: Buf>(size: u8, buf: &mut B) -> Result<(u8, usize), Error> {
    assert!(size <= 8);
    let mut first = buf.get::<u8>()?;

    // NOTE: following casts to u8 intend to trim the most significant bits, they are used as a
    //       workaround for shiftoverflow errors when size == 8.
    let flags = ((first as usize) >> size) as u8;
    let mask = 0xFF >> (8 - size);
    first &= mask;

    // if first < 2usize.pow(size) - 1
    if first < mask {
        return Ok((flags, first as usize));
    }

    let mut value = mask as usize;
    let mut power = 0usize;
    loop {
        let byte = buf.get::<u8>()? as usize;
        value += (byte & 127) << power;
        power += 7;

        if byte & 128 == 0 {
            break;
        }

        if power >= MAX_POWER {
            return Err(Error::Overflow);
        }
    }

    Ok((flags, value))
}

pub fn encode<B: BufMut>(size: u8, flags: u8, value: usize, buf: &mut B) {
    assert!(size <= 8);
    // NOTE: following casts to u8 intend to trim the most significant bits, they are used as a
    //       workaround for shiftoverflow errors when size == 8.
    let mask = !(0xFF << size) as u8;
    let flags = ((flags as usize) << size) as u8;

    // if value < 2usize.pow(size) - 1
    if value < (mask as usize) {
        buf.write(flags | value as u8);
        return;
    }

    buf.write(mask | flags);
    let mut remaining = value - mask as usize;

    while remaining >= 128 {
        let rest = (remaining % 128) as u8;
        buf.write(rest + 128);
        remaining /= 128;
    }
    buf.write(remaining as u8);
}

#[cfg(target_pointer_width = "64")]
const MAX_POWER: usize = 10 * 7;

#[cfg(target_pointer_width = "32")]
const MAX_POWER: usize = 5 * 7;

impl From<coding::UnexpectedEnd> for Error {
    fn from(_: coding::UnexpectedEnd) -> Self {
        Error::UnexpectedEnd
    }
}

#[cfg(test)]
mod test {
    use std::io::Cursor;

    fn check_codec(size: u8, flags: u8, value: usize, data: &[u8]) {
        let mut buf = Vec::new();
        super::encode(size, flags, value, &mut buf);
        assert_eq!(buf, data);
        let mut read = Cursor::new(&buf);
        assert_eq!((flags, value), super::decode(size, &mut read).unwrap());
    }

    #[test]
    fn codec_5_bits() {
        check_codec(5, 0b101, 10, &[0b1010_1010]);
        check_codec(5, 0b101, 0, &[0b1010_0000]);
        check_codec(5, 0b010, 1337, &[0b0101_1111, 154, 10]);
        check_codec(5, 0b010, 31, &[0b0101_1111, 0]);
        check_codec(
            5,
            0b010,
            usize::max_value(),
            &[95, 224, 255, 255, 255, 255, 255, 255, 255, 255, 1],
        );
    }

    #[test]
    fn codec_8_bits() {
        check_codec(8, 0, 42, &[0b0010_1010]);
        check_codec(8, 0, 424_242, &[255, 179, 240, 25]);
        check_codec(
            8,
            0,
            usize::max_value(),
            &[255, 128, 254, 255, 255, 255, 255, 255, 255, 255, 1],
        );
    }

    #[test]
    #[should_panic]
    fn size_too_big_value() {
        let mut buf = vec![];
        super::encode(9, 1, 1, &mut buf);
    }

    #[test]
    #[should_panic]
    fn size_too_big_of_size() {
        let buf = vec![];
        let mut read = Cursor::new(&buf);
        super::decode(9, &mut read).unwrap();
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn overflow() {
        let buf = vec![255, 128, 254, 255, 255, 255, 255, 255, 255, 255, 255, 1];
        let mut read = Cursor::new(&buf);
        assert!(super::decode(8, &mut read).is_err());
    }

    #[test]
    fn number_never_ends_with_0x80() {
        check_codec(4, 0b0001, 143, &[31, 128, 1]);
    }
}
