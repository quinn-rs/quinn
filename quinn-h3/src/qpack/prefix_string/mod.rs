mod bitwin;
mod decode;
mod encode;

pub use self::bitwin::BitWindow;

pub use self::{
    decode::{DecodeIter, Error as HuffmanDecodingError, HpackStringDecode},
    encode::{Error as HuffmanEncodingError, HpackStringEncode},
};

use crate::qpack::prefix_int::{self, Error as IntegerError};
use bytes::{buf::ext::BufExt, Buf, BufMut};
use quinn_proto::coding::BufMutExt;

#[derive(Debug, PartialEq)]
pub enum Error {
    UnexpectedEnd,
    Integer(IntegerError),
    HuffmanDecoding(HuffmanDecodingError),
    HuffmanEncoding(HuffmanEncodingError),
}

pub fn decode<B: Buf>(size: u8, buf: &mut B) -> Result<Vec<u8>, Error> {
    let (flags, len) = prefix_int::decode(size - 1, buf)?;
    if buf.remaining() < len {
        return Err(Error::UnexpectedEnd);
    }

    let payload = buf.take(len).to_bytes();
    let value = if flags & 1 == 0 {
        payload.into_iter().collect()
    } else {
        let mut decoded = Vec::new();
        for byte in payload.into_iter().collect::<Vec<u8>>().hpack_decode() {
            decoded.push(byte?);
        }
        decoded
    };
    Ok(value)
}

pub fn encode<B: BufMut>(size: u8, flags: u8, value: &[u8], buf: &mut B) -> Result<(), Error> {
    let encoded = Vec::from(value).hpack_encode()?;
    prefix_int::encode(size - 1, flags << 1 | 1, encoded.len(), buf);
    for byte in encoded {
        buf.write(byte);
    }
    Ok(())
}

impl From<HuffmanEncodingError> for Error {
    fn from(error: HuffmanEncodingError) -> Self {
        Error::HuffmanEncoding(error)
    }
}

impl From<IntegerError> for Error {
    fn from(error: IntegerError) -> Self {
        match error {
            IntegerError::UnexpectedEnd => Error::UnexpectedEnd,
            e => Error::Integer(e),
        }
    }
}

impl From<HuffmanDecodingError> for Error {
    fn from(error: HuffmanDecodingError) -> Self {
        Error::HuffmanDecoding(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn codec_6() {
        let mut buf = Vec::new();
        encode(6, 0b01, b"name without ref", &mut buf).unwrap();
        let mut read = Cursor::new(&buf);
        assert_eq!(
            &buf,
            &[
                0b0110_1100,
                168,
                116,
                149,
                79,
                6,
                76,
                231,
                181,
                42,
                88,
                89,
                127
            ]
        );
        assert_eq!(decode(6, &mut read).unwrap(), b"name without ref");
    }

    #[test]
    fn codec_8() {
        let mut buf = Vec::new();
        encode(8, 0b01, b"name with ref", &mut buf).unwrap();
        let mut read = Cursor::new(&buf);
        assert_eq!(
            &buf,
            &[0b100_01010, 168, 116, 149, 79, 6, 76, 234, 88, 89, 127]
        );
        assert_eq!(decode(8, &mut read).unwrap(), b"name with ref");
    }

    #[test]
    fn codec_8_empty() {
        let mut buf = Vec::new();
        encode(8, 0b01, b"", &mut buf).unwrap();
        let mut read = Cursor::new(&buf);
        assert_eq!(&buf, &[0b100_00000]);
        assert_eq!(decode(8, &mut read).unwrap(), b"");
    }

    #[test]
    fn decode_non_huffman() {
        let buf = vec![0b0100_0011, b'b', b'a', b'r'];
        let mut read = Cursor::new(&buf);
        assert_eq!(decode(6, &mut read).unwrap(), b"bar");
    }

    #[test]
    fn decode_too_short() {
        let buf = vec![0b0100_0011, b'b', b'a'];
        let mut read = Cursor::new(&buf);
        assert_matches!(decode(6, &mut read), Err(Error::UnexpectedEnd));
    }
}
