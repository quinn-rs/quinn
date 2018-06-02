// This is only here because qpack is new and quinn no uses it yet.
// TODO remove allow dead code
#![allow(dead_code)]

use std::io::Cursor;
use bytes::Buf;

use super::iocontext::StarterByte;
use super::string::{HpackStringDecode, Error as HuffmanEncodingError};


#[derive(Debug, PartialEq)]
pub enum Error {
    NoByteForIntegerLength,
    TooShortBufferForInteger,
    NoByteForStringLength,
    TooShortBufferForString(usize),
    InvalidHuffmanStringEncoding(HuffmanEncodingError)
}


pub struct Parser<'a> {
    buf: &'a mut Buf
}


impl<'a> Parser<'a> {

    pub fn new<T: Buf>(buf: &'a mut T) -> Parser<'a> {
        Parser { buf }
    }

    fn next_byte(&mut self) -> Option<usize> {
        if self.buf.has_remaining() { Some(self.buf.get_u8() as usize) }
        else { None }
    }

    pub fn integer(&mut self, starter: StarterByte)
        -> Result<usize, Error>
    {
        let byte =
            starter.byte
            .or_else(|| self.next_byte())
            .ok_or(Error::NoByteForIntegerLength)?;

        if starter.mask & byte != starter.mask {
            Ok(byte & starter.mask)
        } else {
            self.var_len_integer(starter)
        }
    }

    fn var_len_integer(&mut self, starter: StarterByte)
        -> Result<usize, Error>
    {
        let mut value = starter.mask;

        let mut count = 0usize;
        loop {
            let byte = self.next_byte()
                .ok_or(Error::TooShortBufferForInteger)?;
            value += (byte & 127) * 2usize.pow(count as u32);
            count += 7;
            if byte & 128 != 128{ break; }
        }

        Ok(value)
    }

    pub fn string(&mut self, starter: StarterByte)
        -> Result<Vec<u8>, Error>
    {
        let byte =
            starter.byte
            .or_else(|| self.next_byte())
            .ok_or(Error::NoByteForIntegerLength)?;

        let huffman_bit = 1usize << (starter.prefix - 1);
        let huffman_encoded = byte & huffman_bit == huffman_bit;

        let str_len = 
            if starter.prefix > 1 {
                self.integer(
                    StarterByte::valued(starter.prefix - 1, byte)
                    .expect("valid starter byte"))?
            } 
            else { 
                // Corner case where ]x x x x x x x H]  where x: taken
                // huffman flag is the last bit, so size must be read afterwards
                self.integer(StarterByte::noprefix())? 
            };

        if self.buf.remaining() < str_len {
            let delta = str_len - self.buf.remaining();
            return Err(Error::TooShortBufferForString(delta as usize));
        }

        let mut str_bytes = Vec::new();
        (0..str_len).for_each(|_| str_bytes.push(0u8));
        self.buf.copy_to_slice(&mut str_bytes.as_mut_slice());

        if huffman_encoded {
            let decoded: Result<Vec<_>, HuffmanEncodingError> = 
                str_bytes.hpack_decode().collect();
            str_bytes = decoded.map_err(
                |x| Error::InvalidHuffmanStringEncoding(x))?;
        }

        Ok(str_bytes)
    }

}


#[cfg(test)]
mod tests {
    use super::*;


    /**
     * https://tools.ietf.org/html/rfc7541
     * 5.1.  Integer Representation
     *
     * https://tools.ietf.org/html/rfc7541
     * C.1.1.  Example 1: Encoding 10 Using a 5-Bit Prefix
     */
    #[test]
    fn test_read_integer_fit_in_prefix() {
        let bytes: [u8; 1] = [ 10u8 ];
        let value = 10;

        let mut cursor = Cursor::new(&bytes);
        let mut parser = Parser::new(&mut cursor);
        let res = parser.integer(StarterByte::prefix(7)
                                 .expect("valid starter byte"));

        assert_eq!(res, Ok(value));
    }

    /**
     * https://tools.ietf.org/html/rfc7541
     * 5.1.  Integer Representation
     *
     * https://tools.ietf.org/html/rfc7541
     * C.1.2.  Example 2: Encoding 1337 Using a 5-Bit Prefix
     */
    #[test]
    fn test_read_integer_too_large_for_prefix() {
        let bytes: [u8; 3] = [ 31, 154, 10 ];
        let value = 1337;

        let mut cursor = Cursor::new(&bytes);
        let mut parser = Parser::new(&mut cursor);
        let res = parser.integer(StarterByte::prefix(5)
                                 .expect("valid starter byte"));

        assert_eq!(res, Ok(value));
    }

    /**
     * https://tools.ietf.org/html/rfc7541
     * 5.1.  Integer Representation
     *
     * https://tools.ietf.org/html/rfc7541
     * C.1.2.  Example 2: Encoding 1337 Using a 5-Bit Prefix
     */
    #[test]
    fn test_read_invalid_var_len_integer() {
        let bytes: [u8; 2] = [ 3, 128 ];

        let mut cursor = Cursor::new(&bytes);
        let mut parser = Parser::new(&mut cursor);
        let res = parser.integer(StarterByte::prefix(2)
                                 .expect("valid starter byte"));

        assert_eq!(res, Err(Error::TooShortBufferForInteger));
    }

    #[test]
    fn test_preprefix_content_is_ditched_when_integer_fit_in_prefix() {
        let bytes: [u8; 1] = [ 128 | 57 ];
        let value = 57;

        let mut cursor = Cursor::new(&bytes);
        let mut parser = Parser::new(&mut cursor);
        let res = parser.integer(StarterByte::prefix(7)
                                 .expect("valid starter byte"));

        assert_eq!(res, Ok(value));
    }

    #[test]
    fn test_read_integer_with_ahead_byte() {
        let bytes: [u8; 1] = [ 26 ];
        let first_byte = 31;
        let value = 57;

        let mut cursor = Cursor::new(&bytes);
        let mut parser = Parser::new(&mut cursor);
        let res = parser.integer(
            StarterByte::valued(5, first_byte)
            .expect("valid starter byte"));

        assert_eq!(res, Ok(value));
    }

    /**
     * https://tools.ietf.org/html/rfc7541
     * 5.2.  String Literal Representation
     */
    #[test]
    fn test_read_ascii_string() {
        let text = "Testing ascii";
        let bytes: [u8; 14] = [
            // not huffman, size
            13,
            // bytes
            'T' as u8,
            'e' as u8,
            's' as u8,
            't' as u8,
            'i' as u8,
            'n' as u8,
            'g' as u8,
            ' ' as u8,
            'a' as u8,
            's' as u8,
            'c' as u8,
            'i' as u8,
            'i' as u8
        ];

        let mut cursor = Cursor::new(&bytes);
        let mut parser = Parser::new(&mut cursor);
        let res = parser.string(StarterByte::noprefix());

        assert_eq!(res, Ok(Vec::from(text)));
    }

    /**
     * https://tools.ietf.org/html/rfc7541
     * 5.2.  String Literal Representation
     */
    #[test]
    fn test_read_ascii_string_huffman_encoded() {
        let text = "abc";
        let bytes: [u8; 4] = [
            // huffman, size
            0b1000_0000 | 3,
            // bytes
            (0b00011 << 3) | 0b100,
            (0b011 << 5) | 0b00100,
            255
        ];

        let mut cursor = Cursor::new(&bytes);
        let mut parser = Parser::new(&mut cursor);
        let res = parser.string(StarterByte::noprefix());

        assert_eq!(res, Ok(Vec::from(text)));
    }

    /**
     * https://tools.ietf.org/html/rfc7541
     * 5.2.  String Literal Representation
     */
    #[test]
    fn test_read_empty_string() {
        let bytes: [u8; 1] = [
            // not huffman, size
            0 | 0
        ];

        let mut cursor = Cursor::new(&bytes);
        let mut parser = Parser::new(&mut cursor);
        let res = parser.string(StarterByte::noprefix());

        assert_eq!(res, Ok(Vec::new()));
    }

    #[test]
    fn test_read_string_with_huffman_flag_and_size_on_different_byte() {
        let text = "Aaa";
        let starter = StarterByte::prefix(1).expect("valid starter byte");
        let bytes: [u8; 5] = [
            // not huffman
            0,
            // size
            3,
            // bytes
            'A' as u8,
            'a' as u8,
            'a' as u8
        ];

        let mut cursor = Cursor::new(&bytes);
        let mut parser = Parser::new(&mut cursor);
        let res = parser.string(starter);

        assert_eq!(res, Ok(Vec::from(text)));
    }

    #[test]
    fn test_read_invalid_string() {
        let bytes: [u8; 2] = [
            // not huffman, size
            0 | 15, // not huffman, size
            // bytes (not enough)
            'a' as u8
        ];

        let mut cursor = Cursor::new(&bytes);
        let mut parser = Parser::new(&mut cursor);
        let res = parser.string(StarterByte::noprefix());

        assert_eq!(res, Err(Error::TooShortBufferForString(14)));
    }


}
