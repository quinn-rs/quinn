// This is only here because qpack is new and quinn no uses it yet.
// TODO remove allow dead code
#![allow(dead_code)]

use std::borrow::Cow;
use std::io::{Write, Cursor, Error as IoError, ErrorKind};

use super::iocontext::StarterByte;
use super::string::{HpackStringEncode, HuffmanEncodingError};


#[derive(Debug)]
pub enum Error {
    IoError(IoError),
    InvalidHuffmanStringEncoding(HuffmanEncodingError)
}


pub enum StringEncoding {
    NoEncoding,
    HuffmanEncoding
}



pub struct Dump<'a> {
    buf: &'a mut Write
}


impl<'a> Dump<'a> {

    pub fn new<T: Write>(buf: &'a mut T) -> Dump<'a> {
        Dump { buf }
    }

    fn put_byte<T>(&mut self, byte: T) 
        -> Result<(), Error> where T: Into<u8> {
        let bytes: [u8; 1] = [ byte.into() ];
        self.buf.write(&bytes).map(|_| ())
            .map_err(|x| Error::IoError(x))
    }

    pub fn integer(&mut self, value: usize, starter: StarterByte) 
        -> Result<(), Error> 
    {
        if value < starter.mask {
            let first_byte = starter.safe_start();
            self.put_byte((first_byte | value) as u8)
        } else {
            self.var_len_integer(value, starter)
        }
    }

    fn var_len_integer(&mut self, value: usize, starter: StarterByte) 
        -> Result<(), Error> 
    {
        let first_byte = starter.safe_start() | starter.mask;
        let _ = self.put_byte(first_byte as u8)?;
        let mut value = value - starter.mask;

        while value >= 128 {
            let rest = value % 128;
            let _ = self.put_byte(128 + rest as u8)?;
            value /= 128;
        }
        
        self.put_byte(value as u8)
    }

    pub fn string<T>(&mut self, value: T, starter: StarterByte) 
        -> Result<(), Error> 
        where T: Into<Cow<'a, [u8]>>,
    {
        self.string_with_encoding(value, StringEncoding::NoEncoding, starter)
    }
    
    pub fn string_with_encoding<T>(
        &mut self, 
        value: T, 
        encoding: StringEncoding,
        starter: StarterByte
        ) -> Result<(), Error> 
        where T: Into<Cow<'a, [u8]>>,
    {
        let input = value.into();

        if starter.prefix > 1 {
            let mut first_byte = starter.safe_start();
            if let StringEncoding::HuffmanEncoding = encoding {
                let bit = 2usize.pow(starter.prefix as u32 - 1) as usize;
                first_byte |= bit;
            }
            
            let _ = self.integer(
                input.len(),
                StarterByte::valued(starter.prefix - 1, first_byte)
                .expect("valid starter byte"))?;
        }
        // Corner case where ]x x x x x x x H]  where x: taken
        // huffman flag is the last bit, so size must be written afterwards
        else {
            let mut first_byte = starter.safe_start();
            if let StringEncoding::HuffmanEncoding = encoding {
                first_byte |= 1;
            }
            
            let _ = self.put_byte(first_byte as u8)?;
            let _ = self.integer(input.len(), StarterByte::noprefix())?;
        }

        match encoding {
            StringEncoding::NoEncoding =>
                self.buf.write(&input[..])
                .map_err(|x| Error::IoError(x))
                .map(|_| ()),
            StringEncoding::HuffmanEncoding => {
                let encoded = match input {
                    // NOTE: At the moment, input must be a Vec so copy is made
                    // if necessary.
                    // It uses underling 'bitlab' crate to manipulate 
                    // individual bits, but it only works on Vec and not 
                    // on slice or array. 
                    Cow::Borrowed(borrowed) =>
                        borrowed.to_owned().hpack_encode()
                        .map_err(|x| Error::InvalidHuffmanStringEncoding(x))?,
                    Cow::Owned(owned) =>
                        owned.hpack_encode()
                        .map_err(|x| Error::InvalidHuffmanStringEncoding(x))?
                };
                
                self.buf.write(&encoded[..])
                    .map_err(|x| Error::IoError(x))
                    .map(|_| ())
            }
        }
        
    }

}


#[cfg(test)]
mod tests {
    use super::*;

    /**
     * https://tools.ietf.org/html/rfc7541
     * 5.1.  Integer Representation
     * 
     * C.1.1.  Example 1: Encoding 10 Using a 5-Bit Prefix
     */
    #[test]
    fn test_write_integer_fit_in_prefix() {
        let value = 10;
        let starter = StarterByte::prefixed(5)
            .expect("valid starter byte");
        let expected: [u8; 1] = [ 10 ];

        let mut bytes = Vec::new();
        {
            let mut cursor = Cursor::new(&mut bytes);
            let mut dump = Dump::new(&mut cursor);
            assert!(dump.integer(value, starter).is_ok());
        }

        assert_eq!(bytes.as_slice(), expected);
    }
    
    /**
     * https://tools.ietf.org/html/rfc7541
     * 5.1.  Integer Representation
     * 
     * C.1.2.  Example 2: Encoding 1337 Using a 5-Bit Prefix
     */
    #[test]
    fn test_write_var_len_integer() {
        let value = 1337;
        let starter = StarterByte::prefixed(5)
            .expect("valid starter byte");
        let expected: [u8; 3] = [ 31, 154, 10 ];

        let mut bytes = Vec::new();
        {
            let mut cursor = Cursor::new(&mut bytes);
            let mut dump = Dump::new(&mut cursor);
            assert!(dump.integer(value, starter).is_ok());
        }

        assert_eq!(bytes.as_slice(), expected);
    }
    
    #[test]
    fn test_write_integer_not_starting_at_byte_boundary() {
        let value = 10;
        let starter = StarterByte::valued(5, 128 + 64)
            .expect("valid starter byte");
        let expected: [u8; 1] = [ 128 + 64 | 10 ];

        let mut bytes = Vec::new();
        {
            let mut cursor = Cursor::new(&mut bytes);
            let mut dump = Dump::new(&mut cursor);
            assert!(dump.integer(value, starter).is_ok());
        }

        assert_eq!(bytes.as_slice(), expected);
    }
    
    /**
     * https://tools.ietf.org/html/rfc7541
     * 5.2.  String Literal Representation
     */
    #[test]
    fn test_write_ascii_string() {
        let text = b"Testing ascii";
        let starter = StarterByte::noprefix();
        let expected: [u8; 14] = [
            // not huffman, size
            0 | 13,
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

        let mut bytes = Vec::new();
        {
            let mut cursor = Cursor::new(&mut bytes);
            let mut dump = Dump::new(&mut cursor);
            let res = dump.string(&text[..], starter);
            assert!(res.is_ok());
        }

        assert_eq!(bytes.as_slice(), expected);
    }

    /**
     * https://tools.ietf.org/html/rfc7541
     * 5.2.  String Literal Representation
     */
    #[test]
    fn test_write_empty_string() {
        let text = b"";
        let starter = StarterByte::noprefix();
        let expected: [u8; 1] = [
            0 | 0 // not huffman, size
        ];

        let mut bytes = Vec::new();
        {
            let mut cursor = Cursor::new(&mut bytes);
            let mut dump = Dump::new(&mut cursor);
            let res = dump.string(&text[..], starter);
            assert!(res.is_ok());
        }

        assert_eq!(bytes.as_slice(), expected);
    }
    
    #[test]
    fn test_write_ascii_string_not_starting_at_byte_boundary() {
        let text = b"Aaa";
        let starter = StarterByte::valued(5, 128 + 32)
            .expect("valid starter byte");
        let expected: [u8; 4] = [
            // first byte, not huffman, size
            128 + 32 | 0 | 3,
            // bytes
            'A' as u8,
            'a' as u8,
            'a' as u8
        ];

        let mut bytes = Vec::new();
        {
            let mut cursor = Cursor::new(&mut bytes);
            let mut dump = Dump::new(&mut cursor);
            let res = dump.string(&text[..], starter);
            assert!(res.is_ok());
        }

        assert_eq!(bytes.as_slice(), expected);
    }

    #[test]
    fn test_write_string_with_huffman_flag_and_size_on_different_byte() {
        let text = b"Aaa";
        let starter = StarterByte::prefixed(1)
            .expect("valid starter byte");
        let expected: [u8; 5] = [
            // huffman
            1,
            // size
            3,
            // bytes
            (0b100001 << 2) | 0b00,
            (0b011 << 5) | 0b00011,
            255
        ];

        let mut bytes = Vec::new();
        {
            let mut cursor = Cursor::new(&mut bytes);
            let mut dump = Dump::new(&mut cursor);
            let res = dump.string_with_encoding(
                &text[..], StringEncoding::HuffmanEncoding, starter);
            assert!(res.is_ok());
        }

        assert_eq!(bytes.as_slice(), expected);
    }


}
