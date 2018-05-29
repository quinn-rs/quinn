// This is only here because qpack is new and quinn no uses it yet.
// TODO remove allow dead code
#![allow(dead_code)]

use std::borrow::Cow;
use std::io::{Write, Cursor, Result, Error, ErrorKind};

use super::iocontext::StarterByte;



pub struct Dump<'a> {
    buf: &'a mut Write
}


impl<'a> Dump<'a> {

    pub fn new<T: Write>(buf: &'a mut T) -> Dump<'a> {
        Dump { buf }
    }

    fn put_byte<T>(&mut self, byte: T) -> Result<()> where T: Into<u8> {
        let bytes: [u8; 1] = [ byte.into() ];
        self.buf.write(&bytes).map(|_| ())
    }

    pub fn integer(&mut self, value: usize, starter: StarterByte) 
        -> Result<()> 
    {
        if value < starter.mask {
            let first_byte = starter.safe_start();
            self.put_byte((first_byte | value) as u8)
        } else {
            self.var_len_integer(value, starter)
        }
    }

    fn var_len_integer(&mut self, value: usize, starter: StarterByte) 
        -> Result<()> 
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
        -> Result<()> 
        where T: Into<Cow<'a, [u8]>>,
    {
        let input = value.into();

        // TODO huffman encoding
        let _huffman = false;
        
        if starter.prefix > 1 {
            let mut first_byte = starter.safe_start();
            if _huffman {
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
            if _huffman {
                first_byte |= 1;
            }
            
            let _ = self.put_byte(first_byte as u8)?;
            let _ = self.integer(
                input.len(),
                StarterByte::prefix(8).expect("valid starter byte"))?;
        }
        
        self.buf.write(&input[..]).map(|_| ())
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
        let starter = StarterByte::prefix(5)
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
        let starter = StarterByte::prefix(5)
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
        let starter = StarterByte::prefix(8).expect("valid starter byte");
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
        let starter = StarterByte::prefix(8).expect("valid starter byte");
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
        let starter = StarterByte::prefix(1)
            .expect("valid starter byte");
        let expected: [u8; 5] = [
            // not huffman
            0,
            // size
            3,
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


}
