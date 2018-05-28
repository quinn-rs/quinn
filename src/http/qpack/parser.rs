// This is only here because qpack is new and quinn no uses it yet.
// TODO remove allow dead code
#![allow(dead_code)]

use std::io::Cursor;
use bytes::Buf;


#[derive(Debug, PartialEq)]
pub enum Error {
    MissingSomeBytesForInteger,
    MissingSomeBytesForString
}


pub struct Parser<'a> {
    buf: &'a mut Buf
}


impl<'a> Parser<'a> {

    pub fn new<T: Buf>(buf: &'a mut T) -> Parser<'a> {
        Parser { buf }
    }

    fn next_byte(&mut self) -> Option<u8> {
        if self.buf.has_remaining() { Some(self.buf.get_u8()) }
        else { None }
    }

    pub fn integer(&mut self, prefix: u8) -> Result<u32, Error> {
        let byte = self.next_byte()
            .ok_or(Error::MissingSomeBytesForInteger)?;
        self.integer_from(prefix, byte)
    }
    
    pub fn integer_from(&mut self, prefix: u8, byte: u8) -> Result<u32, Error> {
        let byte = byte as u16;
        let prefix_byte = 2u16.pow(prefix as u32) - 1;
        
        if prefix_byte != byte { 
            Ok((byte & prefix_byte) as u32)
        } else { 
            self.var_len_integer(prefix) 
        }
    }

    fn var_len_integer(&mut self, prefix: u8) -> Result<u32, Error> {
        let mut value = 2u32.pow(prefix as u32) - 1;

        let mut count = 0u32;
        loop {
            let byte = self.next_byte()
                .ok_or(Error::MissingSomeBytesForInteger)?;
            value += (byte & 127u8) as u32 * 2u32.pow(count);
            count += 7;
            if byte & 128u8 != 128u8 { break; }
        }

        Ok(value)
    }
    
    pub fn string(&mut self, prefix: u8) -> Result<Vec<u8>, Error> {
        let byte = self.next_byte()
            .ok_or(Error::MissingSomeBytesForString)?;
        self.string_from(prefix, byte)
    }
    
    pub fn string_from(&mut self, _prefix: u8, byte: u8) -> Result<Vec<u8>, Error> {
        let _huffman_encoded = byte & 128u8 == 128u8;

        let str_len = self.integer_from(7, byte)? as usize;
        let str_bytes = self.buf.take(str_len);
        if str_bytes.limit() != str_len {
            Err(Error::MissingSomeBytesForString)
        } else {
            // TODO decode huffman code
            Ok(Vec::from(str_bytes.bytes()))
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
     * https://tools.ietf.org/html/rfc7541
     * C.1.1.  Example 1: Encoding 10 Using a 5-Bit Prefix
     */
    #[test]
    fn test_read_integer_fit_in_prefix() {
        let bytes: [u8; 1] = [ 10u8 ];
        let value = 10;
        
        let mut cursor = Cursor::new(&bytes);
        let mut parser = Parser::new(&mut cursor);
        let res = parser.integer(7);
        
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
        let res = parser.integer(5);
        
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
        let res = parser.integer(2);
        
        assert_eq!(res, Err(Error::MissingSomeBytesForInteger));
    }
    
    #[test]
    fn test_preprefix_content_is_ditched_when_integer_fit_in_prefix() {
        let bytes: [u8; 1] = [ 128 | 57 ];
        let value = 57;
        
        let mut cursor = Cursor::new(&bytes);
        let mut parser = Parser::new(&mut cursor);
        let res = parser.integer(7);
        
        assert_eq!(res, Ok(value));
    }
    
    #[test]
    fn test_read_integer_with_ahead_byte() {
        let bytes: [u8; 1] = [ 26 ];
        let first_byte = 31;
        let value = 57;
        
        let mut cursor = Cursor::new(&bytes);
        let mut parser = Parser::new(&mut cursor);
        let res = parser.integer_from(5, first_byte);
        
        assert_eq!(res, Ok(value));
    }

    /**
     * https://tools.ietf.org/html/rfc7541
     * 5.2.  String Literal Representation
     */
    #[test]
    fn test_read_ascii_string() {
        let text = "testing string is not fun";
        assert!(text.len() < 127);

        let text_bytes = Vec::from(text);
        
        let mut bytes = Vec::new();
        bytes.push(text.len() as u8);
        bytes.extend(text_bytes.clone());
        
        let mut cursor = Cursor::new(&bytes);
        let mut parser = Parser::new(&mut cursor);
        let res = parser.string(0);
        
        let text_bytes = Vec::from(text);
        assert_eq!(res, Ok(text_bytes));
    }
    

}
