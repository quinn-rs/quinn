// This is only here because qpack is new and quinn no uses it yet.
// TODO remove allow dead code
#![allow(dead_code)]

use bit_field::BitField;
use bytes::{Bytes, Buf, IntoBuf};

#[derive(Debug, PartialEq)]
pub enum Bit {
    Set,
    Unset
}


impl From<bool> for Bit {
    fn from(v: bool) -> Bit {
        if v { Bit::Set }
        else { Bit::Unset }
    }
}


#[derive(Debug, PartialEq)]
pub enum Value {
    IndexHeaderField(u32)
}


#[derive(Debug, PartialEq)]
pub enum Error {
    NoMoreInput,
    InvalidIndexHeaderField
}


pub struct Parser {
    buffer: Vec<u8>,
    next_offset: usize
}


impl Parser {

    pub fn new<'a>(bytes: &'a [u8]) -> Parser {
        Parser {
            buffer: Vec::from(bytes),
            next_offset: 0
        }
    }

    pub fn next(&mut self) -> Result<Value, Error> {
        let (msb, rest) = self.next_bit_byte()?;
        match msb.into() {
            Bit::Set => self.read_index_header_field(rest),
            Bit::Unset => unimplemented!()
        }
    }

    fn next_byte(&mut self) -> Result<u8, Error> {
        if self.next_offset >= self.buffer.len() {
            return Err(Error::NoMoreInput);
        }

        let byte = self.buffer[self.next_offset];
        self.next_offset += 1;
        Ok(byte)
    }


    fn next_bit_byte(&mut self) -> Result<(bool, u8), Error> {
        let mut byte = self.next_byte()?;

        let msb = byte.get_bit(7);
        byte.set_bit(7, false);

        Ok((msb, byte))
    }

    fn read_index_header_field(&mut self, byte: u8) -> Result<Value, Error> {
        match byte {
            0 => Err(Error::InvalidIndexHeaderField),
            x => Ok(Value::IndexHeaderField(self.read_integer(7, x)?))
        }
    }

    fn read_integer(&mut self, prefix: u32, byte: u8) -> Result<u32, Error> {
        let prefix_byte = 2u8.pow(prefix) - 1;
        if prefix_byte != byte { Ok(byte.into()) }
        else { self.read_var_len_integer(prefix) }
    }

    fn read_var_len_integer(&mut self, prefix: u32) -> Result<u32, Error> {
        let mut value = 2u32.pow(prefix) - 1;

        let mut count = 0u32;
        loop {
            let (msb, rest) = self.next_bit_byte()?;
            value += rest as u32 * 2u32.pow(count);
            count += 7;
            if !msb { break; }
        }

        Ok(value)
    }

}


#[cfg(test)]
mod tests {
    use super::*;

    
    macro_rules! bit_to_byte {
        ( $a:expr, $b:expr, $c:expr, $d:expr, 
          $e:expr, $f:expr, $g:expr, $h:expr ) => { {
            let mut v = 0u8;
            v.set_bit(7, $a == 1)
                .set_bit(6, $b == 1)
                .set_bit(5, $c == 1)
                .set_bit(4, $d == 1)
                .set_bit(3, $e == 1)
                .set_bit(2, $f == 1)
                .set_bit(1, $g == 1)
                .set_bit(0, $h == 1);
                v
        } }
    }


    #[test]
    fn test_reader_has_no_more_data() {
        let bytes: [u8; 0] = [];
        let mut parser = Parser::new(&bytes);
        let res = parser.next();
        assert_eq!(res, Err(Error::NoMoreInput));
    }

    /**
     * https://tools.ietf.org/html/rfc7541
     * 6.1.  Indexed Header Field Representation
     */
    #[test]
    fn test_read_indexed_header_field() {
        let bytes: [u8; 1] = [
            bit_to_byte!(1, 1, 0, 0, 0, 0, 1, 1)
        ];
        let index = 67;
        
        let mut parser = Parser::new(&bytes);
        let res = parser.next();
        
        assert_eq!(res, Ok(Value::IndexHeaderField(index as u32)));
    }

    /**
     * https://tools.ietf.org/html/rfc7541
     * 6.1.  Indexed Header Field Representation
     */
    #[test]
    fn test_read_indexed_header_field_invalid_value() {
        let bytes: [u8; 1] = [
            bit_to_byte!(1, 0, 0, 0, 0, 0, 0, 0)
        ];
        
        let mut parser = Parser::new(&bytes);
        let res = parser.next();
        
        assert_eq!(res, Err(Error::InvalidIndexHeaderField));
    }
    
    /**
     * https://tools.ietf.org/html/rfc7541
     * 5.1.  Integer Representation
     * 
     * https://tools.ietf.org/html/rfc7541
     * C.1.1.  Example 1: Encoding 10 Using a 5-Bit Prefix
     */
    #[test]
    fn test_read_integer_fit_in_prefix() {
        let bytes: [u8; 1] = [
            bit_to_byte!(1, 0, 0, 0, 1, 0, 1, 0)
        ];
        let value = 10;
        
        let mut parser = Parser::new(&bytes);
        let res = parser.next();
        
        assert_eq!(res, Ok(Value::IndexHeaderField(value)));
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
        let bytes: [u8; 3] = [
            bit_to_byte!(1, 1, 1, 1, 1, 1, 1, 1),
            bit_to_byte!(1, 0, 0, 1, 1, 0, 1, 0),
            bit_to_byte!(0, 0, 0, 0, 1, 0, 1, 0)
        ];
        let value = 1337 + 96;
        
        let mut parser = Parser::new(&bytes);
        let res = parser.next();
        
        assert_eq!(res, Ok(Value::IndexHeaderField(value)));
    }


}
