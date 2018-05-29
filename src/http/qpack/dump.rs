// This is only here because qpack is new and quinn no uses it yet.
// TODO remove allow dead code
#![allow(dead_code)]

use std::io::{Write, Cursor, Result, Error, ErrorKind};

use super::iocontext::StartingByte;



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

    pub fn integer(&mut self, value: usize, starter: StartingByte) 
        -> Result<()> 
    {
        if value < starter.mask {
            self.put_byte(value as u8)
        } else {
            self.var_len_integer(value, starter)
        }
    }

    fn var_len_integer(&mut self, value: usize, starter: StartingByte) 
        -> Result<()> 
    {
        let first_byte = starter.byte.unwrap_or(0) | starter.mask;
        let _ = self.put_byte(first_byte as u8)?;
        let mut value = value - starter.mask;

        while value >= 128 {
            let rest = value % 128;
            let _ = self.put_byte(128 + rest as u8)?;
            value /= 128;
        }
        
        self.put_byte(value as u8)
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
        let prefix = 5;
        let expected: [u8; 1] = [ 10 ];

        let mut bytes = Vec::new();
        {
            let mut cursor = Cursor::new(&mut bytes);
            let mut dump = Dump::new(&mut cursor);
            assert!(dump.integer(
                    value, 
                    StartingByte::prefix(prefix)
                    .expect("valid starting byte")
                    ).is_ok());
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
        let prefix = 5;
        let expected: [u8; 3] = [ 31, 154, 10 ];

        let mut bytes = Vec::new();
        {
            let mut cursor = Cursor::new(&mut bytes);
            let mut dump = Dump::new(&mut cursor);
            assert!(dump.integer(
                    value, 
                    StartingByte::prefix(prefix)
                    .expect("valid starting byte")
                    ).is_ok());
        }

        assert_eq!(bytes.as_slice(), expected);
    }

}
