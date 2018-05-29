// This is only here because qpack is new and quinn no uses it yet.
// TODO remove allow dead code
#![allow(dead_code)]

use std::io::{Write, Cursor, Result, Error, ErrorKind};



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

    pub fn integer(&mut self, prefix: usize, value: usize) -> Result<()> {
        if prefix == 0 || prefix > 7 {
            return Err(Error::new(ErrorKind::Other, "bad prefix"));
        }

        let prefix_mask = 2usize.pow(prefix as u32) - 1;

        if value < prefix_mask {
            self.put_byte(value as u8)
        } else {
            self.var_len_integer(prefix_mask, value)
        }
    }

    fn var_len_integer(&mut self, prefix_mask: usize, value: usize) 
        -> Result<()> 
    {
        let _ = self.put_byte(prefix_mask as u8)?;
        let mut value = value - prefix_mask;

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
            assert!(dump.integer(prefix, value).is_ok());
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
            assert!(dump.integer(prefix, value).is_ok());
        }

        assert_eq!(bytes.as_slice(), expected);
    }
    
    fn test_integer_null_prefix() {
        let any_value = 10000;
        let mut bytes = Vec::new();
        let mut cursor = Cursor::new(&mut bytes);
        let mut dump = Dump::new(&mut cursor);
        assert!(dump.integer(0, any_value).is_err());
    }
    
    fn test_integer_bad_prefix() {
        let any_value = 10000;
        let mut bytes = Vec::new();
        let mut cursor = Cursor::new(&mut bytes);
        let mut dump = Dump::new(&mut cursor);
        assert!(dump.integer(15, any_value).is_err());
    }

}
