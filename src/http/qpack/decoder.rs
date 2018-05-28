// This is only here because qpack is new and quinn no uses it yet.
// TODO remove allow dead code
#![allow(dead_code)]

use std::io::Cursor;
use bytes::Buf;

use super::parser::Parser;
use super::dyn_table::DynamicTable;
use super::static_table::StaticTable;


#[derive(Debug, PartialEq)]
pub enum Error {
    BadBufferLen,
    InvalidIntegerPrimitive,
    BadMaximumDynamicTableSize
}


pub struct Decoder {
    pub table: DynamicTable
}


impl Decoder {
    pub fn new() -> Decoder {
        Decoder { table: DynamicTable::new() }
    }

    pub fn feed<T: Buf>(&mut self, buf: &mut T) -> Result<(), Error> {
        let block_len = Parser::new(buf).integer(8)
            .map_err(|_| Error::InvalidIntegerPrimitive)?;

        if block_len as usize != buf.remaining() {
            return Err(Error::BadBufferLen);
        }

        while buf.has_remaining() {
            match buf.get_u8() {
                x if x & 128u8 == 128u8 
                    => self.read_name_insert_by_ref(x, buf)?,
                x if x & 64u8 == 64u8 => self.read_name_insert(x, buf)?,
                x if x & 32u8 == 32u8 => self.read_table_size_update(x, buf)?,
                x => self.read_duplicate_entry(x, buf)?
            }
        }

        Ok(())
    }

    fn read_name_insert_by_ref<T: Buf>(&mut self, _byte: u8, _buf: &mut T)
        -> Result<(), Error>
    {
        unimplemented!();
    }

    fn read_name_insert<T: Buf>(&mut self, _byte: u8, _buf: &mut T)
        -> Result<(), Error>
    {
        unimplemented!();
    }

    fn read_table_size_update<T: Buf>(&mut self, byte: u8, buf: &mut T)
        -> Result<(), Error>
    {
        let size = Parser::new(buf).integer_from(5, byte)
            .map_err(|_| Error::InvalidIntegerPrimitive)?;

        self.table.set_max_mem_size(size as usize)
            .map_err(|_| Error::BadMaximumDynamicTableSize)
            .map(|_| ())
    }

    fn read_duplicate_entry<T: Buf>(&mut self, _byte: u8, _buf: &mut T)
        -> Result<(), Error>
    {
        unimplemented!();
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    /**
     * https://tools.ietf.org/html/draft-ietf-quic-qpack-00
     * 3.3.  QPACK Encoder Stream
     */
    #[test]
    fn test_wrong_block_length() {
        let mut decoder = Decoder::new();
        let bytes: [u8; 1] = [
            5 // block length
        ];

        let mut cursor = Cursor::new(&bytes);
        let res = decoder.feed(&mut cursor);
        
        assert_eq!(res, Err(Error::BadBufferLen));
    }

    /**
     * https://tools.ietf.org/html/draft-ietf-quic-qpack-00
     * 3.3.4.  Dynamic Table Size Update
     */
    #[test]
    fn test_dynamic_table_size_update() {
        let mut decoder = Decoder::new();
        let bytes: [u8; 2] = [
            1, // block length
            32 | 25 // 0b001 message code, size
        ];
        let expected_size = 25;

        let mut cursor = Cursor::new(&bytes);
        let res = decoder.feed(&mut cursor);
        assert_eq!(res, Ok(()));

        let actual_max_size = decoder.table.max_mem_size();
        assert_eq!(actual_max_size, expected_size);
    }

}
