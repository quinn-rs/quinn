// This is only here because qpack is new and quinn no uses it yet.
// TODO remove allow dead code
#![allow(dead_code)]

use std::borrow::Cow;
use std::io::Cursor;
use bytes::Buf;

use super::parser::Parser;
use super::table::HeaderField;
use super::dyn_table::DynamicTable;
use super::static_table::StaticTable;


#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidIntegerPrimitive,
    InvalidStringPrimitive,
    BadBufferLen,
    BadMaximumDynamicTableSize,
    BadNameIndexOnDynamicTable,
    BadNameIndexOnStaticTable,
    BadDuplicateIndex
}


pub struct Decoder {
    pub table: DynamicTable
}


impl Decoder {
    pub fn new() -> Decoder {
        Decoder { table: DynamicTable::new() }
    }

    pub fn get_static_field(&self, index: usize) -> Option<&HeaderField> {
        StaticTable::get(index)
    }

    pub fn get_rel_field(&self, rel_index: usize) -> Option<&HeaderField> {
        // TODO get true field (now assuming relative = absolute index)
        self.table.get(rel_index)
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

    fn read_name_insert_by_ref<T: Buf>(&mut self, byte: u8, buf: &mut T)
        -> Result<(), Error>
    {
        let is_static_table = byte & 64u8 == 64u8;

        let mut parser = Parser::new(buf);
        let name_index = parser.integer_from(6, byte)
            .map_err(|_| Error::InvalidIntegerPrimitive)? as usize;
        let value = parser.string(8)
            .map_err(|_| Error::InvalidStringPrimitive)?;

        // TODO get true field (now assuming relative = absolute index)
        let name = 
            if is_static_table {
                StaticTable::get(name_index)
                    .map(|x| x.name.clone())
                    .ok_or(Error::BadNameIndexOnStaticTable)?
            } else {
                self.table.get(name_index)
                    .map(|x| x.name.clone())
                    .ok_or(Error::BadNameIndexOnDynamicTable)?
            };

        self.table.put_field(HeaderField {
            name: name.clone(),
            value: Cow::Owned(value)
        });

        Ok(())
    }

    fn read_name_insert<T: Buf>(&mut self, byte: u8, buf: &mut T)
        -> Result<(), Error>
    {
        let mut parser = Parser::new(buf);
        let name = parser.string_from(7, byte)
            .map_err(|_| Error::InvalidStringPrimitive)?;
        let value = parser.string(8)
            .map_err(|_| Error::InvalidStringPrimitive)?;

        self.table.put_field(HeaderField::new(name, value));

        Ok(())
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

    fn read_duplicate_entry<T: Buf>(&mut self, byte: u8, buf: &mut T)
        -> Result<(), Error>
    {
        let dup_index = Parser::new(buf).integer_from(5, byte)
            .map_err(|_| Error::InvalidIntegerPrimitive)?;
 
        let field = self.table.get(dup_index as usize)
            .map(|x| x.clone())
            .ok_or(Error::BadDuplicateIndex)?;

        self.table.put_field(field);

        Ok(())
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
     * 3.3.1.  Insert With Name Reference
     */
    #[test]
    fn test_insert_field_with_name_ref_into_dynamic_table() {
        let name_index = 1u8;
        let text = "serial value";
        
        let bytes: [u8; 15] = [
            // size
            14,
            // code, from static, name index
            128 | 64 | 1,
            // not huffman, string size
            0 | 12,
            // bytes
            's' as u8,
            'e' as u8,
            'r' as u8,
            'i' as u8,
            'a' as u8,
            'l' as u8,
            ' ' as u8,
            'v' as u8,
            'a' as u8,
            'l' as u8,
            'u' as u8,
            'e' as u8
        ];

        let mut decoder = Decoder::new();
        let model_field = decoder.get_static_field(name_index as usize)
            .map(|x| x.clone());
        let expected_field = HeaderField::new(
            model_field.expect("field exists at name index").name,
            text);

        let mut cursor = Cursor::new(&bytes);
        let res = decoder.feed(&mut cursor);
        assert_eq!(res, Ok(()));

        let field = decoder.get_rel_field(0);
        assert_eq!(field, Some(&expected_field));
    }

    /**
     * https://tools.ietf.org/html/draft-ietf-quic-qpack-00
     * 3.3.1.  Insert With Name Reference
     */
    #[test]
    fn test_insert_field_with_wrong_name_index_from_static_table() {
        let mut decoder = Decoder::new();
        
        // NOTE this are the values encoded
        let _name_index = 3000;
        let _text = "";

        let bytes: [u8; 5] = [
            // size
            4,
            // code, from static, name index
            128 | 64 | 63,
            // name index (variable length encoding)
            128 | 121,
            // name index (variable length encoding, end)
            22,
            // not huffman, string size
            0 | 0
        ];

        let mut cursor = Cursor::new(&bytes);
        let res = decoder.feed(&mut cursor);
        assert_eq!(res, Err(Error::BadNameIndexOnStaticTable));
    }

    /**
     * https://tools.ietf.org/html/draft-ietf-quic-qpack-00
     * 3.3.1.  Insert With Name Reference
     */
    #[test]
    fn test_insert_field_with_wrong_name_index_from_dynamic_table() {
        let mut decoder = Decoder::new();
        
        // NOTE this are the values encoded
        let _name_index = 3000;
        let _text = "";

        let bytes: [u8; 5] = [
            // size
            4,
            // code, not from static, name index
            128 | 0 | 63,
            // name index (variable length encoding)
            128 | 121,
            // name index (variable length encoding, end)
            22,
            // not huffman, string size
            0 | 0
        ];

        let mut cursor = Cursor::new(&bytes);
        let res = decoder.feed(&mut cursor);
        assert_eq!(res, Err(Error::BadNameIndexOnDynamicTable));
    }
    
    /**
     * https://tools.ietf.org/html/draft-ietf-quic-qpack-00
     * 3.3.2.  Insert Without Name Reference
     */
    #[test]
    fn test_insert_field_without_name_ref() {
        let key = "key";
        let value = "value";
        
        let bytes: [u8; 11] = [
            // size
            10,
            // code, not huffman, string size
            64 | 0 | 3,
            // bytes
            'k' as u8,
            'e' as u8,
            'y' as u8,
            // not huffman, string size
            0 | 5,
            // bytes
            'v' as u8,
            'a' as u8,
            'l' as u8,
            'u' as u8,
            'e' as u8
        ];

        let mut decoder = Decoder::new();
        let expected_field = HeaderField::new(key, value);

        let mut cursor = Cursor::new(&bytes);
        let res = decoder.feed(&mut cursor);
        assert_eq!(res, Ok(()));

        let field = decoder.get_rel_field(0);
        assert_eq!(field, Some(&expected_field));
    }
    
    /**
     * https://tools.ietf.org/html/draft-ietf-quic-qpack-00
     * 3.3.3.  Duplicate
     */
    #[test]
    fn test_duplicate_field() {
        let _index = 1;
        
        let bytes: [u8; 2] = [
            // size
            1,
            // code, index
            0 | 1,
        ];

        let mut decoder = Decoder::new();
        decoder.table.put_field(HeaderField::new("", ""));
        decoder.table.put_field(HeaderField::new("", ""));
        assert_eq!(decoder.table.count(), 2);

        let mut cursor = Cursor::new(&bytes);
        let res = decoder.feed(&mut cursor);
        assert_eq!(res, Ok(()));

        assert_eq!(decoder.table.count(), 3);
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
