// This is only here because qpack is new and quinn no uses it yet.
// TODO remove allow dead code
#![allow(dead_code)]

use bytes::Buf;
use std::borrow::Cow;
use std::io::Cursor;

use super::table::{DynamicTable, HeaderField, StaticTable};
use super::vas::VirtualAddressSpace;

use super::prefix_int;
use super::string;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidInteger(prefix_int::Error),
    InvalidString(string::Error),
    InvalidIntegerPrimitive,
    InvalidStringPrimitive,
    BadBufferLen,
    // Same as HTTP_QPACK_DECOMPRESSION_FAILED
    BadMaximumDynamicTableSize,
    // Same as HTTP_QPACK_DECOMPRESSION_FAILED
    BadNameIndexOnDynamicTable,
    BadNameIndexOnStaticTable,
    BadDuplicateIndex,
}

pub struct Decoder {
    table: DynamicTable,
    vas: VirtualAddressSpace,
}

impl Decoder {
    pub fn new() -> Decoder {
        Decoder {
            table: DynamicTable::new(),
            vas: VirtualAddressSpace::new(),
        }
    }

    // The recieving side of encoder stream
    pub fn feed_stream<T: Buf>(&mut self, buf: &mut T) -> Result<(), Error> {
        while buf.has_remaining() {
            let first = buf.bytes()[0];
            match first {
                x if x & 128 == 128 => self.read_name_insert_by_ref(buf)?,
                x if x & 64 == 64 => self.read_name_insert(buf)?,
                x if x & 32 == 32 => self.read_table_size_update(buf)?,
                _ => self.read_duplicate_entry(buf)?,
            }
        }

        Ok(())
    }

    pub fn relative_field(&self, index: usize) -> Option<&HeaderField> {
        self.vas.relative(index).and_then(|x| self.table.get(x))
    }

    pub fn put_field(&mut self, field: HeaderField) {
        let (is_added, dropped) = self.table.put_field(field);

        if is_added {
            self.vas.add();
        }
        self.vas.drop_many(dropped);
    }

    fn resize_table(&mut self, size: usize) -> Result<(), Error> {
        self.table
            .set_max_mem_size(size)
            .map(|x| {
                self.vas.drop_many(x);
            })
            .map_err(|_| Error::BadMaximumDynamicTableSize)
    }

    // TODO remove this when base index is modifiable via `feed_stream`
    pub fn temp_set_base_index(&mut self, base: usize) {
        self.vas.set_base_index(base);
    }

    fn read_name_insert_by_ref<T: Buf>(&mut self, buf: &mut T) -> Result<(), Error> {
        let (flags, name_index) = prefix_int::decode(6, buf)?;
        let value = string::decode(8, buf)?;

        let field = if flags & 0b01 != 0 {
            StaticTable::get(name_index).ok_or(Error::BadNameIndexOnStaticTable)?
        } else {
            self.relative_field(name_index)
                .ok_or(Error::BadNameIndexOnDynamicTable)?
        };

        self.put_field(HeaderField {
            name: field.name.clone(),
            value: Cow::Owned(value),
        });

        Ok(())
    }

    fn read_name_insert<T: Buf>(&mut self, buf: &mut T) -> Result<(), Error> {
        let name = string::decode(6, buf)?;
        let value = string::decode(8, buf)?;
        self.put_field(HeaderField::new(name, value));
        Ok(())
    }

    fn read_table_size_update<T: Buf>(&mut self, buf: &mut T) -> Result<(), Error> {
        let (_, size) = prefix_int::decode(5, buf)?;
        self.resize_table(size)
    }

    fn read_duplicate_entry<T: Buf>(&mut self, buf: &mut T) -> Result<(), Error> {
        let (_, dup_index) = prefix_int::decode(5, buf)?;

        let field = self
            .relative_field(dup_index)
            .ok_or(Error::BadDuplicateIndex)?;

        self.put_field(field.clone());

        Ok(())
    }
}

impl From<prefix_int::Error> for Error {
    fn from(e: prefix_int::Error) -> Self {
        Error::InvalidInteger(e)
    }
}

impl From<string::Error> for Error {
    fn from(e: string::Error) -> Self {
        Error::InvalidString(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /**
     * https://tools.ietf.org/html/draft-ietf-quic-qpack-00
     * 4.3.1.  Insert With Name Reference
     */
    #[test]
    fn test_insert_field_with_name_ref_into_dynamic_table() {
        let name_index = 1u8;
        let text = "serial value";

        let bytes = vec![
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
            'e' as u8,
        ];

        let mut decoder = Decoder::new();
        let model_field = StaticTable::get(name_index as usize).map(|x| x.clone());
        let expected_field =
            HeaderField::new(model_field.expect("field exists at name index").name, text);

        let mut cursor = Cursor::new(&bytes);
        let res = decoder.feed_stream(&mut cursor);
        assert_eq!(res, Ok(()));

        decoder.temp_set_base_index(1);
        let field = decoder.relative_field(0);
        assert_eq!(field, Some(&expected_field));
    }

    /**
     * https://tools.ietf.org/html/draft-ietf-quic-qpack-00
     * 4.3.1.  Insert With Name Reference
     */
    #[test]
    fn test_insert_field_with_wrong_name_index_from_static_table() {
        let mut decoder = Decoder::new();

        // NOTE this are the values encoded
        let _name_index = 3000;
        let _text = "";

        let bytes = vec![
            // code, from static, name index
            128 | 64 | 63,
            // name index (variable length encoding)
            128 | 121,
            // name index (variable length encoding, end)
            22,
            // not huffman, string size
            0 | 0,
        ];

        let mut cursor = Cursor::new(&bytes);
        let res = decoder.feed_stream(&mut cursor);
        assert_eq!(res, Err(Error::BadNameIndexOnStaticTable));
    }

    /**
     * https://tools.ietf.org/html/draft-ietf-quic-qpack-00
     * 4.3.1.  Insert With Name Reference
     */
    #[test]
    fn test_insert_field_with_wrong_name_index_from_dynamic_table() {
        let mut decoder = Decoder::new();

        // NOTE this are the values encoded
        let _name_index = 3000;
        let _text = "";

        let bytes = vec![
            // code, not from static, name index
            128 | 0 | 63,
            // name index (variable length encoding)
            128 | 121,
            // name index (variable length encoding, end)
            22,
            // not huffman, string size
            0 | 0,
        ];

        let mut cursor = Cursor::new(&bytes);
        let res = decoder.feed_stream(&mut cursor);
        assert_eq!(res, Err(Error::BadNameIndexOnDynamicTable));
    }

    /**
     * https://tools.ietf.org/html/draft-ietf-quic-qpack-00
     * 4.3.2.  Insert Without Name Reference
     */
    #[test]
    fn test_insert_field_without_name_ref() {
        let key = "key";
        let value = "value";

        let bytes = vec![
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
            'e' as u8,
        ];

        let mut decoder = Decoder::new();
        let expected_field = HeaderField::new(key, value);

        let mut cursor = Cursor::new(&bytes);
        let res = decoder.feed_stream(&mut cursor);
        assert_eq!(res, Ok(()));

        decoder.temp_set_base_index(1);
        let field = decoder.relative_field(0);
        assert_eq!(field, Some(&expected_field));
    }

    /**
     * https://tools.ietf.org/html/draft-ietf-quic-qpack-00
     * 3.3.3.  Duplicate
     */
    #[test]
    fn test_duplicate_field() {
        let _index = 1;

        let bytes = vec![
            // code, index
            0 | 1,
        ];

        let mut decoder = Decoder::new();
        decoder.put_field(HeaderField::new("", ""));
        decoder.put_field(HeaderField::new("", ""));
        decoder.temp_set_base_index(2);
        assert_eq!(decoder.table.count(), 2);

        let mut cursor = Cursor::new(&bytes);
        let res = decoder.feed_stream(&mut cursor);
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
        let bytes = vec![
            32 | 25, // 0b001 message code, size
        ];
        let expected_size = 25;

        let mut cursor = Cursor::new(&bytes);
        let res = decoder.feed_stream(&mut cursor);
        assert_eq!(res, Ok(()));

        let actual_max_size = decoder.table.max_mem_size();
        assert_eq!(actual_max_size, expected_size);
    }

}
