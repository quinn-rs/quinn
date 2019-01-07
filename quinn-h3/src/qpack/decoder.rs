// This is only here because qpack is new and quinn no uses it yet.
// TODO remove allow dead code
#![allow(dead_code)]

use bytes::Buf;
use std::borrow::Cow;
use std::io::Cursor;

use super::table::{dynamic, static_, DynamicTable, HeaderField, StaticTable};
use super::vas::{self, VirtualAddressSpace};

use super::prefix_int;
use super::prefix_string;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidInteger(prefix_int::Error),
    InvalidString(prefix_string::Error),
    BadMaximumDynamicTableSize,
    BadNameIndexOnDynamicTable(usize),
    BadNameIndexOnStaticTable,
    BadDuplicateIndex,
    InvalidIndex(vas::Error),
    InvalidStaticIndex(usize),
    UnknownPrefix,
    MissingRefs,
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

    // Decode a header bloc received on Request of Push stream. (draft: 4.5)
    pub fn decode_header<T: Buf>(&mut self, buf: &mut T) -> Result<Vec<HeaderField>, Error> {
        let (_, encoded_largest_ref) = prefix_int::decode(8, buf)?;
        let (sign, encoded_base_index) = prefix_int::decode(7, buf)?;
        let remote_largest_ref = self.largest_ref(encoded_largest_ref);

        if remote_largest_ref > self.vas.largest_ref() {
            // TODO here the header block cannot be decoded because it contains references to
            //      dynamic table entries that have not been recieved yet. It should be saved
            //      and then be decoded when the missing dynamic entries arrive on encoder
            //      stream.
            return Err(Error::MissingRefs);
        }

        if sign == 0 {
            self.vas
                .set_base_index(remote_largest_ref + encoded_base_index);
        } else {
            self.vas
                .set_base_index(remote_largest_ref - encoded_base_index);
        }

        let mut fields = Vec::new();

        while buf.has_remaining() {
            let first = buf.bytes()[0];
            let field = match first {
                x if x & 0b1000_0000 != 0 => {
                    // 4.5.2. Indexed Header Field
                    let (flags, index) = prefix_int::decode(6, buf)?;
                    if flags & 0b01 != 0 {
                        StaticTable::get(index)?.clone()
                    } else {
                        self.table.get(self.vas.relative(index)?)?.clone()
                    }
                }
                x if x & 0b1111_0000 == 0b0001_0000 => {
                    // 4.5.3. Indexed Header Field With Post-Base Index
                    let (_, postbase_index) = prefix_int::decode(4, buf)?;
                    let index = self.vas.post_base(postbase_index)?;
                    self.table.get(index)?.clone()
                }
                x if x & 0b1100_0000 == 0b0100_0000 => {
                    // 4.5.4. Literal Header Field With Name Reference
                    let (flags, index) = prefix_int::decode(4, buf)?;

                    let field = if flags & 0b0001 != 0 {
                        StaticTable::get(index)?
                    } else {
                        self.table.get(self.vas.relative(index)?)?
                    };

                    field.with_value(prefix_string::decode(8, buf)?)
                }
                x if x & 0b1111_0000 == 0 => {
                    // 4.5.5. Literal Header Field With Post-Base Name Reference
                    let (_flags, postbase_index) = prefix_int::decode(3, buf)?.into();
                    let index = self.vas.post_base(postbase_index)?;
                    let field = self.table.get(index)?.clone();
                    field.with_value(prefix_string::decode(8, buf)?)
                }
                x if x & 0b1110_0000 == 0b0010_0000 => {
                    // 4.5.6. Literal Header Field Without Name Reference
                    HeaderField {
                        name: prefix_string::decode(4, buf)?.into(),
                        value: prefix_string::decode(8, buf)?.into(),
                    }
                }
                _ => return Err(Error::UnknownPrefix),
            };
            fields.push(field);
        }

        Ok(fields)
    }

    fn largest_ref(&self, bloc_largest_ref: usize) -> usize {
        if bloc_largest_ref == 0 {
            return 0;
        }

        let total_inserted = self.vas.total_inserted();
        let mut lref_value = bloc_largest_ref - 1;
        let max_entries = self.table.max_mem_size() / 32;
        let mut wrapped = total_inserted % (2 * max_entries);

        if wrapped >= lref_value + max_entries {
            // Largest Reference wrapped around 1 extra time
            lref_value += 2 * max_entries;
        } else if wrapped + max_entries < lref_value {
            // Decoder wrapped around 1 extra time
            wrapped += 2 * max_entries;
        }

        lref_value + total_inserted - wrapped
    }

    // The receiving side of encoder stream
    pub fn feed_stream<T: Buf>(&mut self, buf: &mut T) -> Result<(), Error> {
        while buf.has_remaining() {
            let first = buf.bytes()[0];
            match first {
                x if x & 128 == 128 => self.read_name_insert_by_ref(buf)?,
                x if x & 64 == 64 => self.read_name_insert(buf)?,
                x if x & 32 == 32 => self.read_table_size_update(buf)?,
                x if x & 0xE0 == 0 => self.read_duplicate_entry(buf)?,
                _ => return Err(Error::UnknownPrefix),
            }
        }

        Ok(())
    }

    pub fn relative_field(&self, index: usize) -> Result<&HeaderField, Error> {
        Ok(self.table.get(self.vas.relative(index)?)?)
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
        let value = prefix_string::decode(8, buf)?;

        let field = if flags & 0b01 != 0 {
            StaticTable::get(name_index)?
        } else {
            self.relative_field(name_index)?
        };

        self.put_field(HeaderField {
            name: field.name.clone(),
            value: Cow::Owned(value),
        });

        Ok(())
    }

    fn read_name_insert<T: Buf>(&mut self, buf: &mut T) -> Result<(), Error> {
        let name = prefix_string::decode(6, buf)?;
        let value = prefix_string::decode(8, buf)?;
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
            .relative_field(dup_index)?;

        self.put_field(field.clone());

        Ok(())
    }
}

impl From<prefix_int::Error> for Error {
    fn from(e: prefix_int::Error) -> Self {
        Error::InvalidInteger(e)
    }
}

impl From<prefix_string::Error> for Error {
    fn from(e: prefix_string::Error) -> Self {
        Error::InvalidString(e)
    }
}

impl From<vas::Error> for Error {
    fn from(e: vas::Error) -> Self {
        Error::InvalidIndex(e)
    }
}

impl From<static_::Error> for Error {
    fn from(e: static_::Error) -> Self {
        match e {
            static_::Error::Unknown(i) => Error::InvalidStaticIndex(i),
        }
    }
}

impl From<dynamic::ErrorKind> for Error {
    fn from(e: dynamic::ErrorKind) -> Self {
        match e {
            dynamic::ErrorKind::MaximumTableSizeTooLarge => Error::BadMaximumDynamicTableSize,
            dynamic::ErrorKind::BadIndex(i) => Error::BadNameIndexOnDynamicTable(i),
        }
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
        let model_field = StaticTable::get(1).map(|x| x.clone());
        let expected_field =
            HeaderField::new(model_field.expect("field exists at name index").name, text);

        let mut cursor = Cursor::new(&bytes);
        let res = decoder.feed_stream(&mut cursor);
        assert_eq!(res, Ok(()));

        decoder.temp_set_base_index(1);
        let field = decoder.relative_field(0);
        assert_eq!(field, Ok(&expected_field));
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
        assert_eq!(res, Err(Error::InvalidStaticIndex(3000)));
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
        assert_eq!(res, Err(Error::InvalidIndex(vas::Error::BadRelativeIndex(3000))));
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
        assert_eq!(field, Ok(&expected_field));
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

    #[test]
    fn largest_ref_too_big() {
        let mut decoder = Decoder::new();
        const MAX_ENTRIES: usize = (4242 * 31) / 32;

        let mut buf = vec![];
        let encoded_largest_ref = (8 % (2 * MAX_ENTRIES)) + 1;
        prefix_int::encode(8, 0, encoded_largest_ref, &mut buf);
        prefix_int::encode(7, 0, 0, &mut buf);

        for _ in 0..7 {
            decoder.vas.add();
        }

        let mut read = Cursor::new(&buf);
        assert_eq!(decoder.decode_header(&mut read), Err(Error::MissingRefs));
    }

    // Largest Reference
    //   Base Index = 2
    //       |
    //     foo2   foo1
    //    +-----+-----+
    //    |  2  |  1  |  Absolute Index
    //    +-----+-----+
    //    |  0  |  1  |  Relative Index
    //    --+---+-----+

    #[test]
    fn decode_indexed_header_field() {
        let mut decoder = Decoder::new();
        let foo1 = HeaderField::new(b"foo1".to_vec(), b"bar1".to_vec());
        let foo2 = HeaderField::new(b"foo2".to_vec(), b"bar2".to_vec());
        decoder.put_field(foo1.clone());
        decoder.put_field(foo2.clone());

        const MAX_ENTRIES: usize = (4242 * 31) / 32;

        let mut buf = vec![];
        let encoded_largest_ref = (2 % (2 * MAX_ENTRIES)) + 1;
        prefix_int::encode(8, 0, encoded_largest_ref, &mut buf);
        prefix_int::encode(7, 0, 0, &mut buf); // base index = 2
        prefix_int::encode(6, 0b10, 0, &mut buf); // foo2
        prefix_int::encode(6, 0b10, 1, &mut buf); // foo1
        prefix_int::encode(6, 0b11, 18, &mut buf); // static  :method GET

        let mut read = Cursor::new(&buf);
        let headers = decoder.decode_header(&mut read).unwrap();
        assert_eq!(
            headers,
            &[foo2, foo1, StaticTable::get(18).unwrap().clone()]
        )
    }

    //      Largest Reference
    //        Base Index = 2
    //             |
    // foo4 foo3  foo2  foo1
    // +---+-----+-----+-----+
    // | 4 |  3  |  2  |  1  |  Absolute Index
    // +---+-----+-----+-----+
    //           |  0  |  1  |  Relative Index
    // +-----+-----+---+-----+
    // | 1 |  0  |              Post-Base Index
    // +---+-----+

    #[test]
    fn decode_post_base_indexed() {
        let mut decoder = Decoder::new();
        let foo1 = HeaderField::new(b"foo1".to_vec(), b"bar1".to_vec());
        let foo2 = HeaderField::new(b"foo2".to_vec(), b"bar2".to_vec());
        let foo3 = HeaderField::new(b"foo3".to_vec(), b"bar3".to_vec());
        let foo4 = HeaderField::new(b"foo4".to_vec(), b"bar4".to_vec());
        decoder.put_field(foo1.clone());
        decoder.put_field(foo2.clone());
        decoder.put_field(foo3.clone());
        decoder.put_field(foo4.clone());

        const MAX_ENTRIES: usize = (4242 * 31) / 32;

        let mut buf = vec![];
        let encoded_largest_ref = (2 % (2 * MAX_ENTRIES)) + 1;
        prefix_int::encode(8, 0, encoded_largest_ref, &mut buf);
        prefix_int::encode(7, 0, 0, &mut buf); // base index = 2
        prefix_int::encode(6, 0b10, 0, &mut buf); // relative foo2
        prefix_int::encode(4, 0b0001, 0, &mut buf); // post base foo3
        prefix_int::encode(4, 0b0001, 1, &mut buf); // post base foo4

        let mut read = Cursor::new(&buf);
        let headers = decoder.decode_header(&mut read).unwrap();
        assert_eq!(headers, &[foo2, foo3, foo4])
    }

    #[test]
    fn decode_name_ref_header_field() {
        let mut decoder = Decoder::new();
        let foo1 = HeaderField::new(b"foo1".to_vec(), b"bar1".to_vec());
        let foo2 = HeaderField::new(b"foo2".to_vec(), b"bar2".to_vec());
        decoder.put_field(foo1.clone());
        decoder.put_field(foo2.clone());

        const MAX_ENTRIES: usize = (4242 * 31) / 32;

        let mut buf = vec![];
        let encoded_largest_ref = (2 % (2 * MAX_ENTRIES)) + 1;
        prefix_int::encode(8, 0, encoded_largest_ref, &mut buf);
        prefix_int::encode(7, 0, 0, &mut buf); // base index = 2
        prefix_int::encode(4, 0b0100, 1, &mut buf); // foo1
        prefix_string::encode(8, 0, b"new bar1", &mut buf).unwrap();
        prefix_int::encode(4, 0b0101, 18, &mut buf); // static  :method GET
        prefix_string::encode(8, 0, b"PUT", &mut buf).unwrap();

        let mut read = Cursor::new(&buf);
        let headers = decoder.decode_header(&mut read).unwrap();
        assert_eq!(
            headers,
            &[
                foo1.with_value("new bar1"),
                StaticTable::get(18).unwrap().with_value("PUT")
            ]
        )
    }

    #[test]
    fn decode_post_base_name_ref_header_field() {
        let mut decoder = Decoder::new();
        let foo1 = HeaderField::new(b"foo1".to_vec(), b"bar1".to_vec());
        let foo2 = HeaderField::new(b"foo2".to_vec(), b"bar2".to_vec());
        let foo3 = HeaderField::new(b"foo3".to_vec(), b"bar3".to_vec());
        let foo4 = HeaderField::new(b"foo4".to_vec(), b"bar4".to_vec());
        decoder.put_field(foo1.clone());
        decoder.put_field(foo2.clone());
        decoder.put_field(foo3.clone());
        decoder.put_field(foo4.clone());

        const MAX_ENTRIES: usize = (4242 * 31) / 32;

        let mut buf = vec![];
        let encoded_largest_ref = (2 % (2 * MAX_ENTRIES)) + 1;
        prefix_int::encode(8, 0, encoded_largest_ref, &mut buf);
        prefix_int::encode(7, 0, 0, &mut buf); // base index = 2
        prefix_int::encode(3, 0b00000, 0, &mut buf); // post base foo3
        prefix_string::encode(8, 0, b"new bar3", &mut buf).unwrap();

        let mut read = Cursor::new(&buf);
        let headers = decoder.decode_header(&mut read).unwrap();
        assert_eq!(headers, &[foo3.with_value("new bar3")]);
    }

    #[test]
    fn decode_without_name_ref_header_field() {
        let mut buf = vec![];
        prefix_int::encode(8, 0, 0, &mut buf);
        prefix_int::encode(7, 0, 0, &mut buf);
        prefix_string::encode(4, 0b0010, b"foo", &mut buf).unwrap();
        prefix_string::encode(8, 0, b"bar", &mut buf).unwrap();

        let mut read = Cursor::new(&buf);
        let headers = Decoder::new().decode_header(&mut read).unwrap();
        assert_eq!(
            headers,
            &[HeaderField::new(b"foo".to_vec(), b"bar".to_vec())]
        );
    }
}
