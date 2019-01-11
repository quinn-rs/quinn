// This is only here because qpack is new and quinn no uses it yet.
// TODO remove allow dead code
#![allow(dead_code)]

use bytes::{Buf, BufMut};
use std::borrow::Cow;
use std::io::Cursor;

use super::table::{dynamic, static_, DynamicTable, HeaderField, StaticTable};
use super::vas::{self, VirtualAddressSpace};

use super::bloc::{
    HeaderBlocField, Indexed, IndexedWithPostBase, Literal, LiteralWithNameRef,
    LiteralWithPostBaseNameRef,
};
use super::stream::{
    Duplicate, DynamicTableSizeUpdate, InsertWithNameRef, InsertWithoutNameRef, InstructionType,
    TableSizeSync,
};
use super::ParseError;

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
    BadBaseIndex(isize),
    UnexpectedEnd,
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

        if remote_largest_ref > self.vas.total_inserted() {
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
            if encoded_base_index > remote_largest_ref - 1 {
                return Err(Error::BadBaseIndex(
                    remote_largest_ref as isize - encoded_base_index as isize - 1,
                ));
            }
            self.vas
                .set_base_index(remote_largest_ref - encoded_base_index - 1);
        }

        let mut fields = Vec::new();

        while buf.has_remaining() {
            fields.push(self.parse_header_field(buf)?);
        }

        Ok(fields)
    }

    fn parse_header_field<R: Buf>(&self, buf: &mut R) -> Result<HeaderField, Error> {
        let first = buf.bytes()[0];
        let field = match HeaderBlocField::decode(first) {
            HeaderBlocField::Indexed => match Indexed::decode(buf)? {
                Indexed::Static(index) => StaticTable::get(index)?.clone(),
                Indexed::Dynamic(index) => self.table.get(self.vas.relative(index)?)?.clone(),
            },
            HeaderBlocField::IndexedWithPostBase => {
                let postbase = IndexedWithPostBase::decode(buf)?;
                let index = self.vas.post_base(postbase.0)?;
                self.table.get(index)?.clone()
            }
            HeaderBlocField::LiteralWithNameRef => match LiteralWithNameRef::decode(buf)? {
                LiteralWithNameRef::Static { index, value } => {
                    StaticTable::get(index)?.with_value(value)
                }
                LiteralWithNameRef::Dynamic { index, value } => {
                    self.table.get(self.vas.relative(index)?)?.with_value(value)
                }
            },
            HeaderBlocField::LiteralWithPostBaseNameRef => {
                let literal = LiteralWithPostBaseNameRef::decode(buf)?;
                let index = self.vas.post_base(literal.index)?;
                self.table.get(index)?.with_value(literal.value)
            }
            HeaderBlocField::Literal => {
                let literal = Literal::decode(buf)?;
                HeaderField::new(literal.name, literal.value)
            }
            _ => return Err(Error::UnknownPrefix),
        };
        Ok(field)
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
    pub fn on_encoder_recv<R: Buf, W: BufMut>(
        &mut self,
        read: &mut R,
        write: &mut W,
    ) -> Result<(), Error> {
        let inserted_on_start = self.vas.total_inserted();

        while let Some(instruction) = self.parse_instruction(read)? {
            match instruction {
                Instruction::Insert(field) => self.put_field(field),
                Instruction::TableSizeUpdate(size) => {
                    self.table.set_max_mem_size(size)?;
                }
            }
        }

        if self.vas.total_inserted() != inserted_on_start {
            TableSizeSync {
                insert_count: self.vas.total_inserted() - inserted_on_start,
            }
            .encode(write);
        }

        Ok(())
    }

    fn put_field(&mut self, field: HeaderField) {
        let (is_added, dropped) = self.table.put_field(field);
        if is_added {
            self.vas.add();
        }
        self.vas.drop_many(dropped);
    }

    fn parse_instruction<R: Buf>(&self, read: &mut R) -> Result<Option<Instruction>, Error> {
        if read.remaining() < 1 {
            return Ok(None);
        }

        let mut buf = Cursor::new(read.bytes());
        let first = buf.bytes()[0];
        let instruction = match InstructionType::decode(first) {
            InstructionType::Unknown => return Err(Error::UnknownPrefix),
            InstructionType::DynamicTableSizeUpdate => DynamicTableSizeUpdate::decode(&mut buf)?
                .map(|x| Instruction::TableSizeUpdate(x.size)),
            InstructionType::InsertWithoutNameRef => InsertWithoutNameRef::decode(&mut buf)?
                .map(|x| Instruction::Insert(HeaderField::new(x.name, x.value))),
            InstructionType::Duplicate => match Duplicate::decode(&mut buf)? {
                Some(Duplicate { index }) => Some(Instruction::Insert(
                    self.table.get(self.vas.relative(index)?)?.clone(),
                )),
                None => None,
            },
            InstructionType::InsertWithNameRef => match InsertWithNameRef::decode(&mut buf)? {
                Some(InsertWithNameRef::Static { index, value }) => Some(Instruction::Insert(
                    StaticTable::get(index)?.with_value(value),
                )),
                Some(InsertWithNameRef::Dynamic { index, value }) => Some(Instruction::Insert(
                    self.table.get(self.vas.relative(index)?)?.with_value(value),
                )),
                None => None,
            },
        };

        if instruction.is_some() {
            read.advance(buf.position() as usize);
        }

        Ok(instruction)
    }
}

#[derive(Debug, PartialEq)]
enum Instruction {
    Insert(HeaderField),
    TableSizeUpdate(usize),
}

impl From<prefix_int::Error> for Error {
    fn from(e: prefix_int::Error) -> Self {
        match e {
            prefix_int::Error::UnexpectedEnd => Error::UnexpectedEnd,
            e => Error::InvalidInteger(e),
        }
    }
}

impl From<prefix_string::Error> for Error {
    fn from(e: prefix_string::Error) -> Self {
        match e {
            prefix_string::Error::UnexpectedEnd => Error::UnexpectedEnd,
            e => Error::InvalidString(e),
        }
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

impl From<ParseError> for Error {
    fn from(e: ParseError) -> Self {
        match e {
            ParseError::InvalidInteger(x) => Error::InvalidInteger(x),
            ParseError::InvalidString(x) => Error::InvalidString(x),
            ParseError::InvalidPrefix => Error::UnknownPrefix,
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
        let mut buf = vec![];
        InsertWithNameRef::new_static(1, "serial value")
            .encode(&mut buf)
            .unwrap();
        let mut decoder = Decoder::new();
        let mut enc = Cursor::new(&buf);
        let mut dec = vec![];
        assert!(decoder.on_encoder_recv(&mut enc, &mut dec).is_ok());

        decoder.vas.set_base_index(1);
        assert_eq!(
            decoder.table.get(decoder.vas.relative(0).unwrap()),
            Ok(&StaticTable::get(1).unwrap().with_value("serial value"))
        );

        let mut dec_cursor = Cursor::new(&dec);
        assert_eq!(
            TableSizeSync::decode(&mut dec_cursor),
            Ok(Some(TableSizeSync { insert_count: 1 }))
        );
    }

    /**
     * https://tools.ietf.org/html/draft-ietf-quic-qpack-00
     * 4.3.1.  Insert With Name Reference
     */
    #[test]
    fn test_insert_field_with_wrong_name_index_from_static_table() {
        let mut buf = vec![];
        InsertWithNameRef::new_static(3000, "")
            .encode(&mut buf)
            .unwrap();
        let mut enc = Cursor::new(&buf);
        let res = Decoder::new().on_encoder_recv(&mut enc, &mut vec![]);
        assert_eq!(res, Err(Error::InvalidStaticIndex(3000)));
    }

    /**
     * https://tools.ietf.org/html/draft-ietf-quic-qpack-00
     * 4.3.1.  Insert With Name Reference
     */
    #[test]
    fn test_insert_field_with_wrong_name_index_from_dynamic_table() {
        let mut buf = vec![];
        InsertWithNameRef::new_dynamic(3000, "")
            .encode(&mut buf)
            .unwrap();
        let mut enc = Cursor::new(&buf);
        let mut dec = vec![];
        let res = Decoder::new().on_encoder_recv(&mut enc, &mut dec);
        assert_eq!(
            res,
            Err(Error::InvalidIndex(vas::Error::BadRelativeIndex(3000)))
        );

        assert!(dec.is_empty());
    }

    /**
     * https://tools.ietf.org/html/draft-ietf-quic-qpack-00
     * 4.3.2.  Insert Without Name Reference
     */
    #[test]
    fn test_insert_field_without_name_ref() {
        let mut buf = vec![];
        InsertWithoutNameRef::new("key", "value")
            .encode(&mut buf)
            .unwrap();

        let mut decoder = Decoder::new();
        let mut enc = Cursor::new(&buf);
        let mut dec = vec![];
        assert!(decoder.on_encoder_recv(&mut enc, &mut dec).is_ok());

        decoder.vas.set_base_index(1);
        assert_eq!(
            decoder.table.get(decoder.vas.relative(0).unwrap()),
            Ok(&HeaderField::new("key", "value"))
        );

        let mut dec_cursor = Cursor::new(&dec);
        assert_eq!(
            TableSizeSync::decode(&mut dec_cursor),
            Ok(Some(TableSizeSync { insert_count: 1 }))
        );
    }

    /**
     * https://tools.ietf.org/html/draft-ietf-quic-qpack-00
     * 4.3.3.  Duplicate
     */
    #[test]
    fn test_duplicate_field() {
        let mut decoder = Decoder::new();
        decoder.put_field(HeaderField::new("", ""));
        decoder.put_field(HeaderField::new("", ""));
        decoder.vas.set_base_index(2);
        assert_eq!(decoder.table.count(), 2);

        let mut buf = vec![];
        Duplicate { index: 1 }.encode(&mut buf);

        let mut enc = Cursor::new(&buf);
        let mut dec = vec![];
        let res = decoder.on_encoder_recv(&mut enc, &mut dec);
        assert_eq!(res, Ok(()));

        assert_eq!(decoder.table.count(), 3);

        let mut dec_cursor = Cursor::new(&dec);
        assert_eq!(
            TableSizeSync::decode(&mut dec_cursor),
            Ok(Some(TableSizeSync { insert_count: 1 }))
        );
    }

    /**
     * https://tools.ietf.org/html/draft-ietf-quic-qpack-00
     * 4.3.4.  Dynamic Table Size Update
     */
    #[test]
    fn test_dynamic_table_size_update() {
        let mut buf = vec![];
        DynamicTableSizeUpdate { size: 25 }.encode(&mut buf);

        let mut enc = Cursor::new(&buf);
        let mut dec = vec![];
        let mut decoder = Decoder::new();
        let res = decoder.on_encoder_recv(&mut enc, &mut dec);
        assert_eq!(res, Ok(()));

        let actual_max_size = decoder.table.max_mem_size();
        assert_eq!(actual_max_size, 25);
        assert!(dec.is_empty());
    }

    #[test]
    fn enc_recv_buf_too_short() {
        let mut buf = vec![];
        {
            let mut enc = Cursor::new(&buf);
            assert_eq!(Decoder::new().parse_instruction(&mut enc), Ok(None));
        }

        buf.push(0b1000_0000);
        let mut enc = Cursor::new(&buf);
        assert_eq!(Decoder::new().parse_instruction(&mut enc), Ok(None));
    }

    #[test]
    fn enc_recv_accepts_truncated_messages() {
        let mut buf = vec![];
        InsertWithoutNameRef::new("keyfoobarbaz", "value")
            .encode(&mut buf)
            .unwrap();

        let mut decoder = Decoder::new();
        // cut in middle of the first int
        let mut enc = Cursor::new(&buf[..2]);
        let mut dec = vec![];
        assert!(decoder.on_encoder_recv(&mut enc, &mut dec).is_ok());
        assert_eq!(enc.position(), 0);

        // cut the last byte of the 2nd string
        let mut enc = Cursor::new(&buf[..buf.len() - 1]);
        let mut dec = vec![];
        assert!(decoder.on_encoder_recv(&mut enc, &mut dec).is_ok());
        assert_eq!(enc.position(), 0);

        InsertWithoutNameRef::new("keyfoobarbaz2", "value")
            .encode(&mut buf)
            .unwrap();

        // the first valid field is inserted and buf is left at the first byte of incomplete string
        let mut enc = Cursor::new(&buf[..buf.len() - 1]);
        let mut dec = vec![];
        assert!(decoder.on_encoder_recv(&mut enc, &mut dec).is_ok());
        assert_eq!(enc.position(), 15);
        assert_eq!(decoder.table.count(), 1);

        let mut dec_cursor = Cursor::new(&dec);
        assert_eq!(prefix_int::decode(6, &mut dec_cursor), Ok((0, 1)));
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

    fn build_decoder(n_field: usize, max_table_size: usize) -> (Decoder, usize) {
        let mut decoder = Decoder::new();
        let max_entries = max_table_size / 32;
        decoder.table.set_max_mem_size(max_table_size).unwrap();

        for i in 0..n_field {
            decoder.put_field(HeaderField::new(format!("foo{}", i + 1), "bar"));
        }

        (decoder, max_entries)
    }

    fn field(n: usize) -> HeaderField {
        HeaderField::new(format!("foo{}", n), "bar")
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
        let (mut decoder, max_entries) = build_decoder(2, 4242 * 31);

        let mut buf = vec![];
        let encoded_largest_ref = (2 % (2 * max_entries)) + 1;
        prefix_int::encode(8, 0, encoded_largest_ref, &mut buf);
        prefix_int::encode(7, 0, 0, &mut buf); // base index = 2
        Indexed::Dynamic(0).encode(&mut buf);
        Indexed::Dynamic(1).encode(&mut buf);
        Indexed::Static(18).encode(&mut buf);

        let mut read = Cursor::new(&buf);
        let headers = decoder.decode_header(&mut read).unwrap();
        assert_eq!(
            headers,
            &[field(2), field(1), StaticTable::get(18).unwrap().clone()]
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
        let (mut decoder, max_entries) = build_decoder(4, 4242 * 31);

        let mut buf = vec![];
        let encoded_largest_ref = (2 % (2 * max_entries)) + 1;
        prefix_int::encode(8, 0, encoded_largest_ref, &mut buf);
        prefix_int::encode(7, 0, 0, &mut buf); // base index = 2
        Indexed::Dynamic(0).encode(&mut buf);
        IndexedWithPostBase(0).encode(&mut buf);
        IndexedWithPostBase(1).encode(&mut buf);

        let mut read = Cursor::new(&buf);
        let headers = decoder.decode_header(&mut read).unwrap();
        assert_eq!(headers, &[field(2), field(3), field(4)])
    }

    #[test]
    fn decode_name_ref_header_field() {
        let (mut decoder, max_entries) = build_decoder(2, 4242 * 31);

        let mut buf = vec![];
        let encoded_largest_ref = (2 % (2 * max_entries)) + 1;
        prefix_int::encode(8, 0, encoded_largest_ref, &mut buf);
        prefix_int::encode(7, 0, 0, &mut buf); // base index = 2
        LiteralWithNameRef::new_dynamic(1, "new bar1")
            .encode(&mut buf)
            .unwrap();
        LiteralWithNameRef::new_static(18, "PUT")
            .encode(&mut buf)
            .unwrap();

        let mut read = Cursor::new(&buf);
        let headers = decoder.decode_header(&mut read).unwrap();
        assert_eq!(
            headers,
            &[
                field(1).with_value("new bar1"),
                StaticTable::get(18).unwrap().with_value("PUT")
            ]
        )
    }

    #[test]
    fn decode_post_base_name_ref_header_field() {
        let (mut decoder, max_entries) = build_decoder(4, 4242 * 31);

        let mut buf = vec![];
        let encoded_largest_ref = (2 % (2 * max_entries)) + 1;
        prefix_int::encode(8, 0, encoded_largest_ref, &mut buf);
        prefix_int::encode(7, 0, 0, &mut buf); // base index = 2
        LiteralWithPostBaseNameRef::new(0, "new bar3")
            .encode(&mut buf)
            .unwrap();

        let mut read = Cursor::new(&buf);
        let headers = decoder.decode_header(&mut read).unwrap();
        assert_eq!(headers, &[field(3).with_value("new bar3")]);
    }

    #[test]
    fn decode_without_name_ref_header_field() {
        let mut buf = vec![];
        prefix_int::encode(8, 0, 0, &mut buf);
        prefix_int::encode(7, 0, 0, &mut buf);
        Literal::new("foo", "bar").encode(&mut buf).unwrap();

        let mut read = Cursor::new(&buf);
        let headers = Decoder::new().decode_header(&mut read).unwrap();
        assert_eq!(
            headers,
            &[HeaderField::new(b"foo".to_vec(), b"bar".to_vec())]
        );
    }

    // Largest Reference = 4
    //  |            Base Index = 0
    //  |                |
    // foo4 foo3  foo2  foo1
    // +---+-----+-----+-----+
    // | 4 |  3  |  2  |  1  |  Absolute Index
    // +---+-----+-----+-----+
    //                          Relative Index
    // +---+-----+-----+-----+
    // | 2 |   2 |  1  |  0  |  Post-Base Index
    // +---+-----+-----+-----+

    #[test]
    fn decode_single_pass_encoded() {
        let (mut decoder, max_entries) = build_decoder(4, 4242 * 31);

        let mut buf = vec![];
        let encoded_largest_ref = (4 % (2 * max_entries)) + 1;
        prefix_int::encode(8, 0, encoded_largest_ref, &mut buf);
        prefix_int::encode(7, 1, 3, &mut buf); // base index negative = 0
        IndexedWithPostBase(0).encode(&mut buf);
        IndexedWithPostBase(1).encode(&mut buf);
        IndexedWithPostBase(2).encode(&mut buf);
        IndexedWithPostBase(3).encode(&mut buf);

        let mut read = Cursor::new(&buf);
        let headers = decoder.decode_header(&mut read).unwrap();
        assert_eq!(headers, &[field(1), field(2), field(3), field(4)]);
    }

    #[test]
    fn base_index_too_small() {
        let (mut decoder, max_entries) = build_decoder(2, 4242 * 31);

        let mut buf = vec![];
        let encoded_largest_ref = (2 % (2 * max_entries)) + 1;
        prefix_int::encode(8, 0, encoded_largest_ref, &mut buf);
        prefix_int::encode(7, 1, 2, &mut buf); // base index negative = 0

        let mut read = Cursor::new(&buf);
        assert_eq!(
            decoder.decode_header(&mut read),
            Err(Error::BadBaseIndex(-1))
        );
    }

    #[test]
    fn largest_ref_greater_than_max_entries() {
        let (mut decoder, max_entries) = build_decoder(((4242 * 31) / 32) + 10, 4242 * 31);
        let mut buf = vec![];

        // Pre-base relative reference
        let encoded_largest_ref = ((max_entries + 5) % (2 * max_entries)) + 1;
        prefix_int::encode(8, 0, encoded_largest_ref, &mut buf);
        prefix_int::encode(7, 0, 0, &mut buf); // base index = 4114
        Indexed::Dynamic(10).encode(&mut buf);

        let mut read = Cursor::new(&buf);
        let headers = decoder.decode_header(&mut read).unwrap();
        assert_eq!(headers, &[field(4104)]);

        let mut buf = vec![];

        // Post-base reference
        let encoded_largest_ref = ((max_entries + 10) % (2 * max_entries)) + 1;
        prefix_int::encode(8, 0, encoded_largest_ref, &mut buf);
        prefix_int::encode(7, 1, 4, &mut buf); // base index = 4114
        IndexedWithPostBase(0).encode(&mut buf);
        IndexedWithPostBase(4).encode(&mut buf);

        let mut read = Cursor::new(&buf);
        let headers = decoder.decode_header(&mut read).unwrap();
        assert_eq!(headers, &[field(4115), field(4119)]);
    }
}
