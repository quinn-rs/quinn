use bytes::{Buf, BufMut};
use std::io::Cursor;

use err_derive::Error;

use super::{
    static_::{Error as StaticError, StaticTable},
    vas, DynamicTable, DynamicTableDecoder, DynamicTableError, DynamicTableInserter, HeaderField,
};

use super::{
    block::{
        HeaderBlockField, HeaderPrefix, Indexed, IndexedWithPostBase, Literal, LiteralWithNameRef,
        LiteralWithPostBaseNameRef,
    },
    parse_error::ParseError,
    stream::{
        Duplicate, DynamicTableSizeUpdate, EncoderInstruction, HeaderAck, InsertCountIncrement,
        InsertWithNameRef, InsertWithoutNameRef, StreamCancel,
    },
};

use super::{prefix_int, prefix_string};

#[derive(Debug, PartialEq, Error)]
pub enum Error {
    #[error(display = "failed to parse integer: {:?}", _0)]
    InvalidInteger(prefix_int::Error),
    #[error(display = "failed to parse string: {:?}", _0)]
    InvalidString(prefix_string::Error),
    #[error(display = "index is out of dynamic table bounds: {:?}", _0)]
    InvalidIndex(vas::Error),
    #[error(display = "dynamic table error: {}", _0)]
    DynamicTableError(DynamicTableError),
    #[error(display = "index '{}' is out of static table bounds", _0)]
    InvalidStaticIndex(usize),
    #[error(display = "invalid data prefix")]
    UnknownPrefix,
    #[error(display = "missing references from dynamic table to decode header block")]
    MissingRefs(usize),
    #[error(display = "header prefix contains invalid base index: {:?}", _0)]
    BadBaseIndex(isize),
    #[error(display = "data is unexpectedly truncated")]
    UnexpectedEnd,
}

pub fn ack_header<W: BufMut>(stream_id: u64, decoder: &mut W) {
    HeaderAck(stream_id).encode(decoder);
}

pub fn stream_canceled<W: BufMut>(stream_id: u64, decoder: &mut W) {
    StreamCancel(stream_id).encode(decoder);
}

// Decode a header bloc received on Request of Push stream. (draft: 4.5)
pub fn decode_header<T: Buf>(table: &DynamicTable, buf: &mut T) -> Result<Vec<HeaderField>, Error> {
    let (required_ref, base) =
        HeaderPrefix::decode(buf)?.get(table.total_inserted(), table.max_mem_size())?;

    if required_ref > table.total_inserted() {
        return Err(Error::MissingRefs(required_ref));
    }

    let decoder_table = table.decoder(base);

    let mut fields = Vec::new();
    while buf.has_remaining() {
        fields.push(parse_header_field(&decoder_table, buf)?);
    }

    Ok(fields)
}

fn parse_header_field<R: Buf>(
    table: &DynamicTableDecoder,
    buf: &mut R,
) -> Result<HeaderField, Error> {
    let first = buf.bytes()[0];
    let field = match HeaderBlockField::decode(first) {
        HeaderBlockField::Indexed => match Indexed::decode(buf)? {
            Indexed::Static(index) => StaticTable::get(index)?.clone(),
            Indexed::Dynamic(index) => table.get_relative(index)?.clone(),
        },
        HeaderBlockField::IndexedWithPostBase => {
            let index = IndexedWithPostBase::decode(buf)?.0;
            table.get_postbase(index)?.clone()
        }
        HeaderBlockField::LiteralWithNameRef => match LiteralWithNameRef::decode(buf)? {
            LiteralWithNameRef::Static { index, value } => {
                StaticTable::get(index)?.with_value(value)
            }
            LiteralWithNameRef::Dynamic { index, value } => {
                table.get_relative(index)?.with_value(value)
            }
        },
        HeaderBlockField::LiteralWithPostBaseNameRef => {
            let literal = LiteralWithPostBaseNameRef::decode(buf)?;
            table.get_postbase(literal.index)?.with_value(literal.value)
        }
        HeaderBlockField::Literal => {
            let literal = Literal::decode(buf)?;
            HeaderField::new(literal.name, literal.value)
        }
        _ => return Err(Error::UnknownPrefix),
    };
    Ok(field)
}

// The receiving side of encoder stream
pub fn on_encoder_recv<R: Buf, W: BufMut>(
    table: &mut DynamicTableInserter,
    read: &mut R,
    write: &mut W,
) -> Result<(), Error> {
    let inserted_on_start = table.total_inserted();

    while let Some(instruction) = parse_instruction(&table, read)? {
        match instruction {
            Instruction::Insert(field) => table.put_field(field)?,
            Instruction::TableSizeUpdate(size) => {
                table.set_max_size(size)?;
            }
        }
    }

    if table.total_inserted() != inserted_on_start {
        InsertCountIncrement(table.total_inserted() - inserted_on_start).encode(write);
    }

    Ok(())
}

fn parse_instruction<R: Buf>(
    table: &DynamicTableInserter,
    read: &mut R,
) -> Result<Option<Instruction>, Error> {
    if read.remaining() < 1 {
        return Ok(None);
    }

    let mut buf = Cursor::new(read.bytes());
    let first = buf.bytes()[0];
    let instruction = match EncoderInstruction::decode(first) {
        EncoderInstruction::Unknown => return Err(Error::UnknownPrefix),
        EncoderInstruction::DynamicTableSizeUpdate => {
            DynamicTableSizeUpdate::decode(&mut buf)?.map(|x| Instruction::TableSizeUpdate(x.0))
        }
        EncoderInstruction::InsertWithoutNameRef => InsertWithoutNameRef::decode(&mut buf)?
            .map(|x| Instruction::Insert(HeaderField::new(x.name, x.value))),
        EncoderInstruction::Duplicate => match Duplicate::decode(&mut buf)? {
            Some(Duplicate(index)) => Some(Instruction::Insert(table.get_relative(index)?.clone())),
            None => None,
        },
        EncoderInstruction::InsertWithNameRef => match InsertWithNameRef::decode(&mut buf)? {
            Some(InsertWithNameRef::Static { index, value }) => Some(Instruction::Insert(
                StaticTable::get(index)?.with_value(value),
            )),
            Some(InsertWithNameRef::Dynamic { index, value }) => Some(Instruction::Insert(
                table.get_relative(index)?.with_value(value),
            )),
            None => None,
        },
    };

    if instruction.is_some() {
        let pos = buf.position();
        read.advance(pos as usize);
    }

    Ok(instruction)
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

impl From<StaticError> for Error {
    fn from(e: StaticError) -> Self {
        match e {
            StaticError::Unknown(i) => Error::InvalidStaticIndex(i),
        }
    }
}

impl From<DynamicTableError> for Error {
    fn from(e: DynamicTableError) -> Self {
        Error::DynamicTableError(e)
    }
}

impl From<ParseError> for Error {
    fn from(e: ParseError) -> Self {
        match e {
            ParseError::InvalidInteger(x) => Error::InvalidInteger(x),
            ParseError::InvalidString(x) => Error::InvalidString(x),
            ParseError::InvalidPrefix(_) => Error::UnknownPrefix,
            ParseError::InvalidBase(b) => Error::BadBaseIndex(b),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qpack::tests::helpers::{build_table_with_size, TABLE_SIZE};

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
        let mut table = build_table_with_size(0);
        let mut enc = Cursor::new(&buf);
        let mut dec = vec![];
        assert!(on_encoder_recv(&mut table.inserter(), &mut enc, &mut dec).is_ok());

        assert_eq!(
            table.decoder(1).get_relative(0),
            Ok(&StaticTable::get(1).unwrap().with_value("serial value"))
        );

        let mut dec_cursor = Cursor::new(&dec);
        assert_eq!(
            InsertCountIncrement::decode(&mut dec_cursor),
            Ok(Some(InsertCountIncrement(1)))
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
        let mut table = build_table_with_size(0);
        let res = on_encoder_recv(&mut table.inserter(), &mut enc, &mut vec![]);
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
        let mut table = build_table_with_size(0);
        let res = on_encoder_recv(&mut table.inserter(), &mut enc, &mut dec);
        assert_eq!(
            res,
            Err(Error::DynamicTableError(
                DynamicTableError::BadRelativeIndex(3000)
            ))
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

        let mut table = build_table_with_size(0);
        let mut enc = Cursor::new(&buf);
        let mut dec = vec![];
        assert!(on_encoder_recv(&mut table.inserter(), &mut enc, &mut dec).is_ok());

        assert_eq!(
            table.decoder(1).get_relative(0),
            Ok(&HeaderField::new("key", "value"))
        );

        let mut dec_cursor = Cursor::new(&dec);
        assert_eq!(
            InsertCountIncrement::decode(&mut dec_cursor),
            Ok(Some(InsertCountIncrement(1)))
        );
    }

    fn insert_fields(table: &mut DynamicTable, fields: Vec<HeaderField>) {
        let mut inserter = table.inserter();
        for field in fields {
            inserter.put_field(field).unwrap();
        }
    }

    /**
     * https://tools.ietf.org/html/draft-ietf-quic-qpack-00
     * 4.3.3.  Duplicate
     */
    #[test]
    fn test_duplicate_field() {
        // let mut table = build_table_with_size(0);
        let mut table = build_table_with_size(0);
        insert_fields(
            &mut table,
            vec![HeaderField::new("", ""), HeaderField::new("", "")],
        );

        let mut buf = vec![];
        Duplicate(1).encode(&mut buf);

        let mut enc = Cursor::new(&buf);
        let mut dec = vec![];
        let res = on_encoder_recv(&mut table.inserter(), &mut enc, &mut dec);
        assert_eq!(res, Ok(()));

        let mut dec_cursor = Cursor::new(&dec);
        assert_eq!(
            InsertCountIncrement::decode(&mut dec_cursor),
            Ok(Some(InsertCountIncrement(1)))
        );
    }

    /**
     * https://tools.ietf.org/html/draft-ietf-quic-qpack-00
     * 4.3.4.  Dynamic Table Size Update
     */
    #[test]
    fn test_dynamic_table_size_update() {
        let mut buf = vec![];
        DynamicTableSizeUpdate(25).encode(&mut buf);

        let mut enc = Cursor::new(&buf);
        let mut dec = vec![];
        let mut table = build_table_with_size(0);
        let res = on_encoder_recv(&mut table.inserter(), &mut enc, &mut dec);
        assert_eq!(res, Ok(()));

        let actual_max_size = table.max_mem_size();
        assert_eq!(actual_max_size, 25);
        assert!(dec.is_empty());
    }

    #[test]
    fn enc_recv_buf_too_short() {
        let mut table = build_table_with_size(0);
        let inserting = table.inserter();
        let mut buf = vec![];
        {
            let mut enc = Cursor::new(&buf);
            assert_eq!(parse_instruction(&inserting, &mut enc), Ok(None));
        }

        buf.push(0b1000_0000);
        let mut enc = Cursor::new(&buf);
        assert_eq!(parse_instruction(&inserting, &mut enc), Ok(None));
    }

    #[test]
    fn enc_recv_accepts_truncated_messages() {
        let mut buf = vec![];
        InsertWithoutNameRef::new("keyfoobarbaz", "value")
            .encode(&mut buf)
            .unwrap();

        let mut table = build_table_with_size(0);
        // cut in middle of the first int
        let mut enc = Cursor::new(&buf[..2]);
        let mut dec = vec![];
        assert!(on_encoder_recv(&mut table.inserter(), &mut enc, &mut dec).is_ok());
        assert_eq!(enc.position(), 0);

        // cut the last byte of the 2nd string
        let mut enc = Cursor::new(&buf[..buf.len() - 1]);
        let mut dec = vec![];
        assert!(on_encoder_recv(&mut table.inserter(), &mut enc, &mut dec).is_ok());
        assert_eq!(enc.position(), 0);

        InsertWithoutNameRef::new("keyfoobarbaz2", "value")
            .encode(&mut buf)
            .unwrap();

        // the first valid field is inserted and buf is left at the first byte of incomplete string
        let mut enc = Cursor::new(&buf[..buf.len() - 1]);
        let mut dec = vec![];
        assert!(on_encoder_recv(&mut table.inserter(), &mut enc, &mut dec).is_ok());
        assert_eq!(enc.position(), 15);

        let mut dec_cursor = Cursor::new(&dec);
        assert_eq!(
            InsertCountIncrement::decode(&mut dec_cursor),
            Ok(Some(InsertCountIncrement(1)))
        );
    }

    #[test]
    fn largest_ref_too_big() {
        let table = build_table_with_size(0);
        let mut buf = vec![];
        HeaderPrefix::new(8, 8, 10, TABLE_SIZE).encode(&mut buf);

        let mut read = Cursor::new(&buf);
        assert_eq!(decode_header(&table, &mut read), Err(Error::MissingRefs(8)));
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
        let mut buf = vec![];
        HeaderPrefix::new(2, 2, 2, TABLE_SIZE).encode(&mut buf);
        Indexed::Dynamic(0).encode(&mut buf);
        Indexed::Dynamic(1).encode(&mut buf);
        Indexed::Static(18).encode(&mut buf);

        let mut read = Cursor::new(&buf);
        let headers = decode_header(&build_table_with_size(2), &mut read).unwrap();
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
        let mut buf = vec![];
        HeaderPrefix::new(4, 2, 4, TABLE_SIZE).encode(&mut buf);
        Indexed::Dynamic(0).encode(&mut buf);
        IndexedWithPostBase(0).encode(&mut buf);
        IndexedWithPostBase(1).encode(&mut buf);

        let mut read = Cursor::new(&buf);
        let headers = decode_header(&build_table_with_size(4), &mut read).unwrap();
        assert_eq!(headers, &[field(2), field(3), field(4)])
    }

    #[test]
    fn decode_name_ref_header_field() {
        let mut buf = vec![];
        HeaderPrefix::new(2, 2, 4, TABLE_SIZE).encode(&mut buf);
        LiteralWithNameRef::new_dynamic(1, "new bar1")
            .encode(&mut buf)
            .unwrap();
        LiteralWithNameRef::new_static(18, "PUT")
            .encode(&mut buf)
            .unwrap();

        let mut read = Cursor::new(&buf);
        let headers = decode_header(&build_table_with_size(4), &mut read).unwrap();
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
        let mut buf = vec![];
        HeaderPrefix::new(2, 2, 4, TABLE_SIZE).encode(&mut buf);
        LiteralWithPostBaseNameRef::new(0, "new bar3")
            .encode(&mut buf)
            .unwrap();

        let mut read = Cursor::new(&buf);
        let headers = decode_header(&build_table_with_size(4), &mut read).unwrap();
        assert_eq!(headers, &[field(3).with_value("new bar3")]);
    }

    #[test]
    fn decode_without_name_ref_header_field() {
        let mut buf = vec![];
        HeaderPrefix::new(0, 0, 0, TABLE_SIZE).encode(&mut buf);
        Literal::new("foo", "bar").encode(&mut buf).unwrap();

        let mut read = Cursor::new(&buf);
        let table = build_table_with_size(0);
        let headers = decode_header(&table, &mut read).unwrap();
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
        let mut buf = vec![];
        HeaderPrefix::new(4, 0, 4, TABLE_SIZE).encode(&mut buf);
        IndexedWithPostBase(0).encode(&mut buf);
        IndexedWithPostBase(1).encode(&mut buf);
        IndexedWithPostBase(2).encode(&mut buf);
        IndexedWithPostBase(3).encode(&mut buf);

        let mut read = Cursor::new(&buf);
        let headers = decode_header(&build_table_with_size(4), &mut read).unwrap();
        assert_eq!(headers, &[field(1), field(2), field(3), field(4)]);
    }

    #[test]
    fn largest_ref_greater_than_max_entries() {
        let max_entries = TABLE_SIZE / 32;
        // some fields evicted
        let table = build_table_with_size(max_entries + 10);
        let mut buf = vec![];

        // Pre-base relative reference
        HeaderPrefix::new(
            max_entries + 5,
            max_entries + 5,
            max_entries + 10,
            TABLE_SIZE,
        )
        .encode(&mut buf);
        Indexed::Dynamic(10).encode(&mut buf);

        let mut read = Cursor::new(&buf);
        let headers =
            decode_header(&build_table_with_size(max_entries + 10), &mut read).expect("decode");
        assert_eq!(headers, &[field(max_entries - 5)]);

        let mut buf = vec![];

        // Post-base reference
        HeaderPrefix::new(
            max_entries + 10,
            max_entries + 5,
            max_entries + 10,
            TABLE_SIZE,
        )
        .encode(&mut buf);
        IndexedWithPostBase(0).encode(&mut buf);
        IndexedWithPostBase(4).encode(&mut buf);

        let mut read = Cursor::new(&buf);
        let headers = decode_header(&table, &mut read).unwrap();
        assert_eq!(headers, &[field(max_entries + 6), field(max_entries + 10)]);
    }
}
