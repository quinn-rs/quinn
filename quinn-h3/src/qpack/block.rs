use bytes::{Buf, BufMut};

use super::{parse_error::ParseError, prefix_int, prefix_string};

pub enum HeaderBlockField {
    Indexed,
    IndexedWithPostBase,
    LiteralWithNameRef,
    LiteralWithPostBaseNameRef,
    Literal,
    Unknown,
}

impl HeaderBlockField {
    pub fn decode(first: u8) -> Self {
        if first & 0b1000_0000 != 0 {
            HeaderBlockField::Indexed
        } else if first & 0b1111_0000 == 0b0001_0000 {
            HeaderBlockField::IndexedWithPostBase
        } else if first & 0b1100_0000 == 0b0100_0000 {
            HeaderBlockField::LiteralWithNameRef
        } else if first & 0b1111_0000 == 0 {
            HeaderBlockField::LiteralWithPostBaseNameRef
        } else if first & 0b1110_0000 == 0b0010_0000 {
            HeaderBlockField::Literal
        } else {
            HeaderBlockField::Unknown
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct HeaderPrefix {
    encoded_insert_count: usize,
    sign_negative: bool,
    delta_base: usize,
}

impl HeaderPrefix {
    pub fn new(required: usize, base: usize, total_inserted: usize, max_table_size: usize) -> Self {
        if max_table_size == 0 {
            return Self {
                encoded_insert_count: 0,
                sign_negative: false,
                delta_base: 0,
            };
        }

        if required == 0 {
            return Self {
                encoded_insert_count: 0,
                delta_base: 0,
                sign_negative: false,
            };
        }

        assert!(required <= total_inserted);
        let (sign_negative, delta_base) = if required > base {
            (true, required - base - 1)
        } else {
            (false, base - required)
        };

        let max_entries = max_table_size / 32;

        Self {
            encoded_insert_count: required % (2 * max_entries) + 1,
            sign_negative,
            delta_base,
        }
    }

    pub fn get(
        self,
        total_inserted: usize,
        max_table_size: usize,
    ) -> Result<(usize, usize), ParseError> {
        if max_table_size == 0 {
            return Ok((0, 0));
        }

        let required = if self.encoded_insert_count == 0 {
            0
        } else {
            let mut insert_count = self.encoded_insert_count - 1;
            let max_entries = max_table_size / 32;
            let mut wrapped = total_inserted % (2 * max_entries);

            if wrapped >= insert_count + max_entries {
                insert_count += 2 * max_entries;
            } else if wrapped + max_entries < insert_count {
                wrapped += 2 * max_entries;
            }

            insert_count + total_inserted - wrapped
        };

        let base = if required == 0 {
            0
        } else if !self.sign_negative {
            required + self.delta_base
        } else {
            if self.delta_base + 1 > required {
                return Err(ParseError::InvalidBase(
                    required as isize - self.delta_base as isize - 1,
                ));
            }
            required - self.delta_base - 1
        };

        Ok((required, base))
    }

    pub fn decode<R: Buf>(buf: &mut R) -> Result<Self, ParseError> {
        let (_, encoded_insert_count) = prefix_int::decode(8, buf)?;
        let (sign_negative, delta_base) = prefix_int::decode(7, buf)?;
        Ok(Self {
            encoded_insert_count,
            delta_base,
            sign_negative: sign_negative == 1,
        })
    }

    pub fn encode<W: BufMut>(&self, buf: &mut W) {
        let sign_bit = if self.sign_negative { 1 } else { 0 };
        prefix_int::encode(8, 0, self.encoded_insert_count, buf);
        prefix_int::encode(7, sign_bit, self.delta_base, buf);
    }
}

#[derive(Debug, PartialEq)]
pub enum Indexed {
    Static(usize),
    Dynamic(usize),
}

impl Indexed {
    pub fn decode<R: Buf>(buf: &mut R) -> Result<Self, ParseError> {
        match prefix_int::decode(6, buf)? {
            (0b11, i) => Ok(Indexed::Static(i)),
            (0b10, i) => Ok(Indexed::Dynamic(i)),
            (f, _) => Err(ParseError::InvalidPrefix(f)),
        }
    }

    pub fn encode<W: BufMut>(&self, buf: &mut W) {
        match self {
            Indexed::Static(i) => prefix_int::encode(6, 0b11, *i, buf),
            Indexed::Dynamic(i) => prefix_int::encode(6, 0b10, *i, buf),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct IndexedWithPostBase(pub usize);

impl IndexedWithPostBase {
    pub fn decode<R: Buf>(buf: &mut R) -> Result<Self, ParseError> {
        match prefix_int::decode(4, buf)? {
            (0b0001, i) => Ok(IndexedWithPostBase(i)),
            (f, _) => Err(ParseError::InvalidPrefix(f)),
        }
    }

    pub fn encode<W: BufMut>(&self, buf: &mut W) {
        prefix_int::encode(4, 0b0001, self.0, buf)
    }
}

#[derive(Debug, PartialEq)]
pub enum LiteralWithNameRef {
    Static { index: usize, value: Vec<u8> },
    Dynamic { index: usize, value: Vec<u8> },
}

impl LiteralWithNameRef {
    pub fn new_static<T: Into<Vec<u8>>>(index: usize, value: T) -> Self {
        LiteralWithNameRef::Static {
            index,
            value: value.into(),
        }
    }

    pub fn new_dynamic<T: Into<Vec<u8>>>(index: usize, value: T) -> Self {
        LiteralWithNameRef::Dynamic {
            index,
            value: value.into(),
        }
    }

    pub fn decode<R: Buf>(buf: &mut R) -> Result<Self, ParseError> {
        match prefix_int::decode(4, buf)? {
            (f, i) if f & 0b0101 == 0b0101 => Ok(LiteralWithNameRef::new_static(
                i,
                prefix_string::decode(8, buf)?,
            )),
            (f, i) if f & 0b0101 == 0b0100 => Ok(LiteralWithNameRef::new_dynamic(
                i,
                prefix_string::decode(8, buf)?,
            )),
            (f, _) => Err(ParseError::InvalidPrefix(f)),
        }
    }

    pub fn encode<W: BufMut>(&self, buf: &mut W) -> Result<(), prefix_string::Error> {
        match self {
            LiteralWithNameRef::Static { index, value } => {
                prefix_int::encode(4, 0b0101, *index, buf);
                prefix_string::encode(8, 0, value, buf)?;
            }
            LiteralWithNameRef::Dynamic { index, value } => {
                prefix_int::encode(4, 0b0100, *index, buf);
                prefix_string::encode(8, 0, value, buf)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub struct LiteralWithPostBaseNameRef {
    pub index: usize,
    pub value: Vec<u8>,
}

impl LiteralWithPostBaseNameRef {
    pub fn new<T: Into<Vec<u8>>>(index: usize, value: T) -> Self {
        LiteralWithPostBaseNameRef {
            index,
            value: value.into(),
        }
    }

    pub fn decode<R: Buf>(buf: &mut R) -> Result<Self, ParseError> {
        match prefix_int::decode(3, buf)? {
            (f, i) if f & 0b1111_0000 == 0 => Ok(LiteralWithPostBaseNameRef::new(
                i,
                prefix_string::decode(8, buf)?,
            )),
            (f, _) => Err(ParseError::InvalidPrefix(f)),
        }
    }

    pub fn encode<W: BufMut>(&self, buf: &mut W) -> Result<(), prefix_string::Error> {
        prefix_int::encode(3, 0b0000, self.index, buf);
        prefix_string::encode(8, 0, &self.value, buf)?;
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub struct Literal {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

impl Literal {
    pub fn new<T: Into<Vec<u8>>>(name: T, value: T) -> Self {
        Literal {
            name: name.into(),
            value: value.into(),
        }
    }

    pub fn decode<R: Buf>(buf: &mut R) -> Result<Self, ParseError> {
        if buf.remaining() < 1 {
            return Err(ParseError::InvalidInteger(prefix_int::Error::UnexpectedEnd));
        } else if buf.chunk()[0] & 0b1110_0000 != 0b0010_0000 {
            return Err(ParseError::InvalidPrefix(buf.chunk()[0]));
        }
        Ok(Literal::new(
            prefix_string::decode(4, buf)?,
            prefix_string::decode(8, buf)?,
        ))
    }

    pub fn encode<W: BufMut>(&self, buf: &mut W) -> Result<(), prefix_string::Error> {
        prefix_string::encode(4, 0b0010, &self.name, buf)?;
        prefix_string::encode(8, 0, &self.value, buf)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Cursor;

    const TABLE_SIZE: usize = 4096;

    #[test]
    fn indexed_static() {
        let field = Indexed::Static(42);
        let mut buf = vec![];
        field.encode(&mut buf);
        let mut read = Cursor::new(&buf);
        assert_eq!(Indexed::decode(&mut read), Ok(field));
    }

    #[test]
    fn indexed_dynamic() {
        let field = Indexed::Dynamic(42);
        let mut buf = vec![];
        field.encode(&mut buf);
        let mut read = Cursor::new(&buf);
        assert_eq!(Indexed::decode(&mut read), Ok(field));
    }

    #[test]
    fn indexed_with_postbase() {
        let field = IndexedWithPostBase(42);
        let mut buf = vec![];
        field.encode(&mut buf);
        let mut read = Cursor::new(&buf);
        assert_eq!(IndexedWithPostBase::decode(&mut read), Ok(field));
    }

    #[test]
    fn literal_with_name_ref() {
        let field = LiteralWithNameRef::new_static(42, "foo");
        let mut buf = vec![];
        field.encode(&mut buf).unwrap();
        let mut read = Cursor::new(&buf);
        assert_eq!(LiteralWithNameRef::decode(&mut read), Ok(field));
    }

    #[test]
    fn literal_with_post_base_name_ref() {
        let field = LiteralWithPostBaseNameRef::new(42, "foo");
        let mut buf = vec![];
        field.encode(&mut buf).unwrap();
        let mut read = Cursor::new(&buf);
        assert_eq!(LiteralWithPostBaseNameRef::decode(&mut read), Ok(field));
    }

    #[test]
    fn literal() {
        let field = Literal::new("foo", "bar");
        let mut buf = vec![];
        field.encode(&mut buf).unwrap();
        let mut read = Cursor::new(&buf);
        assert_eq!(Literal::decode(&mut read), Ok(field));
    }

    #[test]
    fn header_prefix() {
        let prefix = HeaderPrefix::new(10, 5, 12, TABLE_SIZE);
        let mut buf = vec![];
        prefix.encode(&mut buf);
        let mut read = Cursor::new(&buf);
        let decoded = HeaderPrefix::decode(&mut read);
        assert_eq!(decoded, Ok(prefix));
        assert_eq!(decoded.unwrap().get(13, 3332).unwrap(), (10, 5));
    }

    #[test]
    fn header_prefix_table_size_0() {
        HeaderPrefix::new(10, 5, 12, 0).get(1, 0).unwrap();
    }

    #[test]
    fn base_index_too_small() {
        let mut buf = vec![];
        let encoded_largest_ref = (2 % (2 * TABLE_SIZE / 32)) + 1;
        prefix_int::encode(8, 0, encoded_largest_ref, &mut buf);
        prefix_int::encode(7, 1, 2, &mut buf); // base index negative = 0

        let mut read = Cursor::new(&buf);
        assert_eq!(
            HeaderPrefix::decode(&mut read).unwrap().get(2, TABLE_SIZE),
            Err(ParseError::InvalidBase(-1))
        );
    }
}
