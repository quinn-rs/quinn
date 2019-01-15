use bytes::{Buf, BufMut};
use std::io::Cursor;

use super::prefix_int;
use super::prefix_string;
use super::ParseError;

pub enum HeaderBlocField {
    Indexed,
    IndexedWithPostBase,
    LiteralWithNameRef,
    LiteralWithPostBaseNameRef,
    Literal,
    Unknown,
}

impl HeaderBlocField {
    pub fn decode(first: u8) -> Self {
        if first & 0b1000_0000 != 0 {
            HeaderBlocField::Indexed
        } else if first & 0b1111_0000 == 0b0001_0000 {
            HeaderBlocField::IndexedWithPostBase
        } else if first & 0b1100_0000 == 0b0100_0000 {
            HeaderBlocField::LiteralWithNameRef
        } else if first & 0b1111_0000 == 0 {
            HeaderBlocField::LiteralWithPostBaseNameRef
        } else if first & 0b1110_0000 == 0b0010_0000 {
            HeaderBlocField::Literal
        } else {
            HeaderBlocField::Unknown
        }
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
            (f, i) => Err(ParseError::InvalidPrefix(f)),
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
        } else if buf.bytes()[0] & 0b1110_0000 != 0b0010_0000 {
            return Err(ParseError::InvalidPrefix(buf.bytes()[0]));
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
}
