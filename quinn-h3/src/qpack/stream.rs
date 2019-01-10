use bytes::{Buf, BufMut};
use std::borrow::Cow;
use std::io::Cursor;

use super::prefix_int::{self, Error as IntError};
use super::prefix_string::{self, Error as StringError};
use super::table::field::HeaderField;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidInteger(prefix_int::Error),
    InvalidString(prefix_string::Error),
    InvalidPrefix,
}

pub enum InstructionType {
    InsertWithNameRef,
    InsertWithoutNameRef,
    Duplicate,
    DynamicTableSizeUpdate,
    Unknown,
}

impl InstructionType {
    pub fn decode(first: u8) -> Self {
        if first & 0b1000_0000 != 0 {
            InstructionType::InsertWithNameRef
        } else if first & 0b0100_0000 == 0b0100_0000 {
            InstructionType::InsertWithoutNameRef
        } else if first & 0b1110_0000 == 0 {
            InstructionType::Duplicate
        } else if first & 0b0010_0000 == 0b0010_0000 {
            InstructionType::DynamicTableSizeUpdate
        } else {
            InstructionType::Unknown
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum InsertWithNameRef {
    Static { index: usize, value: Vec<u8> },
    Dynamic { index: usize, value: Vec<u8> },
}

impl InsertWithNameRef {
    pub fn new_static<T: Into<Vec<u8>>>(index: usize, value: T) -> Self {
        InsertWithNameRef::Static {
            index,
            value: value.into(),
        }
    }

    pub fn new_dynamic<T: Into<Vec<u8>>>(index: usize, value: T) -> Self {
        InsertWithNameRef::Dynamic {
            index,
            value: value.into(),
        }
    }

    pub fn decode<R: Buf>(buf: &mut R) -> Result<Option<Self>, Error> {
        let (flags, index) = match prefix_int::decode(6, buf) {
            Ok((f, x)) if f & 0b10 == 0b10 => (f, x),
            Ok((_, _)) => return Err(Error::InvalidPrefix),
            Err(IntError::UnexpectedEnd) => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        let value = match prefix_string::decode(8, buf) {
            Ok(x) => x,
            Err(StringError::UnexpectedEnd) => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        if flags & 0b01 == 0b01 {
            Ok(Some(InsertWithNameRef::new_static(index, value)))
        } else {
            Ok(Some(InsertWithNameRef::new_dynamic(index, value)))
        }
    }

    pub fn encode<W: BufMut>(&self, buf: &mut W) -> Result<(), prefix_string::Error> {
        match self {
            InsertWithNameRef::Static { index, value } => {
                prefix_int::encode(6, 0b11, *index, buf);
                prefix_string::encode(8, 0, value, buf)?;
            }
            InsertWithNameRef::Dynamic { index, value } => {
                prefix_int::encode(6, 0b10, *index, buf);
                prefix_string::encode(8, 0, value, buf)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub struct InsertWithoutNameRef {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

impl InsertWithoutNameRef {
    pub fn new<T: Into<Vec<u8>>>(name: T, value: T) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    pub fn decode<R: Buf>(buf: &mut R) -> Result<Option<Self>, Error> {
        let name = match prefix_string::decode(6, buf) {
            Ok(x) => x,
            Err(StringError::UnexpectedEnd) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let value = match prefix_string::decode(8, buf) {
            Ok(x) => x,
            Err(StringError::UnexpectedEnd) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        Ok(Some(Self::new(name, value)))
    }

    pub fn encode<W: BufMut>(&self, buf: &mut W) -> Result<(), prefix_string::Error> {
        prefix_string::encode(6, 0b01, &self.name, buf)?;
        prefix_string::encode(8, 0, &self.value, buf)?;
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub struct Duplicate {
    pub index: usize,
}

impl Duplicate {
    pub fn decode<R: Buf>(buf: &mut R) -> Result<Option<Self>, Error> {
        let index = match prefix_int::decode(5, buf) {
            Ok((0, x)) => x,
            Ok((_, _)) => return Err(Error::InvalidPrefix),
            Err(IntError::UnexpectedEnd) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        Ok(Some(Duplicate { index }))
    }

    pub fn encode<W: BufMut>(&self, buf: &mut W) {
        prefix_int::encode(5, 0, self.index, buf);
    }
}

#[derive(Debug, PartialEq)]
pub struct DynamicTableSizeUpdate {
    pub size: usize,
}

impl DynamicTableSizeUpdate {
    pub fn decode<R: Buf>(buf: &mut R) -> Result<Option<Self>, Error> {
        let size = match prefix_int::decode(5, buf) {
            Ok((0b001, x)) => x,
            Ok((_, _)) => return Err(Error::InvalidPrefix),
            Err(IntError::UnexpectedEnd) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        Ok(Some(DynamicTableSizeUpdate { size }))
    }

    pub fn encode<W: BufMut>(&self, buf: &mut W) {
        prefix_int::encode(5, 0b001, self.size, buf);
    }
}

#[derive(Debug, PartialEq)]
pub struct TableSizeSync {
    pub insert_count: usize,
}

impl TableSizeSync {
    pub fn decode<R: Buf>(buf: &mut R) -> Result<Option<Self>, Error> {
        let insert_count = match prefix_int::decode(6, buf) {
            Ok((0b00, x)) => x,
            Ok((_, _)) => return Err(Error::InvalidPrefix),
            Err(IntError::UnexpectedEnd) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        Ok(Some(TableSizeSync { insert_count }))
    }

    pub fn encode<W: BufMut>(&self, buf: &mut W) {
        prefix_int::encode(6, 0b00, self.insert_count, buf);
    }
}

impl From<prefix_int::Error> for Error {
    fn from(e: prefix_int::Error) -> Self {
        match e {
            e => Error::InvalidInteger(e),
        }
    }
}

impl From<prefix_string::Error> for Error {
    fn from(e: prefix_string::Error) -> Self {
        match e {
            e => Error::InvalidString(e),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn insert_with_name_ref() {
        let instruction = InsertWithNameRef::new_static(0, "value");
        let mut buf = vec![];
        instruction.encode(&mut buf).unwrap();
        let mut read = Cursor::new(&buf);
        assert_eq!(InsertWithNameRef::decode(&mut read), Ok(Some(instruction)));
    }

    #[test]
    fn insert_without_name_ref() {
        let instruction = InsertWithoutNameRef::new("name", "value");
        let mut buf = vec![];
        instruction.encode(&mut buf).unwrap();
        let mut read = Cursor::new(&buf);
        assert_eq!(
            InsertWithoutNameRef::decode(&mut read),
            Ok(Some(instruction))
        );
    }

    #[test]
    fn insert_duplicate() {
        let instruction = Duplicate { index: 42 };
        let mut buf = vec![];
        instruction.encode(&mut buf);
        let mut read = Cursor::new(&buf);
        assert_eq!(Duplicate::decode(&mut read), Ok(Some(instruction)));
    }

    #[test]
    fn dynamic_table_size_update() {
        let instruction = DynamicTableSizeUpdate { size: 42 };
        let mut buf = vec![];
        instruction.encode(&mut buf);
        let mut read = Cursor::new(&buf);
        assert_eq!(
            DynamicTableSizeUpdate::decode(&mut read),
            Ok(Some(instruction))
        );
    }

    #[test]
    fn table_size_sync() {
        let instruction = TableSizeSync { insert_count: 42 };
        let mut buf = vec![];
        instruction.encode(&mut buf);
        let mut read = Cursor::new(&buf);
        assert_eq!(TableSizeSync::decode(&mut read), Ok(Some(instruction)));
    }
}
