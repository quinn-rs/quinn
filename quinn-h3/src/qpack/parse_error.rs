use super::{prefix_int, prefix_string};

#[derive(Debug, PartialEq)]
pub enum ParseError {
    InvalidInteger(prefix_int::Error),
    InvalidString(prefix_string::Error),
    InvalidPrefix(u8),
    InvalidBase(isize),
}

impl From<prefix_int::Error> for ParseError {
    fn from(e: prefix_int::Error) -> Self {
        ParseError::InvalidInteger(e)
    }
}

impl From<prefix_string::Error> for ParseError {
    fn from(e: prefix_string::Error) -> Self {
        ParseError::InvalidString(e)
    }
}
