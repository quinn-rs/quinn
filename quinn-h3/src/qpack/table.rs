// This is only here because qpack is new and quinn no uses it yet.
// TODO remove allow dead code
#![allow(dead_code)]

use std::borrow::Cow;
use std::collections::VecDeque;


#[derive(Debug, PartialEq, Clone)]
pub struct HeaderField {
    pub name: Cow<'static, str>,
    pub value: Cow<'static, str>
}


impl HeaderField {
    pub fn new<T>(name: T, value: T) -> HeaderField
        where T: Into<String> {
        HeaderField {
            name: Cow::Owned(name.into()),
            value: Cow::Owned(value.into())
        }
    }

    pub fn from_static(name: &'static str, value: &'static str) -> HeaderField {
        HeaderField {
            name: Cow::Borrowed(name),
            value: Cow::Borrowed(value)
        }
    }
}


pub trait HeaderTable {
    fn get(&self, index: usize) -> Option<&HeaderField>;

    fn count(&self) -> usize;
}
