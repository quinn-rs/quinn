// This is only here because qpack is new and quinn no uses it yet.
// TODO remove allow dead code
#![allow(dead_code)]

use std::collections::VecDeque;


#[derive(Debug, PartialEq, Clone)]
pub struct HeaderField {
    // TODO use Cow to avoid copy when possible
    pub name: String,
    pub value: String,
}


impl HeaderField {
    pub fn new<T>(name: T, value: T) -> HeaderField where T: Into<String> {
        HeaderField {
            name: name.into(),
            value: value.into()
        }
    }
}


pub trait HeaderTable {
    fn get(&self, index: usize) -> Option<&HeaderField>;

    fn count(&self) -> usize;
}
