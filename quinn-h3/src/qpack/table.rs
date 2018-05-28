// This is only here because qpack is new and quinn no uses it yet.
// TODO remove allow dead code
#![allow(dead_code)]

use std::borrow::Cow;
use std::collections::VecDeque;


#[derive(Debug, PartialEq, Clone)]
pub struct HeaderField {
    pub name: Cow<'static, [u8]>,
    pub value: Cow<'static, [u8]>
}


impl HeaderField {
    pub fn new<T, S>(name: T, value: S) -> HeaderField
        where T: Into<Vec<u8>>,
              S: Into<Vec<u8>> {
        HeaderField {
            name: Cow::Owned(name.into()),
            value: Cow::Owned(value.into())
        }
    }
}
