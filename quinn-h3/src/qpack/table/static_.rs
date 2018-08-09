// This is only here because qpack is new and quinn no uses it yet.
// TODO remove allow dead code
#![allow(dead_code)]

use std::borrow::Cow;

use super::field::HeaderField;


#[allow(unused_macros)]
macro_rules! decl_fields {
    [ $( ($key:expr, $value:expr) ),* ] => {
        [ $(
            HeaderField {
                name: Cow::Borrowed($key),
                value: Cow::Borrowed($value)
            },
        )* ]
    }
}

const PREDEFINED_HEADERS: [HeaderField; 61] = decl_fields![
    (b":authority", b""),
    (b":method", b"GET"),
    (b":method", b"POST"),
    (b":path", b"/"),
    (b":path", b"/index.html"),
    (b":scheme", b"http"),
    (b":scheme", b"https"),
    (b":status", b"200"),
    (b":status", b"204"),
    (b":status", b"206"),
    (b":status", b"304"),
    (b":status", b"400"),
    (b":status", b"404"),
    (b":status", b"500"),
    (b"accept-charset", b""),
    (b"accept-encoding", b"gzip, deflate"),
    (b"accept-language", b""),
    (b"accept-ranges", b""),
    (b"accept", b""),
    (b"access-control-allow-origin", b""),
    (b"age", b""),
    (b"allow", b""),
    (b"authorization", b""),
    (b"cache-control", b""),
    (b"content-disposition", b""),
    (b"content-encoding", b""),
    (b"content-language", b""),
    (b"content-length", b""),
    (b"content-location", b""),
    (b"content-range", b""),
    (b"content-type", b""),
    (b"cookie", b""),
    (b"date", b""),
    (b"etag", b""),
    (b"expect", b""),
    (b"expires", b""),
    (b"from", b""),
    (b"host", b""),
    (b"if-match", b""),
    (b"if-modified-since", b""),
    (b"if-none-match", b""),
    (b"if-range", b""),
    (b"if-unmodified-since", b""),
    (b"last-modified", b""),
    (b"link", b""),
    (b"location", b""),
    (b"max-forwards", b""),
    (b"proxy-authenticate", b""),
    (b"proxy-authorization", b""),
    (b"range", b""),
    (b"referer", b""),
    (b"refresh", b""),
    (b"retry-after", b""),
    (b"server", b""),
    (b"set-cookie", b""),
    (b"strict-transport-security", b""),
    (b"transfer-encoding", b""),
    (b"user-agent", b""),
    (b"vary", b""),
    (b"via", b""),
    (b"www-authenticate", b"")
];

pub struct StaticTable {}


impl StaticTable {
    pub fn get(index: usize) -> Option<&'static HeaderField> {
        PREDEFINED_HEADERS.get(index)
    }
    
    pub fn count() -> usize {
        PREDEFINED_HEADERS.len()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_table_is_available() {
        let field = HeaderField::new("www-authenticate", "");
        assert_eq!(StaticTable::count(), 61);
        assert_eq!(StaticTable::get(60), Some(&field));
    }
}
