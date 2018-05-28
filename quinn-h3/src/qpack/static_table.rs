// This is only here because qpack is new and quinn no uses it yet.
// TODO remove allow dead code
#![allow(dead_code)]

use std::borrow::Cow;

use super::table::{HeaderField, HeaderTable};


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
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", "")
];

pub struct StaticTable {}


impl HeaderTable for StaticTable {
    fn get(&self, index: usize) -> Option<&HeaderField> {
        PREDEFINED_HEADERS.get(index)
    }
    
    fn count(&self) -> usize {
        PREDEFINED_HEADERS.len()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_table_is_available() {
        let table = StaticTable {};
        let field = HeaderField::new("www-authenticate", "");
        assert_eq!(table.get(60), Some(&field));
    }
}
