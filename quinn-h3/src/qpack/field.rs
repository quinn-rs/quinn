use std::{
    borrow::Cow,
    fmt::{Display, Formatter},
};

/**
 * https://tools.ietf.org/html/rfc7541
 * 4.1.  Calculating Table Size
 */
pub const ESTIMATED_OVERHEAD_BYTES: usize = 32;

#[derive(Debug, PartialEq, Clone, Hash, Eq)]
pub struct HeaderField {
    pub name: Cow<'static, [u8]>,
    pub value: Cow<'static, [u8]>,
}

impl HeaderField {
    pub fn new<T, S>(name: T, value: S) -> HeaderField
    where
        T: Into<Vec<u8>>,
        S: Into<Vec<u8>>,
    {
        HeaderField {
            name: Cow::Owned(name.into()),
            value: Cow::Owned(value.into()),
        }
    }

    pub fn mem_size(&self) -> usize {
        self.name.len() + self.value.len() + ESTIMATED_OVERHEAD_BYTES
    }

    pub fn with_value<T>(&self, value: T) -> Self
    where
        T: Into<Vec<u8>>,
    {
        Self {
            name: self.name.to_owned(),
            value: Cow::Owned(value.into()),
        }
    }

    pub fn into_inner(self) -> (Cow<'static, [u8]>, Cow<'static, [u8]>) {
        (self.name, self.value)
    }
}

impl AsRef<HeaderField> for HeaderField {
    fn as_ref(&self) -> &Self {
        &self
    }
}

impl Display for HeaderField {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "\"{}\": \"{}\"",
            String::from_utf8_lossy(&self.name),
            String::from_utf8_lossy(&self.value)
        )?;
        Ok(())
    }
}

impl From<HeaderField> for String {
    fn from(field: HeaderField) -> String {
        format!(
            "{}\t{}",
            String::from_utf8_lossy(&field.name),
            String::from_utf8_lossy(&field.value)
        )
    }
}

impl<N, V> From<(N, V)> for HeaderField
where
    N: AsRef<[u8]>,
    V: AsRef<[u8]>,
{
    fn from(header: (N, V)) -> Self {
        let (name, value) = header;
        Self {
            // FIXME: could avoid allocation if HeaderField had a lifetime
            name: Cow::Owned(Vec::from(name.as_ref())),
            value: Cow::Owned(Vec::from(value.as_ref())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /**
     * https://tools.ietf.org/html/rfc7541#section-4.1
     * "The size of an entry is the sum of its name's length in octets (as
     *  defined in Section 5.2), its value's length in octets, and 32."
     * "The size of an entry is calculated using the length of its name and
     *  value without any Huffman encoding applied."
     */
    #[test]
    fn test_field_size_is_offset_by_32() {
        let field = HeaderField {
            name: Cow::Borrowed(b"Name"),
            value: Cow::Borrowed(b"Value"),
        };
        assert_eq!(field.mem_size(), 4 + 5 + 32);
    }

    #[test]
    fn with_value() {
        let field = HeaderField {
            name: Cow::Borrowed(b"Name"),
            value: Cow::Borrowed(b"Value"),
        };
        assert_eq!(
            field.with_value("New value"),
            HeaderField {
                name: Cow::Borrowed(b"Name"),
                value: Cow::Borrowed(b"New value"),
            }
        );
    }
}
