// This is only here because qpack is new and quinn no uses it yet.
// TODO remove allow dead code
#![allow(dead_code)]


#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidPrefix(usize),
}

#[derive(Debug, PartialEq)]
pub struct StarterByte {
    pub prefix: usize,
    pub mask: usize,
    pub byte: Option<usize>,
}

impl StarterByte {
    pub fn noprefix() -> StarterByte {
        StarterByte {
            prefix: 8,
            mask: 255,
            byte: None,
        }
    }

    pub fn prefixed(prefix: usize) -> Result<StarterByte, Error> {
        Self::build(prefix, None)
    }

    pub fn valued(prefix: usize, byte: usize) -> Result<StarterByte, Error> {
        Self::build(prefix, Some(byte))
    }

    fn build(prefix: usize, byte: Option<usize>) -> Result<StarterByte, Error> {
        // NOTE this implementation should be faster than using `pow` function
        // to compute bitmask
        match prefix {
            1 => Ok(StarterByte {
                prefix,
                mask: 1,
                byte,
            }),
            2 => Ok(StarterByte {
                prefix,
                mask: 3,
                byte,
            }),
            3 => Ok(StarterByte {
                prefix,
                mask: 7,
                byte,
            }),
            4 => Ok(StarterByte {
                prefix,
                mask: 15,
                byte,
            }),
            5 => Ok(StarterByte {
                prefix,
                mask: 31,
                byte,
            }),
            6 => Ok(StarterByte {
                prefix,
                mask: 63,
                byte,
            }),
            7 => Ok(StarterByte {
                prefix,
                mask: 127,
                byte,
            }),
            8 => Ok(StarterByte {
                prefix,
                mask: 255,
                byte,
            }),
            _ => Err(Error::InvalidPrefix(prefix)),
        }
    }

    pub fn safe_start(&self) -> usize {
        let rev = 255usize - self.mask;
        self.byte.map(|x| x & rev).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noprefix_consistency() {
        assert_eq!(StarterByte::prefixed(8), Ok(StarterByte::noprefix()));
    }

    #[test]
    fn test_prefix_transform_to_mask() {
        assert_eq!(StarterByte::prefixed(6).unwrap().mask, 63);
    }

    #[test]
    fn test_prefix_with_ahead_byte() {
        assert_eq!(StarterByte::valued(3, 5).unwrap().byte, Some(5));
    }

    #[test]
    fn test_ahead_byte_not_given() {
        assert_eq!(StarterByte::prefixed(3).unwrap().byte, None);
    }

    #[test]
    fn test_null_prefix() {
        assert_eq!(StarterByte::prefixed(0), Err(Error::InvalidPrefix(0)));
    }

    #[test]
    fn test_bad_prefix() {
        assert_eq!(StarterByte::prefixed(15), Err(Error::InvalidPrefix(15)));
    }

    #[test]
    fn test_clear_bytes_bit_after_prefix() {
        let starter = StarterByte::valued(6, 255).expect("valid starter byte");
        assert_eq!(starter.safe_start(), 255 & (128 | 64));
    }

}
