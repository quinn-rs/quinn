// This is only here because qpack is new and quinn no uses it yet.
// TODO remove allow dead code
#![allow(dead_code)]


#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidPrefix(usize)
}


#[derive(Debug, PartialEq)]
pub struct StarterByte {
    pub prefix: usize,
    pub mask: usize,
    pub byte: Option<usize>
}


impl StarterByte {

    pub fn noprefix() -> StarterByte {
        StarterByte { prefix: 8, mask: 255, byte: None }
    }

    pub fn prefix(prefix: usize) -> Result<StarterByte, Error> {
        Self::build(prefix, None)
    }

    pub fn valued(prefix: usize, byte: usize) -> Result<StarterByte, Error> {
        Self::build(prefix, Some(byte))
    }
    
    fn build(prefix: usize, byte: Option<usize>) 
        -> Result<StarterByte, Error> 
    {
        if prefix == 0 || prefix > 8 {
            Err(Error::InvalidPrefix(prefix))
        } else {
            let mask = 2usize.pow(prefix as u32) - 1;
            Ok(StarterByte { prefix, mask, byte })
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
    fn test_prefix_transform_to_mask() {
        assert_eq!(StarterByte::prefix(6).unwrap().mask, 63);
    }

    #[test]
    fn test_prefix_with_ahead_byte() {
        assert_eq!(StarterByte::valued(3, 5).unwrap().byte, Some(5));
    }

    #[test]
    fn test_ahead_byte_not_given() {
        assert_eq!(StarterByte::prefix(3).unwrap().byte, None);
    }

    #[test]
    fn test_null_prefix() {
        assert_eq!(StarterByte::prefix(0), Err(Error::InvalidPrefix(0)));
    }
    
    #[test]
    fn test_bad_prefix() {
        assert_eq!(StarterByte::prefix(15), Err(Error::InvalidPrefix(15)));
    }

}
