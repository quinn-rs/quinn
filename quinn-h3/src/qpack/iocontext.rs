// This is only here because qpack is new and quinn no uses it yet.
// TODO remove allow dead code
#![allow(dead_code)]


#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidPrefix(usize)
}


#[derive(Debug, PartialEq)]
pub struct StartingByte {
    pub prefix: usize,
    pub mask: usize,
    pub byte: Option<usize>
}


impl StartingByte {

    pub fn prefix(prefix: usize) -> Result<StartingByte, Error> {
        Self::build(prefix, None)
    }

    pub fn valued(prefix: usize, byte: usize) -> Result<StartingByte, Error> {
        Self::build(prefix, Some(byte))
    }
    
    fn build(prefix: usize, byte: Option<usize>) 
        -> Result<StartingByte, Error> 
    {
        if prefix == 0 || prefix > 8 {
            Err(Error::InvalidPrefix(prefix))
        } else {
            let mask = 2usize.pow(prefix as u32) - 1;
            Ok(StartingByte { prefix, mask, byte })
        }
    }

}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_transform_to_mask() {
        assert_eq!(StartingByte::prefix(6).unwrap().mask, 63);
    }

    #[test]
    fn test_prefix_with_ahead_byte() {
        assert_eq!(StartingByte::valued(3, 5).unwrap().byte, Some(5));
    }

    #[test]
    fn test_ahead_byte_not_given() {
        assert_eq!(StartingByte::prefix(3).unwrap().byte, None);
    }

    #[test]
    fn test_null_prefix() {
        assert_eq!(StartingByte::prefix(0), Err(Error::InvalidPrefix(0)));
    }
    
    #[test]
    fn test_bad_prefix() {
        assert_eq!(StartingByte::prefix(15), Err(Error::InvalidPrefix(15)));
    }

}
