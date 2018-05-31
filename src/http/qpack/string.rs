extern crate bitlab;

use bitlab::*;


#[derive(Debug, PartialEq, Clone)]
pub struct BitRange {
    pub byte: u32,
    pub bit: u32,
    pub count: u32
}


impl BitRange {

    pub fn new() -> BitRange {
        BitRange { byte: 0, bit: 0, count: 0 }
    }

    pub fn forwards(&mut self, step: u32) {
        self.bit += self.count;
        
        self.byte += self.bit / 8;;
        self.bit %= 8;
        
        self.count = step;
    }

    pub fn byte_boundary(&self) -> BitRange {
        BitRange {
            byte: self.byte,
            bit: self.bit,
            count: 8 - (self.bit % 8)
        }
    }

}


#[derive(Debug, PartialEq)]
pub enum Error {
    MissingBits(BitRange),
    Unhandled(BitRange, usize)
}


#[derive(Clone, Debug)]
pub enum DecodeValue {
    Unimplemented,
    Partial(&'static HuffmanDecoder),
    Sym(u8)
}


#[derive(Clone, Debug)]
pub struct HuffmanDecoder {
    lookup: u32,
    table: &'static [DecodeValue]
}


impl HuffmanDecoder {

    fn check_eof(&self,
        range: &mut BitRange,
        input: &Vec<u8>
    ) -> Result<Option<u32>, Error> {
        if (range.byte + 1) as usize >= input.len() {
            let side = range.byte_boundary();
            
            let rest = input.get_u8(side.byte, side.bit, side.count)
                .map_err(|_| Error::MissingBits(side.clone()))?;
            
            let eof_filler = ((2u16 << (side.count - 1)) - 1) as u8;
            if rest & eof_filler == eof_filler {
                return Ok(None);
            }
        }
        
        Err(Error::MissingBits(range.clone()))
    }

    fn value(
        &self,
        range: &mut BitRange,
        input: &Vec<u8>
    ) -> Result<Option<u32>, Error> {
        let value = match input.get_u32(
            range.byte, range.bit, range.count) {
            Ok(x) => x,
            Err(_) => return self.check_eof(range, &input)
        };
        
        Ok(Some(value))
    }

    pub fn decode_next(
        &self,
        range: &mut BitRange,
        input: &Vec<u8>
    ) -> Result<Option<u8>, Error> {
        range.forwards(self.lookup);
        
        let value = match self.value(range, input) {
            Ok(Some(x)) => x as usize,
            Ok(None) => return Ok(None),
            Err(err) => return Err(err)
        };

        let at_value = match (&self.table[..]).get(value) {
            Some(x) => x,
            None => return Err(Error::Unhandled(range.clone(), value))
        };

        match at_value {
            &DecodeValue::Sym(x) => Ok(Some(x)),
            &DecodeValue::Partial(d) => d.decode_next(range, input),
            &DecodeValue::Unimplemented
                => Err(Error::Unhandled(range.clone(), value))
        }
    }

}


pub mod huffman_code {
    #![allow(dead_code)]

    use super::*;

    macro_rules! endings {
        ($name:ident, $low:expr, $high:expr) => {
            const $name: HuffmanDecoder = HuffmanDecoder {
                lookup: 1,
                table: &[
                 DecodeValue::Sym($low as u8), DecodeValue::Sym($high as u8) ]
            };
        };
        ($name:ident, $va:expr, $vb:expr, $vc:expr, $vd:expr) => {
            const $name: HuffmanDecoder = HuffmanDecoder {
                lookup: 2,
                table: &[
                 DecodeValue::Sym($va as u8), DecodeValue::Sym($vb as u8),
                 DecodeValue::Sym($vc as u8), DecodeValue::Sym($vd as u8) ]
            };
        };
        [ $( $name:ident => ( $($variant:expr),* ), )* ] => {
            $( endings!($name, $( $variant ),* ); )*
        }
    }

    endings![
        ROOT_01010 => ( 32, '%'),
        ROOT_01011 => ('-', '.'),
        ROOT_01100 => ('/', '3'),
        ROOT_01101 => ('4', '5'),
        ROOT_01110 => ('6', '7'),
        ROOT_01111 => ('8', '9'),
        ROOT_10000 => ('=', 'A'),
        ROOT_10001 => ('_', 'b'),
        ROOT_10010 => ('d', 'f'),
        ROOT_10011 => ('g', 'h'),
        ROOT_10100 => ('l', 'm'),
        ROOT_10101 => ('n', 'p'),
        ROOT_10110 => ('r', 'u'),
        ROOT_10111 => (':', 'B', 'C', 'D'),
        ROOT_11000 => ('E', 'F', 'G', 'H'),
    ];

    pub const NULL: HuffmanDecoder = HuffmanDecoder {
        lookup: 8, // at mininum the end of the byte
        table: &[]
    };
    
    pub const HPACK_STRING: HuffmanDecoder = HuffmanDecoder {
        lookup: 5,
        table: &[
            DecodeValue::Sym('0' as u8), // 0
            DecodeValue::Sym('1' as u8),
            DecodeValue::Sym('2' as u8),
            DecodeValue::Sym('a' as u8),
            DecodeValue::Sym('c' as u8),
            DecodeValue::Sym('e' as u8), // 5
            DecodeValue::Sym('i' as u8),
            DecodeValue::Sym('o' as u8),
            DecodeValue::Sym('s' as u8),
            DecodeValue::Sym('t' as u8),
            DecodeValue::Partial(&ROOT_01010), // 10
            DecodeValue::Partial(&ROOT_01011),
            DecodeValue::Partial(&ROOT_01100),
            DecodeValue::Partial(&ROOT_01101),
            DecodeValue::Partial(&ROOT_01110),
            DecodeValue::Partial(&ROOT_01111), // 15
            DecodeValue::Partial(&ROOT_10000),
            DecodeValue::Partial(&ROOT_10001),
            DecodeValue::Partial(&ROOT_10010),
            DecodeValue::Partial(&ROOT_10011),
            DecodeValue::Partial(&ROOT_10100), // 20
            DecodeValue::Partial(&ROOT_10101),
            DecodeValue::Partial(&ROOT_10110),
            DecodeValue::Partial(&ROOT_10111),
            DecodeValue::Partial(&ROOT_11000),
            DecodeValue::Unimplemented, // 25
            DecodeValue::Unimplemented,
            DecodeValue::Unimplemented,
            DecodeValue::Unimplemented,
            DecodeValue::Unimplemented,
            DecodeValue::Unimplemented, // 30
            DecodeValue::Partial(&NULL),
            ]
    };

}


pub struct DecodeIter<'a> {
    range: BitRange,
    content: &'a Vec<u8>
}


impl<'a> Iterator for DecodeIter<'a> {
    type Item = Result<u8, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match huffman_code::HPACK_STRING
            .decode_next(&mut self.range, self.content) {
            Ok(Some(x)) => Some(Ok(x)),
            Err(err) => Some(Err(err)),
            Ok(None) => None
        }
    }
}


pub trait HpackStringDecode {
    fn hpack_decode<'a>(&'a self) -> DecodeIter<'a>;
}


impl HpackStringDecode for Vec<u8> {
    fn hpack_decode<'a>(&'a self) -> DecodeIter<'a> {
        DecodeIter {
            range: BitRange::new(),
            content: self
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    /**
     * https://tools.ietf.org/html/rfc7541
     * Appendix B.  Huffman Code
     */
    #[test]
    fn test_decode_first_letters() {
        let bytes = [
            // a: 00011, b: 100-011
            0b00011100,
            // b: 100-011, c: 00100
            0b01100100,
            // d: 100100, e: 00-101
            0b10010000,
            // e: 00-101, f: 10010-1
            0b10110010,
            // f: 10010-1, eof: 11111.....
            0b11111111
        ].to_vec();
        let text = b"abcdef";
        let res: Result<Vec<_>, Error> = bytes.hpack_decode().collect();
        assert_eq!(res, Ok(text.to_vec()));
    }

}
