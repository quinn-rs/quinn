use std::io::{self, Read, Write};

use byteorder::{ByteOrder, BigEndian, WriteBytesExt};

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Varint(u64);

impl Varint {
    pub fn new(x: u64) -> Option<Self> {
        if x >= 2u64.pow(62) {
            None
        } else {
            Some(Varint(x))
        }
    }

    pub fn read<R: Read>(r: &mut R) -> io::Result<Self> {
        let mut buf = [0; 8];
        r.read_exact(&mut buf[0..1])?;
        let tag = buf[0] >> 6;
        buf[0] &= 0b00111111;
        Ok(Varint(match tag {
            0b00 => buf[0] as u64,
            0b01 => {
                r.read_exact(&mut buf[1..2])?;
                BigEndian::read_u16(&buf) as u64
            }
            0b10 => {
                r.read_exact(&mut buf[1..4])?;
                BigEndian::read_u32(&buf) as u64
            }
            0b11 => {
                r.read_exact(&mut buf[1..8])?;
                BigEndian::read_u64(&buf) as u64
            }
            _ => unreachable!(),
        }))
    }

    pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        if self.0 < 2u64.pow(6) {
            w.write_u8(self.0 as u8)
        } else if self.0 < 2u64.pow(14) {
            w.write_u16::<BigEndian>(0b01 << 14 | self.0 as u16)
        } else if self.0 < 2u64.pow(30) {
            w.write_u32::<BigEndian>(0b10 << 30 | self.0 as u32)
        } else if self.0 < 2u64.pow(62) {
            w.write_u64::<BigEndian>(0b11 << 62 | self.0)
        } else {
            unreachable!()
        }
    }
}

impl From<u32> for Varint {
    fn from(x: u32) -> Self { Varint(x as u64) }
}

impl From<u16> for Varint {
    fn from(x: u16) -> Self { Varint(x as u64) }
}

impl From<u8> for Varint {
    fn from(x: u8) -> Self { Varint(x as u64) }
}

impl From<Varint> for u64 {
    fn from(x: Varint) -> Self { x.0 }
}

impl AsRef<u64> for Varint {
    fn as_ref(&self) -> &u64 { &self.0 }
}
