use std::io::{self, Read, Result, Write};
use std::ops::Deref;

use stream;

#[derive(Debug)]
pub struct MemoryStream {
    incoming: stream::Assembler,
    outgoing: Vec<u8>,
}

impl MemoryStream {
    pub fn new() -> Self {
        Self {
            incoming: stream::Assembler::new(),
            outgoing: Vec::new(),
        }
    }

    pub fn insert(&mut self, offset: u64, data: &[u8]) {
        self.incoming.insert(offset, data);
    }

    pub fn take_outgoing(&mut self) -> Outgoing {
        Outgoing(&mut self.outgoing)
    }

    pub fn read_blocked(&self) -> bool {
        self.incoming.blocked()
    }
    pub fn read_offset(&self) -> u64 {
        self.incoming.offset()
    }

    pub fn reset_read(&mut self) {
        self.incoming = stream::Assembler::new();
    }
}

impl Read for MemoryStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let n = self.incoming.read(buf);
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "no data available",
            ));
        }
        Ok(n)
    }
}

impl Write for MemoryStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.outgoing.write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

pub struct Outgoing<'a>(&'a mut Vec<u8>);

impl<'a> Drop for Outgoing<'a> {
    fn drop(&mut self) {
        self.0.clear();
    }
}

impl<'a> Deref for Outgoing<'a> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> AsRef<[u8]> for Outgoing<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
