use std::{cmp::Ordering, collections::BinaryHeap};

use bytes::{Buf, Bytes};

/// Helper to assemble unordered stream frames into an ordered stream
#[derive(Debug)]
pub(crate) struct Assembler {
    offset: u64,
    data: BinaryHeap<Chunk>,
}

impl Assembler {
    pub fn new() -> Self {
        Self {
            offset: 0,
            data: BinaryHeap::new(),
        }
    }

    pub(crate) fn read(&mut self, buf: &mut [u8]) -> usize {
        let mut read = 0;
        loop {
            if self.consume(buf, &mut read) {
                self.data.pop();
            } else {
                break;
            }
            if read == buf.len() {
                break;
            }
        }
        read
    }

    // Read as much from the first chunk in the heap as fits in the buffer.
    // Takes the buffer to read into and the amount of bytes that has already
    // been read into it. Returns whether the first chunk has been fully consumed.
    fn consume(&mut self, buf: &mut [u8], read: &mut usize) -> bool {
        let mut chunk = match self.data.peek_mut() {
            Some(chunk) => chunk,
            None => return false,
        };

        // If this chunk is either after the current offset or fully before it,
        // return directly, indicating whether the chunk can be discarded.
        if chunk.offset > self.offset {
            return false;
        } else if (chunk.offset + chunk.bytes.len() as u64) <= self.offset {
            return true;
        }

        // Determine `start` and `len` of slice to read from chunk
        let start = (self.offset - chunk.offset) as usize;
        let left = buf.len() - *read;
        let len = left.min(chunk.bytes.len() - start) as usize;

        // Actually write into the buffer and update the related state
        (&mut buf[*read..*read + len]).copy_from_slice(&chunk.bytes[start..start + len]);
        *read += len;
        self.offset += len as u64;

        if start + len == chunk.bytes.len() {
            // This chunk has been fully consumed and can be discarded
            true
        } else {
            // Mutate the chunk; `peek_mut()` is documented to update the heap's ordering
            // accordingly if necessary on dropping the `PeekMut`. Don't pop the chunk.
            chunk.offset = chunk.offset + start as u64 + len as u64;
            chunk.bytes.advance(start + len);
            false
        }
    }

    #[cfg(test)]
    fn next(&mut self, size: usize) -> Option<Box<[u8]>> {
        let mut buf = vec![0; size];
        let read = self.read(&mut buf);
        buf.resize(read, 0);
        if !buf.is_empty() {
            Some(buf.into())
        } else {
            None
        }
    }

    pub(crate) fn pop(&mut self) -> Option<(u64, Bytes)> {
        self.data.pop().map(|x| (x.offset, x.bytes))
    }

    pub(crate) fn insert(&mut self, offset: u64, bytes: Bytes) {
        self.data.push(Chunk { offset, bytes });
    }

    /// Current position in the stream
    pub(crate) fn offset(&self) -> u64 {
        self.offset
    }

    /// Discard all buffered data
    pub(crate) fn clear(&mut self) {
        self.data.clear();
    }
}

#[derive(Debug, Eq)]
struct Chunk {
    offset: u64,
    bytes: Bytes,
}

impl Ord for Chunk {
    // Invert ordering based on offset (max-heap, min offset first),
    // prioritize longer chunks at the same offset.
    fn cmp(&self, other: &Chunk) -> Ordering {
        self.offset
            .cmp(&other.offset)
            .reverse()
            .then(self.bytes.len().cmp(&other.bytes.len()))
    }
}

impl PartialOrd for Chunk {
    fn partial_cmp(&self, other: &Chunk) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Chunk {
    fn eq(&self, other: &Chunk) -> bool {
        (self.offset, self.bytes.len()) == (other.offset, other.bytes.len())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use assert_matches::assert_matches;

    #[test]
    fn assemble_ordered() {
        let mut x = Assembler::new();
        assert_matches!(x.next(32), None);
        x.insert(0, Bytes::from_static(b"123"));
        assert_matches!(x.next(1), Some(ref y) if &y[..] == b"1");
        assert_matches!(x.next(3), Some(ref y) if &y[..] == b"23");
        x.insert(3, Bytes::from_static(b"456"));
        assert_matches!(x.next(32), Some(ref y) if &y[..] == b"456");
        x.insert(6, Bytes::from_static(b"789"));
        x.insert(9, Bytes::from_static(b"10"));
        assert_matches!(x.next(32), Some(ref y) if &y[..] == b"78910");
        assert_matches!(x.next(32), None);
    }

    #[test]
    fn assemble_unordered() {
        let mut x = Assembler::new();
        x.insert(3, Bytes::from_static(b"456"));
        assert_matches!(x.next(32), None);
        x.insert(0, Bytes::from_static(b"123"));
        assert_matches!(x.next(32), Some(ref y) if &y[..] == b"123456");
        assert_matches!(x.next(32), None);
    }

    #[test]
    fn assemble_duplicate() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"123"));
        x.insert(0, Bytes::from_static(b"123"));
        assert_matches!(x.next(32), Some(ref y) if &y[..] == b"123");
        assert_matches!(x.next(32), None);
    }

    #[test]
    fn assemble_contained() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"12345"));
        x.insert(1, Bytes::from_static(b"234"));
        assert_matches!(x.next(32), Some(ref y) if &y[..] == b"12345");
        assert_matches!(x.next(32), None);
    }

    #[test]
    fn assemble_contains() {
        let mut x = Assembler::new();
        x.insert(1, Bytes::from_static(b"234"));
        x.insert(0, Bytes::from_static(b"12345"));
        assert_matches!(x.next(32), Some(ref y) if &y[..] == b"12345");
        assert_matches!(x.next(32), None);
    }

    #[test]
    fn assemble_overlapping() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"123"));
        x.insert(1, Bytes::from_static(b"234"));
        assert_matches!(x.next(32), Some(ref y) if &y[..] == b"1234");
        assert_matches!(x.next(32), None);
    }

    #[test]
    fn assemble_complex() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"1"));
        x.insert(2, Bytes::from_static(b"3"));
        x.insert(4, Bytes::from_static(b"5"));
        x.insert(0, Bytes::from_static(b"123456"));
        assert_matches!(x.next(32), Some(ref y) if &y[..] == b"123456");
        assert_matches!(x.next(32), None);
    }

    #[test]
    fn assemble_old() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"1234"));
        assert_matches!(x.next(32), Some(ref y) if &y[..] == b"1234");
        x.insert(0, Bytes::from_static(b"1234"));
        assert_matches!(x.next(32), None);
    }
}
