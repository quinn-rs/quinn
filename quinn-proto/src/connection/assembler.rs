use std::{cmp::Ordering, collections::BinaryHeap, mem};

use bytes::{Buf, Bytes, BytesMut};

/// Helper to assemble unordered stream frames into an ordered stream
#[derive(Debug, Default)]
pub(crate) struct Assembler {
    /// Stream offset of the first byte unread by the application. Meaningless if `unordered` is
    /// true.
    offset: u64,
    data: BinaryHeap<Chunk>,
    defragmented: usize,
    /// Whether any unordered reads have been performed, making this assembler unusable for ordered
    /// reads
    unordered: bool,
    /// Number of bytes read. Equal to offset when `unordered` is false, may or may not be
    /// otherwise.
    bytes_read: u64,
}

impl Assembler {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn read(&mut self, buf: &mut [u8]) -> usize {
        assert!(
            !self.unordered,
            "cannot perform ordered reads following unordered reads on a stream"
        );

        let mut read = 0;
        loop {
            if self.consume(buf, &mut read) {
                self.pop();
            } else {
                break;
            }
            if read == buf.len() {
                break;
            }
        }
        self.bytes_read += read as u64;
        read
    }

    pub(crate) fn read_unordered(&mut self) -> Option<(u64, Bytes)> {
        self.unordered = true;
        let (n, data) = self.pop()?;
        self.bytes_read += n;
        Some((n, data))
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

    // Copy the buffered chunk data to new chunks backed by a single buffer to
    // make sure we're not unnecessarily holding on to many larger allocations.
    // Merge contiguous chunks in the process of doing so. Reset the `defragmented`
    // counter to the new number of chunks left in the heap so that we can decide
    // when to defragment the queue again if necessary.
    fn defragment(&mut self) {
        let buffered = self.data.iter().map(|c| c.bytes.len()).sum::<usize>();
        let mut buffer = BytesMut::with_capacity(buffered);
        let mut offset = self.offset;

        let new = BinaryHeap::with_capacity(self.data.len());
        let old = mem::replace(&mut self.data, new);
        for chunk in old.into_sorted_vec().into_iter().rev() {
            let end = offset + (buffer.len() as u64);
            if let Some(overlap) = end.checked_sub(chunk.offset) {
                if let Some(bytes) = chunk.bytes.get(overlap as usize..) {
                    buffer.extend_from_slice(bytes);
                }
            } else {
                let bytes = buffer.split().freeze();
                self.data.push(Chunk { offset, bytes });
                offset = chunk.offset;
                buffer.extend_from_slice(&chunk.bytes);
            }
        }

        let bytes = buffer.split().freeze();
        self.data.push(Chunk { offset, bytes });
        self.defragmented = self.data.len();
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

    fn pop(&mut self) -> Option<(u64, Bytes)> {
        self.defragmented = self.defragmented.saturating_sub(1);
        self.data.pop().map(|x| (x.offset, x.bytes))
    }

    pub(crate) fn insert(&mut self, offset: u64, bytes: Bytes) {
        self.data.push(Chunk { offset, bytes });
        // Why 32: on the one hand, we want to defragment rarely, ideally never
        // in non-pathological scenarios. However, a pathological or malicious
        // peer could send us one-byte frames, and since we use reference-counted
        // buffers in order to prevent copying, this could result in keeping a lot
        // of memory allocated. In the worst case scenario of 32 1-byte chunks,
        // each one from a ~1000-byte datagram, using 32 limits us to having a
        // maximum pathological over-allocation of about 32k bytes.
        if self.data.len() - self.defragmented > 32 {
            self.defragment()
        }
    }

    /// Current position in the stream
    pub(crate) fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    /// Discard all buffered data
    pub(crate) fn clear(&mut self) {
        self.data.clear();
        self.defragmented = 0;
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
    fn assemble_duplicate_compact() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"123"));
        x.insert(0, Bytes::from_static(b"123"));
        x.defragment();
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
    fn assemble_contained_compact() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"12345"));
        x.insert(1, Bytes::from_static(b"234"));
        x.defragment();
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
    fn assemble_contains_compact() {
        let mut x = Assembler::new();
        x.insert(1, Bytes::from_static(b"234"));
        x.insert(0, Bytes::from_static(b"12345"));
        x.defragment();
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
    fn assemble_overlapping_compact() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"123"));
        x.insert(1, Bytes::from_static(b"234"));
        x.defragment();
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
    fn assemble_complex_compact() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"1"));
        x.insert(2, Bytes::from_static(b"3"));
        x.insert(4, Bytes::from_static(b"5"));
        x.insert(0, Bytes::from_static(b"123456"));
        x.defragment();
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

    #[test]
    fn assemble_old_compact() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"1234"));
        x.defragment();
        assert_matches!(x.next(32), Some(ref y) if &y[..] == b"1234");
        x.insert(0, Bytes::from_static(b"1234"));
        x.defragment();
        assert_matches!(x.next(32), None);
    }

    #[test]
    fn compact() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"abc"));
        x.insert(3, Bytes::from_static(b"def"));
        x.insert(9, Bytes::from_static(b"jkl"));
        x.insert(12, Bytes::from_static(b"mno"));
        x.defragment();
        assert_eq!(x.pop(), Some((0, Bytes::from_static(b"abcdef"))));
        assert_eq!(x.pop(), Some((9, Bytes::from_static(b"jklmno"))));
    }
}
