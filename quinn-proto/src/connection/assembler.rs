use std::{
    cmp::{Ordering, max},
    collections::VecDeque,
    mem,
};

use bytes::{Buf, Bytes, BytesMut};

use crate::range_set::RangeSet;

/// Helper to assemble unordered stream frames into an ordered stream
#[derive(Debug, Default)]
pub(super) struct Assembler {
    state: State,
    /// Buffered chunks, in `Buffer::cmp` order
    data: VecDeque<Buffer>,
    /// Total number of buffered bytes, including duplicates in ordered mode.
    buffered: usize,
    /// Estimated number of allocated bytes, will never be less than `buffered`.
    allocated: usize,
    /// Number of bytes read by the application. When only ordered reads have been used, this is the
    /// length of the contiguous prefix of the stream which has been consumed by the application,
    /// aka the stream offset.
    bytes_read: u64,
    end: u64,
}

impl Assembler {
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Reset to the initial state
    pub(super) fn reinit(&mut self) {
        let old_data = mem::take(&mut self.data);
        *self = Self::default();
        self.data = old_data;
        self.data.clear();
    }

    pub(super) fn ensure_ordering(&mut self, ordered: bool) -> Result<(), IllegalOrderedRead> {
        if ordered && !self.state.is_ordered() {
            return Err(IllegalOrderedRead);
        } else if !ordered && self.state.is_ordered() {
            // Enter unordered mode
            if !self.data.is_empty() {
                // Get rid of possible duplicates
                self.defragment();
            }
            let mut recvd = RangeSet::new();
            recvd.insert(0..self.bytes_read);
            for chunk in &self.data {
                recvd.insert(chunk.offset..chunk.offset + chunk.bytes.len() as u64);
            }
            self.state = State::Unordered { recvd };
        }
        Ok(())
    }

    /// Get the the next chunk
    pub(super) fn read(&mut self, max_length: usize, ordered: bool) -> Option<Chunk> {
        loop {
            let chunk = self.data.front_mut()?;

            if ordered {
                if chunk.offset > self.bytes_read {
                    // Next chunk is after current read index
                    return None;
                } else if (chunk.offset + chunk.bytes.len() as u64) <= self.bytes_read {
                    // Next chunk is useless as the read index is beyond its end
                    self.buffered -= chunk.bytes.len();
                    self.allocated -= chunk.allocation_size;
                    self.data.pop_front();
                    continue;
                }

                // Determine `start` and `len` of the slice of useful data in chunk
                let start = (self.bytes_read - chunk.offset) as usize;
                // Advancing the offset can push the front past data[1]; both exits below fix that
                if start > 0 {
                    chunk.bytes.advance(start);
                    chunk.offset += start as u64;
                    self.buffered -= start;
                }
            }

            if max_length < chunk.bytes.len() {
                self.bytes_read += max_length as u64;
                let offset = chunk.offset;
                chunk.offset += max_length as u64;
                self.buffered -= max_length;
                let bytes = chunk.bytes.split_to(max_length);
                self.restore_front_order();
                return Some(Chunk::new(offset, bytes));
            }

            self.bytes_read += chunk.bytes.len() as u64;
            self.buffered -= chunk.bytes.len();
            self.allocated -= chunk.allocation_size;
            let offset = chunk.offset;
            let bytes = mem::take(&mut chunk.bytes);
            self.data.pop_front();
            return Some(Chunk::new(offset, bytes));
        }
    }

    /// Restore ordering after `read` advanced the front's offset
    fn restore_front_order(&mut self) {
        let chunk = self.data.pop_front().unwrap();
        let idx = self.data.iter().take_while(|other| **other < chunk).count();
        self.data.insert(idx, chunk);
    }

    /// Copy fragmented chunk data to new chunks backed by a single buffer
    ///
    /// This makes sure we're not unnecessarily holding on to many larger allocations.
    /// We merge contiguous chunks in the process of doing so.
    fn defragment(&mut self) {
        // Chunks smaller than min_chunk_size are merged regardless of fragmentation
        let min_chunk_size = max(self.buffered.div_ceil(MAX_CHUNKS), MIN_RETAINED_CHUNK_SIZE);
        let mut buffers = mem::take(&mut self.data);
        self.buffered = 0;
        let mut fragmented_buffered = 0;
        let mut offset = 0;
        for chunk in &mut buffers {
            chunk.try_mark_defragment(offset);
            let size = chunk.bytes.len();
            offset = chunk.offset + size as u64;
            self.buffered += size;
            if !chunk.defragmented || size < min_chunk_size {
                fragmented_buffered += size;
            }
        }
        self.allocated = self.buffered;
        self.data.reserve(buffers.len());
        let mut buffer = BytesMut::with_capacity(fragmented_buffered);
        let mut offset = 0;
        for chunk in buffers {
            // bytes might be empty after try_mark_defragment
            if chunk.bytes.is_empty() {
                continue;
            }
            if chunk.defragmented && chunk.bytes.len() >= min_chunk_size {
                // The accumulated chunk starts before this one, so it goes first
                if !buffer.is_empty() {
                    self.data
                        .push_back(Buffer::new_defragmented(offset, buffer.split().freeze()));
                }
                offset = chunk.offset + chunk.bytes.len() as u64;
                self.data.push_back(chunk);
                continue;
            }
            // Overlap is resolved by try_mark_defragment
            if chunk.offset != offset + (buffer.len() as u64) {
                if !buffer.is_empty() {
                    self.data
                        .push_back(Buffer::new_defragmented(offset, buffer.split().freeze()));
                }
                offset = chunk.offset;
            }
            buffer.extend_from_slice(&chunk.bytes);
        }
        if !buffer.is_empty() {
            self.data
                .push_back(Buffer::new_defragmented(offset, buffer.split().freeze()));
        }
    }

    // Note: If a packet contains many frames from the same stream, the estimated over-allocation
    // will be much higher because we are counting the same allocation multiple times.
    pub(super) fn insert(
        &mut self,
        mut offset: u64,
        mut bytes: Bytes,
        allocation_size: usize,
    ) -> Result<(), TooManyChunks> {
        debug_assert!(
            bytes.len() <= allocation_size,
            "allocation_size less than bytes.len(): {:?} < {:?}",
            allocation_size,
            bytes.len()
        );
        self.end = self.end.max(offset + bytes.len() as u64);
        if let State::Unordered { ref mut recvd } = self.state {
            // Discard duplicate data
            for duplicate in recvd.replace(offset..offset + bytes.len() as u64) {
                if duplicate.start > offset {
                    let buffer = Buffer::new(
                        offset,
                        bytes.split_to((duplicate.start - offset) as usize),
                        allocation_size,
                    );
                    self.buffered += buffer.bytes.len();
                    self.allocated += buffer.allocation_size;
                    insert_ordered(&mut self.data, buffer);
                    offset = duplicate.start;
                }
                bytes.advance((duplicate.end - offset) as usize);
                offset = duplicate.end;
            }
        } else if offset < self.bytes_read {
            if (offset + bytes.len() as u64) <= self.bytes_read {
                return Ok(());
            } else {
                let diff = self.bytes_read - offset;
                offset += diff;
                bytes.advance(diff as usize);
            }
        }

        // No early return when empty: the dedup loop above may already have pushed chunks.
        if !bytes.is_empty() {
            let buffer = Buffer::new(offset, bytes, allocation_size);
            self.buffered += buffer.bytes.len();
            self.allocated += buffer.allocation_size;
            insert_ordered(&mut self.data, buffer);
        }
        // `self.buffered` also counts duplicate bytes, therefore we use
        // `self.end - self.bytes_read` as an upper bound of buffered unique
        // bytes. This will cause a defragmentation if the amount of duplicate
        // bytes exceedes a proportion of the receive window size.
        let buffered = self.buffered.min((self.end - self.bytes_read) as usize);
        let over_allocation = self.allocated - buffered;
        // Rationale: on the one hand, we want to defragment rarely, ideally never
        // in non-pathological scenarios. However, a pathological or malicious
        // peer could send us one-byte frames, and since we use reference-counted
        // buffers in order to prevent copying, this could result in keeping a lot
        // of memory allocated. This limits over-allocation in proportion to the
        // buffered data. The constants are chosen somewhat arbitrarily and try to
        // balance between defragmentation overhead and over-allocation.
        let threshold = 32768.max(buffered * 3 / 2);
        // Small gapped frames hold over-allocation below the threshold, so bound the count too.
        if over_allocation > threshold || self.data.len() > COMPACT_THRESHOLD {
            self.defragment();
            // ngtcp2 uses a threshold of 4000 -- try to be a little more conservative?
            if self.data.len() > MAX_CHUNKS {
                return Err(TooManyChunks);
            }
        }

        Ok(())
    }

    /// Number of bytes consumed by the application
    pub(super) fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    /// Discard all buffered data
    pub(super) fn clear(&mut self) {
        self.data.clear();
        self.buffered = 0;
        self.allocated = 0;
    }
}

/// A chunk of data from the receive stream
#[derive(Debug, PartialEq, Eq)]
pub struct Chunk {
    /// The offset in the stream
    pub offset: u64,
    /// The contents of the chunk
    pub bytes: Bytes,
}

impl Chunk {
    fn new(offset: u64, bytes: Bytes) -> Self {
        Self { offset, bytes }
    }
}

#[derive(Debug, Eq)]
struct Buffer {
    offset: u64,
    bytes: Bytes,
    /// Size of the allocation behind `bytes`, if `defragmented == false`.
    /// Otherwise this will be set to `bytes.len()` by `try_mark_defragment`.
    /// Will never be less than `bytes.len()`.
    allocation_size: usize,
    defragmented: bool,
}

impl Buffer {
    /// Constructs a new fragmented Buffer
    fn new(offset: u64, bytes: Bytes, allocation_size: usize) -> Self {
        Self {
            offset,
            bytes,
            allocation_size,
            defragmented: false,
        }
    }

    /// Constructs a new defragmented Buffer
    fn new_defragmented(offset: u64, bytes: Bytes) -> Self {
        let allocation_size = bytes.len();
        Self {
            offset,
            bytes,
            allocation_size,
            defragmented: true,
        }
    }

    /// Discards data before `offset` and flags `self` as defragmented if it has good utilization
    fn try_mark_defragment(&mut self, offset: u64) {
        let duplicate = offset.saturating_sub(self.offset) as usize;
        self.offset = self.offset.max(offset);
        if duplicate >= self.bytes.len() {
            // All bytes are duplicate
            self.bytes = Bytes::new();
            self.defragmented = true;
            self.allocation_size = 0;
            return;
        }
        self.bytes.advance(duplicate);
        // Make sure that fragmented buffers with high utilization become defragmented and
        // defragmented buffers remain defragmented
        self.defragmented = self.defragmented || self.bytes.len() * 6 / 5 >= self.allocation_size;
        if self.defragmented {
            // Make sure that defragmented buffers do not contribute to over-allocation
            self.allocation_size = self.bytes.len();
        }
    }
}

impl Ord for Buffer {
    // Ascending offset, longer chunks first at equal offsets
    fn cmp(&self, other: &Self) -> Ordering {
        self.offset
            .cmp(&other.offset)
            .then(other.bytes.len().cmp(&self.bytes.len()))
    }
}

impl PartialOrd for Buffer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Buffer {
    fn eq(&self, other: &Self) -> bool {
        (self.offset, self.bytes.len()) == (other.offset, other.bytes.len())
    }
}

#[derive(Debug, Default)]
enum State {
    #[default]
    Ordered,
    Unordered {
        /// The set of offsets that have been received from the peer, including portions not yet
        /// read by the application.
        recvd: RangeSet,
    },
}

impl State {
    fn is_ordered(&self) -> bool {
        matches!(self, Self::Ordered)
    }
}

/// Error indicating that an ordered read was performed on a stream after an unordered read
#[derive(Debug)]
pub(crate) struct IllegalOrderedRead;

/// Error indicating that too many chunks are buffered due to maliciously small/gapped frames
#[derive(Debug)]
pub(crate) struct TooManyChunks;

/// O(1) for a frame in order or below everything buffered, otherwise an insert that
/// shifts up to half of `data` (see `COMPACT_THRESHOLD`)
fn insert_ordered(data: &mut VecDeque<Buffer>, buffer: Buffer) {
    if data.back().is_none_or(|back| *back <= buffer) {
        data.push_back(buffer);
        return;
    }
    // Order among equal chunks is unspecified, as it was under the heap, so a duplicate
    // of the front takes this path rather than an insert
    if data.front().is_some_and(|front| buffer <= *front) {
        data.push_front(buffer);
        return;
    }
    let idx = data.partition_point(|chunk| *chunk <= buffer);
    data.insert(idx, buffer);
}

/// Bound on the number of distinct spans kept for a stream
///
/// Independent of how much memory those spans over-allocate. A frame is rejected only
/// if compaction cannot get the count back down to this.
const MAX_CHUNKS: usize = 1024;

/// Minimum size of a defragmented chunk that is retained without coalescing.
///
/// Chunks below this size will be copied on every compaction. 128 bytes balances
/// being cheap to copy while reducing the overhead of many small buffer nodes.
const MIN_RETAINED_CHUNK_SIZE: usize = 128;

/// Chunk count past which `insert` compacts before deciding whether to reject
///
/// Above `MAX_CHUNKS` so a flood of mergeable frames cannot force a defragmentation
/// per frame.
const COMPACT_THRESHOLD: usize = 2 * MAX_CHUNKS;

#[cfg(test)]
mod test {
    use rand::prelude::*;
    use rand_pcg::Pcg32;

    use super::*;
    use assert_matches::assert_matches;

    #[test]
    fn assemble_ordered() {
        let mut x = Assembler::new();
        assert_matches!(next(&mut x, 32), None);
        x.insert(0, Bytes::from_static(b"123"), 3).unwrap();
        assert_matches!(next(&mut x, 1), Some(ref y) if &y[..] == b"1");
        assert_matches!(next(&mut x, 3), Some(ref y) if &y[..] == b"23");
        x.insert(3, Bytes::from_static(b"456"), 3).unwrap();
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"456");
        x.insert(6, Bytes::from_static(b"789"), 3).unwrap();
        x.insert(9, Bytes::from_static(b"10"), 2).unwrap();
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"789");
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"10");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_unordered() {
        let mut x = Assembler::new();
        x.ensure_ordering(false).unwrap();
        x.insert(3, Bytes::from_static(b"456"), 3).unwrap();
        assert_matches!(next(&mut x, 32), None);
        x.insert(0, Bytes::from_static(b"123"), 3).unwrap();
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"123");
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"456");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_duplicate() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"123"), 3).unwrap();
        x.insert(0, Bytes::from_static(b"123"), 3).unwrap();
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"123");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_duplicate_compact() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"123"), 3).unwrap();
        x.insert(0, Bytes::from_static(b"123"), 3).unwrap();
        x.defragment();
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"123");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_contained() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"12345"), 5).unwrap();
        x.insert(1, Bytes::from_static(b"234"), 3).unwrap();
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"12345");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_contained_compact() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"12345"), 5).unwrap();
        x.insert(1, Bytes::from_static(b"234"), 3).unwrap();
        x.defragment();
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"12345");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_contains() {
        let mut x = Assembler::new();
        x.insert(1, Bytes::from_static(b"234"), 3).unwrap();
        x.insert(0, Bytes::from_static(b"12345"), 5).unwrap();
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"12345");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_contains_compact() {
        let mut x = Assembler::new();
        x.insert(1, Bytes::from_static(b"234"), 3).unwrap();
        x.insert(0, Bytes::from_static(b"12345"), 5).unwrap();
        x.defragment();
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"12345");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_overlapping() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"123"), 3).unwrap();
        x.insert(1, Bytes::from_static(b"234"), 3).unwrap();
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"123");
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"4");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_overlapping_compact() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"123"), 4).unwrap();
        x.insert(1, Bytes::from_static(b"234"), 4).unwrap();
        x.defragment();
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"1234");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_complex() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"1"), 1).unwrap();
        x.insert(2, Bytes::from_static(b"3"), 1).unwrap();
        x.insert(4, Bytes::from_static(b"5"), 1).unwrap();
        x.insert(0, Bytes::from_static(b"123456"), 6).unwrap();
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"123456");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_complex_compact() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"1"), 1).unwrap();
        x.insert(2, Bytes::from_static(b"3"), 1).unwrap();
        x.insert(4, Bytes::from_static(b"5"), 1).unwrap();
        x.insert(0, Bytes::from_static(b"123456"), 6).unwrap();
        x.defragment();
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"123456");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_old() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"1234"), 4).unwrap();
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"1234");
        x.insert(0, Bytes::from_static(b"1234"), 4).unwrap();
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn compact() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"abc"), 4).unwrap();
        x.insert(3, Bytes::from_static(b"def"), 4).unwrap();
        x.insert(9, Bytes::from_static(b"jkl"), 4).unwrap();
        x.insert(12, Bytes::from_static(b"mno"), 4).unwrap();
        x.defragment();
        assert_eq!(
            next_unordered(&mut x),
            Chunk::new(0, Bytes::from_static(b"abcdef"))
        );
        assert_eq!(
            next_unordered(&mut x),
            Chunk::new(9, Bytes::from_static(b"jklmno"))
        );
    }

    #[test]
    fn defrag_with_missing_prefix() {
        let mut x = Assembler::new();
        x.insert(3, Bytes::from_static(b"def"), 3).unwrap();
        x.defragment();
        assert_eq!(
            next_unordered(&mut x),
            Chunk::new(3, Bytes::from_static(b"def"))
        );
    }

    #[test]
    fn defrag_read_chunk() {
        let mut x = Assembler::new();
        x.insert(3, Bytes::from_static(b"def"), 4).unwrap();
        x.insert(0, Bytes::from_static(b"abc"), 4).unwrap();
        x.insert(7, Bytes::from_static(b"hij"), 4).unwrap();
        x.insert(11, Bytes::from_static(b"lmn"), 4).unwrap();
        x.defragment();
        assert_matches!(x.read(usize::MAX, true), Some(ref y) if &y.bytes[..] == b"abcdef");
        x.insert(5, Bytes::from_static(b"fghijklmn"), 9).unwrap();
        assert_matches!(x.read(usize::MAX, true), Some(ref y) if &y.bytes[..] == b"ghijklmn");
        x.insert(13, Bytes::from_static(b"nopq"), 4).unwrap();
        assert_matches!(x.read(usize::MAX, true), Some(ref y) if &y.bytes[..] == b"opq");
        x.insert(15, Bytes::from_static(b"pqrs"), 4).unwrap();
        assert_matches!(x.read(usize::MAX, true), Some(ref y) if &y.bytes[..] == b"rs");
        assert_matches!(x.read(usize::MAX, true), None);
    }

    #[test]
    fn unordered_happy_path() {
        let mut x = Assembler::new();
        x.ensure_ordering(false).unwrap();
        x.insert(0, Bytes::from_static(b"abc"), 3).unwrap();
        assert_eq!(
            next_unordered(&mut x),
            Chunk::new(0, Bytes::from_static(b"abc"))
        );
        assert_eq!(x.read(usize::MAX, false), None);
        x.insert(3, Bytes::from_static(b"def"), 3).unwrap();
        assert_eq!(
            next_unordered(&mut x),
            Chunk::new(3, Bytes::from_static(b"def"))
        );
        assert_eq!(x.read(usize::MAX, false), None);
    }

    #[test]
    fn unordered_dedup() {
        let mut x = Assembler::new();
        x.ensure_ordering(false).unwrap();
        x.insert(3, Bytes::from_static(b"def"), 3).unwrap();
        assert_eq!(
            next_unordered(&mut x),
            Chunk::new(3, Bytes::from_static(b"def"))
        );
        assert_eq!(x.read(usize::MAX, false), None);
        x.insert(0, Bytes::from_static(b"a"), 1).unwrap();
        x.insert(0, Bytes::from_static(b"abcdefghi"), 9).unwrap();
        x.insert(0, Bytes::from_static(b"abcd"), 4).unwrap();
        assert_eq!(
            next_unordered(&mut x),
            Chunk::new(0, Bytes::from_static(b"a"))
        );
        assert_eq!(
            next_unordered(&mut x),
            Chunk::new(1, Bytes::from_static(b"bc"))
        );
        assert_eq!(
            next_unordered(&mut x),
            Chunk::new(6, Bytes::from_static(b"ghi"))
        );
        assert_eq!(x.read(usize::MAX, false), None);
        x.insert(8, Bytes::from_static(b"ijkl"), 4).unwrap();
        assert_eq!(
            next_unordered(&mut x),
            Chunk::new(9, Bytes::from_static(b"jkl"))
        );
        assert_eq!(x.read(usize::MAX, false), None);
        x.insert(12, Bytes::from_static(b"mno"), 3).unwrap();
        assert_eq!(
            next_unordered(&mut x),
            Chunk::new(12, Bytes::from_static(b"mno"))
        );
        assert_eq!(x.read(usize::MAX, false), None);
        x.insert(2, Bytes::from_static(b"cde"), 3).unwrap();
        assert_eq!(x.read(usize::MAX, false), None);
    }

    #[test]
    fn chunks_dedup() {
        let mut x = Assembler::new();
        x.insert(3, Bytes::from_static(b"def"), 3).unwrap();
        assert_eq!(x.read(usize::MAX, true), None);
        x.insert(0, Bytes::from_static(b"a"), 1).unwrap();
        x.insert(1, Bytes::from_static(b"bcdefghi"), 9).unwrap();
        x.insert(0, Bytes::from_static(b"abcd"), 4).unwrap();
        assert_eq!(
            x.read(usize::MAX, true),
            Some(Chunk::new(0, Bytes::from_static(b"abcd")))
        );
        assert_eq!(
            x.read(usize::MAX, true),
            Some(Chunk::new(4, Bytes::from_static(b"efghi")))
        );
        assert_eq!(x.read(usize::MAX, true), None);
        x.insert(8, Bytes::from_static(b"ijkl"), 4).unwrap();
        assert_eq!(
            x.read(usize::MAX, true),
            Some(Chunk::new(9, Bytes::from_static(b"jkl")))
        );
        assert_eq!(x.read(usize::MAX, true), None);
        x.insert(12, Bytes::from_static(b"mno"), 3).unwrap();
        assert_eq!(
            x.read(usize::MAX, true),
            Some(Chunk::new(12, Bytes::from_static(b"mno")))
        );
        assert_eq!(x.read(usize::MAX, true), None);
        x.insert(2, Bytes::from_static(b"cde"), 3).unwrap();
        assert_eq!(x.read(usize::MAX, true), None);
    }

    #[test]
    fn ordered_eager_discard() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"abc"), 3).unwrap();
        assert_eq!(x.data.len(), 1);
        assert_eq!(
            x.read(usize::MAX, true),
            Some(Chunk::new(0, Bytes::from_static(b"abc")))
        );
        x.insert(0, Bytes::from_static(b"ab"), 2).unwrap();
        assert_eq!(x.data.len(), 0);
        x.insert(2, Bytes::from_static(b"cd"), 2).unwrap();
        assert_eq!(
            x.data.front(),
            Some(&Buffer::new(3, Bytes::from_static(b"d"), 2))
        );
    }

    #[test]
    fn ordered_insert_unordered_read() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"abc"), 3).unwrap();
        x.insert(0, Bytes::from_static(b"abc"), 3).unwrap();
        x.ensure_ordering(false).unwrap();
        assert_eq!(
            x.read(3, false),
            Some(Chunk::new(0, Bytes::from_static(b"abc")))
        );
        assert_eq!(x.read(3, false), None);
    }

    #[test]
    fn ordered_lossless_stream_is_not_rejected() {
        const FRAME_LEN: usize = 32;

        let mut x = Assembler::new();
        let data = Bytes::from(vec![0; FRAME_LEN]);
        let mut offset = 0u64;
        while offset < (2 * COMPACT_THRESHOLD * FRAME_LEN) as u64 {
            x.insert(offset, data.clone(), FRAME_LEN)
                .expect("contiguous lossless data must not be rejected");
            offset += FRAME_LEN as u64;
        }
    }

    #[test]
    fn defrag_respects_max_chunks_at_rounding_boundary() {
        let mut x = Assembler::new();
        let data = Bytes::from(vec![0; MIN_RETAINED_CHUNK_SIZE]);
        let mut offset = 0;
        // Fill with minimium sized chunks.
        for _ in 0..MAX_CHUNKS {
            x.insert(offset, data.clone(), data.len()).unwrap();
            offset += data.len() as u64;
        }
        // Add 1 extra chunk, defragment must coalesce the previous
        // chunks to stay within MAX_CHUNKS
        x.insert(offset, Bytes::from_static(b"x"), 1).unwrap();
        x.defragment();
        assert!(x.data.len() <= MAX_CHUNKS);
    }

    #[test]
    fn bounded_chunks_under_low_over_allocation() {
        // Gapped frames whose `allocation_size` equals their length hold
        // `over_allocation` at zero, so that trigger never fires.
        let mut x = Assembler::new();
        // Withhold offset 0 so an ordered reader can never drain anything.
        let mut offset = 1u64;
        let mut result = Ok(());
        for _ in 0..(MAX_CHUNKS * 8) {
            result = x.insert(offset, Bytes::from_static(b"gap"), 3);
            if result.is_err() {
                break;
            }
            offset += 3 + 1; // 3 data bytes, 1 byte gap
        }
        assert_matches!(result, Err(TooManyChunks));
        assert!(
            x.data.len() <= COMPACT_THRESHOLD + 1,
            "chunk count {} exceeded the bound",
            x.data.len()
        );
    }

    #[test]
    fn bounded_chunks_unordered_overlap_flood() {
        // Overlapping frames whose tail is already received: the dedup loop pushes
        // the fresh head byte and leaves `bytes` empty, and `end` never rises, so
        // the flood costs the peer no flow control.
        let mut x = Assembler::new();
        x.ensure_ordering(false).unwrap();
        let top = 1_000_000u64;
        x.insert(top, Bytes::from_static(b"ab"), 2).unwrap();
        for k in 0..(4 * MAX_CHUNKS as u64) {
            x.insert(top - k - 1, Bytes::from_static(b"ab"), 2).unwrap();
            assert!(
                x.data.len() <= COMPACT_THRESHOLD + 1,
                "chunk count {} exceeded the bound at k={k}",
                x.data.len()
            );
        }
    }

    #[test]
    fn bounded_chunks_duplicate_flood() {
        // Duplicates against a stream already at the cap. Ordered mode does not dedup,
        // so each one pushes a chunk; they must not be rejected, or compact every frame.
        let mut x = Assembler::new();
        // Withhold offset 0 so nothing can be drained.
        for i in 0..MAX_CHUNKS as u64 {
            x.insert(1 + i * 4, Bytes::from_static(b"abc"), 3).unwrap();
        }
        let mut max_len = x.data.len();
        for _ in 0..(3 * MAX_CHUNKS) {
            x.insert(1, Bytes::from_static(b"abc"), 3)
                .expect("duplicate flood must not be rejected");
            max_len = max_len.max(x.data.len());
            assert!(
                x.data.len() <= COMPACT_THRESHOLD + 1,
                "chunk count {} exceeded the bound",
                x.data.len()
            );
        }
        // Compacting on every frame would pin the count at `MAX_CHUNKS`.
        assert!(
            max_len > MAX_CHUNKS,
            "buffer compacted on every frame (max observed len {max_len})"
        );
    }

    fn new_rng() -> impl Rng {
        Pcg32::from_seed(0xdeadbeefdeadbeefdeadbeefdeadbeef_u128.to_le_bytes())
    }

    /// Panics unless `data` is in `Buffer::cmp` order
    #[track_caller]
    fn assert_sorted(x: &Assembler) {
        for i in 1..x.data.len() {
            assert!(
                x.data[i - 1] <= x.data[i],
                "data out of order at {i}: (offset {}, len {}) then (offset {}, len {})",
                x.data[i - 1].offset,
                x.data[i - 1].bytes.len(),
                x.data[i].offset,
                x.data[i].bytes.len(),
            );
        }
    }

    #[test]
    fn assemble_random() {
        random_stream(true);
    }

    #[test]
    fn assemble_random_unordered() {
        random_stream(false);
    }

    /// Fragments arriving retransmitted and shuffled must still read back as the exact stream
    fn random_stream(ordered: bool) {
        const LEN: usize = 2048;
        let mut rng = new_rng();
        let stream: Vec<u8> = (0..LEN).map(|_| rng.random()).collect();
        for _ in 0..64 {
            let mut frags = Vec::new();
            let mut at = 0;
            while at < LEN {
                let size = rng.random_range(1..=32).min(LEN - at);
                frags.push((at as u64, size));
                at += size;
            }
            // Retransmits are refragmented from scratch, so they overlap the original frames at
            // arbitrary boundaries rather than repeating them
            for _ in 0..frags.len() / 4 {
                let start = rng.random_range(0..LEN);
                let end = (start + rng.random_range(1..=64)).min(LEN);
                let mut at = start;
                while at < end {
                    let size = rng.random_range(1..=32).min(end - at);
                    frags.push((at as u64, size));
                    at += size;
                }
            }
            frags.shuffle(&mut rng);

            let mut x = Assembler::new();
            if !ordered {
                x.ensure_ordering(false).unwrap();
            }
            let mut delivered = vec![false; LEN];
            for (offset, size) in frags {
                let bytes =
                    Bytes::copy_from_slice(&stream[offset as usize..offset as usize + size]);
                x.insert(offset, bytes, size).unwrap();
                assert_sorted(&x);
                if rng.random_ratio(1, 3) {
                    let max = rng.random_range(1..=64);
                    drain(&mut x, max, ordered, &stream, &mut delivered);
                }
            }
            drain(&mut x, usize::MAX, ordered, &stream, &mut delivered);
            assert!(
                delivered.iter().all(|d| *d),
                "stream did not fully assemble"
            );
        }
    }

    /// Read `x` dry, checking chunks against `stream` and that no byte arrives twice
    #[track_caller]
    fn drain(x: &mut Assembler, max: usize, ordered: bool, stream: &[u8], delivered: &mut [bool]) {
        while let Some(chunk) = x.read(max, ordered) {
            let start = chunk.offset as usize;
            let end = start + chunk.bytes.len();
            assert_eq!(&chunk.bytes[..], &stream[start..end]);
            for d in &mut delivered[start..end] {
                assert!(!*d, "offset {start} delivered twice");
                *d = true;
            }
            assert_sorted(x);
        }
    }

    #[test]
    fn ordered_partial_overlap() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"0123456789"), 10).unwrap();
        x.insert(2, Bytes::from_static(b"23456789abcdef"), 14)
            .unwrap();
        let chunk = x.read(5, true).unwrap();
        assert_eq!(&chunk.bytes[..], b"01234");
        assert_sorted(&x);
        let mut got = chunk.bytes.to_vec();
        while let Some(chunk) = x.read(usize::MAX, true) {
            got.extend_from_slice(&chunk.bytes);
        }
        assert_eq!(&got[..], b"0123456789abcdef");
    }

    #[test]
    fn defrag_mixed_order() {
        let mut x = Assembler::new();
        // Too badly utilized to be marked defragmented, unlike the chunk after it
        x.insert(0, Bytes::from_static(b"a"), 4096).unwrap();
        x.insert(1, Bytes::from_static(b"bcdefghij"), 9).unwrap();
        x.defragment();
        assert_sorted(&x);
        let mut got = Vec::new();
        while let Some(chunk) = x.read(usize::MAX, true) {
            got.extend_from_slice(&chunk.bytes);
        }
        assert_eq!(&got[..], b"abcdefghij");
    }

    fn next_unordered(x: &mut Assembler) -> Chunk {
        x.read(usize::MAX, false).unwrap()
    }

    fn next(x: &mut Assembler, size: usize) -> Option<Bytes> {
        x.read(size, true).map(|chunk| chunk.bytes)
    }
}
