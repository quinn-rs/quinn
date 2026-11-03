use std::{cmp::Ordering, collections::VecDeque, mem};

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
    /// Chunks buffered that `defragment` has not copied yet, which may each hold on to the
    /// larger allocation they arrived in
    fresh: usize,
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
                self.defragment(self.bytes_read);
            }
            let mut recvd = RangeSet::new();
            recvd.insert(0..self.bytes_read);
            for chunk in &self.data {
                recvd.insert(chunk.offset..chunk.end());
            }
            self.state = State::Unordered { recvd };
        }
        Ok(())
    }

    /// Get the the next chunk
    pub(super) fn read(&mut self, max_length: usize, ordered: bool) -> Option<Chunk> {
        while ordered && self.data.front()?.end() <= self.bytes_read {
            // Next buffer ends before the current read index
            let front = self.data.pop_front().unwrap();
            self.buffered -= front.bytes.len();
            self.allocated -= front.allocation_size;
            self.fresh -= usize::from(!front.owned);
        }

        if ordered && self.data.front()?.offset > self.bytes_read {
            // Next buffer starts after the current read index
            return None;
        }

        let mut front = self.data.pop_front()?;
        if ordered && let Some(skip) = self.bytes_read.checked_sub(front.offset) {
            // Advance front to the slice of useful data
            front.bytes.advance(skip as usize);
            front.offset = self.bytes_read;
            self.buffered -= skip as usize;
        }

        let chunk = if max_length < front.bytes.len() {
            // Take a prefix of the front buffer and reinsert the remainder
            let chunk = Chunk::new(front.offset, front.bytes.split_to(max_length));
            front.offset += max_length as u64;
            let idx = self.data.iter().take_while(|other| **other < front).count();
            self.data.insert(idx, front);
            chunk
        } else {
            // Take the entirety of the front buffer
            self.allocated -= front.allocation_size;
            self.fresh -= usize::from(!front.owned);
            Chunk::new(front.offset, front.bytes)
        };

        self.bytes_read += chunk.bytes.len() as u64;
        self.buffered -= chunk.bytes.len();
        Some(chunk)
    }

    /// Copy chunk data to buffers of our own, one per run of contiguous data
    ///
    /// No chunk holds on to the allocation it arrived in afterwards. Owned chunks of at least
    /// `MIN_RETAINED_CHUNK_SIZE` that still use half of their copy stay as they are, so a
    /// long run isn't copied again on each call. Bytes before `start` are treated as already delivered and discarded. Returns
    /// the number of disjoint spans buffered.
    fn defragment(&mut self, start: u64) -> usize {
        let buffers = mem::take(&mut self.data);
        self.buffered = 0;
        self.allocated = 0;
        self.fresh = 0;
        let mut spans = 0;
        // End of the data so far, once there is any
        let mut end = None;
        let mut offset = start;
        // Contiguous chunks to copy into one buffer, and their length
        let mut pending = Vec::new();
        let mut pending_len = 0;
        for mut chunk in buffers {
            chunk.discard_before(offset);
            // bytes might be empty after discard_before
            if chunk.bytes.is_empty() {
                continue;
            }
            if end != Some(chunk.offset) {
                self.push_merged(&mut pending);
                pending_len = 0;
                spans += 1;
            }
            offset = chunk.end();
            end = Some(offset);
            self.buffered += chunk.bytes.len();
            // A small piece before it is copied together with it rather than left alone
            if chunk.uses_allocation()
                && chunk.bytes.len() >= MIN_RETAINED_CHUNK_SIZE
                && (pending.is_empty() || pending_len >= MIN_RETAINED_CHUNK_SIZE)
            {
                self.push_merged(&mut pending);
                pending_len = 0;
                self.allocated += chunk.allocation_size;
                self.data.push_back(chunk);
            } else {
                pending_len += chunk.bytes.len();
                pending.push(chunk);
            }
        }
        self.push_merged(&mut pending);
        spans
    }

    /// Append `chunks`, contiguous, as one owned chunk
    fn push_merged(&mut self, chunks: &mut Vec<Buffer>) {
        match chunks.len() {
            0 => return,
            1 if chunks[0].uses_allocation() => {
                self.allocated += chunks[0].allocation_size;
                self.data.extend(chunks.pop());
                return;
            }
            _ => {}
        }
        let len = chunks.iter().map(|chunk| chunk.bytes.len()).sum();
        let mut buffer = BytesMut::with_capacity(len);
        for chunk in chunks.iter() {
            buffer.extend_from_slice(&chunk.bytes);
        }
        self.allocated += len;
        self.data
            .push_back(Buffer::new_owned(chunks[0].offset, buffer.freeze()));
        chunks.clear();
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
        if let State::Unordered { recvd } = &mut self.state {
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
                    self.fresh += 1;
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
            self.fresh += 1;
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
        // A chunk may hold on to a larger allocation than `allocation_size` (the datagrams
        // received at once), so bound the number not yet copied too.
        if over_allocation > threshold || self.fresh > COMPACT_THRESHOLD {
            let start = match self.state {
                State::Ordered => self.bytes_read,
                State::Unordered { .. } => 0,
            };
            if self.defragment(start) > max_spans(self.buffered) {
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
        self.fresh = 0;
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
    /// Size of the allocation behind `bytes`, as received or copied (if `owned`).
    /// Will never be less than `bytes.len()`.
    allocation_size: usize,
    /// Whether `bytes` is a copy made by `Assembler::defragment`, holding on to nothing else
    owned: bool,
}

impl Buffer {
    /// Constructs a Buffer of received data
    fn new(offset: u64, bytes: Bytes, allocation_size: usize) -> Self {
        Self {
            offset,
            bytes,
            allocation_size,
            owned: false,
        }
    }

    /// Constructs a Buffer of a copy of our own
    fn new_owned(offset: u64, bytes: Bytes) -> Self {
        let allocation_size = bytes.len();
        Self {
            offset,
            bytes,
            allocation_size,
            owned: true,
        }
    }

    /// Exclusive upper bound of the covered index range
    fn end(&self) -> u64 {
        self.offset + self.bytes.len() as u64
    }

    /// Discards data before `offset`
    fn discard_before(&mut self, offset: u64) {
        let duplicate = offset.saturating_sub(self.offset) as usize;
        self.offset = self.offset.max(offset);
        if duplicate >= self.bytes.len() {
            self.bytes = Bytes::new();
            self.allocation_size = 0;
            return;
        }
        self.bytes.advance(duplicate);
    }

    /// Whether `bytes` is our own copy and still uses at least half of it
    fn uses_allocation(&self) -> bool {
        self.owned && 2 * self.bytes.len() >= self.allocation_size
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
/// shifts up to half of `data` (see `max_spans` and `COMPACT_THRESHOLD`)
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

/// Bound on the number of disjoint spans kept for a stream with `buffered` bytes
///
/// A frame is rejected only if compaction leaves more. Each lost packet leaves a gap, so
/// past `MAX_CHUNKS` one more span is allowed per `MIN_BYTES_PER_SPAN` buffered: a large
/// receive window may hold thousands of gaps while a peer sends at full rate into a
/// queue that drops every other packet. Tiny gapped frames stay bounded by `MAX_CHUNKS`.
fn max_spans(buffered: usize) -> usize {
    (buffered / MIN_BYTES_PER_SPAN).clamp(MAX_CHUNKS, MAX_SPANS)
}

/// Spans allowed regardless of how little data they hold
// ngtcp2 uses a threshold of 4000 -- try to be a little more conservative?
const MAX_CHUNKS: usize = 1024;

/// Bound on the number of disjoint spans regardless of the data they hold
///
/// Inserting into the middle of `data` costs time linear in its length. 8192 spans hold the
/// gaps of every other packet lost in an 8 MiB receive window.
const MAX_SPANS: usize = 8 * MAX_CHUNKS;

/// Buffered bytes that each span past `MAX_CHUNKS` must bring
///
/// Below the stream data of a packet at QUIC's minimum datagram size (1200 bytes).
const MIN_BYTES_PER_SPAN: usize = 1024;

/// Minimum size of an owned chunk that `defragment` retains without copying
///
/// Bounds the chunks per span: all but its last hold at least this many bytes.
const MIN_RETAINED_CHUNK_SIZE: usize = 16 * 1024;

/// Chunks not yet copied past which `insert` compacts
///
/// Bounds the allocations that received chunks hold on to (as the fixed bound on all
/// chunks did before), while a flood of mergeable frames cannot force a defragmentation
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
        assert_matches!(next(&mut x, 1), Some(y) if &y[..] == b"1");
        assert_matches!(next(&mut x, 3), Some(y) if &y[..] == b"23");
        x.insert(3, Bytes::from_static(b"456"), 3).unwrap();
        assert_matches!(next(&mut x, 32), Some(y) if &y[..] == b"456");
        x.insert(6, Bytes::from_static(b"789"), 3).unwrap();
        x.insert(9, Bytes::from_static(b"10"), 2).unwrap();
        assert_matches!(next(&mut x, 32), Some(y) if &y[..] == b"789");
        assert_matches!(next(&mut x, 32), Some(y) if &y[..] == b"10");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_unordered() {
        let mut x = Assembler::new();
        x.ensure_ordering(false).unwrap();
        x.insert(3, Bytes::from_static(b"456"), 3).unwrap();
        assert_matches!(next(&mut x, 32), None);
        x.insert(0, Bytes::from_static(b"123"), 3).unwrap();
        assert_matches!(next(&mut x, 32), Some(y) if &y[..] == b"123");
        assert_matches!(next(&mut x, 32), Some(y) if &y[..] == b"456");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn unordered_after_ordered_read_drops_a_stale_duplicate() {
        let mut x = Assembler::new();
        // The same range arrives twice (a spurious retransmission) before
        // the application reads it.
        x.insert(0, Bytes::from_static(b"abc"), 3).unwrap();
        x.insert(0, Bytes::from_static(b"abc"), 3).unwrap();
        // An ordered read consumes one copy.
        assert_matches!(next(&mut x, 3), Some(y) if &y[..] == b"abc");
        assert_eq!(x.bytes_read(), 3);
        // Switching to unordered must not hand the stale copy back.
        x.ensure_ordering(false).unwrap();
        assert_eq!(x.read(usize::MAX, false), None);
        assert_eq!(x.bytes_read(), 3);
    }

    #[test]
    fn assemble_duplicate() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"123"), 3).unwrap();
        x.insert(0, Bytes::from_static(b"123"), 3).unwrap();
        assert_matches!(next(&mut x, 32), Some(y) if &y[..] == b"123");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_duplicate_compact() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"123"), 3).unwrap();
        x.insert(0, Bytes::from_static(b"123"), 3).unwrap();
        x.defragment(0);
        assert_matches!(next(&mut x, 32), Some(y) if &y[..] == b"123");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_contained() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"12345"), 5).unwrap();
        x.insert(1, Bytes::from_static(b"234"), 3).unwrap();
        assert_matches!(next(&mut x, 32), Some(y) if &y[..] == b"12345");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_contained_compact() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"12345"), 5).unwrap();
        x.insert(1, Bytes::from_static(b"234"), 3).unwrap();
        x.defragment(0);
        assert_matches!(next(&mut x, 32), Some(y) if &y[..] == b"12345");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_contains() {
        let mut x = Assembler::new();
        x.insert(1, Bytes::from_static(b"234"), 3).unwrap();
        x.insert(0, Bytes::from_static(b"12345"), 5).unwrap();
        assert_matches!(next(&mut x, 32), Some(y) if &y[..] == b"12345");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_contains_compact() {
        let mut x = Assembler::new();
        x.insert(1, Bytes::from_static(b"234"), 3).unwrap();
        x.insert(0, Bytes::from_static(b"12345"), 5).unwrap();
        x.defragment(0);
        assert_matches!(next(&mut x, 32), Some(y) if &y[..] == b"12345");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_overlapping() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"123"), 3).unwrap();
        x.insert(1, Bytes::from_static(b"234"), 3).unwrap();
        assert_matches!(next(&mut x, 32), Some(y) if &y[..] == b"123");
        assert_matches!(next(&mut x, 32), Some(y) if &y[..] == b"4");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_overlapping_compact() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"123"), 4).unwrap();
        x.insert(1, Bytes::from_static(b"234"), 4).unwrap();
        x.defragment(0);
        assert_matches!(next(&mut x, 32), Some(y) if &y[..] == b"1234");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_complex() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"1"), 1).unwrap();
        x.insert(2, Bytes::from_static(b"3"), 1).unwrap();
        x.insert(4, Bytes::from_static(b"5"), 1).unwrap();
        x.insert(0, Bytes::from_static(b"123456"), 6).unwrap();
        assert_matches!(next(&mut x, 32), Some(y) if &y[..] == b"123456");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_complex_compact() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"1"), 1).unwrap();
        x.insert(2, Bytes::from_static(b"3"), 1).unwrap();
        x.insert(4, Bytes::from_static(b"5"), 1).unwrap();
        x.insert(0, Bytes::from_static(b"123456"), 6).unwrap();
        x.defragment(0);
        assert_matches!(next(&mut x, 32), Some(y) if &y[..] == b"123456");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_old() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"1234"), 4).unwrap();
        assert_matches!(next(&mut x, 32), Some(y) if &y[..] == b"1234");
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
        x.defragment(0);
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
        x.defragment(0);
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
        x.defragment(0);
        assert_matches!(x.read(usize::MAX, true), Some(y) if &y.bytes[..] == b"abcdef");
        x.insert(5, Bytes::from_static(b"fghijklmn"), 9).unwrap();
        assert_matches!(x.read(usize::MAX, true), Some(y) if &y.bytes[..] == b"ghijklmn");
        x.insert(13, Bytes::from_static(b"nopq"), 4).unwrap();
        assert_matches!(x.read(usize::MAX, true), Some(y) if &y.bytes[..] == b"opq");
        x.insert(15, Bytes::from_static(b"pqrs"), 4).unwrap();
        assert_matches!(x.read(usize::MAX, true), Some(y) if &y.bytes[..] == b"rs");
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
        x.defragment(0);
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
            x.data.len() <= MAX_CHUNKS + COMPACT_THRESHOLD + 1,
            "chunk count {} exceeded the bound",
            x.data.len()
        );
    }

    /// Chunks not yet copied by `defragment`
    fn not_owned(x: &Assembler) -> usize {
        x.data.iter().filter(|chunk| !chunk.owned).count()
    }

    #[test]
    fn every_other_packet_lost_is_not_rejected() {
        // A drop-tail queue overflowing under a sender at full rate loses about every
        // other packet; an 8 MiB stream receive window holds ~3500 such gaps. Each frame
        // arrives in a receive batch of its own (64 KiB).
        const PAYLOAD: usize = 1200;
        let data = Bytes::from(vec![0; PAYLOAD]);
        // As accounted (the packet), and as possibly held (a receive batch)
        for allocation_size in [PAYLOAD + 32, 65536] {
            let mut x = Assembler::new();
            for i in 0..3500u64 {
                x.insert((2 * i + 1) * PAYLOAD as u64, data.clone(), allocation_size)
                    .expect("full-size frames behind lost packets must not be rejected");
                assert!(not_owned(&x) <= COMPACT_THRESHOLD + 1);
            }
            assert_eq!(x.defragment(0), 3500);
            assert_eq!(not_owned(&x), 0);
        }
    }

    #[test]
    fn fresh_counts_chunks_not_yet_copied() {
        // Chunks read whole leave the count, so an application reading as data arrives
        // causes no compaction
        let mut x = Assembler::new();
        let data = Bytes::from(vec![0; 1200]);
        for i in 0..(3 * COMPACT_THRESHOLD as u64) {
            x.insert(i * 1200, data.clone(), 1200).unwrap();
            assert_eq!(x.fresh, not_owned(&x));
            while x.read(usize::MAX, true).is_some() {}
            assert_eq!(x.fresh, 0);
        }
        // Gapped, then read in part and whole up to the first gap
        let base = x.bytes_read();
        for i in 0..(3 * COMPACT_THRESHOLD as u64) {
            x.insert(base + 2 * i * 1200, data.clone(), 1200).unwrap();
            assert_eq!(x.fresh, not_owned(&x));
        }
        x.insert(base + 1200, data.clone(), 1200).unwrap();
        while x.read(1000, true).is_some() {
            assert_eq!(x.fresh, not_owned(&x));
        }
        assert_eq!(x.bytes_read(), base + 3 * 1200);
    }

    #[test]
    fn spans_bounded_regardless_of_data() {
        const PAYLOAD: usize = 1200;
        let mut x = Assembler::new();
        let data = Bytes::from(vec![0; PAYLOAD]);
        let mut accepted = 0;
        while x
            .insert((2 * accepted + 1) * PAYLOAD as u64, data.clone(), PAYLOAD)
            .is_ok()
        {
            accepted += 1;
            assert!(
                accepted as usize <= MAX_SPANS + COMPACT_THRESHOLD,
                "never rejected"
            );
        }
        assert!(accepted as usize >= MAX_SPANS);
    }

    #[test]
    fn filled_gaps_leave_no_small_chunks() {
        // Gaps between large copies filled one byte each: no one-byte chunk stays between them
        const LEN: usize = MIN_RETAINED_CHUNK_SIZE;
        let mut x = Assembler::new();
        for i in 0..64u64 {
            let offset = 1 + i * (LEN as u64 + 1);
            x.insert(offset, Bytes::from(vec![0; LEN]), LEN).unwrap();
        }
        assert_eq!(x.defragment(0), 64);
        for i in 1..64u64 {
            x.insert(i * (LEN as u64 + 1), Bytes::from_static(b"x"), 1)
                .unwrap();
        }
        assert_eq!(x.defragment(0), 1);
        assert!(
            x.data
                .iter()
                .rev()
                .skip(1)
                .all(|chunk| chunk.bytes.len() >= LEN)
        );
    }

    #[test]
    fn trimmed_copy_is_not_retained() {
        // Frames each overlapping the start of a large copy must not leave most of it
        // held by a chunk that keeps only its tail
        const LEN: usize = 1 << 20;
        const FRAME: usize = 1400;
        let mut x = Assembler::new();
        let mut start = 1 << 30;
        x.insert(start, Bytes::from(vec![0; LEN]), 2 * LEN).unwrap();
        x.defragment(0);
        let copy = x.data[0].bytes.as_ptr_range();
        for _ in 0..(LEN / FRAME) {
            start -= 1;
            x.insert(start, Bytes::from(vec![0; FRAME]), FRAME).unwrap();
            x.defragment(0);
            start = x.data.back().unwrap().offset;
            for chunk in &x.data {
                if copy.contains(&chunk.bytes.as_ptr()) {
                    assert!(
                        2 * chunk.bytes.len() >= LEN,
                        "{} bytes hold the copy",
                        chunk.bytes.len()
                    );
                }
            }
        }
    }

    #[test]
    fn many_chunks_behind_one_gap_are_not_rejected() {
        // Large and small chunks alternating behind one missing byte are one span
        let mut x = Assembler::new();
        let mut offset = 1;
        for _ in 0..600 {
            for len in [5000, 400, 400, 400] {
                x.insert(offset, Bytes::from(vec![0; len]), len)
                    .expect("contiguous data must not be rejected");
                offset += len as u64;
            }
        }
        assert_eq!(x.defragment(0), 1);
    }

    #[test]
    fn bounded_chunks_with_bulk_data_buffered() {
        // Bulk data buffered must not let small gapped frames add more spans than it pays for
        let mut x = Assembler::new();
        let bulk = 8 << 20;
        x.insert(1, Bytes::from(vec![0; bulk]), bulk).unwrap();
        let mut offset = 2 + bulk as u64;
        let mut accepted = 0;
        let result: Result<(), _> = loop {
            if let Err(e) = x.insert(offset, Bytes::from_static(b"gap"), 3) {
                break Err(e);
            }
            assert!(accepted < 8 * max_spans(bulk), "never rejected");
            accepted += 1;
            offset += 3 + 1; // 3 data bytes, 1 byte gap
        };
        assert_matches!(result, Err(TooManyChunks));
        assert!(accepted >= max_spans(bulk) - 1);
        assert!(
            x.data.len() <= max_spans(x.buffered) + COMPACT_THRESHOLD + 1,
            "chunk count {} exceeded the bound",
            x.data.len()
        );
    }

    #[test]
    fn duplicates_do_not_raise_the_bound() {
        // Duplicates count toward `buffered` in ordered mode until compacted away
        let mut x = Assembler::new();
        let bulk = 1 << 20;
        let data = Bytes::from(vec![0; bulk]);
        for _ in 0..8 {
            x.insert(1, data.clone(), bulk).unwrap();
        }
        let mut offset = 2 + bulk as u64;
        let mut accepted = 0;
        while x.insert(offset, Bytes::from_static(b"gap"), 3).is_ok() {
            accepted += 1;
            offset += 3 + 1;
        }
        assert!(
            accepted <= max_spans(bulk) + COMPACT_THRESHOLD,
            "{accepted} gapped frames accepted"
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
                x.data.len() <= MAX_CHUNKS + COMPACT_THRESHOLD + 1,
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
                x.data.len() <= MAX_CHUNKS + COMPACT_THRESHOLD + 1,
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
        x.defragment(0);
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
