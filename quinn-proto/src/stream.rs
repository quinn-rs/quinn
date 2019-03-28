use std::cmp::Ordering;
use std::collections::{hash_map, BinaryHeap};

use bytes::Bytes;
use err_derive::Error;
use fnv::FnvHashMap;

use crate::range_set::RangeSet;
use crate::{Directionality, Side, StreamId, TransportError};

pub struct Streams {
    // Set of streams that are currently open, or could be immediately opened by the peer
    pub streams: FnvHashMap<StreamId, Stream>,
    pub next_uni: u64,
    pub next_bi: u64,
    // Locally initiated
    pub max_uni: u64,
    pub max_bi: u64,
    // Maximum that can be remotely initiated
    pub max_remote_uni: u64,
    pub max_remote_bi: u64,
    // Lowest that hasn't actually been opened
    pub next_remote_uni: u64,
    pub next_remote_bi: u64,
    // Next to report to the application, once opened
    pub next_reported_remote_uni: u64,
    pub next_reported_remote_bi: u64,
}

impl Streams {
    pub fn read(&mut self, id: StreamId, buf: &mut [u8]) -> Result<(usize, bool), ReadError> {
        let rs = self.get_recv_mut(id).ok_or(ReadError::UnknownStream)?;
        Ok((rs.read(buf)?, rs.receiving_unknown_size()))
    }

    pub fn read_unordered(&mut self, id: StreamId) -> Result<(Bytes, u64, bool), ReadError> {
        let rs = self.get_recv_mut(id).ok_or(ReadError::UnknownStream)?;
        let (buf, len) = rs.read_unordered()?;
        Ok((buf, len, rs.receiving_unknown_size()))
    }

    pub fn get_recv_stream(
        &mut self,
        side: Side,
        id: StreamId,
    ) -> Result<Option<&mut Stream>, TransportError> {
        if side == id.initiator() {
            match id.directionality() {
                Directionality::Uni => {
                    return Err(TransportError::STREAM_STATE_ERROR(
                        "illegal operation on send-only stream",
                    ));
                }
                Directionality::Bi if id.index() >= self.next_bi => {
                    return Err(TransportError::STREAM_STATE_ERROR(
                        "operation on unopened stream",
                    ));
                }
                Directionality::Bi => {}
            };
        } else {
            let limit = match id.directionality() {
                Directionality::Bi => self.max_remote_bi,
                Directionality::Uni => self.max_remote_uni,
            };
            if id.index() >= limit {
                return Err(TransportError::STREAM_LIMIT_ERROR(""));
            }
        }
        Ok(self.streams.get_mut(&id))
    }

    /// Discard state for a stream if it's fully closed.
    ///
    /// Called when one side of a stream transitions to a closed state
    pub fn maybe_cleanup(&mut self, id: StreamId) {
        match self.streams.entry(id) {
            hash_map::Entry::Vacant(_) => unreachable!(),
            hash_map::Entry::Occupied(e) => {
                if e.get().is_closed() {
                    e.remove_entry();
                }
            }
        }
    }

    pub fn get_recv_mut(&mut self, id: StreamId) -> Option<&mut Recv> {
        self.streams.get_mut(&id)?.recv_mut()
    }

    pub fn get_send_mut(&mut self, id: StreamId) -> Option<&mut Send> {
        self.streams.get_mut(&id)?.send_mut()
    }

    /// Whether a presumed-local stream is or was previously open
    pub fn is_local_unopened(&self, id: StreamId) -> bool {
        id.index()
            >= match id.directionality() {
                Directionality::Bi => self.next_bi,
                Directionality::Uni => self.next_uni,
            }
    }
}

#[derive(Debug)]
pub enum Stream {
    Send(Send),
    Recv(Recv),
    Both(Send, Recv),
}

impl Stream {
    pub fn new_bi() -> Self {
        Stream::Both(Send::new(), Recv::new())
    }

    pub fn send(&self) -> Option<&Send> {
        match *self {
            Stream::Send(ref x) => Some(x),
            Stream::Both(ref x, _) => Some(x),
            _ => None,
        }
    }

    pub fn recv(&self) -> Option<&Recv> {
        match *self {
            Stream::Recv(ref x) => Some(x),
            Stream::Both(_, ref x) => Some(x),
            _ => None,
        }
    }

    pub fn send_mut(&mut self) -> Option<&mut Send> {
        match *self {
            Stream::Send(ref mut x) => Some(x),
            Stream::Both(ref mut x, _) => Some(x),
            _ => None,
        }
    }

    pub fn recv_mut(&mut self) -> Option<&mut Recv> {
        match *self {
            Stream::Recv(ref mut x) => Some(x),
            Stream::Both(_, ref mut x) => Some(x),
            _ => None,
        }
    }

    /// Safe to free
    pub fn is_closed(&self) -> bool {
        self.send().map_or(true, |x| x.is_closed()) && self.recv().map_or(true, |x| x.is_closed())
    }
}

impl From<Send> for Stream {
    fn from(x: Send) -> Stream {
        Stream::Send(x)
    }
}
impl From<Recv> for Stream {
    fn from(x: Recv) -> Stream {
        Stream::Recv(x)
    }
}

#[derive(Debug)]
pub struct Send {
    pub offset: u64,
    pub max_data: u64,
    pub state: SendState,
    /// Number of bytes sent but unacked
    pub bytes_in_flight: u64,
}

impl Send {
    pub fn new() -> Self {
        Self {
            offset: 0,
            max_data: 0,
            state: SendState::Ready,
            bytes_in_flight: 0,
        }
    }

    pub fn write_budget(&mut self) -> Result<u64, WriteError> {
        match self.state {
            SendState::ResetSent {
                ref mut stop_reason,
            }
            | SendState::ResetRecvd {
                ref mut stop_reason,
            } => {
                if let Some(error_code) = stop_reason.take() {
                    return Err(WriteError::Stopped { error_code });
                }
            }
            _ => {}
        };

        let budget = self.max_data - self.offset;
        if budget == 0 {
            Err(WriteError::Blocked)
        } else {
            Ok(budget)
        }
    }

    /// All data acknowledged and STOP_SENDING error code, if any, processed by application
    pub fn is_closed(&self) -> bool {
        use self::SendState::*;
        match self.state {
            DataRecvd | ResetRecvd { stop_reason: None } => true,
            _ => false,
        }
    }
}

#[derive(Debug, Error, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum WriteError {
    /// The peer is not able to accept additional data, or the connection is congested.
    #[error(display = "unable to accept further writes")]
    Blocked,
    /// The peer is no longer accepting data on this stream.
    #[error(display = "stopped by peer: error {}", error_code)]
    Stopped { error_code: u16 },
}

#[derive(Debug)]
pub struct Recv {
    pub state: RecvState,
    pub recvd: RangeSet,
    /// Whether any unordered reads have been performed, making this stream unusable for ordered
    /// reads
    pub unordered: bool,
    pub assembler: Assembler,
    /// Number of bytes read by the application. Equal to assembler.offset when `unordered` is
    /// false.
    pub bytes_read: u64,
}

impl Recv {
    pub fn new() -> Self {
        Self {
            state: RecvState::Recv { size: None },
            recvd: RangeSet::new(),
            unordered: false,
            assembler: Assembler::new(),
            bytes_read: 0,
        }
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, ReadError> {
        assert!(
            !self.unordered,
            "cannot perform ordered reads following unordered reads on a stream"
        );

        let read = self.assembler.read(buf);
        if read > 0 {
            self.bytes_read += read as u64;
            Ok(read)
        } else {
            Err(self.read_blocked())
        }
    }

    pub fn read_unordered(&mut self) -> Result<(Bytes, u64), ReadError> {
        self.unordered = true;

        // Return data we already have buffered, regardless of state
        if let Some((offset, bytes)) = self.assembler.pop() {
            self.bytes_read += bytes.len() as u64;
            Ok((bytes, offset))
        } else {
            Err(self.read_blocked())
        }
    }

    fn read_blocked(&mut self) -> ReadError {
        match self.state {
            RecvState::ResetRecvd { error_code, .. } => {
                self.state = RecvState::Closed;
                ReadError::Reset { error_code }
            }
            RecvState::Closed => panic!("tried to read from a closed stream"),
            RecvState::Recv { .. } => ReadError::Blocked,
            RecvState::DataRecvd { .. } => {
                self.state = RecvState::Closed;
                ReadError::Finished
            }
        }
    }

    pub fn receiving_unknown_size(&self) -> bool {
        match self.state {
            RecvState::Recv { size: None } => true,
            _ => false,
        }
    }

    /// No more data expected from peer
    pub fn is_finished(&self) -> bool {
        match self.state {
            RecvState::Recv { .. } => false,
            _ => true,
        }
    }

    /// All data read by application
    pub fn is_closed(&self) -> bool {
        self.state == self::RecvState::Closed
    }

    pub fn buffer(&mut self, bytes: Bytes, offset: u64) {
        // TODO: Dedup
        if bytes.is_empty() {
            return;
        }
        self.assembler.insert(offset, bytes);
    }

    /// Offset after the largest byte received
    pub fn limit(&self) -> u64 {
        self.recvd.max().map_or(0, |x| x + 1)
    }

    pub fn final_offset(&self) -> Option<u64> {
        match self.state {
            RecvState::Recv { size } => size,
            RecvState::ResetRecvd { size, .. } => Some(size),
            RecvState::DataRecvd { size } => Some(size),
            _ => None,
        }
    }

    pub fn reset(&mut self, error_code: u16, final_offset: u64) {
        if self.is_closed() {
            return;
        }
        self.state = RecvState::ResetRecvd {
            size: final_offset,
            error_code,
        };
        // Nuke buffers so that future reads fail immediately, which ensures future reads don't
        // issue flow control credit redundant to that already issued. We could instead special-case
        // reset streams during read, but it's unclear if there's any benefit to retaining data for
        // reset streams.
        self.assembler.clear();
    }
}

#[derive(Debug, Error, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ReadError {
    /// No more data is currently available on this stream.
    #[error(display = "blocked")]
    Blocked,
    /// The peer abandoned transmitting data on this stream.
    #[error(display = "reset by peer: error {}", error_code)]
    Reset { error_code: u16 },
    /// The data on this stream has been fully delivered and no more will be transmitted.
    #[error(display = "finished")]
    Finished,
    /// Unknown stream
    #[error(display = "unknown stream")]
    UnknownStream,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SendState {
    Ready,
    DataSent,
    ResetSent { stop_reason: Option<u16> },
    DataRecvd,
    ResetRecvd { stop_reason: Option<u16> },
}

impl SendState {
    pub fn was_reset(self) -> bool {
        use self::SendState::*;
        match self {
            ResetSent { .. } | ResetRecvd { .. } => true,
            _ => false,
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum RecvState {
    Recv { size: Option<u64> },
    DataRecvd { size: u64 },
    ResetRecvd { size: u64, error_code: u16 },
    Closed,
}

/// Helper to assemble unordered stream frames into an ordered stream
#[derive(Debug)]
pub struct Assembler {
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

    pub fn read(&mut self, buf: &mut [u8]) -> usize {
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
        let mut chunk = if let Some(chunk) = self.data.peek_mut() {
            chunk
        } else {
            return false;
        };

        // If this chunk is either after the current offset or fully before it,
        // return directly, indicating whether the chunk can be discarded.
        if chunk.offset > self.offset {
            return false;
        } else if (chunk.offset + chunk.bytes.len() as u64) < self.offset {
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

    pub fn pop(&mut self) -> Option<(u64, Bytes)> {
        self.data.pop().map(|x| (x.offset, x.bytes))
    }

    pub fn insert(&mut self, offset: u64, bytes: Bytes) {
        self.data.push(Chunk { offset, bytes });
    }

    /// Current position in the stream
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Discard all buffered data
    pub fn clear(&mut self) {
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
