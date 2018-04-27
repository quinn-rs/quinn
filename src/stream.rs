use std::collections::{VecDeque, BTreeMap};

use bytes::Bytes;

use range_set::RangeSet;

use {Side, StreamId};

#[derive(Debug)]
pub enum Stream {
    Send(Send),
    Recv(Recv),
    Both(Send, Recv),
}

impl Stream {
    pub fn new(id: StreamId, side: Side, window: u64) -> Self {
        use Directionality::*;
        match (id.directionality(), id.initiator(), side) {
            (Bi, _, _) => Stream::Both(Send::new(), Recv::new(window)),
            (Uni, x, y) if x == y => Send::new().into(),
            (Uni, _, _) => Recv::new(window).into()
        }
    }

    pub fn new_bi(window: u64) -> Self { Stream::Both(Send::new(), Recv::new(window)) }

    pub fn send(&self) -> Option<&Send> {
        match *self {
            Stream::Send(ref x) => Some(x),
            Stream::Both(ref x, _) => Some(x),
            _ => None
        }
    }

    pub fn recv(&self) -> Option<&Recv> {
        match *self {
            Stream::Recv(ref x) => Some(x),
            Stream::Both(_, ref x) => Some(x),
            _ => None
        }
    }

    pub fn send_mut(&mut self) -> Option<&mut Send> {
        match *self {
            Stream::Send(ref mut x) => Some(x),
            Stream::Both(ref mut x, _) => Some(x),
            _ => None
        }
    }

    pub fn recv_mut(&mut self) -> Option<&mut Recv> {
        match *self {
            Stream::Recv(ref mut x) => Some(x),
            Stream::Both(_, ref mut x) => Some(x),
            _ => None
        }
    }

    /// Safe to free
    pub fn is_closed(&self) -> bool {
        self.send().map_or(true, |x| x.is_closed())
            && self.recv().map_or(true, |x| x.is_closed())
    }
}

impl From<Send> for Stream { fn from(x: Send) -> Stream { Stream::Send(x) } }
impl From<Recv> for Stream { fn from(x: Recv) -> Stream { Stream::Recv(x) } }

#[derive(Debug, Copy, Clone)]
pub struct Send {
    pub offset: u64,
    pub max_data: u64,
    pub state: SendState,
    /// Number of bytes sent but unacked
    pub bytes_in_flight: u64,
}

impl Send {
    pub fn new() -> Self { Self {
        offset: 0,
        max_data: 0,
        state: SendState::Ready,
        bytes_in_flight: 0,
    }}

    /// All data acknowledged and STOP_SENDING error code, if any, processed by application
    pub fn is_closed(&self) -> bool {
        use self::SendState::*;
        match self.state {
            DataRecvd | ResetRecvd { stop_reason: None } => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Recv {
    pub state: RecvState,
    pub recvd: RangeSet,
    pub buffered: VecDeque<(Bytes, u64)>,
    /// Current limit, which may or may not have been sent
    pub max_data: u64,
}

impl Recv {
    pub fn new(max_data: u64) -> Self { Self {
        state: RecvState::Recv { size: None },
        recvd: RangeSet::new(),
        buffered: VecDeque::new(),
        max_data,
    }}

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

    pub fn buffer(&mut self, data: Bytes, offset: u64) {
        // TODO: Dedup
        self.buffered.push_back((data, offset));
    }

    /// Offset after the largest byte received
    pub fn limit(&self) -> u64 { self.recvd.max().map_or(0, |x| x+1) }

    pub fn final_offset(&self) -> Option<u64> {
        match self.state {
            RecvState::Recv { size } => size,
            RecvState::ResetRecvd { size, .. } => Some(size),
            RecvState::DataRecvd { size } => Some(size),
            _ => None,
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SendState {
    Ready, DataSent, ResetSent { stop_reason: Option<u16> }, DataRecvd, ResetRecvd { stop_reason: Option<u16> },
}

impl SendState {
    pub fn was_reset(&self) -> bool {
        use self::SendState::*;
        match *self {
            ResetSent { .. } | ResetRecvd { .. } => true,
            _ => false,
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum RecvState {
    Recv { size: Option<u64> },
    DataRecvd { size: u64 }, ResetRecvd { size: u64, error_code: u16 },
    Closed,
}

#[derive(Debug)]
pub struct Assembler {
    offset: u64,
    /// (offset, data)
    segments: BTreeMap<u64, Bytes>,
}

impl Assembler {
    pub fn new() -> Self { Self::with_offset(0) }
    pub fn with_offset(x: u64) -> Self { Self { offset: x, segments: BTreeMap::new() } }
    pub fn is_empty(&self) -> bool { self.segments.is_empty() }
    pub fn offset(&self) -> u64 { self.offset }

    pub fn next(&mut self) -> Option<Bytes> {
        if let Some(data) = self.segments.remove(&self.offset) {
            self.offset += data.len() as u64;
            Some(data)
        } else { None }
    }

    pub fn insert(&mut self, mut offset: u64, mut data: Bytes) {
        let prev_end = if let Some((&prev_off, prev_data)) = self.segments.range(..offset).rev().next() {
            prev_off + prev_data.len() as u64
        } else {
            self.offset
        };
        if let Some(relative) = prev_end.checked_sub(offset) {
            if relative >= data.len() as u64 { return; }
            offset += relative;
            data.advance(relative as usize);
        }

        // For every segment we overlap:
        // - if the segment extends past our end, truncate ourselves and finish
        // - if we meet or extend past the segment's end, drop it
        // This ensures our data remains roughly as contiguous as possible.
        let mut to_drop = Vec::new();
        for (&next_off, next_data) in self.segments.range(offset..) {
            let end = offset + data.len() as u64;
            let next_end = next_off + next_data.len() as u64;
            if next_off >= end {
                // There's a gap here, so we're finished.
                break;
            } else if next_end < end {
                // The existing segment is a subset of us; discard it
                to_drop.push(next_off);
            } else if next_off == offset {
                // We are wholly contained by the existing segment; bail out.
                // Note that this can only happen on the first iteration, so to_drop is necessarily empty, so skipping
                // the cleanup is fine.
                return;
            } else {
                // We partially overlap the existing segment; truncate and finish.
                data.truncate((next_off - offset) as usize);
                break;
            }
        }
        for x in to_drop { self.segments.remove(&x); }
        self.segments.insert(offset, data);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn assemble_ordered() {
        let mut x = Assembler::new();
        assert_matches!(x.next(), None);
        x.insert(0, (&b"123"[..]).into());
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"123");
        x.insert(3, (&b"456"[..]).into());
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"456");
        x.insert(6, (&b"789"[..]).into());
        x.insert(9, (&b"10"[..]).into());
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"789");
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"10");
        assert_matches!(x.next(), None);
    }

    #[test]
    fn assemble_unordered() {
        let mut x = Assembler::new();
        x.insert(3, (&b"456"[..]).into());
        assert_matches!(x.next(), None);
        x.insert(0, (&b"123"[..]).into());
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"123");
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"456");
        assert_matches!(x.next(), None);
    }

    #[test]
    fn assemble_duplicate() {
        let mut x = Assembler::new();
        x.insert(0, (&b"123"[..]).into());
        x.insert(0, (&b"123"[..]).into());
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"123");
        assert_matches!(x.next(), None);
    }

    #[test]
    fn assemble_contained() {
        let mut x = Assembler::new();
        x.insert(0, (&b"12345"[..]).into());
        x.insert(1, (&b"234"[..]).into());
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"12345");
        assert_matches!(x.next(), None);
    }

    #[test]
    fn assemble_contains() {
        let mut x = Assembler::new();
        x.insert(1, (&b"234"[..]).into());
        x.insert(0, (&b"12345"[..]).into());
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"12345");
        assert_matches!(x.next(), None);
    }

    #[test]
    fn assemble_overlapping() {
        let mut x = Assembler::new();
        x.insert(0, (&b"123"[..]).into());
        x.insert(1, (&b"234"[..]).into());
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"123");
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"4");
        assert_matches!(x.next(), None);
    }

    #[test]
    fn assemble_complex() {
        let mut x = Assembler::new();
        x.insert(0, (&b"1"[..]).into());
        x.insert(2, (&b"3"[..]).into());
        x.insert(4, (&b"5"[..]).into());
        x.insert(0, (&b"123456"[..]).into());
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"123456");
        assert_matches!(x.next(), None);
    }
}
