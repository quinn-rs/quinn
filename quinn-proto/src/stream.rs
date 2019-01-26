use std::collections::VecDeque;

use bytes::Bytes;
use err_derive::Error;

use crate::range_set::RangeSet;

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
    pub buffered: VecDeque<(Bytes, u64)>,
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
            buffered: VecDeque::new(),
            unordered: false,
            assembler: Assembler::new(),
            bytes_read: 0,
        }
    }

    /// Whether a read is guaranteed to fail now, but might succeed later
    pub fn is_blocked(&self) -> bool {
        self.buffered.is_empty() && self.assembler.blocked() && !self.is_finished()
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, ReadError> {
        assert!(
            !self.unordered,
            "cannot perform ordered reads following unordered reads on a stream"
        );

        for (data, offset) in self.buffered.drain(..) {
            self.assembler.insert(offset, &data);
        }

        if !self.assembler.blocked() {
            let n = self.assembler.read(buf);
            self.bytes_read += n as u64;
            Ok(n)
        } else {
            Err(self.read_blocked())
        }
    }

    pub fn read_unordered(&mut self) -> Result<(Bytes, u64), ReadError> {
        self.unordered = true;
        // TODO: Drain rs.assembler to handle ordered-then-unordered reads reliably

        // Return data we already have buffered, regardless of state
        if let Some(x) = self.buffered.pop_front() {
            self.bytes_read += x.0.len() as u64;
            Ok(x)
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

    pub fn buffer(&mut self, data: Bytes, offset: u64) {
        // TODO: Dedup
        if data.is_empty() {
            return;
        }
        self.buffered.push_back((data, offset));
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
        self.buffered.clear();
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
    data: VecDeque<u8>,
    /// bitmap of data bytes; 0 = written, 1 = not
    written: VecDeque<u8>,
    /// number of bits of written to skip; always < 8
    written_offset: u8,
}

impl Assembler {
    pub fn new() -> Self {
        Self {
            offset: 0,
            data: VecDeque::new(),
            written: VecDeque::new(),
            written_offset: 0,
        }
    }

    /// Whether `read` will return nonzero
    pub fn blocked(&self) -> bool {
        let mask = !0 >> self.written_offset;
        self.written.front().map_or(true, |x| x & mask == mask)
    }

    /// Leading written bytes
    fn prefix_len(&self) -> usize {
        for i in 0..self.written.len() {
            let x = self.written[i];
            if x == 0 || (i == 0 && x << self.written_offset == 0) {
                continue;
            }
            return (i * 8 + x.leading_zeros() as usize) - self.written_offset as usize;
        }
        self.written.len()
    }

    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let (a, b) = self.data.as_slices();
        let available = self.prefix_len();
        let a_len = a.len().min(available);
        let (a, b) = (&a[0..a_len], &b[0..(available - a_len)]);
        let a_n = a.len().min(buf.len());
        buf[0..a_n].copy_from_slice(&a[0..a_n]);
        let b_n = b.len().min(buf.len().saturating_sub(a.len()));
        buf[a_n..(a_n + b_n)].copy_from_slice(&b[0..b_n]);
        let n = a_n + b_n;

        self.offset += n as u64;
        self.data.drain(0..n);
        let q = n / 8;
        let r = n % 8;
        let carry = (self.written_offset as usize + r) / 8;
        self.written.drain(0..(q + carry));
        self.written_offset = (self.written_offset as usize + r - carry * 8) as u8;

        n
    }

    #[cfg(test)]
    fn next(&mut self) -> Option<Box<[u8]>> {
        let mut buf = Vec::new();
        buf.resize(self.prefix_len(), 0);
        self.read(&mut buf);
        if !buf.is_empty() {
            Some(buf.into())
        } else {
            None
        }
    }

    pub fn insert(&mut self, mut offset: u64, mut data: &[u8]) {
        if let Some(advance) = self.offset.checked_sub(offset) {
            if advance >= data.len() as u64 {
                return;
            }
            data = &data[advance as usize..];
            offset += advance;
        }
        let start = (offset - self.offset) as usize;
        let end = start + data.len();
        if end > self.data.len() {
            self.data.resize(end, 0);
            // 1 extra to leave room for written_extra
            self.written
                .resize(end / 8 + (end % 8 != 0) as usize + 1, !0);
        }
        for (i, b) in data.iter().enumerate() {
            let position = start + i;
            self.data[position] = *b;
            let bit = self.written_offset as usize + position;
            self.written[bit / 8] &= !(1 << (7 - bit % 8));
        }
    }

    /// Current position in the stream
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Discard all buffered data
    pub fn clear(&mut self) {
        self.written = VecDeque::new();
        self.data = VecDeque::new();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn assemble_ordered() {
        let mut x = Assembler::new();
        assert_matches!(x.next(), None);
        x.insert(0, &b"123"[..]);
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"123");
        x.insert(3, &b"456"[..]);
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"456");
        x.insert(6, &b"789"[..]);
        x.insert(9, &b"10"[..]);
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"78910");
        assert_matches!(x.next(), None);
    }

    #[test]
    fn assemble_unordered() {
        let mut x = Assembler::new();
        x.insert(3, &b"456"[..]);
        assert_matches!(x.next(), None);
        x.insert(0, &b"123"[..]);
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"123456");
        assert_matches!(x.next(), None);
    }

    #[test]
    fn assemble_duplicate() {
        let mut x = Assembler::new();
        x.insert(0, &b"123"[..]);
        x.insert(0, &b"123"[..]);
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"123");
        assert_matches!(x.next(), None);
    }

    #[test]
    fn assemble_contained() {
        let mut x = Assembler::new();
        x.insert(0, &b"12345"[..]);
        x.insert(1, &b"234"[..]);
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"12345");
        assert_matches!(x.next(), None);
    }

    #[test]
    fn assemble_contains() {
        let mut x = Assembler::new();
        x.insert(1, &b"234"[..]);
        x.insert(0, &b"12345"[..]);
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"12345");
        assert_matches!(x.next(), None);
    }

    #[test]
    fn assemble_overlapping() {
        let mut x = Assembler::new();
        x.insert(0, &b"123"[..]);
        x.insert(1, &b"234"[..]);
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"1234");
        assert_matches!(x.next(), None);
    }

    #[test]
    fn assemble_complex() {
        let mut x = Assembler::new();
        x.insert(0, &b"1"[..]);
        x.insert(2, &b"3"[..]);
        x.insert(4, &b"5"[..]);
        x.insert(0, &b"123456"[..]);
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"123456");
        assert_matches!(x.next(), None);
    }

    #[test]
    fn assemble_old() {
        let mut x = Assembler::new();
        x.insert(0, b"1234");
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"1234");
        x.insert(0, b"1234");
        assert_matches!(x.next(), None);
    }
}
