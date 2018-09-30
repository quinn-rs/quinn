use std::collections::VecDeque;

use bytes::Bytes;

use range_set::RangeSet;

#[derive(Debug)]
pub enum Stream {
    Send(Send),
    Recv(Recv),
    Both(Send, Recv),
}

impl Stream {
    pub fn new_bi(window: u64) -> Self {
        Stream::Both(Send::new(), Recv::new(window))
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

    /// All data acknowledged and STOP_SENDING error code, if any, processed by application
    pub fn is_closed(&self) -> bool {
        use self::SendState::*;
        match self.state {
            DataRecvd | ResetRecvd { stop_reason: None } => true,
            _ => false,
        }
    }
}

#[derive(Debug)]
pub struct Recv {
    pub state: RecvState,
    pub recvd: RangeSet,
    pub buffered: VecDeque<(Bytes, u64)>,
    /// Upper limit dictated by the peer
    pub max_data: u64,
    /// Whether any unordered reads have been performed, making this stream unusable for ordered reads
    pub unordered: bool,
    pub assembler: Assembler,
    /// Whether the application is aware of this stream yet
    pub fresh: bool,
}

impl Recv {
    pub fn new(max_data: u64) -> Self {
        Self {
            state: RecvState::Recv { size: None },
            recvd: RangeSet::new(),
            buffered: VecDeque::new(),
            max_data,
            unordered: false,
            assembler: Assembler::new(),
            fresh: true,
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

    /// Whether `peek` will return at least one nonempty slice
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
        let n;
        {
            let (a, b) = self.data.as_slices();
            let available = self.prefix_len();
            let a_len = a.len().min(available);
            let (a, b) = (&a[0..a_len], &b[0..(available - a_len)]);
            let a_n = a.len().min(buf.len());
            buf[0..a_n].copy_from_slice(&a[0..a_n]);
            let b_n = b.len().min(buf.len().saturating_sub(a.len()));
            buf[a_n..(a_n + b_n)].copy_from_slice(&b[0..b_n]);
            n = a_n + b_n;
        }

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
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"78910");
        assert_matches!(x.next(), None);
    }

    #[test]
    fn assemble_unordered() {
        let mut x = Assembler::new();
        x.insert(3, (&b"456"[..]).into());
        assert_matches!(x.next(), None);
        x.insert(0, (&b"123"[..]).into());
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"123456");
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
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"1234");
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

    #[test]
    fn assemble_old() {
        let mut x = Assembler::new();
        x.insert(0, b"1234");
        assert_matches!(x.next(), Some(ref y) if &y[..] == b"1234");
        x.insert(0, b"1234");
        assert_matches!(x.next(), None);
    }
}
