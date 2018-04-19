use std::collections::VecDeque;

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
