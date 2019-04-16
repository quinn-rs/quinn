use std::collections::hash_map;

use bytes::Bytes;
use err_derive::Error;
use fnv::FnvHashMap;
use slog::Logger;

use crate::assembler::Assembler;
use crate::frame;
use crate::range_set::RangeSet;
use crate::{Directionality, Side, StreamId, TransportError};

pub struct Streams {
    // Set of streams that are currently open, or could be immediately opened by the peer
    streams: FnvHashMap<StreamId, Stream>,
    next_uni: u64,
    next_bi: u64,
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
    next_reported_remote_uni: u64,
    next_reported_remote_bi: u64,
}

impl Streams {
    pub fn new(side: Side, max_remote_uni: u64, max_remote_bi: u64) -> Self {
        let mut streams = FnvHashMap::default();
        for i in 0..max_remote_uni {
            streams.insert(
                StreamId::new(!side, Directionality::Uni, i),
                Recv::new().into(),
            );
        }
        for i in 0..max_remote_bi {
            streams.insert(
                StreamId::new(!side, Directionality::Bi, i as u64),
                Stream::new_bi(),
            );
        }
        Self {
            streams,
            next_uni: 0,
            next_bi: 0,
            max_uni: 0,
            max_bi: 0,
            max_remote_uni,
            max_remote_bi,
            next_remote_uni: 0,
            next_remote_bi: 0,
            next_reported_remote_uni: 0,
            next_reported_remote_bi: 0,
        }
    }

    pub fn open(&mut self, side: Side, direction: Directionality) -> Option<StreamId> {
        let (id, stream) = match direction {
            Directionality::Uni if self.next_uni < self.max_uni => {
                self.next_uni += 1;
                (
                    StreamId::new(side, direction, self.next_uni - 1),
                    Send::new().into(),
                )
            }
            Directionality::Bi if self.next_bi < self.max_bi => {
                self.next_bi += 1;
                (
                    StreamId::new(side, direction, self.next_bi - 1),
                    Stream::new_bi(),
                )
            }
            _ => {
                return None;
            }
        };
        assert!(self.streams.insert(id, stream).is_none());
        Some(id)
    }

    pub fn alloc_remote_stream(&mut self, side: Side, ty: Directionality) {
        let (id, stream) = match ty {
            Directionality::Bi => {
                self.max_remote_bi += 1;
                (
                    StreamId::new(!side, Directionality::Bi, self.max_remote_bi - 1),
                    Stream::new_bi(),
                )
            }
            Directionality::Uni => {
                self.max_remote_uni += 1;
                (
                    StreamId::new(!side, Directionality::Uni, self.max_remote_uni - 1),
                    Recv::new().into(),
                )
            }
        };
        self.streams.insert(id, stream);
    }

    pub fn accept(&mut self, side: Side) -> Option<StreamId> {
        if self.next_remote_uni > self.next_reported_remote_uni {
            let x = self.next_reported_remote_uni;
            self.next_reported_remote_uni = x + 1;
            Some(StreamId::new(!side, Directionality::Uni, x))
        } else if self.next_remote_bi > self.next_reported_remote_bi {
            let x = self.next_reported_remote_bi;
            self.next_reported_remote_bi = x + 1;
            Some(StreamId::new(!side, Directionality::Bi, x))
        } else {
            None
        }
    }

    pub fn zero_rtt_rejected(&mut self, side: Side) {
        // Revert to initial state for outgoing streams
        for i in 0..self.next_bi {
            self.streams
                .remove(&StreamId::new(side, Directionality::Bi, i))
                .unwrap();
        }
        self.next_bi = 0;
        for i in 0..self.next_uni {
            self.streams
                .remove(&StreamId::new(side, Directionality::Uni, i))
                .unwrap();
        }
        self.next_uni = 0;
    }

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
        self.send().map_or(true, Send::is_closed) && self.recv().map_or(true, Recv::is_closed)
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

/// Errors triggered while writing to a send stream
#[derive(Debug, Error, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum WriteError {
    /// The peer is not able to accept additional data, or the connection is congested.
    #[error(display = "unable to accept further writes")]
    Blocked,
    /// The peer is no longer accepting data on this stream.
    #[error(display = "stopped by peer: error {}", error_code)]
    Stopped {
        /// Application-defined reason for stopping the stream
        error_code: u16,
    },
    /// Unknown stream
    #[error(display = "unknown stream")]
    UnknownStream,
}

#[derive(Debug)]
pub struct Recv {
    state: RecvState,
    recvd: RangeSet,
    /// Whether any unordered reads have been performed, making this stream unusable for ordered
    /// reads
    unordered: bool,
    assembler: Assembler,
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

    pub fn ingest(
        &mut self,
        log: &Logger,
        frame: frame::Stream,
        received: u64,
        max_data: u64,
        receive_window: u64,
    ) -> Result<u64, TransportError> {
        let end = frame.offset + frame.data.len() as u64;
        if let Some(final_offset) = self.final_offset() {
            if end > final_offset || (frame.fin && end != final_offset) {
                debug!(log, "final offset error"; "frame end" => end, "final offset" => final_offset);
                return Err(TransportError::FINAL_OFFSET_ERROR(""));
            }
        }

        let prev_end = self.limit();
        let new_bytes = end.saturating_sub(prev_end);
        let stream_max_data = self.bytes_read + receive_window;
        if end > stream_max_data || received + new_bytes > max_data {
            debug!(log, "flow control error";
                       "stream" => frame.id.0, "recvd" => received, "new bytes" => new_bytes,
                       "max data" => max_data, "end" => end, "stream max data" => stream_max_data);
            return Err(TransportError::FLOW_CONTROL_ERROR(""));
        }

        if frame.fin {
            if let RecvState::Recv { ref mut size } = self.state {
                *size = Some(end);
            }
        }

        self.recvd.insert(frame.offset..end);
        if !frame.data.is_empty() {
            self.assembler.insert(frame.offset, frame.data);
        }

        if let RecvState::Recv { size: Some(size) } = self.state {
            if self.recvd.len() == 1 && self.recvd.iter().next().unwrap() == (0..size) {
                self.state = RecvState::DataRecvd { size };
            }
        }

        Ok(new_bytes)
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

/// Errors triggered when reading from a recv stream
#[derive(Debug, Error, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ReadError {
    /// No more data is currently available on this stream.
    #[error(display = "blocked")]
    Blocked,
    /// The peer abandoned transmitting data on this stream.
    #[error(display = "reset by peer: error {}", error_code)]
    Reset {
        /// Application-defined reason for resetting the stream
        error_code: u16,
    },
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
