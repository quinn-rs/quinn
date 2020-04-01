use std::collections::{hash_map, HashMap};

use bytes::Bytes;
use err_derive::Error;
use tracing::debug;

use crate::{
    assembler::Assembler, frame, range_set::RangeSet, transport_parameters::TransportParameters,
    Dir, Side, StreamId, TransportError, VarInt,
};

pub(crate) struct Streams {
    // Set of streams that are currently open, or could be immediately opened by the peer
    send: HashMap<StreamId, Send>,
    recv: HashMap<StreamId, Recv>,
    next: [u64; 2],
    // Locally initiated
    pub max: [u64; 2],
    // Maximum that can be remotely initiated
    pub max_remote: [u64; 2],
    // Lowest that hasn't actually been opened
    pub next_remote: [u64; 2],
    // Next to report to the application, once opened
    next_reported_remote: [u64; 2],
    /// Number of outbound streams
    ///
    /// This differs from `self.send.len()` in that it does not include streams that the peer is
    /// permitted to open but which have not yet been opened.
    send_streams: usize,
}

impl Streams {
    pub fn new(side: Side, max_remote_uni: u64, max_remote_bi: u64) -> Self {
        let mut this = Self {
            send: HashMap::default(),
            recv: HashMap::default(),
            next: [0, 0],
            max: [0, 0],
            max_remote: [max_remote_bi, max_remote_uni],
            next_remote: [0, 0],
            next_reported_remote: [0, 0],
            send_streams: 0,
        };

        for dir in Dir::iter() {
            for i in 0..this.max_remote[dir as usize] {
                this.insert(None, true, StreamId::new(!side, dir, i));
            }
        }

        this
    }

    pub fn open(&mut self, params: &TransportParameters, side: Side, dir: Dir) -> Option<StreamId> {
        if self.next[dir as usize] >= self.max[dir as usize] {
            return None;
        }

        self.next[dir as usize] += 1;
        let id = StreamId::new(side, dir, self.next[dir as usize] - 1);
        self.insert(Some(params), false, id);
        self.send_streams += 1;
        Some(id)
    }

    pub fn send_streams(&self) -> usize {
        self.send_streams
    }

    pub fn alloc_remote_stream(&mut self, params: &TransportParameters, side: Side, dir: Dir) {
        self.max_remote[dir as usize] += 1;
        let id = StreamId::new(!side, dir, self.max_remote[dir as usize] - 1);
        self.insert(Some(params), true, id);
    }

    pub fn accept(&mut self, side: Side, dir: Dir) -> Option<StreamId> {
        if self.next_remote[dir as usize] == self.next_reported_remote[dir as usize] {
            return None;
        }
        let x = self.next_reported_remote[dir as usize];
        self.next_reported_remote[dir as usize] = x + 1;
        if dir == Dir::Bi {
            self.send_streams += 1;
        }
        Some(StreamId::new(!side, dir, x))
    }

    pub fn zero_rtt_rejected(&mut self, side: Side) {
        // Revert to initial state for outgoing streams
        for dir in Dir::iter() {
            for i in 0..self.next[dir as usize] {
                self.send.remove(&StreamId::new(side, dir, i)).unwrap();
                if let Dir::Bi = dir {
                    self.recv.remove(&StreamId::new(side, dir, i)).unwrap();
                }
            }
            self.next[dir as usize] = 0;
        }
    }

    pub fn read(
        &mut self,
        id: StreamId,
        buf: &mut [u8],
    ) -> Result<Option<(usize, bool)>, ReadError> {
        let rs = self.recv_mut(id).ok_or(ReadError::UnknownStream)?;
        match rs.read(buf) {
            Ok(Some(len)) => Ok(Some((len, rs.receiving_unknown_size()))),
            Ok(None) => {
                self.maybe_cleanup(id);
                Ok(None)
            }
            Err(e @ ReadError::Reset { .. }) => {
                self.maybe_cleanup(id);
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    pub fn read_unordered(
        &mut self,
        id: StreamId,
    ) -> Result<Option<(Bytes, u64, bool)>, ReadError> {
        let rs = self.recv_mut(id).ok_or(ReadError::UnknownStream)?;
        match rs.read_unordered() {
            Ok(Some((buf, offset))) => Ok(Some((buf, offset, rs.receiving_unknown_size()))),
            Ok(None) => {
                self.maybe_cleanup(id);
                Ok(None)
            }
            Err(e @ ReadError::Reset { .. }) => {
                self.maybe_cleanup(id);
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    /// Access a receive stream due to a message from the peer
    ///
    /// Similar to `recv_mut`, but with additional sanity-checks are performed to detect peer
    /// misbehavior.
    pub fn recv_stream(
        &mut self,
        side: Side,
        id: StreamId,
    ) -> Result<Option<&mut Recv>, TransportError> {
        if side == id.initiator() {
            match id.dir() {
                Dir::Uni => {
                    return Err(TransportError::STREAM_STATE_ERROR(
                        "illegal operation on send-only stream",
                    ));
                }
                Dir::Bi if id.index() >= self.next[Dir::Bi as usize] => {
                    return Err(TransportError::STREAM_STATE_ERROR(
                        "operation on unopened stream",
                    ));
                }
                Dir::Bi => {}
            };
        } else {
            let limit = self.max_remote[id.dir() as usize];
            if id.index() >= limit {
                return Err(TransportError::STREAM_LIMIT_ERROR(""));
            }
        }
        Ok(self.recv.get_mut(&id))
    }

    /// Discard state for a stream if it's fully closed.
    ///
    /// Called when one side of a stream transitions to a closed state
    pub fn maybe_cleanup(&mut self, id: StreamId) {
        match self.send.entry(id) {
            hash_map::Entry::Vacant(_) => {}
            hash_map::Entry::Occupied(e) => {
                if e.get().is_closed() {
                    self.send_streams -= 1;
                    e.remove_entry();
                }
            }
        }
        match self.recv.entry(id) {
            hash_map::Entry::Vacant(_) => {}
            hash_map::Entry::Occupied(e) => {
                if e.get().is_closed() {
                    e.remove_entry();
                }
            }
        }
    }

    pub fn recv_mut(&mut self, id: StreamId) -> Option<&mut Recv> {
        self.recv.get_mut(&id)
    }

    pub fn send_mut(&mut self, id: StreamId) -> Option<&mut Send> {
        self.send.get_mut(&id)
    }

    /// Whether a locally initiated stream has never been open
    pub fn is_local_unopened(&self, id: StreamId) -> bool {
        id.index() >= self.next[id.dir() as usize]
    }

    fn insert(&mut self, params: Option<&TransportParameters>, remote: bool, id: StreamId) {
        let bi = id.dir() == Dir::Bi;
        if bi || !remote {
            let max_data = params.map_or(0, |params| match id.dir() {
                Dir::Uni => params.initial_max_stream_data_uni,
                // Remote/local appear reversed here because the transport parameters are named from
                // the perspective of the peer.
                Dir::Bi if remote => params.initial_max_stream_data_bidi_local,
                Dir::Bi => params.initial_max_stream_data_bidi_remote,
            });
            assert!(self.send.insert(id, Send::new(max_data)).is_none());
        }
        if bi || remote {
            assert!(self.recv.insert(id, Recv::new()).is_none());
        }
    }
}

#[derive(Debug)]
pub(crate) struct Send {
    pub offset: u64,
    pub max_data: u64,
    pub state: SendState,
    /// Number of bytes sent but unacked
    pub bytes_in_flight: u64,
}

impl Send {
    pub fn new(max_data: u64) -> Self {
        Self {
            offset: 0,
            max_data,
            state: SendState::Ready,
            bytes_in_flight: 0,
        }
    }

    pub fn write_budget(&mut self) -> Result<u64, WriteError> {
        if let Some(error_code) = self.take_stop_reason() {
            return Err(WriteError::Stopped(error_code));
        }
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

    pub fn finish(&mut self) -> Result<(), FinishError> {
        if self.state == SendState::Ready {
            self.state = SendState::DataSent {
                finish_acked: false,
            };
            Ok(())
        } else if let Some(error_code) = self.take_stop_reason() {
            Err(FinishError::Stopped(error_code))
        } else {
            Err(FinishError::UnknownStream)
        }
    }

    fn take_stop_reason(&mut self) -> Option<VarInt> {
        match self.state {
            SendState::ResetSent {
                ref mut stop_reason,
            }
            | SendState::ResetRecvd {
                ref mut stop_reason,
            } => stop_reason.take(),
            _ => None,
        }
    }
}

/// Errors triggered while writing to a send stream
#[derive(Debug, Error, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum WriteError {
    /// The peer is not able to accept additional data, or the connection is congested.
    ///
    /// If the peer issues additional flow control credit, a [`StreamWritable`] event will be
    /// generated, indicating that retrying the write might succeed.
    ///
    /// [`StreamWritable`]: crate::Event::StreamWritable
    #[error(display = "unable to accept further writes")]
    Blocked,
    /// The peer is no longer accepting data on this stream, and it has been implicitly reset. The
    /// stream cannot be finished or further written to.
    ///
    /// Carries an application-defined error code.
    ///
    /// [`StreamFinished`]: crate::Event::StreamFinished
    #[error(display = "stopped by peer: code {}", 0)]
    Stopped(VarInt),
    /// Unknown stream
    ///
    /// Occurs when attempting to access a stream after finishing it or observing that it has been
    /// stopped.
    #[error(display = "unknown stream")]
    UnknownStream,
}

#[derive(Debug)]
pub(crate) struct Recv {
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
        frame: frame::Stream,
        received: u64,
        max_data: u64,
        receive_window: u64,
    ) -> Result<u64, TransportError> {
        let end = frame.offset + frame.data.len() as u64;
        if end >= 2u64.pow(62) {
            return Err(TransportError::FLOW_CONTROL_ERROR(
                "maximum stream offset too large",
            ));
        }

        if let Some(final_offset) = self.final_offset() {
            if end > final_offset || (frame.fin && end != final_offset) {
                debug!(end, final_offset, "final size error");
                return Err(TransportError::FINAL_SIZE_ERROR(""));
            }
        }

        let prev_end = self.limit();
        let new_bytes = end.saturating_sub(prev_end);
        let stream_max_data = self.bytes_read + receive_window;
        if end > stream_max_data || received + new_bytes > max_data {
            debug!(stream = %frame.id, received, new_bytes, max_data, end, stream_max_data, "flow control error");
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

    pub fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, ReadError> {
        assert!(
            !self.unordered,
            "cannot perform ordered reads following unordered reads on a stream"
        );

        let read = self.assembler.read(buf);
        if read > 0 {
            self.bytes_read += read as u64;
            Ok(Some(read))
        } else {
            self.read_blocked().map(|()| None)
        }
    }

    pub fn read_unordered(&mut self) -> Result<Option<(Bytes, u64)>, ReadError> {
        self.unordered = true;

        // Return data we already have buffered, regardless of state
        if let Some((offset, bytes)) = self.assembler.pop() {
            self.bytes_read += bytes.len() as u64;
            Ok(Some((bytes, offset)))
        } else {
            self.read_blocked().map(|()| None)
        }
    }

    fn read_blocked(&mut self) -> Result<(), ReadError> {
        match self.state {
            RecvState::ResetRecvd { error_code, .. } => {
                self.state = RecvState::Closed;
                Err(ReadError::Reset(error_code))
            }
            RecvState::Closed => panic!("tried to read from a closed stream"),
            RecvState::Recv { .. } => Err(ReadError::Blocked),
            RecvState::DataRecvd { .. } => {
                self.state = RecvState::Closed;
                Ok(())
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

    pub fn reset(&mut self, error_code: VarInt, final_offset: u64) {
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
    ///
    /// If more data on this stream is received from the peer, an `Event::StreamReadable` will be
    /// generated for this stream, indicating that retrying the read might succeed.
    #[error(display = "blocked")]
    Blocked,
    /// The peer abandoned transmitting data on this stream.
    ///
    /// Carries an application-defined error code.
    #[error(display = "reset by peer: code {}", 0)]
    Reset(VarInt),
    /// Unknown stream
    ///
    /// Occurs when attempting to access a stream after observing that it has been finished or
    /// reset.
    #[error(display = "unknown stream")]
    UnknownStream,
}

/// `stop_reason` below should be set iff the stream was stopped and application has not yet been
/// notified, as we never discard resources for a stream that has it set.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum SendState {
    /// Sending new data
    Ready,
    /// Stream was finished; now sending retransmits only
    DataSent { finish_acked: bool },
    /// Sent RESET
    ResetSent { stop_reason: Option<VarInt> },
    /// All sent data acknowledged
    DataRecvd,
    /// Reset acknowledged
    ResetRecvd { stop_reason: Option<VarInt> },
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
pub(crate) enum RecvState {
    Recv { size: Option<u64> },
    DataRecvd { size: u64 },
    ResetRecvd { size: u64, error_code: VarInt },
    Closed,
}

/// Reasons why attempting to finish a stream might fail
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FinishError {
    /// The peer is no longer accepting data on this stream. No
    /// [`StreamFinished`](crate::Event::StreamFinished) event will be emitted for this stream.
    ///
    /// Carries an application-defined error code.
    #[error(display = "stopped by peer: code {}", 0)]
    Stopped(VarInt),
    /// The stream has not yet been created or was already finished or stopped.
    #[error(display = "unknown stream")]
    UnknownStream,
}

/// Unknown stream ID
#[derive(Debug)]
pub struct UnknownStream {
    pub(crate) _private: (),
}
