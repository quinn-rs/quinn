use std::{
    cell::RefCell,
    collections::{hash_map, BinaryHeap, VecDeque},
};

use bytes::Bytes;
use thiserror::Error;
use tracing::trace;

use super::spaces::{Retransmits, ThinRetransmits};
use crate::{frame, Dir, StreamId, VarInt};

mod recv;
use recv::Recv;
pub use recv::{Chunks, ReadError, ReadableError};

mod send;
pub use send::{ByteSlice, BytesArray, BytesSource, FinishError, WriteError, Written};
use send::{Send, SendState};

mod state;
pub use state::StreamsState;

/// Access to streams
pub struct Streams<'a> {
    pub(super) state: &'a mut StreamsState,
    pub(super) conn_state: &'a super::State,
}

impl<'a> Streams<'a> {
    #[cfg(fuzzing)]
    pub fn new(state: &'a mut StreamsState, conn_state: &'a super::State) -> Self {
        Self { state, conn_state }
    }

    /// Open a single stream if possible
    ///
    /// Returns `None` if the streams in the given direction are currently exhausted.
    pub fn open(&mut self, dir: Dir) -> Option<StreamId> {
        if self.conn_state.is_closed() {
            return None;
        }

        // TODO: Queue STREAM_ID_BLOCKED if this fails
        if self.state.next[dir as usize] >= self.state.max[dir as usize] {
            return None;
        }

        self.state.next[dir as usize] += 1;
        let id = StreamId::new(self.state.side, dir, self.state.next[dir as usize] - 1);
        self.state.insert(false, id);
        self.state.send_streams += 1;
        Some(id)
    }

    /// Accept a remotely initiated stream of a certain directionality, if possible
    ///
    /// Returns `None` if there are no new incoming streams for this connection.
    pub fn accept(&mut self, dir: Dir) -> Option<StreamId> {
        if self.state.next_remote[dir as usize] == self.state.next_reported_remote[dir as usize] {
            return None;
        }

        let x = self.state.next_reported_remote[dir as usize];
        self.state.next_reported_remote[dir as usize] = x + 1;
        if dir == Dir::Bi {
            self.state.send_streams += 1;
        }

        Some(StreamId::new(!self.state.side, dir, x))
    }

    #[cfg(fuzzing)]
    pub fn state(&mut self) -> &mut StreamsState {
        self.state
    }

    /// The number of streams that may have unacknowledged data.
    pub fn send_streams(&self) -> usize {
        self.state.send_streams
    }
}

/// Access to streams
pub struct RecvStream<'a> {
    pub(super) id: StreamId,
    pub(super) state: &'a mut StreamsState,
    pub(super) pending: &'a mut Retransmits,
}

impl<'a> RecvStream<'a> {
    /// Read from the given recv stream
    ///
    /// `max_length` limits the maximum size of the returned `Bytes` value; passing `usize::MAX`
    /// will yield the best performance. `ordered` will make sure the returned chunk's offset will
    /// have an offset exactly equal to the previously returned offset plus the previously returned
    /// bytes' length.
    ///
    /// Yields `Ok(None)` if the stream was finished. Otherwise, yields a segment of data and its
    /// offset in the stream. If `ordered` is `false`, segments may be received in any order, and
    /// the `Chunk`'s `offset` field can be used to determine ordering in the caller.
    ///
    /// While most applications will prefer to consume stream data in order, unordered reads can
    /// improve performance when packet loss occurs and data cannot be retransmitted before the flow
    /// control window is filled. On any given stream, you can switch from ordered to unordered
    /// reads, but ordered reads on streams that have seen previous unordered reads will return
    /// `ReadError::IllegalOrderedRead`.
    pub fn read(&mut self, ordered: bool) -> Result<Chunks, ReadableError> {
        Chunks::new(self.id, ordered, self.state, self.pending)
    }

    /// Stop accepting data on the given receive stream
    ///
    /// Discards unread data and notifies the peer to stop transmitting. Once stopped, further
    /// attempts to operate on a stream will yield `UnknownStream` errors.
    pub fn stop(&mut self, error_code: VarInt) -> Result<(), UnknownStream> {
        let mut entry = match self.state.recv.entry(self.id) {
            hash_map::Entry::Occupied(s) => s,
            hash_map::Entry::Vacant(_) => return Err(UnknownStream { _private: () }),
        };
        let stream = entry.get_mut();

        let (read_credits, stop_sending) = stream.stop()?;
        if stop_sending.should_transmit() {
            self.pending.stop_sending.push(frame::StopSending {
                id: self.id,
                error_code,
            });
        }

        // We need to keep stopped streams around until they're finished or reset so we can update
        // connection-level flow control to account for discarded data. Otherwise, we can discard
        // state immediately.
        if !stream.receiving_unknown_size() {
            entry.remove();
            self.state.stream_freed(self.id, StreamHalf::Recv);
        }

        if self.state.add_read_credits(read_credits).should_transmit() {
            self.pending.max_data = true;
        }

        Ok(())
    }
}

/// Access to streams
pub struct SendStream<'a> {
    pub(super) id: StreamId,
    pub(super) state: &'a mut StreamsState,
    pub(super) pending: &'a mut Retransmits,
    pub(super) conn_state: &'a super::State,
}

impl<'a> SendStream<'a> {
    #[cfg(fuzzing)]
    pub fn new(
        id: StreamId,
        state: &'a mut StreamsState,
        pending: &'a mut Retransmits,
        conn_state: &'a super::State,
    ) -> Self {
        Self {
            id,
            state,
            pending,
            conn_state,
        }
    }

    /// Send data on the given stream
    ///
    /// Returns the number of bytes successfully written.
    pub fn write(&mut self, data: &[u8]) -> Result<usize, WriteError> {
        Ok(self.write_source(&mut ByteSlice::from_slice(data))?.bytes)
    }

    /// Send data on the given stream
    ///
    /// Returns the number of bytes and chunks successfully written.
    /// Note that this method might also write a partial chunk. In this case
    /// [`Written::chunks`] will not count this chunk as fully written. However
    /// the chunk will be advanced and contain only non-written data after the call.
    pub fn write_chunks(&mut self, data: &mut [Bytes]) -> Result<Written, WriteError> {
        self.write_source(&mut BytesArray::from_chunks(data))
    }

    fn write_source<B: BytesSource>(&mut self, source: &mut B) -> Result<Written, WriteError> {
        if self.conn_state.is_closed() {
            trace!(%self.id, "write blocked; connection draining");
            return Err(WriteError::Blocked);
        }

        let limit = self.state.write_limit();
        let stream = self
            .state
            .send
            .get_mut(&self.id)
            .ok_or(WriteError::UnknownStream)?;
        if limit == 0 {
            trace!(
                stream = %self.id, max_data = self.state.max_data, data_sent = self.state.data_sent,
                "write blocked by connection-level flow control or send window"
            );
            if !stream.connection_blocked {
                stream.connection_blocked = true;
                self.state.connection_blocked.push(self.id);
            }
            return Err(WriteError::Blocked);
        }

        let was_pending = stream.is_pending();
        let written = stream.write(source, limit)?;
        self.state.data_sent += written.bytes as u64;
        self.state.unacked_data += written.bytes as u64;
        trace!(stream = %self.id, "wrote {} bytes", written.bytes);
        if !was_pending {
            push_pending(&mut self.state.pending, self.id, stream.priority);
        }
        Ok(written)
    }

    /// Check if this stream was stopped, get the reason if it was
    pub fn stopped(&mut self) -> Result<Option<VarInt>, UnknownStream> {
        match self.state.send.get(&self.id) {
            Some(s) => Ok(s.stop_reason),
            None => Err(UnknownStream { _private: () }),
        }
    }

    /// Finish a send stream, signalling that no more data will be sent.
    ///
    /// If this fails, no [`StreamEvent::Finished`] will be generated.
    ///
    /// [`StreamEvent::Finished`]: crate::StreamEvent::Finished
    pub fn finish(&mut self) -> Result<(), FinishError> {
        let stream = self
            .state
            .send
            .get_mut(&self.id)
            .ok_or(FinishError::UnknownStream)?;

        let was_pending = stream.is_pending();
        stream.finish()?;
        if !was_pending {
            push_pending(&mut self.state.pending, self.id, stream.priority);
        }

        Ok(())
    }

    /// Abandon transmitting data on a stream
    ///
    /// # Panics
    /// - when applied to a receive stream
    pub fn reset(&mut self, error_code: VarInt) -> Result<(), UnknownStream> {
        let stream = self
            .state
            .send
            .get_mut(&self.id)
            .ok_or(UnknownStream { _private: () })?;

        if matches!(stream.state, SendState::ResetSent) {
            // Redundant reset call
            return Err(UnknownStream { _private: () });
        }

        // Restore the portion of the send window consumed by the data that we aren't about to
        // send. We leave flow control alone because the peer's responsible for issuing additional
        // credit based on the final offset communicated in the RESET_STREAM frame we send.
        self.state.unacked_data -= stream.pending.unacked();
        stream.reset();
        self.pending.reset_stream.push((self.id, error_code));

        // Don't reopen an already-closed stream we haven't forgotten yet
        Ok(())
    }

    /// Set the priority of a stream
    ///
    /// # Panics
    /// - when applied to a receive stream
    pub fn set_priority(&mut self, priority: i32) -> Result<(), UnknownStream> {
        let stream = self
            .state
            .send
            .get_mut(&self.id)
            .ok_or(UnknownStream { _private: () })?;

        stream.priority = priority;
        Ok(())
    }

    /// Get the priority of a stream
    ///
    /// # Panics
    /// - when applied to a receive stream
    pub fn priority(&self) -> Result<i32, UnknownStream> {
        let stream = self
            .state
            .send
            .get(&self.id)
            .ok_or(UnknownStream { _private: () })?;

        Ok(stream.priority)
    }
}

fn push_pending(pending: &mut BinaryHeap<PendingLevel>, id: StreamId, priority: i32) {
    for level in pending.iter() {
        if priority == level.priority {
            level.queue.borrow_mut().push_back(id);
            return;
        }
    }

    // If there is only a single level and it's empty, repurpose it for the
    // required priority
    if pending.len() == 1 {
        if let Some(mut first) = pending.peek_mut() {
            let mut queue = first.queue.borrow_mut();
            if queue.is_empty() {
                queue.push_back(id);
                drop(queue);
                first.priority = priority;
                return;
            }
        }
    }

    let mut queue = VecDeque::new();
    queue.push_back(id);
    pending.push(PendingLevel {
        queue: RefCell::new(queue),
        priority,
    });
}

struct PendingLevel {
    // RefCell is needed because BinaryHeap doesn't have an iter_mut()
    queue: RefCell<VecDeque<StreamId>>,
    priority: i32,
}

impl PartialEq for PendingLevel {
    fn eq(&self, other: &Self) -> bool {
        self.priority.eq(&other.priority)
    }
}

impl PartialOrd for PendingLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for PendingLevel {}

impl Ord for PendingLevel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority.cmp(&other.priority)
    }
}

/// Application events about streams
#[derive(Debug, PartialEq, Eq)]
pub enum StreamEvent {
    /// One or more new streams has been opened and might be readable
    Opened {
        /// Directionality for which streams have been opened
        dir: Dir,
    },
    /// A currently open stream likely has data or errors waiting to be read
    Readable {
        /// Which stream is now readable
        id: StreamId,
    },
    /// A formerly write-blocked stream might be ready for a write or have been stopped
    ///
    /// Only generated for streams that are currently open.
    Writable {
        /// Which stream is now writable
        id: StreamId,
    },
    /// A finished stream has been fully acknowledged or stopped
    Finished {
        /// Which stream has been finished
        id: StreamId,
    },
    /// The peer asked us to stop sending on an outgoing stream
    Stopped {
        /// Which stream has been stopped
        id: StreamId,
        /// Error code supplied by the peer
        error_code: VarInt,
    },
    /// At least one new stream of a certain directionality may be opened
    Available {
        /// Directionality for which streams are newly available
        dir: Dir,
    },
}

/// Indicates whether a frame needs to be transmitted
///
/// This type wraps around bool and uses the `#[must_use]` attribute in order
/// to prevent accidental loss of the frame transmission requirement.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
#[must_use = "A frame might need to be enqueued"]
pub struct ShouldTransmit(bool);

impl ShouldTransmit {
    /// Returns whether a frame should be transmitted
    pub fn should_transmit(self) -> bool {
        self.0
    }
}

/// Error indicating that a stream has not been opened or has already been finished or reset
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("unknown stream")]
pub struct UnknownStream {
    _private: (),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum StreamHalf {
    Send,
    Recv,
}
