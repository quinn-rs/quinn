use std::{
    collections::{BinaryHeap, hash_map},
    io,
};

use bytes::Bytes;
use thiserror::Error;
use tracing::{trace, warn};

use super::spaces::{Retransmits, ThinRetransmits};
use crate::{
    Dir, StreamId, VarInt,
    connection::streams::state::{get_or_insert_recv, get_or_insert_send},
    frame,
};

mod recv;
use recv::Recv;
pub use recv::{Chunks, ReadError, ReadableError};

mod send;
pub(crate) use send::{ByteSlice, BytesArray};
use send::{BytesSource, Send, SendState};
pub use send::{FinishError, WriteError, Written};

mod state;
#[allow(unreachable_pub)] // fuzzing only
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

    /// The number of remotely initiated open streams of a certain directionality.
    pub fn remote_open_streams(&self, dir: Dir) -> u64 {
        self.state.next_remote[dir as usize]
            - (self.state.max_remote[dir as usize]
                - self.state.allocated_remote_count[dir as usize])
    }
}

/// Access to streams
pub struct RecvStream<'a> {
    pub(super) id: StreamId,
    pub(super) state: &'a mut StreamsState,
    pub(super) pending: &'a mut Retransmits,
}

impl RecvStream<'_> {
    /// Read from the given recv stream
    ///
    /// `max_length` limits the maximum size of the returned `Bytes` value.
    /// `ordered` ensures the returned chunk's offset is sequential.
    ///
    /// Yields `Ok(None)` if the stream was finished. Otherwise, yields a segment of data and its
    /// offset in the stream.
    ///
    /// Unordered reads can improve performance when packet loss occurs, but ordered reads
    /// on streams that have seen previous unordered reads will return `ReadError::IllegalOrderedRead`.
    pub fn read(&mut self, ordered: bool) -> Result<Chunks, ReadableError> {
        if self.state.conn_closed() {
            return Err(ReadableError::ConnectionClosed);
        }
        
        Chunks::new(self.id, ordered, self.state, self.pending)
    }

    /// Stop accepting data on the given receive stream
    ///
    /// Discards unread data and notifies the peer to stop transmitting.
    pub fn stop(&mut self, error_code: VarInt) -> Result<(), ClosedStream> {
        if self.state.conn_closed() {
            return Err(ClosedStream { _private: () });
        }
        
        let mut entry = match self.state.recv.entry(self.id) {
            hash_map::Entry::Occupied(s) => s,
            hash_map::Entry::Vacant(_) => return Err(ClosedStream { _private: () }),
        };
        let stream = get_or_insert_recv(self.state.stream_receive_window)(entry.get_mut());

        let (read_credits, stop_sending) = stream.stop()?;
        if stop_sending.should_transmit() {
            self.pending.stop_sending.push(frame::StopSending {
                id: self.id,
                error_code,
            });
        }

        // Clean up stream state if possible
        if !stream.final_offset_unknown() {
            let recv = entry.remove().expect("must have recv when stopping");
            self.state.stream_recv_freed(self.id, recv);
        }

        // Update flow control if needed
        if self.state.add_read_credits(read_credits).should_transmit() {
            self.pending.max_data = true;
        }

        Ok(())
    }

    /// Check whether this stream has been reset by the peer
    ///
    /// Returns the reset error code if the stream was reset.
    pub fn received_reset(&mut self) -> Result<Option<VarInt>, ClosedStream> {
        if self.state.conn_closed() {
            return Err(ClosedStream { _private: () });
        }
        
        let hash_map::Entry::Occupied(entry) = self.state.recv.entry(self.id) else {
            return Err(ClosedStream { _private: () });
        };
        
        let Some(s) = entry.get().as_ref().and_then(|s| s.as_open_recv()) else {
            return Ok(None);
        };
        
        if s.stopped {
            return Err(ClosedStream { _private: () });
        }
        
        let Some(code) = s.reset_code() else {
            return Ok(None);
        };

        // Clean up state after application observes the reset
        let (_, recv) = entry.remove_entry();
        self.state
            .stream_recv_freed(self.id, recv.expect("must have recv on reset"));
        self.state.queue_max_stream_id(self.pending);

        Ok(Some(code))
    }
}

/// Access to streams
pub struct SendStream<'a> {
    pub(super) id: StreamId,
    pub(super) state: &'a mut StreamsState,
    pub(super) pending: &'a mut Retransmits,
    pub(super) conn_state: &'a super::State,
}

#[allow(clippy::needless_lifetimes)] // Needed for cfg(fuzzing)
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

        let max_send_data = self.state.max_send_data(self.id);

        let stream = self
            .state
            .send
            .get_mut(&self.id)
            .map(get_or_insert_send(max_send_data))
            .ok_or(WriteError::ClosedStream)?;

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
            self.state.pending.push_pending(self.id, stream.priority);
        }
        Ok(written)
    }

    /// Check if this stream was stopped, get the reason if it was
    pub fn stopped(&self) -> Result<Option<VarInt>, ClosedStream> {
        match self.state.send.get(&self.id).as_ref() {
            Some(Some(s)) => Ok(s.stop_reason),
            Some(None) => Ok(None),
            None => Err(ClosedStream { _private: () }),
        }
    }

    /// Finish a send stream, signalling that no more data will be sent.
    ///
    /// If this fails, no [`StreamEvent::Finished`] will be generated.
    ///
    /// [`StreamEvent::Finished`]: crate::StreamEvent::Finished
    pub fn finish(&mut self) -> Result<(), FinishError> {
        let max_send_data = self.state.max_send_data(self.id);
        let stream = self
            .state
            .send
            .get_mut(&self.id)
            .map(get_or_insert_send(max_send_data))
            .ok_or(FinishError::ClosedStream)?;

        let was_pending = stream.is_pending();
        stream.finish()?;
        if !was_pending {
            self.state.pending.push_pending(self.id, stream.priority);
        }

        Ok(())
    }

    /// Abandon transmitting data on a stream
    ///
    /// # Panics
    /// - when applied to a receive stream
    pub fn reset(&mut self, error_code: VarInt) -> Result<(), ClosedStream> {
        let max_send_data = self.state.max_send_data(self.id);
        let stream = self
            .state
            .send
            .get_mut(&self.id)
            .map(get_or_insert_send(max_send_data))
            .ok_or(ClosedStream { _private: () })?;

        if matches!(stream.state, SendState::ResetSent) {
            // Redundant reset call
            return Err(ClosedStream { _private: () });
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
    pub fn set_priority(&mut self, priority: i32) -> Result<(), ClosedStream> {
        let max_send_data = self.state.max_send_data(self.id);
        let stream = self
            .state
            .send
            .get_mut(&self.id)
            .map(get_or_insert_send(max_send_data))
            .ok_or(ClosedStream { _private: () })?;

        stream.priority = priority;
        Ok(())
    }

    /// Get the priority of a stream
    ///
    /// # Panics
    /// - when applied to a receive stream
    pub fn priority(&self) -> Result<i32, ClosedStream> {
        let stream = self
            .state
            .send
            .get(&self.id)
            .ok_or(ClosedStream { _private: () })?;

        Ok(stream.as_ref().map(|s| s.priority).unwrap_or_default())
    }
}

/// A queue of streams with pending outgoing data, sorted by priority
struct PendingStreamsQueue {
    streams: BinaryHeap<PendingStream>,
    /// The next stream to write out. This is `Some` when writing a stream is
    /// interrupted while the stream still has some pending data.
    next: Option<PendingStream>,
    /// A monotonically decreasing counter for round-robin scheduling of streams with the same priority
    recency: u64,
}

impl PendingStreamsQueue {
    fn new() -> Self {
        Self {
            streams: BinaryHeap::new(),
            next: None,
            recency: u64::MAX,
        }
    }

    /// Reinsert a stream that was pending and still contains unsent data.
    fn reinsert_pending(&mut self, id: StreamId, priority: i32) {
        if self.next.is_some() {
            warn!("Attempting to reinsert a pending stream when next is already set");
            return;
        }

        self.next = Some(PendingStream {
            priority,
            recency: self.recency,
            id,
        });
    }

    /// Push a pending stream ID with the given priority
    fn push_pending(&mut self, id: StreamId, priority: i32) {
        // Decrement recency to ensure round-robin scheduling for streams of the same priority
        self.recency = self.recency.saturating_sub(1);
        self.streams.push(PendingStream {
            priority,
            recency: self.recency,
            id,
        });
    }

    /// Pop the highest priority stream
    fn pop(&mut self) -> Option<PendingStream> {
        self.next.take().or_else(|| self.streams.pop())
    }

    /// Clear all pending streams
    fn clear(&mut self) {
        self.next = None;
        self.streams.clear();
    }

    /// Iterate over all pending streams
    fn iter(&self) -> impl Iterator<Item = &PendingStream> {
        self.next.iter().chain(self.streams.iter())
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.streams.len() + self.next.is_some() as usize
    }
}

/// The [`StreamId`] of a stream with pending data queued, ordered by its priority and recency
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PendingStream {
    /// The priority of the stream
    // Note that this field should be kept above the `recency` field, in order for the `Ord` derive to be correct
    // (See https://doc.rust-lang.org/stable/std/cmp/trait.Ord.html#derivable)
    priority: i32,
    /// A tie-breaker for streams of the same priority, used to improve fairness by implementing round-robin scheduling:
    /// Larger values are prioritized, so it is initialised to `u64::MAX`, and when a stream writes data, we know
    /// that it currently has the highest recency value, so it is deprioritized by setting its recency to 1 less than the
    /// previous lowest recency value, such that all other streams of this priority will get processed once before we get back
    /// round to this one
    recency: u64,
    /// The ID of the stream
    // The way this type is used ensures that every instance has a unique `recency` value, so this field should be kept below
    // the `priority` and `recency` fields, so that it does not interfere with the behaviour of the `Ord` derive
    id: StreamId,
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
#[derive(Debug, Default, Error, Clone, PartialEq, Eq)]
#[error("closed stream")]
pub struct ClosedStream {
    _private: (),
}

impl From<ClosedStream> for io::Error {
    fn from(x: ClosedStream) -> Self {
        Self::new(io::ErrorKind::NotConnected, x)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum StreamHalf {
    Send,
    Recv,
}
