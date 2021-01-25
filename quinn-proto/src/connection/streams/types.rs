use bytes::Bytes;
use thiserror::Error;
use tracing::debug;

use crate::connection::{
    assembler::{Assembler, IllegalOrderedRead},
    send_buffer::SendBuffer,
};
use crate::{
    frame::{self, ShouldTransmit},
    TransportError, VarInt,
};

#[derive(Debug)]
pub(super) struct Send {
    pub(super) max_data: u64,
    pub(super) state: SendState,
    pub(super) pending: SendBuffer,
    /// Whether a frame containing a FIN bit must be transmitted, even if we don't have any new data
    pub(super) fin_pending: bool,
    /// Whether this stream is in the `connection_blocked` list of `Streams`
    pub(super) connection_blocked: bool,
    /// The reason the peer wants us to stop, if `STOP_SENDING` was received
    pub(super) stop_reason: Option<VarInt>,
}

impl Send {
    pub(super) fn new(max_data: VarInt) -> Self {
        Self {
            max_data: max_data.into(),
            state: SendState::Ready,
            pending: SendBuffer::new(),
            fin_pending: false,
            connection_blocked: false,
            stop_reason: None,
        }
    }

    /// Whether the stream has been reset
    pub(super) fn is_reset(&self) -> bool {
        matches!(self.state, SendState::ResetSent { .. } | SendState::ResetRecvd { .. })
    }

    pub(super) fn finish(&mut self) -> Result<(), FinishError> {
        if let Some(error_code) = self.stop_reason {
            Err(FinishError::Stopped(error_code))
        } else if self.state == SendState::Ready {
            self.state = SendState::DataSent {
                finish_acked: false,
            };
            self.fin_pending = true;
            Ok(())
        } else {
            Err(FinishError::UnknownStream)
        }
    }

    pub(super) fn write(&mut self, data: &[u8]) -> Result<usize, WriteError> {
        if !self.is_writable() {
            return Err(WriteError::UnknownStream);
        }
        if let Some(error_code) = self.stop_reason {
            return Err(WriteError::Stopped(error_code));
        }
        let budget = self.max_data - self.pending.offset();
        if budget == 0 {
            return Err(WriteError::Blocked);
        }
        let len = (data.len() as u64).min(budget) as usize;
        self.pending.write(&data[0..len]);
        Ok(len)
    }

    /// Update stream state due to a reset sent by the local application
    pub(super) fn reset(&mut self) {
        use SendState::*;
        if let DataSent { .. } | Ready = self.state {
            self.state = ResetSent;
        }
    }

    /// Handle STOP_SENDING
    pub(super) fn stop(&mut self, error_code: VarInt) {
        self.stop_reason = Some(error_code);
    }

    pub(super) fn ack(&mut self, frame: frame::StreamMeta) {
        self.pending.ack(frame.offsets);
        if let SendState::DataSent {
            ref mut finish_acked,
        } = self.state
        {
            *finish_acked |= frame.fin;
            if *finish_acked && self.pending.is_fully_acked() {
                self.state = SendState::DataRecvd;
            }
        }
    }

    /// Handle increase to stream-level flow control limit
    ///
    /// Returns whether the stream was unblocked
    pub(super) fn increase_max_data(&mut self, offset: u64) -> bool {
        if offset <= self.max_data || self.state != SendState::Ready {
            return false;
        }
        let was_blocked = self.pending.offset() == self.max_data;
        self.max_data = offset;
        was_blocked
    }

    pub(super) fn offset(&self) -> u64 {
        self.pending.offset()
    }

    pub(super) fn is_pending(&self) -> bool {
        self.pending.has_unsent_data() || self.fin_pending
    }

    pub(super) fn is_writable(&self) -> bool {
        matches!(self.state, SendState::Ready)
    }
}

/// Result of a successful `Streams::stop` call
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[must_use = "A frame might need to be enqueued"]
pub struct StopResult {
    pub stop_sending: ShouldTransmit,
    pub max_data: ShouldTransmit,
}

/// Errors triggered while writing to a send stream
#[derive(Debug, Error, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum WriteError {
    /// The peer is not able to accept additional data, or the connection is congested.
    ///
    /// If the peer issues additional flow control credit, a [`StreamEvent::Writable`] event will
    /// be generated, indicating that retrying the write might succeed.
    ///
    /// [`StreamEvent::Writable`]: crate::StreamEvent::Writable
    #[error("unable to accept further writes")]
    Blocked,
    /// The peer is no longer accepting data on this stream, and it has been implicitly reset. The
    /// stream cannot be finished or further written to.
    ///
    /// Carries an application-defined error code.
    ///
    /// [`StreamEvent::Finished`]: crate::StreamEvent::Finished
    #[error("stopped by peer: code {}", 0)]
    Stopped(VarInt),
    /// The stream has not been opened or has already been finished or reset
    #[error("unknown stream")]
    UnknownStream,
}

#[derive(Debug, Default)]
pub(super) struct Recv {
    state: RecvState,
    pub(super) assembler: Assembler,
    sent_max_stream_data: u64,
}

impl Recv {
    pub(super) fn new(initial_max_data: u64) -> Self {
        Self {
            state: RecvState::default(),
            assembler: Assembler::new(),
            sent_max_stream_data: initial_max_data,
        }
    }

    pub(super) fn ingest(
        &mut self,
        frame: frame::Stream,
        received: u64,
        max_data: u64,
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

        let new_bytes = self.credit_consumed_by(end, received, max_data)?;

        if frame.fin {
            if self.assembler.is_stopped() {
                // Stopped streams don't need to wait for the actual data, they just need to know
                // how much there was.
                self.state = RecvState::Closed;
            } else if let RecvState::Recv { ref mut size } = self.state {
                *size = Some(end);
            }
        }

        self.assembler.insert(frame.offset, frame.data);

        Ok(new_bytes)
    }

    pub(super) fn read(&mut self, buf: &mut [u8]) -> StreamReadResult<usize> {
        if self.assembler.is_stopped() {
            return Err(ReadError::UnknownStream);
        }

        let mut read = 0;
        while let Some(chunk) = self.assembler.read(buf.len() - read)? {
            (&mut buf[read..read + chunk.len()]).copy_from_slice(&chunk);
            read += chunk.len();
            if read == buf.len() {
                break;
            }
        }

        if read > 0 {
            Ok(Some(read))
        } else {
            self.read_blocked().map(|()| None)
        }
    }

    pub(super) fn read_unordered(&mut self) -> StreamReadResult<(Bytes, u64)> {
        if self.assembler.is_stopped() {
            return Err(ReadError::UnknownStream);
        }
        // Return data we already have buffered, regardless of state
        if let Some((offset, bytes)) = self.assembler.read_unordered() {
            Ok(Some((bytes, offset)))
        } else {
            self.read_blocked().map(|()| None)
        }
    }

    pub(super) fn read_chunk(&mut self, max_length: usize) -> StreamReadResult<Bytes> {
        match self.assembler.read(max_length)? {
            Some(bytes) => Ok(Some(bytes)),
            None => self.read_blocked().map(|()| None),
        }
    }

    pub(super) fn read_chunks(
        &mut self,
        chunks: &mut [Bytes],
    ) -> Result<Option<ReadChunks>, ReadError> {
        let mut out = ReadChunks { bufs: 0, read: 0 };
        if chunks.is_empty() {
            return Ok(Some(out));
        }

        while let Some(bytes) = self.assembler.read(usize::MAX)? {
            chunks[out.bufs] = bytes;
            out.read += chunks[out.bufs].len();
            out.bufs += 1;

            if out.bufs >= chunks.len() {
                return Ok(Some(out));
            }
        }

        if out.bufs > 0 {
            return Ok(Some(out));
        }

        self.read_blocked().map(|()| None)
    }

    fn read_blocked(&mut self) -> Result<(), ReadError> {
        match self.state {
            RecvState::ResetRecvd { error_code, .. } => {
                self.state = RecvState::Closed;
                Err(ReadError::Reset(error_code))
            }
            RecvState::Closed => Err(ReadError::UnknownStream),
            RecvState::Recv { size } => {
                if size == Some(self.assembler.end()) && self.assembler.is_fully_read() {
                    self.state = RecvState::Closed;
                    Ok(())
                } else {
                    Err(ReadError::Blocked)
                }
            }
        }
    }

    /// Returns the window that should be advertised in a `MAX_STREAM_DATA` frame
    ///
    /// The method returns a tuple which consists of the window that should be
    /// announced, as well as a boolean parameter which indicates if a new
    /// transmission of the value is recommended. If the boolean value is
    /// `false` the new window should only be transmitted if a previous transmission
    /// had failed.
    pub(super) fn max_stream_data(&mut self, stream_receive_window: u64) -> (u64, ShouldTransmit) {
        let max_stream_data = self.assembler.bytes_read() + stream_receive_window;

        // Only announce a window update if it's significant enough
        // to make it worthwhile sending a MAX_STREAM_DATA frame.
        // We use here a fraction of the configured stream receive window to make
        // the decision, and accomodate for streams using bigger windows requring
        // less updates. A fixed size would also work - but it would need to be
        // smaller than `stream_receive_window` in order to make sure the stream
        // does not get stuck.
        let diff = max_stream_data - self.sent_max_stream_data;
        let transmit = self.receiving_unknown_size() && diff >= (stream_receive_window / 8);
        (max_stream_data, ShouldTransmit::new(transmit))
    }

    /// Records that a `MAX_STREAM_DATA` announcing a certain window was sent
    ///
    /// This will suppress enqueuing further `MAX_STREAM_DATA` frames unless
    /// either the previous transmission was not acknowledged or the window
    /// further increased.
    pub fn record_sent_max_stream_data(&mut self, sent_value: u64) {
        if sent_value > self.sent_max_stream_data {
            self.sent_max_stream_data = sent_value;
        }
    }

    fn receiving_unknown_size(&self) -> bool {
        matches!(self.state, RecvState::Recv { size: None })
    }

    /// No more data expected from peer
    pub(super) fn is_finished(&self) -> bool {
        !matches!(self.state, RecvState::Recv { .. })
    }

    /// All data read by application
    pub(super) fn is_closed(&self) -> bool {
        self.state == self::RecvState::Closed
    }

    fn final_offset(&self) -> Option<u64> {
        match self.state {
            RecvState::Recv { size } => size,
            RecvState::ResetRecvd { size, .. } => Some(size),
            _ => None,
        }
    }

    /// Returns `false` iff the reset was redundant
    pub(super) fn reset(
        &mut self,
        error_code: VarInt,
        final_offset: VarInt,
        received: u64,
        max_data: u64,
    ) -> Result<bool, TransportError> {
        // Validate final_offset
        if let Some(offset) = self.final_offset() {
            if offset != final_offset.into() {
                return Err(TransportError::FINAL_SIZE_ERROR("inconsistent value"));
            }
        } else if self.assembler.end() > final_offset.into() {
            return Err(TransportError::FINAL_SIZE_ERROR(
                "lower than high water mark",
            ));
        }
        self.credit_consumed_by(final_offset.into(), received, max_data)?;

        if matches!(self.state, RecvState::ResetRecvd { .. } | RecvState::Closed) {
            return Ok(false);
        }
        self.state = RecvState::ResetRecvd {
            size: final_offset.into(),
            error_code,
        };
        // Nuke buffers so that future reads fail immediately, which ensures future reads don't
        // issue flow control credit redundant to that already issued. We could instead special-case
        // reset streams during read, but it's unclear if there's any benefit to retaining data for
        // reset streams.
        self.assembler.clear();
        Ok(true)
    }

    /// Compute the amount of flow control credit consumed, or return an error if more was consumed
    /// than issued
    fn credit_consumed_by(
        &self,
        offset: u64,
        received: u64,
        max_data: u64,
    ) -> Result<u64, TransportError> {
        let prev_end = self.assembler.end();
        let new_bytes = offset.saturating_sub(prev_end);
        if offset > self.sent_max_stream_data || received + new_bytes > max_data {
            debug!(
                received,
                new_bytes,
                max_data,
                offset,
                stream_max_data = self.sent_max_stream_data,
                "flow control error"
            );
            return Err(TransportError::FLOW_CONTROL_ERROR(""));
        }

        Ok(new_bytes)
    }
}

pub(crate) type ReadResult<T> = Result<Option<DidRead<T>>, ReadError>;

/// Result of a `Streams::read` call in case the stream had not ended yet
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[must_use = "A frame might need to be enqueued"]
pub(crate) struct DidRead<T> {
    pub result: T,
    pub max_stream_data: ShouldTransmit,
    pub max_data: ShouldTransmit,
}

pub(super) type StreamReadResult<T> = Result<Option<T>, ReadError>;

pub(crate) trait BytesRead {
    fn bytes_read(&self) -> u64;
}

impl BytesRead for usize {
    fn bytes_read(&self) -> u64 {
        *self as u64
    }
}

impl BytesRead for Bytes {
    fn bytes_read(&self) -> u64 {
        self.len() as u64
    }
}

impl BytesRead for (Bytes, u64) {
    fn bytes_read(&self) -> u64 {
        self.0.len() as u64
    }
}

pub(crate) struct ReadChunks {
    pub bufs: usize,
    pub read: usize,
}

impl BytesRead for ReadChunks {
    fn bytes_read(&self) -> u64 {
        self.read as u64
    }
}

/// Errors triggered when reading from a recv stream
#[derive(Debug, Error, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ReadError {
    /// No more data is currently available on this stream.
    ///
    /// If more data on this stream is received from the peer, an `Event::StreamReadable` will be
    /// generated for this stream, indicating that retrying the read might succeed.
    #[error("blocked")]
    Blocked,
    /// The peer abandoned transmitting data on this stream.
    ///
    /// Carries an application-defined error code.
    #[error("reset by peer: code {}", 0)]
    Reset(VarInt),
    /// The stream has not been opened or was already stopped, finished, or reset
    #[error("unknown stream")]
    UnknownStream,
    /// Attempted an ordered read following an unordered read
    ///
    /// Performing an unordered read allows discontinuities to arise in the receive buffer of a
    /// stream which cannot be recovered, making further ordered reads impossible.
    #[error("ordered read after unordered read")]
    IllegalOrderedRead,
}

impl From<IllegalOrderedRead> for ReadError {
    fn from(_: IllegalOrderedRead) -> Self {
        ReadError::IllegalOrderedRead
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(super) enum SendState {
    /// Sending new data
    Ready,
    /// Stream was finished; now sending retransmits only
    DataSent { finish_acked: bool },
    /// Sent RESET
    ResetSent,
    /// All sent data acknowledged
    DataRecvd,
    /// Reset acknowledged
    ResetRecvd,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum RecvState {
    Recv { size: Option<u64> },
    ResetRecvd { size: u64, error_code: VarInt },
    Closed,
}

impl Default for RecvState {
    fn default() -> Self {
        RecvState::Recv { size: None }
    }
}

/// Reasons why attempting to finish a stream might fail
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FinishError {
    /// The peer is no longer accepting data on this stream. No
    /// [`StreamEvent::Finished`] event will be emitted for this stream.
    ///
    /// Carries an application-defined error code.
    ///
    /// [`StreamEvent::Finished`]: crate::StreamEvent::Finished
    #[error("stopped by peer: code {}", 0)]
    Stopped(VarInt),
    /// The stream has not been opened or was already finished or reset
    #[error("unknown stream")]
    UnknownStream,
}
