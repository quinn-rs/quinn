use bytes::Bytes;
use thiserror::Error;

use crate::{VarInt, connection::send_buffer::SendBuffer, frame};

#[derive(Debug)]
pub(super) struct Send {
    pub(super) max_data: u64,
    pub(super) state: SendState,
    pub(super) pending: SendBuffer,
    pub(super) priority: i32,
    /// Whether a frame containing a FIN bit must be transmitted, even if we don't have any new data
    pub(super) fin_pending: bool,
    /// Whether this stream is in the `connection_blocked` list of `Streams`
    pub(super) connection_blocked: bool,
    /// The reason the peer wants us to stop, if `STOP_SENDING` was received
    pub(super) stop_reason: Option<VarInt>,
}

impl Send {
    pub(super) fn new(max_data: VarInt) -> Box<Self> {
        Box::new(Self {
            max_data: max_data.into(),
            state: SendState::Ready,
            pending: SendBuffer::new(),
            priority: 0,
            fin_pending: false,
            connection_blocked: false,
            stop_reason: None,
        })
    }

    /// Whether the stream has been reset
    pub(super) fn is_reset(&self) -> bool {
        matches!(self.state, SendState::ResetSent)
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
            Err(FinishError::ClosedStream)
        }
    }

    pub(super) fn write<T>(
        &mut self,
        source: impl FnOnce(usize, &mut Vec<Bytes>) -> T,
        limit: u64,
    ) -> Result<(usize, T), WriteError> {
        if !self.is_writable() {
            return Err(WriteError::ClosedStream);
        }
        if let Some(error_code) = self.stop_reason {
            return Err(WriteError::Stopped(error_code));
        }
        let budget = self.max_data - self.pending.offset();
        if budget == 0 {
            return Err(WriteError::Blocked);
        }
        let limit = limit.min(budget) as usize;

        let mut chunks = Vec::new();
        let source_output = source(limit, &mut chunks);

        let mut written = 0;

        for mut chunk in chunks.drain(..) {
            let prefix = chunk.split_to(chunk.len().min(limit - written));
            written += prefix.len();
            self.pending.write(prefix);

            debug_assert!(written <= limit);
            if written == limit {
                break;
            }
        }

        Ok((written, source_output))
    }

    /// Update stream state due to a reset sent by the local application
    pub(super) fn reset(&mut self) {
        use SendState::*;
        if let DataSent { .. } | Ready = self.state {
            self.state = ResetSent;
        }
    }

    /// Handle STOP_SENDING
    ///
    /// Returns true if the stream was stopped due to this frame, and false
    /// if it had been stopped before
    pub(super) fn try_stop(&mut self, error_code: VarInt) -> bool {
        if self.stop_reason.is_none() {
            self.stop_reason = Some(error_code);
            true
        } else {
            false
        }
    }

    /// Returns whether the stream has been finished and all data has been acknowledged by the peer
    pub(super) fn ack(&mut self, frame: frame::StreamMeta) -> bool {
        self.pending.ack(frame.offsets);
        match self.state {
            SendState::DataSent {
                ref mut finish_acked,
            } => {
                *finish_acked |= frame.fin;
                *finish_acked && self.pending.is_fully_acked()
            }
            _ => false,
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

/// Indicates how many bytes and chunks had been transferred in a write operation
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub struct Written {
    /// The amount of bytes which had been written
    pub bytes: usize,
    /// The amount of full chunks which had been written
    ///
    /// If a chunk was only partially written, it will not be counted by this field.
    pub chunks: usize,
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
    #[error("stopped by peer: code {0}")]
    Stopped(VarInt),
    /// The stream has not been opened or has already been finished or reset
    #[error("closed stream")]
    ClosedStream,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(super) enum SendState {
    /// Sending new data
    Ready,
    /// Stream was finished; now sending retransmits only
    DataSent { finish_acked: bool },
    /// Sent RESET
    ResetSent,
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
    #[error("stopped by peer: code {0}")]
    Stopped(VarInt),
    /// The stream has not been opened or was already finished or reset
    #[error("closed stream")]
    ClosedStream,
}
