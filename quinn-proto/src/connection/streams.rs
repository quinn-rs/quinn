use std::{
    collections::{hash_map, HashMap, VecDeque},
    convert::TryFrom,
    mem,
};

use bytes::{BufMut, Bytes};
use thiserror::Error;
use tracing::{debug, trace};

use super::spaces::Retransmits;
use crate::{
    coding::BufMutExt,
    connection::stats::FrameStats,
    frame::{self, FrameStruct},
    transport_parameters::TransportParameters,
    Dir, Side, StreamId, TransportError, VarInt, MAX_STREAM_COUNT,
};

mod recv;
pub use recv::ReadError;
use recv::{BytesRead, ReadChunks, Recv, StreamReadResult};
pub(super) use recv::{DidRead, ReadResult};

mod send;
pub use send::{FinishError, WriteError};
use send::{Send, SendState, StopResult};

pub struct Streams {
    side: Side,
    // Set of streams that are currently open, or could be immediately opened by the peer
    send: HashMap<StreamId, Send>,
    recv: HashMap<StreamId, Recv>,
    next: [u64; 2],
    // Locally initiated
    max: [u64; 2],
    // Maximum that can be remotely initiated
    max_remote: [u64; 2],
    // Lowest that hasn't actually been opened
    next_remote: [u64; 2],
    /// Whether the remote endpoint has opened any streams the application doesn't know about yet,
    /// per directionality
    opened: [bool; 2],
    // Next to report to the application, once opened
    next_reported_remote: [u64; 2],
    /// Number of outbound streams
    ///
    /// This differs from `self.send.len()` in that it does not include streams that the peer is
    /// permitted to open but which have not yet been opened.
    send_streams: usize,
    /// Streams with outgoing data queued
    pending: VecDeque<StreamId>,

    events: VecDeque<StreamEvent>,
    /// Streams blocked on connection-level flow control or stream window space
    ///
    /// Streams are only added to this list when a write fails.
    connection_blocked: Vec<StreamId>,
    /// Connection-level flow control budget dictated by the peer
    max_data: u64,
    /// The initial receive window
    receive_window: u64,
    /// Limit on incoming data, which is transmitted through `MAX_DATA` frames
    local_max_data: u64,
    /// The last value of `MAX_DATA` which had been queued for transmission in
    /// an outgoing `MAX_DATA` frame
    sent_max_data: VarInt,
    /// Sum of current offsets of all send streams.
    data_sent: u64,
    /// Sum of end offsets of all receive streams. Includes gaps, so it's an upper bound.
    data_recvd: u64,
    /// Total quantity of unacknowledged outgoing data
    unacked_data: u64,
    /// Configured upper bound for `unacked_data`
    send_window: u64,
    /// Configured upper bound for how much unacked data the peer can send us per stream
    stream_receive_window: u64,
    /// Whether the corresponding `max_remote` has increased
    max_streams_dirty: [bool; 2],

    // Pertinent state from the TransportParameters supplied by the peer
    initial_max_stream_data_uni: VarInt,
    initial_max_stream_data_bidi_local: VarInt,
    initial_max_stream_data_bidi_remote: VarInt,
}

impl Streams {
    pub fn new(
        side: Side,
        max_remote_uni: VarInt,
        max_remote_bi: VarInt,
        send_window: u64,
        receive_window: VarInt,
        stream_receive_window: VarInt,
    ) -> Self {
        let mut this = Self {
            side,
            send: HashMap::default(),
            recv: HashMap::default(),
            next: [0, 0],
            max: [0, 0],
            max_remote: [max_remote_bi.into(), max_remote_uni.into()],
            next_remote: [0, 0],
            opened: [false, false],
            next_reported_remote: [0, 0],
            send_streams: 0,
            pending: VecDeque::new(),
            events: VecDeque::new(),
            connection_blocked: Vec::new(),
            max_data: 0,
            receive_window: receive_window.into(),
            local_max_data: receive_window.into(),
            sent_max_data: receive_window,
            data_sent: 0,
            data_recvd: 0,
            unacked_data: 0,
            send_window,
            stream_receive_window: stream_receive_window.into(),
            max_streams_dirty: [false, false],
            initial_max_stream_data_uni: 0u32.into(),
            initial_max_stream_data_bidi_local: 0u32.into(),
            initial_max_stream_data_bidi_remote: 0u32.into(),
        };

        for dir in Dir::iter() {
            for i in 0..this.max_remote[dir as usize] {
                this.insert(true, StreamId::new(!side, dir, i));
            }
        }

        this
    }

    pub fn open(&mut self, dir: Dir) -> Option<StreamId> {
        if self.next[dir as usize] >= self.max[dir as usize] {
            return None;
        }

        self.next[dir as usize] += 1;
        let id = StreamId::new(self.side, dir, self.next[dir as usize] - 1);
        self.insert(false, id);
        self.send_streams += 1;
        Some(id)
    }

    pub fn set_params(&mut self, params: &TransportParameters) {
        self.initial_max_stream_data_uni = params.initial_max_stream_data_uni;
        self.initial_max_stream_data_bidi_local = params.initial_max_stream_data_bidi_local;
        self.initial_max_stream_data_bidi_remote = params.initial_max_stream_data_bidi_remote;
        self.max[Dir::Bi as usize] = params.initial_max_streams_bidi.into();
        self.max[Dir::Uni as usize] = params.initial_max_streams_uni.into();
        self.received_max_data(params.initial_max_data);
        for i in 0..self.max_remote[Dir::Bi as usize] {
            let id = StreamId::new(!self.side, Dir::Bi, i as u64);
            self.send.get_mut(&id).unwrap().max_data =
                params.initial_max_stream_data_bidi_local.into();
        }
    }

    pub fn send_streams(&self) -> usize {
        self.send_streams
    }

    fn alloc_remote_stream(&mut self, dir: Dir) {
        self.max_remote[dir as usize] += 1;
        let id = StreamId::new(!self.side, dir, self.max_remote[dir as usize] - 1);
        self.insert(true, id);
        self.max_streams_dirty[dir as usize] = true;
    }

    pub fn accept(&mut self, dir: Dir) -> Option<StreamId> {
        if self.next_remote[dir as usize] == self.next_reported_remote[dir as usize] {
            return None;
        }
        let x = self.next_reported_remote[dir as usize];
        self.next_reported_remote[dir as usize] = x + 1;
        if dir == Dir::Bi {
            self.send_streams += 1;
        }
        Some(StreamId::new(!self.side, dir, x))
    }

    pub fn zero_rtt_rejected(&mut self) {
        // Revert to initial state for outgoing streams
        for dir in Dir::iter() {
            for i in 0..self.next[dir as usize] {
                // We don't bother calling `stream_freed` here because we explicitly reset affected
                // counters below.
                let id = StreamId::new(self.side, dir, i);
                self.send.remove(&id).unwrap();
                if let Dir::Bi = dir {
                    self.recv.remove(&id).unwrap();
                }
            }
            self.next[dir as usize] = 0;
        }
        self.pending.clear();
        self.send_streams = 0;
        self.data_sent = 0;
        self.connection_blocked.clear();
    }

    pub(crate) fn read(
        &mut self,
        id: StreamId,
        max_length: usize,
        ordered: bool,
    ) -> ReadResult<(Bytes, u64)> {
        self.try_read(id, |rs| rs.read(max_length, ordered))
    }

    pub(crate) fn read_chunks(
        &mut self,
        id: StreamId,
        bufs: &mut [Bytes],
    ) -> ReadResult<ReadChunks> {
        self.try_read(id, |rs| rs.read_chunks(bufs))
    }

    fn try_read<F, O>(&mut self, id: StreamId, mut read: F) -> ReadResult<O>
    where
        F: FnMut(&mut Recv) -> StreamReadResult<O>,
        O: BytesRead,
    {
        let mut entry = match self.recv.entry(id) {
            hash_map::Entry::Vacant(_) => return Err(ReadError::UnknownStream),
            hash_map::Entry::Occupied(e) => e,
        };
        let rs = entry.get_mut();
        match read(rs) {
            Ok(Some(out)) => {
                let (_, max_stream_data) = rs.max_stream_data(self.stream_receive_window);
                let max_data = self.add_read_credits(out.bytes_read());
                Ok(Some(DidRead {
                    result: out,
                    max_stream_data,
                    max_data,
                }))
            }
            Ok(None) => {
                entry.remove_entry();
                self.stream_freed(id, StreamHalf::Recv);
                Ok(None)
            }
            Err(e @ ReadError::Reset { .. }) => {
                entry.remove_entry();
                self.stream_freed(id, StreamHalf::Recv);
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    /// Queue `data` to be written for `stream`
    pub fn write(&mut self, id: StreamId, data: &[u8]) -> Result<usize, WriteError> {
        let limit = (self.max_data - self.data_sent).min(self.send_window - self.unacked_data);
        let stream = self.send.get_mut(&id).ok_or(WriteError::UnknownStream)?;
        if limit == 0 {
            trace!(stream = %id, "write blocked by connection-level flow control or send window");
            if !stream.connection_blocked {
                stream.connection_blocked = true;
                self.connection_blocked.push(id);
            }
            return Err(WriteError::Blocked);
        }

        let was_pending = stream.is_pending();
        let len = (data.len() as u64).min(limit) as usize;
        let len = stream.write(&data[0..len])?;
        self.data_sent += len as u64;
        self.unacked_data += len as u64;
        trace!(stream = %id, "wrote {} bytes", len);
        if !was_pending {
            self.pending.push_back(id);
        }
        Ok(len)
    }

    /// Process incoming stream frame
    ///
    /// If successful, returns whether a `MAX_DATA` frame needs to be transmitted
    pub fn received(&mut self, frame: frame::Stream) -> Result<ShouldTransmit, TransportError> {
        trace!(id = %frame.id, offset = frame.offset, len = frame.data.len(), fin = frame.fin, "got stream");
        let stream = frame.id;
        self.validate_receive_id(stream).map_err(|e| {
            debug!("received illegal STREAM frame");
            e
        })?;

        let rs = match self.recv.get_mut(&stream) {
            Some(rs) => rs,
            None => {
                trace!("dropping frame for closed stream");
                return Ok(ShouldTransmit(false));
            }
        };

        if rs.is_finished() {
            trace!("dropping frame for finished stream");
            return Ok(ShouldTransmit(false));
        }

        let new_bytes = rs.ingest(frame, self.data_recvd, self.local_max_data)?;
        self.data_recvd = self.data_recvd.saturating_add(new_bytes);

        if !rs.assembler.is_stopped() {
            self.on_stream_frame(true, stream);
            return Ok(ShouldTransmit(false));
        }

        // Stopped streams become closed instantly on FIN, so check whether we need to clean up
        if rs.is_closed() {
            self.recv.remove(&stream);
            self.stream_freed(stream, StreamHalf::Recv);
        }

        // We don't buffer data on stopped streams, so issue flow control credit immediately
        Ok(self.add_read_credits(new_bytes))
    }

    /// Process incoming RESET_STREAM frame
    ///
    /// If successful, returns whether a `MAX_DATA` frame needs to be transmitted
    pub fn received_reset(
        &mut self,
        frame: frame::ResetStream,
    ) -> Result<ShouldTransmit, TransportError> {
        let frame::ResetStream {
            id,
            error_code,
            final_offset,
        } = frame;
        self.validate_receive_id(id).map_err(|e| {
            debug!("received illegal RESET_STREAM frame");
            e
        })?;

        let rs = match self.recv.get_mut(&id) {
            Some(stream) => stream,
            None => {
                trace!("received RESET_STREAM on closed stream");
                return Ok(ShouldTransmit(false));
            }
        };

        // State transition
        if !rs.reset(
            error_code,
            final_offset,
            self.data_recvd,
            self.local_max_data,
        )? {
            // Redundant reset
            return Ok(ShouldTransmit(false));
        }
        let bytes_read = rs.assembler.bytes_read();
        let stopped = rs.assembler.is_stopped();
        let end = rs.assembler.end();
        if stopped {
            // Stopped streams should be disposed immediately on reset
            self.recv.remove(&id);
        }
        self.on_stream_frame(!stopped, id);

        // Update flow control
        Ok(if bytes_read != final_offset.into() {
            // bytes_read is always <= end, so this won't underflow.
            self.data_recvd = self
                .data_recvd
                .saturating_add(u64::from(final_offset) - end);
            self.add_read_credits(u64::from(final_offset) - bytes_read)
        } else {
            ShouldTransmit(false)
        })
    }

    /// Process incoming `STOP_SENDING` frame
    pub fn received_stop_sending(&mut self, id: StreamId, error_code: VarInt) {
        let stream = match self.send.get_mut(&id) {
            Some(ss) => ss,
            None => return,
        };
        self.events
            .push_back(StreamEvent::Stopped { id, error_code });
        stream.stop(error_code);
        self.on_stream_frame(false, id);
    }

    /// Set the FIN bit in the next stream frame, generating an empty one if necessary
    pub fn finish(&mut self, id: StreamId) -> Result<(), FinishError> {
        let stream = self.send.get_mut(&id).ok_or(FinishError::UnknownStream)?;
        let was_pending = stream.is_pending();
        stream.finish()?;
        if !was_pending {
            self.pending.push_back(id);
        }
        Ok(())
    }

    /// Abandon pending and future transmits
    ///
    /// Does not cause the actual RESET_STREAM frame to be sent, just updates internal
    /// state.
    pub fn reset(&mut self, id: StreamId) -> Result<(), UnknownStream> {
        let stream = match self.send.get_mut(&id) {
            Some(ss) => ss,
            None => return Err(UnknownStream { _private: () }),
        };

        if matches!(stream.state, SendState::ResetSent | SendState::ResetRecvd) {
            // Redundant reset call
            return Err(UnknownStream { _private: () });
        }

        // Restore the portion of the send window consumed by the data that we aren't about to
        // send. We leave flow control alone because the peer's responsible for issuing additional
        // credit based on the final offset communicated in the RESET_STREAM frame we send.
        self.unacked_data -= stream.pending.unacked();
        stream.reset();

        // Don't reopen an already-closed stream we haven't forgotten yet
        Ok(())
    }

    pub fn reset_acked(&mut self, id: StreamId) {
        match self.send.entry(id) {
            hash_map::Entry::Vacant(_) => {}
            hash_map::Entry::Occupied(e) => {
                if let SendState::ResetSent = e.get().state {
                    e.remove_entry();
                    self.stream_freed(id, StreamHalf::Send);
                }
            }
        }
    }

    /// Cease accepting data on a stream
    ///
    /// Returns a structure which indicates whether this action
    /// requires transmitting any frames.
    pub fn stop(&mut self, id: StreamId) -> Result<StopResult, UnknownStream> {
        let stream = match self.recv.get_mut(&id) {
            Some(s) => s,
            None => return Err(UnknownStream { _private: () }),
        };
        if stream.assembler.is_stopped() {
            return Err(UnknownStream { _private: () });
        }
        stream.assembler.stop();
        let stop_sending = ShouldTransmit(!stream.is_finished());

        // Issue flow control credit for unread data
        let read_credits = stream.assembler.end() - stream.assembler.bytes_read();
        let max_data = self.add_read_credits(read_credits);
        Ok(StopResult {
            stop_sending,
            max_data,
        })
    }

    pub fn stop_reason(&self, id: StreamId) -> Result<Option<VarInt>, UnknownStream> {
        match self.send.get(&id) {
            Some(s) => Ok(s.stop_reason),
            None => Err(UnknownStream { _private: () }),
        }
    }

    pub fn can_send(&self) -> bool {
        !self.pending.is_empty()
    }

    pub fn write_control_frames(
        &mut self,
        buf: &mut Vec<u8>,
        pending: &mut Retransmits,
        sent: &mut Retransmits,
        stats: &mut FrameStats,
        max_size: usize,
    ) {
        // RESET_STREAM
        while buf.len() + frame::ResetStream::SIZE_BOUND < max_size {
            let (id, error_code) = match pending.reset_stream.pop() {
                Some(x) => x,
                None => break,
            };
            let stream = match self.send.get_mut(&id) {
                Some(x) => x,
                None => continue,
            };
            trace!(stream = %id, "RESET_STREAM");
            sent.reset_stream.push((id, error_code));
            frame::ResetStream {
                id,
                error_code,
                final_offset: VarInt::try_from(stream.offset()).expect("impossibly large offset"),
            }
            .encode(buf);
            stats.reset_stream += 1;
        }

        // STOP_SENDING
        while buf.len() + frame::StopSending::SIZE_BOUND < max_size {
            let frame = match pending.stop_sending.pop() {
                Some(x) => x,
                None => break,
            };
            let stream = match self.recv.get_mut(&frame.id) {
                Some(x) => x,
                None => continue,
            };
            if stream.is_finished() {
                continue;
            }
            trace!(stream = %frame.id, "STOP_SENDING");
            frame.encode(buf);
            sent.stop_sending.push(frame);
            stats.stop_sending += 1;
        }

        // MAX_DATA
        if pending.max_data && buf.len() + 9 < max_size {
            pending.max_data = false;

            // `local_max_data` can grow bigger than `VarInt`.
            // For transmission inside QUIC frames we need to clamp it to the
            // maximum allowed `VarInt` size.
            let max = VarInt::try_from(self.local_max_data).unwrap_or(VarInt::MAX);

            trace!(value = max.into_inner(), "MAX_DATA");
            self.record_sent_max_data(max);
            sent.max_data = true;
            buf.write(frame::Type::MAX_DATA);
            buf.write(max);
            stats.max_data += 1;
        }

        // MAX_STREAM_DATA
        while buf.len() + 17 < max_size {
            let id = match pending.max_stream_data.iter().next() {
                Some(x) => *x,
                None => break,
            };
            pending.max_stream_data.remove(&id);
            let rs = match self.recv.get_mut(&id) {
                Some(x) => x,
                None => continue,
            };
            if rs.is_finished() {
                continue;
            }
            sent.max_stream_data.insert(id);

            let (max, _) = rs.max_stream_data(self.stream_receive_window);
            rs.record_sent_max_stream_data(max);

            trace!(stream = %id, max = max, "MAX_STREAM_DATA");
            buf.write(frame::Type::MAX_STREAM_DATA);
            buf.write(id);
            buf.write_var(max);
            stats.max_stream_data += 1;
        }

        // MAX_STREAMS_UNI
        if pending.max_uni_stream_id && buf.len() + 9 < max_size {
            pending.max_uni_stream_id = false;
            sent.max_uni_stream_id = true;
            trace!(
                value = self.max_remote[Dir::Uni as usize],
                "MAX_STREAMS (unidirectional)"
            );
            buf.write(frame::Type::MAX_STREAMS_UNI);
            buf.write_var(self.max_remote[Dir::Uni as usize]);
            stats.max_streams_uni += 1;
        }

        // MAX_STREAMS_BIDI
        if pending.max_bi_stream_id && buf.len() + 9 < max_size {
            pending.max_bi_stream_id = false;
            sent.max_bi_stream_id = true;
            trace!(
                value = self.max_remote[Dir::Bi as usize],
                "MAX_STREAMS (bidirectional)"
            );
            buf.write(frame::Type::MAX_STREAMS_BIDI);
            buf.write_var(self.max_remote[Dir::Bi as usize]);
            stats.max_streams_bidi += 1;
        }
    }

    pub fn write_stream_frames(
        &mut self,
        buf: &mut Vec<u8>,
        max_buf_size: usize,
    ) -> Vec<frame::StreamMeta> {
        let mut stream_frames = Vec::new();
        while buf.len() + frame::Stream::SIZE_BOUND < max_buf_size {
            let max_data_len = match max_buf_size.checked_sub(buf.len() + frame::Stream::SIZE_BOUND)
            {
                Some(x) => x,
                None => break,
            };
            // Poppping data from the front of the queue, storing as much data
            // as possible in a single frame, and enqueing sending further
            // remaining data at the end of the queue helps with fairness.
            // Other streams will have a chance to write data before we touch
            // this stream again.
            let id = match self.pending.pop_front() {
                Some(x) => x,
                None => break,
            };
            let stream = match self.send.get_mut(&id) {
                Some(s) => s,
                // Stream was reset with pending data and the reset was acknowledged
                None => continue,
            };

            // Reset streams aren't removed from the pending list and still exist while the peer
            // hasn't acknowledged the reset, but should not generate STREAM frames, so we need to
            // check for them explicitly.
            if stream.is_reset() {
                continue;
            }
            let offsets = stream.pending.poll_transmit(max_data_len);
            let fin = offsets.end == stream.pending.offset()
                && matches!(stream.state, SendState::DataSent { .. });
            if fin {
                stream.fin_pending = false;
            }
            if stream.is_pending() {
                self.pending.push_back(id);
            }

            let meta = frame::StreamMeta { id, offsets, fin };
            trace!(id = %meta.id, off = meta.offsets.start, len = meta.offsets.end - meta.offsets.start, fin = meta.fin, "STREAM");
            meta.encode(true, buf);

            // The range might not be retrievable in a single `get` if it is
            // stored in noncontiguous fashion. Therefore this loop iterates
            // until the range is fully copied into the frame.
            let mut offsets = meta.offsets.clone();
            while offsets.start != offsets.end {
                let data = stream.pending.get(offsets.clone());
                offsets.start += data.len() as u64;
                buf.put_slice(data);
            }
            stream_frames.push(meta);
        }

        stream_frames
    }

    /// Notify the application that new streams were opened or a stream became readable.
    fn on_stream_frame(&mut self, notify_readable: bool, stream: StreamId) {
        if stream.initiator() == self.side {
            // Notifying about the opening of locally-initiated streams would be redundant.
            if notify_readable {
                self.events.push_back(StreamEvent::Readable { id: stream });
            }
            return;
        }
        let next = &mut self.next_remote[stream.dir() as usize];
        if stream.index() >= *next {
            *next = stream.index() + 1;
            self.opened[stream.dir() as usize] = true;
        } else if notify_readable {
            self.events.push_back(StreamEvent::Readable { id: stream });
        }
    }

    pub fn received_ack_of(&mut self, frame: frame::StreamMeta) {
        let mut entry = match self.send.entry(frame.id) {
            hash_map::Entry::Vacant(_) => return,
            hash_map::Entry::Occupied(e) => e,
        };
        let stream = entry.get_mut();
        if stream.is_reset() {
            // We account for outstanding data on reset streams at time of reset
            return;
        }
        let id = frame.id;
        self.unacked_data -= frame.offsets.end - frame.offsets.start;
        stream.ack(frame);
        if stream.state != SendState::DataRecvd {
            return;
        }

        entry.remove_entry();
        self.stream_freed(id, StreamHalf::Send);
        self.events.push_back(StreamEvent::Finished { id });
    }

    pub fn retransmit(&mut self, frame: frame::StreamMeta) {
        let stream = match self.send.get_mut(&frame.id) {
            // Loss of data on a closed stream is a noop
            None => return,
            Some(x) => x,
        };
        if !stream.is_pending() {
            self.pending.push_back(frame.id);
        }
        stream.fin_pending |= frame.fin;
        stream.pending.retransmit(frame.offsets);
    }

    pub fn retransmit_all_for_0rtt(&mut self) {
        for dir in Dir::iter() {
            for index in 0..self.next[dir as usize] {
                let id = StreamId::new(Side::Client, dir, index);
                let stream = self.send.get_mut(&id).unwrap();
                if stream.pending.is_fully_acked() && !stream.fin_pending {
                    // Stream data can't be acked in 0-RTT, so we must not have sent anything on
                    // this stream
                    continue;
                }
                if !stream.is_pending() {
                    self.pending.push_back(id);
                }
                stream.pending.retransmit_all_for_0rtt();
            }
        }
    }

    pub fn received_max_streams(&mut self, dir: Dir, count: u64) -> Result<(), TransportError> {
        if count > MAX_STREAM_COUNT {
            return Err(TransportError::FRAME_ENCODING_ERROR(
                "unrepresentable stream limit",
            ));
        }

        let current = &mut self.max[dir as usize];
        if count > *current {
            *current = count;
            self.events.push_back(StreamEvent::Available { dir });
        }

        Ok(())
    }

    /// Handle increase to connection-level flow control limit
    pub fn received_max_data(&mut self, n: VarInt) {
        self.max_data = self.max_data.max(n.into());
    }

    pub fn received_max_stream_data(
        &mut self,
        id: StreamId,
        offset: u64,
    ) -> Result<(), TransportError> {
        if id.initiator() != self.side && id.dir() == Dir::Uni {
            debug!("got MAX_STREAM_DATA on recv-only {}", id);
            return Err(TransportError::STREAM_STATE_ERROR(
                "MAX_STREAM_DATA on recv-only stream",
            ));
        }

        if let Some(ss) = self.send.get_mut(&id) {
            if ss.increase_max_data(offset) {
                self.events.push_back(StreamEvent::Writable { id });
            }
        } else if id.initiator() == self.side && self.is_local_unopened(id) {
            debug!("got MAX_STREAM_DATA on unopened {}", id);
            return Err(TransportError::STREAM_STATE_ERROR(
                "MAX_STREAM_DATA on unopened stream",
            ));
        }

        self.on_stream_frame(false, id);
        Ok(())
    }

    /// Yield stream events
    pub fn poll(&mut self) -> Option<StreamEvent> {
        if let Some(dir) = Dir::iter().find(|&i| mem::replace(&mut self.opened[i as usize], false))
        {
            return Some(StreamEvent::Opened { dir });
        }

        if let Some(id) = self.poll_unblocked() {
            return Some(StreamEvent::Writable { id });
        }

        self.events.pop_front()
    }

    pub fn take_max_streams_dirty(&mut self, dir: Dir) -> bool {
        mem::replace(&mut self.max_streams_dirty[dir as usize], false)
    }

    /// Fetch a stream for which a write previously failed due to *connection-level* flow control or
    /// send window limits which no longer apply.
    fn poll_unblocked(&mut self) -> Option<StreamId> {
        if self.flow_blocked() {
            // Everything's still blocked
            return None;
        }

        while let Some(id) = self.connection_blocked.pop() {
            let stream = match self.send.get_mut(&id) {
                None => continue,
                Some(s) => s,
            };
            debug_assert!(stream.connection_blocked);
            stream.connection_blocked = false;
            // If it's no longer sensible to write to a stream (even to detect an error) then don't
            // report it.
            if stream.is_writable() {
                return Some(id);
            }
        }

        None
    }

    /// Check for errors entailed by the peer's use of `id` as a send stream
    fn validate_receive_id(&mut self, id: StreamId) -> Result<(), TransportError> {
        if self.side == id.initiator() {
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
        Ok(())
    }

    /// Whether a locally initiated stream has never been open
    pub fn is_local_unopened(&self, id: StreamId) -> bool {
        id.index() >= self.next[id.dir() as usize]
    }

    fn insert(&mut self, remote: bool, id: StreamId) {
        let bi = id.dir() == Dir::Bi;
        if bi || !remote {
            let max_data = match id.dir() {
                Dir::Uni => self.initial_max_stream_data_uni,
                // Remote/local appear reversed here because the transport parameters are named from
                // the perspective of the peer.
                Dir::Bi if remote => self.initial_max_stream_data_bidi_local,
                Dir::Bi => self.initial_max_stream_data_bidi_remote,
            };
            let stream = Send::new(max_data);
            assert!(self.send.insert(id, stream).is_none());
        }
        if bi || remote {
            assert!(self
                .recv
                .insert(id, Recv::new(self.stream_receive_window))
                .is_none());
        }
    }

    /// Whether application stream writes are currently blocked on connection-level flow control or
    /// the send window
    fn flow_blocked(&self) -> bool {
        self.data_sent >= self.max_data || self.unacked_data >= self.send_window
    }

    /// Adds credits to the connection flow control window
    ///
    /// Returns whether a `MAX_DATA` frame should be enqueued as soon as possible.
    /// This will only be the case if the window update would is significant
    /// enough. As soon as a window update with a `MAX_DATA` frame has been
    /// queued, the [`record_sent_max_data`] function should be called to
    /// suppress sending further updates until the window increases significantly
    /// again.
    fn add_read_credits(&mut self, credits: u64) -> ShouldTransmit {
        self.local_max_data = self.local_max_data.saturating_add(credits);

        if self.local_max_data > VarInt::MAX.into_inner() {
            return ShouldTransmit(false);
        }

        // Only announce a window update if it's significant enough
        // to make it worthwhile sending a MAX_DATA frame.
        // We use a fraction of the configured connection receive window to make
        // the decision, to accomodate for connection using bigger windows requring
        // less updates.
        let diff = self.local_max_data - self.sent_max_data.into_inner();
        ShouldTransmit(diff >= (self.receive_window / 8))
    }

    /// Records that a `MAX_DATA` announcing a certain window was sent
    ///
    /// This will suppress enqueuing further `MAX_DATA` frames unless
    /// either the previous transmission was not acknowledged or the window
    /// further increased.
    fn record_sent_max_data(&mut self, sent_value: VarInt) {
        if sent_value > self.sent_max_data {
            self.sent_max_data = sent_value;
        }
    }

    /// Update counters for removal of a stream
    fn stream_freed(&mut self, id: StreamId, half: StreamHalf) {
        if id.initiator() != self.side {
            let fully_free = id.dir() == Dir::Uni
                || match half {
                    StreamHalf::Send => !self.recv.contains_key(&id),
                    StreamHalf::Recv => !self.send.contains_key(&id),
                };
            if fully_free {
                self.alloc_remote_stream(id.dir());
            }
        }
        if half == StreamHalf::Send {
            self.send_streams -= 1;
        }
    }
}

/// Application events about streams
#[derive(Debug)]
pub enum StreamEvent {
    /// One or more new streams has been opened
    Opened {
        /// Directionality for which streams have been opened
        dir: Dir,
    },
    /// A currently open stream has data or errors waiting to be read
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TransportErrorCode;

    fn make(side: Side) -> Streams {
        Streams::new(
            side,
            128u32.into(),
            128u32.into(),
            1024 * 1024,
            (1024 * 1024u32).into(),
            (1024 * 1024u32).into(),
        )
    }

    #[test]
    fn reset_flow_control() {
        let mut client = make(Side::Client);
        let id = StreamId::new(Side::Server, Dir::Uni, 0);
        let initial_max = client.local_max_data;
        assert_eq!(
            client
                .received(frame::Stream {
                    id,
                    offset: 0,
                    fin: false,
                    data: Bytes::from_static(&[0; 2048]),
                })
                .unwrap(),
            ShouldTransmit(false)
        );
        assert_eq!(client.data_recvd, 2048);
        assert_eq!(client.local_max_data - initial_max, 0);
        client.read(id, 1024, true).unwrap();
        assert_eq!(client.local_max_data - initial_max, 1024);
        assert_eq!(
            client
                .received_reset(frame::ResetStream {
                    id,
                    error_code: 0u32.into(),
                    final_offset: 4096u32.into(),
                })
                .unwrap(),
            ShouldTransmit(false)
        );
        assert_eq!(client.data_recvd, 4096);
        assert_eq!(client.local_max_data - initial_max, 4096);
    }

    #[test]
    fn reset_after_empty_frame_flow_control() {
        let mut client = make(Side::Client);
        let id = StreamId::new(Side::Server, Dir::Uni, 0);
        let initial_max = client.local_max_data;
        assert_eq!(
            client
                .received(frame::Stream {
                    id,
                    offset: 4096,
                    fin: false,
                    data: Bytes::from_static(&[0; 0]),
                })
                .unwrap(),
            ShouldTransmit(false)
        );
        assert_eq!(client.data_recvd, 4096);
        assert_eq!(client.local_max_data - initial_max, 0);
        assert_eq!(
            client
                .received_reset(frame::ResetStream {
                    id,
                    error_code: 0u32.into(),
                    final_offset: 4096u32.into(),
                })
                .unwrap(),
            ShouldTransmit(false)
        );
        assert_eq!(client.data_recvd, 4096);
        assert_eq!(client.local_max_data - initial_max, 4096);
    }

    #[test]
    fn duplicate_reset_flow_control() {
        let mut client = make(Side::Client);
        let id = StreamId::new(Side::Server, Dir::Uni, 0);
        assert_eq!(
            client
                .received_reset(frame::ResetStream {
                    id,
                    error_code: 0u32.into(),
                    final_offset: 4096u32.into(),
                })
                .unwrap(),
            ShouldTransmit(false)
        );
        assert_eq!(client.data_recvd, 4096);
        assert_eq!(
            client
                .received_reset(frame::ResetStream {
                    id,
                    error_code: 0u32.into(),
                    final_offset: 4096u32.into(),
                })
                .unwrap(),
            ShouldTransmit(false)
        );
        assert_eq!(client.data_recvd, 4096);
    }

    #[test]
    fn recv_stopped() {
        let mut client = make(Side::Client);
        let id = StreamId::new(Side::Server, Dir::Uni, 0);
        let initial_max = client.local_max_data;
        assert_eq!(
            client
                .received(frame::Stream {
                    id,
                    offset: 0,
                    fin: false,
                    data: Bytes::from_static(&[0; 32]),
                })
                .unwrap(),
            ShouldTransmit(false)
        );
        assert_eq!(client.local_max_data, initial_max);
        assert_eq!(
            client.stop(id).unwrap(),
            StopResult {
                max_data: ShouldTransmit(false),
                stop_sending: ShouldTransmit(true),
            }
        );
        assert!(client.stop(id).is_err());
        assert_eq!(client.read(id, 0, true), Err(ReadError::UnknownStream));
        assert_eq!(
            client.read(id, usize::MAX, false),
            Err(ReadError::UnknownStream)
        );
        assert_eq!(client.local_max_data - initial_max, 32);
        assert_eq!(
            client
                .received(frame::Stream {
                    id,
                    offset: 32,
                    fin: true,
                    data: Bytes::from_static(&[0; 16]),
                })
                .unwrap(),
            ShouldTransmit(false)
        );
        assert_eq!(client.local_max_data - initial_max, 48);
        assert!(!client.recv.contains_key(&id));
    }

    #[test]
    fn stopped_reset() {
        let mut client = make(Side::Client);
        let id = StreamId::new(Side::Server, Dir::Uni, 0);
        // Server opens stream
        assert_eq!(
            client
                .received(frame::Stream {
                    id,
                    offset: 0,
                    fin: false,
                    data: Bytes::from_static(&[0; 32]),
                })
                .unwrap(),
            ShouldTransmit(false)
        );
        // Client stops it
        assert_eq!(
            client.stop(id).unwrap(),
            StopResult {
                max_data: ShouldTransmit(false),
                stop_sending: ShouldTransmit(true),
            }
        );
        // Server complies
        assert_eq!(
            client
                .received_reset(frame::ResetStream {
                    id,
                    error_code: 0u32.into(),
                    final_offset: 32u32.into(),
                })
                .unwrap(),
            ShouldTransmit(false)
        );
        assert!(!client.recv.contains_key(&id), "stream state is freed");
    }

    #[test]
    fn send_stopped() {
        let mut server = make(Side::Server);
        server.set_params(&TransportParameters {
            initial_max_streams_uni: 1u32.into(),
            initial_max_data: 42u32.into(),
            initial_max_stream_data_uni: 42u32.into(),
            ..Default::default()
        });
        let id = server.open(Dir::Uni).unwrap();
        let reason = 0u32.into();
        server.received_stop_sending(id, reason);
        assert_eq!(server.write(id, &[]), Err(WriteError::Stopped(reason)));
        server.reset(id).unwrap();
        assert_eq!(server.write(id, &[]), Err(WriteError::UnknownStream));
    }

    #[test]
    fn final_offset_flow_control() {
        let mut client = make(Side::Client);
        assert_eq!(
            client
                .received_reset(frame::ResetStream {
                    id: StreamId::new(Side::Server, Dir::Uni, 0),
                    error_code: 0u32.into(),
                    final_offset: VarInt::MAX,
                })
                .unwrap_err()
                .code,
            TransportErrorCode::FLOW_CONTROL_ERROR
        );
    }
}
