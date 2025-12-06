//! Implements support for emitting qlog events.
//!
//! This uses the [`n0-qlog`] crate to emit qlog events. The n0-qlog crate, and thus this implementation,
//! is currently based on [draft-ietf-quic-qlog-main-schema-13] an [draft-ietf-quic-qlog-quic-events-12].
//!
//! [draft-ietf-quic-qlog-main-schema-13]: https://www.ietf.org/archive/id/draft-ietf-quic-qlog-main-schema-13.html
//! [draft-ietf-quic-qlog-quic-events-12]: https://www.ietf.org/archive/id/draft-ietf-quic-qlog-quic-events-12.html

// Function bodies in this module are regularly cfg'd out
#![allow(unused_variables)]

#[cfg(not(feature = "qlog"))]
use std::marker::PhantomData;
#[cfg(feature = "qlog")]
use std::sync::{Arc, Mutex};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

#[cfg(feature = "qlog")]
use qlog::{
    CommonFields, HexSlice, TokenType, VantagePoint,
    events::{
        ApplicationError, ConnectionClosedFrameError, Event, EventData, RawInfo, TupleEndpointInfo,
        quic::{
            self, AckedRanges, AddressDiscoveryRole, ConnectionStarted, ErrorSpace, PacketHeader,
            PacketLost, PacketLostTrigger, PacketReceived, PacketSent, PacketType,
            ParametersRestored, ParametersSet, PreferredAddress, QlogTimerType, QuicFrame,
            StreamType, TimerEventType, TimerType, TimerUpdated, TransportInitiator, TupleAssigned,
        },
    },
    streamer::QlogStreamer,
};
#[cfg(feature = "qlog")]
use tracing::warn;

use crate::{
    Connection, ConnectionId, Frame, Instant, PathId,
    connection::{PathData, SentPacket, timer::Timer},
    frame::{EcnCounts, StreamMeta},
    packet::{Header, SpaceId},
    range_set::ArrayRangeSet,
    transport_parameters::TransportParameters,
};
#[cfg(feature = "qlog")]
use crate::{
    QlogConfig, Side, TransportErrorCode,
    connection::timer::{ConnTimer, PathTimer},
    frame::Close,
};

/// Shareable handle to a single qlog output stream
#[cfg(feature = "qlog")]
#[derive(Clone)]
pub(crate) struct QlogStream(Arc<Mutex<QlogStreamer>>);

#[cfg(feature = "qlog")]
impl QlogStream {
    pub(crate) fn new(
        config: QlogConfig,
        initial_dst_cid: ConnectionId,
        side: Side,
        now: Instant,
    ) -> Result<Self, qlog::Error> {
        let vantage_point = VantagePoint {
            name: None,
            ty: match side {
                Side::Client => qlog::VantagePointType::Client,
                Side::Server => qlog::VantagePointType::Server,
            },
            flow: None,
        };

        let common_fields = CommonFields {
            group_id: Some(initial_dst_cid.to_string()),
            ..Default::default()
        };

        let trace = qlog::TraceSeq::new(
            config.title.clone(),
            config.description.clone(),
            Some(common_fields),
            Some(vantage_point),
            vec![],
        );

        let start_time = config.start_time.unwrap_or(now);

        let mut streamer = QlogStreamer::new(
            config.title,
            config.description,
            start_time,
            trace,
            qlog::events::EventImportance::Extra,
            config.writer,
        );

        streamer.start_log()?;
        Ok(Self(Arc::new(Mutex::new(streamer))))
    }

    fn emit_event(&self, event: EventData, now: Instant) {
        self.emit_event_with_tuple_id(event, now, None);
    }

    fn emit_event_with_tuple_id(&self, event: EventData, now: Instant, tuple: Option<String>) {
        // Time will be overwritten by `add_event_with_instant`
        let mut event = Event::with_time(0.0, event);
        event.tuple = tuple;
        let mut qlog_streamer = self.0.lock().unwrap();
        if let Err(e) = qlog_streamer.add_event_with_instant(event, now) {
            warn!("could not emit qlog event: {e}");
        }
    }
}

/// A [`QlogStream`] that may be either dynamically disabled or compiled out entirely
#[derive(Clone, Default)]
pub(crate) struct QlogSink {
    #[cfg(feature = "qlog")]
    stream: Option<QlogStream>,
}

impl QlogSink {
    #[cfg(feature = "qlog")]
    pub(crate) fn new(
        config: QlogConfig,
        initial_dst_cid: ConnectionId,
        side: Side,
        now: Instant,
    ) -> Self {
        let stream = QlogStream::new(config, initial_dst_cid, side, now)
            .inspect_err(|err| warn!("failed to initialize qlog streamer: {err}"))
            .ok();
        Self { stream }
    }

    pub(crate) fn emit_connection_started(
        &self,
        now: Instant,
        loc_cid: ConnectionId,
        rem_cid: ConnectionId,
        remote: SocketAddr,
        local_ip: Option<IpAddr>,
        transport_params: &TransportParameters,
    ) {
        #[cfg(feature = "qlog")]
        {
            let Some(stream) = self.stream.as_ref() else {
                return;
            };
            stream.emit_event(
                EventData::ConnectionStarted(ConnectionStarted {
                    local: tuple_endpoint_info(local_ip, None, Some(loc_cid)),
                    remote: tuple_endpoint_info(
                        Some(remote.ip()),
                        Some(remote.port()),
                        Some(rem_cid),
                    ),
                }),
                now,
            );

            let params = transport_params.to_qlog(TransportInitiator::Local);
            let event = EventData::ParametersSet(params);
            stream.emit_event(event, now);
        }
    }

    pub(super) fn emit_recovery_metrics(&self, path_id: PathId, path: &mut PathData, now: Instant) {
        #[cfg(feature = "qlog")]
        {
            let Some(stream) = self.stream.as_ref() else {
                return;
            };

            let Some(metrics) = path.qlog_recovery_metrics(path_id) else {
                return;
            };

            stream.emit_event(EventData::MetricsUpdated(metrics), now);
        }
    }

    pub(super) fn emit_packet_lost(
        &self,
        pn: u64,
        info: &SentPacket,
        loss_delay: Duration,
        space: SpaceId,
        now: Instant,
    ) {
        #[cfg(feature = "qlog")]
        {
            let Some(stream) = self.stream.as_ref() else {
                return;
            };

            let event = PacketLost {
                header: Some(PacketHeader {
                    packet_number: Some(pn),
                    packet_type: packet_type(space, false),
                    length: Some(info.size),
                    ..Default::default()
                }),
                frames: None,
                trigger: Some(
                    match info.time_sent.saturating_duration_since(now) >= loss_delay {
                        true => PacketLostTrigger::TimeThreshold,
                        false => PacketLostTrigger::ReorderingThreshold,
                    },
                ),
                is_mtu_probe_packet: None,
            };

            stream.emit_event(EventData::PacketLost(event), now);
        }
    }

    pub(super) fn emit_peer_transport_params_restored(&self, conn: &Connection, now: Instant) {
        #[cfg(feature = "qlog")]
        {
            let Some(stream) = self.stream.as_ref() else {
                return;
            };
            let params = conn.peer_params.to_qlog_restored();
            let event = EventData::ParametersRestored(params);
            stream.emit_event(event, now);
        }
    }

    pub(super) fn emit_peer_transport_params_received(&self, conn: &Connection, now: Instant) {
        #[cfg(feature = "qlog")]
        {
            let Some(stream) = self.stream.as_ref() else {
                return;
            };
            let params = conn.peer_params.to_qlog(TransportInitiator::Remote);
            let event = EventData::ParametersSet(params);
            stream.emit_event(event, now);
        }
    }

    pub(super) fn emit_new_path(&self, path_id: PathId, remote: SocketAddr, now: Instant) {
        #[cfg(feature = "qlog")]
        {
            let Some(stream) = self.stream.as_ref() else {
                return;
            };
            let tuple_id = fmt_tuple_id(path_id.as_u32() as u64);
            let event = TupleAssigned {
                tuple_id,
                tuple_local: None,
                tuple_remote: Some(tuple_endpoint_info(
                    Some(remote.ip()),
                    Some(remote.port()),
                    None,
                )),
            };

            stream.emit_event(EventData::TupleAssigned(event), now);
        }
    }

    pub(super) fn emit_packet_sent(&self, packet: QlogSentPacket, now: Instant) {
        #[cfg(feature = "qlog")]
        {
            let Some(stream) = self.stream.as_ref() else {
                return;
            };
            let tuple_id = packet.inner.header.path_id.map(fmt_tuple_id);
            stream.emit_event_with_tuple_id(EventData::PacketSent(packet.inner), now, tuple_id);
        }
    }

    pub(super) fn emit_packet_received(&self, packet: QlogRecvPacket, now: Instant) {
        #[cfg(feature = "qlog")]
        {
            let Some(stream) = self.stream.as_ref() else {
                return;
            };
            let mut packet = packet;
            packet.emit_padding();
            let tuple_id = packet.inner.header.path_id.map(fmt_tuple_id);
            let event = packet.inner;
            stream.emit_event_with_tuple_id(EventData::PacketReceived(event), now, tuple_id);
        }
    }

    /// Emits a timer event.
    ///
    /// This function is not public: Instead, create a [`QlogSinkWithTime`] via [`Self::with_time`] and use
    /// its `emit_timer_` methods.
    #[cfg(feature = "qlog")]
    fn emit_timer(&self, timer: Timer, op: TimerOp, now: Instant) {
        let Some(stream) = self.stream.as_ref() else {
            return;
        };

        let timer_type: Option<TimerType> = match timer {
            Timer::Conn(conn_timer) => match conn_timer {
                ConnTimer::Idle => Some(QlogTimerType::IdleTimeout.into()),
                ConnTimer::Close => Some(TimerType::custom("close")),
                ConnTimer::KeyDiscard => Some(TimerType::custom("key_discard")),
                ConnTimer::KeepAlive => Some(TimerType::custom("keep_alive")),
                ConnTimer::PushNewCid => Some(TimerType::custom("push_new_cid")),
            },
            Timer::PerPath(_, path_timer) => match path_timer {
                PathTimer::LossDetection => Some(QlogTimerType::LossTimeout.into()),
                PathTimer::PathIdle => Some(TimerType::custom("path_idle")),
                PathTimer::PathValidation => Some(QlogTimerType::PathValidation.into()),
                PathTimer::PathChallengeLost => Some(TimerType::custom("path_challenge_lost")),
                PathTimer::PathOpen => Some(TimerType::custom("path_open")),
                PathTimer::PathKeepAlive => Some(TimerType::custom("path_keep_alive")),
                PathTimer::Pacing => Some(TimerType::custom("pacing")),
                PathTimer::MaxAckDelay => Some(QlogTimerType::Ack.into()),
                PathTimer::PathAbandoned => Some(TimerType::custom("path_abandoned")),
                PathTimer::PathNotAbandoned => Some(TimerType::custom("path_not_abandoned")),
            },
        };

        let Some(timer_type) = timer_type else {
            return;
        };

        let delta = match op {
            TimerOp::Set(instant) => instant
                .checked_duration_since(now)
                .map(|dur| dur.as_secs_f32() * 1000.),
            _ => None,
        };
        let path_id = match timer {
            Timer::Conn(_) => None,
            Timer::PerPath(path_id, _) => Some(path_id.as_u32() as u64),
        };

        let event_type = match op {
            TimerOp::Set(_) => TimerEventType::Set,
            TimerOp::Expire => TimerEventType::Expired,
            TimerOp::Cancelled => TimerEventType::Cancelled,
        };

        let event = TimerUpdated {
            path_id,
            timer_type: Some(timer_type),
            timer_id: None,
            packet_number_space: None,
            event_type,
            delta,
        };
        stream.emit_event(EventData::TimerUpdated(event), now);
    }

    /// Returns a [`QlogSinkWithTime`] that passes along a `now` timestamp.
    ///
    /// This may be used if you want to pass a [`QlogSink`] downwards together with the current
    /// `now` timestamp, to not have to pass the latter separately as an additional argument just
    /// for qlog support.
    pub(super) fn with_time(&self, now: Instant) -> QlogSinkWithTime<'_> {
        #[cfg(feature = "qlog")]
        let s = QlogSinkWithTime { sink: self, now };
        #[cfg(not(feature = "qlog"))]
        let s = QlogSinkWithTime {
            _phantom: PhantomData,
        };
        s
    }
}

/// A [`QlogSink`] with a `now` timestamp.
pub(super) struct QlogSinkWithTime<'a> {
    #[cfg(feature = "qlog")]
    sink: &'a QlogSink,
    #[cfg(feature = "qlog")]
    now: Instant,
    #[cfg(not(feature = "qlog"))]
    _phantom: PhantomData<&'a ()>,
}

impl<'a> QlogSinkWithTime<'a> {
    pub(super) fn emit_timer_stop(&self, timer: Timer) {
        #[cfg(feature = "qlog")]
        self.sink.emit_timer(timer, TimerOp::Cancelled, self.now)
    }

    pub(super) fn emit_timer_set(&self, timer: Timer, expire_at: Instant) {
        #[cfg(feature = "qlog")]
        self.sink
            .emit_timer(timer, TimerOp::Set(expire_at), self.now)
    }

    pub(super) fn emit_timer_expire(&self, timer: Timer) {
        #[cfg(feature = "qlog")]
        self.sink.emit_timer(timer, TimerOp::Expire, self.now)
    }
}

#[cfg(feature = "qlog")]
enum TimerOp {
    Set(Instant),
    Expire,
    Cancelled,
}

/// Info about a sent packet. Zero-sized struct if `qlog` feature is not enabled.
#[derive(Default)]
pub(crate) struct QlogSentPacket {
    #[cfg(feature = "qlog")]
    inner: PacketSent,
}

impl QlogSentPacket {
    /// Sets data from the packet header.
    pub(crate) fn header(
        &mut self,
        header: &Header,
        pn: Option<u64>,
        space: SpaceId,
        is_0rtt: bool,
        path_id: PathId,
    ) {
        #[cfg(feature = "qlog")]
        {
            self.inner.header.scid = header.src_cid().map(stringify_cid);
            self.inner.header.dcid = Some(stringify_cid(header.dst_cid()));
            self.inner.header.packet_number = pn;
            self.inner.header.packet_type = packet_type(space, is_0rtt);
            self.inner.header.path_id = Some(path_id.as_u32() as u64);
        }
    }

    /// Adds a frame by pushing a [`Frame`].
    pub(crate) fn frame(&mut self, frame: &Frame) {
        #[cfg(feature = "qlog")]
        self.frame_raw(frame.to_qlog())
    }

    /// Adds a PADDING frame.
    ///
    /// This is a no-op if the `qlog` feature is not enabled.
    pub(crate) fn frame_padding(&mut self, count: usize) {
        #[cfg(feature = "qlog")]
        self.frame_raw(QuicFrame::Padding {
            raw: Some(RawInfo {
                length: Some(count as u64),
                payload_length: Some(count as u64),
                data: None,
            }),
        });
    }

    /// Adds an ACK frame.
    ///
    /// This is a no-op if the `qlog` feature is not enabled.
    pub(crate) fn frame_ack(
        &mut self,
        delay: u64,
        ranges: &ArrayRangeSet,
        ecn: Option<&EcnCounts>,
    ) {
        #[cfg(feature = "qlog")]
        self.frame_raw(QuicFrame::Ack {
            ack_delay: Some(delay as f32),
            acked_ranges: Some(AckedRanges::Double(
                ranges
                    .iter()
                    .map(|range| (range.start, range.end))
                    .collect(),
            )),
            ect1: ecn.map(|e| e.ect1),
            ect0: ecn.map(|e| e.ect0),
            ce: ecn.map(|e| e.ce),
            raw: None,
        });
    }

    /// Adds a PATH_ACK frame.
    ///
    /// This is a no-op if the `qlog` feature is not enabled.
    pub(crate) fn frame_path_ack(
        &mut self,
        path_id: PathId,
        delay: u64,
        ranges: &ArrayRangeSet,
        ecn: Option<&EcnCounts>,
    ) {
        #[cfg(feature = "qlog")]
        self.frame_raw(QuicFrame::PathAck {
            path_id: path_id.as_u32() as u64,
            ack_delay: Some(delay as f32),
            acked_ranges: Some(AckedRanges::Double(
                ranges
                    .iter()
                    .map(|range| (range.start, range.end))
                    .collect(),
            )),
            ect1: ecn.map(|e| e.ect1),
            ect0: ecn.map(|e| e.ect0),
            ce: ecn.map(|e| e.ce),
            raw: None,
        });
    }

    /// Adds a DATAGRAM frame.
    ///
    /// This is a no-op if the `qlog` feature is not enabled.
    pub(crate) fn frame_datagram(&mut self, len: u64) {
        #[cfg(feature = "qlog")]
        self.frame_raw(QuicFrame::Datagram {
            raw: Some(RawInfo {
                length: Some(len),
                ..Default::default()
            }),
        });
    }

    /// Adds a STREAM frame.
    ///
    /// This is a no-op if the `qlog` feature is not enabled.
    pub(crate) fn frame_stream(&mut self, meta: &StreamMeta) {
        #[cfg(feature = "qlog")]
        self.frame_raw(QuicFrame::Stream {
            stream_id: meta.id.into(),
            offset: Some(meta.offsets.start),
            fin: Some(meta.fin),
            raw: Some(RawInfo {
                length: Some(meta.offsets.end - meta.offsets.start),
                ..Default::default()
            }),
        });
    }

    /// Adds a frame by pushing a [`QuicFrame`].
    ///
    /// This function is only available if the `qlog` feature is enabled, because constructing a [`QuicFrame`] may involve
    /// calculations which shouldn't be performed if the `qlog` feature is disabled.
    #[cfg(feature = "qlog")]
    fn frame_raw(&mut self, frame: QuicFrame) {
        self.inner.frames.get_or_insert_default().push(frame);
    }

    /// Finalizes the packet by setting the final packet length (after encryption).
    pub(super) fn finalize(&mut self, len: usize) {
        #[cfg(feature = "qlog")]
        {
            self.inner.header.length = Some(len as u16);
        }
    }
}

/// Info about a received packet. Zero-sized struct if `qlog` feature is not enabled.
pub(crate) struct QlogRecvPacket {
    #[cfg(feature = "qlog")]
    inner: PacketReceived,
    #[cfg(feature = "qlog")]
    padding: usize,
}

impl QlogRecvPacket {
    /// Creates a new [`QlogRecvPacket`]. Noop if `qlog` feature is not enabled.
    ///
    /// `len` is the packet's full length (before decryption).
    pub(crate) fn new(len: usize) -> Self {
        #[cfg(not(feature = "qlog"))]
        let this = Self {};

        #[cfg(feature = "qlog")]
        let this = {
            let mut this = Self {
                inner: Default::default(),
                padding: 0,
            };
            this.inner.header.length = Some(len as u16);
            this
        };

        this
    }

    /// Adds info from the packet header.
    pub(crate) fn header(&mut self, header: &Header, pn: Option<u64>, path_id: PathId) {
        #[cfg(feature = "qlog")]
        {
            let is_0rtt = !header.is_1rtt();
            self.inner.header.scid = header.src_cid().map(stringify_cid);
            self.inner.header.dcid = Some(stringify_cid(header.dst_cid()));
            self.inner.header.packet_number = pn;
            self.inner.header.packet_type = packet_type(header.space(), is_0rtt);
            self.inner.header.path_id = Some(path_id.as_u32() as u64);
        }
    }

    /// Adds a frame.
    pub(crate) fn frame(&mut self, frame: &Frame) {
        #[cfg(feature = "qlog")]
        {
            if matches!(frame, crate::Frame::Padding) {
                self.padding += 1;
            } else {
                self.emit_padding();
                self.inner
                    .frames
                    .get_or_insert_default()
                    .push(frame.to_qlog())
            }
        }
    }

    #[cfg(feature = "qlog")]
    fn emit_padding(&mut self) {
        if self.padding > 0 {
            self.inner
                .frames
                .get_or_insert_default()
                .push(QuicFrame::Padding {
                    raw: Some(RawInfo {
                        length: Some(self.padding as u64),
                        payload_length: Some(self.padding as u64),
                        data: None,
                    }),
                });
            self.padding = 0;
        }
    }
}

#[cfg(feature = "qlog")]
impl Frame {
    /// Converts a [`crate::Frame`] into a [`QuicFrame`].
    pub(crate) fn to_qlog(&self) -> QuicFrame {
        match self {
            Self::Padding => QuicFrame::Padding {
                raw: Some(RawInfo {
                    length: None,
                    payload_length: Some(1),
                    data: None,
                }),
            },
            Self::Ping => QuicFrame::Ping { raw: None },
            Self::Ack(f) => QuicFrame::Ack {
                ack_delay: Some(f.delay as f32),
                acked_ranges: Some(AckedRanges::Double(
                    f.iter()
                        .map(|range| (*range.start(), *range.end()))
                        .collect(),
                )),
                ect1: f.ecn.as_ref().map(|e| e.ect1),
                ect0: f.ecn.as_ref().map(|e| e.ect0),
                ce: f.ecn.as_ref().map(|e| e.ce),
                raw: None,
            },
            Self::ResetStream(f) => QuicFrame::ResetStream {
                stream_id: f.id.into(),
                error_code: Some(f.error_code.into_inner()),
                final_size: f.final_offset.into(),
                error: ApplicationError::Unknown,
                raw: None,
            },
            Self::StopSending(f) => QuicFrame::StopSending {
                stream_id: f.id.into(),
                error_code: Some(f.error_code.into_inner()),
                error: ApplicationError::Unknown,
                raw: None,
            },
            Self::Crypto(f) => QuicFrame::Crypto {
                offset: f.offset,
                raw: Some(RawInfo {
                    length: Some(f.data.len() as u64),
                    ..Default::default()
                }),
            },
            Self::NewToken(f) => QuicFrame::NewToken {
                token: qlog::Token {
                    ty: Some(TokenType::Retry),
                    raw: Some(RawInfo {
                        data: HexSlice::maybe_string(Some(&f.token)),
                        length: Some(f.token.len() as u64),
                        payload_length: None,
                    }),
                    details: None,
                },
                raw: None,
            },
            Self::Stream(s) => QuicFrame::Stream {
                stream_id: s.id.into(),
                offset: Some(s.offset),
                fin: Some(s.fin),
                raw: Some(RawInfo {
                    length: Some(s.data.len() as u64),
                    ..Default::default()
                }),
            },
            Self::MaxData(v) => QuicFrame::MaxData {
                maximum: (*v).into(),
                raw: None,
            },
            Self::MaxStreamData { id, offset } => QuicFrame::MaxStreamData {
                stream_id: (*id).into(),
                maximum: *offset,
                raw: None,
            },
            Self::MaxStreams { dir, count } => QuicFrame::MaxStreams {
                maximum: *count,
                stream_type: (*dir).into(),
                raw: None,
            },
            Self::DataBlocked { offset } => QuicFrame::DataBlocked {
                limit: *offset,
                raw: None,
            },
            Self::StreamDataBlocked { id, offset } => QuicFrame::StreamDataBlocked {
                stream_id: (*id).into(),
                limit: *offset,
                raw: None,
            },
            Self::StreamsBlocked { dir, limit } => QuicFrame::StreamsBlocked {
                stream_type: (*dir).into(),
                limit: *limit,
                raw: None,
            },
            Self::NewConnectionId(f) => QuicFrame::NewConnectionId {
                sequence_number: f.sequence,
                retire_prior_to: f.retire_prior_to,
                connection_id_length: Some(f.id.len() as u8),
                connection_id: f.id.to_string(),
                stateless_reset_token: Some(f.reset_token.to_string()),
                raw: None,
            },
            Self::RetireConnectionId(f) => QuicFrame::RetireConnectionId {
                sequence_number: f.sequence,
                raw: None,
            },
            Self::PathChallenge(token) => QuicFrame::PathChallenge {
                data: Some(token.to_string()),
                raw: None,
            },
            Self::PathResponse(token) => QuicFrame::PathResponse {
                data: Some(token.to_string()),
                raw: None,
            },
            Self::Close(close) => match close {
                Close::Connection(f) => {
                    let (error, error_code) = transport_error(f.error_code);
                    let error = error.map(|transport_error| {
                        ConnectionClosedFrameError::TransportError(transport_error)
                    });
                    QuicFrame::ConnectionClose {
                        error_space: Some(ErrorSpace::TransportError),
                        error,
                        error_code,
                        reason: String::from_utf8(f.reason.to_vec()).ok(),
                        reason_bytes: None,
                        trigger_frame_type: None,
                    }
                }
                Close::Application(f) => QuicFrame::ConnectionClose {
                    error_space: Some(ErrorSpace::ApplicationError),
                    error: None,
                    error_code: Some(f.error_code.into_inner()),
                    reason: String::from_utf8(f.reason.to_vec()).ok(),
                    reason_bytes: None,
                    trigger_frame_type: None,
                },
            },
            Self::Datagram(d) => QuicFrame::Datagram {
                raw: Some(RawInfo {
                    length: Some(d.data.len() as u64),
                    ..Default::default()
                }),
            },
            Self::HandshakeDone => QuicFrame::HandshakeDone { raw: None },
            Self::PathAck(ack) => QuicFrame::PathAck {
                path_id: ack.path_id.as_u32().into(),
                ack_delay: Some(ack.delay as f32),
                ect1: ack.ecn.as_ref().map(|e| e.ect1),
                ect0: ack.ecn.as_ref().map(|e| e.ect0),
                ce: ack.ecn.as_ref().map(|e| e.ce),
                raw: None,
                acked_ranges: Some(AckedRanges::Double(
                    ack.into_iter()
                        .map(|range| (*range.start(), *range.end()))
                        .collect(),
                )),
            },
            Self::PathAbandon(frame) => QuicFrame::PathAbandon {
                path_id: frame.path_id.as_u32().into(),
                error_code: frame.error_code.into(),
                raw: None,
            },
            Self::PathAvailable(frame) => QuicFrame::PathStatusAvailable {
                path_id: frame.path_id.as_u32().into(),
                path_status_sequence_number: frame.status_seq_no.into(),
                raw: None,
            },
            Self::PathBackup(frame) => QuicFrame::PathStatusBackup {
                path_id: frame.path_id.as_u32().into(),
                path_status_sequence_number: frame.status_seq_no.into(),
                raw: None,
            },
            Self::PathsBlocked(frame) => QuicFrame::PathsBlocked {
                maximum_path_id: frame.0.as_u32().into(),
                raw: None,
            },
            Self::PathCidsBlocked(frame) => QuicFrame::PathCidsBlocked {
                path_id: frame.path_id.as_u32().into(),
                next_sequence_number: frame.next_seq.into(),
                raw: None,
            },
            Self::MaxPathId(id) => QuicFrame::MaxPathId {
                maximum_path_id: id.0.as_u32().into(),
                raw: None,
            },
            Self::AckFrequency(f) => QuicFrame::AckFrequency {
                sequence_number: f.sequence.into_inner(),
                ack_eliciting_threshold: f.ack_eliciting_threshold.into_inner(),
                requested_max_ack_delay: f.request_max_ack_delay.into_inner(),
                reordering_threshold: f.reordering_threshold.into_inner(),
                raw: None,
            },
            Self::ImmediateAck => QuicFrame::ImmediateAck { raw: None },
            Self::ObservedAddr(f) => QuicFrame::ObservedAddress {
                sequence_number: f.seq_no.into_inner(),
                ip_v4: match f.ip {
                    IpAddr::V4(ipv4_addr) => Some(ipv4_addr.to_string()),
                    IpAddr::V6(ipv6_addr) => None,
                },
                ip_v6: match f.ip {
                    IpAddr::V4(ipv4_addr) => None,
                    IpAddr::V6(ipv6_addr) => Some(ipv6_addr.to_string()),
                },
                port: f.port,
                raw: None,
            },
            Self::AddAddress(f) => QuicFrame::AddAddress {
                sequence_number: f.seq_no.into_inner(),
                ip_v4: match f.ip {
                    IpAddr::V4(ipv4_addr) => Some(ipv4_addr.to_string()),
                    IpAddr::V6(ipv6_addr) => None,
                },
                ip_v6: match f.ip {
                    IpAddr::V4(ipv4_addr) => None,
                    IpAddr::V6(ipv6_addr) => Some(ipv6_addr.to_string()),
                },
                port: f.port,
            },
            Self::ReachOut(f) => QuicFrame::ReachOut {
                round: f.round.into_inner(),
                ip_v4: match f.ip {
                    IpAddr::V4(ipv4_addr) => Some(ipv4_addr.to_string()),
                    IpAddr::V6(ipv6_addr) => None,
                },
                ip_v6: match f.ip {
                    IpAddr::V4(ipv4_addr) => None,
                    IpAddr::V6(ipv6_addr) => Some(ipv6_addr.to_string()),
                },
                port: f.port,
            },
            Self::RemoveAddress(f) => QuicFrame::RemoveAddress {
                sequence_number: f.seq_no.into_inner(),
            },
        }
    }
}

#[cfg(feature = "qlog")]
impl From<crate::Dir> for StreamType {
    fn from(value: crate::Dir) -> Self {
        match value {
            crate::Dir::Bi => Self::Bidirectional,
            crate::Dir::Uni => Self::Unidirectional,
        }
    }
}

#[cfg(feature = "qlog")]
fn packet_type(space: SpaceId, is_0rtt: bool) -> PacketType {
    match space {
        SpaceId::Initial => PacketType::Initial,
        SpaceId::Handshake => PacketType::Handshake,
        SpaceId::Data if is_0rtt => PacketType::ZeroRtt,
        SpaceId::Data => PacketType::OneRtt,
    }
}

#[cfg(feature = "qlog")]
fn stringify_cid(cid: ConnectionId) -> String {
    format!("{cid}")
}

#[cfg(feature = "qlog")]
fn tuple_endpoint_info(
    ip: Option<IpAddr>,
    port: Option<u16>,
    cid: Option<ConnectionId>,
) -> TupleEndpointInfo {
    let (ip_v4, port_v4, ip_v6, port_v6) = match ip {
        Some(addr) => match addr {
            IpAddr::V4(ipv4_addr) => (Some(ipv4_addr.to_string()), port, None, None),
            IpAddr::V6(ipv6_addr) => (None, None, Some(ipv6_addr.to_string()), port),
        },
        None => (None, None, None, None),
    };
    TupleEndpointInfo {
        ip_v4,
        port_v4,
        ip_v6,
        port_v6,
        connection_ids: cid.map(|cid| vec![cid.to_string()]),
    }
}

#[cfg(feature = "qlog")]
fn transport_error(code: TransportErrorCode) -> (Option<quic::TransportError>, Option<u64>) {
    let transport_error = match code {
        TransportErrorCode::NO_ERROR => Some(quic::TransportError::NoError),
        TransportErrorCode::INTERNAL_ERROR => Some(quic::TransportError::InternalError),
        TransportErrorCode::CONNECTION_REFUSED => Some(quic::TransportError::ConnectionRefused),
        TransportErrorCode::FLOW_CONTROL_ERROR => Some(quic::TransportError::FlowControlError),
        TransportErrorCode::STREAM_LIMIT_ERROR => Some(quic::TransportError::StreamLimitError),
        TransportErrorCode::STREAM_STATE_ERROR => Some(quic::TransportError::StreamStateError),
        TransportErrorCode::FINAL_SIZE_ERROR => Some(quic::TransportError::FinalSizeError),
        TransportErrorCode::FRAME_ENCODING_ERROR => Some(quic::TransportError::FrameEncodingError),
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR => {
            Some(quic::TransportError::TransportParameterError)
        }
        TransportErrorCode::CONNECTION_ID_LIMIT_ERROR => {
            Some(quic::TransportError::ConnectionIdLimitError)
        }
        TransportErrorCode::PROTOCOL_VIOLATION => Some(quic::TransportError::ProtocolViolation),
        TransportErrorCode::INVALID_TOKEN => Some(quic::TransportError::InvalidToken),
        TransportErrorCode::APPLICATION_ERROR => Some(quic::TransportError::ApplicationError),
        TransportErrorCode::CRYPTO_BUFFER_EXCEEDED => {
            Some(quic::TransportError::CryptoBufferExceeded)
        }
        TransportErrorCode::KEY_UPDATE_ERROR => Some(quic::TransportError::KeyUpdateError),
        TransportErrorCode::AEAD_LIMIT_REACHED => Some(quic::TransportError::AeadLimitReached),
        TransportErrorCode::NO_VIABLE_PATH => Some(quic::TransportError::NoViablePath),
        // multipath
        TransportErrorCode::APPLICATION_ABANDON_PATH => {
            Some(quic::TransportError::ApplicationAbandonPath)
        }
        TransportErrorCode::PATH_RESOURCE_LIMIT_REACHED => {
            Some(quic::TransportError::PathResourceLimitReached)
        }
        TransportErrorCode::PATH_UNSTABLE_OR_POOR => Some(quic::TransportError::PathUnstableOrPoor),
        TransportErrorCode::NO_CID_AVAILABLE_FOR_PATH => {
            Some(quic::TransportError::NoCidsAvailableForPath)
        }
        _ => None,
    };
    let code = match transport_error {
        None => Some(code.into()),
        Some(_) => None,
    };
    (transport_error, code)
}

#[cfg(feature = "qlog")]
fn fmt_tuple_id(path_id: u64) -> String {
    format!("p{path_id}")
}

#[cfg(feature = "qlog")]
impl TransportParameters {
    fn to_qlog(self, initiator: TransportInitiator) -> ParametersSet {
        ParametersSet {
            initiator: Some(initiator),
            resumption_allowed: None,
            early_data_enabled: None,
            tls_cipher: None,
            original_destination_connection_id: self
                .original_dst_cid
                .as_ref()
                .map(ToString::to_string),
            initial_source_connection_id: self.initial_src_cid.as_ref().map(ToString::to_string),
            retry_source_connection_id: self.retry_src_cid.as_ref().map(ToString::to_string),
            stateless_reset_token: self.stateless_reset_token.as_ref().map(ToString::to_string),
            disable_active_migration: Some(self.disable_active_migration),
            max_idle_timeout: Some(self.max_idle_timeout.into()),
            max_udp_payload_size: Some(self.max_udp_payload_size.into()),
            ack_delay_exponent: Some(self.ack_delay_exponent.into()),
            max_ack_delay: Some(self.max_ack_delay.into()),
            active_connection_id_limit: Some(self.active_connection_id_limit.into()),
            initial_max_data: Some(self.initial_max_data.into()),
            initial_max_stream_data_bidi_local: Some(
                self.initial_max_stream_data_bidi_local.into(),
            ),
            initial_max_stream_data_bidi_remote: Some(
                self.initial_max_stream_data_bidi_remote.into(),
            ),
            initial_max_stream_data_uni: Some(self.initial_max_stream_data_uni.into()),
            initial_max_streams_bidi: Some(self.initial_max_streams_bidi.into()),
            initial_max_streams_uni: Some(self.initial_max_streams_uni.into()),
            preferred_address: self.preferred_address.as_ref().map(Into::into),
            min_ack_delay: self.min_ack_delay.map(Into::into),
            address_discovery: self.address_discovery_role.to_qlog(),
            initial_max_path_id: self.initial_max_path_id.map(|p| p.as_u32() as u64),
            max_remote_nat_traversal_addresses: self
                .max_remote_nat_traversal_addresses
                .map(|v| u64::from(v.get())),
            max_datagram_frame_size: self.max_datagram_frame_size.map(Into::into),
            grease_quic_bit: Some(self.grease_quic_bit),
            unknown_parameters: Default::default(),
        }
    }

    fn to_qlog_restored(self) -> ParametersRestored {
        ParametersRestored {
            disable_active_migration: Some(self.disable_active_migration),
            max_idle_timeout: Some(self.max_idle_timeout.into()),
            max_udp_payload_size: Some(self.max_udp_payload_size.into()),
            active_connection_id_limit: Some(self.active_connection_id_limit.into()),
            initial_max_data: Some(self.initial_max_data.into()),
            initial_max_stream_data_bidi_local: Some(
                self.initial_max_stream_data_bidi_local.into(),
            ),
            initial_max_stream_data_bidi_remote: Some(
                self.initial_max_stream_data_bidi_remote.into(),
            ),
            initial_max_stream_data_uni: Some(self.initial_max_stream_data_uni.into()),
            initial_max_streams_bidi: Some(self.initial_max_streams_bidi.into()),
            initial_max_streams_uni: Some(self.initial_max_streams_uni.into()),
            max_datagram_frame_size: self.max_datagram_frame_size.map(Into::into),
            grease_quic_bit: Some(self.grease_quic_bit),
        }
    }
}

#[cfg(feature = "qlog")]
impl From<&crate::transport_parameters::PreferredAddress> for PreferredAddress {
    fn from(value: &crate::transport_parameters::PreferredAddress) -> Self {
        let port_v4 = value.address_v4.map(|addr| addr.port()).unwrap_or_default();
        let port_v6 = value.address_v6.map(|addr| addr.port()).unwrap_or_default();
        let ip_v4 = value
            .address_v4
            .map(|addr| addr.ip().to_string())
            .unwrap_or_default();
        let ip_v6 = value
            .address_v6
            .map(|addr| addr.ip().to_string())
            .unwrap_or_default();
        let connection_id = value.connection_id.to_string();
        let stateless_reset_token = value.stateless_reset_token.to_string();

        Self {
            ip_v4,
            ip_v6,
            port_v4,
            port_v6,
            connection_id,
            stateless_reset_token,
        }
    }
}

#[cfg(feature = "qlog")]
impl crate::address_discovery::Role {
    fn to_qlog(self) -> Option<AddressDiscoveryRole> {
        match self {
            Self::SendOnly => Some(AddressDiscoveryRole::SendOnly),
            Self::ReceiveOnly => Some(AddressDiscoveryRole::ReceiveOnly),
            Self::Both => Some(AddressDiscoveryRole::Both),
            Self::Disabled => None,
        }
    }
}
