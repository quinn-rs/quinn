//! Implements support for emitting qlog events.
//!
//! This uses the [`qlog`] crate to emit qlog events. The qlog crate, and thus this implementation,
//! is currently based on [draft-ietf-quic-qlog-main-schema-02] an [draft-ietf-quic-qlog-quic-events-05].
//!
//! [draft-ietf-quic-qlog-main-schema-02]: https://www.ietf.org/archive/id/draft-ietf-quic-qlog-main-schema-02.html
//! [draft-ietf-quic-qlog-quic-events-05]: https://www.ietf.org/archive/id/draft-ietf-quic-qlog-quic-events-05.html

// Function bodies in this module are regularly cfg'd out
#![allow(unused_variables)]

#[cfg(feature = "qlog")]
use std::sync::{Arc, Mutex};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

#[cfg(feature = "qlog")]
use qlog::{
    events::{
        Event, EventData, RawInfo,
        connectivity::ConnectionStarted,
        quic::{
            AckedRanges, PacketHeader, PacketLost, PacketLostTrigger, PacketReceived, PacketSent,
            PacketType, QuicFrame, StreamType,
        },
    },
    streamer::QlogStreamer,
};
#[cfg(feature = "qlog")]
use tracing::warn;

#[cfg(feature = "qlog")]
use crate::FrameType;
use crate::{
    Connection, ConnectionId, Frame, Instant, PathId,
    connection::{PathData, SentPacket},
    frame::{EcnCounts, StreamMeta},
    packet::{Header, SpaceId},
    range_set::ArrayRangeSet,
};

/// Shareable handle to a single qlog output stream
#[cfg(feature = "qlog")]
#[derive(Clone)]
pub struct QlogStream(pub(crate) Arc<Mutex<QlogStreamer>>);

#[cfg(feature = "qlog")]
impl QlogStream {
    fn emit_event(&self, initial_dst_cid: ConnectionId, event: EventData, now: Instant) {
        // Time will be overwritten by `add_event_with_instant`
        let mut event = Event::with_time(0.0, event);
        event.group_id = Some(initial_dst_cid.to_string());

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
    pub(crate) fn is_enabled(&self) -> bool {
        #[cfg(feature = "qlog")]
        {
            self.stream.is_some()
        }
        #[cfg(not(feature = "qlog"))]
        {
            false
        }
    }

    pub(super) fn emit_connection_started(
        &self,
        now: Instant,
        loc_cid: ConnectionId,
        rem_cid: ConnectionId,
        remote: SocketAddr,
        local_ip: Option<IpAddr>,
        initial_dst_cid: ConnectionId,
    ) {
        #[cfg(feature = "qlog")]
        {
            let Some(stream) = self.stream.as_ref() else {
                return;
            };
            // TODO: Review fields. The standard has changed since.
            stream.emit_event(
                initial_dst_cid,
                EventData::ConnectionStarted(ConnectionStarted {
                    ip_version: Some(String::from(match remote.ip() {
                        IpAddr::V4(_) => "v4",
                        IpAddr::V6(_) => "v6",
                    })),
                    src_ip: local_ip.map(|addr| addr.to_string()).unwrap_or_default(),
                    dst_ip: remote.ip().to_string(),
                    protocol: None,
                    src_port: None,
                    dst_port: Some(remote.port()),
                    src_cid: Some(loc_cid.to_string()),
                    dst_cid: Some(rem_cid.to_string()),
                }),
                now,
            );
        }
    }

    pub(super) fn emit_recovery_metrics(
        &self,
        pto_count: u32,
        path: &mut PathData,
        now: Instant,
        initial_dst_cid: ConnectionId,
    ) {
        #[cfg(feature = "qlog")]
        {
            let Some(stream) = self.stream.as_ref() else {
                return;
            };

            let Some(metrics) = path.qlog_recovery_metrics(pto_count) else {
                return;
            };

            stream.emit_event(initial_dst_cid, EventData::MetricsUpdated(metrics), now);
        }
    }

    pub(super) fn emit_packet_lost(
        &self,
        pn: u64,
        info: &SentPacket,
        loss_delay: Duration,
        space: SpaceId,
        now: Instant,
        initial_dst_cid: ConnectionId,
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
            };

            stream.emit_event(initial_dst_cid, EventData::PacketLost(event), now);
        }
    }

    pub(super) fn emit_packet_sent(&self, conn: &Connection, packet: QlogSentPacket, now: Instant) {
        #[cfg(feature = "qlog")]
        {
            let Some(stream) = self.stream.as_ref() else {
                return;
            };
            stream.emit_event(
                conn.initial_dst_cid,
                EventData::PacketSent(packet.inner),
                now,
            );
        }
    }

    pub(super) fn emit_packet_received(
        &self,
        conn: &Connection,
        packet: QlogRecvPacket,
        now: Instant,
    ) {
        #[cfg(feature = "qlog")]
        {
            let Some(stream) = self.stream.as_ref() else {
                return;
            };
            let mut packet = packet;
            packet.emit_padding();
            let event = packet.inner;
            stream.emit_event(conn.initial_dst_cid, EventData::PacketReceived(event), now);
        }
    }
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
    ) {
        #[cfg(feature = "qlog")]
        {
            self.inner.header.scid = header.src_cid().map(stringify_cid);
            self.inner.header.dcid = Some(stringify_cid(header.dst_cid()));
            self.inner.header.packet_number = pn;
            self.inner.header.packet_type = packet_type(space, is_0rtt);
        }
    }

    /// Adds a frame by pushing a [`Frame`].
    ///
    /// This is a no-op if the `qlog` feature is not enabled.
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
            length: Some(count as u32),
            payload_length: count as u32,
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
            length: None,
            payload_length: None,
        });
    }

    /// Adds a PATH_ACK frame.
    ///
    /// This is a no-op if the `qlog` feature is not enabled.
    pub(crate) fn frame_path_ack(
        &mut self,
        _path_id: PathId,
        _delay: u64,
        _ranges: &ArrayRangeSet,
        _ecn: Option<&EcnCounts>,
    ) {
        // TODO: Add proper support for this frame once we have multipath support in qlog.
        #[cfg(feature = "qlog")]
        self.frame_raw(unknown_frame(&FrameType::PATH_ACK))
    }

    /// Adds a DATAGRAM frame.
    ///
    /// This is a no-op if the `qlog` feature is not enabled.
    pub(crate) fn frame_datagram(&mut self, len: u64) {
        #[cfg(feature = "qlog")]
        self.frame_raw(QuicFrame::Datagram {
            length: len,
            raw: None,
        });
    }

    /// Adds a STREAM frame.
    ///
    /// This is a no-op if the `qlog` feature is not enabled.
    pub(crate) fn frame_stream(&mut self, meta: &StreamMeta) {
        #[cfg(feature = "qlog")]
        self.frame_raw(QuicFrame::Stream {
            stream_id: meta.id.into(),
            offset: meta.offsets.start,
            fin: Some(meta.fin),
            length: meta.offsets.end - meta.offsets.start,
            raw: None,
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
    pub(crate) fn header(&mut self, header: &Header, pn: Option<u64>) {
        #[cfg(feature = "qlog")]
        {
            let is_0rtt = !header.is_1rtt();
            self.inner.header.scid = header.src_cid().map(stringify_cid);
            self.inner.header.dcid = Some(stringify_cid(header.dst_cid()));
            self.inner.header.packet_number = pn;
            self.inner.header.packet_type = packet_type(header.space(), is_0rtt);
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
                    length: Some(self.padding as u32),
                    payload_length: self.padding as u32,
                });
            self.padding = 0;
        }
    }
}

#[cfg(feature = "qlog")]
fn unknown_frame(frame: &FrameType) -> QuicFrame {
    let ty = frame.to_u64();
    QuicFrame::Unknown {
        raw_frame_type: ty,
        frame_type_value: Some(ty),
        raw: Some(RawInfo {
            length: None,
            payload_length: None,
            data: Some(format!("{frame}")),
        }),
    }
}

#[cfg(feature = "qlog")]
impl crate::Frame {
    /// Converts a [`crate::Frame`] into a [`QuicFrame`].
    fn to_qlog(&self) -> QuicFrame {
        use qlog::events::quic::AckedRanges;

        match self {
            Self::Padding => QuicFrame::Padding {
                length: None,
                payload_length: 1,
            },
            Self::Ping => QuicFrame::Ping {
                length: None,
                payload_length: None,
            },
            Self::Ack(ack) => QuicFrame::Ack {
                ack_delay: Some(ack.delay as f32),
                acked_ranges: Some(AckedRanges::Double(
                    ack.iter()
                        .map(|range| (*range.start(), *range.end()))
                        .collect(),
                )),
                ect1: ack.ecn.as_ref().map(|e| e.ect1),
                ect0: ack.ecn.as_ref().map(|e| e.ect0),
                ce: ack.ecn.as_ref().map(|e| e.ce),
                length: None,
                payload_length: None,
            },
            Self::ResetStream(f) => QuicFrame::ResetStream {
                stream_id: f.id.into(),
                error_code: f.error_code.into(),
                final_size: f.final_offset.into(),
                length: None,
                payload_length: None,
            },
            Self::StopSending(f) => QuicFrame::StopSending {
                stream_id: f.id.into(),
                error_code: f.error_code.into(),
                length: None,
                payload_length: None,
            },
            Self::Crypto(c) => QuicFrame::Crypto {
                offset: c.offset,
                length: c.data.len() as u64,
            },
            Self::NewToken(t) => {
                use ::qlog;
                QuicFrame::NewToken {
                    token: qlog::Token {
                        ty: Some(::qlog::TokenType::Retry),
                        raw: Some(qlog::events::RawInfo {
                            data: qlog::HexSlice::maybe_string(Some(&t.token)),
                            length: Some(t.token.len() as u64),
                            payload_length: None,
                        }),
                        details: None,
                    },
                }
            }
            Self::Stream(s) => QuicFrame::Stream {
                stream_id: s.id.into(),
                offset: s.offset,
                length: s.data.len() as u64,
                fin: Some(s.fin),
                raw: None,
            },
            Self::MaxData(v) => QuicFrame::MaxData {
                maximum: (*v).into(),
            },
            Self::MaxStreamData { id, offset } => QuicFrame::MaxStreamData {
                stream_id: (*id).into(),
                maximum: *offset,
            },
            Self::MaxStreams { dir, count } => QuicFrame::MaxStreams {
                maximum: *count,
                stream_type: (*dir).into(),
            },
            Self::DataBlocked { offset } => QuicFrame::DataBlocked { limit: *offset },
            Self::StreamDataBlocked { id, offset } => QuicFrame::StreamDataBlocked {
                stream_id: (*id).into(),
                limit: *offset,
            },
            Self::StreamsBlocked { dir, limit } => QuicFrame::StreamsBlocked {
                stream_type: (*dir).into(),
                limit: *limit,
            },
            Self::NewConnectionId(f) => QuicFrame::NewConnectionId {
                sequence_number: f.sequence as u32,
                retire_prior_to: f.retire_prior_to as u32,
                connection_id_length: Some(f.id.len() as u8),
                connection_id: format!("{}", f.id),
                stateless_reset_token: Some(format!("{}", f.reset_token)),
            },
            Self::RetireConnectionId(f) => QuicFrame::RetireConnectionId {
                sequence_number: f.sequence as u32,
            },
            Self::PathChallenge(_) => QuicFrame::PathChallenge { data: None },
            Self::PathResponse(_) => QuicFrame::PathResponse { data: None },
            Self::Close(close) => QuicFrame::ConnectionClose {
                error_space: None,
                error_code: Some(close.error_code()),
                error_code_value: None,
                reason: None,
                trigger_frame_type: None,
            },
            Self::Datagram(d) => QuicFrame::Datagram {
                length: d.data.len() as u64,
                raw: None,
            },
            Self::HandshakeDone => QuicFrame::HandshakeDone,
            // Extensions and unsupported frames.
            Self::AckFrequency(_)
            | Self::ImmediateAck
            | Self::ObservedAddr(_)
            | Self::PathAck(_)
            | Self::PathAbandon(_)
            | Self::PathAvailable(_)
            | Self::PathBackup(_)
            | Self::MaxPathId(_)
            | Self::PathsBlocked(_)
            | Self::PathCidsBlocked(_)
            | Self::AddAddress(_)
            | Self::ReachOut(_)
            | Self::RemoveAddress(_) => unknown_frame(&self.ty()),
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
impl From<Option<QlogStream>> for QlogSink {
    fn from(stream: Option<QlogStream>) -> Self {
        Self { stream }
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
