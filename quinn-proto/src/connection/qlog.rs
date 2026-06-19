// Function bodies in this module are regularly cfg'd out
#![allow(unused_variables)]

#[cfg(feature = "qlog")]
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[cfg(feature = "qlog")]
use qlog::{
    events::{
        Event, EventData, ExData,
        quic::{
            PacketHeader, PacketLost, PacketLostTrigger, PacketReceived, PacketSent, PacketType,
        },
    },
    streamer::QlogStreamer,
};
#[cfg(feature = "qlog")]
use tracing::warn;

use crate::{
    ConnectionId, Instant,
    connection::{PathData, PathId, SentPacket},
    packet::SpaceId,
};

#[cfg(feature = "qlog")]
const PATH_ID_EX_DATA_KEY: &str = "path_id";

/// Shareable handle to a single qlog output stream
#[cfg(feature = "qlog")]
#[derive(Clone)]
pub struct QlogStream(pub(crate) Arc<Mutex<QlogStreamer>>);

#[cfg(feature = "qlog")]
impl QlogStream {
    fn emit_event(&self, orig_rem_cid: ConnectionId, event: EventData, now: Instant) {
        self.emit_event_ex(orig_rem_cid, event, ExData::default(), now);
    }

    fn emit_event_ex(
        &self,
        orig_rem_cid: ConnectionId,
        event: EventData,
        ex_data: ExData,
        now: Instant,
    ) {
        // Time will be overwritten by `add_event_with_instant`
        let mut event = Event::with_time_ex(0.0, event, ex_data);
        event.group_id = Some(Box::new(orig_rem_cid.to_string()));

        let mut qlog_streamer = self.0.lock().unwrap();
        if let Err(e) = qlog_streamer.add_event_with_instant(event, now) {
            warn!("could not emit qlog event: {e}");
        }
    }
}

#[cfg(feature = "qlog")]
fn insert_path_ex_data(ex_data: &mut ExData, path_id: PathId) {
    ex_data.insert(
        PATH_ID_EX_DATA_KEY.to_string(),
        u64::from(path_id.into_inner()).into(),
    );
}

#[cfg(feature = "qlog")]
fn path_ex_data(path_id: PathId) -> ExData {
    let mut ex_data = ExData::default();
    insert_path_ex_data(&mut ex_data, path_id);
    ex_data
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

    pub(super) fn emit_recovery_metrics(
        &self,
        pto_count: u32,
        path_id: PathId,
        path: &mut PathData,
        now: Instant,
        orig_rem_cid: ConnectionId,
    ) {
        #[cfg(feature = "qlog")]
        {
            let Some(stream) = self.stream.as_ref() else {
                return;
            };

            let Some(mut metrics) = path.qlog_recovery_metrics(pto_count) else {
                return;
            };
            insert_path_ex_data(&mut metrics.ex_data, path_id);

            stream.emit_event(orig_rem_cid, EventData::QuicMetricsUpdated(metrics), now);
        }
    }

    pub(super) fn emit_packet_lost(
        &self,
        pn: u64,
        info: &SentPacket,
        loss_delay: Duration,
        space: SpaceId,
        path_id: PathId,
        now: Instant,
        orig_rem_cid: ConnectionId,
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
                is_mtu_probe_packet: None,
                trigger: Some(
                    match info.time_sent.saturating_duration_since(now) >= loss_delay {
                        true => PacketLostTrigger::TimeThreshold,
                        false => PacketLostTrigger::ReorderingThreshold,
                    },
                ),
            };

            stream.emit_event_ex(
                orig_rem_cid,
                EventData::QuicPacketLost(event),
                path_ex_data(path_id),
                now,
            );
        }
    }

    pub(super) fn emit_packet_sent(
        &self,
        pn: u64,
        len: usize,
        space: SpaceId,
        is_0rtt: bool,
        path_id: PathId,
        now: Instant,
        orig_rem_cid: ConnectionId,
    ) {
        #[cfg(feature = "qlog")]
        {
            let Some(stream) = self.stream.as_ref() else {
                return;
            };

            let event = PacketSent {
                header: PacketHeader {
                    packet_number: Some(pn),
                    packet_type: packet_type(space, is_0rtt),
                    length: Some(len as u16),
                    ..Default::default()
                },
                ..Default::default()
            };

            stream.emit_event_ex(
                orig_rem_cid,
                EventData::QuicPacketSent(event),
                path_ex_data(path_id),
                now,
            );
        }
    }

    pub(super) fn emit_packet_received(
        &self,
        pn: u64,
        space: SpaceId,
        is_0rtt: bool,
        path_id: PathId,
        now: Instant,
        orig_rem_cid: ConnectionId,
    ) {
        #[cfg(feature = "qlog")]
        {
            let Some(stream) = self.stream.as_ref() else {
                return;
            };

            let event = PacketReceived {
                header: PacketHeader {
                    packet_number: Some(pn),
                    packet_type: packet_type(space, is_0rtt),
                    ..Default::default()
                },
                ..Default::default()
            };

            stream.emit_event_ex(
                orig_rem_cid,
                EventData::QuicPacketReceived(event),
                path_ex_data(path_id),
                now,
            );
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
