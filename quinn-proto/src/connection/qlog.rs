// Function bodies in this module are regularly cfg'd out
#![allow(unused_variables)]

#[cfg(feature = "qlog")]
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[cfg(feature = "qlog")]
use qlog::{
    events::{
        Event, EventData,
        quic::{
            PacketHeader, PacketLost, PacketLostTrigger, PacketReceived, PacketSent, PacketType,
        },
    },
    streamer::QlogStreamer,
};
#[cfg(feature = "qlog")]
use tracing::warn;

use crate::{
    ConnectionId, EcnCounts, Instant,
    connection::{PathData, SentPacket},
    packet::SpaceId,
};

/// Shareable handle to a single qlog output stream
#[cfg(feature = "qlog")]
#[derive(Clone)]
pub struct QlogStream(pub(crate) Arc<Mutex<QlogStreamer>>);

#[cfg(feature = "qlog")]
impl QlogStream {
    fn emit_event(&self, orig_rem_cid: ConnectionId, event: EventData, now: Instant) {
        // Time will be overwritten by `add_event_with_instant`
        let mut event = Event::with_time(0.0, event);
        event.group_id = Some(Box::new(orig_rem_cid.to_string()));

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

    pub(super) fn emit_recovery_metrics(
        &self,
        pto_count: u32,
        path: &mut PathData,
        now: Instant,
        orig_rem_cid: ConnectionId,
    ) {
        #[cfg(feature = "qlog")]
        {
            let Some(stream) = self.stream.as_ref() else {
                return;
            };

            let Some(metrics) = path.qlog_recovery_metrics(pto_count) else {
                return;
            };

            stream.emit_event(orig_rem_cid, EventData::QuicMetricsUpdated(metrics), now);
        }
    }

    pub(super) fn emit_packet_lost(
        &self,
        pn: u64,
        info: &SentPacket,
        loss_delay: Duration,
        space: SpaceId,
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

            stream.emit_event(orig_rem_cid, EventData::QuicPacketLost(event), now);
        }
    }

    pub(super) fn emit_packet_sent(
        &self,
        pn: u64,
        len: usize,
        space: SpaceId,
        is_0rtt: bool,
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

            stream.emit_event(orig_rem_cid, EventData::QuicPacketSent(event), now);
        }
    }

    pub(super) fn emit_packet_received(
        &self,
        pn: u64,
        space: SpaceId,
        is_0rtt: bool,
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

            stream.emit_event(orig_rem_cid, EventData::QuicPacketReceived(event), now);
        }
    }

    pub(super) fn emit_loss_event(
        &self,
        size_of_lost_packets: u64,
        now: Instant,
        orig_rem_cid: ConnectionId,
    ) {
        #[cfg(feature = "qlog")]
        {
            use qlog::events::quic::{CongestionStateUpdated, CongestionStateUpdatedTrigger};

            let Some(stream) = self.stream.as_ref() else {
                return;
            };

            let event = CongestionStateUpdated {
                old: None,
                new: format!("LOSS:size_of_lost_packets={}", size_of_lost_packets),
                trigger: Some(CongestionStateUpdatedTrigger::Unknown),
            };

            stream.emit_event(
                orig_rem_cid,
                EventData::QuicCongestionStateUpdated(event),
                now,
            );
        }
    }

    pub(super) fn emit_ecn_event(
        &self,
        increment: EcnCounts,
        now: Instant,
        orig_rem_cid: ConnectionId,
    ) {
        #[cfg(feature = "qlog")]
        {
            use qlog::events::quic::{CongestionStateUpdated, CongestionStateUpdatedTrigger};

            let Some(stream) = self.stream.as_ref() else {
                return;
            };

            let event = CongestionStateUpdated {
                old: None,
                new: format!(
                    "ECN:ect0+={},ect1+={},ce+={}",
                    increment.ect0, increment.ect1, increment.ce
                ),
                trigger: Some(CongestionStateUpdatedTrigger::Ecn),
            };

            stream.emit_event(
                orig_rem_cid,
                EventData::QuicCongestionStateUpdated(event),
                now,
            );
        }
    }

    #[allow(dead_code)]
    pub(crate) fn emit_l4s_event(&self, alpha: f64, now: Instant, orig_rem_cid: ConnectionId) {
        #[cfg(feature = "qlog")]
        {
            use qlog::events::quic::{CongestionStateUpdated, CongestionStateUpdatedTrigger};

            let Some(stream) = self.stream.as_ref() else {
                return;
            };

            let event = CongestionStateUpdated {
                old: None,
                new: format!("ALPHA:alpha={:?}", alpha),
                trigger: Some(CongestionStateUpdatedTrigger::Ecn),
            };

            stream.emit_event(
                orig_rem_cid,
                EventData::QuicCongestionStateUpdated(event),
                now,
            );
        }
    }

    pub(super) fn emit_ecn_state_update(
        &self,
        ecn_capable: bool,
        now: Instant,
        orig_rem_cid: ConnectionId,
    ) {
        #[cfg(feature = "qlog")]
        {
            use qlog::events::quic::{EcnState, EcnStateUpdated};

            let Some(stream) = self.stream.as_ref() else {
                return;
            };

            let event = EcnStateUpdated {
                old: None,
                new: if ecn_capable {
                    EcnState::Capable
                } else {
                    EcnState::Failed
                },
            };

            stream.emit_event(orig_rem_cid, EventData::QuicEcnStateUpdated(event), now);
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
