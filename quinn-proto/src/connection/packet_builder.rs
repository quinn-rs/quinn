use std::time::Instant;

use bytes::Bytes;
use rand::Rng;
use tracing::{trace, trace_span};

use super::{spaces::SentPacket, Connection, SentFrames};
use crate::{
    frame::{self, Close},
    packet::{Header, LongType, PacketNumber, PartialEncode, SpaceId, FIXED_BIT},
    TransportError, TransportErrorCode,
};

pub(super) struct PacketBuilder {
    pub datagram_start: usize,
    pub space: SpaceId,
    pub partial_encode: PartialEncode,
    pub ack_eliciting: bool,
    pub exact_number: u64,
    pub short_header: bool,
    pub min_size: usize,
    pub max_size: usize,
    pub tag_len: usize,
    pub span: tracing::Span,
}

impl PacketBuilder {
    /// Write a new packet header to `buffer` and determine the packet's properties
    ///
    /// Marks the connection drained and returns `None` if the confidentiality limit would be
    /// violated.
    pub fn new(
        now: Instant,
        space_id: SpaceId,
        buffer: &mut Vec<u8>,
        buffer_capacity: usize,
        datagram_start: usize,
        ack_eliciting: bool,
        conn: &mut Connection,
        version: u32,
    ) -> Option<PacketBuilder> {
        // Initiate key update if we're approaching the confidentiality limit
        let confidentiality_limit = conn.spaces[space_id]
            .crypto
            .as_ref()
            .map_or_else(
                || &conn.zero_rtt_crypto.as_ref().unwrap().packet,
                |keys| &keys.packet.local,
            )
            .confidentiality_limit();
        let sent_with_keys = conn.spaces[space_id].sent_with_keys;
        if space_id == SpaceId::Data {
            if sent_with_keys.saturating_add(KEY_UPDATE_MARGIN) >= confidentiality_limit {
                conn.initiate_key_update();
            }
        } else if sent_with_keys.saturating_add(1) == confidentiality_limit {
            // We still have time to attempt a graceful close
            conn.close_inner(
                now,
                Close::Connection(frame::ConnectionClose {
                    error_code: TransportErrorCode::AEAD_LIMIT_REACHED,
                    frame_type: None,
                    reason: Bytes::from_static(b"confidentiality limit reached"),
                }),
            )
        } else if sent_with_keys > confidentiality_limit {
            // Confidentiality limited violated and there's nothing we can do
            conn.kill(TransportError::AEAD_LIMIT_REACHED("confidentiality limit reached").into());
            return None;
        }

        let space = &mut conn.spaces[space_id];

        space.loss_probes = space.loss_probes.saturating_sub(1);
        let exact_number = space.get_tx_number();

        let span = trace_span!("send", space = ?space_id, pn = exact_number);
        span.with_subscriber(|(id, dispatch)| dispatch.enter(id));

        let number = PacketNumber::new(exact_number, space.largest_acked_packet.unwrap_or(0));
        let header = match space_id {
            SpaceId::Data if space.crypto.is_some() => Header::Short {
                dst_cid: conn.rem_cids.active(),
                number,
                spin: if conn.spin_enabled {
                    conn.spin
                } else {
                    conn.rng.gen()
                },
                key_phase: conn.key_phase,
            },
            SpaceId::Data => Header::Long {
                ty: LongType::ZeroRtt,
                src_cid: conn.handshake_cid,
                dst_cid: conn.rem_cids.active(),
                number,
                version,
            },
            SpaceId::Handshake => Header::Long {
                ty: LongType::Handshake,
                src_cid: conn.handshake_cid,
                dst_cid: conn.rem_cids.active(),
                number,
                version,
            },
            SpaceId::Initial => Header::Initial {
                src_cid: conn.handshake_cid,
                dst_cid: conn.rem_cids.active(),
                token: conn.retry_token.clone(),
                number,
                version,
            },
        };
        let partial_encode = header.encode(buffer);
        if conn.peer_params.grease_quic_bit && conn.rng.gen() {
            buffer[partial_encode.start] ^= FIXED_BIT;
        }

        let (sample_size, tag_len) = if let Some(ref crypto) = space.crypto {
            (
                crypto.header.local.sample_size(),
                crypto.packet.local.tag_len(),
            )
        } else if space_id == SpaceId::Data {
            let zero_rtt = conn.zero_rtt_crypto.as_ref().unwrap();
            (zero_rtt.header.sample_size(), zero_rtt.packet.tag_len())
        } else {
            unreachable!("tried to send {:?} packet without keys", space_id);
        };

        // Each packet must be large enough for header protection sampling, i.e. the
        // combined lengths of the encoded packet number and protected payload must be at
        // least 4 bytes longer than the sample required for header protection

        // pn_len + payload_len + tag_len >= sample_size + 4
        // payload_len >= sample_size + 4 - pn_len - tag_len
        let min_size = buffer.len() + (sample_size + 4).saturating_sub(number.len() + tag_len);
        let max_size = buffer_capacity - partial_encode.start - partial_encode.header_len - tag_len;

        Some(PacketBuilder {
            datagram_start,
            space: space_id,
            partial_encode,
            exact_number,
            short_header: header.is_short(),
            min_size,
            max_size,
            span,
            tag_len,
            ack_eliciting,
        })
    }

    pub fn pad_to(&mut self, min_size: u16) {
        let prev = self.min_size;
        self.min_size = self.datagram_start + (min_size as usize) - self.tag_len;
        debug_assert!(self.min_size >= prev, "padding must not shrink datagram");
    }

    pub fn finish_and_track(
        self,
        now: Instant,
        conn: &mut Connection,
        sent: Option<SentFrames>,
        buffer: &mut Vec<u8>,
    ) {
        let ack_eliciting = self.ack_eliciting;
        let exact_number = self.exact_number;
        let space_id = self.space;
        let (size, padded) = self.finish(conn, buffer);
        let sent = match sent {
            Some(sent) => sent,
            None => return,
        };

        let size = match padded || ack_eliciting {
            true => size as u16,
            false => 0,
        };

        let packet = SentPacket {
            acks: sent.acks,
            time_sent: now,
            size,
            ack_eliciting,
            retransmits: sent.retransmits,
            stream_frames: sent.stream_frames,
        };

        conn.in_flight.insert(&packet);
        conn.spaces[space_id].sent(exact_number, packet);
        conn.stats.path.sent_packets += 1;
        conn.reset_keep_alive(now);
        if size != 0 {
            if ack_eliciting {
                conn.spaces[space_id].time_of_last_ack_eliciting_packet = Some(now);
                if conn.permit_idle_reset {
                    conn.reset_idle_timeout(now, space_id);
                }
                conn.permit_idle_reset = false;
            }
            conn.set_loss_detection_timer(now);
            conn.path.pacing.on_transmit(size);
        }
    }

    /// Encrypt packet, returning the length of the packet and whether padding was added
    pub fn finish(
        self: PacketBuilder,
        conn: &mut Connection,
        buffer: &mut Vec<u8>,
    ) -> (usize, bool) {
        let pad = buffer.len() < self.min_size;
        if pad {
            trace!("PADDING * {}", self.min_size - buffer.len());
            buffer.resize(self.min_size, 0);
        }

        let space = &conn.spaces[self.space];
        let (header_crypto, packet_crypto) = if let Some(ref crypto) = space.crypto {
            (&*crypto.header.local, &*crypto.packet.local)
        } else if self.space == SpaceId::Data {
            let zero_rtt = conn.zero_rtt_crypto.as_ref().unwrap();
            (&*zero_rtt.header, &*zero_rtt.packet)
        } else {
            unreachable!("tried to send {:?} packet without keys", self.space);
        };

        debug_assert_eq!(
            packet_crypto.tag_len(),
            self.tag_len,
            "Mismatching crypto tag len"
        );

        buffer.resize(buffer.len() + packet_crypto.tag_len(), 0);
        debug_assert!(
            buffer.len() <= self.datagram_start + conn.path.max_udp_payload_size as usize
        );
        let encode_start = self.partial_encode.start;
        let packet_buf = &mut buffer[encode_start..];
        self.partial_encode.finish(
            packet_buf,
            header_crypto,
            Some((self.exact_number, packet_crypto)),
        );
        self.span
            .with_subscriber(|(id, dispatch)| dispatch.exit(id));

        (buffer.len() - encode_start, pad)
    }
}

/// Perform key updates this many packets before the AEAD confidentiality limit.
///
/// Chosen arbitrarily, intended to be large enough to prevent spurious connection loss.
const KEY_UPDATE_MARGIN: u64 = 10000;
