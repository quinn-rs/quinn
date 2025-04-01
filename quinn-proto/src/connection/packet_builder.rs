use bytes::{BufMut, Bytes};
use rand::Rng;
use tracing::{trace, trace_span};

use super::{Connection, SentFrames, TransmitBuf, spaces::SentPacket};
use crate::{
    ConnectionId, Instant, TransportError, TransportErrorCode,
    connection::ConnectionSide,
    frame::{self, Close},
    packet::{FIXED_BIT, Header, InitialHeader, LongType, PacketNumber, PartialEncode, SpaceId},
};

/// QUIC packet builder
///
/// This allows building QUIC packets: it takes care of writing the header, allows writing
/// frames and on [`PacketBuilder::finalize`] (or [`PacketBuilder::finalize_and_track`]) it
/// encrypts the packet so it is ready to be sent on the wire.
///
/// The builder manages the write buffer into which the packet is written, and directly
/// implements [`BufMut`] to write frames into the packet.
pub(super) struct PacketBuilder<'a, 'b> {
    pub(super) buf: &'a mut TransmitBuf<'b>,
    pub(super) space: SpaceId,
    pub(super) partial_encode: PartialEncode,
    pub(super) ack_eliciting: bool,
    pub(super) exact_number: u64,
    pub(super) short_header: bool,
    /// Smallest absolute position in the associated buffer that must be occupied by this packet's
    /// frames
    pub(super) min_size: usize,
    /// Largest absolute position in the buffer that may be occupied by this packet's frames
    ///
    /// This takes the size of the cryptographic tag into account.
    pub(super) max_size: usize,
    pub(super) tag_len: usize,
    pub(super) _span: tracing::span::EnteredSpan,
}

impl<'a, 'b> PacketBuilder<'a, 'b> {
    /// Write a new packet header to `buffer` and determine the packet's properties
    ///
    /// Marks the connection drained and returns `None` if the confidentiality limit would be
    /// violated.
    pub(super) fn new(
        now: Instant,
        space_id: SpaceId,
        dst_cid: ConnectionId,
        buffer: &'a mut TransmitBuf<'b>,
        ack_eliciting: bool,
        conn: &mut Connection,
    ) -> Option<Self>
    where
        'b: 'a,
    {
        let version = conn.version;
        // Initiate key update if we're approaching the confidentiality limit
        let sent_with_keys = conn.spaces[space_id].sent_with_keys;
        if space_id == SpaceId::Data {
            if sent_with_keys >= conn.key_phase_size {
                conn.force_key_update();
            }
        } else {
            let confidentiality_limit = conn.spaces[space_id]
                .crypto
                .as_ref()
                .map_or_else(
                    || &conn.zero_rtt_crypto.as_ref().unwrap().packet,
                    |keys| &keys.packet.local,
                )
                .confidentiality_limit();
            if sent_with_keys.saturating_add(1) == confidentiality_limit {
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
                conn.kill(
                    TransportError::AEAD_LIMIT_REACHED("confidentiality limit reached").into(),
                );
                return None;
            }
        }

        let space = &mut conn.spaces[space_id];
        let exact_number = match space_id {
            SpaceId::Data => conn.packet_number_filter.allocate(&mut conn.rng, space),
            _ => space.get_tx_number(),
        };

        let span = trace_span!("send", space = ?space_id, pn = exact_number).entered();

        let number = PacketNumber::new(exact_number, space.largest_acked_packet.unwrap_or(0));
        let header = match space_id {
            SpaceId::Data if space.crypto.is_some() => Header::Short {
                dst_cid,
                number,
                spin: if conn.spin_enabled {
                    conn.spin
                } else {
                    conn.rng.random()
                },
                key_phase: conn.key_phase,
            },
            SpaceId::Data => Header::Long {
                ty: LongType::ZeroRtt,
                src_cid: conn.handshake_cid,
                dst_cid,
                number,
                version,
            },
            SpaceId::Handshake => Header::Long {
                ty: LongType::Handshake,
                src_cid: conn.handshake_cid,
                dst_cid,
                number,
                version,
            },
            SpaceId::Initial => Header::Initial(InitialHeader {
                src_cid: conn.handshake_cid,
                dst_cid,
                token: match &conn.side {
                    ConnectionSide::Client { token, .. } => token.clone(),
                    ConnectionSide::Server { .. } => Bytes::new(),
                },
                number,
                version,
            }),
        };
        let partial_encode = header.encode(buffer);
        if conn.peer_params.grease_quic_bit && conn.rng.random() {
            buffer.as_mut_slice()[partial_encode.start] ^= FIXED_BIT;
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
            unreachable!();
        };

        // Each packet must be large enough for header protection sampling, i.e. the combined
        // lengths of the encoded packet number and protected payload must be at least 4 bytes
        // longer than the sample required for header protection. Further, each packet should be at
        // least tag_len + 6 bytes larger than the destination CID on incoming packets so that the
        // peer may send stateless resets that are indistinguishable from regular traffic.

        // pn_len + payload_len + tag_len >= sample_size + 4
        // payload_len >= sample_size + 4 - pn_len - tag_len
        let min_size = Ord::max(
            buffer.len() + (sample_size + 4).saturating_sub(number.len() + tag_len),
            partial_encode.start + dst_cid.len() + 6,
        );
        let max_size = buffer.datagram_max_offset() - tag_len;
        debug_assert!(max_size >= min_size);

        Some(Self {
            buf: buffer,
            space: space_id,
            partial_encode,
            exact_number,
            short_header: header.is_short(),
            min_size,
            max_size,
            tag_len,
            ack_eliciting,
            _span: span,
        })
    }

    /// Append the minimum amount of padding to the packet such that, after encryption, the
    /// enclosing datagram will occupy at least `min_size` bytes
    pub(super) fn pad_to(&mut self, min_size: u16) {
        // The datagram might already have a larger minimum size than the caller is requesting, if
        // e.g. we're coalescing packets and have populated more than `min_size` bytes with packets
        // already.
        self.min_size = Ord::max(
            self.min_size,
            self.buf.datagram_start_offset() + (min_size as usize) - self.tag_len,
        );
    }

    /// Returns a writable buffer limited to the remaining frame space
    ///
    /// The [`BufMut::remaining_mut`] call on the returned buffer indicates the amount of
    /// space available to write QUIC frames into.
    // In rust 1.82 we can use `-> impl BufMut + use<'_, 'a, 'b>`
    pub(super) fn frame_space_mut(&mut self) -> bytes::buf::Limit<&mut TransmitBuf<'b>> {
        self.buf.limit(self.frame_space_remaining())
    }

    pub(super) fn finish_and_track(self, now: Instant, conn: &mut Connection, sent: SentFrames) {
        let ack_eliciting = self.ack_eliciting;
        let exact_number = self.exact_number;
        let space_id = self.space;
        let (size, padded) = self.finish(conn);

        let size = match padded || ack_eliciting {
            true => size as u16,
            false => 0,
        };

        let packet = SentPacket {
            largest_acked: sent.largest_acked,
            time_sent: now,
            size,
            ack_eliciting,
            retransmits: sent.retransmits,
            stream_frames: sent.stream_frames,
        };

        conn.path
            .sent(exact_number, packet, &mut conn.spaces[space_id]);
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
    pub(super) fn finish(self, conn: &mut Connection) -> (usize, bool) {
        debug_assert!(
            self.buf.len() <= self.max_size,
            "packet exceeds maximum size"
        );
        let pad = self.buf.len() < self.min_size;
        if pad {
            trace!("PADDING * {}", self.min_size - self.buf.len());
            self.buf.put_bytes(0, self.min_size - self.buf.len());
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

        self.buf.put_bytes(0, packet_crypto.tag_len());
        let encode_start = self.partial_encode.start;
        let packet_buf = &mut self.buf.as_mut_slice()[encode_start..];
        self.partial_encode.finish(
            packet_buf,
            header_crypto,
            Some((self.exact_number, packet_crypto)),
        );

        (self.buf.len() - encode_start, pad)
    }

    /// Predicts the size of the packet if it were finished now without additional padding
    ///
    /// This will include any padding which is required to make the size large enough to be
    /// encrypted correctly.
    pub(super) fn predict_packet_size(&self) -> usize {
        self.buf.len().max(self.min_size) - self.buf.datagram_start_offset() + self.tag_len
    }

    /// Returns the remaining space in the packet that can be taken up by QUIC frames
    ///
    /// This leaves space in the datagram for the cryptographic tag that needs to be written
    /// when the packet is finished.
    pub(super) fn frame_space_remaining(&self) -> usize {
        debug_assert!(self.max_size >= self.buf.len(), "packet exceeds bounds");
        self.max_size.saturating_sub(self.buf.len())
    }
}
