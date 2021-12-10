use std::{
    cmp,
    collections::{BTreeMap, VecDeque},
    mem,
    ops::{Index, IndexMut},
    time::{Duration, Instant},
};

use rustc_hash::FxHashSet;

use super::assembler::Assembler;
use crate::{
    connection::StreamsState, crypto::Keys, frame, packet::SpaceId, range_set::ArrayRangeSet,
    shared::IssuedCid, StreamId, VarInt,
};

pub(crate) struct PacketSpace {
    pub(crate) crypto: Option<Keys>,
    pub(crate) dedup: Dedup,
    /// Highest received packet number
    pub(crate) rx_packet: u64,

    /// Data to send
    pub(crate) pending: Retransmits,
    /// Packet numbers to acknowledge
    pub(crate) pending_acks: PendingAcks,

    /// The packet number of the next packet that will be sent, if any.
    pub(crate) next_packet_number: u64,
    /// The largest packet number the remote peer acknowledged in an ACK frame.
    pub(crate) largest_acked_packet: Option<u64>,
    pub(crate) largest_acked_packet_sent: Instant,
    /// Transmitted but not acked
    // We use a BTreeMap here so we can efficiently query by range on ACK and for loss detection
    pub(crate) sent_packets: BTreeMap<u64, SentPacket>,
    /// Number of explicit congestion notification codepoints seen on incoming packets
    pub(crate) ecn_counters: frame::EcnCounts,
    /// Recent ECN counters sent by the peer in ACK frames
    ///
    /// Updated (and inspected) whenever we receive an ACK with a new highest acked packet
    /// number. Stored per-space to simplify verification, which would otherwise have difficulty
    /// distinguishing between ECN bleaching and counts having been updated by a near-simultaneous
    /// ACK already processed in another space.
    pub(crate) ecn_feedback: frame::EcnCounts,

    /// Incoming cryptographic handshake stream
    pub(crate) crypto_stream: Assembler,
    /// Current offset of outgoing cryptographic handshake stream
    pub(crate) crypto_offset: u64,

    /// The time the most recently sent retransmittable packet was sent.
    pub(crate) time_of_last_ack_eliciting_packet: Option<Instant>,
    /// The time at which the earliest sent packet in this space will be considered lost based on
    /// exceeding the reordering window in time. Only set for packets numbered prior to a packet
    /// that has been acknowledged.
    pub(crate) loss_time: Option<Instant>,
    /// Number of tail loss probes to send
    pub(crate) loss_probes: u32,
    pub(crate) ping_pending: bool,
    /// Number of congestion control "in flight" bytes
    pub(crate) in_flight: u64,
    /// Number of packets sent in the current key phase
    pub(crate) sent_with_keys: u64,
}

impl PacketSpace {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            crypto: None,
            dedup: Dedup::new(),
            rx_packet: 0,

            pending: Retransmits::default(),
            pending_acks: PendingAcks::default(),

            next_packet_number: 0,
            largest_acked_packet: None,
            largest_acked_packet_sent: now,
            sent_packets: BTreeMap::new(),
            ecn_counters: frame::EcnCounts::ZERO,
            ecn_feedback: frame::EcnCounts::ZERO,

            crypto_stream: Assembler::new(),
            crypto_offset: 0,

            time_of_last_ack_eliciting_packet: None,
            loss_time: None,
            loss_probes: 0,
            ping_pending: false,
            in_flight: 0,
            sent_with_keys: 0,
        }
    }

    /// Queue data for a tail loss probe (or anti-amplification deadlock prevention) packet
    ///
    /// Probes are sent similarly to normal packets when an expect ACK has not arrived. We never
    /// deem a packet lost until we receive an ACK that should have included it, but if a trailing
    /// run of packets (or their ACKs) are lost, this might not happen in a timely fashion. We send
    /// probe packets to force an ACK, and exempt them from congestion control to prevent a deadlock
    /// when the congestion window is filled with lost tail packets.
    ///
    /// We prefer to send new data, to make the most efficient use of bandwidth. If there's no data
    /// waiting to be sent, then we retransmit in-flight data to reduce odds of loss. If there's no
    /// in-flight data either, we're probably a client guarding against a handshake
    /// anti-amplification deadlock and we just make something up.
    pub(crate) fn maybe_queue_probe(&mut self, streams: &StreamsState) {
        if self.loss_probes == 0 {
            return;
        }

        // Retransmit the data of the oldest in-flight packet
        if !self.pending.is_empty(streams) {
            // There's real data to send here, no need to make something up
            return;
        }

        for packet in self.sent_packets.values_mut() {
            if !packet.retransmits.is_empty(streams) {
                // Remove retransmitted data from the old packet so we don't end up retransmitting
                // it *again* even if the copy we're sending now gets acknowledged.
                self.pending |= mem::take(&mut packet.retransmits);
                return;
            }
        }

        // Nothing new to send and nothing to retransmit, so fall back on a ping. This should only
        // happen in rare cases during the handshake when the server becomes blocked by
        // anti-amplification.
        self.ping_pending = true;
    }

    pub(crate) fn get_tx_number(&mut self) -> u64 {
        // TODO: Handle packet number overflow gracefully
        assert!(self.next_packet_number < 2u64.pow(62));
        let x = self.next_packet_number;
        self.next_packet_number += 1;
        self.sent_with_keys += 1;
        x
    }

    pub(crate) fn can_send(&self, streams: &StreamsState) -> SendableFrames {
        let acks = self.pending_acks.can_send();
        let other = !self.pending.is_empty(streams) || self.ping_pending;

        SendableFrames { acks, other }
    }

    /// Verifies sanity of an ECN block and returns whether congestion was encountered.
    pub(crate) fn detect_ecn(
        &mut self,
        newly_acked: u64,
        ecn: frame::EcnCounts,
    ) -> Result<bool, &'static str> {
        let ect0_increase = ecn
            .ect0
            .checked_sub(self.ecn_feedback.ect0)
            .ok_or("peer ECT(0) count regression")?;
        let ect1_increase = ecn
            .ect1
            .checked_sub(self.ecn_feedback.ect1)
            .ok_or("peer ECT(1) count regression")?;
        let ce_increase = ecn
            .ce
            .checked_sub(self.ecn_feedback.ce)
            .ok_or("peer CE count regression")?;
        let total_increase = ect0_increase + ect1_increase + ce_increase;
        if total_increase < newly_acked {
            return Err("ECN bleaching");
        }
        if (ect0_increase + ce_increase) < newly_acked || ect1_increase != 0 {
            return Err("ECN corruption");
        }
        // If total_increase > newly_acked (which happens when ACKs are lost), this is required by
        // the draft so that long-term drift does not occur. If =, then the only question is whether
        // to count CE packets as CE or ECT0. Recording them as CE is more consistent and keeps the
        // congestion check obvious.
        self.ecn_feedback = ecn;
        Ok(ce_increase != 0)
    }

    pub(crate) fn sent(&mut self, number: u64, packet: SentPacket) {
        self.in_flight += u64::from(packet.size);
        self.sent_packets.insert(number, packet);
    }
}

impl Index<SpaceId> for [PacketSpace; 3] {
    type Output = PacketSpace;
    fn index(&self, space: SpaceId) -> &PacketSpace {
        &self.as_ref()[space as usize]
    }
}

impl IndexMut<SpaceId> for [PacketSpace; 3] {
    fn index_mut(&mut self, space: SpaceId) -> &mut PacketSpace {
        &mut self.as_mut()[space as usize]
    }
}

/// Represents one or more packets subject to retransmission
#[derive(Debug, Clone)]
pub(crate) struct SentPacket {
    /// The time the packet was sent.
    pub(crate) time_sent: Instant,
    /// The number of bytes sent in the packet, not including UDP or IP overhead, but including QUIC
    /// framing overhead. Zero if this packet is not counted towards congestion control, i.e. not an
    /// "in flight" packet.
    pub(crate) size: u16,
    /// Whether an acknowledgement is expected directly in response to this packet.
    pub(crate) ack_eliciting: bool,
    pub(crate) acks: ArrayRangeSet,
    /// Data which needs to be retransmitted in case the packet is lost.
    /// The data is boxed to minimize `SentPacket` size for the typical case of
    /// packets only containing ACKs and STREAM frames.
    pub(crate) retransmits: ThinRetransmits,
    /// Metadata for stream frames in a packet
    ///
    /// The actual application data is stored with the stream state.
    pub(crate) stream_frames: frame::StreamMetaVec,
}

/// Retransmittable data queue
#[derive(Debug, Default, Clone)]
pub struct Retransmits {
    pub(crate) max_data: bool,
    pub(crate) max_uni_stream_id: bool,
    pub(crate) max_bi_stream_id: bool,
    pub(crate) reset_stream: Vec<(StreamId, VarInt)>,
    pub(crate) stop_sending: Vec<frame::StopSending>,
    pub(crate) max_stream_data: FxHashSet<StreamId>,
    pub(crate) crypto: VecDeque<frame::Crypto>,
    pub(crate) new_cids: Vec<IssuedCid>,
    pub(crate) retire_cids: Vec<u64>,
    pub(crate) handshake_done: bool,
}

impl Retransmits {
    pub fn is_empty(&self, streams: &StreamsState) -> bool {
        !self.max_data
            && !self.max_uni_stream_id
            && !self.max_bi_stream_id
            && self.reset_stream.is_empty()
            && self.stop_sending.is_empty()
            && self
                .max_stream_data
                .iter()
                .all(|&id| !streams.can_send_flow_control(id))
            && self.crypto.is_empty()
            && self.new_cids.is_empty()
            && self.retire_cids.is_empty()
            && !self.handshake_done
    }
}

impl ::std::ops::BitOrAssign for Retransmits {
    fn bitor_assign(&mut self, rhs: Self) {
        // We reduce in-stream head-of-line blocking by queueing retransmits before other data for
        // STREAM and CRYPTO frames.
        self.max_data |= rhs.max_data;
        self.max_uni_stream_id |= rhs.max_uni_stream_id;
        self.max_bi_stream_id |= rhs.max_bi_stream_id;
        self.reset_stream.extend_from_slice(&rhs.reset_stream);
        self.stop_sending.extend_from_slice(&rhs.stop_sending);
        self.max_stream_data.extend(&rhs.max_stream_data);
        for crypto in rhs.crypto.into_iter().rev() {
            self.crypto.push_front(crypto);
        }
        self.new_cids.extend(&rhs.new_cids);
        self.retire_cids.extend(rhs.retire_cids);
        self.handshake_done |= rhs.handshake_done;
    }
}

impl ::std::ops::BitOrAssign<ThinRetransmits> for Retransmits {
    fn bitor_assign(&mut self, rhs: ThinRetransmits) {
        if let Some(retransmits) = rhs.retransmits {
            self.bitor_assign(*retransmits)
        }
    }
}

impl ::std::iter::FromIterator<Retransmits> for Retransmits {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = Retransmits>,
    {
        let mut result = Retransmits::default();
        for packet in iter {
            result |= packet;
        }
        result
    }
}

/// A variant of `Retransmits` which only allocates storage when required
#[derive(Debug, Default, Clone)]
pub struct ThinRetransmits {
    retransmits: Option<Box<Retransmits>>,
}

impl ThinRetransmits {
    /// Returns `true` if no retransmits are necessary
    pub fn is_empty(&self, streams: &StreamsState) -> bool {
        match &self.retransmits {
            Some(retransmits) => retransmits.is_empty(streams),
            None => true,
        }
    }

    /// Returns a reference to the retransmits stored in this box
    pub fn get(&self) -> Option<&Retransmits> {
        self.retransmits.as_deref()
    }

    /// Returns a mutable reference to the stored retransmits
    ///
    /// This function will allocate a backing storage if required.
    pub fn get_or_create(&mut self) -> &mut Retransmits {
        if self.retransmits.is_none() {
            self.retransmits = Some(Box::new(Retransmits::default()));
        }
        self.retransmits.as_deref_mut().unwrap()
    }
}

/// RFC4303-style sliding window packet number deduplicator.
///
/// A contiguous bitfield, where each bit corresponds to a packet number and the rightmost bit is
/// always set. A set bit represents a packet that has been successfully authenticated. Bits left of
/// the window are assumed to be set.
///
/// ```text
/// ...xxxxxxxxx 1 0
///     ^        ^ ^
/// window highest next
/// ```
pub struct Dedup {
    window: Window,
    /// Lowest packet number higher than all yet authenticated.
    next: u64,
}

/// Inner bitfield type.
///
/// Because QUIC never reuses packet numbers, this only needs to be large enough to deal with
/// packets that are reordered but still delivered in a timely manner.
type Window = u128;

/// Number of packets tracked by `Dedup`.
const WINDOW_SIZE: u64 = 1 + mem::size_of::<Window>() as u64 * 8;

impl Dedup {
    /// Construct an empty window positioned at the start.
    pub fn new() -> Self {
        Self { window: 0, next: 0 }
    }

    /// Highest packet number authenticated.
    fn highest(&self) -> u64 {
        self.next - 1
    }

    /// Record a newly authenticated packet number.
    ///
    /// Returns whether the packet might be a duplicate.
    pub fn insert(&mut self, packet: u64) -> bool {
        if let Some(diff) = packet.checked_sub(self.next) {
            // Right of window
            self.window = (self.window << 1 | 1)
                .checked_shl(cmp::min(diff, u64::from(u32::max_value())) as u32)
                .unwrap_or(0);
            self.next = packet + 1;
            false
        } else if self.highest() - packet < WINDOW_SIZE {
            // Within window
            if let Some(bit) = (self.highest() - packet).checked_sub(1) {
                // < highest
                let mask = 1 << bit;
                let duplicate = self.window & mask != 0;
                self.window |= mask;
                duplicate
            } else {
                // == highest
                true
            }
        } else {
            // Left of window
            true
        }
    }
}

/// Indicates which data is available for sending
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct SendableFrames {
    pub acks: bool,
    pub other: bool,
}

impl SendableFrames {
    /// Returns that no data is available for sending
    pub fn empty() -> Self {
        Self {
            acks: false,
            other: false,
        }
    }

    /// Whether no data is sendable
    pub fn is_empty(&self) -> bool {
        !self.acks && !self.other
    }
}

#[derive(Debug, Default)]
pub(crate) struct PendingAcks {
    permit_ack_only: bool,
    ranges: ArrayRangeSet,
    /// This value will be used for calculating ACK delay once it is implemented
    ///
    /// ACK delay will be the delay between when a packet arrived (`latest_incoming`)
    /// and between it will be allowed to be acknowledged (`can_send() == true`).
    latest_incoming: Option<Instant>,
    ack_delay: Duration,
    /// Whether packets have been received in this space since we last ACKed
    dirty: bool,
}

impl PendingAcks {
    /// Whether any ACK frames can be sent
    pub fn can_send(&self) -> bool {
        self.permit_ack_only && !self.ranges.is_empty()
    }

    /// Returns the duration the acknowledgement of the latest incoming packet has been delayed
    pub fn ack_delay(&self) -> Duration {
        self.ack_delay
    }

    /// Handle receipt of a new packet
    pub fn packet_received(&mut self, ack_eliciting: bool) {
        self.dirty = true;
        self.permit_ack_only |= ack_eliciting;
    }

    /// Should be called whenever ACKs have been sent
    ///
    /// This will suppress sending further ACKs until additional ACK eliciting frames arrive
    pub fn acks_sent(&mut self) {
        self.dirty = false;
        // If we sent any acks, don't immediately resend them. Setting this even if ack_only is
        // false needlessly prevents us from ACKing the next packet if it's ACK-only, but saves
        // the need for subtler logic to avoid double-transmitting acks all the time.
        // This reset needs to happen before we check whether more data
        // is available in this space - because otherwise it would return
        // `true` purely due to the ACKs
        self.permit_ack_only = false;
    }

    /// Insert one packet that needs to be acknowledged
    pub fn insert_one(&mut self, packet: u64, now: Instant) {
        self.ranges.insert_one(packet);
        self.latest_incoming = Some(now);

        if self.ranges.len() > MAX_ACK_BLOCKS {
            self.ranges.pop_min();
        }
    }

    /// Removes the given ACKs from the set of pending ACKs
    pub fn subtract(&mut self, acks: &ArrayRangeSet) {
        self.ranges.subtract(acks);
        if self.ranges.is_empty() {
            self.permit_ack_only = false;
        }
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Returns the set of currently pending ACK ranges
    pub fn ranges(&self) -> &ArrayRangeSet {
        &self.ranges
    }
}

/// Ensures we can always fit all our ACKs in a single minimum-MTU packet with room to spare
const MAX_ACK_BLOCKS: usize = 64;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn sanity() {
        let mut dedup = Dedup::new();
        assert!(!dedup.insert(0));
        assert_eq!(dedup.next, 1);
        assert_eq!(dedup.window, 0b1);
        assert!(dedup.insert(0));
        assert_eq!(dedup.next, 1);
        assert_eq!(dedup.window, 0b1);
        assert!(!dedup.insert(1));
        assert_eq!(dedup.next, 2);
        assert_eq!(dedup.window, 0b11);
        assert!(!dedup.insert(2));
        assert_eq!(dedup.next, 3);
        assert_eq!(dedup.window, 0b111);
        assert!(!dedup.insert(4));
        assert_eq!(dedup.next, 5);
        assert_eq!(dedup.window, 0b11110);
        assert!(!dedup.insert(7));
        assert_eq!(dedup.next, 8);
        assert_eq!(dedup.window, 0b1111_0100);
        assert!(dedup.insert(4));
        assert!(!dedup.insert(3));
        assert_eq!(dedup.next, 8);
        assert_eq!(dedup.window, 0b1111_1100);
        assert!(!dedup.insert(6));
        assert_eq!(dedup.next, 8);
        assert_eq!(dedup.window, 0b1111_1101);
        assert!(!dedup.insert(5));
        assert_eq!(dedup.next, 8);
        assert_eq!(dedup.window, 0b1111_1111);
    }

    #[test]
    fn happypath() {
        let mut dedup = Dedup::new();
        for i in 0..(2 * WINDOW_SIZE) {
            assert!(!dedup.insert(i));
            for j in 0..=i {
                assert!(dedup.insert(j));
            }
        }
    }

    #[test]
    fn jump() {
        let mut dedup = Dedup::new();
        dedup.insert(2 * WINDOW_SIZE);
        assert!(dedup.insert(WINDOW_SIZE));
        assert_eq!(dedup.next, 2 * WINDOW_SIZE + 1);
        assert_eq!(dedup.window, 0);
        assert!(!dedup.insert(WINDOW_SIZE + 1));
        assert_eq!(dedup.next, 2 * WINDOW_SIZE + 1);
        assert_eq!(dedup.window, 1 << (WINDOW_SIZE - 2));
    }

    #[test]
    fn sent_packet_size() {
        // The tracking state of sent packets should be minimal, and not grow
        // over time.
        assert!(std::mem::size_of::<SentPacket>() <= 128);
    }
}
