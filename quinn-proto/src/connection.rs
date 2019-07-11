use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{cmp, io, mem};

use bytes::{Bytes, BytesMut};
use err_derive::Error;
use fnv::FnvHashSet;
use rand::{rngs::StdRng, Rng, SeedableRng};
use slog::Logger;

use crate::coding::BufMutExt;
use crate::crypto::{self, HeaderKeys, Keys};
use crate::frame::{Close, FrameStruct};
use crate::packet::{
    Header, LongType, Packet, PacketNumber, PartialDecode, SpaceId, LONG_RESERVED_BITS,
    SHORT_RESERVED_BITS,
};
use crate::range_set::RangeSet;
use crate::shared::{
    ConnectionEvent, ConnectionEventInner, ConnectionId, EcnCodepoint, EndpointConfig,
    EndpointEvent, EndpointEventInner, IssuedCid, ServerConfig, TransportConfig,
};
use crate::spaces::{CryptoSpace, PacketSpace, Retransmits, SentPacket};
use crate::streams::{self, FinishError, ReadError, Streams, WriteError};
use crate::timer::{Timer, TimerKind, TimerTable};
use crate::transport_parameters::{self, TransportParameters};
use crate::{
    frame, Directionality, Frame, Side, StreamId, Transmit, TransportError, TransportErrorCode,
    VarInt, MAX_STREAM_COUNT, MIN_INITIAL_SIZE, MIN_MTU, REM_CID_COUNT, RESET_TOKEN_SIZE,
    TIMER_GRANULARITY,
};

/// Protocol state and logic for a single QUIC connection
///
/// Objects of this type receive `ConnectionEvent`s and emit `EndpointEvents` and application
/// `Event`s to make progress. To handle timeouts, a `Connection` returns timer updates and
/// expects timeouts through various methods. A number of simple getter methods are exposed
/// to allow callers to inspect some of the connection state.
pub struct Connection<S>
where
    S: crypto::Session,
{
    log: Logger,
    endpoint_config: Arc<EndpointConfig>,
    server_config: Option<Arc<ServerConfig<S>>>,
    config: Arc<TransportConfig>,
    rng: StdRng,
    tls: S,
    /// The CID we initially chose, for use during the handshake
    handshake_cid: ConnectionId,
    rem_cid: ConnectionId,
    /// The CID the peer initially chose, for use during the handshake
    rem_handshake_cid: ConnectionId,
    rem_cid_seq: u64,
    remote: SocketAddr,
    prev_remote: Option<SocketAddr>,
    state: State,
    side: Side,
    mtu: u16,
    /// Whether or not 0-RTT was enabled during the handshake. Does not imply acceptance.
    zero_rtt_enabled: bool,
    /// Set if 0-RTT is supported, then cleared when no longer needed.
    zero_rtt_crypto: Option<CryptoSpace<S::Keys>>,
    key_phase: bool,
    /// Transport parameters set by the peer
    params: TransportParameters,
    /// Streams on which writing was blocked on *connection-level* flow or congestion control
    blocked_streams: FnvHashSet<StreamId>,
    /// Limit on outgoing data, dictated by peer
    max_data: u64,
    /// Sum of current offsets of all send streams.
    data_sent: u64,
    /// Sum of end offsets of all receive streams. Includes gaps, so it's an upper bound.
    data_recvd: u64,
    /// Limit on incoming data
    local_max_data: u64,
    /// Stream data we're sending that hasn't been acknowledged or reset yet
    unacked_data: u64,
    /// ConnectionId sent by this client on the first Initial, if a Retry was received.
    orig_rem_cid: Option<ConnectionId>,
    /// Total number of outgoing packets that have been deemed lost
    lost_packets: u64,
    io: IoQueue,
    events: VecDeque<Event>,
    endpoint_events: VecDeque<EndpointEventInner>,
    /// Number of local connection IDs that have been issued in NEW_CONNECTION_ID frames.
    cids_issued: u64,
    /// Whether the spin bit is in use for this connection
    spin_enabled: bool,
    /// Outgoing spin bit state
    spin: bool,
    /// Packet number spaces: initial, handshake, 1-RTT
    spaces: [PacketSpace<S::Keys>; 3],
    /// Highest usable packet number space
    highest_space: SpaceId,
    /// 1-RTT keys used prior to a key update
    prev_crypto: Option<PrevCrypto<S::Keys>>,
    /// Latest PATH_CHALLENGE token issued to the peer along the current path
    path_challenge: Option<u64>,
    /// Whether the remote endpoint has opened any streams the application doesn't know about yet
    stream_opened: bool,
    accepted_0rtt: bool,
    /// Whether the idle timer should be reset the next time an ack-eliciting packet is transmitted.
    permit_idle_reset: bool,
    /// Negotiated idle timeout
    idle_timeout: u64,
    /// Number of the first 1-RTT packet transmitted
    first_1rtt_sent: Option<u64>,
    /// Sequence number of the first remote CID that we haven't been asked to retire
    first_unretired_cid: u64,

    //
    // Queued non-retransmittable 1-RTT data
    //
    path_challenge_pending: bool,
    ping_pending: bool,
    path_response: Option<PathResponse>,

    //
    // Loss Detection
    //
    /// The number of times all unacknowledged CRYPTO data has been retransmitted without receiving
    /// an ack.
    crypto_count: u32,
    /// The number of times a PTO has been sent without receiving an ack.
    pto_count: u32,
    /// The time the most recently sent retransmittable packet was sent.
    time_of_last_sent_ack_eliciting_packet: Instant,
    /// The time the most recently sent handshake packet was sent.
    time_of_last_sent_crypto_packet: Instant,
    rtt: RttEstimator,

    //
    // Congestion Control
    //
    /// Summary statistics of packets that have been sent, but not yet acked or deemed lost
    in_flight: InFlight,
    /// Maximum number of bytes in flight that may be sent.
    congestion_window: u64,
    /// The time when QUIC first detects a loss, causing it to enter recovery. When a packet sent
    /// after this time is acknowledged, QUIC exits recovery.
    recovery_start_time: Instant,
    /// Slow start threshold in bytes. When the congestion window is below ssthresh, the mode is
    /// slow start and the window grows by the number of bytes acknowledged.
    ssthresh: u64,
    /// Explicit congestion notification (ECN) counters
    ecn_counters: frame::EcnCounts,
    /// Whether we're enabling ECN on outgoing packets
    sending_ecn: bool,
    /// Whether the most recently received packet had an ECN codepoint set
    receiving_ecn: bool,
    remote_validated: bool,
    /// Total UDP datagram bytes received, tracked for handshake anti-amplification
    total_recvd: u64,
    total_sent: u64,

    streams: Streams,
    /// Surplus remote CIDs for future use on new paths
    rem_cids: Vec<IssuedCid>,
}

impl<S> Connection<S>
where
    S: crypto::Session,
{
    pub(crate) fn new(
        log: Logger,
        endpoint_config: Arc<EndpointConfig>,
        server_config: Option<Arc<ServerConfig<S>>>,
        config: Arc<TransportConfig>,
        init_cid: ConnectionId,
        loc_cid: ConnectionId,
        rem_cid: ConnectionId,
        remote: SocketAddr,
        tls: S,
        now: Instant,
    ) -> Self {
        let side = if server_config.is_some() {
            Side::Server
        } else {
            Side::Client
        };
        let initial_space = PacketSpace {
            crypto: Some(CryptoSpace::new(S::Keys::new_initial(&init_cid, side))),
            ..PacketSpace::new(now)
        };
        let state = State::Handshake(state::Handshake {
            rem_cid_set: side.is_server(),
            token: None,
            client_hello: None,
        });
        let mut rng = StdRng::from_entropy();
        let remote_validated = server_config
            .as_ref()
            .map_or(false, |c| c.use_stateless_retry);
        let mut this = Self {
            log,
            endpoint_config,
            server_config,
            tls,
            handshake_cid: loc_cid,
            rem_cid,
            rem_handshake_cid: rem_cid,
            rem_cid_seq: 0,
            remote,
            prev_remote: None,
            side,
            state,
            mtu: MIN_MTU,
            zero_rtt_enabled: false,
            zero_rtt_crypto: None,
            key_phase: false,
            params: TransportParameters::default(),
            blocked_streams: FnvHashSet::default(),
            max_data: 0,
            data_sent: 0,
            data_recvd: 0,
            local_max_data: config.receive_window as u64,
            unacked_data: 0,
            orig_rem_cid: None,
            lost_packets: 0,
            io: IoQueue::new(),
            events: VecDeque::new(),
            endpoint_events: VecDeque::new(),
            cids_issued: 0,
            spin_enabled: config.allow_spin && rng.gen_ratio(7, 8),
            spin: false,
            spaces: [initial_space, PacketSpace::new(now), PacketSpace::new(now)],
            highest_space: SpaceId::Initial,
            prev_crypto: None,
            path_challenge: None,
            stream_opened: false,
            accepted_0rtt: false,
            permit_idle_reset: true,
            idle_timeout: config.idle_timeout,
            first_1rtt_sent: None,
            first_unretired_cid: 0,

            path_challenge_pending: false,
            ping_pending: false,
            path_response: None,

            crypto_count: 0,
            pto_count: 0,
            time_of_last_sent_ack_eliciting_packet: now,
            time_of_last_sent_crypto_packet: now,
            rtt: RttEstimator::new(),

            in_flight: InFlight::new(),
            congestion_window: config.initial_window,
            recovery_start_time: now,
            ssthresh: u64::max_value(),
            ecn_counters: frame::EcnCounts::ZERO,
            sending_ecn: true,
            receiving_ecn: false,
            remote_validated,
            total_recvd: 0,
            total_sent: 0,

            streams: Streams::new(side, config.stream_window_uni, config.stream_window_bidi),
            config,
            rem_cids: Vec::new(),
            rng,
        };
        if side.is_client() {
            // Kick off the connection
            this.write_tls();
            this.init_0rtt();
        }
        this
    }

    /// Replace the diagnostic logger
    pub fn set_logger(&mut self, log: Logger) {
        self.log = log;
    }

    /// Returns timer updates
    ///
    /// Connections should be polled for timer updates after:
    /// - the application performed some I/O on the connection
    /// - an incoming packet is handled
    /// - a packet is transmitted
    /// - any timer expires
    pub fn poll_timers(&mut self) -> Option<TimerUpdate> {
        for (timer, update) in self.io.timers.iter_mut() {
            if let Some(update) = update.take() {
                return Some(TimerUpdate { timer, update });
            }
        }
        None
    }

    /// Returns application-facing events
    ///
    /// Connections should be polled for events after:
    /// - an incoming packet is handled, or
    /// - the idle timer expires
    pub fn poll(&mut self) -> Option<Event> {
        if mem::replace(&mut self.stream_opened, false) {
            return Some(Event::StreamOpened);
        }

        if let Some(x) = self.events.pop_front() {
            return Some(x);
        }

        None
    }

    /// Return endpoint-facing events
    pub fn poll_endpoint_events(&mut self) -> Option<EndpointEvent> {
        self.endpoint_events.pop_front().map(EndpointEvent)
    }

    fn on_packet_sent(
        &mut self,
        now: Instant,
        space: SpaceId,
        packet_number: u64,
        packet: SentPacket,
    ) {
        let SentPacket {
            size,
            is_crypto_packet,
            ack_eliciting,
            ..
        } = packet;

        self.in_flight.insert(&packet);
        self.space_mut(space)
            .sent_packets
            .insert(packet_number, packet);
        self.reset_keep_alive(now);
        if size != 0 {
            if ack_eliciting {
                self.time_of_last_sent_ack_eliciting_packet = now;
                if self.permit_idle_reset {
                    self.reset_idle_timeout(now);
                }
                self.permit_idle_reset = false;
            }
            if is_crypto_packet {
                self.time_of_last_sent_crypto_packet = now;
            }
            self.set_loss_detection_timer();
        }
    }

    fn on_ack_received(
        &mut self,
        now: Instant,
        space: SpaceId,
        ack: frame::Ack,
    ) -> Result<(), TransportError> {
        trace!(self.log, "handling ack"; "ranges" => ?ack.iter().collect::<Vec<_>>());
        if ack.largest >= self.space(space).next_packet_number {
            return Err(TransportError::PROTOCOL_VIOLATION("unsent packet acked"));
        }
        let was_blocked = self.blocked();
        let new_largest = {
            let space = self.space_mut(space);
            if space
                .largest_acked_packet
                .map_or(true, |pn| ack.largest > pn)
            {
                space.largest_acked_packet = Some(ack.largest);
                if let Some(info) = space.sent_packets.get(&ack.largest) {
                    // This should always succeed, but a misbehaving peer might ACK a packet we
                    // haven't sent. At worst, that will result in us spuriously reducing the
                    // congestion window.
                    space.largest_acked_packet_sent = info.time_sent;
                }
                true
            } else {
                false
            }
        };

        if let Some(info) = self.space(space).sent_packets.get(&ack.largest) {
            if info.ack_eliciting {
                let delay = if space != SpaceId::Data {
                    Duration::from_micros(0)
                } else {
                    cmp::min(
                        self.max_ack_delay(),
                        Duration::from_micros(ack.delay << self.params.ack_delay_exponent),
                    )
                };
                let rtt = instant_saturating_sub(now, info.time_sent);
                self.rtt.update(delay, rtt);
            }
        }

        // Avoid DoS from unreasonably huge ack ranges by filtering out just the new acks.
        let newly_acked = ack
            .iter()
            .flat_map(|range| self.space(space).sent_packets.range(range).map(|(&n, _)| n))
            .collect::<Vec<_>>();
        if newly_acked.is_empty() {
            return Ok(());
        }
        for &packet in &newly_acked {
            self.on_packet_acked(space, packet);
        }

        if self.space(SpaceId::Handshake).crypto.is_some()
            && space == SpaceId::Data
            && self.first_1rtt_sent.map_or(false, |pn| ack.largest >= pn)
        {
            // Received first acknowledgment of 1-RTT packet
            self.discard_space(SpaceId::Handshake);
        }

        // Must be called before crypto/pto_count are clobbered
        self.detect_lost_packets(now, space);

        self.crypto_count = 0;
        self.pto_count = 0;

        // Explicit congestion notification
        if self.sending_ecn {
            if let Some(ecn) = ack.ecn {
                // We only examine ECN counters from ACKs that we are certain we received in transmit
                // order, allowing us to compute an increase in ECN counts to compare against the number
                // of newly acked packets that remains well-defined in the presence of arbitrary packet
                // reordering.
                if new_largest {
                    let sent = self.space(space).largest_acked_packet_sent;
                    self.process_ecn(now, space, newly_acked.len() as u64, ecn, sent);
                }
            } else {
                // We always start out sending ECN, so any ack that doesn't acknowledge it disables it.
                debug!(self.log, "ECN not acknowledged by peer");
                self.sending_ecn = false;
            }
        }

        self.set_loss_detection_timer();
        if was_blocked && !self.blocked() {
            for stream in self.blocked_streams.drain() {
                self.events.push_back(Event::StreamWritable { stream });
            }
        }
        Ok(())
    }

    /// Process a new ECN block from an in-order ACK
    fn process_ecn(
        &mut self,
        now: Instant,
        space: SpaceId,
        newly_acked: u64,
        ecn: frame::EcnCounts,
        largest_sent_time: Instant,
    ) {
        match self.space_mut(space).detect_ecn(newly_acked, ecn) {
            Err(e) => {
                debug!(
                    self.log,
                    "halting ECN due to verification failure: {error}",
                    error = e
                );
                self.sending_ecn = false;
            }
            Ok(false) => {}
            Ok(true) => {
                self.congestion_event(now, largest_sent_time);
            }
        }
    }

    // Not timing-aware, so it's safe to call this for inferred acks, such as arise from
    // high-latency handshakes
    fn on_packet_acked(&mut self, space: SpaceId, packet: u64) {
        let info = match self.space_mut(space).sent_packets.remove(&packet) {
            Some(x) => x,
            None => return,
        };
        self.in_flight.remove(&info);
        if info.ack_eliciting {
            // Congestion control
            // Do not increase congestion window in recovery period.
            if !self.in_recovery(info.time_sent) {
                if self.congestion_window < self.ssthresh {
                    // Slow start.
                    self.congestion_window += u64::from(info.size);
                } else {
                    // Congestion avoidance.
                    self.congestion_window += self.config.max_datagram_size * u64::from(info.size)
                        / self.congestion_window;
                }
            }
        }

        // Update state for confirmed delivery of frames
        for (id, _) in info.retransmits.rst_stream {
            if let streams::SendState::ResetSent { stop_reason } =
                self.streams.get_send_mut(id).unwrap().state
            {
                self.streams.get_send_mut(id).unwrap().state =
                    streams::SendState::ResetRecvd { stop_reason };
                if stop_reason.is_none() {
                    self.streams.maybe_cleanup(id);
                }
            }
        }
        for frame in info.retransmits.stream {
            let ss = match self.streams.get_send_mut(frame.id) {
                Some(x) => x,
                None => continue,
            };
            ss.bytes_in_flight -= frame.data.len() as u64;
            self.unacked_data -= frame.data.len() as u64;
            if ss.state == streams::SendState::DataSent && ss.bytes_in_flight == 0 {
                ss.state = streams::SendState::DataRecvd;
                self.streams.maybe_cleanup(frame.id);
                self.events.push_back(Event::StreamFinished {
                    stream: frame.id,
                    stop_reason: None,
                });
            }
        }
        self.space_mut(space).pending_acks.subtract(&info.acks);
    }

    /// Process timer expirations
    ///
    /// Executes protocol logic, potentially preparing signals (including application `Event`s,
    /// `EndpointEvent`s and outgoing datagrams) that should be extracted through the relevant
    /// methods.
    pub fn handle_timeout(&mut self, now: Instant, timer: Timer) {
        match timer.0 {
            TimerKind::Close => {
                self.state = State::Drained;
                self.endpoint_events.push_back(EndpointEventInner::Drained);
            }
            TimerKind::Idle => {
                self.close_common();
                self.events.push_back(ConnectionError::TimedOut.into());
                self.state = State::Drained;
                self.endpoint_events.push_back(EndpointEventInner::Drained);
            }
            TimerKind::KeepAlive => {
                trace!(self.log, "sending keep-alive");
                self.ping();
            }
            TimerKind::LossDetection => {
                self.on_loss_detection_timeout(now);
            }
            TimerKind::KeyDiscard => {
                self.zero_rtt_crypto = None;
                self.prev_crypto = None;
            }
            TimerKind::PathValidation => {
                debug!(self.log, "path validation failed");
                self.path_challenge = None;
                self.path_challenge_pending = false;
                if let Some(prev) = self.prev_remote.take() {
                    self.remote = prev;
                }
            }
        }
    }

    fn set_key_discard_timer(&mut self, now: Instant) {
        let start = if self.zero_rtt_crypto.is_some() {
            now
        } else {
            self.prev_crypto
                .as_ref()
                .expect("no previous keys")
                .end_packet
                .as_ref()
                .expect("update not acknowledged yet")
                .1
        };
        self.io
            .timer_start(TimerKind::KeyDiscard, start + self.pto() * 3);
    }

    fn on_loss_detection_timeout(&mut self, now: Instant) {
        if let Some((_, pn_space)) = self.earliest_loss_time() {
            // Time threshold loss Detection
            self.detect_lost_packets(now, pn_space);
        } else if self.in_flight.crypto != 0 {
            trace!(self.log, "retransmitting handshake packets");
            for &space_id in [SpaceId::Initial, SpaceId::Handshake].iter() {
                let space = self.space_mut(space_id);
                for packet in space.sent_packets.values_mut() {
                    space
                        .pending
                        .crypto
                        .extend(packet.retransmits.crypto.drain(..));
                }
            }
            self.crypto_count = self.crypto_count.saturating_add(1);
        } else if self.state.is_handshake() && self.side.is_client() {
            trace!(self.log, "sending anti-deadlock handshake packet");
            self.io.probes += 1;
            self.crypto_count = self.crypto_count.saturating_add(1);
        } else {
            trace!(self.log, "PTO fired"; "in flight" => self.in_flight.bytes);
            self.io.probes += 2;
            self.pto_count = self.pto_count.saturating_add(1);
        }
        self.set_loss_detection_timer();
    }

    fn detect_lost_packets(&mut self, now: Instant, pn_space: SpaceId) {
        let mut lost_packets = Vec::<u64>::new();
        let rtt = self
            .rtt
            .smoothed
            .map_or(self.rtt.latest, |x| cmp::max(x, self.rtt.latest));
        let rtt = cmp::max(rtt, TIMER_GRANULARITY);
        let loss_delay = rtt + ((rtt * u32::from(self.config.time_threshold)) / 65536);

        // Packets sent before this time are deemed lost.
        let lost_send_time = now - loss_delay;
        let largest_acked_packet = self.space(pn_space).largest_acked_packet.unwrap();
        let packet_threshold = self.config.packet_threshold as u64;

        let space = self.space_mut(pn_space);
        space.loss_time = None;
        for (&packet, info) in space.sent_packets.range(0..largest_acked_packet) {
            if info.time_sent <= lost_send_time || largest_acked_packet >= packet + packet_threshold
            {
                lost_packets.push(packet);
            } else {
                let next_loss_time = info.time_sent + loss_delay;
                space.loss_time = Some(
                    space
                        .loss_time
                        .map_or(next_loss_time, |x| cmp::min(x, next_loss_time)),
                );
            }
        }

        // OnPacketsLost
        if let Some(largest_lost) = lost_packets.last().cloned() {
            let old_bytes_in_flight = self.in_flight.bytes;
            let largest_lost_sent = self.space(pn_space).sent_packets[&largest_lost].time_sent;
            self.lost_packets += lost_packets.len() as u64;
            trace!(self.log, "packets lost: {:?}", lost_packets);
            for packet in &lost_packets {
                let info = self
                    .space_mut(pn_space)
                    .sent_packets
                    .remove(&packet)
                    .unwrap();
                self.in_flight.remove(&info);
                self.space_mut(pn_space).pending += info.retransmits;
            }
            // Don't apply congestion penalty for lost ack-only packets
            let lost_ack_eliciting = old_bytes_in_flight != self.in_flight.bytes;

            // InPersistentCongestion: Determine if all packets in the time period before the newest
            // lost packet, including the edges, are marked lost
            let congestion_period = self.pto() * self.config.persistent_congestion_threshold;
            let in_persistent_congestion = self.space(pn_space).largest_acked_packet_sent
                < largest_lost_sent - congestion_period;

            if lost_ack_eliciting {
                self.congestion_event(now, largest_lost_sent);
                if in_persistent_congestion {
                    self.congestion_window = self.config.minimum_window;
                }
            }
        }
    }

    fn congestion_event(&mut self, now: Instant, sent_time: Instant) {
        // Start a new recovery epoch if the lost packet is larger than the end of the
        // previous recovery epoch.
        if self.in_recovery(sent_time) {
            return;
        }
        self.recovery_start_time = now;
        // *= factor
        self.congestion_window =
            (self.congestion_window * u64::from(self.config.loss_reduction_factor)) >> 16;
        self.congestion_window = cmp::max(self.congestion_window, self.config.minimum_window);
        self.ssthresh = self.congestion_window;
    }

    fn in_recovery(&self, sent_time: Instant) -> bool {
        sent_time <= self.recovery_start_time
    }

    fn earliest_loss_time(&self) -> Option<(Instant, SpaceId)> {
        SpaceId::iter()
            .filter_map(|id| self.space(id).loss_time.map(|x| (x, id)))
            .min_by_key(|&(time, _)| time)
    }

    fn set_loss_detection_timer(&mut self) {
        if let Some((loss_time, _)) = self.earliest_loss_time() {
            // Time threshold loss detection.
            self.io.timer_start(TimerKind::LossDetection, loss_time);
            return;
        }

        if self.in_flight.crypto != 0 || (self.state.is_handshake() && self.side.is_client()) {
            // Handshake retransmission timer.
            let timeout = 2 * self
                .rtt
                .smoothed
                .unwrap_or_else(|| Duration::from_micros(self.config.initial_rtt));
            let timeout = cmp::max(timeout, TIMER_GRANULARITY)
                * 2u32.pow(cmp::min(self.crypto_count, MAX_BACKOFF_EXPONENT));
            self.io.timer_start(
                TimerKind::LossDetection,
                self.time_of_last_sent_crypto_packet + timeout,
            );
            return;
        }

        if self.in_flight.ack_eliciting == 0 {
            self.io.timer_stop(TimerKind::LossDetection);
            return;
        }

        // Calculate PTO duration
        let timeout = self.pto() * 2u32.pow(cmp::min(self.pto_count, MAX_BACKOFF_EXPONENT));
        self.io.timer_start(
            TimerKind::LossDetection,
            self.time_of_last_sent_ack_eliciting_packet + timeout,
        );
    }

    /// Probe Timeout
    fn pto(&self) -> Duration {
        let rtt = self
            .rtt
            .smoothed
            .unwrap_or_else(|| Duration::from_micros(self.config.initial_rtt));
        rtt + cmp::max(4 * self.rtt.var, TIMER_GRANULARITY) + self.max_ack_delay()
    }

    fn on_packet_authenticated(
        &mut self,
        now: Instant,
        space_id: SpaceId,
        ecn: Option<EcnCodepoint>,
        packet: Option<u64>,
        spin: bool,
        is_1rtt: bool,
    ) {
        self.reset_keep_alive(now);
        self.reset_idle_timeout(now);
        self.permit_idle_reset = true;
        self.receiving_ecn |= ecn.is_some();
        if let Some(x) = ecn {
            self.ecn_counters += x;
        }

        let packet = match packet {
            Some(x) => x,
            None => return,
        };
        trace!(
            self.log,
            "{space:?} packet {packet} authenticated",
            space = space_id,
            packet = packet
        );
        if self.side.is_server() {
            if self.spaces[SpaceId::Initial as usize].crypto.is_some()
                && space_id == SpaceId::Handshake
            {
                // A server stops sending and processing Initial packets when it receives its first Handshake packet.
                self.discard_space(SpaceId::Initial);
            }
            if self.zero_rtt_crypto.is_some() && is_1rtt {
                // Discard 0-RTT keys soon after receiving a 1-RTT packet
                self.set_key_discard_timer(now)
            }
        }
        let space = &mut self.spaces[space_id as usize];
        space.pending_acks.insert_one(packet);
        if space.pending_acks.len() > MAX_ACK_BLOCKS {
            space.pending_acks.pop_min();
        }
        if packet >= space.rx_packet {
            space.rx_packet = packet;
            space.rx_packet_time = now;
            // Update outgoing spin bit, inverting iff we're the client
            self.spin = self.side.is_client() ^ spin;
        }
    }

    fn reset_idle_timeout(&mut self, now: Instant) {
        if self.idle_timeout == 0 {
            return;
        }
        if self.state.is_closed() {
            self.io.timer_stop(TimerKind::Idle);
            return;
        }
        let dt = cmp::max(Duration::from_millis(self.idle_timeout), 3 * self.pto());
        self.io.timer_start(TimerKind::Idle, now + dt);
    }

    fn reset_keep_alive(&mut self, now: Instant) {
        if self.config.keep_alive_interval == 0 || !self.state.is_established() {
            return;
        }
        self.io.timer_start(
            TimerKind::KeepAlive,
            now + Duration::from_millis(u64::from(self.config.keep_alive_interval)),
        );
    }

    fn queue_stream_data(&mut self, stream: StreamId, data: Bytes) {
        let ss = self.streams.get_send_mut(stream).unwrap();
        assert_eq!(ss.state, streams::SendState::Ready);
        let offset = ss.offset;
        ss.offset += data.len() as u64;
        ss.bytes_in_flight += data.len() as u64;
        self.data_sent += data.len() as u64;
        self.unacked_data += data.len() as u64;
        self.space_mut(SpaceId::Data)
            .pending
            .stream
            .push_back(frame::Stream {
                offset,
                fin: false,
                data,
                id: stream,
            });
    }

    /// Abandon transmitting data on a stream
    ///
    /// # Panics
    /// - when applied to a receive stream or an unopened send stream
    pub fn reset(&mut self, stream_id: StreamId, error_code: VarInt) {
        self.reset_inner(stream_id, error_code, false);
    }

    /// `stopped` should be set iff this is an internal implicit reset due to `STOP_SENDING`
    fn reset_inner(&mut self, stream_id: StreamId, error_code: VarInt, stopped: bool) {
        assert!(
            stream_id.directionality() == Directionality::Bi || stream_id.initiator() == self.side,
            "only streams supporting outgoing data may be reset"
        );

        // reset is a noop on a closed stream
        let stream = match self.streams.get_send_mut(stream_id) {
            Some(x) => x,
            None => return,
        };
        let stop_reason = if stopped { Some(error_code) } else { None };

        use streams::SendState::*;
        match stream.state {
            DataRecvd | ResetSent { .. } | ResetRecvd { .. } => {
                // Nothing to do
                return;
            }
            DataSent => {
                self.events.push_back(Event::StreamFinished {
                    stream: stream_id,
                    stop_reason,
                });
                // No need to hold on to the stop_reason since it's propagated above
                stream.state = ResetSent { stop_reason: None };
            }
            _ => {
                // If this is an implicit reset due to `STOP_SENDING` and the caller might have a
                // blocked write task, notify the caller to try writing again so they'll receive the
                // `WriteError::Stopped` and the stream can be disposed of.
                if stopped
                    && (self.blocked_streams.remove(&stream_id) || stream.offset == stream.max_data)
                {
                    self.events
                        .push_back(Event::StreamWritable { stream: stream_id });
                }
                stream.state = ResetSent { stop_reason };
            }
        }

        self.spaces[SpaceId::Data as usize]
            .pending
            .rst_stream
            .push((stream_id, error_code));
    }

    pub(crate) fn handle_initial(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        ecn: Option<EcnCodepoint>,
        packet_number: u64,
        packet: Packet,
        remaining: Option<BytesMut>,
    ) -> Result<(), TransportError> {
        debug_assert!(self.side.is_server());
        let len = packet.header_data.len() + packet.payload.len();
        self.total_recvd = len as u64;

        self.on_packet_authenticated(
            now,
            SpaceId::Initial,
            ecn,
            Some(packet_number),
            false,
            false,
        );
        self.process_early_payload(now, packet)?;
        if self.state.is_closed() {
            return Ok(());
        }
        let params = self
            .tls
            .transport_parameters()?
            .ok_or_else(|| TransportError {
                code: TransportErrorCode::crypto(0x6d),
                frame: None,
                reason: "transport parameters missing".into(),
            })?;
        self.validate_params(&params)?;
        self.set_params(params);
        if params.active_connection_id_limit != 0 {
            self.endpoint_events
                .push_back(EndpointEventInner::NeedIdentifiers(
                    params.active_connection_id_limit,
                ));
        }
        self.write_tls();
        self.init_0rtt();
        if let Some(data) = remaining {
            self.handle_coalesced(now, remote, ecn, data);
        }
        Ok(())
    }

    fn init_0rtt(&mut self) {
        let packet = match self.tls.early_crypto() {
            Some(x) => x,
            None => return,
        };
        if self.side.is_client() {
            match self.tls.transport_parameters() {
                Ok(params) => {
                    let params =
                        params.expect("rustls didn't supply transport parameters with ticket");
                    // Certain values must not be cached
                    let params = TransportParameters {
                        original_connection_id: None,
                        preferred_address: None,
                        stateless_reset_token: None,
                        ack_delay_exponent: TransportParameters::default().ack_delay_exponent,
                        active_connection_id_limit: 0,
                        ..params
                    };
                    self.set_params(params);
                }
                Err(e) => {
                    error!(
                        self.log,
                        "session ticket has malformed transport parameters: {}", e
                    );
                    return;
                }
            }
        }
        trace!(self.log, "0-RTT enabled");
        self.zero_rtt_enabled = true;
        self.zero_rtt_crypto = Some(CryptoSpace {
            header: packet.header_keys(),
            packet,
        });
    }

    fn read_tls(&mut self, space: SpaceId, crypto: &frame::Crypto) -> Result<(), TransportError> {
        let expected = if !self.state.is_handshake() {
            SpaceId::Data
        } else if self.highest_space == SpaceId::Initial {
            SpaceId::Initial
        } else {
            SpaceId::Handshake
        };
        let end = crypto.offset + crypto.data.len() as u64;
        if space < expected && end > self.space(space).crypto_stream.offset() {
            warn!(
                self.log,
                "received new {actual:?} CRYPTO data when expecting {expected:?}",
                actual = space,
                expected = expected
            );
            return Err(TransportError::PROTOCOL_VIOLATION(
                "new data at unexpected encryption level",
            ));
        }

        let space = &mut self.spaces[space as usize];
        let max = space.crypto_stream.offset() + self.config.crypto_buffer_size as u64;
        if end > max {
            return Err(TransportError::CRYPTO_BUFFER_EXCEEDED(""));
        }
        space
            .crypto_stream
            .insert(crypto.offset, crypto.data.clone());
        let mut buf = [0; 8192];
        loop {
            let n = space.crypto_stream.read(&mut buf);
            if n == 0 {
                return Ok(());
            }
            trace!(self.log, "read {} TLS bytes", n);
            self.tls.read_handshake(&buf[..n])?;
        }
    }

    fn write_tls(&mut self) {
        loop {
            let space = self.highest_space;
            let mut outgoing = Vec::new();
            if let Some(crypto) = self.tls.write_handshake(&mut outgoing) {
                match space {
                    SpaceId::Initial => {
                        self.upgrade_crypto(SpaceId::Handshake, crypto);
                    }
                    SpaceId::Handshake => {
                        self.upgrade_crypto(SpaceId::Data, crypto);
                    }
                    _ => unreachable!("got updated secrets during 1-RTT"),
                }
            }
            if outgoing.is_empty() {
                break;
            }
            let offset = self.space_mut(space).crypto_offset;
            let outgoing = Bytes::from(outgoing);
            if let State::Handshake(ref mut state) = self.state {
                if space == SpaceId::Initial && offset == 0 && self.side.is_client() {
                    state.client_hello = Some(outgoing.clone());
                }
            }
            self.space_mut(space).crypto_offset += outgoing.len() as u64;
            trace!(
                self.log,
                "wrote {} {space:?} TLS bytes",
                outgoing.len(),
                space = space
            );
            self.space_mut(space)
                .pending
                .crypto
                .push_back(frame::Crypto {
                    offset,
                    data: outgoing,
                });
        }
    }

    /// Switch to stronger cryptography during handshake
    fn upgrade_crypto(&mut self, space: SpaceId, crypto: S::Keys) {
        debug_assert!(
            self.spaces[space as usize].crypto.is_none(),
            "already reached packet space {:?}",
            space
        );
        trace!(self.log, "{space:?} keys ready", space = space);
        self.spaces[space as usize].crypto = Some(CryptoSpace::new(crypto));
        debug_assert!(space as usize > self.highest_space as usize);
        self.highest_space = space;
        if space == SpaceId::Data && self.side.is_client() {
            // Discard 0-RTT keys because 1-RTT keys are available.
            self.zero_rtt_crypto = None;
        }
    }

    fn discard_space(&mut self, space: SpaceId) {
        trace!(self.log, "discarding {space:?} keys", space = space);
        self.space_mut(space).crypto = None;
        let sent_packets = mem::replace(&mut self.space_mut(space).sent_packets, BTreeMap::new());
        for (_, packet) in sent_packets.into_iter() {
            self.in_flight.remove(&packet);
        }
    }

    /// Process `ConnectionEvent`s generated by the associated `Endpoint`
    ///
    /// Will execute protocol logic upon receipt of a connection event, in turn preparing signals
    /// (including application `Event`s, `EndpointEvent`s and outgoing datagrams) that should be
    /// extracted through the relevant methods.
    pub fn handle_event(&mut self, event: ConnectionEvent) {
        use self::ConnectionEventInner::*;
        match event.0 {
            Datagram {
                now,
                remote,
                ecn,
                first_decode,
                remaining,
            } => {
                if remote != self.remote && self.side.is_client() {
                    trace!(
                        self.log,
                        "discarding packet from unknown server {address}",
                        address = format!("{}", remote)
                    );
                    return;
                }

                self.total_recvd = self.total_recvd.wrapping_add(first_decode.len() as u64);

                self.handle_decode(now, remote, ecn, first_decode);
                if let Some(data) = remaining {
                    self.handle_coalesced(now, remote, ecn, data);
                }
            }
            NewIdentifiers(ids) => {
                ids.into_iter().for_each(|frame| {
                    self.cids_issued += 1;
                    self.space_mut(SpaceId::Data).pending.new_cids.push(frame);
                });
            }
        }
    }

    fn handle_coalesced(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        ecn: Option<EcnCodepoint>,
        data: BytesMut,
    ) {
        self.total_recvd = self.total_recvd.wrapping_add(data.len() as u64);
        let mut remaining = Some(data);
        while let Some(data) = remaining {
            match PartialDecode::new(data, self.endpoint_config.local_cid_len) {
                Ok((partial_decode, rest)) => {
                    remaining = rest;
                    self.handle_decode(now, remote, ecn, partial_decode);
                }
                Err(e) => {
                    trace!(self.log, "malformed header"; "reason" => %e);
                    return;
                }
            }
        }
    }

    fn handle_decode(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        ecn: Option<EcnCodepoint>,
        partial_decode: PartialDecode,
    ) {
        let header_crypto = if partial_decode.is_0rtt() {
            if let Some(ref crypto) = self.zero_rtt_crypto {
                Some(&crypto.header)
            } else {
                debug!(self.log, "dropping unexpected 0-RTT packet");
                return;
            }
        } else if let Some(space) = partial_decode.space() {
            if let Some(ref crypto) = self.spaces[space as usize].crypto {
                Some(&crypto.header)
            } else {
                debug!(
                    self.log,
                    "discarding unexpected {space:?} packet ({len} bytes)",
                    space = space,
                    len = partial_decode.len(),
                );
                return;
            }
        } else {
            // Unprotected packet
            None
        };

        match partial_decode.finish(header_crypto) {
            Ok(packet) => self.handle_packet(now, remote, ecn, packet),
            Err(e) => {
                trace!(self.log, "unable to complete packet decoding"; "reason" => %e);
            }
        }
    }

    fn handle_packet(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        ecn: Option<EcnCodepoint>,
        mut packet: Packet,
    ) {
        trace!(
            self.log,
            "got {space:?} packet ({len} bytes) from {remote} using id {connection}",
            space = packet.header.space(),
            len = packet.payload.len() + packet.header_data.len(),
            remote = remote,
            connection = packet.header.dst_cid(),
        );
        let was_closed = self.state.is_closed();
        let was_drained = self.state.is_drained();
        let stateless_reset = self.params.stateless_reset_token.map_or(false, |token| {
            packet.payload.len() >= RESET_TOKEN_SIZE
                && packet.payload[packet.payload.len() - RESET_TOKEN_SIZE..] == token[..]
        });

        let result = match self.decrypt_packet(now, &mut packet) {
            Err(Some(e)) => {
                warn!(self.log, "got illegal packet"; "reason" => %e);
                Err(e.into())
            }
            Err(None) => {
                if stateless_reset {
                    debug!(self.log, "got stateless reset");
                    Err(ConnectionError::Reset)
                } else {
                    debug!(self.log, "failed to authenticate packet");
                    return;
                }
            }
            Ok(number) => {
                let duplicate = number.and_then(|n| {
                    if self.space_mut(packet.header.space()).dedup.insert(n) {
                        Some(n)
                    } else {
                        None
                    }
                });

                if let Some(number) = duplicate {
                    if stateless_reset {
                        Err(ConnectionError::Reset)
                    } else {
                        warn!(
                            self.log,
                            "discarding possible duplicate packet {packet}",
                            packet = number
                        );
                        return;
                    }
                } else if self.state.is_handshake() && packet.header.is_short() {
                    // TODO: SHOULD buffer these to improve reordering tolerance.
                    trace!(self.log, "dropping short packet during handshake");
                    return;
                } else {
                    if !self.state.is_closed() {
                        let spin = match packet.header {
                            Header::Short { spin, .. } => spin,
                            _ => false,
                        };
                        self.on_packet_authenticated(
                            now,
                            packet.header.space(),
                            ecn,
                            number,
                            spin,
                            packet.header.is_1rtt(),
                        );
                    }
                    self.handle_connected_inner(now, remote, number, packet)
                }
            }
        };

        // State transitions for error cases
        if let Err(conn_err) = result {
            self.events.push_back(conn_err.clone().into());
            self.state = match conn_err {
                ConnectionError::ApplicationClosed { reason } => State::closed(reason),
                ConnectionError::ConnectionClosed { reason } => State::closed(reason),
                ConnectionError::Reset => State::Drained,
                ConnectionError::TimedOut => {
                    unreachable!("timeouts aren't generated by packet processing");
                }
                ConnectionError::TransportError(err) => {
                    debug!(
                        self.log,
                        "closing connection due to transport error: {error}",
                        error = &err
                    );
                    State::closed(err)
                }
                ConnectionError::VersionMismatch => State::Draining,
                ConnectionError::LocallyClosed => {
                    unreachable!("LocallyClosed isn't generated by packet processing")
                }
            };
        }

        if !was_closed && self.state.is_closed() {
            self.close_common();
            if !self.state.is_drained() {
                self.set_close_timer(now);
            }
        }
        if !was_drained && self.state.is_drained() {
            self.endpoint_events.push_back(EndpointEventInner::Drained);
            // Close timer may have been started previously, e.g. if we sent a close and got a
            // stateless reset in response
            self.io.timer_stop(TimerKind::Close);
        }

        // Transmit CONNECTION_CLOSE if necessary
        if let State::Closed(_) = self.state {
            self.io.close = remote == self.remote;
        }
    }

    fn handle_connected_inner(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        number: Option<u64>,
        packet: Packet,
    ) -> Result<(), ConnectionError> {
        match self.state {
            State::Handshake(ref mut state) => {
                match packet.header {
                    Header::Retry {
                        src_cid: rem_cid,
                        orig_dst_cid,
                        ..
                    } => {
                        if self.side.is_server() {
                            return Err(
                                TransportError::PROTOCOL_VIOLATION("client sent Retry").into()
                            );
                        }
                        if self.orig_rem_cid.is_some() || orig_dst_cid != self.rem_cid {
                            // A client MUST accept and process at most one Retry packet for each
                            // connection attempt, and clients MUST discard Retry packets that
                            // contain an Original Destination Connection ID field that does not
                            // match the Destination Connection ID from its Initial packet.
                            return Ok(());
                        }
                        trace!(self.log, "retrying with CID {rem_cid}", rem_cid = rem_cid);
                        let client_hello = state.client_hello.take().unwrap();
                        self.orig_rem_cid = Some(self.rem_cid);
                        self.rem_cid = rem_cid;
                        self.rem_handshake_cid = rem_cid;
                        self.on_packet_acked(SpaceId::Initial, 0);

                        self.discard_space(SpaceId::Initial); // Make sure we clean up after any retransmitted Initials
                        self.spaces[0] = PacketSpace {
                            crypto: Some(CryptoSpace::new(S::Keys::new_initial(
                                &rem_cid, self.side,
                            ))),
                            next_packet_number: self.spaces[0].next_packet_number,
                            crypto_offset: client_hello.len() as u64,
                            ..PacketSpace::new(now)
                        };
                        self.spaces[0].pending.crypto.push_back(frame::Crypto {
                            offset: 0,
                            data: client_hello,
                        });

                        self.state = State::Handshake(state::Handshake {
                            token: Some(packet.payload.into()),
                            rem_cid_set: false,
                            client_hello: None,
                        });
                        Ok(())
                    }
                    Header::Long {
                        ty: LongType::Handshake,
                        src_cid: rem_cid,
                        ..
                    } => {
                        if rem_cid != self.rem_handshake_cid {
                            debug!(self.log, "discarding packet with mismatched remote CID: {expected} != {actual}", expected = self.rem_handshake_cid, actual = rem_cid);
                            return Ok(());
                        }
                        self.remote_validated = true;

                        let state = state.clone();
                        self.process_early_payload(now, packet)?;
                        if self.state.is_closed() {
                            return Ok(());
                        }

                        if self.tls.is_handshaking() {
                            trace!(self.log, "handshake ongoing");
                            self.state = State::Handshake(state::Handshake {
                                token: None,
                                ..state
                            });
                            return Ok(());
                        }

                        if self.side.is_client() {
                            // Client-only beceause server params were set from the client's Initial
                            let params =
                                self.tls
                                    .transport_parameters()?
                                    .ok_or_else(|| TransportError {
                                        code: TransportErrorCode::crypto(0x6d),
                                        frame: None,
                                        reason: "transport parameters missing".into(),
                                    })?;

                            if self.has_0rtt() {
                                if !self.tls.early_data_accepted().unwrap() {
                                    self.reject_0rtt();
                                } else {
                                    self.accepted_0rtt = true;
                                    if params.initial_max_data < self.params.initial_max_data
                                        || params.initial_max_stream_data_bidi_local
                                            < self.params.initial_max_stream_data_bidi_local
                                        || params.initial_max_stream_data_bidi_remote
                                            < self.params.initial_max_stream_data_bidi_remote
                                        || params.initial_max_stream_data_uni
                                            < self.params.initial_max_stream_data_uni
                                        || params.initial_max_streams_bidi
                                            < self.params.initial_max_streams_bidi
                                        || params.initial_max_streams_uni
                                            < self.params.initial_max_streams_uni
                                    {
                                        return Err(TransportError::PROTOCOL_VIOLATION(
                                            "flow control parameters were reduced wrt. 0-RTT",
                                        )
                                        .into());
                                    }
                                }
                            }
                            self.endpoint_events
                                .push_back(EndpointEventInner::ResetToken(
                                    params.stateless_reset_token.unwrap(),
                                ));
                            self.validate_params(&params)?;
                            self.set_params(params);
                            if params.active_connection_id_limit != 0 {
                                self.endpoint_events.push_back(
                                    EndpointEventInner::NeedIdentifiers(
                                        params.active_connection_id_limit,
                                    ),
                                );
                            }
                        }

                        self.events.push_back(Event::Connected);
                        self.state = State::Established;
                        trace!(self.log, "established");
                        Ok(())
                    }
                    Header::Initial {
                        src_cid: rem_cid, ..
                    } => {
                        if !state.rem_cid_set {
                            trace!(
                                self.log,
                                "switching remote CID to {rem_cid}",
                                rem_cid = rem_cid
                            );
                            let mut state = state.clone();
                            self.rem_cid = rem_cid;
                            self.rem_handshake_cid = rem_cid;
                            state.rem_cid_set = true;
                            self.state = State::Handshake(state);
                        } else if rem_cid != self.rem_handshake_cid {
                            debug!(self.log, "discarding packet with mismatched remote CID: {expected} != {actual}", expected = self.rem_handshake_cid, actual = rem_cid);
                            return Ok(());
                        }
                        self.process_early_payload(now, packet)?;
                        Ok(())
                    }
                    Header::Long {
                        ty: LongType::ZeroRtt,
                        ..
                    } => {
                        self.process_payload(now, remote, number.unwrap(), packet.payload.into())?;
                        Ok(())
                    }
                    Header::VersionNegotiate { .. } => {
                        debug!(self.log, "remote doesn't support our version");
                        Err(ConnectionError::VersionMismatch)
                    }
                    Header::Short { .. } => unreachable!(
                        "short packets received during handshake are discarded in handle_packet"
                    ),
                }
            }
            State::Established => {
                match packet.header.space() {
                    SpaceId::Data => {
                        self.process_payload(now, remote, number.unwrap(), packet.payload.into())?
                    }
                    _ => self.process_early_payload(now, packet)?,
                }
                Ok(())
            }
            State::Closed(_) => {
                for frame in frame::Iter::new(packet.payload.into()) {
                    match frame {
                        Frame::Close(_) => {
                            trace!(self.log, "draining");
                            self.state = State::Draining;
                            return Ok(());
                        }
                        _ => {}
                    };
                }
                Ok(())
            }
            State::Draining | State::Drained => Ok(()),
        }
    }

    /// Process an Initial or Handshake packet payload
    fn process_early_payload(
        &mut self,
        now: Instant,
        packet: Packet,
    ) -> Result<(), TransportError> {
        debug_assert_ne!(packet.header.space(), SpaceId::Data);
        for frame in frame::Iter::new(packet.payload.into()) {
            match frame {
                Frame::Padding => {}
                _ => {
                    trace!(self.log, "got {type}", type=frame.ty());
                }
            }
            match frame {
                Frame::Ack(_) | Frame::Padding => {}
                _ => {
                    self.space_mut(packet.header.space()).permit_ack_only = true;
                }
            }
            match frame {
                Frame::Padding => {}
                Frame::Crypto(frame) => {
                    self.read_tls(packet.header.space(), &frame)?;
                }
                Frame::Ack(ack) => {
                    self.on_ack_received(now, packet.header.space(), ack)?;
                }
                Frame::Close(reason) => {
                    self.events.push_back(ConnectionError::from(reason).into());
                    self.state = State::Draining;
                    return Ok(());
                }
                Frame::Invalid { ty, reason } => {
                    let mut err = TransportError::FRAME_ENCODING_ERROR(reason);
                    err.frame = Some(ty);
                    return Err(err);
                }
                _ => {
                    let mut err =
                        TransportError::PROTOCOL_VIOLATION("illegal frame type in handshake");
                    err.frame = Some(frame.ty());
                    return Err(err);
                }
            }
        }
        self.write_tls();
        Ok(())
    }

    fn process_payload(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        number: u64,
        payload: Bytes,
    ) -> Result<(), TransportError> {
        let is_0rtt = self.space(SpaceId::Data).crypto.is_none();
        let mut is_probing_packet = true;
        for frame in frame::Iter::new(payload) {
            match frame {
                Frame::Padding => {}
                _ => {
                    trace!(self.log, "got {type}", type=frame.ty());
                }
            }
            if is_0rtt {
                match frame {
                    Frame::Crypto(_) | Frame::Close(_) => {
                        return Err(TransportError::PROTOCOL_VIOLATION(
                            "illegal frame type in 0-RTT",
                        ));
                    }
                    _ => {}
                }
            }
            match frame {
                Frame::Ack(_) | Frame::Padding => {}
                _ => {
                    self.space_mut(SpaceId::Data).permit_ack_only = true;
                }
            }
            match frame {
                Frame::Padding
                | Frame::PathChallenge(_)
                | Frame::PathResponse(_)
                | Frame::NewConnectionId(_) => {}
                _ => {
                    is_probing_packet = false;
                }
            }
            match frame {
                Frame::Invalid { ty, reason } => {
                    let mut err = TransportError::FRAME_ENCODING_ERROR(reason);
                    err.frame = Some(ty);
                    return Err(err);
                }
                Frame::Crypto(frame) => {
                    self.read_tls(SpaceId::Data, &frame)?;
                }
                Frame::Stream(frame) => {
                    trace!(self.log, "got stream"; "id" => frame.id.0, "offset" => frame.offset, "len" => frame.data.len(), "fin" => frame.fin);
                    let stream = frame.id;
                    let rs = match self.streams.get_recv_stream(self.side, stream) {
                        Err(e) => {
                            debug!(self.log, "received illegal stream frame"; "stream" => stream.0);
                            return Err(e);
                        }
                        Ok(None) => {
                            trace!(self.log, "dropping frame for closed stream");
                            continue;
                        }
                        Ok(Some(rs)) => rs,
                    };
                    if rs.is_finished() {
                        trace!(self.log, "dropping frame for finished stream");
                        continue;
                    }

                    self.data_recvd += rs.ingest(
                        &self.log,
                        frame,
                        self.data_recvd,
                        self.local_max_data,
                        self.config.stream_receive_window,
                    )?;
                    self.on_stream_frame(true, stream);
                }
                Frame::Ack(ack) => {
                    self.on_ack_received(now, SpaceId::Data, ack)?;
                }
                Frame::Padding | Frame::Ping => {}
                Frame::Close(reason) => {
                    self.events.push_back(ConnectionError::from(reason).into());
                    self.state = State::Draining;
                    self.io.close = true;
                    return Ok(());
                }
                Frame::PathChallenge(token) => {
                    if self
                        .path_response
                        .as_ref()
                        .map_or(true, |x| x.packet <= number)
                    {
                        self.path_response = Some(PathResponse {
                            packet: number,
                            token,
                        });
                    }
                }
                Frame::PathResponse(token) => {
                    if self.path_challenge != Some(token) || remote != self.remote {
                        continue;
                    }
                    trace!(self.log, "path validated");
                    self.io.timer_stop(TimerKind::PathValidation);
                    self.path_challenge = None;
                }
                Frame::MaxData(bytes) => {
                    let was_blocked = self.blocked();
                    self.max_data = cmp::max(bytes, self.max_data);
                    if was_blocked && !self.blocked() {
                        for stream in self.blocked_streams.drain() {
                            self.events.push_back(Event::StreamWritable { stream });
                        }
                    }
                }
                Frame::MaxStreamData { id, offset } => {
                    if id.initiator() != self.side && id.directionality() == Directionality::Uni {
                        debug!(
                            self.log,
                            "got MAX_STREAM_DATA on recv-only {stream}",
                            stream = id
                        );
                        return Err(TransportError::STREAM_STATE_ERROR(
                            "MAX_STREAM_DATA on recv-only stream",
                        ));
                    }
                    if let Some(ss) = self.streams.get_send_mut(id) {
                        if offset > ss.max_data {
                            trace!(self.log, "stream limit increased"; "stream" => id.0,
                                   "old" => ss.max_data, "new" => offset, "current offset" => ss.offset);
                            if ss.offset == ss.max_data {
                                self.events.push_back(Event::StreamWritable { stream: id });
                            }
                            ss.max_data = offset;
                        }
                    } else if id.initiator() == self.side() && self.streams.is_local_unopened(id) {
                        debug!(
                            self.log,
                            "got MAX_STREAM_DATA on unopened {stream}",
                            stream = id
                        );
                        return Err(TransportError::STREAM_STATE_ERROR(
                            "MAX_STREAM_DATA on unopened stream",
                        ));
                    }
                    self.on_stream_frame(false, id);
                }
                Frame::MaxStreams {
                    directionality,
                    count,
                } => {
                    if count > MAX_STREAM_COUNT {
                        return Err(TransportError::STREAM_LIMIT_ERROR(
                            "unrepresentable stream limit",
                        ));
                    }
                    let current = &mut self.streams.max[directionality as usize];
                    if count > *current {
                        *current = count;
                        self.events
                            .push_back(Event::StreamAvailable { directionality });
                    }
                }
                Frame::ResetStream(frame::ResetStream {
                    id,
                    error_code,
                    final_offset,
                }) => {
                    let rs = match self.streams.get_recv_stream(self.side, id) {
                        Err(e) => {
                            debug!(self.log, "received illegal RST_STREAM");
                            return Err(e);
                        }
                        Ok(None) => {
                            trace!(self.log, "received RST_STREAM on closed stream");
                            continue;
                        }
                        Ok(Some(stream)) => stream,
                    };
                    let limit = rs.limit();

                    // Validate final_offset
                    if let Some(offset) = rs.final_offset() {
                        if offset != final_offset {
                            return Err(TransportError::FINAL_OFFSET_ERROR("inconsistent value"));
                        }
                    } else if limit > final_offset {
                        return Err(TransportError::FINAL_OFFSET_ERROR(
                            "lower than high water mark",
                        ));
                    }

                    // State transition
                    rs.reset(error_code, final_offset);

                    // Update flow control
                    if rs.bytes_read != final_offset {
                        self.data_recvd += final_offset - limit;
                        // bytes_read is always <= limit, so this won't underflow.
                        self.local_max_data += final_offset - rs.bytes_read;
                        self.space_mut(SpaceId::Data).pending.max_data = true;
                    }

                    // Notify application
                    self.on_stream_frame(true, id);
                }
                Frame::DataBlocked { offset } => {
                    debug!(self.log, "peer claims to be blocked at connection level"; "offset" => offset);
                }
                Frame::StreamDataBlocked { id, offset } => {
                    if id.initiator() == self.side && id.directionality() == Directionality::Uni {
                        debug!(
                            self.log,
                            "got STREAM_DATA_BLOCKED on send-only {stream}",
                            stream = id
                        );
                        return Err(TransportError::STREAM_STATE_ERROR(
                            "STREAM_DATA_BLOCKED on send-only stream",
                        ));
                    }
                    debug!(self.log, "peer claims to be blocked at stream level"; "stream" => id, "offset" => offset);
                }
                Frame::StreamsBlocked {
                    directionality,
                    limit,
                } => {
                    debug!(self.log, "peer claims to be blocked opening more than {limit} {directionality} streams", limit=limit, directionality=directionality);
                }
                Frame::StopSending(frame::StopSending { id, error_code }) => {
                    if id.initiator() != self.side {
                        if id.directionality() == Directionality::Uni {
                            debug!(
                                self.log,
                                "got STOP_SENDING on recv-only {stream}",
                                stream = id
                            );
                            return Err(TransportError::STREAM_STATE_ERROR(
                                "STOP_SENDING on recv-only stream",
                            ));
                        }
                    } else if self.streams.is_local_unopened(id) {
                        return Err(TransportError::STREAM_STATE_ERROR(
                            "STOP_SENDING on unopened stream",
                        ));
                    }
                    self.reset_inner(id, error_code, true);
                    // We might have already closed this stream
                    if let Some(ss) = self.streams.get_send_mut(id) {
                        // Don't reopen an already-closed stream we haven't forgotten yet
                        if !ss.is_closed() {
                            self.on_stream_frame(false, id);
                        }
                    }
                }
                Frame::RetireConnectionId { sequence } => {
                    if self.endpoint_config.local_cid_len == 0 {
                        return Err(TransportError::PROTOCOL_VIOLATION(
                            "RETIRE_CONNECTION_ID when CIDs aren't in use",
                        ));
                    }
                    if sequence > self.cids_issued {
                        debug!(
                            self.log,
                            "got RETIRE_CONNECTION_ID for unissued cid sequence number {sequence}",
                            sequence = sequence,
                        );
                        return Err(TransportError::PROTOCOL_VIOLATION(
                            "RETIRE_CONNECTION_ID for unissued sequence number",
                        ));
                    }
                    self.endpoint_events
                        .push_back(EndpointEventInner::RetireConnectionId(sequence));
                }
                Frame::NewConnectionId(frame) => {
                    trace!(
                        self.log,
                        "NEW_CONNECTION_ID {sequence} = {id}",
                        sequence = frame.sequence,
                        id = frame.id,
                    );
                    if self.rem_cid.is_empty() {
                        return Err(TransportError::PROTOCOL_VIOLATION(
                            "NEW_CONNECTION_ID when CIDs aren't in use",
                        ));
                    }
                    if frame.retire_prior_to > frame.sequence {
                        return Err(TransportError::PROTOCOL_VIOLATION(
                            "NEW_CONNECTION_ID retiring unissued CIDs",
                        ));
                    }

                    if frame.retire_prior_to > self.first_unretired_cid {
                        self.first_unretired_cid = frame.retire_prior_to;
                        self.rem_cids
                            .retain(|x| x.sequence >= frame.retire_prior_to);
                    }

                    let issued = IssuedCid {
                        sequence: frame.sequence,
                        id: frame.id,
                        reset_token: frame.reset_token,
                    };
                    if self.params.stateless_reset_token.is_none() {
                        // We're a server using the initial remote CID for the client, so let's
                        // switch immediately to enable clientside stateless resets.
                        debug_assert!(self.side.is_server());
                        debug_assert_eq!(self.rem_cid_seq, 0);
                        self.update_rem_cid(issued);
                    } else {
                        // Reasonable limit to bound memory use
                        if (self.rem_cids.len() as u64) < REM_CID_COUNT {
                            self.rem_cids.push(issued);
                        }
                    }

                    if self.rem_cid_seq < self.first_unretired_cid {
                        // If our current CID is earlier than the first unretired one we must not
                        // have adopted the one we just got, so it must be cached, so this unwrap is
                        // guaranteed to succeed.
                        let new = self.rem_cids.pop().unwrap();
                        self.update_rem_cid(new);
                    }
                }
                Frame::NewToken { .. } => {
                    trace!(self.log, "got new token");
                    // TODO: Cache, or perhaps forward to user?
                }
            }
        }

        if remote != self.remote && !is_probing_packet {
            let server_config = self
                .server_config
                .as_ref()
                .expect("packets from unknown remote should be dropped by clients");
            if !server_config.migration {
                return Err(TransportError::INVALID_MIGRATION(""));
            }
            self.migrate(now, remote);
            // Break linkability, if possible
            if let Some(cid) = self.rem_cids.pop() {
                self.update_rem_cid(cid);
            }
        }

        Ok(())
    }

    /// Notify the application that new streams were opened or a stream became readable.
    fn on_stream_frame(&mut self, notify_readable: bool, stream: StreamId) {
        if stream.initiator() == self.side {
            // Notifying about the opening of locally-initiated streams would be redundant.
            if notify_readable {
                self.events.push_back(Event::StreamReadable { stream });
            }
            return;
        }
        let next = &mut self.streams.next_remote[stream.directionality() as usize];
        if stream.index() >= *next {
            *next = stream.index() + 1;
            self.stream_opened = true;
        } else if notify_readable {
            self.events.push_back(Event::StreamReadable { stream });
        }
    }

    fn migrate(&mut self, now: Instant, remote: SocketAddr) {
        trace!(
            self.log,
            "migration initiated from {remote}",
            remote = remote
        );
        if remote.ip() != self.remote.ip() {
            // Reset rtt/congestion state for new path
            self.rtt = RttEstimator::new();
            self.congestion_window = self.config.initial_window;
            self.ssthresh = u64::max_value();
        }
        self.prev_remote = Some(mem::replace(&mut self.remote, remote));

        // Initiate path validation
        self.io.timer_start(
            TimerKind::PathValidation,
            now + 3 * cmp::max(
                self.pto(),
                Duration::from_micros(2 * self.config.initial_rtt),
            ),
        );
        self.path_challenge = Some(self.rng.gen());
        self.path_challenge_pending = true;
    }

    fn update_rem_cid(&mut self, new: IssuedCid) {
        trace!(
            self.log,
            "switching to remote CID {sequence}: {connection_id}",
            sequence = new.sequence,
            connection_id = new.id
        );
        let retired = self.rem_cid_seq;
        self.space_mut(SpaceId::Data)
            .pending
            .retire_cids
            .push(retired);
        self.rem_cid = new.id;
        self.rem_cid_seq = new.sequence;
        self.endpoint_events
            .push_back(EndpointEventInner::ResetToken(new.reset_token));
        self.params.stateless_reset_token = Some(new.reset_token);
        // Reduce linkability
        self.spin = false;
    }

    /// Returns packets to transmit
    ///
    /// Connections should be polled for transmit after:
    /// - the application performed some I/O on the connection
    /// - an incoming packet is handled
    /// - the LossDetection timer expires
    pub fn poll_transmit(&mut self, now: Instant) -> Option<Transmit> {
        if self.state.is_handshake()
            && !self.remote_validated
            && self.side.is_server()
            && self.total_recvd * 3 < self.total_sent + u64::from(self.mtu)
        {
            trace!(self.log, "blocked by anti-amplification");
            return None;
        }

        let (spaces, close) = match self.state {
            State::Drained => {
                return None;
            }
            State::Draining | State::Closed(_) => {
                if mem::replace(&mut self.io.close, false) {
                    (vec![self.highest_space], true)
                } else {
                    return None;
                }
            }
            _ => (
                SpaceId::iter()
                    .filter(|&x| {
                        (self.space(x).crypto.is_some() && self.space(x).can_send())
                            || (x == self.highest_space && self.io.probes != 0)
                            || (x == SpaceId::Data
                                && ((self.space(x).crypto.is_some() && self.can_send_1rtt())
                                    || (self.zero_rtt_crypto.is_some()
                                        && self.side.is_client()
                                        && (self.space(x).can_send() || self.can_send_1rtt()))))
                    })
                    .collect(),
                false,
            ),
        };

        let mut buf = Vec::with_capacity(self.mtu as usize);
        let mut coalesce = spaces.len() > 1;
        let pad_space = if self.side.is_client() && spaces.first() == Some(&SpaceId::Initial) {
            spaces.last().cloned()
        } else {
            None
        };

        for space_id in spaces {
            let probe = !close && self.io.probes != 0;
            let mut ack_only = self.space(space_id).pending.is_empty();
            if space_id == SpaceId::Data {
                ack_only &= self.path_response.is_none();
                if !probe && !ack_only && self.congestion_blocked() {
                    continue;
                }
            }

            //
            // From here on, we've determined that a packet will definitely be sent.
            //

            self.io.probes = self.io.probes.saturating_sub(1);
            if self.spaces[SpaceId::Initial as usize].crypto.is_some()
                && space_id == SpaceId::Handshake
                && self.side.is_client()
            {
                // A client stops both sending and processing Initial packets when it
                // sends its first Handshake packet.
                self.discard_space(SpaceId::Initial);
            }
            if let Some(ref mut prev) = self.prev_crypto {
                prev.update_unacked = false;
            }

            let space = &mut self.spaces[space_id as usize];
            let exact_number = space.get_tx_number();
            trace!(
                self.log,
                "sending {space:?} packet {number}",
                space = space_id,
                number = exact_number
            );
            let number = PacketNumber::new(exact_number, space.largest_acked_packet.unwrap_or(0));
            let header = match space_id {
                SpaceId::Data if space.crypto.is_some() => Header::Short {
                    dst_cid: self.rem_cid,
                    number,
                    spin: if self.spin_enabled {
                        self.spin
                    } else {
                        self.rng.gen()
                    },
                    key_phase: self.key_phase,
                },
                SpaceId::Data => Header::Long {
                    ty: LongType::ZeroRtt,
                    src_cid: self.handshake_cid,
                    dst_cid: self.rem_cid,
                    number,
                },
                SpaceId::Handshake => Header::Long {
                    ty: LongType::Handshake,
                    src_cid: self.handshake_cid,
                    dst_cid: self.rem_cid,
                    number,
                },
                SpaceId::Initial => Header::Initial {
                    src_cid: self.handshake_cid,
                    dst_cid: self.rem_cid,
                    token: match self.state {
                        State::Handshake(ref state) => {
                            state.token.clone().unwrap_or_else(Bytes::new)
                        }
                        _ => Bytes::new(),
                    },
                    number,
                },
            };
            let partial_encode = header.encode(&mut buf);
            coalesce = coalesce && !header.is_short();

            if probe && ack_only && header.is_1rtt() {
                // Nothing ack-eliciting to send, so we need to make something up
                self.ping_pending = true;
            }
            ack_only &= !self.ping_pending;

            let sent = if close {
                trace!(self.log, "sending CONNECTION_CLOSE");
                let max_len = buf.capacity()
                    - partial_encode.start
                    - partial_encode.header_len
                    - space.crypto.as_ref().unwrap().packet.tag_len();
                match self.state {
                    State::Closed(state::Closed { ref reason }) => reason.encode(&mut buf, max_len),
                    State::Draining => frame::ConnectionClose {
                        error_code: TransportErrorCode::NO_ERROR,
                        frame_type: None,
                        reason: Bytes::new(),
                    }
                    .encode(&mut buf, max_len),
                    _ => unreachable!(
                        "tried to make a close packet when the connection wasn't closed"
                    ),
                }
                coalesce = false;
                None
            } else {
                Some(self.populate_packet(now, space_id, &mut buf))
            };

            let space = &mut self.spaces[space_id as usize];
            let crypto = if let Some(ref crypto) = space.crypto {
                if self.first_1rtt_sent.is_none() && space_id == SpaceId::Data {
                    self.first_1rtt_sent = Some(exact_number);
                }
                crypto
            } else if space_id == SpaceId::Data {
                self.zero_rtt_crypto.as_ref().unwrap()
            } else {
                unreachable!("tried to send {:?} packet without keys", space_id);
            };

            let mut padded = if pad_space == Some(space_id)
                && buf.len() < MIN_INITIAL_SIZE - crypto.packet.tag_len()
            {
                // Initial-only packets MUST be padded
                buf.resize(MIN_INITIAL_SIZE - crypto.packet.tag_len(), 0);
                true
            } else {
                false
            };

            let pn_len = number.len();
            // To ensure that sufficient data is available for sampling, packets are padded so that the
            // combined lengths of the encoded packet number and protected payload is at least 4 bytes
            // longer than the sample required for header protection.
            let protected_payload_len = (buf.len() + crypto.packet.tag_len())
                - partial_encode.start
                - partial_encode.header_len;
            if let Some(padding_minus_one) =
                (crypto.header.sample_size() + 3).checked_sub(pn_len + protected_payload_len)
            {
                let padding = padding_minus_one + 1;
                padded = true;
                trace!(self.log, "PADDING * {count}", count = padding);
                buf.resize(buf.len() + padding, 0);
            }

            buf.resize(buf.len() + crypto.packet.tag_len(), 0);
            debug_assert!(buf.len() < self.mtu as usize);
            let packet_buf = &mut buf[partial_encode.start..];
            partial_encode.finish(
                packet_buf,
                &crypto.header,
                Some((exact_number, &crypto.packet)),
            );

            if let Some((sent, acks)) = sent {
                // If we sent any acks, don't immediately resend them. Setting this even if ack_only is
                // false needlessly prevents us from ACKing the next packet if it's ACK-only, but saves
                // the need for subtler logic to avoid double-transmitting acks all the time.
                space.permit_ack_only &= acks.is_empty();

                self.on_packet_sent(
                    now,
                    space_id,
                    exact_number,
                    SentPacket {
                        acks,
                        time_sent: now,
                        size: if padded || !ack_only {
                            buf.len() as u16
                        } else {
                            0
                        },
                        is_crypto_packet: space_id != SpaceId::Data && !sent.crypto.is_empty(),
                        ack_eliciting: !ack_only,
                        retransmits: sent,
                    },
                );
            }

            if !coalesce || buf.capacity() - buf.len() < MIN_PACKET_SPACE {
                break;
            }
        }

        if buf.is_empty() {
            return None;
        }

        trace!(self.log, "{len} bytes", len = buf.len());
        self.total_sent = self.total_sent.wrapping_add(buf.len() as u64);

        Some(Transmit {
            destination: self.remote,
            contents: buf.into(),
            ecn: if self.sending_ecn {
                Some(EcnCodepoint::ECT0)
            } else {
                None
            },
        })
    }

    fn populate_packet(
        &mut self,
        now: Instant,
        space_id: SpaceId,
        buf: &mut Vec<u8>,
    ) -> (Retransmits, RangeSet) {
        let space = &mut self.spaces[space_id as usize];
        let mut sent = Retransmits::default();
        let zero_rtt_crypto = self.zero_rtt_crypto.as_ref();
        let tag_len = space
            .crypto
            .as_ref()
            .unwrap_or_else(|| {
                debug_assert_eq!(
                    space_id,
                    SpaceId::Data,
                    "tried to send {:?} packet without keys",
                    space_id
                );
                zero_rtt_crypto.unwrap()
            })
            .packet
            .tag_len();
        let max_size = buf.capacity() - tag_len;
        let is_0rtt = space_id == SpaceId::Data && space.crypto.is_none();
        let is_1rtt = space_id == SpaceId::Data && space.crypto.is_some();

        // PING
        if is_1rtt && mem::replace(&mut self.ping_pending, false) {
            trace!(self.log, "PING");
            buf.write(frame::Type::PING);
        }

        // ACK
        // 0-RTT packets must never carry acks (which would have to be of handshake packets)
        let acks = if !space.pending_acks.is_empty() {
            debug_assert!(space.crypto.is_some(), "tried to send ACK in 0-RTT");
            let delay = (instant_saturating_sub(now, space.rx_packet_time).as_micros()
                >> ACK_DELAY_EXPONENT) as u64;
            trace!(self.log, "ACK"; "ranges" => ?space.pending_acks.iter().collect::<Vec<_>>(), "delay" => delay);
            let ecn = if self.receiving_ecn {
                Some(&self.ecn_counters)
            } else {
                None
            };
            frame::Ack::encode(delay, &space.pending_acks, ecn, buf);
            space.pending_acks.clone()
        } else {
            RangeSet::new()
        };

        // PATH_CHALLENGE
        if buf.len() + 9 < max_size && space_id == SpaceId::Data {
            // Transmit challenges with every outgoing frame on an unvalidated path
            if let Some(token) = self.path_challenge {
                // But only send a packet solely for that purpose at most once
                self.path_challenge_pending = false;
                trace!(self.log, "PATH_CHALLENGE {token:08x}", token = token);
                buf.write(frame::Type::PATH_CHALLENGE);
                buf.write(token);
            }
        }

        // PATH_RESPONSE
        if buf.len() + 9 < max_size && space_id == SpaceId::Data {
            if let Some(response) = self.path_response.take() {
                trace!(
                    self.log,
                    "PATH_RESPONSE {token:08x}",
                    token = response.token
                );
                buf.write(frame::Type::PATH_RESPONSE);
                buf.write(response.token);
            }
        }

        // CRYPTO
        while buf.len() + frame::Crypto::SIZE_BOUND < max_size && !is_0rtt {
            let mut frame = match space.pending.crypto.pop_front() {
                Some(x) => x,
                None => break,
            };
            let len = cmp::min(
                frame.data.len(),
                max_size as usize - buf.len() - frame::Crypto::SIZE_BOUND,
            );
            let data = frame.data.split_to(len);
            let truncated = frame::Crypto {
                offset: frame.offset,
                data,
            };
            trace!(
                self.log,
                "CRYPTO: off {offset} len {length}",
                offset = truncated.offset,
                length = truncated.data.len()
            );
            truncated.encode(buf);
            sent.crypto.push_back(truncated);
            if !frame.data.is_empty() {
                frame.offset += len as u64;
                space.pending.crypto.push_front(frame);
            }
        }

        // RESET_STREAM
        while buf.len() + frame::ResetStream::SIZE_BOUND < max_size && space_id == SpaceId::Data {
            let (id, error_code) = match space.pending.rst_stream.pop() {
                Some(x) => x,
                None => break,
            };
            let stream = match self.streams.get_send_mut(id) {
                Some(x) => x,
                None => continue,
            };
            trace!(self.log, "RESET_STREAM"; "stream" => id.0);
            sent.rst_stream.push((id, error_code));
            frame::ResetStream {
                id,
                error_code,
                final_offset: stream.offset,
            }
            .encode(buf);
        }

        // STOP_SENDING
        while buf.len() + frame::StopSending::SIZE_BOUND < max_size && space_id == SpaceId::Data {
            let frame = match space.pending.stop_sending.pop() {
                Some(x) => x,
                None => break,
            };
            let stream = match self.streams.get_recv_mut(frame.id) {
                Some(x) => x,
                None => continue,
            };
            if stream.is_finished() {
                continue;
            }
            trace!(self.log, "STOP_SENDING"; "stream" => frame.id);
            frame.encode(buf);
            sent.stop_sending.push(frame);
        }

        // MAX_DATA
        if space.pending.max_data && buf.len() + 9 < max_size {
            trace!(self.log, "MAX_DATA"; "value" => self.local_max_data);
            space.pending.max_data = false;
            sent.max_data = true;
            buf.write(frame::Type::MAX_DATA);
            buf.write_var(self.local_max_data);
        }

        // MAX_STREAM_DATA
        while buf.len() + 17 < max_size {
            let id = match space.pending.max_stream_data.iter().next() {
                Some(x) => *x,
                None => break,
            };
            space.pending.max_stream_data.remove(&id);
            let rs = match self.streams.get_recv_mut(id) {
                Some(x) => x,
                None => continue,
            };
            if rs.is_finished() {
                continue;
            }
            sent.max_stream_data.insert(id);
            let max = rs.bytes_read + self.config.stream_receive_window;
            trace!(
                self.log,
                "MAX_STREAM_DATA: {stream} = {max}",
                stream = id,
                max = max
            );
            buf.write(frame::Type::MAX_STREAM_DATA);
            buf.write(id);
            buf.write_var(max);
        }

        // MAX_STREAMS_UNI
        if space.pending.max_uni_stream_id && buf.len() + 9 < max_size {
            space.pending.max_uni_stream_id = false;
            sent.max_uni_stream_id = true;
            trace!(self.log, "MAX_STREAMS (unidirectional)"; "value" => self.streams.max_remote[Directionality::Uni as usize]);
            buf.write(frame::Type::MAX_STREAMS_UNI);
            buf.write_var(self.streams.max_remote[Directionality::Uni as usize]);
        }

        // MAX_STREAMS_BIDI
        if space.pending.max_bi_stream_id && buf.len() + 9 < max_size {
            space.pending.max_bi_stream_id = false;
            sent.max_bi_stream_id = true;
            trace!(self.log, "MAX_STREAMS (bidirectional)"; "value" => self.streams.max_remote[Directionality::Bi as usize] - 1);
            buf.write(frame::Type::MAX_STREAMS_BIDI);
            buf.write_var(self.streams.max_remote[Directionality::Bi as usize]);
        }

        // NEW_CONNECTION_ID
        while buf.len() + 44 < max_size {
            let issued = match space.pending.new_cids.pop() {
                Some(x) => x,
                None => break,
            };
            trace!(
                self.log,
                "NEW_CONNECTION_ID {sequence} = {id}",
                sequence = issued.sequence,
                id = issued.id,
            );
            frame::NewConnectionId {
                sequence: issued.sequence,
                retire_prior_to: 0,
                id: issued.id,
                reset_token: issued.reset_token,
            }
            .encode(buf);
            sent.new_cids.push(issued);
        }

        // RETIRE_CONNECTION_ID
        while buf.len() + frame::RETIRE_CONNECTION_ID_SIZE_BOUND < max_size {
            let seq = match space.pending.retire_cids.pop() {
                Some(x) => x,
                None => break,
            };
            trace!(self.log, "RETIRE_CONNECTION_ID {sequence}", sequence = seq);
            buf.write(frame::Type::RETIRE_CONNECTION_ID);
            buf.write_var(seq);
            sent.retire_cids.push(seq);
        }

        // STREAM
        while buf.len() + frame::Stream::SIZE_BOUND < max_size {
            let mut stream = match space.pending.stream.pop_front() {
                Some(x) => x,
                None => break,
            };
            if self
                .streams
                .get_send_mut(stream.id)
                .map_or(true, |s| s.state.was_reset())
            {
                self.unacked_data -= stream.data.len() as u64;
                continue;
            }
            let len = cmp::min(
                stream.data.len(),
                max_size as usize - buf.len() - frame::Stream::SIZE_BOUND,
            );
            let data = stream.data.split_to(len);
            let fin = stream.fin && stream.data.is_empty();
            trace!(self.log, "STREAM"; "id" => stream.id.0, "off" => stream.offset, "len" => len, "fin" => fin);
            let frame = frame::Stream {
                id: stream.id,
                offset: stream.offset,
                fin,
                data,
            };
            frame.encode(true, buf);
            sent.stream.push_back(frame);
            if !stream.data.is_empty() {
                stream.offset += len as u64;
                space.pending.stream.push_front(stream);
            }
        }

        (sent, acks)
    }

    /// Close a connection immediately
    ///
    /// This does not ensure delivery of outstanding data. It is the application's responsibility
    /// to call this only when all important communications have been completed.
    pub fn close(&mut self, now: Instant, error_code: VarInt, reason: Bytes) {
        let was_closed = self.state.is_closed();
        if !was_closed {
            self.close_common();
            self.set_close_timer(now);
            self.io.close = true;
            self.state = State::Closed(state::Closed {
                reason: Close::Application(frame::ApplicationClose { error_code, reason }),
            });
        }
    }

    fn close_common(&mut self) {
        trace!(self.log, "connection closed");
        for (_, timer) in &mut self.io.timers {
            *timer = Some(TimerSetting::Stop);
        }
    }

    fn set_close_timer(&mut self, now: Instant) {
        self.io.timer_start(TimerKind::Close, now + 3 * self.pto());
    }

    /// Validate transport parameters received from the peer
    fn validate_params(&mut self, params: &TransportParameters) -> Result<(), TransportError> {
        if self.side.is_client() && self.orig_rem_cid != params.original_connection_id {
            debug!(
                self.log,
                "original connection ID mismatch: expected {expected:x?}, actual {actual:x?}",
                expected = self.orig_rem_cid,
                actual = params.original_connection_id
            );
            return Err(TransportError::TRANSPORT_PARAMETER_ERROR(
                "original CID mismatch",
            ));
        }
        if params.initial_max_streams_bidi > MAX_STREAM_COUNT
            || params.initial_max_streams_uni > MAX_STREAM_COUNT
        {
            return Err(TransportError::STREAM_LIMIT_ERROR(
                "unrepresentable initial stream limit",
            ));
        }

        Ok(())
    }

    fn set_params(&mut self, params: TransportParameters) {
        self.streams.max[Directionality::Bi as usize] = params.initial_max_streams_bidi;
        self.streams.max[Directionality::Uni as usize] = params.initial_max_streams_uni;
        self.max_data = params.initial_max_data as u64;
        for i in 0..self.streams.max_remote[Directionality::Bi as usize] {
            let id = StreamId::new(!self.side, Directionality::Bi, i as u64);
            self.streams.get_send_mut(id).unwrap().max_data =
                params.initial_max_stream_data_bidi_local as u64;
        }
        self.idle_timeout = if self.config.idle_timeout == 0 || params.idle_timeout == 0 {
            cmp::max(self.config.idle_timeout, params.idle_timeout)
        } else {
            cmp::min(self.config.idle_timeout, params.idle_timeout)
        };
        self.params = params;
    }

    /// Open a single stream if possible
    ///
    /// Returns `None` if the streams in the given direction are currently exhausted.
    pub fn open(&mut self, dir: Directionality) -> Option<StreamId> {
        let id = self.streams.open(self.side, dir)?;
        // TODO: Queue STREAM_ID_BLOCKED if None
        self.streams.get_send_mut(id).unwrap().max_data = match dir {
            Directionality::Uni => self.params.initial_max_stream_data_uni,
            Directionality::Bi => self.params.initial_max_stream_data_bidi_remote,
        } as u64;
        Some(id)
    }

    /// Ping the remote endpoint
    ///
    /// Causes an ACK-eliciting packet to be transmitted.
    pub fn ping(&mut self) {
        self.ping_pending = true;
    }

    /// Permit an additional remote `ty` stream.
    fn alloc_remote_stream(&mut self, dir: Directionality) {
        let space = &mut self.spaces[SpaceId::Data as usize];
        match dir {
            Directionality::Bi => {
                space.pending.max_bi_stream_id = true;
            }
            Directionality::Uni => {
                space.pending.max_uni_stream_id = true;
            }
        }
        self.streams.alloc_remote_stream(self.side, dir);
    }

    /// Accept a remotely initiated stream if possible
    ///
    /// Returns `None` if there are no new incoming streams for this connection.
    pub fn accept(&mut self) -> Option<StreamId> {
        let id = self.streams.accept(self.side)?;
        self.alloc_remote_stream(id.directionality());
        Some(id)
    }

    /// Finish a send stream, signalling that no more data will be sent
    pub fn finish(&mut self, id: StreamId) -> Result<(), FinishError> {
        let ss = self
            .streams
            .get_send_mut(id)
            .ok_or(FinishError::UnknownStream)?;
        ss.finish()?;
        self.spaces[SpaceId::Data as usize].finish_stream(id, ss.offset);
        Ok(())
    }

    /// Read from the given recv stream, in undefined order
    ///
    /// While stream data is usually returned to the application in order, for some applications
    /// it can make sense to leverage the reduced latency of unordered reads. For ordered reads,
    /// the sibling `read()` method can be used.
    ///
    /// The return value if `Ok` contains the bytes and their offset in the stream.
    pub fn read_unordered(&mut self, id: StreamId) -> Result<Option<(Bytes, u64)>, ReadError> {
        Ok(self.streams.read_unordered(id)?.map(|(buf, offset, more)| {
            self.add_read_credits(id, buf.len() as u64, more);
            (buf, offset)
        }))
    }

    /// Read from the given recv stream
    pub fn read(&mut self, id: StreamId, buf: &mut [u8]) -> Result<Option<usize>, ReadError> {
        Ok(self.streams.read(id, buf)?.map(|(len, more)| {
            self.add_read_credits(id, len as u64, more);
            len
        }))
    }

    fn add_read_credits(&mut self, id: StreamId, len: u64, more: bool) {
        self.local_max_data += len;
        let space = &mut self.spaces[SpaceId::Data as usize];
        space.pending.max_data = true;
        if more {
            // Only bother issuing stream credit if the peer wants to send more
            space.pending.max_stream_data.insert(id);
        }
    }

    /// Signal to the peer that it should stop sending on the given recv stream
    pub fn stop_sending(&mut self, id: StreamId, error_code: VarInt) {
        assert!(
            id.directionality() == Directionality::Bi || id.initiator() != self.side,
            "only streams supporting incoming data may be stopped"
        );
        let stream = self.streams.get_recv_mut(id).unwrap();
        // Only bother if there's data we haven't received yet
        if !stream.is_finished() {
            let space = &mut self.spaces[SpaceId::Data as usize];
            space
                .pending
                .stop_sending
                .push(frame::StopSending { id, error_code });
        }
    }

    fn congestion_blocked(&self) -> bool {
        if let State::Established = self.state {
            self.congestion_window.saturating_sub(self.in_flight.bytes) < u64::from(self.mtu)
        } else {
            false
        }
    }

    fn blocked(&self) -> bool {
        self.data_sent >= self.max_data
            || self.congestion_blocked()
            || self.unacked_data >= self.config.send_window
    }

    fn decrypt_packet(
        &mut self,
        now: Instant,
        packet: &mut Packet,
    ) -> Result<Option<u64>, Option<TransportError>> {
        if !packet.header.is_protected() {
            // Unprotected packets also don't have packet numbers
            return Ok(None);
        }
        let space = packet.header.space();
        let rx_packet = self.space(space).rx_packet;
        let number = packet.header.number().ok_or(None)?.expand(rx_packet + 1);
        let key_phase = packet.header.key_phase();

        let mut crypto_update = None;
        let crypto = if packet.header.is_0rtt() {
            &self.zero_rtt_crypto.as_ref().unwrap().packet
        } else if key_phase == self.key_phase || space != SpaceId::Data {
            &self.spaces[space as usize].crypto.as_mut().unwrap().packet
        } else if let Some(prev) = self.prev_crypto.as_ref().and_then(|crypto| {
            // If this packet comes prior to acknowledgment of the key update by the peer,
            if crypto.end_packet.map_or(true, |(pn, _)| number < pn) {
                // use the previous keys.
                Some(crypto)
            } else {
                // Otherwise, this must be a remotely-initiated key update, so fall through to the
                // final case.
                None
            }
        }) {
            &prev.crypto
        } else {
            // We're in the Data space with a key phase mismatch and either there is no locally
            // initiated key update or the locally initiated key update was acknowledged by a
            // lower-numbered packet. The key phase mismatch must therefore represent a new
            // remotely-initiated key update.
            crypto_update = Some(
                self.tls.update_keys(
                    &self.spaces[SpaceId::Data as usize]
                        .crypto
                        .as_ref()
                        .unwrap()
                        .packet,
                ),
            );
            crypto_update.as_ref().unwrap()
        };

        crypto
            .decrypt(number, &packet.header_data, &mut packet.payload)
            .map_err(|()| {
                trace!(
                    self.log,
                    "decryption failed with packet number {packet}",
                    packet = number
                );
                None
            })?;

        if let Some(ref mut prev) = self.prev_crypto {
            if prev.end_packet.is_none() && key_phase == self.key_phase {
                // Outgoing key update newly acknowledged
                prev.end_packet = Some((number, now));
                self.set_key_discard_timer(now);
            }
        }

        let reserved = match packet.header {
            Header::Short { .. } => SHORT_RESERVED_BITS,
            _ => LONG_RESERVED_BITS,
        };
        if packet.header_data[0] & reserved != 0 {
            return Err(Some(TransportError::PROTOCOL_VIOLATION(
                "reserved bits set",
            )));
        }

        if let Some(crypto) = crypto_update {
            // Validate and commit incoming key update
            if number <= rx_packet
                || self
                    .prev_crypto
                    .as_ref()
                    .map_or(false, |x| x.update_unacked)
            {
                return Err(Some(TransportError::PROTOCOL_VIOLATION(
                    "illegal key update",
                )));
            }
            trace!(self.log, "key update authenticated");
            self.update_keys(crypto, Some((number, now)), true);
            self.set_key_discard_timer(now);
        }

        Ok(Some(number))
    }

    #[doc(hidden)]
    pub fn initiate_key_update(&mut self) {
        let space = self.space(SpaceId::Data);
        let update = self.tls.update_keys(&space.crypto.as_ref().unwrap().packet);
        self.update_keys(update, None, false);
    }

    /// Send data on the given stream
    ///
    /// Returns the number of bytes successfully written.
    pub fn write(&mut self, stream: StreamId, data: &[u8]) -> Result<usize, WriteError> {
        assert!(stream.directionality() == Directionality::Bi || stream.initiator() == self.side);
        if self.state.is_closed() {
            trace!(self.log, "write blocked; connection draining"; "stream" => stream.0);
            return Err(WriteError::Blocked);
        }

        if self.blocked() {
            if self.congestion_blocked() {
                trace!(
                    self.log,
                    "write on {stream} blocked by congestion",
                    stream = stream
                );
            } else {
                trace!(
                    self.log,
                    "write on {stream} blocked by connection-level flow control",
                    stream = stream
                );
            }
            self.blocked_streams.insert(stream);
            return Err(WriteError::Blocked);
        }

        let budget_res = self
            .streams
            .get_send_mut(stream)
            .ok_or(WriteError::UnknownStream)?
            .write_budget();

        let stream_budget = match budget_res {
            Ok(budget) => budget,
            Err(e @ WriteError::Stopped { .. }) => {
                self.streams.maybe_cleanup(stream);
                return Err(e);
            }
            Err(e @ WriteError::Blocked) => {
                trace!(
                    self.log,
                    "write on {stream} blocked by flow control",
                    stream = stream
                );
                return Err(e);
            }
            Err(WriteError::UnknownStream) => unreachable!("not returned here"),
        };

        let conn_budget = cmp::min(
            self.max_data - self.data_sent,
            self.config.send_window - self.unacked_data,
        );
        let n = conn_budget.min(stream_budget).min(data.len() as u64) as usize;
        self.queue_stream_data(stream, (&data[0..n]).into());
        trace!(
            self.log,
            "wrote {len} bytes to {stream}",
            len = n,
            stream = stream
        );
        Ok(n)
    }

    fn update_keys(&mut self, crypto: S::Keys, end_packet: Option<(u64, Instant)>, remote: bool) {
        let old = mem::replace(
            &mut self.spaces[SpaceId::Data as usize]
                .crypto
                .as_mut()
                .unwrap()
                .packet,
            crypto,
        );
        self.prev_crypto = Some(PrevCrypto {
            crypto: old,
            end_packet,
            update_unacked: remote,
        });
        self.key_phase = !self.key_phase;
    }

    /// If the connection is currently handshaking
    pub fn is_handshaking(&self) -> bool {
        self.state.is_handshake()
    }

    /// If the connection is closed
    pub fn is_closed(&self) -> bool {
        self.state.is_closed()
    }

    /// If the connection is drained
    pub fn is_drained(&self) -> bool {
        self.state.is_drained()
    }

    /// For clients, if the peer accepted the 0-RTT data packets
    ///
    /// The value is meaningless until after the handshake completes.
    pub fn accepted_0rtt(&self) -> bool {
        self.accepted_0rtt
    }

    /// Whether 0-RTT is/was possible during the handshake
    pub fn has_0rtt(&self) -> bool {
        self.zero_rtt_enabled
    }

    /// Look up whether we're the client or server of this Connection
    pub fn side(&self) -> Side {
        self.side
    }

    /// The `ConnectionId` defined for this Connection by the peer.
    pub fn rem_cid(&self) -> ConnectionId {
        self.rem_cid
    }

    /// The latest socket address for this connection's peer
    pub fn remote(&self) -> SocketAddr {
        self.remote
    }

    /// The ALPN protocol negotiated during this connection's handshake
    pub fn protocol(&self) -> Option<&[u8]> {
        self.tls.alpn_protocol()
    }

    /// The number of bytes of packets containing retransmittable frames that have not been
    /// acknowledged or declared lost.
    #[cfg(all(test, feature = "rustls"))]
    pub(crate) fn bytes_in_flight(&self) -> u64 {
        self.in_flight.bytes
    }

    /// Number of bytes worth of non-ack-only packets that may be sent
    #[cfg(all(test, feature = "rustls"))]
    pub(crate) fn congestion_state(&self) -> u64 {
        self.congestion_window.saturating_sub(self.in_flight.bytes)
    }

    /// The name a client supplied via SNI
    ///
    /// `None` if no name was supplised or if this connection was locally initiated.
    pub fn server_name(&self) -> Option<&str> {
        self.tls.sni_hostname()
    }

    /// Total number of outgoing packets that have been deemed lost
    #[cfg(all(test, feature = "rustls"))]
    pub(crate) fn lost_packets(&self) -> u64 {
        self.lost_packets
    }

    /// Whether explicit congestion notification is in use on outgoing packets.
    #[cfg(all(test, feature = "rustls"))]
    pub(crate) fn using_ecn(&self) -> bool {
        self.sending_ecn
    }

    fn max_ack_delay(&self) -> Duration {
        Duration::from_micros(self.params.max_ack_delay * 1000)
    }

    fn space(&self, id: SpaceId) -> &PacketSpace<S::Keys> {
        &self.spaces[id as usize]
    }

    fn space_mut(&mut self, id: SpaceId) -> &mut PacketSpace<S::Keys> {
        &mut self.spaces[id as usize]
    }

    /// Whether we have non-retransmittable 1-RTT data to send
    ///
    /// See also `self.space(SpaceId::Data).can_send()`
    fn can_send_1rtt(&self) -> bool {
        self.path_challenge_pending || self.ping_pending || self.path_response.is_some()
    }

    /// Reset state to account for 0-RTT being ignored by the server
    fn reject_0rtt(&mut self) {
        debug_assert!(self.side.is_client());
        debug!(self.log, "0-RTT rejected");
        self.accepted_0rtt = false;
        self.streams.zero_rtt_rejected(self.side);
        // Discard already-queued frames
        self.space_mut(SpaceId::Data).pending = Retransmits::default();
        // Discard 0-RTT packets
        let sent_packets = mem::replace(
            &mut self.space_mut(SpaceId::Data).sent_packets,
            BTreeMap::new(),
        );
        for (_, packet) in sent_packets {
            self.in_flight.remove(&packet);
        }
        self.data_sent = 0;
        self.blocked_streams.clear();
    }
}

pub fn initial_close<K, R>(
    crypto: &K,
    header_crypto: &K::HeaderKeys,
    remote_id: &ConnectionId,
    local_id: &ConnectionId,
    packet_number: u8,
    reason: R,
) -> Box<[u8]>
where
    K: crypto::Keys,
    R: Into<Close>,
{
    let number = PacketNumber::U8(packet_number);
    let header = Header::Initial {
        dst_cid: *remote_id,
        src_cid: *local_id,
        number,
        token: Bytes::new(),
    };

    let mut buf = Vec::<u8>::new();
    let partial_encode = header.encode(&mut buf);
    let max_len = MIN_MTU as usize - partial_encode.header_len - crypto.tag_len();
    reason.into().encode(&mut buf, max_len);
    buf.resize(buf.len() + crypto.tag_len(), 0);
    partial_encode.finish(
        &mut buf,
        header_crypto,
        Some((u64::from(packet_number), crypto)),
    );
    buf.into()
}

/// Reasons why a connection might be lost.
#[derive(Debug, Clone, Error)]
pub enum ConnectionError {
    /// The peer doesn't implement any supported version.
    #[error(display = "peer doesn't implement any supported version")]
    VersionMismatch,
    /// The peer violated the QUIC specification as understood by this implementation.
    #[error(display = "{}", _0)]
    TransportError(TransportError),
    /// The peer's QUIC stack aborted the connection automatically.
    #[error(display = "aborted by peer: {}", reason)]
    ConnectionClosed {
        /// The reason for closing the connection
        reason: frame::ConnectionClose,
    },
    /// The peer closed the connection.
    #[error(display = "closed by peer: {}", reason)]
    ApplicationClosed {
        /// The reason for closing the connection
        reason: frame::ApplicationClose,
    },
    /// The peer is unable to continue processing this connection, usually due to having restarted.
    #[error(display = "reset by peer")]
    Reset,
    /// The peer has become unreachable.
    #[error(display = "timed out")]
    TimedOut,
    /// The local application closed the connection.
    #[error(display = "closed")]
    LocallyClosed,
}

impl From<TransportError> for ConnectionError {
    fn from(x: TransportError) -> Self {
        ConnectionError::TransportError(x)
    }
}

impl From<Close> for ConnectionError {
    fn from(x: Close) -> Self {
        match x {
            Close::Connection(reason) => ConnectionError::ConnectionClosed { reason },
            Close::Application(reason) => ConnectionError::ApplicationClosed { reason },
        }
    }
}

// For compatibility with API consumers
impl From<ConnectionError> for io::Error {
    fn from(x: ConnectionError) -> io::Error {
        use self::ConnectionError::*;
        let kind = match x {
            TimedOut => io::ErrorKind::TimedOut,
            Reset => io::ErrorKind::ConnectionReset,
            ApplicationClosed { .. } | ConnectionClosed { .. } => io::ErrorKind::ConnectionAborted,
            TransportError(_) | VersionMismatch | LocallyClosed => io::ErrorKind::Other,
        };
        io::Error::new(kind, x)
    }
}

impl From<transport_parameters::Error> for ConnectionError {
    fn from(e: transport_parameters::Error) -> Self {
        TransportError::from(e).into()
    }
}

#[derive(Clone)]
enum State {
    Handshake(state::Handshake),
    Established,
    Closed(state::Closed),
    Draining,
    /// Waiting for application to call close so we can dispose of the resources
    Drained,
}

impl State {
    fn closed<R: Into<Close>>(reason: R) -> Self {
        State::Closed(state::Closed {
            reason: reason.into(),
        })
    }

    fn is_handshake(&self) -> bool {
        match *self {
            State::Handshake(_) => true,
            _ => false,
        }
    }

    fn is_established(&self) -> bool {
        match *self {
            State::Established => true,
            _ => false,
        }
    }

    fn is_closed(&self) -> bool {
        match *self {
            State::Closed(_) => true,
            State::Draining => true,
            State::Drained => true,
            _ => false,
        }
    }

    fn is_drained(&self) -> bool {
        if let State::Drained = *self {
            true
        } else {
            false
        }
    }
}

mod state {
    use super::*;

    #[derive(Clone)]
    pub struct Handshake {
        /// Whether the remote CID has been set by the peer yet
        ///
        /// Always set for servers
        pub rem_cid_set: bool,
        /// Stateless retry token, if the peer has provided one
        ///
        /// Only set for clients
        pub token: Option<Bytes>,
        /// First cryptographic message
        ///
        /// Only set for clients
        pub client_hello: Option<Bytes>,
    }

    #[derive(Clone)]
    pub struct Closed {
        pub reason: Close,
    }
}

/// Ensures we can always fit all our ACKs in a single minimum-MTU packet with room to spare
const MAX_ACK_BLOCKS: usize = 64;

/// Encoding of I/O operations to emit on upcoming `poll_io` calls
#[derive(Debug)]
struct IoQueue {
    /// Number of probe packets to transmit
    probes: u8,
    /// Whether to transmit a close packet
    close: bool,
    /// Changes to the loss detection, idle, and close timers, in that order
    ///
    /// Note that this ordering exactly matches the values of the `Timer` enum for convenient
    /// indexing.
    timers: TimerTable<Option<TimerSetting>>,
}

impl IoQueue {
    fn new() -> Self {
        Self {
            probes: 0,
            close: false,
            timers: Default::default(),
        }
    }

    /// Start or reset a timer associated with this connection.
    fn timer_start(&mut self, timer: TimerKind, time: Instant) {
        self.timers[Timer(timer)] = Some(TimerSetting::Start(time));
    }

    /// Start one of the timers associated with this connection.
    fn timer_stop(&mut self, timer: TimerKind) {
        self.timers[Timer(timer)] = Some(TimerSetting::Stop);
    }
}

/// Change applicable to one of a connection's timers
#[derive(Debug, Copy, Clone)]
pub enum TimerSetting {
    /// Set the timer to expire at an a certain point in time
    Start(Instant),
    /// Cancel time timer if it's currently running
    Stop,
}

/// Change to apply to a specific timer
#[derive(Debug, Copy, Clone)]
pub struct TimerUpdate {
    /// Which timer needs an update
    pub timer: Timer,
    /// The new state for the timer
    pub update: TimerSetting,
}

struct PrevCrypto<K>
where
    K: crypto::Keys,
{
    /// The keys used for the previous key phase, temporarily retained to decrypt packets sent by
    /// the peer prior to its own key update.
    crypto: K,
    /// The incoming packet that ends the interval for which these keys are applicable, and the time
    /// of its receipt.
    ///
    /// Incoming packets should be decrypted using these keys iff this is `None` or their packet
    /// number is lower. `None` indicates that we have not yet received a packet using newer keys,
    /// which implies that the update was locally initiated.
    end_packet: Option<(u64, Instant)>,
    /// Whether the following key phase is from a remotely initiated update that we haven't acked
    update_unacked: bool,
}

struct InFlight {
    /// Sum of the sizes of all sent packets considered "in flight" by congestion control
    ///
    /// The size does not include IP or UDP overhead. Packets only containing ACK frames do not
    /// count towards this to ensure congestion control does not impede congestion feedback.
    bytes: u64,
    /// Number of unacknowledged Initial or Handshake packets bearing CRYPTO frames
    crypto: u64,
    /// Number of packets in flight containing frames other than ACK and PADDING
    ///
    /// This can be 0 even when bytes is not 0 because PADDING frames cause a packet to be
    /// considered "in flight" by congestion control. However, if this is nonzero, bytes will always
    /// also be nonzero.
    ack_eliciting: u64,
}

impl InFlight {
    pub fn new() -> Self {
        Self {
            bytes: 0,
            crypto: 0,
            ack_eliciting: 0,
        }
    }

    fn insert(&mut self, packet: &SentPacket) {
        self.bytes += u64::from(packet.size);
        self.crypto += u64::from(packet.is_crypto_packet);
        self.ack_eliciting += u64::from(packet.ack_eliciting);
    }

    /// Update counters to account for a packet becoming acknowledged, lost, or abandoned
    fn remove(&mut self, packet: &SentPacket) {
        self.bytes -= u64::from(packet.size);
        self.crypto -= u64::from(packet.is_crypto_packet);
        self.ack_eliciting -= u64::from(packet.ack_eliciting);
    }
}

struct RttEstimator {
    /// The most recent RTT measurement made when receiving an ack for a previously unacked packet
    latest: Duration,
    /// The smoothed RTT of the connection, computed as described in RFC6298
    smoothed: Option<Duration>,
    /// The RTT variance, computed as described in RFC6298
    var: Duration,
    /// The minimum RTT seen in the connection, ignoring ack delay.
    min: Duration,
}

impl RttEstimator {
    fn new() -> Self {
        Self {
            latest: Duration::new(0, 0),
            smoothed: None,
            var: Duration::new(0, 0),
            min: Duration::new(u64::max_value(), 0),
        }
    }

    fn update(&mut self, ack_delay: Duration, rtt: Duration) {
        self.latest = rtt;
        // min_rtt ignores ack delay.
        self.min = cmp::min(self.min, self.latest);
        // Adjust for ack delay if it's plausible.
        if self.latest - self.min > ack_delay {
            self.latest -= ack_delay;
        }
        // Based on RFC6298.
        if let Some(smoothed) = self.smoothed {
            let var_sample = if smoothed > self.latest {
                smoothed - self.latest
            } else {
                self.latest - smoothed
            };
            self.var = (3 * self.var + var_sample) / 4;
            self.smoothed = Some((7 * smoothed + self.latest) / 8);
        } else {
            self.smoothed = Some(self.latest);
            self.var = self.latest / 2;
        }
    }
}

/// Events of interest to the application
#[derive(Debug)]
pub enum Event {
    /// The connection was successfully established
    Connected,
    /// The connection was lost
    ///
    /// Emitted if the peer closes the connection or an error is encountered.
    ConnectionLost {
        /// Reason that the connection was closed
        reason: ConnectionError,
    },
    /// One or more new streams has been opened and is readable
    StreamOpened,
    /// An existing stream has data or errors waiting to be read
    StreamReadable {
        /// Which stream is now readable
        stream: StreamId,
    },
    /// A formerly write-blocked stream might now accept a write
    StreamWritable {
        /// Which stream is now writable
        stream: StreamId,
    },
    /// A finished stream has been fully acknowledged or stopped
    StreamFinished {
        /// Which stream has been finished
        stream: StreamId,
        /// Error code supplied by the peer if the stream was stopped
        stop_reason: Option<VarInt>,
    },
    /// At least one new stream of a certain directionality may be opened
    StreamAvailable {
        /// On which direction streams are newly available
        directionality: Directionality,
    },
}

impl From<ConnectionError> for Event {
    fn from(x: ConnectionError) -> Self {
        Event::ConnectionLost { reason: x }
    }
}

struct PathResponse {
    /// The packet number the corresponding PATH_CHALLENGE was received in
    packet: u64,
    token: u64,
}

fn instant_saturating_sub(x: Instant, y: Instant) -> Duration {
    if x > y {
        x - y
    } else {
        Duration::new(0, 0)
    }
}

/// Value used in ACKs we transmit
const ACK_DELAY_EXPONENT: u8 = 3;
// Prevents overflow and improves behavior in extreme circumstances
const MAX_BACKOFF_EXPONENT: u32 = 16;
// Minimal remaining size to allow packet coalescing
const MIN_PACKET_SPACE: usize = 40;
