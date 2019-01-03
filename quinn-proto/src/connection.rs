use std::collections::{hash_map, BTreeMap, HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::{cmp, io, mem};

use bytes::{Buf, Bytes, BytesMut};
use fnv::{FnvHashMap, FnvHashSet};
use slog::Logger;

use crate::coding::{BufExt, BufMutExt};
use crate::crypto::{
    self, reset_token_for, Crypto, HeaderCrypto, Secrets, TlsSession, ACK_DELAY_EXPONENT,
};
use crate::dedup::Dedup;
use crate::endpoint::{Config, Event, Timer};
use crate::frame::FrameStruct;
use crate::packet::{
    set_payload_length, ConnectionId, EcnCodepoint, Header, LongType, Packet, PacketNumber,
    PartialDecode, SpaceId, LONG_RESERVED_BITS, SHORT_RESERVED_BITS,
};
use crate::range_set::RangeSet;
use crate::stream::{self, ReadError, Stream, WriteError};
use crate::transport_parameters::{self, TransportParameters};
use crate::{
    frame, Directionality, Frame, Side, StreamId, TransportError, MIN_INITIAL_SIZE, MIN_MTU,
    RESET_TOKEN_SIZE, TIMER_GRANULARITY, VERSION,
};

pub struct Connection {
    log: Logger,
    config: Arc<Config>,
    tls: TlsSession,
    app_closed: bool,
    /// DCID of Initial packet
    pub(crate) init_cid: ConnectionId,
    loc_cids: HashMap<u64, ConnectionId>,
    rem_cid: ConnectionId,
    rem_cid_seq: u64,
    remote: SocketAddr,
    state: State,
    side: Side,
    mtu: u16,
    /// Highest received packet number
    rx_packet: u64,
    rx_packet_space: SpaceId,
    /// Time at which the above was received
    rx_packet_time: u64,
    //zero_rtt_crypto: Option<Crypto>,
    key_phase: bool,
    params: TransportParameters,
    /// Streams on which writing was blocked on *connection-level* flow or congestion control
    blocked_streams: FnvHashSet<StreamId>,
    /// Limit on outgoing data, dictated by peer
    max_data: u64,
    data_sent: u64,
    /// Sum of end offsets of all streams. Includes gaps, so it's an upper bound.
    data_recvd: u64,
    /// Limit on incoming data
    local_max_data: u64,
    client_config: Option<ClientConfig>,
    /// ConnectionId sent by this client on the first Initial, if a Retry was received.
    orig_rem_cid: Option<ConnectionId>,
    /// Total number of outgoing packets that have been deemed lost
    lost_packets: u64,
    io: IoQueue,
    events: VecDeque<Event>,
    /// Number of local connection IDs that have been issued in NEW_CONNECTION_ID frames.
    cids_issued: u64,
    /// Outgoing spin bit state
    spin: bool,
    /// Packet number spaces: initial, handshake, 1-RTT
    spaces: [Option<PacketSpace>; 3],
    /// Highest usable packet number space
    highest_space: SpaceId,
    /// 1-RTT keys used prior to a key update
    prev_crypto: Option<PrevCrypto>,

    //
    // Loss Detection
    //
    /// The number of times all unacknowledged CRYPTO data has been retransmitted without receiving
    /// an ack.
    crypto_count: u32,
    /// The number of times a PTO has been sent without receiving an ack.
    pto_count: u32,
    /// The time at which the next packet will be considered lost based on early transmit or
    /// exceeding the reordering window in time.
    loss_time: u64,
    /// The most recent RTT measurement made when receiving an ack for a previously unacked packet.
    /// μs
    latest_rtt: u64,
    /// The smoothed RTT of the connection, computed as described in RFC6298. μs
    smoothed_rtt: u64,
    /// The RTT variance, computed as described in RFC6298
    rttvar: u64,
    /// The minimum RTT seen in the connection, ignoring ack delay.
    min_rtt: u64,
    /// The time the most recently sent retransmittable packet was sent.
    time_of_last_sent_ack_eliciting_packet: u64,
    /// The time the most recently sent handshake packet was sent.
    time_of_last_sent_crypto_packet: u64,

    //
    // Congestion Control
    //
    /// Summary statistics of packets that have been sent, but not yet acked or deemed lost
    in_flight: InFlight,
    /// Maximum number of bytes in flight that may be sent.
    congestion_window: u64,
    /// The time when QUIC first detects a loss, causing it to enter recovery. When a packet sent
    /// after this time is acknowledged, QUIC exits recovery.
    recovery_start_time: u64,
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
    total_recvd: u64,
    total_sent: u64,

    streams: Streams,
}

impl Connection {
    pub fn new(
        log: Logger,
        config: Arc<Config>,
        init_cid: ConnectionId,
        loc_cid: ConnectionId,
        rem_cid: ConnectionId,
        remote: SocketAddr,
        client_config: Option<ClientConfig>,
        tls: TlsSession,
        remote_validated: bool,
    ) -> Self {
        let side = if client_config.is_some() {
            Side::Client
        } else {
            Side::Server
        };

        let initial_space = PacketSpace::new(Crypto::new_initial(&init_cid, side));
        let mut streams = FnvHashMap::default();
        for i in 0..config.max_remote_streams_uni {
            streams.insert(
                StreamId::new(!side, Directionality::Uni, u64::from(i)),
                stream::Recv::new(u64::from(config.stream_receive_window)).into(),
            );
        }
        for i in 0..config.max_remote_streams_bidi {
            streams.insert(
                StreamId::new(!side, Directionality::Bi, i as u64),
                Stream::new_bi(config.stream_receive_window as u64),
            );
        }
        let mut loc_cids = HashMap::new();
        loc_cids.insert(0, loc_cid);
        let state = State::Handshake(state::Handshake {
            rem_cid_set: side.is_server(),
            token: None,
        });
        let mut this = Self {
            log,
            tls,
            app_closed: false,
            init_cid,
            loc_cids,
            rem_cid,
            rem_cid_seq: 0,
            remote,
            side,
            state,
            mtu: MIN_MTU,
            rx_packet: 0,
            rx_packet_space: SpaceId::Initial,
            rx_packet_time: 0,
            //zero_rtt_crypto: None,
            key_phase: false,
            params: TransportParameters::new(&config),
            blocked_streams: FnvHashSet::default(),
            max_data: 0,
            data_sent: 0,
            data_recvd: 0,
            local_max_data: config.receive_window as u64,
            client_config,
            orig_rem_cid: None,
            lost_packets: 0,
            io: IoQueue::new(),
            events: VecDeque::new(),
            cids_issued: 0,
            spin: false,
            spaces: [Some(initial_space), None, None],
            highest_space: SpaceId::Initial,
            prev_crypto: None,

            crypto_count: 0,
            pto_count: 0,
            loss_time: 0,
            latest_rtt: 0,
            smoothed_rtt: 0,
            rttvar: 0,
            min_rtt: u64::max_value(),
            time_of_last_sent_ack_eliciting_packet: 0,
            time_of_last_sent_crypto_packet: 0,

            in_flight: InFlight::new(),
            congestion_window: config.initial_window,
            recovery_start_time: 0,
            ssthresh: u64::max_value(),
            ecn_counters: frame::EcnCounts::ZERO,
            sending_ecn: true,
            receiving_ecn: false,
            remote_validated,
            total_recvd: 0,
            total_sent: 0,

            streams: Streams {
                streams,
                next_uni: 0,
                next_bi: 0,
                max_uni: 0,
                max_bi: 0,
                max_remote_uni: config.max_remote_streams_uni as u64,
                max_remote_bi: config.max_remote_streams_bidi as u64,
                finished: Vec::new(),
            },
            config,
        };
        if side.is_client() {
            // Kick off the connection
            this.write_tls();
        }
        this
    }

    /// Returns I/O actions to execute immediately
    ///
    /// Connections should be polled for I/O after:
    /// - the application performed some I/O on the connection
    /// - an incoming packet is handled
    /// - any timer expires
    pub fn poll_io(&mut self, now: u64) -> Option<Io> {
        if let Some(packet) = self.next_packet(now) {
            self.reset_idle_timeout(now);
            return Some(Io::Transmit {
                destination: self.remote,
                ecn: if self.sending_ecn {
                    Some(EcnCodepoint::ECT0)
                } else {
                    None
                },
                packet,
            });
        }

        for (&timer, update) in Timer::VALUES.iter().zip(self.io.timers.iter_mut()) {
            if let Some(update) = update.take() {
                return Some(Io::TimerUpdate { timer, update });
            }
        }

        if let Some(cid) = self.io.retired_cids.pop() {
            return Some(Io::RetireConnectionId { connection_id: cid });
        }

        None
    }

    /// Returns application-facing events
    ///
    /// Connections should be polled for events after:
    /// - an incoming packet is handled, or
    /// - the idle timer expires
    pub fn poll(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    fn on_packet_sent(&mut self, now: u64, space: SpaceId, packet_number: u64, packet: SentPacket) {
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
        if size != 0 {
            if ack_eliciting {
                self.time_of_last_sent_ack_eliciting_packet = now;
            }
            if is_crypto_packet {
                self.time_of_last_sent_crypto_packet = now;
            }
            self.set_loss_detection_timer();
        }

        if space == SpaceId::Handshake
            && !self.state.is_handshake()
            && self.side.is_server()
            && !self.space(SpaceId::Handshake).permit_ack_only
        {
            // We've acked the TLS FIN.
            self.set_key_discard_timer(now);
        }
    }

    fn on_ack_received(&mut self, now: u64, space: SpaceId, ack: frame::Ack) {
        trace!(self.log, "got ack"; "ranges" => ?ack.iter().collect::<Vec<_>>());
        let was_blocked = self.blocked();
        let largest_acked_packet = &mut self.space_mut(space).largest_acked_packet;
        let prev_largest = *largest_acked_packet;
        *largest_acked_packet = cmp::max(ack.largest, *largest_acked_packet);

        let largest_acked_time_sent;
        if let Some(info) = self.space(space).sent_packets.get(&ack.largest).cloned() {
            if info.ack_eliciting {
                self.latest_rtt = now - info.time_sent;
                let delay = ack.delay << self.params.ack_delay_exponent;
                self.update_rtt(delay);
            }
            largest_acked_time_sent = Some(info.time_sent);
        } else {
            largest_acked_time_sent = None;
        }

        // Avoid DoS from unreasonably huge ack ranges by filtering out just the new acks.
        let newly_acked = ack
            .iter()
            .flat_map(|range| self.space(space).sent_packets.range(range).map(|(&n, _)| n))
            .collect::<Vec<_>>();
        if newly_acked.is_empty() {
            return;
        }
        for &packet in &newly_acked {
            self.on_packet_acked(space, packet);
        }

        if space == SpaceId::Handshake
            && !self.state.is_handshake()
            && self.side.is_client()
            && self.in_flight.crypto == 0
            && self.space(SpaceId::Handshake).pending.crypto.is_empty()
        {
            // All Handshake CRYPTO data sent and acked.
            self.set_key_discard_timer(now);
        }

        self.crypto_count = 0;
        self.pto_count = 0;

        // Explicit congestion notification
        if self.sending_ecn {
            if let Some(ecn) = ack.ecn {
                // We only examine ECN counters from ACKs that we are certain we received in transmit
                // order, allowing us to compute an increase in ECN counts to compare against the number
                // of newly acked packets that remains well-defined in the presence of arbitrary packet
                // reordering.
                if ack.largest > prev_largest {
                    self.process_ecn(
                        now,
                        space,
                        newly_acked.len() as u64,
                        ecn,
                        largest_acked_time_sent.unwrap(),
                    );
                }
            } else {
                // We always start out sending ECN, so any ack that doesn't acknowledge it disables it.
                debug!(self.log, "ECN not acknowledged by peer");
                self.sending_ecn = false;
            }
        }

        self.detect_lost_packets(now);
        self.set_loss_detection_timer();
        if was_blocked && !self.blocked() {
            for stream in self.blocked_streams.drain() {
                self.events.push_back(Event::StreamWritable { stream });
            }
        }
    }

    /// Process a new ECN block from an in-order ACK
    fn process_ecn(
        &mut self,
        now: u64,
        space: SpaceId,
        newly_acked: u64,
        ecn: frame::EcnCounts,
        largest_sent_time: u64,
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

    fn update_rtt(&mut self, ack_delay: u64) {
        // min_rtt ignores ack delay.
        self.min_rtt = cmp::min(self.min_rtt, self.latest_rtt);
        // Limit ack_delay by max_ack_delay
        let ack_delay = cmp::min(ack_delay, self.max_ack_delay());
        // Adjust for ack delay if it's plausible.
        if self.latest_rtt - self.min_rtt > ack_delay {
            self.latest_rtt -= ack_delay;
        }
        // Based on RFC6298.
        if self.smoothed_rtt == 0 {
            self.smoothed_rtt = self.latest_rtt;
            self.rttvar = self.latest_rtt / 2;
        } else {
            let rttvar_sample = (self.smoothed_rtt as i64 - self.latest_rtt as i64).abs() as u64;
            self.rttvar = (3 * self.rttvar + rttvar_sample) / 4;
            self.smoothed_rtt = (7 * self.smoothed_rtt + self.latest_rtt) / 8;
        }
    }

    // Not timing-aware, so it's safe to call this for inferred acks, such as arise from
    // high-latency handshakes
    fn on_packet_acked(&mut self, space: SpaceId, packet: u64) {
        let info = if let Some(x) = self.space_mut(space).sent_packets.remove(&packet) {
            x
        } else {
            return;
        };
        self.in_flight.remove(&info);
        if info.ack_eliciting {
            // Congestion control
            // Do not increase congestion window in recovery period.
            if !self.in_recovery(packet) {
                if self.congestion_window < self.ssthresh {
                    // Slow start.
                    self.congestion_window += info.size as u64;
                } else {
                    // Congestion avoidance.
                    self.congestion_window +=
                        self.config.max_datagram_size * info.size as u64 / self.congestion_window;
                }
            }
        }

        // Update state for confirmed delivery of frames
        for (id, _) in info.retransmits.rst_stream {
            if let stream::SendState::ResetSent { stop_reason } =
                self.streams.get_send_mut(id).unwrap().state
            {
                self.streams.get_send_mut(id).unwrap().state =
                    stream::SendState::ResetRecvd { stop_reason };
                if stop_reason.is_none() {
                    self.maybe_cleanup(id);
                }
            }
        }
        for frame in info.retransmits.stream {
            let recvd = {
                let ss = if let Some(x) = self.streams.get_send_mut(frame.id) {
                    x
                } else {
                    continue;
                };
                ss.bytes_in_flight -= frame.data.len() as u64;
                if ss.state == stream::SendState::DataSent && ss.bytes_in_flight == 0 {
                    ss.state = stream::SendState::DataRecvd;
                    true
                } else {
                    false
                }
            };
            if recvd {
                self.maybe_cleanup(frame.id);
                self.streams.finished.push(frame.id);
            }
        }
        self.space_mut(space).pending_acks.subtract(&info.acks);
    }

    pub fn timeout(&mut self, now: u64, timer: Timer) -> bool {
        match timer {
            Timer::Close => {
                self.io.timer_stop(Timer::Idle);
                self.state = State::Drained;
                return self.app_closed;
            }
            Timer::Idle => {
                self.close_common(now);
                self.events.push_back(ConnectionError::TimedOut.into());
                self.state = State::Draining;
            }
            Timer::LossDetection => {
                self.on_loss_detection_timeout(now);
            }
            Timer::KeyDiscard => {
                if self.spaces[SpaceId::Handshake as usize].is_some() {
                    self.discard_space(SpaceId::Handshake);
                    // Might have a key update to discard too
                    self.set_key_discard_timer(now);
                } else if let Some(ref prev) = self.prev_crypto {
                    if prev
                        .update_ack_time
                        .map_or(false, |x| now.saturating_sub(x) >= self.pto() * 3)
                    {
                        self.prev_crypto = None;
                    } else {
                        self.set_key_discard_timer(now);
                    }
                }
            }
        }
        false
    }

    fn set_key_discard_timer(&mut self, now: u64) {
        let time = if self.spaces[SpaceId::Handshake as usize].is_some() {
            now + self.pto() * 3
        } else if let Some(ref time) = self.prev_crypto.as_ref().and_then(|x| x.update_ack_time) {
            time + self.pto() * 3
        } else {
            return;
        };
        self.io.timer_start(Timer::KeyDiscard, time);
    }

    fn on_loss_detection_timeout(&mut self, now: u64) {
        if self.in_flight.crypto != 0 {
            trace!(self.log, "retransmitting handshake packets");
            for &space_id in [SpaceId::Initial, SpaceId::Handshake].iter() {
                if self.spaces[space_id as usize].is_none() {
                    continue;
                }
                let sent_packets =
                    mem::replace(&mut self.space_mut(space_id).sent_packets, BTreeMap::new());
                for (_, packet) in sent_packets {
                    self.in_flight.remove(&packet);
                    self.space_mut(space_id).pending += packet.retransmits;
                }
            }
            self.crypto_count += 1;
        } else if self.state.is_handshake() && self.side.is_client() {
            trace!(self.log, "sending anti-deadlock handshake packet");
            self.io.probes += 1;
            self.crypto_count += 1;
        } else if self.loss_time != 0 {
            // Time threshold loss Detection
            self.detect_lost_packets(now);
        } else {
            trace!(self.log, "PTO fired"; "in flight" => self.in_flight.bytes);
            self.io.probes += 2;
            self.pto_count += 1;
        }
        self.set_loss_detection_timer();
    }

    fn detect_lost_packets(&mut self, now: u64) {
        self.loss_time = 0;
        let mut lost_packets = Vec::<u64>::new();
        let rtt = cmp::max(self.latest_rtt, self.smoothed_rtt);
        let loss_delay = rtt + ((rtt * self.config.time_threshold as u64) >> 16);
        let lost_send_time = now.saturating_sub(loss_delay);

        let mut lost_ack_eliciting = false;
        let mut largest_lost_time = 0;
        for space in self.spaces.iter_mut().filter_map(|x| x.as_mut()) {
            lost_packets.clear();
            let lost_pn = space
                .largest_acked_packet
                .saturating_sub(self.config.packet_threshold as u64);
            for (&packet, info) in space.sent_packets.range(0..space.largest_acked_packet) {
                if info.time_sent <= lost_send_time || packet <= lost_pn {
                    lost_packets.push(packet);
                } else if self.loss_time == 0 {
                    self.loss_time = info.time_sent + loss_delay;
                } else {
                    self.loss_time = cmp::min(self.loss_time, info.time_sent + loss_delay);
                }
            }

            // OnPacketsLost
            if let Some(largest_lost) = lost_packets.last().cloned() {
                let old_bytes_in_flight = self.in_flight.bytes;
                largest_lost_time = cmp::max(
                    largest_lost_time,
                    space.sent_packets[&largest_lost].time_sent,
                );
                for packet in &lost_packets {
                    let info = space.sent_packets.remove(&packet).unwrap();
                    self.in_flight.remove(&info);
                    self.lost_packets += 1;
                    space.pending += info.retransmits;
                }
                // Don't apply congestion penalty for lost ack-only packets
                lost_ack_eliciting |= old_bytes_in_flight != self.in_flight.bytes;
            }
        }
        if lost_ack_eliciting {
            self.congestion_event(now, largest_lost_time)
        }
    }

    fn congestion_event(&mut self, now: u64, sent_time: u64) {
        // Start a new recovery epoch if the lost packet is larger than the end of the
        // previous recovery epoch.
        if self.in_recovery(sent_time) {
            return;
        }
        self.recovery_start_time = now;
        // *= factor
        self.congestion_window =
            (self.congestion_window * self.config.loss_reduction_factor as u64) >> 16;
        self.congestion_window = cmp::max(self.congestion_window, self.config.minimum_window);
        self.ssthresh = self.congestion_window;
    }

    fn in_recovery(&self, sent_time: u64) -> bool {
        sent_time <= self.recovery_start_time
    }

    fn set_loss_detection_timer(&mut self) {
        if self.in_flight.crypto != 0 || (self.state.is_handshake() && self.side.is_client()) {
            // Handshake retransmission alarm.
            let timeout = if self.smoothed_rtt == 0 {
                2 * self.config.initial_rtt
            } else {
                2 * self.smoothed_rtt
            };
            let timeout = cmp::max(timeout, TIMER_GRANULARITY) * 2u64.pow(self.crypto_count);
            self.io.timer_start(
                Timer::LossDetection,
                self.time_of_last_sent_crypto_packet + timeout,
            );
            return;
        }

        if self.in_flight.ack_eliciting == 0 {
            self.io.timer_stop(Timer::LossDetection);
            return;
        }

        if self.loss_time != 0 {
            // Time threshold loss detection.
            self.io.timer_start(Timer::LossDetection, self.loss_time);
            return;
        }

        // Calculate PTO duration
        let timeout = self.smoothed_rtt + 4 * self.rttvar + self.max_ack_delay();
        let timeout = cmp::max(timeout, TIMER_GRANULARITY) * 2u64.pow(self.pto_count);
        self.io.timer_start(
            Timer::LossDetection,
            self.time_of_last_sent_ack_eliciting_packet + timeout,
        );
    }

    /// Probe Timeout
    fn pto(&self) -> u64 {
        let computed = self.smoothed_rtt + 4 * self.rttvar + self.max_ack_delay();
        cmp::max(computed, TIMER_GRANULARITY)
    }

    fn on_packet_authenticated(
        &mut self,
        now: u64,
        space_id: SpaceId,
        ecn: Option<EcnCodepoint>,
        packet: Option<u64>,
        spin: bool,
        size: usize,
    ) {
        self.remote_validated |= space_id == SpaceId::Handshake;
        self.total_recvd = self.total_recvd.wrapping_add(size as u64);
        self.reset_idle_timeout(now);
        self.receiving_ecn |= ecn.is_some();
        if let Some(x) = ecn {
            self.ecn_counters += x;
        }

        let packet = if let Some(x) = packet {
            x
        } else {
            return;
        };
        trace!(
            self.log,
            "{space:?} packet {packet} authenticated",
            space = space_id,
            packet = packet
        );
        if self.spaces[SpaceId::Initial as usize].is_some()
            && space_id == SpaceId::Handshake
            && self.side.is_server()
        {
            // A server stops sending and processing Initial packets when it receives its first Handshake packet.
            self.discard_space(SpaceId::Initial);
        }
        let space = self.spaces[space_id as usize].as_mut().unwrap();
        space.pending_acks.insert_one(packet);
        if space.pending_acks.len() > MAX_ACK_BLOCKS {
            space.pending_acks.pop_min();
        }
        if (space_id, packet) >= (self.rx_packet_space, self.rx_packet) {
            self.rx_packet = packet;
            self.rx_packet_time = now;
            // Update outgoing spin bit, inverting iff we're the client
            self.spin = self.side.is_client() ^ spin;
        }
    }

    fn reset_idle_timeout(&mut self, now: u64) {
        let dt = if self.config.idle_timeout == 0 || self.params.idle_timeout == 0 {
            cmp::max(self.config.idle_timeout, self.params.idle_timeout)
        } else {
            cmp::min(self.config.idle_timeout, self.params.idle_timeout)
        };
        self.io
            .timer_start(Timer::Idle, now + dt as u64 * 1_000_000);
    }

    fn queue_stream_data(&mut self, stream: StreamId, data: Bytes) {
        let ss = self.streams.get_send_mut(stream).unwrap();
        assert_eq!(ss.state, stream::SendState::Ready);
        let offset = ss.offset;
        ss.offset += data.len() as u64;
        ss.bytes_in_flight += data.len() as u64;
        self.data_sent += data.len() as u64;
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
    pub fn reset(&mut self, stream_id: StreamId, error_code: u16) {
        assert!(
            stream_id.directionality() == Directionality::Bi || stream_id.initiator() == self.side,
            "only streams supporting outgoing data may be reset"
        );

        // reset is a noop on a closed stream
        let stream = if let Some(x) = self.streams.get_send_mut(stream_id) {
            x
        } else {
            return;
        };
        match stream.state {
            stream::SendState::DataRecvd
            | stream::SendState::ResetSent { .. }
            | stream::SendState::ResetRecvd { .. } => {
                return;
            } // Nothing to do
            _ => {}
        }
        stream.state = stream::SendState::ResetSent { stop_reason: None };

        self.spaces[SpaceId::Data as usize]
            .as_mut()
            .unwrap()
            .pending
            .rst_stream
            .push((stream_id, error_code));
    }

    pub fn handle_initial(
        &mut self,
        now: u64,
        ecn: Option<EcnCodepoint>,
        packet_number: u64,
        packet: Packet,
    ) -> Result<(), TransportError> {
        let len = packet.header_data.len() + packet.payload.len();
        self.on_packet_authenticated(now, SpaceId::Initial, ecn, Some(packet_number), false, len);
        self.process_early_payload(now, packet)?;
        if self.state.is_closed() {
            return Ok(());
        }
        let params = TransportParameters::read(
            Side::Server,
            &mut io::Cursor::new(self.tls.get_quic_transport_parameters().unwrap()),
        )?;
        self.set_params(params)?;
        self.write_tls();
        Ok(())
    }

    fn read_tls(&mut self, space: SpaceId, crypto: &frame::Crypto) -> Result<(), TransportError> {
        let space = self.spaces[space as usize].as_mut().unwrap();
        space.crypto_stream.insert(crypto.offset, &crypto.data);
        let mut buf = [0; 8192];
        loop {
            let n = space.crypto_stream.read(&mut buf);
            if n == 0 {
                return Ok(());
            }
            trace!(self.log, "read {} TLS bytes", n);
            if let Err(e) = self.tls.read_hs(&buf[..n]) {
                debug!(self.log, "TLS error: {}", e);
                return Err(if let Some(alert) = self.tls.take_alert() {
                    TransportError::crypto(alert)
                } else {
                    TransportError::PROTOCOL_VIOLATION
                });
            }
        }
    }

    fn write_tls(&mut self) {
        loop {
            let space = self.highest_space;
            let mut outgoing = Vec::new();
            if let Some(secrets) = self.tls.write_hs(&mut outgoing) {
                match space {
                    SpaceId::Initial => {
                        self.upgrade_crypto(SpaceId::Handshake, secrets);
                    }
                    SpaceId::Handshake => {
                        self.upgrade_crypto(SpaceId::Data, secrets);
                    }
                    _ => unreachable!("got updated secrets during 1-RTT"),
                }
            }
            if outgoing.is_empty() {
                break;
            }
            let offset = self.space_mut(space).crypto_offset;
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
                    data: outgoing.into(),
                });
        }
    }

    /// Switch to stronger cryptography during handshake
    fn upgrade_crypto(&mut self, space: SpaceId, secrets: Secrets) {
        let suite = self.tls.get_negotiated_ciphersuite().unwrap();
        let crypto = Crypto::new(self.side, suite.get_hash(), suite.get_aead_alg(), secrets);
        debug_assert!(
            self.spaces[space as usize].is_none(),
            "already reached packet space {:?}",
            space
        );
        trace!(self.log, "{space:?} keys ready", space = space);
        self.spaces[space as usize] = Some(PacketSpace::new(crypto));
        debug_assert!(space as usize > self.highest_space as usize);
        self.highest_space = space;
    }

    fn discard_space(&mut self, space: SpaceId) {
        trace!(self.log, "discarding {space:?} keys", space = space);
        let space = self.spaces[space as usize].take().unwrap();
        for (_, packet) in space.sent_packets {
            self.in_flight.remove(&packet);
        }
    }

    pub fn handle_decode(
        &mut self,
        now: u64,
        remote: SocketAddr,
        ecn: Option<EcnCodepoint>,
        partial_decode: PartialDecode,
    ) -> Option<BytesMut> {
        if remote != self.remote && self.side.is_client() {
            trace!(
                self.log,
                "discarding packet from unknown server {address}",
                address = format!("{}", remote)
            );
            return None;
        }
        let header_crypto = if let Some(space) = partial_decode.space() {
            if let Some(ref space) = self.spaces[space as usize] {
                Some(&space.header_crypto)
            } else {
                debug!(
                    self.log,
                    "discarding unexpected {space:?} packet ({len} bytes)",
                    space = space,
                    len = partial_decode.len(),
                );
                return None;
            }
        } else {
            // Unprotected packet
            None
        };

        match partial_decode.finish(header_crypto) {
            Ok((packet, rest)) => {
                self.handle_packet(now, ecn, packet);
                rest
            }
            Err(e) => {
                trace!(self.log, "unable to complete packet decoding"; "reason" => %e);
                None
            }
        }
    }

    fn handle_packet(&mut self, now: u64, ecn: Option<EcnCodepoint>, mut packet: Packet) {
        trace!(
            self.log,
            "connection got {space:?} packet ({len} bytes)",
            space = packet.header.space(),
            len = packet.payload.len() + packet.header_data.len()
        );
        let was_closed = self.state.is_closed();

        let stateless_reset = self.params.stateless_reset_token.map_or(false, |token| {
            packet.payload.len() >= RESET_TOKEN_SIZE
                && packet.payload[packet.payload.len() - RESET_TOKEN_SIZE..] == token
        });

        let result = match self.decrypt_packet(now, &mut packet) {
            Err(Some(e)) => {
                warn!(self.log, "got illegal packet"; "reason" => %e);
                Err(e.into())
            }
            Err(None) => {
                debug!(self.log, "failed to authenticate packet");
                if stateless_reset {
                    Err(ConnectionError::Reset)
                } else {
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
                } else {
                    if !self.state.is_closed() {
                        let spin = if let Header::Short { spin, .. } = packet.header {
                            spin
                        } else {
                            false
                        };
                        self.on_packet_authenticated(
                            now,
                            packet.header.space(),
                            ecn,
                            number,
                            spin,
                            packet.header_data.len() + packet.payload.len(),
                        );
                    }
                    self.handle_connected_inner(now, number, packet)
                }
            }
        };

        // State transitions for error cases
        if let Err(conn_err) = result {
            self.events.push_back(conn_err.clone().into());
            self.state = match conn_err {
                ConnectionError::ApplicationClosed { reason } => State::closed(reason),
                ConnectionError::ConnectionClosed { reason } => State::closed(reason),
                ConnectionError::Reset => {
                    if !self.state.is_drained() {
                        debug!(self.log, "got stateless reset");
                        self.io.timer_stop(Timer::LossDetection);
                        self.io.timer_stop(Timer::Close);
                        self.io.timer_stop(Timer::Idle);
                    }
                    State::Drained
                }
                ConnectionError::TimedOut => {
                    debug!(self.log, "unexpected connection timed out error received"; "err" => %conn_err, "initial_conn_id" => %self.init_cid);
                    panic!("unexpected connection timed out error received");
                }
                ConnectionError::TransportError { error_code } => State::closed(error_code),
                ConnectionError::VersionMismatch => State::Draining,
            };
        }

        if !was_closed && self.state.is_closed() {
            self.close_common(now);
        }

        // Transmit CONNECTION_CLOSE if necessary
        if let State::Closed(_) = self.state {
            self.io.close = true;
        }
    }

    fn handle_connected_inner(
        &mut self,
        now: u64,
        number: Option<u64>,
        packet: Packet,
    ) -> Result<(), ConnectionError> {
        match self.state {
            State::Handshake(ref state) => {
                match packet.header {
                    Header::Retry {
                        src_cid: rem_cid,
                        orig_dst_cid,
                        ..
                    } => {
                        if self.orig_rem_cid.is_some() || orig_dst_cid != self.rem_cid {
                            // A client MUST accept and process at most one Retry packet for each
                            // connection attempt, and clients MUST discard Retry packets that
                            // contain an Original Destination Connection ID field that does not
                            // match the Destination Connection ID from its Initial packet.
                            return Ok(());
                        }
                        trace!(self.log, "retrying");
                        self.orig_rem_cid = Some(self.rem_cid);
                        self.rem_cid = rem_cid;
                        self.on_packet_acked(SpaceId::Initial, 0);

                        // Reset to initial state
                        let client_config = self.client_config.as_ref().unwrap();
                        self.tls = TlsSession::new_client(
                            &client_config.tls_config,
                            &client_config.server_name,
                            &TransportParameters::new(&self.config),
                        )
                        .unwrap();
                        self.spaces[0] =
                            Some(PacketSpace::new(Crypto::new_initial(&rem_cid, self.side)));
                        self.write_tls();

                        self.state = State::Handshake(state::Handshake {
                            token: Some(packet.payload.into()),
                            rem_cid_set: false,
                        });
                        Ok(())
                    }
                    Header::Long {
                        ty: LongType::Handshake,
                        src_cid: rem_cid,
                        ..
                    } => {
                        if rem_cid != self.rem_cid {
                            debug!(self.log, "discarding packet with mismatched remote CID: {expected} != {actual}", expected = self.rem_cid, actual = rem_cid);
                            return Ok(());
                        }

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

                        let params = self
                            .tls
                            .get_quic_transport_parameters()
                            .ok_or_else(|| {
                                debug!(self.log, "remote didn't send transport params");
                                ConnectionError::from(TransportError::PROTOCOL_VIOLATION)
                            })
                            .and_then(|x| {
                                TransportParameters::read(self.side, &mut io::Cursor::new(x))
                                    .map_err(Into::into)
                            })?;
                        self.set_params(params)?;
                        if self.side.is_client() {
                            // Server applications don't see connections until the handshake
                            // completes, so this would be redundant.
                            self.events.push_back(Event::Connected {
                                protocol: self.tls.get_alpn_protocol().map(|x| x.into()),
                            });
                        }
                        self.state = State::Established;
                        trace!(self.log, "established");
                        Ok(())
                    }
                    Header::Initial {
                        src_cid: rem_cid, ..
                    } => {
                        if !state.rem_cid_set {
                            let mut state = state.clone();
                            self.rem_cid = rem_cid;
                            state.rem_cid_set = true;
                            self.state = State::Handshake(state);
                        } else if rem_cid != self.rem_cid {
                            debug!(self.log, "discarding packet with mismatched remote CID: {expected} != {actual}", expected = self.rem_cid, actual = rem_cid);
                            return Ok(());
                        }
                        self.process_early_payload(now, packet)?;
                        Ok(())
                    }
                    /*Header::Long {
                        ty: types::ZERO_RTT,
                        number,
                        dst_cid: ref id,
                        ..
                    } if self.side.is_server() =>
                    {
                        if let Some(ref crypto) = self.zero_rtt_crypto {
                            if crypto
                                .decrypt(number as u64, &packet.header_data, &mut packet.payload)
                                .is_err()
                            {
                                debug!(
                                    self.log,
                                    "{connection} failed to authenticate 0-RTT packet",
                                    connection = id.clone()
                                );
                                return State::Handshake(state);
                            }
                        } else {
                            debug!(
                                self.log,
                                "{connection} ignoring unsupported 0-RTT packet",
                                connection = id.clone()
                            );
                            return State::Handshake(state);
                        };
                        self.on_packet_authenticated(ctx, now, number as u64);
                        match self.process_payload(
                            ctx,
                            now,
                            conn,
                            number as u64,
                            packet.payload.into(),
                            state.tls.get_mut(),
                        ) {
                            Err(e) => State::HandshakeFailed(state::HandshakeFailed {
                                reason: e,
                                app_closed: false,
                                alert: None,
                            }),
                            Ok(true) => State::Draining(state.into()),
                            Ok(false) => State::Handshake(state),
                        }
                    }*/
                    Header::Long {
                        ty: LongType::ZeroRtt,
                        ..
                    } => {
                        debug!(self.log, "dropping 0-RTT packet (currently unimplemented)");
                        Ok(())
                    }
                    Header::VersionNegotiate { .. } => {
                        let mut payload = io::Cursor::new(&packet.payload[..]);
                        if packet.payload.len() % 4 != 0 {
                            debug!(self.log, "malformed version negotiation");
                            return Err(TransportError::PROTOCOL_VIOLATION.into());
                        }
                        while payload.has_remaining() {
                            let version = payload.get::<u32>().unwrap();
                            if version == VERSION {
                                // Our version is supported, so this packet is spurious
                                return Ok(());
                            }
                        }
                        debug!(self.log, "remote doesn't support our version");
                        Err(ConnectionError::VersionMismatch)
                    }
                    // TODO: SHOULD buffer these to improve reordering tolerance.
                    Header::Short { .. } => {
                        trace!(self.log, "dropping short packet during handshake");
                        Ok(())
                    }
                }
            }
            State::Established => {
                match packet.header.space() {
                    SpaceId::Data => {
                        self.process_payload(now, number.unwrap(), packet.payload.into())?
                    }
                    _ => self.process_early_payload(now, packet)?,
                }
                Ok(())
            }
            State::Closed(_) => {
                for frame in frame::Iter::new(packet.payload.into()) {
                    match frame {
                        Frame::ConnectionClose(_) | Frame::ApplicationClose(_) => {
                            trace!(self.log, "draining");
                            self.state = State::Draining;
                            return Ok(());
                        }
                        _ => {}
                    }
                }
                Ok(())
            }
            State::Draining | State::Drained => Ok(()),
        }
    }

    /// Process an Initial or Handshake packet payload
    fn process_early_payload(&mut self, now: u64, packet: Packet) -> Result<(), TransportError> {
        debug_assert_ne!(packet.header.space(), SpaceId::Data);
        for frame in frame::Iter::new(packet.payload.into()) {
            match frame {
                Frame::Padding => {}
                _ => {
                    trace!(self.log, "got frame"; "type" => %frame.ty());
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
                    self.on_ack_received(now, packet.header.space(), ack);
                }
                Frame::ConnectionClose(reason) => {
                    trace!(
                        self.log,
                        "peer aborted the handshake: {error}",
                        error = reason.error_code
                    );
                    self.events
                        .push_back(ConnectionError::ConnectionClosed { reason }.into());
                    self.state = State::Draining;
                    return Ok(());
                }
                Frame::ApplicationClose(reason) => {
                    self.events
                        .push_back(ConnectionError::ApplicationClosed { reason }.into());
                    self.state = State::Draining;
                    return Ok(());
                }
                _ => {
                    debug!(self.log, "unexpected frame type in handshake"; "type" => %frame.ty());
                    return Err(TransportError::PROTOCOL_VIOLATION);
                }
            }
        }
        self.write_tls();
        Ok(())
    }

    pub fn issue_cid(&mut self, cid: ConnectionId) {
        let token = reset_token_for(&self.config.reset_key, &cid);
        self.cids_issued += 1;
        let sequence = self.cids_issued;
        self.space_mut(SpaceId::Data)
            .pending
            .new_cids
            .push(frame::NewConnectionId {
                id: cid,
                sequence,
                reset_token: token,
            });
        self.loc_cids.insert(self.cids_issued, cid);
    }

    fn process_payload(
        &mut self,
        now: u64,
        number: u64,
        payload: Bytes,
    ) -> Result<(), TransportError> {
        for frame in frame::Iter::new(payload) {
            match frame {
                Frame::Padding => {}
                _ => {
                    trace!(self.log, "got frame"; "type" => %frame.ty());
                }
            }
            match frame {
                Frame::Ack(_) | Frame::Padding => {}
                _ => {
                    self.space_mut(SpaceId::Data).permit_ack_only = true;
                }
            }
            match frame {
                Frame::Invalid(ty) => {
                    debug!(self.log, "received malformed {type} frame", type=ty);
                    return Err(TransportError::FRAME_ENCODING_ERROR);
                }
                Frame::Illegal(ty) => {
                    debug!(self.log, "received illegal {type} frame", type=ty);
                    return Err(TransportError::PROTOCOL_VIOLATION);
                }
                Frame::Crypto(frame) => {
                    self.read_tls(SpaceId::Data, &frame)?;
                }
                Frame::Stream(frame) => {
                    trace!(self.log, "got stream"; "id" => frame.id.0, "offset" => frame.offset, "len" => frame.data.len(), "fin" => frame.fin);
                    let data_recvd = self.data_recvd;
                    let max_data = self.local_max_data;
                    match self.streams.get_recv_stream(self.side, frame.id) {
                        Err(e) => {
                            debug!(self.log, "received illegal stream frame"; "stream" => frame.id.0);
                            return Err(e);
                        }
                        Ok(None) => {
                            trace!(self.log, "dropping frame for closed stream");
                            continue;
                        }
                        _ => {}
                    }
                    let rs = self.streams.get_recv_mut(frame.id).unwrap();

                    let end = frame.offset + frame.data.len() as u64;
                    if let Some(final_offset) = rs.final_offset() {
                        if end > final_offset || (frame.fin && end != final_offset) {
                            debug!(self.log, "final offset error"; "frame end" => end, "final offset" => final_offset);
                            return Err(TransportError::FINAL_OFFSET_ERROR);
                        }
                    }
                    let prev_end = rs.limit();
                    let new_bytes = end.saturating_sub(prev_end);
                    if end > rs.max_data || data_recvd + new_bytes > max_data {
                        debug!(self.log, "flow control error";
                                   "stream" => frame.id.0, "recvd" => data_recvd, "new bytes" => new_bytes,
                                   "max data" => max_data, "end" => end, "stream max data" => rs.max_data);
                        return Err(TransportError::FLOW_CONTROL_ERROR);
                    }
                    if frame.fin {
                        if let stream::RecvState::Recv { ref mut size } = rs.state {
                            *size = Some(end);
                        }
                    }
                    rs.recvd.insert(frame.offset..end);
                    rs.buffer(frame.data, frame.offset);
                    if let stream::RecvState::Recv { size: Some(size) } = rs.state {
                        if rs.recvd.len() == 1 && rs.recvd.iter().next().unwrap() == (0..size) {
                            rs.state = stream::RecvState::DataRecvd { size };
                        }
                    }

                    let fresh = mem::replace(&mut rs.fresh, false);
                    self.events.push_back(Event::StreamReadable {
                        stream: frame.id,
                        fresh,
                    });
                    self.data_recvd += new_bytes;
                }
                Frame::Ack(ack) => {
                    self.on_ack_received(now, SpaceId::Data, ack);
                    for stream in self.streams.finished.drain(..) {
                        self.events.push_back(Event::StreamFinished { stream });
                    }
                }
                Frame::Padding | Frame::Ping => {}
                Frame::ConnectionClose(reason) => {
                    self.events
                        .push_back(ConnectionError::ConnectionClosed { reason }.into());
                    self.state = State::Draining;
                    return Ok(());
                }
                Frame::ApplicationClose(reason) => {
                    self.events
                        .push_back(ConnectionError::ApplicationClosed { reason }.into());
                    self.state = State::Draining;
                    return Ok(());
                }
                Frame::PathChallenge(x) => {
                    self.space_mut(SpaceId::Data)
                        .pending
                        .path_challenge(number, x);
                }
                Frame::PathResponse(_) => {
                    debug!(self.log, "unsolicited PATH_RESPONSE");
                    return Err(TransportError::PROTOCOL_VIOLATION);
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
                        debug!(self.log, "got MAX_STREAM_DATA on recv-only stream");
                        return Err(TransportError::PROTOCOL_VIOLATION);
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
                    } else {
                        debug!(self.log, "got MAX_STREAM_DATA on unopened stream");
                        return Err(TransportError::PROTOCOL_VIOLATION);
                    }
                }
                Frame::MaxStreams {
                    directionality,
                    count,
                } => {
                    let current = match directionality {
                        Directionality::Uni => &mut self.streams.max_uni,
                        Directionality::Bi => &mut self.streams.max_bi,
                    };
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
                    let (offset, fresh) = match self.streams.get_recv_stream(self.side, id) {
                        Err(e) => {
                            debug!(self.log, "received illegal RST_STREAM");
                            return Err(e);
                        }
                        Ok(None) => {
                            trace!(self.log, "received RST_STREAM on closed stream");
                            continue;
                        }
                        Ok(Some(stream)) => {
                            let rs = stream.recv_mut().unwrap();
                            if let Some(offset) = rs.final_offset() {
                                if offset != final_offset {
                                    return Err(TransportError::FINAL_OFFSET_ERROR);
                                }
                            }
                            if !rs.is_closed() {
                                rs.state = stream::RecvState::ResetRecvd {
                                    size: final_offset,
                                    error_code,
                                };
                            }
                            (rs.limit(), mem::replace(&mut rs.fresh, false))
                        }
                    };
                    self.data_recvd += final_offset.saturating_sub(offset);
                    self.events
                        .push_back(Event::StreamReadable { stream: id, fresh });
                }
                Frame::DataBlocked { offset } => {
                    debug!(self.log, "peer claims to be blocked at connection level"; "offset" => offset);
                }
                Frame::StreamDataBlocked { id, offset } => {
                    debug!(self.log, "peer claims to be blocked at stream level"; "stream" => id, "offset" => offset);
                }
                Frame::StreamsBlocked {
                    directionality,
                    limit,
                } => {
                    debug!(self.log, "peer claims to be blocked opening more than {limit} {directionality} streams", limit=limit, directionality=directionality);
                }
                Frame::StopSending { id, error_code } => {
                    if self.streams.streams.get(&id).map_or(true, |x| {
                        x.send()
                            .map_or(true, |ss| id.initiator() == self.side && ss.offset == 0)
                    }) {
                        debug!(
                            self.log,
                            "got STOP_SENDING on invalid stream {stream}",
                            stream = id
                        );
                        return Err(TransportError::PROTOCOL_VIOLATION);
                    }
                    self.reset(id, error_code);
                    self.streams.get_send_mut(id).unwrap().state = stream::SendState::ResetSent {
                        stop_reason: Some(error_code),
                    };
                }
                Frame::RetireConnectionId { sequence } => {
                    if self.config.local_cid_len == 0 {
                        debug!(
                            self.log,
                            "got RETIRE_CONNECTION_ID when we're not using connection IDs"
                        );
                        return Err(TransportError::PROTOCOL_VIOLATION);
                    }
                    if sequence > self.cids_issued {
                        debug!(
                            self.log,
                            "got RETIRE_CONNECTION_ID for unissued cid sequence number {sequence}",
                            sequence = sequence,
                        );
                        return Err(TransportError::PROTOCOL_VIOLATION);
                    }
                    if let Some(old) = self.loc_cids.remove(&sequence) {
                        self.io.retired_cids.push(old);
                    }
                }
                Frame::NewConnectionId(frame) => {
                    if self.rem_cid.is_empty() {
                        debug!(
                            self.log,
                            "got NEW_CONNECTION_ID when remote isn't using connection IDs"
                        );
                        return Err(TransportError::PROTOCOL_VIOLATION);
                    }
                    if self.params.stateless_reset_token.is_none() {
                        // We're a server using the initial remote CID for the client, so let's
                        // switch immediately to enable clientside stateless resets.
                        debug_assert!(self.side.is_server());
                        debug_assert_eq!(self.rem_cid_seq, 0);
                        self.update_rem_cid(frame);
                    } else {
                        trace!(self.log, "ignoring NEW_CONNECTION_ID (unimplemented)");
                    }
                }
                Frame::NewToken { .. } => {
                    trace!(self.log, "got new token");
                    // TODO: Cache, or perhaps forward to user?
                }
            }
        }
        Ok(())
    }

    fn update_rem_cid(&mut self, new: frame::NewConnectionId) {
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
        self.params.stateless_reset_token = Some(new.reset_token);
    }

    fn populate_packet(
        &mut self,
        now: u64,
        space_id: SpaceId,
        buf: &mut Vec<u8>,
    ) -> (Retransmits, RangeSet) {
        let space = self.spaces[space_id as usize].as_mut().unwrap();
        let mut sent = Retransmits::default();
        let max_size = self.mtu as usize - space.crypto.tag_len();

        // PING
        if space.pending.ping {
            trace!(self.log, "ping");
            space.pending.ping = false;
            buf.write(frame::Type::PING);
        }

        // ACK
        // 0-RTT packets must never carry acks (which would have to be of handshake packets)
        let acks = if !space.pending_acks.is_empty() {
            //&& !crypto.is_0rtt() {
            let delay = (now - self.rx_packet_time) >> ACK_DELAY_EXPONENT;
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

        // PATH_RESPONSE
        if buf.len() + 9 < max_size {
            // No need to retransmit these, so we don't save the value after encoding it.
            if let Some((_, x)) = space.pending.path_response.take() {
                trace!(self.log, "PATH_RESPONSE"; "value" => format!("{:08x}", x));
                buf.write(frame::Type::PATH_RESPONSE);
                buf.write(x);
            }
        }

        // CRYPTO
        while buf.len() + frame::Crypto::SIZE_BOUND < max_size {
            let mut frame = if let Some(x) = space.pending.crypto.pop_front() {
                x
            } else {
                break;
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
        while buf.len() + frame::ResetStream::SIZE_BOUND < max_size {
            let (id, error_code) = if let Some(x) = space.pending.rst_stream.pop() {
                x
            } else {
                break;
            };
            let stream = if let Some(x) = self.streams.streams.get(&id) {
                x
            } else {
                continue;
            };
            trace!(self.log, "RESET_STREAM"; "stream" => id.0);
            sent.rst_stream.push((id, error_code));
            frame::ResetStream {
                id,
                error_code,
                final_offset: stream.send().unwrap().offset,
            }
            .encode(buf);
        }

        // STOP_SENDING
        while buf.len() + 11 < max_size {
            let (id, error_code) = if let Some(x) = space.pending.stop_sending.pop() {
                x
            } else {
                break;
            };
            let stream = if let Some(x) = self.streams.streams.get(&id) {
                x.recv().unwrap()
            } else {
                continue;
            };
            if stream.is_finished() {
                continue;
            }
            trace!(self.log, "STOP_SENDING"; "stream" => id.0);
            sent.stop_sending.push((id, error_code));
            buf.write(frame::Type::STOP_SENDING);
            buf.write(id);
            buf.write(error_code);
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
            let id = if let Some(x) = space.pending.max_stream_data.iter().next() {
                *x
            } else {
                break;
            };
            space.pending.max_stream_data.remove(&id);
            let rs = if let Some(x) = self.streams.streams.get(&id) {
                x.recv().unwrap()
            } else {
                continue;
            };
            if rs.is_finished() {
                continue;
            }
            sent.max_stream_data.insert(id);
            trace!(self.log, "MAX_STREAM_DATA"; "stream" => id.0, "value" => rs.max_data);
            buf.write(frame::Type::MAX_STREAM_DATA);
            buf.write(id);
            buf.write_var(rs.max_data);
        }

        // MAX_STREAMS_UNI
        if space.pending.max_uni_stream_id && buf.len() + 9 < max_size {
            space.pending.max_uni_stream_id = false;
            sent.max_uni_stream_id = true;
            trace!(self.log, "MAX_STREAMS (unidirectional)"; "value" => self.streams.max_remote_uni);
            buf.write(frame::Type::MAX_STREAMS_UNI);
            buf.write_var(self.streams.max_remote_uni);
        }

        // MAX_STREAMS_BIDI
        if space.pending.max_bi_stream_id && buf.len() + 9 < max_size {
            space.pending.max_bi_stream_id = false;
            sent.max_bi_stream_id = true;
            trace!(self.log, "MAX_STREAMS (bidirectional)"; "value" => self.streams.max_remote_bi - 1);
            buf.write(frame::Type::MAX_STREAMS_BIDI);
            buf.write_var(self.streams.max_remote_bi);
        }

        // NEW_CONNECTION_ID
        while buf.len() + 44 < max_size {
            let frame = if let Some(x) = space.pending.new_cids.pop() {
                x
            } else {
                break;
            };
            trace!(
                self.log,
                "NEW_CONNECTION_ID {sequence}",
                sequence = frame.sequence
            );
            frame.encode(buf);
            sent.new_cids.push(frame);
        }

        // RETIRE_CONNECTION_ID
        while buf.len() + frame::RETIRE_CONNECTION_ID_SIZE_BOUND < max_size {
            let seq = if let Some(x) = space.pending.retire_cids.pop() {
                x
            } else {
                break;
            };
            trace!(self.log, "RETIRE_CONNECTION_ID {sequence}", sequence = seq);
            buf.write(frame::Type::RETIRE_CONNECTION_ID);
            buf.write_var(seq);
            sent.retire_cids.push(seq);
        }

        // STREAM
        while buf.len() + frame::Stream::SIZE_BOUND < max_size {
            let mut stream = if let Some(x) = space.pending.stream.pop_front() {
                x
            } else {
                break;
            };
            if self
                .streams
                .streams
                .get(&stream.id)
                .map_or(true, |s| s.send().unwrap().state.was_reset())
            {
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

    fn next_packet(&mut self, now: u64) -> Option<Box<[u8]>> {
        let close = mem::replace(&mut self.io.close, false);
        let space_id = if close {
            self.highest_space
        } else if self.state.is_closed() {
            return None;
        } else {
            SpaceId::VALUES
                .iter()
                .find(|&&x| {
                    self.spaces[x as usize]
                        .as_ref()
                        .map_or(false, |space| space.can_send())
                })
                .cloned()
                .or_else(|| {
                    if self.io.probes != 0 {
                        Some(self.highest_space)
                    } else {
                        None
                    }
                })?
        };
        let probe = !close && self.io.probes != 0;
        let mut ack_only = self.space(space_id).pending.is_empty();
        if space_id == SpaceId::Data && !probe && !ack_only && self.congestion_blocked() {
            return None;
        }
        if self.state.is_handshake()
            && !self.remote_validated
            && self.side.is_server()
            && self.total_recvd * 3 < self.total_sent + self.mtu as u64
        {
            trace!(self.log, "blocked by anti-amplification");
            return None;
        }

        //
        // From here on, we've determined that a packet will definitely be sent.
        //

        self.io.probes = self.io.probes.saturating_sub(1);
        if self.spaces[SpaceId::Initial as usize].is_some()
            && space_id == SpaceId::Handshake
            && self.side.is_client()
        {
            // A client stops both sending and processing Initial packets when it
            // sends its first Handshake packet.
            self.discard_space(SpaceId::Initial)
        }
        if let Some(ref mut prev) = self.prev_crypto {
            prev.update_unacked = false;
        }

        // SCID must be consistent through the handshake, even if we've issued new CIDs in 1-RTT; an
        // earlier Handshake packet might have gotten lost.
        let src_cid = *self
            .loc_cids
            .get(&0)
            .unwrap_or_else(|| self.loc_cids.values().next().unwrap());
        let space = self.spaces[space_id as usize].as_mut().unwrap();
        let number = space.get_tx_number();
        trace!(
            self.log,
            "sending {space:?} packet {number}",
            space = space_id,
            number = number
        );
        let header = match space_id {
            SpaceId::Data => Header::Short {
                dst_cid: self.rem_cid,
                number: PacketNumber::new(number, space.largest_acked_packet),
                spin: self.spin,
                key_phase: self.key_phase,
            },
            SpaceId::Handshake => Header::Long {
                ty: LongType::Handshake,
                src_cid,
                dst_cid: self.rem_cid,
                number: PacketNumber::new(number, space.largest_acked_packet),
            },
            SpaceId::Initial => Header::Initial {
                src_cid,
                dst_cid: self.rem_cid,
                token: match self.state {
                    State::Handshake(ref state) => state.token.clone().unwrap_or_else(Bytes::new),
                    _ => Bytes::new(),
                },
                number: PacketNumber::new(number, space.largest_acked_packet),
            },
        };
        let mut buf = Vec::new();
        let partial_encode = header.encode(&mut buf);
        let header_len = buf.len();

        let sent = if close {
            trace!(self.log, "sending CONNECTION_CLOSE");
            let max_len = self.mtu as usize - header_len - space.crypto.tag_len();
            match self.state {
                State::Closed(state::Closed {
                    reason: state::CloseReason::Application(ref x),
                }) => x.encode(&mut buf, max_len),
                State::Closed(state::Closed {
                    reason: state::CloseReason::Connection(ref x),
                }) => x.encode(&mut buf, max_len),
                _ => unreachable!("tried to make a close packet when the connection wasn't closed"),
            }
            None
        } else {
            Some(self.populate_packet(now, space_id, &mut buf))
        };

        if probe && ack_only && !self.state.is_handshake() {
            // Nothing ack-eliciting to send, so we need to make something up
            buf.write(frame::Type::PING);
            ack_only = false;
        }

        let space = self.spaces[space_id as usize].as_mut().unwrap();
        let mut padded = false;
        if self.side.is_client()
            && (space_id == SpaceId::Initial || (probe && space_id == SpaceId::Handshake))
        {
            // Either this is an initial packet, or the server might be blocked by
            // anti-amplification measures and need some bytes to continue
            buf.resize(MIN_INITIAL_SIZE - space.crypto.tag_len(), 0);
            padded = true;
        }
        let pn_len = header
            .number()
            .expect("next_packet should only send numbered packets")
            .len();
        // To ensure that sufficient data is available for sampling, packets are padded so that the
        // combined lengths of the encoded packet number and protected payload is at least 4 bytes
        // longer than the sample required for header protection.
        let protected_payload_len = (buf.len() + space.crypto.tag_len()) - header_len;
        if let Some(padding_minus_one) =
            (space.header_crypto.sample_size() + 3).checked_sub(pn_len + protected_payload_len)
        {
            let padding = padding_minus_one + 1;
            padded = true;
            trace!(self.log, "PADDING * {count}", count = padding);
            buf.resize(buf.len() + padding, 0);
        }
        if !header.is_short() {
            set_payload_length(&mut buf, header_len, pn_len, space.crypto.tag_len());
        }
        space.crypto.encrypt(number, &mut buf, header_len);
        partial_encode.finish(&mut buf, &space.header_crypto);

        if let Some((sent, acks)) = sent {
            // If we sent any acks, don't immediately resend them. Setting this even if ack_only is
            // false needlessly prevents us from ACKing the next packet if it's ACK-only, but saves
            // the need for subtler logic to avoid double-transmitting acks all the time.
            space.permit_ack_only &= acks.is_empty();

            self.on_packet_sent(
                now,
                space_id,
                number,
                SentPacket {
                    acks,
                    time_sent: now,
                    size: if padded || !ack_only {
                        buf.len() as u16
                    } else {
                        0
                    },
                    is_crypto_packet: space_id != SpaceId::Data && !ack_only,
                    ack_eliciting: !ack_only,
                    retransmits: sent,
                },
            );
        }

        trace!(self.log, "{len} bytes", len = buf.len());
        self.total_sent = self.total_sent.wrapping_add(buf.len() as u64);

        Some(buf.into())
    }

    /// Close a connection immediately
    ///
    /// This does not ensure delivery of outstanding data. It is the application's responsibility
    /// to call this only when all important communications have been completed.
    pub fn close(&mut self, now: u64, error_code: u16, reason: Bytes) {
        let was_closed = self.state.is_closed();
        let reason =
            state::CloseReason::Application(frame::ApplicationClose { error_code, reason });
        if !was_closed {
            self.close_common(now);
            self.io.close = true;
        }

        self.app_closed = true;
        match self.state {
            State::Handshake(_) | State::Established => {
                self.state = State::Closed(state::Closed { reason });
            }
            _ => {}
        }
    }

    fn close_common(&mut self, now: u64) {
        trace!(self.log, "connection closed");
        self.io.timer_stop(Timer::LossDetection);
        self.io.timer_start(Timer::Close, now + 3 * self.pto());
    }

    fn set_params(&mut self, params: TransportParameters) -> Result<(), TransportError> {
        // Validate
        if self.side.is_client() && self.orig_rem_cid != params.original_connection_id {
            debug!(
                self.log,
                "original connection ID mismatch: expected {expected:x?}, actual {actual:x?}",
                expected = self.orig_rem_cid,
                actual = params.original_connection_id
            );
            return Err(TransportError::TRANSPORT_PARAMETER_ERROR);
        }

        // Apply
        self.streams.max_bi = params.initial_max_streams_bidi;
        self.streams.max_uni = params.initial_max_streams_uni;
        self.max_data = params.initial_max_data as u64;
        for i in 0..self.streams.max_remote_bi {
            let id = StreamId::new(!self.side, Directionality::Bi, i as u64);
            self.streams.get_send_mut(id).unwrap().max_data =
                params.initial_max_stream_data_bidi_local as u64;
        }
        self.params = params;
        Ok(())
    }

    pub fn open(&mut self, direction: Directionality) -> Option<StreamId> {
        let (id, mut stream) = match direction {
            Directionality::Uni if self.streams.next_uni < self.streams.max_uni => {
                self.streams.next_uni += 1;
                (
                    StreamId::new(self.side, direction, self.streams.next_uni - 1),
                    stream::Send::new().into(),
                )
            }
            Directionality::Bi if self.streams.next_bi < self.streams.max_bi => {
                self.streams.next_bi += 1;
                (
                    StreamId::new(self.side, direction, self.streams.next_bi - 1),
                    Stream::new_bi(self.config.stream_receive_window as u64),
                )
            }
            _ => {
                return None;
            } // TODO: Queue STREAM_ID_BLOCKED
        };
        stream.send_mut().unwrap().max_data = match direction {
            Directionality::Uni => self.params.initial_max_stream_data_uni,
            Directionality::Bi => self.params.initial_max_stream_data_bidi_remote,
        } as u64;
        let old = self.streams.streams.insert(id, stream);
        assert!(old.is_none());
        Some(id)
    }

    /// Ping the remote endpoint
    ///
    /// Useful for preventing an otherwise idle connection from timing out.
    pub fn ping(&mut self) {
        self.space_mut(SpaceId::Data).pending.ping = true;
    }

    /// Discard state for a stream if it's fully closed.
    ///
    /// Called when one side of a stream transitions to a closed state
    pub fn maybe_cleanup(&mut self, id: StreamId) {
        let new = match self.streams.streams.entry(id) {
            hash_map::Entry::Vacant(_) => unreachable!(),
            hash_map::Entry::Occupied(e) => {
                if e.get().is_closed() {
                    e.remove_entry();
                    if id.initiator() != self.side {
                        let space = self.spaces[SpaceId::Data as usize].as_mut().unwrap();
                        Some(match id.directionality() {
                            Directionality::Uni => {
                                self.streams.max_remote_uni += 1;
                                space.pending.max_uni_stream_id = true;
                                (
                                    StreamId::new(
                                        !self.side,
                                        Directionality::Uni,
                                        self.streams.max_remote_uni - 1,
                                    ),
                                    stream::Recv::new(self.config.stream_receive_window).into(),
                                )
                            }
                            Directionality::Bi => {
                                self.streams.max_remote_bi += 1;
                                space.pending.max_bi_stream_id = true;
                                (
                                    StreamId::new(
                                        !self.side,
                                        Directionality::Bi,
                                        self.streams.max_remote_bi - 1,
                                    ),
                                    Stream::new_bi(self.config.stream_receive_window as u64),
                                )
                            }
                        })
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        };
        if let Some((id, stream)) = new {
            self.streams.streams.insert(id, stream);
        }
    }

    pub fn finish(&mut self, id: StreamId) {
        let ss = self
            .streams
            .get_send_mut(id)
            .expect("unknown or recv-only stream");
        assert_eq!(ss.state, stream::SendState::Ready);
        ss.state = stream::SendState::DataSent;
        let space = self.spaces[SpaceId::Data as usize].as_mut().unwrap();
        for frame in &mut space.pending.stream {
            if frame.id == id && frame.offset + frame.data.len() as u64 == ss.offset {
                frame.fin = true;
                return;
            }
        }
        space.pending.stream.push_back(frame::Stream {
            id,
            data: Bytes::new(),
            offset: ss.offset,
            fin: true,
        });
    }

    pub fn read_unordered(&mut self, id: StreamId) -> Result<(Bytes, u64), ReadError> {
        let rs = self.streams.get_recv_mut(id).unwrap();
        let (buf, len) = rs.read_unordered()?;
        // TODO: Reduce granularity of flow control credit, while still avoiding stalls, to
        // reduce overhead
        self.local_max_data += buf.len() as u64; // BUG: Don't issue credit for
                                                 // already-received data!
        let space = self.spaces[SpaceId::Data as usize].as_mut().unwrap();
        space.pending.max_data = true;
        if rs.receiving_unknown_size() {
            space.pending.max_stream_data.insert(id);
        }
        Ok((buf, len))
    }

    pub fn read(&mut self, id: StreamId, buf: &mut [u8]) -> Result<usize, ReadError> {
        let rs = self.streams.get_recv_mut(id).unwrap();
        let len = rs.read(buf)?;
        // TODO: Reduce granularity of flow control credit, while still avoiding stalls, to
        // reduce overhead
        self.local_max_data += len as u64;
        let space = self.spaces[SpaceId::Data as usize].as_mut().unwrap();
        space.pending.max_data = true;
        if rs.receiving_unknown_size() {
            space.pending.max_stream_data.insert(id);
        }
        Ok(len)
    }

    pub fn stop_sending(&mut self, id: StreamId, error_code: u16) {
        assert!(
            id.directionality() == Directionality::Bi || id.initiator() != self.side,
            "only streams supporting incoming data may be reset"
        );
        let stream = self
            .streams
            .streams
            .get(&id)
            .expect("stream must have begun sending to be stopped")
            .recv()
            .unwrap();
        // Only bother if there's data we haven't received yet
        if !stream.is_finished() {
            let space = self.spaces[SpaceId::Data as usize].as_mut().unwrap();
            space.pending.stop_sending.push((id, error_code));
        }
    }

    fn congestion_blocked(&self) -> bool {
        if let State::Established = self.state {
            self.congestion_window.saturating_sub(self.in_flight.bytes) < self.mtu as u64
        } else {
            false
        }
    }

    fn blocked(&self) -> bool {
        self.data_sent >= self.max_data || self.congestion_blocked()
    }

    fn decrypt_packet(
        &mut self,
        now: u64,
        packet: &mut Packet,
    ) -> Result<Option<u64>, Option<TransportError>> {
        if packet.header.is_retry() {
            // Retry packets are not encrypted and have no packet number
            return Ok(None);
        }
        let number = packet
            .header
            .number()
            .ok_or(None)?
            .expand(self.rx_packet + 1);
        let space = packet.header.space();
        let key_phase = packet.header.key_phase();

        let mut crypto_update = None;
        let crypto = if key_phase == self.key_phase {
            &self.spaces[space as usize].as_mut().unwrap().crypto
        } else if let Some(prev) = self.prev_crypto.as_ref().and_then(|crypto| {
            if number < crypto.end_packet {
                Some(crypto)
            } else {
                None
            }
        }) {
            &prev.crypto
        } else {
            assert_eq!(space, SpaceId::Data);
            crypto_update = Some(
                self.spaces[space as usize]
                    .as_mut()
                    .unwrap()
                    .crypto
                    .update(self.side, &self.tls),
            );
            crypto_update.as_ref().unwrap()
        };

        crypto
            .decrypt(number, &packet.header_data, &mut packet.payload)
            .map_err(|()| None)?;

        if let Some(ref mut prev) = self.prev_crypto {
            if prev.update_ack_time.is_none() && key_phase == self.key_phase {
                // Key update newly acknowledged
                prev.update_ack_time = Some(now);
                self.set_key_discard_timer(now);
            }
        }

        let reserved = match packet.header {
            Header::Short { .. } => SHORT_RESERVED_BITS,
            _ => LONG_RESERVED_BITS,
        };
        if packet.header_data[0] & reserved != 0 {
            debug!(self.log, "peer set reserved bits");
            return Err(Some(TransportError::PROTOCOL_VIOLATION));
        }

        if let Some(crypto) = crypto_update {
            if number <= self.rx_packet
                || self
                    .prev_crypto
                    .as_ref()
                    .map_or(false, |x| x.update_unacked)
            {
                warn!(self.log, "recieved an illegal key update");
                return Err(Some(TransportError::PROTOCOL_VIOLATION));
            }
            trace!(self.log, "key update authenticated");
            self.update_keys(crypto, number, true);
            // No need to wait for confirmation of a remotely-initiated key update
            self.prev_crypto.as_mut().unwrap().update_ack_time = Some(now);
            self.set_key_discard_timer(now);
        }

        Ok(Some(number))
    }

    #[cfg(test)]
    pub fn initiate_key_update(&mut self) {
        let space = self.space(SpaceId::Data);
        let update = space.crypto.update(self.side, &self.tls);
        self.update_keys(update, space.next_packet_number, false);
    }

    pub fn write(&mut self, stream: StreamId, data: &[u8]) -> Result<usize, WriteError> {
        assert!(stream.directionality() == Directionality::Bi || stream.initiator() == self.side);
        if self.state.is_closed() {
            trace!(self.log, "write blocked; connection draining"; "stream" => stream.0);
            return Err(WriteError::Blocked);
        }

        if self.blocked() {
            if self.congestion_blocked() {
                trace!(self.log, "write blocked by congestion"; "stream" => stream.0);
            } else {
                trace!(self.log, "write blocked by connection-level flow control"; "stream" => stream.0);
            }
            self.blocked_streams.insert(stream);
            return Err(WriteError::Blocked);
        }

        let budget_res = self
            .streams
            .get_send_mut(stream)
            .expect("stream already closed")
            .write_budget();

        let stream_budget = match budget_res {
            Ok(budget) => budget,
            Err(e @ WriteError::Stopped { .. }) => {
                self.maybe_cleanup(stream);
                return Err(e);
            }
            Err(e @ WriteError::Blocked) => {
                trace!(self.log, "write blocked by flow control"; "stream" => stream.0);
                return Err(e);
            }
        };

        let conn_budget = self.max_data - self.data_sent;
        let n = conn_budget.min(stream_budget).min(data.len() as u64) as usize;
        self.queue_stream_data(stream, (&data[0..n]).into());
        trace!(self.log, "write"; "stream" => stream.0, "len" => n);
        Ok(n)
    }

    fn update_keys(&mut self, crypto: Crypto, number: u64, remote: bool) {
        let old = mem::replace(
            &mut self.spaces[SpaceId::Data as usize].as_mut().unwrap().crypto,
            crypto,
        );
        self.prev_crypto = Some(PrevCrypto {
            crypto: old,
            end_packet: number,
            update_ack_time: None,
            update_unacked: remote,
        });
        self.key_phase = !self.key_phase;
    }

    pub fn is_handshaking(&self) -> bool {
        self.state.is_handshake()
    }

    pub fn is_closed(&self) -> bool {
        self.state.is_closed()
    }

    pub fn has_1rtt(&self) -> bool {
        self.spaces[SpaceId::Data as usize].is_some()
    }

    pub fn is_drained(&self) -> bool {
        self.state.is_drained()
    }

    /// Look up whether we're the client or server of this Connection
    pub fn side(&self) -> Side {
        self.side
    }

    /// The `ConnectionId`s defined for this Connection locally.
    pub fn loc_cids(&self) -> impl Iterator<Item = &ConnectionId> {
        self.loc_cids.values()
    }

    /// The `ConnectionId` defined for this Connection by the peer.
    pub fn rem_cid(&self) -> ConnectionId {
        self.rem_cid
    }

    pub fn remote(&self) -> SocketAddr {
        self.remote
    }

    pub fn protocol(&self) -> Option<&[u8]> {
        self.tls.get_alpn_protocol().map(|p| p.as_bytes())
    }

    /// The number of bytes of packets containing retransmittable frames that have not been
    /// acknowledged or declared lost.
    pub fn bytes_in_flight(&self) -> u64 {
        self.in_flight.bytes
    }

    /// Number of bytes worth of non-ack-only packets that may be sent
    pub fn congestion_state(&self) -> u64 {
        self.congestion_window.saturating_sub(self.in_flight.bytes)
    }

    /// The name a client supplied via SNI
    ///
    /// `None` if no name was supplised or if this connection was locally initiated.
    pub fn server_name(&self) -> Option<&str> {
        self.tls.get_sni_hostname()
    }

    /// Whether a previous session was successfully resumed by this connection
    pub fn session_resumed(&self) -> bool {
        false // TODO: fixme?
    }

    /// Total number of outgoing packets that have been deemed lost
    pub fn lost_packets(&self) -> u64 {
        self.lost_packets
    }

    /// Whether explicit congestion notification is in use on outgoing packets.
    pub fn using_ecn(&self) -> bool {
        self.sending_ecn
    }

    /// Microseconds
    fn max_ack_delay(&self) -> u64 {
        u64::from(self.params.max_ack_delay) * 1000
    }

    fn space(&self, id: SpaceId) -> &PacketSpace {
        self.spaces[id as usize]
            .as_ref()
            .expect("tried to access unavailable packet space")
    }

    fn space_mut(&mut self, id: SpaceId) -> &mut PacketSpace {
        self.spaces[id as usize]
            .as_mut()
            .expect("tried to access unavailable packet space")
    }
}

pub fn initial_close<R>(
    crypto: &Crypto,
    header_crypto: &HeaderCrypto,
    remote_id: &ConnectionId,
    local_id: &ConnectionId,
    packet_number: u8,
    reason: R,
) -> Box<[u8]>
where
    R: Into<state::CloseReason>,
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
    let header_len = buf.len();
    let max_len = MIN_MTU as usize - header_len - crypto.tag_len();
    match reason.into() {
        state::CloseReason::Application(ref x) => x.encode(&mut buf, max_len),
        state::CloseReason::Connection(ref x) => x.encode(&mut buf, max_len),
    }
    set_payload_length(&mut buf, header_len, number.len(), crypto.tag_len());
    crypto.encrypt(packet_number as u64, &mut buf, header_len);
    partial_encode.finish(&mut buf, header_crypto);
    buf.into()
}

struct Streams {
    // Set of streams that are currently open, or could be immediately opened by the peer
    streams: FnvHashMap<StreamId, Stream>,
    next_uni: u64,
    next_bi: u64,
    // Locally initiated
    max_uni: u64,
    max_bi: u64,
    // Remotely initiated
    max_remote_uni: u64,
    max_remote_bi: u64,

    finished: Vec<StreamId>,
}

impl Streams {
    fn get_recv_stream(
        &mut self,
        side: Side,
        id: StreamId,
    ) -> Result<Option<&mut Stream>, TransportError> {
        if side == id.initiator() {
            match id.directionality() {
                Directionality::Uni => {
                    return Err(TransportError::STREAM_STATE_ERROR);
                }
                Directionality::Bi if id.index() >= self.next_bi => {
                    return Err(TransportError::STREAM_STATE_ERROR);
                }
                Directionality::Bi => {}
            };
        } else {
            let limit = match id.directionality() {
                Directionality::Bi => self.max_remote_bi,
                Directionality::Uni => self.max_remote_uni,
            };
            if id.index() >= limit {
                return Err(TransportError::STREAM_LIMIT_ERROR);
            }
        }
        Ok(self.streams.get_mut(&id))
    }

    fn get_recv_mut(&mut self, id: StreamId) -> Option<&mut stream::Recv> {
        self.streams.get_mut(&id)?.recv_mut()
    }

    fn get_send_mut(&mut self, id: StreamId) -> Option<&mut stream::Send> {
        self.streams.get_mut(&id)?.send_mut()
    }
}

#[derive(Debug, Clone)]
struct Retransmits {
    max_data: bool,
    max_uni_stream_id: bool,
    max_bi_stream_id: bool,
    ping: bool,
    stream: VecDeque<frame::Stream>,
    /// packet number, token
    path_response: Option<(u64, u64)>,
    rst_stream: Vec<(StreamId, u16)>,
    stop_sending: Vec<(StreamId, u16)>,
    max_stream_data: FnvHashSet<StreamId>,
    crypto: VecDeque<frame::Crypto>,
    new_cids: Vec<frame::NewConnectionId>,
    retire_cids: Vec<u64>,
}

impl Retransmits {
    fn is_empty(&self) -> bool {
        !self.max_data
            && !self.max_uni_stream_id
            && !self.max_bi_stream_id
            && !self.ping
            && self.stream.is_empty()
            && self.path_response.is_none()
            && self.rst_stream.is_empty()
            && self.stop_sending.is_empty()
            && self.max_stream_data.is_empty()
            && self.crypto.is_empty()
            && self.new_cids.is_empty()
            && self.retire_cids.is_empty()
    }

    fn path_challenge(&mut self, packet: u64, token: u64) {
        match self.path_response {
            None => {
                self.path_response = Some((packet, token));
            }
            Some((existing, _)) if packet > existing => {
                self.path_response = Some((packet, token));
            }
            Some(_) => {}
        }
    }
}

impl Default for Retransmits {
    fn default() -> Self {
        Self {
            max_data: false,
            max_uni_stream_id: false,
            max_bi_stream_id: false,
            ping: false,
            stream: VecDeque::new(),
            path_response: None,
            rst_stream: Vec::new(),
            stop_sending: Vec::new(),
            max_stream_data: FnvHashSet::default(),
            crypto: VecDeque::new(),
            new_cids: Vec::new(),
            retire_cids: Vec::new(),
        }
    }
}

impl ::std::ops::AddAssign for Retransmits {
    /// Take ownership of retransmittable data from `rhs`; discard the rest.
    fn add_assign(&mut self, rhs: Self) {
        self.max_data |= rhs.max_data;
        self.ping |= rhs.ping;
        self.max_uni_stream_id |= rhs.max_uni_stream_id;
        self.max_bi_stream_id |= rhs.max_bi_stream_id;
        self.stream.extend(rhs.stream.into_iter());
        self.rst_stream.extend_from_slice(&rhs.rst_stream);
        self.stop_sending.extend_from_slice(&rhs.stop_sending);
        self.max_stream_data.extend(&rhs.max_stream_data);
        self.crypto.extend(rhs.crypto.into_iter());
        self.new_cids.extend(&rhs.new_cids);
        self.retire_cids.extend(rhs.retire_cids);
    }
}

impl ::std::iter::FromIterator<Retransmits> for Retransmits {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = Retransmits>,
    {
        let mut result = Retransmits::default();
        for packet in iter {
            result += packet;
        }
        result
    }
}

/// Reasons why a connection might be lost.
#[derive(Debug, Clone, Fail)]
pub enum ConnectionError {
    /// The peer doesn't implement any supported version.
    #[fail(display = "peer doesn't implement any supported version")]
    VersionMismatch,
    /// The peer violated the QUIC specification as understood by this implementation.
    #[fail(display = "{}", error_code)]
    TransportError { error_code: TransportError },
    /// The peer's QUIC stack aborted the connection automatically.
    #[fail(display = "aborted by peer: {}", reason)]
    ConnectionClosed { reason: frame::ConnectionClose },
    /// The peer closed the connection.
    #[fail(display = "closed by peer: {}", reason)]
    ApplicationClosed { reason: frame::ApplicationClose },
    /// The peer is unable to continue processing this connection, usually due to having restarted.
    #[fail(display = "reset by peer")]
    Reset,
    /// The peer has become unreachable.
    #[fail(display = "timed out")]
    TimedOut,
}

impl From<TransportError> for ConnectionError {
    fn from(x: TransportError) -> Self {
        ConnectionError::TransportError { error_code: x }
    }
}

// For compatibility with API consumers
impl From<ConnectionError> for io::Error {
    fn from(x: ConnectionError) -> io::Error {
        use self::ConnectionError::*;
        match x {
            TimedOut => io::Error::new(io::ErrorKind::TimedOut, "timed out"),
            Reset => io::Error::new(io::ErrorKind::ConnectionReset, "reset by peer"),
            ApplicationClosed { reason } => io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("closed by peer application: {}", reason),
            ),
            ConnectionClosed { reason } => io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("peer detected an error: {}", reason),
            ),
            TransportError { error_code } => {
                io::Error::new(io::ErrorKind::Other, format!("{}", error_code))
            }
            VersionMismatch => io::Error::new(io::ErrorKind::Other, "version mismatch"),
        }
    }
}

impl From<state::CloseReason> for ConnectionError {
    fn from(cr: state::CloseReason) -> ConnectionError {
        match cr {
            state::CloseReason::Connection(conn_close) => conn_close.error_code.into(),
            state::CloseReason::Application(app_close) => {
                ConnectionError::ApplicationClosed { reason: app_close }
            }
        }
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
    fn closed<R: Into<state::CloseReason>>(reason: R) -> Self {
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
        pub rem_cid_set: bool,
        pub token: Option<Bytes>,
    }

    #[derive(Clone)]
    pub enum CloseReason {
        Connection(frame::ConnectionClose),
        Application(frame::ApplicationClose),
    }

    impl From<TransportError> for CloseReason {
        fn from(x: TransportError) -> Self {
            CloseReason::Connection(x.into())
        }
    }
    impl From<frame::ConnectionClose> for CloseReason {
        fn from(x: frame::ConnectionClose) -> Self {
            CloseReason::Connection(x)
        }
    }
    impl From<frame::ApplicationClose> for CloseReason {
        fn from(x: frame::ApplicationClose) -> Self {
            CloseReason::Application(x)
        }
    }

    #[derive(Clone)]
    pub struct Closed {
        pub reason: CloseReason,
    }
}

#[derive(Clone)]
pub struct ClientConfig {
    pub server_name: String,
    pub tls_config: Arc<crypto::ClientConfig>,
}

/// Represents one or more packets subject to retransmission
#[derive(Debug, Clone)]
struct SentPacket {
    /// The time the packet was sent.
    time_sent: u64,
    /// The number of bytes sent in the packet, not including UDP or IP overhead, but including QUIC
    /// framing overhead. Zero if this packet is not counted towards congestion control, i.e. not an
    /// "in flight" packet.
    size: u16,
    /// Whether an acknowledgement is expected directly in response to this packet.
    ack_eliciting: bool,
    /// Whether the packet contains cryptographic handshake messages critical to the completion of
    /// the QUIC handshake.
    // FIXME: Implied by retransmits + space
    is_crypto_packet: bool,
    acks: RangeSet,
    retransmits: Retransmits,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct ConnectionHandle(pub usize);

impl From<ConnectionHandle> for usize {
    fn from(x: ConnectionHandle) -> usize {
        x.0
    }
}

/// Ensures we can always fit all our ACKs in a single minimum-MTU packet with room to spare
const MAX_ACK_BLOCKS: usize = 64;

/// I/O operations to be immediately executed the backend.
#[derive(Debug)]
pub enum Io {
    Transmit {
        destination: SocketAddr,
        /// Explicit congestion notification bits to set on the packet
        ecn: Option<EcnCodepoint>,
        packet: Box<[u8]>,
    },
    /// Stop or (re)start a timer
    TimerUpdate {
        timer: Timer,
        update: TimerUpdate,
    },
    RetireConnectionId {
        connection_id: ConnectionId,
    },
}

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
    timers: [Option<TimerUpdate>; 4],
    retired_cids: Vec<ConnectionId>,
}

impl IoQueue {
    fn new() -> Self {
        Self {
            probes: 0,
            close: false,
            timers: [None; 4],
            retired_cids: Vec::new(),
        }
    }

    /// Start or reset a timer associated with this connection.
    fn timer_start(&mut self, timer: Timer, time: u64) {
        self.timers[timer as usize] = Some(TimerUpdate::Start(time));
    }

    /// Start one of the timers associated with this connection.
    fn timer_stop(&mut self, timer: Timer) {
        self.timers[timer as usize] = Some(TimerUpdate::Stop);
    }
}

/// Changes to a connection's timers
#[derive(Debug, Copy, Clone)]
pub enum TimerUpdate {
    /// Set the timer to expire at an a certain point in time, in absolute microseconds
    Start(u64),
    /// Cancel time timer if it's currently running
    Stop,
}

struct PacketSpace {
    crypto: Crypto,
    header_crypto: HeaderCrypto,
    dedup: Dedup,

    /// Data to send
    pending: Retransmits,
    /// Packet numbers to acknowledge
    pending_acks: RangeSet,
    /// Set iff we have received a non-ack frame since the last ack-only packet we sent
    permit_ack_only: bool,

    /// The packet number of the next packet that will be sent, if any.
    next_packet_number: u64,
    /// The largest packet number the remote peer acknowledged in an ACK frame.
    largest_acked_packet: u64,
    /// Transmitted but not acked
    // We use a BTreeMap here so we can efficiently query by range on ACK and for loss detection
    sent_packets: BTreeMap<u64, SentPacket>,
    /// Recent ECN counters sent by the peer in ACK frames
    ///
    /// Updated (and inspected) whenever we receive an ACK with a new highest acked packet
    /// number. Stored per-space to simplify verification, which would otherwise have difficulty
    /// distinguishing between ECN bleaching and counts having been updated by a near-simultaneous
    /// ACK already processed in another space.
    ecn_feedback: frame::EcnCounts,

    /// Incoming cryptographic handshake stream
    crypto_stream: stream::Assembler,
    /// Current offset of outgoing cryptographic handshake stream
    crypto_offset: u64,
}

impl PacketSpace {
    fn new(crypto: Crypto) -> Self {
        Self {
            header_crypto: crypto.header_crypto(),
            crypto,
            dedup: Dedup::new(),

            pending: Retransmits::default(),
            pending_acks: RangeSet::new(),
            permit_ack_only: false,

            next_packet_number: 0,
            largest_acked_packet: 0,
            sent_packets: BTreeMap::new(),
            ecn_feedback: frame::EcnCounts::ZERO,

            crypto_stream: stream::Assembler::new(),
            crypto_offset: 0,
        }
    }

    fn get_tx_number(&mut self) -> u64 {
        // TODO: Handle packet number overflow gracefully
        assert!(self.next_packet_number < 2u64.pow(62));
        let x = self.next_packet_number;
        self.next_packet_number += 1;
        x
    }

    fn can_send(&self) -> bool {
        !self.pending.is_empty() || (self.permit_ack_only && !self.pending_acks.is_empty())
    }

    /// Verifies sanity of an ECN block and returns whether congestion was encountered.
    fn detect_ecn(
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
}

struct PrevCrypto {
    crypto: Crypto,
    end_packet: u64,
    /// Time at which a packet using the following key phase was received
    update_ack_time: Option<u64>,
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
        self.bytes += packet.size as u64;
        self.crypto += packet.is_crypto_packet as u64;
        self.ack_eliciting += packet.ack_eliciting as u64;
    }

    /// Update counters to account for a packet becoming acknowledged, lost, or abandoned
    fn remove(&mut self, packet: &SentPacket) {
        self.bytes -= packet.size as u64;
        self.crypto -= packet.is_crypto_packet as u64;
        self.ack_eliciting -= packet.ack_eliciting as u64;
    }
}
