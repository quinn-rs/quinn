use std::collections::{hash_map, BTreeMap, HashMap, VecDeque};
use std::net::SocketAddrV6;
use std::sync::Arc;
use std::{cmp, io, mem};

use bytes::{Buf, Bytes, BytesMut};
use fnv::{FnvHashMap, FnvHashSet};
use slog::Logger;

use crate::coding::{BufExt, BufMutExt};
use crate::crypto::{self, reset_token_for, Crypto, HeaderCrypto, TlsSession, ACK_DELAY_EXPONENT};
use crate::dedup::Dedup;
use crate::endpoint::{Config, Event, Timer};
use crate::frame::FrameStruct;
use crate::packet::{
    set_payload_length, ConnectionId, EcnCodepoint, Header, LongType, Packet, PacketNumber,
    PartialDecode, AEAD_TAG_SIZE, LONG_RESERVED_BITS, SHORT_RESERVED_BITS,
};
use crate::range_set::RangeSet;
use crate::stream::{self, ReadError, Stream, WriteError};
use crate::transport_parameters::{self, TransportParameters};
use crate::{
    frame, Directionality, Frame, Side, StreamId, TransportError, MIN_INITIAL_SIZE, MIN_MTU,
    RESET_TOKEN_SIZE, TIMER_GRANULARITY, VERSION,
};
use rustls::internal::msgs::enums::AlertDescription;

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
    pub(crate) remote: SocketAddrV6,
    state: State,
    side: Side,
    mtu: u16,
    /// Highest received packet number
    rx_packet: u64,
    /// Time at which the above was received
    rx_packet_time: u64,
    cryptos: VecDeque<CryptoSpace>,
    header_cryptos: VecDeque<(CryptoLevel, HeaderCrypto)>,
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
    /// Incoming cryptographic handshake stream
    crypto_stream: stream::Assembler,
    /// Current offset of outgoing cryptographic handshake stream
    crypto_offset: u64,
    /// ConnectionId sent by this client on the first Initial, if a Retry was received.
    orig_rem_cid: Option<ConnectionId>,
    dedup: Dedup,
    /// Total number of outgoing packets that have been deemed lost
    lost_packets: u64,
    io: IoQueue,
    events: VecDeque<Event>,
    /// Number of local connection IDs that have been issued in NEW_CONNECTION_ID frames.
    cids_issued: u64,

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
    /// The packet number of the next packet that will be sent, if any.
    next_packet_number: u64,
    /// The largest packet number the remote peer acknowledged in an ACK frame.
    largest_acked_packet: u64,
    /// Transmitted but not acked
    sent_packets: BTreeMap<u64, SentPacket>,

    //
    // Congestion Control
    //
    /// The sum of the size in bytes of all sent packets that contain at least one retransmittable
    /// frame, and have not been acked or declared lost.
    ///
    /// The size does not include IP or UDP overhead. Packets only containing ACK frames do not
    /// count towards bytes_in_flight to ensure congestion control does not impede congestion
    /// feedback.
    bytes_in_flight: u64,
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
    /// Recent ECN counters sent by the peer in ACK frames
    ///
    /// Updated (and inspected) whenever we receive an ACK with a new highest acked packet number.
    ecn_feedback: frame::EcnCounts,
    /// Whether we're enabling ECN on outgoing packets
    sending_ecn: bool,
    /// Whether the most recently received packet had an ECN codepoint set
    receiving_ecn: bool,

    //
    // Handshake retransmit state
    //
    /// Whether we've sent crypto packets that have not been either explicitly acknowledged or
    /// rendered moot by handshake completion, i.e. whether we're waiting for proof that the peer
    /// has advanced their handshake state machine.
    crypto_in_flight: bool,
    crypto_pending: Retransmits,

    //
    // Transmit queue
    //
    pub(crate) pending: Retransmits,
    pending_acks: RangeSet,
    /// Set iff we have received a non-ack frame since the last ack-only packet we sent
    permit_ack_only: bool,

    //
    // Stream states
    //
    streams: Streams,
}

impl Connection {
    pub fn new(
        log: Logger,
        config: Arc<Config>,
        init_cid: ConnectionId,
        loc_cid: ConnectionId,
        rem_cid: ConnectionId,
        remote: SocketAddrV6,
        client_config: Option<ClientConfig>,
        tls: TlsSession,
    ) -> Self {
        let side = if client_config.is_some() {
            Side::Client
        } else {
            Side::Server
        };

        let crypto = CryptoSpace {
            level: CryptoLevel::Initial,
            start: 0,
            crypto: Crypto::new_initial(&init_cid, side),
        };
        let mut header_cryptos = VecDeque::with_capacity(3);
        header_cryptos.push_back((CryptoLevel::Initial, crypto.crypto.header_crypto()));
        let mut cryptos = VecDeque::with_capacity(4);
        cryptos.push_back(crypto);
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
            rx_packet_time: 0,
            cryptos,
            header_cryptos,
            //zero_rtt_crypto: None,
            key_phase: false,
            params: TransportParameters::new(&config),
            blocked_streams: FnvHashSet::default(),
            max_data: 0,
            data_sent: 0,
            data_recvd: 0,
            local_max_data: config.receive_window as u64,
            client_config,
            crypto_stream: stream::Assembler::new(),
            crypto_offset: 0,
            orig_rem_cid: None,
            dedup: Dedup::new(),
            lost_packets: 0,
            io: IoQueue::new(),
            events: VecDeque::new(),
            cids_issued: 0,

            crypto_count: 0,
            pto_count: 0,
            loss_time: 0,
            latest_rtt: 0,
            smoothed_rtt: 0,
            rttvar: 0,
            min_rtt: u64::max_value(),
            time_of_last_sent_ack_eliciting_packet: 0,
            time_of_last_sent_crypto_packet: 0,
            next_packet_number: 0,
            largest_acked_packet: 0,
            sent_packets: BTreeMap::new(),

            bytes_in_flight: 0,
            congestion_window: config.initial_window,
            recovery_start_time: 0,
            ssthresh: u64::max_value(),
            ecn_counters: frame::EcnCounts::ZERO,
            ecn_feedback: frame::EcnCounts::ZERO,
            sending_ecn: true,
            receiving_ecn: false,

            crypto_in_flight: false,
            crypto_pending: Retransmits::default(),

            pending: Retransmits::default(),
            pending_acks: RangeSet::new(),
            permit_ack_only: false,

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
            this.connect();
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
        let packet = self
            .next_packet(now)
            .or_else(|| {
                if self.io.probes == 0 {
                    return None;
                }
                self.io.probes -= 1;
                Some(self.make_probe(now))
            })
            .or_else(|| {
                if !self.io.close {
                    return None;
                }
                self.io.close = false;
                Some(self.make_close())
            });

        if let Some(packet) = packet {
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

    /// Initiate a connection
    fn connect(&mut self) {
        self.write_tls();
    }

    fn get_tx_number(&mut self) -> u64 {
        // TODO: Handle packet number overflow gracefully
        assert!(self.next_packet_number < 2u64.pow(62));
        let x = self.next_packet_number;
        self.next_packet_number += 1;
        x
    }

    fn on_packet_sent(&mut self, now: u64, packet_number: u64, packet: SentPacket) {
        let SentPacket {
            size,
            is_crypto_packet,
            ack_eliciting,
            ..
        } = packet;
        if is_crypto_packet {
            self.crypto_in_flight = true;
        }
        self.sent_packets.insert(packet_number, packet);
        if ack_eliciting {
            self.time_of_last_sent_ack_eliciting_packet = now;
            if is_crypto_packet {
                self.time_of_last_sent_crypto_packet = now;
            }
            self.bytes_in_flight += size as u64;
            self.set_loss_detection_timer();
        }
    }

    fn on_ack_received(&mut self, now: u64, ack: frame::Ack) {
        trace!(self.log, "got ack"; "ranges" => ?ack.iter().collect::<Vec<_>>());
        let was_blocked = self.blocked();
        let prev_largest = self.largest_acked_packet;
        self.largest_acked_packet = cmp::max(ack.largest, self.largest_acked_packet);
        let largest_acked_time_sent = self.sent_packets.get(&ack.largest).map(|x| x.time_sent);

        if let Some(info) = self.sent_packets.get(&ack.largest).cloned() {
            if info.ack_eliciting {
                self.latest_rtt = now - info.time_sent;
                let delay = ack.delay << self.params.ack_delay_exponent;
                self.update_rtt(delay);
            }
        }

        // Avoid DoS from unreasonably huge ack ranges by filtering out just the new acks.
        let newly_acked = ack
            .iter()
            .flat_map(|range| self.sent_packets.range(range).map(|(&n, _)| n))
            .collect::<Vec<_>>();
        if newly_acked.is_empty() {
            return;
        }
        for &packet in &newly_acked {
            self.on_packet_acked(packet);
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
                    self.process_ecn(now, newly_acked.len() as u64, ecn, largest_acked_time_sent);
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
        newly_acked: u64,
        ecn: frame::EcnCounts,
        largest_sent_time: Option<u64>,
    ) {
        // TODO: largest_sent_time shouldn't be optional, because a new largest ack is by definition
        // newly acked, but our remaining draft-11 handshake hacks violate that. To be fixed when
        // the handshake procedure is updated.
        match self.detect_ecn(newly_acked, ecn) {
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
                if let Some(time) = largest_sent_time {
                    self.congestion_event(now, time);
                }
            }
        }
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
    fn on_packet_acked(&mut self, packet: u64) {
        let info = if let Some(x) = self.sent_packets.remove(&packet) {
            x
        } else {
            return;
        };
        if info.ack_eliciting {
            // Congestion control
            self.bytes_in_flight -= info.size as u64;
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
        self.pending_acks.subtract(&info.acks);
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
        }
        false
    }

    fn on_loss_detection_timeout(&mut self, now: u64) {
        if self.crypto_in_flight {
            trace!(self.log, "retransmitting handshake packets");
            let packets = self
                .sent_packets
                .iter()
                .filter_map(|(&packet, info)| {
                    if info.is_crypto_packet {
                        Some(packet)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            for number in packets {
                let info = self.sent_packets.remove(&number).unwrap();
                self.crypto_pending += info.retransmits;
                self.bytes_in_flight -= info.size as u64;
            }
            debug_assert!(!self.crypto_pending.is_empty());
            self.crypto_count += 1;
        } else if self.loss_time != 0 {
            // Time threshold loss Detection
            self.detect_lost_packets(now);
        } else {
            trace!(self.log, "PTO fired";
                   "outstanding" => ?self.sent_packets.keys().collect::<Vec<_>>(),
                   "in flight" => self.bytes_in_flight);
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
        let lost_pn = self
            .largest_acked_packet
            .saturating_sub(self.config.packet_threshold as u64);
        for (&packet, info) in self.sent_packets.range(0..self.largest_acked_packet) {
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
            let old_bytes_in_flight = self.bytes_in_flight;
            let largest_lost_time = self.sent_packets[&largest_lost].time_sent;
            for packet in lost_packets {
                let info = self.sent_packets.remove(&packet).unwrap();
                if !info.in_flight {
                    continue;
                }
                self.bytes_in_flight -= info.size as u64;
                self.lost_packets += 1;
                if info.is_crypto_packet {
                    self.crypto_pending += info.retransmits;
                } else {
                    self.pending += info.retransmits;
                }
            }
            // Don't apply congestion penalty for lost ack-only packets
            let lost_nonack = old_bytes_in_flight != self.bytes_in_flight;
            if lost_nonack {
                self.congestion_event(now, largest_lost_time)
            }
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
        if self.bytes_in_flight == 0 {
            self.io.timer_stop(Timer::LossDetection);
            return;
        }

        if self.crypto_in_flight {
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
        ecn: Option<EcnCodepoint>,
        packet: Option<u64>,
    ) {
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
        trace!(self.log, "packet {packet} authenticated", packet = packet);
        self.pending_acks.insert_one(packet);
        if self.pending_acks.len() > MAX_ACK_BLOCKS {
            self.pending_acks.pop_min();
        }
        if packet > self.rx_packet {
            self.rx_packet = packet;
            self.rx_packet_time = now;
        }
    }

    pub fn reset_idle_timeout(&mut self, now: u64) {
        let dt = if self.config.idle_timeout == 0 || self.params.idle_timeout == 0 {
            cmp::max(self.config.idle_timeout, self.params.idle_timeout)
        } else {
            cmp::min(self.config.idle_timeout, self.params.idle_timeout)
        };
        self.io
            .timer_start(Timer::Idle, now + dt as u64 * 1_000_000);
    }

    /// Consider all previously transmitted handshake packets to be delivered. Called when we
    /// receive a new handshake packet.
    fn handshake_cleanup(&mut self) {
        if !self.crypto_in_flight {
            return;
        }
        self.crypto_in_flight = false;
        self.crypto_pending = Retransmits::default();
        let mut packets = Vec::new();
        for (&packet, info) in &self.sent_packets {
            if info.is_crypto_packet {
                packets.push(packet);
            }
        }
        for packet in packets {
            self.on_packet_acked(packet);
        }
        self.set_loss_detection_timer();
    }

    fn queue_stream_data(&mut self, stream: StreamId, data: Bytes) {
        let ss = self.streams.get_send_mut(stream).unwrap();
        assert_eq!(ss.state, stream::SendState::Ready);
        let offset = ss.offset;
        ss.offset += data.len() as u64;
        ss.bytes_in_flight += data.len() as u64;
        self.data_sent += data.len() as u64;
        self.pending.stream.push_back(frame::Stream {
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

        self.pending.rst_stream.push((stream_id, error_code));
    }

    pub fn handle_initial(
        &mut self,
        now: u64,
        ecn: Option<EcnCodepoint>,
        packet_number: u64,
        payload: Bytes,
    ) -> Result<(), TransportError> {
        let frame = if let Ok(Some(frame)) = parse_initial(&self.log, payload) {
            frame
        } else {
            return Ok(());
        }; // TODO: Send close?

        trace!(self.log, "got initial");
        self.read_tls(&frame)?;
        let params = TransportParameters::read(
            Side::Server,
            &mut io::Cursor::new(self.tls.get_quic_transport_parameters().unwrap()),
        )?;
        self.set_params(params)?;
        self.on_packet_authenticated(now, ecn, Some(packet_number));
        self.write_tls();
        Ok(())
    }

    fn read_tls(&mut self, crypto: &frame::Crypto) -> Result<(), TransportError> {
        self.crypto_stream.insert(crypto.offset, &crypto.data);
        let mut buf = [0; 8192];
        loop {
            let n = self.crypto_stream.read(&mut buf);
            if n == 0 {
                return Ok(());
            }
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
        let mut outgoing = Vec::new();
        self.tls.write_hs(&mut outgoing);
        let offset = self.crypto_offset;
        self.crypto_offset += outgoing.len() as u64;
        if !outgoing.is_empty() {
            self.crypto_pending.crypto.push_back(frame::Crypto {
                offset,
                data: outgoing.into(),
            });
            self.crypto_in_flight = true;
        }
    }

    pub fn handle_decode(
        &mut self,
        now: u64,
        ecn: Option<EcnCodepoint>,
        partial_decode: PartialDecode,
    ) -> Option<BytesMut> {
        let header_crypto = if partial_decode.is_handshake() {
            self.find_header_crypto(CryptoLevel::Initial).unwrap()
        } else {
            let (level, ref x) = *self.header_cryptos.back().unwrap();
            if level != CryptoLevel::OneRtt {
                warn!(
                    self.log,
                    "received a non-handshake packet before handshake completed"
                );
                return None;
            }
            x
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
        trace!(self.log, "connection got packet"; "len" => packet.payload.len());
        let was_handshake = self.is_handshaking();
        let was_closed = self.state.is_closed();

        let stateless_reset = self.params.stateless_reset_token.map_or(false, |token| {
            packet.payload.len() >= RESET_TOKEN_SIZE
                && packet.payload[packet.payload.len() - RESET_TOKEN_SIZE..] == token
        });

        let result = match self.decrypt_packet(was_handshake, &mut packet) {
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
                let duplicate =
                    number.and_then(|n| if self.dedup.insert(n) { Some(n) } else { None });

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
                    if !was_closed {
                        self.on_packet_authenticated(now, ecn, number);
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
                        self.on_packet_acked(0);

                        // Reset to initial state
                        let client_config = self.client_config.as_ref().unwrap();
                        self.tls = TlsSession::new_client(
                            &client_config.tls_config,
                            &client_config.server_name,
                            &TransportParameters::new(&self.config),
                        )
                        .unwrap();
                        self.crypto_offset = 0;
                        let new_crypto = Crypto::new_initial(&rem_cid, self.side);
                        self.header_cryptos[0].1 = new_crypto.header_crypto();
                        self.cryptos[0].crypto = new_crypto;
                        self.write_tls();

                        self.state = State::Handshake(state::Handshake {
                            token: Some(packet.payload.into()),
                            rem_cid_set: true,
                        });
                        Ok(())
                    }
                    Header::Long {
                        ty: LongType::Handshake,
                        dst_cid: id,
                        src_cid: rem_cid,
                        ..
                    } => {
                        let mut state = state.clone();
                        if !state.rem_cid_set {
                            self.rem_cid = rem_cid;
                            state.rem_cid_set = true;
                        }
                        // Complete handshake (and ultimately send Finished)
                        for frame in frame::Iter::new(packet.payload.into()) {
                            match frame {
                                Frame::Ack(_) | Frame::Padding => {}
                                _ => {
                                    self.permit_ack_only = true;
                                }
                            }
                            match frame {
                                Frame::Padding => {}
                                Frame::Crypto(frame) => {
                                    self.read_tls(&frame)?;
                                }
                                Frame::Stream(frame::Stream { .. }) => {
                                    debug!(self.log, "stream frame in handshake");
                                    return Err(TransportError::PROTOCOL_VIOLATION.into());
                                }
                                Frame::Ack(ack) => {
                                    self.on_ack_received(now, ack);
                                }
                                Frame::ConnectionClose(reason) => {
                                    trace!(
                                        self.log,
                                        "peer aborted the handshake: {error}",
                                        error = reason.error_code
                                    );
                                    self.events.push_back(
                                        ConnectionError::ConnectionClosed { reason }.into(),
                                    );
                                    self.state = State::Draining;
                                    return Ok(());
                                }
                                Frame::ApplicationClose(reason) => {
                                    self.events.push_back(
                                        ConnectionError::ApplicationClosed { reason }.into(),
                                    );
                                    self.state = State::Draining;
                                    return Ok(());
                                }
                                Frame::PathChallenge(value) => {
                                    self.crypto_pending.path_challenge(number.unwrap(), value);
                                }
                                _ => {
                                    debug!(self.log, "unexpected frame type in handshake"; "type" => %frame.ty());
                                    return Err(TransportError::PROTOCOL_VIOLATION.into());
                                }
                            }
                        }

                        if self.tls.is_handshaking() {
                            trace!(self.log, "handshake ongoing");
                            self.handshake_cleanup();
                            self.write_tls();
                            self.state = State::Handshake(state::Handshake {
                                token: None,
                                ..state
                            });
                            return Ok(());
                        }

                        trace!(self.log, "handshake complete");
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
                        trace!(self.log, "{connection} established", connection = id);
                        self.handshake_cleanup();
                        self.write_tls();
                        if self.side.is_server() {
                            self.crypto_in_flight = false;
                        }
                        let crypto = CryptoSpace {
                            level: CryptoLevel::OneRtt,
                            start: 0,
                            crypto: Crypto::new_1rtt(&self.tls, self.side),
                        };
                        self.header_cryptos
                            .push_back((crypto.level, crypto.crypto.header_crypto()));
                        self.cryptos.push_back(crypto);
                        if self.side.is_client() {
                            // Server applications don't see connections until the handshake
                            // completes, so this would be redundant.
                            self.events.push_back(Event::Connected {
                                protocol: self.tls.get_alpn_protocol().map(|x| x.into()),
                            });
                        }
                        self.state = State::Established;
                        Ok(())
                    }
                    Header::Initial { .. } => {
                        if self.side.is_server() {
                            trace!(self.log, "dropping duplicate Initial");
                        } else {
                            trace!(self.log, "dropping Initial for initiated connection");
                        }
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
                if let Header::Long { .. } = packet.header {
                    trace!(self.log, "discarding unprotected packet");
                    return Ok(());
                }

                if self.crypto_in_flight {
                    assert_eq!(
                        self.side,
                        Side::Client,
                        "only the client confirms handshake completion based on a protected packet"
                    );
                    // Forget about unacknowledged handshake packets
                    self.handshake_cleanup();
                }
                let closed = self.process_payload(now, number.unwrap(), packet.payload.into())?;
                self.state = if closed {
                    State::Draining
                } else {
                    State::Established
                };
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

    pub fn issue_cid(&mut self, cid: ConnectionId) {
        let token = reset_token_for(&self.config.reset_key, &cid);
        self.cids_issued += 1;
        self.pending.new_cids.push(frame::NewConnectionId {
            id: cid,
            sequence: self.cids_issued,
            reset_token: token,
        });
        self.loc_cids.insert(self.cids_issued, cid);
    }

    fn process_payload(
        &mut self,
        now: u64,
        number: u64,
        payload: Bytes,
    ) -> Result<bool, TransportError> {
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
                    self.permit_ack_only = true;
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
                    self.read_tls(&frame)?;
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
                    self.on_ack_received(now, ack);
                    for stream in self.streams.finished.drain(..) {
                        self.events.push_back(Event::StreamFinished { stream });
                    }
                }
                Frame::Padding | Frame::Ping => {}
                Frame::ConnectionClose(reason) => {
                    self.events
                        .push_back(ConnectionError::ConnectionClosed { reason }.into());
                    return Ok(true);
                }
                Frame::ApplicationClose(reason) => {
                    self.events
                        .push_back(ConnectionError::ApplicationClosed { reason }.into());
                    return Ok(true);
                }
                Frame::PathChallenge(x) => {
                    self.pending.path_challenge(number, x);
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
        Ok(false)
    }

    fn update_rem_cid(&mut self, new: frame::NewConnectionId) {
        trace!(
            self.log,
            "switching to remote CID {sequence}: {connection_id}",
            sequence = new.sequence,
            connection_id = new.id
        );
        self.pending.retire_cids.push(self.rem_cid_seq);
        self.rem_cid = new.id;
        self.rem_cid_seq = new.sequence;
        self.params.stateless_reset_token = Some(new.reset_token);
    }

    fn next_packet(&mut self, now: u64) -> Option<Box<[u8]>> {
        let established = match self.state {
            State::Handshake(_) => false,
            State::Established => true,
            ref e => {
                assert!(e.is_closed());
                return None;
            }
        };

        let mut buf = Vec::new();
        let mut sent = Retransmits::default();

        let (number, header, crypto, header_crypto, pending, crypto_level) = if (!established
            || self.crypto_in_flight)
            && (!self.crypto_pending.is_empty()
                || (!self.pending_acks.is_empty() && self.permit_ack_only))
        {
            // (re)transmit handshake data in long-header packets
            buf.reserve_exact(self.mtu as usize);
            let number = self.get_tx_number();
            let header = if self.side.is_client()
                && self
                    .crypto_pending
                    .crypto
                    .front()
                    .map_or(false, |x| x.offset == 0)
            {
                trace!(self.log, "sending initial packet"; "pn" => number);
                Header::Initial {
                    src_cid: *self.loc_cids.values().next().unwrap(),
                    dst_cid: self.rem_cid,
                    token: match self.state {
                        State::Handshake(ref state) => {
                            state.token.clone().unwrap_or_else(Bytes::new)
                        }
                        _ => unreachable!("initial only sent in handshake state"),
                    },
                    number: PacketNumber::new(number, self.largest_acked_packet),
                }
            } else {
                trace!(self.log, "sending handshake packet"; "pn" => number);
                Header::Long {
                    ty: LongType::Handshake,
                    src_cid: *self.loc_cids.values().next().unwrap(),
                    dst_cid: self.rem_cid,
                    number: PacketNumber::new(number, self.largest_acked_packet),
                }
            };
            (
                number,
                header,
                &self.cryptos.front().unwrap().crypto,
                &self.header_cryptos.front().unwrap().1,
                &mut self.crypto_pending,
                CryptoLevel::Initial,
            )
        } else if established {
            //|| (self.zero_rtt_crypto.is_some() && self.side.is_client()) {
            // Send 0RTT or 1RTT data
            if self.congestion_blocked()
                || self.pending.is_empty()
                    && (!self.permit_ack_only || self.pending_acks.is_empty())
            {
                return None;
            }
            let number = self.get_tx_number();
            buf.reserve_exact(self.mtu as usize);
            trace!(self.log, "sending protected packet"; "pn" => number);

            /*if !established {
                crypto = self.zero_rtt_crypto.as_ref().unwrap();
                Header::Long {
                    ty: types::ZERO_RTT,
                    number: number as u32,
                    src_cid: self.loc_cid.clone(),
                    dst_cid: self.init_cid.clone(),
                }.encode(&mut buf);
            } else {*/
            let header = Header::Short {
                dst_cid: self.rem_cid,
                number: PacketNumber::new(number, self.largest_acked_packet),
                key_phase: self.key_phase,
            };
            //}
            (
                number,
                header,
                &self.cryptos.back().unwrap().crypto,
                &self.header_cryptos.back().unwrap().1,
                &mut self.pending,
                CryptoLevel::OneRtt,
            )
        } else {
            return None;
        };

        let partial_encode = header.encode(&mut buf);
        let ack_only = pending.is_empty();
        let header_len = buf.len();
        let max_size = self.mtu as usize - AEAD_TAG_SIZE;

        // PING
        if pending.ping {
            trace!(self.log, "ping");
            pending.ping = false;
            buf.write(frame::Type::PING);
        }

        // ACK
        // We will never ack protected packets in handshake packets because handshake_cleanup
        // ensures we never send handshake packets after receiving protected packets.
        // 0-RTT packets must never carry acks (which would have to be of handshake packets)
        let acks = if !self.pending_acks.is_empty() {
            //&& !crypto.is_0rtt() {
            let delay = (now - self.rx_packet_time) >> ACK_DELAY_EXPONENT;
            trace!(self.log, "ACK"; "ranges" => ?self.pending_acks.iter().collect::<Vec<_>>(), "delay" => delay);
            let ecn = if self.receiving_ecn {
                Some(&self.ecn_counters)
            } else {
                None
            };
            frame::Ack::encode(delay, &self.pending_acks, ecn, &mut buf);
            self.pending_acks.clone()
        } else {
            RangeSet::new()
        };

        // PATH_RESPONSE
        if buf.len() + 9 < max_size {
            // No need to retransmit these, so we don't save the value after encoding it.
            if let Some((_, x)) = pending.path_response.take() {
                trace!(self.log, "PATH_RESPONSE"; "value" => format!("{:08x}", x));
                buf.write(frame::Type::PATH_RESPONSE);
                buf.write(x);
            }
        }

        // CRYPTO
        while buf.len() + frame::Crypto::SIZE_BOUND < max_size {
            let mut frame = if let Some(x) = pending.crypto.pop_front() {
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
            truncated.encode(&mut buf);
            sent.crypto.push_back(truncated);
            if !frame.data.is_empty() {
                frame.offset += len as u64;
                pending.crypto.push_front(frame);
            }
        }

        // RESET_STREAM
        while buf.len() + frame::ResetStream::SIZE_BOUND < max_size {
            let (id, error_code) = if let Some(x) = pending.rst_stream.pop() {
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
            .encode(&mut buf);
        }

        // STOP_SENDING
        while buf.len() + 11 < max_size {
            let (id, error_code) = if let Some(x) = pending.stop_sending.pop() {
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
        if pending.max_data && buf.len() + 9 < max_size {
            trace!(self.log, "MAX_DATA"; "value" => self.local_max_data);
            pending.max_data = false;
            sent.max_data = true;
            buf.write(frame::Type::MAX_DATA);
            buf.write_var(self.local_max_data);
        }

        // MAX_STREAM_DATA
        while buf.len() + 17 < max_size {
            let id = if let Some(x) = pending.max_stream_data.iter().next() {
                *x
            } else {
                break;
            };
            pending.max_stream_data.remove(&id);
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
        if pending.max_uni_stream_id && buf.len() + 9 < max_size {
            pending.max_uni_stream_id = false;
            sent.max_uni_stream_id = true;
            trace!(self.log, "MAX_STREAMS (unidirectional)"; "value" => self.streams.max_remote_uni);
            buf.write(frame::Type::MAX_STREAMS_UNI);
            buf.write_var(self.streams.max_remote_uni);
        }

        // MAX_STREAMS_BIDI
        if pending.max_bi_stream_id && buf.len() + 9 < max_size {
            pending.max_bi_stream_id = false;
            sent.max_bi_stream_id = true;
            trace!(self.log, "MAX_STREAMS (bidirectional)"; "value" => self.streams.max_remote_bi - 1);
            buf.write(frame::Type::MAX_STREAMS_BIDI);
            buf.write_var(self.streams.max_remote_bi);
        }

        // NEW_CONNECTION_ID
        while buf.len() + 44 < max_size {
            let frame = if let Some(x) = pending.new_cids.pop() {
                x
            } else {
                break;
            };
            trace!(
                self.log,
                "NEW_CONNECTION_ID {sequence}",
                sequence = frame.sequence
            );
            frame.encode(&mut buf);
            sent.new_cids.push(frame);
        }

        // RETIRE_CONNECTION_ID
        while buf.len() + frame::RETIRE_CONNECTION_ID_SIZE_BOUND < max_size {
            let seq = if let Some(x) = pending.retire_cids.pop() {
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
        while buf.len() + frame::Stream::<Bytes>::SIZE_BOUND < max_size {
            let mut stream = if let Some(x) = pending.stream.pop_front() {
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
                max_size as usize - buf.len() - frame::Stream::<Bytes>::SIZE_BOUND,
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
            frame.encode(true, &mut buf);
            sent.stream.push_back(frame);
            if !stream.data.is_empty() {
                stream.offset += len as u64;
                pending.stream.push_front(stream);
            }
        }

        let mut padded = false;
        if let Header::Initial { .. } = header {
            if buf.len() < MIN_INITIAL_SIZE - AEAD_TAG_SIZE {
                buf.resize(MIN_INITIAL_SIZE - AEAD_TAG_SIZE, 0);
                padded = true;
            }
        }
        let pn_len = header
            .number()
            .expect("next_packet should only send numbered packets")
            .len();
        // To ensure that sufficient data is available for sampling, packets are padded so that the
        // combined lengths of the encoded packet number and protected payload is at least 4 bytes
        // longer than the sample required for header protection.
        if let Some(padding) =
            (header_crypto.sample_size() + 4).checked_sub(buf.len() - header_len + pn_len)
        {
            padded |= padding != 0;
            buf.resize(buf.len() + padding, 0);
        }
        if crypto_level != CryptoLevel::OneRtt {
            set_payload_length(&mut buf, header_len, pn_len);
        }
        crypto.encrypt(number, &mut buf, header_len);
        partial_encode.finish(&mut buf, header_crypto, header_len);

        // If we sent any acks, don't immediately resend them. Setting this even if ack_only is
        // false needlessly prevents us from ACKing the next packet if it's ACK-only, but saves
        // the need for subtler logic to avoid double-transmitting acks all the time.
        self.permit_ack_only &= acks.is_empty();

        self.on_packet_sent(
            now,
            number,
            SentPacket {
                acks,
                time_sent: now,
                size: buf.len() as u16,
                is_crypto_packet: crypto_level == CryptoLevel::Initial && !ack_only,
                ack_eliciting: !ack_only,
                in_flight: padded || !ack_only,
                retransmits: sent,
            },
        );

        Some(buf.into())
    }

    /// Construct a packet when there's nothing to transmit
    ///
    /// Useful for tail loss and RTO probes
    fn make_probe(&mut self, now: u64) -> Box<[u8]> {
        let number = self.get_tx_number();
        let mut buf = Vec::new();
        let header = Header::Short {
            dst_cid: self.rem_cid,
            number: PacketNumber::new(number, self.largest_acked_packet),
            key_phase: self.key_phase,
        };
        let partial_encode = header.encode(&mut buf);
        let header_len = buf.len() as u16;
        buf.write(frame::Type::PING);

        let crypto = &self.cryptos.back().unwrap().crypto;
        crypto.encrypt(number, &mut buf, header_len as usize);
        partial_encode.finish(
            &mut buf,
            &self.header_cryptos.back().unwrap().1,
            header_len as usize,
        );

        self.on_packet_sent(
            now,
            number,
            SentPacket {
                time_sent: now,
                size: buf.len() as u16,
                is_crypto_packet: false,
                ack_eliciting: true,
                in_flight: true,
                acks: RangeSet::new(),
                retransmits: Retransmits::default(),
            },
        );
        buf.into()
    }

    fn make_close(&mut self) -> Box<[u8]> {
        trace!(self.log, "sending CONNECTION_CLOSE");
        let full_number = self.get_tx_number();
        let number = PacketNumber::new(full_number, self.largest_acked_packet);
        let mut buf = Vec::new();
        let crypto_space = self.cryptos.back().unwrap();
        let header = match crypto_space.level {
            CryptoLevel::OneRtt => Header::Short {
                dst_cid: self.rem_cid,
                number,
                key_phase: self.key_phase,
            },
            CryptoLevel::Initial => Header::Long {
                ty: LongType::Handshake,
                dst_cid: self.rem_cid,
                src_cid: *self.loc_cids.values().next().unwrap(),
                number,
            },
        };
        let partial_encode = header.encode(&mut buf);
        let header_len = buf.len();

        let max_len = self.mtu as usize - header_len - AEAD_TAG_SIZE;
        match self.state {
            State::Closed(state::Closed {
                reason: state::CloseReason::Application(ref x),
            }) => x.encode(&mut buf, max_len),
            State::Closed(state::Closed {
                reason: state::CloseReason::Connection(ref x),
            }) => x.encode(&mut buf, max_len),
            _ => unreachable!("tried to make a close packet when the connection wasn't closed"),
        }

        if let Header::Long { .. } = header {
            set_payload_length(&mut buf, header_len as usize, number.len());
        }

        crypto_space
            .crypto
            .encrypt(full_number, &mut buf, header_len as usize);
        partial_encode.finish(
            &mut buf,
            &self.header_cryptos.back().unwrap().1,
            header_len as usize,
        );
        buf.into()
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
        self.pending.ping = true;
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
                        Some(match id.directionality() {
                            Directionality::Uni => {
                                self.streams.max_remote_uni += 1;
                                self.pending.max_uni_stream_id = true;
                                (
                                    StreamId::new(
                                        !self.side,
                                        Directionality::Uni,
                                        self.streams.max_remote_uni - 1,
                                    ),
                                    stream::Recv::new(u64::from(self.config.stream_receive_window))
                                        .into(),
                                )
                            }
                            Directionality::Bi => {
                                self.streams.max_remote_bi += 1;
                                self.pending.max_bi_stream_id = true;
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
        for frame in &mut self.pending.stream {
            if frame.id == id && frame.offset + frame.data.len() as u64 == ss.offset {
                frame.fin = true;
                return;
            }
        }
        self.pending.stream.push_back(frame::Stream {
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
        self.pending.max_data = true;
        if rs.receiving_unknown_size() {
            self.pending.max_stream_data.insert(id);
        }
        Ok((buf, len))
    }

    pub fn read(&mut self, id: StreamId, buf: &mut [u8]) -> Result<usize, ReadError> {
        let rs = self.streams.get_recv_mut(id).unwrap();
        let len = rs.read(buf)?;
        // TODO: Reduce granularity of flow control credit, while still avoiding stalls, to
        // reduce overhead
        self.local_max_data += len as u64;
        self.pending.max_data = true;
        if rs.receiving_unknown_size() {
            self.pending.max_stream_data.insert(id);
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
            self.pending.stop_sending.push((id, error_code));
        }
    }

    fn congestion_blocked(&self) -> bool {
        self.congestion_window.saturating_sub(self.bytes_in_flight) < self.mtu as u64
    }

    fn blocked(&self) -> bool {
        self.data_sent >= self.max_data || self.congestion_blocked()
    }

    fn decrypt_packet(
        &mut self,
        handshake: bool,
        packet: &mut Packet,
    ) -> Result<Option<u64>, Option<TransportError>> {
        if packet.header.is_retry() {
            // Retry packets are not encrypted and have no packet number
            return Ok(None);
        }
        let (level, number, key_phase) = match packet.header {
            Header::Short {
                number, key_phase, ..
            } if !handshake => (CryptoLevel::OneRtt, number, key_phase),
            Header::Initial { number, .. } | Header::Long { number, .. } if handshake => {
                (CryptoLevel::Initial, number, false)
            }
            _ => {
                return Err(None);
            }
        };
        let number = number.expand(self.rx_packet + 1);

        let mut crypto_update = None;
        let crypto = if key_phase == self.key_phase {
            self.find_crypto(level, number).unwrap()
        } else {
            assert_eq!(level, CryptoLevel::OneRtt);
            crypto_update = Some(self.find_crypto(level, number).unwrap().update());
            crypto_update.as_ref().unwrap()
        };

        crypto
            .decrypt(number, &packet.header_data, &mut packet.payload)
            .map_err(|()| None)?;

        let reserved = match packet.header {
            Header::Short { .. } => SHORT_RESERVED_BITS,
            _ => LONG_RESERVED_BITS,
        };
        if packet.header_data[0] & reserved != 0 {
            debug!(self.log, "peer set reserved bits");
            return Err(Some(TransportError::PROTOCOL_VIOLATION));
        }

        if let Some(crypto) = crypto_update {
            if number <= self.rx_packet {
                warn!(self.log, "recieved an illegal key update");
                return Err(Some(TransportError::PROTOCOL_VIOLATION));
            }
            trace!(self.log, "key update authenticated");
            self.update_keys(crypto, number);
        }

        Ok(Some(number))
    }

    #[cfg(test)]
    pub fn initiate_key_update(&mut self) {
        self.update_keys(
            self.cryptos.back().unwrap().crypto.update(),
            self.next_packet_number,
        );
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

    fn update_keys(&mut self, crypto: Crypto, number: u64) {
        // Remove the penultimate crypto space if it's at the OneRtt level; do this before
        // adding the new crypto to save on allocation space for the cryptos deque.
        let len = self.cryptos.len();
        if len > 2
            && self
                .cryptos
                .get(len - 2)
                .map_or(false, |cs| cs.level == CryptoLevel::OneRtt)
        {
            self.cryptos.remove(len - 2);
        }
        self.cryptos.push_back(CryptoSpace {
            level: CryptoLevel::OneRtt,
            start: number,
            crypto,
        });
        self.key_phase = !self.key_phase;
    }

    fn find_crypto(&self, level: CryptoLevel, number: u64) -> Option<&Crypto> {
        self.cryptos.iter().rev().find_map(|space| {
            if space.level == level && space.start <= number {
                Some(&space.crypto)
            } else {
                None
            }
        })
    }

    fn find_header_crypto(&self, level: CryptoLevel) -> Option<&HeaderCrypto> {
        self.header_cryptos
            .iter()
            .rev()
            .find_map(|x| if x.0 == level { Some(&x.1) } else { None })
    }

    pub fn is_handshaking(&self) -> bool {
        self.state.is_handshake()
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

    pub fn remote(&self) -> SocketAddrV6 {
        self.remote
    }

    pub fn protocol(&self) -> Option<&[u8]> {
        self.tls.get_alpn_protocol().map(|p| p.as_bytes())
    }

    /// The number of bytes of packets containing retransmittable frames that have not been
    /// acknowledged or declared lost.
    pub fn bytes_in_flight(&self) -> u64 {
        self.bytes_in_flight
    }

    /// Number of bytes worth of non-ack-only packets that may be sent
    pub fn congestion_state(&self) -> u64 {
        self.congestion_window.saturating_sub(self.bytes_in_flight)
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
}

struct CryptoSpace {
    level: CryptoLevel,
    start: u64,
    crypto: Crypto,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CryptoLevel {
    Initial,
    OneRtt,
}

/// Extract crypto data from the first Initial packet
fn parse_initial(log: &Logger, payload: Bytes) -> Result<Option<frame::Crypto>, ()> {
    let mut result = None;
    for frame in frame::Iter::new(payload) {
        match frame {
            Frame::Padding => {}
            Frame::Ack(_) => {}
            Frame::ConnectionClose(_) => {}
            Frame::Crypto(x) => {
                if x.offset != 0 {
                    debug!(log, "nonzero offset in first crypto frame"; "offset" => x.offset);
                    return Err(());
                }
                result = Some(x);
            }
            x => {
                debug!(log, "unexpected frame in initial/retry packet"; "ty" => %x.ty());
                return Err(());
            } // Invalid packet
        }
    }
    Ok(result)
}

pub fn handshake_close<R>(
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
    let header = Header::Long {
        ty: LongType::Handshake,
        dst_cid: *remote_id,
        src_cid: *local_id,
        number,
    };

    let mut buf = Vec::<u8>::new();
    let partial_encode = header.encode(&mut buf);
    let header_len = buf.len();
    let max_len = MIN_MTU as usize - header_len - AEAD_TAG_SIZE;
    match reason.into() {
        state::CloseReason::Application(ref x) => x.encode(&mut buf, max_len),
        state::CloseReason::Connection(ref x) => x.encode(&mut buf, max_len),
    }
    set_payload_length(&mut buf, header_len, number.len());
    crypto.encrypt(packet_number as u64, &mut buf, header_len);
    partial_encode.finish(&mut buf, header_crypto, header_len);
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
pub struct Retransmits {
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

    pub fn path_challenge(&mut self, packet: u64, token: u64) {
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
    fn add_assign(&mut self, rhs: Self) {
        self.max_data |= rhs.max_data;
        self.ping |= rhs.ping;
        self.max_uni_stream_id |= rhs.max_uni_stream_id;
        self.max_bi_stream_id |= rhs.max_bi_stream_id;
        self.stream.extend(rhs.stream.into_iter());
        if let Some((packet, token)) = rhs.path_response {
            self.path_challenge(packet, token);
        }
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

pub mod state {
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
    impl From<AlertDescription> for CloseReason {
        fn from(x: AlertDescription) -> Self {
            TransportError::crypto(x).into()
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
pub struct SentPacket {
    /// The time the packet was sent.
    pub time_sent: u64,
    /// The number of bytes sent in the packet, not including UDP or IP overhead, but including QUIC
    /// framing overhead.
    pub size: u16,
    /// Whether an acknowledgement is expected directly in response to this packet.
    pub ack_eliciting: bool,
    /// Whether the packet contains cryptographic handshake messages critical to the completion of
    /// the QUIC handshake.
    pub is_crypto_packet: bool,
    /// Whether the packet counts towards bytes in flight
    pub in_flight: bool,
    pub acks: RangeSet,
    pub retransmits: Retransmits,
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
        destination: SocketAddrV6,
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
pub struct IoQueue {
    /// Number of probe packets to transmit
    probes: u8,
    /// Whether to transmit a close packet
    close: bool,
    /// Changes to the loss detection, idle, and close timers, in that order
    ///
    /// Note that this ordering exactly matches the values of the `Timer` enum for convenient
    /// indexing.
    timers: [Option<TimerUpdate>; 3],
    retired_cids: Vec<ConnectionId>,
}

impl IoQueue {
    pub fn new() -> Self {
        Self {
            probes: 0,
            close: false,
            timers: [None; 3],
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
