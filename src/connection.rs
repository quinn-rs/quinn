use std::collections::{hash_map, BTreeMap, VecDeque};
use std::net::SocketAddrV6;
use std::{cmp, fmt, io, mem};

use arrayvec::ArrayVec;
use bytes::{Buf, Bytes};
use fnv::{FnvHashMap, FnvHashSet};
use openssl;
use openssl::ssl::{
    self, HandshakeError, MidHandshakeSslStream, Ssl, SslSession, SslStream, SslStreamBuilder,
};
use openssl::x509::verify::X509CheckFlags;
use rand::Rng;
use slog::{self, Logger};

use coding::{BufExt, BufMutExt};
use crypto::{
    ConnectionInfo, Crypto, CryptoContext, ZeroRttCrypto, ACK_DELAY_EXPONENT, AEAD_TAG_SIZE,
    CONNECTION_INFO_INDEX, TLS_MAX_EARLY_DATA,
};
use endpoint::{
    packet, set_payload_length, ClientConfig, Config, Context, Header, Packet, PacketNumber,
    MAX_ACK_BLOCKS, MIN_INITIAL_SIZE, MIN_MTU,
};
use memory_stream::MemoryStream;
use range_set::RangeSet;
use stream::{self, Stream};
use transport_parameters::TransportParameters;
use {frame, Directionality, Side, StreamId, TransportError, MAX_CID_SIZE};

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct ConnectionHandle(pub usize);

impl From<ConnectionHandle> for usize {
    fn from(x: ConnectionHandle) -> usize {
        x.0
    }
}

/// Protocol-level identifier for a connection.
///
/// Mainly useful for identifying this connection's packets on the wire with tools like Wireshark.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ConnectionId(pub(crate) ArrayVec<[u8; MAX_CID_SIZE]>);

impl ::std::ops::Deref for ConnectionId {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl ::std::ops::DerefMut for ConnectionId {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl ConnectionId {
    pub fn new(data: [u8; MAX_CID_SIZE], len: usize) -> Self {
        let mut x = ConnectionId(data.into());
        x.0.truncate(len);
        x
    }

    pub fn random<R: Rng>(rng: &mut R, len: u8) -> Self {
        debug_assert!(len as usize <= MAX_CID_SIZE);
        let mut v = ArrayVec::from([0; MAX_CID_SIZE]);
        rng.fill_bytes(&mut v[0..len as usize]);
        v.truncate(len as usize);
        ConnectionId(v)
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl slog::Value for ConnectionId {
    fn serialize(
        &self,
        _: &slog::Record,
        key: slog::Key,
        serializer: &mut slog::Serializer,
    ) -> slog::Result {
        serializer.emit_arguments(key, &format_args!("{}", self))
    }
}

pub struct Connection {
    /// DCID of Initial packet
    pub initial_id: ConnectionId,
    pub local_id: ConnectionId,
    pub remote_id: ConnectionId,
    pub remote: SocketAddrV6,
    pub state: Option<State>,
    pub side: Side,
    pub mtu: u16,
    pub rx_packet: u64,
    pub rx_packet_time: u64,
    pub crypto: Option<CryptoContext>,
    pub prev_crypto: Option<(u64, CryptoContext)>,
    pub zero_rtt_crypto: Option<ZeroRttCrypto>,
    pub key_phase: bool,
    pub params: TransportParameters,
    /// Streams with data buffered for reading by the application
    pub readable_streams: FnvHashSet<StreamId>,
    /// Streams on which writing was blocked on *connection-level* flow or congestion control
    pub blocked_streams: FnvHashSet<StreamId>,
    /// Limit on outgoing data, dictated by peer
    pub max_data: u64,
    pub data_sent: u64,
    /// Sum of end offsets of all streams. Includes gaps, so it's an upper bound.
    pub data_recvd: u64,
    /// Limit on incoming data
    pub local_max_data: u64,

    //
    // Loss Detection
    //
    /// The number of times the handshake packets have been retransmitted without receiving an ack.
    pub handshake_count: u32,
    /// The number of times a tail loss probe has been sent without receiving an ack.
    pub tlp_count: u32,
    /// The number of times an rto has been sent without receiving an ack.
    pub rto_count: u32,
    /// The largest packet number gap between the largest acked retransmittable packet and an unacknowledged
    /// retransmittable packet before it is declared lost.
    pub reordering_threshold: u32,
    /// The time at which the next packet will be considered lost based on early transmit or exceeding the reordering
    /// window in time.
    pub loss_time: u64,
    /// The most recent RTT measurement made when receiving an ack for a previously unacked packet. μs
    pub latest_rtt: u64,
    /// The smoothed RTT of the connection, computed as described in RFC6298. μs
    pub smoothed_rtt: u64,
    /// The RTT variance, computed as described in RFC6298
    pub rttvar: u64,
    /// The minimum RTT seen in the connection, ignoring ack delay.
    pub min_rtt: u64,
    /// The maximum ack delay in an incoming ACK frame for this connection.
    ///
    /// Excludes ack delays for ack only packets and those that create an RTT sample less than min_rtt.
    pub max_ack_delay: u64,
    /// The last packet number sent prior to the first retransmission timeout.
    pub largest_sent_before_rto: u64,
    /// The time the most recently sent retransmittable packet was sent.
    pub time_of_last_sent_retransmittable_packet: u64,
    /// The time the most recently sent handshake packet was sent.
    pub time_of_last_sent_handshake_packet: u64,
    /// The packet number of the most recently sent packet.
    pub largest_sent_packet: u64,
    /// The largest packet number the remote peer acknowledged in an ACK frame.
    pub largest_acked_packet: u64,
    /// Transmitted but not acked
    pub sent_packets: BTreeMap<u64, SentPacket>,

    //
    // Congestion Control
    //
    /// The sum of the size in bytes of all sent packets that contain at least one retransmittable frame, and have not
    /// been acked or declared lost.
    ///
    /// The size does not include IP or UDP overhead. Packets only containing ACK frames do not count towards
    /// bytes_in_flight to ensure congestion control does not impede congestion feedback.
    pub bytes_in_flight: u64,
    /// Maximum number of bytes in flight that may be sent.
    pub congestion_window: u64,
    /// The largest packet number sent when QUIC detects a loss. When a larger packet is acknowledged, QUIC exits recovery.
    pub end_of_recovery: u64,
    /// Slow start threshold in bytes. When the congestion window is below ssthresh, the mode is slow start and the
    /// window grows by the number of bytes acknowledged.
    pub ssthresh: u64,

    //
    // Handshake retransmit state
    //
    /// Whether we've sent handshake packets that have not been either explicitly acknowledged or rendered moot by
    /// handshake completion, i.e. whether we're waiting for proof that the peer has advanced their handshake state
    /// machine.
    pub awaiting_handshake: bool,
    pub handshake_pending: Retransmits,
    pub handshake_crypto: CryptoContext,

    //
    // Transmit queue
    //
    pub pending: Retransmits,
    pub pending_acks: RangeSet,
    /// Set iff we have received a non-ack frame since the last ack-only packet we sent
    pub permit_ack_only: bool,

    // Timer updates: None if no change, Some(None) to stop, Some(Some(_)) to reset
    pub set_idle: Option<Option<u64>>,
    pub set_loss_detection: Option<Option<u64>>,

    //
    // Stream states
    //
    pub streams: FnvHashMap<StreamId, Stream>,
    pub next_uni_stream: u64,
    pub next_bi_stream: u64,
    // Locally initiated
    pub max_uni_streams: u64,
    pub max_bi_streams: u64,
    // Remotely initiated
    pub max_remote_uni_streams: u64,
    pub max_remote_bi_streams: u64,
    pub finished_streams: Vec<StreamId>,
}

/// Represents one or more packets subject to retransmission
#[derive(Debug, Clone)]
pub struct SentPacket {
    pub time: u64,
    /// 0 iff ack-only
    pub bytes: u16,
    pub handshake: bool,
    pub acks: RangeSet,
    pub retransmits: Retransmits,
}

impl SentPacket {
    fn ack_only(&self) -> bool {
        self.bytes == 0
    }
}

#[derive(Debug, Clone)]
pub struct Retransmits {
    pub max_data: bool,
    pub max_uni_stream_id: bool,
    pub max_bi_stream_id: bool,
    pub ping: bool,
    pub new_connection_id: Option<ConnectionId>,
    pub stream: VecDeque<frame::Stream>,
    /// packet number, token
    pub path_response: Option<(u64, u64)>,
    pub rst_stream: Vec<(StreamId, u16)>,
    pub stop_sending: Vec<(StreamId, u16)>,
    pub max_stream_data: FnvHashSet<StreamId>,
}

impl Retransmits {
    fn is_empty(&self) -> bool {
        !self.max_data
            && !self.max_uni_stream_id
            && !self.max_bi_stream_id
            && !self.ping
            && self.new_connection_id.is_none()
            && self.stream.is_empty()
            && self.path_response.is_none()
            && self.rst_stream.is_empty()
            && self.stop_sending.is_empty()
            && self.max_stream_data.is_empty()
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
            new_connection_id: None,
            stream: VecDeque::new(),
            path_response: None,
            rst_stream: Vec::new(),
            stop_sending: Vec::new(),
            max_stream_data: FnvHashSet::default(),
        }
    }
}

impl ::std::ops::AddAssign for Retransmits {
    fn add_assign(&mut self, rhs: Self) {
        self.max_data |= rhs.max_data;
        self.ping |= rhs.ping;
        self.max_uni_stream_id |= rhs.max_uni_stream_id;
        self.max_bi_stream_id |= rhs.max_bi_stream_id;
        if let Some(x) = rhs.new_connection_id {
            self.new_connection_id = Some(x);
        }
        self.stream.extend(rhs.stream.into_iter());
        if let Some((packet, token)) = rhs.path_response {
            self.path_challenge(packet, token);
        }
        self.rst_stream.extend_from_slice(&rhs.rst_stream);
        self.stop_sending.extend_from_slice(&rhs.stop_sending);
        self.max_stream_data.extend(&rhs.max_stream_data);
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

impl Connection {
    pub fn new(
        initial_id: ConnectionId,
        local_id: ConnectionId,
        remote_id: ConnectionId,
        remote: SocketAddrV6,
        initial_packet_number: u64,
        side: Side,
        config: &Config,
    ) -> Self {
        let handshake_crypto = CryptoContext::handshake(&initial_id, side);
        let mut streams = FnvHashMap::default();
        for i in 0..config.max_remote_uni_streams {
            streams.insert(
                StreamId::new(!side, Directionality::Uni, i as u64),
                stream::Recv::new(config.stream_receive_window as u64).into(),
            );
        }
        streams.insert(
            StreamId(0),
            Stream::new_bi(config.stream_receive_window as u64),
        );
        let max_remote_bi_streams = config.max_remote_bi_streams as u64 + match side {
            Side::Server => 1,
            _ => 0,
        };
        for i in match side {
            Side::Server => 1,
            _ => 0,
        }..max_remote_bi_streams
        {
            streams.insert(
                StreamId::new(!side, Directionality::Bi, i as u64),
                Stream::new_bi(config.stream_receive_window as u64),
            );
        }
        Self {
            initial_id,
            local_id,
            remote_id,
            remote,
            side,
            state: None,
            mtu: MIN_MTU,
            rx_packet: 0,
            rx_packet_time: 0,
            crypto: None,
            prev_crypto: None,
            zero_rtt_crypto: None,
            key_phase: false,
            params: TransportParameters::default(),
            readable_streams: FnvHashSet::default(),
            blocked_streams: FnvHashSet::default(),
            max_data: 0,
            data_sent: 0,
            data_recvd: 0,
            local_max_data: config.receive_window as u64,

            handshake_count: 0,
            tlp_count: 0,
            rto_count: 0,
            reordering_threshold: if config.using_time_loss_detection {
                u32::max_value()
            } else {
                config.reordering_threshold
            },
            loss_time: 0,
            latest_rtt: 0,
            smoothed_rtt: 0,
            rttvar: 0,
            min_rtt: u64::max_value(),
            max_ack_delay: 0,
            largest_sent_before_rto: 0,
            time_of_last_sent_retransmittable_packet: 0,
            time_of_last_sent_handshake_packet: 0,
            largest_sent_packet: initial_packet_number.overflowing_sub(1).0,
            largest_acked_packet: 0,
            sent_packets: BTreeMap::new(),

            bytes_in_flight: 0,
            congestion_window: config.initial_window,
            end_of_recovery: 0,
            ssthresh: u64::max_value(),

            awaiting_handshake: false,
            handshake_pending: Retransmits::default(),
            handshake_crypto,

            pending: Retransmits::default(),
            pending_acks: RangeSet::new(),
            permit_ack_only: false,

            set_idle: None,
            set_loss_detection: None,

            streams,
            next_uni_stream: 0,
            next_bi_stream: match side {
                Side::Client => 1,
                Side::Server => 0,
            },
            max_uni_streams: 0,
            max_bi_streams: 0,
            max_remote_uni_streams: config.max_remote_uni_streams as u64,
            max_remote_bi_streams,
            finished_streams: Vec::new(),
        }
    }

    /// Initiate a connection
    pub fn connect(&mut self, ctx: &Context, config: ClientConfig) -> Result<(), ConnectError> {
        let mut tls = Ssl::new(&ctx.tls)?;
        if !config.accept_insecure_certs {
            tls.set_verify_callback(ssl::SslVerifyMode::PEER, |x, _| x);
            let param = tls.param_mut();
            if let Some(name) = config.server_name {
                param.set_hostflags(X509CheckFlags::NO_PARTIAL_WILDCARDS);
                match name.parse() {
                    Ok(ip) => {
                        param.set_ip(ip).expect("failed to inform TLS of remote ip");
                    }
                    Err(_) => {
                        param
                            .set_host(name)
                            .expect("failed to inform TLS of remote hostname");
                    }
                }
            }
        } else {
            tls.set_verify(ssl::SslVerifyMode::NONE);
        }
        tls.set_ex_data(
            *CONNECTION_INFO_INDEX,
            ConnectionInfo {
                id: self.local_id.clone(),
                remote: self.remote,
            },
        );
        if let Some(name) = config.server_name {
            tls.set_hostname(name)?;
        }
        let result = if let Some(session) = config.session_ticket {
            if session.len() < 2 {
                return Err(ConnectError::MalformedSession);
            }
            let mut buf = io::Cursor::new(session);
            let len = buf
                .get::<u16>()
                .map_err(|_| ConnectError::MalformedSession)? as usize;
            if buf.remaining() < len {
                return Err(ConnectError::MalformedSession);
            }
            let session = SslSession::from_der(&buf.bytes()[0..len])
                .map_err(|_| ConnectError::MalformedSession)?;
            buf.advance(len);
            let params = TransportParameters::read(Side::Client, &mut buf)
                .map_err(|_| ConnectError::MalformedSession)?;
            self.set_params(params);
            unsafe { tls.set_session(&session) }?;
            let mut tls = SslStreamBuilder::new(tls, MemoryStream::new());
            tls.set_connect_state();
            if session.max_early_data() == TLS_MAX_EARLY_DATA {
                trace!(
                    ctx.log,
                    "{connection} enabling 0rtt",
                    connection = self.local_id.clone()
                );
                tls.write_early_data(&[])?; // Prompt OpenSSL to generate early keying material, read below
                self.zero_rtt_crypto = Some(ZeroRttCrypto::new(tls.ssl()));
            }
            tls.handshake()
        } else {
            tls.connect(MemoryStream::new())
        };
        let mut tls = match result {
            Ok(_) => unreachable!(),
            Err(HandshakeError::WouldBlock(tls)) => tls,
            Err(e) => panic!("unexpected TLS error: {}", e),
        };
        self.transmit_handshake(&tls.get_mut().take_outgoing());
        self.state = Some(State::Handshake(state::Handshake {
            tls,
            clienthello_packet: None,
            remote_id_set: false,
        }));
        Ok(())
    }

    pub fn get_tx_number(&mut self) -> u64 {
        self.largest_sent_packet = self.largest_sent_packet.overflowing_add(1).0;
        // TODO: Handle packet number overflow gracefully
        assert!(self.largest_sent_packet <= 2u64.pow(62) - 1);
        self.largest_sent_packet
    }

    pub fn on_packet_sent(
        &mut self,
        config: &Config,
        now: u64,
        packet_number: u64,
        packet: SentPacket,
    ) {
        self.largest_sent_packet = packet_number;
        let bytes = packet.bytes;
        let handshake = packet.handshake;
        if handshake {
            self.awaiting_handshake = true;
        }
        self.sent_packets.insert(packet_number, packet);
        if bytes != 0 {
            self.time_of_last_sent_retransmittable_packet = now;
            if handshake {
                self.time_of_last_sent_handshake_packet = now;
            }
            self.bytes_in_flight += bytes as u64;
            self.set_loss_detection_alarm(config);
        }
    }

    /// Updates set_loss_detection
    pub fn on_ack_received(&mut self, config: &Config, now: u64, ack: frame::Ack) {
        self.largest_acked_packet = cmp::max(self.largest_acked_packet, ack.largest); // TODO: Validate
        if let Some(info) = self.sent_packets.get(&ack.largest).cloned() {
            self.latest_rtt = now - info.time;
            let delay = ack.delay << self.params.ack_delay_exponent;
            self.update_rtt(delay, info.ack_only());
        }
        for range in &ack {
            // Avoid DoS from unreasonably huge ack ranges
            let packets = self
                .sent_packets
                .range(range)
                .map(|(&n, _)| n)
                .collect::<Vec<_>>();
            for packet in packets {
                self.on_packet_acked(config, packet);
            }
        }
        self.detect_lost_packets(config, now, ack.largest);
        self.set_loss_detection_alarm(config);
    }

    pub fn update_rtt(&mut self, ack_delay: u64, ack_only: bool) {
        self.min_rtt = cmp::min(self.min_rtt, self.latest_rtt);
        if self.latest_rtt - self.min_rtt > ack_delay {
            self.latest_rtt -= ack_delay;
            if !ack_only {
                self.max_ack_delay = cmp::max(self.max_ack_delay, ack_delay);
            }
        }
        if self.smoothed_rtt == 0 {
            self.smoothed_rtt = self.latest_rtt;
            self.rttvar = self.latest_rtt / 2;
        } else {
            let rttvar_sample = (self.smoothed_rtt as i64 - self.latest_rtt as i64).abs() as u64;
            self.rttvar = (3 * self.rttvar + rttvar_sample) / 4;
            self.smoothed_rtt = (7 * self.smoothed_rtt + self.latest_rtt) / 8;
        }
    }

    // Not timing-aware, so it's safe to call this for inferred acks, such as arise from high-latency handshakes
    pub fn on_packet_acked(&mut self, config: &Config, packet: u64) {
        let info = if let Some(x) = self.sent_packets.remove(&packet) {
            x
        } else {
            return;
        };
        if info.bytes != 0 {
            // Congestion control
            self.bytes_in_flight -= info.bytes as u64;
            // Do not increase congestion window in recovery period.
            if !self.in_recovery(packet) {
                if self.congestion_window < self.ssthresh {
                    // Slow start.
                    self.congestion_window += info.bytes as u64;
                } else {
                    // Congestion avoidance.
                    self.congestion_window +=
                        config.default_mss * info.bytes as u64 / self.congestion_window;
                }
            }
        }

        // Loss recovery

        // If a packet sent prior to RTO was acked, then the RTO was spurious.  Otherwise, inform congestion control.
        if self.rto_count > 0 && packet > self.largest_sent_before_rto {
            // Retransmission timeout verified
            self.congestion_window = config.minimum_window;
        }

        self.handshake_count = 0;
        self.tlp_count = 0;
        self.rto_count = 0;

        // Update state for confirmed delivery of frames
        for (id, _) in info.retransmits.rst_stream {
            if let stream::SendState::ResetSent { stop_reason } =
                self.streams.get_mut(&id).unwrap().send_mut().unwrap().state
            {
                self.streams.get_mut(&id).unwrap().send_mut().unwrap().state =
                    stream::SendState::ResetRecvd { stop_reason };
                if stop_reason.is_none() {
                    self.maybe_cleanup(id);
                }
            }
        }
        for frame in info.retransmits.stream {
            let recvd = {
                let ss = if let Some(x) = self.streams.get_mut(&frame.id) {
                    x.send_mut().unwrap()
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
                self.finished_streams.push(frame.id);
            }
        }
        self.pending_acks.subtract(&info.acks);
    }

    pub fn detect_lost_packets(&mut self, config: &Config, now: u64, largest_acked: u64) {
        self.loss_time = 0;
        let mut lost_packets = Vec::<u64>::new();
        let delay_until_lost;
        let rtt = cmp::max(self.latest_rtt, self.smoothed_rtt);
        if config.using_time_loss_detection {
            // factor * (1 + fraction)
            delay_until_lost = rtt + (rtt * config.time_reordering_fraction as u64) >> 16;
        } else if largest_acked == self.largest_sent_packet {
            // Early retransmit alarm.
            delay_until_lost = (5 * rtt) / 4;
        } else {
            delay_until_lost = u64::max_value();
        }
        for (&packet, info) in self.sent_packets.range(0..largest_acked) {
            let time_since_sent = now - info.time;
            let delta = largest_acked - packet;
            // Use of >= for time comparison here is critical so that we successfully detect lost packets in testing
            // when rtt = 0
            if time_since_sent >= delay_until_lost || delta > self.reordering_threshold as u64 {
                lost_packets.push(packet);
            } else if self.loss_time == 0 && delay_until_lost != u64::max_value() {
                self.loss_time = now + delay_until_lost - time_since_sent;
            }
        }

        if let Some(largest_lost) = lost_packets.last().cloned() {
            let old_bytes_in_flight = self.bytes_in_flight;
            for packet in lost_packets {
                let mut info = self.sent_packets.remove(&packet).unwrap();
                if info.handshake {
                    self.handshake_pending += info.retransmits;
                } else {
                    self.pending += info.retransmits;
                }
                self.bytes_in_flight -= info.bytes as u64;
            }
            // Don't apply congestion penalty for lost ack-only packets
            let lost_nonack = old_bytes_in_flight != self.bytes_in_flight;
            // Start a new recovery epoch if the lost packet is larger than the end of the previous recovery epoch.
            if lost_nonack && !self.in_recovery(largest_lost) {
                self.end_of_recovery = self.largest_sent_packet;
                // *= factor
                self.congestion_window =
                    (self.congestion_window * config.loss_reduction_factor as u64) >> 16;
                self.congestion_window = cmp::max(self.congestion_window, config.minimum_window);
                self.ssthresh = self.congestion_window;
            }
        }
    }

    pub fn in_recovery(&self, packet: u64) -> bool {
        packet <= self.end_of_recovery
    }

    pub fn set_loss_detection_alarm(&mut self, config: &Config) {
        if self.bytes_in_flight == 0 {
            self.set_loss_detection = Some(None);
            return;
        }

        let mut alarm_duration: u64;
        if self.awaiting_handshake {
            // Handshake retransmission alarm.
            if self.smoothed_rtt == 0 {
                alarm_duration = 2 * config.default_initial_rtt;
            } else {
                alarm_duration = 2 * self.smoothed_rtt;
            }
            alarm_duration = cmp::max(alarm_duration + self.max_ack_delay, config.min_tlp_timeout);
            alarm_duration = alarm_duration * 2u64.pow(self.handshake_count);
            self.set_loss_detection = Some(Some(
                self.time_of_last_sent_handshake_packet + alarm_duration,
            ));
            return;
        }

        if self.loss_time != 0 {
            // Early retransmit timer or time loss detection.
            alarm_duration = self.loss_time - self.time_of_last_sent_retransmittable_packet;
        } else {
            // TLP or RTO alarm
            alarm_duration = self.rto(config);
            if self.tlp_count < config.max_tlps {
                // Tail Loss Probe
                let tlp_duration = cmp::max(
                    (3 * self.smoothed_rtt) / 2 + self.max_ack_delay,
                    config.min_tlp_timeout,
                );
                alarm_duration = cmp::min(alarm_duration, tlp_duration);
            }
        }
        self.set_loss_detection = Some(Some(
            self.time_of_last_sent_retransmittable_packet + alarm_duration,
        ));
    }

    /// Retransmit time-out
    pub fn rto(&self, config: &Config) -> u64 {
        let computed = self.smoothed_rtt + 4 * self.rttvar + self.max_ack_delay;
        cmp::max(computed, config.min_rto_timeout) * 2u64.pow(self.rto_count)
    }

    pub fn on_packet_authenticated(&mut self, now: u64, packet: u64) {
        self.pending_acks.insert_one(packet);
        if self.pending_acks.len() > MAX_ACK_BLOCKS {
            self.pending_acks.pop_min();
        }
        if packet > self.rx_packet {
            self.rx_packet = packet;
            self.rx_packet_time = now;
        }
    }

    /// Consider all previously transmitted handshake packets to be delivered. Called when we receive a new handshake packet.
    pub fn handshake_cleanup(&mut self, config: &Config) {
        if !self.awaiting_handshake {
            return;
        }
        self.awaiting_handshake = false;
        self.handshake_pending = Retransmits::default();
        let mut packets = Vec::new();
        for (&packet, info) in &self.sent_packets {
            if info.handshake {
                packets.push(packet);
            }
        }
        for packet in packets {
            self.on_packet_acked(config, packet);
        }
        self.set_loss_detection_alarm(config);
    }

    pub fn update_keys(&mut self, packet: u64, header: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
        let new = self.crypto.as_mut().unwrap().update(self.side);
        let data = new.decrypt(packet, header, payload)?;
        let old = mem::replace(self.crypto.as_mut().unwrap(), new);
        self.prev_crypto = Some((packet, old));
        self.key_phase = !self.key_phase;
        Some(data)
    }

    pub fn decrypt(
        &self,
        handshake: bool,
        packet: u64,
        header: &[u8],
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        if handshake {
            self.handshake_crypto.decrypt(packet, header, payload)
        } else {
            if let Some((boundary, ref prev)) = self.prev_crypto {
                if packet < boundary {
                    return prev.decrypt(packet, header, payload);
                }
            }
            self.crypto
                .as_ref()
                .unwrap()
                .decrypt(packet, header, payload)
        }
    }

    pub fn transmit_handshake(&mut self, messages: &[u8]) {
        let offset = {
            let ss = self
                .streams
                .get_mut(&StreamId(0))
                .unwrap()
                .send_mut()
                .unwrap();
            let x = ss.offset;
            ss.offset += messages.len() as u64;
            ss.bytes_in_flight += messages.len() as u64;
            x
        };
        self.handshake_pending.stream.push_back(frame::Stream {
            id: StreamId(0),
            fin: false,
            offset,
            data: messages.into(),
        });
        self.awaiting_handshake = true;
    }

    pub fn transmit(&mut self, stream: StreamId, data: Bytes) {
        let ss = self.streams.get_mut(&stream).unwrap().send_mut().unwrap();
        assert_eq!(ss.state, stream::SendState::Ready);
        let offset = ss.offset;
        ss.offset += data.len() as u64;
        ss.bytes_in_flight += data.len() as u64;
        if stream != StreamId(0) {
            self.data_sent += data.len() as u64;
        }
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
    pub fn reset(
        &mut self,
        ctx: &mut Context,
        stream: StreamId,
        error_code: u16,
        conn_h: ConnectionHandle,
    ) {
        assert!(
            stream.directionality() == Directionality::Bi || stream.initiator() == self.side,
            "only streams supporting outgoing data may be reset"
        );
        {
            // reset is a noop on a closed stream
            let stream = if let Some(x) = self.streams.get_mut(&stream) {
                x.send_mut().unwrap()
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
        }
        self.pending.rst_stream.push((stream, error_code));
        ctx.dirty_conns.insert(conn_h);
    }

    pub fn next_packet(&mut self, log: &Logger, config: &Config, now: u64) -> Option<Vec<u8>> {
        let established = match *self.state.as_ref().unwrap() {
            State::Handshake(_) => false,
            State::Established(_) => true,
            ref e => {
                assert!(e.is_closed());
                return None;
            }
        };

        let mut buf = Vec::new();
        let mut sent = Retransmits::default();
        let acks;
        let number;
        let ack_only;
        let is_initial;
        let header_len;
        let crypto;

        {
            let pending;
            if (!established || self.awaiting_handshake)
                && (!self.handshake_pending.is_empty()
                    || (!self.pending_acks.is_empty() && self.permit_ack_only))
            {
                // (re)transmit handshake data in long-header packets
                buf.reserve_exact(self.mtu as usize);
                number = self.get_tx_number();
                trace!(log, "sending handshake packet"; "pn" => number);
                let ty = if self.side == Side::Client
                    && self
                        .handshake_pending
                        .stream
                        .front()
                        .map_or(false, |x| x.offset == 0)
                {
                    match *self.state.as_mut().unwrap() {
                        State::Handshake(ref mut state) => {
                            if state.clienthello_packet.is_none() {
                                state.clienthello_packet = Some(number as u32);
                            }
                        }
                        _ => {}
                    }
                    is_initial = true;
                    packet::INITIAL
                } else {
                    is_initial = false;
                    packet::HANDSHAKE
                };
                Header::Long {
                    ty,
                    number: number as u32,
                    source_id: self.local_id.clone(),
                    destination_id: self.remote_id.clone(),
                }.encode(&mut buf);
                pending = &mut self.handshake_pending;
                crypto = Crypto::Handshake;
            } else if established || (self.zero_rtt_crypto.is_some() && self.side == Side::Client) {
                // Send 0RTT or 1RTT data
                is_initial = false;
                if self.congestion_blocked()
                    || self.pending.is_empty()
                        && (!self.permit_ack_only || self.pending_acks.is_empty())
                {
                    return None;
                }
                number = self.get_tx_number();
                buf.reserve_exact(self.mtu as usize);
                trace!(log, "sending protected packet"; "pn" => number);

                if !established {
                    crypto = Crypto::ZeroRtt;
                    Header::Long {
                        ty: packet::ZERO_RTT,
                        number: number as u32,
                        source_id: self.local_id.clone(),
                        destination_id: self.initial_id.clone(),
                    }.encode(&mut buf);
                } else {
                    crypto = Crypto::OneRtt;
                    Header::Short {
                        id: self.remote_id.clone(),
                        number: PacketNumber::new(number, self.largest_acked_packet),
                        key_phase: self.key_phase,
                    }.encode(&mut buf);
                }

                pending = &mut self.pending;
            } else {
                return None;
            }
            ack_only = pending.is_empty();
            header_len = buf.len() as u16;
            let max_size = self.mtu as usize - AEAD_TAG_SIZE;

            // PING
            if pending.ping {
                trace!(log, "ping");
                pending.ping = false;
                sent.ping = true;
                buf.write(frame::Type::PING);
            }

            // ACK
            // We will never ack protected packets in handshake packets because handshake_cleanup ensures we never send
            // handshake packets after receiving protected packets.
            // 0-RTT packets must never carry acks (which would have to be of handshake packets)
            if !self.pending_acks.is_empty() && crypto != Crypto::ZeroRtt {
                let delay = (now - self.rx_packet_time) >> ACK_DELAY_EXPONENT;
                trace!(log, "ACK"; "ranges" => ?self.pending_acks.iter().collect::<Vec<_>>(), "delay" => delay);
                frame::Ack::encode(delay, &self.pending_acks, &mut buf);
                acks = self.pending_acks.clone();
            } else {
                acks = RangeSet::new();
            }

            // PATH_RESPONSE
            if buf.len() + 9 < max_size {
                // No need to retransmit these, so we don't save the value after encoding it.
                if let Some((_, x)) = pending.path_response.take() {
                    trace!(log, "PATH_RESPONSE"; "value" => format!("{:08x}", x));
                    buf.write(frame::Type::PATH_RESPONSE);
                    buf.write(x);
                }
            }

            // RST_STREAM
            while buf.len() + 19 < max_size {
                let (id, error_code) = if let Some(x) = pending.rst_stream.pop() {
                    x
                } else {
                    break;
                };
                let stream = if let Some(x) = self.streams.get(&id) {
                    x
                } else {
                    continue;
                };
                trace!(log, "RST_STREAM"; "stream" => id.0);
                sent.rst_stream.push((id, error_code));
                frame::RstStream {
                    id,
                    error_code,
                    final_offset: stream.send().unwrap().offset,
                }.encode(&mut buf);
            }

            // STOP_SENDING
            while buf.len() + 11 < max_size {
                let (id, error_code) = if let Some(x) = pending.stop_sending.pop() {
                    x
                } else {
                    break;
                };
                let stream = if let Some(x) = self.streams.get(&id) {
                    x.recv().unwrap()
                } else {
                    continue;
                };
                if stream.is_finished() {
                    continue;
                }
                trace!(log, "STOP_SENDING"; "stream" => id.0);
                sent.stop_sending.push((id, error_code));
                buf.write(frame::Type::STOP_SENDING);
                buf.write(id);
                buf.write(error_code);
            }

            // MAX_DATA
            if pending.max_data && buf.len() + 9 < max_size {
                trace!(log, "MAX_DATA"; "value" => self.local_max_data);
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
                let rs = if let Some(x) = self.streams.get(&id) {
                    x.recv().unwrap()
                } else {
                    continue;
                };
                if rs.is_finished() {
                    continue;
                }
                sent.max_stream_data.insert(id);
                trace!(log, "MAX_STREAM_DATA"; "stream" => id.0, "value" => rs.max_data);
                buf.write(frame::Type::MAX_STREAM_DATA);
                buf.write(id);
                buf.write_var(rs.max_data);
            }

            // MAX_STREAM_ID uni
            if pending.max_uni_stream_id && buf.len() + 9 < max_size {
                pending.max_uni_stream_id = false;
                sent.max_uni_stream_id = true;
                trace!(log, "MAX_STREAM_ID (unidirectional)");
                buf.write(frame::Type::MAX_STREAM_ID);
                buf.write(StreamId::new(
                    !self.side,
                    Directionality::Uni,
                    self.max_remote_uni_streams - 1,
                ));
            }

            // MAX_STREAM_ID bi
            if pending.max_bi_stream_id && buf.len() + 9 < max_size {
                pending.max_bi_stream_id = false;
                sent.max_bi_stream_id = true;
                trace!(log, "MAX_STREAM_ID (bidirectional)");
                buf.write(frame::Type::MAX_STREAM_ID);
                buf.write(StreamId::new(
                    !self.side,
                    Directionality::Bi,
                    self.max_remote_bi_streams - 1,
                ));
            }

            // STREAM
            while buf.len() + 25 < max_size {
                let mut stream = if let Some(x) = pending.stream.pop_front() {
                    x
                } else {
                    break;
                };
                if stream.id != StreamId(0)
                    && self
                        .streams
                        .get(&stream.id)
                        .map_or(true, |s| s.send().unwrap().state.was_reset())
                {
                    continue;
                }
                let len = cmp::min(stream.data.len(), max_size as usize - buf.len() - 25);
                let data = stream.data.split_to(len);
                let fin = stream.fin && stream.data.is_empty();
                trace!(log, "STREAM"; "id" => stream.id.0, "off" => stream.offset, "len" => len, "fin" => fin);
                let frame = frame::Stream {
                    id: stream.id,
                    offset: stream.offset,
                    fin: fin,
                    data: data,
                };
                frame.encode(true, &mut buf);
                sent.stream.push_back(frame);
                if !stream.data.is_empty() {
                    let stream = frame::Stream {
                        offset: stream.offset + len as u64,
                        ..stream
                    };
                    pending.stream.push_front(stream);
                }
            }
        }

        if is_initial && buf.len() < MIN_INITIAL_SIZE - AEAD_TAG_SIZE {
            buf.resize(
                MIN_INITIAL_SIZE - AEAD_TAG_SIZE,
                frame::Type::PADDING.into(),
            );
        }
        if crypto != Crypto::OneRtt {
            set_payload_length(&mut buf, header_len as usize);
        }
        self.encrypt(crypto, number, &mut buf, header_len);

        // If we sent any acks, don't immediately resend them.  Setting this even if ack_only is false needlessly
        // prevents us from ACKing the next packet if it's ACK-only, but saves the need for subtler logic to avoid
        // double-transmitting acks all the time.
        self.permit_ack_only &= acks.is_empty();

        self.on_packet_sent(
            config,
            now,
            number,
            SentPacket {
                acks,
                time: now,
                bytes: if ack_only { 0 } else { buf.len() as u16 },
                handshake: crypto == Crypto::Handshake,
                retransmits: sent,
            },
        );

        Some(buf)
    }

    pub fn encrypt(&self, crypto: Crypto, number: u64, buf: &mut Vec<u8>, header_len: u16) {
        let payload = match crypto {
            Crypto::ZeroRtt => self.zero_rtt_crypto.as_ref().unwrap().encrypt(
                number,
                &buf[0..header_len as usize],
                &buf[header_len as usize..],
            ),
            Crypto::Handshake => self.handshake_crypto.encrypt(
                number,
                &buf[0..header_len as usize],
                &buf[header_len as usize..],
            ),
            Crypto::OneRtt => self.crypto.as_ref().unwrap().encrypt(
                number,
                &buf[0..header_len as usize],
                &buf[header_len as usize..],
            ),
        };
        debug_assert_eq!(
            payload.len(),
            buf.len() - header_len as usize + AEAD_TAG_SIZE
        );
        buf.truncate(header_len as usize);
        buf.extend_from_slice(&payload);
    }

    // TLP/RTO transmit
    pub fn force_transmit(&mut self, config: &Config, now: u64) -> Box<[u8]> {
        let number = self.get_tx_number();
        let mut buf = Vec::new();
        Header::Short {
            id: self.remote_id.clone(),
            number: PacketNumber::new(number, self.largest_acked_packet),
            key_phase: self.key_phase,
        }.encode(&mut buf);
        let header_len = buf.len() as u16;
        buf.push(frame::Type::PING.into());
        self.encrypt(Crypto::OneRtt, number, &mut buf, header_len);
        self.on_packet_sent(
            config,
            now,
            number,
            SentPacket {
                time: now,
                bytes: buf.len() as u16,
                handshake: false,
                acks: RangeSet::new(),
                retransmits: Retransmits::default(),
            },
        );
        buf.into()
    }

    pub fn make_close(&mut self, reason: &state::CloseReason) -> Box<[u8]> {
        let number = self.get_tx_number();
        let mut buf = Vec::new();
        Header::Short {
            id: self.remote_id.clone(),
            number: PacketNumber::new(number, self.largest_acked_packet),
            key_phase: self.key_phase,
        }.encode(&mut buf);
        let header_len = buf.len() as u16;
        let max_len = self.mtu - header_len - AEAD_TAG_SIZE as u16;
        match *reason {
            state::CloseReason::Application(ref x) => x.encode(&mut buf, max_len),
            state::CloseReason::Connection(ref x) => x.encode(&mut buf, max_len),
        }
        self.encrypt(Crypto::OneRtt, number, &mut buf, header_len);
        buf.into()
    }

    pub fn set_params(&mut self, params: TransportParameters) {
        self.max_bi_streams = params.initial_max_streams_bidi as u64;
        if self.side == Side::Client {
            self.max_bi_streams += 1;
        } // Account for TLS stream
        self.max_uni_streams = params.initial_max_streams_uni as u64;
        self.max_data = params.initial_max_data as u64;
        for i in 0..self.max_remote_bi_streams {
            let id = StreamId::new(!self.side, Directionality::Bi, i as u64);
            self.streams
                .get_mut(&id)
                .unwrap()
                .send_mut()
                .unwrap()
                .max_data = params.initial_max_stream_data as u64;
        }
        self.params = params;
    }

    pub fn open(&mut self, config: &Config, direction: Directionality) -> Option<StreamId> {
        let (id, mut stream) = match direction {
            Directionality::Uni if self.next_uni_stream < self.max_uni_streams => {
                self.next_uni_stream += 1;
                (
                    StreamId::new(self.side, direction, self.next_uni_stream - 1),
                    stream::Send::new().into(),
                )
            }
            Directionality::Bi if self.next_bi_stream < self.max_bi_streams => {
                self.next_bi_stream += 1;
                (
                    StreamId::new(self.side, direction, self.next_bi_stream - 1),
                    Stream::new_bi(config.stream_receive_window as u64),
                )
            }
            _ => {
                return None;
            } // TODO: Queue STREAM_ID_BLOCKED
        };
        stream.send_mut().unwrap().max_data = self.params.initial_max_stream_data as u64;
        let old = self.streams.insert(id, stream);
        assert!(old.is_none());
        Some(id)
    }

    /// Discard state for a stream if it's fully closed.
    ///
    /// Called when one side of a stream transitions to a closed state
    pub fn maybe_cleanup(&mut self, id: StreamId) {
        match self.streams.entry(id) {
            hash_map::Entry::Vacant(_) => unreachable!(),
            hash_map::Entry::Occupied(e) => {
                if e.get().is_closed() {
                    e.remove_entry();
                    if id.initiator() != self.side {
                        match id.directionality() {
                            Directionality::Uni => {
                                self.max_remote_uni_streams += 1;
                                self.pending.max_uni_stream_id = true;
                            }
                            Directionality::Bi => {
                                self.max_remote_bi_streams += 1;
                                self.pending.max_bi_stream_id = true;
                            }
                        }
                    }
                }
            }
        }
    }

    pub fn finish(&mut self, id: StreamId) {
        let ss = self
            .streams
            .get_mut(&id)
            .expect("unknown stream")
            .send_mut()
            .expect("recv-only stream");
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
        assert_ne!(id, StreamId(0), "cannot read an internal stream");
        let rs = self.streams.get_mut(&id).unwrap().recv_mut().unwrap();
        rs.unordered = true;
        // TODO: Drain rs.assembler to handle ordered-then-unordered reads reliably

        // Return data we already have buffered, regardless of state
        if let Some(x) = rs.buffered.pop_front() {
            // TODO: Reduce granularity of flow control credit, while still avoiding stalls, to reduce overhead
            self.local_max_data += x.0.len() as u64; // BUG: Don't issue credit for already-received data!
            self.pending.max_data = true;
            // Only bother issuing stream credit if the peer wants to send more
            if let stream::RecvState::Recv { size: None } = rs.state {
                rs.max_data += x.0.len() as u64;
                self.pending.max_stream_data.insert(id);
            }
            Ok(x)
        } else {
            match rs.state {
                stream::RecvState::ResetRecvd { error_code, .. } => {
                    rs.state = stream::RecvState::Closed;
                    Err(ReadError::Reset { error_code })
                }
                stream::RecvState::Closed => unreachable!(),
                stream::RecvState::Recv { .. } => Err(ReadError::Blocked),
                stream::RecvState::DataRecvd { .. } => {
                    rs.state = stream::RecvState::Closed;
                    Err(ReadError::Finished)
                }
            }
        }
    }

    pub fn read(&mut self, id: StreamId, buf: &mut [u8]) -> Result<usize, ReadError> {
        assert_ne!(id, StreamId(0), "cannot read an internal stream");
        let rs = self.streams.get_mut(&id).unwrap().recv_mut().unwrap();
        assert!(
            !rs.unordered,
            "cannot perform ordered reads following unordered reads on a stream"
        );

        for (data, offset) in rs.buffered.drain(..) {
            rs.assembler.insert(offset, &data);
        }

        if !rs.assembler.blocked() {
            let n = rs.assembler.read(buf);
            // TODO: Reduce granularity of flow control credit, while still avoiding stalls, to reduce overhead
            self.local_max_data += n as u64;
            self.pending.max_data = true;
            // Only bother issuing stream credit if the peer wants to send more
            if let stream::RecvState::Recv { size: None } = rs.state {
                rs.max_data += n as u64;
                self.pending.max_stream_data.insert(id);
            }
            Ok(n)
        } else {
            match rs.state {
                stream::RecvState::ResetRecvd { error_code, .. } => {
                    rs.state = stream::RecvState::Closed;
                    Err(ReadError::Reset { error_code })
                }
                stream::RecvState::Closed => unreachable!(),
                stream::RecvState::Recv { .. } => Err(ReadError::Blocked),
                stream::RecvState::DataRecvd { .. } => {
                    rs.state = stream::RecvState::Closed;
                    Err(ReadError::Finished)
                }
            }
        }
    }

    pub fn stop_sending(&mut self, id: StreamId, error_code: u16) {
        assert!(
            id.directionality() == Directionality::Bi || id.initiator() != self.side,
            "only streams supporting incoming data may be reset"
        );
        let stream = self
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

    pub fn congestion_blocked(&self) -> bool {
        self.congestion_window.saturating_sub(self.bytes_in_flight) < self.mtu as u64
    }

    pub fn blocked(&self) -> bool {
        self.data_sent >= self.max_data || self.congestion_blocked()
    }

    pub fn decrypt_packet(
        &mut self,
        handshake: bool,
        packet: Packet,
    ) -> Result<(Vec<u8>, u64), Option<TransportError>> {
        let (key_phase, number) = match packet.header {
            Header::Short {
                key_phase, number, ..
            } if !handshake =>
            {
                (key_phase, number)
            }
            Header::Long { number, .. } if handshake => (false, PacketNumber::U32(number)),
            _ => {
                return Err(None);
            }
        };
        let number = number.expand(self.rx_packet);
        if key_phase != self.key_phase {
            if number <= self.rx_packet {
                // Illegal key update
                return Err(Some(TransportError::PROTOCOL_VIOLATION));
            }
            if let Some(payload) = self.update_keys(number, &packet.header_data, &packet.payload) {
                Ok((payload, number))
            } else {
                // Invalid key update
                Err(None)
            }
        } else if let Some(payload) =
            self.decrypt(handshake, number, &packet.header_data, &packet.payload)
        {
            Ok((payload, number))
        } else {
            // Unable to authenticate
            Err(None)
        }
    }

    pub fn get_recv_stream(&mut self, id: StreamId) -> Result<Option<&mut Stream>, TransportError> {
        if self.side == id.initiator() {
            match id.directionality() {
                Directionality::Uni => {
                    return Err(TransportError::STREAM_STATE_ERROR);
                }
                Directionality::Bi if id.index() >= self.next_bi_stream => {
                    return Err(TransportError::STREAM_STATE_ERROR);
                }
                Directionality::Bi => {}
            };
        } else {
            let limit = match id.directionality() {
                Directionality::Bi => self.max_remote_bi_streams,
                Directionality::Uni => self.max_remote_uni_streams,
            };
            if id.index() >= limit {
                return Err(TransportError::STREAM_ID_ERROR);
            }
        }
        Ok(self.streams.get_mut(&id))
    }

    pub fn write(&mut self, stream: StreamId, data: &[u8]) -> Result<usize, WriteError> {
        if self.state.as_ref().unwrap().is_closed() {
            return Err(WriteError::Blocked);
        }
        assert!(stream.directionality() == Directionality::Bi || stream.initiator() == self.side);
        if self.blocked() {
            self.blocked_streams.insert(stream);
            return Err(WriteError::Blocked);
        }
        let (stop_reason, stream_budget) = {
            let ss = self
                .streams
                .get_mut(&stream)
                .expect("stream already closed")
                .send_mut()
                .unwrap();
            (
                match ss.state {
                    stream::SendState::ResetSent {
                        ref mut stop_reason,
                    }
                    | stream::SendState::ResetRecvd {
                        ref mut stop_reason,
                    } => stop_reason.take(),
                    _ => None,
                },
                ss.max_data - ss.offset,
            )
        };

        if let Some(error_code) = stop_reason {
            self.maybe_cleanup(stream);
            return Err(WriteError::Stopped { error_code });
        }

        if stream_budget == 0 {
            return Err(WriteError::Blocked);
        }

        let conn_budget = self.max_data - self.data_sent;
        let n = conn_budget.min(stream_budget).min(data.len() as u64) as usize;
        self.transmit(stream, (&data[0..n]).into());
        Ok(n)
    }
}

#[derive(Debug, Fail, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ReadError {
    /// No more data is currently available on this stream.
    #[fail(display = "blocked")]
    Blocked,
    /// The peer abandoned transmitting data on this stream.
    #[fail(display = "reset by peer: error {}", error_code)]
    Reset { error_code: u16 },
    /// The data on this stream has been fully delivered and no more will be transmitted.
    #[fail(display = "finished")]
    Finished,
}

#[derive(Debug, Fail, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum WriteError {
    /// The peer is not able to accept additional data, or the connection is congested.
    #[fail(display = "unable to accept further writes")]
    Blocked,
    /// The peer is no longer accepting data on this stream.
    #[fail(display = "stopped by peer: error {}", error_code)]
    Stopped { error_code: u16 },
}

#[derive(Debug, Fail)]
pub enum ConnectError {
    #[fail(display = "session ticket was malformed")]
    MalformedSession,
    #[fail(display = "TLS error: {}", _0)]
    Tls(ssl::Error),
}

impl From<ssl::Error> for ConnectError {
    fn from(x: ssl::Error) -> Self {
        ConnectError::Tls(x)
    }
}
impl From<openssl::error::ErrorStack> for ConnectError {
    fn from(x: openssl::error::ErrorStack) -> Self {
        ConnectError::Tls(x.into())
    }
}

pub enum State {
    Handshake(state::Handshake),
    Established(state::Established),
    HandshakeFailed(state::HandshakeFailed),
    Closed(state::Closed),
    Draining(state::Draining),
    /// Waiting for application to call close so we can dispose of the resources
    Drained,
}

impl State {
    pub fn closed<R: Into<state::CloseReason>>(reason: R) -> Self {
        State::Closed(state::Closed {
            reason: reason.into(),
            app_closed: false,
        })
    }

    pub fn handshake_failed<R: Into<state::CloseReason>>(
        reason: R,
        alert: Option<Box<[u8]>>,
    ) -> Self {
        State::HandshakeFailed(state::HandshakeFailed {
            reason: reason.into(),
            alert,
            app_closed: false,
        })
    }

    pub fn is_closed(&self) -> bool {
        match *self {
            State::HandshakeFailed(_) => true,
            State::Closed(_) => true,
            State::Draining(_) => true,
            State::Drained => true,
            _ => false,
        }
    }

    pub fn is_app_closed(&self) -> bool {
        match *self {
            State::HandshakeFailed(ref x) => x.app_closed,
            State::Closed(ref x) => x.app_closed,
            State::Draining(ref x) => x.app_closed,
            _ => false,
        }
    }

    pub fn is_drained(&self) -> bool {
        if let State::Drained = *self {
            true
        } else {
            false
        }
    }
}

pub mod state {
    use super::*;

    pub struct Handshake {
        pub tls: MidHandshakeSslStream<MemoryStream>,
        /// The number of the packet that first contained the latest version of the TLS ClientHello. Present iff we're
        /// the client.
        pub clienthello_packet: Option<u32>,
        pub remote_id_set: bool,
    }

    pub struct Established {
        pub tls: SslStream<MemoryStream>,
    }

    pub struct HandshakeFailed {
        // Closed
        pub reason: CloseReason,
        pub alert: Option<Box<[u8]>>,
        pub app_closed: bool,
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

    pub struct Closed {
        pub reason: CloseReason,
        pub app_closed: bool,
    }

    pub struct Draining {
        pub app_closed: bool,
    }

    impl From<Handshake> for Draining {
        fn from(_: Handshake) -> Self {
            Draining { app_closed: false }
        }
    }

    impl From<HandshakeFailed> for Draining {
        fn from(x: HandshakeFailed) -> Self {
            Draining {
                app_closed: x.app_closed,
            }
        }
    }

    impl From<Established> for Draining {
        fn from(_: Established) -> Self {
            Draining { app_closed: false }
        }
    }

    impl From<Closed> for Draining {
        fn from(x: Closed) -> Self {
            Draining {
                app_closed: x.app_closed,
            }
        }
    }
}
