use std::collections::{HashMap, VecDeque, BTreeMap};
use std::{io, cmp};
use std::net::SocketAddrV6;
use std::sync::Arc;
use std::time::Duration;

use bytes::{BufMut, Bytes, ByteOrder, BigEndian, IntoBuf};
use rand::{distributions, OsRng, Rng, Rand};
use rand::distributions::Sample;
use slab::Slab;
use openssl::ex_data;
use openssl::ssl::{self, SslContext, SslMethod, SslOptions, SslVersion, SslMode, Ssl, SslStream, HandshakeError, MidHandshakeSslStream, SslStreamBuilder, SslAlert};
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use failure::Error;
use blake2::Blake2b;
use digest::{Input, VariableOutput};
use constant_time_eq::constant_time_eq;
use bincode;
use slog::Logger;

use memory_stream::MemoryStream;
use transport_parameters::TransportParameters;
use frame::StreamId;
use {frame, Frame, from_bytes, BytesExt, TransportError, VERSION};

type Result<T> = ::std::result::Result<T, Error>;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct ConnectionHandle(usize);

pub struct Config {
    pub listen: Option<ListenConfig>,
    
    /// Maximum number of tail loss probes before an RTO fires.
    pub max_tlps: u32,
    /// Maximum reordering in packet number space before FACK style loss detection considers a packet lost.
    pub reordering_threshold: u32,
    /// Maximum reordering in time space before time based loss detection considers a packet lost. 0.16 format
    pub time_reordering_fraction: u16,
    /// Whether time based loss detection is in use. If false, uses FACK style loss detection.
    pub using_time_loss_detection: bool,
    /// Minimum time in the future a tail loss probe alarm may be set for (μs).
    pub min_tlp_timeout: u64,
    /// Minimum time in the future an RTO alarm may be set for (μs).
    pub min_rto_timeout: u64,
    /// The length of the peer’s delayed ack timer (μs).
    pub delayed_ack_timeout: u64,
    /// The default RTT used before an RTT sample is taken (μs)
    pub default_initial_rtt: u64,

    /// The default max packet size used for calculating default and minimum congestion windows.
    pub default_mss: u64,
    /// Default limit on the amount of outstanding data in bytes.
    pub initial_window: u64,
    /// Default minimum congestion window.
    pub minimum_window: u64,
    /// Reduction in congestion window when a new loss event is detected. 0.16 format
    pub loss_reduction_factor: u16,
}

pub struct ListenConfig {
    pub private_key: PKey<Private>,
    pub cert: X509,
}

impl Default for Config {
    fn default() -> Self { Self {
        listen: None,
        
        max_tlps: 2,
        reordering_threshold: 3,
        time_reordering_fraction: 0x2000, // 1/8
        using_time_loss_detection: false,
        min_tlp_timeout: 10,
        min_rto_timeout: 200,
        delayed_ack_timeout: 25,
        default_initial_rtt: 100,
        
        default_mss: 1460,
        initial_window: 10 * 1460,
        minimum_window: 2 * 1460,
        loss_reduction_factor: 0x8000, // 1/2
    }}
}

pub struct Endpoint {
    log: Logger,
    rng: OsRng,
    initial_packet_number: distributions::Range<u64>,
    tls: SslContext,
    connection_ids: HashMap<ConnectionId, ConnectionHandle>,
    connections: Slab<Connection>,
    config: Config,
    state: PersistentState,
    events: VecDeque<Event>,
    io: VecDeque<Io>,
}

const MIN_INITIAL_SIZE: usize = 1200;

fn reset_token_for(key: &[u8], id: ConnectionId) -> [u8; 16] {
    let mut mac = Blake2b::new_keyed(key, 16);
    {
        let mut buf = [0; 8];
        BigEndian::write_u64(&mut buf, id.0);
        mac.process(&buf);
    }
    // TODO: Server ID??
    let mut result = [0; 16];
    mac.variable_result(&mut result).unwrap();
    result
}

fn gen_transport_params(key: &[u8], am_server: bool, id: ConnectionId) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut params = TransportParameters::default();
    if am_server {
        params.stateless_reset_token = Some(reset_token_for(key, id));
    } else {
        params.omit_connection_id = true;
    }
    params.write(&mut buf);
    buf
}

#[derive(Copy, Clone)]
pub struct PersistentState {
    pub cookie_key: [u8; 64],
    pub reset_key: [u8; 64],
}

impl Rand for PersistentState {
    fn rand<R: Rng>(rng: &mut R) -> Self {
        let mut cookie_key = [0; 64];
        let mut reset_key = [0; 64];
        rng.fill_bytes(&mut cookie_key);
        rng.fill_bytes(&mut reset_key);
        Self { cookie_key, reset_key }
    }
}

impl Endpoint {
    /// Create an endpoint for outgoing connections only
    pub fn new(log: Logger, config: Config, state: PersistentState) -> Result<Self> {
        let rng = OsRng::new()?;
        let cookie_factory = Arc::new(CookieFactory::new(state.cookie_key));

        let mut tls = SslContext::builder(SslMethod::tls())?;
        tls.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        tls.set_options(
            SslOptions::NO_COMPRESSION | SslOptions::NO_SSLV2 | SslOptions::NO_SSLV3 | SslOptions::NO_TLSV1 |
            SslOptions::NO_TLSV1_1 | SslOptions::NO_TLSV1_2 | SslOptions::DONT_INSERT_EMPTY_FRAGMENTS
        );
        tls.clear_options(SslOptions::ENABLE_MIDDLEBOX_COMPAT);
        tls.set_mode(
            SslMode::ACCEPT_MOVING_WRITE_BUFFER | SslMode::ENABLE_PARTIAL_WRITE | SslMode::RELEASE_BUFFERS
        );
        tls.set_default_verify_paths()?;
        {
            let cookie_factory = cookie_factory.clone();
            tls.set_cookie_generate_cb(move |tls, buf| {
                let conn = tls.ex_data(*CONNECTION_INFO_INDEX).unwrap();
                Ok(cookie_factory.generate(conn, buf))
            });
        }
        tls.set_cookie_verify_cb(move |tls, cookie| {
            let conn = tls.ex_data(*CONNECTION_INFO_INDEX).unwrap();
            cookie_factory.verify(conn, cookie)
        });
        let reset_key = state.reset_key;
        tls.add_custom_ext(
            26, ssl::ExtensionContext::TLS1_3_ONLY | ssl::ExtensionContext::CLIENT_HELLO | ssl::ExtensionContext::TLS1_3_ENCRYPTED_EXTENSIONS,
            move |tls, ctx, _| {
                let conn = tls.ex_data(*CONNECTION_INFO_INDEX).unwrap();
                let am_server = ctx == ssl::ExtensionContext::TLS1_3_ENCRYPTED_EXTENSIONS;
                Ok(Some(gen_transport_params(&reset_key, am_server, conn.id).into()))
            },
            |tls, ctx, data, _| {
                let am_server = ctx == ssl::ExtensionContext::CLIENT_HELLO;
                match TransportParameters::read(am_server, &mut data.into_buf()) {
                    Ok(params) => {
                        tls.set_ex_data(*TRANSPORT_PARAMS_INDEX, Ok(params));
                        Ok(())
                    }
                    Err(e) => {
                        use transport_parameters::Error::*;
                        tls.set_ex_data(*TRANSPORT_PARAMS_INDEX, Err(e));
                        Err(match e {
                            VersionNegotiation => SslAlert::ILLEGAL_PARAMETER,
                            IllegalValue => SslAlert::ILLEGAL_PARAMETER,
                            Malformed => SslAlert::DECODE_ERROR,
                        })
                    }
                }
            }
        )?;

        if let Some(ref listen) = config.listen {
            tls.set_private_key(&listen.private_key)?;
            tls.set_certificate(&listen.cert)?;
            tls.check_private_key()?;
        }

        let tls = tls.build();

        Ok(Self {
            log, rng, config, state, tls,
            initial_packet_number: distributions::Range::new(0, 2u64.pow(32) - 1024),
            connection_ids: HashMap::new(),
            connections: Slab::new(),
            events: VecDeque::new(),
            io: VecDeque::new(),
        })
    }

    pub fn poll(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    pub fn poll_io(&mut self) -> Option<Io> {
        self.io.pop_front()
    }

    pub fn handle(&mut self, now: u64, remote: SocketAddrV6, local: SocketAddrV6, data: Bytes) {
        let packet = match Packet::decode(data.clone()) {
            Ok(x) => x,
            Err(HeaderError::UnsupportedVersion(id)) => {
                trace!(self.log, "sending version negotiation");
                // Negotiate versions
                let mut buf = Vec::<u8>::new();
                buf.reserve_exact(17);
                Header::VersionNegotiate { id }.encode(&mut buf);
                buf.put_u32::<BigEndian>(0x0a1a2a3a); // reserved version
                buf.put_u32::<BigEndian>(VERSION); // supported version
                self.transmit(remote, buf.into());
                return;
            }
            Err(_) => {
                trace!(self.log, "dropping packet with malformed header");
                return;
            }
        };

        //
        // Handle packet on existing connection, if any
        //

        let conn_id = match packet.header {
            Header::Long { id, .. } | Header::Short { id: Some(id), .. } | Header::VersionNegotiate { id } => Some(id),
            _ => None
        };

        if let Some(conn) = conn_id.and_then(|x| self.connection_ids.get(&x).cloned()) {
            self.handle_connected(now, conn, remote, packet);
            return;
        }

        //
        // Potentially create a new connection
        //

        if self.config.listen.is_none() {
            trace!(self.log, "dropping packet from unknown connection");
            return;
        }
        if let Header::Long { ty, id, number } = packet.header {
            // MAY buffer non-initial packets a little for better 0RTT behavior
            if ty == packet::INITIAL && data.len() >= MIN_INITIAL_SIZE {
                self.handle_initial(remote, id, number, packet.payload);
                return;
            }
        }

        //
        // If we got this far, we're a server receiving a seemingly valid packet for an unknown connection. Send a stateless reset.
        //

        if let Some(id) = conn_id {
            debug!(self.log, "sending stateless reset");
            let mut buf = Vec::<u8>::new();
            // Bound reply size to mitigate spoofed source address amplification attacks
            let padding = self.rng.gen_range(0, cmp::max(16, packet.payload.len()) - 16);
            buf.reserve_exact(1 + 8 + 4 + padding + 16);
            (Header::Short { id: conn_id, number: PacketNumber::U8(self.rng.gen()) })
                .encode(&mut buf);
            {
                let start = buf.len();
                buf.resize(start + padding, 0);
                self.rng.fill_bytes(&mut buf[start..start+padding]);
            }
            buf.extend(&reset_token_for(&self.state.reset_key, id));
            self.transmit(remote, buf.into());
        }
    }

    pub fn connect(&mut self, local: SocketAddrV6, remote: SocketAddrV6) -> Result<ConnectionHandle> {
        let mut tls = Ssl::new(&self.tls)?;
        let id = self.rng.gen();
        tls.set_ex_data(*CONNECTION_INFO_INDEX, ConnectionInfo { id, remote });
        let mut tls = match tls.connect(MemoryStream::new()) {
            Ok(_) => unreachable!(),
            Err(HandshakeError::WouldBlock(tls)) => tls,
            Err(e) => return Err(e.into()),
        };
        let conn = self.add_connection(id);

        let mut buf = Vec::<u8>::new();
        buf.reserve_exact(MIN_INITIAL_SIZE);
        let packet = self.connections[conn.0].get_tx_number() as u32;
        encode_long_header(&mut buf, packet::INITIAL, id, packet);
        let client_hello = tls.get_mut().take_outgoing().to_vec();
        frame::stream(&mut buf, StreamId(0), None, true, false, &client_hello);
        self.connections[conn.0].state = Some(State::Handshake(state::Handshake {
            tls,
            clienthello_packet: Some(packet),
        }));
        if buf.len() < MIN_INITIAL_SIZE {
            buf.resize(MIN_INITIAL_SIZE, frame::Type::PADDING.into());
        }
        self.transmit(remote, buf.into());
        Ok(conn)
    }

    fn transmit(&mut self, destination: SocketAddrV6, packet: Box<[u8]>) {
        self.io.push_back(Io::Transmit { destination, packet });
    }

    fn add_connection(&mut self, id: ConnectionId) -> ConnectionHandle {
        let i = self.connections.insert(Connection::new(id, self.initial_packet_number.sample(&mut self.rng).into(), &self.config));
        self.connection_ids.insert(id, ConnectionHandle(i));
        ConnectionHandle(i)
    }

    fn handle_initial(&mut self, remote: SocketAddrV6, id: ConnectionId, packet_number: u32, payload: Bytes) {
        let mut stream = MemoryStream::new();
        // TODO: Proper reassembly
        for frame in frame::Iter::new(payload) {
            match frame {
                Frame::Padding => {}
                Frame::Stream(frame::Stream { id, data, .. }) => {
                    if id != StreamId(0) { return; } // Invalid packet
                    stream.extend_incoming(&data[..]);
                }
                _ => { return; } // Invalid packet
            }
        }

        let mut tls = Ssl::new(&self.tls).unwrap(); // TODO: is this reliable?
        tls.set_ex_data(*CONNECTION_INFO_INDEX, ConnectionInfo { id, remote });
        let mut tls = SslStreamBuilder::new(tls, stream);
        match tls.stateless() {
            Ok(()) => {
                match tls.accept() {
                    Ok(_) => unreachable!(),
                    Err(HandshakeError::WouldBlock(mut tls)) => {
                        trace!(self.log, "got fresh cookie");
                        let handshake = tls.get_mut().take_outgoing().to_owned();
                        if let Some(params) = tls.ssl().ex_data(*TRANSPORT_PARAMS_INDEX).cloned() {
                            let params = params.expect("transport parameter errors should have aborted the handshake");
                            let conn = self.add_connection(id);
                            self.connections[conn.0].state = Some(State::Handshake(state::Handshake {
                                tls,
                                clienthello_packet: None,
                            }));
                            self.events.push_back(Event::Connected(conn));
                        } else {
                            debug!(self.log, "ClientHello missing transport params extension");
                            // TODO: Respond with CONNECTION_CLOSE
                            unimplemented!()
                        }
                    }
                    Err(e) => {
                        debug!(self.log, "accept failed"; "reason" => %e);
                    }
                }
            }
            Err(None) => {
                trace!(self.log, "sending HelloRetryRequest");
                let data = tls.get_mut().take_outgoing();
                let mut buf = Vec::<u8>::new();
                buf.reserve_exact(17 + data.len());
                encode_long_header(&mut buf, packet::RETRY, id, packet_number);
                frame::stream(&mut buf, StreamId(0), None, true, false, &data);
                self.transmit(remote, buf.into());
            }
            Err(Some(e)) => {
                debug!(self.log, "stateless handshake failed"; "reason" => %e);
                // TODO: Respond with CONNECTION_CLOSE
                unimplemented!()
            }
        }
    }

    fn handle_connected(&mut self, now: u64, conn: ConnectionHandle, remote: SocketAddrV6, packet: Packet) {
        trace!(self.log, "connection got packet"; "id" => conn.0, "len" => packet.payload.len());
        let was_closed = self.connections[conn.0].state.as_ref().unwrap().is_closed();
        self.connections[conn.0].state = Some(match self.connections[conn.0].state.take().unwrap() {
            State::Handshake(mut state) => {
                match packet.header {
                    Header::Long { ty: packet::RETRY, number, .. } => {
                        match state.clienthello_packet {
                            Some(x) if number < x => {
                                // Retry corresponds to an outdated Initial; ignore
                                State::Handshake(state)
                            }
                            None => {
                                // Received Retry as a server
                                self.events.push_back(Event::ConnectionLost { connection: conn, reason: ConnectionError::HandshakeFailed });
                                State::HandshakeFailed(state::HandshakeFailed {
                                    reason: TransportError::PROTOCOL_VIOLATION,
                                    alert: None,
                                })
                            }
                            Some(_) => {
                                // Send updated ClientHello
                                parse_handshake(state.tls.get_mut(), packet.payload.clone());
                                match state.tls.handshake() {
                                    Err(HandshakeError::WouldBlock(mut tls)) => {
                                        trace!(self.log, "resending ClientHello");
                                        // TODO: Reliable transmit
                                        let mut buf = Vec::<u8>::new();
                                        buf.reserve_exact(MIN_INITIAL_SIZE);
                                        let packet = self.connections[conn.0].get_tx_number() as u32;
                                        encode_long_header(&mut buf, packet::INITIAL, self.connections[conn.0].id, packet);
                                        frame::stream(&mut buf, StreamId(0), None, true, false, &tls.get_mut().take_outgoing());
                                        if buf.len() < MIN_INITIAL_SIZE {
                                            buf.resize(MIN_INITIAL_SIZE, frame::Type::PADDING.into());
                                        }
                                        self.transmit(remote, buf.into());
                                        State::Handshake(state::Handshake { tls, clienthello_packet: Some(packet) })
                                    },
                                    Ok(_) => {
                                        debug!(self.log, "unexpectedly completed handshake in RETRY packet");
                                        self.events.push_back(Event::ConnectionLost { connection: conn, reason: ConnectionError::HandshakeFailed });
                                        State::HandshakeFailed(state::HandshakeFailed {
                                            reason: TransportError::TLS_HANDSHAKE_FAILED,
                                            alert: None,
                                        })
                                    }
                                    Err(HandshakeError::Failure(mut tls)) => {
                                        debug!(self.log, "handshake failed"; "reason" => %tls.error());
                                        self.events.push_back(Event::ConnectionLost { connection: conn, reason: ConnectionError::HandshakeFailed });
                                        State::HandshakeFailed(state::HandshakeFailed {
                                            reason: TransportError::TLS_HANDSHAKE_FAILED,
                                            alert: Some(tls.get_mut().take_outgoing().to_owned().into()),
                                        })
                                    }
                                    Err(HandshakeError::SetupFailure(e)) => {
                                        error!(self.log, "handshake setup failed"; "reason" => %e);
                                        self.events.push_back(Event::ConnectionLost { connection: conn, reason: ConnectionError::InternalError });
                                        State::HandshakeFailed(state::HandshakeFailed {
                                            reason: TransportError::INTERNAL_ERROR,
                                            alert: None,
                                        })
                                    }
                                }
                            }
                        }
                    }
                    Header::Long { ty: packet::HANDSHAKE, .. } => {
                        // Complete handshake (and ultimately send Finished)
                        unimplemented!()
                    }
                    Header::Long { .. } => {
                        self.events.push_back(Event::ConnectionLost { connection: conn, reason: ConnectionError::HandshakeFailed });
                        State::HandshakeFailed(state::HandshakeFailed {
                            reason: TransportError::PROTOCOL_VIOLATION,
                            alert: None,
                        })
                    }
                    Header::VersionNegotiate { .. } => {
                        // TODO: MUST ignore if supported version is listed
                        self.forget(conn);
                        self.events.push_back(Event::ConnectionLost { connection: conn, reason: ConnectionError::VersionMismatch });
                        return; // Connection forgotten, no further processing is useful
                    }
                    // TODO: SHOULD buffer these.
                    Header::Short { .. } => {
                        State::Handshake(state)
                    }
                }
            }
            State::Established(state) => {
                unimplemented!();
                State::Established(state)
            }
            State::HandshakeFailed(state) => {
                // TODO: Switch to close if draining
                unimplemented!()
            }
            State::Draining => State::Draining,
        });

        if !was_closed && self.connections[conn.0].state.as_ref().unwrap().is_closed() {
            self.io.push_back(Io::TimerStart {
                connection: conn,
                timer: Timer::Close,
                time: now + 3 * self.connections[conn.0].rto(&self.config),
            });
        }

        // Send CONNECTION_CLOSE if necessary
        match self.connections[conn.0].state.as_ref().unwrap() {
            &State::HandshakeFailed(_) => {
                unimplemented!()
            }
            _ => {}
        }
    }

    pub fn timeout(&mut self, now: u64, conn: ConnectionHandle, timer: Timer) {
        match timer {
            Timer::Close => {
                self.forget(conn);
            }
            Timer::LossDetection => {
                let in_handshake = match self.connections[conn.0].state { Some(State::Handshake(_)) => true, _ => false };
                if in_handshake && !self.connections[conn.0].sent_packets.is_empty() {
                    unimplemented!(); // TODO: Retransmit all of stream 0?
                    self.connections[conn.0].handshake_count += 1;
                } else if self.connections[conn.0].loss_time != 0 {
                    // Early retransmit or Time Loss Detection
                    let largest = self.connections[conn.0].largest_acked_packet;
                    self.connections[conn.0].detect_lost_packets(&self.config, now, largest);
                } else if self.connections[conn.0].tlp_count < self.config.max_tlps {
                    // Tail Loss Probe.
                    unimplemented!(); // TODO: Send one packet?
                    self.connections[conn.0].tlp_count += 1;
                } else {
                    // RTO
                    if self.connections[conn.0].rto_count == 0 {
                        self.connections[conn.0].largest_sent_before_rto = self.connections[conn.0].largest_sent_packet;
                    }
                    unimplemented!(); // TODO: Send two packets?
                    self.connections[conn.0].rto_count += 1;
                }
                let alarm = self.connections[conn.0].compute_loss_detection_alarm(&self.config, in_handshake);
                if alarm != u64::max_value() {
                    self.io.push_back(Io::TimerStart {
                        connection: conn,
                        timer: Timer::LossDetection,
                        time: alarm,
                    });
                }
            }
        }
    }

    fn forget(&mut self, conn: ConnectionHandle) {
        self.connection_ids.remove(&self.connections[conn.0].id);
        self.connections.remove(conn.0);
    }
}

fn encode_long_header(buf: &mut Vec<u8>, ty: u8, id: ConnectionId, packet: u32) {
    buf.put_u8(0b10000000 | ty);
    buf.put_u64::<BigEndian>(id.0);
    buf.put_u32::<BigEndian>(VERSION);
    buf.put_u32::<BigEndian>(packet)
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
struct ConnectionId(u64);

impl Rand for ConnectionId {
    fn rand<R: Rng>(rng: &mut R) -> Self { ConnectionId(rng.gen()) }
}

struct Connection {
    id: ConnectionId,
    state: Option<State>,
    tx_packet_number: u64,
    streams: HashMap<StreamId, Stream>,
    /// Packets we haven't yet acknowledged
    pending_acks: Vec<u64>,
    /// Acks we've sent which haven't been acked in turn
    unconfirmed_acks: HashMap<u64, Vec<u64>>,
    /// Present iff we're the client
    reset_token: Option<[u8; 16]>,

    //
    // Loss Detection
    // 

    /// The number of times the handshake packets have been retransmitted without receiving an ack.
    handshake_count: u32,
    /// The number of times a tail loss probe has been sent without receiving an ack.
    tlp_count: u32,
    /// The number of times an rto has been sent without receiving an ack.
    rto_count: u32,
    /// The largest delta between the largest acked retransmittable packet and a packet containing retransmittable frames before it’s declared lost.
    reordering_threshold: u32,
    /// The time at which the next packet will be considered lost based on early transmit or exceeding the reordering window in time.
    loss_time: u64,
    /// The most recent RTT measurement made when receiving an ack for a previously unacked packet. μs
    latest_rtt: u64,
    /// The smoothed RTT of the connection, computed as described in RFC6298. μs
    smoothed_rtt: u64,
    /// The RTT variance, computed as described in RFC6298
    rttvar: u64,
    /// The minimum RTT seen in the connection, ignoring ack delay.
    min_rtt: u64,
    /// The maximum ack delay in an incoming ACK frame for this connection.
    ///
    /// Excludes ack delays for ack only packets and those that create an RTT sample less than min_rtt.
    max_ack_delay: u64,
    /// The last packet number sent prior to the first retransmission timeout.
    largest_sent_before_rto: u64,
    /// The time the most recently sent packet was sent.
    time_of_last_sent_packet: u64,
    /// The packet number of the most recently sent packet.
    largest_sent_packet: u64,
    /// The largest packet number acknowledged in an ACK frame.
    largest_acked_packet: u64,
    /// Transmitted but not acked
    sent_packets: BTreeMap<u64, SentPacket>,
    /// Number of sent_packets that aren't ack-only
    retransmittable_outstanding: u64,

    //
    // Congestion Control
    //

    /// The sum of the size in bytes of all sent packets that contain at least one retransmittable or PADDING frame, and
    /// have not been acked or declared lost.
    ///
    /// The size does not include IP or UDP overhead. Packets only containing ACK frames do not count towards
    /// byte_in_flight to ensure congestion control does not impede congestion feedback.
    bytes_in_flight: u64,
    /// Maximum number of bytes in flight that may be sent.
    congestion_window: u64,
    /// The largest packet number sent when QUIC detects a loss. When a larger packet is acknowledged, QUIC exits recovery.
    end_of_recovery: u64,
    /// Slow start threshold in bytes. When the congestion window is below ssthresh, the mode is slow start and the
    /// window grows by the number of bytes acknowledged.
    ssthresh: u64,
}

#[derive(Debug, Clone)]
struct SentPacket {
    time: u64,
    bytes: Option<u16>,
    max_stream_data: bool,
    max_data: bool,
    max_stream_id: bool,
    ack: bool,
    new_connection_id: Option<ConnectionId>,
    stream: Vec<frame::Stream>,
}

impl SentPacket {
    fn ack_only(&self) -> bool { self.bytes.is_none() }
}

impl Connection {
    fn new(id: ConnectionId, tx_packet_number: u64, config: &Config) -> Self {
        let mut streams = HashMap::with_capacity(1);
        streams.insert(StreamId(0), Stream::new());
        Self {
            id, tx_packet_number, streams,
            state: None,
            pending_acks: Vec::new(),
            unconfirmed_acks: HashMap::new(),
            reset_token: None,

            handshake_count: 0,
            tlp_count: 0,
            rto_count: 0,
            reordering_threshold: if config.using_time_loss_detection { u32::max_value() } else { config.reordering_threshold },
            loss_time: 0,
            latest_rtt: 0,
            smoothed_rtt: 0,
            rttvar: 0,
            min_rtt: 0,
            max_ack_delay: 0,
            largest_sent_before_rto: 0,
            time_of_last_sent_packet: 0,
            largest_sent_packet: 0,
            largest_acked_packet: 0,
            sent_packets: BTreeMap::new(),
            retransmittable_outstanding: 0,

            bytes_in_flight: 0,
            congestion_window: config.initial_window,
            end_of_recovery: 0,
            ssthresh: u64::max_value(),
        }
    }

    fn get_tx_number(&mut self) -> u64 {
        let x = self.tx_packet_number;
        self.tx_packet_number += 1;
        // TODO: Handle packet number overflow gracefully
        assert!(self.tx_packet_number <= 2u64.pow(62)-1);
        x
    }

    /// Returns new loss detection alarm time, if applicable
    fn on_packet_sent(&mut self, config: &Config, now: u64, in_handshake: bool, packet_number: u64, packet: SentPacket) -> Option<u64> {
        self.time_of_last_sent_packet = now;
        self.largest_sent_packet = packet_number;
        let bytes = packet.bytes;
        self.sent_packets.insert(packet_number, packet);
        if let Some(bytes) = bytes {
            self.bytes_in_flight += bytes as u64;
            self.retransmittable_outstanding += 1;
            Some(self.compute_loss_detection_alarm(config, in_handshake))
        } else {
            None
        }
    }

    /// Returns new loss detection alarm time
    fn on_ack_received(&mut self, config: &Config, now: u64, in_handshake: bool, ack: frame::Ack) -> u64 {
        self.largest_acked_packet = ack.largest;
        if let Some(info) = self.sent_packets.get(&ack.largest).cloned() {
            self.latest_rtt = now - info.time;
            self.update_rtt(ack.delay, info.ack_only());
        }
        for packet in ack.packets {
            if let Some(bytes) = self.sent_packets.get(&packet).map(|x| x.bytes) {
                self.on_packet_acked(config, packet, bytes)
            }
        }
        self.detect_lost_packets(config, now, ack.largest);
        self.compute_loss_detection_alarm(config, in_handshake)
    }

    fn update_rtt(&mut self, ack_delay: u64, ack_only: bool) {
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

    fn on_packet_acked(&mut self, config: &Config, packet: u64, bytes: Option<u16>) {
        if let Some(bytes) = bytes {
            // Congestion control
            self.bytes_in_flight -= bytes as u64;
            // Do not increase congestion window in recovery period.
            if !self.in_recovery(packet) {
                if self.congestion_window < self.ssthresh {
                    // Slow start.
                    self.congestion_window += bytes as u64;
                } else {
                    // Congestion avoidance.
                    self.congestion_window += config.default_mss * bytes as u64 / self.congestion_window;
                }
            }
            
            self.retransmittable_outstanding -= 1;
            self.unconfirmed_acks.remove(&packet);
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
        self.sent_packets.remove(&packet);
    }

    fn detect_lost_packets(&mut self, config: &Config, now: u64, largest_acked: u64) {
        self.loss_time = 0;
        let mut lost_packets = Vec::<u64>::new();
        let delay_until_lost;
        let factor = cmp::max(self.latest_rtt, self.smoothed_rtt);
        if config.using_time_loss_detection {
            // factor * (1 + fraction)
            delay_until_lost = factor + (factor * config.time_reordering_fraction as u64) >> 16;
        } else if largest_acked == self.largest_sent_packet {
            // Early retransmit alarm.
            delay_until_lost = (5 * factor) / 4;
        } else {
            delay_until_lost = u64::max_value();
        }
        for (&packet, info) in &self.sent_packets {
            let time_since_sent = now - info.time;
            let delta = largest_acked - packet;
            if time_since_sent > delay_until_lost || delta > self.reordering_threshold as u64 {
                lost_packets.push(packet);
            } else if self.loss_time == 0 && delay_until_lost != u64::max_value() {
                self.loss_time = now + delay_until_lost - time_since_sent;
            }
        }

        if let Some(largest_lost) = lost_packets.last().cloned() {
            for packet in lost_packets {
                let info = self.sent_packets.remove(&packet).unwrap();
                self.bytes_in_flight -= info.bytes.unwrap_or(0) as u64;
                // TODO: Schedule retransmit
                unimplemented!()
            }
            // Start a new recovery epoch if the lost packet is larger than the end of the previous recovery epoch.
            if !self.in_recovery(largest_lost) {
                self.end_of_recovery = self.largest_sent_packet;
                // *= factor
                self.congestion_window = (self.congestion_window * config.loss_reduction_factor as u64) >> 16;
                self.congestion_window = cmp::max(self.congestion_window, config.minimum_window);
                self.ssthresh = self.congestion_window;
            }
        }
    }

    fn in_recovery(&self, packet: u64) -> bool { packet <= self.end_of_recovery }

    fn compute_loss_detection_alarm(&self, config: &Config, in_handshake: bool) -> u64 {
        if self.retransmittable_outstanding == 0 {
            return u64::max_value();
        }

        let mut alarm_duration: u64;
        if in_handshake && !self.sent_packets.is_empty() {
            // Handshake retransmission alarm.
            if self.smoothed_rtt == 0 {
                alarm_duration = 2 * config.default_initial_rtt;
            } else {
                alarm_duration = 2 * self.smoothed_rtt;
            }
            alarm_duration = cmp::max(alarm_duration + self.max_ack_delay,
                                      config.min_tlp_timeout);
            alarm_duration = alarm_duration * 2u64.pow(self.handshake_count);
        } else if self.loss_time != 0 {
            // Early retransmit timer or time loss detection.
            alarm_duration = self.loss_time - self.time_of_last_sent_packet;
        } else if self.tlp_count != config.max_tlps {
            // Tail Loss Probe
            alarm_duration = cmp::max((3 * self.smoothed_rtt) / 2 + self.max_ack_delay,
                                      config.min_tlp_timeout);
        } else {
            // RTO alarm
            alarm_duration = self.smoothed_rtt + 4 * self.rttvar + self.max_ack_delay;
            alarm_duration = cmp::max(alarm_duration, config.min_rto_timeout);
            alarm_duration = alarm_duration * 2u64.pow(self.rto_count);
        }
        self.time_of_last_sent_packet + alarm_duration
    }

    /// Retransmit time-out
    fn rto(&self, config: &Config) -> u64 {
        let computed = self.smoothed_rtt + 4 * self.rttvar + self.max_ack_delay;
        cmp::max(computed, config.min_rto_timeout) * 2u64.pow(self.rto_count)
    }
}

struct Stream {
}

impl Stream {
    fn new() -> Self { Self {} }
}

#[derive(Debug, Copy, Clone)]
enum Header {
    Long {
        ty: u8,
        id: ConnectionId,
        number: u32,
    },
    Short {
        id: Option<ConnectionId>,
        number: PacketNumber,
    },
    VersionNegotiate {
        id: ConnectionId
    }
}

#[derive(Debug, Copy, Clone)]
enum PacketNumber {
    U8(u8),
    U16(u16),
    U32(u32),
}

impl PacketNumber {
    fn ty(&self) -> u8 {
        use self::PacketNumber::*;
        match *self {
            U8(_) => 0x1F,
            U16(_) => 0x1E,
            U32(_) => 0x1D,
        }
    }

    pub fn encode<W: BufMut>(&self, w: &mut W) {
        use self::PacketNumber::*;
        match *self {
            U8(x) => w.put_u8(x),
            U16(x) => w.put_u16::<BigEndian>(x),
            U32(x) => w.put_u32::<BigEndian>(x),
        }
    }
}

impl Header {
    pub fn encode<W: BufMut>(&self, w: &mut W) {
        use self::Header::*;
        match *self {
            Long { ty, id, number } => {
                w.put_u8(0b10000000 | ty);
                w.put_u64::<BigEndian>(id.0);
                w.put_u32::<BigEndian>(VERSION);
                w.put_u32::<BigEndian>(number)
            }
            Short { id, number} => {
                if let Some(x) = id {
                    w.put_u8(number.ty() | 0x40);
                    w.put_u64::<BigEndian>(x.0);
                } else {
                    w.put_u8(number.ty());
                }
                number.encode(w);
            }
            VersionNegotiate { id } => {
                w.put_u8(0x80);
                w.put_u64::<BigEndian>(id.0);
                w.put_u32::<BigEndian>(0);
            }
        }
    }
}

struct Packet {
    header: Header,
    payload: Bytes,
}

#[derive(Copy, Clone, Debug, Fail)]
enum HeaderError {
    #[fail(display = "unsupported version")]
    UnsupportedVersion(ConnectionId),
    #[fail(display = "invalid header")]
    InvalidHeader,
}

impl From<from_bytes::TooShort> for HeaderError {
    fn from(_: from_bytes::TooShort) -> Self { HeaderError::InvalidHeader }
}

impl Packet {
    fn decode(mut packet: Bytes) -> ::std::result::Result<Self, HeaderError> {
        let ty = packet.take::<u8>()?;
        let long = ty & 0x80 != 0;
        let ty = ty & !0x80;
        if long {
            let id = ConnectionId(packet.take()?);
            let version: u32 = packet.take()?;
            Ok(match version {
                0 => Packet {
                    header: Header::VersionNegotiate { id },
                    payload: packet,
                },
                VERSION => Packet {
                    header: Header::Long { ty, id, number: packet.take()? },
                    payload: packet,
                },
                _ => return Err(HeaderError::UnsupportedVersion(id)),
            })
        } else {
            let id = if ty & 0x40 == 0 { Some(ConnectionId(packet.take()?)) } else { None };
            let number = match ty & 0b00011111 {
                0x1F => PacketNumber::U8(packet.take::<u8>()?),
                0x1E => PacketNumber::U16(packet.take::<u16>()?),
                0x1D => PacketNumber::U32(packet.take::<u32>()?),
                _ => { return Err(HeaderError::InvalidHeader); }
            };
            Ok(Packet {
                header: Header::Short { id, number },
                payload: packet
            })
        }
    }
}

enum State {
    Handshake(state::Handshake),
    Established(state::Established),
    HandshakeFailed(state::HandshakeFailed),
    Draining,
}

impl State {
    pub fn is_closed(&self) -> bool {
        match *self {
            State::HandshakeFailed(_) => true,
            State::Draining => true,
            _ => false,
        }
    }
}

mod state {
    use super::*;

    pub struct Handshake {
        pub tls: MidHandshakeSslStream<MemoryStream>,
        pub clienthello_packet: Option<u32>, // present iff client
    }

    pub struct Established {
        pub tls: SslStream<MemoryStream>,
    }

    pub struct HandshakeFailed { // Closing
        pub reason: TransportError,
        pub alert: Option<Box<[u8]>>,
    }
}

struct CookieFactory {
    mac_key: [u8; 64]
}

const COOKIE_MAC_BYTES: usize = 64;

// remote ip and port are taken from the underlying transport
#[derive(Serialize, Deserialize)]
struct Cookie {}

impl CookieFactory {
    fn new(mac_key: [u8; 64]) -> Self {
        Self { mac_key }
    }

    fn generate(&self, conn: &ConnectionInfo, out: &mut [u8]) -> usize {
        let cookie = Cookie {};
        let cap = out.len();
        let (len, out) = {
            let mut cursor = io::Cursor::new(out);
            bincode::serialize_into(&mut cursor, &cookie, bincode::Bounded((cap - COOKIE_MAC_BYTES) as u64)).unwrap();
            (cursor.position() as usize, cursor.into_inner())
        };
        let mac = self.generate_mac(conn, &out[0..len]);
        out[len..len+COOKIE_MAC_BYTES].copy_from_slice(&mac);
        len + COOKIE_MAC_BYTES
    }

    fn generate_mac(&self, conn: &ConnectionInfo, data: &[u8]) -> [u8; COOKIE_MAC_BYTES] {
        let mut mac = Blake2b::new_keyed(&self.mac_key, COOKIE_MAC_BYTES);
        mac.process(&conn.remote.ip().octets());
        {
            let mut buf = [0; 2];
            BigEndian::write_u16(&mut buf, conn.remote.port());
            mac.process(&buf);
        }
        mac.process(data);
        let mut result = [0; COOKIE_MAC_BYTES];
        mac.variable_result(&mut result).unwrap();
        result
    }

    fn verify(&self, conn: &ConnectionInfo, cookie_data: &[u8]) -> bool {
        if cookie_data.len() < COOKIE_MAC_BYTES { return false; }
        let (cookie_data, mac) = cookie_data.split_at(cookie_data.len() - COOKIE_MAC_BYTES);
        let expected = self.generate_mac(conn, cookie_data);
        if !constant_time_eq(&mac, &expected) { return false; }
        if let Err(_) = bincode::deserialize::<Cookie>(cookie_data) { return false; };
        true
    }
}

fn duration_ms(d: Duration) -> u64 {
    d.as_secs() * 1000 + (d.subsec_nanos() / 1000_000) as u64
}

struct ConnectionInfo {
    id: ConnectionId,
    remote: SocketAddrV6,
}

lazy_static! {
    static ref CONNECTION_INFO_INDEX: ex_data::Index<Ssl, ConnectionInfo> = Ssl::new_ex_index().unwrap();
    static ref TRANSPORT_PARAMS_INDEX: ex_data::Index<Ssl, ::std::result::Result<TransportParameters, ::transport_parameters::Error>>
        = Ssl::new_ex_index().unwrap();
}

#[derive(Debug)]
pub enum Event {
    Connected(ConnectionHandle),
    ConnectionLost {
        connection: ConnectionHandle,
        reason: ConnectionError
    },
}

#[derive(Debug)]
pub enum Io {
    Transmit {
        destination: SocketAddrV6,
        packet: Box<[u8]>,
    },
    TimerStart {
        connection: ConnectionHandle,
        timer: Timer,
        /// Absolute μs
        time: u64,
    },
    TimerStop {
        connection: ConnectionHandle,
        timer: Timer,
    }
}

#[derive(Debug, Copy, Clone)]
pub enum Timer {
    Close,
    LossDetection,
}

#[derive(Debug, Fail)]
pub enum ConnectionError {
    #[fail(display = "peer doesn't implement any supported version")]
    VersionMismatch,
    #[fail(display = "handshake failed")]
    HandshakeFailed,
    #[fail(display = "internal error")]
    InternalError,
}

mod packet {
    pub const INITIAL: u8 = 0x7F;
    pub const RETRY: u8 = 0x7E;
    pub const HANDSHAKE: u8 = 0x7D;
}

/// Forward data from an Initial or Retry packet to a stream for a TLS context
fn parse_handshake(stream: &mut MemoryStream, payload: Bytes) {
    for frame in frame::Iter::new(payload) {
        match frame {
            Frame::Stream(frame::Stream { id: StreamId(0), data, .. }) => {
                stream.extend_incoming(&data[..]);
            }
            _ => {}
        }
    }
}

#[derive(Debug, Clone)]
enum Retransmit {
    Stream(frame::Stream),
    MaxStreamData {
        stream: StreamId,
    },
    MaxData,
    MaxStreamId,
    Ack,
    NewConnectionId(ConnectionId),
}
