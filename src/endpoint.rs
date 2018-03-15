use std::collections::{HashMap, VecDeque, BTreeMap};
use std::{io, cmp, fmt, mem};
use std::net::SocketAddrV6;
use std::sync::Arc;

use bytes::{Buf, BufMut, Bytes, ByteOrder, BigEndian, IntoBuf};
use rand::{distributions, OsRng, Rng, Rand};
use rand::distributions::Sample;
use slab::Slab;
use openssl::ex_data;
use openssl::ssl::{self, SslContext, SslMethod, SslOptions, SslVersion, SslMode, Ssl, SslStream, HandshakeError, MidHandshakeSslStream,
                   SslStreamBuilder, SslAlert, SslRef};
use openssl::pkey::{PKeyRef, Private};
use openssl::x509::X509Ref;
use openssl::hash::MessageDigest;
use openssl::symm::{Cipher, encrypt_aead, decrypt_aead};
use failure::Error;
use blake2::Blake2b;
use digest::{Input, VariableOutput};
use constant_time_eq::constant_time_eq;
use bincode;
use slog::Logger;

use memory_stream::MemoryStream;
use transport_parameters::TransportParameters;
use frame::StreamId;
use coding::{self, BufExt};
use {hkdf, frame, Frame, TransportError, VERSION};

type Result<T> = ::std::result::Result<T, Error>;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct ConnectionHandle(usize);

impl From<ConnectionHandle> for usize { fn from(x: ConnectionHandle) -> usize { x.0 } }

pub struct Config {
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

pub struct ListenConfig<'a> {
    pub private_key: &'a PKeyRef<Private>,
    pub cert: &'a X509Ref,
}

impl Default for Config {
    fn default() -> Self { Self {
        max_tlps: 2,
        reordering_threshold: 3,
        time_reordering_fraction: 0x2000, // 1/8
        using_time_loss_detection: false,
        min_tlp_timeout: 10 * 1000,
        min_rto_timeout: 200 * 1000,
        delayed_ack_timeout: 25 * 1000,
        default_initial_rtt: 100 * 1000,
        
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
    connection_remotes: HashMap<SocketAddrV6, ConnectionHandle>,
    connections: Slab<Connection>,
    config: Config,
    state: PersistentState,
    events: VecDeque<Event>,
    io: VecDeque<Io>,
    listen: bool,
}

const MIN_INITIAL_SIZE: usize = 1200;
const MIN_MTU: u16 = 1232;

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
    pub fn new(log: Logger, config: Config, state: PersistentState, listen: Option<ListenConfig>) -> Result<Self> {
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
                Ok(Some(gen_transport_params(&reset_key, am_server, conn.id)))
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

        if let Some(ref listen) = listen {
            tls.set_private_key(listen.private_key)?;
            tls.set_certificate(listen.cert)?;
            tls.check_private_key()?;
        }

        let tls = tls.build();

        Ok(Self {
            log, rng, config, state, tls,
            initial_packet_number: distributions::Range::new(0, 2u64.pow(32) - 1024),
            connection_ids: HashMap::new(),
            connection_remotes: HashMap::new(),
            connections: Slab::new(),
            events: VecDeque::new(),
            io: VecDeque::new(),
            listen: listen.is_some(),
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
                buf.reserve_exact(LONG_HEADER_SIZE + 4);
                Header::VersionNegotiate { id }.encode(&mut buf);
                buf[0] |= self.rng.gen::<u8>();
                buf.put_u32::<BigEndian>(0x0a1a2a3a); // reserved version
                buf.put_u32::<BigEndian>(VERSION); // supported version
                self.io.push_back(Io::Transmit { destination: remote, packet: buf.into() });
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

        let conn_id = packet.header.id();
        if let Some(id) = conn_id {
            if let Some(&conn) = self.connection_ids.get(&id) {
                self.handle_connected(now, conn, remote, packet);
                return;
            }
            if let Some(&conn) = self.connection_remotes.get(&remote) {
                if self.connections[conn.0].stream0.rx_offset == 0 {
                    // First packet from remote server resets our connection id
                    if self.connections[conn.0].id != id {
                        trace!(self.log, "server updated connection ID"; "old" => %self.connections[conn.0].id, "new" => %id);
                        self.connection_ids.remove(&self.connections[conn.0].id);
                        self.connections[conn.0].id = id;
                        self.connection_ids.insert(id, conn);
                    }
                    self.handle_connected(now, conn, remote, packet);
                    return;
                }
            }
        }

        //
        // Potentially create a new connection
        //

        if !self.listen {
            debug!(self.log, "dropping packet from unrecognized connection"; "header" => ?packet.header);
            return;
        }
        if let Header::Long { ty, id, number } = packet.header {
            // MAY buffer non-initial packets a little for better 0RTT behavior
            if ty == packet::INITIAL && data.len() >= MIN_INITIAL_SIZE {
                self.handle_initial(now, remote, id, number, &packet.header_data, &packet.payload);
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
            (Header::Short { id: conn_id, number: PacketNumber::U8(self.rng.gen()), key_phase: false })
                .encode(&mut buf);
            {
                let start = buf.len();
                buf.resize(start + padding, 0);
                self.rng.fill_bytes(&mut buf[start..start+padding]);
            }
            buf.extend(&reset_token_for(&self.state.reset_key, id));
            self.io.push_back(Io::Transmit { destination: remote, packet: buf.into() });
        }
    }

    pub fn connect(&mut self, now: u64, local: SocketAddrV6, remote: SocketAddrV6) -> Result<ConnectionHandle> {
        let mut tls = Ssl::new(&self.tls)?;
        let id = self.rng.gen();
        tls.set_ex_data(*CONNECTION_INFO_INDEX, ConnectionInfo { id, remote });
        let mut tls = match tls.connect(MemoryStream::new()) {
            Ok(_) => unreachable!(),
            Err(HandshakeError::WouldBlock(tls)) => tls,
            Err(e) => return Err(e.into()),
        };
        let conn = self.add_connection(id, remote, true);
        let packet = self.transmit_handshake(now, conn, remote, &tls.get_mut().take_outgoing());
        self.connections[conn.0].state = Some(State::Handshake(state::Handshake {
            tls, clienthello_packet: Some(packet),
        }));
        Ok(conn)
    }

    fn gen_initial_packet_num(&mut self) -> u32 { self.initial_packet_number.sample(&mut self.rng) as u32 }

    fn add_connection(&mut self, id: ConnectionId, remote: SocketAddrV6, client: bool) -> ConnectionHandle {
        let packet_num = self.gen_initial_packet_num();
        let i = self.connections.insert(Connection::new(id, remote, packet_num.into(), client, &self.config));
        self.connection_ids.insert(id, ConnectionHandle(i));
        self.connection_remotes.insert(remote, ConnectionHandle(i));
        ConnectionHandle(i)
    }

    fn handle_initial(&mut self, now: u64, remote: SocketAddrV6, id: ConnectionId, packet_number: u32, header: &[u8], payload: &[u8]) {
        let crypto = CryptoContext::handshake(id, false);
        let payload = if let Some(x) = crypto.decrypt(packet_number as u64, header, payload) { x.into() } else {
            debug!(self.log, "failed to decrypt initial packet"; "connection" => %id);
            return;
        };
        let mut stream = MemoryStream::new();
        if !parse_initial(&mut stream, payload) { return; } // TODO: Send close?
        let incoming_len = stream.incoming_len() as u64;
        trace!(self.log, "got initial"; "len" => incoming_len);
        let mut tls = Ssl::new(&self.tls).unwrap(); // TODO: is this reliable?
        tls.set_ex_data(*CONNECTION_INFO_INDEX, ConnectionInfo { id, remote });
        let mut tls = SslStreamBuilder::new(tls, stream);
        match tls.stateless() {
            Ok(()) => {
                match tls.accept() {
                    Ok(_) => unreachable!(),
                    Err(HandshakeError::WouldBlock(mut tls)) => {
                        trace!(self.log, "performing handshake"; "connection" => %id);
                        if let Some(params) = tls.ssl().ex_data(*TRANSPORT_PARAMS_INDEX).cloned() {
                            let params = params.expect("transport parameter errors should have aborted the handshake");
                            let conn = self.add_connection(id, remote, false);
                            self.connections[conn.0].stream0_data = frame::StreamAssembler::with_offset(incoming_len);
                            self.transmit_handshake(now, conn, remote, &tls.get_mut().take_outgoing());
                            self.connections[conn.0].state = Some(State::Handshake(state::Handshake {
                                tls, clienthello_packet: None,
                            }));
                            self.connections[conn.0].rx_packet = packet_number as u64;
                        } else {
                            debug!(self.log, "ClientHello missing transport params extension");
                            let n = self.gen_initial_packet_num();
                            self.io.push_back(Io::Transmit {
                                destination: remote,
                                packet: handshake_close(&crypto, id, n, TransportError::TRANSPORT_PARAMETER_ERROR, "missing transport parameters"),
                            });
                        }
                    }
                    Err(HandshakeError::Failure(tls)) => {
                        let code = if let Some(params_err) = tls.ssl().ex_data(*TRANSPORT_PARAMS_INDEX).and_then(|x| x.err()) {
                            debug!(self.log, "received invalid transport parameters"; "connection" => %id, "reason" => %params_err);
                            TransportError::TRANSPORT_PARAMETER_ERROR
                        } else {
                            debug!(self.log, "accept failed"; "reason" => %tls.error());
                            TransportError::TLS_HANDSHAKE_FAILED
                        };
                        let n = self.gen_initial_packet_num();
                        self.io.push_back(Io::Transmit {
                            destination: remote,
                            packet: handshake_close(&crypto, id, n, code, ""),
                        });
                    }
                    Err(HandshakeError::SetupFailure(e)) => {
                        debug!(self.log, "accept failed"; "reason" => %e);
                        let n = self.gen_initial_packet_num();
                        self.io.push_back(Io::Transmit {
                            destination: remote,
                            packet: handshake_close(&crypto, id, n, TransportError::INTERNAL_ERROR, ""),
                        });
                    }
                }
            }
            Err(None) => {
                trace!(self.log, "sending HelloRetryRequest"; "connection" => %id);
                let data = tls.get_mut().take_outgoing();
                let mut buf = Vec::<u8>::new();
                buf.reserve_exact(LONG_HEADER_SIZE + data.len());
                encode_long_header(&mut buf, packet::RETRY, id, packet_number);
                frame::Stream {
                    id: StreamId(0),
                    offset: 0,
                    fin: false,
                    data: data,
                }.encode(false, &mut buf);
                let payload = crypto.encrypt(packet_number as u64, &buf[0..LONG_HEADER_SIZE], &buf[LONG_HEADER_SIZE..]);
                debug_assert_eq!(payload.len(), buf.len() - LONG_HEADER_SIZE + AEAD_TAG_SIZE);
                buf.truncate(LONG_HEADER_SIZE);
                buf.extend_from_slice(&payload);
                self.io.push_back(Io::Transmit { destination: remote, packet: buf.into() });
            }
            Err(Some(e)) => {
                debug!(self.log, "stateless handshake failed"; "connection" => %id, "reason" => %e);
                let n = self.gen_initial_packet_num();
                self.io.push_back(Io::Transmit {
                    destination: remote,
                    packet: handshake_close(&crypto, id, n, TransportError::TLS_HANDSHAKE_FAILED, ""),
                });
            }
        }
    }

    fn handle_connected_inner(&mut self, now: u64, conn: ConnectionHandle, remote: SocketAddrV6, packet: Packet, state: State) -> State { match state {
        State::Handshake(mut state) => {
            match packet.header {
                Header::Long { ty: packet::RETRY, number, id: conn_id, .. } => {
                    if state.clienthello_packet.is_none() {
                        // Received Retry as a server
                        debug!(self.log, "received retry from client"; "connection" => %conn_id);
                        self.events.push_back(Event::ConnectionLost { connection: conn, reason: TransportError::PROTOCOL_VIOLATION.into() });
                        State::HandshakeFailed(state::HandshakeFailed {
                            reason: TransportError::PROTOCOL_VIOLATION,
                            alert: None,
                        })
                    } else if state.clienthello_packet.unwrap() > number {
                        // Retry corresponds to an outdated Initial; must be a duplicate, so ignore it
                        State::Handshake(state)
                    } else if self.connections[conn.0].stream0.rx_offset != 0 {
                        // Received current Retry after Handshake
                        debug!(self.log, "received seemingly-valid retry following handshake packets");
                        self.events.push_back(Event::ConnectionLost { connection: conn, reason: TransportError::PROTOCOL_VIOLATION.into() });
                        State::HandshakeFailed(state::HandshakeFailed {
                            reason: TransportError::PROTOCOL_VIOLATION,
                            alert: None,
                        })
                    } else if !self.connections[conn.0].decrypt(number as u64, &packet.header_data, &packet.payload)
                        .map_or(false, |x| parse_initial(state.tls.get_mut(), x.into()))
                    {
                        debug!(self.log, "invalid retry payload");
                        self.events.push_back(Event::ConnectionLost { connection: conn, reason: TransportError::PROTOCOL_VIOLATION.into() });
                        State::HandshakeFailed(state::HandshakeFailed {
                            reason: TransportError::PROTOCOL_VIOLATION,
                            alert: None,
                        })
                    } else { match state.tls.handshake() {
                        Err(HandshakeError::WouldBlock(mut tls)) => {
                            trace!(self.log, "resending ClientHello");
                            let id = self.connections[conn.0].id;
                            // Discard transport state
                            self.connections[conn.0] = Connection::new(
                                id, remote, self.initial_packet_number.sample(&mut self.rng).into(), true, &self.config
                            );
                            self.connections[conn.0].client = true;
                            // Send updated ClientHello
                            let packet = self.transmit_handshake(now, conn, remote, &tls.get_mut().take_outgoing());
                            State::Handshake(state::Handshake { tls, clienthello_packet: Some(packet) })
                        },
                        Ok(_) => {
                            debug!(self.log, "unexpectedly completed handshake in RETRY packet");
                            self.events.push_back(Event::ConnectionLost { connection: conn, reason: TransportError::PROTOCOL_VIOLATION.into() });
                            State::HandshakeFailed(state::HandshakeFailed {
                                reason: TransportError::PROTOCOL_VIOLATION,
                                alert: None,
                            })
                        }
                        Err(HandshakeError::Failure(mut tls)) => {
                            debug!(self.log, "handshake failed"; "reason" => %tls.error());
                            self.events.push_back(Event::ConnectionLost { connection: conn, reason: TransportError::TLS_HANDSHAKE_FAILED.into() });
                            State::HandshakeFailed(state::HandshakeFailed {
                                reason: TransportError::TLS_HANDSHAKE_FAILED,
                                alert: Some(tls.get_mut().take_outgoing().to_owned().into()),
                            })
                        }
                        Err(HandshakeError::SetupFailure(e)) => {
                            error!(self.log, "handshake setup failed"; "reason" => %e);
                            self.events.push_back(Event::ConnectionLost { connection: conn, reason: TransportError::INTERNAL_ERROR.into() });
                            State::HandshakeFailed(state::HandshakeFailed {
                                reason: TransportError::INTERNAL_ERROR,
                                alert: None,
                            })
                        }
                    }
                    }
                }
                Header::Long { ty: packet::HANDSHAKE, id, number, .. } => {
                    let payload = if let Some(x) = self.connections[conn.0].decrypt(number as u64, &packet.header_data, &packet.payload) { x } else {
                        debug!(self.log, "failed to decrypt handshake packet");
                        return State::Handshake(state);
                    };
                    self.connections[conn.0].on_packet_authenticated(number as u64);
                    // Complete handshake (and ultimately send Finished)
                    for frame in frame::Iter::new(payload.into()) {
                        match frame {
                            Frame::Padding => {}
                            Frame::Stream(frame::Stream { id: StreamId(0), offset, data, .. }) => {
                                self.connections[conn.0].stream0_data.insert(offset, data);
                            }
                            Frame::Stream(frame::Stream { .. }) => {
                                debug!(self.log, "non-stream-0 frame in handshake");
                                self.events.push_back(Event::ConnectionLost { connection: conn, reason: TransportError::PROTOCOL_VIOLATION.into() });
                                return State::HandshakeFailed(state::HandshakeFailed {
                                    reason: TransportError::PROTOCOL_VIOLATION,
                                    alert: None,
                                });
                            }
                            Frame::Ack(ack) => {
                                self.on_ack_received(now, conn, true, ack);
                            }
                            Frame::ConnectionClose(reason) => {
                                self.events.push_back(Event::ConnectionLost { connection: conn, reason: ConnectionError::ConnectionClosed { reason } });
                                return State::Draining;
                            }
                            Frame::ApplicationClose(reason) => {
                                self.events.push_back(Event::ConnectionLost { connection: conn, reason: ConnectionError::ApplicationClosed { reason } });
                                return State::Draining;
                            }
                            _ => {
                                debug!(self.log, "invalid frame type in handshake");
                                self.events.push_back(Event::ConnectionLost { connection: conn, reason: TransportError::PROTOCOL_VIOLATION.into() });
                                return State::HandshakeFailed(state::HandshakeFailed {
                                    reason: TransportError::PROTOCOL_VIOLATION,
                                    alert: None,
                                });
                            }
                        }
                    }
                    while let Some(segment) = self.connections[conn.0].stream0_data.next() {
                        self.connections[conn.0].stream0.rx_offset += segment.len() as u64;
                        state.tls.get_mut().extend_incoming(&segment);
                    }
                    match state.tls.handshake() {
                        Ok(mut tls) => {
                            trace!(self.log, "established"; "connection" => %id);
                            // FIXME: Use protected packet!
                            self.transmit_handshake(now, conn, remote, &tls.get_mut().take_outgoing());
                            self.events.push_back(Event::Connected(conn));
                            self.connections[conn.0].crypto = CryptoContext::established(tls.ssl(), self.connections[conn.0].client);
                            State::Established(state::Established { tls, key_phase: false })
                        }
                        Err(HandshakeError::WouldBlock(mut tls)) => {
                            trace!(self.log, "handshake ongoing"; "connection" => %id);
                            {
                                let response = tls.get_mut().take_outgoing();
                                if !response.is_empty() {
                                    self.transmit_handshake(now, conn, remote, &response);
                                }
                            }
                            State::Handshake(state::Handshake { tls, clienthello_packet: state.clienthello_packet })
                        }
                        Err(HandshakeError::Failure(mut tls)) => {
                            debug!(self.log, "handshake failed"; "connection" => %id, "reason" => %tls.error());
                            self.events.push_back(Event::ConnectionLost { connection: conn, reason: TransportError::TLS_HANDSHAKE_FAILED.into() });
                            State::HandshakeFailed(state::HandshakeFailed {
                                reason: TransportError::TLS_HANDSHAKE_FAILED,
                                alert: Some(tls.get_mut().take_outgoing().to_owned().into()),
                            })
                        }
                        Err(HandshakeError::SetupFailure(e)) => {
                            error!(self.log, "handshake failed"; "connection" => %id, "reason" => %e);
                            self.events.push_back(Event::ConnectionLost { connection: conn, reason: TransportError::INTERNAL_ERROR.into() });
                            State::HandshakeFailed(state::HandshakeFailed {
                                reason: TransportError::INTERNAL_ERROR,
                                alert: None,
                            })
                        }
                    }
                }
                Header::Long { ty, .. } => {
                    debug!(self.log, "unexpected packet type"; "type" => ty);
                    self.events.push_back(Event::ConnectionLost { connection: conn, reason: TransportError::PROTOCOL_VIOLATION.into() });
                    State::HandshakeFailed(state::HandshakeFailed {
                        reason: TransportError::PROTOCOL_VIOLATION,
                        alert: None,
                    })
                }
                Header::VersionNegotiate { id } => {
                    let mut payload = io::Cursor::new(&packet.payload[..]);
                    if packet.payload.len() % 4 != 0 {
                        debug!(self.log, "malformed version negotiation"; "connection" => %id);
                        self.events.push_back(Event::ConnectionLost { connection: conn, reason: TransportError::PROTOCOL_VIOLATION.into() });
                        return State::HandshakeFailed(state::HandshakeFailed {
                            reason: TransportError::PROTOCOL_VIOLATION,
                            alert: None,
                        });
                    }
                    while payload.has_remaining() {
                        let version = payload.get_u32::<BigEndian>();
                        if version == VERSION {
                            // Our version is supported, so this packet is spurious
                            return State::Handshake(state);
                        }
                    }
                    debug!(self.log, "remote doesn't support our version");
                    self.events.push_back(Event::ConnectionLost { connection: conn, reason: ConnectionError::VersionMismatch });
                    State::Draining
                }
                // TODO: SHOULD buffer these.
                Header::Short { .. } => {
                    State::Handshake(state)
                }
            }
        }
        State::Established(mut state) => {
            let (key_phase, number) = match packet.header {
                Header::Short { key_phase, number, .. } => (key_phase, number),
                _ => {
                    debug!(self.log, "ignoring unprotected packet");
                    return State::Established(state);
                }
            };
            let number = number.expand(self.connections[conn.0].rx_packet);
            if key_phase != state.key_phase {
                let id = self.connections[conn.0].id;
                if number <= self.connections[conn.0].rx_packet {
                    warn!(self.log, "got illegal key update"; "connection" => %id);
                    self.events.push_back(Event::ConnectionLost { connection: conn, reason: TransportError::PROTOCOL_VIOLATION.into() });
                    return State::Closed(state::Closed {
                        tls: state.tls,
                        reason: TransportError::PROTOCOL_VIOLATION.into(),
                    });
                }
                trace!(self.log, "updating keys"; "connection" => %id);
                self.connections[conn.0].update_keys(number);
                state.key_phase = key_phase;
            }
            let payload = if let Some(x) = self.connections[conn.0].decrypt(number, &packet.header_data, &packet.payload) { x } else {
                debug!(self.log, "failed to decrypt packet");
                return State::Established(state);
            };
            self.connections[conn.0].on_packet_authenticated(number);
            for frame in frame::Iter::new(payload.into()) {
                match frame {
                    Frame::Stream(frame::Stream { id: StreamId(0), offset, data, .. }) => {
                        self.connections[conn.0].stream0_data.insert(offset, data);
                    }
                    Frame::Stream(stream) => {
                        // TODO: Stream state management
                        self.events.push_back(Event::Recv(stream));
                    }
                    Frame::Ack(ack) => {
                        self.on_ack_received(now, conn, false, ack);
                    }
                    Frame::Padding => {}
                    Frame::ConnectionClose(reason) => {
                        self.events.push_back(Event::ConnectionLost { connection: conn, reason: ConnectionError::ConnectionClosed { reason } });
                        return State::Draining;
                    }
                    Frame::ApplicationClose(reason) => {
                        self.events.push_back(Event::ConnectionLost { connection: conn, reason: ConnectionError::ApplicationClosed { reason } });
                        return State::Draining;
                    }
                    _ => unimplemented!(),
                }
            }
            while let Some(segment) = self.connections[conn.0].stream0_data.next() {
                self.connections[conn.0].stream0.rx_offset += segment.len() as u64;
                state.tls.get_mut().extend_incoming(&segment);
            }
            if state.tls.get_ref().incoming_len() != 0 {
                match state.tls.ssl_read(&mut [0; 2048]) {
                    Err(ref e) if e.code() == ssl::ErrorCode::WANT_READ => {}
                    Ok(_) => {} // Padding
                    Err(ref e) if e.code() == ssl::ErrorCode::SSL => {
                        debug!(self.log, "TLS error"; "error" => %e);
                        self.events.push_back(Event::ConnectionLost { connection: conn, reason: TransportError::TLS_FATAL_ALERT_RECEIVED.into() });
                        return State::Closed(state::Closed {
                            tls: state.tls,
                            reason: TransportError::TLS_FATAL_ALERT_RECEIVED.into(),
                        });
                    }
                    Err(ref e) if e.code() == ssl::ErrorCode::ZERO_RETURN => {
                        debug!(self.log, "TLS session terminated unexpectedly");
                        self.events.push_back(Event::ConnectionLost { connection: conn, reason: TransportError::PROTOCOL_VIOLATION.into() });
                        return State::Closed(state::Closed {
                            tls: state.tls,
                            reason: TransportError::PROTOCOL_VIOLATION.into(),
                        });
                    }
                    Err(e) => {
                        error!(self.log, "unexpected TLS error"; "error" => %e);
                        self.events.push_back(Event::ConnectionLost { connection: conn, reason: TransportError::INTERNAL_ERROR.into() });
                        return State::Closed(state::Closed {
                            tls: state.tls,
                            reason: TransportError::INTERNAL_ERROR.into(),
                        });
                    }
                }
            }
            State::Established(state)
        }
        State::HandshakeFailed(state) => {
            for frame in frame::Iter::new(packet.payload) {
                match frame {
                    Frame::ConnectionClose(_) | Frame::ApplicationClose(_) => { return State::Draining; }
                    _ => {}
                }
            }
            State::HandshakeFailed(state)
        }
        State::Closed(state) => {
            for frame in frame::Iter::new(packet.payload) {
                match frame {
                    Frame::ConnectionClose(_) | Frame::ApplicationClose(_) => { return State::Draining; }
                    _ => {}
                }
            }
            State::Closed(state)
        }
        State::Draining => State::Draining,
    }}

    fn handle_connected(&mut self, now: u64, conn: ConnectionHandle, remote: SocketAddrV6, packet: Packet) {
        trace!(self.log, "connection got packet"; "id" => %self.connections[conn.0].id, "len" => packet.payload.len());
        let was_closed = self.connections[conn.0].state.as_ref().unwrap().is_closed();

        // State transitions
        let state = self.connections[conn.0].state.take().unwrap();
        let state = self.handle_connected_inner(now, conn, remote, packet, state);

        // Close timer
        if !was_closed && state.is_closed() {
            self.io.push_back(Io::TimerStart {
                connection: conn,
                timer: Timer::Close,
                time: now + 3 * self.connections[conn.0].rto(&self.config),
            });
        }

        // Transmit CONNECTION_CLOSE if necessary
        match &state {
            &State::HandshakeFailed(ref state) => {
                let n = self.connections[conn.0].get_tx_number();
                self.io.push_back(Io::Transmit {
                    destination: remote,
                    packet: handshake_close(&self.connections[conn.0].crypto, self.connections[conn.0].id, n as u32,
                                            state.reason, ""),
                });
            }
            &State::Closed(_) => {
                unimplemented!()
            }
            _ => {}
        }
        self.connections[conn.0].state = Some(state);

        // TODO: Send frames that were formerly blocked by congestion
    }

    pub fn timeout(&mut self, now: u64, conn: ConnectionHandle, timer: Timer) {
        match timer {
            Timer::Close => {
                self.connection_ids.remove(&self.connections[conn.0].id);
                self.connection_remotes.remove(&self.connections[conn.0].remote);
                self.connections.remove(conn.0);
            }
            Timer::LossDetection => {
                let in_handshake = match self.connections[conn.0].state { Some(State::Handshake(_)) => true, _ => false };
                if in_handshake {
                    debug_assert!(!self.connections[conn.0].sent_packets.is_empty());
                    // Retransmit all
                    trace!(self.log, "retransmitting handshake"; "connection" => %self.connections[conn.0].id);
                    for packet in self.connections[conn.0].handshake_retransmit(&self.config, now) {
                        self.io.push_back(Io::Transmit { destination: self.connections[conn.0].remote, packet });
                    }
                    self.connections[conn.0].handshake_count += 1;
                } else if self.connections[conn.0].loss_time != 0 {
                    // Early retransmit or Time Loss Detection
                    let largest = self.connections[conn.0].largest_acked_packet;
                    self.connections[conn.0].detect_lost_packets(&self.config, now, largest);
                    self.retransmit(conn);
                } else if self.connections[conn.0].tlp_count < self.config.max_tlps {
                    // Tail Loss Probe.
                    unimplemented!(); // TODO: Send one packet
                    self.connections[conn.0].tlp_count += 1;
                } else {
                    // RTO
                    if self.connections[conn.0].rto_count == 0 {
                        self.connections[conn.0].largest_sent_before_rto = self.connections[conn.0].largest_sent_packet;
                    }
                    unimplemented!(); // TODO: Send two packets
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

    fn transmit_handshake(&mut self, now: u64, conn: ConnectionHandle, destination: SocketAddrV6, messages: &[u8]) -> u32 {
        let mut first_packet_number = None;
        debug_assert!(!messages.is_empty());
        let mut cursor = 0;
        while cursor != messages.len() {
            let frame_header_size = if self.connections[conn.0].stream0.tx_offset < 2u64.pow(14) { 3 } else { 5 };
            let overhead = LONG_HEADER_SIZE + frame_header_size + AEAD_TAG_SIZE; // packet header + frame header + aead tag
            let bound = cmp::min(self.connections[conn.0].mtu as usize - overhead, messages.len() - cursor);
            let segment = &messages[cursor..cursor+bound];
            cursor += bound;
            let mut buf = Vec::<u8>::new();
            let packet_number = self.connections[conn.0].get_tx_number() as u32;
            if first_packet_number.is_none() {
                first_packet_number = Some(packet_number);
            }
            let tx_offset = {
                let x = &mut self.connections[conn.0].stream0.tx_offset;
                let initial = *x;
                *x += segment.len() as u64;
                initial
            };
            let ty = if self.connections[conn.0].client && tx_offset == 0 { packet::INITIAL } else { packet::HANDSHAKE };
            encode_long_header(&mut buf, ty, self.connections[conn.0].id, packet_number);
            let frame = frame::Stream {
                id: StreamId(0),
                offset: tx_offset,
                fin: false,
                data: Bytes::from(segment),
            };
            if ty == packet::INITIAL && buf.len() < MIN_INITIAL_SIZE - AEAD_TAG_SIZE {
                frame.encode(true, &mut buf);
                buf.resize(MIN_INITIAL_SIZE - AEAD_TAG_SIZE, frame::Type::PADDING.into());
            } else {
                // Only need length tag if we're adding padding
                frame.encode(false, &mut buf);
            }
            let payload = self.connections[conn.0].crypto.encrypt(packet_number as u64, &buf[0..LONG_HEADER_SIZE], &buf[LONG_HEADER_SIZE..]);
            debug_assert_eq!(payload.len(), buf.len() - LONG_HEADER_SIZE + AEAD_TAG_SIZE);
            buf.truncate(LONG_HEADER_SIZE);
            buf.extend_from_slice(&payload);

            let bytes = buf.len() as u16;
            self.io.push_back(Io::Transmit { destination, packet: buf.into() });
            self.on_packet_sent(now, conn, true, packet_number as u64, SentPacket {
                time: now,
                bytes,
                retransmits: Retransmits::from_stream(frame)
            });
        }
        first_packet_number.unwrap()
    }

    fn on_packet_sent(&mut self, now: u64, conn: ConnectionHandle, in_handshake: bool, packet_number: u64, packet: SentPacket) {
        if let Some(time) = self.connections[conn.0].on_packet_sent(&self.config, now, in_handshake, packet_number, packet) {
            self.io.push_back(Io::TimerStart {
                connection: conn,
                timer: Timer::LossDetection,
                time
            });
        }
    }

    fn on_ack_received(&mut self, now: u64, conn: ConnectionHandle, in_handshake: bool, ack: frame::Ack) {
        let time = self.connections[conn.0].on_ack_received(&self.config, now, in_handshake, ack);
        self.retransmit(conn);  // Congestion window may have opened and/or new packets may have been deemed lost
        self.io.push_back(Io::TimerStart {
            connection: conn,
            timer: Timer::LossDetection,
            time,
        });
    }

    // Transmit as much lost data as the congestion window allows
    fn retransmit(&mut self, conn: ConnectionHandle) {
        unimplemented!()
    }
}

fn encode_long_header<W: BufMut>(buf: &mut W, ty: u8, id: ConnectionId, packet: u32) {
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

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}


struct Connection {
    id: ConnectionId,
    remote: SocketAddrV6,
    state: Option<State>,
    stream0: Stream,
    stream0_data: frame::StreamAssembler,
    streams: HashMap<StreamId, Stream>,
    /// Packets we haven't yet acknowledged
    pending_acks: Vec<u64>,
    /// Acks we've sent which haven't been acked in turn
    unconfirmed_acks: HashMap<u64, Vec<u64>>,
    client: bool,
    /// Present iff we're the client and the handshake is complete
    reset_token: Option<[u8; 16]>,
    mtu: u16,
    rx_packet: u64,
    crypto: CryptoContext,
    prev_crypto: Option<(u64, CryptoContext)>,

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

    //
    // Transmit queue
    //
    pending_retransmits: Retransmits,
}

/// Represents one or more packets subject to retransmission
#[derive(Debug, Clone)]
struct SentPacket {
    time: u64,
    /// 0 iff ack-only
    bytes: u16,
    retransmits: Retransmits
}

impl SentPacket {
    fn ack_only(&self) -> bool { self.bytes == 0 }
}

#[derive(Debug, Clone)]
struct Retransmits {
    max_stream_data: bool,
    max_data: bool,
    max_stream_id: bool,
    ack: bool,
    new_connection_id: Option<ConnectionId>,
    stream: VecDeque<frame::Stream>,
}

impl Default for Retransmits {
    fn default() -> Self { Self {
        max_stream_data: false,
        max_data: false,
        max_stream_id: false,
        ack: false,
        new_connection_id: None,
        stream: VecDeque::new(),
    }}
}

impl ::std::ops::AddAssign for Retransmits {
    fn add_assign(&mut self, rhs: Self) {
        self.max_stream_data |= rhs.max_stream_data;
        self.max_data |= rhs.max_data;
        self.max_stream_id |= rhs.max_stream_id;
        self.ack |= rhs.ack;
        self.new_connection_id = rhs.new_connection_id.or(self.new_connection_id);
        self.stream.extend(rhs.stream.into_iter());
    }
}

impl ::std::iter::FromIterator<Retransmits> for Retransmits {
    fn from_iter<T>(iter: T) -> Self
        where T: IntoIterator<Item = Retransmits>
    {
        let mut result = Retransmits::default();
        for packet in iter {
            result += packet;
        }
        result
    }
}

impl Retransmits {
    fn from_stream(frame: frame::Stream) -> Self {
        let mut stream = VecDeque::new();
        stream.push_back(frame);
        Self { stream, ..Self::default() }
    }
}

impl Connection {
    fn new(id: ConnectionId, remote: SocketAddrV6, initial_packet_number: u64, client: bool, config: &Config) -> Self {
        Self {
            id, remote, client,
            stream0: Stream::new(),
            stream0_data: frame::StreamAssembler::new(),
            streams: HashMap::new(),
            state: None,
            pending_acks: Vec::new(),
            unconfirmed_acks: HashMap::new(),
            reset_token: None,
            mtu: MIN_MTU,
            rx_packet: 0,
            crypto: CryptoContext::handshake(id, client),
            prev_crypto: None,

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
            largest_sent_packet: initial_packet_number.overflowing_sub(1).0,
            largest_acked_packet: 0,
            sent_packets: BTreeMap::new(),
            retransmittable_outstanding: 0,

            bytes_in_flight: 0,
            congestion_window: config.initial_window,
            end_of_recovery: 0,
            ssthresh: u64::max_value(),

            pending_retransmits: Retransmits::default(),
        }
    }

    fn get_tx_number(&mut self) -> u64 {
        self.largest_sent_packet = self.largest_sent_packet.overflowing_add(1).0;
        // TODO: Handle packet number overflow gracefully
        assert!(self.largest_sent_packet <= 2u64.pow(62)-1);
        self.largest_sent_packet
    }

    /// Returns new loss detection alarm time, if applicable
    fn on_packet_sent(&mut self, config: &Config, now: u64, in_handshake: bool, packet_number: u64, packet: SentPacket) -> Option<u64> {
        self.time_of_last_sent_packet = now;
        self.largest_sent_packet = packet_number;
        let bytes = packet.bytes;
        self.sent_packets.insert(packet_number, packet);
        if bytes != 0 {
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
        for packet in &ack {
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

    fn on_packet_acked(&mut self, config: &Config, packet: u64, bytes: u16) {
        if bytes != 0 {
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
            // Start a new recovery epoch if the lost packet is larger than the end of the previous recovery epoch.
            if !self.in_recovery(largest_lost) {
                self.end_of_recovery = self.largest_sent_packet;
                // *= factor
                self.congestion_window = (self.congestion_window * config.loss_reduction_factor as u64) >> 16;
                self.congestion_window = cmp::max(self.congestion_window, config.minimum_window);
                self.ssthresh = self.congestion_window;
            }
            for packet in lost_packets {
                let info = self.sent_packets.remove(&packet).unwrap();
                self.bytes_in_flight -= info.bytes as u64;
                self.pending_retransmits += info.retransmits;
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
            alarm_duration = self.rto(config);
        }
        self.time_of_last_sent_packet + alarm_duration
    }

    /// Retransmit time-out
    fn rto(&self, config: &Config) -> u64 {
        let computed = self.smoothed_rtt + 4 * self.rttvar + self.max_ack_delay;
        cmp::max(computed, config.min_rto_timeout) * 2u64.pow(self.rto_count)
    }

    fn handshake_retransmit(&mut self, config: &Config, now: u64) -> Vec<Box<[u8]>> {
        let mut unacked = mem::replace(&mut self.sent_packets, BTreeMap::new()).into_iter()
            .map(|(_, x)| x.retransmits).collect::<Retransmits>();
        let mut packets = Vec::new();
        // TODO: Retransmit ACKs
        let mut data = Vec::new();
        let start = unacked.stream.front().unwrap().offset;
        let mut offset = start;
        while let Some(segment) = unacked.stream.pop_front() {
            data.extend_from_slice(&segment.data);
        }
        while offset - start < data.len() as u64 {
            let mut buf = Vec::new();
            buf.reserve_exact(self.mtu as usize);
            let number = self.get_tx_number();
            let ty = if offset == 0 { packet::INITIAL } else { packet::HANDSHAKE };
            encode_long_header(&mut buf, ty, self.id, number as u32);
            let start = (offset-start) as usize;
            let len = cmp::min(data.len(), self.mtu as usize - buf.len() - 1 - 8); // conservative
            let frame = frame::Stream {
                id: StreamId(0), fin: false, offset, data: (&data[start..start+len]).into()
            };
            frame.encode(false, &mut buf);
            if ty == packet::INITIAL && buf.len() < MIN_INITIAL_SIZE - AEAD_TAG_SIZE {
                buf.resize(MIN_INITIAL_SIZE - AEAD_TAG_SIZE, frame::Type::PADDING.into());
            }
            let payload = self.crypto.encrypt(number as u64, &buf[0..LONG_HEADER_SIZE], &buf[LONG_HEADER_SIZE..]);
            debug_assert_eq!(payload.len(), buf.len() - LONG_HEADER_SIZE + AEAD_TAG_SIZE);
            buf.truncate(LONG_HEADER_SIZE);
            buf.extend_from_slice(&payload);
            // We can ignore on_packet_sent's return value because we're called only from the loss detection timeout,
            // which resets the timer explicitly afterwards.
            self.on_packet_sent(config, now, true, number, SentPacket { time: now, bytes: buf.len() as u16,
                                                                        retransmits: Retransmits::from_stream(frame) });
            offset += len as u64;
            packets.push(buf.into());
        }
        packets
    }

    fn on_packet_authenticated(&mut self, packet: u64) {
        self.pending_acks.push(packet);
        self.rx_packet = cmp::max(packet, self.rx_packet);
    }

    fn update_keys(&mut self, packet: u64) {
        let new = self.crypto.update(self.client);
        let old = mem::replace(&mut self.crypto, new);
        self.prev_crypto = Some((packet, old));
    }

    fn decrypt(&self, packet: u64, header: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
        if let Some((boundary, ref prev)) = self.prev_crypto {
            if packet < boundary {
                return prev.decrypt(packet, header, payload);
            }
        }
        self.crypto.decrypt(packet, header, payload)
    }
}

struct Stream {
    tx_offset: u64,
    rx_offset: u64,
}

impl Stream {
    fn new() -> Self { Self {
        tx_offset: 0,
        rx_offset: 0,
    }}
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
        key_phase: bool,
    },
    VersionNegotiate {
        id: ConnectionId
    }
}

impl Header {
    fn id(&self) -> Option<ConnectionId> {
        use self::Header::*;
        match *self {
            Header::Long { id, .. } => Some(id),
            Header::Short { id, .. } => id,
            VersionNegotiate { id, .. } => Some(id),
        }
    }

    fn number(&self) -> Option<PacketNumber> {
        use self::Header::*;
        match *self {
            Header::Long { number, .. } => Some(PacketNumber::U32(number)),
            Header::Short { number, .. } => Some(number),
            VersionNegotiate { .. } => None,
        }
    }
}

// An encoded packet number
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
            U8(_) => 0x00,
            U16(_) => 0x01,
            U32(_) => 0x02,
        }
    }

    fn encode<W: BufMut>(&self, w: &mut W) {
        use self::PacketNumber::*;
        match *self {
            U8(x) => w.put_u8(x),
            U16(x) => w.put_u16::<BigEndian>(x),
            U32(x) => w.put_u32::<BigEndian>(x),
        }
    }

    fn expand(&self, prev: u64) -> u64 {
        use self::PacketNumber::*;
        let t = prev + 1;
        // Compute missing bits that minimize the difference from expected
        let d = match *self {
            U8(_) => 1 << 8,
            U16(_) => 1 << 16,
            U32(_) => 1 << 32,
        };
        let x = match *self {
            U8(x) => x as u64,
            U16(x) => x as u64,
            U32(x) => x as u64,
        };
        if t > d/2 {
            x + d * (t + d/2 - x) / d
        } else {
            x % d
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
            Short { id, number, key_phase } => {
                let ty = number.ty() | 0x10
                    | if key_phase { 0x20 } else { 0 };
                if let Some(x) = id {
                    w.put_u8(ty | 0x40);
                    w.put_u64::<BigEndian>(x.0);
                } else {
                    w.put_u8(ty);
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
    header_data: Bytes,
    payload: Bytes,
}

#[derive(Copy, Clone, Debug, Fail)]
enum HeaderError {
    #[fail(display = "unsupported version")]
    UnsupportedVersion(ConnectionId),
    #[fail(display = "invalid header")]
    InvalidHeader,
}

impl From<coding::UnexpectedEnd> for HeaderError {
    fn from(_: coding::UnexpectedEnd) -> Self { HeaderError::InvalidHeader }
}

impl Packet {
    fn decode(packet: Bytes) -> ::std::result::Result<Self, HeaderError> {
        let mut buf = io::Cursor::new(&packet[..]);
        let ty = buf.get::<u8>()?;
        let long = ty & 0x80 != 0;
        let ty = ty & !0x80;
        if long {
            let id = ConnectionId(buf.get()?);
            let version: u32 = buf.get()?;
            Ok(match version {
                0 => {
                    let header_data = packet.slice(0, buf.position() as usize);
                    let payload = packet.slice(buf.position() as usize, packet.len());
                    Packet {
                        header: Header::VersionNegotiate { id },
                        header_data, payload,
                    }
                }
                VERSION => {
                    let number = buf.get()?;
                    let header_data = packet.slice(0, buf.position() as usize);
                    let payload = packet.slice(buf.position() as usize, packet.len());
                    Packet {
                        header: Header::Long { ty, id, number },
                        header_data, payload,
                    }
                }
                _ => return Err(HeaderError::UnsupportedVersion(id)),
            })
        } else {
            let id = if ty & 0x40 == 0 { Some(ConnectionId(buf.get()?)) } else { None };
            let number = match ty & 0b0111 {
                0x0 => PacketNumber::U8(buf.get()?),
                0x1 => PacketNumber::U16(buf.get()?),
                0x2 => PacketNumber::U32(buf.get()?),
                _ => { return Err(HeaderError::InvalidHeader); }
            };
            let key_phase = ty & 0x20 != 0;
            let header_data = packet.slice(0, buf.position() as usize);
            let payload = packet.slice(buf.position() as usize, packet.len());
            Ok(Packet {
                header: Header::Short { id, number, key_phase },
                header_data, payload,
            })
        }
    }
}

enum State {
    Handshake(state::Handshake),
    Established(state::Established),
    HandshakeFailed(state::HandshakeFailed),
    Closed(state::Closed),
    Draining,
}

impl State {
    pub fn is_closed(&self) -> bool {
        match *self {
            State::HandshakeFailed(_) => true,
            State::Closed(_) => true,
            State::Draining => true,
            _ => false,
        }
    }
}

mod state {
    use super::*;

    pub struct Handshake {
        pub tls: MidHandshakeSslStream<MemoryStream>,
        /// The number of the packet that first contained the latest version of the TLS ClientHello. Present iff we're
        /// the client.
        pub clienthello_packet: Option<u32>,
    }

    pub struct Established {
        pub tls: SslStream<MemoryStream>,
        pub key_phase: bool,
    }

    pub struct HandshakeFailed { // Closed
        pub reason: TransportError,
        pub alert: Option<Box<[u8]>>,
    }

    pub enum CloseReason {
        Connection(frame::ConnectionClose),
        Application(frame::ApplicationClose),
    }

    impl From<TransportError> for CloseReason { fn from(x: TransportError) -> Self { CloseReason::Connection(x.into()) } }
    impl From<frame::ConnectionClose> for CloseReason { fn from(x: frame::ConnectionClose) -> Self { CloseReason::Connection(x) } }
    impl From<frame::ApplicationClose> for CloseReason { fn from(x: frame::ApplicationClose) -> Self { CloseReason::Application(x) } }

    pub struct Closed {
        pub tls: SslStream<MemoryStream>,
        pub reason: CloseReason,
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
    Recv(frame::Stream),
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

#[derive(Debug, Clone, Fail)]
pub enum ConnectionError {
    #[fail(display = "peer doesn't implement any supported version")]
    VersionMismatch,
    #[fail(display = "{}", error_code)]
    TransportError { error_code: TransportError },
    #[fail(display = "closed by peer: {}", reason)]
    ConnectionClosed { reason: frame::ConnectionClose },
    #[fail(display = "closed by peer application: {}", reason)]
    ApplicationClosed { reason: frame::ApplicationClose },
}

impl From<TransportError> for ConnectionError {
    fn from(x: TransportError) -> Self { ConnectionError::TransportError { error_code: x } }
}

mod packet {
    pub const INITIAL: u8 = 0x7F;
    pub const RETRY: u8 = 0x7E;
    pub const HANDSHAKE: u8 = 0x7D;
}

/// Forward data from an Initial or Retry packet to a stream for a TLS context
fn parse_initial(stream: &mut MemoryStream, payload: Bytes) -> bool {
    let mut staging = frame::StreamAssembler::new();
    for frame in frame::Iter::new(payload) {
        match frame {
            Frame::Padding => {}
            Frame::Stream(frame::Stream { id, offset, data, .. }) => {
                if id != StreamId(0) { return false; } // Invalid packet
                staging.insert(offset, data);
            }
            _ => { return false; } // Invalid packet
        }
    }
    while let Some(data) = staging.next() { stream.extend_incoming(&data); }
    if !staging.is_empty() { return false; } // Invalid packet (incomplete stream)
    true
}

fn handshake_close(crypto: &CryptoContext, id: ConnectionId, packet_number: u32, error_code: TransportError, reason: &str) -> Box<[u8]> {
    let mut buf = Vec::<u8>::new();
    encode_long_header(&mut buf, packet::HANDSHAKE, id, packet_number);
    frame::ConnectionClose { error_code, reason: reason.as_bytes() }.encode(&mut buf);
    let payload = crypto.encrypt(packet_number as u64, &buf[0..LONG_HEADER_SIZE], &buf[LONG_HEADER_SIZE..]);
    debug_assert_eq!(payload.len(), buf.len() - LONG_HEADER_SIZE + AEAD_TAG_SIZE);
    buf.truncate(LONG_HEADER_SIZE);
    buf.extend_from_slice(&payload);
    buf.into()
}

const HANDSHAKE_SALT: [u8; 20] = [0x9c, 0x10, 0x8f, 0x98, 0x52, 0x0a, 0x5c, 0x5c, 0x32, 0x96, 0x8e, 0x95, 0x0e, 0x8a, 0x2c, 0x5f, 0xe0, 0x6d, 0x6c, 0x38];

pub struct CryptoState {
    secret: Box<[u8]>,
    key: Box<[u8]>,
    iv: Box<[u8]>,
}

impl CryptoState {
    fn new(digest: MessageDigest, cipher: Cipher, secret: Box<[u8]>) -> Self {
        let key = hkdf::qexpand(digest, &secret, b"key", cipher.key_len() as u16);
        let iv = hkdf::qexpand(digest, &secret, b"iv", cipher.iv_len().unwrap() as u16);
        Self { secret, key, iv }
    }

    fn update(&self, digest: MessageDigest, cipher: Cipher, client: bool) -> CryptoState {
        let secret = hkdf::qexpand(digest, &self.secret, if client { b"client 1rtt" } else { b"server 1rtt" }, digest.size() as u16);
        Self::new(digest, cipher, secret)
    }
}

pub struct CryptoContext {
    local: CryptoState,
    remote: CryptoState,
    digest: MessageDigest,
    cipher: Cipher,
}

impl CryptoContext {
    fn handshake(id: ConnectionId, client: bool) -> Self {
        let digest = MessageDigest::sha256();
        let cipher = Cipher::aes_128_gcm();
        let mut id_buf = [0; 8];
        BigEndian::write_u64(&mut id_buf, id.0);
        let hs_secret = hkdf::extract(digest, &HANDSHAKE_SALT, &id_buf);
        let (local_label, remote_label) = if client { (b"client hs", b"server hs") } else { (b"server hs", b"client hs") };
        let local = CryptoState::new(digest, cipher, hkdf::qexpand(digest, &hs_secret, &local_label[..], digest.size() as u16));
        let remote = CryptoState::new(digest, cipher, hkdf::qexpand(digest, &hs_secret, &remote_label[..], digest.size() as u16));
        CryptoContext {
            local, remote, digest, cipher,
        }
    }

    fn established(tls: &SslRef, client: bool) -> Self {
        let tls_cipher = tls.current_cipher().unwrap();
        let digest = tls_cipher.handshake_digest().unwrap();
        let cipher = Cipher::from_nid(tls_cipher.cipher_nid().unwrap()).unwrap();

        const SERVER_LABEL: &str = "EXPORTER-QUIC client 1rtt";
        const CLIENT_LABEL: &str = "EXPORTER-QUIC client 1rtt";

        let (local_label, remote_label) = if client { (CLIENT_LABEL, SERVER_LABEL) } else { (SERVER_LABEL, CLIENT_LABEL) };
        let mut local_secret = vec![0; digest.size()];
        tls.export_keying_material(&mut local_secret, local_label, Some(b"")).unwrap();
        let local = CryptoState::new(digest, cipher, local_secret.into());
        
        let mut remote_secret = vec![0; digest.size()];
        tls.export_keying_material(&mut remote_secret, remote_label, Some(b"")).unwrap();
        let remote = CryptoState::new(digest, cipher, remote_secret.into());
        CryptoContext {
            local, remote, digest, cipher
        }
    }

    fn update(&self, client: bool) -> Self {
        CryptoContext {
            local: self.local.update(self.digest, self.cipher, client),
            remote: self.local.update(self.digest, self.cipher, !client),
            digest: self.digest, cipher: self.cipher,
        }
    }

    fn encrypt(&self, packet: u64, header: &[u8], payload: &[u8]) -> Vec<u8> {
        // FIXME: Output to caller-owned memory with preexisting header; retain crypter
        let mut tag = [0; AEAD_TAG_SIZE];
        let mut nonce = [0; 12];
        BigEndian::write_u64(&mut nonce[4..12], packet);
        for i in 0..12 {
            nonce[i] ^= self.local.iv[i];
        }
        let mut buf = encrypt_aead(self.cipher, &self.local.key, Some(&nonce), header, payload, &mut tag).unwrap();
        buf.extend_from_slice(&tag);
        buf
    }

    fn decrypt(&self, packet: u64, header: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
        let mut nonce = [0; 12];
        BigEndian::write_u64(&mut nonce[4..12], packet);
        for i in 0..12 {
            nonce[i] ^= self.remote.iv[i];
        }
        if payload.len() < AEAD_TAG_SIZE { return None; }
        let (payload, tag) = payload.split_at(payload.len() - AEAD_TAG_SIZE);
        decrypt_aead(self.cipher, &self.remote.key, Some(&nonce), header, payload, tag).ok()
    }
}

const LONG_HEADER_SIZE: usize = 17;
const AEAD_TAG_SIZE: usize = 16;

#[cfg(test)]
mod test {
    use super::*;
    use rand;

    #[test]
    fn packet_number() {
        for prev in 0..1024 {
            for x in 0..256 {
                let found = PacketNumber::U8(x as u8).expand(prev);
                assert!(found as i64 - (prev+1) as i64 <= 128 || prev < 128 );
            }
        }
    }

    #[test]
    fn handshake_crypto() {
        let conn = rand::random();
        let client = CryptoContext::handshake(conn, true);
        let server = CryptoContext::handshake(conn, false);
        let header = b"header";
        let payload = b"payload";
        let encrypted = client.encrypt(0, header, payload);
        let decrypted = server.decrypt(0, header, &encrypted).unwrap();
        assert_eq!(decrypted, payload);
    }
}
