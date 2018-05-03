use std::collections::{hash_map, VecDeque, BTreeMap};
use std::{io, cmp, fmt, mem, str};
use std::net::SocketAddrV6;
use std::sync::Arc;
use std::path::PathBuf;

use bytes::{Buf, BufMut, Bytes, ByteOrder, BigEndian, IntoBuf};
use rand::{distributions, OsRng, Rng};
use rand::distributions::Sample;
use slab::Slab;
use openssl::{self, ex_data};
use openssl::ssl::{self, SslContext, SslMethod, SslOptions, SslVersion, SslMode, Ssl, SslStream, HandshakeError, MidHandshakeSslStream,
                   SslStreamBuilder, SslAlert, SslRef};
use openssl::pkey::{PKeyRef, Private};
use openssl::x509::X509Ref;
use openssl::hash::MessageDigest;
use openssl::symm::{Cipher, encrypt_aead, decrypt_aead};
use blake2::Blake2b;
use digest::{Input, VariableOutput};
use constant_time_eq::constant_time_eq;
use slog::Logger;
use arrayvec::ArrayVec;
use fnv::{FnvHashMap, FnvHashSet};

use memory_stream::MemoryStream;
use transport_parameters::TransportParameters;
use coding::{self, BufExt, BufMutExt};
use {hkdf, frame, Frame, TransportError, StreamId, Side, Directionality, VERSION};
use range_set::RangeSet;
use stream::{self, Stream};

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct ConnectionHandle(usize);

impl From<ConnectionHandle> for usize { fn from(x: ConnectionHandle) -> usize { x.0 } }

/// Parameters governing the core QUIC state machine.
pub struct Config {
    /// Maximum number of peer-initiated bidirectional streams that may exist at one time.
    pub max_remote_bi_streams: u16,
    /// Maximum number of peer-initiated  unidirectional streams that may exist at one time.
    pub max_remote_uni_streams: u16,
    /// Maximum duration of inactivity to accept before timing out the connection (s).
    ///
    /// Maximum value is 600 seconds. The actual value used is the minimum of this and the peer's own idle timeout.
    pub idle_timeout: u16,
    /// Maximum number of bytes the peer may transmit on any one stream before becoming blocked.
    pub stream_receive_window: u32,
    /// Maximum number of bytes the peer may transmit across all streams of a connection before becoming blocked.
    pub receive_window: u32,
    /// Maximum number of incoming connections to buffer.
    ///
    /// Calling `Endpoint::accept` removes a connection from the buffer, so this does not need to be large.
    pub accept_buffer: u32,

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

    /// List of supported application protocols.
    ///
    /// If empty, application-layer protocol negotiation will not be preformed.
    pub protocols: Vec<Box<[u8]>>,

    /// Whether to accept inauthentic or unverifiable peer certificates.
    ///
    /// Turning this off exposes clients to man-in-the-middle attacks in the same manner as an unencrypted TCP
    /// connection, but allows them to connect to servers that are using self-signed certificates.
    pub accept_insecure_certs: bool,

    /// Path to write NSS SSLKEYLOGFILE-compatible key log.
    ///
    /// Enabling this compromises security by committing secret information to disk. Useful for debugging communications
    /// when using tools like Wireshark.
    pub keylog: Option<PathBuf>,
}

pub struct CertConfig<'a> {
    /// A TLS private key.
    pub private_key: &'a PKeyRef<Private>,
    /// A TLS certificate corresponding to `private_key`.
    pub cert: &'a X509Ref,
}

impl Default for Config {
    fn default() -> Self {
        const EXPECTED_RTT: u32 = 100;                  // ms
        const MAX_STREAM_BANDWIDTH: u32 = 12500 * 1000; // bytes/s
        // Window size needed to avoid pipeline stalls
        const STREAM_RWND: u32 = MAX_STREAM_BANDWIDTH / 1000 * EXPECTED_RTT;
        Self {
            max_remote_bi_streams: 0,
            max_remote_uni_streams: 0,
            idle_timeout: 10,
            stream_receive_window: STREAM_RWND,
            receive_window: 8 * STREAM_RWND,
            accept_buffer: 1024,

            max_tlps: 2,
            reordering_threshold: 3,
            time_reordering_fraction: 0x2000, // 1/8
            using_time_loss_detection: false,
            min_tlp_timeout: 10 * 1000,
            min_rto_timeout: 200 * 1000,
            delayed_ack_timeout: 25 * 1000,
            default_initial_rtt: EXPECTED_RTT as u64 * 1000,

            default_mss: 1460,
            initial_window: 10 * 1460,
            minimum_window: 2 * 1460,
            loss_reduction_factor: 0x8000, // 1/2
            protocols: Vec::new(),

            accept_insecure_certs: false,
            keylog: None,
        }
    }
}

/// The main entry point to the library
///
/// This object performs no I/O whatsoever. Instead, it generates a stream of I/O operations for a backend to perform
/// via `poll_io`, and consumes incoming packets and timer expirations via `handle` and `timeout`.
pub struct Endpoint {
    log: Logger,
    rng: OsRng,
    initial_packet_number: distributions::Range<u64>,
    tls: SslContext,
    connection_ids: FnvHashMap<ConnectionId, ConnectionHandle>,
    connection_remotes: FnvHashMap<SocketAddrV6, ConnectionHandle>,
    connections: Slab<Connection>,
    config: Arc<Config>,
    listen_keys: Option<ListenKeys>,
    events: VecDeque<(ConnectionHandle, Event)>,
    io: VecDeque<Io>,
    dirty_conns: FnvHashSet<ConnectionHandle>,
    readable_conns: FnvHashSet<ConnectionHandle>,
    incoming: VecDeque<ConnectionHandle>,
    incoming_handshakes: usize,
}

const MIN_INITIAL_SIZE: usize = 1200;
const MIN_MTU: u16 = 1232;
const LOCAL_ID_LEN: usize = 8;
/// Ensures we can always fit all our ACKs in a single minimum-MTU packet with room to spare
const MAX_ACK_BLOCKS: usize = 64;
/// Value used in ACKs we transmit
const ACK_DELAY_EXPONENT: u8 = 3;
const RESET_TOKEN_SIZE: usize = 16;
const MAX_CID_SIZE: usize = 18;

fn reset_token_for(key: &[u8], id: &ConnectionId) -> [u8; RESET_TOKEN_SIZE] {
    let mut mac = Blake2b::new_keyed(key, RESET_TOKEN_SIZE);
    mac.process(id);
    // TODO: Server ID??
    let mut result = [0; RESET_TOKEN_SIZE];
    mac.variable_result(&mut result).unwrap();
    result
}

/// Information that should be preserved between restarts for server endpoints.
///
/// Keeping this around allows better behavior by clients that communicated with a previous instance of the same
/// endpoint.
#[derive(Copy, Clone)]
pub struct ListenKeys {
    /// Cryptographic key used to ensure integrity of data included in handshake cookies.
    ///
    /// Initialize with random bytes.
    pub cookie: [u8; 64],
    /// Cryptographic key used to send authenticated connection resets to clients who were communicating with a previous
    /// instance of tihs endpoint.
    ///
    /// Initialize with random bytes.
    pub reset: [u8; 64],
}

impl ListenKeys {
    /// Generate new keys.
    ///
    /// Be careful to use a cryptography-grade RNG.
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        let mut cookie = [0; 64];
        let mut reset = [0; 64];
        rng.fill_bytes(&mut cookie);
        rng.fill_bytes(&mut reset);
        Self { cookie, reset }
    }
}

#[derive(Debug, Fail)]
pub enum EndpointError {
    #[fail(display = "failed to configure TLS: {}", _0)]
    Tls(ssl::Error),
    #[fail(display = "failed open keylog file: {}", _0)]
    Keylog(io::Error),
    #[fail(display = "protocol ID longer than 255 bytes")]
    ProtocolTooLong(Box<[u8]>),
}

impl From<ssl::Error> for EndpointError { fn from(x: ssl::Error) -> Self { EndpointError::Tls(x) } }
impl From<openssl::error::ErrorStack> for EndpointError { fn from(x: openssl::error::ErrorStack) -> Self { EndpointError::Tls(x.into()) } }

impl Endpoint {
    pub fn new(log: Logger, config: Config, cert: Option<CertConfig>, listen: Option<ListenKeys>) -> Result<Self, EndpointError> {
        let rng = OsRng::new().unwrap();
        let config = Arc::new(config);

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
        if !config.accept_insecure_certs { tls.set_verify(ssl::SslVerifyMode::PEER); }
        if let Some(ref listen) = listen {
            let cookie_factory = Arc::new(CookieFactory::new(listen.cookie));
            {
                let cookie_factory = cookie_factory.clone();
                tls.set_stateless_cookie_generate_cb(move |tls, buf| {
                    let conn = tls.ex_data(*CONNECTION_INFO_INDEX).unwrap();
                    Ok(cookie_factory.generate(conn, buf))
                });
            }
            tls.set_stateless_cookie_verify_cb(move |tls, cookie| {
                let conn = tls.ex_data(*CONNECTION_INFO_INDEX).unwrap();
                cookie_factory.verify(conn, cookie)
            });
        }
        let reset_key = listen.as_ref().map(|x| x.reset);
        tls.add_custom_ext(
            26, ssl::ExtensionContext::TLS1_3_ONLY | ssl::ExtensionContext::CLIENT_HELLO | ssl::ExtensionContext::TLS1_3_ENCRYPTED_EXTENSIONS,
            { let config = config.clone();
              move |tls, ctx, _| {
                  let conn = tls.ex_data(*CONNECTION_INFO_INDEX).unwrap();
                  let mut buf = Vec::new();
                  let mut params = TransportParameters {
                      initial_max_streams_bidi: config.max_remote_bi_streams,
                      initial_max_streams_uni: config.max_remote_uni_streams,
                      initial_max_data: config.receive_window,
                      initial_max_stream_data: config.stream_receive_window,
                      ack_delay_exponent: ACK_DELAY_EXPONENT,
                      ..TransportParameters::default()
                  };
                  let am_server = ctx == ssl::ExtensionContext::TLS1_3_ENCRYPTED_EXTENSIONS;
                  if am_server {
                      params.stateless_reset_token = Some(reset_token_for(reset_key.as_ref().unwrap(), &conn.id));
                  }
                  params.write(&mut buf);
                  Ok(Some(buf))
              }
            },
            |tls, ctx, data, _| {
                let side = if ctx == ssl::ExtensionContext::CLIENT_HELLO { Side::Server } else { Side::Client };
                match TransportParameters::read(side, &mut data.into_buf()) {
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

        if let Some(ref cert) = cert {
            tls.set_private_key(cert.private_key)?;
            tls.set_certificate(cert.cert)?;
            tls.check_private_key()?;
        }

        if !config.protocols.is_empty() {
            let mut buf = Vec::new();
            for protocol in &config.protocols {
                if protocol.len() > 255 { return Err(EndpointError::ProtocolTooLong(protocol.clone())); }
                buf.push(protocol.len() as u8);
                buf.extend_from_slice(protocol);
            }
            tls.set_alpn_protos(&buf)?;
            tls.set_alpn_select_callback(move |_ssl, protos| {
                if let Some(x) = ssl::select_next_proto(&buf, protos) {
                    Ok(x)
                } else {
                    Err(ssl::AlpnError::ALERT_FATAL)
                }
            });
        }

        if let Some(ref path) = config.keylog {
            let file = ::std::fs::File::create(path).map_err(EndpointError::Keylog)?;
            let file = ::std::sync::Mutex::new(file);
            tls.set_keylog_callback(move |_, line| {
                use std::io::Write;
                let mut file = file.lock().unwrap();
                let _ = file.write_all(line.as_bytes());
                let _ = file.write_all(b"\n");
            });
        }

        let tls = tls.build();

        Ok(Self {
            log, rng, config, tls,
            listen_keys: listen,
            initial_packet_number: distributions::Range::new(0, 2u64.pow(32) - 1024),
            connection_ids: FnvHashMap::default(),
            connection_remotes: FnvHashMap::default(),
            connections: Slab::new(),
            events: VecDeque::new(),
            io: VecDeque::new(),
            dirty_conns: FnvHashSet::default(),
            readable_conns: FnvHashSet::default(),
            incoming: VecDeque::new(),
            incoming_handshakes: 0,
        })
    }

    fn listen(&self) -> bool { self.listen_keys.is_some() }

    /// Get an application-facing event
    pub fn poll(&mut self) -> Option<(ConnectionHandle, Event)> {
        if let Some(x) = self.events.pop_front() { return Some(x); }
        loop {
            let &conn = self.readable_conns.iter().next()?;
            if let Some(&stream) = self.connections[conn.0].readable_streams.iter().next() {
                self.connections[conn.0].readable_streams.remove(&stream);
                let rs = self.connections[conn.0].streams.get_mut(&stream).unwrap()
                    .recv_mut().unwrap();
                let fresh = mem::replace(&mut rs.fresh, false);
                return Some((conn, Event::StreamReadable { stream, fresh }));
            }
            self.readable_conns.remove(&conn);
        }
    }

    /// Get a pending IO operation
    pub fn poll_io(&mut self, now: u64) -> Option<Io> {
        loop {
            if let Some(x) = self.io.pop_front() { return Some(x); }
            let &conn = self.dirty_conns.iter().next()?;
            // TODO: Only pop once, only remove if that fails
            self.flush_pending(now, conn);
            self.dirty_conns.remove(&conn);
        }
    }

    /// Process an incoming UDP datagram
    pub fn handle(&mut self, now: u64, remote: SocketAddrV6, mut data: Bytes) {
        let datagram_len = data.len();
        while !data.is_empty() {
            let (packet, rest) = match Packet::decode(&data, LOCAL_ID_LEN) {
                Ok(x) => x,
                Err(HeaderError::UnsupportedVersion { source, destination }) => {
                    if !self.listen() {
                        debug!(self.log, "dropping packet with unsupported version");
                        return;
                    }
                    trace!(self.log, "sending version negotiation");
                    // Negotiate versions
                    let mut buf = Vec::<u8>::new();
                    Header::VersionNegotiate { ty: self.rng.gen(), source_id: destination, destination_id: source }.encode(&mut buf);
                    buf.write::<u32>(0x0a1a2a3a); // reserved version
                    buf.write(VERSION); // supported version
                    self.io.push_back(Io::Transmit { destination: remote, packet: buf.into() });
                    return;
                }
                Err(e) => {
                    trace!(self.log, "unable to process packet"; "reason" => %e);
                    return;
                }
            };
            self.handle_packet(now, remote, packet, datagram_len);
            data = rest;
        }
    }

    fn handle_packet(&mut self, now: u64, remote: SocketAddrV6, packet: Packet, datagram_len: usize) {
        //
        // Handle packet on existing connection, if any
        //

        let dest_id = packet.header.destination_id().clone();
        if let Some(&conn) = self.connection_ids.get(&dest_id) {
            self.handle_connected(now, conn, remote, packet);
            return;
        }
        if let Some(&conn) = self.connection_remotes.get(&remote) {
            if let Some(token) = self.connections[conn.0].params.stateless_reset_token {
                if packet.payload.len() >= 16 && &packet.payload[packet.payload.len() - 16..] == token {
                    debug!(self.log, "got stateless reset"; "connection" => %self.connections[conn.0].local_id);
                    self.io.push_back(Io::TimerStop { connection: conn, timer: Timer::LossDetection });
                    self.io.push_back(Io::TimerStop { connection: conn, timer: Timer::Close });
                    self.io.push_back(Io::TimerStop { connection: conn, timer: Timer::Idle });
                    self.events.push_back((conn, Event::ConnectionLost { reason: ConnectionError::Reset }));
                    self.connections[conn.0].state = Some(State::Drained);
                    return;
                }
            }
        }

        //
        // Potentially create a new connection
        //

        if !self.listen() {
            debug!(self.log, "dropping packet from unrecognized connection"; "header" => ?packet.header);
            return;
        }
        let key_phase = packet.header.key_phase();
        if let Header::Long { ty, destination_id, source_id, number } = packet.header {
            // MAY buffer non-initial packets a little for better 0RTT behavior
            if ty == packet::INITIAL && datagram_len >= MIN_INITIAL_SIZE {
                self.handle_initial(remote, destination_id, source_id, number, &packet.header_data, &packet.payload);
                return;
            }
        }

        //
        // If we got this far, we're a server receiving a seemingly valid packet for an unknown connection. Send a stateless reset.
        //

        if !dest_id.is_empty() {
            debug!(self.log, "sending stateless reset");
            let mut buf = Vec::<u8>::new();
            // Bound padding size to at most 8 bytes larger than input to mitigate amplification attacks
            let padding = self.rng.gen_range(0, cmp::max(RESET_TOKEN_SIZE + 8, packet.payload.len()) - RESET_TOKEN_SIZE);
            buf.reserve_exact(1 + MAX_CID_SIZE + 1 + padding + RESET_TOKEN_SIZE);
            Header::Short {
                id: ConnectionId::random(&mut self.rng, MAX_CID_SIZE as u8), number: PacketNumber::U8(self.rng.gen()), key_phase
            }.encode(&mut buf);
            {
                let start = buf.len();
                buf.resize(start + padding, 0);
                self.rng.fill_bytes(&mut buf[start..start+padding]);
            }
            buf.extend(&reset_token_for(&self.listen_keys.as_ref().unwrap().reset, &dest_id));
            self.io.push_back(Io::Transmit { destination: remote, packet: buf.into() });
        } else {
            trace!(self.log, "dropping unrecognized short packet without ID");
        }
    }

    /// Initiate a connection
    pub fn connect(&mut self, remote: SocketAddrV6, hostname: Option<&[u8]>) -> ConnectionHandle {
        let local_id = ConnectionId::random(&mut self.rng, LOCAL_ID_LEN as u8);
        let remote_id = ConnectionId::random(&mut self.rng, MAX_CID_SIZE as u8);
        trace!(self.log, "initial dcid"; "value" => %remote_id);
        let conn = self.add_connection(remote_id.clone(), local_id, remote_id, remote, Side::Client);
        let mut tls = Ssl::new(&self.tls).unwrap(); // Is this fallible?
        tls.set_ex_data(*CONNECTION_INFO_INDEX, ConnectionInfo { id: self.connections[conn.0].local_id.clone(), remote });
        if let Some(hostname) = hostname { tls.set_hostname(str::from_utf8(hostname).expect("malformed hostname")).unwrap(); }
        let mut tls = match tls.connect(MemoryStream::new()) {
            Ok(_) => unreachable!(),
            Err(HandshakeError::WouldBlock(tls)) => tls,
            Err(e) => panic!("unexpected TLS error: {}", e),
        };
        self.transmit_handshake(conn, &tls.get_mut().take_outgoing());
        self.connections[conn.0].state = Some(State::Handshake(state::Handshake {
            tls, clienthello_packet: None, remote_id_set: false
        }));
        self.dirty_conns.insert(conn);
        conn
    }

    fn gen_initial_packet_num(&mut self) -> u32 { self.initial_packet_number.sample(&mut self.rng) as u32 }

    fn add_connection(&mut self, crypto_id: ConnectionId, local_id: ConnectionId, remote_id: ConnectionId, remote: SocketAddrV6, side: Side) -> ConnectionHandle {
        debug_assert!(!local_id.is_empty());
        let packet_num = self.gen_initial_packet_num();
        let crypto = CryptoContext::handshake(&crypto_id, side);
        let i = self.connections.insert(Connection::new(crypto, local_id.clone(), remote_id, remote, packet_num.into(), side, &self.config));
        self.connection_ids.insert(local_id, ConnectionHandle(i));
        self.connection_remotes.insert(remote, ConnectionHandle(i));
        ConnectionHandle(i)
    }

    fn handle_initial(&mut self, remote: SocketAddrV6, dest_id: ConnectionId, source_id: ConnectionId,
                      packet_number: u32, header: &[u8], payload: &[u8])
    {
        let crypto = CryptoContext::handshake(&dest_id, Side::Server);
        let payload = if let Some(x) = crypto.decrypt(packet_number as u64, header, payload) { x.into() } else {
            debug!(self.log, "failed to authenticate initial packet");
            return;
        };
        let mut stream = MemoryStream::new();
        if !parse_initial(&self.log, &mut stream, payload) { return; } // TODO: Send close?
        trace!(self.log, "got initial");
        let local_id = ConnectionId::random(&mut self.rng, LOCAL_ID_LEN as u8);
        let mut tls = Ssl::new(&self.tls).unwrap(); // TODO: is this reliable?
        tls.set_ex_data(*CONNECTION_INFO_INDEX, ConnectionInfo { id: local_id.clone(), remote });
        let mut tls = SslStreamBuilder::new(tls, stream);
        match tls.stateless() {
            Ok(true) => {
                match tls.accept() {
                    Ok(_) => unreachable!(),
                    Err(HandshakeError::WouldBlock(mut tls)) => {
                        if self.incoming.len() + self.incoming_handshakes == self.config.accept_buffer as usize {
                            debug!(self.log, "rejecting connection due to full accept buffer");
                            let n = self.gen_initial_packet_num();
                            self.io.push_back(Io::Transmit {
                                destination: remote,
                                packet: handshake_close(&crypto, &source_id, &local_id, n, TransportError::SERVER_BUSY),
                            });
                            return;
                        }

                        trace!(self.log, "performing handshake"; "connection" => %local_id);
                        if let Some(params) = tls.ssl().ex_data(*TRANSPORT_PARAMS_INDEX).cloned() {
                            let params = params.expect("transport parameter errors should have aborted the handshake");
                            let conn = self.add_connection(dest_id, local_id, source_id, remote, Side::Server);
                            self.transmit_handshake(conn, &tls.get_mut().take_outgoing());
                            self.connections[conn.0].state = Some(State::Handshake(state::Handshake {
                                tls, clienthello_packet: None, remote_id_set: true,
                            }));
                            self.connections[conn.0].rx_packet = packet_number as u64;
                            self.connections[conn.0].set_params(&self.config, params);
                            self.connections[conn.0].pending_acks.insert_one(packet_number as u64);
                            self.dirty_conns.insert(conn);
                            self.incoming_handshakes += 1;
                        } else {
                            debug!(self.log, "ClientHello missing transport params extension");
                            let n = self.gen_initial_packet_num();
                            self.io.push_back(Io::Transmit {
                                destination: remote,
                                packet: handshake_close(&crypto, &source_id, &local_id, n, TransportError::TRANSPORT_PARAMETER_ERROR),
                            });
                        }
                    }
                    Err(HandshakeError::Failure(tls)) => {
                        let code = if let Some(params_err) = tls.ssl().ex_data(*TRANSPORT_PARAMS_INDEX).and_then(|x| x.err()) {
                            debug!(self.log, "received invalid transport parameters"; "connection" => %local_id, "reason" => %params_err);
                            TransportError::TRANSPORT_PARAMETER_ERROR
                        } else {
                            debug!(self.log, "accept failed"; "reason" => %tls.error());
                            TransportError::TLS_HANDSHAKE_FAILED
                        };
                        let n = self.gen_initial_packet_num();
                        self.io.push_back(Io::Transmit {
                            destination: remote,
                            packet: handshake_close(&crypto, &source_id, &local_id, n, code),
                        });
                    }
                    Err(HandshakeError::SetupFailure(e)) => {
                        error!(self.log, "accept setup failed"; "reason" => %e);
                        let n = self.gen_initial_packet_num();
                        self.io.push_back(Io::Transmit {
                            destination: remote,
                            packet: handshake_close(&crypto, &source_id, &local_id, n, TransportError::INTERNAL_ERROR),
                        });
                    }
                }
            }
            Ok(false) => {
                let data = tls.get_mut().take_outgoing();
                trace!(self.log, "sending HelloRetryRequest"; "connection" => %local_id, "len" => data.len());
                let mut buf = Vec::<u8>::new();
                Header::Long {
                    ty: packet::RETRY,
                    number: packet_number,
                    destination_id: source_id, source_id: local_id,
                }.encode(&mut buf);
                let header_len = buf.len();
                let mut ack = RangeSet::new();
                ack.insert_one(packet_number as u64);
                frame::Ack::encode(0, &ack, &mut buf);
                frame::Stream {
                    id: StreamId(0),
                    offset: 0,
                    fin: false,
                    data: data,
                }.encode(false, &mut buf);
                set_payload_length(&mut buf, header_len);
                let payload = crypto.encrypt(packet_number as u64, &buf[0..header_len], &buf[header_len..]);
                debug_assert_eq!(payload.len(), buf.len() - header_len + AEAD_TAG_SIZE);
                buf.truncate(header_len);
                buf.extend_from_slice(&payload);
                self.io.push_back(Io::Transmit { destination: remote, packet: buf.into() });
            }
            Err(e) => {
                debug!(self.log, "stateless handshake failed"; "connection" => %local_id, "reason" => %e);
                let n = self.gen_initial_packet_num();
                self.io.push_back(Io::Transmit {
                    destination: remote,
                    packet: handshake_close(&crypto, &source_id, &local_id, n, TransportError::TLS_HANDSHAKE_FAILED),
                });
            }
        }
    }

    fn handle_connected_inner(&mut self, now: u64, conn: ConnectionHandle, remote: SocketAddrV6, packet: Packet, state: State) -> State { match state {
        State::Handshake(mut state) => {
            match packet.header {
                Header::Long { ty: packet::RETRY, number, destination_id: conn_id, source_id: remote_id, .. } => {
                    trace!(self.log, "retry packet"; "connection" => %conn_id, "pn" => number);
                    // FIXME: the below guards fail to handle repeated retries resulting from retransmitted initials
                    if state.clienthello_packet.is_none() {
                        // Received Retry as a server
                        debug!(self.log, "received retry from client"; "connection" => %conn_id);
                        self.events.push_back((conn, Event::ConnectionLost { reason: TransportError::PROTOCOL_VIOLATION.into() }));
                        State::handshake_failed(TransportError::PROTOCOL_VIOLATION, None)
                    } else if state.clienthello_packet.unwrap() > number {
                        // Retry corresponds to an outdated Initial; must be a duplicate, so ignore it
                        State::Handshake(state)
                    } else if state.tls.get_ref().read_offset() != 0 {
                        // This condition works because Handshake packets are the only ones that we allow to make lasting changes to the read_offset
                        debug!(self.log, "received retry after a handshake packet");
                        self.events.push_back((conn, Event::ConnectionLost { reason: TransportError::PROTOCOL_VIOLATION.into() }));
                        State::handshake_failed(TransportError::PROTOCOL_VIOLATION,None)
                    } else if let Some(payload) = self.connections[conn.0].decrypt(true, number as u64, &packet.header_data, &packet.payload) {
                        let mut new_stream = MemoryStream::new();
                        if !parse_initial(&self.log, &mut new_stream, payload.into()) {
                            debug!(self.log, "invalid retry payload");
                            self.events.push_back((conn, Event::ConnectionLost { reason: TransportError::PROTOCOL_VIOLATION.into() }));
                            return State::handshake_failed(TransportError::PROTOCOL_VIOLATION, None);
                        }
                        *state.tls.get_mut() = new_stream;
                        match state.tls.handshake() {
                            Err(HandshakeError::WouldBlock(mut tls)) => {
                                trace!(self.log, "resending ClientHello"; "remote_id" => %remote_id);
                                self.on_packet_authenticated(now, conn, number as u64);
                                let local_id = self.connections[conn.0].local_id.clone();
                                // The server sees the next Initial packet as our first, so we update our keys to match the new remote_id
                                let crypto = CryptoContext::handshake(&remote_id, Side::Client);
                                // Discard transport state
                                self.connections[conn.0] = Connection::new(
                                    crypto, local_id, remote_id, remote, self.initial_packet_number.sample(&mut self.rng).into(), Side::Client, &self.config
                                );
                                // Send updated ClientHello
                                self.transmit_handshake(conn, &tls.get_mut().take_outgoing());
                                // Prepare to receive Handshake packets that start stream 0 from offset 0
                                tls.get_mut().reset_read();
                                State::Handshake(state::Handshake { tls, clienthello_packet: state.clienthello_packet, remote_id_set: state.remote_id_set })
                            },
                            Ok(_) => {
                                debug!(self.log, "unexpectedly completed handshake in RETRY packet");
                                self.events.push_back((conn, Event::ConnectionLost { reason: TransportError::PROTOCOL_VIOLATION.into() }));
                                State::handshake_failed(TransportError::PROTOCOL_VIOLATION, None)
                            }
                            Err(HandshakeError::Failure(mut tls)) => {
                                debug!(self.log, "handshake failed"; "reason" => %tls.error());
                                self.events.push_back((conn, Event::ConnectionLost { reason: TransportError::TLS_HANDSHAKE_FAILED.into() }));
                                State::handshake_failed(TransportError::TLS_HANDSHAKE_FAILED, Some(tls.get_mut().take_outgoing().to_owned().into()))
                            }
                            Err(HandshakeError::SetupFailure(e)) => {
                                error!(self.log, "handshake setup failed"; "reason" => %e);
                                self.events.push_back((conn, Event::ConnectionLost { reason: TransportError::INTERNAL_ERROR.into() }));
                                State::handshake_failed(TransportError::INTERNAL_ERROR, None)
                            }
                        }
                    } else {
                        debug!(self.log, "failed to authenticate retry packet");
                        State::Handshake(state)
                    }
                }
                Header::Long { ty: packet::HANDSHAKE, destination_id: id, source_id: remote_id, number, .. } => {
                    if !state.remote_id_set {
                        trace!(self.log, "got remote connection id"; "connection" => %id, "remote_id" => %remote_id);
                        self.connections[conn.0].remote_id = remote_id;
                        state.remote_id_set = true;
                    }
                    let payload = if let Some(x) = self.connections[conn.0].decrypt(true, number as u64, &packet.header_data, &packet.payload) { x } else {
                        debug!(self.log, "failed to authenticate handshake packet");
                        return State::Handshake(state);
                    };
                    self.on_packet_authenticated(now, conn, number as u64);
                    // Complete handshake (and ultimately send Finished)
                    for frame in frame::Iter::new(payload.into()) {
                        match frame {
                            Frame::Padding => {}
                            Frame::Stream(frame::Stream { id: StreamId(0), offset, data, .. }) => {
                                state.tls.get_mut().insert(offset, &data);
                            }
                            Frame::Stream(frame::Stream { .. }) => {
                                debug!(self.log, "non-stream-0 stream frame in handshake");
                                self.events.push_back((conn, Event::ConnectionLost { reason: TransportError::PROTOCOL_VIOLATION.into() }));
                                return State::handshake_failed(TransportError::PROTOCOL_VIOLATION, None);
                            }
                            Frame::Ack(ack) => {
                                self.on_ack_received(now, conn, ack);
                            }
                            Frame::ConnectionClose(reason) => {
                                self.events.push_back((conn, Event::ConnectionLost { reason: ConnectionError::ConnectionClosed { reason } }));
                                return State::Draining(state.into());
                            }
                            Frame::ApplicationClose(reason) => {
                                self.events.push_back((conn, Event::ConnectionLost { reason: ConnectionError::ApplicationClosed { reason } }));
                                return State::Draining(state.into());
                            }
                            Frame::PathChallenge(value) => {
                                self.connections[conn.0].handshake_pending.path_challenge(number as u64, value);
                            }
                            _ => {
                                debug!(self.log, "unexpected frame type in handshake"; "connection" => %id, "type" => %frame.ty());
                                self.events.push_back((conn, Event::ConnectionLost { reason: TransportError::PROTOCOL_VIOLATION.into() }));
                                return State::handshake_failed(TransportError::PROTOCOL_VIOLATION, None);
                            }
                        }
                    }
                    if state.tls.get_ref().read_blocked() {
                        return State::Handshake(state);
                    }
                    let prev_offset = state.tls.get_ref().read_offset();
                    match state.tls.handshake() {
                        Ok(mut tls) => {
                            if self.connections[conn.0].side == Side::Client {
                                if let Some(params) = tls.ssl().ex_data(*TRANSPORT_PARAMS_INDEX).cloned() {
                                    self.connections[conn.0].set_params(&self.config, params.expect("transport param errors should fail the handshake"));
                                } else {
                                    debug!(self.log, "server didn't send transport params");
                                    self.events.push_back((conn, Event::ConnectionLost { reason: TransportError::TRANSPORT_PARAMETER_ERROR.into() }));
                                    return State::handshake_failed(TransportError::TLS_HANDSHAKE_FAILED,
                                                                   Some(tls.get_mut().take_outgoing().to_owned().into()));
                                }
                            }
                            trace!(self.log, "established"; "connection" => %id);
                            if self.connections[conn.0].side == Side::Client {
                                self.transmit_handshake(conn, &tls.get_mut().take_outgoing());
                            } else {
                                self.connections[conn.0].transmit(StreamId(0), tls.get_mut().take_outgoing()[..].into());
                            }
                            match self.connections[conn.0].side {
                                Side::Client => {
                                    self.events.push_back((conn, Event::Connected {
                                        protocol: tls.ssl().selected_alpn_protocol().map(|x| x.into()),
                                    }));
                                }
                                Side::Server => {
                                    self.incoming_handshakes -= 1;
                                    self.incoming.push_back(conn);
                                }
                            }
                            self.connections[conn.0].crypto = Some(CryptoContext::established(tls.ssl(), self.connections[conn.0].side));
                            self.connections[conn.0].streams.get_mut(&StreamId(0)).unwrap()
                                .recv_mut().unwrap().max_data += tls.get_ref().read_offset() - prev_offset;
                            self.connections[conn.0].pending.max_stream_data.insert(StreamId(0));
                            self.connections[conn.0].pending.max_data = true;
                            State::Established(state::Established { tls })
                        }
                        Err(HandshakeError::WouldBlock(mut tls)) => {
                            trace!(self.log, "handshake ongoing"; "connection" => %id);
                            self.connections[conn.0].streams.get_mut(&StreamId(0)).unwrap()
                                .recv_mut().unwrap().max_data += tls.get_ref().read_offset() - prev_offset;
                            {
                                let response = tls.get_mut().take_outgoing();
                                if !response.is_empty() {
                                    self.transmit_handshake(conn, &response);
                                }
                            }
                            State::Handshake(state::Handshake { tls, clienthello_packet: state.clienthello_packet, remote_id_set: state.remote_id_set })
                        }
                        Err(HandshakeError::Failure(mut tls)) => {
                            let code = if let Some(params_err) = tls.ssl().ex_data(*TRANSPORT_PARAMS_INDEX).and_then(|x| x.err()) {
                                debug!(self.log, "received invalid transport parameters"; "connection" => %id, "reason" => %params_err);
                                TransportError::TRANSPORT_PARAMETER_ERROR
                            } else {
                                debug!(self.log, "accept failed"; "reason" => %tls.error());
                                TransportError::TLS_HANDSHAKE_FAILED
                            };
                            self.events.push_back((conn, Event::ConnectionLost { reason: code.into() }));
                            State::handshake_failed(code, Some(tls.get_mut().take_outgoing().to_owned().into()))
                        }
                        Err(HandshakeError::SetupFailure(e)) => {
                            error!(self.log, "handshake failed"; "connection" => %id, "reason" => %e);
                            self.events.push_back((conn, Event::ConnectionLost { reason: TransportError::INTERNAL_ERROR.into() }));
                            State::handshake_failed(TransportError::INTERNAL_ERROR, None)
                        }
                    }
                }
                Header::Long { ty, .. } => {
                    debug!(self.log, "unexpected packet type"; "type" => ty);
                    self.events.push_back((conn, Event::ConnectionLost { reason: TransportError::PROTOCOL_VIOLATION.into() }));
                    State::handshake_failed(TransportError::PROTOCOL_VIOLATION, None)
                }
                Header::VersionNegotiate { destination_id: id, .. } => {
                    let mut payload = io::Cursor::new(&packet.payload[..]);
                    if packet.payload.len() % 4 != 0 {
                        debug!(self.log, "malformed version negotiation"; "connection" => %id);
                        self.events.push_back((conn, Event::ConnectionLost { reason: TransportError::PROTOCOL_VIOLATION.into() }));
                        return State::handshake_failed(TransportError::PROTOCOL_VIOLATION, None);
                    }
                    while payload.has_remaining() {
                        let version = payload.get::<u32>().unwrap();
                        if version == VERSION {
                            // Our version is supported, so this packet is spurious
                            return State::Handshake(state);
                        }
                    }
                    debug!(self.log, "remote doesn't support our version");
                    self.events.push_back((conn, Event::ConnectionLost { reason: ConnectionError::VersionMismatch }));
                    State::Draining(state.into())
                }
                // TODO: SHOULD buffer these to improve reordering tolerance.
                Header::Short { .. } => {
                    trace!(self.log, "dropping short packet during handshake");
                    State::Handshake(state)
                }
            }
        }
        State::Established(mut state) => {
            let id = self.connections[conn.0].local_id.clone();
            if let Header::Long { .. } = packet.header {
                trace!(self.log, "discarding unprotected packet"; "connection" => %id);
                return State::Established(state);
            }
            let (payload, number) = match self.connections[conn.0].decrypt_packet(false, packet) {
                Ok(x) => x,
                Err(None) => {
                    trace!(self.log, "failed to authenticate packet"; "connection" => %id);
                    return State::Established(state);
                }
                Err(Some(e)) => {
                    warn!(self.log, "got illegal packet"; "connection" => %id);
                    self.events.push_back((conn, Event::ConnectionLost { reason: e.into() }));
                    return State::closed(e);
                }
            };
            trace!(self.log, "packet authenticated"; "pn" => number);
            self.on_packet_authenticated(now, conn, number);
            for frame in frame::Iter::new(payload.into()) {
                match frame {
                    Frame::Padding => {}
                    _ => {
                        trace!(self.log, "got frame"; "connection" => %self.connections[conn.0].local_id, "type" => %frame.ty());
                    }
                }
                match frame {
                    Frame::Ack(_) => {}
                    _ => { self.connections[conn.0].permit_ack_only = true; }
                }
                match frame {
                    Frame::Stream(frame) => {
                        trace!(self.log, "got stream"; "id" => frame.id.0, "offset" => frame.offset, "len" => frame.data.len(), "fin" => frame.fin);
                        let data_recvd = self.connections[conn.0].data_recvd;
                        let max_data = self.connections[conn.0].local_max_data;
                        let new_bytes = match self.connections[conn.0].get_recv_stream(frame.id) {
                            Err(e) => {
                                debug!(self.log, "received illegal stream frame"; "stream" => frame.id.0);
                                self.events.push_back((conn, Event::ConnectionLost { reason: e.into() }));
                                return State::closed(e);
                            }
                            Ok(None) => {
                                trace!(self.log, "dropping frame for closed stream");
                                return State::Established(state);
                            }
                            Ok(Some(stream)) => {
                                let end = frame.offset + frame.data.len() as u64;
                                let rs = stream.recv_mut().unwrap();
                                if let Some(final_offset) = rs.final_offset() {
                                    if end > final_offset || (frame.fin && end != final_offset) {
                                        debug!(self.log, "final offset error"; "frame end" => end, "final offset" => final_offset);
                                        self.events.push_back((conn, Event::ConnectionLost { reason: TransportError::FINAL_OFFSET_ERROR.into() }));
                                        return State::closed(TransportError::FINAL_OFFSET_ERROR);
                                    }
                                }
                                let prev_end = rs.limit();
                                let new_bytes = end.saturating_sub(prev_end);
                                if end > rs.max_data || data_recvd + new_bytes > max_data {
                                    debug!(self.log, "flow control error";
                                           "stream" => frame.id.0, "recvd" => data_recvd, "new bytes" => new_bytes,
                                           "max data" => max_data, "end" => end, "stream max data" => rs.max_data);
                                    self.events.push_back((conn, Event::ConnectionLost { reason: TransportError::FLOW_CONTROL_ERROR.into() }));
                                    return State::closed(TransportError::FLOW_CONTROL_ERROR);
                                }
                                if frame.fin {
                                    match rs.state {
                                        stream::RecvState::Recv { ref mut size } => { *size = Some(end); }
                                        _ => {}
                                    }
                                }
                                rs.recvd.insert(frame.offset..end);
                                if frame.id == StreamId(0) {
                                    if frame.fin {
                                        debug!(self.log, "got fin on stream 0"; "connection" => %id);
                                        self.events.push_back((conn, Event::ConnectionLost { reason: TransportError::PROTOCOL_VIOLATION.into() }));
                                        return State::closed(TransportError::PROTOCOL_VIOLATION);
                                    }
                                    state.tls.get_mut().insert(frame.offset, &frame.data);
                                } else {
                                    rs.buffer(frame.data, frame.offset);
                                }
                                if let stream::RecvState::Recv { size: Some(size) } = rs.state {
                                    if rs.recvd.len() == 1 && rs.recvd.iter().next().unwrap() == (0..size) {
                                        rs.state = stream::RecvState::DataRecvd { size };
                                    }
                                }
                                new_bytes
                            }
                        };
                        if frame.id != StreamId(0) {
                            self.connections[conn.0].readable_streams.insert(frame.id);
                            self.readable_conns.insert(conn);
                        }
                        self.connections[conn.0].data_recvd += new_bytes;
                    }
                    Frame::Ack(ack) => {
                        self.on_ack_received(now, conn, ack);
                        for stream in self.connections[conn.0].finished_streams.drain(..) {
                            self.events.push_back((conn, Event::StreamFinished { stream }));
                        }
                    }
                    Frame::Padding | Frame::Ping => {}
                    Frame::ConnectionClose(reason) => {
                        self.events.push_back((conn, Event::ConnectionLost { reason: ConnectionError::ConnectionClosed { reason } }));
                        return State::Draining(state.into());
                    }
                    Frame::ApplicationClose(reason) => {
                        self.events.push_back((conn, Event::ConnectionLost { reason: ConnectionError::ApplicationClosed { reason } }));
                        return State::Draining(state.into());
                    }
                    Frame::Invalid(ty) => {
                        debug!(self.log, "received malformed frame"; "type" => %ty);
                        self.events.push_back((conn, Event::ConnectionLost { reason: TransportError::frame(ty).into() }));
                        return State::closed(TransportError::frame(ty));
                    }
                    Frame::PathChallenge(x) => {
                        self.connections[conn.0].pending.path_challenge(number, x);
                    }
                    Frame::PathResponse(_) => {
                        debug!(self.log, "unsolicited PATH_RESPONSE");
                        self.events.push_back((conn, Event::ConnectionLost { reason: TransportError::UNSOLICITED_PATH_RESPONSE.into() }));
                        return State::closed(TransportError::UNSOLICITED_PATH_RESPONSE);
                    }
                    Frame::MaxData(bytes) => {
                        let was_blocked = self.connections[conn.0].blocked();
                        self.connections[conn.0].max_data = cmp::max(bytes, self.connections[conn.0].max_data);
                        if was_blocked && !self.connections[conn.0].blocked() {
                            for stream in self.connections[conn.0].blocked_streams.drain() {
                                self.events.push_back((conn, Event::StreamWritable { stream }));
                            }
                        }
                    }
                    Frame::MaxStreamData { id, offset } => {
                        if id.initiator() != self.connections[conn.0].side && id.directionality() == Directionality::Uni {
                            debug!(self.log, "got MAX_STREAM_DATA on recv-only stream");
                            self.events.push_back((conn, Event::ConnectionLost { reason: TransportError::PROTOCOL_VIOLATION.into() }));
                            return State::closed(TransportError::PROTOCOL_VIOLATION);
                        }
                        if let Some(stream) = self.connections[conn.0].streams.get_mut(&id) {
                            let ss = stream.send_mut().unwrap();
                            if offset > ss.max_data {
                                trace!(self.log, "stream limit increased"; "stream" => id.0,
                                       "old" => ss.max_data, "new" => offset, "current offset" => ss.offset);
                                if ss.offset == ss.max_data {
                                    self.events.push_back((conn, Event::StreamWritable { stream: id }));
                                }
                                ss.max_data = offset;
                            }
                        } else {
                            debug!(self.log, "got MAX_STREAM_DATA on unopened stream");
                            self.events.push_back((conn, Event::ConnectionLost { reason: TransportError::PROTOCOL_VIOLATION.into() }));
                            return State::closed(TransportError::PROTOCOL_VIOLATION);
                        }
                    }
                    Frame::MaxStreamId(id) => {
                        let limit = match id.directionality() {
                            Directionality::Uni => &mut self.connections[conn.0].max_uni_streams,
                            Directionality::Bi => &mut self.connections[conn.0].max_bi_streams,
                        };
                        if id.index() > *limit {
                            *limit = id.index();
                            self.events.push_back((conn, Event::StreamAvailable { directionality: id.directionality() }));
                        }
                    }
                    Frame::RstStream(frame::RstStream { id, error_code, final_offset }) => {
                        if id == StreamId(0) {
                            debug!(self.log, "got RST_STREAM on stream 0");
                            self.events.push_back((conn, Event::ConnectionLost { reason: TransportError::PROTOCOL_VIOLATION.into() }));
                            return State::closed(TransportError::PROTOCOL_VIOLATION);
                        }
                        let offset = match self.connections[conn.0].get_recv_stream(id) {
                            Err(e) => {
                                debug!(self.log, "received illegal RST_STREAM");
                                self.events.push_back((conn, Event::ConnectionLost { reason: e.into() }));
                                return State::closed(e);
                            }
                            Ok(None) => {
                                trace!(self.log, "received RST_STREAM on closed stream");
                                return State::Established(state);
                            }
                            Ok(Some(stream)) => {
                                let rs = stream.recv_mut().unwrap();
                                if let Some(offset) = rs.final_offset() {
                                    if offset != final_offset {
                                        self.events.push_back((conn, Event::ConnectionLost { reason: TransportError::FINAL_OFFSET_ERROR.into() }));
                                        return State::closed(TransportError::FINAL_OFFSET_ERROR);
                                    }
                                }
                                if !rs.is_closed() {
                                    rs.state = stream::RecvState::ResetRecvd { size: final_offset, error_code };
                                }
                                rs.limit()
                            }
                        };
                        self.connections[conn.0].data_recvd += final_offset.saturating_sub(offset);
                        self.connections[conn.0].readable_streams.insert(id);
                        self.readable_conns.insert(conn);
                    }
                    Frame::Blocked { offset } => {
                        debug!(self.log, "peer claims to be blocked at connection level"; "offset" => offset);
                    }
                    Frame::StreamBlocked { id, offset } => {
                        debug!(self.log, "peer claims to be blocked at stream level"; "stream" => %id, "offset" => offset);
                    }
                    Frame::StreamIdBlocked { id } => {
                        debug!(self.log, "peer claims to be blocked at stream ID level"; "stream" => %id);
                    }
                    Frame::StopSending { id, error_code } => {
                        if self.connections[conn.0].streams.get(&id).map_or(true, |x| x.send().map_or(true, |ss| ss.offset == 0)) {
                            debug!(self.log, "got STOP_SENDING on invalid stream");
                            self.events.push_back((conn, Event::ConnectionLost { reason: TransportError::PROTOCOL_VIOLATION.into() }));
                            return State::closed(TransportError::PROTOCOL_VIOLATION);
                        }
                        self.reset(conn, id, 0);
                        self.connections[conn.0].streams.get_mut(&id).unwrap().send_mut().unwrap().state =
                            stream::SendState::ResetSent { stop_reason: Some(error_code) };
                    }
                }
            }
            if !state.tls.get_ref().read_blocked() {
                let prev_offset = state.tls.get_ref().read_offset();
                let status = state.tls.ssl_read(&mut [0; 2048]);
                self.connections[conn.0].streams.get_mut(&StreamId(0)).unwrap()
                    .recv_mut().unwrap().max_data += state.tls.get_ref().read_offset() - prev_offset;
                self.connections[conn.0].pending.max_stream_data.insert(StreamId(0));
                match status {
                    Err(ref e) if e.code() == ssl::ErrorCode::WANT_READ => {}
                    Ok(_) => {} // Padding; illegal but harmless(?)
                    Err(ref e) if e.code() == ssl::ErrorCode::SSL => {
                        debug!(self.log, "TLS error"; "error" => %e);
                        self.events.push_back((conn, Event::ConnectionLost { reason: TransportError::TLS_FATAL_ALERT_RECEIVED.into() }));
                        return State::closed(TransportError::TLS_FATAL_ALERT_RECEIVED);
                    }
                    Err(ref e) if e.code() == ssl::ErrorCode::ZERO_RETURN => {
                        debug!(self.log, "TLS session terminated unexpectedly");
                        self.events.push_back((conn, Event::ConnectionLost { reason: TransportError::PROTOCOL_VIOLATION.into() }));
                        return State::closed(TransportError::PROTOCOL_VIOLATION);
                    }
                    Err(e) => {
                        error!(self.log, "unexpected TLS error"; "error" => %e);
                        self.events.push_back((conn, Event::ConnectionLost { reason: TransportError::INTERNAL_ERROR.into() }));
                        return State::closed(TransportError::INTERNAL_ERROR);
                    }
                }
            }
            State::Established(state)
        }
        State::HandshakeFailed(state) => {
            if let Ok((payload, _)) = self.connections[conn.0].decrypt_packet(true, packet) {
                for frame in frame::Iter::new(payload.into()) {
                    match frame {
                        Frame::ConnectionClose(_) | Frame::ApplicationClose(_) => {
                            trace!(self.log, "draining");
                            return State::Draining(state.into());
                        }
                        _ => {}
                    }
                }
            }
            State::HandshakeFailed(state)
        }
        State::Closed(state) => {
            if let Ok((payload, _)) = self.connections[conn.0].decrypt_packet(false, packet) {
                for frame in frame::Iter::new(payload.into()) {
                    match frame {
                        Frame::ConnectionClose(_) | Frame::ApplicationClose(_) => {
                            trace!(self.log, "draining");
                            return State::Draining(state.into());
                        }
                        _ => {}
                    }
                }
            }
            State::Closed(state)
        }
        State::Draining(x) => State::Draining(x),
        State::Drained => State::Drained,
    }}

    fn handle_connected(&mut self, now: u64, conn: ConnectionHandle, remote: SocketAddrV6, packet: Packet) {
        trace!(self.log, "connection got packet"; "connection" => %self.connections[conn.0].local_id, "len" => packet.payload.len());
        let was_closed = self.connections[conn.0].state.as_ref().unwrap().is_closed();

        // State transitions
        let state = self.connections[conn.0].state.take().unwrap();
        let state = self.handle_connected_inner(now, conn, remote, packet, state);

        if !was_closed && state.is_closed() {
            self.close_common(now, conn);
        }

        // Transmit CONNECTION_CLOSE if necessary
        match state {
            State::HandshakeFailed(ref state) => {
                if !was_closed && self.connections[conn.0].side == Side::Server {
                    self.incoming_handshakes -= 1;
                }
                let n = self.connections[conn.0].get_tx_number();
                self.io.push_back(Io::Transmit {
                    destination: remote,
                    packet: handshake_close(&self.connections[conn.0].handshake_crypto,
                                            &self.connections[conn.0].remote_id,
                                            &self.connections[conn.0].local_id,
                                            n as u32, state.reason.clone()),
                });
                self.reset_idle_timeout(now, conn);
            }
            State::Closed(ref state) => {
                self.io.push_back(Io::Transmit {
                    destination: remote,
                    packet: self.connections[conn.0].make_close(&state.reason),
                });
                self.reset_idle_timeout(now, conn);
            }
            _ => {}
        }
        self.connections[conn.0].state = Some(state);

        self.dirty_conns.insert(conn);
    }

    fn reset_idle_timeout(&mut self, now: u64, conn: ConnectionHandle) {
        let dt = cmp::min(self.config.idle_timeout, self.connections[conn.0].params.idle_timeout) as u64 * 1000000;
        self.connections[conn.0].set_idle = Some(Some(now + dt));
    }

    fn flush_pending(&mut self, now: u64, conn: ConnectionHandle) {
        let mut sent = false;
        while let Some(packet) = self.connections[conn.0].next_packet(&self.log, &self.config, now) {
            self.io.push_back(Io::Transmit {
                destination: self.connections[conn.0].remote,
                packet: packet.into(),
            });
            sent = true;
        }
        if sent {
            self.reset_idle_timeout(now, conn);
        }
        {
            let c = &mut self.connections[conn.0];
            if let Some(setting) = c.set_idle.take() {
                if let Some(time) = setting {
                    self.io.push_back(Io::TimerStart { connection: conn, timer: Timer::Idle, time });
                } else {
                    self.io.push_back(Io::TimerStop { connection: conn, timer: Timer::Idle });
                }
            }
            if let Some(setting) = c.set_loss_detection.take() {
                if let Some(time) = setting {
                    self.io.push_back(Io::TimerStart { connection: conn, timer: Timer::LossDetection, time });
                } else {
                    self.io.push_back(Io::TimerStop { connection: conn, timer: Timer::LossDetection });
                }
            }
        }
    }

    fn forget(&mut self, conn: ConnectionHandle) {
        self.connection_ids.remove(&self.connections[conn.0].local_id);
        self.connection_remotes.remove(&self.connections[conn.0].remote);
        self.dirty_conns.remove(&conn);
        self.readable_conns.remove(&conn);
        self.connections.remove(conn.0);
    }

    /// Handle a timer expiring
    pub fn timeout(&mut self, now: u64, conn: ConnectionHandle, timer: Timer) {
        match timer {
            Timer::Close => {
                self.io.push_back(Io::TimerStop { connection: conn, timer: Timer::Idle });
                self.events.push_back((conn, Event::ConnectionDrained));
                if self.connections[conn.0].state.as_ref().unwrap().is_app_closed() {
                    self.forget(conn);
                } else {
                    self.connections[conn.0].state = Some(State::Drained);
                }
            }
            Timer::Idle => {
                self.close_common(now, conn);
                let state = State::Draining(match self.connections[conn.0].state.take().unwrap() {
                    State::Handshake(x) => x.into(),
                    State::HandshakeFailed(x) => x.into(),
                    State::Established(x) => x.into(),
                    State::Closed(x) => x.into(),
                    State::Draining(x) => x.into(),
                    State::Drained => unreachable!(),
                });
                self.connections[conn.0].state = Some(state);
                self.events.push_back((conn, Event::ConnectionLost {
                    reason: ConnectionError::TimedOut,
                }));
                self.dirty_conns.insert(conn); // Ensure the loss detection timer cancellation goes through
            }
            Timer::LossDetection => {
                if self.connections[conn.0].handshake_sent != 0 {
                    trace!(self.log, "retransmitting handshake packets"; "connection" => %self.connections[conn.0].local_id);
                    self.connections[conn.0].handshake_sent = 0;
                    let packets = self.connections[conn.0].sent_packets.iter()
                        .filter_map(|(&packet, info)| if info.handshake { Some(packet) } else { None })
                        .collect::<Vec<_>>();
                    for number in packets {
                        let mut info = self.connections[conn.0].sent_packets.remove(&number).unwrap();
                        self.connections[conn.0].handshake_pending += info.retransmits;
                    }
                    self.connections[conn.0].handshake_count += 1;
                } else if self.connections[conn.0].loss_time != 0 {
                    // Early retransmit or Time Loss Detection
                    let largest = self.connections[conn.0].largest_acked_packet;
                    self.connections[conn.0].detect_lost_packets(&self.config, now, largest);
                } else if self.connections[conn.0].tlp_count < self.config.max_tlps {
                    trace!(self.log, "sending TLP"; "pn" => self.connections[conn.0].largest_sent_packet + 1);
                    // Tail Loss Probe.
                    self.io.push_back(Io::Transmit {
                        destination: self.connections[conn.0].remote,
                        packet: self.connections[conn.0].force_transmit(&self.config, now),
                    });
                    self.reset_idle_timeout(now, conn);
                    self.connections[conn.0].tlp_count += 1;
                } else {
                    trace!(self.log, "RTO fired, retransmitting"; "pn" => self.connections[conn.0].largest_sent_packet + 1);
                    // RTO
                    if self.connections[conn.0].rto_count == 0 {
                        self.connections[conn.0].largest_sent_before_rto = self.connections[conn.0].largest_sent_packet;
                    }
                    for _ in 0..2 {
                        self.io.push_back(Io::Transmit {
                            destination: self.connections[conn.0].remote,
                            packet: self.connections[conn.0].force_transmit(&self.config, now),
                        });
                    }
                    self.reset_idle_timeout(now, conn);
                    self.connections[conn.0].rto_count += 1;
                }
                self.connections[conn.0].set_loss_detection_alarm(&self.config);
                self.dirty_conns.insert(conn);
            }
        }
    }

    fn transmit_handshake(&mut self, conn: ConnectionHandle, messages: &[u8]) {
        let offset = {
            let ss = self.connections[conn.0].streams.get_mut(&StreamId(0)).unwrap().send_mut().unwrap();
            let x = ss.offset;
            ss.offset += messages.len() as u64;
            ss.bytes_in_flight += messages.len() as u64;
            x
        };
        self.connections[conn.0].handshake_pending.stream.push_back(frame::Stream { id: StreamId(0), fin: false, offset, data: messages.into()});
    }

    fn on_ack_received(&mut self, now: u64, conn: ConnectionHandle, ack: frame::Ack) {
        trace!(self.log, "got ack"; "ranges" => ?ack.iter().collect::<Vec<_>>());
        let was_blocked = self.connections[conn.0].blocked();
        self.connections[conn.0].on_ack_received(&self.config, now, ack);
        if was_blocked && !self.connections[conn.0].blocked() {
            for stream in self.connections[conn.0].blocked_streams.drain() {
                self.events.push_back((conn, Event::StreamWritable { stream }));
            }
        }
    }

    /// Transmit data on a stream
    ///
    /// Returns the number of bytes written on success.
    ///
    /// # Panics
    /// - when applied to a stream that does not have an active outgoing channel
    pub fn write(&mut self, conn: ConnectionHandle, stream: StreamId, data: &[u8]) -> Result<usize, WriteError> {
        let r = self.connections[conn.0].write(stream, data);
        match r {
            Ok(n) => {
                self.dirty_conns.insert(conn);
                trace!(self.log, "write"; "connection" => %self.connections[conn.0].local_id, "stream" => stream.0, "len" => n)
            }
            Err(WriteError::Blocked) => {
                if self.connections[conn.0].congestion_blocked() {
                    trace!(self.log, "write blocked by congestion"; "connection" => %self.connections[conn.0].local_id);
                } else {
                    trace!(self.log, "write blocked by flow control"; "connection" => %self.connections[conn.0].local_id, "stream" => stream.0);
                }
            }
            _ => {}
        }
        r
    }

    /// Indicate that no more data will be sent on a stream
    ///
    /// All previously transmitted data will still be delivered. Incoming data on bidirectional streams is unaffected.
    ///
    /// # Panics
    /// - when applied to a stream that does not have an active outgoing channel
    pub fn finish(&mut self, conn: ConnectionHandle, stream: StreamId) {
        self.connections[conn.0].finish(stream);
        self.dirty_conns.insert(conn);
    }

    /// Read data from a stream
    ///
    /// Treats a stream like a simple pipe, similar to a TCP connection. Subject to head-of-line blocking within the
    /// stream. Consider `read_unordered` for higher throughput.
    ///
    /// # Panics
    /// - when applied to a stream that does not have an active incoming channel
    pub fn read(&mut self, conn: ConnectionHandle, stream: StreamId, buf: &mut [u8]) -> Result<usize, ReadError> {
        self.dirty_conns.insert(conn); // May need to send flow control frames after reading
        match self.connections[conn.0].read(stream, buf) {
            x@Err(ReadError::Finished) | x@Err(ReadError::Reset { .. }) => {
                self.connections[conn.0].maybe_cleanup(stream);
                x
            }
            x => x
        }
    }

    /// Read data from a stream out of order
    ///
    /// Unlike `read`, this interface is not subject to head-of-line blocking within the stream, and hence can achieve
    /// higher throughput over lossy links.
    ///
    /// Some segments may be received multiple times.
    ///
    /// On success, returns `Ok((data, offset))` where `offset` is the position `data` begins in the stream.
    ///
    /// # Panics
    /// - when applied to a stream that does not have an active incoming channel
    pub fn read_unordered(&mut self, conn: ConnectionHandle, stream: StreamId) -> Result<(Bytes, u64), ReadError> {
        self.dirty_conns.insert(conn); // May need to send flow control frames after reading
        match self.connections[conn.0].read_unordered(stream) {
            x@Err(ReadError::Finished) | x@Err(ReadError::Reset { .. }) => {
                self.connections[conn.0].maybe_cleanup(stream);
                x
            }
            x => x
        }
    }

    /// Abandon transmitting data on a stream
    ///
    /// # Panics
    /// - when applied to a receive stream or an unopened send stream
    pub fn reset(&mut self, conn: ConnectionHandle, stream: StreamId, error_code: u16) {
        assert!(stream.directionality() == Directionality::Bi || stream.initiator() == self.connections[conn.0].side,
                "only streams supporting outgoing data may be reset");
        {
            // reset is a noop on a closed stream
            let stream = if let Some(x) = self.connections[conn.0].streams.get_mut(&stream) { x.send_mut().unwrap() } else { return; };
            match stream.state {
                stream::SendState::DataRecvd | stream::SendState::ResetSent { .. } | stream::SendState::ResetRecvd { .. } => { return; } // Nothing to do
                _ => {}
            }
            stream.state = stream::SendState::ResetSent { stop_reason: None };
        }
        self.connections[conn.0].pending.rst_stream.push((stream, error_code));
        self.dirty_conns.insert(conn);
    }

    /// Instruct the peer to abandon transmitting data on a stream
    ///
    /// # Panics
    /// - when applied to a stream that has not begin receiving data
    pub fn stop_sending(&mut self, conn: ConnectionHandle, stream: StreamId, error_code: u16) {
        self.connections[conn.0].stop_sending(stream, error_code);
        self.dirty_conns.insert(conn);
    }

    /// Create a new stream
    ///
    /// Returns `None` if the maximum number of streams currently permitted by the remote endpoint are already open.
    pub fn open(&mut self, conn: ConnectionHandle, direction: Directionality) -> Option<StreamId> {
        self.connections[conn.0].open(&self.config, direction)
    }

    /// Ping the remote endpoint
    ///
    /// Useful for preventing an otherwise idle connection from timing out.
    pub fn ping(&mut self, conn: ConnectionHandle) {
        self.connections[conn.0].pending.ping = true;
        self.dirty_conns.insert(conn);
    }

    fn close_common(&mut self, now: u64, conn: ConnectionHandle) {
        trace!(self.log, "connection closed");
        self.connections[conn.0].set_loss_detection = Some(None);
        self.io.push_back(Io::TimerStart {
            connection: conn,
            timer: Timer::Close,
            time: now + 3 * self.connections[conn.0].rto(&self.config),
        });
    }

    /// Close a connection immediately
    ///
    /// This does not ensure delivery of outstanding data. It is the application's responsibility to call this only when
    /// all important communications have been completed.
    pub fn close(&mut self, now: u64, conn: ConnectionHandle, error_code: u16, reason: Bytes) {
        if let &State::Drained = self.connections[conn.0].state.as_ref().unwrap() {
            self.forget(conn);
            return;
        }

        let was_closed = self.connections[conn.0].state.as_ref().unwrap().is_closed();
        let reason = state::CloseReason::Application(frame::ApplicationClose { error_code, reason });
        if !was_closed {
            self.close_common(now, conn);
            self.io.push_back(Io::Transmit {
                destination: self.connections[conn.0].remote,
                packet: self.connections[conn.0].make_close(&reason),
            });
            self.reset_idle_timeout(now, conn);
            self.dirty_conns.insert(conn);
        }
        self.connections[conn.0].state = Some(match self.connections[conn.0].state.take().unwrap() {
            State::Handshake(_) => State::HandshakeFailed(state::HandshakeFailed { reason, alert: None, app_closed: true }),
            State::HandshakeFailed(x) => State::HandshakeFailed(state::HandshakeFailed { app_closed: true, ..x }),
            State::Established(_) => State::Closed(state::Closed { reason, app_closed: true }),
            State::Closed(x) => State::Closed(state::Closed { app_closed: true, ..x}),
            State::Draining(x) => State::Draining(state::Draining { app_closed: true, ..x}),
            State::Drained => unreachable!(),
        });
    }

    fn on_packet_authenticated(&mut self, now: u64, conn: ConnectionHandle, packet: u64) {
        self.reset_idle_timeout(now, conn);
        self.connections[conn.0].on_packet_authenticated(now, packet);
    }

    /// Look up whether we're the client or server of `conn`.
    pub fn get_side(&self, conn: ConnectionHandle) -> Side { self.connections[conn.0].side }

    /// The `ConnectionId` used for `conn` locally.
    pub fn get_local_id(&self, conn: ConnectionHandle) -> &ConnectionId { &self.connections[conn.0].local_id }
    /// The `ConnectionId` used for `conn` by the peer.
    pub fn get_remote_id(&self, conn: ConnectionHandle) -> &ConnectionId { &self.connections[conn.0].remote_id }
    pub fn get_remote_address(&self, conn: ConnectionHandle) -> &SocketAddrV6 { &self.connections[conn.0].remote }
    pub fn get_protocol(&self, conn: ConnectionHandle) -> Option<&[u8]> {
        if let State::Established(ref state) = *self.connections[conn.0].state.as_ref().unwrap() {
            state.tls.ssl().selected_alpn_protocol()
        } else { None }
    }

    /// Number of bytes worth of non-ack-only packets that may be sent
    pub fn get_congestion_state(&self, conn: ConnectionHandle) -> u64 {
        let c = &self.connections[conn.0];
        c.congestion_window.saturating_sub(c.bytes_in_flight)
    }

    pub fn accept(&mut self) -> Option<ConnectionHandle> { self.incoming.pop_front() }
}

/// Protocol-level identifier for a connection.
///
/// Mainly useful for identifying this connection's packets on the wire with tools like Wireshark.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ConnectionId(ArrayVec<[u8; MAX_CID_SIZE]>);

impl ::std::ops::Deref for ConnectionId {
    type Target = [u8];
    fn deref(&self) -> &[u8] { &self.0 }
}

impl ::std::ops::DerefMut for ConnectionId {
    fn deref_mut(&mut self) -> &mut [u8] { &mut self.0 }
}

impl ConnectionId {
    fn random<R: Rng>(rng: &mut R, len: u8) -> Self {
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


struct Connection {
    local_id: ConnectionId,
    remote_id: ConnectionId,
    remote: SocketAddrV6,
    state: Option<State>,
    side: Side,
    mtu: u16,
    rx_packet: u64,
    rx_packet_time: u64,
    crypto: Option<CryptoContext>,
    prev_crypto: Option<(u64, CryptoContext)>,
    key_phase: bool,
    params: TransportParameters,
    /// Streams with data buffered for reading by the application
    readable_streams: FnvHashSet<StreamId>,
    /// Streams on which writing was blocked on *connection-level* flow or congestion control
    blocked_streams: FnvHashSet<StreamId>,
    /// Limit on outgoing data, dictated by peer
    max_data: u64,
    data_sent: u64,
    /// Sum of end offsets of all streams. Includes gaps, so it's an upper bound.
    data_recvd: u64,
    /// Limit on incoming data
    local_max_data: u64,

    //
    // Loss Detection
    // 

    /// The number of times the handshake packets have been retransmitted without receiving an ack.
    handshake_count: u32,
    /// The number of times a tail loss probe has been sent without receiving an ack.
    tlp_count: u32,
    /// The number of times an rto has been sent without receiving an ack.
    rto_count: u32,
    /// The largest packet number gap between the largest acked retransmittable packet and an unacknowledged
    /// retransmittable packet before it is declared lost.
    reordering_threshold: u32,
    /// The time at which the next packet will be considered lost based on early transmit or exceeding the reordering
    /// window in time.
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
    /// The time the most recently sent retransmittable packet was sent.
    time_of_last_sent_retransmittable_packet: u64,
    /// The time the most recently sent handshake packet was sent.
    time_of_last_sent_handshake_packet: u64,
    /// The packet number of the most recently sent packet.
    largest_sent_packet: u64,
    /// The largest packet number the remote peer acknowledged in an ACK frame.
    largest_acked_packet: u64,
    /// Transmitted but not acked
    sent_packets: BTreeMap<u64, SentPacket>,

    //
    // Congestion Control
    //

    /// The sum of the size in bytes of all sent packets that contain at least one retransmittable frame, and have not
    /// been acked or declared lost.
    ///
    /// The size does not include IP or UDP overhead. Packets only containing ACK frames do not count towards
    /// bytes_in_flight to ensure congestion control does not impede congestion feedback.
    bytes_in_flight: u64,
    /// Maximum number of bytes in flight that may be sent.
    congestion_window: u64,
    /// The largest packet number sent when QUIC detects a loss. When a larger packet is acknowledged, QUIC exits recovery.
    end_of_recovery: u64,
    /// Slow start threshold in bytes. When the congestion window is below ssthresh, the mode is slow start and the
    /// window grows by the number of bytes acknowledged.
    ssthresh: u64,

    //
    // Handshake retransmit state
    //

    handshake_sent: u64,
    handshake_pending: Retransmits,
    handshake_crypto: CryptoContext,

    //
    // Transmit queue
    //

    pending: Retransmits,
    pending_acks: RangeSet,
    /// Set iff we have received a non-ack frame since the last ack-only packet we sent
    permit_ack_only: bool,

    // Timer updates: None if no change, Some(None) to stop, Some(Some(_)) to reset

    set_idle: Option<Option<u64>>,
    set_loss_detection: Option<Option<u64>>,

    //
    // Stream states
    //
    streams: FnvHashMap<StreamId, Stream>,
    next_uni_stream: u64,
    next_bi_stream: u64,
    // Locally initiated
    max_uni_streams: u64,
    max_bi_streams: u64,
    // Remotely initiated
    max_remote_uni_stream: u64,
    max_remote_bi_stream: u64,
    finished_streams: Vec<StreamId>,
}

/// Represents one or more packets subject to retransmission
#[derive(Debug, Clone)]
struct SentPacket {
    time: u64,
    /// 0 iff ack-only
    bytes: u16,
    handshake: bool,
    acks: RangeSet,
    retransmits: Retransmits
}

impl SentPacket {
    fn ack_only(&self) -> bool { self.bytes == 0 }
}

#[derive(Debug, Clone)]
struct Retransmits {
    max_data: bool,
    max_uni_stream_id: bool,
    max_bi_stream_id: bool,
    ping: bool,
    new_connection_id: Option<ConnectionId>,
    stream: VecDeque<frame::Stream>,
    /// packet number, token
    path_response: Option<(u64, u64)>,
    rst_stream: Vec<(StreamId, u16)>,
    stop_sending: Vec<(StreamId, u16)>,
    max_stream_data: FnvHashSet<StreamId>,
 }

impl Retransmits {
    fn is_empty(&self) -> bool {
        !self.max_data && !self.max_uni_stream_id && !self.max_bi_stream_id && !self.ping
            && self.new_connection_id.is_none() && self.stream.is_empty() && self.path_response.is_none()
            && self.rst_stream.is_empty() && self.stop_sending.is_empty() && self.max_stream_data.is_empty()
    }

    fn path_challenge(&mut self, packet: u64, token: u64) {
        match self.path_response {
            None => { self.path_response = Some((packet, token)); }
            Some((existing, _)) if packet > existing => { self.path_response = Some((packet, token)); }
            Some(_) => {}
        }
    }
}

impl Default for Retransmits {
    fn default() -> Self { Self {
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
    }}
}

impl ::std::ops::AddAssign for Retransmits {
    fn add_assign(&mut self, rhs: Self) {
        self.max_data |= rhs.max_data;
        self.ping |= rhs.ping;
        self.max_uni_stream_id |= rhs.max_uni_stream_id;
        self.max_bi_stream_id |= rhs.max_bi_stream_id;
        if let Some(x) = rhs.new_connection_id { self.new_connection_id = Some(x); }
        self.stream.extend(rhs.stream.into_iter());
        if let Some((packet, token)) = rhs.path_response { self.path_challenge(packet, token); }
        self.rst_stream.extend_from_slice(&rhs.rst_stream);
        self.stop_sending.extend_from_slice(&rhs.stop_sending);
        self.max_stream_data.extend(&rhs.max_stream_data);
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

impl Connection {
    fn new(handshake_crypto: CryptoContext, local_id: ConnectionId, remote_id: ConnectionId, remote: SocketAddrV6,
           initial_packet_number: u64, side: Side, config: &Config) -> Self
    {
        let mut streams = FnvHashMap::default();
        streams.insert(StreamId(0), Stream::new_bi(config.stream_receive_window as u64));
        for i in 0..config.max_remote_uni_streams {
            streams.insert(StreamId::new(!side, Directionality::Uni, i as u64), stream::Recv::new(config.stream_receive_window as u64).into());
        }
        for i in match side { Side::Client => 0..config.max_remote_bi_streams, Side::Server => 1..(config.max_remote_bi_streams+1) } {
            streams.insert(StreamId::new(!side, Directionality::Bi, i as u64), Stream::new_bi(config.stream_receive_window as u64).into());
        }
        Self {
            local_id, remote_id, remote, side,
            state: None,
            mtu: MIN_MTU,
            rx_packet: 0,
            rx_packet_time: 0,
            crypto: None,
            prev_crypto: None,
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
            reordering_threshold: if config.using_time_loss_detection { u32::max_value() } else { config.reordering_threshold },
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

            handshake_sent: 0,
            handshake_pending: Retransmits::default(),
            handshake_crypto,

            pending: Retransmits::default(),
            pending_acks: RangeSet::new(),
            permit_ack_only: false,

            set_idle: None,
            set_loss_detection: None,

            streams,
            next_uni_stream: 0,
            next_bi_stream: match side { Side::Client => 1, Side::Server => 0 },
            max_uni_streams: 0,
            max_bi_streams: 0,
            max_remote_uni_stream: config.max_remote_uni_streams as u64,
            max_remote_bi_stream: config.max_remote_bi_streams as u64,
            finished_streams: Vec::new(),
        }
    }

    fn get_tx_number(&mut self) -> u64 {
        self.largest_sent_packet = self.largest_sent_packet.overflowing_add(1).0;
        // TODO: Handle packet number overflow gracefully
        assert!(self.largest_sent_packet <= 2u64.pow(62)-1);
        self.largest_sent_packet
    }

    /// Returns new loss detection alarm time, if applicable
    fn on_packet_sent(&mut self, config: &Config, now: u64, packet_number: u64, packet: SentPacket) {
        self.largest_sent_packet = packet_number;
        let bytes = packet.bytes;
        let handshake = packet.handshake;
        if handshake {
            self.handshake_sent += 1;
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
    fn on_ack_received(&mut self, config: &Config, now: u64, ack: frame::Ack) {
        self.largest_acked_packet = cmp::max(self.largest_acked_packet, ack.largest); // TODO: Validate
        if let Some(info) = self.sent_packets.get(&ack.largest).cloned() {
            self.latest_rtt = now - info.time;
            let delay = ack.delay << self.params.ack_delay_exponent;
            self.update_rtt(delay, info.ack_only());
        }
        for range in &ack {
            // Avoid DoS from unreasonably huge ack ranges
            let packets = self.sent_packets.range(range).map(|(&n, _)| n).collect::<Vec<_>>();
            for packet in packets {
                if let Some(bytes) = self.sent_packets.get(&packet).map(|x| x.bytes) {
                    self.on_packet_acked(config, packet, bytes)
                }
            }
        }
        self.detect_lost_packets(config, now, ack.largest);
        self.set_loss_detection_alarm(config);
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
        let info = self.sent_packets.remove(&packet).unwrap();

        // Update state for confirmed delivery of frames
        self.handshake_sent -= info.handshake as u64;
        for (id, _) in info.retransmits.rst_stream {
            if let stream::SendState::ResetSent { stop_reason } = self.streams.get_mut(&id).unwrap().send_mut().unwrap().state {
                self.streams.get_mut(&id).unwrap().send_mut().unwrap().state = stream::SendState::ResetRecvd { stop_reason };
                if stop_reason.is_none() {
                    self.maybe_cleanup(id);
                }
            }
        }
        for frame in info.retransmits.stream {
            let recvd = {
                let ss = if let Some(x) = self.streams.get_mut(&frame.id) { x.send_mut().unwrap() } else { continue; };
                ss.bytes_in_flight -= frame.data.len() as u64;
                if ss.state == stream::SendState::DataSent && ss.bytes_in_flight == 0 {
                    ss.state = stream::SendState::DataRecvd;
                    true
                } else { false }
            };
            if recvd {
                self.maybe_cleanup(frame.id);
                self.finished_streams.push(frame.id);
            }
        }
        self.pending_acks.subtract(&info.acks);
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
        for (&packet, info) in self.sent_packets.range(0..largest_acked) {
            let time_since_sent = now - info.time;
            let delta = largest_acked - packet;
            if time_since_sent > delay_until_lost || delta > self.reordering_threshold as u64 {
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
                self.congestion_window = (self.congestion_window * config.loss_reduction_factor as u64) >> 16;
                self.congestion_window = cmp::max(self.congestion_window, config.minimum_window);
                self.ssthresh = self.congestion_window;
            }
        }
    }

    fn in_recovery(&self, packet: u64) -> bool { packet <= self.end_of_recovery }

    fn set_loss_detection_alarm(&mut self, config: &Config) {
        if self.bytes_in_flight == 0 {
            self.set_loss_detection = Some(None);
            return;
        }

        let mut alarm_duration: u64;
        if self.handshake_sent != 0 || !self.handshake_pending.is_empty() {
            // Handshake retransmission alarm.
            if self.smoothed_rtt == 0 {
                alarm_duration = 2 * config.default_initial_rtt;
            } else {
                alarm_duration = 2 * self.smoothed_rtt;
            }
            alarm_duration = cmp::max(alarm_duration + self.max_ack_delay,
                                      config.min_tlp_timeout);
            alarm_duration = alarm_duration * 2u64.pow(self.handshake_count);
            self.set_loss_detection = Some(Some(self.time_of_last_sent_handshake_packet + alarm_duration));
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
                let tlp_duration = cmp::max((3 * self.smoothed_rtt) / 2 + self.max_ack_delay,
                                            config.min_tlp_timeout);
                alarm_duration = cmp::min(alarm_duration, tlp_duration);
            }
        }
        self.set_loss_detection = Some(Some(self.time_of_last_sent_retransmittable_packet + alarm_duration));
    }

    /// Retransmit time-out
    fn rto(&self, config: &Config) -> u64 {
        let computed = self.smoothed_rtt + 4 * self.rttvar + self.max_ack_delay;
        cmp::max(computed, config.min_rto_timeout) * 2u64.pow(self.rto_count)
    }

    fn on_packet_authenticated(&mut self, now: u64, packet: u64) {
        self.pending_acks.insert_one(packet);
        if self.pending_acks.len() > MAX_ACK_BLOCKS {
            self.pending_acks.pop_min();
        }
        if packet > self.rx_packet {
            self.rx_packet = packet;
            self.rx_packet_time = now;
        }
    }

    fn update_keys(&mut self, packet: u64, header: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
        let new = self.crypto.as_mut().unwrap().update(self.side);
        let data = new.decrypt(packet, header, payload)?;
        let old = mem::replace(self.crypto.as_mut().unwrap(), new);
        self.prev_crypto = Some((packet, old));
        self.key_phase = !self.key_phase;
        Some(data)
    }

    fn decrypt(&self, handshake: bool, packet: u64, header: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
        if handshake {
            self.handshake_crypto.decrypt(packet, header, payload)
        } else {
            if let Some((boundary, ref prev)) = self.prev_crypto {
                if packet < boundary {
                    return prev.decrypt(packet, header, payload);
                }
            }
            self.crypto.as_ref().unwrap().decrypt(packet, header, payload)
        }
    }

    fn transmit(&mut self, stream: StreamId, data: Bytes) {
        let ss = self.streams.get_mut(&stream).unwrap().send_mut().unwrap();
        assert_eq!(ss.state, stream::SendState::Ready);
        let offset = ss.offset;
        ss.offset += data.len() as u64;
        ss.bytes_in_flight += data.len() as u64;
        if stream != StreamId(0) {
            self.data_sent += data.len() as u64;
        }
        self.pending.stream.push_back(frame::Stream {
            offset, fin: false, data,
            id: stream,
        });
    }

    fn next_packet(&mut self, log: &Logger, config: &Config, now: u64) -> Option<Vec<u8>> {
        let is_handshake;
        match *self.state.as_ref().unwrap() {
            ref x if x.is_closed() => { return None; }
            State::Handshake(_) => { is_handshake = true; }
            _ => is_handshake = !self.handshake_pending.is_empty()
        };

        let mut buf = Vec::new();
        let mut sent = Retransmits::default();
        let acks;
        let number;
        let ack_only;
        let is_initial;
        let header_len;

        {
            let pending;
            if is_handshake {
                // Special case: (re)transmit handshake data in long-header packets
                if self.handshake_pending.is_empty() { return None; }
                buf.reserve_exact(self.mtu as usize);
                number = self.get_tx_number();
                trace!(log, "sending handshake packet"; "pn" => number);
                let ty = if self.side == Side::Client && self.handshake_pending.stream.front().map_or(false, |x| x.offset == 0) {
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
                    ty, number: number as u32, source_id: self.local_id.clone(), destination_id: self.remote_id.clone()
                }.encode(&mut buf);
                pending = &mut self.handshake_pending;
            } else {
                is_initial = false;
                if self.congestion_blocked() || self.pending.is_empty() && (!self.permit_ack_only || self.pending_acks.is_empty())
                {
                    return None;
                }
                number = self.get_tx_number();
                buf.reserve_exact(self.mtu as usize);
                trace!(log, "sending protected packet"; "pn" => number);

                Header::Short {
                    id: self.remote_id.clone(),
                    number: PacketNumber::new(number, self.largest_acked_packet),
                    key_phase: self.key_phase
                }.encode(&mut buf);
                pending = &mut self.pending;
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
            // TODO: Don't ack protected packets in handshake packets
            if !self.pending_acks.is_empty() {
                trace!(log, "ACK"; "ranges" => ?self.pending_acks.iter().collect::<Vec<_>>());
                let delay = now - self.rx_packet_time;
                frame::Ack::encode(delay >> ACK_DELAY_EXPONENT, &self.pending_acks, &mut buf);
            }
            acks = self.pending_acks.clone();

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
                let (id, error_code) = if let Some(x) = pending.rst_stream.pop() { x } else { break; };
                let stream = if let Some(x) = self.streams.get(&id) { x } else { continue; };
                trace!(log, "RST_STREAM"; "stream" => id.0);
                sent.rst_stream.push((id, error_code));
                frame::RstStream {
                    id, error_code,
                    final_offset: stream.send().unwrap().offset,
                }.encode(&mut buf);
            }

            // STOP_SENDING
            while buf.len() + 11 < max_size {
                let (id, error_code) = if let Some(x) = pending.stop_sending.pop() { x } else { break; };
                let stream = if let Some(x) = self.streams.get(&id) { x.recv().unwrap() } else { continue; };
                if stream.is_finished() { continue; }
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
                let id = if let Some(x) = pending.max_stream_data.iter().next() { *x } else { break; };
                pending.max_stream_data.remove(&id);
                let rs = if let Some(x) = self.streams.get(&id) { x.recv().unwrap() } else { continue; };
                if rs.is_finished() { continue; }
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
                buf.write(StreamId::new(!self.side, Directionality::Uni, self.max_remote_uni_stream));
            }

            // MAX_STREAM_ID bi
            if pending.max_bi_stream_id && buf.len() + 9 < max_size {
                pending.max_bi_stream_id = false;
                sent.max_bi_stream_id = true;
                trace!(log, "MAX_STREAM_ID (bidirectional)");
                buf.write(frame::Type::MAX_STREAM_ID);
                buf.write(StreamId::new(!self.side, Directionality::Bi, self.max_remote_bi_stream));
            }

            // STREAM
            while buf.len() + 25 < max_size {
                let mut stream = if let Some(x) = pending.stream.pop_front() { x } else { break; };
                if stream.id != StreamId(0) && self.streams.get(&stream.id).map_or(true, |s| s.send().unwrap().state.was_reset()) {
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
                    let stream = frame::Stream { offset: stream.offset + len as u64, ..stream };
                    pending.stream.push_front(stream);
                }
            }
        }

        if is_initial && buf.len() < MIN_INITIAL_SIZE - AEAD_TAG_SIZE {
            buf.resize(MIN_INITIAL_SIZE - AEAD_TAG_SIZE, frame::Type::PADDING.into());
        }
        if is_handshake {
            set_payload_length(&mut buf, header_len as usize);
        }
        self.encrypt(is_handshake, number, &mut buf, header_len);

        self.on_packet_sent(config, now, number, SentPacket {
            acks,
            time: now, bytes: if ack_only { 0 } else { buf.len() as u16 },
            handshake: is_handshake,
            retransmits: sent,
        });

        // If we have any acks, we just sent them; don't immediately resend.  Setting this even if ack_only is false
        // needlessly prevents us from ACKing the next packet if it's ACK-only, but saves the need for subtler logic to
        // avoid double-transmitting acks all the time.
        self.permit_ack_only = false;
        Some(buf)
    }

    fn encrypt(&self, handshake: bool, number: u64, buf: &mut Vec<u8>, header_len: u16) {
        let payload = if handshake {
            self.handshake_crypto.encrypt(number, &buf[0..header_len as usize], &buf[header_len as usize..])
        } else {
            self.crypto.as_ref().unwrap().encrypt(number, &buf[0..header_len as usize], &buf[header_len as usize..])
        };
        debug_assert_eq!(payload.len(), buf.len() - header_len as usize + AEAD_TAG_SIZE);
        buf.truncate(header_len as usize);
        buf.extend_from_slice(&payload);
    }

    // TLP/RTO transmit
    fn force_transmit(&mut self, config: &Config, now: u64) -> Box<[u8]> {
        let number = self.get_tx_number();
        let mut buf = Vec::new();
        Header::Short {
            id: self.remote_id.clone(),
            number: PacketNumber::new(number, self.largest_acked_packet),
            key_phase: self.key_phase
        }.encode(&mut buf);
        let header_len = buf.len() as u16;
        buf.push(frame::Type::PING.into());
        self.encrypt(false, number, &mut buf, header_len);
        self.on_packet_sent(config, now, number, SentPacket {
            time: now, bytes: buf.len() as u16, handshake: false, acks: RangeSet::new(), retransmits: Retransmits::default()
        });
        buf.into()
    }

    fn make_close(&mut self, reason: &state::CloseReason) -> Box<[u8]> {
        let number = self.get_tx_number();
        let mut buf = Vec::new();
        Header::Short {
            id: self.remote_id.clone(),
            number: PacketNumber::new(number, self.largest_acked_packet),
            key_phase: self.key_phase
        }.encode(&mut buf);
        let header_len = buf.len() as u16;
        let max_len = self.mtu - header_len - AEAD_TAG_SIZE as u16;
        match *reason {
            state::CloseReason::Application(ref x) => x.encode(&mut buf, max_len),
            state::CloseReason::Connection(ref x) => x.encode(&mut buf, max_len),
        }
        self.encrypt(false, number, &mut buf, header_len);
        buf.into()
    }

    fn set_params(&mut self, config: &Config, params: TransportParameters) {
        self.max_bi_streams = params.initial_max_streams_bidi as u64;
        self.max_uni_streams = params.initial_max_streams_uni as u64;
        self.max_data = params.initial_max_data as u64;
        for i in match self.side { Side::Client => 0..config.max_remote_bi_streams, Side::Server => 0..(config.max_remote_bi_streams+1) } {
            let id = StreamId::new(!self.side, Directionality::Bi, i as u64);
            self.streams.get_mut(&id).unwrap().send_mut().unwrap().max_data = params.initial_max_stream_data as u64;
        }
        self.params = params;
    }

    fn open(&mut self, config: &Config, direction: Directionality) -> Option<StreamId> {
        let (id, mut stream) = match direction {
            Directionality::Uni if self.next_uni_stream < self.max_uni_streams => {
                self.next_uni_stream += 1;
                (StreamId::new(self.side, direction, self.next_uni_stream - 1), stream::Send::new().into())
            }
            Directionality::Bi if self.next_bi_stream < self.max_bi_streams => {
                self.next_bi_stream += 1;
                (StreamId::new(self.side, direction, self.next_bi_stream - 1), Stream::new_bi(config.stream_receive_window as u64))
            }
            _ => { return None; } // TODO: Queue STREAM_ID_BLOCKED
        };
        stream.send_mut().unwrap().max_data = self.params.initial_max_stream_data as u64;
        let old = self.streams.insert(id, stream);
        assert!(old.is_none());
        Some(id)
    }

    /// Discard state for a stream if it's fully closed.
    ///
    /// Called when one side of a stream transitions to a closed state
    fn maybe_cleanup(&mut self, id: StreamId) {
        match self.streams.entry(id) {
            hash_map::Entry::Vacant(_) => unreachable!(),
            hash_map::Entry::Occupied(e) => {
                if e.get().is_closed() {
                    e.remove_entry();
                    if id.initiator() != self.side {
                        match id.directionality() {
                            Directionality::Uni => {
                                self.max_remote_uni_stream += 1;
                                self.pending.max_uni_stream_id = true;
                            }
                            Directionality::Bi => {
                                self.max_remote_bi_stream += 1;
                                self.pending.max_bi_stream_id = true;
                            }
                        }
                    }
                }
            }
        }
    }

    fn finish(&mut self, id: StreamId) {
        let ss = self.streams.get_mut(&id).expect("unknown stream").send_mut().expect("recv-only stream");
        assert_eq!(ss.state, stream::SendState::Ready);
        ss.state = stream::SendState::DataSent;
        for frame in &mut self.pending.stream {
            if frame.id == id && frame.offset + frame.data.len() as u64 == ss.offset {
                frame.fin = true;
                return;
            }
        }
        self.pending.stream.push_back(frame::Stream { id, data: Bytes::new(), offset: ss.offset, fin: true });
    }

    fn read_unordered(&mut self, id: StreamId) -> Result<(Bytes, u64), ReadError> {
        assert_ne!(id, StreamId(0), "cannot read an internal stream");
        let rs = self.streams.get_mut(&id).unwrap().recv_mut().unwrap();
        rs.unordered = true;
        // TODO: Drain rs.assembler to handle ordered-then-unordered reads reliably

        // Return data we already have buffered, regardless of state
        if let Some(x) = rs.buffered.pop_front() {
            // TODO: Reduce granularity of flow control credit, while still avoiding stalls, to reduce overhead
            self.local_max_data += x.0.len() as u64;
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

    fn read(&mut self, id: StreamId, buf: &mut [u8]) -> Result<usize, ReadError> {
        assert_ne!(id, StreamId(0), "cannot read an internal stream");
        let rs = self.streams.get_mut(&id).unwrap().recv_mut().unwrap();
        assert!(!rs.unordered, "cannot perform ordered reads following unordered reads on a stream");

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

    fn stop_sending(&mut self, id: StreamId, error_code: u16) {
        assert!(id.directionality() == Directionality::Bi || id.initiator() != self.side,
                "only streams supporting incoming data may be reset");
        let stream = self.streams.get(&id).expect("stream must have begun sending to be stopped")
            .recv().unwrap();
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

    fn decrypt_packet(&mut self, handshake: bool, packet: Packet) -> Result<(Vec<u8>, u64), Option<TransportError>> {
        let (key_phase, number) = match packet.header {
            Header::Short { key_phase, number, .. } if !handshake => (key_phase, number),
            Header::Long { number, .. } if handshake => (false, PacketNumber::U32(number)),
            _ => { return Err(None); }
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
        } else if let Some(payload) = self.decrypt(handshake, number, &packet.header_data, &packet.payload) {
            Ok((payload, number))
        } else {
            // Unable to authenticate
            Err(None)
        }
    }

    fn get_recv_stream(&mut self, id: StreamId) -> Result<Option<&mut Stream>, TransportError> {
        if self.side == id.initiator() {
            match id.directionality() {
                Directionality::Uni => { return Err(TransportError::STREAM_STATE_ERROR); }
                Directionality::Bi if id.index() >= self.next_bi_stream => { return Err(TransportError::STREAM_STATE_ERROR); }
                Directionality::Bi => {}
            };
        } else {
            let limit = match id.directionality() {
                Directionality::Bi => self.max_remote_bi_stream,
                Directionality::Uni => self.max_remote_uni_stream,
            };
            if id.index() > limit {
                return Err(TransportError::STREAM_ID_ERROR);
            }
        }
        Ok(self.streams.get_mut(&id))
    }

    fn write(&mut self, stream: StreamId, data: &[u8]) -> Result<usize, WriteError> {
        if self.state.as_ref().unwrap().is_closed() { return Err(WriteError::Blocked); }
        assert!(stream.directionality() == Directionality::Bi || stream.initiator() == self.side);
        if self.blocked() {
            self.blocked_streams.insert(stream);
            return Err(WriteError::Blocked);
        }
        let (stop_reason, stream_budget) = {
            let ss = self.streams.get_mut(&stream).expect("stream already closed").send_mut().unwrap();
            (match ss.state {
                stream::SendState::ResetSent  { ref mut stop_reason }
                | stream::SendState::ResetRecvd { ref mut stop_reason } => stop_reason.take(),
                _ => None,
            },
             ss.max_data - ss.offset)
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

#[derive(Debug, Clone)]
enum Header {
    Long {
        ty: u8,
        source_id: ConnectionId,
        destination_id: ConnectionId,
        number: u32,
    },
    Short {
        id: ConnectionId,
        number: PacketNumber,
        key_phase: bool,
    },
    VersionNegotiate {
        ty: u8,
        source_id: ConnectionId,
        destination_id: ConnectionId,
    }
}

impl Header {
    fn destination_id(&self) -> &ConnectionId {
        use self::Header::*;
        match *self {
            Long { ref destination_id, .. } => destination_id,
            Short { ref id, .. } => id,
            VersionNegotiate { ref destination_id, .. } => destination_id,
        }
    }

    fn key_phase(&self) -> bool {
        match *self {
            Header::Short { key_phase, .. } => key_phase,
            _ => false,
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
    fn new(n: u64, largest_acked: u64) -> Self {
        if largest_acked == 0 { return PacketNumber::U32(n as u32); }
        let range = (n - largest_acked) / 2;
        if range < 1 << 8 {
            PacketNumber::U8(n as u8)
        } else if range < 1 << 16 {
            PacketNumber::U16(n as u16)
        } else if range < 1 << 32 {
            PacketNumber::U32(n as u32)
        } else {
            panic!("packet number too large to encode")
        }
    }

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
            U8(x) => w.write(x),
            U16(x) => w.write(x),
            U32(x) => w.write(x),
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
            x + d * ((t + d/2 - x) / d)
        } else {
            x % d
        }
    }
}

const KEY_PHASE_BIT: u8 = 0x40;

impl Header {
    fn encode<W: BufMut>(&self, w: &mut W) {
        use self::Header::*;
        match *self {
            Long { ty, ref source_id, ref destination_id, number } => {
                w.write(0b10000000 | ty);
                w.write(VERSION);
                let mut dcil = destination_id.len() as u8;
                if dcil > 0 { dcil -= 3; }
                let mut scil = source_id.len() as u8;
                if scil > 0 { scil -= 3; }
                w.write(dcil << 4 | scil);
                w.put_slice(destination_id);
                w.put_slice(source_id);
                w.write::<u16>(0); // Placeholder for payload length; see `set_payload_length`
                w.write(number);
            }
            Short { ref id, number, key_phase } => {
                let ty = number.ty() | 0x30
                    | if key_phase { KEY_PHASE_BIT } else { 0 };
                w.write(ty);
                w.put_slice(id);
                number.encode(w);
            }
            VersionNegotiate { ty, ref source_id, ref destination_id } => {
                w.write(0x80 | ty);
                w.write::<u32>(0);
                let mut dcil = destination_id.len() as u8;
                if dcil > 0 { dcil -= 3; }
                let mut scil = source_id.len() as u8;
                if scil > 0 { scil -= 3; }
                w.write(dcil << 4 | scil);
                w.put_slice(destination_id);
                w.put_slice(source_id);
            }
        }
    }
}

struct Packet {
    header: Header,
    header_data: Bytes,
    payload: Bytes,
}

#[derive(Debug, Fail, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
enum HeaderError {
    #[fail(display = "unsupported version")]
    UnsupportedVersion { source: ConnectionId, destination: ConnectionId },
    #[fail(display = "invalid header")]
    InvalidHeader,
}

impl From<coding::UnexpectedEnd> for HeaderError {
    fn from(_: coding::UnexpectedEnd) -> Self { HeaderError::InvalidHeader }
}

impl Packet {
    fn decode(packet: &Bytes, dest_id_len: usize) -> Result<(Self, Bytes), HeaderError> {
        let mut buf = io::Cursor::new(&packet[..]);
        let ty = buf.get::<u8>()?;
        let long = ty & 0x80 != 0;
        let ty = ty & !0x80;
        let mut cid_stage = [0; MAX_CID_SIZE];
        if long {
            let version = buf.get::<u32>()?;
            let ci_lengths = buf.get::<u8>()?;
            let mut dcil = ci_lengths >> 4;
            if dcil > 0 { dcil += 3 };
            let mut scil = ci_lengths & 0xF;
            if scil > 0 { scil += 3 };
            if buf.remaining() < (dcil + scil) as usize { return Err(HeaderError::InvalidHeader); }
            buf.copy_to_slice(&mut cid_stage[0..dcil as usize]);
            let mut destination_id = ConnectionId(cid_stage.into());
            destination_id.0.truncate(dcil as usize);
            buf.copy_to_slice(&mut cid_stage[0..scil as usize]);
            let mut source_id = ConnectionId(cid_stage.into());
            source_id.0.truncate(scil as usize);
            Ok(match version {
                0 => {
                    let header_data = packet.slice(0, buf.position() as usize);
                    let payload = packet.slice(buf.position() as usize, packet.len());
                    (Packet {
                        header: Header::VersionNegotiate { ty, source_id, destination_id },
                        header_data, payload,
                    }, Bytes::new())
                }
                VERSION => {
                    let len = buf.get_var()?;
                    let number = buf.get()?;
                    let header_data = packet.slice(0, buf.position() as usize);
                    let payload = packet.slice(buf.position() as usize, (buf.position() + len) as usize);
                    (Packet {
                        header: Header::Long { ty, source_id, destination_id, number },
                        header_data, payload,
                    }, packet.slice((buf.position() + len) as usize, packet.len()))
                }
                _ => return Err(HeaderError::UnsupportedVersion { source: source_id, destination: destination_id }),
            })
        } else {
            if buf.remaining() < dest_id_len { return Err(HeaderError::InvalidHeader); }
            buf.copy_to_slice(&mut cid_stage[0..dest_id_len]);
            let mut id = ConnectionId(cid_stage.into());
            id.0.truncate(dest_id_len);
            let key_phase = ty & KEY_PHASE_BIT != 0;
            let number = match ty & 0b0111 {
                0x0 => PacketNumber::U8(buf.get()?),
                0x1 => PacketNumber::U16(buf.get()?),
                0x2 => PacketNumber::U32(buf.get()?),
                _ => { return Err(HeaderError::InvalidHeader); }
            };
            let header_data = packet.slice(0, buf.position() as usize);
            let payload = packet.slice(buf.position() as usize, packet.len());
            Ok((Packet {
                header: Header::Short { id, number, key_phase },
                header_data, payload,
            }, Bytes::new()))
        }
    }
}

enum State {
    Handshake(state::Handshake),
    Established(state::Established),
    HandshakeFailed(state::HandshakeFailed),
    Closed(state::Closed),
    Draining(state::Draining),
    /// Waiting for application to call close so we can dispose of the resources
    Drained,
}

impl State {
    fn closed<R: Into<state::CloseReason>>(reason: R) -> Self {
        State::Closed(state::Closed {
            reason: reason.into(), app_closed: false,
        })
    }

    fn handshake_failed<R: Into<state::CloseReason>>(reason: R, alert: Option<Box<[u8]>>) -> Self {
        State::HandshakeFailed(state::HandshakeFailed {
            reason: reason.into(), alert, app_closed: false,
        })
    }

    fn is_closed(&self) -> bool {
        match *self {
            State::HandshakeFailed(_) => true,
            State::Closed(_) => true,
            State::Draining(_) => true,
            State::Drained => true,
            _ => false,
        }
    }

    fn is_app_closed(&self) -> bool {
        match *self {
            State::HandshakeFailed(ref x) => x.app_closed,
            State::Closed(ref x) => x.app_closed,
            State::Draining(ref x) => x.app_closed,
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
        pub remote_id_set: bool,
    }

    pub struct Established {
        pub tls: SslStream<MemoryStream>,
    }

    pub struct HandshakeFailed { // Closed
        pub reason: CloseReason,
        pub alert: Option<Box<[u8]>>,
        pub app_closed: bool,
    }

    #[derive(Clone)]
    pub enum CloseReason {
        Connection(frame::ConnectionClose),
        Application(frame::ApplicationClose),
    }

    impl From<TransportError> for CloseReason { fn from(x: TransportError) -> Self { CloseReason::Connection(x.into()) } }
    impl From<frame::ConnectionClose> for CloseReason { fn from(x: frame::ConnectionClose) -> Self { CloseReason::Connection(x) } }
    impl From<frame::ApplicationClose> for CloseReason { fn from(x: frame::ApplicationClose) -> Self { CloseReason::Application(x) } }

    pub struct Closed {
        pub reason: CloseReason,
        pub app_closed: bool,
    }

    pub struct Draining {
        pub app_closed: bool,
    }

    impl From<Handshake> for Draining {
        fn from(_: Handshake) -> Self { Draining { app_closed: false } }
    }

    impl From<HandshakeFailed> for Draining {
        fn from(x: HandshakeFailed) -> Self { Draining { app_closed: x.app_closed } }
    }

    impl From<Established> for Draining {
        fn from(_: Established) -> Self { Draining { app_closed: false } }
    }

    impl From<Closed> for Draining {
        fn from(x: Closed) -> Self { Draining { app_closed: x.app_closed } }
    }
}

struct CookieFactory {
    mac_key: [u8; 64]
}

const COOKIE_MAC_BYTES: usize = 64;

impl CookieFactory {
    fn new(mac_key: [u8; 64]) -> Self {
        Self { mac_key }
    }

    fn generate(&self, conn: &ConnectionInfo, out: &mut [u8]) -> usize {
        let mac = self.generate_mac(conn);
        out[0..COOKIE_MAC_BYTES].copy_from_slice(&mac);
        COOKIE_MAC_BYTES
    }

    fn generate_mac(&self, conn: &ConnectionInfo) -> [u8; COOKIE_MAC_BYTES] {
        let mut mac = Blake2b::new_keyed(&self.mac_key, COOKIE_MAC_BYTES);
        mac.process(&conn.remote.ip().octets());
        {
            let mut buf = [0; 2];
            BigEndian::write_u16(&mut buf, conn.remote.port());
            mac.process(&buf);
        }
        let mut result = [0; COOKIE_MAC_BYTES];
        mac.variable_result(&mut result).unwrap();
        result
    }

    fn verify(&self, conn: &ConnectionInfo, cookie_data: &[u8]) -> bool {
        let expected = self.generate_mac(conn);
        if !constant_time_eq(cookie_data, &expected) { return false; }
        true
    }
}

struct ConnectionInfo {
    id: ConnectionId,
    remote: SocketAddrV6,
}

lazy_static! {
    static ref CONNECTION_INFO_INDEX: ex_data::Index<Ssl, ConnectionInfo> = Ssl::new_ex_index().unwrap();
    static ref TRANSPORT_PARAMS_INDEX: ex_data::Index<Ssl, Result<TransportParameters, ::transport_parameters::Error>>
        = Ssl::new_ex_index().unwrap();
}

/// Events of interest to the application
#[derive(Debug)]
pub enum Event {
    /// A connection was successfully established.
    Connected {
        protocol: Option<Box<[u8]>>,
    },
    /// A connection was lost.
    ConnectionLost {
        reason: ConnectionError
    },
    /// A closed connection was dropped.
    ConnectionDrained,
    /// A stream has data or errors waiting to be read
    StreamReadable {
        /// The affected stream
        stream: StreamId,
        /// Whether this is the first event on the stream
        fresh: bool,
    },
    /// A formerly write-blocked stream might now accept a write
    StreamWritable {
        stream: StreamId,
    },
    /// All data sent on `stream` has been received by the peer
    StreamFinished {
        stream: StreamId,
    },
    /// At least one new stream of a certain directionality may be opened
    StreamAvailable {
        directionality: Directionality,
    },
}

/// I/O operations to be immediately executed the backend.
#[derive(Debug)]
pub enum Io {
    Transmit {
        destination: SocketAddrV6,
        packet: Box<[u8]>,
    },
    /// Start or reset a timer
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

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum Timer {
    Close,
    LossDetection,
    Idle,
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
    fn from(x: TransportError) -> Self { ConnectionError::TransportError { error_code: x } }
}

impl From<ConnectionError> for io::Error {
    fn from(x: ConnectionError) -> io::Error {
        use self::ConnectionError::*;
        match x {
            TimedOut => io::Error::new(io::ErrorKind::TimedOut, "timed out"),
            Reset => io::Error::new(io::ErrorKind::ConnectionReset, "reset by peer"),
            ApplicationClosed { reason } => io::Error::new(io::ErrorKind::ConnectionAborted, format!("closed by peer application: {}", reason)),
            ConnectionClosed { reason } => io::Error::new(io::ErrorKind::ConnectionAborted, format!("peer detected an error: {}", reason)),
            TransportError { error_code } => io::Error::new(io::ErrorKind::Other, format!("{}", error_code)),
            VersionMismatch => io::Error::new(io::ErrorKind::Other, "version mismatch"),
        }
    }
}

mod packet {
    pub const INITIAL: u8 = 0x7F;
    pub const RETRY: u8 = 0x7E;
    pub const HANDSHAKE: u8 = 0x7D;
}

/// Forward data from an Initial or Retry packet to a stream for a TLS context
fn parse_initial(log: &Logger, stream: &mut MemoryStream, payload: Bytes) -> bool {
    for frame in frame::Iter::new(payload) {
        match frame {
            Frame::Padding => {}
            Frame::Ack(_) => {}
            Frame::Stream(frame::Stream { id: StreamId(0), fin: false, offset, data, .. }) => {
                stream.insert(offset, &data);
            }
            x => { debug!(log, "unexpected frame in initial/retry packet"; "ty" => %x.ty()); return false; } // Invalid packet
        }
    }
    if stream.read_blocked() {
        debug!(log, "initial/retry packet missing stream frame(s)");
        false
    } else { true }
}

fn handshake_close<R>(crypto: &CryptoContext,
                      remote_id: &ConnectionId, local_id: &ConnectionId, packet_number: u32,
                      reason: R) -> Box<[u8]>
    where R: Into<state::CloseReason>
{
    let mut buf = Vec::<u8>::new();
    Header::Long {
        ty: packet::HANDSHAKE, destination_id: remote_id.clone(), source_id: local_id.clone(), number: packet_number
    }.encode(&mut buf);
    let header_len = buf.len();
    let max_len = MIN_MTU - header_len as u16 - AEAD_TAG_SIZE as u16;
    match reason.into() {
        state::CloseReason::Application(ref x) => x.encode(&mut buf, max_len),
        state::CloseReason::Connection(ref x) => x.encode(&mut buf, max_len),
    }
    set_payload_length(&mut buf, header_len);
    let payload = crypto.encrypt(packet_number as u64, &buf[0..header_len], &buf[header_len..]);
    debug_assert_eq!(payload.len(), buf.len() - header_len + AEAD_TAG_SIZE);
    buf.truncate(header_len);
    buf.extend_from_slice(&payload);
    buf.into()
}

fn set_payload_length(packet: &mut [u8], header_len: usize) {
    let len = packet.len() - header_len + AEAD_TAG_SIZE;
    assert!(len < 2usize.pow(14)); // Fits in reserved space
    BigEndian::write_u16(&mut packet[header_len-6..], len as u16 | 0b01 << 14);
}

const HANDSHAKE_SALT: [u8; 20] = [0x9c, 0x10, 0x8f, 0x98, 0x52, 0x0a, 0x5c, 0x5c, 0x32, 0x96, 0x8e, 0x95, 0x0e, 0x8a, 0x2c, 0x5f, 0xe0, 0x6d, 0x6c, 0x38];

#[derive(Clone)]
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

    fn update(&self, digest: MessageDigest, cipher: Cipher, side: Side) -> CryptoState {
        let secret = hkdf::qexpand(digest, &self.secret, if side == Side::Client { b"client 1rtt" } else { b"server 1rtt" }, digest.size() as u16);
        Self::new(digest, cipher, secret)
    }
}

#[derive(Clone)]
pub struct CryptoContext {
    local: CryptoState,
    remote: CryptoState,
    digest: MessageDigest,
    cipher: Cipher,
}

impl CryptoContext {
    fn handshake(id: &ConnectionId, side: Side) -> Self {
        let digest = MessageDigest::sha256();
        let cipher = Cipher::aes_128_gcm();
        let hs_secret = hkdf::extract(digest, &HANDSHAKE_SALT, &id.0);
        let (local_label, remote_label) = if side == Side::Client { (b"client hs", b"server hs") } else { (b"server hs", b"client hs") };
        let local = CryptoState::new(digest, cipher, hkdf::qexpand(digest, &hs_secret, &local_label[..], digest.size() as u16));
        let remote = CryptoState::new(digest, cipher, hkdf::qexpand(digest, &hs_secret, &remote_label[..], digest.size() as u16));
        CryptoContext {
            local, remote, digest, cipher,
        }
    }

    fn established(tls: &SslRef, side: Side) -> Self {
        let tls_cipher = tls.current_cipher().unwrap();
        let digest = tls_cipher.handshake_digest().unwrap();
        let cipher = Cipher::from_nid(tls_cipher.cipher_nid().unwrap()).unwrap();

        const SERVER_LABEL: &str = "EXPORTER-QUIC server 1rtt";
        const CLIENT_LABEL: &str = "EXPORTER-QUIC client 1rtt";

        let (local_label, remote_label) = if side == Side::Client { (CLIENT_LABEL, SERVER_LABEL) } else { (SERVER_LABEL, CLIENT_LABEL) };
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

    fn update(&self, side: Side) -> Self {
        CryptoContext {
            local: self.local.update(self.digest, self.cipher, side),
            remote: self.local.update(self.digest, self.cipher, !side),
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
        // Order of operations regression test
        assert_eq!(PacketNumber::U32(0xa0bd197c).expand(0xa0bd197a), 0xa0bd197c);
    }

    #[test]
    fn handshake_crypto_roundtrip() {
        let conn = ConnectionId::random(&mut rand::thread_rng(), MAX_CID_SIZE as u8);
        let client = CryptoContext::handshake(&conn, Side::Client);
        let server = CryptoContext::handshake(&conn, Side::Server);
        let header = b"header";
        let payload = b"payload";
        let encrypted = client.encrypt(0, header, payload);
        let decrypted = server.decrypt(0, header, &encrypted).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn key_derivation() {
        let id = ConnectionId([0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08].iter().cloned().collect());
        let digest = MessageDigest::sha256();
        let cipher = Cipher::aes_128_gcm();
        let hs_secret = hkdf::extract(digest, &HANDSHAKE_SALT, &id.0);
        assert_eq!(&hs_secret[..],
                   [0xa5, 0x72, 0xb0, 0x24, 0x5a, 0xf1, 0xed, 0xdf,
                    0x5c, 0x61, 0xc6, 0xe3, 0xf7, 0xf9, 0x30, 0x4c,
                    0xa6, 0x6b, 0xfb, 0x4c, 0xaa, 0xf7, 0x65, 0x67,
                    0xd5, 0xcb, 0x8d, 0xd1, 0xdc, 0x4e, 0x82, 0x0b]);
        
        let client_secret = hkdf::qexpand(digest, &hs_secret, b"client hs", digest.size() as u16);
        assert_eq!(&client_secret[..],
                   [0x83, 0x55, 0xf2, 0x1a, 0x3d, 0x8f, 0x83, 0xec,
                    0xb3, 0xd0, 0xf9, 0x71, 0x08, 0xd3, 0xf9, 0x5e,
                    0x0f, 0x65, 0xb4, 0xd8, 0xae, 0x88, 0xa0, 0x61,
                    0x1e, 0xe4, 0x9d, 0xb0, 0xb5, 0x23, 0x59, 0x1d]);
        let client_state = CryptoState::new(digest, cipher, client_secret);
        assert_eq!(&client_state.key[..],
                   [0x3a, 0xd0, 0x54, 0x2c, 0x4a, 0x85, 0x84, 0x74,
                    0x00, 0x63, 0x04, 0x9e, 0x3b, 0x3c, 0xaa, 0xb2]);
        assert_eq!(&client_state.iv[..],
                   [0xd1, 0xfd, 0x26, 0x05, 0x42, 0x75, 0x3a, 0xba,
                    0x38, 0x58, 0x9b, 0xad]);

        let server_secret = hkdf::qexpand(digest, &hs_secret, b"server hs", digest.size() as u16);
        assert_eq!(&server_secret[..],
                   [0xf8, 0x0e, 0x57, 0x71, 0x48, 0x4b, 0x21, 0xcd,
                    0xeb, 0xb5, 0xaf, 0xe0, 0xa2, 0x56, 0xa3, 0x17,
                    0x41, 0xef, 0xe2, 0xb5, 0xc6, 0xb6, 0x17, 0xba,
                    0xe1, 0xb2, 0xf1, 0x5a, 0x83, 0x04, 0x83, 0xd6]);
        let server_state = CryptoState::new(digest, cipher, server_secret);
        assert_eq!(&server_state.key[..],
                   [0xbe, 0xe4, 0xc2, 0x4d, 0x2a, 0xf1, 0x33, 0x80,
                    0xa9, 0xfa, 0x24, 0xa5, 0xe2, 0xba, 0x2c, 0xff]);
        assert_eq!(&server_state.iv[..],
                   [0x25, 0xb5, 0x8e, 0x24, 0x6d, 0x9e, 0x7d, 0x5f,
                    0xfe, 0x43, 0x23, 0xfe]);
    }
}
