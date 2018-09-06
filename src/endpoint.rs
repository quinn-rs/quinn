use std::collections::VecDeque;
use std::net::SocketAddrV6;
use std::path::PathBuf;
use std::sync::Arc;
use std::{cmp, io, mem, str};

use bytes::{BigEndian, Buf, BufMut, ByteOrder, Bytes};
use fnv::{FnvHashMap, FnvHashSet};
use openssl;
use openssl::ssl::{self, HandshakeError, Ssl, SslContext, SslStream, SslStreamBuilder};
use openssl::x509::X509StoreContextRef;
use rand::distributions::Sample;
use rand::{distributions, OsRng, Rng};
use slab::Slab;
use slog::{self, Logger};

use coding::{self, BufExt, BufMutExt};
use connection::{
    state, ConnectError, Connection, ConnectionError, ConnectionHandle, ConnectionId, ReadError,
    State, WriteError,
};
use crypto::{
    new_tls_ctx, reset_token_for, CertConfig, ConnectionInfo, CryptoContext, SessionTicketBuffer,
    ZeroRttCrypto, AEAD_TAG_SIZE, CONNECTION_INFO_INDEX, TRANSPORT_PARAMS_INDEX,
};
use memory_stream::MemoryStream;
use range_set::RangeSet;
use {
    frame, Directionality, Frame, Side, StreamId, TransportError, MAX_CID_SIZE, RESET_TOKEN_SIZE,
    VERSION,
};

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
    ///
    /// This should be set to at least the expected connection latency multiplied by the maximum desired
    /// throughput. Setting this smaller than `receive_window` helps ensure that a single stream doesn't monopolize
    /// receive buffers, which may otherwise occur if the application chooses not to read from a large stream for a time
    /// while still requiring data on other streams.
    pub stream_receive_window: u32,
    /// Maximum number of bytes the peer may transmit across all streams of a connection before becoming blocked.
    ///
    /// This should be set to at least the expected connection latency multiplied by the maximum desired
    /// throughput. Larger values can be useful to allow maximum throughput within a stream while another is blocked.
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

    /// Path to write NSS SSLKEYLOGFILE-compatible key log.
    ///
    /// Enabling this compromises security by committing secret information to disk. Useful for debugging communications
    /// when using tools like Wireshark.
    pub keylog: Option<PathBuf>,

    /// Whether to force clients to prove they can receive responses before allocating resources for them.
    ///
    /// This adds a round trip to the handshake, increasing connection establishment latency, in exchange for improved
    /// resistance to denial of service attacks.
    ///
    /// Only meaningful for endpoints that accept incoming connections.
    pub use_stateless_retry: bool,

    /// Whether incoming connections are required to provide certificates.
    ///
    /// If this is not set but a `client_cert_verifier` is supplied, a certificate will still be requested, but the
    /// handshake will proceed even if one is not supplied.
    pub require_client_certs: bool,

    /// Function to preform application-level verification of client certificates from incoming connections.
    ///
    /// Called with a boolean indicating whether the certificate chain is valid at the TLS level, and a
    /// `X509StoreContextRef` containing said chain. Returns whether the certificate should be considered valid.
    ///
    /// If `None`, all valid certificates will be accepted.
    pub client_cert_verifier:
        Option<Box<Fn(bool, &mut X509StoreContextRef) -> bool + Send + Sync + 'static>>,
}

impl Default for Config {
    fn default() -> Self {
        const EXPECTED_RTT: u32 = 100; // ms
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

            keylog: None,
            use_stateless_retry: false,

            require_client_certs: false,
            client_cert_verifier: None,
        }
    }
}

pub struct ClientConfig<'a> {
    /// The name of the server the client intends to connect to.
    ///
    /// Used for both certificate validation, and for disambiguating between multiple domains hosted by the same IP
    /// address (using SNI).
    pub server_name: Option<&'a str>,

    /// A ticket to resume a previous session faster than performing a full handshake.
    ///
    /// Required for transmitting 0-RTT data.
    // Encoding: u16 length, DER-encoded OpenSSL session ticket, transport params
    pub session_ticket: Option<&'a [u8]>,

    /// Whether to accept inauthentic or unverifiable peer certificates.
    ///
    /// Turning this off exposes clients to man-in-the-middle attacks in the same manner as an unencrypted TCP
    /// connection, but allows them to connect to servers that are using self-signed certificates.
    pub accept_insecure_certs: bool,
}

impl<'a> Default for ClientConfig<'a> {
    fn default() -> Self {
        Self {
            server_name: None,
            session_ticket: None,
            accept_insecure_certs: false,
        }
    }
}

/// The main entry point to the library
///
/// This object performs no I/O whatsoever. Instead, it generates a stream of I/O operations for a backend to perform
/// via `poll_io`, and consumes incoming packets and timer expirations via `handle` and `timeout`.
pub struct Endpoint {
    pub(crate) ctx: Context,
    connection_ids_initial: FnvHashMap<ConnectionId, ConnectionHandle>,
    connection_ids: FnvHashMap<ConnectionId, ConnectionHandle>,
    connection_remotes: FnvHashMap<SocketAddrV6, ConnectionHandle>,
    pub(crate) connections: Slab<Connection>,
    listen_keys: Option<ListenKeys>,
    io: VecDeque<Io>,
    session_ticket_buffer: SessionTicketBuffer,
}

pub struct Context {
    pub log: Logger,
    pub tls: SslContext,
    pub rng: OsRng,
    pub config: Arc<Config>,
    pub events: VecDeque<(ConnectionHandle, Event)>,
    pub incoming: VecDeque<ConnectionHandle>,
    pub incoming_handshakes: usize,
    pub dirty_conns: FnvHashSet<ConnectionHandle>,
    pub readable_conns: FnvHashSet<ConnectionHandle>,
    pub initial_packet_number: distributions::Range<u64>,
}

impl Context {
    fn gen_initial_packet_num(&mut self) -> u32 {
        self.initial_packet_number.sample(&mut self.rng) as u32
    }
}

pub const MIN_INITIAL_SIZE: usize = 1200;
pub const MIN_MTU: u16 = 1232;
const LOCAL_ID_LEN: usize = 8;
/// Ensures we can always fit all our ACKs in a single minimum-MTU packet with room to spare
pub const MAX_ACK_BLOCKS: usize = 64;

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

impl From<ssl::Error> for EndpointError {
    fn from(x: ssl::Error) -> Self {
        EndpointError::Tls(x)
    }
}
impl From<openssl::error::ErrorStack> for EndpointError {
    fn from(x: openssl::error::ErrorStack) -> Self {
        EndpointError::Tls(x.into())
    }
}

impl Endpoint {
    pub fn new(
        log: Logger,
        config: Config,
        cert: Option<CertConfig>,
        listen: Option<ListenKeys>,
    ) -> Result<Self, EndpointError> {
        let rng = OsRng::new().unwrap();
        let config = Arc::new(config);
        let (tls, session_ticket_buffer) = new_tls_ctx(config.clone(), cert, listen)?;

        Ok(Self {
            ctx: Context {
                log,
                tls,
                rng,
                config,
                initial_packet_number: distributions::Range::new(0, 2u64.pow(32) - 1024),
                events: VecDeque::new(),
                dirty_conns: FnvHashSet::default(),
                readable_conns: FnvHashSet::default(),
                incoming: VecDeque::new(),
                incoming_handshakes: 0,
            },
            listen_keys: listen,
            connection_ids_initial: FnvHashMap::default(),
            connection_ids: FnvHashMap::default(),
            connection_remotes: FnvHashMap::default(),
            connections: Slab::new(),
            io: VecDeque::new(),
            session_ticket_buffer,
        })
    }

    fn listen(&self) -> bool {
        self.listen_keys.is_some()
    }

    /// Get an application-facing event
    pub fn poll(&mut self) -> Option<(ConnectionHandle, Event)> {
        if let Some(x) = self.ctx.events.pop_front() {
            return Some(x);
        }
        loop {
            let &conn = self.ctx.readable_conns.iter().next()?;
            if let Some(&stream) = self.connections[conn.0].readable_streams.iter().next() {
                self.connections[conn.0].readable_streams.remove(&stream);
                let rs = self.connections[conn.0]
                    .streams
                    .get_mut(&stream)
                    .unwrap()
                    .recv_mut()
                    .unwrap();
                let fresh = mem::replace(&mut rs.fresh, false);
                return Some((conn, Event::StreamReadable { stream, fresh }));
            }
            self.ctx.readable_conns.remove(&conn);
        }
    }

    /// Get a pending IO operation
    pub fn poll_io(&mut self, now: u64) -> Option<Io> {
        loop {
            if let Some(x) = self.io.pop_front() {
                return Some(x);
            }
            let &conn = self.ctx.dirty_conns.iter().next()?;
            // TODO: Only determine a single operation; only remove from dirty set if that fails
            self.flush_pending(now, conn);
            self.ctx.dirty_conns.remove(&conn);
        }
    }

    /// Process an incoming UDP datagram
    pub fn handle(&mut self, now: u64, remote: SocketAddrV6, mut data: Bytes) {
        let datagram_len = data.len();
        while !data.is_empty() {
            let (packet, rest) = match Packet::decode(&data, LOCAL_ID_LEN) {
                Ok(x) => x,
                Err(HeaderError::UnsupportedVersion {
                    source,
                    destination,
                }) => {
                    if !self.listen() {
                        debug!(self.ctx.log, "dropping packet with unsupported version");
                        return;
                    }
                    trace!(self.ctx.log, "sending version negotiation");
                    // Negotiate versions
                    let mut buf = Vec::<u8>::new();
                    Header::VersionNegotiate {
                        ty: self.ctx.rng.gen(),
                        source_id: destination,
                        destination_id: source,
                    }.encode(&mut buf);
                    buf.write::<u32>(0x0a1a2a3a); // reserved version
                    buf.write(VERSION); // supported version
                    self.io.push_back(Io::Transmit {
                        destination: remote,
                        packet: buf.into(),
                    });
                    return;
                }
                Err(e) => {
                    trace!(self.ctx.log, "unable to process packet"; "reason" => %e);
                    return;
                }
            };
            self.handle_packet(now, remote, packet, datagram_len);
            data = rest;
        }
    }

    fn handle_packet(
        &mut self,
        now: u64,
        remote: SocketAddrV6,
        packet: Packet,
        datagram_len: usize,
    ) {
        //
        // Handle packet on existing connection, if any
        //

        let dest_id = packet.header.destination_id().clone();
        if let Some(&conn) = self.connection_ids.get(&dest_id) {
            self.handle_connected(now, conn, remote, packet);
            return;
        }
        if let Some(&conn) = self.connection_ids_initial.get(&dest_id) {
            self.handle_connected(now, conn, remote, packet);
            return;
        }
        if let Some(&conn) = self.connection_remotes.get(&remote) {
            if let Some(token) = self.connections[conn.0].params.stateless_reset_token {
                if packet.payload.len() >= 16
                    && &packet.payload[packet.payload.len() - 16..] == token
                {
                    if !self.connections[conn.0]
                        .state
                        .as_ref()
                        .unwrap()
                        .is_drained()
                    {
                        debug!(self.ctx.log, "got stateless reset"; "connection" => %self.connections[conn.0].local_id);
                        self.io.push_back(Io::TimerStop {
                            connection: conn,
                            timer: Timer::LossDetection,
                        });
                        self.io.push_back(Io::TimerStop {
                            connection: conn,
                            timer: Timer::Close,
                        });
                        self.io.push_back(Io::TimerStop {
                            connection: conn,
                            timer: Timer::Idle,
                        });
                        self.ctx.events.push_back((
                            conn,
                            Event::ConnectionLost {
                                reason: ConnectionError::Reset,
                            },
                        ));
                        self.connections[conn.0].state = Some(State::Drained);
                    }
                    return;
                }
            }
        }

        //
        // Potentially create a new connection
        //

        if !self.listen() {
            debug!(self.ctx.log, "dropping packet from unrecognized connection"; "header" => ?packet.header);
            return;
        }
        let key_phase = packet.header.key_phase();
        if let Header::Long {
            ty,
            destination_id,
            source_id,
            number,
        } = packet.header
        {
            match ty {
                packet::INITIAL => {
                    if datagram_len >= MIN_INITIAL_SIZE {
                        self.handle_initial(
                            now,
                            remote,
                            destination_id,
                            source_id,
                            number,
                            &packet.header_data,
                            &packet.payload,
                        );
                    } else {
                        debug!(
                            self.ctx.log,
                            "ignoring short initial on {connection}",
                            connection = destination_id.clone()
                        );
                    }
                    return;
                }
                packet::ZERO_RTT => {
                    // MAY buffer a limited amount
                    trace!(
                        self.ctx.log,
                        "dropping 0-RTT packet for unknown connection {connection}",
                        connection = destination_id.clone()
                    );
                    return;
                }
                _ => {
                    debug!(self.ctx.log, "ignoring packet for unknown connection {connection} with unexpected type {type:02x}",
                           connection=destination_id.clone(), type=ty);
                    return;
                }
            }
        }

        //
        // If we got this far, we're a server receiving a seemingly valid packet for an unknown connection. Send a stateless reset.
        //

        if !dest_id.is_empty() {
            debug!(self.ctx.log, "sending stateless reset");
            let mut buf = Vec::<u8>::new();
            // Bound padding size to at most 8 bytes larger than input to mitigate amplification attacks
            let padding = self.ctx.rng.gen_range(
                0,
                cmp::max(RESET_TOKEN_SIZE + 8, packet.payload.len()) - RESET_TOKEN_SIZE,
            );
            buf.reserve_exact(1 + MAX_CID_SIZE + 1 + padding + RESET_TOKEN_SIZE);
            Header::Short {
                id: ConnectionId::random(&mut self.ctx.rng, MAX_CID_SIZE as u8),
                number: PacketNumber::U8(self.ctx.rng.gen()),
                key_phase,
            }.encode(&mut buf);
            {
                let start = buf.len();
                buf.resize(start + padding, 0);
                self.ctx.rng.fill_bytes(&mut buf[start..start + padding]);
            }
            buf.extend(&reset_token_for(
                &self.listen_keys.as_ref().unwrap().reset,
                &dest_id,
            ));
            self.io.push_back(Io::Transmit {
                destination: remote,
                packet: buf.into(),
            });
        } else {
            trace!(
                self.ctx.log,
                "dropping unrecognized short packet without ID"
            );
        }
    }

    /// Initiate a connection
    pub fn connect(
        &mut self,
        remote: SocketAddrV6,
        config: ClientConfig,
    ) -> Result<ConnectionHandle, ConnectError> {
        let local_id = ConnectionId::random(&mut self.ctx.rng, LOCAL_ID_LEN as u8);
        let remote_id = ConnectionId::random(&mut self.ctx.rng, MAX_CID_SIZE as u8);
        trace!(self.ctx.log, "initial dcid"; "value" => %remote_id);
        let conn = self.add_connection(
            remote_id.clone(),
            local_id.clone(),
            remote_id,
            remote,
            Side::Client,
        );
        self.connections[conn.0].connect(&self.ctx, config)?;
        self.ctx.dirty_conns.insert(conn);
        Ok(conn)
    }

    fn add_connection(
        &mut self,
        initial_id: ConnectionId,
        local_id: ConnectionId,
        remote_id: ConnectionId,
        remote: SocketAddrV6,
        side: Side,
    ) -> ConnectionHandle {
        debug_assert!(!local_id.is_empty());
        let packet_num = self.ctx.gen_initial_packet_num();
        let i = self.connections.insert(Connection::new(
            initial_id,
            local_id.clone(),
            remote_id,
            remote,
            packet_num.into(),
            side,
            &self.ctx.config,
        ));
        self.connection_ids.insert(local_id, ConnectionHandle(i));
        self.connection_remotes.insert(remote, ConnectionHandle(i));
        ConnectionHandle(i)
    }

    fn handle_initial(
        &mut self,
        now: u64,
        remote: SocketAddrV6,
        dest_id: ConnectionId,
        source_id: ConnectionId,
        packet_number: u32,
        header: &[u8],
        payload: &[u8],
    ) {
        let crypto = CryptoContext::handshake(&dest_id, Side::Server);
        let payload = if let Some(x) = crypto.decrypt(packet_number as u64, header, payload) {
            x.into()
        } else {
            debug!(self.ctx.log, "failed to authenticate initial packet");
            return;
        };
        let local_id = ConnectionId::random(&mut self.ctx.rng, LOCAL_ID_LEN as u8);

        if self.ctx.incoming.len() + self.ctx.incoming_handshakes
            == self.ctx.config.accept_buffer as usize
        {
            debug!(
                self.ctx.log,
                "rejecting connection due to full accept buffer"
            );
            let n = self.ctx.gen_initial_packet_num();
            self.io.push_back(Io::Transmit {
                destination: remote,
                packet: handshake_close(
                    &crypto,
                    &source_id,
                    &local_id,
                    n,
                    TransportError::SERVER_BUSY,
                    None,
                ),
            });
            return;
        }

        let mut stream = MemoryStream::new();
        if !parse_initial(&self.ctx.log, &mut stream, payload) {
            return;
        } // TODO: Send close?
        trace!(self.ctx.log, "got initial");
        let mut tls = Ssl::new(&self.ctx.tls).unwrap(); // TODO: is this reliable?
        tls.set_ex_data(
            *CONNECTION_INFO_INDEX,
            ConnectionInfo {
                id: local_id.clone(),
                remote,
            },
        );
        let mut tls = SslStreamBuilder::new(tls, stream);
        tls.set_accept_state();

        let zero_rtt_crypto;
        if self.ctx.config.use_stateless_retry {
            zero_rtt_crypto = None;
            match tls.stateless() {
                Ok(true) => {} // Continue on to the below accept call
                Ok(false) => {
                    let data = tls.get_mut().take_outgoing();
                    trace!(self.ctx.log, "sending HelloRetryRequest"; "connection" => %local_id, "len" => data.len());
                    let mut buf = Vec::<u8>::new();
                    Header::Long {
                        ty: packet::RETRY,
                        number: packet_number,
                        destination_id: source_id,
                        source_id: local_id,
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
                    let payload = crypto.encrypt(
                        packet_number as u64,
                        &buf[0..header_len],
                        &buf[header_len..],
                    );
                    debug_assert_eq!(payload.len(), buf.len() - header_len + AEAD_TAG_SIZE);
                    buf.truncate(header_len);
                    buf.extend_from_slice(&payload);
                    self.io.push_back(Io::Transmit {
                        destination: remote,
                        packet: buf.into(),
                    });
                    return;
                }
                Err(e) => {
                    debug!(self.ctx.log, "stateless handshake failed"; "connection" => %local_id, "reason" => %e);
                    let n = self.ctx.gen_initial_packet_num();
                    self.io.push_back(Io::Transmit {
                        destination: remote,
                        packet: handshake_close(
                            &crypto,
                            &source_id,
                            &local_id,
                            n,
                            TransportError::TLS_HANDSHAKE_FAILED,
                            Some(&tls.get_mut().take_outgoing()),
                        ),
                    });
                    return;
                }
            }
        } else {
            match tls.read_early_data(&mut [0; 1]) {
                Ok(0) => {
                    zero_rtt_crypto = None;
                }
                Ok(_) => {
                    debug!(self.ctx.log, "got TLS early data"; "connection" => local_id.clone());
                    let n = self.ctx.gen_initial_packet_num();
                    self.io.push_back(Io::Transmit {
                        destination: remote,
                        packet: handshake_close(
                            &crypto,
                            &source_id,
                            &local_id,
                            n,
                            TransportError::PROTOCOL_VIOLATION,
                            None,
                        ),
                    });
                    return;
                }
                Err(ref e) if e.code() == ssl::ErrorCode::WANT_READ => {
                    trace!(
                        self.ctx.log,
                        "{connection} enabled 0rtt",
                        connection = local_id.clone()
                    );
                    zero_rtt_crypto = Some(ZeroRttCrypto::new(tls.ssl()));
                }
                Err(e) => {
                    debug!(self.ctx.log, "failure in SSL_read_early_data"; "connection" => local_id.clone(), "reason" => %e);
                    let n = self.ctx.gen_initial_packet_num();
                    self.io.push_back(Io::Transmit {
                        destination: remote,
                        packet: handshake_close(
                            &crypto,
                            &source_id,
                            &local_id,
                            n,
                            TransportError::TLS_HANDSHAKE_FAILED,
                            None,
                        ),
                    });
                    return;
                }
            }
        }

        match tls.handshake() {
            Ok(_) => unreachable!(),
            Err(HandshakeError::WouldBlock(mut tls)) => {
                trace!(self.ctx.log, "performing handshake"; "connection" => local_id.clone());
                if let Some(params) = tls.ssl().ex_data(*TRANSPORT_PARAMS_INDEX).cloned() {
                    let params = params
                        .expect("transport parameter errors should have aborted the handshake");
                    let conn = self.add_connection(
                        dest_id.clone(),
                        local_id,
                        source_id,
                        remote,
                        Side::Server,
                    );
                    self.connection_ids_initial.insert(dest_id, conn);
                    self.connections[conn.0].zero_rtt_crypto = zero_rtt_crypto;
                    self.connections[conn.0].on_packet_authenticated(
                        &mut self.ctx,
                        now,
                        packet_number as u64,
                    );
                    self.connections[conn.0].transmit_handshake(&tls.get_mut().take_outgoing());
                    self.connections[conn.0].state = Some(State::Handshake(state::Handshake {
                        tls,
                        clienthello_packet: None,
                        remote_id_set: true,
                    }));
                    self.connections[conn.0].set_params(params);
                    self.ctx.dirty_conns.insert(conn);
                    self.ctx.incoming_handshakes += 1;
                } else {
                    debug!(
                        self.ctx.log,
                        "ClientHello missing transport params extension"
                    );
                    let n = self.ctx.gen_initial_packet_num();
                    self.io.push_back(Io::Transmit {
                        destination: remote,
                        packet: handshake_close(
                            &crypto,
                            &source_id,
                            &local_id,
                            n,
                            TransportError::TRANSPORT_PARAMETER_ERROR,
                            None,
                        ),
                    });
                }
            }
            Err(HandshakeError::Failure(mut tls)) => {
                let code = if let Some(params_err) = tls
                    .ssl()
                    .ex_data(*TRANSPORT_PARAMS_INDEX)
                    .and_then(|x| x.err())
                {
                    debug!(self.ctx.log, "received invalid transport parameters"; "connection" => %local_id, "reason" => %params_err);
                    TransportError::TRANSPORT_PARAMETER_ERROR
                } else {
                    debug!(self.ctx.log, "accept failed"; "reason" => %tls.error());
                    TransportError::TLS_HANDSHAKE_FAILED
                };
                let n = self.ctx.gen_initial_packet_num();
                self.io.push_back(Io::Transmit {
                    destination: remote,
                    packet: handshake_close(
                        &crypto,
                        &source_id,
                        &local_id,
                        n,
                        code,
                        Some(&tls.get_mut().take_outgoing()),
                    ),
                });
            }
            Err(HandshakeError::SetupFailure(e)) => {
                error!(self.ctx.log, "accept setup failed"; "reason" => %e);
                let n = self.ctx.gen_initial_packet_num();
                self.io.push_back(Io::Transmit {
                    destination: remote,
                    packet: handshake_close(
                        &crypto,
                        &source_id,
                        &local_id,
                        n,
                        TransportError::INTERNAL_ERROR,
                        None,
                    ),
                });
            }
        }
    }

    fn drive_tls(
        &mut self,
        conn: ConnectionHandle,
        tls: &mut SslStream<MemoryStream>,
    ) -> Result<(), TransportError> {
        if tls.get_ref().read_blocked() {
            return Ok(());
        }
        let prev_offset = tls.get_ref().read_offset();
        let status = tls.ssl_read(&mut [0; 1]);
        let progress = tls.get_ref().read_offset() - prev_offset;
        trace!(
            self.ctx.log,
            "stream 0 read {bytes} bytes",
            bytes = progress
        );
        self.connections[conn.0]
            .streams
            .get_mut(&StreamId(0))
            .unwrap()
            .recv_mut()
            .unwrap()
            .max_data += progress;
        self.connections[conn.0]
            .pending
            .max_stream_data
            .insert(StreamId(0));

        // Process any new session tickets that might have been delivered
        {
            let mut buffer = self.session_ticket_buffer.lock().unwrap();
            for session in buffer.drain(..) {
                if let Ok(session) = session {
                    trace!(
                        self.ctx.log,
                        "{connection} got session ticket",
                        connection = self.connections[conn.0].local_id.clone()
                    );

                    let params = &self.connections[conn.0].params;
                    let session = session
                        .to_der()
                        .expect("failed to serialize session ticket");

                    let mut buf = Vec::new();
                    buf.put_u16_be(session.len() as u16);
                    buf.extend_from_slice(&session);
                    params.write(Side::Server, &mut buf);

                    self.ctx
                        .events
                        .push_back((conn, Event::NewSessionTicket { ticket: buf.into() }));
                } else {
                    debug!(
                        self.ctx.log,
                        "{connection} got malformed session ticket",
                        connection = self.connections[conn.0].local_id.clone()
                    );
                    self.ctx.events.push_back((
                        conn,
                        Event::ConnectionLost {
                            reason: TransportError::PROTOCOL_VIOLATION.into(),
                        },
                    ));
                    return Err(TransportError::PROTOCOL_VIOLATION.into());
                }
            }
        }

        match status {
            Err(ref e) if e.code() == ssl::ErrorCode::WANT_READ => Ok(()),
            Ok(_) => {
                debug!(self.ctx.log, "got TLS application data");
                self.ctx.events.push_back((
                    conn,
                    Event::ConnectionLost {
                        reason: TransportError::PROTOCOL_VIOLATION.into(),
                    },
                ));
                Err(TransportError::PROTOCOL_VIOLATION.into())
            }
            Err(ref e) if e.code() == ssl::ErrorCode::SSL => {
                debug!(self.ctx.log, "TLS error"; "error" => %e);
                self.ctx.events.push_back((
                    conn,
                    Event::ConnectionLost {
                        reason: TransportError::TLS_FATAL_ALERT_RECEIVED.into(),
                    },
                ));
                Err(TransportError::TLS_FATAL_ALERT_RECEIVED.into())
            }
            Err(ref e) if e.code() == ssl::ErrorCode::ZERO_RETURN => {
                debug!(self.ctx.log, "TLS session terminated unexpectedly");
                self.ctx.events.push_back((
                    conn,
                    Event::ConnectionLost {
                        reason: TransportError::PROTOCOL_VIOLATION.into(),
                    },
                ));
                Err(TransportError::PROTOCOL_VIOLATION.into())
            }
            Err(e) => {
                error!(self.ctx.log, "unexpected TLS error"; "error" => %e);
                self.ctx.events.push_back((
                    conn,
                    Event::ConnectionLost {
                        reason: TransportError::INTERNAL_ERROR.into(),
                    },
                ));
                Err(TransportError::INTERNAL_ERROR.into())
            }
        }
    }

    fn handle_connected_inner(
        &mut self,
        now: u64,
        conn: ConnectionHandle,
        remote: SocketAddrV6,
        packet: Packet,
        state: State,
    ) -> State {
        match state {
            State::Handshake(mut state) => {
                match packet.header {
                    Header::Long {
                        ty: packet::RETRY,
                        number,
                        destination_id: conn_id,
                        source_id: remote_id,
                        ..
                    } => {
                        // FIXME: the below guards fail to handle repeated retries resulting from retransmitted initials
                        if state.clienthello_packet.is_none() {
                            // Received Retry as a server
                            debug!(self.ctx.log, "received retry from client"; "connection" => %conn_id);
                            self.ctx.events.push_back((
                                conn,
                                Event::ConnectionLost {
                                    reason: TransportError::PROTOCOL_VIOLATION.into(),
                                },
                            ));
                            State::handshake_failed(TransportError::PROTOCOL_VIOLATION, None)
                        } else if state.clienthello_packet.unwrap() > number {
                            // Retry corresponds to an outdated Initial; must be a duplicate, so ignore it
                            State::Handshake(state)
                        } else if state.tls.get_ref().read_offset() != 0 {
                            // This condition works because Handshake packets are the only ones that we allow to make lasting changes to the read_offset
                            debug!(self.ctx.log, "received retry after a handshake packet");
                            self.ctx.events.push_back((
                                conn,
                                Event::ConnectionLost {
                                    reason: TransportError::PROTOCOL_VIOLATION.into(),
                                },
                            ));
                            State::handshake_failed(TransportError::PROTOCOL_VIOLATION, None)
                        } else if let Some(payload) = self.connections[conn.0].decrypt(
                            true,
                            number as u64,
                            &packet.header_data,
                            &packet.payload,
                        ) {
                            let mut new_stream = MemoryStream::new();
                            if !parse_initial(&self.ctx.log, &mut new_stream, payload.into()) {
                                debug!(self.ctx.log, "invalid retry payload");
                                self.ctx.events.push_back((
                                    conn,
                                    Event::ConnectionLost {
                                        reason: TransportError::PROTOCOL_VIOLATION.into(),
                                    },
                                ));
                                return State::handshake_failed(
                                    TransportError::PROTOCOL_VIOLATION,
                                    None,
                                );
                            }
                            *state.tls.get_mut() = new_stream;
                            match state.tls.handshake() {
                                Err(HandshakeError::WouldBlock(mut tls)) => {
                                    self.connections[conn.0].on_packet_authenticated(
                                        &mut self.ctx,
                                        now,
                                        number as u64,
                                    );
                                    trace!(self.ctx.log, "resending ClientHello"; "remote_id" => %remote_id);
                                    let local_id = self.connections[conn.0].local_id.clone();
                                    // Discard transport state
                                    self.connections[conn.0] = Connection::new(
                                        remote_id.clone(),
                                        local_id,
                                        remote_id,
                                        remote,
                                        self.ctx
                                            .initial_packet_number
                                            .sample(&mut self.ctx.rng)
                                            .into(),
                                        Side::Client,
                                        &self.ctx.config,
                                    );
                                    // Send updated ClientHello
                                    self.connections[conn.0]
                                        .transmit_handshake(&tls.get_mut().take_outgoing());
                                    // Prepare to receive Handshake packets that start stream 0 from offset 0
                                    tls.get_mut().reset_read();
                                    State::Handshake(state::Handshake {
                                        tls,
                                        clienthello_packet: state.clienthello_packet,
                                        remote_id_set: state.remote_id_set,
                                    })
                                }
                                Ok(_) => {
                                    debug!(
                                        self.ctx.log,
                                        "unexpectedly completed handshake in RETRY packet"
                                    );
                                    self.ctx.events.push_back((
                                        conn,
                                        Event::ConnectionLost {
                                            reason: TransportError::PROTOCOL_VIOLATION.into(),
                                        },
                                    ));
                                    State::handshake_failed(
                                        TransportError::PROTOCOL_VIOLATION,
                                        None,
                                    )
                                }
                                Err(HandshakeError::Failure(mut tls)) => {
                                    debug!(self.ctx.log, "handshake failed"; "reason" => %tls.error());
                                    self.ctx.events.push_back((
                                        conn,
                                        Event::ConnectionLost {
                                            reason: TransportError::TLS_HANDSHAKE_FAILED.into(),
                                        },
                                    ));
                                    State::handshake_failed(
                                        TransportError::TLS_HANDSHAKE_FAILED,
                                        Some(tls.get_mut().take_outgoing().to_owned().into()),
                                    )
                                }
                                Err(HandshakeError::SetupFailure(e)) => {
                                    error!(self.ctx.log, "handshake setup failed"; "reason" => %e);
                                    self.ctx.events.push_back((
                                        conn,
                                        Event::ConnectionLost {
                                            reason: TransportError::INTERNAL_ERROR.into(),
                                        },
                                    ));
                                    State::handshake_failed(TransportError::INTERNAL_ERROR, None)
                                }
                            }
                        } else {
                            debug!(self.ctx.log, "failed to authenticate retry packet");
                            State::Handshake(state)
                        }
                    }
                    Header::Long {
                        ty: packet::HANDSHAKE,
                        destination_id: id,
                        source_id: remote_id,
                        number,
                        ..
                    } => {
                        if !state.remote_id_set {
                            trace!(self.ctx.log, "got remote connection id"; "connection" => %id, "remote_id" => %remote_id);
                            self.connections[conn.0].remote_id = remote_id;
                            state.remote_id_set = true;
                        }
                        let payload = if let Some(x) = self.connections[conn.0].decrypt(
                            true,
                            number as u64,
                            &packet.header_data,
                            &packet.payload,
                        ) {
                            x
                        } else {
                            debug!(self.ctx.log, "failed to authenticate handshake packet");
                            return State::Handshake(state);
                        };
                        self.connections[conn.0].on_packet_authenticated(
                            &mut self.ctx,
                            now,
                            number as u64,
                        );
                        // Complete handshake (and ultimately send Finished)
                        for frame in frame::Iter::new(payload.into()) {
                            match frame {
                                Frame::Ack(_) => {}
                                _ => {
                                    self.connections[conn.0].permit_ack_only = true;
                                }
                            }
                            match frame {
                                Frame::Padding => {}
                                Frame::Stream(frame::Stream {
                                    id: StreamId(0),
                                    offset,
                                    data,
                                    ..
                                }) => {
                                    state.tls.get_mut().insert(offset, &data);
                                }
                                Frame::Stream(frame::Stream { .. }) => {
                                    debug!(self.ctx.log, "non-stream-0 stream frame in handshake");
                                    self.ctx.events.push_back((
                                        conn,
                                        Event::ConnectionLost {
                                            reason: TransportError::PROTOCOL_VIOLATION.into(),
                                        },
                                    ));
                                    return State::handshake_failed(
                                        TransportError::PROTOCOL_VIOLATION,
                                        None,
                                    );
                                }
                                Frame::Ack(ack) => {
                                    self.connections[conn.0].on_ack_received(
                                        &mut self.ctx,
                                        now,
                                        conn,
                                        ack,
                                    );
                                }
                                Frame::ConnectionClose(reason) => {
                                    self.ctx.events.push_back((
                                        conn,
                                        Event::ConnectionLost {
                                            reason: ConnectionError::ConnectionClosed { reason },
                                        },
                                    ));
                                    return State::Draining(state.into());
                                }
                                Frame::ApplicationClose(reason) => {
                                    self.ctx.events.push_back((
                                        conn,
                                        Event::ConnectionLost {
                                            reason: ConnectionError::ApplicationClosed { reason },
                                        },
                                    ));
                                    return State::Draining(state.into());
                                }
                                Frame::PathChallenge(value) => {
                                    self.connections[conn.0]
                                        .handshake_pending
                                        .path_challenge(number as u64, value);
                                }
                                _ => {
                                    debug!(self.ctx.log, "unexpected frame type in handshake"; "connection" => %id, "type" => %frame.ty());
                                    self.ctx.events.push_back((
                                        conn,
                                        Event::ConnectionLost {
                                            reason: TransportError::PROTOCOL_VIOLATION.into(),
                                        },
                                    ));
                                    return State::handshake_failed(
                                        TransportError::PROTOCOL_VIOLATION,
                                        None,
                                    );
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
                                    if let Some(params) =
                                        tls.ssl().ex_data(*TRANSPORT_PARAMS_INDEX).cloned()
                                    {
                                        self.connections[conn.0].set_params(params.expect(
                                            "transport param errors should fail the handshake",
                                        ));
                                    } else {
                                        debug!(self.ctx.log, "server didn't send transport params");
                                        self.ctx.events.push_back((
                                            conn,
                                            Event::ConnectionLost {
                                                reason: TransportError::TRANSPORT_PARAMETER_ERROR
                                                    .into(),
                                            },
                                        ));
                                        return State::handshake_failed(
                                            TransportError::TLS_HANDSHAKE_FAILED,
                                            Some(tls.get_mut().take_outgoing().to_owned().into()),
                                        );
                                    }
                                }
                                trace!(
                                    self.ctx.log,
                                    "{connection} established",
                                    connection = id.clone()
                                );
                                self.connections[conn.0].handshake_cleanup(&self.ctx.config);
                                if self.connections[conn.0].side == Side::Client {
                                    self.connections[conn.0]
                                        .transmit_handshake(&tls.get_mut().take_outgoing());
                                } else {
                                    self.connections[conn.0].transmit(
                                        StreamId(0),
                                        tls.get_mut().take_outgoing()[..].into(),
                                    );
                                }
                                match self.connections[conn.0].side {
                                    Side::Client => {
                                        self.ctx.events.push_back((
                                            conn,
                                            Event::Connected {
                                                protocol: tls
                                                    .ssl()
                                                    .selected_alpn_protocol()
                                                    .map(|x| x.into()),
                                            },
                                        ));
                                    }
                                    Side::Server => {
                                        self.ctx.incoming_handshakes -= 1;
                                        self.ctx.incoming.push_back(conn);
                                    }
                                }
                                self.connections[conn.0].crypto = Some(CryptoContext::established(
                                    tls.ssl(),
                                    self.connections[conn.0].side,
                                ));
                                self.connections[conn.0]
                                    .streams
                                    .get_mut(&StreamId(0))
                                    .unwrap()
                                    .recv_mut()
                                    .unwrap()
                                    .max_data += tls.get_ref().read_offset() - prev_offset;
                                self.connections[conn.0]
                                    .pending
                                    .max_stream_data
                                    .insert(StreamId(0));
                                State::Established(state::Established { tls })
                            }
                            Err(HandshakeError::WouldBlock(mut tls)) => {
                                trace!(self.ctx.log, "handshake ongoing"; "connection" => %id);
                                self.connections[conn.0].handshake_cleanup(&self.ctx.config);
                                self.connections[conn.0]
                                    .streams
                                    .get_mut(&StreamId(0))
                                    .unwrap()
                                    .recv_mut()
                                    .unwrap()
                                    .max_data += tls.get_ref().read_offset() - prev_offset;
                                {
                                    let response = tls.get_mut().take_outgoing();
                                    if !response.is_empty() {
                                        self.connections[conn.0].transmit_handshake(&response);
                                    }
                                }
                                State::Handshake(state::Handshake {
                                    tls,
                                    clienthello_packet: state.clienthello_packet,
                                    remote_id_set: state.remote_id_set,
                                })
                            }
                            Err(HandshakeError::Failure(mut tls)) => {
                                let code = if let Some(params_err) = tls
                                    .ssl()
                                    .ex_data(*TRANSPORT_PARAMS_INDEX)
                                    .and_then(|x| x.err())
                                {
                                    debug!(self.ctx.log, "received invalid transport parameters"; "connection" => %id, "reason" => %params_err);
                                    TransportError::TRANSPORT_PARAMETER_ERROR
                                } else {
                                    debug!(self.ctx.log, "handshake failed"; "reason" => %tls.error());
                                    TransportError::TLS_HANDSHAKE_FAILED
                                };
                                self.ctx.events.push_back((
                                    conn,
                                    Event::ConnectionLost {
                                        reason: code.into(),
                                    },
                                ));
                                State::handshake_failed(
                                    code,
                                    Some(tls.get_mut().take_outgoing().to_owned().into()),
                                )
                            }
                            Err(HandshakeError::SetupFailure(e)) => {
                                error!(self.ctx.log, "handshake failed"; "connection" => %id, "reason" => %e);
                                self.ctx.events.push_back((
                                    conn,
                                    Event::ConnectionLost {
                                        reason: TransportError::INTERNAL_ERROR.into(),
                                    },
                                ));
                                State::handshake_failed(TransportError::INTERNAL_ERROR, None)
                            }
                        }
                    }
                    Header::Long {
                        ty: packet::INITIAL,
                        ..
                    } if self.connections[conn.0].side == Side::Server =>
                    {
                        trace!(self.ctx.log, "dropping duplicate Initial");
                        State::Handshake(state)
                    }
                    Header::Long {
                        ty: packet::ZERO_RTT,
                        number,
                        destination_id: ref id,
                        ..
                    } if self.connections[conn.0].side == Side::Server =>
                    {
                        let payload = if let Some(ref crypto) =
                            self.connections[conn.0].zero_rtt_crypto
                        {
                            if let Some(x) =
                                crypto.decrypt(number as u64, &packet.header_data, &packet.payload)
                            {
                                x
                            } else {
                                debug!(
                                    self.ctx.log,
                                    "{connection} failed to authenticate 0-RTT packet",
                                    connection = id.clone()
                                );
                                return State::Handshake(state);
                            }
                        } else {
                            debug!(
                                self.ctx.log,
                                "{connection} ignoring unsupported 0-RTT packet",
                                connection = id.clone()
                            );
                            return State::Handshake(state);
                        };
                        self.connections[conn.0].on_packet_authenticated(
                            &mut self.ctx,
                            now,
                            number as u64,
                        );
                        match self.connections[conn.0].process_payload(
                            &mut self.ctx,
                            now,
                            conn,
                            number as u64,
                            payload.into(),
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
                    }
                    Header::Long { ty, .. } => {
                        debug!(self.ctx.log, "unexpected packet type"; "type" => format!("{:02X}", ty));
                        self.ctx.events.push_back((
                            conn,
                            Event::ConnectionLost {
                                reason: TransportError::PROTOCOL_VIOLATION.into(),
                            },
                        ));
                        State::handshake_failed(TransportError::PROTOCOL_VIOLATION, None)
                    }
                    Header::VersionNegotiate {
                        destination_id: id, ..
                    } => {
                        let mut payload = io::Cursor::new(&packet.payload[..]);
                        if packet.payload.len() % 4 != 0 {
                            debug!(self.ctx.log, "malformed version negotiation"; "connection" => %id);
                            self.ctx.events.push_back((
                                conn,
                                Event::ConnectionLost {
                                    reason: TransportError::PROTOCOL_VIOLATION.into(),
                                },
                            ));
                            return State::handshake_failed(
                                TransportError::PROTOCOL_VIOLATION,
                                None,
                            );
                        }
                        while payload.has_remaining() {
                            let version = payload.get::<u32>().unwrap();
                            if version == VERSION {
                                // Our version is supported, so this packet is spurious
                                return State::Handshake(state);
                            }
                        }
                        debug!(self.ctx.log, "remote doesn't support our version");
                        self.ctx.events.push_back((
                            conn,
                            Event::ConnectionLost {
                                reason: ConnectionError::VersionMismatch,
                            },
                        ));
                        State::Draining(state.into())
                    }
                    // TODO: SHOULD buffer these to improve reordering tolerance.
                    Header::Short { .. } => {
                        trace!(self.ctx.log, "dropping short packet during handshake");
                        State::Handshake(state)
                    }
                }
            }
            State::Established(mut state) => {
                let id = self.connections[conn.0].local_id.clone();
                if let Header::Long { .. } = packet.header {
                    trace!(self.ctx.log, "discarding unprotected packet"; "connection" => %id);
                    return State::Established(state);
                }
                let (payload, number) = match self.connections[conn.0].decrypt_packet(false, packet)
                {
                    Ok(x) => x,
                    Err(None) => {
                        trace!(self.ctx.log, "failed to authenticate packet"; "connection" => %id);
                        return State::Established(state);
                    }
                    Err(Some(e)) => {
                        warn!(self.ctx.log, "got illegal packet"; "connection" => %id);
                        self.ctx
                            .events
                            .push_back((conn, Event::ConnectionLost { reason: e.into() }));
                        return State::closed(e);
                    }
                };
                self.connections[conn.0].on_packet_authenticated(&mut self.ctx, now, number);
                if self.connections[conn.0].awaiting_handshake {
                    assert_eq!(
                        self.connections[conn.0].side,
                        Side::Client,
                        "only the client confirms handshake completion based on a protected packet"
                    );
                    // Forget about unacknowledged handshake packets
                    self.connections[conn.0].handshake_cleanup(&self.ctx.config);
                }
                match self.connections[conn.0]
                    .process_payload(
                        &mut self.ctx,
                        now,
                        conn,
                        number,
                        payload.into(),
                        state.tls.get_mut(),
                    )
                    .and_then(|x| {
                        self.drive_tls(conn, &mut state.tls)?;
                        Ok(x)
                    }) {
                    Err(e) => State::closed(e),
                    Ok(true) => {
                        // Inform OpenSSL that the connection is being closed gracefully. This ensures that a resumable
                        // session is not erased from the anti-replay cache as it otherwise might be.
                        state.tls.shutdown().unwrap();
                        State::Draining(state.into())
                    }
                    Ok(false) => State::Established(state),
                }
            }
            State::HandshakeFailed(state) => {
                if let Ok((payload, _)) = self.connections[conn.0].decrypt_packet(true, packet) {
                    for frame in frame::Iter::new(payload.into()) {
                        match frame {
                            Frame::ConnectionClose(_) | Frame::ApplicationClose(_) => {
                                trace!(self.ctx.log, "draining");
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
                                trace!(self.ctx.log, "draining");
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
        }
    }

    fn handle_connected(
        &mut self,
        now: u64,
        conn: ConnectionHandle,
        remote: SocketAddrV6,
        packet: Packet,
    ) {
        trace!(self.ctx.log, "connection got packet"; "connection" => %self.connections[conn.0].local_id, "len" => packet.payload.len());
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
                    self.ctx.incoming_handshakes -= 1;
                }
                let n = self.connections[conn.0].get_tx_number();
                self.io.push_back(Io::Transmit {
                    destination: remote,
                    packet: handshake_close(
                        &self.connections[conn.0].handshake_crypto,
                        &self.connections[conn.0].remote_id,
                        &self.connections[conn.0].local_id,
                        n as u32,
                        state.reason.clone(),
                        state.alert.as_ref().map(|x| &x[..]),
                    ),
                });
                self.connections[conn.0].reset_idle_timeout(&self.ctx.config, now);
            }
            State::Closed(ref state) => {
                self.io.push_back(Io::Transmit {
                    destination: remote,
                    packet: self.connections[conn.0].make_close(&state.reason),
                });
                self.connections[conn.0].reset_idle_timeout(&self.ctx.config, now);
            }
            _ => {}
        }
        self.connections[conn.0].state = Some(state);

        self.ctx.dirty_conns.insert(conn);
    }

    fn flush_pending(&mut self, now: u64, conn: ConnectionHandle) {
        let mut sent = false;
        while let Some(packet) =
            self.connections[conn.0].next_packet(&self.ctx.log, &self.ctx.config, now)
        {
            self.io.push_back(Io::Transmit {
                destination: self.connections[conn.0].remote,
                packet: packet.into(),
            });
            sent = true;
        }
        if sent {
            self.connections[conn.0].reset_idle_timeout(&self.ctx.config, now);
        }
        {
            let c = &mut self.connections[conn.0];
            if let Some(setting) = c.set_idle.take() {
                if let Some(time) = setting {
                    self.io.push_back(Io::TimerStart {
                        connection: conn,
                        timer: Timer::Idle,
                        time,
                    });
                } else {
                    self.io.push_back(Io::TimerStop {
                        connection: conn,
                        timer: Timer::Idle,
                    });
                }
            }
            if let Some(setting) = c.set_loss_detection.take() {
                if let Some(time) = setting {
                    self.io.push_back(Io::TimerStart {
                        connection: conn,
                        timer: Timer::LossDetection,
                        time,
                    });
                } else {
                    self.io.push_back(Io::TimerStop {
                        connection: conn,
                        timer: Timer::LossDetection,
                    });
                }
            }
        }
    }

    fn forget(&mut self, conn: ConnectionHandle) {
        if self.connections[conn.0].side == Side::Server {
            self.connection_ids_initial
                .remove(&self.connections[conn.0].initial_id);
        }
        self.connection_ids
            .remove(&self.connections[conn.0].local_id);
        self.connection_remotes
            .remove(&self.connections[conn.0].remote);
        self.ctx.dirty_conns.remove(&conn);
        self.ctx.readable_conns.remove(&conn);
        self.connections.remove(conn.0);
    }

    /// Handle a timer expiring
    pub fn timeout(&mut self, now: u64, conn: ConnectionHandle, timer: Timer) {
        match timer {
            Timer::Close => {
                self.io.push_back(Io::TimerStop {
                    connection: conn,
                    timer: Timer::Idle,
                });
                self.ctx.events.push_back((conn, Event::ConnectionDrained));
                if self.connections[conn.0]
                    .state
                    .as_ref()
                    .unwrap()
                    .is_app_closed()
                {
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
                self.ctx.events.push_back((
                    conn,
                    Event::ConnectionLost {
                        reason: ConnectionError::TimedOut,
                    },
                ));
                self.ctx.dirty_conns.insert(conn); // Ensure the loss detection timer cancellation goes through
            }
            Timer::LossDetection => {
                if self.connections[conn.0].awaiting_handshake {
                    trace!(self.ctx.log, "retransmitting handshake packets"; "connection" => %self.connections[conn.0].local_id);
                    let packets = self.connections[conn.0]
                        .sent_packets
                        .iter()
                        .filter_map(
                            |(&packet, info)| if info.handshake { Some(packet) } else { None },
                        )
                        .collect::<Vec<_>>();
                    for number in packets {
                        let mut info = self.connections[conn.0]
                            .sent_packets
                            .remove(&number)
                            .unwrap();
                        self.connections[conn.0].handshake_pending += info.retransmits;
                        self.connections[conn.0].bytes_in_flight -= info.bytes as u64;
                    }
                    self.connections[conn.0].handshake_count += 1;
                } else if self.connections[conn.0].loss_time != 0 {
                    // Early retransmit or Time Loss Detection
                    let largest = self.connections[conn.0].largest_acked_packet;
                    self.connections[conn.0].detect_lost_packets(&self.ctx.config, now, largest);
                } else if self.connections[conn.0].tlp_count < self.ctx.config.max_tlps {
                    trace!(self.ctx.log, "sending TLP {number} in {pn}",
                           number=self.connections[conn.0].tlp_count,
                           pn=self.connections[conn.0].largest_sent_packet + 1;
                           "outstanding" => ?self.connections[conn.0].sent_packets.keys().collect::<Vec<_>>(),
                           "in flight" => self.connections[conn.0].bytes_in_flight);
                    // Tail Loss Probe.
                    self.io.push_back(Io::Transmit {
                        destination: self.connections[conn.0].remote,
                        packet: self.connections[conn.0].force_transmit(&self.ctx.config, now),
                    });
                    self.connections[conn.0].reset_idle_timeout(&self.ctx.config, now);
                    self.connections[conn.0].tlp_count += 1;
                } else {
                    trace!(self.ctx.log, "RTO fired, retransmitting"; "pn" => self.connections[conn.0].largest_sent_packet + 1,
                           "outstanding" => ?self.connections[conn.0].sent_packets.keys().collect::<Vec<_>>(),
                           "in flight" => self.connections[conn.0].bytes_in_flight);
                    // RTO
                    if self.connections[conn.0].rto_count == 0 {
                        self.connections[conn.0].largest_sent_before_rto =
                            self.connections[conn.0].largest_sent_packet;
                    }
                    for _ in 0..2 {
                        self.io.push_back(Io::Transmit {
                            destination: self.connections[conn.0].remote,
                            packet: self.connections[conn.0].force_transmit(&self.ctx.config, now),
                        });
                    }
                    self.connections[conn.0].reset_idle_timeout(&self.ctx.config, now);
                    self.connections[conn.0].rto_count += 1;
                }
                self.connections[conn.0].set_loss_detection_alarm(&self.ctx.config);
                self.ctx.dirty_conns.insert(conn);
            }
        }
    }

    /// Transmit data on a stream
    ///
    /// Returns the number of bytes written on success.
    ///
    /// # Panics
    /// - when applied to a stream that does not have an active outgoing channel
    pub fn write(
        &mut self,
        conn: ConnectionHandle,
        stream: StreamId,
        data: &[u8],
    ) -> Result<usize, WriteError> {
        let r = self.connections[conn.0].write(stream, data);
        match r {
            Ok(n) => {
                self.ctx.dirty_conns.insert(conn);
                trace!(self.ctx.log, "write"; "connection" => %self.connections[conn.0].local_id, "stream" => stream.0, "len" => n)
            }
            Err(WriteError::Blocked) => {
                if self.connections[conn.0].congestion_blocked() {
                    trace!(self.ctx.log, "write blocked by congestion"; "connection" => %self.connections[conn.0].local_id);
                } else {
                    trace!(self.ctx.log, "write blocked by flow control"; "connection" => %self.connections[conn.0].local_id, "stream" => stream.0);
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
        self.ctx.dirty_conns.insert(conn);
    }

    /// Read data from a stream
    ///
    /// Treats a stream like a simple pipe, similar to a TCP connection. Subject to head-of-line blocking within the
    /// stream. Consider `read_unordered` for higher throughput.
    ///
    /// # Panics
    /// - when applied to a stream that does not have an active incoming channel
    pub fn read(
        &mut self,
        conn: ConnectionHandle,
        stream: StreamId,
        buf: &mut [u8],
    ) -> Result<usize, ReadError> {
        self.ctx.dirty_conns.insert(conn); // May need to send flow control frames after reading
        match self.connections[conn.0].read(stream, buf) {
            x @ Err(ReadError::Finished) | x @ Err(ReadError::Reset { .. }) => {
                self.connections[conn.0].maybe_cleanup(stream);
                x
            }
            x => x,
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
    pub fn read_unordered(
        &mut self,
        conn: ConnectionHandle,
        stream: StreamId,
    ) -> Result<(Bytes, u64), ReadError> {
        self.ctx.dirty_conns.insert(conn); // May need to send flow control frames after reading
        match self.connections[conn.0].read_unordered(stream) {
            x @ Err(ReadError::Finished) | x @ Err(ReadError::Reset { .. }) => {
                self.connections[conn.0].maybe_cleanup(stream);
                x
            }
            x => x,
        }
    }

    /// Abandon transmitting data on a stream
    ///
    /// # Panics
    /// - when applied to a receive stream or an unopened send stream
    pub fn reset(&mut self, conn: ConnectionHandle, stream: StreamId, error_code: u16) {
        self.connections[conn.0].reset(&mut self.ctx, stream, error_code, conn)
    }

    /// Instruct the peer to abandon transmitting data on a stream
    ///
    /// # Panics
    /// - when applied to a stream that has not begin receiving data
    pub fn stop_sending(&mut self, conn: ConnectionHandle, stream: StreamId, error_code: u16) {
        self.connections[conn.0].stop_sending(stream, error_code);
        self.ctx.dirty_conns.insert(conn);
    }

    /// Create a new stream
    ///
    /// Returns `None` if the maximum number of streams currently permitted by the remote endpoint are already open.
    pub fn open(&mut self, conn: ConnectionHandle, direction: Directionality) -> Option<StreamId> {
        self.connections[conn.0].open(&self.ctx.config, direction)
    }

    /// Ping the remote endpoint
    ///
    /// Useful for preventing an otherwise idle connection from timing out.
    pub fn ping(&mut self, conn: ConnectionHandle) {
        self.connections[conn.0].pending.ping = true;
        self.ctx.dirty_conns.insert(conn);
    }

    fn close_common(&mut self, now: u64, conn: ConnectionHandle) {
        trace!(self.ctx.log, "connection closed");
        self.connections[conn.0].set_loss_detection = Some(None);
        self.io.push_back(Io::TimerStart {
            connection: conn,
            timer: Timer::Close,
            time: now + 3 * self.connections[conn.0].rto(&self.ctx.config),
        });
    }

    /// Close a connection immediately
    ///
    /// This does not ensure delivery of outstanding data. It is the application's responsibility to call this only when
    /// all important communications have been completed.
    pub fn close(&mut self, now: u64, conn: ConnectionHandle, error_code: u16, reason: Bytes) {
        if let State::Drained = *self.connections[conn.0].state.as_ref().unwrap() {
            self.forget(conn);
            return;
        }

        if let State::Established(ref mut state) = *self.connections[conn.0].state.as_mut().unwrap()
        {
            // Inform OpenSSL that the connection is being closed gracefully. This ensures that a resumable session is
            // not erased from the anti-replay cache as it otherwise might be.
            state.tls.shutdown().unwrap();
        }

        let was_closed = self.connections[conn.0].state.as_ref().unwrap().is_closed();
        let reason =
            state::CloseReason::Application(frame::ApplicationClose { error_code, reason });
        if !was_closed {
            self.close_common(now, conn);
            self.io.push_back(Io::Transmit {
                destination: self.connections[conn.0].remote,
                packet: self.connections[conn.0].make_close(&reason),
            });
            self.connections[conn.0].reset_idle_timeout(&self.ctx.config, now);
            self.ctx.dirty_conns.insert(conn);
        }
        self.connections[conn.0].state =
            Some(match self.connections[conn.0].state.take().unwrap() {
                State::Handshake(_) => State::HandshakeFailed(state::HandshakeFailed {
                    reason,
                    alert: None,
                    app_closed: true,
                }),
                State::HandshakeFailed(x) => State::HandshakeFailed(state::HandshakeFailed {
                    app_closed: true,
                    ..x
                }),
                State::Established(_) => State::Closed(state::Closed {
                    reason,
                    app_closed: true,
                }),
                State::Closed(x) => State::Closed(state::Closed {
                    app_closed: true,
                    ..x
                }),
                State::Draining(x) => State::Draining(state::Draining {
                    app_closed: true,
                    ..x
                }),
                State::Drained => unreachable!(),
            });
    }

    /// Look up whether we're the client or server of `conn`.
    pub fn get_side(&self, conn: ConnectionHandle) -> Side {
        self.connections[conn.0].side
    }

    /// The `ConnectionId` used for `conn` locally.
    pub fn get_local_id(&self, conn: ConnectionHandle) -> &ConnectionId {
        &self.connections[conn.0].local_id
    }
    /// The `ConnectionId` used for `conn` by the peer.
    pub fn get_remote_id(&self, conn: ConnectionHandle) -> &ConnectionId {
        &self.connections[conn.0].remote_id
    }
    pub fn get_remote_address(&self, conn: ConnectionHandle) -> &SocketAddrV6 {
        &self.connections[conn.0].remote
    }
    pub fn get_protocol(&self, conn: ConnectionHandle) -> Option<&[u8]> {
        if let State::Established(ref state) = *self.connections[conn.0].state.as_ref().unwrap() {
            state.tls.ssl().selected_alpn_protocol()
        } else {
            None
        }
    }
    /// The number of bytes of packets containing retransmittable frames that have not been acknowleded or declared lost
    pub fn get_bytes_in_flight(&self, conn: ConnectionHandle) -> u64 {
        self.connections[conn.0].bytes_in_flight
    }

    /// Number of bytes worth of non-ack-only packets that may be sent.
    pub fn get_congestion_state(&self, conn: ConnectionHandle) -> u64 {
        let c = &self.connections[conn.0];
        c.congestion_window.saturating_sub(c.bytes_in_flight)
    }

    /// The name a client supplied via SNI.
    ///
    /// None if no name was supplied or if this connection was locally-initiated.
    pub fn get_servername(&self, conn: ConnectionHandle) -> Option<&str> {
        match *self.connections[conn.0].state.as_ref().unwrap() {
            State::Handshake(ref state) => state.tls.ssl().servername(ssl::NameType::HOST_NAME),
            State::Established(ref state) => state.tls.ssl().servername(ssl::NameType::HOST_NAME),
            _ => None,
        }
    }

    /// Whether a previous session was successfully resumed by `conn`.
    pub fn get_session_resumed(&self, conn: ConnectionHandle) -> bool {
        if let State::Established(ref state) = self.connections[conn.0].state.as_ref().unwrap() {
            state.tls.ssl().session_reused()
        } else {
            false
        }
    }

    pub fn accept(&mut self) -> Option<ConnectionHandle> {
        self.ctx.incoming.pop_front()
    }
}

#[derive(Debug, Clone)]
pub enum Header {
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
    },
}

impl Header {
    fn destination_id(&self) -> &ConnectionId {
        use self::Header::*;
        match *self {
            Long {
                ref destination_id, ..
            } => destination_id,
            Short { ref id, .. } => id,
            VersionNegotiate {
                ref destination_id, ..
            } => destination_id,
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
pub enum PacketNumber {
    U8(u8),
    U16(u16),
    U32(u32),
}

impl PacketNumber {
    pub fn new(n: u64, largest_acked: u64) -> Self {
        if largest_acked == 0 {
            return PacketNumber::U32(n as u32);
        }
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

    pub fn encode<W: BufMut>(&self, w: &mut W) {
        use self::PacketNumber::*;
        match *self {
            U8(x) => w.write(x),
            U16(x) => w.write(x),
            U32(x) => w.write(x),
        }
    }

    pub fn expand(&self, prev: u64) -> u64 {
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
        if t > d / 2 {
            x + d * ((t + d / 2 - x) / d)
        } else {
            x % d
        }
    }
}

const KEY_PHASE_BIT: u8 = 0x40;

impl Header {
    pub fn encode<W: BufMut>(&self, w: &mut W) {
        use self::Header::*;
        match *self {
            Long {
                ty,
                ref source_id,
                ref destination_id,
                number,
            } => {
                w.write(0b10000000 | ty);
                w.write(VERSION);
                let mut dcil = destination_id.len() as u8;
                if dcil > 0 {
                    dcil -= 3;
                }
                let mut scil = source_id.len() as u8;
                if scil > 0 {
                    scil -= 3;
                }
                w.write(dcil << 4 | scil);
                w.put_slice(destination_id);
                w.put_slice(source_id);
                w.write::<u16>(0); // Placeholder for payload length; see `set_payload_length`
                w.write(number);
            }
            Short {
                ref id,
                number,
                key_phase,
            } => {
                let ty = number.ty() | 0x30 | if key_phase { KEY_PHASE_BIT } else { 0 };
                w.write(ty);
                w.put_slice(id);
                number.encode(w);
            }
            VersionNegotiate {
                ty,
                ref source_id,
                ref destination_id,
            } => {
                w.write(0x80 | ty);
                w.write::<u32>(0);
                let mut dcil = destination_id.len() as u8;
                if dcil > 0 {
                    dcil -= 3;
                }
                let mut scil = source_id.len() as u8;
                if scil > 0 {
                    scil -= 3;
                }
                w.write(dcil << 4 | scil);
                w.put_slice(destination_id);
                w.put_slice(source_id);
            }
        }
    }
}

pub struct Packet {
    pub header: Header,
    pub header_data: Bytes,
    pub payload: Bytes,
}

#[derive(Debug, Fail, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
enum HeaderError {
    #[fail(display = "unsupported version")]
    UnsupportedVersion {
        source: ConnectionId,
        destination: ConnectionId,
    },
    #[fail(display = "invalid header: {}", _0)]
    InvalidHeader(&'static str),
}

impl From<coding::UnexpectedEnd> for HeaderError {
    fn from(_: coding::UnexpectedEnd) -> Self {
        HeaderError::InvalidHeader("unexpected end of packet")
    }
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
            if dcil > 0 {
                dcil += 3
            };
            let mut scil = ci_lengths & 0xF;
            if scil > 0 {
                scil += 3
            };
            if buf.remaining() < (dcil + scil) as usize {
                return Err(HeaderError::InvalidHeader(
                    "connection IDs longer than packet",
                ));
            }
            buf.copy_to_slice(&mut cid_stage[0..dcil as usize]);
            let destination_id = ConnectionId::new(cid_stage, dcil as usize);
            buf.copy_to_slice(&mut cid_stage[0..scil as usize]);
            let source_id = ConnectionId::new(cid_stage, scil as usize);
            Ok(match version {
                0 => {
                    let header_data = packet.slice(0, buf.position() as usize);
                    let payload = packet.slice(buf.position() as usize, packet.len());
                    (
                        Packet {
                            header: Header::VersionNegotiate {
                                ty,
                                source_id,
                                destination_id,
                            },
                            header_data,
                            payload,
                        },
                        Bytes::new(),
                    )
                }
                VERSION => {
                    let len = buf.get_var()?;
                    let number = buf.get()?;
                    let header_data = packet.slice(0, buf.position() as usize);
                    if buf.position() + len > packet.len() as u64 {
                        return Err(HeaderError::InvalidHeader("payload longer than packet"));
                    }
                    let payload = if len == 0 {
                        Bytes::new()
                    } else {
                        packet.slice(buf.position() as usize, (buf.position() + len) as usize)
                    };
                    (
                        Packet {
                            header: Header::Long {
                                ty,
                                source_id,
                                destination_id,
                                number,
                            },
                            header_data,
                            payload,
                        },
                        packet.slice((buf.position() + len) as usize, packet.len()),
                    )
                }
                _ => {
                    return Err(HeaderError::UnsupportedVersion {
                        source: source_id,
                        destination: destination_id,
                    })
                }
            })
        } else {
            if buf.remaining() < dest_id_len {
                return Err(HeaderError::InvalidHeader(
                    "destination connection ID longer than packet",
                ));
            }
            buf.copy_to_slice(&mut cid_stage[0..dest_id_len]);
            let id = ConnectionId::new(cid_stage, dest_id_len);
            let key_phase = ty & KEY_PHASE_BIT != 0;
            let number = match ty & 0b11 {
                0x0 => PacketNumber::U8(buf.get()?),
                0x1 => PacketNumber::U16(buf.get()?),
                0x2 => PacketNumber::U32(buf.get()?),
                _ => {
                    return Err(HeaderError::InvalidHeader("unknown packet type"));
                }
            };
            let header_data = packet.slice(0, buf.position() as usize);
            let payload = packet.slice(buf.position() as usize, packet.len());
            Ok((
                Packet {
                    header: Header::Short {
                        id,
                        number,
                        key_phase,
                    },
                    header_data,
                    payload,
                },
                Bytes::new(),
            ))
        }
    }
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
        reason: ConnectionError,
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
    NewSessionTicket {
        ticket: Box<[u8]>,
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
    },
}

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum Timer {
    Close,
    LossDetection,
    Idle,
}

impl slog::Value for Timer {
    fn serialize(
        &self,
        _: &slog::Record,
        key: slog::Key,
        serializer: &mut slog::Serializer,
    ) -> slog::Result {
        serializer.emit_arguments(key, &format_args!("{:?}", self))
    }
}

pub mod packet {
    pub const INITIAL: u8 = 0x7F;
    pub const RETRY: u8 = 0x7E;
    pub const ZERO_RTT: u8 = 0x7C;
    pub const HANDSHAKE: u8 = 0x7D;
}

/// Forward data from an Initial or Retry packet to a stream for a TLS context
fn parse_initial(log: &Logger, stream: &mut MemoryStream, payload: Bytes) -> bool {
    for frame in frame::Iter::new(payload) {
        match frame {
            Frame::Padding => {}
            Frame::Ack(_) => {}
            Frame::Stream(frame::Stream {
                id: StreamId(0),
                fin: false,
                offset,
                data,
                ..
            }) => {
                stream.insert(offset, &data);
            }
            x => {
                debug!(log, "unexpected frame in initial/retry packet"; "ty" => %x.ty());
                return false;
            } // Invalid packet
        }
    }
    if stream.read_blocked() {
        debug!(log, "initial/retry packet missing stream frame(s)");
        false
    } else {
        true
    }
}

fn handshake_close<R>(
    crypto: &CryptoContext,
    remote_id: &ConnectionId,
    local_id: &ConnectionId,
    packet_number: u32,
    reason: R,
    tls_alert: Option<&[u8]>,
) -> Box<[u8]>
where
    R: Into<state::CloseReason>,
{
    let mut buf = Vec::<u8>::new();
    Header::Long {
        ty: packet::HANDSHAKE,
        destination_id: remote_id.clone(),
        source_id: local_id.clone(),
        number: packet_number,
    }.encode(&mut buf);
    let header_len = buf.len();
    let max_len = MIN_MTU - header_len as u16 - AEAD_TAG_SIZE as u16;
    match reason.into() {
        state::CloseReason::Application(ref x) => x.encode(&mut buf, max_len),
        state::CloseReason::Connection(ref x) => x.encode(&mut buf, max_len),
    }
    if let Some(data) = tls_alert {
        if !data.is_empty() {
            frame::Stream {
                id: StreamId(0),
                fin: false,
                offset: 0,
                data,
            }.encode(false, &mut buf);
        }
    }
    set_payload_length(&mut buf, header_len);
    let payload = crypto.encrypt(
        packet_number as u64,
        &buf[0..header_len],
        &buf[header_len..],
    );
    debug_assert_eq!(payload.len(), buf.len() - header_len + AEAD_TAG_SIZE);
    buf.truncate(header_len);
    buf.extend_from_slice(&payload);
    buf.into()
}

pub fn set_payload_length(packet: &mut [u8], header_len: usize) {
    let len = packet.len() - header_len + AEAD_TAG_SIZE;
    assert!(len < 2usize.pow(14)); // Fits in reserved space
    BigEndian::write_u16(&mut packet[header_len - 6..], len as u16 | 0b01 << 14);
}
