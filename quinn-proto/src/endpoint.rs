use std::cmp;
use std::collections::VecDeque;
use std::net::SocketAddrV6;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::{BufMut, Bytes, BytesMut};
use fnv::{FnvHashMap, FnvHashSet};
use rand::{rngs::OsRng, Rng, RngCore};
use ring::digest;
use ring::hmac::SigningKey;
use slab::Slab;
use slog::{self, Logger};

use crate::coding::BufMutExt;
use crate::connection::{
    handshake_close, ClientConfig, Connection, ConnectionError, ConnectionHandle, Multiplexer,
    State,
};
use crate::crypto::{self, reset_token_for, ConnectError, Crypto, TlsSession, TokenKey};
use crate::packet::{
    ConnectionId, EcnCodepoint, Header, Packet, PacketDecodeError, PacketNumber, PartialDecode,
    PACKET_NUMBER_32_MASK,
};
use crate::stream::{ReadError, WriteError};
use crate::transport_parameters::TransportParameters;
use crate::{
    Directionality, Side, StreamId, TransportError, MAX_CID_SIZE, MIN_CID_SIZE, MIN_INITIAL_SIZE,
    RESET_TOKEN_SIZE, VERSION,
};

/// Parameters governing the core QUIC state machine.
pub struct Config {
    /// Maximum number of peer-initiated bidirectional streams that may exist at one time.
    pub max_remote_bi_streams: u16,
    /// Maximum number of peer-initiated  unidirectional streams that may exist at one time.
    pub max_remote_uni_streams: u16,
    /// Maximum duration of inactivity to accept before timing out the connection (s).
    ///
    /// Maximum value is 600 seconds. The actual value used is the minimum of this and the peer's
    /// own idle timeout. 0 for none.
    pub idle_timeout: u16,
    /// Maximum number of bytes the peer may transmit on any one stream before becoming blocked.
    ///
    /// This should be set to at least the expected connection latency multiplied by the maximum
    /// desired throughput. Setting this smaller than `receive_window` helps ensure that a single
    /// stream doesn't monopolize receive buffers, which may otherwise occur if the application
    /// chooses not to read from a large stream for a time while still requiring data on other
    /// streams.
    pub stream_receive_window: u32,
    /// Maximum number of bytes the peer may transmit across all streams of a connection before
    /// becoming blocked.
    ///
    /// This should be set to at least the expected connection latency multiplied by the maximum
    /// desired throughput. Larger values can be useful to allow maximum throughput within a
    /// stream while another is blocked.
    pub receive_window: u32,

    /// Maximum number of tail loss probes before an RTO fires.
    pub max_tlps: u32,
    /// Maximum reordering in packet number space before FACK style loss detection considers a
    /// packet lost.
    pub reordering_threshold: u32,
    /// Maximum reordering in time space before time based loss detection considers a packet lost.
    /// 0.16 format
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

    /// Length of connection IDs for the endpoint.
    ///
    /// This must be either 0 or between 4 and 18 inclusive. The length of the local connection IDs
    /// constrains the amount of simultaneous connections the endpoint can maintain. The API user is
    /// responsible for making sure that the pool is large enough to cover the intended usage.
    pub local_cid_len: usize,
}

impl Default for Config {
    fn default() -> Self {
        const EXPECTED_RTT: u32 = 100; // ms
        const MAX_STREAM_BANDWIDTH: u32 = 12500 * 1000; // bytes/s
                                                        // Window size needed to avoid pipeline
                                                        // stalls
        const STREAM_RWND: u32 = MAX_STREAM_BANDWIDTH / 1000 * EXPECTED_RTT;
        Self {
            max_remote_bi_streams: 0,
            max_remote_uni_streams: 0,
            idle_timeout: 10,
            stream_receive_window: STREAM_RWND,
            receive_window: 8 * STREAM_RWND,

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

            local_cid_len: 8,
        }
    }
}

/// The main entry point to the library
///
/// This object performs no I/O whatsoever. Instead, it generates a stream of I/O operations for a
/// backend to perform via `poll_io`, and consumes incoming packets and timer expirations via
/// `handle` and `timeout`.
pub struct Endpoint {
    log: Logger,
    rng: OsRng,
    ctx: Context,
    connection_ids_initial: FnvHashMap<ConnectionId, ConnectionHandle>,
    connection_ids: FnvHashMap<ConnectionId, ConnectionHandle>,
    connection_remotes: FnvHashMap<SocketAddrV6, ConnectionHandle>,
    pub(crate) connections: Slab<Connection>,
    config: Arc<Config>,
    server_config: Option<ServerConfig>,
    dirty_conns: FnvHashSet<ConnectionHandle>,
    incoming_handshakes: usize,
}

struct Context {
    io: VecDeque<Io>,
    events: VecDeque<(ConnectionHandle, Event)>,
    incoming: VecDeque<ConnectionHandle>,
}

/// Parameters governing incoming connections.
pub struct ServerConfig {
    /// TLS configuration used for incoming connections.
    ///
    /// Must be set to use TLS 1.3 only.
    pub tls_config: Arc<crypto::ServerConfig>,

    /// Private key used to authenticate data included in handshake tokens.
    pub token_key: TokenKey,
    /// Whether to require clients to prove ownership of an address before committing resources.
    ///
    /// Introduces an additional round-trip to the handshake to make denial of service attacks more difficult.
    pub use_stateless_retry: bool,
    /// Microseconds after a stateless retry token was issued for which it's considered valid.
    pub retry_token_lifetime: u64,

    /// Private key used to send authenticated connection resets to clients who were communicating
    /// with a previous instance of this endpoint.
    ///
    /// Must be persisted across restarts to be useful.
    pub reset_key: SigningKey,
    /// Maximum number of incoming connections to buffer.
    ///
    /// Calling `Endpoint::accept` removes a connection from the buffer, so this does not need to
    /// be large.
    pub accept_buffer: u32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        let rng = &mut rand::thread_rng();

        let mut token_value = [0; 64];
        let mut reset_value = [0; 64];
        rng.fill_bytes(&mut token_value);
        rng.fill_bytes(&mut reset_value);

        Self {
            tls_config: Arc::new(crypto::build_server_config()),

            token_key: TokenKey::new(&token_value),
            use_stateless_retry: false,
            retry_token_lifetime: 15_000_000,

            reset_key: SigningKey::new(&digest::SHA512_256, &reset_value),
            accept_buffer: 1024,
        }
    }
}

#[derive(Debug, Fail)]
pub enum EndpointError {
    #[fail(display = "failed to configure TLS: {}", _0)]
    Tls(crypto::TLSError),
}

impl From<crypto::TLSError> for EndpointError {
    fn from(x: crypto::TLSError) -> Self {
        EndpointError::Tls(x)
    }
}

impl Endpoint {
    pub fn new(
        log: Logger,
        config: Config,
        server_config: Option<ServerConfig>,
    ) -> Result<Self, EndpointError> {
        let rng = OsRng::new().unwrap();
        let config = Arc::new(config);
        assert!(
            (config.local_cid_len == 0 || config.local_cid_len >= MIN_CID_SIZE)
                && config.local_cid_len <= MAX_CID_SIZE
        );
        Ok(Self {
            ctx: Context {
                io: VecDeque::new(),
                // session_ticket_buffer,
                events: VecDeque::new(),
                incoming: VecDeque::new(),
            },
            log,
            rng,
            connection_ids_initial: FnvHashMap::default(),
            connection_ids: FnvHashMap::default(),
            connection_remotes: FnvHashMap::default(),
            connections: Slab::new(),
            dirty_conns: FnvHashSet::default(),
            incoming_handshakes: 0,
            config,
            server_config,
        })
    }

    fn is_server(&self) -> bool {
        self.server_config.is_some()
    }

    /// Get an application-facing event
    pub fn poll(&mut self) -> Option<(ConnectionHandle, Event)> {
        self.ctx.events.pop_front()
    }

    /// Get a pending IO operation
    pub fn poll_io(&mut self, now: u64) -> Option<Io> {
        loop {
            if let Some(x) = self.ctx.io.pop_front() {
                return Some(x);
            }
            let &conn = self.dirty_conns.iter().next()?;
            // TODO: Only determine a single operation; only remove from dirty set if that fails
            let mut mux = EndpointMux::new(&mut self.ctx, conn, self.connections[conn.0].side());
            self.connections[conn.0].flush_pending(&mut mux, now);
            self.dirty_conns.remove(&conn);
        }
    }

    /// Process an incoming UDP datagram
    pub fn handle(
        &mut self,
        now: u64,
        remote: SocketAddrV6,
        ecn: Option<EcnCodepoint>,
        mut data: BytesMut,
    ) {
        let datagram_len = data.len();
        while !data.is_empty() {
            match PartialDecode::new(data, self.config.local_cid_len) {
                Ok(partial_decode) => {
                    match self.handle_decode(now, remote, ecn, partial_decode, datagram_len) {
                        Some(rest) => {
                            data = rest;
                        }
                        None => {
                            return;
                        }
                    }
                }
                Err(PacketDecodeError::UnsupportedVersion {
                    source,
                    destination,
                }) => {
                    if !self.is_server() {
                        debug!(self.log, "dropping packet with unsupported version");
                        return;
                    }
                    trace!(self.log, "sending version negotiation");
                    // Negotiate versions
                    let mut buf = Vec::<u8>::new();
                    Header::VersionNegotiate {
                        random: self.rng.gen(),
                        src_cid: destination,
                        dst_cid: source,
                    }
                    .encode(&mut buf);
                    buf.write::<u32>(0x0a1a_2a3a); // reserved version
                    buf.write(VERSION); // supported version
                    self.ctx.io.push_back(Io::Transmit {
                        destination: remote,
                        ecn: None,
                        packet: buf.into(),
                    });
                    return;
                }
                Err(e) => {
                    trace!(self.log, "unable to decode invariant header"; "reason" => %e);
                    return;
                }
            }
        }
    }

    fn handle_decode(
        &mut self,
        now: u64,
        remote: SocketAddrV6,
        ecn: Option<EcnCodepoint>,
        partial_decode: PartialDecode,
        datagram_len: usize,
    ) -> Option<BytesMut> {
        //
        // Handle packet on existing connection, if any
        //

        let dst_cid = partial_decode.dst_cid();
        let conn = {
            let conn = if self.config.local_cid_len > 0 {
                self.connection_ids.get(&dst_cid)
            } else {
                None
            };
            conn.or_else(|| self.connection_ids_initial.get(&dst_cid))
                .or_else(|| self.connection_remotes.get(&remote))
                .cloned()
        };
        if let Some(conn_id) = conn {
            let conn = &mut self.connections[conn_id.0];
            let was_handshake = conn.is_handshaking();
            let mut mux = EndpointMux::new(&mut self.ctx, conn_id, conn.side());
            let remaining = conn.handle_decode(&mut mux, now, remote, ecn, partial_decode);
            if was_handshake && !conn.is_handshaking() && conn.side().is_server() {
                self.incoming_handshakes -= 1;
            }
            self.dirty_conns.insert(conn_id);
            return remaining;
        }

        //
        // Potentially create a new connection
        //

        if !self.is_server() {
            debug!(
                self.log,
                "dropping packet on unrecognized connection {connection} because this endpoint is not a server",
                connection = dst_cid
            );
            return None;
        }

        if partial_decode.has_long_header() {
            if partial_decode.is_initial() {
                if datagram_len < MIN_INITIAL_SIZE {
                    debug!(
                        self.log,
                        "ignoring short initial on {connection}",
                        connection = partial_decode.dst_cid()
                    );
                    return None;
                }

                let crypto = Crypto::new_initial(&partial_decode.dst_cid(), Side::Server);
                return match partial_decode.finish(crypto.pn_decrypt_key()) {
                    Ok((packet, rest)) => {
                        self.handle_initial(now, remote, ecn, packet, &crypto);
                        rest
                    }
                    Err(e) => {
                        trace!(self.log, "unable to decode packet"; "reason" => %e);
                        None
                    }
                };
            } else {
                debug!(
                    self.log,
                    "ignoring non-initial packet for unknown connection {connection}",
                    connection = dst_cid
                );
                return None;
            }
        }

        //
        // If we got this far, we're a server receiving a seemingly valid packet for an unknown
        // connection. Send a stateless reset.
        //

        if !dst_cid.is_empty() {
            debug!(self.log, "sending stateless reset");
            let mut buf = Vec::<u8>::new();
            // Bound padding size to at most 8 bytes larger than input to mitigate amplification
            // attacks
            let header_len = 1 + MAX_CID_SIZE + 1;
            let padding = self.rng.gen_range(
                0,
                cmp::max(
                    RESET_TOKEN_SIZE + 8,
                    datagram_len.saturating_sub(header_len),
                )
                .saturating_sub(RESET_TOKEN_SIZE),
            );
            buf.reserve_exact(header_len + padding + RESET_TOKEN_SIZE);
            let number = self.rng.gen::<u32>() & PACKET_NUMBER_32_MASK | 0x4000;
            Header::Short {
                dst_cid: ConnectionId::random(&mut self.rng, MAX_CID_SIZE),
                number: PacketNumber::U32(number),
                key_phase: false,
            }
            .encode(&mut buf);

            let padding_start = buf.len();
            buf.resize(padding_start + padding, 0);
            self.rng
                .fill_bytes(&mut buf[padding_start..padding_start + padding]);
            buf.extend(&reset_token_for(
                &self.server_config.as_ref().unwrap().reset_key,
                &dst_cid,
            ));

            self.ctx.io.push_back(Io::Transmit {
                destination: remote,
                ecn: None,
                packet: buf.into(),
            });
        } else {
            trace!(self.log, "dropping unrecognized short packet without ID");
        }
        None
    }

    /// Initiate a connection
    pub fn connect(
        &mut self,
        remote: SocketAddrV6,
        config: &Arc<crypto::ClientConfig>,
        server_name: &str,
    ) -> Result<ConnectionHandle, ConnectError> {
        let local_id = self.new_cid();
        let remote_id = ConnectionId::random(&mut self.rng, MAX_CID_SIZE);
        trace!(self.log, "initial dcid"; "value" => %remote_id);
        let conn = self.add_connection(
            remote_id,
            local_id,
            remote_id,
            remote,
            ConnectionOpts::Client(ClientConfig {
                tls_config: config.clone(),
                server_name: server_name.into(),
            }),
        )?;
        self.dirty_conns.insert(conn);
        Ok(conn)
    }

    fn new_cid(&mut self) -> ConnectionId {
        loop {
            let cid = ConnectionId::random(&mut self.rng, self.config.local_cid_len);
            if !self.connection_ids.contains_key(&cid) {
                break cid;
            }
            assert!(self.config.local_cid_len > 0);
        }
    }

    fn add_connection(
        &mut self,
        initial_id: ConnectionId,
        local_id: ConnectionId,
        remote_id: ConnectionId,
        remote: SocketAddrV6,
        opts: ConnectionOpts,
    ) -> Result<ConnectionHandle, ConnectError> {
        debug_assert!(!local_id.is_empty());
        let (tls, client_config) = match opts {
            ConnectionOpts::Client(config) => (
                TlsSession::new_client(
                    &config.tls_config,
                    &config.server_name,
                    &TransportParameters::new(&self.config),
                )?,
                Some(config),
            ),
            ConnectionOpts::Server { orig_dst_cid } => {
                let server_params = TransportParameters {
                    stateless_reset_token: Some(reset_token_for(
                        &self.server_config.as_ref().unwrap().reset_key,
                        &local_id,
                    )),
                    original_connection_id: orig_dst_cid,
                    ..TransportParameters::new(&self.config)
                };
                (
                    TlsSession::new_server(
                        &self.server_config.as_ref().unwrap().tls_config,
                        &server_params,
                    ),
                    None,
                )
            }
        };

        let conn = self.connections.insert(Connection::new(
            self.log.new(o!("connection" => local_id)),
            Arc::clone(&self.config),
            initial_id,
            local_id,
            remote_id,
            remote,
            client_config,
            tls,
        ));
        let conn = ConnectionHandle(conn);

        if self.config.local_cid_len > 0 {
            self.connection_ids.insert(local_id, conn);
        }
        self.connection_remotes.insert(remote, conn);
        Ok(conn)
    }

    fn handle_initial(
        &mut self,
        now: u64,
        remote: SocketAddrV6,
        ecn: Option<EcnCodepoint>,
        packet: Packet,
        crypto: &Crypto,
    ) {
        let Packet {
            header,
            header_data,
            mut payload,
        } = packet;
        let (src_cid, dst_cid, token, packet_number) = match header {
            Header::Initial {
                src_cid,
                dst_cid,
                token,
                number,
            } => (src_cid, dst_cid, token, number),
            _ => panic!("non-initial packet in handle_initial()"),
        };
        let packet_number = packet_number.expand(0);

        if crypto
            .decrypt(packet_number as u64, &header_data, &mut payload)
            .is_err()
        {
            debug!(self.log, "failed to authenticate initial packet");
            return;
        };
        let loc_cid = self.new_cid();

        if self.ctx.incoming.len() + self.incoming_handshakes
            == self.server_config.as_ref().unwrap().accept_buffer as usize
        {
            debug!(self.log, "rejecting connection due to full accept buffer");
            self.ctx.io.push_back(Io::Transmit {
                destination: remote,
                ecn: None,
                packet: handshake_close(
                    &crypto,
                    &src_cid,
                    &loc_cid,
                    0,
                    TransportError::SERVER_BUSY,
                ),
            });
            return;
        }

        let mut retry_cid = None;
        if self.server_config.as_ref().unwrap().use_stateless_retry {
            if let Some((token_dst_cid, token_issued)) = self
                .server_config
                .as_ref()
                .unwrap()
                .token_key
                .check(&remote, &token)
            {
                let expires = token_issued
                    + Duration::from_micros(
                        self.server_config.as_ref().unwrap().retry_token_lifetime,
                    );
                if expires > SystemTime::now() {
                    retry_cid = Some(token_dst_cid);
                } else {
                    trace!(self.log, "sending stateless retry due to expired token");
                }
            } else {
                trace!(self.log, "sending stateless retry due to invalid token");
            }
            if retry_cid.is_none() {
                let token = self.server_config.as_ref().unwrap().token_key.generate(
                    &remote,
                    &dst_cid,
                    SystemTime::now(),
                );
                let mut buf = Vec::new();
                let header = Header::Retry {
                    src_cid: loc_cid,
                    dst_cid: src_cid,
                    orig_dst_cid: dst_cid,
                };
                let encode = header.encode(&mut buf);
                let header_len = buf.len();
                encode.finish(&mut buf, crypto.pn_encrypt_key(), header_len);
                buf.put_slice(&token);

                self.ctx.io.push_back(Io::Transmit {
                    destination: remote,
                    ecn: None,
                    packet: buf.into(),
                });
                return;
            }
        }

        let conn = self
            .add_connection(
                dst_cid,
                loc_cid,
                src_cid,
                remote,
                ConnectionOpts::Server {
                    orig_dst_cid: retry_cid,
                },
            )
            .unwrap();
        self.connection_ids_initial.insert(dst_cid, conn);
        let mut mux = EndpointMux::new(&mut self.ctx, conn, self.connections[conn.0].side());
        match self.connections[conn.0].handle_initial(
            &mut mux,
            now,
            ecn,
            packet_number as u64,
            payload.freeze(),
        ) {
            Ok(()) => {
                self.incoming_handshakes += 1;
                self.dirty_conns.insert(conn);
            }
            Err(e) => {
                debug!(self.log, "handshake failed"; "reason" => %e);
                self.ctx.io.push_back(Io::Transmit {
                    destination: remote,
                    ecn: None,
                    packet: handshake_close(&crypto, &src_cid, &loc_cid, 0, e),
                });
            }
        }
    }

    fn forget(&mut self, conn: ConnectionHandle) {
        if self.connections[conn.0].side().is_server() {
            self.connection_ids_initial
                .remove(&self.connections[conn.0].init_cid);
        }
        if self.config.local_cid_len > 0 {
            self.connection_ids
                .remove(&self.connections[conn.0].loc_cid());
        }
        self.connection_remotes
            .remove(&self.connections[conn.0].remote);
        self.dirty_conns.remove(&conn);
        self.connections.remove(conn.0);
    }

    /// Handle a timer expiring
    pub fn timeout(&mut self, now: u64, conn: ConnectionHandle, timer: Timer) {
        match timer {
            Timer::Close => {
                self.ctx.io.push_back(Io::TimerStop {
                    connection: conn,
                    timer: Timer::Idle,
                });
                self.ctx.events.push_back((conn, Event::ConnectionDrained));
                if self.connections[conn.0].app_closed {
                    self.forget(conn);
                } else {
                    self.connections[conn.0].state = State::Drained;
                }
            }
            Timer::Idle => {
                let mut mux =
                    EndpointMux::new(&mut self.ctx, conn, self.connections[conn.0].side());
                self.connections[conn.0].close_common(&mut mux, now);
                self.connections[conn.0].state = State::Draining;
                self.ctx
                    .events
                    .push_back((conn, ConnectionError::TimedOut.into()));
                self.dirty_conns.insert(conn); // Ensure the loss detection timer cancellation
                                               // goes through
            }
            Timer::LossDetection => {
                let mut mux =
                    EndpointMux::new(&mut self.ctx, conn, self.connections[conn.0].side());
                self.connections[conn.0].check_packet_loss(&mut mux, now);
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
        let result = self.connections[conn.0].write(stream, data);
        self.dirty_conns.insert(conn);
        result
    }

    /// Indicate that no more data will be sent on a stream
    ///
    /// All previously transmitted data will still be delivered. Incoming data on bidirectional
    /// streams is unaffected.
    ///
    /// # Panics
    /// - when applied to a stream that does not have an active outgoing channel
    pub fn finish(&mut self, conn: ConnectionHandle, stream: StreamId) {
        self.connections[conn.0].finish(stream);
        self.dirty_conns.insert(conn);
    }

    /// Read data from a stream
    ///
    /// Treats a stream like a simple pipe, similar to a TCP connection. Subject to head-of-line
    /// blocking within the stream. Consider `read_unordered` for higher throughput.
    ///
    /// # Panics
    /// - when applied to a stream that does not have an active incoming channel
    pub fn read(
        &mut self,
        conn: ConnectionHandle,
        stream: StreamId,
        buf: &mut [u8],
    ) -> Result<usize, ReadError> {
        self.dirty_conns.insert(conn); // May need to send flow control frames after reading
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
    /// Unlike `read`, this interface is not subject to head-of-line blocking within the stream,
    /// and hence can achieve higher throughput over lossy links.
    ///
    /// Some segments may be received multiple times.
    ///
    /// On success, returns `Ok((data, offset))` where `offset` is the position `data` begins in
    /// the stream.
    ///
    /// # Panics
    /// - when applied to a stream that does not have an active incoming channel
    pub fn read_unordered(
        &mut self,
        conn: ConnectionHandle,
        stream: StreamId,
    ) -> Result<(Bytes, u64), ReadError> {
        self.dirty_conns.insert(conn); // May need to send flow control frames after reading
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
        self.connections[conn.0].reset(stream, error_code);
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
    /// Returns `None` if the maximum number of streams currently permitted by the remote endpoint
    /// are already open.
    pub fn open(&mut self, conn: ConnectionHandle, direction: Directionality) -> Option<StreamId> {
        self.connections[conn.0].open(direction)
    }

    /// Ping the remote endpoint
    ///
    /// Useful for preventing an otherwise idle connection from timing out.
    pub fn ping(&mut self, conn: ConnectionHandle) {
        self.connections[conn.0].pending.ping = true;
        self.dirty_conns.insert(conn);
    }

    /// Close a connection immediately
    ///
    /// This does not ensure delivery of outstanding data. It is the application's responsibility
    /// to call this only when all important communications have been completed.
    pub fn close(&mut self, now: u64, conn: ConnectionHandle, error_code: u16, reason: Bytes) {
        if let State::Drained = self.connections[conn.0].state {
            self.forget(conn);
            return;
        }
        let mut mux = EndpointMux::new(&mut self.ctx, conn, self.connections[conn.0].side());
        self.connections[conn.0].close(&mut mux, now, error_code, reason);
    }

    pub fn accept(&mut self) -> Option<ConnectionHandle> {
        self.ctx.incoming.pop_front()
    }

    pub fn connection(&self, handle: ConnectionHandle) -> &Connection {
        &self.connections[handle.0]
    }
}

/// Events of interest to the application
#[derive(Debug)]
pub enum Event {
    /// A connection was successfully established.
    Connected {
        protocol: Option<String>,
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

impl From<ConnectionError> for Event {
    fn from(x: ConnectionError) -> Self {
        Event::ConnectionLost { reason: x }
    }
}

/// I/O operations to be immediately executed the backend.
#[derive(Debug)]
pub enum Io {
    Transmit {
        destination: SocketAddrV6,
        /// Explicit congestion notification bits to set on the packet
        ecn: Option<EcnCodepoint>,
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
        _: &slog::Record<'_>,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_arguments(key, &format_args!("{:?}", self))
    }
}

enum ConnectionOpts {
    Client(ClientConfig),
    Server { orig_dst_cid: Option<ConnectionId> },
}

// TODO: Deduplicate events and timer signals.
pub struct EndpointMux<'a> {
    handle: ConnectionHandle,
    side: Side,
    ctx: &'a mut Context,
}

impl<'a> EndpointMux<'a> {
    fn new(ctx: &'a mut Context, handle: ConnectionHandle, side: Side) -> Self {
        Self { handle, side, ctx }
    }
}

impl Multiplexer for EndpointMux<'_> {
    fn transmit(
        &mut self,
        destination: SocketAddrV6,
        ecn: Option<EcnCodepoint>,
        packet: Box<[u8]>,
    ) {
        self.ctx.io.push_back(Io::Transmit {
            destination,
            ecn,
            packet,
        });
    }
    fn timer_start(&mut self, timer: Timer, time: u64) {
        self.ctx.io.push_back(Io::TimerStart {
            connection: self.handle,
            timer,
            time,
        });
    }
    fn timer_stop(&mut self, timer: Timer) {
        self.ctx.io.push_back(Io::TimerStop {
            connection: self.handle,
            timer,
        });
    }
    fn emit(&mut self, event: Event) {
        if let (Side::Server, &Event::Connected { .. }) = (self.side, &event) {
            self.ctx.incoming.push_back(self.handle);
        } else {
            self.ctx.events.push_back((self.handle, event));
        }
    }
}
