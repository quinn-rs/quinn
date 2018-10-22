use std::collections::VecDeque;
use std::net::SocketAddrV6;
use std::sync::Arc;
use std::{cmp, io, mem};

use bytes::{Bytes, BytesMut};
use fnv::{FnvHashMap, FnvHashSet};
use rand::distributions::Distribution;
use rand::{distributions, OsRng, Rng, RngCore};
use slab::Slab;
use slog::{self, Logger};

use coding::BufMutExt;
use connection::{
    make_tls, state, ClientConfig, Connection, ConnectionError, ConnectionHandle, ReadError, State,
    WriteError,
};
use crypto::{self, reset_token_for, ConnectError, Crypto, ServerConfig};
use packet::{
    set_payload_length, types, ConnectionId, Header, HeaderError, Packet, PacketNumber,
    AEAD_TAG_SIZE,
};
use {
    frame, Directionality, Side, StreamId, TransportError, MAX_CID_SIZE, MIN_INITIAL_SIZE, MIN_MTU,
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
    /// Maximum value is 600 seconds. The actual value used is the minimum of this and the peer's own idle timeout. 0 for none.
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

    pub tls_server_config: Arc<ServerConfig>,
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

            tls_server_config: Arc::new(crypto::build_server_config()),
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
}

pub struct Context {
    pub log: Logger,
    pub rng: OsRng,
    pub config: Arc<Config>,
    pub io: VecDeque<Io>,
    // pub session_ticket_buffer: SessionTicketBuffer,
    pub events: VecDeque<(ConnectionHandle, Event)>,
    pub incoming: VecDeque<ConnectionHandle>,
    pub incoming_handshakes: usize,
    pub dirty_conns: FnvHashSet<ConnectionHandle>,
    pub readable_conns: FnvHashSet<ConnectionHandle>,
    pub initial_packet_number: distributions::Uniform<u64>,
    pub listen_keys: Option<ListenKeys>,
}

impl Context {
    fn gen_initial_packet_num(&mut self) -> u32 {
        self.initial_packet_number.sample(&mut self.rng) as u32
    }
}

const LOCAL_ID_LEN: usize = 8;

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
    Tls(crypto::TLSError),
    #[fail(display = "failed open keylog file: {}", _0)]
    Keylog(io::Error),
    #[fail(display = "protocol ID longer than 255 bytes")]
    ProtocolTooLong(Box<[u8]>),
    #[fail(display = "invalid DNS name: {}", _0)]
    InvalidDnsName(String),
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
        listen: Option<ListenKeys>,
    ) -> Result<Self, EndpointError> {
        let rng = OsRng::new().unwrap();
        let config = Arc::new(config);
        Ok(Self {
            ctx: Context {
                log,
                rng,
                config,
                io: VecDeque::new(),
                // session_ticket_buffer,
                initial_packet_number: distributions::Uniform::from(0..2u64.pow(32) - 1024),
                events: VecDeque::new(),
                dirty_conns: FnvHashSet::default(),
                readable_conns: FnvHashSet::default(),
                incoming: VecDeque::new(),
                incoming_handshakes: 0,
                listen_keys: listen,
            },
            connection_ids_initial: FnvHashMap::default(),
            connection_ids: FnvHashMap::default(),
            connection_remotes: FnvHashMap::default(),
            connections: Slab::new(),
        })
    }

    fn listen(&self) -> bool {
        self.ctx.listen_keys.is_some()
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
            if let Some(x) = self.ctx.io.pop_front() {
                return Some(x);
            }
            let &conn = self.ctx.dirty_conns.iter().next()?;
            // TODO: Only determine a single operation; only remove from dirty set if that fails
            self.flush_pending(now, conn);
            self.ctx.dirty_conns.remove(&conn);
        }
    }

    /// Process an incoming UDP datagram
    pub fn handle(&mut self, now: u64, remote: SocketAddrV6, mut data: BytesMut) {
        let datagram_len = data.len();
        while !data.is_empty() {
            let (packet, rest) = match Packet::decode(data, LOCAL_ID_LEN) {
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
                    buf.write::<u32>(0x0a1a_2a3a); // reserved version
                    buf.write(VERSION); // supported version
                    self.ctx.io.push_back(Io::Transmit {
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

        let dest_id = packet.header.destination_id();
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
                    && packet.payload[packet.payload.len() - 16..] == token
                {
                    if !self.connections[conn.0]
                        .state
                        .as_ref()
                        .unwrap()
                        .is_drained()
                    {
                        debug!(self.ctx.log, "got stateless reset"; "connection" => %self.connections[conn.0].local_id);
                        self.ctx.io.push_back(Io::TimerStop {
                            connection: conn,
                            timer: Timer::LossDetection,
                        });
                        self.ctx.io.push_back(Io::TimerStop {
                            connection: conn,
                            timer: Timer::Close,
                        });
                        self.ctx.io.push_back(Io::TimerStop {
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
        let Packet {
            header_data,
            header,
            payload,
        } = packet;
        if let Header::Long {
            ty,
            ref destination_id,
            ref source_id,
            number,
        } = header
        {
            match ty {
                types::INITIAL => {
                    if datagram_len >= MIN_INITIAL_SIZE {
                        self.handle_initial(
                            now,
                            remote,
                            destination_id.clone(),
                            source_id.clone(),
                            number,
                            &header_data,
                            payload,
                        );
                    } else {
                        debug!(
                            self.ctx.log,
                            "ignoring short initial on {connection}",
                            connection = destination_id
                        );
                    }
                    return;
                }
                /*types::ZERO_RTT => {
                    // MAY buffer a limited amount
                    trace!(
                        self.ctx.log,
                        "dropping 0-RTT packet for unknown connection {connection}",
                        connection = destination_id.clone()
                    );
                    return;
                }*/
                _ => {
                    debug!(self.ctx.log, "ignoring packet for unknown connection {connection} with unexpected type {type:02x}",
                           connection=destination_id, type=ty);
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
                cmp::max(RESET_TOKEN_SIZE + 8, payload.len()) - RESET_TOKEN_SIZE,
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
                &self.ctx.listen_keys.as_ref().unwrap().reset,
                &dest_id,
            ));
            self.ctx.io.push_back(Io::Transmit {
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
        config: &Arc<crypto::ClientConfig>,
        server_name: &str,
    ) -> Result<ConnectionHandle, ConnectError> {
        let local_id = ConnectionId::random(&mut self.ctx.rng, LOCAL_ID_LEN as u8);
        let remote_id = ConnectionId::random(&mut self.ctx.rng, MAX_CID_SIZE as u8);
        trace!(self.ctx.log, "initial dcid"; "value" => %remote_id);
        let conn = self.add_connection(
            remote_id,
            local_id,
            remote_id,
            remote,
            Some(ClientConfig {
                tls_config: config.clone(),
                server_name: server_name.into(),
            }),
        );
        self.ctx.dirty_conns.insert(conn);
        Ok(conn)
    }

    fn add_connection(
        &mut self,
        initial_id: ConnectionId,
        local_id: ConnectionId,
        remote_id: ConnectionId,
        remote: SocketAddrV6,
        client_config: Option<ClientConfig>,
    ) -> ConnectionHandle {
        debug_assert!(!local_id.is_empty());
        let packet_num = self.ctx.gen_initial_packet_num();
        let conn = {
            let entry = self.connections.vacant_entry();
            let conn = ConnectionHandle(entry.key());
            let tls = make_tls(&self.ctx, &local_id, client_config.as_ref());

            entry.insert(Connection::new(
                initial_id,
                local_id,
                remote_id,
                remote,
                packet_num.into(),
                client_config,
                tls,
                &mut self.ctx,
                conn,
            ));
            conn
        };
        self.connection_ids.insert(local_id, conn);
        self.connection_remotes.insert(remote, conn);
        conn
    }

    fn handle_initial(
        &mut self,
        now: u64,
        remote: SocketAddrV6,
        dest_id: ConnectionId,
        source_id: ConnectionId,
        packet_number: u32,
        header: &[u8],
        mut payload: BytesMut,
    ) {
        let crypto = Crypto::new_handshake(&dest_id, Side::Server);
        if crypto
            .decrypt(packet_number as u64, header, &mut payload)
            .is_err()
        {
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
            self.ctx.io.push_back(Io::Transmit {
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

        let conn = self.add_connection(dest_id, local_id, source_id, remote, None);
        self.connection_ids_initial.insert(dest_id, conn);
        match self.connections[conn.0].handle_initial(
            &mut self.ctx,
            now,
            packet_number as u64,
            payload.freeze(),
        ) {
            Ok(()) => {}
            Err(e) => {
                debug!(self.ctx.log, "handshake failed"; "reason" => %e);
                let n = self.ctx.gen_initial_packet_num();
                self.ctx.io.push_back(Io::Transmit {
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
            }
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
        let prev_state = self.connections[conn.0].state.take().unwrap();
        let was_handshake = match prev_state {
            State::Handshake(_) => true,
            _ => false,
        };
        let state = match self.connections[conn.0].handle_connected_inner(
            &mut self.ctx,
            now,
            remote,
            packet,
            prev_state,
        ) {
            Ok(state) => state,
            Err(conn_err) => {
                self.ctx.events.push_back((
                    conn,
                    Event::ConnectionLost {
                        reason: conn_err.clone(),
                    },
                ));

                match conn_err {
                    ConnectionError::ApplicationClosed { reason } => {
                        if was_handshake {
                            State::handshake_failed(reason, None)
                        } else {
                            State::closed(reason)
                        }
                    }
                    ConnectionError::ConnectionClosed { reason } => {
                        if was_handshake {
                            State::handshake_failed(reason, None)
                        } else {
                            State::closed(reason)
                        }
                    }
                    ConnectionError::Reset => {
                        debug!(self.ctx.log, "unexpected connection reset error received"; "err" => %conn_err, "initial_conn_id" => %self.connections[conn.0].initial_id);
                        panic!("unexpected connection reset error received");
                    }
                    ConnectionError::TimedOut => {
                        debug!(self.ctx.log, "unexpected connection timed out error received"; "err" => %conn_err, "initial_conn_id" => %self.connections[conn.0].initial_id);
                        panic!("unexpected connection timed out error received");
                    }
                    ConnectionError::TransportError { error_code } => {
                        if was_handshake {
                            State::handshake_failed(error_code, None)
                        } else {
                            State::closed(error_code)
                        }
                    }
                    ConnectionError::VersionMismatch => State::Draining,
                }
            }
        };

        if !was_closed && state.is_closed() {
            self.connections[conn.0].close_common(&mut self.ctx, now);
        }

        // Transmit CONNECTION_CLOSE if necessary
        match state {
            State::HandshakeFailed(ref state) => {
                if !was_closed && self.connections[conn.0].side == Side::Server {
                    self.ctx.incoming_handshakes -= 1;
                }
                let n = self.connections[conn.0].get_tx_number();
                self.ctx.io.push_back(Io::Transmit {
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
                self.ctx.io.push_back(Io::Transmit {
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
            self.ctx.io.push_back(Io::Transmit {
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
                    self.ctx.io.push_back(Io::TimerStart {
                        connection: conn,
                        timer: Timer::Idle,
                        time,
                    });
                } else {
                    self.ctx.io.push_back(Io::TimerStop {
                        connection: conn,
                        timer: Timer::Idle,
                    });
                }
            }
            if let Some(setting) = c.set_loss_detection.take() {
                if let Some(time) = setting {
                    self.ctx.io.push_back(Io::TimerStart {
                        connection: conn,
                        timer: Timer::LossDetection,
                        time,
                    });
                } else {
                    self.ctx.io.push_back(Io::TimerStop {
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
                self.ctx.io.push_back(Io::TimerStop {
                    connection: conn,
                    timer: Timer::Idle,
                });
                self.ctx.events.push_back((conn, Event::ConnectionDrained));
                if self.connections[conn.0].app_closed {
                    self.forget(conn);
                } else {
                    self.connections[conn.0].state = Some(State::Drained);
                }
            }
            Timer::Idle => {
                self.connections[conn.0].close_common(&mut self.ctx, now);
                self.connections[conn.0].state = Some(State::Draining);
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
                        ).collect::<Vec<_>>();
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
                    self.ctx.io.push_back(Io::Transmit {
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
                        self.ctx.io.push_back(Io::Transmit {
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
        let r = self.connections[conn.0].write(&self.ctx.config, stream, data);
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
                self.connections[conn.0].maybe_cleanup(&self.ctx.config, stream);
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
                self.connections[conn.0].maybe_cleanup(&self.ctx.config, stream);
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
        self.connections[conn.0].reset(&mut self.ctx, stream, error_code)
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

    /// Close a connection immediately
    ///
    /// This does not ensure delivery of outstanding data. It is the application's responsibility to call this only when
    /// all important communications have been completed.
    pub fn close(&mut self, now: u64, conn: ConnectionHandle, error_code: u16, reason: Bytes) {
        if let State::Drained = *self.connections[conn.0].state.as_ref().unwrap() {
            self.forget(conn);
            return;
        }
        self.connections[conn.0].close(&mut self.ctx, now, error_code, reason);
    }

    /// Look up whether we're the client or server of `conn`.
    pub fn get_side(&self, conn: ConnectionHandle) -> Side {
        self.connections[conn.0].side
    }

    /// The `ConnectionId` used for `conn` locally.
    pub fn get_local_id(&self, conn: ConnectionHandle) -> ConnectionId {
        self.connections[conn.0].local_id
    }
    /// The `ConnectionId` used for `conn` by the peer.
    pub fn get_remote_id(&self, conn: ConnectionHandle) -> ConnectionId {
        self.connections[conn.0].remote_id
    }
    pub fn get_remote_address(&self, conn: ConnectionHandle) -> &SocketAddrV6 {
        &self.connections[conn.0].remote
    }
    pub fn get_protocol(&self, conn: ConnectionHandle) -> Option<&[u8]> {
        self.connections[conn.0]
            .tls
            .get_alpn_protocol()
            .map(|p| p.as_bytes())
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
    pub fn get_server_name(&self, conn: ConnectionHandle) -> Option<&str> {
        self.connections[conn.0].tls.get_sni_hostname()
    }

    /// Whether a previous session was successfully resumed by `conn`.
    pub fn get_session_resumed(&self, _: ConnectionHandle) -> bool {
        false // TODO: fixme?
    }

    pub fn accept(&mut self) -> Option<ConnectionHandle> {
        self.ctx.incoming.pop_front()
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

fn handshake_close<R>(
    crypto: &Crypto,
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
        ty: types::HANDSHAKE,
        destination_id: *remote_id,
        source_id: *local_id,
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
    crypto.encrypt(packet_number as u64, &mut buf, header_len);
    buf.into()
}
