use std::cmp;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::ops::{Index, IndexMut};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use bytes::{BufMut, BytesMut};
use err_derive::Error;
use fnv::FnvHashMap;
use rand::{rngs::OsRng, Rng, RngCore};
use ring::digest;
use ring::hmac::SigningKey;
use slab::Slab;
use slog::{self, Logger};

use crate::coding::BufMutExt;
use crate::connection::{
    initial_close, ClientConfig, Connection, ConnectionError, ConnectionEvent, EndpointEvent,
};
use crate::crypto::{
    self, reset_token_for, Crypto, CryptoClientConfig, CryptoServerConfig, RingHeaderCrypto,
    TokenKey,
};
use crate::packet::{ConnectionId, EcnCodepoint, Header, Packet, PacketDecodeError, PartialDecode};
use crate::transport_parameters::TransportParameters;
use crate::{
    varint, Directionality, Side, StreamId, Transmit, TransportError, LOC_CID_COUNT, MAX_CID_SIZE,
    MIN_CID_SIZE, MIN_INITIAL_SIZE, RESET_TOKEN_SIZE, VERSION,
};

/// The main entry point to the library
///
/// This object performs no I/O whatsoever. Instead, it generates a stream of I/O operations for a
/// backend to perform via `poll_io`, and consumes incoming packets and timer expirations via
/// `handle` and `timeout`.
pub struct Endpoint {
    log: Logger,
    rng: OsRng,
    transmits: VecDeque<Transmit>,
    connection_ids_initial: FnvHashMap<ConnectionId, ConnectionHandle>,
    connection_ids: FnvHashMap<ConnectionId, ConnectionHandle>,
    connection_remotes: FnvHashMap<SocketAddr, ConnectionHandle>,
    connections: Slab<ConnectionMeta>,
    config: Arc<EndpointConfig>,
    server_config: Option<Arc<ServerConfig>>,
    incoming_handshakes: usize,
}

impl Endpoint {
    pub fn new(
        log: Logger,
        config: Arc<EndpointConfig>,
        server_config: Option<Arc<ServerConfig>>,
    ) -> Result<Self, ConfigError> {
        config.validate()?;
        let rng = OsRng::new().unwrap();
        Ok(Self {
            log,
            rng,
            transmits: VecDeque::new(),
            connection_ids_initial: FnvHashMap::default(),
            connection_ids: FnvHashMap::default(),
            connection_remotes: FnvHashMap::default(),
            connections: Slab::new(),
            incoming_handshakes: 0,
            config,
            server_config,
        })
    }

    fn is_server(&self) -> bool {
        self.server_config.is_some()
    }

    /// Get the next packet to transmit
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        self.transmits.pop_front()
    }

    pub fn handle_event(
        &mut self,
        ch: ConnectionHandle,
        event: EndpointEvent,
    ) -> Option<ConnectionEvent> {
        match event {
            EndpointEvent::NeedIdentifiers => {
                if self.config.local_cid_len != 0 {
                    // We've already issued one CID as part of the normal handshake process.
                    return Some(self.send_new_identifiers(ch, LOC_CID_COUNT - 1));
                }
            }
            EndpointEvent::RetireConnectionId(seq) => {
                if let Some(cid) = self.connections[ch].loc_cids.remove(&seq) {
                    trace!(
                        self.log,
                        "peer retired CID {sequence}: {cid}",
                        sequence = seq,
                        cid = cid,
                    );
                    self.connection_ids.remove(&cid);
                    return Some(self.send_new_identifiers(ch, 1));
                }
            }
            EndpointEvent::Closed { remote } => {
                let init_cid = self.connections[ch].init_cid;
                if init_cid.len() > 0 {
                    self.connection_ids_initial.remove(&init_cid);
                }

                for cid in self.connections[ch].loc_cids.values() {
                    self.connection_ids.remove(&cid);
                }

                self.connection_remotes.remove(&remote);
                self.connections.remove(ch.0);
            }
        }
        None
    }

    /// Process an incoming UDP datagram
    pub fn handle(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        ecn: Option<EcnCodepoint>,
        data: BytesMut,
    ) -> Option<(ConnectionHandle, DatagramEvent)> {
        let datagram_len = data.len();
        let (first_decode, remaining) = match PartialDecode::new(data, self.config.local_cid_len) {
            Ok(x) => x,
            Err(PacketDecodeError::UnsupportedVersion {
                source,
                destination,
            }) => {
                if !self.is_server() {
                    debug!(self.log, "dropping packet with unsupported version");
                    return None;
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
                self.transmits.push_back(Transmit {
                    destination: remote,
                    ecn: None,
                    packet: buf.into(),
                });
                return None;
            }
            Err(e) => {
                trace!(self.log, "malformed header"; "reason" => %e);
                return None;
            }
        };

        //
        // Handle packet on existing connection, if any
        //

        let dst_cid = first_decode.dst_cid();
        let known_ch = {
            let ch = if self.config.local_cid_len > 0 {
                self.connection_ids.get(&dst_cid)
            } else {
                None
            };
            ch.or_else(|| self.connection_ids_initial.get(&dst_cid))
                .or_else(|| {
                    // If CIDs are in use, only stateless resets (which use short headers) will
                    // legitimately have unknown CIDs.
                    if self.config.local_cid_len == 0 || !first_decode.has_long_header() {
                        self.connection_remotes.get(&remote)
                    } else {
                        None
                    }
                })
                .cloned()
        };
        if let Some(ch) = known_ch {
            return Some((
                ch,
                DatagramEvent::ConnectionEvent(ConnectionEvent::Datagram {
                    now,
                    remote,
                    ecn,
                    first_decode,
                    remaining,
                }),
            ));
        }

        //
        // Potentially create a new connection
        //

        if !self.is_server() {
            debug!(
                self.log,
                "got unexpected packet on unrecognized connection {connection}",
                connection = dst_cid
            );
            self.stateless_reset(datagram_len, remote, &dst_cid);
            return None;
        }

        if first_decode.has_long_header() {
            return if first_decode.is_initial() {
                if datagram_len < MIN_INITIAL_SIZE {
                    debug!(
                        self.log,
                        "ignoring short initial on {connection}",
                        connection = dst_cid
                    );
                    return None;
                }

                let crypto = Crypto::new_initial(&dst_cid, Side::Server);
                let header_crypto = crypto.header_crypto();
                match first_decode.finish(Some(&header_crypto)) {
                    Ok(packet) => self
                        .handle_initial(
                            now,
                            remote,
                            ecn,
                            packet,
                            remaining,
                            &crypto,
                            &header_crypto,
                        )
                        .map(|(ch, conn)| (ch, DatagramEvent::NewConnection(conn))),
                    Err(e) => {
                        trace!(self.log, "unable to decode packet"; "reason" => %e);
                        None
                    }
                }
            } else {
                debug!(
                    self.log,
                    "ignoring non-initial packet for unknown connection {connection}",
                    connection = dst_cid
                );
                None
            };
        }

        //
        // If we got this far, we're a server receiving a seemingly valid packet for an unknown
        // connection. Send a stateless reset.
        //

        if !dst_cid.is_empty() {
            self.stateless_reset(datagram_len, remote, &dst_cid);
        } else {
            trace!(self.log, "dropping unrecognized short packet without ID");
        }
        None
    }

    fn stateless_reset(
        &mut self,
        inciting_dgram_len: usize,
        remote: SocketAddr,
        dst_cid: &ConnectionId,
    ) {
        /// Minimum amount of padding for the stateless reset to look like a short-header packet
        const MIN_PADDING_LEN: usize = 23;

        // Prevent amplification attacks and reset loops by ensuring we pad to at most 1 byte
        // smaller than the inciting packet.
        let max_padding_len = match inciting_dgram_len.checked_sub(RESET_TOKEN_SIZE) {
            Some(headroom) if headroom > MIN_PADDING_LEN => headroom,
            _ => {
                debug!(self.log, "ignoring unexpected {len} byte packet: not larger than minimum stateless reset size", len=inciting_dgram_len);
                return;
            }
        };

        debug!(
            self.log,
            "sending stateless reset for {connection} to {remote}",
            connection = dst_cid,
            remote = remote,
        );
        let mut buf = Vec::<u8>::new();
        let padding_len = self.rng.gen_range(MIN_PADDING_LEN, max_padding_len);
        buf.reserve_exact(padding_len + RESET_TOKEN_SIZE);
        buf.resize(padding_len, 0);
        self.rng.fill_bytes(&mut buf[0..padding_len]);
        buf[0] = 0b0100_0000 | buf[0] >> 2;
        buf.extend(&reset_token_for(&self.config.reset_key, dst_cid));

        debug_assert!(buf.len() < inciting_dgram_len);

        self.transmits.push_back(Transmit {
            destination: remote,
            ecn: None,
            packet: buf.into(),
        });
    }

    /// Initiate a connection
    pub fn connect(
        &mut self,
        remote: SocketAddr,
        transport_config: Arc<TransportConfig>,
        crypto_config: Arc<crypto::ClientConfig>,
        server_name: &str,
    ) -> Result<(ConnectionHandle, Connection), ConnectError> {
        transport_config.validate(&self.log)?;
        let remote_id = ConnectionId::random(&mut self.rng, MAX_CID_SIZE);
        trace!(self.log, "initial dcid"; "value" => %remote_id);
        let (ch, conn) = self.add_connection(
            remote_id,
            remote_id,
            remote,
            transport_config,
            ConnectionOpts::Client(ClientConfig {
                tls_config: crypto_config,
                server_name: server_name.into(),
            }),
        )?;
        Ok((ch, conn))
    }

    fn send_new_identifiers(&mut self, ch: ConnectionHandle, num: usize) -> ConnectionEvent {
        let mut ids = vec![];
        for _ in 0..num {
            let cid = self.new_cid();
            self.connection_ids.insert(cid, ch);
            let meta = &mut self.connections[ch];
            meta.cids_issued += 1;
            let seq = meta.cids_issued;
            meta.loc_cids.insert(seq, cid);
            ids.push((seq, cid));
        }
        ConnectionEvent::NewIdentifiers(ids)
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
        init_cid: ConnectionId,
        rem_cid: ConnectionId,
        remote: SocketAddr,
        transport_config: Arc<TransportConfig>,
        opts: ConnectionOpts,
    ) -> Result<(ConnectionHandle, Connection), ConnectError> {
        let loc_cid = self.new_cid();
        let params = TransportParameters::new(&transport_config);
        let (tls, client_config) = match opts {
            ConnectionOpts::Client(config) => (
                config
                    .tls_config
                    .start_session(&config.server_name, &params)?,
                Some(config),
            ),
            ConnectionOpts::Server { orig_dst_cid } => {
                let server_params = TransportParameters {
                    stateless_reset_token: Some(reset_token_for(&self.config.reset_key, &loc_cid)),
                    original_connection_id: orig_dst_cid,
                    ..params
                };
                (
                    self.server_config
                        .as_ref()
                        .unwrap()
                        .tls_config
                        .start_session(&server_params),
                    None,
                )
            }
        };

        let remote_validated = self.server_config.as_ref().map_or(false, |cfg| {
            cfg.use_stateless_retry && client_config.is_none()
        });
        let conn = Connection::new(
            self.log.new(o!("connection" => loc_cid)),
            Arc::clone(&self.config),
            transport_config,
            init_cid,
            loc_cid,
            rem_cid,
            remote,
            client_config,
            tls,
            remote_validated,
        );
        let id = self.connections.insert(ConnectionMeta {
            init_cid,
            cids_issued: 0,
            loc_cids: HashMap::new(),
        });
        let ch = ConnectionHandle(id);

        if self.config.local_cid_len > 0 {
            self.connection_ids.insert(loc_cid, ch);
        }
        self.connection_remotes.insert(remote, ch);
        Ok((ch, conn))
    }

    fn handle_initial(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        ecn: Option<EcnCodepoint>,
        mut packet: Packet,
        rest: Option<BytesMut>,
        crypto: &Crypto,
        header_crypto: &RingHeaderCrypto,
    ) -> Option<(ConnectionHandle, Connection)> {
        let (src_cid, dst_cid, token, packet_number) = match packet.header {
            Header::Initial {
                src_cid,
                dst_cid,
                ref token,
                number,
            } => (src_cid, dst_cid, token.clone(), number),
            _ => panic!("non-initial packet in handle_initial()"),
        };
        let packet_number = packet_number.expand(0);

        if crypto
            .decrypt(
                packet_number as u64,
                &packet.header_data,
                &mut packet.payload,
            )
            .is_err()
        {
            debug!(self.log, "failed to authenticate initial packet"; "pn" => packet_number);
            return None;
        };

        // Local CID used for stateless packets
        let temp_loc_cid = ConnectionId::random(&mut self.rng, self.config.local_cid_len);
        let server_config = self.server_config.as_ref().unwrap();

        if self.incoming_handshakes == server_config.accept_buffer as usize {
            debug!(self.log, "rejecting connection due to full accept buffer");
            self.transmits.push_back(Transmit {
                destination: remote,
                ecn: None,
                packet: initial_close(
                    crypto,
                    header_crypto,
                    &src_cid,
                    &temp_loc_cid,
                    0,
                    TransportError::SERVER_BUSY(""),
                ),
            });
            return None;
        }

        if dst_cid.len() < 8
            && (!server_config.use_stateless_retry || dst_cid.len() != self.config.local_cid_len)
        {
            debug!(
                self.log,
                "rejecting connection due to invalid DCID length {len}",
                len = dst_cid.len()
            );
            self.transmits.push_back(Transmit {
                destination: remote,
                ecn: None,
                packet: initial_close(
                    crypto,
                    header_crypto,
                    &src_cid,
                    &temp_loc_cid,
                    0,
                    TransportError::PROTOCOL_VIOLATION("invalid destination CID length"),
                ),
            });
            return None;
        }

        let mut retry_cid = None;
        if server_config.use_stateless_retry {
            if let Some((token_dst_cid, token_issued)) =
                server_config.token_key.check(&remote, &token)
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
                let token = server_config
                    .token_key
                    .generate(&remote, &dst_cid, SystemTime::now());
                let mut buf = Vec::new();
                let header = Header::Retry {
                    src_cid: temp_loc_cid,
                    dst_cid: src_cid,
                    orig_dst_cid: dst_cid,
                };
                let encode = header.encode(&mut buf);
                encode.finish(&mut buf, header_crypto);
                buf.put_slice(&token);

                self.transmits.push_back(Transmit {
                    destination: remote,
                    ecn: None,
                    packet: buf.into(),
                });
                return None;
            }
        }

        let (ch, mut conn) = self
            .add_connection(
                dst_cid,
                src_cid,
                remote,
                server_config.transport_config.clone(),
                ConnectionOpts::Server {
                    orig_dst_cid: retry_cid,
                },
            )
            .unwrap();
        if dst_cid.len() != 0 {
            self.connection_ids_initial.insert(dst_cid, ch);
        }
        match conn.handle_initial(now, remote, ecn, packet_number as u64, packet, rest) {
            Ok(()) => {
                trace!(self.log, "connection incoming; ICID {icid}", icid = dst_cid);
                self.incoming_handshakes += 1;
                if conn.has_1rtt() {
                    if let Some(event) = self.handle_event(ch, EndpointEvent::NeedIdentifiers) {
                        conn.handle_event(event);
                    }
                }
                Some((ch, conn))
            }
            Err(e) => {
                debug!(self.log, "handshake failed"; "reason" => %e);
                self.handle_event(ch, EndpointEvent::Closed { remote });
                self.transmits.push_back(Transmit {
                    destination: remote,
                    ecn: None,
                    packet: initial_close(crypto, header_crypto, &src_cid, &temp_loc_cid, 0, e),
                });
                None
            }
        }
    }

    /// Free a handshake slot for reuse
    ///
    /// Every time an [`Event::Handshaking`] is emitted, a slot is consumed, up to a limit of
    /// [`ServerConfig.accept_buffer`]. Calling this indicates the application's acceptance of that
    /// connection and releases the slot for reuse.
    pub fn accept(&mut self) {
        self.incoming_handshakes -= 1;
    }
}

pub(crate) struct ConnectionMeta {
    init_cid: ConnectionId,
    /// Number of local connection IDs that have been issued in NEW_CONNECTION_ID frames.
    cids_issued: u64,
    loc_cids: HashMap<u64, ConnectionId>,
}

/// Parameters governing the core QUIC state machine
///
/// This should be tuned to suit the application. In particular, window sizes for streams, stream
/// data, and overall connection data should be set differently depending on the expected round trip
/// time, link capacity, memory availability, and rate of stream creation. Tuning for higher
/// bandwidths and latencies increases worst-case memory consumption, but does not impair
/// performance at lower bandwidths and latencies. The default configuration is tuned for a 100Mbps
/// link with a 100ms round trip time, with remote endpoints opening at most 320 new streams per
/// second. Applications which do not require remotely-initiated streams should set the stream
/// windows to zero.
pub struct TransportConfig {
    /// Maximum number of bidirectional streams that may be initiated by the peer but not yet
    /// accepted locally
    ///
    /// Must be nonzero for the peer to open any bidirectional streams.
    ///
    /// Any number of streams may be in flight concurrently. However, to ensure predictable resource
    /// use, the number of streams which the peer has initiated but which the local application has
    /// not yet accepted will be kept below this threshold.
    ///
    /// Because it takes at least one round trip for an endpoint to open a new stream and be
    /// notified of its peer's flow control updates, this imposes a hard upper bound on the number
    /// of streams that may be opened per round-trip. In other words, this should be set to at least
    /// the desired number of streams opened per unit time, multiplied by the round trip time.
    ///
    /// Note that worst-case memory use is directly proportional to `stream_window_bidi *
    /// stream_receive_window`, with an upper bound proportional to `receive_window`.
    pub stream_window_bidi: u64,
    /// Variant of `stream_window_bidi` affecting unidirectional streams
    pub stream_window_uni: u64,
    /// Maximum duration of inactivity to accept before timing out the connection (s).
    ///
    /// The actual value used is the minimum of this and the peer's own idle timeout. 0 for none.
    pub idle_timeout: u64,
    /// Maximum number of bytes the peer may transmit without acknowledgement on any one stream
    /// before becoming blocked.
    ///
    /// This should be set to at least the expected connection latency multiplied by the maximum
    /// desired throughput. Setting this smaller than `receive_window` helps ensure that a single
    /// stream doesn't monopolize receive buffers, which may otherwise occur if the application
    /// chooses not to read from a large stream for a time while still requiring data on other
    /// streams.
    pub stream_receive_window: u64,
    /// Maximum number of bytes the peer may transmit across all streams of a connection before
    /// becoming blocked.
    ///
    /// This should be set to at least the expected connection latency multiplied by the maximum
    /// desired throughput. Larger values can be useful to allow maximum throughput within a
    /// stream while another is blocked.
    pub receive_window: u64,
    /// Maximum number of bytes to transmit to a peer without acknowledgment
    ///
    /// Provides an upper bound on memory when communicating with peers that issue large amounts of
    /// flow control credit. Endpoints that wish to handle large numbers of connections robustly
    /// should take care to set this low enough to guarantee memory exhaustion does not occur if
    /// every connection uses the entire window.
    pub send_window: u64,

    /// Maximum number of tail loss probes before an RTO fires.
    pub max_tlps: u32,
    /// Maximum reordering in packet number space before FACK style loss detection considers a
    /// packet lost.
    pub packet_threshold: u32,
    /// Maximum reordering in time space before time based loss detection considers a packet lost.
    /// 0.16 format, added to 1
    pub time_threshold: u16,
    /// The length of the peer’s delayed ack timer (μs).
    pub delayed_ack_timeout: u64,
    /// The RTT used before an RTT sample is taken (μs)
    pub initial_rtt: u64,

    /// The max packet size that was used for calculating default and minimum congestion windows.
    pub max_datagram_size: u64,
    /// Default limit on the amount of outstanding data in bytes.
    ///
    /// Recommended value: `min(10 * max_datagram_size, max(2 * max_datagram_size, 14600))`
    pub initial_window: u64,
    /// Default minimum congestion window.
    ///
    /// Recommended value: `2 * max_datagram_size`.
    pub minimum_window: u64,
    /// Reduction in congestion window when a new loss event is detected. 0.16 format
    pub loss_reduction_factor: u16,
    /// Number of consecutive PTOs after which network is considered to be experiencing persistent congestion.
    pub persistent_congestion_threshold: u32,
    /// Number of seconds of inactivity before sending a keep-alive packet
    ///
    /// Keep-alive packets prevent an inactive but otherwise healthy connection from timing out.
    ///
    /// 0 to disable, which is the default. Only one side of any given connection needs keep-alive
    /// enabled for the connection to be preserved. Must be set lower than the idle_timeout of both
    /// peers to be effective.
    pub keep_alive_interval: u32,
}

impl Default for TransportConfig {
    fn default() -> Self {
        const EXPECTED_RTT: u64 = 100; // ms
        const MAX_STREAM_BANDWIDTH: u64 = 12500 * 1000; // bytes/s
                                                        // Window size needed to avoid pipeline
                                                        // stalls
        const STREAM_RWND: u64 = MAX_STREAM_BANDWIDTH / 1000 * EXPECTED_RTT;
        const MAX_DATAGRAM_SIZE: u64 = 1200;

        TransportConfig {
            stream_window_bidi: 32,
            stream_window_uni: 32,
            idle_timeout: 10,
            stream_receive_window: STREAM_RWND,
            receive_window: 8 * STREAM_RWND,
            send_window: 8 * STREAM_RWND,

            max_tlps: 2,
            packet_threshold: 3,
            time_threshold: 0x2000, // 1/8
            delayed_ack_timeout: 25 * 1000,
            initial_rtt: EXPECTED_RTT as u64 * 1000,

            max_datagram_size: MAX_DATAGRAM_SIZE,
            initial_window: cmp::min(
                10 * MAX_DATAGRAM_SIZE,
                cmp::max(2 * MAX_DATAGRAM_SIZE, 14600),
            ),
            minimum_window: 2 * MAX_DATAGRAM_SIZE,
            loss_reduction_factor: 0x8000, // 1/2
            persistent_congestion_threshold: 2,
            keep_alive_interval: 0,
        }
    }
}

impl TransportConfig {
    fn validate(&self, log: &Logger) -> Result<(), ConfigError> {
        if let Some((name, _)) = [
            ("stream_window_bidi", self.stream_window_bidi),
            ("stream_window_uni", self.stream_window_uni),
            ("receive_window", self.receive_window),
            ("stream_receive_window", self.stream_receive_window),
            ("idle_timeout", self.idle_timeout),
        ]
        .iter()
        .find(|&&(_, x)| x > varint::MAX_VALUE)
        {
            return Err(ConfigError::VarIntBounds(name));
        }
        if self.idle_timeout != 0 && self.keep_alive_interval as u64 >= self.idle_timeout {
            warn!(
                log,
                "keep-alive interval {} is ineffective due to lower idle timeout {}",
                self.keep_alive_interval,
                self.idle_timeout
            );
        }
        Ok(())
    }
}

/// Global configuration for the endpoint, affecting all connections
pub struct EndpointConfig {
    /// Length of connection IDs for the endpoint.
    ///
    /// This must be either 0 or between 4 and 18 inclusive. The length of the local connection IDs
    /// constrains the amount of simultaneous connections the endpoint can maintain. The API user is
    /// responsible for making sure that the pool is large enough to cover the intended usage.
    pub local_cid_len: usize,

    /// Private key used to send authenticated connection resets to peers who were communicating
    /// with a previous instance of this endpoint.
    ///
    /// Must be persisted across restarts to be useful.
    pub reset_key: SigningKey,
}

impl Default for EndpointConfig {
    fn default() -> Self {
        let mut reset_value = [0; 64];
        rand::thread_rng().fill_bytes(&mut reset_value);
        Self {
            local_cid_len: 8,
            reset_key: SigningKey::new(&digest::SHA512_256, &reset_value),
        }
    }
}

impl EndpointConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if (self.local_cid_len != 0 && self.local_cid_len < MIN_CID_SIZE)
            || self.local_cid_len > MAX_CID_SIZE
        {
            return Err(ConfigError::IllegalValue(
                "local_cid_len must be 0 or in [4, 18]",
            ));
        }
        Ok(())
    }
}

/// Parameters governing incoming connections.
pub struct ServerConfig {
    /// Transport configuration to use for incoming connections
    pub transport_config: Arc<TransportConfig>,

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

    /// Maximum number of incoming connections to buffer.
    ///
    /// Accepting a connection removes it from the buffer, so this does not need to be large.
    pub accept_buffer: u32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        let rng = &mut rand::thread_rng();

        let mut token_value = [0; 64];
        rng.fill_bytes(&mut token_value);

        Self {
            transport_config: Arc::new(TransportConfig::default()),
            tls_config: Arc::new(crypto::build_server_config()),

            token_key: TokenKey::new(&token_value),
            use_stateless_retry: false,
            retry_token_lifetime: 15_000_000,

            accept_buffer: 1024,
        }
    }
}

/// Errors in the configuration of an endpoint
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The supplied configuration contained an invalid value
    #[error(display = "illegal configuration value: {}", _0)]
    IllegalValue(&'static str),
    /// A configuration field that will be encoded as a variable-length integer exceeds the 0..2^62
    /// range
    #[error(display = "{} must be at most 2^62-1", _0)]
    VarIntBounds(&'static str),
}

/// Events of interest to the application
#[derive(Debug)]
pub enum Event {
    /// A connection was successfully established.
    Connected,
    /// A connection was lost.
    ///
    /// Emitted at the end of the lifetime of a connection, even if it was closed locally.
    ConnectionLost { reason: ConnectionError },
    /// One or more new streams has been opened and is readable
    StreamOpened,
    /// An existing stream has data or errors waiting to be read
    StreamReadable { stream: StreamId },
    /// A formerly write-blocked stream might now accept a write
    StreamWritable { stream: StreamId },
    /// All data sent on `stream` has been received by the peer
    StreamFinished { stream: StreamId },
    /// At least one new stream of a certain directionality may be opened
    StreamAvailable { directionality: Directionality },
}

impl From<ConnectionError> for Event {
    fn from(x: ConnectionError) -> Self {
        Event::ConnectionLost { reason: x }
    }
}

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum Timer {
    LossDetection = 0,
    Idle = 1,
    /// When the close timer expires, the connection has been gracefully terminated.
    Close = 2,
    KeyDiscard = 3,
    PathValidation = 4,
    KeepAlive = 5,
}

impl Timer {
    /// Number of types of timers that a connection may start
    pub const COUNT: usize = 6;

    pub fn iter() -> impl Iterator<Item = Self> {
        [
            Timer::LossDetection,
            Timer::Idle,
            Timer::Close,
            Timer::KeyDiscard,
            Timer::PathValidation,
            Timer::KeepAlive,
        ]
        .iter()
        .cloned()
    }
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

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct ConnectionHandle(pub usize);

impl From<ConnectionHandle> for usize {
    fn from(x: ConnectionHandle) -> usize {
        x.0
    }
}

impl Index<ConnectionHandle> for Slab<ConnectionMeta> {
    type Output = ConnectionMeta;
    fn index(&self, ch: ConnectionHandle) -> &ConnectionMeta {
        &self[ch.0]
    }
}

impl IndexMut<ConnectionHandle> for Slab<ConnectionMeta> {
    fn index_mut(&mut self, ch: ConnectionHandle) -> &mut ConnectionMeta {
        &mut self[ch.0]
    }
}

pub enum DatagramEvent {
    ConnectionEvent(ConnectionEvent),
    NewConnection(Connection),
}

enum ConnectionOpts {
    Client(ClientConfig),
    Server { orig_dst_cid: Option<ConnectionId> },
}

/// Errors in the parameters being used to create a new connection
///
/// These arise before any I/O has been performed.
#[derive(Debug, Error)]
pub enum ConnectError {
    /// The domain name supplied was malformed
    #[error(display = "invalid DNS name: {}", _0)]
    InvalidDnsName(String),
    /// The TLS configuration was invalid
    #[error(display = "TLS error: {}", _0)]
    Tls(crypto::TLSError),
    /// The transport configuration was invalid
    #[error(display = "transport configuration error: {}", _0)]
    Config(ConfigError),
}

impl From<crypto::TLSError> for ConnectError {
    fn from(x: crypto::TLSError) -> Self {
        ConnectError::Tls(x)
    }
}

impl From<ConfigError> for ConnectError {
    fn from(x: ConfigError) -> Self {
        ConnectError::Config(x)
    }
}
