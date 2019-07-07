use std::collections::{HashMap, VecDeque};
use std::iter;
use std::net::SocketAddr;
use std::ops::{Index, IndexMut};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use bytes::{BufMut, BytesMut};
use err_derive::Error;
use fnv::FnvHashMap;
use rand::{rngs::OsRng, Rng, RngCore};
use slab::Slab;
use slog::{self, Logger};

use crate::coding::BufMutExt;
use crate::connection::{initial_close, Connection};
use crate::crypto::{
    self, ClientConfig as ClientCryptoConfig, HmacKey, Keys, ServerConfig as ServerCryptoConfig,
};
use crate::frame::NewConnectionId;
use crate::packet::{Header, Packet, PacketDecodeError, PartialDecode};
use crate::shared::{
    ClientConfig, ClientOpts, ConfigError, ConnectionEvent, ConnectionEventInner, ConnectionId,
    EcnCodepoint, EndpointConfig, EndpointEvent, EndpointEventInner, ResetToken, ServerConfig,
};
use crate::transport_parameters::TransportParameters;
use crate::{
    Side, Transmit, TransportError, LOC_CID_COUNT, MAX_CID_SIZE, MIN_INITIAL_SIZE,
    RESET_TOKEN_SIZE, VERSION,
};

/// The main entry point to the library
///
/// This object performs no I/O whatsoever. Instead, it generates a stream of packets to send via
/// `poll_transmit`, and consumes incoming packets and connection-generated events via `handle` and
/// `handle_event`.
pub struct Endpoint<S>
where
    S: crypto::Session,
{
    log: Logger,
    rng: OsRng,
    transmits: VecDeque<Transmit>,
    connection_ids_initial: FnvHashMap<ConnectionId, ConnectionHandle>,
    connection_ids: FnvHashMap<ConnectionId, ConnectionHandle>,
    /// Identifies connections with zero-length CIDs
    connection_remotes: FnvHashMap<SocketAddr, ConnectionHandle>,
    /// Reset tokens provided by the peer for the CID each connection is currently sending to
    ///
    /// Incoming stateless resets do not have correct CIDs, so we need this to identify the correct
    /// recipient, if any.
    connection_reset_tokens: HashMap<ResetToken, ConnectionHandle>,
    connections: Slab<ConnectionMeta>,
    config: Arc<EndpointConfig>,
    server_config: Option<Arc<ServerConfig<S>>>,
    incoming_handshakes: usize,
    /// Whether incoming connections should be unconditionally rejected by a server
    ///
    /// Equivalent to a `ServerConfig.accept_buffer` of `0`, but can be changed after the endpoint is constructed.
    reject_new_connections: bool,
    reset_key: S::HmacKey,
    token_key: Option<S::HmacKey>, // only available when server_config.is_some()
}

impl<S> Endpoint<S>
where
    S: crypto::Session,
{
    /// Create a new endpoint
    ///
    /// Returns `Err` if the configuration is invalid.
    pub fn new(
        log: Logger,
        config: Arc<EndpointConfig>,
        server_config: Option<Arc<ServerConfig<S>>>,
    ) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self {
            log,
            rng: OsRng,
            transmits: VecDeque::new(),
            connection_ids_initial: FnvHashMap::default(),
            connection_ids: FnvHashMap::default(),
            connection_remotes: FnvHashMap::default(),
            connection_reset_tokens: HashMap::new(),
            connections: Slab::new(),
            incoming_handshakes: 0,
            reject_new_connections: false,
            reset_key: S::HmacKey::new(&config.reset_key)?,
            token_key: server_config
                .as_ref()
                .map(|c| S::HmacKey::new(&c.token_key))
                .transpose()?,
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

    /// Process `EndpointEvent`s emitted from related `Connection`s
    ///
    /// In turn, processing this event may return a `ConnectionEvent` for the same `Connection`.
    pub fn handle_event(
        &mut self,
        ch: ConnectionHandle,
        event: EndpointEvent,
    ) -> Option<ConnectionEvent> {
        use EndpointEventInner::*;
        match event.0 {
            NeedIdentifiers(max) => {
                if self.config.local_cid_len != 0 {
                    // We've already issued one CID as part of the normal handshake process.
                    return Some(
                        self.send_new_identifiers(ch, max.min(LOC_CID_COUNT - 1) as usize),
                    );
                }
            }
            ResetToken(token) => {
                if let Some(old) = self.connections[ch].reset_token.replace(token) {
                    self.connection_reset_tokens.remove(&old).unwrap();
                }
                self.connection_reset_tokens.insert(token, ch);
            }
            RetireConnectionId(seq) => {
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
            Drained => {
                let conn = self.connections.remove(ch.0);
                if conn.init_cid.len() > 0 {
                    self.connection_ids_initial.remove(&conn.init_cid);
                }
                for cid in conn.loc_cids.values() {
                    self.connection_ids.remove(&cid);
                }
                self.connection_remotes.remove(&conn.initial_remote);
                if let Some(token) = conn.reset_token {
                    self.connection_reset_tokens.remove(&token).unwrap();
                }
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
    ) -> Option<(ConnectionHandle, DatagramEvent<S>)> {
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
                    random: self.rng.gen::<u8>() | 0x40,
                    src_cid: destination,
                    dst_cid: source,
                }
                .encode(&mut buf);
                buf.write::<u32>(0x0a1a_2a3a); // reserved version
                buf.write(VERSION); // supported version
                self.transmits.push_back(Transmit {
                    destination: remote,
                    ecn: None,
                    contents: buf.into(),
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
                    if self.config.local_cid_len == 0 {
                        self.connection_remotes.get(&remote)
                    } else {
                        None
                    }
                })
                .or_else(|| {
                    let data = first_decode.data();
                    if data.len() >= RESET_TOKEN_SIZE {
                        self.connection_reset_tokens
                            .get(&data[data.len() - RESET_TOKEN_SIZE..])
                    } else {
                        None
                    }
                })
                .cloned()
        };
        if let Some(ch) = known_ch {
            return Some((
                ch,
                DatagramEvent::ConnectionEvent(ConnectionEvent(ConnectionEventInner::Datagram {
                    now,
                    remote,
                    ecn,
                    first_decode,
                    remaining,
                })),
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

                let crypto = S::Keys::new_initial(&dst_cid, Side::Server);
                let header_crypto = crypto.header_keys();
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
        buf.extend_from_slice(&reset_token_for(&self.reset_key, dst_cid));

        debug_assert!(buf.len() < inciting_dgram_len);

        self.transmits.push_back(Transmit {
            destination: remote,
            ecn: None,
            contents: buf.into(),
        });
    }

    /// Initiate a connection
    pub fn connect(
        &mut self,
        config: ClientConfig<S::ClientConfig>,
        remote: SocketAddr,
        server_name: &str,
    ) -> Result<(ConnectionHandle, Connection<S>), ConnectError> {
        config.transport.validate(&self.log)?;
        let remote_id = ConnectionId::random(&mut self.rng, MAX_CID_SIZE);
        trace!(self.log, "initial dcid"; "value" => %remote_id);
        let (ch, conn) = self.add_connection(
            remote_id,
            remote_id,
            remote,
            ConnectionOpts::Client {
                config,
                server_name: server_name.into(),
            },
            Instant::now(),
        )?;
        Ok((ch, conn))
    }

    fn send_new_identifiers(&mut self, ch: ConnectionHandle, num: usize) -> ConnectionEvent {
        let mut ids = vec![];
        for _ in 0..num {
            let id = self.new_cid();
            self.connection_ids.insert(id, ch);
            let meta = &mut self.connections[ch];
            meta.cids_issued += 1;
            let sequence = meta.cids_issued;
            meta.loc_cids.insert(sequence, id);
            ids.push(NewConnectionId {
                sequence,
                id,
                reset_token: reset_token_for(&self.reset_key, &id),
            });
        }
        ConnectionEvent(ConnectionEventInner::NewIdentifiers(ids))
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
        opts: ConnectionOpts<S::ClientConfig>,
        now: Instant,
    ) -> Result<(ConnectionHandle, Connection<S>), ConnectError> {
        let loc_cid = self.new_cid();
        let (tls, client_opts, transport_config, log) = match opts {
            ConnectionOpts::Client {
                config,
                server_name,
            } => {
                let params = TransportParameters::new::<S>(&config.transport, None);
                (
                    config.crypto.start_session(&server_name, &params)?,
                    Some(ClientOpts {
                        crypto: config.crypto,
                        server_name,
                    }),
                    config.transport,
                    config
                        .log
                        .unwrap_or_else(|| self.log.new(o!("connection" => loc_cid))),
                )
            }
            ConnectionOpts::Server { orig_dst_cid } => {
                let config = self.server_config.as_ref().unwrap();
                let params = TransportParameters::new(&config.transport, Some(config));
                let server_params = TransportParameters {
                    stateless_reset_token: Some(reset_token_for(&self.reset_key, &loc_cid)),
                    original_connection_id: orig_dst_cid,
                    ..params
                };
                (
                    config.crypto.start_session(&server_params),
                    None,
                    config.transport.clone(),
                    self.log.new(o!("connection" => loc_cid)),
                )
            }
        };

        let remote_validated = self.server_config.as_ref().map_or(false, |cfg| {
            cfg.use_stateless_retry && client_opts.is_none()
        });
        let conn = Connection::new(
            log,
            Arc::clone(&self.config),
            self.server_config.as_ref().map(Arc::clone),
            transport_config,
            init_cid,
            loc_cid,
            rem_cid,
            remote,
            client_opts,
            tls,
            now,
            remote_validated,
        );
        let id = self.connections.insert(ConnectionMeta {
            init_cid,
            cids_issued: 0,
            loc_cids: iter::once((0, loc_cid)).collect(),
            initial_remote: remote,
            reset_token: None,
        });
        let ch = ConnectionHandle(id);

        if self.config.local_cid_len > 0 {
            self.connection_ids.insert(loc_cid, ch);
        } else {
            self.connection_remotes.insert(remote, ch);
        }
        Ok((ch, conn))
    }

    fn handle_initial(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        ecn: Option<EcnCodepoint>,
        mut packet: Packet,
        rest: Option<BytesMut>,
        crypto: &S::Keys,
        header_crypto: &<S::Keys as Keys>::HeaderKeys,
    ) -> Option<(ConnectionHandle, Connection<S>)> {
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

        if self.incoming_handshakes == server_config.accept_buffer as usize
            || self.reject_new_connections
        {
            debug!(self.log, "rejecting connection due to full accept buffer");
            self.transmits.push_back(Transmit {
                destination: remote,
                ecn: None,
                contents: initial_close(
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
                contents: initial_close(
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
                token::check(self.token_key.as_ref().unwrap(), &remote, &token)
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
                let token = token::generate(
                    self.token_key.as_ref().unwrap(),
                    &remote,
                    &dst_cid,
                    SystemTime::now(),
                );
                let mut buf = Vec::new();
                let header = Header::Retry {
                    src_cid: temp_loc_cid,
                    dst_cid: src_cid,
                    orig_dst_cid: dst_cid,
                };
                let encode = header.encode(&mut buf);
                encode.finish::<S::Keys, <S::Keys as Keys>::HeaderKeys>(
                    &mut buf,
                    header_crypto,
                    None,
                );
                buf.put_slice(&token);

                self.transmits.push_back(Transmit {
                    destination: remote,
                    ecn: None,
                    contents: buf.into(),
                });
                return None;
            }
        }

        let (ch, mut conn) = self
            .add_connection(
                dst_cid,
                src_cid,
                remote,
                ConnectionOpts::Server {
                    orig_dst_cid: retry_cid,
                },
                now,
            )
            .unwrap();
        if dst_cid.len() != 0 {
            self.connection_ids_initial.insert(dst_cid, ch);
        }
        match conn.handle_initial(now, remote, ecn, packet_number as u64, packet, rest) {
            Ok(()) => {
                trace!(self.log, "connection incoming; ICID {icid}", icid = dst_cid);
                self.incoming_handshakes += 1;
                Some((ch, conn))
            }
            Err(e) => {
                debug!(self.log, "handshake failed"; "reason" => %e);
                self.handle_event(ch, EndpointEvent(EndpointEventInner::Drained));
                self.transmits.push_back(Transmit {
                    destination: remote,
                    ecn: None,
                    contents: initial_close(crypto, header_crypto, &src_cid, &temp_loc_cid, 0, e),
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

    /// Unconditionally reject future incoming connections
    pub fn reject_new_connections(&mut self) {
        self.reject_new_connections = true;
    }

    #[cfg(all(test, feature = "rustls"))]
    pub(crate) fn known_connections(&self) -> usize {
        let x = self.connections.len();
        debug_assert_eq!(x, self.connection_ids_initial.len());
        // Not all connections have known reset tokens
        debug_assert!(x >= self.connection_reset_tokens.len());
        // Not all connections have unique remotes, and 0-length CIDs might not be in use.
        debug_assert!(x >= self.connection_remotes.len());
        x
    }

    #[cfg(all(test, feature = "rustls"))]
    pub(crate) fn known_cids(&self) -> usize {
        self.connection_ids.len()
    }
}

pub(crate) struct ConnectionMeta {
    init_cid: ConnectionId,
    /// Number of local connection IDs that have been issued in NEW_CONNECTION_ID frames.
    cids_issued: u64,
    loc_cids: HashMap<u64, ConnectionId>,
    /// Remote address the connection began with
    ///
    /// Only needed to support connections with zero-length CIDs, which cannot migrate, so we don't
    /// bother keeping it up to date.
    initial_remote: SocketAddr,
    /// Reset token provided by the peer for the CID we're currently sending to
    reset_token: Option<ResetToken>,
}

fn reset_token_for<H>(key: &H, id: &ConnectionId) -> ResetToken
where
    H: crypto::HmacKey,
{
    let signature = key.sign(id);
    // TODO: Server ID??
    let mut result = [0; RESET_TOKEN_SIZE];
    result.copy_from_slice(&signature.as_ref()[..RESET_TOKEN_SIZE]);
    result.into()
}

mod token {
    use std::io;
    use std::net::{IpAddr, SocketAddr};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use bytes::{Buf, BufMut};

    use crate::coding::{BufExt, BufMutExt};
    use crate::crypto::HmacKey;
    use crate::shared::ConnectionId;
    use crate::{MAX_CID_SIZE, MIN_CID_SIZE};

    // TODO: Use AEAD to hide token details from clients for better stability guarantees:
    // - ticket consists of (random, aead-encrypted-data)
    // - AEAD encryption key is HKDF(master-key, random)
    // - AEAD nonce is always set to 0
    // in other words, for each ticket, use different key derived from random using HKDF

    pub fn generate<K>(
        key: &K,
        address: &SocketAddr,
        dst_cid: &ConnectionId,
        issued: SystemTime,
    ) -> Vec<u8>
    where
        K: HmacKey,
    {
        let mut buf = Vec::new();
        buf.write(dst_cid.len() as u8);
        buf.put_slice(dst_cid);
        buf.write::<u64>(
            issued
                .duration_since(UNIX_EPOCH)
                .map(|x| x.as_secs())
                .unwrap_or(0),
        );
        let signature_pos = buf.len();
        match address.ip() {
            IpAddr::V4(x) => buf.put_slice(&x.octets()),
            IpAddr::V6(x) => buf.put_slice(&x.octets()),
        }
        buf.write(address.port());
        let signature = key.sign(&buf);
        // No reason to actually encode the IP in the token, since we always have the remote addr for an incoming packet.
        buf.truncate(signature_pos);
        buf.extend_from_slice(signature.as_ref());
        buf
    }

    pub fn check<K>(
        key: &K,
        address: &SocketAddr,
        data: &[u8],
    ) -> Option<(ConnectionId, SystemTime)>
    where
        K: HmacKey,
    {
        let mut reader = io::Cursor::new(data);
        let dst_cid_len = reader.get::<u8>().ok()? as usize;
        if dst_cid_len > reader.remaining()
            || dst_cid_len != 0 && (dst_cid_len < MIN_CID_SIZE || dst_cid_len > MAX_CID_SIZE)
        {
            return None;
        }
        let dst_cid = ConnectionId::new(&data[1..=dst_cid_len]);
        reader.advance(dst_cid_len);
        let issued = UNIX_EPOCH + Duration::new(reader.get::<u64>().ok()?, 0);
        let signature_start = reader.position() as usize;

        let mut buf = Vec::new();
        buf.put_slice(&data[0..signature_start]);
        match address.ip() {
            IpAddr::V4(x) => buf.put_slice(&x.octets()),
            IpAddr::V6(x) => buf.put_slice(&x.octets()),
        }
        buf.write(address.port());

        key.verify(&buf, &data[signature_start..]).ok()?;
        Some((dst_cid, issued))
    }
}

/// Internal identifier for a `Connection` currently associated with an endpoint
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

/// Event resulting from processing a single datagram
pub enum DatagramEvent<S>
where
    S: crypto::Session,
{
    /// The datagram is redirected to its `Connection`
    ConnectionEvent(ConnectionEvent),
    /// The datagram has resulted in starting a new `Connection`
    NewConnection(Connection<S>),
}

enum ConnectionOpts<C> {
    Client {
        config: ClientConfig<C>,
        server_name: String,
    },
    Server {
        orig_dst_cid: Option<ConnectionId>,
    },
}

/// Errors in the parameters being used to create a new connection
///
/// These arise before any I/O has been performed.
#[derive(Debug, Error)]
pub enum ConnectError {
    /// The endpoint can no longer create new connections
    ///
    /// Indicates that a necessary component of the endpoint has been dropped or otherwise disabled.
    #[error(display = "endpoint stopping")]
    EndpointStopping,
    /// The domain name supplied was malformed
    #[error(display = "invalid DNS name: {}", _0)]
    InvalidDnsName(String),
    /// The transport configuration was invalid
    #[error(display = "transport configuration error: {}", _0)]
    Config(ConfigError),
}

impl From<ConfigError> for ConnectError {
    fn from(x: ConfigError) -> Self {
        ConnectError::Config(x)
    }
}

#[cfg(test)]
mod test {
    #[cfg(feature = "ring")]
    #[test]
    fn token_sanity() {
        use super::*;
        use crate::crypto::HmacKey;
        use ring::hmac::SigningKey;
        use std::net::Ipv6Addr;
        use std::time::{Duration, UNIX_EPOCH};

        let mut key = [0; 64];
        rand::thread_rng().fill_bytes(&mut key);
        let key = <SigningKey as HmacKey>::new(&key).unwrap();
        let addr = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 4433);
        let dst_cid = ConnectionId::random(&mut rand::thread_rng(), MAX_CID_SIZE);
        let issued = UNIX_EPOCH + Duration::new(42, 0); // Fractional seconds would be lost
        let token = token::generate(&key, &addr, &dst_cid, issued);
        let (dst_cid2, issued2) = token::check(&key, &addr, &token).expect("token didn't validate");
        assert_eq!(dst_cid, dst_cid2);
        assert_eq!(issued, issued2);
    }
}
