use std::{
    collections::{HashMap, VecDeque},
    convert::TryFrom,
    fmt, iter,
    net::SocketAddr,
    ops::{Index, IndexMut},
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use bytes::{BufMut, BytesMut};
use err_derive::Error;
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
use slab::Slab;
use tracing::{debug, trace, warn};

use crate::{
    coding::BufMutExt,
    config::{ClientConfig, ConfigError, EndpointConfig, ServerConfig},
    connection::{initial_close, Connection, ConnectionError},
    crypto::{self, ClientConfig as ClientCryptoConfig, Keys, ServerConfig as ServerCryptoConfig},
    packet::{Header, Packet, PacketDecodeError, PartialDecode},
    shared::{
        ConnectionEvent, ConnectionEventInner, ConnectionId, EcnCodepoint, EndpointEvent,
        EndpointEventInner, IssuedCid, ResetToken,
    },
    transport_parameters::TransportParameters,
    Side, Transmit, TransportError, MAX_CID_SIZE, MIN_INITIAL_SIZE, RESET_TOKEN_SIZE, VERSION,
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
    rng: StdRng,
    transmits: VecDeque<Transmit>,
    connection_ids_initial: HashMap<ConnectionId, ConnectionHandle>,
    connection_ids: HashMap<ConnectionId, ConnectionHandle>,
    /// Identifies connections with zero-length CIDs
    connection_remotes: HashMap<SocketAddr, ConnectionHandle>,
    /// Reset tokens provided by the peer for the CID each connection is currently sending to
    ///
    /// Incoming stateless resets do not have correct CIDs, so we need this to identify the correct
    /// recipient, if any.
    connection_reset_tokens: ResetTokenTable,
    connections: Slab<ConnectionMeta>,
    config: Arc<EndpointConfig<S>>,
    server_config: Option<Arc<ServerConfig<S>>>,
    incoming_handshakes: usize,
    /// Whether incoming connections should be unconditionally rejected by a server
    ///
    /// Equivalent to a `ServerConfig.accept_buffer` of `0`, but can be changed after the endpoint is constructed.
    reject_new_connections: bool,
}

impl<S> Endpoint<S>
where
    S: crypto::Session,
{
    /// Create a new endpoint
    ///
    /// Returns `Err` if the configuration is invalid.
    pub fn new(
        config: Arc<EndpointConfig<S>>,
        server_config: Option<Arc<ServerConfig<S>>>,
    ) -> Self {
        Self {
            rng: StdRng::from_entropy(),
            transmits: VecDeque::new(),
            connection_ids_initial: HashMap::new(),
            connection_ids: HashMap::new(),
            connection_remotes: HashMap::new(),
            connection_reset_tokens: ResetTokenTable::default(),
            connections: Slab::new(),
            incoming_handshakes: 0,
            reject_new_connections: false,
            config,
            server_config,
        }
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
            NeedIdentifiers(n) => {
                return Some(self.send_new_identifiers(ch, n));
            }
            ResetToken(remote, token) => {
                if let Some(old) = self.connections[ch].reset_token.replace((remote, token)) {
                    self.connection_reset_tokens.remove(old.0, old.1);
                }
                if self.connection_reset_tokens.insert(remote, token, ch) {
                    warn!("duplicate reset token");
                }
            }
            RetireConnectionId(seq) => {
                if let Some(cid) = self.connections[ch].loc_cids.remove(&seq) {
                    trace!("peer retired CID {}: {}", seq, cid);
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
                if let Some((remote, token)) = conn.reset_token {
                    self.connection_reset_tokens.remove(remote, token);
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
                    debug!("dropping packet with unsupported version");
                    return None;
                }
                trace!("sending version negotiation");
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
                trace!("malformed header: {}", e);
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
            ch.or_else(|| {
                if first_decode.is_initial() || first_decode.is_0rtt() {
                    self.connection_ids_initial.get(&dst_cid)
                } else {
                    None
                }
            })
            .or_else(|| {
                if self.config.local_cid_len == 0 {
                    self.connection_remotes.get(&remote)
                } else {
                    None
                }
            })
            .or_else(|| {
                let data = first_decode.data();
                if data.len() < RESET_TOKEN_SIZE {
                    return None;
                }
                self.connection_reset_tokens
                    .get(remote, &data[data.len() - RESET_TOKEN_SIZE..])
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
            debug!("packet for unrecognized connection {}", dst_cid);
            self.stateless_reset(datagram_len, remote, &dst_cid);
            return None;
        }

        if first_decode.has_long_header() {
            if !first_decode.is_initial() {
                debug!(
                    "ignoring non-initial packet for unknown connection {}",
                    dst_cid
                );
                return None;
            }
            if datagram_len < MIN_INITIAL_SIZE {
                debug!("ignoring short initial for connection {}", dst_cid);
                return None;
            }

            let crypto = S::Keys::new_initial(&dst_cid, Side::Server);
            let header_crypto = crypto.header_keys();
            return match first_decode.finish(Some(&header_crypto)) {
                Ok(packet) => self
                    .handle_first_packet(
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
                    trace!("unable to decode initial packet: {}", e);
                    None
                }
            };
        }

        //
        // If we got this far, we're a server receiving a seemingly valid packet for an unknown
        // connection. Send a stateless reset.
        //

        if !dst_cid.is_empty() {
            self.stateless_reset(datagram_len, remote, &dst_cid);
        } else {
            trace!("dropping unrecognized short packet without ID");
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
        const MIN_PADDING_LEN: usize = 5;

        // Prevent amplification attacks and reset loops by ensuring we pad to at most 1 byte
        // smaller than the inciting packet.
        let max_padding_len = match inciting_dgram_len.checked_sub(RESET_TOKEN_SIZE) {
            Some(headroom) if headroom > MIN_PADDING_LEN => headroom - 1,
            _ => {
                debug!("ignoring unexpected {} byte packet: not larger than minimum stateless reset size", inciting_dgram_len);
                return;
            }
        };

        debug!("sending stateless reset for {} to {}", dst_cid, remote);
        let mut buf = Vec::<u8>::new();
        // Resets with at least this much padding can't possibly be distinguished from real packets
        const IDEAL_MIN_PADDING_LEN: usize = MIN_PADDING_LEN + MAX_CID_SIZE;
        let padding_len = if max_padding_len <= IDEAL_MIN_PADDING_LEN {
            max_padding_len
        } else {
            self.rng.gen_range(IDEAL_MIN_PADDING_LEN, max_padding_len)
        };
        buf.reserve_exact(padding_len + RESET_TOKEN_SIZE);
        buf.resize(padding_len, 0);
        self.rng.fill_bytes(&mut buf[0..padding_len]);
        buf[0] = 0b0100_0000 | buf[0] >> 2;
        buf.extend_from_slice(&reset_token_for(&*self.config.reset_key, dst_cid));

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
        config: ClientConfig<S>,
        remote: SocketAddr,
        server_name: &str,
    ) -> Result<(ConnectionHandle, Connection<S>), ConnectError> {
        if self.is_full() {
            return Err(ConnectError::TooManyConnections);
        }
        let remote_id = ConnectionId::random(&mut self.rng, MAX_CID_SIZE);
        trace!(initial_dcid = %remote_id);
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

    fn send_new_identifiers(&mut self, ch: ConnectionHandle, num: u64) -> ConnectionEvent {
        let mut ids = vec![];
        for _ in 0..num {
            let id = self.new_cid();
            self.connection_ids.insert(id, ch);
            let meta = &mut self.connections[ch];
            meta.cids_issued += 1;
            let sequence = meta.cids_issued;
            meta.loc_cids.insert(sequence, id);
            ids.push(IssuedCid {
                sequence,
                id,
                reset_token: reset_token_for(&*self.config.reset_key, &id),
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
        opts: ConnectionOpts<S>,
        now: Instant,
    ) -> Result<(ConnectionHandle, Connection<S>), ConnectError> {
        let loc_cid = self.new_cid();
        let (server_config, tls, transport_config) = match opts {
            ConnectionOpts::Client {
                config,
                server_name,
            } => {
                let params = TransportParameters::new::<S>(&config.transport, &self.config, None);
                (
                    None,
                    config.crypto.start_session(&server_name, &params)?,
                    config.transport,
                )
            }
            ConnectionOpts::Server { orig_dst_cid } => {
                let config = self.server_config.as_ref().unwrap();
                let params =
                    TransportParameters::new(&config.transport, &self.config, Some(config));
                let server_params = TransportParameters {
                    stateless_reset_token: Some(reset_token_for(&*self.config.reset_key, &loc_cid)),
                    original_connection_id: orig_dst_cid,
                    ..params
                };
                (
                    Some(config.clone()),
                    config.crypto.start_session(&server_params),
                    config.transport.clone(),
                )
            }
        };

        let conn = Connection::new(
            Arc::clone(&self.config),
            server_config,
            transport_config,
            init_cid,
            loc_cid,
            rem_cid,
            remote,
            tls,
            now,
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

    fn handle_first_packet(
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
            _ => panic!("non-initial packet in handle_first_packet()"),
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
            debug!(packet_number, "failed to authenticate initial packet");
            return None;
        };

        if !packet.reserved_bits_valid() {
            debug!("dropping connection attempt with invalid reserved bits");
            return None;
        }

        // Local CID used for stateless packets
        let temp_loc_cid = self.new_cid();
        let server_config = self.server_config.as_ref().unwrap();

        if self.incoming_handshakes == server_config.accept_buffer as usize
            || self.reject_new_connections
            || self.is_full()
        {
            debug!("rejecting connection due to full accept buffer");
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
                "rejecting connection due to invalid DCID length {}",
                dst_cid.len()
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

        let retry_cid = if server_config.use_stateless_retry {
            if token.is_empty() {
                // First Initial
                let token = token::generate(
                    &*server_config.token_key,
                    &remote,
                    &dst_cid,
                    SystemTime::now(),
                );
                let mut buf = Vec::new();
                let header = Header::Retry {
                    src_cid: temp_loc_cid,
                    dst_cid: src_cid,
                };
                let encode = header.encode(&mut buf);
                buf.put_slice(&token);
                buf.extend_from_slice(&S::retry_tag(&dst_cid, &buf));
                encode.finish::<S::Keys, <S::Keys as Keys>::HeaderKeys>(
                    &mut buf,
                    header_crypto,
                    None,
                );

                self.transmits.push_back(Transmit {
                    destination: remote,
                    ecn: None,
                    contents: buf.into(),
                });
                return None;
            }

            match token::check(&*server_config.token_key, &remote, &token) {
                Some((cid, issued))
                    if issued
                        + Duration::from_micros(
                            self.server_config.as_ref().unwrap().retry_token_lifetime,
                        )
                        > SystemTime::now() =>
                {
                    Some(cid)
                }
                _ => {
                    debug!("rejecting invalid stateless retry token");
                    self.transmits.push_back(Transmit {
                        destination: remote,
                        ecn: None,
                        contents: initial_close(
                            crypto,
                            header_crypto,
                            &src_cid,
                            &temp_loc_cid,
                            0,
                            TransportError::INVALID_TOKEN(""),
                        ),
                    });
                    return None;
                }
            }
        } else {
            None
        };

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
        match conn.handle_first_packet(now, remote, ecn, packet_number as u64, packet, rest) {
            Ok(()) => {
                trace!(id = ch.0, icid = %dst_cid, "connection incoming");
                self.incoming_handshakes += 1;
                Some((ch, conn))
            }
            Err(e) => {
                debug!("handshake failed: {}", e);
                self.handle_event(ch, EndpointEvent(EndpointEventInner::Drained));
                if let ConnectionError::TransportError(e) = e {
                    self.transmits.push_back(Transmit {
                        destination: remote,
                        ecn: None,
                        contents: initial_close(
                            crypto,
                            header_crypto,
                            &src_cid,
                            &temp_loc_cid,
                            0,
                            e,
                        ),
                    });
                }
                None
            }
        }
    }

    /// Free a handshake slot for reuse
    ///
    /// Every time an [`DatagramEvent::NewConnection`] is yielded by `Endpoint::handle`, a slot is
    /// consumed, up to a limit of [`ServerConfig.accept_buffer`]. Calling this indicates the
    /// application's acceptance of that connection and releases the slot for reuse.
    pub fn accept(&mut self) {
        // Don't overflow if a buggy caller invokes this too many times.
        self.incoming_handshakes = self.incoming_handshakes.saturating_sub(1);
    }

    /// Unconditionally reject future incoming connections
    pub fn reject_new_connections(&mut self) {
        self.reject_new_connections = true;
    }

    #[cfg(test)]
    pub(crate) fn known_connections(&self) -> usize {
        let x = self.connections.len();
        debug_assert_eq!(x, self.connection_ids_initial.len());
        // Not all connections have known reset tokens
        debug_assert!(x >= self.connection_reset_tokens.0.len());
        // Not all connections have unique remotes, and 0-length CIDs might not be in use.
        debug_assert!(x >= self.connection_remotes.len());
        x
    }

    #[cfg(test)]
    pub(crate) fn known_cids(&self) -> usize {
        self.connection_ids.len()
    }

    /// Whether we've used up 3/4 of the available CID space
    ///
    /// We leave some space unused so that `new_cid` can be relied upon to finish quickly. We don't
    /// bother to check when CID longer than 4 bytes are used because 2^40 connections is a lot.
    fn is_full(&self) -> bool {
        self.config.local_cid_len <= 4
            && self.config.local_cid_len != 0
            && (2usize.pow(self.config.local_cid_len as u32 * 8) - self.connection_ids.len())
                < 2usize.pow(self.config.local_cid_len as u32 * 8 - 2)
    }
}

impl<S> fmt::Debug for Endpoint<S>
where
    S: crypto::Session,
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("Endpoint<T>")
            .field("rng", &self.rng)
            .field("transmits", &self.transmits)
            .field("connection_ids_initial", &self.connection_ids_initial)
            .field("connection_ids", &self.connection_ids)
            .field("connection_remotes", &self.connection_remotes)
            .field("connection_reset_tokens", &self.connection_reset_tokens)
            .field("connections", &self.connections)
            .field("config", &self.config)
            .field("server_config", &self.server_config)
            .field("incoming_handshakes", &self.incoming_handshakes)
            .field("reject_new_connections", &self.reject_new_connections)
            .finish()
    }
}

#[derive(Debug)]
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
    /// Reset token provided by the peer for the CID we're currently sending to, and the address
    /// being sent to
    reset_token: Option<(SocketAddr, ResetToken)>,
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
    use std::{
        io,
        net::{IpAddr, SocketAddr},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use bytes::{Buf, BufMut};

    use crate::{
        coding::{BufExt, BufMutExt},
        crypto::HmacKey,
        shared::ConnectionId,
        MAX_CID_SIZE,
    };

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
        if dst_cid_len > reader.remaining() || dst_cid_len > MAX_CID_SIZE {
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

enum ConnectionOpts<S: crypto::Session> {
    Client {
        config: ClientConfig<S>,
        server_name: String,
    },
    Server {
        orig_dst_cid: Option<ConnectionId>,
    },
}

/// Errors in the parameters being used to create a new connection
///
/// These arise before any I/O has been performed.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConnectError {
    /// The endpoint can no longer create new connections
    ///
    /// Indicates that a necessary component of the endpoint has been dropped or otherwise disabled.
    #[error(display = "endpoint stopping")]
    EndpointStopping,
    /// The number of active connections on the local endpoint is at the limit
    ///
    /// Try a larger `EndpointConfig::local_cid_len`.
    #[error(display = "too many connections")]
    TooManyConnections,
    /// The domain name supplied was malformed
    #[error(display = "invalid DNS name: {}", _0)]
    InvalidDnsName(String),
    /// The transport configuration was invalid
    #[error(display = "transport configuration error: {}", _0)]
    Config(#[source] ConfigError),
}

#[derive(Default, Debug)]
struct ResetTokenTable(HashMap<SocketAddr, HashMap<ResetToken, ConnectionHandle>>);

impl ResetTokenTable {
    fn insert(&mut self, remote: SocketAddr, token: ResetToken, ch: ConnectionHandle) -> bool {
        self.0
            .entry(remote)
            .or_default()
            .insert(token, ch)
            .is_some()
    }

    fn remove(&mut self, remote: SocketAddr, token: ResetToken) {
        use std::collections::hash_map::Entry;
        match self.0.entry(remote) {
            Entry::Vacant(_) => {}
            Entry::Occupied(mut e) => {
                e.get_mut().remove(&token);
                if e.get().is_empty() {
                    e.remove_entry();
                }
            }
        }
    }

    fn get(&self, remote: SocketAddr, token: &[u8]) -> Option<&ConnectionHandle> {
        let token = ResetToken::from(<[u8; RESET_TOKEN_SIZE]>::try_from(token).ok()?);
        self.0.get(&remote)?.get(&token)
    }
}

#[cfg(test)]
mod test {
    #[cfg(feature = "ring")]
    #[test]
    fn token_sanity() {
        use super::*;
        use crate::crypto::HmacKey;
        use ring::hmac;
        use std::{
            net::Ipv6Addr,
            time::{Duration, UNIX_EPOCH},
        };

        let mut key = [0; 64];
        rand::thread_rng().fill_bytes(&mut key);
        let key = <hmac::Key as HmacKey>::new(&key).unwrap();
        let addr = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 4433);
        let dst_cid = ConnectionId::random(&mut rand::thread_rng(), MAX_CID_SIZE);
        let issued = UNIX_EPOCH + Duration::new(42, 0); // Fractional seconds would be lost
        let token = token::generate(&key, &addr, &dst_cid, issued);
        let (dst_cid2, issued2) = token::check(&key, &addr, &token).expect("token didn't validate");
        assert_eq!(dst_cid, dst_cid2);
        assert_eq!(issued, issued2);
    }
}
