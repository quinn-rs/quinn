use std::{
    collections::{hash_map, HashMap},
    convert::TryFrom,
    fmt, iter,
    net::{IpAddr, SocketAddr},
    ops::{Index, IndexMut},
    sync::{Arc, Mutex, RwLock},
    time::{Instant, SystemTime},
};

use bytes::{BufMut, Bytes, BytesMut};
use rand::{Rng, RngCore};
use rustc_hash::FxHashMap;
use slab::Slab;
use thiserror::Error;
use tracing::{debug, trace, warn};

use crate::{
    cid_generator::{ConnectionIdGenerator, RandomConnectionIdGenerator},
    coding::BufMutExt,
    config::{ClientConfig, EndpointConfig, ServerConfig},
    connection::{Connection, ConnectionError},
    crypto::{self, Keys, UnsupportedVersion},
    frame,
    packet::{Header, Packet, PacketDecodeError, PacketNumber, PartialDecode},
    shared::{ConnectionDatagram, ConnectionId, EcnCodepoint, IssuedCid},
    transport_parameters::TransportParameters,
    ResetToken, RetryToken, Side, Transmit, TransportConfig, TransportError, INITIAL_MTU,
    MAX_CID_SIZE, MIN_INITIAL_SIZE, RESET_TOKEN_SIZE,
};

/// The main entry point to the library
///
/// This object performs no I/O whatsoever. Instead, it consumes incoming packets and
/// connection-generated events via `handle` and `handle_event`.
pub struct Endpoint {
    index: RwLock<ConnectionIndex>,
    /// Must be locked after `index` when locks overlap
    connections: Mutex<Slab<ConnectionMeta>>,
    local_cid_generator: Box<dyn ConnectionIdGenerator>,
    config: Arc<EndpointConfig>,
    /// Must never be locked concurrently with other locks
    server_config: RwLock<Option<Arc<ServerConfig>>>,
    /// Whether the underlying UDP socket promises not to fragment packets
    allow_mtud: bool,
}

impl Endpoint {
    /// Create a new endpoint
    ///
    /// `allow_mtud` enables path MTU detection when requested by `Connection` configuration for
    /// better performance. This requires that outgoing packets are never fragmented, which can be
    /// achieved via e.g. the `IPV6_DONTFRAG` socket option.
    pub fn new(
        config: Arc<EndpointConfig>,
        server_config: Option<Arc<ServerConfig>>,
        allow_mtud: bool,
    ) -> Self {
        Self {
            index: RwLock::new(ConnectionIndex::default()),
            connections: Mutex::new(Slab::new()),
            local_cid_generator: (config.connection_id_generator_factory.as_ref())(),
            config,
            server_config: RwLock::new(server_config),
            allow_mtud,
        }
    }

    /// Replace the server configuration, affecting new incoming connections only
    pub fn set_server_config(&self, server_config: Option<Arc<ServerConfig>>) {
        *self.server_config.write().unwrap() = server_config;
    }

    pub(crate) fn handle_drained(&self, ch: ConnectionHandle) {
        let conn = self.connections.lock().unwrap().remove(ch.0);
        self.index.write().unwrap().remove(&conn);
    }

    pub(crate) fn set_reset_token(
        &self,
        ch: ConnectionHandle,
        remote: SocketAddr,
        token: ResetToken,
    ) {
        let old = self.connections.lock().unwrap()[ch]
            .reset_token
            .replace((remote, token));
        let mut index = self.index.write().unwrap();
        if let Some(old) = old {
            index.connection_reset_tokens.remove(old.0, old.1);
        }
        if index.connection_reset_tokens.insert(remote, token, ch) {
            warn!("duplicate reset token");
        }
    }

    pub(crate) fn retire_cid(&self, ch: ConnectionHandle, seq: u64) {
        let cid = self.connections.lock().unwrap()[ch].loc_cids.remove(&seq);
        if let Some(cid) = cid {
            trace!("peer retired CID {}: {}", seq, cid);
            self.index.write().unwrap().retire(&cid);
        }
    }

    /// Process an incoming UDP datagram
    pub fn handle(
        &self,
        now: Instant,
        remote: SocketAddr,
        local_ip: Option<IpAddr>,
        ecn: Option<EcnCodepoint>,
        data: BytesMut,
    ) -> Option<DatagramEvent> {
        let datagram_len = data.len();
        let (first_decode, remaining) = match PartialDecode::new(
            data,
            self.local_cid_generator.cid_len(),
            &self.config.supported_versions,
            self.config.grease_quic_bit,
        ) {
            Ok(x) => x,
            Err(PacketDecodeError::UnsupportedVersion {
                src_cid,
                dst_cid,
                version,
            }) => {
                if self.server_config.read().unwrap().is_none() {
                    debug!("dropping packet with unsupported version");
                    return None;
                }
                trace!("sending version negotiation");
                // Negotiate versions
                let mut buf = BytesMut::new();
                Header::VersionNegotiate {
                    random: rand::thread_rng().gen::<u8>() | 0x40,
                    src_cid: dst_cid,
                    dst_cid: src_cid,
                }
                .encode(&mut buf);
                // Grease with a reserved version
                if version != 0x0a1a_2a3a {
                    buf.write::<u32>(0x0a1a_2a3a);
                } else {
                    buf.write::<u32>(0x0a1a_2a4a);
                }
                for &version in &self.config.supported_versions {
                    buf.write(version);
                }
                return Some(DatagramEvent::Response(Transmit {
                    destination: remote,
                    ecn: None,
                    contents: buf.freeze(),
                    segment_size: None,
                    src_ip: local_ip,
                }));
            }
            Err(e) => {
                trace!("malformed header: {}", e);
                return None;
            }
        };

        //
        // Handle packet on existing connection, if any
        //

        let addresses = FourTuple { remote, local_ip };
        if let Some(ch) = self.index.read().unwrap().get(&addresses, &first_decode) {
            return Some(DatagramEvent::ConnectionEvent(
                ch,
                ConnectionDatagram {
                    now,
                    remote: addresses.remote,
                    ecn,
                    first_decode,
                    remaining,
                },
            ));
        }

        //
        // Potentially create a new connection
        //

        let dst_cid = first_decode.dst_cid();
        let server_config = match &*self.server_config.read().unwrap() {
            Some(config) => config.clone(),
            None => {
                debug!("packet for unrecognized connection {}", dst_cid);
                return self
                    .stateless_reset(datagram_len, addresses, dst_cid)
                    .map(DatagramEvent::Response);
            }
        };

        if let Some(version) = first_decode.initial_version() {
            if datagram_len < MIN_INITIAL_SIZE as usize {
                debug!("ignoring short initial for connection {}", dst_cid);
                return None;
            }

            let crypto = match server_config
                .crypto
                .initial_keys(version, dst_cid, Side::Server)
            {
                Ok(keys) => keys,
                Err(UnsupportedVersion) => {
                    // This probably indicates that the user set supported_versions incorrectly in
                    // `EndpointConfig`.
                    debug!(
                        "ignoring initial packet version {:#x} unsupported by cryptographic layer",
                        version
                    );
                    return None;
                }
            };
            return match first_decode.finish(Some(&*crypto.header.remote)) {
                Ok(packet) => {
                    self.handle_first_packet(now, addresses, ecn, packet, remaining, &crypto)
                }
                Err(e) => {
                    trace!("unable to decode initial packet: {}", e);
                    None
                }
            };
        } else if first_decode.has_long_header() {
            debug!(
                "ignoring non-initial packet for unknown connection {}",
                dst_cid
            );
            return None;
        }

        //
        // If we got this far, we're a server receiving a seemingly valid packet for an unknown
        // connection. Send a stateless reset if possible.
        //
        if !dst_cid.is_empty() {
            return self
                .stateless_reset(datagram_len, addresses, dst_cid)
                .map(DatagramEvent::Response);
        }

        trace!("dropping unrecognized short packet without ID");
        None
    }

    fn stateless_reset(
        &self,
        inciting_dgram_len: usize,
        addresses: FourTuple,
        dst_cid: &ConnectionId,
    ) -> Option<Transmit> {
        /// Minimum amount of padding for the stateless reset to look like a short-header packet
        const MIN_PADDING_LEN: usize = 5;

        // Prevent amplification attacks and reset loops by ensuring we pad to at most 1 byte
        // smaller than the inciting packet.
        let max_padding_len = match inciting_dgram_len.checked_sub(RESET_TOKEN_SIZE) {
            Some(headroom) if headroom > MIN_PADDING_LEN => headroom - 1,
            _ => {
                debug!("ignoring unexpected {} byte packet: not larger than minimum stateless reset size", inciting_dgram_len);
                return None;
            }
        };

        debug!(
            "sending stateless reset for {} to {}",
            dst_cid, addresses.remote
        );
        let mut buf = BytesMut::new();
        // Resets with at least this much padding can't possibly be distinguished from real packets
        const IDEAL_MIN_PADDING_LEN: usize = MIN_PADDING_LEN + MAX_CID_SIZE;
        let padding_len = if max_padding_len <= IDEAL_MIN_PADDING_LEN {
            max_padding_len
        } else {
            rand::thread_rng().gen_range(IDEAL_MIN_PADDING_LEN..max_padding_len)
        };
        buf.reserve(padding_len + RESET_TOKEN_SIZE);
        buf.resize(padding_len, 0);
        rand::thread_rng().fill_bytes(&mut buf[0..padding_len]);
        buf[0] = 0b0100_0000 | buf[0] >> 2;
        buf.extend_from_slice(&ResetToken::new(&*self.config.reset_key, dst_cid));

        debug_assert!(buf.len() < inciting_dgram_len);

        Some(Transmit {
            destination: addresses.remote,
            ecn: None,
            contents: buf.freeze(),
            segment_size: None,
            src_ip: addresses.local_ip,
        })
    }

    /// Initiate a connection
    pub fn connect(
        &self,
        config: ClientConfig,
        remote: SocketAddr,
        server_name: &str,
    ) -> Result<(ConnectionHandle, Connection), ConnectError> {
        if self.is_full() {
            return Err(ConnectError::TooManyConnections);
        }
        if remote.port() == 0 || remote.ip().is_unspecified() {
            return Err(ConnectError::InvalidRemoteAddress(remote));
        }
        if !self.config.supported_versions.contains(&config.version) {
            return Err(ConnectError::UnsupportedVersion);
        }

        let remote_id = RandomConnectionIdGenerator::new(MAX_CID_SIZE).generate_cid();
        trace!(initial_dcid = %remote_id);

        let mut index = self.index.write().unwrap();
        let mut connections = self.connections.lock().unwrap();
        let ch = ConnectionHandle(connections.vacant_key());
        let loc_cid = new_cid(&*self.local_cid_generator, &mut index, ch);
        let params = TransportParameters::new(
            &config.transport,
            &self.config,
            self.local_cid_generator.as_ref(),
            loc_cid,
            None,
        );
        let tls = config
            .crypto
            .start_session(config.version, server_name, &params)?;

        let addresses = FourTuple {
            remote,
            local_ip: None,
        };
        let (meta, conn) = self.make_connection(
            ch,
            config.version,
            remote_id,
            loc_cid,
            remote_id,
            addresses,
            Instant::now(),
            tls,
            None,
            config.transport,
        );
        connections.insert(meta);
        index.insert_conn(addresses, loc_cid, ch);
        Ok((ch, conn))
    }

    pub(crate) fn alloc_new_identifiers(&self, ch: ConnectionHandle, num: u64) -> Vec<IssuedCid> {
        let mut ids = Vec::with_capacity(num as usize);
        let mut index = self.index.write().unwrap();
        let mut connections = self.connections.lock().unwrap();
        for _ in 0..num {
            let id = new_cid(&*self.local_cid_generator, &mut index, ch);
            let meta = &mut connections[ch];
            meta.cids_issued += 1;
            let sequence = meta.cids_issued;
            meta.loc_cids.insert(sequence, id);
            ids.push(IssuedCid {
                sequence,
                id,
                reset_token: ResetToken::new(&*self.config.reset_key, &id),
            });
        }
        ids
    }

    fn handle_first_packet(
        &self,
        now: Instant,
        addresses: FourTuple,
        ecn: Option<EcnCodepoint>,
        mut packet: Packet,
        rest: Option<BytesMut>,
        crypto: &Keys,
    ) -> Option<DatagramEvent> {
        let (src_cid, dst_cid, token, packet_number, version) = match packet.header {
            Header::Initial {
                src_cid,
                dst_cid,
                ref token,
                number,
                version,
                ..
            } => (src_cid, dst_cid, token.clone(), number, version),
            _ => panic!("non-initial packet in handle_first_packet()"),
        };
        let packet_number = packet_number.expand(0);

        if crypto
            .packet
            .remote
            .decrypt(packet_number, &packet.header_data, &mut packet.payload)
            .is_err()
        {
            debug!(packet_number, "failed to authenticate initial packet");
            return None;
        };

        if !packet.reserved_bits_valid() {
            debug!("dropping connection attempt with invalid reserved bits");
            return None;
        }

        let server_config = self.server_config.read().unwrap().as_ref().unwrap().clone();

        if self.connections.lock().unwrap().len() >= server_config.concurrent_connections as usize
            || self.is_full()
        {
            debug!("refusing connection");
            return Some(DatagramEvent::Response(self.initial_close(
                version,
                addresses,
                crypto,
                &src_cid,
                TransportError::CONNECTION_REFUSED(""),
            )));
        }

        if dst_cid.len() < 8
            && (!server_config.use_retry || dst_cid.len() != self.local_cid_generator.cid_len())
        {
            debug!(
                "rejecting connection due to invalid DCID length {}",
                dst_cid.len()
            );
            return Some(DatagramEvent::Response(self.initial_close(
                version,
                addresses,
                crypto,
                &src_cid,
                TransportError::PROTOCOL_VIOLATION("invalid destination CID length"),
            )));
        }

        let (retry_src_cid, orig_dst_cid) = if server_config.use_retry {
            if token.is_empty() {
                // First Initial
                let mut random_bytes = vec![0u8; RetryToken::RANDOM_BYTES_LEN];
                rand::thread_rng().fill_bytes(&mut random_bytes);
                // The peer will use this as the DCID of its following Initials. Initial DCIDs are
                // looked up separately from Handshake/Data DCIDs, so there is no risk of collision
                // with established connections. In the unlikely event that a collision occurs
                // between two connections in the initial phase, both will fail fast and may be
                // retried by the application layer.
                let loc_cid = self.local_cid_generator.generate_cid();

                let token = RetryToken {
                    orig_dst_cid: dst_cid,
                    issued: SystemTime::now(),
                    random_bytes: &random_bytes,
                }
                .encode(&*server_config.token_key, &addresses.remote, &loc_cid);

                let header = Header::Retry {
                    src_cid: loc_cid,
                    dst_cid: src_cid,
                    version,
                };

                let mut buf = BytesMut::new();
                let encode = header.encode(&mut buf);
                buf.put_slice(&token);
                buf.extend_from_slice(&server_config.crypto.retry_tag(version, &dst_cid, &buf));
                encode.finish(&mut buf, &*crypto.header.local, None);

                return Some(DatagramEvent::Response(Transmit {
                    destination: addresses.remote,
                    ecn: None,
                    contents: buf.freeze(),
                    segment_size: None,
                    src_ip: addresses.local_ip,
                }));
            }

            match RetryToken::from_bytes(
                &*server_config.token_key,
                &addresses.remote,
                &dst_cid,
                &token,
            ) {
                Ok(token)
                    if token.issued + server_config.retry_token_lifetime > SystemTime::now() =>
                {
                    (Some(dst_cid), token.orig_dst_cid)
                }
                _ => {
                    debug!("rejecting invalid stateless retry token");
                    return Some(DatagramEvent::Response(self.initial_close(
                        version,
                        addresses,
                        crypto,
                        &src_cid,
                        TransportError::INVALID_TOKEN(""),
                    )));
                }
            }
        } else {
            (None, dst_cid)
        };

        let mut index = self.index.write().unwrap();
        let mut connections = self.connections.lock().unwrap();

        let ch = ConnectionHandle(connections.vacant_key());
        let loc_cid = new_cid(&*self.local_cid_generator, &mut index, ch);
        let mut params = TransportParameters::new(
            &server_config.transport,
            &self.config,
            self.local_cid_generator.as_ref(),
            loc_cid,
            Some(&server_config),
        );
        params.stateless_reset_token = Some(ResetToken::new(&*self.config.reset_key, &loc_cid));
        params.original_dst_cid = Some(orig_dst_cid);
        params.retry_src_cid = retry_src_cid;

        let tls = server_config.crypto.clone().start_session(version, &params);
        let transport_config = server_config.transport.clone();
        let (meta, mut conn) = self.make_connection(
            ch,
            version,
            dst_cid,
            loc_cid,
            src_cid,
            addresses,
            now,
            tls,
            Some(server_config),
            transport_config,
        );
        connections.insert(meta);
        index.insert_conn(addresses, loc_cid, ch);
        if dst_cid.len() != 0 {
            index.insert_initial(dst_cid, ch);
        }
        drop((connections, index));

        let result = conn.handle_first_packet(
            now,
            addresses.remote,
            ecn,
            packet_number,
            packet,
            rest,
            self,
        );
        match result {
            Ok(()) => {
                trace!(id = ch.0, icid = %dst_cid, "connection incoming");
                Some(DatagramEvent::NewConnection(ch, conn))
            }
            Err(e) => {
                debug!("handshake failed: {}", e);
                self.handle_drained(ch);
                match e {
                    ConnectionError::TransportError(e) => Some(DatagramEvent::Response(
                        self.initial_close(version, addresses, crypto, &src_cid, e),
                    )),
                    _ => None,
                }
            }
        }
    }

    fn make_connection(
        &self,
        ch: ConnectionHandle,
        version: u32,
        init_cid: ConnectionId,
        loc_cid: ConnectionId,
        rem_cid: ConnectionId,
        addresses: FourTuple,
        now: Instant,
        tls: Box<dyn crypto::Session>,
        server_config: Option<Arc<ServerConfig>>,
        transport_config: Arc<TransportConfig>,
    ) -> (ConnectionMeta, Connection) {
        let conn = Connection::new(
            ch,
            self.config.clone(),
            server_config,
            transport_config,
            init_cid,
            loc_cid,
            rem_cid,
            addresses.remote,
            addresses.local_ip,
            tls,
            self.local_cid_generator.as_ref(),
            now,
            version,
            self.allow_mtud,
        );

        let meta = ConnectionMeta {
            init_cid,
            cids_issued: 0,
            loc_cids: iter::once((0, loc_cid)).collect(),
            addresses,
            reset_token: None,
        };

        (meta, conn)
    }

    fn initial_close(
        &self,
        version: u32,
        addresses: FourTuple,
        crypto: &Keys,
        remote_id: &ConnectionId,
        reason: TransportError,
    ) -> Transmit {
        // We don't need to worry about CID collisions in initial closes because the peer
        // shouldn't respond, and if it does, and the CID collides, we'll just drop the
        // unexpected response.
        let local_id = self.local_cid_generator.generate_cid();
        let number = PacketNumber::U8(0);
        let header = Header::Initial {
            dst_cid: *remote_id,
            src_cid: local_id,
            number,
            token: Bytes::new(),
            version,
        };

        let mut buf = BytesMut::new();
        let partial_encode = header.encode(&mut buf);
        let max_len =
            INITIAL_MTU as usize - partial_encode.header_len - crypto.packet.local.tag_len();
        frame::Close::from(reason).encode(&mut buf, max_len);
        buf.resize(buf.len() + crypto.packet.local.tag_len(), 0);
        partial_encode.finish(
            &mut buf,
            &*crypto.header.local,
            Some((0, &*crypto.packet.local)),
        );
        Transmit {
            destination: addresses.remote,
            ecn: None,
            contents: buf.freeze(),
            segment_size: None,
            src_ip: addresses.local_ip,
        }
    }

    /// Reject new incoming connections without affecting existing connections
    ///
    /// Convenience short-hand for using
    /// [`set_server_config`](Self::set_server_config) to update
    /// [`concurrent_connections`](ServerConfig::concurrent_connections) to
    /// zero.
    pub fn reject_new_connections(&mut self) {
        if let Some(config) = self.server_config.as_mut() {
            Arc::make_mut(config).concurrent_connections(0);
        }
    }

    /// Access the configuration used by this endpoint
    pub fn config(&self) -> &EndpointConfig {
        &self.config
    }

    #[cfg(test)]
    pub(crate) fn known_connections(&self) -> usize {
        let x = self.connections.lock().unwrap().len();
        let index = self.index.read().unwrap();
        debug_assert_eq!(x, index.connection_ids_initial.len());
        // Not all connections have known reset tokens
        debug_assert!(x >= index.connection_reset_tokens.0.len());
        // Not all connections have unique remotes, and 0-length CIDs might not be in use.
        debug_assert!(x >= index.connection_remotes.len());
        x
    }

    #[cfg(test)]
    pub(crate) fn known_cids(&self) -> usize {
        self.index.read().unwrap().connection_ids.len()
    }

    /// Whether we've used up 3/4 of the available CID space
    ///
    /// We leave some space unused so that `new_cid` can be relied upon to finish quickly. We don't
    /// bother to check when CID longer than 4 bytes are used because 2^40 connections is a lot.
    fn is_full(&self) -> bool {
        self.local_cid_generator.cid_len() <= 4
            && self.local_cid_generator.cid_len() != 0
            && (2usize.pow(self.local_cid_generator.cid_len() as u32 * 8)
                - self.index.read().unwrap().connection_ids.len())
                < 2usize.pow(self.local_cid_generator.cid_len() as u32 * 8 - 2)
    }
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("Endpoint")
            .field("index", &self.index)
            .field("connections", &self.connections)
            .field("config", &self.config)
            .field("server_config", &self.server_config)
            .finish()
    }
}

// Standalone method for use with split borrows of `Endpoint`
/// Generate a connection ID for `ch` if specified
fn new_cid(
    generator: &dyn ConnectionIdGenerator,
    index: &mut ConnectionIndex,
    ch: ConnectionHandle,
) -> ConnectionId {
    loop {
        let cid = generator.generate_cid();
        if let hash_map::Entry::Vacant(e) = index.connection_ids.entry(cid) {
            e.insert(ch);
            break cid;
        }
        assert!(generator.cid_len() > 0);
    }
}

/// Maps packets to existing connections
#[derive(Default, Debug)]
struct ConnectionIndex {
    /// Identifies connections based on the initial DCID the peer utilized
    ///
    /// Uses a standard `HashMap` to protect against hash collision attacks.
    connection_ids_initial: HashMap<ConnectionId, ConnectionHandle>,
    /// Identifies connections based on locally created CIDs
    ///
    /// Uses a cheaper hash function since keys are locally created
    connection_ids: FxHashMap<ConnectionId, ConnectionHandle>,
    /// Identifies connections with zero-length CIDs
    ///
    /// Uses a standard `HashMap` to protect against hash collision attacks.
    connection_remotes: HashMap<FourTuple, ConnectionHandle>,
    /// Reset tokens provided by the peer for the CID each connection is currently sending to
    ///
    /// Incoming stateless resets do not have correct CIDs, so we need this to identify the correct
    /// recipient, if any.
    connection_reset_tokens: ResetTokenTable,
}

impl ConnectionIndex {
    /// Associate a connection with its initial destination CID
    fn insert_initial(&mut self, dst_cid: ConnectionId, connection: ConnectionHandle) {
        self.connection_ids_initial.insert(dst_cid, connection);
    }

    /// Associate a connection with its first locally-chosen destination CID if used, or otherwise
    /// its current 4-tuple
    fn insert_conn(
        &mut self,
        addresses: FourTuple,
        dst_cid: ConnectionId,
        connection: ConnectionHandle,
    ) {
        match dst_cid.len() {
            0 => {
                self.connection_remotes.insert(addresses, connection);
            }
            _ => {
                self.connection_ids.insert(dst_cid, connection);
            }
        }
    }

    /// Discard a connection ID
    fn retire(&mut self, dst_cid: &ConnectionId) {
        self.connection_ids.remove(dst_cid);
    }

    /// Remove all references to a connection
    fn remove(&mut self, conn: &ConnectionMeta) {
        if conn.init_cid.len() > 0 {
            self.connection_ids_initial.remove(&conn.init_cid);
        }
        for cid in conn.loc_cids.values() {
            self.connection_ids.remove(cid);
        }
        self.connection_remotes.remove(&conn.addresses);
        if let Some((remote, token)) = conn.reset_token {
            self.connection_reset_tokens.remove(remote, token);
        }
    }

    /// Find the existing connection that `datagram` should be routed to, if any
    fn get(&self, addresses: &FourTuple, datagram: &PartialDecode) -> Option<ConnectionHandle> {
        if datagram.dst_cid().len() != 0 {
            if let Some(&ch) = self.connection_ids.get(datagram.dst_cid()) {
                return Some(ch);
            }
        }
        if datagram.is_initial() || datagram.is_0rtt() {
            if let Some(&ch) = self.connection_ids_initial.get(datagram.dst_cid()) {
                return Some(ch);
            }
        }
        if datagram.dst_cid().len() == 0 {
            if let Some(&ch) = self.connection_remotes.get(addresses) {
                return Some(ch);
            }
        }
        let data = datagram.data();
        if data.len() < RESET_TOKEN_SIZE {
            return None;
        }
        self.connection_reset_tokens
            .get(addresses.remote, &data[data.len() - RESET_TOKEN_SIZE..])
            .cloned()
    }
}

#[derive(Debug)]
pub(crate) struct ConnectionMeta {
    init_cid: ConnectionId,
    /// Number of local connection IDs that have been issued in NEW_CONNECTION_ID frames.
    cids_issued: u64,
    loc_cids: FxHashMap<u64, ConnectionId>,
    /// Remote/local addresses the connection began with
    ///
    /// Only needed to support connections with zero-length CIDs, which cannot migrate, so we don't
    /// bother keeping it up to date.
    addresses: FourTuple,
    /// Reset token provided by the peer for the CID we're currently sending to, and the address
    /// being sent to
    reset_token: Option<(SocketAddr, ResetToken)>,
}

/// Internal identifier for a `Connection` currently associated with an endpoint
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct ConnectionHandle(pub usize);

impl From<ConnectionHandle> for usize {
    fn from(x: ConnectionHandle) -> Self {
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
#[allow(clippy::large_enum_variant)] // Not passed around extensively
pub enum DatagramEvent {
    /// The datagram is redirected to its `Connection`
    ConnectionEvent(ConnectionHandle, ConnectionDatagram),
    /// The datagram has resulted in starting a new `Connection`
    NewConnection(ConnectionHandle, Connection),
    /// Response generated directly by the endpoint
    Response(Transmit),
}

/// Errors in the parameters being used to create a new connection
///
/// These arise before any I/O has been performed.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConnectError {
    /// The endpoint can no longer create new connections
    ///
    /// Indicates that a necessary component of the endpoint has been dropped or otherwise disabled.
    #[error("endpoint stopping")]
    EndpointStopping,
    /// The number of active connections on the local endpoint is at the limit
    ///
    /// Try using longer connection IDs.
    #[error("too many connections")]
    TooManyConnections,
    /// The domain name supplied was malformed
    #[error("invalid DNS name: {0}")]
    InvalidDnsName(String),
    /// The remote [`SocketAddr`] supplied was malformed
    ///
    /// Examples include attempting to connect to port 0, or using an inappropriate address family.
    #[error("invalid remote address: {0}")]
    InvalidRemoteAddress(SocketAddr),
    /// No default client configuration was set up
    ///
    /// Use `Endpoint::connect_with` to specify a client configuration.
    #[error("no default client config")]
    NoDefaultClientConfig,
    /// The local endpoint does not support the QUIC version specified in the client configuration
    #[error("unsupported QUIC version")]
    UnsupportedVersion,
}

/// Reset Tokens which are associated with peer socket addresses
///
/// The standard `HashMap` is used since both `SocketAddr` and `ResetToken` are
/// peer generated and might be usable for hash collision attacks.
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

/// Identifies a connection by the combination of remote and local addresses
///
/// Including the local ensures good behavior when the host has multiple IP addresses on the same
/// subnet and zero-length connection IDs are in use.
#[derive(Hash, Eq, PartialEq, Debug, Copy, Clone)]
struct FourTuple {
    remote: SocketAddr,
    // A single socket can only listen on a single port, so no need to store it explicitly
    local_ip: Option<IpAddr>,
}
