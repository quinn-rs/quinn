use std::{
    collections::{hash_map, HashMap},
    convert::TryFrom,
    fmt, iter,
    net::{IpAddr, SocketAddr},
    ops::{Index, IndexMut},
    sync::Arc,
    time::{Instant, SystemTime},
};

use bytes::{BufMut, Bytes, BytesMut};
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
use rustc_hash::FxHashMap;
use slab::Slab;
use thiserror::Error;
use tracing::{debug, error, trace, warn};

use crate::{
    cid_generator::{ConnectionIdGenerator, RandomConnectionIdGenerator},
    coding::BufMutExt,
    config::{ClientConfig, EndpointConfig, ServerConfig},
    connection::{Connection, ConnectionError},
    crypto::{self, Keys, UnsupportedVersion},
    frame,
    packet::{
        Header, InitialHeader, InitialPacket, Packet, PacketDecodeError, PacketNumber,
        PartialDecode, PlainInitialHeader,
    },
    shared::{
        ConnectionEvent, ConnectionEventInner, ConnectionId, EcnCodepoint, EndpointEvent,
        EndpointEventInner, IssuedCid,
    },
    transport_parameters::TransportParameters,
    ResetToken, RetryToken, Side, Transmit, TransportConfig, TransportError, INITIAL_MTU,
    MAX_CID_SIZE, MIN_INITIAL_SIZE, RESET_TOKEN_SIZE,
};

/// The main entry point to the library
///
/// This object performs no I/O whatsoever. Instead, it consumes incoming packets and
/// connection-generated events via `handle` and `handle_event`.
pub struct Endpoint {
    rng: StdRng,
    index: ConnectionIndex,
    connections: Slab<ConnectionMeta>,
    local_cid_generator: Box<dyn ConnectionIdGenerator>,
    config: Arc<EndpointConfig>,
    server_config: Option<Arc<ServerConfig>>,
    /// Whether the underlying UDP socket promises not to fragment packets
    allow_mtud: bool,
    /// Time at which a stateless reset was most recently sent
    last_stateless_reset: Option<Instant>,
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
        rng_seed: Option<[u8; 32]>,
    ) -> Self {
        Self {
            rng: rng_seed.map_or(StdRng::from_entropy(), StdRng::from_seed),
            index: ConnectionIndex::default(),
            connections: Slab::new(),
            local_cid_generator: (config.connection_id_generator_factory.as_ref())(),
            config,
            server_config,
            allow_mtud,
            last_stateless_reset: None,
        }
    }

    /// Replace the server configuration, affecting new incoming connections only
    pub fn set_server_config(&mut self, server_config: Option<Arc<ServerConfig>>) {
        self.server_config = server_config;
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
            NeedIdentifiers(now, n) => {
                return Some(self.send_new_identifiers(now, ch, n));
            }
            ResetToken(remote, token) => {
                if let Some(old) = self.connections[ch].reset_token.replace((remote, token)) {
                    self.index.connection_reset_tokens.remove(old.0, old.1);
                }
                if self.index.connection_reset_tokens.insert(remote, token, ch) {
                    warn!("duplicate reset token");
                }
            }
            RetireConnectionId(now, seq, allow_more_cids) => {
                if let Some(cid) = self.connections[ch].loc_cids.remove(&seq) {
                    trace!("peer retired CID {}: {}", seq, cid);
                    self.index.retire(&cid);
                    if allow_more_cids {
                        return Some(self.send_new_identifiers(now, ch, 1));
                    }
                }
            }
            Drained => {
                if let Some(conn) = self.connections.try_remove(ch.0) {
                    self.index.remove(&conn);
                } else {
                    // This indicates a bug in downstream code, which could cause spurious
                    // connection loss instead of this error if the CID was (re)allocated prior to
                    // the illegal call.
                    error!(id = ch.0, "unknown connection drained");
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
        local_ip: Option<IpAddr>,
        ecn: Option<EcnCodepoint>,
        data: BytesMut,
        buf: &mut BytesMut,
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
                if self.server_config.is_none() {
                    debug!("dropping packet with unsupported version");
                    return None;
                }
                trace!("sending version negotiation");
                // Negotiate versions
                Header::VersionNegotiate {
                    random: self.rng.gen::<u8>() | 0x40,
                    src_cid: dst_cid,
                    dst_cid: src_cid,
                }
                .encode(buf);
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
                    size: buf.len(),
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
        if let Some(ch) = self.index.get(&addresses, &first_decode) {
            return Some(DatagramEvent::ConnectionEvent(
                ch,
                ConnectionEvent(ConnectionEventInner::Datagram {
                    now,
                    remote: addresses.remote,
                    ecn,
                    first_decode,
                    remaining,
                }),
            ));
        }

        //
        // Potentially create a new connection
        //

        let dst_cid = first_decode.dst_cid();
        let server_config = match &self.server_config {
            Some(config) => config,
            None => {
                debug!("packet for unrecognized connection {}", dst_cid);
                return self
                    .stateless_reset(now, datagram_len, addresses, dst_cid, buf)
                    .map(DatagramEvent::Response);
            }
        };

        if let Some(header) = first_decode.initial_header() {
            if datagram_len < MIN_INITIAL_SIZE as usize {
                debug!("ignoring short initial for connection {}", dst_cid);
                return None;
            }

            let crypto =
                match server_config
                    .crypto
                    .initial_keys(header.version, dst_cid, Side::Server)
                {
                    Ok(keys) => keys,
                    Err(UnsupportedVersion) => {
                        // This probably indicates that the user set supported_versions incorrectly in
                        // `EndpointConfig`.
                        debug!(
                        "ignoring initial packet version {:#x} unsupported by cryptographic layer",
                        header.version
                    );
                        return None;
                    }
                };

            if let Err(reason) = self.early_validate_first_packet(header) {
                return Some(DatagramEvent::Response(self.initial_close(
                    header.version,
                    addresses,
                    &crypto,
                    &header.src_cid,
                    reason,
                    buf,
                )));
            }

            return match first_decode.finish(Some(&*crypto.header.remote)) {
                Ok(packet) => {
                    self.handle_first_packet(addresses, ecn, packet, remaining, crypto, buf)
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
                .stateless_reset(now, datagram_len, addresses, dst_cid, buf)
                .map(DatagramEvent::Response);
        }

        trace!("dropping unrecognized short packet without ID");
        None
    }

    fn stateless_reset(
        &mut self,
        now: Instant,
        inciting_dgram_len: usize,
        addresses: FourTuple,
        dst_cid: &ConnectionId,
        buf: &mut BytesMut,
    ) -> Option<Transmit> {
        if self
            .last_stateless_reset
            .map_or(false, |last| last + self.config.min_reset_interval > now)
        {
            debug!("ignoring unexpected packet within minimum stateless reset interval");
            return None;
        }

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
        self.last_stateless_reset = Some(now);
        // Resets with at least this much padding can't possibly be distinguished from real packets
        const IDEAL_MIN_PADDING_LEN: usize = MIN_PADDING_LEN + MAX_CID_SIZE;
        let padding_len = if max_padding_len <= IDEAL_MIN_PADDING_LEN {
            max_padding_len
        } else {
            self.rng.gen_range(IDEAL_MIN_PADDING_LEN..max_padding_len)
        };
        buf.reserve(padding_len + RESET_TOKEN_SIZE);
        buf.resize(padding_len, 0);
        self.rng.fill_bytes(&mut buf[0..padding_len]);
        buf[0] = 0b0100_0000 | buf[0] >> 2;
        buf.extend_from_slice(&ResetToken::new(&*self.config.reset_key, dst_cid));

        debug_assert!(buf.len() < inciting_dgram_len);

        Some(Transmit {
            destination: addresses.remote,
            ecn: None,
            size: buf.len(),
            segment_size: None,
            src_ip: addresses.local_ip,
        })
    }

    /// Initiate a connection
    pub fn connect(
        &mut self,
        now: Instant,
        config: ClientConfig,
        remote: SocketAddr,
        server_name: &str,
    ) -> Result<(ConnectionHandle, Connection), ConnectError> {
        if self.cids_exhausted() {
            return Err(ConnectError::CidsExhausted);
        }
        if remote.port() == 0 || remote.ip().is_unspecified() {
            return Err(ConnectError::InvalidRemoteAddress(remote));
        }
        if !self.config.supported_versions.contains(&config.version) {
            return Err(ConnectError::UnsupportedVersion);
        }

        let remote_id = RandomConnectionIdGenerator::new(MAX_CID_SIZE).generate_cid();
        trace!(initial_dcid = %remote_id);

        let ch = ConnectionHandle(self.connections.vacant_key());
        let loc_cid = self.new_cid(ch);
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

        let conn = self.add_connection(
            ch,
            config.version,
            remote_id,
            loc_cid,
            remote_id,
            FourTuple {
                remote,
                local_ip: None,
            },
            now,
            tls,
            None,
            config.transport,
            true,
        );
        Ok((ch, conn))
    }

    fn send_new_identifiers(
        &mut self,
        now: Instant,
        ch: ConnectionHandle,
        num: u64,
    ) -> ConnectionEvent {
        let mut ids = vec![];
        for _ in 0..num {
            let id = self.new_cid(ch);
            let meta = &mut self.connections[ch];
            meta.cids_issued += 1;
            let sequence = meta.cids_issued;
            meta.loc_cids.insert(sequence, id);
            ids.push(IssuedCid {
                sequence,
                id,
                reset_token: ResetToken::new(&*self.config.reset_key, &id),
            });
        }
        ConnectionEvent(ConnectionEventInner::NewIdentifiers(ids, now))
    }

    /// Generate a connection ID for `ch`
    fn new_cid(&mut self, ch: ConnectionHandle) -> ConnectionId {
        loop {
            let cid = self.local_cid_generator.generate_cid();
            if let hash_map::Entry::Vacant(e) = self.index.connection_ids.entry(cid) {
                e.insert(ch);
                break cid;
            }
            assert!(self.local_cid_generator.cid_len() > 0);
        }
    }

    fn handle_first_packet(
        &mut self,
        addresses: FourTuple,
        ecn: Option<EcnCodepoint>,
        packet: Packet,
        rest: Option<BytesMut>,
        crypto: Keys,
        buf: &mut BytesMut,
    ) -> Option<DatagramEvent> {
        if !packet.reserved_bits_valid() {
            debug!("dropping connection attempt with invalid reserved bits");
            return None;
        }

        let Header::Initial(header) = packet.header else {
            panic!("non-initial packet in handle_first_packet()");
        };

        let server_config = self.server_config.as_ref().unwrap().clone();

        let (retry_src_cid, orig_dst_cid) = if header.token.is_empty() {
            (None, header.dst_cid)
        } else {
            match RetryToken::from_bytes(
                &*server_config.token_key,
                &addresses.remote,
                &header.dst_cid,
                &header.token,
            ) {
                Ok(token)
                    if token.issued + server_config.retry_token_lifetime > SystemTime::now() =>
                {
                    (Some(header.dst_cid), token.orig_dst_cid)
                }
                _ => {
                    debug!("rejecting invalid stateless retry token");
                    return Some(DatagramEvent::Response(self.initial_close(
                        header.version,
                        addresses,
                        &crypto,
                        &header.src_cid,
                        TransportError::INVALID_TOKEN(""),
                        buf,
                    )));
                }
            }
        };

        Some(DatagramEvent::NewConnection(Incoming {
            addresses,
            ecn,
            packet: InitialPacket {
                header,
                header_data: packet.header_data,
                payload: packet.payload,
            },
            rest,
            crypto,
            retry_src_cid,
            orig_dst_cid,
        }))
    }

    /// Attempt to accept this incoming connection (an error may still occur)
    pub fn accept(
        &mut self,
        mut incoming: Incoming,
        now: Instant,
        buf: &mut BytesMut,
    ) -> Result<(ConnectionHandle, Connection), AcceptError> {
        let packet_number = incoming.packet.header.number.expand(0);
        let InitialHeader {
            src_cid,
            dst_cid,
            version,
            ..
        } = incoming.packet.header;

        if self.cids_exhausted() {
            debug!("refusing connection");
            return Err(AcceptError {
                cause: ConnectionError::CidsExhausted,
                response: Some(self.initial_close(
                    version,
                    incoming.addresses,
                    &incoming.crypto,
                    &src_cid,
                    TransportError::CONNECTION_REFUSED(""),
                    buf,
                )),
            });
        }

        let server_config = self.server_config.as_ref().unwrap().clone();

        if incoming
            .crypto
            .packet
            .remote
            .decrypt(
                packet_number,
                &incoming.packet.header_data,
                &mut incoming.packet.payload,
            )
            .is_err()
        {
            debug!(packet_number, "failed to authenticate initial packet");
            return Err(AcceptError {
                cause: TransportError::PROTOCOL_VIOLATION("authentication failed").into(),
                response: None,
            });
        };

        let ch = ConnectionHandle(self.connections.vacant_key());
        let loc_cid = self.new_cid(ch);
        let mut params = TransportParameters::new(
            &server_config.transport,
            &self.config,
            self.local_cid_generator.as_ref(),
            loc_cid,
            Some(&server_config),
        );
        params.stateless_reset_token = Some(ResetToken::new(&*self.config.reset_key, &loc_cid));
        params.original_dst_cid = Some(incoming.orig_dst_cid);
        params.retry_src_cid = incoming.retry_src_cid;

        let tls = server_config.crypto.clone().start_session(version, &params);
        let transport_config = server_config.transport.clone();
        let mut conn = self.add_connection(
            ch,
            version,
            dst_cid,
            loc_cid,
            src_cid,
            incoming.addresses,
            now,
            tls,
            Some(server_config),
            transport_config,
            incoming.remote_address_validated(),
        );
        if dst_cid.len() != 0 {
            self.index.insert_initial(dst_cid, ch);
        }
        match conn.handle_first_packet(
            now,
            incoming.addresses.remote,
            incoming.ecn,
            packet_number,
            incoming.packet,
            incoming.rest,
        ) {
            Ok(()) => {
                trace!(id = ch.0, icid = %dst_cid, "new connection");
                Ok((ch, conn))
            }
            Err(e) => {
                debug!("handshake failed: {}", e);
                self.handle_event(ch, EndpointEvent(EndpointEventInner::Drained));
                let response = match e {
                    ConnectionError::TransportError(ref e) => Some(self.initial_close(
                        version,
                        incoming.addresses,
                        &incoming.crypto,
                        &src_cid,
                        e.clone(),
                        buf,
                    )),
                    _ => None,
                };
                Err(AcceptError { cause: e, response })
            }
        }
    }

    /// Check if we should refuse a connection attempt regardless of the packet's contents
    fn early_validate_first_packet(
        &mut self,
        header: &PlainInitialHeader,
    ) -> Result<(), TransportError> {
        if self.cids_exhausted() {
            return Err(TransportError::CONNECTION_REFUSED(""));
        }

        // RFC9000 §7.2 dictates that initial (client-chosen) destination CIDs must be at least 8
        // bytes. If this is a Retry packet, then the length must instead match our usual CID
        // length. If we ever issue non-Retry address validation tokens via `NEW_TOKEN`, then we'll
        // also need to validate CID length for those after decoding the token.
        if header.dst_cid.len() < 8
            && (!header.token_pos.is_empty()
                && header.dst_cid.len() != self.local_cid_generator.cid_len())
        {
            debug!(
                "rejecting connection due to invalid DCID length {}",
                header.dst_cid.len()
            );
            return Err(TransportError::PROTOCOL_VIOLATION(
                "invalid destination CID length",
            ));
        }

        Ok(())
    }

    /// Reject this incoming connection attempt
    pub fn refuse(&mut self, incoming: Incoming, buf: &mut BytesMut) -> Transmit {
        self.initial_close(
            incoming.packet.header.version,
            incoming.addresses,
            &incoming.crypto,
            &incoming.packet.header.src_cid,
            TransportError::CONNECTION_REFUSED(""),
            buf,
        )
    }

    /// Respond with a retry packet, requiring the client to retry with address validation
    ///
    /// Errors if `incoming.remote_address_validated()` is true.
    pub fn retry(
        &mut self,
        incoming: Incoming,
        buf: &mut BytesMut,
    ) -> Result<Transmit, RetryError> {
        if incoming.remote_address_validated() {
            return Err(RetryError(incoming));
        }
        let server_config = self.server_config.as_ref().unwrap();

        // First Initial
        let mut random_bytes = vec![0u8; RetryToken::RANDOM_BYTES_LEN];
        self.rng.fill_bytes(&mut random_bytes);
        // The peer will use this as the DCID of its following Initials. Initial DCIDs are
        // looked up separately from Handshake/Data DCIDs, so there is no risk of collision
        // with established connections. In the unlikely event that a collision occurs
        // between two connections in the initial phase, both will fail fast and may be
        // retried by the application layer.
        let loc_cid = self.local_cid_generator.generate_cid();

        let token = RetryToken {
            orig_dst_cid: incoming.packet.header.dst_cid,
            issued: SystemTime::now(),
            random_bytes: &random_bytes,
        }
        .encode(
            &*server_config.token_key,
            &incoming.addresses.remote,
            &loc_cid,
        );

        let header = Header::Retry {
            src_cid: loc_cid,
            dst_cid: incoming.packet.header.src_cid,
            version: incoming.packet.header.version,
        };

        let encode = header.encode(buf);
        buf.put_slice(&token);
        buf.extend_from_slice(&server_config.crypto.retry_tag(
            incoming.packet.header.version,
            &incoming.packet.header.dst_cid,
            buf,
        ));
        encode.finish(buf, &*incoming.crypto.header.local, None);

        Ok(Transmit {
            destination: incoming.addresses.remote,
            ecn: None,
            size: buf.len(),
            segment_size: None,
            src_ip: incoming.addresses.local_ip,
        })
    }

    fn add_connection(
        &mut self,
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
        path_validated: bool,
    ) -> Connection {
        let mut rng_seed = [0; 32];
        self.rng.fill_bytes(&mut rng_seed);
        let conn = Connection::new(
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
            rng_seed,
            path_validated,
        );

        let id = self.connections.insert(ConnectionMeta {
            init_cid,
            cids_issued: 0,
            loc_cids: iter::once((0, loc_cid)).collect(),
            addresses,
            reset_token: None,
        });
        debug_assert_eq!(id, ch.0, "connection handle allocation out of sync");

        self.index.insert_conn(addresses, loc_cid, ch);

        conn
    }

    fn initial_close(
        &mut self,
        version: u32,
        addresses: FourTuple,
        crypto: &Keys,
        remote_id: &ConnectionId,
        reason: TransportError,
        buf: &mut BytesMut,
    ) -> Transmit {
        // We don't need to worry about CID collisions in initial closes because the peer
        // shouldn't respond, and if it does, and the CID collides, we'll just drop the
        // unexpected response.
        let local_id = self.local_cid_generator.generate_cid();
        let number = PacketNumber::U8(0);
        let header = Header::Initial(InitialHeader {
            dst_cid: *remote_id,
            src_cid: local_id,
            number,
            token: Bytes::new(),
            version,
        });

        let partial_encode = header.encode(buf);
        let max_len =
            INITIAL_MTU as usize - partial_encode.header_len - crypto.packet.local.tag_len();
        frame::Close::from(reason).encode(buf, max_len);
        buf.resize(buf.len() + crypto.packet.local.tag_len(), 0);
        partial_encode.finish(buf, &*crypto.header.local, Some((0, &*crypto.packet.local)));
        Transmit {
            destination: addresses.remote,
            ecn: None,
            size: buf.len(),
            segment_size: None,
            src_ip: addresses.local_ip,
        }
    }

    /// Access the configuration used by this endpoint
    pub fn config(&self) -> &EndpointConfig {
        &self.config
    }

    /// Number of connections that are currently open
    pub fn open_connections(&self) -> usize {
        self.connections.len()
    }

    #[cfg(test)]
    pub(crate) fn known_connections(&self) -> usize {
        let x = self.connections.len();
        debug_assert_eq!(x, self.index.connection_ids_initial.len());
        // Not all connections have known reset tokens
        debug_assert!(x >= self.index.connection_reset_tokens.0.len());
        // Not all connections have unique remotes, and 0-length CIDs might not be in use.
        debug_assert!(x >= self.index.connection_remotes.len());
        x
    }

    #[cfg(test)]
    pub(crate) fn known_cids(&self) -> usize {
        self.index.connection_ids.len()
    }

    /// Whether we've used up 3/4 of the available CID space
    ///
    /// We leave some space unused so that `new_cid` can be relied upon to finish quickly. We don't
    /// bother to check when CID longer than 4 bytes are used because 2^40 connections is a lot.
    fn cids_exhausted(&self) -> bool {
        self.local_cid_generator.cid_len() <= 4
            && self.local_cid_generator.cid_len() != 0
            && (2usize.pow(self.local_cid_generator.cid_len() as u32 * 8)
                - self.index.connection_ids.len())
                < 2usize.pow(self.local_cid_generator.cid_len() as u32 * 8 - 2)
    }
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("Endpoint")
            .field("rng", &self.rng)
            .field("index", &self.index)
            .field("connections", &self.connections)
            .field("config", &self.config)
            .field("server_config", &self.server_config)
            .finish()
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
    ConnectionEvent(ConnectionHandle, ConnectionEvent),
    /// The datagram may result in starting a new `Connection`
    NewConnection(Incoming),
    /// Response generated directly by the endpoint
    Response(Transmit),
}

/// An incoming connection for which the server has not yet begun its part of the handshake.
pub struct Incoming {
    addresses: FourTuple,
    ecn: Option<EcnCodepoint>,
    packet: InitialPacket,
    rest: Option<BytesMut>,
    crypto: Keys,
    retry_src_cid: Option<ConnectionId>,
    orig_dst_cid: ConnectionId,
}

impl Incoming {
    /// The local IP address which was used when the peer established
    /// the connection
    ///
    /// This has the same behavior as [`Connection::local_ip`]
    pub fn local_ip(&self) -> Option<IpAddr> {
        self.addresses.local_ip
    }

    /// The peer's UDP address.
    pub fn remote_address(&self) -> SocketAddr {
        self.addresses.remote
    }

    /// Whether the socket address that is initiating this connection has been validated.
    ///
    /// This means that the sender of the initial packet has proved that they can receive traffic
    /// sent to `self.remote_address()`.
    pub fn remote_address_validated(&self) -> bool {
        self.retry_src_cid.is_some()
    }
}

impl fmt::Debug for Incoming {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Incoming")
            .field("addresses", &self.addresses)
            .field("ecn", &self.ecn)
            // packet doesn't implement debug
            // rest is too big and not meaningful enough
            .field("retry_src_cid", &self.retry_src_cid)
            .field("orig_dst_cid", &self.orig_dst_cid)
            .finish_non_exhaustive()
    }
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
    /// The connection could not be created because not enough of the CID space is available
    ///
    /// Try using longer connection IDs
    #[error("CIDs exhausted")]
    CidsExhausted,
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

/// Error type for attempting to accept an [`Incoming`]
#[derive(Debug)]
pub struct AcceptError {
    /// Underlying error describing reason for failure
    pub cause: ConnectionError,
    /// Optional response to transmit back
    pub response: Option<Transmit>,
}

/// Error for attempting to retry an [`Incoming`] which already bears an address
/// validation token from a previous retry
#[derive(Debug, Error)]
#[error("retry() with validated Incoming")]
pub struct RetryError(Incoming);

impl RetryError {
    /// Get the [`Incoming`]
    pub fn into_incoming(self) -> Incoming {
        self.0
    }
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
