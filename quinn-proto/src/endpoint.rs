use std::{
    collections::{HashMap, hash_map},
    convert::TryFrom,
    fmt, mem,
    net::{IpAddr, SocketAddr},
    ops::{Index, IndexMut},
    sync::Arc,
};

#[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
use std::collections::VecDeque;

use bytes::{BufMut, Bytes, BytesMut};
use rand::{
    Rng, RngExt, SeedableRng,
    rngs::{StdRng, SysRng},
};
use rustc_hash::FxHashMap;
use slab::Slab;
use thiserror::Error;
use tracing::{debug, error, trace, warn};

use crate::{
    Duration, INITIAL_MTU, Instant, MAX_CID_SIZE, MIN_INITIAL_SIZE, RESET_TOKEN_SIZE, ResetToken,
    Side, Transmit, TransportConfig, TransportError,
    cid_generator::ConnectionIdGenerator,
    coding::BufMutExt,
    config::{ClientConfig, EndpointConfig, ServerConfig},
    connection::{Connection, ConnectionArgs, ConnectionError, SideArgs},
    crypto::{self, Keys, UnsupportedVersion},
    frame,
    packet::{
        FixedLengthConnectionIdParser, Header, InitialHeader, InitialPacket, PacketDecodeError,
        PacketNumber, PartialDecode, ProtectedInitialHeader,
    },
    shared::{
        ConnectionEvent, ConnectionEventInner, ConnectionId, DatagramConnectionEvent, EcnCodepoint,
        EndpointEvent, EndpointEventInner, IssuedCid,
    },
    token::{IncomingToken, InvalidRetryTokenError, Token, TokenPayload},
    transport_parameters::{PreferredAddress, TransportParameters},
};

#[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
use crate::{
    connection::{MAX_ACK_BLOCKS, assembler::Assembler},
    range_set::ArrayRangeSet,
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
    /// Buffered Initial and 0-RTT messages for pending incoming connections
    incoming_buffers: Slab<IncomingBuffer>,
    all_incoming_buffers_total_bytes: u64,
}

impl Endpoint {
    /// Create a new endpoint
    ///
    /// `allow_mtud` enables path MTU detection when requested by `Connection` configuration for
    /// better performance. This requires that outgoing packets are never fragmented, which can be
    /// achieved via e.g. the `IPV6_DONTFRAG` socket option.
    ///
    /// Returns an error if the endpoint cannot be seeded from the operating system random source.
    pub fn new(
        config: Arc<EndpointConfig>,
        server_config: Option<Arc<ServerConfig>>,
        allow_mtud: bool,
    ) -> Self {
        Self {
            rng: match config.rng_seed {
                Some(seed) => StdRng::from_seed(seed),
                None => StdRng::try_from_rng(&mut SysRng)
                    .expect("failed to seed random number generator from system"),
            },
            index: ConnectionIndex::default(),
            connections: Slab::new(),
            local_cid_generator: (config.connection_id_generator_factory.as_ref())(),
            config,
            server_config,
            allow_mtud,
            last_stateless_reset: None,
            incoming_buffers: Slab::new(),
            all_incoming_buffers_total_bytes: 0,
        }
    }

    /// Replace the server configuration, affecting new incoming connections only
    ///
    /// Pending incoming connections retain the configuration active when they first arrived.
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
                    self.index.retire(cid);
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
        buf: &mut Vec<u8>,
    ) -> Option<DatagramEvent> {
        // Partially decode packet or short-circuit if unable
        let datagram_len = data.len();
        let event = match PartialDecode::new(
            data,
            &FixedLengthConnectionIdParser::new(self.local_cid_generator.cid_len()),
            &self.config.supported_versions,
            self.config.grease_quic_bit,
        ) {
            Ok((first_decode, remaining)) => DatagramConnectionEvent {
                now,
                remote,
                ecn,
                first_decode,
                remaining,
            },
            Err(PacketDecodeError::UnsupportedVersion {
                src_cid,
                dst_cid,
                version,
            }) => {
                if self.server_config.is_none() {
                    debug!("dropping packet with unsupported version");
                    return None;
                }
                // RFC 9000 §5.2.2: "Servers MUST drop smaller packets that specify unsupported
                // versions." Responding to short packets would let a spoofed source elicit a
                // Version Negotiation packet larger than the datagram that triggered it.
                if datagram_len < MIN_INITIAL_SIZE as usize {
                    debug!("dropping short packet with unsupported version");
                    return None;
                }
                trace!("sending version negotiation");
                // Negotiate versions
                Header::VersionNegotiate {
                    random: self.rng.random::<u8>() | 0x40,
                    src_cid: dst_cid,
                    dst_cid: src_cid,
                }
                .encode(buf);
                // Grease with a reserved version
                buf.write::<u32>(match version {
                    0x0a1a_2a3a => 0x0a1a_2a4a,
                    _ => 0x0a1a_2a3a,
                });
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

        let addresses = FourTuple { remote, local_ip };
        let dst_cid = event.first_decode.dst_cid();

        if let Some(route_to) = self.index.get(&addresses, &event.first_decode) {
            // Handle packet on existing connection
            match route_to {
                RouteDatagramTo::Incoming(incoming_idx) => {
                    let incoming_buffer = &mut self.incoming_buffers[incoming_idx];
                    let config = &incoming_buffer.server_config;

                    if incoming_buffer.addresses != addresses {
                        debug!(
                            remote = %addresses.remote,
                            expected = %incoming_buffer.addresses.remote,
                            "discarding pending incoming datagram from unexpected path"
                        );
                        return None;
                    }

                    if incoming_buffer
                        .total_bytes
                        .checked_add(datagram_len as u64)
                        .is_some_and(|n| n <= config.incoming_buffer_size)
                        && self
                            .all_incoming_buffers_total_bytes
                            .checked_add(datagram_len as u64)
                            .is_some_and(|n| n <= config.incoming_buffer_size_total)
                    {
                        incoming_buffer.datagrams.push(event);
                        incoming_buffer.total_bytes += datagram_len as u64;
                        self.all_incoming_buffers_total_bytes += datagram_len as u64;
                    }

                    None
                }
                RouteDatagramTo::Connection(ch) => Some(DatagramEvent::ConnectionEvent(
                    ch,
                    ConnectionEvent(ConnectionEventInner::Datagram(event)),
                )),
            }
        } else if event.first_decode.initial_header().is_some() {
            // Potentially create a new connection

            self.handle_first_packet(datagram_len, event, addresses, buf)
        } else if event.first_decode.has_long_header() {
            debug!(
                "ignoring non-initial packet for unknown connection {}",
                dst_cid
            );
            None
        } else if !event.first_decode.is_initial()
            && self.local_cid_generator.validate(dst_cid).is_err()
        {
            debug!("dropping packet with invalid CID");
            None
        } else if dst_cid.is_empty() {
            trace!("dropping unrecognized short packet without ID");
            None
        } else {
            // If we got this far, we're receiving a seemingly valid packet for an unknown
            // connection. Send a stateless reset if possible.
            self.stateless_reset(now, datagram_len, addresses, dst_cid, buf)
                .map(DatagramEvent::Response)
        }
    }

    fn stateless_reset(
        &mut self,
        now: Instant,
        inciting_dgram_len: usize,
        addresses: FourTuple,
        dst_cid: ConnectionId,
        buf: &mut Vec<u8>,
    ) -> Option<Transmit> {
        if self
            .last_stateless_reset
            .is_some_and(|last| last + self.config.min_reset_interval > now)
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
                debug!(
                    "ignoring unexpected {} byte packet: not larger than minimum stateless reset size",
                    inciting_dgram_len
                );
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
            self.rng
                .random_range(IDEAL_MIN_PADDING_LEN..max_padding_len)
        };
        buf.reserve(padding_len + RESET_TOKEN_SIZE);
        buf.resize(padding_len, 0);
        self.rng.fill_bytes(&mut buf[0..padding_len]);
        buf[0] = 0b0100_0000 | (buf[0] >> 2);
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

        let remote_id = (config.initial_dst_cid_provider)();
        trace!(initial_dcid = %remote_id);

        let ch = ConnectionHandle(self.connections.vacant_key());
        let loc_cid = self.new_cid(RouteDatagramTo::Connection(ch));
        let params = TransportParameters::new(
            &config.transport,
            &self.config,
            self.local_cid_generator.as_ref(),
            loc_cid,
            None,
            &mut self.rng,
        );
        let tls = config
            .crypto
            .start_session(config.version, server_name, &params)
            .inspect_err(|_| {
                // Remove just issued connection id
                self.index.connection_ids.remove(&loc_cid);
            })?;

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
            config.transport,
            SideArgs::Client {
                token_store: config.token_store,
                server_name: server_name.into(),
            },
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
            let id = self.new_cid(RouteDatagramTo::Connection(ch));
            let meta = &mut self.connections[ch];
            let sequence = meta.cids_issued;
            meta.cids_issued += 1;
            meta.loc_cids.insert(sequence, id);
            ids.push(IssuedCid {
                sequence,
                id,
                reset_token: ResetToken::new(&*self.config.reset_key, id),
            });
        }
        ConnectionEvent(ConnectionEventInner::NewIdentifiers(ids, now))
    }

    /// Generate and reserve a local connection ID
    fn new_cid(&mut self, route_to: RouteDatagramTo) -> ConnectionId {
        loop {
            let cid = self.local_cid_generator.generate_cid();
            if cid.is_empty() {
                // Zero-length CID; nothing to track
                debug_assert_eq!(self.local_cid_generator.cid_len(), 0);
                return cid;
            }
            if let hash_map::Entry::Vacant(e) = self.index.connection_ids.entry(cid) {
                e.insert(route_to);
                break cid;
            }
        }
    }

    fn handle_first_packet(
        &mut self,
        datagram_len: usize,
        event: DatagramConnectionEvent,
        addresses: FourTuple,
        buf: &mut Vec<u8>,
    ) -> Option<DatagramEvent> {
        let dst_cid = event.first_decode.dst_cid();
        let header = event.first_decode.initial_header().unwrap();

        let Some(server_config) = &self.server_config else {
            debug!("packet for unrecognized connection {}", dst_cid);
            return self
                .stateless_reset(event.now, datagram_len, addresses, dst_cid, buf)
                .map(DatagramEvent::Response);
        };

        if datagram_len < MIN_INITIAL_SIZE as usize {
            debug!("ignoring short initial for connection {}", dst_cid);
            return None;
        }

        // Saturation only happens under heavy load, where deriving initial keys per Initial just to
        // reply with CONNECTION_REFUSED would starve packet processing for existing connections.
        if self.cids_exhausted() || self.incoming_buffers.len() >= server_config.max_incoming {
            debug!(
                "ignoring initial for connection {} due to saturation",
                dst_cid
            );
            return None;
        }

        let crypto = match server_config.crypto.initial_keys(header.version, dst_cid) {
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
                header.src_cid,
                reason,
                buf,
            )));
        }

        let packet = match event.first_decode.finish(Some(&*crypto.header.remote)) {
            Ok(packet) => packet,
            Err(e) => {
                trace!("unable to decode initial packet: {}", e);
                return None;
            }
        };

        if !packet.reserved_bits_valid() {
            debug!("dropping connection attempt with invalid reserved bits");
            return None;
        }

        let Header::Initial(header) = packet.header else {
            panic!("non-initial packet in handle_first_packet()");
        };

        let server_config = self.server_config.as_ref().unwrap().clone();

        let token = match IncomingToken::from_header(&header, &server_config, addresses.remote) {
            Ok(token) => token,
            Err(InvalidRetryTokenError) => {
                debug!("rejecting invalid retry token");
                return Some(DatagramEvent::Response(self.initial_close(
                    header.version,
                    addresses,
                    &crypto,
                    header.src_cid,
                    TransportError::INVALID_TOKEN(""),
                    buf,
                )));
            }
        };

        let incoming_idx = self.incoming_buffers.insert(IncomingBuffer {
            server_config,
            addresses,
            datagrams: Vec::new(),
            total_bytes: 0,
        });
        self.index
            .insert_initial_incoming(header.dst_cid, incoming_idx);

        Some(DatagramEvent::NewConnection(Incoming {
            received_at: event.now,
            addresses,
            ecn: event.ecn,
            packet: InitialPacket {
                header,
                header_data: packet.header_data,
                payload: packet.payload,
            },
            rest: event.remaining,
            crypto,
            token,
            incoming_idx,
            improper_drop_warner: IncomingImproperDropWarner,
        }))
    }

    /// Attempt to accept this incoming connection (an error may still occur)
    ///
    /// Equivalent to [`start_accept()`](Self::start_accept) followed by [`Accepting::accept()`] and
    /// [`finish_accept()`](Self::finish_accept).
    // box err to avoid clippy::result_large_err
    pub fn accept(
        &mut self,
        incoming: Incoming,
        now: Instant,
        buf: &mut Vec<u8>,
        server_config: Option<Arc<ServerConfig>>,
    ) -> Result<(ConnectionHandle, Connection), Box<AcceptError>> {
        let accepting = self.start_accept(incoming, now, buf, server_config)?;
        self.finish_accept(accepting.accept(), buf)
    }

    /// Begin accepting this incoming connection, reserving endpoint state for it
    ///
    /// This is the first of three phases which together are equivalent to
    /// [`accept()`](Self::accept). It does only the work that needs the endpoint: validating the
    /// attempt, issuing connection IDs, and arranging for datagrams addressed to the connection to
    /// be buffered. TLS session setup, connection construction, and first-packet handling are
    /// deferred to [`Accepting::accept()`], which does not need the endpoint and can therefore run
    /// concurrently with other operations on it, e.g. outside a lock guarding it. The result must
    /// then be passed to [`finish_accept()`](Self::finish_accept) on this endpoint, which registers
    /// the connection and delivers the buffered datagrams to it, or releases the reserved state if
    /// the handshake failed.
    ///
    /// Until `finish_accept`, the attempt counts toward [`ServerConfig::max_incoming()`], and
    /// datagrams buffered for it toward [`ServerConfig::incoming_buffer_size()`] and
    /// [`ServerConfig::incoming_buffer_size_total()`].
    ///
    /// On error, no endpoint state remains reserved for the attempt.
    // box err to avoid clippy::result_large_err
    pub fn start_accept(
        &mut self,
        mut incoming: Incoming,
        now: Instant,
        buf: &mut Vec<u8>,
        server_config: Option<Arc<ServerConfig>>,
    ) -> Result<Accepting, Box<AcceptError>> {
        let remote_address_validated = incoming.remote_address_validated();

        let packet_number = incoming.packet.header.number.expand(0);
        let InitialHeader {
            src_cid,
            dst_cid,
            version,
            ..
        } = incoming.packet.header;
        let server_config = server_config.unwrap_or_else(|| {
            self.incoming_buffers[incoming.incoming_idx]
                .server_config
                .clone()
        });

        if server_config
            .transport
            .max_idle_timeout
            .is_some_and(|timeout| {
                timeout.into_inner() != 0
                    && incoming.received_at + Duration::from_millis(timeout.into()) <= now
            })
        {
            debug!("abandoning accept of stale initial");
            self.ignore(incoming);
            return Err(Box::new(AcceptError {
                cause: ConnectionError::TimedOut,
                response: None,
            }));
        }

        if self.local_cid_generator.cid_len() == 0
            && self
                .index
                .incoming_connection_remotes
                .contains_key(&incoming.addresses)
        {
            debug!(
                remote = %incoming.addresses.remote,
                "refusing connection because its zero-length CID route is already in use"
            );
            let response = self.initial_close(
                version,
                incoming.addresses,
                &incoming.crypto,
                src_cid,
                TransportError::CONNECTION_REFUSED("zero-length connection ID route in use"),
                buf,
            );
            self.ignore(incoming);
            return Err(Box::new(AcceptError {
                cause: ConnectionError::CidsExhausted,
                response: Some(response),
            }));
        }

        if self.cids_exhausted() {
            debug!("refusing connection");
            let response = self.initial_close(
                version,
                incoming.addresses,
                &incoming.crypto,
                src_cid,
                TransportError::CONNECTION_REFUSED(""),
                buf,
            );
            self.ignore(incoming);
            return Err(Box::new(AcceptError {
                cause: ConnectionError::CidsExhausted,
                response: Some(response),
            }));
        }

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
            self.ignore(incoming);
            return Err(Box::new(AcceptError {
                cause: TransportError::PROTOCOL_VIOLATION("authentication failed").into(),
                response: None,
            }));
        };

        let loc_cid = self.new_cid(RouteDatagramTo::Incoming(incoming.incoming_idx));
        let mut params = TransportParameters::new(
            &server_config.transport,
            &self.config,
            self.local_cid_generator.as_ref(),
            loc_cid,
            Some(&server_config),
            &mut self.rng,
        );
        params.stateless_reset_token = Some(ResetToken::new(&*self.config.reset_key, loc_cid));
        params.original_dst_cid = Some(incoming.token.orig_dst_cid);
        params.retry_src_cid = incoming.token.retry_src_cid;
        let mut pref_addr_cid = None;
        if server_config.has_preferred_address() {
            let cid = self.new_cid(RouteDatagramTo::Incoming(incoming.incoming_idx));
            pref_addr_cid = Some(cid);
            params.preferred_address = Some(PreferredAddress {
                address_v4: server_config.preferred_address_v4,
                address_v6: server_config.preferred_address_v6,
                connection_id: cid,
                stateless_reset_token: ResetToken::new(&*self.config.reset_key, cid),
            });
        }

        // The attempt is now committed: the `Incoming` is consumed, and the state reserved above is
        // released only by `finish_accept`.
        let Incoming {
            received_at,
            addresses,
            ecn,
            packet,
            rest,
            crypto,
            #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
            token,
            incoming_idx,
            improper_drop_warner,
            ..
        } = incoming;
        improper_drop_warner.dismiss();

        let mut rng_seed = [0; 32];
        self.rng.fill_bytes(&mut rng_seed);
        let server_crypto = server_config.crypto.clone();
        let args = ConnectionArgs {
            endpoint_config: self.config.clone(),
            transport_config: server_config.transport.clone(),
            init_cid: dst_cid,
            loc_cid,
            rem_cid: src_cid,
            remote: addresses.remote,
            local_ip: addresses.local_ip,
            local_cid_len: self.local_cid_generator.cid_len(),
            local_cid_lifetime: self.local_cid_generator.cid_lifetime(),
            now: received_at,
            version,
            allow_mtud: self.allow_mtud,
            rng_seed,
            side_args: SideArgs::Server {
                server_config,
                pref_addr_cid,
                path_validated: remote_address_validated,
            },
        };

        if loc_cid.is_empty() {
            let previous = self
                .index
                .incoming_connection_remotes
                .insert(addresses, RouteDatagramTo::Incoming(incoming_idx));
            debug_assert!(previous.is_none());
        }

        Ok(Accepting {
            incoming_idx,
            packet_number,
            packet,
            rest,
            ecn,
            crypto,
            #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
            token,
            server_crypto,
            params,
            args,
            initial_sends: InitialSendState::default(),
            #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
            last_activity: received_at,
            #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
            rustls_buffered_datagrams: 0,
            #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
            rustls_input: VecDeque::new(),
            guard: AcceptDropGuard,
        })
    }

    /// Copy newly buffered datagrams into a staged rustls accept for processing outside the
    /// endpoint lock.
    #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
    #[doc(hidden)]
    pub fn buffer_rustls_acceptor_input(&self, accepting: &mut Accepting) {
        let incoming_buffer = &self.incoming_buffers[accepting.incoming_idx];
        accepting.rustls_input.extend(
            incoming_buffer
                .datagrams
                .iter()
                .skip(accepting.rustls_buffered_datagrams)
                .cloned(),
        );
        accepting.rustls_buffered_datagrams = incoming_buffer.datagrams.len();
    }

    /// Replace the config captured by `start_accept` after ClientHello-based selection.
    #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
    #[doc(hidden)]
    pub fn select_accepting_config(
        &mut self,
        accepting: &mut Accepting,
        server_config: Option<Arc<ServerConfig>>,
        now: Instant,
    ) -> Result<(), ConnectionError> {
        let server_config = server_config.unwrap_or_else(|| accepting.server_config().clone());
        if server_config
            .transport
            .max_idle_timeout
            .is_some_and(|timeout| {
                timeout.into_inner() != 0
                    && accepting.last_activity + Duration::from_millis(timeout.into()) <= now
            })
        {
            return Err(ConnectionError::TimedOut);
        }

        let current_pref_addr_cid = accepting.args.side_args.pref_addr_cid();
        let pref_addr_cid = match (current_pref_addr_cid, server_config.has_preferred_address()) {
            (Some(cid), false) => {
                self.index.retire(cid);
                None
            }
            (None, true) => {
                if self.cids_exhausted() {
                    return Err(ConnectionError::CidsExhausted);
                }
                Some(self.new_cid(RouteDatagramTo::Incoming(accepting.incoming_idx)))
            }
            (cid, _) => cid,
        };

        let mut params = TransportParameters::new(
            &server_config.transport,
            &self.config,
            self.local_cid_generator.as_ref(),
            accepting.args.loc_cid,
            Some(&server_config),
            &mut self.rng,
        );
        params.stateless_reset_token = Some(ResetToken::new(
            &*self.config.reset_key,
            accepting.args.loc_cid,
        ));
        params.original_dst_cid = Some(accepting.token.orig_dst_cid);
        params.retry_src_cid = accepting.token.retry_src_cid;
        if let Some(cid) = pref_addr_cid {
            params.preferred_address = Some(PreferredAddress {
                address_v4: server_config.preferred_address_v4,
                address_v6: server_config.preferred_address_v6,
                connection_id: cid,
                stateless_reset_token: ResetToken::new(&*self.config.reset_key, cid),
            });
        }

        let path_validated = match &accepting.args.side_args {
            SideArgs::Server { path_validated, .. } => *path_validated,
            SideArgs::Client { .. } => unreachable!("accepting a client connection"),
        };
        accepting.server_crypto = server_config.crypto.clone();
        accepting.params = params;
        accepting.args.transport_config = server_config.transport.clone();
        accepting.args.side_args = SideArgs::Server {
            server_config,
            pref_addr_cid,
            path_validated,
        };
        Ok(())
    }

    /// Complete acceptance of a connection begun by [`start_accept()`](Self::start_accept)
    ///
    /// Must be called on the same endpoint. On success, the connection is registered with the
    /// endpoint and any datagrams for it that arrived since `start_accept` are delivered to it.
    /// On failure, the state reserved by `start_accept` is released, and `buf` may be populated
    /// with a close packet to send to the peer, as for [`accept()`](Self::accept).
    // box err to avoid clippy::result_large_err
    pub fn finish_accept(
        &mut self,
        accepted: Accepted,
        buf: &mut Vec<u8>,
    ) -> Result<(ConnectionHandle, Connection), Box<AcceptError>> {
        let Accepted {
            incoming_idx,
            init_cid,
            loc_cid,
            pref_addr_cid,
            addresses,
            version,
            src_cid,
            crypto,
            initial_sends,
            result,
            guard,
        } = accepted;
        guard.dismiss();

        let mut conn = match result {
            Ok(conn) => conn,
            Err(cause) => {
                debug!("handshake failed: {}", cause);
                let response = match &cause {
                    ConnectionError::TransportError(e) => Some(Self::initial_close_with(
                        version,
                        addresses,
                        &crypto,
                        src_cid,
                        loc_cid,
                        initial_sends.next_packet_number,
                        e.clone(),
                        buf,
                    )),
                    _ => None,
                };
                // Release the routes and buffer slot reserved by `start_accept`
                self.index.remove_initial(init_cid);
                self.index.retire(loc_cid);
                if let Some(cid) = pref_addr_cid {
                    self.index.retire(cid);
                }
                if loc_cid.is_empty()
                    && matches!(
                        self.index.incoming_connection_remotes.get(&addresses),
                        Some(RouteDatagramTo::Incoming(idx)) if *idx == incoming_idx
                    )
                {
                    self.index.incoming_connection_remotes.remove(&addresses);
                }
                self.remove_incoming_buffer(incoming_idx);
                return Err(Box::new(AcceptError { cause, response }));
            }
        };

        let incoming_buffer = self.remove_incoming_buffer(incoming_idx);
        let ch = ConnectionHandle(self.connections.vacant_key());
        // Re-points the routes reserved by `start_accept` at the connection
        self.register_connection(
            ch,
            init_cid,
            loc_cid,
            pref_addr_cid,
            addresses,
            Side::Server,
        );
        trace!(id = ch.0, icid = %init_cid, "new connection");

        for event in incoming_buffer.datagrams {
            conn.handle_event(ConnectionEvent(ConnectionEventInner::Datagram(event)))
        }

        Ok((ch, conn))
    }

    /// Clean up a staged rustls accept before it has created a connection.
    #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
    #[doc(hidden)]
    pub fn fail_accepting(
        &mut self,
        accepting: Accepting,
        cause: ConnectionError,
        buf: &mut Vec<u8>,
    ) -> Box<AcceptError> {
        self.finish_accept(accepting.fail(cause), buf)
            .expect_err("failed staged accept unexpectedly created a connection")
    }

    /// Check if we should refuse a connection attempt regardless of the packet's contents
    fn early_validate_first_packet(
        &mut self,
        header: &ProtectedInitialHeader,
    ) -> Result<(), TransportError> {
        // RFC9000 §7.2 dictates that initial (client-chosen) destination CIDs must be at least 8
        // bytes. If this is a Retry packet, then the length must instead match our usual CID
        // length. If we ever issue non-Retry address validation tokens via `NEW_TOKEN`, then we'll
        // also need to validate CID length for those after decoding the token.
        if header.dst_cid.len() < 8
            && (header.token_pos.is_empty()
                || header.dst_cid.len() != self.local_cid_generator.cid_len())
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
    pub fn refuse(&mut self, incoming: Incoming, buf: &mut Vec<u8>) -> Transmit {
        self.remove_incoming_state(&incoming);
        incoming.improper_drop_warner.dismiss();

        self.initial_close(
            incoming.packet.header.version,
            incoming.addresses,
            &incoming.crypto,
            incoming.packet.header.src_cid,
            TransportError::CONNECTION_REFUSED(""),
            buf,
        )
    }

    /// Respond with a retry packet, requiring the client to retry with address validation
    ///
    /// Errors if `incoming.may_retry()` is false.
    pub fn retry(&mut self, incoming: Incoming, buf: &mut Vec<u8>) -> Result<Transmit, RetryError> {
        if !incoming.may_retry() {
            return Err(RetryError(Box::new(incoming)));
        }

        let server_config = self.incoming_buffers[incoming.incoming_idx]
            .server_config
            .clone();
        self.remove_incoming_state(&incoming);
        incoming.improper_drop_warner.dismiss();

        // First Initial
        // The peer will use this as the DCID of its following Initials. Initial DCIDs are
        // looked up separately from Handshake/Data DCIDs, so there is no risk of collision
        // with established connections. In the unlikely event that a collision occurs
        // between two connections in the initial phase, both will fail fast and may be
        // retried by the application layer.
        let loc_cid = self.local_cid_generator.generate_cid();

        let payload = TokenPayload::Retry {
            address: incoming.addresses.remote,
            orig_dst_cid: incoming.packet.header.dst_cid,
            issued: server_config.time_source.now(),
        };
        let token = Token::new(payload, &mut self.rng).encode(&*server_config.token_key);

        let header = Header::Retry {
            src_cid: loc_cid,
            dst_cid: incoming.packet.header.src_cid,
            version: incoming.packet.header.version,
        };

        let encode = header.encode(buf);
        buf.put_slice(&token);
        buf.extend_from_slice(&server_config.crypto.retry_tag(
            incoming.packet.header.version,
            incoming.packet.header.dst_cid,
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

    /// Ignore this incoming connection attempt, not sending any packet in response
    ///
    /// Doing this actively, rather than merely dropping the [`Incoming`], is necessary to prevent
    /// memory leaks due to state within [`Endpoint`] tracking the incoming connection.
    pub fn ignore(&mut self, incoming: Incoming) {
        self.remove_incoming_state(&incoming);
        incoming.improper_drop_warner.dismiss();
    }

    /// Remove endpoint state associated with an `Incoming`.
    fn remove_incoming_state(&mut self, incoming: &Incoming) {
        self.index.remove_initial(incoming.packet.header.dst_cid);
        self.remove_incoming_buffer(incoming.incoming_idx);
    }

    fn remove_incoming_buffer(&mut self, incoming_idx: usize) -> IncomingBuffer {
        let incoming_buffer = self.incoming_buffers.remove(incoming_idx);
        self.all_incoming_buffers_total_bytes -= incoming_buffer.total_bytes;
        incoming_buffer
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
        transport_config: Arc<TransportConfig>,
        side_args: SideArgs,
    ) -> Connection {
        let mut rng_seed = [0; 32];
        self.rng.fill_bytes(&mut rng_seed);
        let side = side_args.side();
        let pref_addr_cid = side_args.pref_addr_cid();
        let conn = Connection::new(
            tls,
            ConnectionArgs {
                endpoint_config: self.config.clone(),
                transport_config,
                init_cid,
                loc_cid,
                rem_cid,
                remote: addresses.remote,
                local_ip: addresses.local_ip,
                local_cid_len: self.local_cid_generator.cid_len(),
                local_cid_lifetime: self.local_cid_generator.cid_lifetime(),
                now,
                version,
                allow_mtud: self.allow_mtud,
                rng_seed,
                side_args,
            },
        );

        self.register_connection(ch, init_cid, loc_cid, pref_addr_cid, addresses, side);

        conn
    }

    /// Register endpoint-owned metadata and routes for an active connection.
    fn register_connection(
        &mut self,
        ch: ConnectionHandle,
        init_cid: ConnectionId,
        loc_cid: ConnectionId,
        pref_addr_cid: Option<ConnectionId>,
        addresses: FourTuple,
        side: Side,
    ) {
        let mut cids_issued = 0;
        let mut loc_cids = FxHashMap::default();

        loc_cids.insert(cids_issued, loc_cid);
        cids_issued += 1;

        if let Some(cid) = pref_addr_cid {
            debug_assert_eq!(cids_issued, 1, "preferred address cid seq must be 1");
            loc_cids.insert(cids_issued, cid);
            cids_issued += 1;
        }

        let id = self.connections.insert(ConnectionMeta {
            init_cid,
            cids_issued,
            loc_cids,
            addresses,
            side,
            reset_token: None,
        });
        debug_assert_eq!(id, ch.0, "connection handle allocation out of sync");

        let conn_meta = &self.connections[ch];
        if conn_meta.side.is_server() {
            self.index.insert_initial(conn_meta.init_cid, ch);
        }
        for cid in conn_meta.loc_cids.values() {
            if cid.is_empty() {
                match conn_meta.side {
                    Side::Server => {
                        self.index
                            .incoming_connection_remotes
                            .insert(conn_meta.addresses, RouteDatagramTo::Connection(ch));
                    }
                    Side::Client => {
                        self.index
                            .outgoing_connection_remotes
                            .insert(conn_meta.addresses.remote, ch);
                    }
                }
            } else {
                self.index
                    .connection_ids
                    .insert(*cid, RouteDatagramTo::Connection(ch));
            }
        }
    }

    fn initial_close(
        &mut self,
        version: u32,
        addresses: FourTuple,
        crypto: &Keys,
        remote_id: ConnectionId,
        reason: TransportError,
        buf: &mut Vec<u8>,
    ) -> Transmit {
        // We don't need to worry about CID collisions in initial closes because the peer
        // shouldn't respond, and if it does, and the CID collides, we'll just drop the
        // unexpected response.
        let local_id = self.local_cid_generator.generate_cid();
        Self::initial_close_with(
            version, addresses, crypto, remote_id, local_id, 0, reason, buf,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn initial_close_with(
        version: u32,
        addresses: FourTuple,
        crypto: &Keys,
        remote_id: ConnectionId,
        local_id: ConnectionId,
        packet_number: u64,
        reason: TransportError,
        buf: &mut Vec<u8>,
    ) -> Transmit {
        let number = PacketNumber::new(packet_number, 0);
        let header = Header::Initial(InitialHeader {
            dst_cid: remote_id,
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
        partial_encode.finish(
            buf,
            &*crypto.header.local,
            Some((packet_number, &*crypto.packet.local)),
        );
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

    /// Counter for the number of bytes currently used
    /// in the buffers for Initial and 0-RTT messages for pending incoming connections
    /// and accepts that are still being finalized
    pub fn incoming_buffer_bytes(&self) -> u64 {
        self.all_incoming_buffers_total_bytes
    }

    #[cfg(test)]
    pub(crate) fn known_connections(&self) -> usize {
        let x = self.connections.len();
        debug_assert_eq!(x, self.index.connection_ids_initial.len());
        // Not all connections have known reset tokens
        debug_assert!(x >= self.index.connection_reset_tokens.0.len());
        // Not all connections have unique remotes, and 0-length CIDs might not be in use.
        debug_assert!(
            x >= self
                .index
                .incoming_connection_remotes
                .values()
                .filter(|route| matches!(route, RouteDatagramTo::Connection(_)))
                .count()
        );
        debug_assert!(x >= self.index.outgoing_connection_remotes.len());
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
        let cid_len = self.local_cid_generator.cid_len();
        if cid_len == 0 || cid_len > 4 {
            return false;
        }

        // Keep this architecture-independent: on 32-bit targets, 2usize.pow(32) overflows.
        let bits = (cid_len * 8) as u32;
        let space = 1u64 << bits;
        let reserve = 1u64 << (bits - 2);
        let len = self.index.connection_ids.len() as u64;

        len > (space - reserve)
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
            // incoming_buffers too large
            .field("incoming_buffers.len", &self.incoming_buffers.len())
            .field(
                "all_incoming_buffers_total_bytes",
                &self.all_incoming_buffers_total_bytes,
            )
            .finish()
    }
}

/// Buffered Initial and 0-RTT messages for a pending incoming connection
struct IncomingBuffer {
    server_config: Arc<ServerConfig>,
    addresses: FourTuple,
    datagrams: Vec<DatagramConnectionEvent>,
    total_bytes: u64,
}

/// Part of protocol state incoming datagrams can be routed to
#[derive(Copy, Clone, Debug)]
enum RouteDatagramTo {
    Incoming(usize),
    Connection(ConnectionHandle),
}

/// Maps packets to existing connections
#[derive(Default, Debug)]
struct ConnectionIndex {
    /// Identifies connections based on the initial DCID the peer utilized
    ///
    /// Uses a standard `HashMap` to protect against hash collision attacks.
    ///
    /// Used by the server, not the client.
    connection_ids_initial: HashMap<ConnectionId, RouteDatagramTo>,
    /// Identifies connections based on locally created CIDs
    ///
    /// Uses a cheaper hash function since keys are locally created
    connection_ids: FxHashMap<ConnectionId, RouteDatagramTo>,
    /// Identifies incoming connections with zero-length CIDs
    ///
    /// Uses a standard `HashMap` to protect against hash collision attacks.
    incoming_connection_remotes: HashMap<FourTuple, RouteDatagramTo>,
    /// Identifies outgoing connections with zero-length CIDs
    ///
    /// We don't yet support explicit source addresses for client connections, and zero-length CIDs
    /// require a unique four-tuple, so at most one client connection with zero-length local CIDs
    /// may be established per remote. We must omit the local address from the key because we don't
    /// necessarily know what address we're sending from, and hence receiving at.
    ///
    /// Uses a standard `HashMap` to protect against hash collision attacks.
    outgoing_connection_remotes: HashMap<SocketAddr, ConnectionHandle>,
    /// Reset tokens provided by the peer for the CID each connection is currently sending to
    ///
    /// Incoming stateless resets do not have correct CIDs, so we need this to identify the correct
    /// recipient, if any.
    connection_reset_tokens: ResetTokenTable,
}

impl ConnectionIndex {
    /// Associate an incoming connection with its initial destination CID
    fn insert_initial_incoming(&mut self, dst_cid: ConnectionId, incoming_key: usize) {
        if dst_cid.is_empty() {
            return;
        }
        self.connection_ids_initial
            .insert(dst_cid, RouteDatagramTo::Incoming(incoming_key));
    }

    /// Remove an association with an initial destination CID
    fn remove_initial(&mut self, dst_cid: ConnectionId) {
        if dst_cid.is_empty() {
            return;
        }
        let removed = self.connection_ids_initial.remove(&dst_cid);
        debug_assert!(removed.is_some());
    }

    /// Associate a connection with its initial destination CID
    fn insert_initial(&mut self, dst_cid: ConnectionId, connection: ConnectionHandle) {
        if dst_cid.is_empty() {
            return;
        }
        self.connection_ids_initial
            .insert(dst_cid, RouteDatagramTo::Connection(connection));
    }

    /// Discard a connection ID
    fn retire(&mut self, dst_cid: ConnectionId) {
        self.connection_ids.remove(&dst_cid);
    }

    /// Remove all references to a connection
    fn remove(&mut self, conn: &ConnectionMeta) {
        if conn.side.is_server() {
            self.remove_initial(conn.init_cid);
        }
        for cid in conn.loc_cids.values() {
            self.connection_ids.remove(cid);
        }
        self.incoming_connection_remotes.remove(&conn.addresses);
        self.outgoing_connection_remotes
            .remove(&conn.addresses.remote);
        if let Some((remote, token)) = conn.reset_token {
            self.connection_reset_tokens.remove(remote, token);
        }
    }

    /// Find the existing connection that `datagram` should be routed to, if any
    fn get(&self, addresses: &FourTuple, datagram: &PartialDecode) -> Option<RouteDatagramTo> {
        if !datagram.dst_cid().is_empty()
            && let Some(&route) = self.connection_ids.get(&datagram.dst_cid())
        {
            return Some(route);
        }
        if (datagram.is_initial() || datagram.is_0rtt())
            && let Some(&route) = self.connection_ids_initial.get(&datagram.dst_cid())
        {
            return Some(route);
        }
        if datagram.dst_cid().is_empty() {
            if let Some(&route) = self.incoming_connection_remotes.get(addresses) {
                return Some(route);
            }
            if let Some(&ch) = self.outgoing_connection_remotes.get(&addresses.remote) {
                return Some(RouteDatagramTo::Connection(ch));
            }
        }
        let data = datagram.data();
        if data.len() < RESET_TOKEN_SIZE {
            return None;
        }
        self.connection_reset_tokens
            .get(addresses.remote, &data[data.len() - RESET_TOKEN_SIZE..])
            .cloned()
            .map(RouteDatagramTo::Connection)
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
    side: Side,
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
    received_at: Instant,
    addresses: FourTuple,
    ecn: Option<EcnCodepoint>,
    packet: InitialPacket,
    rest: Option<BytesMut>,
    crypto: Keys,
    token: IncomingToken,
    incoming_idx: usize,
    improper_drop_warner: IncomingImproperDropWarner,
}

impl Incoming {
    /// The local IP address which was used when the peer established the connection
    ///
    /// This has the same behavior as [`Connection::local_ip`].
    pub fn local_ip(&self) -> Option<IpAddr> {
        self.addresses.local_ip
    }

    /// The peer's UDP address
    pub fn remote_address(&self) -> SocketAddr {
        self.addresses.remote
    }

    /// Whether the socket address that is initiating this connection has been validated
    ///
    /// This means that the sender of the initial packet has proved that they can receive traffic
    /// sent to `self.remote_address()`.
    ///
    /// If `self.remote_address_validated()` is false, `self.may_retry()` is guaranteed to be true.
    /// The inverse is not guaranteed.
    pub fn remote_address_validated(&self) -> bool {
        self.token.validated
    }

    /// Whether it is legal to respond with a retry packet
    ///
    /// If `self.remote_address_validated()` is false, `self.may_retry()` is guaranteed to be true.
    /// The inverse is not guaranteed.
    pub fn may_retry(&self) -> bool {
        self.token.retry_src_cid.is_none()
    }

    /// The original destination connection ID sent by the client
    pub fn orig_dst_cid(&self) -> ConnectionId {
        self.token.orig_dst_cid
    }
}

impl fmt::Debug for Incoming {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Incoming")
            .field("addresses", &self.addresses)
            .field("ecn", &self.ecn)
            // packet doesn't implement debug
            // rest is too big and not meaningful enough
            .field("token", &self.token)
            .field("incoming_idx", &self.incoming_idx)
            // improper drop warner contains no information
            .finish_non_exhaustive()
    }
}

struct IncomingImproperDropWarner;

impl IncomingImproperDropWarner {
    fn dismiss(self) {
        mem::forget(self);
    }
}

impl Drop for IncomingImproperDropWarner {
    fn drop(&mut self) {
        warn!(
            "quinn_proto::Incoming dropped without passing to Endpoint::accept/refuse/retry/ignore \
               (may cause memory leak and eventual inability to accept new connections)"
        );
    }
}

/// Warns when an [`Accepting`] or [`Accepted`] is dropped before [`Endpoint::finish_accept()`]
struct AcceptDropGuard;

impl AcceptDropGuard {
    fn dismiss(self) {
        mem::forget(self);
    }
}

impl Drop for AcceptDropGuard {
    fn drop(&mut self) {
        warn!(
            "quinn_proto::Accepting or Accepted dropped before reaching Endpoint::finish_accept \
             (leaks connection IDs and buffered datagrams, and may cause eventual inability to \
             accept new connections)"
        );
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
    /// The given server name was malformed
    #[error("invalid server name: {0}")]
    InvalidServerName(String),
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

#[derive(Clone, Copy, Debug, Default)]
struct InitialSendState {
    next_packet_number: u64,
    #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
    bytes: u64,
    #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
    datagrams: u64,
}

/// State for reading a rustls QUIC ClientHello before choosing a server config.
#[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
#[allow(unnameable_types)] // internal split-accept API
pub struct RustlsAcceptor {
    tls: crypto::rustls::Acceptor,
    crypto_stream: Assembler,
    processed_first_packet: bool,
    processed_first_datagram_tail: bool,
    rx_packet: u64,
    authenticated_initials: ArrayRangeSet,
    authenticated_initial_count: u64,
    pending_initial_acks: ArrayRangeSet,
    ack_pending: bool,
}

#[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
impl RustlsAcceptor {
    /// Create a rustls acceptor for an incoming connection.
    ///
    /// If supplied, `input` must be empty. It receives all ordered TLS handshake data, starting
    /// with the first ClientHello, and is retained after server configuration selection.
    pub fn new(
        incoming: &Incoming,
        input: Option<Box<dyn crypto::rustls::QuicInputBuffer>>,
    ) -> Result<Self, UnsupportedVersion> {
        Ok(Self {
            tls: crypto::rustls::Acceptor::new(incoming.packet.header.version, input)?,
            crypto_stream: Assembler::new(),
            processed_first_packet: false,
            processed_first_datagram_tail: false,
            rx_packet: 0,
            authenticated_initials: ArrayRangeSet::new(),
            authenticated_initial_count: 0,
            pending_initial_acks: ArrayRangeSet::new(),
            ack_pending: false,
        })
    }

    #[cfg(test)]
    pub(crate) fn test_read_initial_payload(
        &mut self,
        payload: Bytes,
        packet_number: u64,
    ) -> Result<(), ConnectionError> {
        let payload_len = payload.len();
        self.read_initial_payload(payload, payload_len, usize::MAX, packet_number)?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn test_ack_pending(&self) -> bool {
        self.ack_pending
    }

    #[cfg(test)]
    pub(crate) fn test_read_initial_decode(
        &mut self,
        partial_decode: PartialDecode,
        crypto: &Keys,
        expected_src_cid: ConnectionId,
        expected_token: Bytes,
        expected_version: u32,
    ) -> Result<bool, ConnectionError> {
        Ok(self
            .read_initial_decode(
                partial_decode,
                crypto,
                usize::MAX,
                expected_src_cid,
                &expected_token,
                expected_version,
            )?
            .is_some())
    }

    #[allow(clippy::too_many_arguments)]
    fn read_initial_datagram(
        &mut self,
        first_decode: Option<PartialDecode>,
        mut remaining: Option<BytesMut>,
        crypto: &Keys,
        crypto_buffer_size: usize,
        cid_len: usize,
        version: u32,
        grease_quic_bit: bool,
        expected_src_cid: ConnectionId,
        expected_token: &Bytes,
    ) -> Result<Option<RustlsAccepted>, ConnectionError> {
        if let Some(partial_decode) = first_decode
            && partial_decode.initial_header().is_some()
            && let Some(accepted) = self.read_initial_decode(
                partial_decode,
                crypto,
                crypto_buffer_size,
                expected_src_cid,
                expected_token,
                version,
            )?
        {
            return Ok(Some(accepted));
        }

        while let Some(data) = remaining {
            let Ok((partial_decode, rest)) = PartialDecode::new(
                data,
                &FixedLengthConnectionIdParser::new(cid_len),
                &[version],
                grease_quic_bit,
            ) else {
                break;
            };
            remaining = rest;
            if partial_decode.initial_header().is_some()
                && let Some(accepted) = self.read_initial_decode(
                    partial_decode,
                    crypto,
                    crypto_buffer_size,
                    expected_src_cid,
                    expected_token,
                    version,
                )?
            {
                return Ok(Some(accepted));
            }
        }

        Ok(None)
    }

    fn read_initial_decode(
        &mut self,
        partial_decode: PartialDecode,
        crypto: &Keys,
        crypto_buffer_size: usize,
        expected_src_cid: ConnectionId,
        expected_token: &Bytes,
        expected_version: u32,
    ) -> Result<Option<RustlsAccepted>, ConnectionError> {
        let Ok(packet) = partial_decode.finish(Some(&*crypto.header.remote)) else {
            return Ok(None);
        };
        if !packet.reserved_bits_valid() {
            return Ok(None);
        }
        let Header::Initial(header) = packet.header else {
            return Ok(None);
        };
        if header.version != expected_version {
            debug!(
                version = header.version,
                expected_version, "discarding staged Initial with mismatched version"
            );
            return Ok(None);
        }
        let packet_number = header.number.expand(self.rx_packet + 1);
        let payload_len = packet.payload.len();
        let mut payload = packet.payload;
        if crypto
            .packet
            .remote
            .decrypt(packet_number, &packet.header_data, &mut payload)
            .is_err()
        {
            return Ok(None);
        }
        if header.src_cid != expected_src_cid {
            debug!(
                packet_number,
                "discarding staged Initial with mismatched client connection ID"
            );
            return Ok(None);
        }
        if header.token != expected_token {
            debug!(
                packet_number,
                "discarding staged Initial with mismatched Retry token"
            );
            return Ok(None);
        }
        if !self.authenticated_initials.insert_one(packet_number) {
            debug!(packet_number, "discarding duplicate staged Initial");
            return Ok(None);
        }
        self.authenticated_initial_count += 1;
        self.rx_packet = self.rx_packet.max(packet_number);
        self.read_authenticated_initial_payload(
            payload.freeze(),
            payload_len,
            crypto_buffer_size,
            packet_number,
        )
    }

    fn read_initial_payload(
        &mut self,
        payload: Bytes,
        payload_len: usize,
        crypto_buffer_size: usize,
        packet_number: u64,
    ) -> Result<Option<RustlsAccepted>, ConnectionError> {
        if !self.authenticated_initials.insert_one(packet_number) {
            debug!(packet_number, "discarding duplicate staged Initial");
            return Ok(None);
        }
        self.authenticated_initial_count += 1;
        self.rx_packet = self.rx_packet.max(packet_number);
        self.read_authenticated_initial_payload(
            payload,
            payload_len,
            crypto_buffer_size,
            packet_number,
        )
    }

    fn read_authenticated_initial_payload(
        &mut self,
        payload: Bytes,
        payload_len: usize,
        crypto_buffer_size: usize,
        packet_number: u64,
    ) -> Result<Option<RustlsAccepted>, ConnectionError> {
        let mut accepted = None;
        let mut ack_eliciting = false;
        for result in frame::Iter::new(payload)? {
            let frame = result.map_err(TransportError::from)?;
            ack_eliciting |= frame.is_ack_eliciting();
            match frame {
                frame::Frame::Crypto(frame) => {
                    let end = frame.offset + frame.data.len() as u64;
                    let max = end.saturating_sub(self.crypto_stream.bytes_read());
                    if max > crypto_buffer_size as u64 {
                        return Err(TransportError::CRYPTO_BUFFER_EXCEEDED("").into());
                    }

                    self.crypto_stream
                        .insert(frame.offset, frame.data.clone(), payload_len)
                        .map_err(|_| {
                            TransportError::INTERNAL_ERROR("too many gaps in crypto stream buffer")
                        })?;
                    while accepted.is_none() {
                        let Some(chunk) = self.crypto_stream.read(usize::MAX, true) else {
                            break;
                        };
                        accepted = self.tls.read_hs(&chunk.bytes)?.map(|tls| RustlsAccepted {
                            initial_crypto_offset: tls.initial_crypto_offset(),
                            tls,
                        });
                    }
                }
                frame::Frame::Padding | frame::Frame::Ping | frame::Frame::Ack(_) => {}
                frame::Frame::Close(frame::Close::Connection(reason)) => {
                    return Err(ConnectionError::ConnectionClosed(reason));
                }
                frame => {
                    let mut err =
                        TransportError::PROTOCOL_VIOLATION("illegal frame type in handshake");
                    err.frame = Some(frame.ty());
                    return Err(err.into());
                }
            }
        }

        self.pending_initial_acks.insert_one(packet_number);
        if self.pending_initial_acks.len() > MAX_ACK_BLOCKS {
            self.pending_initial_acks.pop_min();
        }
        self.ack_pending |= ack_eliciting;
        Ok(accepted)
    }
}

/// A rustls ClientHello and the state required to continue the QUIC handshake.
#[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
#[allow(unnameable_types)] // internal split-accept API
pub struct RustlsAccepted {
    tls: crypto::rustls::Accepted,
    initial_crypto_offset: u64,
}

#[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
impl RustlsAccepted {
    /// Get the rustls ClientHello for this connection.
    pub fn client_hello(&self) -> rustls::server::ClientHello<'_> {
        self.tls.client_hello()
    }
}

/// An incoming connection whose acceptance has begun, see [`Endpoint::start_accept()`]
///
/// Call [`accept()`](Self::accept) to construct the connection, and pass the result to
/// [`Endpoint::finish_accept()`]. Dropping this instead leaks the endpoint state reserved for the
/// connection, which is reported with a warning.
#[must_use = "must be completed with `Accepting::accept` and `Endpoint::finish_accept`"]
pub struct Accepting {
    incoming_idx: usize,
    // The first packet, processed once the connection is constructed
    packet_number: u64,
    packet: InitialPacket,
    rest: Option<BytesMut>,
    ecn: Option<EcnCodepoint>,
    // Initial keys, retained to send a close if the handshake fails
    crypto: Keys,
    #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
    token: IncomingToken,
    // Inputs to connection construction
    server_crypto: Arc<dyn crypto::ServerConfig>,
    params: TransportParameters,
    args: ConnectionArgs,
    initial_sends: InitialSendState,
    #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
    last_activity: Instant,
    #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
    rustls_buffered_datagrams: usize,
    #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
    rustls_input: VecDeque<DatagramConnectionEvent>,
    guard: AcceptDropGuard,
}

impl Accepting {
    /// Construct the connection and process its first packet
    ///
    /// This is the computationally expensive part of accepting a connection and requires no
    /// access to the [`Endpoint`]. The result must be passed to [`Endpoint::finish_accept()`]
    /// whether or not the first packet was processed successfully.
    pub fn accept(self) -> Accepted {
        let Self {
            incoming_idx,
            packet_number,
            packet,
            rest,
            ecn,
            crypto,
            server_crypto,
            params,
            args,
            initial_sends,
            guard,
            ..
        } = self;
        // Copy out what `finish_accept` needs before `args` is consumed
        let &ConnectionArgs {
            init_cid,
            loc_cid,
            rem_cid: src_cid,
            remote,
            local_ip,
            now,
            version,
            ..
        } = &args;
        let pref_addr_cid = args.side_args.pref_addr_cid();

        let tls = server_crypto.start_session(version, &params);
        let mut conn = Connection::new(tls, args);
        let result = conn
            .handle_first_packet(now, remote, ecn, packet_number, packet, rest)
            .map(|()| conn);

        Accepted {
            incoming_idx,
            init_cid,
            loc_cid,
            pref_addr_cid,
            addresses: FourTuple { remote, local_ip },
            version,
            src_cid,
            crypto,
            initial_sends,
            result,
            guard,
        }
    }

    #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
    fn server_config(&self) -> &Arc<ServerConfig> {
        match &self.args.side_args {
            SideArgs::Server { server_config, .. } => server_config,
            SideArgs::Client { .. } => unreachable!("accepting a client connection"),
        }
    }

    #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
    fn fail(self, cause: ConnectionError) -> Accepted {
        let pref_addr_cid = self.args.side_args.pref_addr_cid();
        Accepted {
            incoming_idx: self.incoming_idx,
            init_cid: self.args.init_cid,
            loc_cid: self.args.loc_cid,
            pref_addr_cid,
            addresses: FourTuple {
                remote: self.args.remote,
                local_ip: self.args.local_ip,
            },
            version: self.args.version,
            src_cid: self.args.rem_cid,
            crypto: self.crypto,
            initial_sends: self.initial_sends,
            result: Err(cause),
            guard: self.guard,
        }
    }

    /// Identifier used to route datagrams and wake this exact pending accept.
    #[doc(hidden)]
    pub fn incoming_idx(&self) -> usize {
        self.incoming_idx
    }

    /// Deadline imposed by the currently selected server config's idle timeout.
    #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
    #[doc(hidden)]
    pub fn idle_timeout_deadline(&self) -> Option<Instant> {
        let timeout = self.server_config().transport.max_idle_timeout?;
        let millis = timeout.into_inner();
        (millis != 0).then(|| self.last_activity + Duration::from_millis(millis))
    }

    #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
    fn observe_authenticated_activity(
        &mut self,
        received_at: Instant,
    ) -> Result<(), ConnectionError> {
        if self
            .idle_timeout_deadline()
            .is_some_and(|deadline| received_at >= deadline)
        {
            return Err(ConnectionError::TimedOut);
        }
        self.last_activity = self.last_activity.max(received_at);
        Ok(())
    }

    /// Authenticate newly buffered Initials, feed contiguous CRYPTO data to rustls, and encode an
    /// optional ACK without holding the endpoint lock.
    #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
    #[doc(hidden)]
    pub fn poll_rustls_acceptor(
        &mut self,
        acceptor: &mut RustlsAcceptor,
        buf: &mut Vec<u8>,
    ) -> Result<(Option<RustlsAccepted>, Option<Transmit>), ConnectionError> {
        let crypto_buffer_size = self.server_config().transport.crypto_buffer_size;
        let mut accepted = None;

        if !acceptor.processed_first_packet {
            acceptor.processed_first_packet = true;
            let before = acceptor.authenticated_initial_count;
            accepted = acceptor.read_initial_payload(
                self.packet.payload.clone().freeze(),
                self.packet.payload.len(),
                crypto_buffer_size,
                self.packet_number,
            )?;
            if acceptor.authenticated_initial_count != before {
                self.observe_authenticated_activity(self.args.now)?;
            }
        }

        if accepted.is_none() && !acceptor.processed_first_datagram_tail {
            acceptor.processed_first_datagram_tail = true;
            let before = acceptor.authenticated_initial_count;
            accepted = acceptor.read_initial_datagram(
                None,
                self.rest.clone(),
                &self.crypto,
                crypto_buffer_size,
                self.args.local_cid_len,
                self.args.version,
                self.args.endpoint_config.grease_quic_bit,
                self.args.rem_cid,
                &self.packet.header.token,
            )?;
            if acceptor.authenticated_initial_count != before {
                self.observe_authenticated_activity(self.args.now)?;
            }
        }

        while accepted.is_none() {
            let Some(event) = self.rustls_input.pop_front() else {
                break;
            };
            let before = acceptor.authenticated_initial_count;
            let received_at = event.now;
            accepted = acceptor.read_initial_datagram(
                Some(event.first_decode),
                event.remaining,
                &self.crypto,
                crypto_buffer_size,
                self.args.local_cid_len,
                self.args.version,
                self.args.endpoint_config.grease_quic_bit,
                self.args.rem_cid,
                &self.packet.header.token,
            )?;
            if acceptor.authenticated_initial_count != before {
                self.observe_authenticated_activity(received_at)?;
            }
        }

        let response = self.poll_rustls_initial_ack(acceptor, buf);
        Ok((accepted, response))
    }

    #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
    fn poll_rustls_initial_ack(
        &mut self,
        acceptor: &mut RustlsAcceptor,
        buf: &mut Vec<u8>,
    ) -> Option<Transmit> {
        if !acceptor.ack_pending || acceptor.pending_initial_acks.is_empty() {
            return None;
        }

        let packet_number = self.initial_sends.next_packet_number;
        self.initial_sends.next_packet_number += 1;
        let header = Header::Initial(InitialHeader {
            dst_cid: self.args.rem_cid,
            src_cid: self.args.loc_cid,
            number: PacketNumber::new(packet_number, 0),
            token: Bytes::new(),
            version: self.args.version,
        });

        let packet_start = buf.len();
        let partial_encode = header.encode(buf);
        frame::Ack::encode(0, &acceptor.pending_initial_acks, None, buf);
        buf.resize(buf.len() + self.crypto.packet.local.tag_len(), 0);
        partial_encode.finish(
            buf,
            &*self.crypto.header.local,
            Some((packet_number, &*self.crypto.packet.local)),
        );
        acceptor.pending_initial_acks = ArrayRangeSet::new();
        acceptor.ack_pending = false;

        self.initial_sends.bytes = self
            .initial_sends
            .bytes
            .saturating_add((buf.len() - packet_start) as u64);
        self.initial_sends.datagrams = self.initial_sends.datagrams.saturating_add(1);

        Some(Transmit {
            destination: self.args.remote,
            ecn: None,
            size: buf.len(),
            segment_size: None,
            src_ip: self.args.local_ip,
        })
    }

    /// Continue a split accept from a rustls handshake paused after ClientHello.
    #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
    #[doc(hidden)]
    pub fn finish_from_rustls(self, accepted: RustlsAccepted) -> Accepted {
        let tls = match self.server_crypto.clone().start_session_from_accepted(
            self.args.version,
            &self.params,
            accepted.tls,
        ) {
            Ok(tls) => tls,
            Err(error) => return self.fail(error.into()),
        };

        let Self {
            incoming_idx,
            packet_number,
            packet,
            rest,
            ecn,
            crypto,
            args,
            initial_sends,
            guard,
            ..
        } = self;
        let &ConnectionArgs {
            init_cid,
            loc_cid,
            rem_cid: src_cid,
            remote,
            local_ip,
            now,
            version,
            ..
        } = &args;
        let pref_addr_cid = args.side_args.pref_addr_cid();

        let mut conn = Connection::new(tls, args);
        conn.skip_initial_crypto(accepted.initial_crypto_offset);
        conn.seed_staged_initial_sends(
            initial_sends.next_packet_number,
            initial_sends.bytes,
            initial_sends.datagrams,
        );
        let result = conn
            .handle_first_packet(now, remote, ecn, packet_number, packet, rest)
            .map(|()| conn);

        Accepted {
            incoming_idx,
            init_cid,
            loc_cid,
            pref_addr_cid,
            addresses: FourTuple { remote, local_ip },
            version,
            src_cid,
            crypto,
            initial_sends,
            result,
            guard,
        }
    }
}

impl fmt::Debug for Accepting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Accepting")
            .field("incoming_idx", &self.incoming_idx)
            .field("init_cid", &self.args.init_cid)
            .field("remote", &self.args.remote)
            .finish_non_exhaustive()
    }
}

/// The outcome of [`Accepting::accept()`], to be passed to [`Endpoint::finish_accept()`]
///
/// Dropping this leaks the endpoint state reserved for the connection, which is reported with a
/// warning.
#[must_use = "must be passed to `Endpoint::finish_accept`"]
pub struct Accepted {
    // Endpoint state reserved by `start_accept`, re-pointed at the connection or released by
    // `finish_accept`
    incoming_idx: usize,
    init_cid: ConnectionId,
    loc_cid: ConnectionId,
    pref_addr_cid: Option<ConnectionId>,
    addresses: FourTuple,
    // For the close response if the handshake failed
    version: u32,
    src_cid: ConnectionId,
    crypto: Keys,
    initial_sends: InitialSendState,
    result: Result<Connection, ConnectionError>,
    guard: AcceptDropGuard,
}

impl fmt::Debug for Accepted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Accepted")
            .field("incoming_idx", &self.incoming_idx)
            .field("init_cid", &self.init_cid)
            .field("remote", &self.addresses.remote)
            .field("result", &self.result)
            .finish_non_exhaustive()
    }
}

/// Error for attempting to retry an [`Incoming`] which already bears a token from a previous retry
#[derive(Debug, Error)]
#[error("retry() with validated Incoming")]
pub struct RetryError(Box<Incoming>);

impl RetryError {
    /// Get the [`Incoming`]
    pub fn into_incoming(self) -> Incoming {
        *self.0
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
