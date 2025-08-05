use std::{
    collections::{HashMap, VecDeque, hash_map},
    convert::TryFrom,
    fmt, mem,
    net::{IpAddr, SocketAddr},
    ops::{Index, IndexMut},
    sync::Arc,
};

use indexmap::IndexMap;

use bytes::{BufMut, Bytes, BytesMut};
use rand::{Rng, RngCore, SeedableRng, rngs::StdRng};
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
    connection::{Connection, ConnectionError, SideArgs},
    crypto::{self, Keys, UnsupportedVersion},
    frame,
    nat_traversal_api::PeerId,
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

/// A queued relay request for bootstrap nodes
#[derive(Debug, Clone)]
struct RelayQueueItem {
    /// Target peer ID for the relay
    target_peer_id: PeerId,
    /// Frame to be relayed
    frame: frame::PunchMeNow,
    /// When this relay request was created
    created_at: Instant,
    /// Number of relay attempts made
    attempts: u32,
    /// Last attempt time
    last_attempt: Option<Instant>,
}

/// Relay queue management for bootstrap nodes
#[derive(Debug)]
struct RelayQueue {
    /// Pending relay requests with insertion order and O(1) access
    pending: IndexMap<u64, RelayQueueItem>,
    /// Next sequence number for insertion order
    next_seq: u64,
    /// Maximum queue size to prevent memory exhaustion
    max_queue_size: usize,
    /// Timeout for relay requests
    request_timeout: Duration,
    /// Maximum retry attempts per request
    max_retries: u32,
    /// Minimum interval between retry attempts
    retry_interval: Duration,
    /// Rate limiting: track recent relay requests per peer
    rate_limiter: HashMap<PeerId, VecDeque<Instant>>,
    /// Maximum relays per peer per time window
    max_relays_per_peer: usize,
    /// Rate limiting time window
    rate_limit_window: Duration,
}

/// Address discovery statistics
#[derive(Debug, Default, Clone)]
pub struct AddressDiscoveryStats {
    /// Number of OBSERVED_ADDRESS frames sent
    pub frames_sent: u64,
    /// Number of OBSERVED_ADDRESS frames received
    pub frames_received: u64,
    /// Number of unique addresses discovered
    pub addresses_discovered: u64,
    /// Number of address changes detected
    pub address_changes_detected: u64,
}

/// Relay statistics for monitoring and debugging
#[derive(Debug, Default)]
pub struct RelayStats {
    /// Total relay requests received
    requests_received: u64,
    /// Successfully relayed requests
    requests_relayed: u64,
    /// Failed relay requests (peer not found)
    requests_failed: u64,
    /// Requests dropped due to queue full
    requests_dropped: u64,
    /// Requests timed out
    requests_timed_out: u64,
    /// Requests dropped due to rate limiting
    requests_rate_limited: u64,
    /// Current queue size
    current_queue_size: usize,
}

impl RelayQueue {
    /// Create a new relay queue with default settings
    fn new() -> Self {
        Self {
            pending: IndexMap::new(),
            next_seq: 0,
            max_queue_size: 1000,                     // Reasonable default
            request_timeout: Duration::from_secs(30), // 30 second timeout
            max_retries: 3,
            retry_interval: Duration::from_millis(500), // 500ms between retries
            rate_limiter: HashMap::new(),
            max_relays_per_peer: 10, // Max 10 relays per peer per time window
            rate_limit_window: Duration::from_secs(60), // 1 minute window
        }
    }

    /// Add a relay request to the queue
    fn enqueue(&mut self, target_peer_id: PeerId, frame: frame::PunchMeNow, now: Instant) -> bool {
        // Check queue size limit
        if self.pending.len() >= self.max_queue_size {
            warn!(
                "Relay queue full, dropping request for peer {:?}",
                target_peer_id
            );
            return false;
        }

        // Check rate limit for this peer
        if !self.check_rate_limit(target_peer_id, now) {
            warn!(
                "Rate limit exceeded for peer {:?}, dropping relay request",
                target_peer_id
            );
            return false;
        }

        let item = RelayQueueItem {
            target_peer_id,
            frame,
            created_at: now,
            attempts: 0,
            last_attempt: None,
        };

        let seq = self.next_seq;
        self.next_seq += 1;
        self.pending.insert(seq, item);

        // Record this request for rate limiting
        self.record_relay_request(target_peer_id, now);

        trace!(
            "Queued relay request for peer {:?}, queue size: {}",
            target_peer_id,
            self.pending.len()
        );
        true
    }

    /// Check if a relay request is within rate limits
    fn check_rate_limit(&mut self, peer_id: PeerId, now: Instant) -> bool {
        // Clean up old entries first
        self.cleanup_rate_limiter(now);

        // Check current request count for this peer
        if let Some(requests) = self.rate_limiter.get(&peer_id) {
            requests.len() < self.max_relays_per_peer
        } else {
            true // No previous requests, allow
        }
    }

    /// Record a relay request for rate limiting
    fn record_relay_request(&mut self, peer_id: PeerId, now: Instant) {
        self.rate_limiter.entry(peer_id).or_default().push_back(now);
    }

    /// Clean up old rate limiting entries
    fn cleanup_rate_limiter(&mut self, now: Instant) {
        self.rate_limiter.retain(|_, requests| {
            requests.retain(|&request_time| {
                now.saturating_duration_since(request_time) <= self.rate_limit_window
            });
            !requests.is_empty()
        });
    }

    /// Get the next relay request that's ready to be processed
    fn next_ready(&mut self, now: Instant) -> Option<RelayQueueItem> {
        // Find the first request that's ready to be retried
        let mut expired_keys = Vec::new();
        let mut ready_key = None;

        for (seq, item) in &self.pending {
            // Check if request has timed out
            if now.saturating_duration_since(item.created_at) > self.request_timeout {
                expired_keys.push(*seq);
                continue;
            }

            // Check if it's ready for retry
            if item.attempts == 0
                || item
                    .last_attempt
                    .is_none_or(|last| now.saturating_duration_since(last) >= self.retry_interval)
            {
                ready_key = Some(*seq);
                break;
            }
        }

        // Remove expired items
        for key in expired_keys {
            if let Some(expired) = self.pending.shift_remove(&key) {
                debug!(
                    "Relay request for peer {:?} timed out after {:?}",
                    expired.target_peer_id,
                    now.saturating_duration_since(expired.created_at)
                );
            }
        }

        // Return ready item if found
        if let Some(key) = ready_key {
            if let Some(mut item) = self.pending.shift_remove(&key) {
                item.attempts += 1;
                item.last_attempt = Some(now);
                return Some(item);
            }
        }

        None
    }

    /// Requeue a failed relay request if it hasn't exceeded max retries
    fn requeue_failed(&mut self, item: RelayQueueItem) {
        if item.attempts < self.max_retries {
            trace!(
                "Requeuing failed relay request for peer {:?}, attempt {}/{}",
                item.target_peer_id, item.attempts, self.max_retries
            );
            let seq = self.next_seq;
            self.next_seq += 1;
            self.pending.insert(seq, item);
        } else {
            debug!(
                "Dropping relay request for peer {:?} after {} failed attempts",
                item.target_peer_id, item.attempts
            );
        }
    }

    /// Clean up expired requests and return number of items cleaned
    fn cleanup_expired(&mut self, now: Instant) -> usize {
        let initial_len = self.pending.len();

        // Collect expired keys
        let expired_keys: Vec<u64> = self
            .pending
            .iter()
            .filter_map(|(seq, item)| {
                if now.saturating_duration_since(item.created_at) > self.request_timeout {
                    Some(*seq)
                } else {
                    None
                }
            })
            .collect();

        // Remove expired items
        for key in expired_keys {
            if let Some(expired) = self.pending.shift_remove(&key) {
                debug!(
                    "Removing expired relay request for peer {:?}",
                    expired.target_peer_id
                );
            }
        }

        initial_len - self.pending.len()
    }

    /// Get current queue length
    fn len(&self) -> usize {
        self.pending.len()
    }
}

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
    /// Mapping from peer IDs to connection handles for relay functionality
    peer_connections: HashMap<PeerId, ConnectionHandle>,
    /// Relay queue for bootstrap nodes
    relay_queue: RelayQueue,
    /// Relay statistics
    relay_stats: RelayStats,
    /// Whether address discovery is enabled (default: true)
    address_discovery_enabled: bool,
    /// Address change callback
    address_change_callback: Option<Box<dyn Fn(Option<SocketAddr>, SocketAddr) + Send + Sync>>,
}

impl Endpoint {
    /// Create a new endpoint
    ///
    /// `allow_mtud` enables path MTU detection when requested by `Connection` configuration for
    /// better performance. This requires that outgoing packets are never fragmented, which can be
    /// achieved via e.g. the `IPV6_DONTFRAG` socket option.
    ///
    /// If `rng_seed` is provided, it will be used to initialize the endpoint's rng (having priority
    /// over the rng seed configured in [`EndpointConfig`]). Note that the `rng_seed` parameter will
    /// be removed in a future release, so prefer setting it to `None` and configuring rng seeds
    /// using [`EndpointConfig::rng_seed`].
    pub fn new(
        config: Arc<EndpointConfig>,
        server_config: Option<Arc<ServerConfig>>,
        allow_mtud: bool,
        rng_seed: Option<[u8; 32]>,
    ) -> Self {
        let rng_seed = rng_seed.or(config.rng_seed);
        Self {
            rng: rng_seed.map_or(StdRng::from_entropy(), StdRng::from_seed),
            index: ConnectionIndex::default(),
            connections: Slab::new(),
            local_cid_generator: (config.connection_id_generator_factory.as_ref())(),
            config,
            server_config,
            allow_mtud,
            last_stateless_reset: None,
            incoming_buffers: Slab::new(),
            all_incoming_buffers_total_bytes: 0,
            peer_connections: HashMap::new(),
            relay_queue: RelayQueue::new(),
            relay_stats: RelayStats::default(),
            address_discovery_enabled: true, // Default to enabled
            address_change_callback: None,
        }
    }

    /// Replace the server configuration, affecting new incoming connections only
    pub fn set_server_config(&mut self, server_config: Option<Arc<ServerConfig>>) {
        self.server_config = server_config;
    }

    /// Register a peer ID with a connection handle for relay functionality
    pub fn register_peer(&mut self, peer_id: PeerId, connection_handle: ConnectionHandle) {
        self.peer_connections.insert(peer_id, connection_handle);
        trace!(
            "Registered peer {:?} with connection {:?}",
            peer_id, connection_handle
        );
    }

    /// Unregister a peer ID from the connection mapping
    pub fn unregister_peer(&mut self, peer_id: &PeerId) {
        if let Some(handle) = self.peer_connections.remove(peer_id) {
            trace!(
                "Unregistered peer {:?} from connection {:?}",
                peer_id, handle
            );
        }
    }

    /// Look up a connection handle for a given peer ID
    pub fn lookup_peer_connection(&self, peer_id: &PeerId) -> Option<ConnectionHandle> {
        self.peer_connections.get(peer_id).copied()
    }

    /// Queue a frame for relay to a target peer
    pub(crate) fn queue_frame_for_peer(
        &mut self,
        peer_id: &PeerId,
        frame: frame::PunchMeNow,
    ) -> bool {
        self.relay_stats.requests_received += 1;

        if let Some(ch) = self.lookup_peer_connection(peer_id) {
            // Peer is currently connected, try to relay immediately
            if self.relay_frame_to_connection(ch, frame.clone()) {
                self.relay_stats.requests_relayed += 1;
                trace!(
                    "Immediately relayed frame to peer {:?} via connection {:?}",
                    peer_id, ch
                );
                return true;
            }
        }

        // Peer not connected or immediate relay failed, queue for later
        let now = Instant::now();
        if self.relay_queue.enqueue(*peer_id, frame, now) {
            self.relay_stats.current_queue_size = self.relay_queue.len();
            trace!("Queued relay request for peer {:?}", peer_id);
            true
        } else {
            // Check if it was rate limited or queue full
            if !self.relay_queue.check_rate_limit(*peer_id, now) {
                self.relay_stats.requests_rate_limited += 1;
            } else {
                self.relay_stats.requests_dropped += 1;
            }
            false
        }
    }

    /// Attempt to relay a frame to a specific connection
    fn relay_frame_to_connection(
        &mut self,
        ch: ConnectionHandle,
        _frame: frame::PunchMeNow,
    ) -> bool {
        // In a complete implementation, this would queue the frame in the connection's
        // pending frames. For now, we'll just return true to indicate success.
        // The actual frame queuing would need to be implemented at the connection level.

        // TODO: Implement actual frame queuing to connection's pending frames
        trace!("Would relay frame to connection {:?}", ch);
        true
    }

    /// Set the peer ID for an existing connection
    pub fn set_connection_peer_id(&mut self, connection_handle: ConnectionHandle, peer_id: PeerId) {
        if let Some(connection) = self.connections.get_mut(connection_handle.0) {
            connection.peer_id = Some(peer_id);
            self.register_peer(peer_id, connection_handle);

            // Process any queued relay requests for this peer
            self.process_queued_relays_for_peer(peer_id);
        }
    }

    /// Process queued relay requests for a specific peer that just connected
    fn process_queued_relays_for_peer(&mut self, peer_id: PeerId) {
        let _now = Instant::now();
        let mut processed = 0;

        // Collect items to process for this peer
        let mut items_to_process = Vec::new();
        let mut keys_to_remove = Vec::new();

        // Find all items for this peer
        for (seq, item) in &self.relay_queue.pending {
            if item.target_peer_id == peer_id {
                items_to_process.push(item.clone());
                keys_to_remove.push(*seq);
            }
        }

        // Remove items from queue
        for key in keys_to_remove {
            self.relay_queue.pending.shift_remove(&key);
        }

        // Process the items
        for item in items_to_process {
            if let Some(ch) = self.lookup_peer_connection(&peer_id) {
                if self.relay_frame_to_connection(ch, item.frame.clone()) {
                    self.relay_stats.requests_relayed += 1;
                    processed += 1;
                    trace!("Processed queued relay for peer {:?}", peer_id);
                } else {
                    // Failed to relay, requeue
                    self.relay_queue.requeue_failed(item);
                    self.relay_stats.requests_failed += 1;
                }
            }
        }

        self.relay_stats.current_queue_size = self.relay_queue.len();

        if processed > 0 {
            debug!(
                "Processed {} queued relay requests for peer {:?}",
                processed, peer_id
            );
        }
    }

    /// Process pending relay requests (should be called periodically)
    pub fn process_relay_queue(&mut self) {
        let now = Instant::now();
        let mut processed = 0;
        let mut failed = 0;

        // Process ready relay requests
        while let Some(item) = self.relay_queue.next_ready(now) {
            if let Some(ch) = self.lookup_peer_connection(&item.target_peer_id) {
                if self.relay_frame_to_connection(ch, item.frame.clone()) {
                    self.relay_stats.requests_relayed += 1;
                    processed += 1;
                    trace!(
                        "Successfully relayed frame to peer {:?}",
                        item.target_peer_id
                    );
                } else {
                    // Failed to relay, requeue for retry
                    self.relay_queue.requeue_failed(item);
                    self.relay_stats.requests_failed += 1;
                    failed += 1;
                }
            } else {
                // Peer not connected, requeue for later
                self.relay_queue.requeue_failed(item);
                failed += 1;
            }
        }

        // Clean up expired requests
        let expired = self.relay_queue.cleanup_expired(now);
        if expired > 0 {
            self.relay_stats.requests_timed_out += expired as u64;
            debug!("Cleaned up {} expired relay requests", expired);
        }

        self.relay_stats.current_queue_size = self.relay_queue.len();

        if processed > 0 || failed > 0 {
            trace!(
                "Relay queue processing: {} processed, {} failed, {} in queue",
                processed,
                failed,
                self.relay_queue.len()
            );
        }
    }

    /// Get relay statistics for monitoring
    pub fn relay_stats(&self) -> &RelayStats {
        &self.relay_stats
    }

    /// Get relay queue length
    pub fn relay_queue_len(&self) -> usize {
        self.relay_queue.len()
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
            EndpointEventInner::NeedIdentifiers(now, n) => {
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
            RelayPunchMeNow(target_peer_id, punch_me_now) => {
                // Handle relay request from bootstrap node
                let peer_id = PeerId(target_peer_id);
                if self.queue_frame_for_peer(&peer_id, punch_me_now) {
                    trace!(
                        "Successfully queued PunchMeNow frame for relay to peer {:?}",
                        peer_id
                    );
                } else {
                    warn!("Failed to queue PunchMeNow relay for peer {:?}", peer_id);
                }
            }
            SendAddressFrame(add_address_frame) => {
                // Handle bootstrap node request to send ADD_ADDRESS frame
                trace!(
                    "Sending ADD_ADDRESS frame: seq={}, addr={}, priority={}",
                    add_address_frame.sequence,
                    add_address_frame.address,
                    add_address_frame.priority
                );

                // For now, log the frame since the queuing mechanism needs more integration
                // TODO: Implement proper frame queuing in the connection layer
                debug!(
                    "ADD_ADDRESS frame ready for transmission: {:?}",
                    add_address_frame
                );
            }
            NatCandidateValidated { address, challenge } => {
                // Handle successful NAT traversal candidate validation
                trace!(
                    "NAT candidate validation succeeded for {} with challenge {:016x}",
                    address, challenge
                );

                // The validation success is primarily handled by the connection-level state machine
                // This event serves as notification to the endpoint for potential coordination
                // with other components or logging/metrics collection
                debug!("NAT candidate {} validated successfully", address);
            }
            Drained => {
                if let Some(conn) = self.connections.try_remove(ch.0) {
                    self.index.remove(&conn);
                    // Clean up peer connection mapping if this connection has a peer ID
                    if let Some(peer_id) = conn.peer_id {
                        self.peer_connections.remove(&peer_id);
                        trace!("Cleaned up peer connection mapping for {:?}", peer_id);
                    }
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
                trace!("sending version negotiation");
                // Negotiate versions
                Header::VersionNegotiate {
                    random: self.rng.r#gen::<u8>() | 0x40,
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
                    let config = &self.server_config.as_ref().unwrap();

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
            // If we got this far, we're receiving a seemingly valid packet for an unknown
            // connection. Send a stateless reset if possible.

            debug!("dropping packet with invalid CID");
            None
        } else if dst_cid.is_empty() {
            trace!("dropping unrecognized short packet without ID");
            None
        } else {
            self.stateless_reset(now, datagram_len, addresses, *dst_cid, buf)
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
            self.rng.gen_range(IDEAL_MIN_PADDING_LEN..max_padding_len)
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
        let loc_cid = self.new_cid(ch);
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
            let id = self.new_cid(ch);
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

    /// Generate a connection ID for `ch`
    fn new_cid(&mut self, ch: ConnectionHandle) -> ConnectionId {
        loop {
            let cid = self.local_cid_generator.generate_cid();
            if cid.is_empty() {
                // Zero-length CID; nothing to track
                debug_assert_eq!(self.local_cid_generator.cid_len(), 0);
                return cid;
            }
            if let hash_map::Entry::Vacant(e) = self.index.connection_ids.entry(cid) {
                e.insert(ch);
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
                .stateless_reset(event.now, datagram_len, addresses, *dst_cid, buf)
                .map(DatagramEvent::Response);
        };

        if datagram_len < MIN_INITIAL_SIZE as usize {
            debug!("ignoring short initial for connection {}", dst_cid);
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
                &header.src_cid,
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
                    &header.src_cid,
                    TransportError::INVALID_TOKEN(""),
                    buf,
                )));
            }
        };

        let incoming_idx = self.incoming_buffers.insert(IncomingBuffer::default());
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
    // AcceptError cannot be made smaller without semver breakage
    #[allow(clippy::result_large_err)]
    pub fn accept(
        &mut self,
        mut incoming: Incoming,
        now: Instant,
        buf: &mut Vec<u8>,
        server_config: Option<Arc<ServerConfig>>,
    ) -> Result<(ConnectionHandle, Connection), AcceptError> {
        let remote_address_validated = incoming.remote_address_validated();
        incoming.improper_drop_warner.dismiss();
        let incoming_buffer = self.incoming_buffers.remove(incoming.incoming_idx);
        self.all_incoming_buffers_total_bytes -= incoming_buffer.total_bytes;

        let packet_number = incoming.packet.header.number.expand(0);
        let InitialHeader {
            src_cid,
            dst_cid,
            version,
            ..
        } = incoming.packet.header;
        let server_config =
            server_config.unwrap_or_else(|| self.server_config.as_ref().unwrap().clone());

        if server_config
            .transport
            .max_idle_timeout
            .is_some_and(|timeout| {
                incoming.received_at + Duration::from_millis(timeout.into()) <= now
            })
        {
            debug!("abandoning accept of stale initial");
            self.index.remove_initial(dst_cid);
            return Err(AcceptError {
                cause: ConnectionError::TimedOut,
                response: None,
            });
        }

        if self.cids_exhausted() {
            debug!("refusing connection");
            self.index.remove_initial(dst_cid);
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
            self.index.remove_initial(dst_cid);
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
            &mut self.rng,
        );
        params.stateless_reset_token = Some(ResetToken::new(&*self.config.reset_key, loc_cid));
        params.original_dst_cid = Some(incoming.token.orig_dst_cid);
        params.retry_src_cid = incoming.token.retry_src_cid;
        let mut pref_addr_cid = None;
        if server_config.has_preferred_address() {
            let cid = self.new_cid(ch);
            pref_addr_cid = Some(cid);
            params.preferred_address = Some(PreferredAddress {
                address_v4: server_config.preferred_address_v4,
                address_v6: server_config.preferred_address_v6,
                connection_id: cid,
                stateless_reset_token: ResetToken::new(&*self.config.reset_key, cid),
            });
        }

        let tls = server_config.crypto.clone().start_session(version, &params);
        let transport_config = server_config.transport.clone();
        let mut conn = self.add_connection(
            ch,
            version,
            dst_cid,
            loc_cid,
            src_cid,
            incoming.addresses,
            incoming.received_at,
            tls,
            transport_config,
            SideArgs::Server {
                server_config,
                pref_addr_cid,
                path_validated: remote_address_validated,
            },
        );
        self.index.insert_initial(dst_cid, ch);

        match conn.handle_first_packet(
            incoming.received_at,
            incoming.addresses.remote,
            incoming.ecn,
            packet_number,
            incoming.packet,
            incoming.rest,
        ) {
            Ok(()) => {
                trace!(id = ch.0, icid = %dst_cid, "new connection");

                for event in incoming_buffer.datagrams {
                    conn.handle_event(ConnectionEvent(ConnectionEventInner::Datagram(event)))
                }

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
        header: &ProtectedInitialHeader,
    ) -> Result<(), TransportError> {
        let config = &self.server_config.as_ref().unwrap();
        if self.cids_exhausted() || self.incoming_buffers.len() >= config.max_incoming {
            return Err(TransportError::CONNECTION_REFUSED(""));
        }

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
        self.clean_up_incoming(&incoming);
        incoming.improper_drop_warner.dismiss();

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
    /// Errors if `incoming.may_retry()` is false.
    pub fn retry(&mut self, incoming: Incoming, buf: &mut Vec<u8>) -> Result<Transmit, RetryError> {
        if !incoming.may_retry() {
            return Err(RetryError(Box::new(incoming)));
        }

        self.clean_up_incoming(&incoming);
        incoming.improper_drop_warner.dismiss();

        let server_config = self.server_config.as_ref().unwrap();

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

    /// Ignore this incoming connection attempt, not sending any packet in response
    ///
    /// Doing this actively, rather than merely dropping the [`Incoming`], is necessary to prevent
    /// memory leaks due to state within [`Endpoint`] tracking the incoming connection.
    pub fn ignore(&mut self, incoming: Incoming) {
        self.clean_up_incoming(&incoming);
        incoming.improper_drop_warner.dismiss();
    }

    /// Clean up endpoint data structures associated with an `Incoming`.
    fn clean_up_incoming(&mut self, incoming: &Incoming) {
        self.index.remove_initial(incoming.packet.header.dst_cid);
        let incoming_buffer = self.incoming_buffers.remove(incoming.incoming_idx);
        self.all_incoming_buffers_total_bytes -= incoming_buffer.total_bytes;
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
            self.config.clone(),
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
            side_args,
        );

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
            peer_id: None,
        });
        debug_assert_eq!(id, ch.0, "connection handle allocation out of sync");

        self.index.insert_conn(addresses, loc_cid, ch, side);

        conn
    }

    fn initial_close(
        &mut self,
        version: u32,
        addresses: FourTuple,
        crypto: &Keys,
        remote_id: &ConnectionId,
        reason: TransportError,
        buf: &mut Vec<u8>,
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

    /// Enable or disable address discovery for this endpoint
    ///
    /// Address discovery is enabled by default. When enabled, the endpoint will:
    /// - Send OBSERVED_ADDRESS frames to peers to inform them of their reflexive addresses
    /// - Process received OBSERVED_ADDRESS frames to learn about its own reflexive addresses
    /// - Integrate discovered addresses with NAT traversal for improved connectivity
    pub fn enable_address_discovery(&mut self, enabled: bool) {
        self.address_discovery_enabled = enabled;
        // Note: Existing connections will continue with their current setting.
        // New connections will use the updated setting.
    }

    /// Check if address discovery is enabled
    pub fn address_discovery_enabled(&self) -> bool {
        self.address_discovery_enabled
    }

    /// Get all discovered addresses across all connections
    ///
    /// Returns a list of unique socket addresses that have been observed
    /// by remote peers and reported via OBSERVED_ADDRESS frames.
    ///
    /// Note: This returns an empty vector in the current implementation.
    /// Applications should track discovered addresses at the connection level.
    pub fn discovered_addresses(&self) -> Vec<SocketAddr> {
        // TODO: Implement address tracking at the endpoint level
        Vec::new()
    }

    /// Set a callback to be invoked when an address change is detected
    ///
    /// The callback receives the old address (if any) and the new address.
    /// Only one callback can be set at a time; setting a new callback replaces the previous one.
    pub fn set_address_change_callback<F>(&mut self, callback: F)
    where
        F: Fn(Option<SocketAddr>, SocketAddr) + Send + Sync + 'static,
    {
        self.address_change_callback = Some(Box::new(callback));
    }

    /// Clear the address change callback
    pub fn clear_address_change_callback(&mut self) {
        self.address_change_callback = None;
    }

    /// Get address discovery statistics
    ///
    /// Note: This returns default statistics in the current implementation.
    /// Applications should track statistics at the connection level.
    pub fn address_discovery_stats(&self) -> AddressDiscoveryStats {
        // TODO: Implement statistics tracking at the endpoint level
        AddressDiscoveryStats::default()
    }

    /// Number of connections that are currently open
    pub fn open_connections(&self) -> usize {
        self.connections.len()
    }

    /// Counter for the number of bytes currently used
    /// in the buffers for Initial and 0-RTT messages for pending incoming connections
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
        debug_assert!(x >= self.index.incoming_connection_remotes.len());
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
#[derive(Default)]
struct IncomingBuffer {
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
    connection_ids: FxHashMap<ConnectionId, ConnectionHandle>,
    /// Identifies incoming connections with zero-length CIDs
    ///
    /// Uses a standard `HashMap` to protect against hash collision attacks.
    incoming_connection_remotes: HashMap<FourTuple, ConnectionHandle>,
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

    /// Associate a connection with its first locally-chosen destination CID if used, or otherwise
    /// its current 4-tuple
    fn insert_conn(
        &mut self,
        addresses: FourTuple,
        dst_cid: ConnectionId,
        connection: ConnectionHandle,
        side: Side,
    ) {
        match dst_cid.len() {
            0 => match side {
                Side::Server => {
                    self.incoming_connection_remotes
                        .insert(addresses, connection);
                }
                Side::Client => {
                    self.outgoing_connection_remotes
                        .insert(addresses.remote, connection);
                }
            },
            _ => {
                self.connection_ids.insert(dst_cid, connection);
            }
        }
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
        let dst_cid = datagram.dst_cid();
        let is_empty_cid = dst_cid.is_empty();

        // Fast path: Try most common lookup first (non-empty CID)
        if !is_empty_cid {
            if let Some(&ch) = self.connection_ids.get(dst_cid) {
                return Some(RouteDatagramTo::Connection(ch));
            }
        }

        // Initial/0RTT packet lookup
        if datagram.is_initial() || datagram.is_0rtt() {
            if let Some(&ch) = self.connection_ids_initial.get(dst_cid) {
                return Some(ch);
            }
        }

        // Empty CID lookup (less common, do after fast path)
        if is_empty_cid {
            // Check incoming connections first (servers handle more incoming)
            if let Some(&ch) = self.incoming_connection_remotes.get(addresses) {
                return Some(RouteDatagramTo::Connection(ch));
            }
            if let Some(&ch) = self.outgoing_connection_remotes.get(&addresses.remote) {
                return Some(RouteDatagramTo::Connection(ch));
            }
        }

        // Stateless reset token lookup (least common, do last)
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
    /// Peer ID for this connection, used for relay functionality
    peer_id: Option<PeerId>,
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
    pub fn orig_dst_cid(&self) -> &ConnectionId {
        &self.token.orig_dst_cid
    }
}

impl fmt::Debug for Incoming {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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
