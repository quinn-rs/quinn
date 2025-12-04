use std::{
    cmp,
    collections::{BTreeMap, VecDeque, btree_map},
    convert::TryFrom,
    fmt, io, mem,
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    sync::Arc,
};

use bytes::{BufMut, Bytes, BytesMut};
use frame::StreamMetaVec;

use rand::{Rng, SeedableRng, rngs::StdRng};
use rustc_hash::{FxHashMap, FxHashSet};
use thiserror::Error;
use tracing::{debug, error, trace, trace_span, warn};

use crate::{
    Dir, Duration, EndpointConfig, Frame, INITIAL_MTU, Instant, MAX_CID_SIZE, MAX_STREAM_COUNT,
    MIN_INITIAL_SIZE, Side, StreamId, TIMER_GRANULARITY, TokenStore, Transmit, TransportError,
    TransportErrorCode, VarInt,
    cid_generator::ConnectionIdGenerator,
    cid_queue::CidQueue,
    coding::BufMutExt,
    config::{ServerConfig, TransportConfig},
    congestion::Controller,
    connection::{
        qlog::{QlogRecvPacket, QlogSentPacket},
        spaces::LostPacket,
        timer::{ConnTimer, PathTimer},
    },
    crypto::{self, KeyPair, Keys, PacketKey},
    frame::{self, Close, Datagram, FrameStruct, NewToken, ObservedAddr},
    iroh_hp,
    packet::{
        FixedLengthConnectionIdParser, Header, InitialHeader, InitialPacket, LongType, Packet,
        PacketNumber, PartialDecode, SpaceId,
    },
    range_set::ArrayRangeSet,
    shared::{
        ConnectionEvent, ConnectionEventInner, ConnectionId, DatagramConnectionEvent, EcnCodepoint,
        EndpointEvent, EndpointEventInner,
    },
    token::{ResetToken, Token, TokenPayload},
    transport_parameters::TransportParameters,
};

mod ack_frequency;
use ack_frequency::AckFrequencyState;

mod assembler;
pub use assembler::Chunk;

mod cid_state;
use cid_state::CidState;

mod datagrams;
use datagrams::DatagramState;
pub use datagrams::{Datagrams, SendDatagramError};

mod mtud;
mod pacing;

mod packet_builder;
use packet_builder::{PacketBuilder, PadDatagram};

mod packet_crypto;
use packet_crypto::{PrevCrypto, ZeroRttCrypto};

mod paths;
pub use paths::{ClosedPath, PathEvent, PathId, PathStatus, RttEstimator, SetPathStatusError};
use paths::{PathData, PathState};

pub(crate) mod qlog;

mod send_buffer;

mod spaces;
#[cfg(fuzzing)]
pub use spaces::Retransmits;
#[cfg(not(fuzzing))]
use spaces::Retransmits;
use spaces::{PacketSpace, SendableFrames, SentPacket, ThinRetransmits};

mod stats;
pub use stats::{ConnectionStats, FrameStats, PathStats, UdpStats};

mod streams;
#[cfg(fuzzing)]
pub use streams::StreamsState;
#[cfg(not(fuzzing))]
use streams::StreamsState;
pub use streams::{
    Chunks, ClosedStream, FinishError, ReadError, ReadableError, RecvStream, SendStream,
    ShouldTransmit, StreamEvent, Streams, WriteError, Written,
};

mod timer;
use timer::{Timer, TimerTable};

mod transmit_buf;
use transmit_buf::TransmitBuf;

mod state;

#[cfg(not(fuzzing))]
use state::State;
#[cfg(fuzzing)]
pub use state::State;
use state::StateType;

/// Protocol state and logic for a single QUIC connection
///
/// Objects of this type receive [`ConnectionEvent`]s and emit [`EndpointEvent`]s and application
/// [`Event`]s to make progress. To handle timeouts, a `Connection` returns timer updates and
/// expects timeouts through various methods. A number of simple getter methods are exposed
/// to allow callers to inspect some of the connection state.
///
/// `Connection` has roughly 4 types of methods:
///
/// - A. Simple getters, taking `&self`
/// - B. Handlers for incoming events from the network or system, named `handle_*`.
/// - C. State machine mutators, for incoming commands from the application. For convenience we
///   refer to this as "performing I/O" below, however as per the design of this library none of the
///   functions actually perform system-level I/O. For example, [`read`](RecvStream::read) and
///   [`write`](SendStream::write), but also things like [`reset`](SendStream::reset).
/// - D. Polling functions for outgoing events or actions for the caller to
///   take, named `poll_*`.
///
/// The simplest way to use this API correctly is to call (B) and (C) whenever
/// appropriate, then after each of those calls, as soon as feasible call all
/// polling methods (D) and deal with their outputs appropriately, e.g. by
/// passing it to the application or by making a system-level I/O call. You
/// should call the polling functions in this order:
///
/// 1. [`poll_transmit`](Self::poll_transmit)
/// 2. [`poll_timeout`](Self::poll_timeout)
/// 3. [`poll_endpoint_events`](Self::poll_endpoint_events)
/// 4. [`poll`](Self::poll)
///
/// Currently the only actual dependency is from (2) to (1), however additional
/// dependencies may be added in future, so the above order is recommended.
///
/// (A) may be called whenever desired.
///
/// Care should be made to ensure that the input events represent monotonically
/// increasing time. Specifically, calling [`handle_timeout`](Self::handle_timeout)
/// with events of the same [`Instant`] may be interleaved in any order with a
/// call to [`handle_event`](Self::handle_event) at that same instant; however
/// events or timeouts with different instants must not be interleaved.
pub struct Connection {
    endpoint_config: Arc<EndpointConfig>,
    config: Arc<TransportConfig>,
    rng: StdRng,
    crypto: Box<dyn crypto::Session>,
    /// The CID we initially chose, for use during the handshake
    handshake_cid: ConnectionId,
    /// The CID the peer initially chose, for use during the handshake
    rem_handshake_cid: ConnectionId,
    /// The "real" local IP address which was was used to receive the initial packet.
    /// This is only populated for the server case, and if known
    local_ip: Option<IpAddr>,
    /// The [`PathData`] for each path
    ///
    /// This needs to be ordered because [`Connection::poll_transmit`] needs to
    /// deterministically select the next PathId to send on.
    // TODO(flub): well does it really? But deterministic is nice for now.
    paths: BTreeMap<PathId, PathState>,
    /// Incremented every time we see a new path
    ///
    /// Stored separately from `path.generation` to account for aborted migrations
    path_counter: u64,
    /// Whether MTU detection is supported in this environment
    allow_mtud: bool,
    state: State,
    side: ConnectionSide,
    /// Whether or not 0-RTT was enabled during the handshake. Does not imply acceptance.
    zero_rtt_enabled: bool,
    /// Set if 0-RTT is supported, then cleared when no longer needed.
    zero_rtt_crypto: Option<ZeroRttCrypto>,
    key_phase: bool,
    /// How many packets are in the current key phase. Used only for `Data` space.
    key_phase_size: u64,
    /// Transport parameters set by the peer
    peer_params: TransportParameters,
    /// Source ConnectionId of the first packet received from the peer
    orig_rem_cid: ConnectionId,
    /// Destination ConnectionId sent by the client on the first Initial
    initial_dst_cid: ConnectionId,
    /// The value that the server included in the Source Connection ID field of a Retry packet, if
    /// one was received
    retry_src_cid: Option<ConnectionId>,
    /// Events returned by [`Connection::poll`]
    events: VecDeque<Event>,
    endpoint_events: VecDeque<EndpointEventInner>,
    /// Whether the spin bit is in use for this connection
    spin_enabled: bool,
    /// Outgoing spin bit state
    spin: bool,
    /// Packet number spaces: initial, handshake, 1-RTT
    spaces: [PacketSpace; 3],
    /// Highest usable [`SpaceId`]
    highest_space: SpaceId,
    /// 1-RTT keys used prior to a key update
    prev_crypto: Option<PrevCrypto>,
    /// 1-RTT keys to be used for the next key update
    ///
    /// These are generated in advance to prevent timing attacks and/or DoS by third-party attackers
    /// spoofing key updates.
    next_crypto: Option<KeyPair<Box<dyn PacketKey>>>,
    accepted_0rtt: bool,
    /// Whether the idle timer should be reset the next time an ack-eliciting packet is transmitted.
    permit_idle_reset: bool,
    /// Negotiated idle timeout
    idle_timeout: Option<Duration>,
    timers: TimerTable,
    /// Number of packets received which could not be authenticated
    authentication_failures: u64,

    //
    // Queued non-retransmittable 1-RTT data
    //
    /// If the CONNECTION_CLOSE frame needs to be sent
    close: bool,

    //
    // ACK frequency
    //
    ack_frequency: AckFrequencyState,

    //
    // Congestion Control
    //
    /// Whether the most recently received packet had an ECN codepoint set
    receiving_ecn: bool,
    /// Number of packets authenticated
    total_authed_packets: u64,
    /// Whether the last `poll_transmit` call yielded no data because there was
    /// no outgoing application data.
    app_limited: bool,

    //
    // ObservedAddr
    //
    /// Sequence number for the next observed address frame sent to the peer.
    next_observed_addr_seq_no: VarInt,

    streams: StreamsState,
    /// Surplus remote CIDs for future use on new paths
    ///
    /// These are given out before multiple paths exist, also for paths that will never
    /// exist.  So if multipath is supported the number of paths here will be higher than
    /// the actual number of paths in use.
    rem_cids: FxHashMap<PathId, CidQueue>,
    /// Attributes of CIDs generated by local endpoint
    ///
    /// Any path that is allowed to be opened is present in this map, as well as the already
    /// opened paths. However since CIDs are issued async by the endpoint driver via
    /// connection events it can not be used to know if CIDs have been issued for a path or
    /// not. See [`Connection::max_path_id_with_cids`] for this.
    local_cid_state: FxHashMap<PathId, CidState>,
    /// State of the unreliable datagram extension
    datagrams: DatagramState,
    /// Connection level statistics
    stats: ConnectionStats,
    /// Path level statistics
    path_stats: FxHashMap<PathId, PathStats>,
    /// QUIC version used for the connection.
    version: u32,

    //
    // Multipath
    //
    /// Maximum number of concurrent paths
    ///
    /// Initially set from the [`TransportConfig::max_concurrent_multipath_paths`]. Even
    /// when multipath is disabled this will be set to 1, it is not used in that case
    /// though.
    max_concurrent_paths: NonZeroU32,
    /// Local maximum [`PathId`] to be used
    ///
    /// This is initially set to [`TransportConfig::get_initial_max_path_id`] when multipath
    /// is negotiated, or to [`PathId::ZERO`] otherwise. This is essentially the value of
    /// the highest MAX_PATH_ID frame sent.
    ///
    /// Any path with an ID equal or below this [`PathId`] is either:
    ///
    /// - Abandoned, if it is also in [`Connection::abandoned_paths`].
    /// - Open, in this case it is present in [`Connection::paths`]
    /// - Not yet opened, if it is in neither of these two places.
    ///
    /// Note that for not-yet-open there may or may not be any CIDs issued. See
    /// [`Connection::max_path_id_with_cids`].
    local_max_path_id: PathId,
    /// Remote's maximum [`PathId`] to be used
    ///
    /// This is initially set to the peer's [`TransportParameters::initial_max_path_id`] when
    /// multipath is negotiated, or to [`PathId::ZERO`] otherwise. A peer may increase this limit
    /// by sending [`Frame::MaxPathId`] frames.
    remote_max_path_id: PathId,
    /// The greatest [`PathId`] we have issued CIDs for
    ///
    /// CIDs are only issued for `min(local_max_path_id, remote_max_path_id)`. It is not
    /// possible to use [`Connection::local_cid_state`] to know if CIDs have been issued
    /// since they are issued asynchronously by the endpoint driver.
    max_path_id_with_cids: PathId,
    /// The paths already abandoned
    ///
    /// They may still have some state left in [`Connection::paths`] or
    /// [`Connection::local_cid_state`] since some of this has to be kept around for some
    /// time after a path is abandoned.
    // TODO(flub): Make this a more efficient data structure.  Like ranges of abandoned
    //    paths.  Or a set together with a minimum.  Or something.
    abandoned_paths: FxHashSet<PathId>,

    iroh_hp: iroh_hp::State,
}

impl Connection {
    pub(crate) fn new(
        endpoint_config: Arc<EndpointConfig>,
        config: Arc<TransportConfig>,
        init_cid: ConnectionId,
        loc_cid: ConnectionId,
        rem_cid: ConnectionId,
        remote: SocketAddr,
        local_ip: Option<IpAddr>,
        crypto: Box<dyn crypto::Session>,
        cid_gen: &dyn ConnectionIdGenerator,
        now: Instant,
        version: u32,
        allow_mtud: bool,
        rng_seed: [u8; 32],
        side_args: SideArgs,
    ) -> Self {
        let pref_addr_cid = side_args.pref_addr_cid();
        let path_validated = side_args.path_validated();
        let connection_side = ConnectionSide::from(side_args);
        let side = connection_side.side();
        let mut rng = StdRng::from_seed(rng_seed);
        let initial_space = {
            let mut space = PacketSpace::new(now, SpaceId::Initial, &mut rng);
            space.crypto = Some(crypto.initial_keys(init_cid, side));
            space
        };
        let handshake_space = PacketSpace::new(now, SpaceId::Handshake, &mut rng);
        #[cfg(test)]
        let data_space = match config.deterministic_packet_numbers {
            true => PacketSpace::new_deterministic(now, SpaceId::Data),
            false => PacketSpace::new(now, SpaceId::Data, &mut rng),
        };
        #[cfg(not(test))]
        let data_space = PacketSpace::new(now, SpaceId::Data, &mut rng);
        let state = State::handshake(state::Handshake {
            rem_cid_set: side.is_server(),
            expected_token: Bytes::new(),
            client_hello: None,
            allow_server_migration: side.is_client(),
        });
        let local_cid_state = FxHashMap::from_iter([(
            PathId::ZERO,
            CidState::new(
                cid_gen.cid_len(),
                cid_gen.cid_lifetime(),
                now,
                if pref_addr_cid.is_some() { 2 } else { 1 },
            ),
        )]);

        let mut path = PathData::new(remote, allow_mtud, None, 0, now, &config);
        // TODO(@divma): consider if we want to delay this until the path is validated
        path.open = true;
        let mut this = Self {
            endpoint_config,
            crypto,
            handshake_cid: loc_cid,
            rem_handshake_cid: rem_cid,
            local_cid_state,
            paths: BTreeMap::from_iter([(
                PathId::ZERO,
                PathState {
                    data: path,
                    prev: None,
                },
            )]),
            path_counter: 0,
            allow_mtud,
            local_ip,
            state,
            side: connection_side,
            zero_rtt_enabled: false,
            zero_rtt_crypto: None,
            key_phase: false,
            // A small initial key phase size ensures peers that don't handle key updates correctly
            // fail sooner rather than later. It's okay for both peers to do this, as the first one
            // to perform an update will reset the other's key phase size in `update_keys`, and a
            // simultaneous key update by both is just like a regular key update with a really fast
            // response. Inspired by quic-go's similar behavior of performing the first key update
            // at the 100th short-header packet.
            key_phase_size: rng.random_range(10..1000),
            peer_params: TransportParameters::default(),
            orig_rem_cid: rem_cid,
            initial_dst_cid: init_cid,
            retry_src_cid: None,
            events: VecDeque::new(),
            endpoint_events: VecDeque::new(),
            spin_enabled: config.allow_spin && rng.random_ratio(7, 8),
            spin: false,
            spaces: [initial_space, handshake_space, data_space],
            highest_space: SpaceId::Initial,
            prev_crypto: None,
            next_crypto: None,
            accepted_0rtt: false,
            permit_idle_reset: true,
            idle_timeout: match config.max_idle_timeout {
                None | Some(VarInt(0)) => None,
                Some(dur) => Some(Duration::from_millis(dur.0)),
            },
            timers: TimerTable::default(),
            authentication_failures: 0,
            close: false,

            ack_frequency: AckFrequencyState::new(get_max_ack_delay(
                &TransportParameters::default(),
            )),

            app_limited: false,
            receiving_ecn: false,
            total_authed_packets: 0,

            next_observed_addr_seq_no: 0u32.into(),

            streams: StreamsState::new(
                side,
                config.max_concurrent_uni_streams,
                config.max_concurrent_bidi_streams,
                config.send_window,
                config.receive_window,
                config.stream_receive_window,
            ),
            datagrams: DatagramState::default(),
            config,
            rem_cids: FxHashMap::from_iter([(PathId::ZERO, CidQueue::new(rem_cid))]),
            rng,
            stats: ConnectionStats::default(),
            path_stats: Default::default(),
            version,

            // peer params are not yet known, so multipath is not enabled
            max_concurrent_paths: NonZeroU32::MIN,
            local_max_path_id: PathId::ZERO,
            remote_max_path_id: PathId::ZERO,
            max_path_id_with_cids: PathId::ZERO,
            abandoned_paths: Default::default(),

            // iroh's nat traversal
            iroh_hp: Default::default(),
        };
        if path_validated {
            this.on_path_validated(PathId::ZERO);
        }
        if side.is_client() {
            // Kick off the connection
            this.write_crypto();
            this.init_0rtt();
        }
        this.config.qlog_sink.emit_connection_started(
            now,
            loc_cid,
            rem_cid,
            remote,
            local_ip,
            this.initial_dst_cid,
        );
        this
    }

    /// Returns the next time at which `handle_timeout` should be called
    ///
    /// The value returned may change after:
    /// - the application performed some I/O on the connection
    /// - a call was made to `handle_event`
    /// - a call to `poll_transmit` returned `Some`
    /// - a call was made to `handle_timeout`
    #[must_use]
    pub fn poll_timeout(&mut self) -> Option<Instant> {
        self.timers.peek()
    }

    /// Returns application-facing events
    ///
    /// Connections should be polled for events after:
    /// - a call was made to `handle_event`
    /// - a call was made to `handle_timeout`
    #[must_use]
    pub fn poll(&mut self) -> Option<Event> {
        if let Some(x) = self.events.pop_front() {
            return Some(x);
        }

        if let Some(event) = self.streams.poll() {
            return Some(Event::Stream(event));
        }

        if let Some(reason) = self.state.take_error() {
            return Some(Event::ConnectionLost { reason });
        }

        None
    }

    /// Return endpoint-facing events
    #[must_use]
    pub fn poll_endpoint_events(&mut self) -> Option<EndpointEvent> {
        self.endpoint_events.pop_front().map(EndpointEvent)
    }

    /// Provide control over streams
    #[must_use]
    pub fn streams(&mut self) -> Streams<'_> {
        Streams {
            state: &mut self.streams,
            conn_state: &self.state,
        }
    }

    /// Provide control over streams
    #[must_use]
    pub fn recv_stream(&mut self, id: StreamId) -> RecvStream<'_> {
        assert!(id.dir() == Dir::Bi || id.initiator() != self.side.side());
        RecvStream {
            id,
            state: &mut self.streams,
            pending: &mut self.spaces[SpaceId::Data].pending,
        }
    }

    /// Provide control over streams
    #[must_use]
    pub fn send_stream(&mut self, id: StreamId) -> SendStream<'_> {
        assert!(id.dir() == Dir::Bi || id.initiator() == self.side.side());
        SendStream {
            id,
            state: &mut self.streams,
            pending: &mut self.spaces[SpaceId::Data].pending,
            conn_state: &self.state,
        }
    }

    /// Opens a new path only if no path to the remote address exists so far
    ///
    /// See [`open_path`]. Returns `(path_id, true)` if the path already existed. `(path_id,
    /// false)` if was opened.
    ///
    /// [`open_path`]: Connection::open_path
    pub fn open_path_ensure(
        &mut self,
        remote: SocketAddr,
        initial_status: PathStatus,
        now: Instant,
    ) -> Result<(PathId, bool), PathError> {
        match self
            .paths
            .iter()
            .find(|(_id, path)| path.data.remote == remote)
        {
            Some((path_id, _state)) => Ok((*path_id, true)),
            None => self
                .open_path(remote, initial_status, now)
                .map(|id| (id, false)),
        }
    }

    /// Opens a new path
    ///
    /// Further errors might occur and they will be emitted in [`PathEvent::LocallyClosed`] events.
    /// When the path is opened it will be reported as an [`PathEvent::Opened`].
    pub fn open_path(
        &mut self,
        remote: SocketAddr,
        initial_status: PathStatus,
        now: Instant,
    ) -> Result<PathId, PathError> {
        if !self.is_multipath_negotiated() {
            return Err(PathError::MultipathNotNegotiated);
        }
        if self.side().is_server() {
            return Err(PathError::ServerSideNotAllowed);
        }

        let max_abandoned = self.abandoned_paths.iter().max().copied();
        let max_used = self.paths.keys().last().copied();
        let path_id = max_abandoned
            .max(max_used)
            .unwrap_or(PathId::ZERO)
            .saturating_add(1u8);

        if Some(path_id) > self.max_path_id() {
            return Err(PathError::MaxPathIdReached);
        }
        if path_id > self.remote_max_path_id {
            self.spaces[SpaceId::Data].pending.paths_blocked = true;
            return Err(PathError::MaxPathIdReached);
        }
        if self.rem_cids.get(&path_id).map(CidQueue::active).is_none() {
            self.spaces[SpaceId::Data]
                .pending
                .path_cids_blocked
                .push(path_id);
            return Err(PathError::RemoteCidsExhausted);
        }

        let path = self.ensure_path(path_id, remote, now, None);
        path.status.local_update(initial_status);

        Ok(path_id)
    }

    /// Closes a path by sending a PATH_ABANDON frame
    ///
    /// This will not allow closing the last path. It does allow closing paths which have
    /// not yet been opened, as e.g. is the case when receiving a PATH_ABANDON from the peer
    /// for a path that was never opened locally.
    pub fn close_path(
        &mut self,
        now: Instant,
        path_id: PathId,
        error_code: VarInt,
    ) -> Result<(), ClosePathError> {
        if self.abandoned_paths.contains(&path_id) || Some(path_id) > self.max_path_id() {
            return Err(ClosePathError::ClosedPath);
        }
        if self.paths.contains_key(&path_id)
            && self
                .paths
                .keys()
                .filter(|&id| !self.abandoned_paths.contains(id))
                .count()
                < 2
        {
            return Err(ClosePathError::LastOpenPath);
        }

        // Send PATH_ABANDON
        self.spaces[SpaceId::Data]
            .pending
            .path_abandon
            .insert(path_id, error_code.into());

        // Consider remotely issued CIDs as retired.
        // Technically we don't have to do this just yet.  We only need to do this *after*
        // the ABANDON_PATH frame is sent, allowing us to still send it on the
        // to-be-abandoned path.  However it is recommended to send it on another path, and
        // we do not allow abandoning the last path anyway.
        self.rem_cids.remove(&path_id);
        self.endpoint_events
            .push_back(EndpointEventInner::RetireResetToken(path_id));

        self.abandoned_paths.insert(path_id);

        self.set_max_path_id(now, self.local_max_path_id.saturating_add(1u8));

        // The peer MUST respond with a corresponding PATH_ABANDON frame. If not, this timer
        // expires.
        self.timers.set(
            Timer::PerPath(path_id, PathTimer::PathNotAbandoned),
            now + 3 * self.pto_max_path(SpaceId::Data),
        );

        Ok(())
    }

    /// Gets the [`PathData`] for a known [`PathId`].
    ///
    /// Will panic if the path_id does not reference any known path.
    #[track_caller]
    fn path_data(&self, path_id: PathId) -> &PathData {
        &self.paths.get(&path_id).expect("known path").data
    }

    /// Gets a reference to the [`PathData`] for a [`PathId`]
    fn path(&self, path_id: PathId) -> Option<&PathData> {
        self.paths.get(&path_id).map(|path_state| &path_state.data)
    }

    /// Gets a mutable reference to the [`PathData`] for a [`PathId`]
    fn path_mut(&mut self, path_id: PathId) -> Option<&mut PathData> {
        self.paths
            .get_mut(&path_id)
            .map(|path_state| &mut path_state.data)
    }

    /// Returns all known paths.
    ///
    /// There is no guarantee any of these paths are open or usable.
    pub fn paths(&self) -> Vec<PathId> {
        self.paths.keys().copied().collect()
    }

    /// Gets the local [`PathStatus`] for a known [`PathId`]
    pub fn path_status(&self, path_id: PathId) -> Result<PathStatus, ClosedPath> {
        self.path(path_id)
            .map(PathData::local_status)
            .ok_or(ClosedPath { _private: () })
    }

    /// Returns the path's remote socket address
    pub fn path_remote_address(&self, path_id: PathId) -> Result<SocketAddr, ClosedPath> {
        self.path(path_id)
            .map(|path| path.remote)
            .ok_or(ClosedPath { _private: () })
    }

    /// Sets the [`PathStatus`] for a known [`PathId`]
    ///
    /// Returns the previous path status on success.
    pub fn set_path_status(
        &mut self,
        path_id: PathId,
        status: PathStatus,
    ) -> Result<PathStatus, SetPathStatusError> {
        if !self.is_multipath_negotiated() {
            return Err(SetPathStatusError::MultipathNotNegotiated);
        }
        let path = self
            .path_mut(path_id)
            .ok_or(SetPathStatusError::ClosedPath)?;
        let prev = match path.status.local_update(status) {
            Some(prev) => {
                self.spaces[SpaceId::Data]
                    .pending
                    .path_status
                    .insert(path_id);
                prev
            }
            None => path.local_status(),
        };
        Ok(prev)
    }

    /// Returns the remote path status
    // TODO(flub): Probably should also be some kind of path event?  Not even sure if I like
    //    this as an API, but for now it allows me to write a test easily.
    // TODO(flub): Technically this should be a Result<Option<PathSTatus>>?
    pub fn remote_path_status(&self, path_id: PathId) -> Option<PathStatus> {
        self.path(path_id).and_then(|path| path.remote_status())
    }

    /// Sets the max_idle_timeout for a specific path
    ///
    /// See [`TransportConfig::default_path_max_idle_timeout`] for details.
    ///
    /// Returns the previous value of the setting.
    pub fn set_path_max_idle_timeout(
        &mut self,
        path_id: PathId,
        timeout: Option<Duration>,
    ) -> Result<Option<Duration>, ClosedPath> {
        let path = self
            .paths
            .get_mut(&path_id)
            .ok_or(ClosedPath { _private: () })?;
        Ok(std::mem::replace(&mut path.data.idle_timeout, timeout))
    }

    /// Sets the keep_alive_interval for a specific path
    ///
    /// See [`TransportConfig::default_path_keep_alive_interval`] for details.
    ///
    /// Returns the previous value of the setting.
    pub fn set_path_keep_alive_interval(
        &mut self,
        path_id: PathId,
        interval: Option<Duration>,
    ) -> Result<Option<Duration>, ClosedPath> {
        let path = self
            .paths
            .get_mut(&path_id)
            .ok_or(ClosedPath { _private: () })?;
        Ok(std::mem::replace(&mut path.data.keep_alive, interval))
    }

    /// Gets the [`PathData`] for a known [`PathId`].
    ///
    /// Will panic if the path_id does not reference any known path.
    #[track_caller]
    fn path_data_mut(&mut self, path_id: PathId) -> &mut PathData {
        &mut self.paths.get_mut(&path_id).expect("known path").data
    }

    /// Check if the remote has been validated in any active path
    fn is_remote_validated(&self, remote: SocketAddr) -> bool {
        self.paths
            .values()
            .any(|path_state| path_state.data.remote == remote && path_state.data.validated)
        // TODO(@divma): we might want to ensure the path has been recently active to consider the
        // address validated
    }

    fn ensure_path(
        &mut self,
        path_id: PathId,
        remote: SocketAddr,
        now: Instant,
        pn: Option<u64>,
    ) -> &mut PathData {
        let validated = self.is_remote_validated(remote);
        let vacant_entry = match self.paths.entry(path_id) {
            btree_map::Entry::Vacant(vacant_entry) => vacant_entry,
            btree_map::Entry::Occupied(occupied_entry) => {
                return &mut occupied_entry.into_mut().data;
            }
        };

        debug!(%validated, %path_id, ?remote, "path added");
        let peer_max_udp_payload_size =
            u16::try_from(self.peer_params.max_udp_payload_size.into_inner()).unwrap_or(u16::MAX);
        self.path_counter = self.path_counter.wrapping_add(1);
        let mut data = PathData::new(
            remote,
            self.allow_mtud,
            Some(peer_max_udp_payload_size),
            self.path_counter,
            now,
            &self.config,
        );

        data.validated = validated;

        let pto = self.ack_frequency.max_ack_delay_for_pto() + data.rtt.pto_base();
        self.timers
            .set(Timer::PerPath(path_id, PathTimer::PathOpen), now + 3 * pto);

        // for the path to be opened we need to send a packet on the path. Sending a challenge
        // guarantees this
        data.send_new_challenge = true;

        let path = vacant_entry.insert(PathState { data, prev: None });

        let mut pn_space = spaces::PacketNumberSpace::new(now, SpaceId::Data, &mut self.rng);
        if let Some(pn) = pn {
            pn_space.dedup.insert(pn);
        }
        self.spaces[SpaceId::Data]
            .number_spaces
            .insert(path_id, pn_space);
        &mut path.data
    }

    /// Returns packets to transmit
    ///
    /// Connections should be polled for transmit after:
    /// - the application performed some I/O on the connection
    /// - a call was made to `handle_event`
    /// - a call was made to `handle_timeout`
    ///
    /// `max_datagrams` specifies how many datagrams can be returned inside a
    /// single Transmit using GSO. This must be at least 1.
    #[must_use]
    pub fn poll_transmit(
        &mut self,
        now: Instant,
        max_datagrams: usize,
        buf: &mut Vec<u8>,
    ) -> Option<Transmit> {
        if let Some(address) = self.spaces[SpaceId::Data].pending.hole_punch_to.pop() {
            trace!(dst = ?address, "RAND_DATA packet");
            buf.reserve_exact(8); // send 8 bytes of random data
            let tmp: [u8; 8] = self.rng.random();
            buf.put_slice(&tmp);
            return Some(Transmit {
                destination: address.into(),
                ecn: None,
                size: 8,
                segment_size: None,
                src_ip: None,
            });
        }

        assert!(max_datagrams != 0);
        let max_datagrams = match self.config.enable_segmentation_offload {
            false => 1,
            true => max_datagrams,
        };

        // Each call to poll_transmit can only send datagrams to one destination, because
        // all datagrams in a GSO batch are for the same destination.  Therefore only
        // datagrams for one Path ID are produced for each poll_transmit call.

        // TODO(flub): this is wishful thinking and not actually implemented, but perhaps it
        //   should be:

        // First, if we have to send a close, select a path for that.
        // Next, all paths that have a PATH_CHALLENGE or PATH_RESPONSE pending.

        // For all, open, validated and AVAILABLE paths:
        // - Is the path congestion blocked or pacing blocked?
        // - call maybe_queue_ to ensure a tail-loss probe would be sent?
        // - do we need to send a close message?
        // - call can_send
        // Once there's nothing more to send on the AVAILABLE paths, do the same for BACKUP paths

        // Check whether we need to send a close message
        let close = match self.state.as_type() {
            StateType::Drained => {
                self.app_limited = true;
                return None;
            }
            StateType::Draining | StateType::Closed => {
                // self.close is only reset once the associated packet had been
                // encoded successfully
                if !self.close {
                    self.app_limited = true;
                    return None;
                }
                true
            }
            _ => false,
        };

        // Check whether we need to send an ACK_FREQUENCY frame
        if let Some(config) = &self.config.ack_frequency_config {
            let rtt = self
                .paths
                .values()
                .map(|p| p.data.rtt.get())
                .min()
                .expect("one path exists");
            self.spaces[SpaceId::Data].pending.ack_frequency = self
                .ack_frequency
                .should_send_ack_frequency(rtt, config, &self.peer_params)
                && self.highest_space == SpaceId::Data
                && self.peer_supports_ack_frequency();
        }

        // Whether this packet can be coalesced with another one in the same datagram.
        let mut coalesce = true;

        // Whether the last packet in the datagram must be padded so the datagram takes up
        // to at least MIN_INITIAL_SIZE, or to the maximum segment size if this is smaller.
        let mut pad_datagram = PadDatagram::No;

        // Whether congestion control stopped the next packet from being sent. Further
        // packets could still be built, as e.g. tail-loss probes are not congestion
        // limited.
        let mut congestion_blocked = false;

        // The packet number of the last built packet.
        let mut last_packet_number = None;

        let mut path_id = *self.paths.first_key_value().expect("one path must exist").0;

        // If there is any open, validated and available path we only want to send frames to
        // any backup path that must be sent on that backup path exclusively.
        let have_available_path = self.paths.iter().any(|(id, path)| {
            path.data.validated
                && path.data.local_status() == PathStatus::Available
                && self.rem_cids.contains_key(id)
        });

        // Setup for the first path_id
        let mut transmit = TransmitBuf::new(
            buf,
            max_datagrams,
            self.path_data(path_id).current_mtu().into(),
        );
        if let Some(challenge) = self.send_prev_path_challenge(now, &mut transmit, path_id) {
            return Some(challenge);
        }
        let mut space_id = match path_id {
            PathId::ZERO => SpaceId::Initial,
            _ => SpaceId::Data,
        };

        loop {
            // check if there is at least one active CID to use for sending
            let Some(remote_cid) = self.rem_cids.get(&path_id).map(CidQueue::active) else {
                let err = PathError::RemoteCidsExhausted;
                if !self.abandoned_paths.contains(&path_id) {
                    debug!(?err, %path_id, "no active CID for path");
                    self.events.push_back(Event::Path(PathEvent::LocallyClosed {
                        id: path_id,
                        error: err,
                    }));
                    // Locally we should have refused to open this path, the remote should
                    // have given us CIDs for this path before opening it.  So we can always
                    // abandon this here.
                    self.close_path(now, path_id, TransportErrorCode::NO_CID_AVAILABLE.into())
                        .ok();
                    self.spaces[SpaceId::Data]
                        .pending
                        .path_cids_blocked
                        .push(path_id);
                } else {
                    trace!(%path_id, "remote CIDs retired for abandoned path");
                }

                match self.paths.keys().find(|&&next| next > path_id) {
                    Some(next_path_id) => {
                        // See if this next path can send anything.
                        path_id = *next_path_id;
                        space_id = SpaceId::Data;

                        // update per path state
                        transmit.set_segment_size(self.path_data(path_id).current_mtu().into());
                        if let Some(challenge) =
                            self.send_prev_path_challenge(now, &mut transmit, path_id)
                        {
                            return Some(challenge);
                        }

                        continue;
                    }
                    None => {
                        // Nothing more to send.
                        trace!(
                            ?space_id,
                            %path_id,
                            "no CIDs to send on path, no more paths"
                        );
                        break;
                    }
                }
            };

            // Determine if anything can be sent in this packet number space (SpaceId +
            // PathId).
            let max_packet_size = if transmit.datagram_remaining_mut() > 0 {
                // We are trying to coalesce another packet into this datagram.
                transmit.datagram_remaining_mut()
            } else {
                // A new datagram needs to be started.
                transmit.segment_size()
            };
            let can_send = self.space_can_send(space_id, path_id, max_packet_size, close);
            let path_should_send = {
                let path_exclusive_only = space_id == SpaceId::Data
                    && have_available_path
                    && self.path_data(path_id).local_status() == PathStatus::Backup;
                let path_should_send = if path_exclusive_only {
                    can_send.path_exclusive
                } else {
                    !can_send.is_empty()
                };
                let needs_loss_probe = self.spaces[space_id].for_path(path_id).loss_probes > 0;
                path_should_send || needs_loss_probe || can_send.close
            };

            if !path_should_send && space_id < SpaceId::Data {
                if self.spaces[space_id].crypto.is_some() {
                    trace!(?space_id, %path_id, "nothing to send in space");
                }
                space_id = space_id.next();
                continue;
            }

            let send_blocked = if path_should_send && transmit.datagram_remaining_mut() == 0 {
                // Only check congestion control if a new datagram is needed.
                self.path_congestion_check(space_id, path_id, &transmit, &can_send, now)
            } else {
                PathBlocked::No
            };
            if send_blocked != PathBlocked::No {
                trace!(?space_id, %path_id, ?send_blocked, "congestion blocked");
                congestion_blocked = true;
            }
            if send_blocked == PathBlocked::Congestion && space_id < SpaceId::Data {
                // Higher spaces might still have tail-loss probes to send, which are not
                // congestion blocked.
                space_id = space_id.next();
                continue;
            }
            if !path_should_send || send_blocked != PathBlocked::No {
                // Nothing more to send on this path, check the next path if possible.

                // If there are any datagrams in the transmit, packets for another path can
                // not be built.
                if transmit.num_datagrams() > 0 {
                    break;
                }

                match self.paths.keys().find(|&&next| next > path_id) {
                    Some(next_path_id) => {
                        // See if this next path can send anything.
                        trace!(
                            ?space_id,
                            %path_id,
                            %next_path_id,
                            "nothing to send on path"
                        );
                        path_id = *next_path_id;
                        space_id = SpaceId::Data;

                        // update per path state
                        transmit.set_segment_size(self.path_data(path_id).current_mtu().into());
                        if let Some(challenge) =
                            self.send_prev_path_challenge(now, &mut transmit, path_id)
                        {
                            return Some(challenge);
                        }

                        continue;
                    }
                    None => {
                        // Nothing more to send.
                        trace!(
                            ?space_id,
                            %path_id,
                            "nothing to send on path, no more paths"
                        );
                        break;
                    }
                }
            }

            // If the datagram is full, we need to start a new one.
            if transmit.datagram_remaining_mut() == 0 {
                if transmit.num_datagrams() >= transmit.max_datagrams() {
                    // No more datagrams allowed
                    break;
                }

                match self.spaces[space_id].for_path(path_id).loss_probes {
                    0 => transmit.start_new_datagram(),
                    _ => {
                        // We need something to send for a tail-loss probe.
                        let request_immediate_ack =
                            space_id == SpaceId::Data && self.peer_supports_ack_frequency();
                        self.spaces[space_id].maybe_queue_probe(
                            path_id,
                            request_immediate_ack,
                            &self.streams,
                        );

                        self.spaces[space_id].for_path(path_id).loss_probes -= 1;

                        // Clamp the datagram to at most the minimum MTU to ensure that loss
                        // probes can get through and enable recovery even if the path MTU
                        // has shrank unexpectedly.
                        transmit.start_new_datagram_with_size(std::cmp::min(
                            usize::from(INITIAL_MTU),
                            transmit.segment_size(),
                        ));
                    }
                }
                trace!(count = transmit.num_datagrams(), "new datagram started");
                coalesce = true;
                pad_datagram = PadDatagram::No;
            }

            // If coalescing another packet into the existing datagram, there should
            // still be enough space for a whole packet.
            if transmit.datagram_start_offset() < transmit.len() {
                debug_assert!(transmit.datagram_remaining_mut() >= MIN_PACKET_SPACE);
            }

            //
            // From here on, we've determined that a packet will definitely be sent.
            //

            if self.spaces[SpaceId::Initial].crypto.is_some()
                && space_id == SpaceId::Handshake
                && self.side.is_client()
            {
                // A client stops both sending and processing Initial packets when it
                // sends its first Handshake packet.
                self.discard_space(now, SpaceId::Initial);
            }
            if let Some(ref mut prev) = self.prev_crypto {
                prev.update_unacked = false;
            }

            let mut qlog = QlogSentPacket::default();
            let mut builder = PacketBuilder::new(
                now,
                space_id,
                path_id,
                remote_cid,
                &mut transmit,
                can_send.other,
                self,
                &mut qlog,
            )?;
            last_packet_number = Some(builder.exact_number);
            coalesce = coalesce && !builder.short_header;

            if space_id == SpaceId::Initial && (self.side.is_client() || can_send.other) {
                // https://www.rfc-editor.org/rfc/rfc9000.html#section-14.1
                pad_datagram |= PadDatagram::ToMinMtu;
            }
            if space_id == SpaceId::Data && self.config.pad_to_mtu {
                pad_datagram |= PadDatagram::ToSegmentSize;
            }

            if can_send.close {
                trace!("sending CONNECTION_CLOSE");
                // Encode ACKs before the ConnectionClose message, to give the receiver
                // a better approximate on what data has been processed. This is
                // especially important with ack delay, since the peer might not
                // have gotten any other ACK for the data earlier on.
                let mut sent_frames = SentFrames::default();
                let is_multipath_enabled = self.is_multipath_negotiated();
                for path_id in self.spaces[space_id]
                    .number_spaces
                    .iter()
                    .filter(|(_, pns)| !pns.pending_acks.ranges().is_empty())
                    .map(|(&path_id, _)| path_id)
                    .collect::<Vec<_>>()
                {
                    debug_assert!(
                        is_multipath_enabled || path_id == PathId::ZERO,
                        "Only PathId::ZERO allowed without multipath (have {path_id:?})"
                    );
                    Self::populate_acks(
                        now,
                        self.receiving_ecn,
                        &mut sent_frames,
                        path_id,
                        &mut self.spaces[space_id],
                        is_multipath_enabled,
                        &mut builder.frame_space_mut(),
                        &mut self.stats,
                        &mut qlog,
                    );
                }

                // Since there only 64 ACK frames there will always be enough space
                // to encode the ConnectionClose frame too. However we still have the
                // check here to prevent crashes if something changes.
                debug_assert!(
                    builder.frame_space_remaining() > frame::ConnectionClose::SIZE_BOUND,
                    "ACKs should leave space for ConnectionClose"
                );
                if frame::ConnectionClose::SIZE_BOUND < builder.frame_space_remaining() {
                    let max_frame_size = builder.frame_space_remaining();
                    match self.state.as_type() {
                        StateType::Closed => {
                            let reason: Close =
                                self.state.as_closed().expect("checked").clone().into();
                            if space_id == SpaceId::Data || reason.is_transport_layer() {
                                reason.encode(&mut builder.frame_space_mut(), max_frame_size);
                                qlog.frame(&Frame::Close(reason));
                            } else {
                                let frame = frame::ConnectionClose {
                                    error_code: TransportErrorCode::APPLICATION_ERROR,
                                    frame_type: None,
                                    reason: Bytes::new(),
                                };
                                frame.encode(&mut builder.frame_space_mut(), max_frame_size);
                                qlog.frame(&Frame::Close(frame::Close::Connection(frame)));
                            }
                        }
                        StateType::Draining => {
                            let frame = frame::ConnectionClose {
                                error_code: TransportErrorCode::NO_ERROR,
                                frame_type: None,
                                reason: Bytes::new(),
                            };
                            frame.encode(&mut builder.frame_space_mut(), max_frame_size);
                            qlog.frame(&Frame::Close(frame::Close::Connection(frame)));
                        }
                        _ => unreachable!(
                            "tried to make a close packet when the connection wasn't closed"
                        ),
                    };
                }
                builder.finish_and_track(now, self, path_id, sent_frames, pad_datagram, qlog);
                if space_id == self.highest_space {
                    // Don't send another close packet. Even with multipath we only send
                    // CONNECTION_CLOSE on a single path since we expect our paths to work.
                    self.close = false;
                    // `CONNECTION_CLOSE` is the final packet
                    break;
                } else {
                    // Send a close frame in every possible space for robustness, per
                    // RFC9000 "Immediate Close during the Handshake". Don't bother trying
                    // to send anything else.
                    space_id = space_id.next();
                    continue;
                }
            }

            // Send an off-path PATH_RESPONSE. Prioritized over on-path data to ensure that
            // path validation can occur while the link is saturated.
            if space_id == SpaceId::Data && builder.buf.num_datagrams() == 1 {
                let path = self.path_data_mut(path_id);
                if let Some((token, remote)) = path.path_responses.pop_off_path(path.remote) {
                    // TODO(flub): We need to use the right CID!  We shouldn't use the same
                    //    CID as the current active one for the path.  Though see also
                    //    https://github.com/quinn-rs/quinn/issues/2184
                    trace!("PATH_RESPONSE {:08x} (off-path)", token);
                    builder
                        .frame_space_mut()
                        .write(frame::FrameType::PATH_RESPONSE);
                    builder.frame_space_mut().write(token);
                    qlog.frame(&Frame::PathResponse(token));
                    self.stats.frame_tx.path_response += 1;
                    builder.finish_and_track(
                        now,
                        self,
                        path_id,
                        SentFrames {
                            non_retransmits: true,
                            ..SentFrames::default()
                        },
                        PadDatagram::ToMinMtu,
                        qlog,
                    );
                    self.stats.udp_tx.on_sent(1, transmit.len());
                    return Some(Transmit {
                        destination: remote,
                        size: transmit.len(),
                        ecn: None,
                        segment_size: None,
                        src_ip: self.local_ip,
                    });
                }
            }

            let sent_frames = {
                let path_exclusive_only = have_available_path
                    && self.path_data(path_id).local_status() == PathStatus::Backup;
                let pn = builder.exact_number;
                self.populate_packet(
                    now,
                    space_id,
                    path_id,
                    path_exclusive_only,
                    &mut builder.frame_space_mut(),
                    pn,
                    &mut qlog,
                )
            };

            // ACK-only packets should only be sent when explicitly allowed. If we write them due to
            // any other reason, there is a bug which leads to one component announcing write
            // readiness while not writing any data. This degrades performance. The condition is
            // only checked if the full MTU is available and when potentially large fixed-size
            // frames aren't queued, so that lack of space in the datagram isn't the reason for just
            // writing ACKs.
            debug_assert!(
                !(sent_frames.is_ack_only(&self.streams)
                    && !can_send.acks
                    && can_send.other
                    && builder.buf.segment_size()
                        == self.path_data(path_id).current_mtu() as usize
                    && self.datagrams.outgoing.is_empty()),
                "SendableFrames was {can_send:?}, but only ACKs have been written"
            );
            if sent_frames.requires_padding {
                pad_datagram |= PadDatagram::ToMinMtu;
            }

            for (path_id, _pn) in sent_frames.largest_acked.iter() {
                self.spaces[space_id]
                    .for_path(*path_id)
                    .pending_acks
                    .acks_sent();
                self.timers
                    .stop(Timer::PerPath(*path_id, PathTimer::MaxAckDelay));
            }

            // Now we need to finish the packet.  Before we do so we need to know if we will
            // be coalescing the next packet into this one, or will be ending the datagram
            // as well.  Because if this is the last packet in the datagram more padding
            // might be needed because of the packet type, or to fill the GSO segment size.

            // Are we allowed to coalesce AND is there enough space for another *packet* in
            // this datagram AND is there another packet to send in this or the next space?
            if coalesce
                && builder
                    .buf
                    .datagram_remaining_mut()
                    .saturating_sub(builder.predict_packet_end())
                    > MIN_PACKET_SPACE
                && self
                    .next_send_space(space_id, path_id, builder.buf, close)
                    .is_some()
            {
                // We can append/coalesce the next packet into the current
                // datagram. Finish the current packet without adding extra padding.
                builder.finish_and_track(now, self, path_id, sent_frames, PadDatagram::No, qlog);
            } else {
                // We need a new datagram for the next packet.  Finish the current
                // packet with padding.
                if builder.buf.num_datagrams() > 1 && matches!(pad_datagram, PadDatagram::No) {
                    // If too many padding bytes would be required to continue the
                    // GSO batch after this packet, end the GSO batch here. Ensures
                    // that fixed-size frames with heterogeneous sizes
                    // (e.g. application datagrams) won't inadvertently waste large
                    // amounts of bandwidth. The exact threshold is a bit arbitrary
                    // and might benefit from further tuning, though there's no
                    // universally optimal value.
                    const MAX_PADDING: usize = 32;
                    if builder.buf.datagram_remaining_mut()
                        > builder.predict_packet_end() + MAX_PADDING
                    {
                        trace!(
                            "GSO truncated by demand for {} padding bytes",
                            builder.buf.datagram_remaining_mut() - builder.predict_packet_end()
                        );
                        builder.finish_and_track(
                            now,
                            self,
                            path_id,
                            sent_frames,
                            PadDatagram::No,
                            qlog,
                        );
                        break;
                    }

                    // Pad the current datagram to GSO segment size so it can be
                    // included in the GSO batch.
                    builder.finish_and_track(
                        now,
                        self,
                        path_id,
                        sent_frames,
                        PadDatagram::ToSegmentSize,
                        qlog,
                    );
                } else {
                    builder.finish_and_track(now, self, path_id, sent_frames, pad_datagram, qlog);
                }
                if transmit.num_datagrams() == 1 {
                    transmit.clip_datagram_size();
                }
            }
        }

        if let Some(last_packet_number) = last_packet_number {
            // Note that when sending in multiple packet spaces the last packet number will
            // be the one from the highest packet space.
            self.path_data_mut(path_id).congestion.on_sent(
                now,
                transmit.len() as u64,
                last_packet_number,
            );
        }

        self.config.qlog_sink.emit_recovery_metrics(
            self.path_data(path_id).pto_count,
            &mut self.paths.get_mut(&path_id).unwrap().data,
            now,
            self.initial_dst_cid,
        );

        self.app_limited = transmit.is_empty() && !congestion_blocked;

        // Send MTU probe if necessary
        // TODO(multipath): We need to send MTUD probes on all paths.  But because of how
        //    the loop is written now we only send an MTUD probe on the last open path.
        if transmit.is_empty() && self.state.is_established() {
            if let Some(active_cid) = self.rem_cids.get(&path_id).map(CidQueue::active) {
                let space_id = SpaceId::Data;
                let next_pn = self.spaces[space_id].for_path(path_id).peek_tx_number();
                let probe_size = self
                    .path_data_mut(path_id)
                    .mtud
                    .poll_transmit(now, next_pn)?;

                debug_assert_eq!(transmit.num_datagrams(), 0);
                transmit.start_new_datagram_with_size(probe_size as usize);

                debug_assert_eq!(transmit.datagram_start_offset(), 0);
                let mut qlog = QlogSentPacket::default();
                let mut builder = PacketBuilder::new(
                    now,
                    space_id,
                    path_id,
                    active_cid,
                    &mut transmit,
                    true,
                    self,
                    &mut qlog,
                )?;

                // We implement MTU probes as ping packets padded up to the probe size
                trace!(?probe_size, "writing MTUD probe");
                trace!("PING");
                builder.frame_space_mut().write(frame::FrameType::PING);
                qlog.frame(&Frame::Ping);
                self.stats.frame_tx.ping += 1;

                // If supported by the peer, we want no delays to the probe's ACK
                if self.peer_supports_ack_frequency() {
                    trace!("IMMEDIATE_ACK");
                    builder
                        .frame_space_mut()
                        .write(frame::FrameType::IMMEDIATE_ACK);
                    self.stats.frame_tx.immediate_ack += 1;
                    qlog.frame(&Frame::ImmediateAck);
                }

                let sent_frames = SentFrames {
                    non_retransmits: true,
                    ..Default::default()
                };
                builder.finish_and_track(
                    now,
                    self,
                    path_id,
                    sent_frames,
                    PadDatagram::ToSize(probe_size),
                    qlog,
                );

                self.path_stats
                    .entry(path_id)
                    .or_default()
                    .sent_plpmtud_probes += 1;
            }
        }

        if transmit.is_empty() {
            return None;
        }

        trace!(
            segment_size = transmit.segment_size(),
            last_datagram_len = transmit.len() % transmit.segment_size(),
            "sending {} bytes in {} datagrams",
            transmit.len(),
            transmit.num_datagrams()
        );
        self.path_data_mut(path_id)
            .inc_total_sent(transmit.len() as u64);

        self.stats
            .udp_tx
            .on_sent(transmit.num_datagrams() as u64, transmit.len());

        Some(Transmit {
            destination: self.path_data(path_id).remote,
            size: transmit.len(),
            ecn: if self.path_data(path_id).sending_ecn {
                Some(EcnCodepoint::Ect0)
            } else {
                None
            },
            segment_size: match transmit.num_datagrams() {
                1 => None,
                _ => Some(transmit.segment_size()),
            },
            src_ip: self.local_ip,
        })
    }

    /// Returns the [`SpaceId`] of the next packet space which has data to send
    ///
    /// This takes into account the space available to frames in the next datagram.
    // TODO(flub): This duplication is not nice.
    fn next_send_space(
        &mut self,
        current_space_id: SpaceId,
        path_id: PathId,
        buf: &TransmitBuf<'_>,
        close: bool,
    ) -> Option<SpaceId> {
        // Number of bytes available for frames if this is a 1-RTT packet. We're guaranteed
        // to be able to send an individual frame at least this large in the next 1-RTT
        // packet. This could be generalized to support every space, but it's only needed to
        // handle large fixed-size frames, which only exist in 1-RTT (application
        // datagrams). We don't account for coalesced packets potentially occupying space
        // because frames can always spill into the next datagram.
        let mut space_id = current_space_id;
        loop {
            let can_send = self.space_can_send(space_id, path_id, buf.segment_size(), close);
            if !can_send.is_empty() || (close && self.spaces[space_id].crypto.is_some()) {
                return Some(space_id);
            }
            space_id = match space_id {
                SpaceId::Initial => SpaceId::Handshake,
                SpaceId::Handshake => SpaceId::Data,
                SpaceId::Data => break,
            }
        }
        None
    }

    /// Checks if creating a new datagram would be blocked by congestion control
    fn path_congestion_check(
        &mut self,
        space_id: SpaceId,
        path_id: PathId,
        transmit: &TransmitBuf<'_>,
        can_send: &SendableFrames,
        now: Instant,
    ) -> PathBlocked {
        // Anti-amplification is only based on `total_sent`, which gets updated after
        // the transmit is sent. Therefore we pass the amount of bytes for datagrams
        // that are already created, as well as 1 byte for starting another datagram. If
        // there is any anti-amplification budget left, we always allow a full MTU to be
        // sent (see https://github.com/quinn-rs/quinn/issues/1082).
        if self.side().is_server()
            && self
                .path_data(path_id)
                .anti_amplification_blocked(transmit.len() as u64 + 1)
        {
            trace!(?space_id, %path_id, "blocked by anti-amplification");
            return PathBlocked::AntiAmplification;
        }

        // Congestion control check.
        // Tail loss probes must not be blocked by congestion, or a deadlock could arise.
        let bytes_to_send = transmit.segment_size() as u64;
        let need_loss_probe = self.spaces[space_id].for_path(path_id).loss_probes > 0;

        if can_send.other && !need_loss_probe && !can_send.close {
            let path = self.path_data(path_id);
            if path.in_flight.bytes + bytes_to_send >= path.congestion.window() {
                trace!(?space_id, %path_id, "blocked by congestion control");
                return PathBlocked::Congestion;
            }
        }

        // Pacing check.
        if let Some(delay) = self.path_data_mut(path_id).pacing_delay(bytes_to_send, now) {
            self.timers
                .set(Timer::PerPath(path_id, PathTimer::Pacing), delay);
            // Loss probes and CONNECTION_CLOSE should be subject to pacing, even though
            // they are not congestion controlled.
            trace!(?space_id, %path_id, "blocked by pacing");
            return PathBlocked::Pacing;
        }

        PathBlocked::No
    }

    /// Send PATH_CHALLENGE for a previous path if necessary
    ///
    /// QUIC-TRANSPORT section 9.3.3
    /// <https://www.rfc-editor.org/rfc/rfc9000.html#name-off-path-packet-forwarding>
    fn send_prev_path_challenge(
        &mut self,
        now: Instant,
        buf: &mut TransmitBuf<'_>,
        path_id: PathId,
    ) -> Option<Transmit> {
        let (prev_cid, prev_path) = self.paths.get_mut(&path_id)?.prev.as_mut()?;
        // TODO (matheus23): We could use !prev_path.is_validating() here instead to
        // (possibly) also re-send challenges when they get lost.
        if !prev_path.send_new_challenge {
            return None;
        };
        prev_path.send_new_challenge = false;
        let token = self.rng.random();
        prev_path.challenges_sent.insert(token, now);
        let destination = prev_path.remote;
        debug_assert_eq!(
            self.highest_space,
            SpaceId::Data,
            "PATH_CHALLENGE queued without 1-RTT keys"
        );
        buf.start_new_datagram_with_size(MIN_INITIAL_SIZE as usize);

        // Use the previous CID to avoid linking the new path with the previous path. We
        // don't bother accounting for possible retirement of that prev_cid because this is
        // sent once, immediately after migration, when the CID is known to be valid. Even
        // if a post-migration packet caused the CID to be retired, it's fair to pretend
        // this is sent first.
        debug_assert_eq!(buf.datagram_start_offset(), 0);
        let mut qlog = QlogSentPacket::default();
        let mut builder = PacketBuilder::new(
            now,
            SpaceId::Data,
            path_id,
            *prev_cid,
            buf,
            false,
            self,
            &mut qlog,
        )?;
        trace!("validating previous path with PATH_CHALLENGE {:08x}", token);
        builder
            .frame_space_mut()
            .write(frame::FrameType::PATH_CHALLENGE);
        builder.frame_space_mut().write(token);
        qlog.frame(&Frame::PathChallenge(token));
        self.stats.frame_tx.path_challenge += 1;

        // An endpoint MUST expand datagrams that contain a PATH_CHALLENGE frame
        // to at least the smallest allowed maximum datagram size of 1200 bytes,
        // unless the anti-amplification limit for the path does not permit
        // sending a datagram of this size
        builder.pad_to(MIN_INITIAL_SIZE);

        builder.finish(self, now, qlog);
        self.stats.udp_tx.on_sent(1, buf.len());

        Some(Transmit {
            destination,
            size: buf.len(),
            ecn: None,
            segment_size: None,
            src_ip: self.local_ip,
        })
    }

    /// Indicate what types of frames are ready to send for the given space
    ///
    /// *packet_size* is the number of bytes available to build the next packet.  *close*
    /// *indicates whether a CONNECTION_CLOSE frame needs to be sent.
    fn space_can_send(
        &mut self,
        space_id: SpaceId,
        path_id: PathId,
        packet_size: usize,
        close: bool,
    ) -> SendableFrames {
        let pn = self.spaces[SpaceId::Data]
            .for_path(path_id)
            .peek_tx_number();
        let frame_space_1rtt = packet_size.saturating_sub(self.predict_1rtt_overhead(pn, path_id));
        if self.spaces[space_id].crypto.is_none()
            && (space_id != SpaceId::Data
                || self.zero_rtt_crypto.is_none()
                || self.side.is_server())
        {
            // No keys available for this space
            return SendableFrames::empty();
        }
        let mut can_send = self.spaces[space_id].can_send(path_id, &self.streams);
        if space_id == SpaceId::Data {
            can_send |= self.can_send_1rtt(path_id, frame_space_1rtt);
        }

        can_send.close = close && self.spaces[space_id].crypto.is_some();

        can_send
    }

    /// Process `ConnectionEvent`s generated by the associated `Endpoint`
    ///
    /// Will execute protocol logic upon receipt of a connection event, in turn preparing signals
    /// (including application `Event`s, `EndpointEvent`s and outgoing datagrams) that should be
    /// extracted through the relevant methods.
    pub fn handle_event(&mut self, event: ConnectionEvent) {
        use ConnectionEventInner::*;
        match event.0 {
            Datagram(DatagramConnectionEvent {
                now,
                remote,
                path_id,
                ecn,
                first_decode,
                remaining,
            }) => {
                let span = trace_span!("pkt", %path_id);
                let _guard = span.enter();
                // If this packet could initiate a migration and we're a client or a server that
                // forbids migration, drop the datagram. This could be relaxed to heuristically
                // permit NAT-rebinding-like migration.
                if let Some(known_remote) = self.path(path_id).map(|path| path.remote) {
                    if remote != known_remote && !self.side.remote_may_migrate(&self.state) {
                        trace!(
                            %path_id,
                            ?remote,
                            path_remote = ?self.path(path_id).map(|p| p.remote),
                            "discarding packet from unrecognized peer"
                        );
                        return;
                    }
                }

                let was_anti_amplification_blocked = self
                    .path(path_id)
                    .map(|path| path.anti_amplification_blocked(1))
                    .unwrap_or(true); // if we don't know about this path it's eagerly considered as unvalidated
                // TODO(@divma): revisit this

                self.stats.udp_rx.datagrams += 1;
                self.stats.udp_rx.bytes += first_decode.len() as u64;
                let data_len = first_decode.len();

                self.handle_decode(now, remote, path_id, ecn, first_decode);
                // The current `path` might have changed inside `handle_decode` since the packet
                // could have triggered a migration. The packet might also belong to an unknown
                // path and have been rejected. Make sure the data received is accounted for the
                // most recent path by accessing `path` after `handle_decode`.
                if let Some(path) = self.path_mut(path_id) {
                    path.inc_total_recvd(data_len as u64);
                }

                if let Some(data) = remaining {
                    self.stats.udp_rx.bytes += data.len() as u64;
                    self.handle_coalesced(now, remote, path_id, ecn, data);
                }

                if let Some(path) = self.paths.get_mut(&path_id) {
                    self.config.qlog_sink.emit_recovery_metrics(
                        path.data.pto_count,
                        &mut path.data,
                        now,
                        self.initial_dst_cid,
                    );
                }

                if was_anti_amplification_blocked {
                    // A prior attempt to set the loss detection timer may have failed due to
                    // anti-amplification, so ensure it's set now. Prevents a handshake deadlock if
                    // the server's first flight is lost.
                    self.set_loss_detection_timer(now, path_id);
                }
            }
            NewIdentifiers(ids, now, cid_len, cid_lifetime) => {
                let path_id = ids.first().map(|issued| issued.path_id).unwrap_or_default();
                debug_assert!(ids.iter().all(|issued| issued.path_id == path_id));
                let cid_state = self
                    .local_cid_state
                    .entry(path_id)
                    .or_insert_with(|| CidState::new(cid_len, cid_lifetime, now, 0));
                cid_state.new_cids(&ids, now);

                ids.into_iter().rev().for_each(|frame| {
                    self.spaces[SpaceId::Data].pending.new_cids.push(frame);
                });
                // Always update Timer::PushNewCid
                self.reset_cid_retirement();
            }
        }
    }

    /// Process timer expirations
    ///
    /// Executes protocol logic, potentially preparing signals (including application `Event`s,
    /// `EndpointEvent`s and outgoing datagrams) that should be extracted through the relevant
    /// methods.
    ///
    /// It is most efficient to call this immediately after the system clock reaches the latest
    /// `Instant` that was output by `poll_timeout`; however spurious extra calls will simply
    /// no-op and therefore are safe.
    pub fn handle_timeout(&mut self, now: Instant) {
        while let Some((timer, _time)) = self.timers.expire_before(now) {
            // TODO(@divma): remove `at` when the unicorn is born
            trace!(?timer, at=?now, "timeout");
            match timer {
                Timer::Conn(timer) => match timer {
                    ConnTimer::Close => {
                        self.state.move_to_drained(None);
                        self.endpoint_events.push_back(EndpointEventInner::Drained);
                    }
                    ConnTimer::Idle => {
                        self.kill(ConnectionError::TimedOut);
                    }
                    ConnTimer::KeepAlive => {
                        trace!("sending keep-alive");
                        self.ping();
                    }
                    ConnTimer::KeyDiscard => {
                        self.zero_rtt_crypto = None;
                        self.prev_crypto = None;
                    }
                    ConnTimer::PushNewCid => {
                        while let Some((path_id, when)) = self.next_cid_retirement() {
                            if when > now {
                                break;
                            }
                            match self.local_cid_state.get_mut(&path_id) {
                                None => error!(%path_id, "No local CID state for path"),
                                Some(cid_state) => {
                                    // Update `retire_prior_to` field in NEW_CONNECTION_ID frame
                                    let num_new_cid = cid_state.on_cid_timeout().into();
                                    if !self.state.is_closed() {
                                        trace!(
                                            "push a new CID to peer RETIRE_PRIOR_TO field {}",
                                            cid_state.retire_prior_to()
                                        );
                                        self.endpoint_events.push_back(
                                            EndpointEventInner::NeedIdentifiers(
                                                path_id,
                                                now,
                                                num_new_cid,
                                            ),
                                        );
                                    }
                                }
                            }
                        }
                    }
                },
                // TODO: add path_id as span somehow
                Timer::PerPath(path_id, timer) => {
                    let span = trace_span!("per-path timer fired", %path_id, ?timer);
                    let _guard = span.enter();
                    match timer {
                        PathTimer::PathIdle => {
                            self.close_path(now, path_id, TransportErrorCode::NO_ERROR.into())
                                .ok();
                        }

                        PathTimer::PathKeepAlive => {
                            trace!("sending keep-alive on path");
                            self.ping_path(path_id).ok();
                        }
                        PathTimer::LossDetection => {
                            self.on_loss_detection_timeout(now, path_id);
                            self.config.qlog_sink.emit_recovery_metrics(
                                self.path_data(path_id).pto_count,
                                &mut self.paths.get_mut(&path_id).unwrap().data,
                                now,
                                self.initial_dst_cid,
                            );
                        }
                        PathTimer::PathValidation => {
                            let Some(path) = self.paths.get_mut(&path_id) else {
                                continue;
                            };
                            self.timers
                                .stop(Timer::PerPath(path_id, PathTimer::PathChallengeLost));
                            debug!("path validation failed");
                            if let Some((_, prev)) = path.prev.take() {
                                path.data = prev;
                            }
                            path.data.challenges_sent.clear();
                            path.data.send_new_challenge = false;
                        }
                        PathTimer::PathChallengeLost => {
                            let Some(path) = self.paths.get_mut(&path_id) else {
                                continue;
                            };
                            trace!("path challenge deemed lost");
                            path.data.send_new_challenge = true;
                        }
                        PathTimer::PathOpen => {
                            let Some(path) = self.path_mut(path_id) else {
                                continue;
                            };
                            path.challenges_sent.clear();
                            path.send_new_challenge = false;
                            debug!("new path validation failed");
                            if let Err(err) = self.close_path(
                                now,
                                path_id,
                                TransportErrorCode::UNSTABLE_INTERFACE.into(),
                            ) {
                                warn!(?err, "failed closing path");
                            }

                            self.events.push_back(Event::Path(PathEvent::LocallyClosed {
                                id: path_id,
                                error: PathError::ValidationFailed,
                            }));
                        }
                        PathTimer::Pacing => trace!("pacing timer expired"),
                        PathTimer::MaxAckDelay => {
                            trace!("max ack delay reached");
                            // This timer is only armed in the Data space
                            self.spaces[SpaceId::Data]
                                .for_path(path_id)
                                .pending_acks
                                .on_max_ack_delay_timeout()
                        }
                        PathTimer::PathAbandoned => {
                            // The path was abandoned and 3*PTO has expired since.  Clean up all
                            // remaining state and install stateless reset token.
                            self.timers.stop_per_path(path_id);
                            if let Some(loc_cid_state) = self.local_cid_state.remove(&path_id) {
                                let (min_seq, max_seq) = loc_cid_state.active_seq();
                                for seq in min_seq..=max_seq {
                                    self.endpoint_events.push_back(
                                        EndpointEventInner::RetireConnectionId(
                                            now, path_id, seq, false,
                                        ),
                                    );
                                }
                            }
                            self.drop_path_state(path_id, now);
                        }
                        PathTimer::PathNotAbandoned => {
                            // The peer failed to respond with a PATH_ABANDON when we sent such a
                            // frame.
                            warn!("missing PATH_ABANDON from peer");
                            // TODO(flub): What should the error code be?
                            self.close(
                                now,
                                TransportErrorCode::NO_ERROR.into(),
                                "peer ignored PATH_ABANDON frame".into(),
                            );
                        }
                    }
                }
            }
        }
    }

    /// Close a connection immediately
    ///
    /// This does not ensure delivery of outstanding data. It is the application's responsibility to
    /// call this only when all important communications have been completed, e.g. by calling
    /// [`SendStream::finish`] on outstanding streams and waiting for the corresponding
    /// [`StreamEvent::Finished`] event.
    ///
    /// If [`Streams::send_streams`] returns 0, all outstanding stream data has been
    /// delivered. There may still be data from the peer that has not been received.
    ///
    /// [`StreamEvent::Finished`]: crate::StreamEvent::Finished
    pub fn close(&mut self, now: Instant, error_code: VarInt, reason: Bytes) {
        self.close_inner(
            now,
            Close::Application(frame::ApplicationClose { error_code, reason }),
        )
    }

    fn close_inner(&mut self, now: Instant, reason: Close) {
        let was_closed = self.state.is_closed();
        if !was_closed {
            self.close_common();
            self.set_close_timer(now);
            self.close = true;
            self.state.move_to_closed_local(reason);
        }
    }

    /// Control datagrams
    pub fn datagrams(&mut self) -> Datagrams<'_> {
        Datagrams { conn: self }
    }

    /// Returns connection statistics
    pub fn stats(&mut self) -> ConnectionStats {
        self.stats.clone()
    }

    /// Returns path statistics
    pub fn path_stats(&mut self, path_id: PathId) -> Option<PathStats> {
        let path = self.paths.get(&path_id)?;
        let stats = self.path_stats.entry(path_id).or_default();
        stats.rtt = path.data.rtt.get();
        stats.cwnd = path.data.congestion.window();
        stats.current_mtu = path.data.mtud.current_mtu();
        Some(*stats)
    }

    /// Ping the remote endpoint
    ///
    /// Causes an ACK-eliciting packet to be transmitted on the connection.
    pub fn ping(&mut self) {
        // TODO(flub): This is very brute-force: it pings *all* the paths.  Instead it would
        //    be nice if we could only send a single packet for this.
        for path_data in self.spaces[self.highest_space].number_spaces.values_mut() {
            path_data.ping_pending = true;
        }
    }

    /// Ping the remote endpoint over a specific path
    ///
    /// Causes an ACK-eliciting packet to be transmitted on the path.
    pub fn ping_path(&mut self, path: PathId) -> Result<(), ClosedPath> {
        let path_data = self.spaces[self.highest_space]
            .number_spaces
            .get_mut(&path)
            .ok_or(ClosedPath { _private: () })?;
        path_data.ping_pending = true;
        Ok(())
    }

    /// Update traffic keys spontaneously
    ///
    /// This can be useful for testing key updates, as they otherwise only happen infrequently.
    pub fn force_key_update(&mut self) {
        if !self.state.is_established() {
            debug!("ignoring forced key update in illegal state");
            return;
        }
        if self.prev_crypto.is_some() {
            // We already just updated, or are currently updating, the keys. Concurrent key updates
            // are illegal.
            debug!("ignoring redundant forced key update");
            return;
        }
        self.update_keys(None, false);
    }

    // Compatibility wrapper for quinn < 0.11.7. Remove for 0.12.
    #[doc(hidden)]
    #[deprecated]
    pub fn initiate_key_update(&mut self) {
        self.force_key_update();
    }

    /// Get a session reference
    pub fn crypto_session(&self) -> &dyn crypto::Session {
        &*self.crypto
    }

    /// Whether the connection is in the process of being established
    ///
    /// If this returns `false`, the connection may be either established or closed, signaled by the
    /// emission of a `Connected` or `ConnectionLost` message respectively.
    pub fn is_handshaking(&self) -> bool {
        self.state.is_handshake()
    }

    /// Whether the connection is closed
    ///
    /// Closed connections cannot transport any further data. A connection becomes closed when
    /// either peer application intentionally closes it, or when either transport layer detects an
    /// error such as a time-out or certificate validation failure.
    ///
    /// A `ConnectionLost` event is emitted with details when the connection becomes closed.
    pub fn is_closed(&self) -> bool {
        self.state.is_closed()
    }

    /// Whether there is no longer any need to keep the connection around
    ///
    /// Closed connections become drained after a brief timeout to absorb any remaining in-flight
    /// packets from the peer. All drained connections have been closed.
    pub fn is_drained(&self) -> bool {
        self.state.is_drained()
    }

    /// For clients, if the peer accepted the 0-RTT data packets
    ///
    /// The value is meaningless until after the handshake completes.
    pub fn accepted_0rtt(&self) -> bool {
        self.accepted_0rtt
    }

    /// Whether 0-RTT is/was possible during the handshake
    pub fn has_0rtt(&self) -> bool {
        self.zero_rtt_enabled
    }

    /// Whether there are any pending retransmits
    pub fn has_pending_retransmits(&self) -> bool {
        !self.spaces[SpaceId::Data].pending.is_empty(&self.streams)
    }

    /// Look up whether we're the client or server of this Connection
    pub fn side(&self) -> Side {
        self.side.side()
    }

    /// Get the address observed by the remote over the given path
    pub fn path_observed_address(&self, path_id: PathId) -> Result<Option<SocketAddr>, ClosedPath> {
        self.path(path_id)
            .map(|path_data| {
                path_data
                    .last_observed_addr_report
                    .as_ref()
                    .map(|observed| observed.socket_addr())
            })
            .ok_or(ClosedPath { _private: () })
    }

    /// The local IP address which was used when the peer established
    /// the connection
    ///
    /// This can be different from the address the endpoint is bound to, in case
    /// the endpoint is bound to a wildcard address like `0.0.0.0` or `::`.
    ///
    /// This will return `None` for clients, or when no `local_ip` was passed to
    /// [`Endpoint::handle()`](crate::Endpoint::handle) for the datagrams establishing this
    /// connection.
    pub fn local_ip(&self) -> Option<IpAddr> {
        self.local_ip
    }

    /// Current best estimate of this connection's latency (round-trip-time)
    pub fn rtt(&self) -> Duration {
        // this should return at worst the same that the poll_transmit logic would use
        // TODO(@divma): wrong
        self.path_data(PathId::ZERO).rtt.get()
    }

    /// Current state of this connection's congestion controller, for debugging purposes
    pub fn congestion_state(&self) -> &dyn Controller {
        // TODO(@divma): same as everything, wrong
        self.path_data(PathId::ZERO).congestion.as_ref()
    }

    /// Resets path-specific settings.
    ///
    /// This will force-reset several subsystems related to a specific network path.
    /// Currently this is the congestion controller, round-trip estimator, and the MTU
    /// discovery.
    ///
    /// This is useful when it is known the underlying network path has changed and the old
    /// state of these subsystems is no longer valid or optimal. In this case it might be
    /// faster or reduce loss to settle on optimal values by restarting from the initial
    /// configuration in the [`TransportConfig`].
    pub fn path_changed(&mut self, now: Instant) {
        // TODO(@divma): evaluate how this is used
        // wrong call in the multipath case anyhow
        self.paths
            .get_mut(&PathId::ZERO)
            .expect("this might fail")
            .data
            .reset(now, &self.config);
    }

    /// Modify the number of remotely initiated streams that may be concurrently open
    ///
    /// No streams may be opened by the peer unless fewer than `count` are already open. Large
    /// `count`s increase both minimum and worst-case memory consumption.
    pub fn set_max_concurrent_streams(&mut self, dir: Dir, count: VarInt) {
        self.streams.set_max_concurrent(dir, count);
        // If the limit was reduced, then a flow control update previously deemed insignificant may
        // now be significant.
        let pending = &mut self.spaces[SpaceId::Data].pending;
        self.streams.queue_max_stream_id(pending);
    }

    /// Modify the number of open paths allowed when multipath is enabled
    ///
    /// When reducing the number of concurrent paths this will only affect delaying sending
    /// new MAX_PATH_ID frames until fewer than this number of paths are possible.  To
    /// actively reduce paths they must be closed using [`Connection::close_path`], which
    /// can also be used to close not-yet-opened paths.
    ///
    /// If multipath is not negotiated (see the [`TransportConfig`]) this can not enable
    /// multipath and will fail.
    pub fn set_max_concurrent_paths(
        &mut self,
        now: Instant,
        count: NonZeroU32,
    ) -> Result<(), MultipathNotNegotiated> {
        if !self.is_multipath_negotiated() {
            return Err(MultipathNotNegotiated { _private: () });
        }
        self.max_concurrent_paths = count;

        let in_use_count = self
            .local_max_path_id
            .next()
            .saturating_sub(self.abandoned_paths.len() as u32)
            .as_u32();
        let extra_needed = count.get().saturating_sub(in_use_count);
        let new_max_path_id = self.local_max_path_id.saturating_add(extra_needed);

        self.set_max_path_id(now, new_max_path_id);

        Ok(())
    }

    /// If needed, issues a new MAX_PATH_ID frame and new CIDs for any newly allowed paths
    fn set_max_path_id(&mut self, now: Instant, max_path_id: PathId) {
        if max_path_id <= self.local_max_path_id {
            return;
        }

        self.local_max_path_id = max_path_id;
        self.spaces[SpaceId::Data].pending.max_path_id = true;

        self.issue_first_path_cids(now);
    }

    /// Current number of remotely initiated streams that may be concurrently open
    ///
    /// If the target for this limit is reduced using [`set_max_concurrent_streams`](Self::set_max_concurrent_streams),
    /// it will not change immediately, even if fewer streams are open. Instead, it will
    /// decrement by one for each time a remotely initiated stream of matching directionality is closed.
    pub fn max_concurrent_streams(&self, dir: Dir) -> u64 {
        self.streams.max_concurrent(dir)
    }

    /// See [`TransportConfig::send_window()`]
    pub fn set_send_window(&mut self, send_window: u64) {
        self.streams.set_send_window(send_window);
    }

    /// See [`TransportConfig::receive_window()`]
    pub fn set_receive_window(&mut self, receive_window: VarInt) {
        if self.streams.set_receive_window(receive_window) {
            self.spaces[SpaceId::Data].pending.max_data = true;
        }
    }

    /// Whether the Multipath for QUIC extension is enabled.
    ///
    /// Multipath is only enabled after the handshake is completed and if it was enabled by both
    /// peers.
    pub fn is_multipath_negotiated(&self) -> bool {
        !self.is_handshaking()
            && self.config.max_concurrent_multipath_paths.is_some()
            && self.peer_params.initial_max_path_id.is_some()
    }

    fn on_ack_received(
        &mut self,
        now: Instant,
        space: SpaceId,
        ack: frame::Ack,
    ) -> Result<(), TransportError> {
        // All ACKs are referencing path 0
        let path = PathId::ZERO;
        self.inner_on_ack_received(now, space, path, ack)
    }

    fn on_path_ack_received(
        &mut self,
        now: Instant,
        space: SpaceId,
        path_ack: frame::PathAck,
    ) -> Result<(), TransportError> {
        let (ack, path) = path_ack.into_ack();
        self.inner_on_ack_received(now, space, path, ack)
    }

    /// Handles an ACK frame acknowledging packets sent on *path*.
    fn inner_on_ack_received(
        &mut self,
        now: Instant,
        space: SpaceId,
        path: PathId,
        ack: frame::Ack,
    ) -> Result<(), TransportError> {
        if self.abandoned_paths.contains(&path) {
            // See also https://www.ietf.org/archive/id/draft-ietf-quic-multipath-17.html#section-3.4.3-3
            // > PATH_ACK frames received with an abandoned path ID are silently ignored, as specified in Section 4.
            trace!("silently ignoring PATH_ACK on abandoned path");
            return Ok(());
        }
        if ack.largest >= self.spaces[space].for_path(path).next_packet_number {
            return Err(TransportError::PROTOCOL_VIOLATION("unsent packet acked"));
        }
        let new_largest = {
            let space = &mut self.spaces[space].for_path(path);
            if space.largest_acked_packet.is_none_or(|pn| ack.largest > pn) {
                space.largest_acked_packet = Some(ack.largest);
                if let Some(info) = space.sent_packets.get(&ack.largest) {
                    // This should always succeed, but a misbehaving peer might ACK a packet we
                    // haven't sent. At worst, that will result in us spuriously reducing the
                    // congestion window.
                    space.largest_acked_packet_sent = info.time_sent;
                }
                true
            } else {
                false
            }
        };

        if self.detect_spurious_loss(&ack, space, path) {
            self.path_data_mut(path)
                .congestion
                .on_spurious_congestion_event();
        }

        // Avoid DoS from unreasonably huge ack ranges by filtering out just the new acks.
        let mut newly_acked = ArrayRangeSet::new();
        for range in ack.iter() {
            self.spaces[space].for_path(path).check_ack(range.clone())?;
            for (&pn, _) in self.spaces[space].for_path(path).sent_packets.range(range) {
                newly_acked.insert_one(pn);
            }
        }

        if newly_acked.is_empty() {
            return Ok(());
        }

        let mut ack_eliciting_acked = false;
        for packet in newly_acked.elts() {
            if let Some(info) = self.spaces[space].for_path(path).take(packet) {
                for (acked_path_id, acked_pn) in info.largest_acked.iter() {
                    // Assume ACKs for all packets below the largest acknowledged in
                    // `packet` have been received. This can cause the peer to spuriously
                    // retransmit if some of our earlier ACKs were lost, but allows for
                    // simpler state tracking. See discussion at
                    // https://www.rfc-editor.org/rfc/rfc9000.html#name-limiting-ranges-by-tracking
                    self.spaces[space]
                        .for_path(*acked_path_id)
                        .pending_acks
                        .subtract_below(*acked_pn);
                }
                ack_eliciting_acked |= info.ack_eliciting;

                // Notify MTU discovery that a packet was acked, because it might be an MTU probe
                let path_data = self.path_data_mut(path);
                let mtu_updated = path_data.mtud.on_acked(space, packet, info.size);
                if mtu_updated {
                    path_data
                        .congestion
                        .on_mtu_update(path_data.mtud.current_mtu());
                }

                // Notify ack frequency that a packet was acked, because it might contain an ACK_FREQUENCY frame
                self.ack_frequency.on_acked(path, packet);

                self.on_packet_acked(now, path, info);
            }
        }

        let largest_ackd = self.spaces[space].for_path(path).largest_acked_packet;
        let app_limited = self.app_limited;
        let path_data = self.path_data_mut(path);
        let in_flight = path_data.in_flight.bytes;

        path_data
            .congestion
            .on_end_acks(now, in_flight, app_limited, largest_ackd);

        if new_largest && ack_eliciting_acked {
            let ack_delay = if space != SpaceId::Data {
                Duration::from_micros(0)
            } else {
                cmp::min(
                    self.ack_frequency.peer_max_ack_delay,
                    Duration::from_micros(ack.delay << self.peer_params.ack_delay_exponent.0),
                )
            };
            let rtt = now.saturating_duration_since(
                self.spaces[space].for_path(path).largest_acked_packet_sent,
            );

            let next_pn = self.spaces[space].for_path(path).next_packet_number;
            let path_data = self.path_data_mut(path);
            // TODO(@divma): should be a method of path, should be contained in a single place
            path_data.rtt.update(ack_delay, rtt);
            if path_data.first_packet_after_rtt_sample.is_none() {
                path_data.first_packet_after_rtt_sample = Some((space, next_pn));
            }
        }

        // Must be called before crypto/pto_count are clobbered
        self.detect_lost_packets(now, space, path, true);

        if self.peer_completed_address_validation(path) {
            self.path_data_mut(path).pto_count = 0;
        }

        // Explicit congestion notification
        // TODO(@divma): this code is a good example of logic that should be contained in a single
        // place but it's split between the path data and the packet number space data, we should
        // find a way to make this work without two lookups
        if self.path_data(path).sending_ecn {
            if let Some(ecn) = ack.ecn {
                // We only examine ECN counters from ACKs that we are certain we received in transmit
                // order, allowing us to compute an increase in ECN counts to compare against the number
                // of newly acked packets that remains well-defined in the presence of arbitrary packet
                // reordering.
                if new_largest {
                    let sent = self.spaces[space].for_path(path).largest_acked_packet_sent;
                    self.process_ecn(now, space, path, newly_acked.len() as u64, ecn, sent);
                }
            } else {
                // We always start out sending ECN, so any ack that doesn't acknowledge it disables it.
                debug!("ECN not acknowledged by peer");
                self.path_data_mut(path).sending_ecn = false;
            }
        }

        self.set_loss_detection_timer(now, path);
        Ok(())
    }

    fn detect_spurious_loss(&mut self, ack: &frame::Ack, space: SpaceId, path: PathId) -> bool {
        let lost_packets = &mut self.spaces[space].for_path(path).lost_packets;

        if lost_packets.is_empty() {
            return false;
        }

        for range in ack.iter() {
            let spurious_losses: Vec<u64> = lost_packets
                .range(range.clone())
                .map(|(pn, _info)| pn)
                .copied()
                .collect();

            for pn in spurious_losses {
                lost_packets.remove(&pn);
            }
        }

        // If this ACK frame acknowledged all deemed lost packets,
        // then we have raised a spurious congestion event in the past.
        // We cannot conclude when there are remaining packets,
        // but future ACK frames might indicate a spurious loss detection.
        lost_packets.is_empty()
    }

    /// Drain lost packets that we reasonably think will never arrive
    ///
    /// The current criterion is copied from `msquic`:
    /// discard packets that were sent earlier than 2 probe timeouts ago.
    fn drain_lost_packets(&mut self, now: Instant, space: SpaceId, path: PathId) {
        let two_pto = 2 * self.path_data(path).rtt.pto_base();

        let lost_packets = &mut self.spaces[space].for_path(path).lost_packets;
        lost_packets.retain(|_pn, info| now.saturating_duration_since(info.time_sent) <= two_pto);
    }

    /// Process a new ECN block from an in-order ACK
    fn process_ecn(
        &mut self,
        now: Instant,
        space: SpaceId,
        path: PathId,
        newly_acked: u64,
        ecn: frame::EcnCounts,
        largest_sent_time: Instant,
    ) {
        match self.spaces[space]
            .for_path(path)
            .detect_ecn(newly_acked, ecn)
        {
            Err(e) => {
                debug!("halting ECN due to verification failure: {}", e);

                self.path_data_mut(path).sending_ecn = false;
                // Wipe out the existing value because it might be garbage and could interfere with
                // future attempts to use ECN on new paths.
                self.spaces[space].for_path(path).ecn_feedback = frame::EcnCounts::ZERO;
            }
            Ok(false) => {}
            Ok(true) => {
                self.path_stats.entry(path).or_default().congestion_events += 1;
                self.path_data_mut(path).congestion.on_congestion_event(
                    now,
                    largest_sent_time,
                    false,
                    true,
                    0,
                );
            }
        }
    }

    // Not timing-aware, so it's safe to call this for inferred acks, such as arise from
    // high-latency handshakes
    fn on_packet_acked(&mut self, now: Instant, path_id: PathId, info: SentPacket) {
        self.paths
            .get_mut(&path_id)
            .expect("known path")
            .remove_in_flight(&info);
        let app_limited = self.app_limited;
        let path = self.path_data_mut(path_id);
        if info.ack_eliciting && !path.is_validating_path() {
            // Only pass ACKs to the congestion controller if we are not validating the current
            // path, so as to ignore any ACKs from older paths still coming in.
            let rtt = path.rtt;
            path.congestion
                .on_ack(now, info.time_sent, info.size.into(), app_limited, &rtt);
        }

        // Update state for confirmed delivery of frames
        if let Some(retransmits) = info.retransmits.get() {
            for (id, _) in retransmits.reset_stream.iter() {
                self.streams.reset_acked(*id);
            }
        }

        for frame in info.stream_frames {
            self.streams.received_ack_of(frame);
        }
    }

    fn set_key_discard_timer(&mut self, now: Instant, space: SpaceId) {
        let start = if self.zero_rtt_crypto.is_some() {
            now
        } else {
            self.prev_crypto
                .as_ref()
                .expect("no previous keys")
                .end_packet
                .as_ref()
                .expect("update not acknowledged yet")
                .1
        };

        // QUIC-MULTIPATH § 2.5 Key Phase Update Process: use largest PTO off all paths.
        self.timers.set(
            Timer::Conn(ConnTimer::KeyDiscard),
            start + self.pto_max_path(space) * 3,
        );
    }

    /// Handle a [`PathTimer::LossDetection`] timeout.
    ///
    /// This timer expires for two reasons:
    /// - An ACK-eliciting packet we sent should be considered lost.
    /// - The PTO may have expired and a tail-loss probe needs to be scheduled.
    ///
    /// The former needs us to schedule re-transmission of the lost data.
    ///
    /// The latter means we have not received an ACK for an ack-eliciting packet we sent
    /// within the PTO time-window. We need to schedule a tail-loss probe, an ack-eliciting
    /// packet, to try and elicit new acknowledgements. These new acknowledgements will
    /// indicate whether the previously sent packets were lost or not.
    fn on_loss_detection_timeout(&mut self, now: Instant, path_id: PathId) {
        if let Some((_, pn_space)) = self.loss_time_and_space(path_id) {
            // Time threshold loss Detection
            self.detect_lost_packets(now, pn_space, path_id, false);
            self.set_loss_detection_timer(now, path_id);
            return;
        }

        let (_, space) = match self.pto_time_and_space(now, path_id) {
            Some(x) => x,
            None => {
                error!(%path_id, "PTO expired while unset");
                return;
            }
        };
        trace!(
            in_flight = self.path_data(path_id).in_flight.bytes,
            count = self.path_data(path_id).pto_count,
            ?space,
            %path_id,
            "PTO fired"
        );

        let count = match self.path_data(path_id).in_flight.ack_eliciting {
            // A PTO when we're not expecting any ACKs must be due to handshake anti-amplification
            // deadlock preventions
            0 => {
                debug_assert!(!self.peer_completed_address_validation(path_id));
                1
            }
            // Conventional loss probe
            _ => 2,
        };
        let pns = self.spaces[space].for_path(path_id);
        pns.loss_probes = pns.loss_probes.saturating_add(count);
        let path_data = self.path_data_mut(path_id);
        path_data.pto_count = path_data.pto_count.saturating_add(1);
        self.set_loss_detection_timer(now, path_id);
    }

    /// Detect any lost packets
    ///
    /// There are two cases in which we detects lost packets:
    ///
    /// - We received an ACK packet.
    /// - The [`PathTimer::LossDetection`] timer expired. So there is an un-acknowledged packet
    ///   that was followed by an acknowledged packet. The loss timer for this
    ///   un-acknowledged packet expired and we need to detect that packet as lost.
    ///
    /// Packets are lost if they are both (See RFC9002 §6.1):
    ///
    /// - Unacknowledged, in flight and sent prior to an acknowledged packet.
    /// - Old enough by either:
    ///   - Having a packet number [`TransportConfig::packet_threshold`] lower then the last
    ///     acknowledged packet.
    ///   - Being sent [`TransportConfig::time_threshold`] * RTT in the past.
    fn detect_lost_packets(
        &mut self,
        now: Instant,
        pn_space: SpaceId,
        path_id: PathId,
        due_to_ack: bool,
    ) {
        let mut lost_packets = Vec::<u64>::new();
        let mut lost_mtu_probe = None;
        let mut in_persistent_congestion = false;
        let mut size_of_lost_packets = 0u64;
        self.spaces[pn_space].for_path(path_id).loss_time = None;

        // Find all the lost packets, populating all variables initialised above.

        let path = self.path_data(path_id);
        let in_flight_mtu_probe = path.mtud.in_flight_mtu_probe();
        let loss_delay = path
            .rtt
            .conservative()
            .mul_f32(self.config.time_threshold)
            .max(TIMER_GRANULARITY);
        let first_packet_after_rtt_sample = path.first_packet_after_rtt_sample;

        let largest_acked_packet = self.spaces[pn_space]
            .for_path(path_id)
            .largest_acked_packet
            .expect("detect_lost_packets only to be called if path received at least one ACK");
        let packet_threshold = self.config.packet_threshold as u64;

        // InPersistentCongestion: Determine if all packets in the time period before the newest
        // lost packet, including the edges, are marked lost. PTO computation must always
        // include max ACK delay, i.e. operate as if in Data space (see RFC9001 §7.6.1).
        let congestion_period = self
            .pto(SpaceId::Data, path_id)
            .saturating_mul(self.config.persistent_congestion_threshold);
        let mut persistent_congestion_start: Option<Instant> = None;
        let mut prev_packet = None;
        let space = self.spaces[pn_space].for_path(path_id);

        for (&packet, info) in space.sent_packets.range(0..largest_acked_packet) {
            if prev_packet != Some(packet.wrapping_sub(1)) {
                // An intervening packet was acknowledged
                persistent_congestion_start = None;
            }

            // Packets sent before now - loss_delay are deemed lost.
            // However, we avoid subtraction as it can panic and there's no
            // saturating equivalent of this subtraction operation with a Duration.
            let packet_too_old = now.saturating_duration_since(info.time_sent) >= loss_delay;
            if packet_too_old || largest_acked_packet >= packet + packet_threshold {
                // The packet should be declared lost.
                if Some(packet) == in_flight_mtu_probe {
                    // Lost MTU probes are not included in `lost_packets`, because they
                    // should not trigger a congestion control response
                    lost_mtu_probe = in_flight_mtu_probe;
                } else {
                    lost_packets.push(packet);
                    size_of_lost_packets += info.size as u64;
                    if info.ack_eliciting && due_to_ack {
                        match persistent_congestion_start {
                            // Two ACK-eliciting packets lost more than
                            // congestion_period apart, with no ACKed packets in between
                            Some(start) if info.time_sent - start > congestion_period => {
                                in_persistent_congestion = true;
                            }
                            // Persistent congestion must start after the first RTT sample
                            None if first_packet_after_rtt_sample
                                .is_some_and(|x| x < (pn_space, packet)) =>
                            {
                                persistent_congestion_start = Some(info.time_sent);
                            }
                            _ => {}
                        }
                    }
                }
            } else {
                // The packet should not yet be declared lost.
                if space.loss_time.is_none() {
                    // Since we iterate in order the lowest packet number's loss time will
                    // always be the earliest.
                    space.loss_time = Some(info.time_sent + loss_delay);
                }
                persistent_congestion_start = None;
            }

            prev_packet = Some(packet);
        }

        self.handle_lost_packets(
            pn_space,
            path_id,
            now,
            lost_packets,
            lost_mtu_probe,
            loss_delay,
            in_persistent_congestion,
            size_of_lost_packets,
        );
    }

    /// Drops the path state, declaring any remaining in-flight packets as lost
    fn drop_path_state(&mut self, path_id: PathId, now: Instant) {
        trace!(%path_id, "dropping path state");
        let path = self.path_data(path_id);
        let in_flight_mtu_probe = path.mtud.in_flight_mtu_probe();

        let mut size_of_lost_packets = 0u64; // add to path_stats.lost_bytes;
        let lost_pns: Vec<_> = self.spaces[SpaceId::Data]
            .for_path(path_id)
            .sent_packets
            .iter()
            .filter(|(pn, _info)| Some(**pn) != in_flight_mtu_probe)
            .map(|(pn, info)| {
                size_of_lost_packets += info.size as u64;
                *pn
            })
            .collect();

        if !lost_pns.is_empty() {
            trace!(
                %path_id,
                count = lost_pns.len(),
                lost_bytes = size_of_lost_packets,
                "packets lost on path abandon"
            );
            self.handle_lost_packets(
                SpaceId::Data,
                path_id,
                now,
                lost_pns,
                in_flight_mtu_probe,
                Duration::ZERO,
                false,
                size_of_lost_packets,
            );
        }
        self.paths.remove(&path_id);
        self.spaces[SpaceId::Data].number_spaces.remove(&path_id);

        let path_stats = self.path_stats.remove(&path_id).unwrap_or_default();
        self.events.push_back(
            PathEvent::Abandoned {
                id: path_id,
                path_stats,
            }
            .into(),
        );
    }

    fn handle_lost_packets(
        &mut self,
        pn_space: SpaceId,
        path_id: PathId,
        now: Instant,
        lost_packets: Vec<u64>,
        lost_mtu_probe: Option<u64>,
        loss_delay: Duration,
        in_persistent_congestion: bool,
        size_of_lost_packets: u64,
    ) {
        debug_assert!(
            {
                let mut sorted = lost_packets.clone();
                sorted.sort();
                sorted == lost_packets
            },
            "lost_packets must be sorted"
        );

        self.drain_lost_packets(now, pn_space, path_id);

        // OnPacketsLost
        if let Some(largest_lost) = lost_packets.last().cloned() {
            let old_bytes_in_flight = self.path_data_mut(path_id).in_flight.bytes;
            let largest_lost_sent =
                self.spaces[pn_space].for_path(path_id).sent_packets[&largest_lost].time_sent;
            let path_stats = self.path_stats.entry(path_id).or_default();
            path_stats.lost_packets += lost_packets.len() as u64;
            path_stats.lost_bytes += size_of_lost_packets;
            trace!(
                %path_id,
                count = lost_packets.len(),
                lost_bytes = size_of_lost_packets,
                "packets lost",
            );

            for &packet in &lost_packets {
                let Some(info) = self.spaces[pn_space].for_path(path_id).take(packet) else {
                    continue;
                };
                self.config.qlog_sink.emit_packet_lost(
                    packet,
                    &info,
                    loss_delay,
                    pn_space,
                    now,
                    self.initial_dst_cid,
                );
                self.paths
                    .get_mut(&path_id)
                    .unwrap()
                    .remove_in_flight(&info);

                for frame in info.stream_frames {
                    self.streams.retransmit(frame);
                }
                self.spaces[pn_space].pending |= info.retransmits;
                self.path_data_mut(path_id)
                    .mtud
                    .on_non_probe_lost(packet, info.size);

                self.spaces[pn_space].for_path(path_id).lost_packets.insert(
                    packet,
                    LostPacket {
                        time_sent: info.time_sent,
                    },
                );
            }

            let path = self.path_data_mut(path_id);
            if path.mtud.black_hole_detected(now) {
                path.congestion.on_mtu_update(path.mtud.current_mtu());
                if let Some(max_datagram_size) = self.datagrams().max_size() {
                    self.datagrams.drop_oversized(max_datagram_size);
                }
                self.path_stats
                    .entry(path_id)
                    .or_default()
                    .black_holes_detected += 1;
            }

            // Don't apply congestion penalty for lost ack-only packets
            let lost_ack_eliciting =
                old_bytes_in_flight != self.path_data_mut(path_id).in_flight.bytes;

            if lost_ack_eliciting {
                self.path_stats
                    .entry(path_id)
                    .or_default()
                    .congestion_events += 1;
                self.path_data_mut(path_id).congestion.on_congestion_event(
                    now,
                    largest_lost_sent,
                    in_persistent_congestion,
                    false,
                    size_of_lost_packets,
                );
            }
        }

        // Handle a lost MTU probe
        if let Some(packet) = lost_mtu_probe {
            let info = self.spaces[SpaceId::Data]
                .for_path(path_id)
                .take(packet)
                .unwrap(); // safe: lost_mtu_probe is omitted from lost_packets, and
            // therefore must not have been removed yet
            self.paths
                .get_mut(&path_id)
                .unwrap()
                .remove_in_flight(&info);
            self.path_data_mut(path_id).mtud.on_probe_lost();
            self.path_stats
                .entry(path_id)
                .or_default()
                .lost_plpmtud_probes += 1;
        }
    }

    /// Returns the earliest time packets should be declared lost for all spaces on a path.
    ///
    /// If a path has an acknowledged packet with any prior un-acknowledged packets, the
    /// earliest un-acknowledged packet can be declared lost after a timeout has elapsed.
    /// The time returned is when this packet should be declared lost.
    fn loss_time_and_space(&self, path_id: PathId) -> Option<(Instant, SpaceId)> {
        SpaceId::iter()
            .filter_map(|id| {
                self.spaces[id]
                    .number_spaces
                    .get(&path_id)
                    .and_then(|pns| pns.loss_time)
                    .map(|time| (time, id))
            })
            .min_by_key(|&(time, _)| time)
    }

    /// Returns the earliest next PTO should fire for all spaces on a path.
    fn pto_time_and_space(&mut self, now: Instant, path_id: PathId) -> Option<(Instant, SpaceId)> {
        let path = self.path(path_id)?;
        let pto_count = path.pto_count;
        let backoff = 2u32.pow(pto_count.min(MAX_BACKOFF_EXPONENT));
        let mut duration = path.rtt.pto_base() * backoff;

        if path_id == PathId::ZERO
            && path.in_flight.ack_eliciting == 0
            && !self.peer_completed_address_validation(PathId::ZERO)
        {
            // Address Validation during Connection Establishment:
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1. To prevent a
            // deadlock if an Initial or Handshake packet from the server is lost and the
            // server can not send more due to its anti-amplification limit the client must
            // send another packet on PTO.
            let space = match self.highest_space {
                SpaceId::Handshake => SpaceId::Handshake,
                _ => SpaceId::Initial,
            };

            return Some((now + duration, space));
        }

        let mut result = None;
        for space in SpaceId::iter() {
            let Some(pns) = self.spaces[space].number_spaces.get(&path_id) else {
                continue;
            };

            if !pns.has_in_flight() {
                continue;
            }
            if space == SpaceId::Data {
                // Skip ApplicationData until handshake completes.
                if self.is_handshaking() {
                    return result;
                }
                // Include max_ack_delay and backoff for ApplicationData.
                duration += self.ack_frequency.max_ack_delay_for_pto() * backoff;
            }
            let Some(last_ack_eliciting) = pns.time_of_last_ack_eliciting_packet else {
                continue;
            };
            let pto = last_ack_eliciting + duration;
            if result.is_none_or(|(earliest_pto, _)| pto < earliest_pto) {
                if path.anti_amplification_blocked(1) {
                    // Nothing would be able to be sent.
                    continue;
                }
                if path.in_flight.ack_eliciting == 0 {
                    // Nothing ack-eliciting, no PTO to arm/fire.
                    continue;
                }
                result = Some((pto, space));
            }
        }
        result
    }

    fn peer_completed_address_validation(&self, path: PathId) -> bool {
        // TODO(flub): This logic needs updating for multipath
        if self.side.is_server() || self.state.is_closed() {
            return true;
        }
        // The server is guaranteed to have validated our address if any of our handshake or 1-RTT
        // packets are acknowledged or we've seen HANDSHAKE_DONE and discarded handshake keys.
        self.spaces[SpaceId::Handshake]
            .path_space(PathId::ZERO)
            .and_then(|pns| pns.largest_acked_packet)
            .is_some()
            || self.spaces[SpaceId::Data]
                .path_space(path)
                .and_then(|pns| pns.largest_acked_packet)
                .is_some()
            || (self.spaces[SpaceId::Data].crypto.is_some()
                && self.spaces[SpaceId::Handshake].crypto.is_none())
    }

    /// Resets the the [`PathTimer::LossDetection`] timer to the next instant it may be needed
    ///
    /// The timer must fire if either:
    /// - An ack-eliciting packet we sent needs to be declared lost.
    /// - A tail-loss probe needs to be sent.
    ///
    /// See [`Connection::on_loss_detection_timeout`] for details.
    fn set_loss_detection_timer(&mut self, now: Instant, path_id: PathId) {
        if self.state.is_closed() {
            // No loss detection takes place on closed connections, and `close_common` already
            // stopped time timer. Ensure we don't restart it inadvertently, e.g. in response to a
            // reordered packet being handled by state-insensitive code.
            return;
        }

        if let Some((loss_time, _)) = self.loss_time_and_space(path_id) {
            // Time threshold loss detection.
            self.timers
                .set(Timer::PerPath(path_id, PathTimer::LossDetection), loss_time);
            return;
        }

        // Determine which PN space to arm PTO for.
        // Calculate PTO duration
        if let Some((timeout, _)) = self.pto_time_and_space(now, path_id) {
            self.timers
                .set(Timer::PerPath(path_id, PathTimer::LossDetection), timeout);
        } else {
            self.timers
                .stop(Timer::PerPath(path_id, PathTimer::LossDetection));
        }
    }

    /// The maximum probe timeout across all paths
    ///
    /// See [`Connection::pto`]
    fn pto_max_path(&self, space: SpaceId) -> Duration {
        match space {
            SpaceId::Initial | SpaceId::Handshake => self.pto(space, PathId::ZERO),
            SpaceId::Data => self
                .paths
                .keys()
                .map(|path_id| self.pto(space, *path_id))
                .max()
                .expect("there should be one at least path"),
        }
    }

    /// Probe Timeout
    ///
    /// The PTO is logically the time in which you'd expect to receive an acknowledgement
    /// for a packet. So approximately RTT + max_ack_delay.
    fn pto(&self, space: SpaceId, path_id: PathId) -> Duration {
        let max_ack_delay = match space {
            SpaceId::Initial | SpaceId::Handshake => Duration::ZERO,
            SpaceId::Data => self.ack_frequency.max_ack_delay_for_pto(),
        };
        self.path_data(path_id).rtt.pto_base() + max_ack_delay
    }

    fn on_packet_authenticated(
        &mut self,
        now: Instant,
        space_id: SpaceId,
        path_id: PathId,
        ecn: Option<EcnCodepoint>,
        packet: Option<u64>,
        spin: bool,
        is_1rtt: bool,
    ) {
        self.total_authed_packets += 1;
        self.reset_keep_alive(path_id, now);
        self.reset_idle_timeout(now, space_id, path_id);
        self.permit_idle_reset = true;
        self.receiving_ecn |= ecn.is_some();
        if let Some(x) = ecn {
            let space = &mut self.spaces[space_id];
            space.for_path(path_id).ecn_counters += x;

            if x.is_ce() {
                space
                    .for_path(path_id)
                    .pending_acks
                    .set_immediate_ack_required();
            }
        }

        let packet = match packet {
            Some(x) => x,
            None => return,
        };
        match &self.side {
            ConnectionSide::Client { .. } => {
                // If we received a handshake packet that authenticated, then we're talking to
                // the real server.  From now on we should no longer allow the server to migrate
                // its address.
                if space_id == SpaceId::Handshake {
                    if let Some(hs) = self.state.as_handshake_mut() {
                        hs.allow_server_migration = false;
                    }
                }
            }
            ConnectionSide::Server { .. } => {
                if self.spaces[SpaceId::Initial].crypto.is_some() && space_id == SpaceId::Handshake
                {
                    // A server stops sending and processing Initial packets when it receives its first Handshake packet.
                    self.discard_space(now, SpaceId::Initial);
                }
                if self.zero_rtt_crypto.is_some() && is_1rtt {
                    // Discard 0-RTT keys soon after receiving a 1-RTT packet
                    self.set_key_discard_timer(now, space_id)
                }
            }
        }
        let space = self.spaces[space_id].for_path(path_id);
        space.pending_acks.insert_one(packet, now);
        if packet >= space.rx_packet.unwrap_or_default() {
            space.rx_packet = Some(packet);
            // Update outgoing spin bit, inverting iff we're the client
            self.spin = self.side.is_client() ^ spin;
        }
    }

    /// Resets the idle timeout timers
    ///
    /// Without multipath there is only the connection-wide idle timeout. When multipath is
    /// enabled there is an additional per-path idle timeout.
    fn reset_idle_timeout(&mut self, now: Instant, space: SpaceId, path_id: PathId) {
        // First reset the global idle timeout.
        if let Some(timeout) = self.idle_timeout {
            if self.state.is_closed() {
                self.timers.stop(Timer::Conn(ConnTimer::Idle));
            } else {
                let dt = cmp::max(timeout, 3 * self.pto_max_path(space));
                self.timers.set(Timer::Conn(ConnTimer::Idle), now + dt);
            }
        }

        // Now handle the per-path state
        if let Some(timeout) = self.path_data(path_id).idle_timeout {
            if self.state.is_closed() {
                self.timers
                    .stop(Timer::PerPath(path_id, PathTimer::PathIdle));
            } else {
                let dt = cmp::max(timeout, 3 * self.pto(space, path_id));
                self.timers
                    .set(Timer::PerPath(path_id, PathTimer::PathIdle), now + dt);
            }
        }
    }

    /// Resets both the [`ConnTimer::KeepAlive`] and [`PathTimer::PathKeepAlive`] timers
    fn reset_keep_alive(&mut self, path_id: PathId, now: Instant) {
        if !self.state.is_established() {
            return;
        }

        if let Some(interval) = self.config.keep_alive_interval {
            self.timers
                .set(Timer::Conn(ConnTimer::KeepAlive), now + interval);
        }

        if let Some(interval) = self.path_data(path_id).keep_alive {
            self.timers.set(
                Timer::PerPath(path_id, PathTimer::PathKeepAlive),
                now + interval,
            );
        }
    }

    /// Sets the timer for when a previously issued CID should be retired next
    fn reset_cid_retirement(&mut self) {
        if let Some((_path, t)) = self.next_cid_retirement() {
            self.timers.set(Timer::Conn(ConnTimer::PushNewCid), t);
        }
    }

    /// The next time when a previously issued CID should be retired
    fn next_cid_retirement(&self) -> Option<(PathId, Instant)> {
        self.local_cid_state
            .iter()
            .filter_map(|(path_id, cid_state)| cid_state.next_timeout().map(|t| (*path_id, t)))
            .min_by_key(|(_path_id, timeout)| *timeout)
    }

    /// Handle the already-decrypted first packet from the client
    ///
    /// Decrypting the first packet in the `Endpoint` allows stateless packet handling to be more
    /// efficient.
    pub(crate) fn handle_first_packet(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        ecn: Option<EcnCodepoint>,
        packet_number: u64,
        packet: InitialPacket,
        remaining: Option<BytesMut>,
    ) -> Result<(), ConnectionError> {
        let span = trace_span!("first recv");
        let _guard = span.enter();
        debug_assert!(self.side.is_server());
        let len = packet.header_data.len() + packet.payload.len();
        let path_id = PathId::ZERO;
        self.path_data_mut(path_id).total_recvd = len as u64;

        if let Some(hs) = self.state.as_handshake_mut() {
            hs.expected_token = packet.header.token.clone();
        } else {
            unreachable!("first packet must be delivered in Handshake state");
        }

        // The first packet is always on PathId::ZERO
        self.on_packet_authenticated(
            now,
            SpaceId::Initial,
            path_id,
            ecn,
            Some(packet_number),
            false,
            false,
        );

        let packet: Packet = packet.into();

        let mut qlog = QlogRecvPacket::new(len);
        qlog.header(&packet.header, Some(packet_number));

        self.process_decrypted_packet(
            now,
            remote,
            path_id,
            Some(packet_number),
            packet,
            &mut qlog,
        )?;
        self.config.qlog_sink.emit_packet_received(self, qlog, now);
        if let Some(data) = remaining {
            self.handle_coalesced(now, remote, path_id, ecn, data);
        }

        self.config.qlog_sink.emit_recovery_metrics(
            self.path_data(path_id).pto_count,
            &mut self.paths.get_mut(&path_id).unwrap().data,
            now,
            self.initial_dst_cid,
        );

        Ok(())
    }

    fn init_0rtt(&mut self) {
        let (header, packet) = match self.crypto.early_crypto() {
            Some(x) => x,
            None => return,
        };
        if self.side.is_client() {
            match self.crypto.transport_parameters() {
                Ok(params) => {
                    let params = params
                        .expect("crypto layer didn't supply transport parameters with ticket");
                    // Certain values must not be cached
                    let params = TransportParameters {
                        initial_src_cid: None,
                        original_dst_cid: None,
                        preferred_address: None,
                        retry_src_cid: None,
                        stateless_reset_token: None,
                        min_ack_delay: None,
                        ack_delay_exponent: TransportParameters::default().ack_delay_exponent,
                        max_ack_delay: TransportParameters::default().max_ack_delay,
                        initial_max_path_id: None,
                        ..params
                    };
                    self.set_peer_params(params);
                }
                Err(e) => {
                    error!("session ticket has malformed transport parameters: {}", e);
                    return;
                }
            }
        }
        trace!("0-RTT enabled");
        self.zero_rtt_enabled = true;
        self.zero_rtt_crypto = Some(ZeroRttCrypto { header, packet });
    }

    fn read_crypto(
        &mut self,
        space: SpaceId,
        crypto: &frame::Crypto,
        payload_len: usize,
    ) -> Result<(), TransportError> {
        let expected = if !self.state.is_handshake() {
            SpaceId::Data
        } else if self.highest_space == SpaceId::Initial {
            SpaceId::Initial
        } else {
            // On the server, self.highest_space can be Data after receiving the client's first
            // flight, but we expect Handshake CRYPTO until the handshake is complete.
            SpaceId::Handshake
        };
        // We can't decrypt Handshake packets when highest_space is Initial, CRYPTO frames in 0-RTT
        // packets are illegal, and we don't process 1-RTT packets until the handshake is
        // complete. Therefore, we will never see CRYPTO data from a later-than-expected space.
        debug_assert!(space <= expected, "received out-of-order CRYPTO data");

        let end = crypto.offset + crypto.data.len() as u64;
        if space < expected && end > self.spaces[space].crypto_stream.bytes_read() {
            warn!(
                "received new {:?} CRYPTO data when expecting {:?}",
                space, expected
            );
            return Err(TransportError::PROTOCOL_VIOLATION(
                "new data at unexpected encryption level",
            ));
        }

        let space = &mut self.spaces[space];
        let max = end.saturating_sub(space.crypto_stream.bytes_read());
        if max > self.config.crypto_buffer_size as u64 {
            return Err(TransportError::CRYPTO_BUFFER_EXCEEDED(""));
        }

        space
            .crypto_stream
            .insert(crypto.offset, crypto.data.clone(), payload_len);
        while let Some(chunk) = space.crypto_stream.read(usize::MAX, true) {
            trace!("consumed {} CRYPTO bytes", chunk.bytes.len());
            if self.crypto.read_handshake(&chunk.bytes)? {
                self.events.push_back(Event::HandshakeDataReady);
            }
        }

        Ok(())
    }

    fn write_crypto(&mut self) {
        loop {
            let space = self.highest_space;
            let mut outgoing = Vec::new();
            if let Some(crypto) = self.crypto.write_handshake(&mut outgoing) {
                match space {
                    SpaceId::Initial => {
                        self.upgrade_crypto(SpaceId::Handshake, crypto);
                    }
                    SpaceId::Handshake => {
                        self.upgrade_crypto(SpaceId::Data, crypto);
                    }
                    _ => unreachable!("got updated secrets during 1-RTT"),
                }
            }
            if outgoing.is_empty() {
                if space == self.highest_space {
                    break;
                } else {
                    // Keys updated, check for more data to send
                    continue;
                }
            }
            let offset = self.spaces[space].crypto_offset;
            let outgoing = Bytes::from(outgoing);
            if let Some(hs) = self.state.as_handshake_mut() {
                if space == SpaceId::Initial && offset == 0 && self.side.is_client() {
                    hs.client_hello = Some(outgoing.clone());
                }
            }
            self.spaces[space].crypto_offset += outgoing.len() as u64;
            trace!("wrote {} {:?} CRYPTO bytes", outgoing.len(), space);
            self.spaces[space].pending.crypto.push_back(frame::Crypto {
                offset,
                data: outgoing,
            });
        }
    }

    /// Switch to stronger cryptography during handshake
    fn upgrade_crypto(&mut self, space: SpaceId, crypto: Keys) {
        debug_assert!(
            self.spaces[space].crypto.is_none(),
            "already reached packet space {space:?}"
        );
        trace!("{:?} keys ready", space);
        if space == SpaceId::Data {
            // Precompute the first key update
            self.next_crypto = Some(
                self.crypto
                    .next_1rtt_keys()
                    .expect("handshake should be complete"),
            );
        }

        self.spaces[space].crypto = Some(crypto);
        debug_assert!(space as usize > self.highest_space as usize);
        self.highest_space = space;
        if space == SpaceId::Data && self.side.is_client() {
            // Discard 0-RTT keys because 1-RTT keys are available.
            self.zero_rtt_crypto = None;
        }
    }

    fn discard_space(&mut self, now: Instant, space_id: SpaceId) {
        debug_assert!(space_id != SpaceId::Data);
        trace!("discarding {:?} keys", space_id);
        if space_id == SpaceId::Initial {
            // No longer needed
            if let ConnectionSide::Client { token, .. } = &mut self.side {
                *token = Bytes::new();
            }
        }
        let space = &mut self.spaces[space_id];
        space.crypto = None;
        let pns = space.for_path(PathId::ZERO);
        pns.time_of_last_ack_eliciting_packet = None;
        pns.loss_time = None;
        pns.loss_probes = 0;
        let sent_packets = mem::take(&mut pns.sent_packets);
        let path = self.paths.get_mut(&PathId::ZERO).unwrap();
        for packet in sent_packets.into_values() {
            path.data.remove_in_flight(&packet);
        }

        self.set_loss_detection_timer(now, PathId::ZERO)
    }

    fn handle_coalesced(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        path_id: PathId,
        ecn: Option<EcnCodepoint>,
        data: BytesMut,
    ) {
        self.path_data_mut(path_id)
            .inc_total_recvd(data.len() as u64);
        let mut remaining = Some(data);
        let cid_len = self
            .local_cid_state
            .values()
            .map(|cid_state| cid_state.cid_len())
            .next()
            .expect("one cid_state must exist");
        while let Some(data) = remaining {
            match PartialDecode::new(
                data,
                &FixedLengthConnectionIdParser::new(cid_len),
                &[self.version],
                self.endpoint_config.grease_quic_bit,
            ) {
                Ok((partial_decode, rest)) => {
                    remaining = rest;
                    self.handle_decode(now, remote, path_id, ecn, partial_decode);
                }
                Err(e) => {
                    trace!("malformed header: {}", e);
                    return;
                }
            }
        }
    }

    fn handle_decode(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        path_id: PathId,
        ecn: Option<EcnCodepoint>,
        partial_decode: PartialDecode,
    ) {
        let qlog = QlogRecvPacket::new(partial_decode.len());
        if let Some(decoded) = packet_crypto::unprotect_header(
            partial_decode,
            &self.spaces,
            self.zero_rtt_crypto.as_ref(),
            self.peer_params.stateless_reset_token,
        ) {
            self.handle_packet(
                now,
                remote,
                path_id,
                ecn,
                decoded.packet,
                decoded.stateless_reset,
                qlog,
            );
        }
    }

    fn handle_packet(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        path_id: PathId,
        ecn: Option<EcnCodepoint>,
        packet: Option<Packet>,
        stateless_reset: bool,
        mut qlog: QlogRecvPacket,
    ) {
        self.stats.udp_rx.ios += 1;
        if let Some(ref packet) = packet {
            trace!(
                "got {:?} packet ({} bytes) from {} using id {}",
                packet.header.space(),
                packet.payload.len() + packet.header_data.len(),
                remote,
                packet.header.dst_cid(),
            );
        }

        if self.is_handshaking() {
            if path_id != PathId::ZERO {
                debug!(%remote, %path_id, "discarding multipath packet during handshake");
                return;
            }
            if remote != self.path_data_mut(path_id).remote {
                if let Some(hs) = self.state.as_handshake() {
                    if hs.allow_server_migration {
                        trace!(?remote, prev = ?self.path_data(path_id).remote, "server migrated to new remote");
                        self.path_data_mut(path_id).remote = remote;
                    } else {
                        debug!("discarding packet with unexpected remote during handshake");
                        return;
                    }
                } else {
                    debug!("discarding packet with unexpected remote during handshake");
                    return;
                }
            }
        }

        let was_closed = self.state.is_closed();
        let was_drained = self.state.is_drained();

        let decrypted = match packet {
            None => Err(None),
            Some(mut packet) => self
                .decrypt_packet(now, path_id, &mut packet)
                .map(move |number| (packet, number)),
        };
        let result = match decrypted {
            _ if stateless_reset => {
                debug!("got stateless reset");
                Err(ConnectionError::Reset)
            }
            Err(Some(e)) => {
                warn!("illegal packet: {}", e);
                Err(e.into())
            }
            Err(None) => {
                debug!("failed to authenticate packet");
                self.authentication_failures += 1;
                let integrity_limit = self.spaces[self.highest_space]
                    .crypto
                    .as_ref()
                    .unwrap()
                    .packet
                    .local
                    .integrity_limit();
                if self.authentication_failures > integrity_limit {
                    Err(TransportError::AEAD_LIMIT_REACHED("integrity limit violated").into())
                } else {
                    return;
                }
            }
            Ok((packet, number)) => {
                qlog.header(&packet.header, number);
                let span = match number {
                    Some(pn) => trace_span!("recv", space = ?packet.header.space(), pn),
                    None => trace_span!("recv", space = ?packet.header.space()),
                };
                let _guard = span.enter();

                let dedup = self.spaces[packet.header.space()]
                    .path_space_mut(path_id)
                    .map(|pns| &mut pns.dedup);
                if number.zip(dedup).is_some_and(|(n, d)| d.insert(n)) {
                    debug!("discarding possible duplicate packet");
                    self.config.qlog_sink.emit_packet_received(self, qlog, now);
                    return;
                } else if self.state.is_handshake() && packet.header.is_short() {
                    // TODO: SHOULD buffer these to improve reordering tolerance.
                    trace!("dropping short packet during handshake");
                    self.config.qlog_sink.emit_packet_received(self, qlog, now);
                    return;
                } else {
                    if let Header::Initial(InitialHeader { ref token, .. }) = packet.header {
                        if let Some(hs) = self.state.as_handshake() {
                            if self.side.is_server() && token != &hs.expected_token {
                                // Clients must send the same retry token in every Initial. Initial
                                // packets can be spoofed, so we discard rather than killing the
                                // connection.
                                warn!("discarding Initial with invalid retry token");
                                self.config.qlog_sink.emit_packet_received(self, qlog, now);
                                return;
                            }
                        }
                    }

                    if !self.state.is_closed() {
                        let spin = match packet.header {
                            Header::Short { spin, .. } => spin,
                            _ => false,
                        };

                        if self.side().is_server() && !self.abandoned_paths.contains(&path_id) {
                            // Only the client is allowed to open paths
                            self.ensure_path(path_id, remote, now, number);
                        }
                        if self.paths.contains_key(&path_id) {
                            self.on_packet_authenticated(
                                now,
                                packet.header.space(),
                                path_id,
                                ecn,
                                number,
                                spin,
                                packet.header.is_1rtt(),
                            );
                        }
                    }

                    let res = self
                        .process_decrypted_packet(now, remote, path_id, number, packet, &mut qlog);

                    self.config.qlog_sink.emit_packet_received(self, qlog, now);
                    res
                }
            }
        };

        // State transitions for error cases
        if let Err(conn_err) = result {
            match conn_err {
                ConnectionError::ApplicationClosed(reason) => self.state.move_to_closed(reason),
                ConnectionError::ConnectionClosed(reason) => self.state.move_to_closed(reason),
                ConnectionError::Reset
                | ConnectionError::TransportError(TransportError {
                    code: TransportErrorCode::AEAD_LIMIT_REACHED,
                    ..
                }) => {
                    self.state.move_to_drained(Some(conn_err));
                }
                ConnectionError::TimedOut => {
                    unreachable!("timeouts aren't generated by packet processing");
                }
                ConnectionError::TransportError(err) => {
                    debug!("closing connection due to transport error: {}", err);
                    self.state.move_to_closed(err);
                }
                ConnectionError::VersionMismatch => {
                    self.state.move_to_draining(Some(conn_err));
                }
                ConnectionError::LocallyClosed => {
                    unreachable!("LocallyClosed isn't generated by packet processing");
                }
                ConnectionError::CidsExhausted => {
                    unreachable!("CidsExhausted isn't generated by packet processing");
                }
            };
        }

        if !was_closed && self.state.is_closed() {
            self.close_common();
            if !self.state.is_drained() {
                self.set_close_timer(now);
            }
        }
        if !was_drained && self.state.is_drained() {
            self.endpoint_events.push_back(EndpointEventInner::Drained);
            // Close timer may have been started previously, e.g. if we sent a close and got a
            // stateless reset in response
            self.timers.stop(Timer::Conn(ConnTimer::Close));
        }

        // Transmit CONNECTION_CLOSE if necessary
        if matches!(self.state.as_type(), StateType::Closed) {
            // If there is no PathData for this PathId the packet was for a brand new
            // path. It was a valid packet however, so the remote is valid and we want to
            // send CONNECTION_CLOSE.
            let path_remote = self
                .paths
                .get(&path_id)
                .map(|p| p.data.remote)
                .unwrap_or(remote);
            self.close = remote == path_remote;
        }
    }

    fn process_decrypted_packet(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        path_id: PathId,
        number: Option<u64>,
        packet: Packet,
        qlog: &mut QlogRecvPacket,
    ) -> Result<(), ConnectionError> {
        if !self.paths.contains_key(&path_id) {
            // There is a chance this is a server side, first (for this path) packet, which would
            // be a protocol violation. It's more likely, however, that this is a packet of a
            // pruned path
            trace!(%path_id, ?number, "discarding packet for unknown path");
            return Ok(());
        }
        let state = match self.state.as_type() {
            StateType::Established => {
                match packet.header.space() {
                    SpaceId::Data => {
                        self.process_payload(now, remote, path_id, number.unwrap(), packet, qlog)?
                    }
                    _ if packet.header.has_frames() => {
                        self.process_early_payload(now, path_id, packet, qlog)?
                    }
                    _ => {
                        trace!("discarding unexpected pre-handshake packet");
                    }
                }
                return Ok(());
            }
            StateType::Closed => {
                for result in frame::Iter::new(packet.payload.freeze())? {
                    let frame = match result {
                        Ok(frame) => frame,
                        Err(err) => {
                            debug!("frame decoding error: {err:?}");
                            continue;
                        }
                    };
                    qlog.frame(&frame);

                    if let Frame::Padding = frame {
                        continue;
                    };

                    self.stats.frame_rx.record(&frame);

                    if let Frame::Close(_error) = frame {
                        trace!("draining");
                        self.state.move_to_draining(None);
                        break;
                    }
                }
                return Ok(());
            }
            StateType::Draining | StateType::Drained => return Ok(()),
            StateType::Handshake => self.state.as_handshake_mut().expect("checked"),
        };

        match packet.header {
            Header::Retry {
                src_cid: rem_cid, ..
            } => {
                debug_assert_eq!(path_id, PathId::ZERO);
                if self.side.is_server() {
                    return Err(TransportError::PROTOCOL_VIOLATION("client sent Retry").into());
                }

                let is_valid_retry = self
                    .rem_cids
                    .get(&path_id)
                    .map(|cids| cids.active())
                    .map(|orig_dst_cid| {
                        self.crypto.is_valid_retry(
                            orig_dst_cid,
                            &packet.header_data,
                            &packet.payload,
                        )
                    })
                    .unwrap_or_default();
                if self.total_authed_packets > 1
                            || packet.payload.len() <= 16 // token + 16 byte tag
                            || !is_valid_retry
                {
                    trace!("discarding invalid Retry");
                    // - After the client has received and processed an Initial or Retry
                    //   packet from the server, it MUST discard any subsequent Retry
                    //   packets that it receives.
                    // - A client MUST discard a Retry packet with a zero-length Retry Token
                    //   field.
                    // - Clients MUST discard Retry packets that have a Retry Integrity Tag
                    //   that cannot be validated
                    return Ok(());
                }

                trace!("retrying with CID {}", rem_cid);
                let client_hello = state.client_hello.take().unwrap();
                self.retry_src_cid = Some(rem_cid);
                self.rem_cids
                    .get_mut(&path_id)
                    .expect("PathId::ZERO not yet abandoned, is_valid_retry would have been false")
                    .update_initial_cid(rem_cid);
                self.rem_handshake_cid = rem_cid;

                let space = &mut self.spaces[SpaceId::Initial];
                if let Some(info) = space.for_path(PathId::ZERO).take(0) {
                    self.on_packet_acked(now, PathId::ZERO, info);
                };

                self.discard_space(now, SpaceId::Initial); // Make sure we clean up after
                // any retransmitted Initials
                self.spaces[SpaceId::Initial] = {
                    let mut space = PacketSpace::new(now, SpaceId::Initial, &mut self.rng);
                    space.crypto = Some(self.crypto.initial_keys(rem_cid, self.side.side()));
                    space.crypto_offset = client_hello.len() as u64;
                    space.for_path(path_id).next_packet_number = self.spaces[SpaceId::Initial]
                        .for_path(path_id)
                        .next_packet_number;
                    space.pending.crypto.push_back(frame::Crypto {
                        offset: 0,
                        data: client_hello,
                    });
                    space
                };

                // Retransmit all 0-RTT data
                let zero_rtt = mem::take(
                    &mut self.spaces[SpaceId::Data]
                        .for_path(PathId::ZERO)
                        .sent_packets,
                );
                for info in zero_rtt.into_values() {
                    self.paths
                        .get_mut(&PathId::ZERO)
                        .unwrap()
                        .remove_in_flight(&info);
                    self.spaces[SpaceId::Data].pending |= info.retransmits;
                }
                self.streams.retransmit_all_for_0rtt();

                let token_len = packet.payload.len() - 16;
                let ConnectionSide::Client { ref mut token, .. } = self.side else {
                    unreachable!("we already short-circuited if we're server");
                };
                *token = packet.payload.freeze().split_to(token_len);

                self.state = State::handshake(state::Handshake {
                    expected_token: Bytes::new(),
                    rem_cid_set: false,
                    client_hello: None,
                    allow_server_migration: true,
                });
                Ok(())
            }
            Header::Long {
                ty: LongType::Handshake,
                src_cid: rem_cid,
                dst_cid: loc_cid,
                ..
            } => {
                debug_assert_eq!(path_id, PathId::ZERO);
                if rem_cid != self.rem_handshake_cid {
                    debug!(
                        "discarding packet with mismatched remote CID: {} != {}",
                        self.rem_handshake_cid, rem_cid
                    );
                    return Ok(());
                }
                self.on_path_validated(path_id);

                self.process_early_payload(now, path_id, packet, qlog)?;
                if self.state.is_closed() {
                    return Ok(());
                }

                if self.crypto.is_handshaking() {
                    trace!("handshake ongoing");
                    return Ok(());
                }

                if self.side.is_client() {
                    // Client-only because server params were set from the client's Initial
                    let params =
                        self.crypto
                            .transport_parameters()?
                            .ok_or_else(|| TransportError {
                                code: TransportErrorCode::crypto(0x6d),
                                frame: None,
                                reason: "transport parameters missing".into(),
                                crypto: None,
                            })?;

                    if self.has_0rtt() {
                        if !self.crypto.early_data_accepted().unwrap() {
                            debug_assert!(self.side.is_client());
                            debug!("0-RTT rejected");
                            self.accepted_0rtt = false;
                            self.streams.zero_rtt_rejected();

                            // Discard already-queued frames
                            self.spaces[SpaceId::Data].pending = Retransmits::default();

                            // Discard 0-RTT packets
                            let sent_packets = mem::take(
                                &mut self.spaces[SpaceId::Data].for_path(path_id).sent_packets,
                            );
                            for packet in sent_packets.into_values() {
                                self.paths
                                    .get_mut(&path_id)
                                    .unwrap()
                                    .remove_in_flight(&packet);
                            }
                        } else {
                            self.accepted_0rtt = true;
                            params.validate_resumption_from(&self.peer_params)?;
                        }
                    }
                    if let Some(token) = params.stateless_reset_token {
                        let remote = self.path_data(path_id).remote;
                        self.endpoint_events
                            .push_back(EndpointEventInner::ResetToken(path_id, remote, token));
                    }
                    self.handle_peer_params(params, loc_cid, rem_cid)?;
                    self.issue_first_cids(now);
                } else {
                    // Server-only
                    self.spaces[SpaceId::Data].pending.handshake_done = true;
                    self.discard_space(now, SpaceId::Handshake);
                    self.events.push_back(Event::HandshakeConfirmed);
                    trace!("handshake confirmed");
                }

                self.events.push_back(Event::Connected);
                self.state.move_to_established();
                trace!("established");

                // Multipath can only be enabled after the state has reached Established.
                // So this can not happen any earlier.
                self.issue_first_path_cids(now);
                Ok(())
            }
            Header::Initial(InitialHeader {
                src_cid: rem_cid,
                dst_cid: loc_cid,
                ..
            }) => {
                debug_assert_eq!(path_id, PathId::ZERO);
                if !state.rem_cid_set {
                    trace!("switching remote CID to {}", rem_cid);
                    let mut state = state.clone();
                    self.rem_cids
                        .get_mut(&path_id)
                        .expect("PathId::ZERO not yet abandoned")
                        .update_initial_cid(rem_cid);
                    self.rem_handshake_cid = rem_cid;
                    self.orig_rem_cid = rem_cid;
                    state.rem_cid_set = true;
                    self.state.move_to_handshake(state);
                } else if rem_cid != self.rem_handshake_cid {
                    debug!(
                        "discarding packet with mismatched remote CID: {} != {}",
                        self.rem_handshake_cid, rem_cid
                    );
                    return Ok(());
                }

                let starting_space = self.highest_space;
                self.process_early_payload(now, path_id, packet, qlog)?;

                if self.side.is_server()
                    && starting_space == SpaceId::Initial
                    && self.highest_space != SpaceId::Initial
                {
                    let params =
                        self.crypto
                            .transport_parameters()?
                            .ok_or_else(|| TransportError {
                                code: TransportErrorCode::crypto(0x6d),
                                frame: None,
                                reason: "transport parameters missing".into(),
                                crypto: None,
                            })?;
                    self.handle_peer_params(params, loc_cid, rem_cid)?;
                    self.issue_first_cids(now);
                    self.init_0rtt();
                }
                Ok(())
            }
            Header::Long {
                ty: LongType::ZeroRtt,
                ..
            } => {
                self.process_payload(now, remote, path_id, number.unwrap(), packet, qlog)?;
                Ok(())
            }
            Header::VersionNegotiate { .. } => {
                if self.total_authed_packets > 1 {
                    return Ok(());
                }
                let supported = packet
                    .payload
                    .chunks(4)
                    .any(|x| match <[u8; 4]>::try_from(x) {
                        Ok(version) => self.version == u32::from_be_bytes(version),
                        Err(_) => false,
                    });
                if supported {
                    return Ok(());
                }
                debug!("remote doesn't support our version");
                Err(ConnectionError::VersionMismatch)
            }
            Header::Short { .. } => unreachable!(
                "short packets received during handshake are discarded in handle_packet"
            ),
        }
    }

    /// Process an Initial or Handshake packet payload
    fn process_early_payload(
        &mut self,
        now: Instant,
        path_id: PathId,
        packet: Packet,
        #[allow(unused)] qlog: &mut QlogRecvPacket,
    ) -> Result<(), TransportError> {
        debug_assert_ne!(packet.header.space(), SpaceId::Data);
        debug_assert_eq!(path_id, PathId::ZERO);
        let payload_len = packet.payload.len();
        let mut ack_eliciting = false;
        for result in frame::Iter::new(packet.payload.freeze())? {
            let frame = result?;
            qlog.frame(&frame);
            let span = match frame {
                Frame::Padding => continue,
                _ => Some(trace_span!("frame", ty = %frame.ty(), path = tracing::field::Empty)),
            };

            self.stats.frame_rx.record(&frame);

            let _guard = span.as_ref().map(|x| x.enter());
            ack_eliciting |= frame.is_ack_eliciting();

            // Process frames
            match frame {
                Frame::Padding | Frame::Ping => {}
                Frame::Crypto(frame) => {
                    self.read_crypto(packet.header.space(), &frame, payload_len)?;
                }
                Frame::Ack(ack) => {
                    self.on_ack_received(now, packet.header.space(), ack)?;
                }
                Frame::PathAck(ack) => {
                    span.as_ref()
                        .map(|span| span.record("path", tracing::field::debug(&ack.path_id)));
                    self.on_path_ack_received(now, packet.header.space(), ack)?;
                }
                Frame::Close(reason) => {
                    self.state.move_to_draining(Some(reason.into()));
                    return Ok(());
                }
                _ => {
                    let mut err =
                        TransportError::PROTOCOL_VIOLATION("illegal frame type in handshake");
                    err.frame = Some(frame.ty());
                    return Err(err);
                }
            }
        }

        if ack_eliciting {
            // In the initial and handshake spaces, ACKs must be sent immediately
            self.spaces[packet.header.space()]
                .for_path(path_id)
                .pending_acks
                .set_immediate_ack_required();
        }

        self.write_crypto();
        Ok(())
    }

    /// Processes the packet payload, always in the data space.
    fn process_payload(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        path_id: PathId,
        number: u64,
        packet: Packet,
        #[allow(unused)] qlog: &mut QlogRecvPacket,
    ) -> Result<(), TransportError> {
        let payload = packet.payload.freeze();
        let mut is_probing_packet = true;
        let mut close = None;
        let payload_len = payload.len();
        let mut ack_eliciting = false;
        // if this packet triggers a path migration and includes a observed address frame, it's
        // stored here
        let mut migration_observed_addr = None;
        for result in frame::Iter::new(payload)? {
            let frame = result?;
            qlog.frame(&frame);
            let span = match frame {
                Frame::Padding => continue,
                _ => trace_span!("frame", ty = %frame.ty(), path = tracing::field::Empty),
            };

            self.stats.frame_rx.record(&frame);
            // Crypto, Stream and Datagram frames are special cased in order no pollute
            // the log with payload data
            match &frame {
                Frame::Crypto(f) => {
                    trace!(offset = f.offset, len = f.data.len(), "got crypto frame");
                }
                Frame::Stream(f) => {
                    trace!(id = %f.id, offset = f.offset, len = f.data.len(), fin = f.fin, "got stream frame");
                }
                Frame::Datagram(f) => {
                    trace!(len = f.data.len(), "got datagram frame");
                }
                f => {
                    trace!("got frame {:?}", f);
                }
            }

            let _guard = span.enter();
            if packet.header.is_0rtt() {
                match frame {
                    Frame::Crypto(_) | Frame::Close(Close::Application(_)) => {
                        return Err(TransportError::PROTOCOL_VIOLATION(
                            "illegal frame type in 0-RTT",
                        ));
                    }
                    _ => {}
                }
            }
            ack_eliciting |= frame.is_ack_eliciting();

            // Check whether this could be a probing packet
            match frame {
                Frame::Padding
                | Frame::PathChallenge(_)
                | Frame::PathResponse(_)
                | Frame::NewConnectionId(_)
                | Frame::ObservedAddr(_) => {}
                _ => {
                    is_probing_packet = false;
                }
            }
            match frame {
                Frame::Crypto(frame) => {
                    self.read_crypto(SpaceId::Data, &frame, payload_len)?;
                }
                Frame::Stream(frame) => {
                    if self.streams.received(frame, payload_len)?.should_transmit() {
                        self.spaces[SpaceId::Data].pending.max_data = true;
                    }
                }
                Frame::Ack(ack) => {
                    self.on_ack_received(now, SpaceId::Data, ack)?;
                }
                Frame::PathAck(ack) => {
                    span.record("path", tracing::field::debug(&ack.path_id));
                    self.on_path_ack_received(now, SpaceId::Data, ack)?;
                }
                Frame::Padding | Frame::Ping => {}
                Frame::Close(reason) => {
                    close = Some(reason);
                }
                Frame::PathChallenge(token) => {
                    let path = &mut self
                        .path_mut(path_id)
                        .expect("payload is processed only after the path becomes known");
                    path.path_responses.push(number, token, remote);
                    if remote == path.remote {
                        // PATH_CHALLENGE on active path, possible off-path packet forwarding
                        // attack. Send a non-probing packet to recover the active path.
                        match self.peer_supports_ack_frequency() {
                            true => self.immediate_ack(path_id),
                            false => {
                                self.ping_path(path_id).ok();
                            }
                        }
                    }
                }
                Frame::PathResponse(token) => {
                    let path = self
                        .paths
                        .get_mut(&path_id)
                        .expect("payload is processed only after the path becomes known");

                    if remote != path.data.remote {
                        debug!(token, "ignoring invalid PATH_RESPONSE");
                    } else if let Some(&challenge_sent) = path.data.challenges_sent.get(&token) {
                        self.timers
                            .stop(Timer::PerPath(path_id, PathTimer::PathValidation));
                        self.timers
                            .stop(Timer::PerPath(path_id, PathTimer::PathChallengeLost));
                        if !path.data.validated {
                            trace!("new path validated");
                        }
                        self.timers
                            .stop(Timer::PerPath(path_id, PathTimer::PathOpen));
                        path.data.challenges_sent.clear();
                        path.data.send_new_challenge = false;
                        path.data.validated = true;
                        path.data.rtt.update(
                            Duration::ZERO,
                            now.saturating_duration_since(challenge_sent),
                        );
                        self.events
                            .push_back(Event::Path(PathEvent::Opened { id: path_id }));
                        // mark the path as open from the application perspective now that Opened
                        // event has been queued
                        if !std::mem::replace(&mut path.data.open, true) {
                            if let Some(observed) = path.data.last_observed_addr_report.as_ref() {
                                self.events.push_back(Event::Path(PathEvent::ObservedAddr {
                                    id: path_id,
                                    addr: observed.socket_addr(),
                                }));
                            }
                        }
                        if let Some((_, ref mut prev)) = path.prev {
                            prev.challenges_sent.clear();
                            prev.send_new_challenge = false;
                        }
                    } else {
                        debug!(token, "ignoring invalid PATH_RESPONSE");
                    }
                }
                Frame::MaxData(bytes) => {
                    self.streams.received_max_data(bytes);
                }
                Frame::MaxStreamData { id, offset } => {
                    self.streams.received_max_stream_data(id, offset)?;
                }
                Frame::MaxStreams { dir, count } => {
                    self.streams.received_max_streams(dir, count)?;
                }
                Frame::ResetStream(frame) => {
                    if self.streams.received_reset(frame)?.should_transmit() {
                        self.spaces[SpaceId::Data].pending.max_data = true;
                    }
                }
                Frame::DataBlocked { offset } => {
                    debug!(offset, "peer claims to be blocked at connection level");
                }
                Frame::StreamDataBlocked { id, offset } => {
                    if id.initiator() == self.side.side() && id.dir() == Dir::Uni {
                        debug!("got STREAM_DATA_BLOCKED on send-only {}", id);
                        return Err(TransportError::STREAM_STATE_ERROR(
                            "STREAM_DATA_BLOCKED on send-only stream",
                        ));
                    }
                    debug!(
                        stream = %id,
                        offset, "peer claims to be blocked at stream level"
                    );
                }
                Frame::StreamsBlocked { dir, limit } => {
                    if limit > MAX_STREAM_COUNT {
                        return Err(TransportError::FRAME_ENCODING_ERROR(
                            "unrepresentable stream limit",
                        ));
                    }
                    debug!(
                        "peer claims to be blocked opening more than {} {} streams",
                        limit, dir
                    );
                }
                Frame::StopSending(frame::StopSending { id, error_code }) => {
                    if id.initiator() != self.side.side() {
                        if id.dir() == Dir::Uni {
                            debug!("got STOP_SENDING on recv-only {}", id);
                            return Err(TransportError::STREAM_STATE_ERROR(
                                "STOP_SENDING on recv-only stream",
                            ));
                        }
                    } else if self.streams.is_local_unopened(id) {
                        return Err(TransportError::STREAM_STATE_ERROR(
                            "STOP_SENDING on unopened stream",
                        ));
                    }
                    self.streams.received_stop_sending(id, error_code);
                }
                Frame::RetireConnectionId(frame::RetireConnectionId { path_id, sequence }) => {
                    if let Some(ref path_id) = path_id {
                        span.record("path", tracing::field::debug(&path_id));
                    }
                    match self.local_cid_state.get_mut(&path_id.unwrap_or_default()) {
                        None => error!(?path_id, "RETIRE_CONNECTION_ID for unknown path"),
                        Some(cid_state) => {
                            let allow_more_cids = cid_state
                                .on_cid_retirement(sequence, self.peer_params.issue_cids_limit())?;
                            self.endpoint_events
                                .push_back(EndpointEventInner::RetireConnectionId(
                                    now,
                                    path_id.unwrap_or_default(),
                                    sequence,
                                    allow_more_cids,
                                ));
                        }
                    }
                }
                Frame::NewConnectionId(frame) => {
                    let path_id = if let Some(path_id) = frame.path_id {
                        if !self.is_multipath_negotiated() {
                            return Err(TransportError::PROTOCOL_VIOLATION(
                                "received PATH_NEW_CONNECTION_ID frame when multipath was not negotiated",
                            ));
                        }
                        if path_id > self.local_max_path_id {
                            return Err(TransportError::PROTOCOL_VIOLATION(
                                "PATH_NEW_CONNECTION_ID contains path_id exceeding current max",
                            ));
                        }
                        path_id
                    } else {
                        PathId::ZERO
                    };

                    if self.abandoned_paths.contains(&path_id) {
                        trace!("ignoring issued CID for abandoned path");
                        continue;
                    }
                    if let Some(ref path_id) = frame.path_id {
                        span.record("path", tracing::field::debug(&path_id));
                    }
                    let rem_cids = self
                        .rem_cids
                        .entry(path_id)
                        .or_insert_with(|| CidQueue::new(frame.id));
                    if rem_cids.active().is_empty() {
                        // TODO(@divma): is the entry removed later? (rem_cids.entry)
                        return Err(TransportError::PROTOCOL_VIOLATION(
                            "NEW_CONNECTION_ID when CIDs aren't in use",
                        ));
                    }
                    if frame.retire_prior_to > frame.sequence {
                        return Err(TransportError::PROTOCOL_VIOLATION(
                            "NEW_CONNECTION_ID retiring unissued CIDs",
                        ));
                    }

                    use crate::cid_queue::InsertError;
                    match rem_cids.insert(frame) {
                        Ok(None) => {}
                        Ok(Some((retired, reset_token))) => {
                            let pending_retired =
                                &mut self.spaces[SpaceId::Data].pending.retire_cids;
                            /// Ensure `pending_retired` cannot grow without bound. Limit is
                            /// somewhat arbitrary but very permissive.
                            const MAX_PENDING_RETIRED_CIDS: u64 = CidQueue::LEN as u64 * 10;
                            // We don't bother counting in-flight frames because those are bounded
                            // by congestion control.
                            if (pending_retired.len() as u64)
                                .saturating_add(retired.end.saturating_sub(retired.start))
                                > MAX_PENDING_RETIRED_CIDS
                            {
                                return Err(TransportError::CONNECTION_ID_LIMIT_ERROR(
                                    "queued too many retired CIDs",
                                ));
                            }
                            pending_retired.extend(retired.map(|seq| (path_id, seq)));
                            self.set_reset_token(path_id, remote, reset_token);
                        }
                        Err(InsertError::ExceedsLimit) => {
                            return Err(TransportError::CONNECTION_ID_LIMIT_ERROR(""));
                        }
                        Err(InsertError::Retired) => {
                            trace!("discarding already-retired");
                            // RETIRE_CONNECTION_ID might not have been previously sent if e.g. a
                            // range of connection IDs larger than the active connection ID limit
                            // was retired all at once via retire_prior_to.
                            self.spaces[SpaceId::Data]
                                .pending
                                .retire_cids
                                .push((path_id, frame.sequence));
                            continue;
                        }
                    };

                    if self.side.is_server()
                        && path_id == PathId::ZERO
                        && self
                            .rem_cids
                            .get(&PathId::ZERO)
                            .map(|cids| cids.active_seq() == 0)
                            .unwrap_or_default()
                    {
                        // We're a server still using the initial remote CID for the client, so
                        // let's switch immediately to enable clientside stateless resets.
                        self.update_rem_cid(PathId::ZERO);
                    }
                }
                Frame::NewToken(NewToken { token }) => {
                    let ConnectionSide::Client {
                        token_store,
                        server_name,
                        ..
                    } = &self.side
                    else {
                        return Err(TransportError::PROTOCOL_VIOLATION("client sent NEW_TOKEN"));
                    };
                    if token.is_empty() {
                        return Err(TransportError::FRAME_ENCODING_ERROR("empty token"));
                    }
                    trace!("got new token");
                    token_store.insert(server_name, token);
                }
                Frame::Datagram(datagram) => {
                    if self
                        .datagrams
                        .received(datagram, &self.config.datagram_receive_buffer_size)?
                    {
                        self.events.push_back(Event::DatagramReceived);
                    }
                }
                Frame::AckFrequency(ack_frequency) => {
                    // This frame can only be sent in the Data space

                    if !self.ack_frequency.ack_frequency_received(&ack_frequency)? {
                        // The AckFrequency frame is stale (we have already received a more
                        // recent one)
                        continue;
                    }

                    // Update the params for all of our paths
                    for (path_id, space) in self.spaces[SpaceId::Data].number_spaces.iter_mut() {
                        space.pending_acks.set_ack_frequency_params(&ack_frequency);

                        // Our `max_ack_delay` has been updated, so we may need to adjust
                        // its associated timeout
                        if let Some(timeout) = space
                            .pending_acks
                            .max_ack_delay_timeout(self.ack_frequency.max_ack_delay)
                        {
                            self.timers
                                .set(Timer::PerPath(*path_id, PathTimer::MaxAckDelay), timeout);
                        }
                    }
                }
                Frame::ImmediateAck => {
                    // This frame can only be sent in the Data space
                    for pns in self.spaces[SpaceId::Data].iter_paths_mut() {
                        pns.pending_acks.set_immediate_ack_required();
                    }
                }
                Frame::HandshakeDone => {
                    if self.side.is_server() {
                        return Err(TransportError::PROTOCOL_VIOLATION(
                            "client sent HANDSHAKE_DONE",
                        ));
                    }
                    if self.spaces[SpaceId::Handshake].crypto.is_some() {
                        self.discard_space(now, SpaceId::Handshake);
                    }
                    self.events.push_back(Event::HandshakeConfirmed);
                    trace!("handshake confirmed");
                }
                Frame::ObservedAddr(observed) => {
                    // check if params allows the peer to send report and this node to receive it
                    trace!(seq_no = %observed.seq_no, ip = %observed.ip, port = observed.port);
                    if !self
                        .peer_params
                        .address_discovery_role
                        .should_report(&self.config.address_discovery_role)
                    {
                        return Err(TransportError::PROTOCOL_VIOLATION(
                            "received OBSERVED_ADDRESS frame when not negotiated",
                        ));
                    }
                    // must only be sent in data space
                    if packet.header.space() != SpaceId::Data {
                        return Err(TransportError::PROTOCOL_VIOLATION(
                            "OBSERVED_ADDRESS frame outside data space",
                        ));
                    }

                    let path = self.path_data_mut(path_id);
                    if remote == path.remote {
                        if let Some(updated) = path.update_observed_addr_report(observed) {
                            if path.open {
                                self.events.push_back(Event::Path(PathEvent::ObservedAddr {
                                    id: path_id,
                                    addr: updated,
                                }));
                            }
                            // otherwise the event is reported when the path is deemed open
                        }
                    } else {
                        // include in migration
                        migration_observed_addr = Some(observed)
                    }
                }
                Frame::PathAbandon(frame::PathAbandon {
                    path_id,
                    error_code,
                }) => {
                    span.record("path", tracing::field::debug(&path_id));
                    // TODO(flub): don't really know which error code to use here.
                    match self.close_path(now, path_id, error_code.into()) {
                        Ok(()) => {
                            trace!("peer abandoned path");
                        }
                        Err(ClosePathError::LastOpenPath) => {
                            trace!("peer abandoned last path, closing connection");
                            // TODO(flub): which error code?
                            self.close(
                                now,
                                TransportErrorCode::NO_ERROR.into(),
                                Bytes::from_static(b"last path abandoned by peer"),
                            );
                        }
                        Err(ClosePathError::ClosedPath) => {
                            trace!("peer abandoned already closed path");
                        }
                    }
                    // If we receive a retransmit of PATH_ABANDON then we may already have
                    // abandoned this path locally.  In that case the PathAbandoned timer
                    // may already have fired and we no longer have any state for this path.
                    // Only set this timer if we still have path state.
                    // TODO(flub): Note that if we process a retransmit and *do* still have
                    //    path state, we are extending the expiration time of this timer.
                    //    That's technically not needed, but not a violation.  We would have
                    //    to be able to inspect if the timer is set to avoid this.
                    if self.path(path_id).is_some() {
                        // TODO(flub): Checking is_some() here followed by a number of calls
                        //    that would panic if it was None is really ugly.  If only we
                        //    could do something like PathData::pto().  One day we'll have
                        //    unified SpaceId and PathId and this will be possible.
                        let delay = self.pto(SpaceId::Data, path_id) * 3;
                        self.timers.set(
                            Timer::PerPath(path_id, PathTimer::PathAbandoned),
                            now + delay,
                        );
                    }
                    self.timers
                        .stop(Timer::PerPath(path_id, PathTimer::PathNotAbandoned));
                }
                Frame::PathAvailable(info) => {
                    span.record("path", tracing::field::debug(&info.path_id));
                    if self.is_multipath_negotiated() {
                        self.on_path_status(
                            info.path_id,
                            PathStatus::Available,
                            info.status_seq_no,
                        );
                    } else {
                        return Err(TransportError::PROTOCOL_VIOLATION(
                            "received PATH_AVAILABLE frame when multipath was not negotiated",
                        ));
                    }
                }
                Frame::PathBackup(info) => {
                    span.record("path", tracing::field::debug(&info.path_id));
                    if self.is_multipath_negotiated() {
                        self.on_path_status(info.path_id, PathStatus::Backup, info.status_seq_no);
                    } else {
                        return Err(TransportError::PROTOCOL_VIOLATION(
                            "received PATH_BACKUP frame when multipath was not negotiated",
                        ));
                    }
                }
                Frame::MaxPathId(frame::MaxPathId(path_id)) => {
                    span.record("path", tracing::field::debug(&path_id));
                    if !self.is_multipath_negotiated() {
                        return Err(TransportError::PROTOCOL_VIOLATION(
                            "received MAX_PATH_ID frame when multipath was not negotiated",
                        ));
                    }
                    // frames that do not increase the path id are ignored
                    if path_id > self.remote_max_path_id {
                        self.remote_max_path_id = path_id;
                        self.issue_first_path_cids(now);
                    }
                }
                Frame::PathsBlocked(frame::PathsBlocked(max_path_id)) => {
                    // Receipt of a value of Maximum Path Identifier or Path Identifier that is higher than the local maximum value MUST
                    // be treated as a connection error of type PROTOCOL_VIOLATION.
                    // Ref <https://www.ietf.org/archive/id/draft-ietf-quic-multipath-14.html#name-paths_blocked-and-path_cids>
                    if self.is_multipath_negotiated() {
                        if self.local_max_path_id > max_path_id {
                            return Err(TransportError::PROTOCOL_VIOLATION(
                                "PATHS_BLOCKED maximum path identifier was larger than local maximum",
                            ));
                        }
                        debug!("received PATHS_BLOCKED({:?})", max_path_id);
                        // TODO(@divma): ensure max concurrent paths
                    } else {
                        return Err(TransportError::PROTOCOL_VIOLATION(
                            "received PATHS_BLOCKED frame when not multipath was not negotiated",
                        ));
                    }
                }
                Frame::PathCidsBlocked(frame::PathCidsBlocked { path_id, next_seq }) => {
                    // Nothing to do.  This is recorded in the frame stats, but otherwise we
                    // always issue all CIDs we're allowed to issue, so either this is an
                    // impatient peer or a bug on our side.

                    // Receipt of a value of Maximum Path Identifier or Path Identifier that is higher than the local maximum value MUST
                    // be treated as a connection error of type PROTOCOL_VIOLATION.
                    // Ref <https://www.ietf.org/archive/id/draft-ietf-quic-multipath-14.html#name-paths_blocked-and-path_cids>
                    if self.is_multipath_negotiated() {
                        if path_id > self.local_max_path_id {
                            return Err(TransportError::PROTOCOL_VIOLATION(
                                "PATH_CIDS_BLOCKED path identifier was larger than local maximum",
                            ));
                        }
                        if next_seq.0
                            > self
                                .local_cid_state
                                .get(&path_id)
                                .map(|cid_state| cid_state.active_seq().1 + 1)
                                .unwrap_or_default()
                        {
                            return Err(TransportError::PROTOCOL_VIOLATION(
                                "PATH_CIDS_BLOCKED next sequence number larger than in local state",
                            ));
                        }
                        debug!(%path_id, %next_seq, "received PATH_CIDS_BLOCKED");
                    } else {
                        return Err(TransportError::PROTOCOL_VIOLATION(
                            "received PATH_CIDS_BLOCKED frame when not multipath was not negotiated",
                        ));
                    }
                }
                Frame::AddAddress(addr) => {
                    let client_state = match self.iroh_hp.client_side_mut() {
                        Ok(state) => state,
                        Err(err) => {
                            return Err(TransportError::PROTOCOL_VIOLATION(format!(
                                "Nat traversal(ADD_ADDRESS): {err}"
                            )));
                        }
                    };

                    if !client_state.check_remote_address(&addr) {
                        // if the address is not valid we flag it, but update anyway
                        warn!(?addr, "server sent illegal ADD_ADDRESS frame");
                    }

                    match client_state.add_remote_address(addr) {
                        Ok(maybe_added) => {
                            if let Some(added) = maybe_added {
                                self.events.push_back(Event::NatTraversal(
                                    iroh_hp::Event::AddressAdded(added),
                                ));
                            }
                        }
                        Err(e) => {
                            warn!(%e, "failed to add remote address")
                        }
                    }
                }
                Frame::RemoveAddress(addr) => {
                    let client_state = match self.iroh_hp.client_side_mut() {
                        Ok(state) => state,
                        Err(err) => {
                            return Err(TransportError::PROTOCOL_VIOLATION(format!(
                                "Nat traversal(REMOVE_ADDRESS): {err}"
                            )));
                        }
                    };
                    if let Some(removed_addr) = client_state.remove_remote_address(addr) {
                        self.events
                            .push_back(Event::NatTraversal(iroh_hp::Event::AddressRemoved(
                                removed_addr,
                            )));
                    }
                }
                Frame::ReachOut(reach_out) => {
                    let server_state = match self.iroh_hp.server_side_mut() {
                        Ok(state) => state,
                        Err(err) => {
                            return Err(TransportError::PROTOCOL_VIOLATION(format!(
                                "Nat traversal(REACH_OUT): {err}"
                            )));
                        }
                    };

                    match server_state.handle_reach_out(reach_out) {
                        Ok(None) => {
                            // no action required here
                        }
                        Ok(Some(info)) => {
                            let iroh_hp::RandDataNeeded {
                                ip,
                                port,
                                round,
                                is_new_round,
                            } = info;
                            if is_new_round {
                                // TODO(@divma): this depends on round starting on 1 right now,
                                // because the round should be greater to the default one, which is
                                // zero
                                self.spaces[SpaceId::Data].pending.hole_punch_round = round;
                                self.spaces[SpaceId::Data].pending.hole_punch_to.clear();
                            }

                            self.spaces[SpaceId::Data]
                                .pending
                                .hole_punch_to
                                .push((ip, port));
                        }
                        Err(iroh_hp::Error::WrongConnectionSide) => {
                            return Err(TransportError::PROTOCOL_VIOLATION(
                                "server sent REACH_OUT frames for nat traversal",
                            ));
                        }
                        Err(iroh_hp::Error::TooManyAddresses) => {
                            return Err(TransportError::PROTOCOL_VIOLATION(
                                "client exceeded allowed REACH_OUT frames for this round",
                            ));
                        }
                        Err(error) => {
                            warn!(%error,"error handling REACH_OUT frame");
                            // TODO(@divma): check if this is reachable
                        }
                    }
                }
            }
        }

        let space = self.spaces[SpaceId::Data].for_path(path_id);
        if space
            .pending_acks
            .packet_received(now, number, ack_eliciting, &space.dedup)
        {
            if self.abandoned_paths.contains(&path_id) {
                // § 3.4.3 QUIC-MULTIPATH: promptly send ACKs for packets received from
                // abandoned paths.
                space.pending_acks.set_immediate_ack_required();
            } else {
                self.timers.set(
                    Timer::PerPath(path_id, PathTimer::MaxAckDelay),
                    now + self.ack_frequency.max_ack_delay,
                );
            }
        }

        // Issue stream ID credit due to ACKs of outgoing finish/resets and incoming finish/resets
        // on stopped streams. Incoming finishes/resets on open streams are not handled here as they
        // are only freed, and hence only issue credit, once the application has been notified
        // during a read on the stream.
        let pending = &mut self.spaces[SpaceId::Data].pending;
        self.streams.queue_max_stream_id(pending);

        if let Some(reason) = close {
            self.state.move_to_draining(Some(reason.into()));
            self.close = true;
        }

        if Some(number) == self.spaces[SpaceId::Data].for_path(path_id).rx_packet
            && !is_probing_packet
            && remote != self.path_data(path_id).remote
        {
            let ConnectionSide::Server { ref server_config } = self.side else {
                panic!("packets from unknown remote should be dropped by clients");
            };
            debug_assert!(
                server_config.migration,
                "migration-initiating packets should have been dropped immediately"
            );
            self.migrate(path_id, now, remote, migration_observed_addr);
            // Break linkability, if possible
            self.update_rem_cid(path_id);
            self.spin = false;
        }

        Ok(())
    }

    fn migrate(
        &mut self,
        path_id: PathId,
        now: Instant,
        remote: SocketAddr,
        observed_addr: Option<ObservedAddr>,
    ) {
        trace!(%remote, %path_id, "migration initiated");
        self.path_counter = self.path_counter.wrapping_add(1);
        // TODO(@divma): conditions for path migration in multipath are very specific, check them
        // again to prevent path migrations that should actually create a new path

        // Reset rtt/congestion state for new path unless it looks like a NAT rebinding.
        // Note that the congestion window will not grow until validation terminates. Helps mitigate
        // amplification attacks performed by spoofing source addresses.
        let prev_pto = self.pto(SpaceId::Data, path_id);
        let known_path = self.paths.get_mut(&path_id).expect("known path");
        let path = &mut known_path.data;
        let mut new_path = if remote.is_ipv4() && remote.ip() == path.remote.ip() {
            PathData::from_previous(remote, path, self.path_counter, now)
        } else {
            let peer_max_udp_payload_size =
                u16::try_from(self.peer_params.max_udp_payload_size.into_inner())
                    .unwrap_or(u16::MAX);
            PathData::new(
                remote,
                self.allow_mtud,
                Some(peer_max_udp_payload_size),
                self.path_counter,
                now,
                &self.config,
            )
        };
        new_path.last_observed_addr_report = path.last_observed_addr_report.clone();
        if let Some(report) = observed_addr {
            if let Some(updated) = new_path.update_observed_addr_report(report) {
                tracing::info!("adding observed addr event from migration");
                self.events.push_back(Event::Path(PathEvent::ObservedAddr {
                    id: path_id,
                    addr: updated,
                }));
            }
        }
        new_path.send_new_challenge = true;

        let mut prev = mem::replace(path, new_path);
        // Don't clobber the original path if the previous one hasn't been validated yet
        if !prev.is_validating_path() {
            prev.send_new_challenge = true;
            // We haven't updated the remote CID yet, this captures the remote CID we were using on
            // the previous path.

            known_path.prev = Some((self.rem_cids.get(&path_id).unwrap().active(), prev));
        }

        self.timers.set(
            Timer::PerPath(path_id, PathTimer::PathValidation),
            now + 3 * cmp::max(self.pto(SpaceId::Data, path_id), prev_pto),
        );
    }

    /// Handle a change in the local address, i.e. an active migration
    pub fn local_address_changed(&mut self) {
        // TODO(flub): if multipath is enabled this needs to create a new path entirely.
        self.update_rem_cid(PathId::ZERO);
        self.ping();
    }

    /// Switch to a previously unused remote connection ID, if possible
    fn update_rem_cid(&mut self, path_id: PathId) {
        let Some((reset_token, retired)) =
            self.rem_cids.get_mut(&path_id).and_then(|cids| cids.next())
        else {
            return;
        };

        // Retire the current remote CID and any CIDs we had to skip.
        self.spaces[SpaceId::Data]
            .pending
            .retire_cids
            .extend(retired.map(|seq| (path_id, seq)));
        let remote = self.path_data(path_id).remote;
        self.set_reset_token(path_id, remote, reset_token);
    }

    /// Sends this reset token to the endpoint
    ///
    /// The endpoint needs to know the reset tokens issued by the peer, so that if the peer
    /// sends a reset token it knows to route it to this connection. See RFC 9000 section
    /// 10.3. Stateless Reset.
    ///
    /// Reset tokens are different for each path, the endpoint identifies paths by peer
    /// socket address however, not by path ID.
    fn set_reset_token(&mut self, path_id: PathId, remote: SocketAddr, reset_token: ResetToken) {
        self.endpoint_events
            .push_back(EndpointEventInner::ResetToken(path_id, remote, reset_token));

        // During the handshake the server sends a reset token in the transport
        // parameters. When we are the client and we receive the reset token during the
        // handshake we want this to affect our peer transport parameters.
        // TODO(flub): Pretty sure this is pointless, the entire params is overwritten
        //    shortly after this was called.  And then the params don't have this anymore.
        if path_id == PathId::ZERO {
            self.peer_params.stateless_reset_token = Some(reset_token);
        }
    }

    /// Issue an initial set of connection IDs to the peer upon connection
    fn issue_first_cids(&mut self, now: Instant) {
        if self
            .local_cid_state
            .get(&PathId::ZERO)
            .expect("PathId::ZERO exists when the connection is created")
            .cid_len()
            == 0
        {
            return;
        }

        // Subtract 1 to account for the CID we supplied while handshaking
        let mut n = self.peer_params.issue_cids_limit() - 1;
        if let ConnectionSide::Server { server_config } = &self.side {
            if server_config.has_preferred_address() {
                // We also sent a CID in the transport parameters
                n -= 1;
            }
        }
        self.endpoint_events
            .push_back(EndpointEventInner::NeedIdentifiers(PathId::ZERO, now, n));
    }

    /// Issues an initial set of CIDs for paths that have not yet had any CIDs issued
    ///
    /// Later CIDs are issued when CIDs expire or are retired by the peer.
    fn issue_first_path_cids(&mut self, now: Instant) {
        if let Some(max_path_id) = self.max_path_id() {
            let mut path_id = self.max_path_id_with_cids.next();
            while path_id <= max_path_id {
                self.endpoint_events
                    .push_back(EndpointEventInner::NeedIdentifiers(
                        path_id,
                        now,
                        self.peer_params.issue_cids_limit(),
                    ));
                path_id = path_id.next();
            }
            self.max_path_id_with_cids = max_path_id;
        }
    }

    /// Populates a packet with frames
    ///
    /// This tries to fit as many frames as possible into the packet.
    ///
    /// *path_exclusive_only* means to only build frames which can only be sent on this
    /// *path.  This is used in multipath for backup paths while there is still an active
    /// *path.
    fn populate_packet(
        &mut self,
        now: Instant,
        space_id: SpaceId,
        path_id: PathId,
        path_exclusive_only: bool,
        buf: &mut impl BufMut,
        pn: u64,
        #[allow(unused)] qlog: &mut QlogSentPacket,
    ) -> SentFrames {
        let mut sent = SentFrames::default();
        let is_multipath_negotiated = self.is_multipath_negotiated();
        let space = &mut self.spaces[space_id];
        let path = &mut self.paths.get_mut(&path_id).expect("known path").data;
        let is_0rtt = space_id == SpaceId::Data && space.crypto.is_none();
        space
            .for_path(path_id)
            .pending_acks
            .maybe_ack_non_eliciting();

        // HANDSHAKE_DONE
        if !is_0rtt && mem::replace(&mut space.pending.handshake_done, false) {
            trace!("HANDSHAKE_DONE");
            buf.write(frame::FrameType::HANDSHAKE_DONE);
            qlog.frame(&Frame::HandshakeDone);
            sent.retransmits.get_or_create().handshake_done = true;
            // This is just a u8 counter and the frame is typically just sent once
            self.stats.frame_tx.handshake_done =
                self.stats.frame_tx.handshake_done.saturating_add(1);
        }

        // REACH_OUT
        // TODO(@divma): path explusive considerations
        if let Some((round, addresses)) = space.pending.reach_out.as_mut() {
            while let Some(local_addr) = addresses.pop() {
                let reach_out = frame::ReachOut::new(*round, local_addr);
                if buf.remaining_mut() > reach_out.size() {
                    trace!(%round, ?local_addr, "REACH_OUT");
                    reach_out.write(buf);
                    let sent_reachouts = sent
                        .retransmits
                        .get_or_create()
                        .reach_out
                        .get_or_insert_with(|| (*round, Default::default()));
                    sent_reachouts.1.push(local_addr);
                    self.stats.frame_tx.reach_out = self.stats.frame_tx.reach_out.saturating_add(1);
                } else {
                    addresses.push(local_addr);
                    break;
                }
            }
            if addresses.is_empty() {
                space.pending.reach_out = None;
            }
        }

        // OBSERVED_ADDR
        if !path_exclusive_only
            && space_id == SpaceId::Data
            && self
                .config
                .address_discovery_role
                .should_report(&self.peer_params.address_discovery_role)
            && (!path.observed_addr_sent || space.pending.observed_addr)
        {
            let frame = frame::ObservedAddr::new(path.remote, self.next_observed_addr_seq_no);
            if buf.remaining_mut() > frame.size() {
                trace!(seq = %frame.seq_no, ip = %frame.ip, port = frame.port, "OBSERVED_ADDRESS");
                frame.write(buf);

                self.next_observed_addr_seq_no = self.next_observed_addr_seq_no.saturating_add(1u8);
                path.observed_addr_sent = true;

                self.stats.frame_tx.observed_addr += 1;
                sent.retransmits.get_or_create().observed_addr = true;
                space.pending.observed_addr = false;
                qlog.frame(&Frame::ObservedAddr(frame));
            }
        }

        // PING
        if mem::replace(&mut space.for_path(path_id).ping_pending, false) {
            trace!("PING");
            buf.write(frame::FrameType::PING);
            sent.non_retransmits = true;
            self.stats.frame_tx.ping += 1;
            qlog.frame(&Frame::Ping);
        }

        // IMMEDIATE_ACK
        if mem::replace(&mut space.for_path(path_id).immediate_ack_pending, false) {
            trace!("IMMEDIATE_ACK");
            buf.write(frame::FrameType::IMMEDIATE_ACK);
            sent.non_retransmits = true;
            self.stats.frame_tx.immediate_ack += 1;
            qlog.frame(&Frame::ImmediateAck);
        }

        // ACK
        // TODO(flub): Should this sends acks for this path anyway?
        if !path_exclusive_only {
            for path_id in space
                .number_spaces
                .iter_mut()
                .filter(|(_, pns)| pns.pending_acks.can_send())
                .map(|(&path_id, _)| path_id)
                .collect::<Vec<_>>()
            {
                debug_assert!(
                    is_multipath_negotiated || path_id == PathId::ZERO,
                    "Only PathId::ZERO allowed without multipath (have {path_id:?})"
                );
                Self::populate_acks(
                    now,
                    self.receiving_ecn,
                    &mut sent,
                    path_id,
                    space,
                    is_multipath_negotiated,
                    buf,
                    &mut self.stats,
                    qlog,
                );
            }
        }

        // ACK_FREQUENCY
        if !path_exclusive_only && mem::replace(&mut space.pending.ack_frequency, false) {
            let sequence_number = self.ack_frequency.next_sequence_number();

            // Safe to unwrap because this is always provided when ACK frequency is enabled
            let config = self.config.ack_frequency_config.as_ref().unwrap();

            // Ensure the delay is within bounds to avoid a PROTOCOL_VIOLATION error
            let max_ack_delay = self.ack_frequency.candidate_max_ack_delay(
                path.rtt.get(),
                config,
                &self.peer_params,
            );

            trace!(?max_ack_delay, "ACK_FREQUENCY");

            let frame = frame::AckFrequency {
                sequence: sequence_number,
                ack_eliciting_threshold: config.ack_eliciting_threshold,
                request_max_ack_delay: max_ack_delay.as_micros().try_into().unwrap_or(VarInt::MAX),
                reordering_threshold: config.reordering_threshold,
            };
            frame.encode(buf);
            qlog.frame(&Frame::AckFrequency(frame));

            sent.retransmits.get_or_create().ack_frequency = true;

            self.ack_frequency
                .ack_frequency_sent(path_id, pn, max_ack_delay);
            self.stats.frame_tx.ack_frequency += 1;
        }

        // PATH_CHALLENGE
        if buf.remaining_mut() > 9 && space_id == SpaceId::Data && path.send_new_challenge {
            path.send_new_challenge = false;

            // Generate a new challenge every time we send a new PATH_CHALLENGE
            let token = self.rng.random();
            path.challenges_sent.insert(token, now);
            sent.non_retransmits = true;
            sent.requires_padding = true;
            trace!("PATH_CHALLENGE {:08x}", token);
            buf.write(frame::FrameType::PATH_CHALLENGE);
            buf.write(token);
            qlog.frame(&Frame::PathChallenge(token));
            self.stats.frame_tx.path_challenge += 1;
            let pto = self.ack_frequency.max_ack_delay_for_pto() + path.rtt.pto_base();
            self.timers.set(
                Timer::PerPath(path_id, PathTimer::PathChallengeLost),
                now + pto,
            );

            if is_multipath_negotiated && !path.validated && path.send_new_challenge {
                // queue informing the path status along with the challenge
                space.pending.path_status.insert(path_id);
            }

            // Always include an OBSERVED_ADDR frame with a PATH_CHALLENGE, regardless
            // of whether one has already been sent on this path.
            if space_id == SpaceId::Data
                && self
                    .config
                    .address_discovery_role
                    .should_report(&self.peer_params.address_discovery_role)
            {
                let frame = frame::ObservedAddr::new(path.remote, self.next_observed_addr_seq_no);
                if buf.remaining_mut() > frame.size() {
                    frame.write(buf);
                    qlog.frame(&Frame::ObservedAddr(frame));

                    self.next_observed_addr_seq_no =
                        self.next_observed_addr_seq_no.saturating_add(1u8);
                    path.observed_addr_sent = true;

                    self.stats.frame_tx.observed_addr += 1;
                    sent.retransmits.get_or_create().observed_addr = true;
                    space.pending.observed_addr = false;
                }
            }
        }

        // PATH_RESPONSE
        if buf.remaining_mut() > 9 && space_id == SpaceId::Data {
            if let Some(token) = path.path_responses.pop_on_path(path.remote) {
                sent.non_retransmits = true;
                sent.requires_padding = true;
                trace!("PATH_RESPONSE {:08x}", token);
                buf.write(frame::FrameType::PATH_RESPONSE);
                buf.write(token);
                qlog.frame(&Frame::PathResponse(token));
                self.stats.frame_tx.path_response += 1;

                // NOTE: this is technically not required but might be useful to ride the
                // request/response nature of path challenges to refresh an observation
                // Since PATH_RESPONSE is a probing frame, this is allowed by the spec.
                if space_id == SpaceId::Data
                    && self
                        .config
                        .address_discovery_role
                        .should_report(&self.peer_params.address_discovery_role)
                {
                    let frame =
                        frame::ObservedAddr::new(path.remote, self.next_observed_addr_seq_no);
                    if buf.remaining_mut() > frame.size() {
                        frame.write(buf);
                        qlog.frame(&Frame::ObservedAddr(frame));

                        self.next_observed_addr_seq_no =
                            self.next_observed_addr_seq_no.saturating_add(1u8);
                        path.observed_addr_sent = true;

                        self.stats.frame_tx.observed_addr += 1;
                        sent.retransmits.get_or_create().observed_addr = true;
                        space.pending.observed_addr = false;
                    }
                }
            }
        }

        // CRYPTO
        while !path_exclusive_only && buf.remaining_mut() > frame::Crypto::SIZE_BOUND && !is_0rtt {
            let mut frame = match space.pending.crypto.pop_front() {
                Some(x) => x,
                None => break,
            };

            // Calculate the maximum amount of crypto data we can store in the buffer.
            // Since the offset is known, we can reserve the exact size required to encode it.
            // For length we reserve 2bytes which allows to encode up to 2^14,
            // which is more than what fits into normally sized QUIC frames.
            let max_crypto_data_size = buf.remaining_mut()
                - 1 // Frame Type
                - VarInt::size(unsafe { VarInt::from_u64_unchecked(frame.offset) })
                - 2; // Maximum encoded length for frame size, given we send less than 2^14 bytes

            let len = frame
                .data
                .len()
                .min(2usize.pow(14) - 1)
                .min(max_crypto_data_size);

            let data = frame.data.split_to(len);
            let truncated = frame::Crypto {
                offset: frame.offset,
                data,
            };
            trace!(
                "CRYPTO: off {} len {}",
                truncated.offset,
                truncated.data.len()
            );
            truncated.encode(buf);
            self.stats.frame_tx.crypto += 1;

            // The clone is cheap but we still cfg it out if qlog is disabled.
            #[cfg(feature = "qlog")]
            qlog.frame(&Frame::Crypto(truncated.clone()));
            sent.retransmits.get_or_create().crypto.push_back(truncated);
            if !frame.data.is_empty() {
                frame.offset += len as u64;
                space.pending.crypto.push_front(frame);
            }
        }

        // TODO(flub): maybe this is much higher priority?
        // PATH_ABANDON
        while !path_exclusive_only
            && space_id == SpaceId::Data
            && frame::PathAbandon::SIZE_BOUND <= buf.remaining_mut()
        {
            let Some((path_id, error_code)) = space.pending.path_abandon.pop_first() else {
                break;
            };
            let frame = frame::PathAbandon {
                path_id,
                error_code,
            };
            frame.encode(buf);
            qlog.frame(&Frame::PathAbandon(frame));
            self.stats.frame_tx.path_abandon += 1;
            trace!(%path_id, "PATH_ABANDON");
            sent.retransmits
                .get_or_create()
                .path_abandon
                .entry(path_id)
                .or_insert(error_code);
        }

        // PATH_AVAILABLE & PATH_BACKUP
        while !path_exclusive_only
            && space_id == SpaceId::Data
            && frame::PathAvailable::SIZE_BOUND <= buf.remaining_mut()
        {
            let Some(path_id) = space.pending.path_status.pop_first() else {
                break;
            };
            let Some(path) = self.paths.get(&path_id).map(|path_state| &path_state.data) else {
                trace!(%path_id, "discarding queued path status for unknown path");
                continue;
            };

            let seq = path.status.seq();
            sent.retransmits.get_or_create().path_status.insert(path_id);
            match path.local_status() {
                PathStatus::Available => {
                    let frame = frame::PathAvailable {
                        path_id,
                        status_seq_no: seq,
                    };
                    frame.encode(buf);
                    qlog.frame(&Frame::PathAvailable(frame));
                    self.stats.frame_tx.path_available += 1;
                    trace!(%path_id, %seq, "PATH_AVAILABLE")
                }
                PathStatus::Backup => {
                    let frame = frame::PathBackup {
                        path_id,
                        status_seq_no: seq,
                    };
                    frame.encode(buf);
                    qlog.frame(&Frame::PathBackup(frame));
                    self.stats.frame_tx.path_backup += 1;
                    trace!(%path_id, %seq, "PATH_BACKUP")
                }
            }
        }

        // MAX_PATH_ID
        if space_id == SpaceId::Data
            && space.pending.max_path_id
            && frame::MaxPathId::SIZE_BOUND <= buf.remaining_mut()
        {
            let frame = frame::MaxPathId(self.local_max_path_id);
            frame.encode(buf);
            qlog.frame(&Frame::MaxPathId(frame));
            space.pending.max_path_id = false;
            sent.retransmits.get_or_create().max_path_id = true;
            trace!(val = %self.local_max_path_id, "MAX_PATH_ID");
            self.stats.frame_tx.max_path_id += 1;
        }

        // PATHS_BLOCKED
        if space_id == SpaceId::Data
            && space.pending.paths_blocked
            && frame::PathsBlocked::SIZE_BOUND <= buf.remaining_mut()
        {
            let frame = frame::PathsBlocked(self.remote_max_path_id);
            frame.encode(buf);
            qlog.frame(&Frame::PathsBlocked(frame));
            space.pending.paths_blocked = false;
            sent.retransmits.get_or_create().paths_blocked = true;
            trace!(max_path_id = ?self.remote_max_path_id, "PATHS_BLOCKED");
            self.stats.frame_tx.paths_blocked += 1;
        }

        // PATH_CIDS_BLOCKED
        while space_id == SpaceId::Data && frame::PathCidsBlocked::SIZE_BOUND <= buf.remaining_mut()
        {
            let Some(path_id) = space.pending.path_cids_blocked.pop() else {
                break;
            };
            let next_seq = match self.rem_cids.get(&path_id) {
                Some(cid_queue) => cid_queue.active_seq() + 1,
                None => 0,
            };
            let frame = frame::PathCidsBlocked {
                path_id,
                next_seq: VarInt(next_seq),
            };
            frame.encode(buf);
            qlog.frame(&Frame::PathCidsBlocked(frame));
            sent.retransmits
                .get_or_create()
                .path_cids_blocked
                .push(path_id);
            trace!(%path_id, next_seq, "PATH_CIDS_BLOCKED");
            self.stats.frame_tx.path_cids_blocked += 1;
        }

        // RESET_STREAM, STOP_SENDING, MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS
        if space_id == SpaceId::Data {
            self.streams.write_control_frames(
                buf,
                &mut space.pending,
                &mut sent.retransmits,
                &mut self.stats.frame_tx,
                qlog,
            );
        }

        // NEW_CONNECTION_ID
        let cid_len = self
            .local_cid_state
            .values()
            .map(|cid_state| cid_state.cid_len())
            .max()
            .expect("some local CID state must exist");
        let new_cid_size_bound =
            frame::NewConnectionId::size_bound(is_multipath_negotiated, cid_len);
        while !path_exclusive_only && buf.remaining_mut() > new_cid_size_bound {
            let issued = match space.pending.new_cids.pop() {
                Some(x) => x,
                None => break,
            };
            let retire_prior_to = self
                .local_cid_state
                .get(&issued.path_id)
                .map(|cid_state| cid_state.retire_prior_to())
                .unwrap_or_else(|| {
                    error!(path_id = ?issued.path_id, "Missing local CID state");
                    0
                });
            let cid_path_id = match is_multipath_negotiated {
                true => {
                    trace!(
                        path_id = ?issued.path_id,
                        sequence = issued.sequence,
                        id = %issued.id,
                        "PATH_NEW_CONNECTION_ID",
                    );
                    self.stats.frame_tx.path_new_connection_id += 1;
                    Some(issued.path_id)
                }
                false => {
                    trace!(
                        sequence = issued.sequence,
                        id = %issued.id,
                        "NEW_CONNECTION_ID"
                    );
                    debug_assert_eq!(issued.path_id, PathId::ZERO);
                    self.stats.frame_tx.new_connection_id += 1;
                    None
                }
            };
            let frame = frame::NewConnectionId {
                path_id: cid_path_id,
                sequence: issued.sequence,
                retire_prior_to,
                id: issued.id,
                reset_token: issued.reset_token,
            };
            frame.encode(buf);
            sent.retransmits.get_or_create().new_cids.push(issued);
            qlog.frame(&Frame::NewConnectionId(frame));
        }

        // RETIRE_CONNECTION_ID
        let retire_cid_bound = frame::RetireConnectionId::size_bound(is_multipath_negotiated);
        while !path_exclusive_only && buf.remaining_mut() > retire_cid_bound {
            let (path_id, sequence) = match space.pending.retire_cids.pop() {
                Some((PathId::ZERO, seq)) if !is_multipath_negotiated => {
                    trace!(sequence = seq, "RETIRE_CONNECTION_ID");
                    self.stats.frame_tx.retire_connection_id += 1;
                    (None, seq)
                }
                Some((path_id, seq)) => {
                    trace!(%path_id, sequence = seq, "PATH_RETIRE_CONNECTION_ID");
                    self.stats.frame_tx.path_retire_connection_id += 1;
                    (Some(path_id), seq)
                }
                None => break,
            };
            let frame = frame::RetireConnectionId { path_id, sequence };
            frame.encode(buf);
            qlog.frame(&Frame::RetireConnectionId(frame));
            sent.retransmits
                .get_or_create()
                .retire_cids
                .push((path_id.unwrap_or_default(), sequence));
        }

        // DATAGRAM
        let mut sent_datagrams = false;
        while !path_exclusive_only
            && buf.remaining_mut() > Datagram::SIZE_BOUND
            && space_id == SpaceId::Data
        {
            let prev_remaining = buf.remaining_mut();
            match self.datagrams.write(buf) {
                true => {
                    sent_datagrams = true;
                    sent.non_retransmits = true;
                    self.stats.frame_tx.datagram += 1;
                    qlog.frame_datagram((prev_remaining - buf.remaining_mut()) as u64);
                }
                false => break,
            }
        }
        if self.datagrams.send_blocked && sent_datagrams {
            self.events.push_back(Event::DatagramsUnblocked);
            self.datagrams.send_blocked = false;
        }

        let path = &mut self.paths.get_mut(&path_id).expect("known path").data;

        // NEW_TOKEN
        while let Some(remote_addr) = space.pending.new_tokens.pop() {
            if path_exclusive_only {
                break;
            }
            debug_assert_eq!(space_id, SpaceId::Data);
            let ConnectionSide::Server { server_config } = &self.side else {
                panic!("NEW_TOKEN frames should not be enqueued by clients");
            };

            if remote_addr != path.remote {
                // NEW_TOKEN frames contain tokens bound to a client's IP address, and are only
                // useful if used from the same IP address.  Thus, we abandon enqueued NEW_TOKEN
                // frames upon an path change. Instead, when the new path becomes validated,
                // NEW_TOKEN frames may be enqueued for the new path instead.
                continue;
            }

            let token = Token::new(
                TokenPayload::Validation {
                    ip: remote_addr.ip(),
                    issued: server_config.time_source.now(),
                },
                &mut self.rng,
            );
            let new_token = NewToken {
                token: token.encode(&*server_config.token_key).into(),
            };

            if buf.remaining_mut() < new_token.size() {
                space.pending.new_tokens.push(remote_addr);
                break;
            }

            trace!("NEW_TOKEN");
            new_token.encode(buf);
            qlog.frame(&Frame::NewToken(new_token));
            sent.retransmits
                .get_or_create()
                .new_tokens
                .push(remote_addr);
            self.stats.frame_tx.new_token += 1;
        }

        // STREAM
        if !path_exclusive_only && space_id == SpaceId::Data {
            sent.stream_frames =
                self.streams
                    .write_stream_frames(buf, self.config.send_fairness, qlog);
            self.stats.frame_tx.stream += sent.stream_frames.len() as u64;
        }

        // ADD_ADDRESS
        // TODO(@divma): check if we need to do path exclusive filters
        while space_id == SpaceId::Data && frame::AddAddress::SIZE_BOUND <= buf.remaining_mut() {
            if let Some(added_address) = space.pending.add_address.pop_last() {
                trace!(
                    seq = %added_address.seq_no,
                    ip = ?added_address.ip,
                    port = added_address.port,
                    "ADD_ADDRESS",
                );
                added_address.write(buf);
                sent.retransmits
                    .get_or_create()
                    .add_address
                    .insert(added_address);
                self.stats.frame_tx.add_address = self.stats.frame_tx.add_address.saturating_add(1);
            } else {
                break;
            }
        }

        // REMOVE_ADDRESS
        while space_id == SpaceId::Data && frame::RemoveAddress::SIZE_BOUND <= buf.remaining_mut() {
            if let Some(removed_address) = space.pending.remove_address.pop_last() {
                trace!(seq = %removed_address.seq_no, "REMOVE_ADDRESS");
                removed_address.write(buf);
                sent.retransmits
                    .get_or_create()
                    .remove_address
                    .insert(removed_address);
                self.stats.frame_tx.remove_address =
                    self.stats.frame_tx.remove_address.saturating_add(1);
            } else {
                break;
            }
        }

        sent
    }

    /// Write pending ACKs into a buffer
    fn populate_acks(
        now: Instant,
        receiving_ecn: bool,
        sent: &mut SentFrames,
        path_id: PathId,
        space: &mut PacketSpace,
        send_path_acks: bool,
        buf: &mut impl BufMut,
        stats: &mut ConnectionStats,
        #[allow(unused)] qlog: &mut QlogSentPacket,
    ) {
        // 0-RTT packets must never carry acks (which would have to be of handshake packets)
        debug_assert!(space.crypto.is_some(), "tried to send ACK in 0-RTT");

        let pns = space.for_path(path_id);
        let ranges = pns.pending_acks.ranges();
        debug_assert!(!ranges.is_empty(), "can not send empty ACK range");
        let ecn = if receiving_ecn {
            Some(&pns.ecn_counters)
        } else {
            None
        };
        if let Some(max) = ranges.max() {
            sent.largest_acked.insert(path_id, max);
        }

        let delay_micros = pns.pending_acks.ack_delay(now).as_micros() as u64;
        // TODO: This should come from `TransportConfig` if that gets configurable.
        let ack_delay_exp = TransportParameters::default().ack_delay_exponent;
        let delay = delay_micros >> ack_delay_exp.into_inner();

        if send_path_acks {
            if !ranges.is_empty() {
                trace!("PATH_ACK {path_id:?} {ranges:?}, Delay = {delay_micros}us");
                frame::PathAck::encode(path_id, delay as _, ranges, ecn, buf);
                qlog.frame_path_ack(path_id, delay as _, ranges, ecn);
                stats.frame_tx.path_acks += 1;
            }
        } else {
            trace!("ACK {ranges:?}, Delay = {delay_micros}us");
            frame::Ack::encode(delay as _, ranges, ecn, buf);
            stats.frame_tx.acks += 1;
            qlog.frame_ack(delay, ranges, ecn);
        }
    }

    fn close_common(&mut self) {
        trace!("connection closed");
        self.timers.reset();
    }

    fn set_close_timer(&mut self, now: Instant) {
        // QUIC-MULTIPATH § 2.6 Connection Closure: draining for 3*PTO with PTO the max of
        // the PTO for all paths.
        self.timers.set(
            Timer::Conn(ConnTimer::Close),
            now + 3 * self.pto_max_path(self.highest_space),
        );
    }

    /// Handle transport parameters received from the peer
    ///
    /// *rem_cid* and *loc_cid* are the source and destination CIDs respectively of the
    /// *packet into which the transport parameters arrived.
    fn handle_peer_params(
        &mut self,
        params: TransportParameters,
        loc_cid: ConnectionId,
        rem_cid: ConnectionId,
    ) -> Result<(), TransportError> {
        if Some(self.orig_rem_cid) != params.initial_src_cid
            || (self.side.is_client()
                && (Some(self.initial_dst_cid) != params.original_dst_cid
                    || self.retry_src_cid != params.retry_src_cid))
        {
            return Err(TransportError::TRANSPORT_PARAMETER_ERROR(
                "CID authentication failure",
            ));
        }
        if params.initial_max_path_id.is_some() && (loc_cid.is_empty() || rem_cid.is_empty()) {
            return Err(TransportError::PROTOCOL_VIOLATION(
                "multipath must not use zero-length CIDs",
            ));
        }

        self.set_peer_params(params);

        Ok(())
    }

    fn set_peer_params(&mut self, params: TransportParameters) {
        self.streams.set_params(&params);
        self.idle_timeout =
            negotiate_max_idle_timeout(self.config.max_idle_timeout, Some(params.max_idle_timeout));
        trace!("negotiated max idle timeout {:?}", self.idle_timeout);

        if let Some(ref info) = params.preferred_address {
            // During the handshake PathId::ZERO exists.
            self.rem_cids.get_mut(&PathId::ZERO).expect("not yet abandoned").insert(frame::NewConnectionId {
                path_id: None,
                sequence: 1,
                id: info.connection_id,
                reset_token: info.stateless_reset_token,
                retire_prior_to: 0,
            })
            .expect(
                "preferred address CID is the first received, and hence is guaranteed to be legal",
            );
            let remote = self.path_data(PathId::ZERO).remote;
            self.set_reset_token(PathId::ZERO, remote, info.stateless_reset_token);
        }
        self.ack_frequency.peer_max_ack_delay = get_max_ack_delay(&params);

        let mut multipath_enabled = None;
        if let (Some(local_max_path_id), Some(remote_max_path_id)) = (
            self.config.get_initial_max_path_id(),
            params.initial_max_path_id,
        ) {
            // multipath is enabled, register the local and remote maximums
            self.local_max_path_id = local_max_path_id;
            self.remote_max_path_id = remote_max_path_id;
            let initial_max_path_id = local_max_path_id.min(remote_max_path_id);
            debug!(%initial_max_path_id, "multipath negotiated");
            multipath_enabled = Some(initial_max_path_id);
        }

        if let Some((max_locally_allowed_remote_addresses, max_remotely_allowed_remote_addresses)) =
            self.config
                .max_remote_nat_traversal_addresses
                .zip(params.max_remote_nat_traversal_addresses)
        {
            if let Some(max_initial_paths) =
                multipath_enabled.map(|path_id| path_id.saturating_add(1u8))
            {
                let max_local_addresses = max_remotely_allowed_remote_addresses.get();
                let max_remote_addresses = max_locally_allowed_remote_addresses.get();
                self.iroh_hp =
                    iroh_hp::State::new(max_remote_addresses, max_local_addresses, self.side());
                debug!(
                    %max_remote_addresses, %max_local_addresses,
                    "iroh hole punching negotiated"
                );

                match self.side() {
                    Side::Client => {
                        if max_initial_paths.as_u32() < max_remote_addresses as u32 + 1 {
                            // in this case the client might try to open `max_remote_addresses` new
                            // paths, but the current multipath configuration will not allow it
                            warn!(%max_initial_paths, %max_remote_addresses, "local client configuration might cause nat traversal issues")
                        } else if max_local_addresses as u64
                            > params.active_connection_id_limit.into_inner()
                        {
                            // the server allows us to send at most `params.active_connection_id_limit`
                            // but they might need at least `max_local_addresses` to effectively send
                            // `PATH_CHALLENGE` frames to each advertised local address
                            warn!(%max_local_addresses, remote_cid_limit=%params.active_connection_id_limit.into_inner(), "remote server configuration might cause nat traversal issues")
                        }
                    }
                    Side::Server => {
                        if (max_initial_paths.as_u32() as u64) < crate::LOC_CID_COUNT {
                            warn!(%max_initial_paths, local_cid_limit=%crate::LOC_CID_COUNT, "local server configuration might cause nat traversal issues")
                        }
                    }
                }
            } else {
                debug!("iroh nat traversal enabled for both endpoints, but multipath is missing")
            }
        }

        self.peer_params = params;
        let peer_max_udp_payload_size =
            u16::try_from(self.peer_params.max_udp_payload_size.into_inner()).unwrap_or(u16::MAX);
        self.path_data_mut(PathId::ZERO)
            .mtud
            .on_peer_max_udp_payload_size_received(peer_max_udp_payload_size);
    }

    /// Decrypts a packet, returning the packet number on success
    fn decrypt_packet(
        &mut self,
        now: Instant,
        path_id: PathId,
        packet: &mut Packet,
    ) -> Result<Option<u64>, Option<TransportError>> {
        let result = packet_crypto::decrypt_packet_body(
            packet,
            path_id,
            &self.spaces,
            self.zero_rtt_crypto.as_ref(),
            self.key_phase,
            self.prev_crypto.as_ref(),
            self.next_crypto.as_ref(),
        )?;

        let result = match result {
            Some(r) => r,
            None => return Ok(None),
        };

        if result.outgoing_key_update_acked {
            if let Some(prev) = self.prev_crypto.as_mut() {
                prev.end_packet = Some((result.number, now));
                self.set_key_discard_timer(now, packet.header.space());
            }
        }

        if result.incoming_key_update {
            trace!("key update authenticated");
            self.update_keys(Some((result.number, now)), true);
            self.set_key_discard_timer(now, packet.header.space());
        }

        Ok(Some(result.number))
    }

    fn update_keys(&mut self, end_packet: Option<(u64, Instant)>, remote: bool) {
        trace!("executing key update");
        // Generate keys for the key phase after the one we're switching to, store them in
        // `next_crypto`, make the contents of `next_crypto` current, and move the current keys into
        // `prev_crypto`.
        let new = self
            .crypto
            .next_1rtt_keys()
            .expect("only called for `Data` packets");
        self.key_phase_size = new
            .local
            .confidentiality_limit()
            .saturating_sub(KEY_UPDATE_MARGIN);
        let old = mem::replace(
            &mut self.spaces[SpaceId::Data]
                .crypto
                .as_mut()
                .unwrap() // safe because update_keys() can only be triggered by short packets
                .packet,
            mem::replace(self.next_crypto.as_mut().unwrap(), new),
        );
        self.spaces[SpaceId::Data]
            .iter_paths_mut()
            .for_each(|s| s.sent_with_keys = 0);
        self.prev_crypto = Some(PrevCrypto {
            crypto: old,
            end_packet,
            update_unacked: remote,
        });
        self.key_phase = !self.key_phase;
    }

    fn peer_supports_ack_frequency(&self) -> bool {
        self.peer_params.min_ack_delay.is_some()
    }

    /// Send an IMMEDIATE_ACK frame to the remote endpoint
    ///
    /// According to the spec, this will result in an error if the remote endpoint does not support
    /// the Acknowledgement Frequency extension
    pub(crate) fn immediate_ack(&mut self, path_id: PathId) {
        self.spaces[self.highest_space]
            .for_path(path_id)
            .immediate_ack_pending = true;
    }

    /// Decodes a packet, returning its decrypted payload, so it can be inspected in tests
    #[cfg(test)]
    pub(crate) fn decode_packet(&self, event: &ConnectionEvent) -> Option<Vec<u8>> {
        let (path_id, first_decode, remaining) = match &event.0 {
            ConnectionEventInner::Datagram(DatagramConnectionEvent {
                path_id,
                first_decode,
                remaining,
                ..
            }) => (path_id, first_decode, remaining),
            _ => return None,
        };

        if remaining.is_some() {
            panic!("Packets should never be coalesced in tests");
        }

        let decrypted_header = packet_crypto::unprotect_header(
            first_decode.clone(),
            &self.spaces,
            self.zero_rtt_crypto.as_ref(),
            self.peer_params.stateless_reset_token,
        )?;

        let mut packet = decrypted_header.packet?;
        packet_crypto::decrypt_packet_body(
            &mut packet,
            *path_id,
            &self.spaces,
            self.zero_rtt_crypto.as_ref(),
            self.key_phase,
            self.prev_crypto.as_ref(),
            self.next_crypto.as_ref(),
        )
        .ok()?;

        Some(packet.payload.to_vec())
    }

    /// The number of bytes of packets containing retransmittable frames that have not been
    /// acknowledged or declared lost.
    #[cfg(test)]
    pub(crate) fn bytes_in_flight(&self) -> u64 {
        // TODO(@divma): consider including for multipath?
        self.path_data(PathId::ZERO).in_flight.bytes
    }

    /// Number of bytes worth of non-ack-only packets that may be sent
    #[cfg(test)]
    pub(crate) fn congestion_window(&self) -> u64 {
        let path = self.path_data(PathId::ZERO);
        path.congestion
            .window()
            .saturating_sub(path.in_flight.bytes)
    }

    /// Whether no timers but keepalive, idle, rtt, pushnewcid, and key discard are running
    #[cfg(test)]
    pub(crate) fn is_idle(&self) -> bool {
        let current_timers = self.timers.values();
        current_timers
            .into_iter()
            .filter(|(timer, _)| {
                !matches!(
                    timer,
                    Timer::Conn(ConnTimer::KeepAlive)
                        | Timer::PerPath(_, PathTimer::PathKeepAlive)
                        | Timer::Conn(ConnTimer::PushNewCid)
                        | Timer::Conn(ConnTimer::KeyDiscard)
                )
            })
            .min_by_key(|(_, time)| *time)
            .is_none_or(|(timer, _)| timer == Timer::Conn(ConnTimer::Idle))
    }

    /// Whether explicit congestion notification is in use on outgoing packets.
    #[cfg(test)]
    pub(crate) fn using_ecn(&self) -> bool {
        self.path_data(PathId::ZERO).sending_ecn
    }

    /// The number of received bytes in the current path
    #[cfg(test)]
    pub(crate) fn total_recvd(&self) -> u64 {
        self.path_data(PathId::ZERO).total_recvd
    }

    #[cfg(test)]
    pub(crate) fn active_local_cid_seq(&self) -> (u64, u64) {
        self.local_cid_state
            .get(&PathId::ZERO)
            .unwrap()
            .active_seq()
    }

    #[cfg(test)]
    #[track_caller]
    pub(crate) fn active_local_path_cid_seq(&self, path_id: u32) -> (u64, u64) {
        self.local_cid_state
            .get(&PathId(path_id))
            .unwrap()
            .active_seq()
    }

    /// Instruct the peer to replace previously issued CIDs by sending a NEW_CONNECTION_ID frame
    /// with updated `retire_prior_to` field set to `v`
    #[cfg(test)]
    pub(crate) fn rotate_local_cid(&mut self, v: u64, now: Instant) {
        let n = self
            .local_cid_state
            .get_mut(&PathId::ZERO)
            .unwrap()
            .assign_retire_seq(v);
        self.endpoint_events
            .push_back(EndpointEventInner::NeedIdentifiers(PathId::ZERO, now, n));
    }

    /// Check the current active remote CID sequence for `PathId::ZERO`
    #[cfg(test)]
    pub(crate) fn active_rem_cid_seq(&self) -> u64 {
        self.rem_cids.get(&PathId::ZERO).unwrap().active_seq()
    }

    /// Returns the detected maximum udp payload size for the current path
    #[cfg(test)]
    pub(crate) fn path_mtu(&self) -> u16 {
        self.path_data(PathId::ZERO).current_mtu()
    }

    /// Triggers path validation on all paths
    #[cfg(test)]
    pub(crate) fn trigger_path_validation(&mut self) {
        for path in self.paths.values_mut() {
            path.data.send_new_challenge = true;
        }
    }

    /// Whether we have 1-RTT data to send
    ///
    /// This checks for frames that can only be sent in the data space (1-RTT):
    /// - Pending PATH_CHALLENGE frames on the active and previous path if just migrated.
    /// - Pending PATH_RESPONSE frames.
    /// - Pending data to send in STREAM frames.
    /// - Pending DATAGRAM frames to send.
    ///
    /// See also [`PacketSpace::can_send`] which keeps track of all other frame types that
    /// may need to be sent.
    fn can_send_1rtt(&self, path_id: PathId, max_size: usize) -> SendableFrames {
        let path_exclusive = self.paths.get(&path_id).is_some_and(|path| {
            path.data.send_new_challenge
                || path
                    .prev
                    .as_ref()
                    .is_some_and(|(_, path)| path.send_new_challenge)
                || !path.data.path_responses.is_empty()
        });
        let other = self.streams.can_send_stream_data()
            || self
                .datagrams
                .outgoing
                .front()
                .is_some_and(|x| x.size(true) <= max_size);
        SendableFrames {
            acks: false,
            other,
            close: false,
            path_exclusive,
        }
    }

    /// Terminate the connection instantly, without sending a close packet
    fn kill(&mut self, reason: ConnectionError) {
        self.close_common();
        self.state.move_to_drained(Some(reason));
        self.endpoint_events.push_back(EndpointEventInner::Drained);
    }

    /// Storage size required for the largest packet that can be transmitted on all currently
    /// available paths
    ///
    /// Buffers passed to [`Connection::poll_transmit`] should be at least this large.
    ///
    /// When multipath is enabled, this value is the minimum MTU across all available paths.
    pub fn current_mtu(&self) -> u16 {
        self.paths
            .iter()
            .filter(|&(path_id, _path_state)| !self.abandoned_paths.contains(path_id))
            .map(|(_path_id, path_state)| path_state.data.current_mtu())
            .min()
            .expect("There is always at least one available path")
    }

    /// Size of non-frame data for a 1-RTT packet
    ///
    /// Quantifies space consumed by the QUIC header and AEAD tag. All other bytes in a packet are
    /// frames. Changes if the length of the remote connection ID changes, which is expected to be
    /// rare. If `pn` is specified, may additionally change unpredictably due to variations in
    /// latency and packet loss.
    fn predict_1rtt_overhead(&mut self, pn: u64, path: PathId) -> usize {
        let pn_len = PacketNumber::new(
            pn,
            self.spaces[SpaceId::Data]
                .for_path(path)
                .largest_acked_packet
                .unwrap_or(0),
        )
        .len();

        // 1 byte for flags
        1 + self
            .rem_cids
            .get(&path)
            .map(|cids| cids.active().len())
            .unwrap_or(20)      // Max CID len in QUIC v1
            + pn_len
            + self.tag_len_1rtt()
    }

    fn predict_1rtt_overhead_no_pn(&self) -> usize {
        let pn_len = 4;

        let cid_len = self
            .rem_cids
            .values()
            .map(|cids| cids.active().len())
            .max()
            .unwrap_or(20); // Max CID len in QUIC v1

        // 1 byte for flags
        1 + cid_len + pn_len + self.tag_len_1rtt()
    }

    fn tag_len_1rtt(&self) -> usize {
        let key = match self.spaces[SpaceId::Data].crypto.as_ref() {
            Some(crypto) => Some(&*crypto.packet.local),
            None => self.zero_rtt_crypto.as_ref().map(|x| &*x.packet),
        };
        // If neither Data nor 0-RTT keys are available, make a reasonable tag length guess. As of
        // this writing, all QUIC cipher suites use 16-byte tags. We could return `None` instead,
        // but that would needlessly prevent sending datagrams during 0-RTT.
        key.map_or(16, |x| x.tag_len())
    }

    /// Mark the path as validated, and enqueue NEW_TOKEN frames to be sent as appropriate
    fn on_path_validated(&mut self, path_id: PathId) {
        self.path_data_mut(path_id).validated = true;
        let ConnectionSide::Server { server_config } = &self.side else {
            return;
        };
        let remote_addr = self.path_data(path_id).remote;
        let new_tokens = &mut self.spaces[SpaceId::Data as usize].pending.new_tokens;
        new_tokens.clear();
        for _ in 0..server_config.validation_token.sent {
            new_tokens.push(remote_addr);
        }
    }

    /// Handle new path status information: PATH_AVAILABLE, PATH_BACKUP
    fn on_path_status(&mut self, path_id: PathId, status: PathStatus, status_seq_no: VarInt) {
        if let Some(path) = self.paths.get_mut(&path_id) {
            path.data.status.remote_update(status, status_seq_no);
        } else {
            debug!("PATH_AVAILABLE received unknown path {:?}", path_id);
        }
        self.events.push_back(
            PathEvent::RemoteStatus {
                id: path_id,
                status,
            }
            .into(),
        );
    }

    /// Returns the maximum [`PathId`] to be used for sending in this connection.
    ///
    /// This is calculated as minimum between the local and remote's maximums when multipath is
    /// enabled, or `None` when disabled.
    ///
    /// For data that's received, we should use [`Self::local_max_path_id`] instead.
    /// The reasoning is that the remote might already have updated to its own newer
    /// [`Self::max_path_id`] after sending out a `MAX_PATH_ID` frame, but it got re-ordered.
    fn max_path_id(&self) -> Option<PathId> {
        if self.is_multipath_negotiated() {
            Some(self.remote_max_path_id.min(self.local_max_path_id))
        } else {
            None
        }
    }

    /// Add addresses the local endpoint considers are reachable for nat traversal
    pub fn add_nat_traversal_address(&mut self, address: SocketAddr) -> Result<(), iroh_hp::Error> {
        if let Some(added) = self.iroh_hp.add_local_address(address)? {
            self.spaces[SpaceId::Data].pending.add_address.insert(added);
        };
        Ok(())
    }

    /// Removes an address the endpoing no longer considers reachable for nat traversal
    ///
    /// Addresses not present in the set will be silently ignored.
    pub fn remove_nat_traversal_address(
        &mut self,
        address: SocketAddr,
    ) -> Result<(), iroh_hp::Error> {
        if let Some(removed) = self.iroh_hp.remove_local_address(address)? {
            self.spaces[SpaceId::Data]
                .pending
                .remove_address
                .insert(removed);
        }
        Ok(())
    }

    /// Get the current local nat traversal addresses
    pub fn get_local_nat_traversal_addresses(&self) -> Result<Vec<SocketAddr>, iroh_hp::Error> {
        self.iroh_hp.get_local_nat_traversal_addresses()
    }

    /// Get the currently advertised nat traversal addresses by the server
    pub fn get_remote_nat_traversal_addresses(&self) -> Result<Vec<SocketAddr>, iroh_hp::Error> {
        Ok(self
            .iroh_hp
            .client_side()?
            .get_remote_nat_traversal_addresses())
    }

    /// Initiates a new nat traversal round
    ///
    /// A nat traversal round involves advertising the client's local addresses in `REACH_OUT`
    /// frames, and initiating probing of the known remote addresses. When a new round is
    /// initiated, the previous one is cancelled, and paths that have not been opened are closed.
    ///
    /// Returns the server addresses that are now being probed.
    pub fn initiate_nat_traversal_round(
        &mut self,
        now: Instant,
    ) -> Result<Vec<SocketAddr>, iroh_hp::Error> {
        let client_state = self.iroh_hp.client_side_mut()?;
        let iroh_hp::NatTraversalRound {
            new_round,
            reach_out_at,
            addresses_to_probe,
            prev_round_path_ids,
        } = client_state.initiate_nat_traversal_round()?;

        self.spaces[SpaceId::Data].pending.reach_out = Some((new_round, reach_out_at));

        for path_id in prev_round_path_ids {
            // TODO(@divma): this sounds reasonable but we need if this actually works for the
            // purposes of the protocol
            let validated = self
                .path(path_id)
                .map(|path| path.validated)
                .unwrap_or(false);

            if !validated {
                let _ =
                    self.close_path(now, path_id, TransportErrorCode::APPLICATION_ABANDON.into());
            }
        }

        let mut err = None;

        let mut path_ids = Vec::with_capacity(addresses_to_probe.len());
        let mut probed_addresses = Vec::with_capacity(addresses_to_probe.len());
        let ipv6 = self.paths.values().any(|p| p.data.remote.is_ipv6());

        for (ip, port) in addresses_to_probe {
            // If this endpoint is an IPv6 endpoint we use IPv6 addresses for all remotes.
            let remote = match ip {
                IpAddr::V4(addr) if ipv6 => SocketAddr::new(addr.to_ipv6_mapped().into(), port),
                IpAddr::V4(addr) => SocketAddr::new(addr.into(), port),
                IpAddr::V6(_) if ipv6 => SocketAddr::new(ip, port),
                IpAddr::V6(_) => {
                    trace!("not using IPv6 nat candidate for IPv4 socket");
                    continue;
                }
            };
            match self.open_path_ensure(remote, PathStatus::Backup, now) {
                Ok((path_id, path_was_known)) if !path_was_known => {
                    path_ids.push(path_id);
                    probed_addresses.push(remote);
                }
                Ok((path_id, _)) => {
                    trace!(%path_id, %remote,"nat traversal: path existed for remote")
                }
                Err(e) => {
                    debug!(%remote, %e,"nat traversal: failed to probe remote");
                    err.get_or_insert(e);
                }
            }
        }

        self.iroh_hp
            .client_side_mut()
            .expect("connection side validated")
            .set_round_path_ids(path_ids);

        Ok(probed_addresses)
    }
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Connection")
            .field("handshake_cid", &self.handshake_cid)
            .finish()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum PathBlocked {
    No,
    AntiAmplification,
    Congestion,
    Pacing,
}

/// Fields of `Connection` specific to it being client-side or server-side
enum ConnectionSide {
    Client {
        /// Sent in every outgoing Initial packet. Always empty after Initial keys are discarded
        token: Bytes,
        token_store: Arc<dyn TokenStore>,
        server_name: String,
    },
    Server {
        server_config: Arc<ServerConfig>,
    },
}

impl ConnectionSide {
    fn remote_may_migrate(&self, state: &State) -> bool {
        match self {
            Self::Server { server_config } => server_config.migration,
            Self::Client { .. } => {
                if let Some(hs) = state.as_handshake() {
                    hs.allow_server_migration
                } else {
                    false
                }
            }
        }
    }

    fn is_client(&self) -> bool {
        self.side().is_client()
    }

    fn is_server(&self) -> bool {
        self.side().is_server()
    }

    fn side(&self) -> Side {
        match *self {
            Self::Client { .. } => Side::Client,
            Self::Server { .. } => Side::Server,
        }
    }
}

impl From<SideArgs> for ConnectionSide {
    fn from(side: SideArgs) -> Self {
        match side {
            SideArgs::Client {
                token_store,
                server_name,
            } => Self::Client {
                token: token_store.take(&server_name).unwrap_or_default(),
                token_store,
                server_name,
            },
            SideArgs::Server {
                server_config,
                pref_addr_cid: _,
                path_validated: _,
            } => Self::Server { server_config },
        }
    }
}

/// Parameters to `Connection::new` specific to it being client-side or server-side
pub(crate) enum SideArgs {
    Client {
        token_store: Arc<dyn TokenStore>,
        server_name: String,
    },
    Server {
        server_config: Arc<ServerConfig>,
        pref_addr_cid: Option<ConnectionId>,
        path_validated: bool,
    },
}

impl SideArgs {
    pub(crate) fn pref_addr_cid(&self) -> Option<ConnectionId> {
        match *self {
            Self::Client { .. } => None,
            Self::Server { pref_addr_cid, .. } => pref_addr_cid,
        }
    }

    pub(crate) fn path_validated(&self) -> bool {
        match *self {
            Self::Client { .. } => true,
            Self::Server { path_validated, .. } => path_validated,
        }
    }

    pub(crate) fn side(&self) -> Side {
        match *self {
            Self::Client { .. } => Side::Client,
            Self::Server { .. } => Side::Server,
        }
    }
}

/// Reasons why a connection might be lost
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConnectionError {
    /// The peer doesn't implement any supported version
    #[error("peer doesn't implement any supported version")]
    VersionMismatch,
    /// The peer violated the QUIC specification as understood by this implementation
    #[error(transparent)]
    TransportError(#[from] TransportError),
    /// The peer's QUIC stack aborted the connection automatically
    #[error("aborted by peer: {0}")]
    ConnectionClosed(frame::ConnectionClose),
    /// The peer closed the connection
    #[error("closed by peer: {0}")]
    ApplicationClosed(frame::ApplicationClose),
    /// The peer is unable to continue processing this connection, usually due to having restarted
    #[error("reset by peer")]
    Reset,
    /// Communication with the peer has lapsed for longer than the negotiated idle timeout
    ///
    /// If neither side is sending keep-alives, a connection will time out after a long enough idle
    /// period even if the peer is still reachable. See also [`TransportConfig::max_idle_timeout()`]
    /// and [`TransportConfig::keep_alive_interval()`].
    #[error("timed out")]
    TimedOut,
    /// The local application closed the connection
    #[error("closed")]
    LocallyClosed,
    /// The connection could not be created because not enough of the CID space is available
    ///
    /// Try using longer connection IDs.
    #[error("CIDs exhausted")]
    CidsExhausted,
}

impl From<Close> for ConnectionError {
    fn from(x: Close) -> Self {
        match x {
            Close::Connection(reason) => Self::ConnectionClosed(reason),
            Close::Application(reason) => Self::ApplicationClosed(reason),
        }
    }
}

// For compatibility with API consumers
impl From<ConnectionError> for io::Error {
    fn from(x: ConnectionError) -> Self {
        use ConnectionError::*;
        let kind = match x {
            TimedOut => io::ErrorKind::TimedOut,
            Reset => io::ErrorKind::ConnectionReset,
            ApplicationClosed(_) | ConnectionClosed(_) => io::ErrorKind::ConnectionAborted,
            TransportError(_) | VersionMismatch | LocallyClosed | CidsExhausted => {
                io::ErrorKind::Other
            }
        };
        Self::new(kind, x)
    }
}

/// Errors that might trigger a path being closed
// TODO(@divma): maybe needs to be reworked based on what we want to do with the public API
#[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
pub enum PathError {
    /// The extension was not negotiated with the peer
    #[error("multipath extension not negotiated")]
    MultipathNotNegotiated,
    /// Paths can only be opened client-side
    #[error("the server side may not open a path")]
    ServerSideNotAllowed,
    /// Current limits do not allow us to open more paths
    #[error("maximum number of concurrent paths reached")]
    MaxPathIdReached,
    /// No remote CIDs available to open a new path
    #[error("remoted CIDs exhausted")]
    RemoteCidsExhausted,
    /// Path could not be validated and will be abandoned
    #[error("path validation failed")]
    ValidationFailed,
    /// The remote address for the path is not supported by the endpoint
    #[error("invalid remote address")]
    InvalidRemoteAddress(SocketAddr),
}

/// Errors triggered when abandoning a path
#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum ClosePathError {
    /// The path is already closed or was never opened
    #[error("closed path")]
    ClosedPath,
    /// This is the last path, which can not be abandoned
    #[error("last open path")]
    LastOpenPath,
}

#[derive(Debug, Error, Clone, Copy)]
#[error("Multipath extension not negotiated")]
pub struct MultipathNotNegotiated {
    _private: (),
}

/// Events of interest to the application
#[derive(Debug)]
pub enum Event {
    /// The connection's handshake data is ready
    HandshakeDataReady,
    /// The connection was successfully established
    Connected,
    /// The TLS handshake was confirmed
    HandshakeConfirmed,
    /// The connection was lost
    ///
    /// Emitted if the peer closes the connection or an error is encountered.
    ConnectionLost {
        /// Reason that the connection was closed
        reason: ConnectionError,
    },
    /// Stream events
    Stream(StreamEvent),
    /// One or more application datagrams have been received
    DatagramReceived,
    /// One or more application datagrams have been sent after blocking
    DatagramsUnblocked,
    /// (Multi)Path events
    Path(PathEvent),
    /// Iroh's nat traversal events
    NatTraversal(iroh_hp::Event),
}

impl From<PathEvent> for Event {
    fn from(source: PathEvent) -> Self {
        Self::Path(source)
    }
}

fn get_max_ack_delay(params: &TransportParameters) -> Duration {
    Duration::from_micros(params.max_ack_delay.0 * 1000)
}

// Prevents overflow and improves behavior in extreme circumstances
const MAX_BACKOFF_EXPONENT: u32 = 16;

/// Minimal remaining size to allow packet coalescing, excluding cryptographic tag
///
/// This must be at least as large as the header for a well-formed empty packet to be coalesced,
/// plus some space for frames. We only care about handshake headers because short header packets
/// necessarily have smaller headers, and initial packets are only ever the first packet in a
/// datagram (because we coalesce in ascending packet space order and the only reason to split a
/// packet is when packet space changes).
const MIN_PACKET_SPACE: usize = MAX_HANDSHAKE_OR_0RTT_HEADER_SIZE + 32;

/// Largest amount of space that could be occupied by a Handshake or 0-RTT packet's header
///
/// Excludes packet-type-specific fields such as packet number or Initial token
// https://www.rfc-editor.org/rfc/rfc9000.html#name-0-rtt: flags + version + dcid len + dcid +
// scid len + scid + length + pn
const MAX_HANDSHAKE_OR_0RTT_HEADER_SIZE: usize =
    1 + 4 + 1 + MAX_CID_SIZE + 1 + MAX_CID_SIZE + VarInt::from_u32(u16::MAX as u32).size() + 4;

/// Perform key updates this many packets before the AEAD confidentiality limit.
///
/// Chosen arbitrarily, intended to be large enough to prevent spurious connection loss.
const KEY_UPDATE_MARGIN: u64 = 10_000;

#[derive(Default)]
struct SentFrames {
    retransmits: ThinRetransmits,
    /// The packet number of the largest acknowledged packet for each path
    largest_acked: FxHashMap<PathId, u64>,
    stream_frames: StreamMetaVec,
    /// Whether the packet contains non-retransmittable frames (like datagrams)
    non_retransmits: bool,
    /// If the datagram containing these frames should be padded to the min MTU
    requires_padding: bool,
}

impl SentFrames {
    /// Returns whether the packet contains only ACKs
    fn is_ack_only(&self, streams: &StreamsState) -> bool {
        !self.largest_acked.is_empty()
            && !self.non_retransmits
            && self.stream_frames.is_empty()
            && self.retransmits.is_empty(streams)
    }
}

/// Compute the negotiated idle timeout based on local and remote max_idle_timeout transport parameters.
///
/// According to the definition of max_idle_timeout, a value of `0` means the timeout is disabled; see <https://www.rfc-editor.org/rfc/rfc9000#section-18.2-4.4.1.>
///
/// According to the negotiation procedure, either the minimum of the timeouts or one specified is used as the negotiated value; see <https://www.rfc-editor.org/rfc/rfc9000#section-10.1-2.>
///
/// Returns the negotiated idle timeout as a `Duration`, or `None` when both endpoints have opted out of idle timeout.
fn negotiate_max_idle_timeout(x: Option<VarInt>, y: Option<VarInt>) -> Option<Duration> {
    match (x, y) {
        (Some(VarInt(0)) | None, Some(VarInt(0)) | None) => None,
        (Some(VarInt(0)) | None, Some(y)) => Some(Duration::from_millis(y.0)),
        (Some(x), Some(VarInt(0)) | None) => Some(Duration::from_millis(x.0)),
        (Some(x), Some(y)) => Some(Duration::from_millis(cmp::min(x, y).0)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiate_max_idle_timeout_commutative() {
        let test_params = [
            (None, None, None),
            (None, Some(VarInt(0)), None),
            (None, Some(VarInt(2)), Some(Duration::from_millis(2))),
            (Some(VarInt(0)), Some(VarInt(0)), None),
            (
                Some(VarInt(2)),
                Some(VarInt(0)),
                Some(Duration::from_millis(2)),
            ),
            (
                Some(VarInt(1)),
                Some(VarInt(4)),
                Some(Duration::from_millis(1)),
            ),
        ];

        for (left, right, result) in test_params {
            assert_eq!(negotiate_max_idle_timeout(left, right), result);
            assert_eq!(negotiate_max_idle_timeout(right, left), result);
        }
    }
}
