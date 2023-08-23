use std::{
    cmp,
    collections::VecDeque,
    convert::TryFrom,
    fmt, io, mem,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::{Bytes, BytesMut};
use frame::StreamMetaVec;
use rand::{rngs::StdRng, Rng, SeedableRng};
use thiserror::Error;
use tracing::{debug, error, trace, trace_span, warn};

use crate::{
    cid_generator::ConnectionIdGenerator,
    cid_queue::CidQueue,
    coding::BufMutExt,
    config::{ServerConfig, TransportConfig},
    crypto::{self, HeaderKey, KeyPair, Keys, PacketKey},
    frame,
    frame::{Close, Datagram, FrameStruct},
    packet::{Header, LongType, Packet, PartialDecode, SpaceId},
    range_set::ArrayRangeSet,
    shared::{
        ConnectionEvent, ConnectionEventInner, ConnectionId, EcnCodepoint, EndpointEvent,
        EndpointEventInner,
    },
    token::ResetToken,
    transport_parameters::TransportParameters,
    Dir, EndpointConfig, Frame, Side, StreamId, Transmit, TransportError, TransportErrorCode,
    VarInt, MAX_STREAM_COUNT, MIN_INITIAL_SIZE, RESET_TOKEN_SIZE, TIMER_GRANULARITY,
};

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
use packet_builder::PacketBuilder;

mod paths;
use paths::PathData;
pub use paths::RttEstimator;

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
//pub(crate) use streams::{ByteSlice, BytesArray};
pub use streams::{
    BytesSource, Chunks, FinishError, ReadError, ReadableError, RecvStream, SendStream,
    StreamEvent, Streams, UnknownStream, WriteError, Written,
};

mod timer;
use crate::congestion::Controller;
use timer::{Timer, TimerTable};

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
    server_config: Option<Arc<ServerConfig>>,
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
    path: PathData,
    prev_path: Option<PathData>,
    state: State,
    side: Side,
    /// Whether or not 0-RTT was enabled during the handshake. Does not imply acceptance.
    zero_rtt_enabled: bool,
    /// Set if 0-RTT is supported, then cleared when no longer needed.
    zero_rtt_crypto: Option<ZeroRttCrypto>,
    key_phase: bool,
    /// Transport parameters set by the peer
    peer_params: TransportParameters,
    /// Source ConnectionId of the first packet received from the peer
    orig_rem_cid: ConnectionId,
    /// Destination ConnectionId sent by the client on the first Initial
    initial_dst_cid: ConnectionId,
    /// The value that the server included in the Source Connection ID field of a Retry packet, if
    /// one was received
    retry_src_cid: Option<ConnectionId>,
    /// Total number of outgoing packets that have been deemed lost
    lost_packets: u64,
    events: VecDeque<Event>,
    endpoint_events: VecDeque<EndpointEventInner>,
    /// Whether the spin bit is in use for this connection
    spin_enabled: bool,
    /// Outgoing spin bit state
    spin: bool,
    /// Packet number spaces: initial, handshake, 1-RTT
    spaces: [PacketSpace; 3],
    /// Highest usable packet number space
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
    idle_timeout: Option<VarInt>,
    timers: TimerTable,
    /// Number of packets received which could not be authenticated
    authentication_failures: u64,
    /// Why the connection was lost, if it has been
    error: Option<ConnectionError>,
    /// Sent in every outgoing Initial packet. Always empty for servers and after Initial keys are
    /// discarded.
    retry_token: Bytes,

    //
    // Queued non-retransmittable 1-RTT data
    //
    path_response: Option<PathResponse>,
    close: bool,

    //
    // Loss Detection
    //
    /// The number of times a PTO has been sent without receiving an ack.
    pto_count: u32,

    //
    // Congestion Control
    //
    /// Summary statistics of packets that have been sent, but not yet acked or deemed lost
    in_flight: InFlight,
    /// Whether the most recently received packet had an ECN codepoint set
    receiving_ecn: bool,
    /// Number of packets authenticated
    total_authed_packets: u64,
    /// Whether the last `poll_transmit` call yielded no data because there was
    /// no outgoing application data.
    app_limited: bool,

    streams: StreamsState,
    /// Surplus remote CIDs for future use on new paths
    rem_cids: CidQueue,
    // Attributes of CIDs generated by local peer
    local_cid_state: CidState,
    /// State of the unreliable datagram extension
    datagrams: DatagramState,
    /// Connection level statistics
    stats: ConnectionStats,
    /// QUIC version used for the connection.
    version: u32,
}

impl Connection {
    pub(crate) fn new(
        endpoint_config: Arc<EndpointConfig>,
        server_config: Option<Arc<ServerConfig>>,
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
    ) -> Self {
        let side = if server_config.is_some() {
            Side::Server
        } else {
            Side::Client
        };
        let initial_space = PacketSpace {
            crypto: Some(crypto.initial_keys(&init_cid, side)),
            ..PacketSpace::new(now)
        };
        let state = State::Handshake(state::Handshake {
            rem_cid_set: side.is_server(),
            expected_token: Bytes::new(),
            client_hello: None,
        });
        let mut rng = StdRng::from_entropy();
        let path_validated = server_config.as_ref().map_or(true, |c| c.use_retry);
        let mut this = Self {
            endpoint_config,
            server_config,
            crypto,
            handshake_cid: loc_cid,
            rem_handshake_cid: rem_cid,
            local_cid_state: CidState::new(cid_gen.cid_len(), cid_gen.cid_lifetime(), now),
            path: PathData::new(
                remote,
                config.initial_rtt,
                config
                    .congestion_controller_factory
                    .build(now, config.get_initial_mtu()),
                config.get_initial_mtu(),
                config.min_mtu,
                None,
                match allow_mtud {
                    true => config.mtu_discovery_config.clone(),
                    false => None,
                },
                now,
                path_validated,
            ),
            local_ip,
            prev_path: None,
            side,
            state,
            zero_rtt_enabled: false,
            zero_rtt_crypto: None,
            key_phase: false,
            peer_params: TransportParameters::default(),
            orig_rem_cid: rem_cid,
            initial_dst_cid: init_cid,
            retry_src_cid: None,
            lost_packets: 0,
            events: VecDeque::new(),
            endpoint_events: VecDeque::new(),
            spin_enabled: config.allow_spin && rng.gen_ratio(7, 8),
            spin: false,
            spaces: [initial_space, PacketSpace::new(now), PacketSpace::new(now)],
            highest_space: SpaceId::Initial,
            prev_crypto: None,
            next_crypto: None,
            accepted_0rtt: false,
            permit_idle_reset: true,
            idle_timeout: config.max_idle_timeout,
            timers: TimerTable::default(),
            authentication_failures: 0,
            error: None,
            retry_token: Bytes::new(),

            path_response: None,
            close: false,

            pto_count: 0,

            app_limited: false,
            in_flight: InFlight::new(),
            receiving_ecn: false,
            total_authed_packets: 0,

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
            rem_cids: CidQueue::new(rem_cid),
            rng,
            stats: ConnectionStats::default(),
            version,
        };
        if side.is_client() {
            // Kick off the connection
            this.write_crypto();
            this.init_0rtt();
        }
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
        self.timers.next_timeout()
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

        if let Some(err) = self.error.take() {
            return Some(Event::ConnectionLost { reason: err });
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
        assert!(id.dir() == Dir::Bi || id.initiator() != self.side);
        RecvStream {
            id,
            state: &mut self.streams,
            pending: &mut self.spaces[SpaceId::Data].pending,
        }
    }

    /// Provide control over streams
    #[must_use]
    pub fn send_stream(&mut self, id: StreamId) -> SendStream<'_> {
        assert!(id.dir() == Dir::Bi || id.initiator() == self.side);
        SendStream {
            id,
            state: &mut self.streams,
            pending: &mut self.spaces[SpaceId::Data].pending,
            conn_state: &self.state,
        }
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
    pub fn poll_transmit(&mut self, now: Instant, max_datagrams: usize) -> Option<Transmit> {
        assert!(max_datagrams != 0);
        let max_datagrams = match self.config.enable_segmentation_offload {
            false => 1,
            true => max_datagrams.min(MAX_TRANSMIT_SEGMENTS),
        };

        let mut num_datagrams = 0;

        // Send PATH_CHALLENGE for a previous path if necessary
        if let Some(ref mut prev_path) = self.prev_path {
            if prev_path.challenge_pending {
                prev_path.challenge_pending = false;
                let token = prev_path
                    .challenge
                    .expect("previous path challenge pending without token");
                let destination = prev_path.remote;
                debug_assert_eq!(
                    self.highest_space,
                    SpaceId::Data,
                    "PATH_CHALLENGE queued without 1-RTT keys"
                );
                let mut buf = BytesMut::with_capacity(self.path.current_mtu() as usize);
                let buf_capacity = self.path.current_mtu() as usize;

                let mut builder = PacketBuilder::new(
                    now,
                    SpaceId::Data,
                    &mut buf,
                    buf_capacity,
                    0,
                    false,
                    self,
                    self.version,
                )?;
                trace!("validating previous path with PATH_CHALLENGE {:08x}", token);
                buf.write(frame::Type::PATH_CHALLENGE);
                buf.write(token);
                self.stats.frame_tx.path_challenge += 1;

                // An endpoint MUST expand datagrams that contain a PATH_CHALLENGE frame
                // to at least the smallest allowed maximum datagram size of 1200 bytes,
                // unless the anti-amplification limit for the path does not permit
                // sending a datagram of this size
                builder.pad_to(MIN_INITIAL_SIZE);

                builder.finish(self, &mut buf);
                self.stats.udp_tx.datagrams += 1;
                self.stats.udp_tx.transmits += 1;
                self.stats.udp_tx.bytes += buf.len() as u64;
                return Some(Transmit {
                    destination,
                    contents: buf.freeze(),
                    ecn: None,
                    segment_size: None,
                    src_ip: self.local_ip,
                });
            }
        }

        // If we need to send a probe, make sure we have something to send.
        for space in SpaceId::iter() {
            self.spaces[space].maybe_queue_probe(&self.streams);
        }

        // Check whether we need to send a close message
        let close = match self.state {
            State::Drained => {
                self.app_limited = true;
                return None;
            }
            State::Draining | State::Closed(_) => {
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

        let mut buf = BytesMut::new();
        // Reserving capacity can provide more capacity than we asked for.
        // However we are not allowed to write more than MTU size. Therefore
        // the maximum capacity is tracked separately.
        let mut buf_capacity = 0;

        let mut coalesce = true;
        let mut builder: Option<PacketBuilder> = None;
        let mut sent_frames = None;
        let mut pad_datagram = false;
        let mut congestion_blocked = false;

        // Iterate over all spaces and find data to send
        let mut space_idx = 0;
        let spaces = [SpaceId::Initial, SpaceId::Handshake, SpaceId::Data];
        // This loop will potentially spend multiple iterations in the same `SpaceId`,
        // so we cannot trivially rewrite it to take advantage of `SpaceId::iter()`.
        while space_idx < spaces.len() {
            let space_id = spaces[space_idx];

            if close && space_id != self.highest_space {
                // We ignore data in this space, since the close message
                // has higher priority
                space_idx += 1;
                continue;
            }

            // Is there data or a close message to send in this space?
            let can_send = self.space_can_send(space_id);
            if can_send.is_empty() && !close {
                space_idx += 1;
                continue;
            }

            let mut ack_eliciting = !self.spaces[space_id].pending.is_empty(&self.streams)
                || self.spaces[space_id].ping_pending;
            if space_id == SpaceId::Data {
                ack_eliciting |= self.can_send_1rtt();
            }

            // Can we append more data into the current buffer?
            // It is not safe to assume that `buf.len()` is the end of the data,
            // since the last packet might not have been finished.
            let buf_end = if let Some(builder) = &builder {
                buf.len().max(builder.min_size) + builder.tag_len
            } else {
                buf.len()
            };

            if !coalesce || buf_capacity - buf_end < MIN_PACKET_SPACE {
                // We need to send 1 more datagram and extend the buffer for that.

                // Is 1 more datagram allowed?
                if buf_capacity >= self.path.current_mtu() as usize * max_datagrams {
                    // No more datagrams allowed
                    break;
                }

                // Anti-amplification is only based on `total_sent`, which gets
                // updated at the end of this method. Therefore we pass the amount
                // of bytes for datagrams that are already created, as well as 1 byte
                // for starting another datagram. If there is any anti-amplification
                // budget left, we always allow a full MTU to be sent
                // (see https://github.com/quinn-rs/quinn/issues/1082)
                if self.path.anti_amplification_blocked(
                    self.path.current_mtu() as u64 * num_datagrams as u64 + 1,
                ) {
                    trace!("blocked by anti-amplification");
                    break;
                }

                // Congestion control and pacing checks
                // Tail loss probes must not be blocked by congestion, or a deadlock could arise
                if ack_eliciting && self.spaces[space_id].loss_probes == 0 {
                    // Assume the current packet will get padded to fill the full MTU
                    let untracked_bytes = if let Some(builder) = &builder {
                        buf_capacity - builder.partial_encode.start
                    } else {
                        0
                    } as u64;
                    debug_assert!(untracked_bytes <= self.path.current_mtu() as u64);

                    let bytes_to_send = u64::from(self.path.current_mtu()) + untracked_bytes;
                    if self.in_flight.bytes + bytes_to_send >= self.path.congestion.window() {
                        space_idx += 1;
                        congestion_blocked = true;
                        // We continue instead of breaking here in order to avoid
                        // blocking loss probes queued for higher spaces.
                        continue;
                    }

                    // Check whether the next datagram is blocked by pacing
                    let smoothed_rtt = self.path.rtt.get();
                    if let Some(delay) = self.path.pacing.delay(
                        smoothed_rtt,
                        bytes_to_send,
                        self.path.current_mtu(),
                        self.path.congestion.window(),
                        now,
                    ) {
                        self.timers.set(Timer::Pacing, delay);
                        congestion_blocked = true;
                        // Loss probes should be subject to pacing, even though
                        // they are not congestion controlled.
                        break;
                    }
                }

                // Finish current packet
                if let Some(mut builder) = builder.take() {
                    // Pad the packet to make it suitable for sending with GSO
                    // which will always send the maximum PDU.
                    builder.pad_to(self.path.current_mtu());

                    builder.finish_and_track(now, self, sent_frames.take(), &mut buf);

                    debug_assert_eq!(buf.len(), buf_capacity, "Packet must be padded");
                }

                // Allocate space for another datagram
                buf_capacity += self.path.current_mtu() as usize;
                if buf.capacity() < buf_capacity {
                    // We reserve the maximum space for sending `max_datagrams` upfront
                    // to avoid any reallocations if more datagrams have to be appended later on.
                    // Benchmarks have shown shown a 5-10% throughput improvement
                    // compared to continuously resizing the datagram buffer.
                    // While this will lead to over-allocation for small transmits
                    // (e.g. purely containing ACKs), modern memory allocators
                    // (e.g. mimalloc and jemalloc) will pool certain allocation sizes
                    // and therefore this is still rather efficient.
                    buf.reserve(max_datagrams * self.path.current_mtu() as usize - buf.capacity());
                }
                num_datagrams += 1;
                coalesce = true;
                pad_datagram = false;
            } else {
                // We can append/coalesce the next packet into the current
                // datagram.
                // Finish current packet without adding extra padding
                if let Some(builder) = builder.take() {
                    builder.finish_and_track(now, self, sent_frames.take(), &mut buf);
                }
            }

            debug_assert!(buf_capacity - buf.len() >= MIN_PACKET_SPACE);

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

            debug_assert!(
                builder.is_none() && sent_frames.is_none(),
                "Previous packet must have been finished"
            );

            // This should really be `builder.insert()`, but `Option::insert`
            // is not stable yet. Since we `debug_assert!(builder.is_none())` it
            // doesn't make any functional difference.
            let builder = builder.get_or_insert(PacketBuilder::new(
                now,
                space_id,
                &mut buf,
                buf_capacity,
                (num_datagrams - 1) * (self.path.current_mtu() as usize),
                ack_eliciting,
                self,
                self.version,
            )?);
            coalesce = coalesce && !builder.short_header;

            // https://tools.ietf.org/html/draft-ietf-quic-transport-34#section-14.1
            pad_datagram |=
                space_id == SpaceId::Initial && (self.side.is_client() || ack_eliciting);

            if close {
                trace!("sending CONNECTION_CLOSE");
                // Encode ACKs before the ConnectionClose message, to give the receiver
                // a better approximate on what data has been processed. This is
                // especially important with ack delay, since the peer might not
                // have gotten any other ACK for the data earlier on.
                if !self.spaces[space_id].pending_acks.ranges().is_empty() {
                    Self::populate_acks(
                        self.receiving_ecn,
                        &mut SentFrames::default(),
                        &mut self.spaces[space_id],
                        &mut buf,
                        &mut self.stats,
                    );
                }

                // Since there only 64 ACK frames there will always be enough space
                // to encode the ConnectionClose frame too. However we still have the
                // check here to prevent crashes if something changes.
                debug_assert!(
                    buf.len() + frame::ConnectionClose::SIZE_BOUND < builder.max_size,
                    "ACKs should leave space for ConnectionClose"
                );
                if buf.len() + frame::ConnectionClose::SIZE_BOUND < builder.max_size {
                    match self.state {
                        State::Closed(state::Closed { ref reason }) => {
                            if space_id == SpaceId::Data {
                                reason.encode(&mut buf, builder.max_size)
                            } else {
                                frame::ConnectionClose {
                                    error_code: TransportErrorCode::APPLICATION_ERROR,
                                    frame_type: None,
                                    reason: Bytes::new(),
                                }
                                .encode(&mut buf, builder.max_size)
                            }
                        }
                        State::Draining => frame::ConnectionClose {
                            error_code: TransportErrorCode::NO_ERROR,
                            frame_type: None,
                            reason: Bytes::new(),
                        }
                        .encode(&mut buf, builder.max_size),
                        _ => unreachable!(
                            "tried to make a close packet when the connection wasn't closed"
                        ),
                    }
                }
                // Don't send another close packet
                self.close = false;
                // `CONNECTION_CLOSE` is the final packet
                break;
            }

            let sent = self.populate_packet(space_id, &mut buf, buf_capacity - builder.tag_len);

            // ACK-only packets should only be sent when explicitly allowed. If we write them due
            // to any other reason, there is a bug which leads to one component announcing write
            // readiness while not writing any data. This degrades performance. The condition is
            // only checked if the full MTU is available, so that lack of space in the datagram isn't
            // the reason for just writing ACKs.
            debug_assert!(
                !(sent.is_ack_only(&self.streams)
                    && !can_send.acks
                    && can_send.other
                    && (buf_capacity - builder.datagram_start) == self.path.current_mtu() as usize),
                "SendableFrames was {can_send:?}, but only ACKs have been written"
            );
            pad_datagram |= sent.requires_padding;

            if sent.largest_acked.is_some() {
                self.spaces[space_id].pending_acks.acks_sent();
            }

            // Keep information about the packet around until it gets finalized
            sent_frames = Some(sent);

            // Don't increment space_idx.
            // We stay in the current space and check if there is more data to send.
        }

        // Finish the last packet
        if let Some(mut builder) = builder {
            if pad_datagram {
                builder.pad_to(MIN_INITIAL_SIZE);
            }
            let last_packet_number = builder.exact_number;
            builder.finish_and_track(now, self, sent_frames, &mut buf);
            self.path
                .congestion
                .on_sent(now, buf.len() as u64, last_packet_number);
        }

        self.app_limited = buf.is_empty() && !congestion_blocked;

        // Send MTU probe if necessary
        if buf.is_empty() && self.state.is_established() {
            let space_id = SpaceId::Data;
            let probe_size = match self
                .path
                .mtud
                .poll_transmit(now, self.spaces[space_id].next_packet_number)
            {
                Some(next_probe_size) => next_probe_size,
                None => return None,
            };

            let buf_capacity = probe_size as usize;
            buf.reserve(buf_capacity);

            let mut builder = PacketBuilder::new(
                now,
                space_id,
                &mut buf,
                buf_capacity,
                0,
                true,
                self,
                self.version,
            )?;

            // We implement MTU probes as ping packets padded up to the probe size
            buf.write(frame::Type::PING);
            builder.pad_to(probe_size);
            let sent_frames = SentFrames {
                non_retransmits: true,
                ..Default::default()
            };
            builder.finish_and_track(now, self, Some(sent_frames), &mut buf);

            self.stats.frame_tx.ping += 1;
            self.stats.path.sent_plpmtud_probes += 1;
            num_datagrams = 1;

            trace!(?probe_size, "writing MTUD probe");
        }

        if buf.is_empty() {
            return None;
        }

        trace!("sending {} bytes in {} datagrams", buf.len(), num_datagrams);
        self.path.total_sent = self.path.total_sent.saturating_add(buf.len() as u64);

        self.stats.udp_tx.datagrams += num_datagrams as u64;
        self.stats.udp_tx.bytes += buf.len() as u64;
        self.stats.udp_tx.transmits += 1;

        Some(Transmit {
            destination: self.path.remote,
            contents: buf.freeze(),
            ecn: if self.path.sending_ecn {
                Some(EcnCodepoint::Ect0)
            } else {
                None
            },
            segment_size: match num_datagrams {
                1 => None,
                _ => Some(self.path.current_mtu() as usize),
            },
            src_ip: self.local_ip,
        })
    }

    /// Indicate what types of frames are ready to send for the given space
    fn space_can_send(&self, space_id: SpaceId) -> SendableFrames {
        if self.spaces[space_id].crypto.is_some() {
            let can_send = self.spaces[space_id].can_send(&self.streams);
            if !can_send.is_empty() {
                return can_send;
            }
        }

        if space_id != SpaceId::Data {
            return SendableFrames::empty();
        }

        if self.spaces[space_id].crypto.is_some() && self.can_send_1rtt() {
            return SendableFrames {
                other: true,
                acks: false,
            };
        }

        if self.zero_rtt_crypto.is_some() && self.side.is_client() {
            let mut can_send = self.spaces[space_id].can_send(&self.streams);
            can_send.other |= self.can_send_1rtt();
            if !can_send.is_empty() {
                return can_send;
            }
        }

        SendableFrames::empty()
    }

    /// Process `ConnectionEvent`s generated by the associated `Endpoint`
    ///
    /// Will execute protocol logic upon receipt of a connection event, in turn preparing signals
    /// (including application `Event`s, `EndpointEvent`s and outgoing datagrams) that should be
    /// extracted through the relevant methods.
    pub fn handle_event(&mut self, event: ConnectionEvent) {
        use self::ConnectionEventInner::*;
        match event.0 {
            Datagram {
                now,
                remote,
                ecn,
                first_decode,
                remaining,
            } => {
                // If this packet could initiate a migration and we're a client or a server that
                // forbids migration, drop the datagram. This could be relaxed to heuristically
                // permit NAT-rebinding-like migration.
                if remote != self.path.remote
                    && self.server_config.as_ref().map_or(true, |x| !x.migration)
                {
                    trace!("discarding packet from unrecognized peer {}", remote);
                    return;
                }

                let was_anti_amplification_blocked = self.path.anti_amplification_blocked(1);

                self.stats.udp_rx.datagrams += 1;
                self.stats.udp_rx.bytes += first_decode.len() as u64;
                let data_len = first_decode.len();

                self.handle_decode(now, remote, ecn, first_decode);
                // The current `path` might have changed inside `handle_decode`,
                // since the packet could have triggered a migration. Make sure
                // the data received is accounted for the most recent path by accessing
                // `path` after `handle_decode`.
                self.path.total_recvd = self.path.total_recvd.saturating_add(data_len as u64);

                if let Some(data) = remaining {
                    self.stats.udp_rx.bytes += data.len() as u64;
                    self.handle_coalesced(now, remote, ecn, data);
                }

                if was_anti_amplification_blocked {
                    // A prior attempt to set the loss detection timer may have failed due to
                    // anti-amplification, so ensure it's set now. Prevents a handshake deadlock if
                    // the server's first flight is lost.
                    self.set_loss_detection_timer(now);
                }
            }
            NewIdentifiers(ids, now) => {
                self.local_cid_state.new_cids(&ids, now);
                ids.into_iter().rev().for_each(|frame| {
                    self.spaces[SpaceId::Data].pending.new_cids.push(frame);
                });
                // Update Timer::PushNewCid
                if self
                    .timers
                    .get(Timer::PushNewCid)
                    .map_or(true, |x| x <= now)
                {
                    self.reset_cid_retirement();
                }
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
        for &timer in &Timer::VALUES {
            if !self.timers.is_expired(timer, now) {
                continue;
            }
            self.timers.stop(timer);
            trace!(timer = ?timer, "timeout");
            match timer {
                Timer::Close => {
                    self.state = State::Drained;
                    self.endpoint_events.push_back(EndpointEventInner::Drained);
                }
                Timer::Idle => {
                    self.kill(ConnectionError::TimedOut);
                }
                Timer::KeepAlive => {
                    trace!("sending keep-alive");
                    self.ping();
                }
                Timer::LossDetection => {
                    self.on_loss_detection_timeout(now);
                }
                Timer::KeyDiscard => {
                    self.zero_rtt_crypto = None;
                    self.prev_crypto = None;
                }
                Timer::PathValidation => {
                    debug!("path validation failed");
                    if let Some(prev) = self.prev_path.take() {
                        self.path = prev;
                    }
                    self.path.challenge = None;
                    self.path.challenge_pending = false;
                }
                Timer::Pacing => trace!("pacing timer expired"),
                Timer::PushNewCid => {
                    // Update `retire_prior_to` field in NEW_CONNECTION_ID frame
                    let num_new_cid = self.local_cid_state.on_cid_timeout().into();
                    if !self.state.is_closed() {
                        trace!(
                            "push a new cid to peer RETIRE_PRIOR_TO field {}",
                            self.local_cid_state.retire_prior_to()
                        );
                        self.endpoint_events
                            .push_back(EndpointEventInner::NeedIdentifiers(now, num_new_cid));
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
            self.state = State::Closed(state::Closed { reason });
        }
    }

    /// Control datagrams
    pub fn datagrams(&mut self) -> Datagrams<'_> {
        Datagrams { conn: self }
    }

    /// Returns connection statistics
    pub fn stats(&self) -> ConnectionStats {
        let mut stats = self.stats;
        stats.path.rtt = self.path.rtt.get();
        stats.path.cwnd = self.path.congestion.window();

        stats
    }

    /// Ping the remote endpoint
    ///
    /// Causes an ACK-eliciting packet to be transmitted.
    pub fn ping(&mut self) {
        self.spaces[self.highest_space].ping_pending = true;
    }

    #[doc(hidden)]
    pub fn initiate_key_update(&mut self) {
        self.update_keys(None, false);
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
        self.side
    }

    /// The latest socket address for this connection's peer
    pub fn remote_address(&self) -> SocketAddr {
        self.path.remote
    }

    /// The local IP address which was used when the peer established
    /// the connection
    ///
    /// This can be different from the address the endpoint is bound to, in case
    /// the endpoint is bound to a wildcard address like `0.0.0.0` or `::`.
    ///
    /// This will return `None` for clients.
    ///
    /// Retrieving the local IP address is currently supported on the following
    /// platforms:
    /// - Linux
    ///
    /// On all non-supported platforms the local IP address will not be available,
    /// and the method will return `None`.
    pub fn local_ip(&self) -> Option<IpAddr> {
        self.local_ip
    }

    /// Current best estimate of this connection's latency (round-trip-time)
    pub fn rtt(&self) -> Duration {
        self.path.rtt.get()
    }

    /// Current state of this connection's congestion controller, for debugging purposes
    pub fn congestion_state(&self) -> &dyn Controller {
        self.path.congestion.as_ref()
    }

    /// Modify the number of remotely initiated streams that may be concurrently open
    ///
    /// No streams may be opened by the peer unless fewer than `count` are already open. Large
    /// `count`s increase both minimum and worst-case memory consumption.
    pub fn set_max_concurrent_streams(&mut self, dir: Dir, count: VarInt) {
        self.streams.set_max_concurrent(dir, count);
    }

    /// Current number of remotely initiated streams that may be concurrently open
    ///
    /// If the target for this limit is reduced using [`set_max_concurrent_streams`](Self::set_max_concurrent_streams),
    /// it will not change immediately, even if fewer streams are open. Instead, it will
    /// decrement by one for each time a remotely initiated stream of matching directionality is closed.
    pub fn max_concurrent_streams(&self, dir: Dir) -> u64 {
        self.streams.max_concurrent(dir)
    }

    /// See [`TransportConfig::receive_window()`]
    pub fn set_receive_window(&mut self, receive_window: VarInt) {
        if self.streams.set_receive_window(receive_window) {
            self.spaces[SpaceId::Data].pending.max_data = true;
        }
    }

    fn on_ack_received(
        &mut self,
        now: Instant,
        space: SpaceId,
        ack: frame::Ack,
    ) -> Result<(), TransportError> {
        if ack.largest >= self.spaces[space].next_packet_number {
            return Err(TransportError::PROTOCOL_VIOLATION("unsent packet acked"));
        }
        let new_largest = {
            let space = &mut self.spaces[space];
            if space
                .largest_acked_packet
                .map_or(true, |pn| ack.largest > pn)
            {
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

        // Avoid DoS from unreasonably huge ack ranges by filtering out just the new acks.
        let mut newly_acked = ArrayRangeSet::new();
        for range in ack.iter() {
            for (&pn, _) in self.spaces[space].sent_packets.range(range) {
                newly_acked.insert_one(pn);
            }
        }

        if newly_acked.is_empty() {
            return Ok(());
        }

        let mut ack_eliciting_acked = false;
        for packet in newly_acked.elts() {
            if let Some(info) = self.spaces[space].sent_packets.remove(&packet) {
                if let Some(acked) = info.largest_acked {
                    // Assume ACKs for all packets below the largest acknowledged in `packet` have
                    // been received. This can cause the peer to spuriously retransmit if some of
                    // our earlier ACKs were lost, but allows for simpler state tracking. See
                    // discussion at
                    // https://www.rfc-editor.org/rfc/rfc9000.html#name-limiting-ranges-by-tracking
                    self.spaces[space].pending_acks.subtract_below(acked);
                }
                ack_eliciting_acked |= info.ack_eliciting;

                // Notify MTU discovery that a packet was acked, because it might be an MTU probe
                let mtu_updated = self.path.mtud.on_acked(space, packet, info.size);
                if mtu_updated {
                    self.path
                        .congestion
                        .on_mtu_update(self.path.mtud.current_mtu());
                }

                self.on_packet_acked(now, space, info);
            }
        }

        self.path.congestion.on_end_acks(
            now,
            self.in_flight.bytes,
            self.app_limited,
            self.spaces[space].largest_acked_packet,
        );

        if new_largest && ack_eliciting_acked {
            let ack_delay = if space != SpaceId::Data {
                Duration::from_micros(0)
            } else {
                cmp::min(
                    self.max_ack_delay(),
                    Duration::from_micros(ack.delay << self.peer_params.ack_delay_exponent.0),
                )
            };
            let rtt = instant_saturating_sub(now, self.spaces[space].largest_acked_packet_sent);
            self.path.rtt.update(ack_delay, rtt);
            if self.path.first_packet_after_rtt_sample.is_none() {
                self.path.first_packet_after_rtt_sample =
                    Some((space, self.spaces[space].next_packet_number));
            }
        }

        // Must be called before crypto/pto_count are clobbered
        self.detect_lost_packets(now, space, true);

        if self.peer_completed_address_validation() {
            self.pto_count = 0;
        }

        // Explicit congestion notification
        if self.path.sending_ecn {
            if let Some(ecn) = ack.ecn {
                // We only examine ECN counters from ACKs that we are certain we received in transmit
                // order, allowing us to compute an increase in ECN counts to compare against the number
                // of newly acked packets that remains well-defined in the presence of arbitrary packet
                // reordering.
                if new_largest {
                    let sent = self.spaces[space].largest_acked_packet_sent;
                    self.process_ecn(now, space, newly_acked.len() as u64, ecn, sent);
                }
            } else {
                // We always start out sending ECN, so any ack that doesn't acknowledge it disables it.
                debug!("ECN not acknowledged by peer");
                self.path.sending_ecn = false;
            }
        }

        self.set_loss_detection_timer(now);
        Ok(())
    }

    /// Process a new ECN block from an in-order ACK
    fn process_ecn(
        &mut self,
        now: Instant,
        space: SpaceId,
        newly_acked: u64,
        ecn: frame::EcnCounts,
        largest_sent_time: Instant,
    ) {
        match self.spaces[space].detect_ecn(newly_acked, ecn) {
            Err(e) => {
                debug!("halting ECN due to verification failure: {}", e);
                self.path.sending_ecn = false;
                // Wipe out the existing value because it might be garbage and could interfere with
                // future attempts to use ECN on new paths.
                self.spaces[space].ecn_feedback = frame::EcnCounts::ZERO;
            }
            Ok(false) => {}
            Ok(true) => {
                self.stats.path.congestion_events += 1;
                self.path
                    .congestion
                    .on_congestion_event(now, largest_sent_time, false, 0);
            }
        }
    }

    // Not timing-aware, so it's safe to call this for inferred acks, such as arise from
    // high-latency handshakes
    fn on_packet_acked(&mut self, now: Instant, space: SpaceId, info: SentPacket) {
        self.remove_in_flight(space, &info);
        if info.ack_eliciting && self.path.challenge.is_none() {
            // Only pass ACKs to the congestion controller if we are not validating the current
            // path, so as to ignore any ACKs from older paths still coming in.
            self.path.congestion.on_ack(
                now,
                info.time_sent,
                info.size.into(),
                self.app_limited,
                &self.path.rtt,
            );
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
        self.timers
            .set(Timer::KeyDiscard, start + self.pto(space) * 3);
    }

    fn on_loss_detection_timeout(&mut self, now: Instant) {
        if let Some((_, pn_space)) = self.loss_time_and_space() {
            // Time threshold loss Detection
            self.detect_lost_packets(now, pn_space, false);
            self.set_loss_detection_timer(now);
            return;
        }

        let (_, space) = match self.pto_time_and_space(now) {
            Some(x) => x,
            None => {
                error!("PTO expired while unset");
                return;
            }
        };
        trace!(
            in_flight = self.in_flight.bytes,
            count = self.pto_count,
            ?space,
            "PTO fired"
        );

        let count = match self.in_flight.ack_eliciting {
            // A PTO when we're not expecting any ACKs must be due to handshake anti-amplification
            // deadlock preventions
            0 => {
                debug_assert!(!self.peer_completed_address_validation());
                1
            }
            // Conventional loss probe
            _ => 2,
        };
        self.spaces[space].loss_probes = self.spaces[space].loss_probes.saturating_add(count);
        self.pto_count = self.pto_count.saturating_add(1);
        self.set_loss_detection_timer(now);
    }

    fn detect_lost_packets(&mut self, now: Instant, pn_space: SpaceId, due_to_ack: bool) {
        let mut lost_packets = Vec::<u64>::new();
        let mut lost_mtu_probe = None;
        let in_flight_mtu_probe = self.path.mtud.in_flight_mtu_probe();
        let rtt = self.path.rtt.conservative();
        let loss_delay = cmp::max(rtt.mul_f32(self.config.time_threshold), TIMER_GRANULARITY);

        // Packets sent before this time are deemed lost.
        let lost_send_time = now.checked_sub(loss_delay).unwrap();
        let largest_acked_packet = self.spaces[pn_space].largest_acked_packet.unwrap();
        let packet_threshold = self.config.packet_threshold as u64;
        let mut size_of_lost_packets = 0u64;

        // InPersistentCongestion: Determine if all packets in the time period before the newest
        // lost packet, including the edges, are marked lost. PTO computation must always
        // include max ACK delay, i.e. operate as if in Data space (see RFC9001 §7.6.1).
        let congestion_period =
            self.pto(SpaceId::Data) * self.config.persistent_congestion_threshold;
        let mut persistent_congestion_start: Option<Instant> = None;
        let mut prev_packet = None;
        let mut in_persistent_congestion = false;

        let space = &mut self.spaces[pn_space];
        space.loss_time = None;

        for (&packet, info) in space.sent_packets.range(0..largest_acked_packet) {
            if prev_packet != Some(packet.wrapping_sub(1)) {
                // An intervening packet was acknowledged
                persistent_congestion_start = None;
            }

            if info.time_sent <= lost_send_time || largest_acked_packet >= packet + packet_threshold
            {
                if Some(packet) == in_flight_mtu_probe {
                    // Lost MTU probes are not included in `lost_packets`, because they should not
                    // trigger a congestion control response
                    lost_mtu_probe = in_flight_mtu_probe;
                } else {
                    lost_packets.push(packet);
                    size_of_lost_packets += info.size as u64;
                    if info.ack_eliciting && due_to_ack {
                        match persistent_congestion_start {
                            // Two ACK-eliciting packets lost more than congestion_period apart, with no
                            // ACKed packets in between
                            Some(start) if info.time_sent - start > congestion_period => {
                                in_persistent_congestion = true;
                            }
                            // Persistent congestion must start after the first RTT sample
                            None if self
                                .path
                                .first_packet_after_rtt_sample
                                .map_or(false, |x| x < (pn_space, packet)) =>
                            {
                                persistent_congestion_start = Some(info.time_sent);
                            }
                            _ => {}
                        }
                    }
                }
            } else {
                let next_loss_time = info.time_sent + loss_delay;
                space.loss_time = Some(
                    space
                        .loss_time
                        .map_or(next_loss_time, |x| cmp::min(x, next_loss_time)),
                );
                persistent_congestion_start = None;
            }

            prev_packet = Some(packet);
        }

        // OnPacketsLost
        if let Some(largest_lost) = lost_packets.last().cloned() {
            let old_bytes_in_flight = self.in_flight.bytes;
            let largest_lost_sent = self.spaces[pn_space].sent_packets[&largest_lost].time_sent;
            self.lost_packets += lost_packets.len() as u64;
            self.stats.path.lost_packets += lost_packets.len() as u64;
            self.stats.path.lost_bytes += size_of_lost_packets;
            trace!(
                "packets lost: {:?}, bytes lost: {}",
                lost_packets,
                size_of_lost_packets
            );

            for packet in &lost_packets {
                let info = self.spaces[pn_space].sent_packets.remove(packet).unwrap(); // safe: lost_packets is populated just above
                self.remove_in_flight(pn_space, &info);
                for frame in info.stream_frames {
                    self.streams.retransmit(frame);
                }
                self.spaces[pn_space].pending |= info.retransmits;
                self.path.mtud.on_non_probe_lost(*packet, info.size);
            }

            if self.path.mtud.black_hole_detected(now) {
                self.stats.path.black_holes_detected += 1;
            }

            // Don't apply congestion penalty for lost ack-only packets
            let lost_ack_eliciting = old_bytes_in_flight != self.in_flight.bytes;

            if lost_ack_eliciting {
                self.stats.path.congestion_events += 1;
                self.path.congestion.on_congestion_event(
                    now,
                    largest_lost_sent,
                    in_persistent_congestion,
                    size_of_lost_packets,
                );
            }
        }

        // Handle a lost MTU probe
        if let Some(packet) = lost_mtu_probe {
            let info = self.spaces[SpaceId::Data]
                .sent_packets
                .remove(&packet)
                .unwrap(); // safe: lost_mtu_probe is omitted from lost_packets, and therefore must not have been removed yet
            self.remove_in_flight(SpaceId::Data, &info);
            self.path.mtud.on_probe_lost();
            self.stats.path.lost_plpmtud_probes += 1;
        }
    }

    fn loss_time_and_space(&self) -> Option<(Instant, SpaceId)> {
        SpaceId::iter()
            .filter_map(|id| Some((self.spaces[id].loss_time?, id)))
            .min_by_key(|&(time, _)| time)
    }

    fn pto_time_and_space(&self, now: Instant) -> Option<(Instant, SpaceId)> {
        let backoff = 2u32.pow(self.pto_count.min(MAX_BACKOFF_EXPONENT));
        let mut duration = self.path.rtt.pto_base() * backoff;

        if self.in_flight.ack_eliciting == 0 {
            debug_assert!(!self.peer_completed_address_validation());
            let space = match self.highest_space {
                SpaceId::Handshake => SpaceId::Handshake,
                _ => SpaceId::Initial,
            };
            return Some((now + duration, space));
        }

        let mut result = None;
        for space in SpaceId::iter() {
            if self.spaces[space].in_flight == 0 {
                continue;
            }
            if space == SpaceId::Data {
                // Skip ApplicationData until handshake completes.
                if self.is_handshaking() {
                    return result;
                }
                // Include max_ack_delay and backoff for ApplicationData.
                duration += self.max_ack_delay() * backoff;
            }
            let last_ack_eliciting = match self.spaces[space].time_of_last_ack_eliciting_packet {
                Some(time) => time,
                None => continue,
            };
            let pto = last_ack_eliciting + duration;
            if result.map_or(true, |(earliest_pto, _)| pto < earliest_pto) {
                result = Some((pto, space));
            }
        }
        result
    }

    #[allow(clippy::suspicious_operation_groupings)]
    fn peer_completed_address_validation(&self) -> bool {
        if self.side.is_server() || self.state.is_closed() {
            return true;
        }
        // The server is guaranteed to have validated our address if any of our handshake or 1-RTT
        // packets are acknowledged or we've seen HANDSHAKE_DONE and discarded handshake keys.
        self.spaces[SpaceId::Handshake]
            .largest_acked_packet
            .is_some()
            || self.spaces[SpaceId::Data].largest_acked_packet.is_some()
            || (self.spaces[SpaceId::Data].crypto.is_some()
                && self.spaces[SpaceId::Handshake].crypto.is_none())
    }

    fn set_loss_detection_timer(&mut self, now: Instant) {
        if let Some((loss_time, _)) = self.loss_time_and_space() {
            // Time threshold loss detection.
            self.timers.set(Timer::LossDetection, loss_time);
            return;
        }

        if self.path.anti_amplification_blocked(1) {
            // We wouldn't be able to send anything, so don't bother.
            self.timers.stop(Timer::LossDetection);
            return;
        }

        if self.in_flight.ack_eliciting == 0 && self.peer_completed_address_validation() {
            // There is nothing to detect lost, so no timer is set. However, the client needs to arm
            // the timer if the server might be blocked by the anti-amplification limit.
            self.timers.stop(Timer::LossDetection);
            return;
        }

        // Determine which PN space to arm PTO for.
        // Calculate PTO duration
        if let Some((timeout, _)) = self.pto_time_and_space(now) {
            self.timers.set(Timer::LossDetection, timeout);
        } else {
            self.timers.stop(Timer::LossDetection);
        }
    }

    /// Probe Timeout
    fn pto(&self, space: SpaceId) -> Duration {
        let max_ack_delay = match space {
            SpaceId::Initial | SpaceId::Handshake => Duration::new(0, 0),
            SpaceId::Data => self.max_ack_delay(),
        };
        self.path.rtt.pto_base() + max_ack_delay
    }

    fn on_packet_authenticated(
        &mut self,
        now: Instant,
        space_id: SpaceId,
        ecn: Option<EcnCodepoint>,
        packet: Option<u64>,
        spin: bool,
        is_1rtt: bool,
    ) {
        self.total_authed_packets += 1;
        self.reset_keep_alive(now);
        self.reset_idle_timeout(now, space_id);
        self.permit_idle_reset = true;
        self.receiving_ecn |= ecn.is_some();
        if let Some(x) = ecn {
            self.spaces[space_id].ecn_counters += x;
        }

        let packet = match packet {
            Some(x) => x,
            None => return,
        };
        if self.side.is_server() {
            if self.spaces[SpaceId::Initial].crypto.is_some() && space_id == SpaceId::Handshake {
                // A server stops sending and processing Initial packets when it receives its first Handshake packet.
                self.discard_space(now, SpaceId::Initial);
            }
            if self.zero_rtt_crypto.is_some() && is_1rtt {
                // Discard 0-RTT keys soon after receiving a 1-RTT packet
                self.set_key_discard_timer(now, space_id)
            }
        }
        let space = &mut self.spaces[space_id];
        space.pending_acks.insert_one(packet, now);
        if packet >= space.rx_packet {
            space.rx_packet = packet;
            // Update outgoing spin bit, inverting iff we're the client
            self.spin = self.side.is_client() ^ spin;
        }
    }

    fn reset_idle_timeout(&mut self, now: Instant, space: SpaceId) {
        let timeout = match self.idle_timeout {
            None => return,
            Some(x) => Duration::from_millis(x.0),
        };
        if self.state.is_closed() {
            self.timers.stop(Timer::Idle);
            return;
        }
        let dt = cmp::max(timeout, 3 * self.pto(space));
        self.timers.set(Timer::Idle, now + dt);
    }

    fn reset_keep_alive(&mut self, now: Instant) {
        let interval = match self.config.keep_alive_interval {
            Some(x) if self.state.is_established() => x,
            _ => return,
        };
        self.timers.set(Timer::KeepAlive, now + interval);
    }

    fn reset_cid_retirement(&mut self) {
        if let Some(t) = self.local_cid_state.next_timeout() {
            self.timers.set(Timer::PushNewCid, t);
        }
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
        packet: Packet,
        remaining: Option<BytesMut>,
    ) -> Result<(), ConnectionError> {
        let span = trace_span!("first recv");
        let _guard = span.enter();
        debug_assert!(self.side.is_server());
        let len = packet.header_data.len() + packet.payload.len();
        self.path.total_recvd = len as u64;

        match self.state {
            State::Handshake(ref mut state) => match packet.header {
                Header::Initial { ref token, .. } => {
                    state.expected_token = token.clone();
                }
                _ => unreachable!("first packet must be an Initial packet"),
            },
            _ => unreachable!("first packet must be delivered in Handshake state"),
        }

        self.on_packet_authenticated(
            now,
            SpaceId::Initial,
            ecn,
            Some(packet_number),
            false,
            false,
        );
        self.process_decrypted_packet(now, remote, Some(packet_number), packet)?;
        if let Some(data) = remaining {
            self.handle_coalesced(now, remote, ecn, data);
        }
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
                        ack_delay_exponent: TransportParameters::default().ack_delay_exponent,
                        max_ack_delay: TransportParameters::default().max_ack_delay,
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
            if let State::Handshake(ref mut state) = self.state {
                if space == SpaceId::Initial && offset == 0 && self.side.is_client() {
                    state.client_hello = Some(outgoing.clone());
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
            self.retry_token = Bytes::new();
        }
        let space = &mut self.spaces[space_id];
        space.crypto = None;
        space.time_of_last_ack_eliciting_packet = None;
        space.loss_time = None;
        let sent_packets = mem::take(&mut space.sent_packets);
        for (_, packet) in sent_packets.into_iter() {
            self.remove_in_flight(space_id, &packet);
        }
        self.set_loss_detection_timer(now)
    }

    fn handle_coalesced(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        ecn: Option<EcnCodepoint>,
        data: BytesMut,
    ) {
        self.path.total_recvd = self.path.total_recvd.saturating_add(data.len() as u64);
        let mut remaining = Some(data);
        while let Some(data) = remaining {
            match PartialDecode::new(
                data,
                self.local_cid_state.cid_len(),
                &[self.version],
                self.endpoint_config.grease_quic_bit,
            ) {
                Ok((partial_decode, rest)) => {
                    remaining = rest;
                    self.handle_decode(now, remote, ecn, partial_decode);
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
        ecn: Option<EcnCodepoint>,
        partial_decode: PartialDecode,
    ) {
        let header_crypto = if partial_decode.is_0rtt() {
            if let Some(ref crypto) = self.zero_rtt_crypto {
                Some(&*crypto.header)
            } else {
                debug!("dropping unexpected 0-RTT packet");
                return;
            }
        } else if let Some(space) = partial_decode.space() {
            if let Some(ref crypto) = self.spaces[space].crypto {
                Some(&*crypto.header.remote)
            } else {
                debug!(
                    "discarding unexpected {:?} packet ({} bytes)",
                    space,
                    partial_decode.len(),
                );
                return;
            }
        } else {
            // Unprotected packet
            None
        };

        let packet = partial_decode.data();
        let stateless_reset = packet.len() >= RESET_TOKEN_SIZE + 5
            && self.peer_params.stateless_reset_token.as_deref()
                == Some(&packet[packet.len() - RESET_TOKEN_SIZE..]);

        match partial_decode.finish(header_crypto) {
            Ok(packet) => self.handle_packet(now, remote, ecn, Some(packet), stateless_reset),
            Err(_) if stateless_reset => self.handle_packet(now, remote, ecn, None, true),
            Err(e) => {
                trace!("unable to complete packet decoding: {}", e);
            }
        }
    }

    fn handle_packet(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        ecn: Option<EcnCodepoint>,
        packet: Option<Packet>,
        stateless_reset: bool,
    ) {
        if let Some(ref packet) = packet {
            trace!(
                "got {:?} packet ({} bytes) from {} using id {}",
                packet.header.space(),
                packet.payload.len() + packet.header_data.len(),
                remote,
                packet.header.dst_cid(),
            );
        }

        if self.is_handshaking() && remote != self.path.remote {
            debug!("discarding packet with unexpected remote during handshake");
            return;
        }

        let was_closed = self.state.is_closed();
        let was_drained = self.state.is_drained();

        let decrypted = match packet {
            None => Err(None),
            Some(mut packet) => self
                .decrypt_packet(now, &mut packet)
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
                let span = match number {
                    Some(pn) => trace_span!("recv", space = ?packet.header.space(), pn),
                    None => trace_span!("recv", space = ?packet.header.space()),
                };
                let _guard = span.enter();

                let is_duplicate = |n| self.spaces[packet.header.space()].dedup.insert(n);
                if number.map_or(false, is_duplicate) {
                    warn!("discarding possible duplicate packet");
                    return;
                } else if self.state.is_handshake() && packet.header.is_short() {
                    // TODO: SHOULD buffer these to improve reordering tolerance.
                    trace!("dropping short packet during handshake");
                    return;
                } else {
                    if let Header::Initial { ref token, .. } = packet.header {
                        if let State::Handshake(ref hs) = self.state {
                            if self.side.is_server() && token != &hs.expected_token {
                                // Clients must send the same retry token in every Initial. Initial
                                // packets can be spoofed, so we discard rather than killing the
                                // connection.
                                warn!("discarding Initial with invalid retry token");
                                return;
                            }
                        }
                    }

                    if !self.state.is_closed() {
                        let spin = match packet.header {
                            Header::Short { spin, .. } => spin,
                            _ => false,
                        };
                        self.on_packet_authenticated(
                            now,
                            packet.header.space(),
                            ecn,
                            number,
                            spin,
                            packet.header.is_1rtt(),
                        );
                    }
                    self.process_decrypted_packet(now, remote, number, packet)
                }
            }
        };

        // State transitions for error cases
        if let Err(conn_err) = result {
            self.error = Some(conn_err.clone());
            self.state = match conn_err {
                ConnectionError::ApplicationClosed(reason) => State::closed(reason),
                ConnectionError::ConnectionClosed(reason) => State::closed(reason),
                ConnectionError::Reset
                | ConnectionError::TransportError(TransportError {
                    code: TransportErrorCode::AEAD_LIMIT_REACHED,
                    ..
                }) => State::Drained,
                ConnectionError::TimedOut => {
                    unreachable!("timeouts aren't generated by packet processing");
                }
                ConnectionError::TransportError(err) => {
                    debug!("closing connection due to transport error: {}", err);
                    State::closed(err)
                }
                ConnectionError::VersionMismatch => State::Draining,
                ConnectionError::LocallyClosed => {
                    unreachable!("LocallyClosed isn't generated by packet processing")
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
            self.timers.stop(Timer::Close);
        }

        // Transmit CONNECTION_CLOSE if necessary
        if let State::Closed(_) = self.state {
            self.close = remote == self.path.remote;
        }
    }

    fn process_decrypted_packet(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        number: Option<u64>,
        packet: Packet,
    ) -> Result<(), ConnectionError> {
        let state = match self.state {
            State::Established => {
                match packet.header.space() {
                    SpaceId::Data => {
                        self.process_payload(now, remote, number.unwrap(), packet.payload.freeze())?
                    }
                    _ => self.process_early_payload(now, packet)?,
                }
                return Ok(());
            }
            State::Closed(_) => {
                for frame in frame::Iter::new(packet.payload.freeze()) {
                    if let Frame::Padding = frame {
                        continue;
                    };

                    self.stats.frame_rx.record(&frame);

                    if let Frame::Close(_) = frame {
                        trace!("draining");
                        self.state = State::Draining;
                        break;
                    }
                }
                return Ok(());
            }
            State::Draining | State::Drained => return Ok(()),
            State::Handshake(ref mut state) => state,
        };

        match packet.header {
            Header::Retry {
                src_cid: rem_cid, ..
            } => {
                if self.side.is_server() {
                    return Err(TransportError::PROTOCOL_VIOLATION("client sent Retry").into());
                }

                if self.total_authed_packets > 1
                            || packet.payload.len() <= 16 // token + 16 byte tag
                            || !self.crypto.is_valid_retry(
                                &self.rem_cids.active(),
                                &packet.header_data,
                                &packet.payload,
                            )
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
                self.rem_cids.update_initial_cid(rem_cid);
                self.rem_handshake_cid = rem_cid;

                let space = &mut self.spaces[SpaceId::Initial];
                if let Some(info) = space.sent_packets.remove(&0) {
                    self.on_packet_acked(now, SpaceId::Initial, info);
                };

                self.discard_space(now, SpaceId::Initial); // Make sure we clean up after any retransmitted Initials
                self.spaces[SpaceId::Initial] = PacketSpace {
                    crypto: Some(self.crypto.initial_keys(&rem_cid, self.side)),
                    next_packet_number: self.spaces[SpaceId::Initial].next_packet_number,
                    crypto_offset: client_hello.len() as u64,
                    ..PacketSpace::new(now)
                };
                self.spaces[SpaceId::Initial]
                    .pending
                    .crypto
                    .push_back(frame::Crypto {
                        offset: 0,
                        data: client_hello,
                    });

                // Retransmit all 0-RTT data
                let zero_rtt = mem::take(&mut self.spaces[SpaceId::Data].sent_packets);
                for (_, info) in zero_rtt {
                    self.remove_in_flight(SpaceId::Data, &info);
                    self.spaces[SpaceId::Data].pending |= info.retransmits;
                }
                self.streams.retransmit_all_for_0rtt();

                let token_len = packet.payload.len() - 16;
                self.retry_token = packet.payload.freeze().split_to(token_len);
                self.state = State::Handshake(state::Handshake {
                    expected_token: Bytes::new(),
                    rem_cid_set: false,
                    client_hello: None,
                });
                Ok(())
            }
            Header::Long {
                ty: LongType::Handshake,
                src_cid: rem_cid,
                ..
            } => {
                if rem_cid != self.rem_handshake_cid {
                    debug!(
                        "discarding packet with mismatched remote CID: {} != {}",
                        self.rem_handshake_cid, rem_cid
                    );
                    return Ok(());
                }
                self.path.validated = true;

                self.process_early_payload(now, packet)?;
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
                            let sent_packets =
                                mem::take(&mut self.spaces[SpaceId::Data].sent_packets);
                            for (_, packet) in sent_packets {
                                self.remove_in_flight(SpaceId::Data, &packet);
                            }
                        } else {
                            self.accepted_0rtt = true;
                            params.validate_resumption_from(&self.peer_params)?;
                        }
                    }
                    if let Some(token) = params.stateless_reset_token {
                        self.endpoint_events
                            .push_back(EndpointEventInner::ResetToken(self.path.remote, token));
                    }
                    self.handle_peer_params(params)?;
                    self.issue_cids(now);
                } else {
                    // Server-only
                    self.spaces[SpaceId::Data].pending.handshake_done = true;
                    self.discard_space(now, SpaceId::Handshake);
                }

                self.events.push_back(Event::Connected);
                self.state = State::Established;
                trace!("established");
                Ok(())
            }
            Header::Initial {
                src_cid: rem_cid, ..
            } => {
                if !state.rem_cid_set {
                    trace!("switching remote CID to {}", rem_cid);
                    let mut state = state.clone();
                    self.rem_cids.update_initial_cid(rem_cid);
                    self.rem_handshake_cid = rem_cid;
                    self.orig_rem_cid = rem_cid;
                    state.rem_cid_set = true;
                    self.state = State::Handshake(state);
                } else if rem_cid != self.rem_handshake_cid {
                    debug!(
                        "discarding packet with mismatched remote CID: {} != {}",
                        self.rem_handshake_cid, rem_cid
                    );
                    return Ok(());
                }

                let starting_space = self.highest_space;
                self.process_early_payload(now, packet)?;

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
                            })?;
                    self.handle_peer_params(params)?;
                    self.issue_cids(now);
                    self.init_0rtt();
                }
                Ok(())
            }
            Header::Long {
                ty: LongType::ZeroRtt,
                ..
            } => {
                self.process_payload(now, remote, number.unwrap(), packet.payload.freeze())?;
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
        packet: Packet,
    ) -> Result<(), TransportError> {
        debug_assert_ne!(packet.header.space(), SpaceId::Data);
        let payload_len = packet.payload.len();
        let mut ack_eliciting = false;
        for frame in frame::Iter::new(packet.payload.freeze()) {
            let span = match frame {
                Frame::Padding => continue,
                _ => Some(trace_span!("frame", ty = %frame.ty())),
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
                Frame::Close(reason) => {
                    self.error = Some(reason.into());
                    self.state = State::Draining;
                    return Ok(());
                }
                Frame::Invalid { ty, reason } => {
                    let mut err = TransportError::FRAME_ENCODING_ERROR(reason);
                    err.frame = Some(ty);
                    return Err(err);
                }
                _ => {
                    let mut err =
                        TransportError::PROTOCOL_VIOLATION("illegal frame type in handshake");
                    err.frame = Some(frame.ty());
                    return Err(err);
                }
            }
        }
        self.spaces[packet.header.space()]
            .pending_acks
            .packet_received(ack_eliciting);

        self.write_crypto();
        Ok(())
    }

    fn process_payload(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        number: u64,
        payload: Bytes,
    ) -> Result<(), TransportError> {
        let is_0rtt = self.spaces[SpaceId::Data].crypto.is_none();
        let mut is_probing_packet = true;
        let mut close = None;
        let payload_len = payload.len();
        let mut ack_eliciting = false;
        for frame in frame::Iter::new(payload) {
            let span = match frame {
                Frame::Padding => continue,
                _ => Some(trace_span!("frame", ty = %frame.ty())),
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

            let _guard = span.as_ref().map(|x| x.enter());
            if is_0rtt {
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
                | Frame::NewConnectionId(_) => {}
                _ => {
                    is_probing_packet = false;
                }
            }
            match frame {
                Frame::Invalid { ty, reason } => {
                    let mut err = TransportError::FRAME_ENCODING_ERROR(reason);
                    err.frame = Some(ty);
                    return Err(err);
                }
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
                Frame::Padding | Frame::Ping => {}
                Frame::Close(reason) => {
                    close = Some(reason);
                }
                Frame::PathChallenge(token) => {
                    if self
                        .path_response
                        .as_ref()
                        .map_or(true, |x| x.packet <= number)
                    {
                        self.path_response = Some(PathResponse {
                            packet: number,
                            token,
                        });
                    }
                    if remote == self.path.remote {
                        // PATH_CHALLENGE on active path, possible off-path packet forwarding
                        // attack. Send a non-probing packet to recover the active path.
                        self.ping();
                    }
                }
                Frame::PathResponse(token) => {
                    if self.path.challenge == Some(token) && remote == self.path.remote {
                        trace!("new path validated");
                        self.timers.stop(Timer::PathValidation);
                        self.path.challenge = None;
                        self.path.validated = true;
                        if let Some(ref mut prev_path) = self.prev_path {
                            prev_path.challenge = None;
                            prev_path.challenge_pending = false;
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
                    if id.initiator() == self.side && id.dir() == Dir::Uni {
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
                    if id.initiator() != self.side {
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
                Frame::RetireConnectionId { sequence } => {
                    let allow_more_cids = self
                        .local_cid_state
                        .on_cid_retirement(sequence, self.peer_params.issue_cids_limit())?;
                    self.endpoint_events
                        .push_back(EndpointEventInner::RetireConnectionId(
                            now,
                            sequence,
                            allow_more_cids,
                        ));
                }
                Frame::NewConnectionId(frame) => {
                    trace!(
                        sequence = frame.sequence,
                        id = %frame.id,
                        retire_prior_to = frame.retire_prior_to,
                    );
                    if self.rem_cids.active().is_empty() {
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
                    match self.rem_cids.insert(frame) {
                        Ok(None) => {}
                        Ok(Some((retired, reset_token))) => {
                            self.spaces[SpaceId::Data]
                                .pending
                                .retire_cids
                                .extend(retired);
                            self.set_reset_token(reset_token);
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
                                .push(frame.sequence);
                            continue;
                        }
                    };

                    if self.side.is_server() && self.rem_cids.active_seq() == 0 {
                        // We're a server still using the initial remote CID for the client, so
                        // let's switch immediately to enable clientside stateless resets.
                        self.update_rem_cid();
                    }
                }
                Frame::NewToken { token } => {
                    if self.side.is_server() {
                        return Err(TransportError::PROTOCOL_VIOLATION("client sent NEW_TOKEN"));
                    }
                    if token.is_empty() {
                        return Err(TransportError::FRAME_ENCODING_ERROR("empty token"));
                    }
                    trace!("got new token");
                    // TODO: Cache, or perhaps forward to user?
                }
                Frame::Datagram(datagram) => {
                    if self
                        .datagrams
                        .received(datagram, &self.config.datagram_receive_buffer_size)?
                    {
                        self.events.push_back(Event::DatagramReceived);
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
                }
            }
        }

        self.spaces[SpaceId::Data]
            .pending_acks
            .packet_received(ack_eliciting);

        // Issue stream ID credit due to ACKs of outgoing finish/resets and incoming finish/resets
        // on stopped streams. Incoming finishes/resets on open streams are not handled here as they
        // are only freed, and hence only issue credit, once the application has been notified
        // during a read on the stream.
        let pending = &mut self.spaces[SpaceId::Data].pending;
        for dir in Dir::iter() {
            if self.streams.take_max_streams_dirty(dir) {
                pending.max_stream_id[dir as usize] = true;
            }
        }

        if let Some(reason) = close {
            self.error = Some(reason.into());
            self.state = State::Draining;
            self.close = true;
        }

        if remote != self.path.remote
            && !is_probing_packet
            && number == self.spaces[SpaceId::Data].rx_packet
        {
            debug_assert!(
                self.server_config
                    .as_ref()
                    .expect("packets from unknown remote should be dropped by clients")
                    .migration,
                "migration-initiating packets should have been dropped immediately"
            );
            self.migrate(now, remote);
            // Break linkability, if possible
            self.update_rem_cid();
            self.spin = false;
        }

        Ok(())
    }

    fn migrate(&mut self, now: Instant, remote: SocketAddr) {
        trace!(%remote, "migration initiated");
        // Reset rtt/congestion state for new path unless it looks like a NAT rebinding.
        // Note that the congestion window will not grow until validation terminates. Helps mitigate
        // amplification attacks performed by spoofing source addresses.
        let mut new_path = if remote.is_ipv4() && remote.ip() == self.path.remote.ip() {
            PathData::from_previous(remote, &self.path, now)
        } else {
            let peer_max_udp_payload_size =
                u16::try_from(self.peer_params.max_udp_payload_size.into_inner())
                    .unwrap_or(u16::MAX);
            PathData::new(
                remote,
                self.config.initial_rtt,
                self.config
                    .congestion_controller_factory
                    .build(now, self.config.get_initial_mtu()),
                self.config.get_initial_mtu(),
                self.config.min_mtu,
                Some(peer_max_udp_payload_size),
                self.config.mtu_discovery_config.clone(),
                now,
                false,
            )
        };
        new_path.challenge = Some(self.rng.gen());
        new_path.challenge_pending = true;
        let prev_pto = self.pto(SpaceId::Data);

        let mut prev = mem::replace(&mut self.path, new_path);
        // Don't clobber the original path if the previous one hasn't been validated yet
        if prev.challenge.is_none() {
            prev.challenge = Some(self.rng.gen());
            prev.challenge_pending = true;
            self.prev_path = Some(prev);
        }

        self.timers.set(
            Timer::PathValidation,
            now + 3 * cmp::max(self.pto(SpaceId::Data), prev_pto),
        );
    }

    /// Switch to a previously unused remote connection ID, if possible
    fn update_rem_cid(&mut self) {
        let (reset_token, retired) = match self.rem_cids.next() {
            Some(x) => x,
            None => return,
        };

        // Retire the current remote CID and any CIDs we had to skip.
        self.spaces[SpaceId::Data]
            .pending
            .retire_cids
            .extend(retired);
        self.set_reset_token(reset_token);
    }

    fn set_reset_token(&mut self, reset_token: ResetToken) {
        self.endpoint_events
            .push_back(EndpointEventInner::ResetToken(
                self.path.remote,
                reset_token,
            ));
        self.peer_params.stateless_reset_token = Some(reset_token);
    }

    /// Issue an initial set of connection IDs to the peer
    fn issue_cids(&mut self, now: Instant) {
        if self.local_cid_state.cid_len() == 0 {
            return;
        }

        // Subtract 1 to account for the CID we supplied while handshaking
        let n = self.peer_params.issue_cids_limit() - 1;
        self.endpoint_events
            .push_back(EndpointEventInner::NeedIdentifiers(now, n));
    }

    fn populate_packet(
        &mut self,
        space_id: SpaceId,
        buf: &mut BytesMut,
        max_size: usize,
    ) -> SentFrames {
        let mut sent = SentFrames::default();
        let space = &mut self.spaces[space_id];
        let is_0rtt = space_id == SpaceId::Data && space.crypto.is_none();

        // HANDSHAKE_DONE
        if !is_0rtt && mem::replace(&mut space.pending.handshake_done, false) {
            buf.write(frame::Type::HANDSHAKE_DONE);
            sent.retransmits.get_or_create().handshake_done = true;
            // This is just a u8 counter and the frame is typically just sent once
            self.stats.frame_tx.handshake_done =
                self.stats.frame_tx.handshake_done.saturating_add(1);
        }

        // PING
        if mem::replace(&mut space.ping_pending, false) {
            trace!("PING");
            buf.write(frame::Type::PING);
            sent.non_retransmits = true;
            self.stats.frame_tx.ping += 1;
        }

        // ACK
        if space.pending_acks.can_send() {
            debug_assert!(!space.pending_acks.ranges().is_empty());
            Self::populate_acks(self.receiving_ecn, &mut sent, space, buf, &mut self.stats);
        }

        // PATH_CHALLENGE
        if buf.len() + 9 < max_size && space_id == SpaceId::Data {
            // Transmit challenges with every outgoing frame on an unvalidated path
            if let Some(token) = self.path.challenge {
                // But only send a packet solely for that purpose at most once
                self.path.challenge_pending = false;
                sent.non_retransmits = true;
                sent.requires_padding = true;
                trace!("PATH_CHALLENGE {:08x}", token);
                buf.write(frame::Type::PATH_CHALLENGE);
                buf.write(token);
                self.stats.frame_tx.path_challenge += 1;
            }
        }

        // PATH_RESPONSE
        if buf.len() + 9 < max_size && space_id == SpaceId::Data {
            if let Some(response) = self.path_response.take() {
                sent.non_retransmits = true;
                sent.requires_padding = true;
                trace!("PATH_RESPONSE {:08x}", response.token);
                buf.write(frame::Type::PATH_RESPONSE);
                buf.write(response.token);
                self.stats.frame_tx.path_response += 1;
            }
        }

        // CRYPTO
        while buf.len() + frame::Crypto::SIZE_BOUND < max_size && !is_0rtt {
            let mut frame = match space.pending.crypto.pop_front() {
                Some(x) => x,
                None => break,
            };

            // Calculate the maximum amount of crypto data we can store in the buffer.
            // Since the offset is known, we can reserve the exact size required to encode it.
            // For length we reserve 2bytes which allows to encode up to 2^14,
            // which is more than what fits into normally sized QUIC frames.
            let max_crypto_data_size = max_size
                - buf.len()
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
            sent.retransmits.get_or_create().crypto.push_back(truncated);
            if !frame.data.is_empty() {
                frame.offset += len as u64;
                space.pending.crypto.push_front(frame);
            }
        }

        if space_id == SpaceId::Data {
            self.streams.write_control_frames(
                buf,
                &mut space.pending,
                &mut sent.retransmits,
                &mut self.stats.frame_tx,
                max_size,
            );
        }

        // NEW_CONNECTION_ID
        while buf.len() + 44 < max_size {
            let issued = match space.pending.new_cids.pop() {
                Some(x) => x,
                None => break,
            };
            trace!(
                sequence = issued.sequence,
                id = %issued.id,
                "NEW_CONNECTION_ID"
            );
            frame::NewConnectionId {
                sequence: issued.sequence,
                retire_prior_to: self.local_cid_state.retire_prior_to(),
                id: issued.id,
                reset_token: issued.reset_token,
            }
            .encode(buf);
            sent.retransmits.get_or_create().new_cids.push(issued);
            self.stats.frame_tx.new_connection_id += 1;
        }

        // RETIRE_CONNECTION_ID
        while buf.len() + frame::RETIRE_CONNECTION_ID_SIZE_BOUND < max_size {
            let seq = match space.pending.retire_cids.pop() {
                Some(x) => x,
                None => break,
            };
            trace!(sequence = seq, "RETIRE_CONNECTION_ID");
            buf.write(frame::Type::RETIRE_CONNECTION_ID);
            buf.write_var(seq);
            sent.retransmits.get_or_create().retire_cids.push(seq);
            self.stats.frame_tx.retire_connection_id += 1;
        }

        // DATAGRAM
        while buf.len() + Datagram::SIZE_BOUND < max_size && space_id == SpaceId::Data {
            match self.datagrams.write(buf, max_size) {
                true => {
                    sent.non_retransmits = true;
                    self.stats.frame_tx.datagram += 1;
                }
                false => break,
            }
        }

        // STREAM
        if space_id == SpaceId::Data {
            sent.stream_frames = self.streams.write_stream_frames(buf, max_size);
            self.stats.frame_tx.stream += sent.stream_frames.len() as u64;
        }

        sent
    }

    /// Write pending ACKs into a buffer
    ///
    /// This method assumes ACKs are pending, and should only be called if
    /// `!PendingAcks::ranges().is_empty()` returns `true`.
    fn populate_acks(
        receiving_ecn: bool,
        sent: &mut SentFrames,
        space: &mut PacketSpace,
        buf: &mut BytesMut,
        stats: &mut ConnectionStats,
    ) {
        debug_assert!(!space.pending_acks.ranges().is_empty());

        // 0-RTT packets must never carry acks (which would have to be of handshake packets)
        debug_assert!(space.crypto.is_some(), "tried to send ACK in 0-RTT");
        let ecn = if receiving_ecn {
            Some(&space.ecn_counters)
        } else {
            None
        };
        sent.largest_acked = space.pending_acks.ranges().max();

        let delay_micros = space.pending_acks.ack_delay().as_micros() as u64;

        // TODO: This should come frome `TransportConfig` if that gets configurable
        let ack_delay_exp = TransportParameters::default().ack_delay_exponent;
        let delay = delay_micros >> ack_delay_exp.into_inner();

        trace!("ACK {:?}, Delay = {}us", space.pending_acks.ranges(), delay);

        frame::Ack::encode(delay as _, space.pending_acks.ranges(), ecn, buf);
        stats.frame_tx.acks += 1;
    }

    fn close_common(&mut self) {
        trace!("connection closed");
        for &timer in &Timer::VALUES {
            self.timers.stop(timer);
        }
    }

    fn set_close_timer(&mut self, now: Instant) {
        self.timers
            .set(Timer::Close, now + 3 * self.pto(self.highest_space));
    }

    /// Handle transport parameters received from the peer
    fn handle_peer_params(&mut self, params: TransportParameters) -> Result<(), TransportError> {
        if Some(self.orig_rem_cid) != params.initial_src_cid
            || (self.side.is_client()
                && (Some(self.initial_dst_cid) != params.original_dst_cid
                    || self.retry_src_cid != params.retry_src_cid))
        {
            return Err(TransportError::TRANSPORT_PARAMETER_ERROR(
                "CID authentication failure",
            ));
        }

        self.set_peer_params(params);
        Ok(())
    }

    fn set_peer_params(&mut self, params: TransportParameters) {
        self.streams.set_params(&params);
        self.idle_timeout = match (self.config.max_idle_timeout, params.max_idle_timeout) {
            (None, VarInt(0)) => None,
            (None, x) => Some(x),
            (Some(x), VarInt(0)) => Some(x),
            (Some(x), y) => Some(cmp::min(x, y)),
        };
        if let Some(ref info) = params.preferred_address {
            self.rem_cids.insert(frame::NewConnectionId {
                sequence: 1,
                id: info.connection_id,
                reset_token: info.stateless_reset_token,
                retire_prior_to: 0,
            }).expect("preferred address CID is the first received, and hence is guaranteed to be legal");
        }
        self.peer_params = params;
        self.path.mtud.on_peer_max_udp_payload_size_received(
            u16::try_from(self.peer_params.max_udp_payload_size.into_inner()).unwrap_or(u16::MAX),
        );
    }

    fn decrypt_packet(
        &mut self,
        now: Instant,
        packet: &mut Packet,
    ) -> Result<Option<u64>, Option<TransportError>> {
        if !packet.header.is_protected() {
            // Unprotected packets also don't have packet numbers
            return Ok(None);
        }
        let space = packet.header.space();
        let rx_packet = self.spaces[space].rx_packet;
        let number = packet.header.number().ok_or(None)?.expand(rx_packet + 1);
        let key_phase = packet.header.key_phase();

        let mut crypto_update = false;
        let crypto = if packet.header.is_0rtt() {
            &self.zero_rtt_crypto.as_ref().unwrap().packet
        } else if key_phase == self.key_phase || space != SpaceId::Data {
            &self.spaces[space].crypto.as_mut().unwrap().packet.remote
        } else if let Some(prev) = self.prev_crypto.as_ref().and_then(|crypto| {
            // If this packet comes prior to acknowledgment of the key update by the peer,
            if crypto.end_packet.map_or(true, |(pn, _)| number < pn) {
                // use the previous keys.
                Some(crypto)
            } else {
                // Otherwise, this must be a remotely-initiated key update, so fall through to the
                // final case.
                None
            }
        }) {
            &prev.crypto.remote
        } else {
            // We're in the Data space with a key phase mismatch and either there is no locally
            // initiated key update or the locally initiated key update was acknowledged by a
            // lower-numbered packet. The key phase mismatch must therefore represent a new
            // remotely-initiated key update.
            crypto_update = true;
            &self.next_crypto.as_ref().unwrap().remote
        };

        crypto
            .decrypt(number, &packet.header_data, &mut packet.payload)
            .map_err(|_| {
                trace!("decryption failed with packet number {}", number);
                None
            })?;

        if let Some(ref mut prev) = self.prev_crypto {
            if prev.end_packet.is_none() && key_phase == self.key_phase {
                // Outgoing key update newly acknowledged
                prev.end_packet = Some((number, now));
                self.set_key_discard_timer(now, space);
            }
        }

        if !packet.reserved_bits_valid() {
            return Err(Some(TransportError::PROTOCOL_VIOLATION(
                "reserved bits set",
            )));
        }

        if crypto_update {
            // Validate and commit incoming key update
            if number <= rx_packet
                || self
                    .prev_crypto
                    .as_ref()
                    .map_or(false, |x| x.update_unacked)
            {
                return Err(Some(TransportError::KEY_UPDATE_ERROR("")));
            }
            trace!("key update authenticated");
            self.update_keys(Some((number, now)), true);
            self.set_key_discard_timer(now, space);
        }

        Ok(Some(number))
    }

    fn update_keys(&mut self, end_packet: Option<(u64, Instant)>, remote: bool) {
        // Generate keys for the key phase after the one we're switching to, store them in
        // `next_crypto`, make the contents of `next_crypto` current, and move the current keys into
        // `prev_crypto`.
        let new = self
            .crypto
            .next_1rtt_keys()
            .expect("only called for `Data` packets");
        let old = mem::replace(
            &mut self.spaces[SpaceId::Data]
                .crypto
                .as_mut()
                .unwrap() // safe because update_keys() can only be triggered by short packets
                .packet,
            mem::replace(self.next_crypto.as_mut().unwrap(), new),
        );
        self.spaces[SpaceId::Data].sent_with_keys = 0;
        self.prev_crypto = Some(PrevCrypto {
            crypto: old,
            end_packet,
            update_unacked: remote,
        });
        self.key_phase = !self.key_phase;
    }

    /// The number of bytes of packets containing retransmittable frames that have not been
    /// acknowledged or declared lost.
    #[cfg(test)]
    pub(crate) fn bytes_in_flight(&self) -> u64 {
        self.in_flight.bytes
    }

    /// Number of bytes worth of non-ack-only packets that may be sent
    #[cfg(test)]
    pub(crate) fn congestion_window(&self) -> u64 {
        self.path
            .congestion
            .window()
            .saturating_sub(self.in_flight.bytes)
    }

    /// Whether no timers but keepalive, idle and pushnewcid are running
    #[cfg(test)]
    pub(crate) fn is_idle(&self) -> bool {
        Timer::VALUES
            .iter()
            .filter(|&&t| t != Timer::KeepAlive && t != Timer::PushNewCid)
            .filter_map(|&t| Some((t, self.timers.get(t)?)))
            .min_by_key(|&(_, time)| time)
            .map_or(true, |(timer, _)| timer == Timer::Idle)
    }

    /// Total number of outgoing packets that have been deemed lost
    #[cfg(test)]
    pub(crate) fn lost_packets(&self) -> u64 {
        self.lost_packets
    }

    /// Whether explicit congestion notification is in use on outgoing packets.
    #[cfg(test)]
    pub(crate) fn using_ecn(&self) -> bool {
        self.path.sending_ecn
    }

    /// The number of received bytes in the current path
    #[cfg(test)]
    pub(crate) fn total_recvd(&self) -> u64 {
        self.path.total_recvd
    }

    #[cfg(test)]
    pub(crate) fn active_local_cid_seq(&self) -> (u64, u64) {
        self.local_cid_state.active_seq()
    }

    /// Instruct the peer to replace previously issued CIDs by sending a NEW_CONNECTION_ID frame
    /// with updated `retire_prior_to` field set to `v`
    #[cfg(test)]
    pub(crate) fn rotate_local_cid(&mut self, v: u64, now: Instant) {
        let n = self.local_cid_state.assign_retire_seq(v);
        self.endpoint_events
            .push_back(EndpointEventInner::NeedIdentifiers(now, n));
    }

    /// Check the current active remote CID sequence
    #[cfg(test)]
    pub(crate) fn active_rem_cid_seq(&self) -> u64 {
        self.rem_cids.active_seq()
    }

    /// Returns the detected maximum udp payload size for the current path
    #[cfg(test)]
    pub(crate) fn path_mtu(&self) -> u16 {
        self.path.current_mtu()
    }

    fn max_ack_delay(&self) -> Duration {
        Duration::from_micros(self.peer_params.max_ack_delay.0 * 1000)
    }

    /// Whether we have 1-RTT data to send
    ///
    /// See also `self.space(SpaceId::Data).can_send()`
    fn can_send_1rtt(&self) -> bool {
        self.streams.can_send_stream_data()
            || self.path.challenge_pending
            || self
                .prev_path
                .as_ref()
                .map_or(false, |x| x.challenge_pending)
            || self.path_response.is_some()
            || !self.datagrams.outgoing.is_empty()
    }

    /// Update counters to account for a packet becoming acknowledged, lost, or abandoned
    fn remove_in_flight(&mut self, space: SpaceId, packet: &SentPacket) {
        self.in_flight.bytes -= u64::from(packet.size);
        self.in_flight.ack_eliciting -= u64::from(packet.ack_eliciting);
        self.spaces[space].in_flight -= u64::from(packet.size);
    }

    /// Terminate the connection instantly, without sending a close packet
    fn kill(&mut self, reason: ConnectionError) {
        self.close_common();
        self.error = Some(reason);
        self.state = State::Drained;
        self.endpoint_events.push_back(EndpointEventInner::Drained);
    }
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Connection")
            .field("handshake_cid", &self.handshake_cid)
            .finish()
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
        use self::ConnectionError::*;
        let kind = match x {
            TimedOut => io::ErrorKind::TimedOut,
            Reset => io::ErrorKind::ConnectionReset,
            ApplicationClosed(_) | ConnectionClosed(_) => io::ErrorKind::ConnectionAborted,
            TransportError(_) | VersionMismatch | LocallyClosed => io::ErrorKind::Other,
        };
        Self::new(kind, x)
    }
}

#[allow(unreachable_pub)] // fuzzing only
#[derive(Clone)]
pub enum State {
    Handshake(state::Handshake),
    Established,
    Closed(state::Closed),
    Draining,
    /// Waiting for application to call close so we can dispose of the resources
    Drained,
}

impl State {
    fn closed<R: Into<Close>>(reason: R) -> Self {
        Self::Closed(state::Closed {
            reason: reason.into(),
        })
    }

    fn is_handshake(&self) -> bool {
        matches!(*self, Self::Handshake(_))
    }

    fn is_established(&self) -> bool {
        matches!(*self, Self::Established)
    }

    fn is_closed(&self) -> bool {
        matches!(*self, Self::Closed(_) | Self::Draining | Self::Drained)
    }

    fn is_drained(&self) -> bool {
        matches!(*self, Self::Drained)
    }
}

mod state {
    use super::*;

    #[allow(unreachable_pub)] // fuzzing only
    #[derive(Clone)]
    pub struct Handshake {
        /// Whether the remote CID has been set by the peer yet
        ///
        /// Always set for servers
        pub(super) rem_cid_set: bool,
        /// Stateless retry token received in the first Initial by a server.
        ///
        /// Must be present in every Initial. Always empty for clients.
        pub(super) expected_token: Bytes,
        /// First cryptographic message
        ///
        /// Only set for clients
        pub(super) client_hello: Option<Bytes>,
    }

    #[allow(unreachable_pub)] // fuzzing only
    #[derive(Clone)]
    pub struct Closed {
        pub(super) reason: Close,
    }
}

struct PrevCrypto {
    /// The keys used for the previous key phase, temporarily retained to decrypt packets sent by
    /// the peer prior to its own key update.
    crypto: KeyPair<Box<dyn PacketKey>>,
    /// The incoming packet that ends the interval for which these keys are applicable, and the time
    /// of its receipt.
    ///
    /// Incoming packets should be decrypted using these keys iff this is `None` or their packet
    /// number is lower. `None` indicates that we have not yet received a packet using newer keys,
    /// which implies that the update was locally initiated.
    end_packet: Option<(u64, Instant)>,
    /// Whether the following key phase is from a remotely initiated update that we haven't acked
    update_unacked: bool,
}

struct InFlight {
    /// Sum of the sizes of all sent packets considered "in flight" by congestion control
    ///
    /// The size does not include IP or UDP overhead. Packets only containing ACK frames do not
    /// count towards this to ensure congestion control does not impede congestion feedback.
    bytes: u64,
    /// Number of packets in flight containing frames other than ACK and PADDING
    ///
    /// This can be 0 even when bytes is not 0 because PADDING frames cause a packet to be
    /// considered "in flight" by congestion control. However, if this is nonzero, bytes will always
    /// also be nonzero.
    ack_eliciting: u64,
}

impl InFlight {
    fn new() -> Self {
        Self {
            bytes: 0,
            ack_eliciting: 0,
        }
    }

    fn insert(&mut self, packet: &SentPacket) {
        self.bytes += u64::from(packet.size);
        self.ack_eliciting += u64::from(packet.ack_eliciting);
    }
}

/// Events of interest to the application
#[derive(Debug)]
pub enum Event {
    /// The connection's handshake data is ready
    HandshakeDataReady,
    /// The connection was successfully established
    Connected,
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
}

struct PathResponse {
    /// The packet number the corresponding PATH_CHALLENGE was received in
    packet: u64,
    token: u64,
}

fn instant_saturating_sub(x: Instant, y: Instant) -> Duration {
    if x > y {
        x - y
    } else {
        Duration::new(0, 0)
    }
}

// Prevents overflow and improves behavior in extreme circumstances
const MAX_BACKOFF_EXPONENT: u32 = 16;
// Minimal remaining size to allow packet coalescing
const MIN_PACKET_SPACE: usize = 40;
/// The maximum amount of datagrams that are sent in a single transmit
///
/// This can be lower than the maximum platform capabilities, to avoid excessive
/// memory allocations when calling `poll_transmit()`. Benchmarks have shown
/// that numbers around 10 are a good compromise.
const MAX_TRANSMIT_SEGMENTS: usize = 10;

struct ZeroRttCrypto {
    header: Box<dyn HeaderKey>,
    packet: Box<dyn PacketKey>,
}

#[derive(Default)]
struct SentFrames {
    retransmits: ThinRetransmits,
    largest_acked: Option<u64>,
    stream_frames: StreamMetaVec,
    /// Whether the packet contains non-retransmittable frames (like datagrams)
    non_retransmits: bool,
    requires_padding: bool,
}

impl SentFrames {
    /// Returns whether the packet contains only ACKs
    fn is_ack_only(&self, streams: &StreamsState) -> bool {
        self.largest_acked.is_some()
            && !self.non_retransmits
            && self.stream_frames.is_empty()
            && self.retransmits.is_empty(streams)
    }
}
