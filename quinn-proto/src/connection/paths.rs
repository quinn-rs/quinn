use std::{cmp, net::SocketAddr};

use tracing::trace;

use super::{
    mtud::MtuDiscovery,
    pacing::Pacer,
    spaces::{PacketSpace, SentPacket},
};
use crate::{
    Duration, Instant, TIMER_GRANULARITY, TransportConfig, VarInt, coding, congestion,
    frame::ObservedAddr, packet::SpaceId,
};

/// Id representing different paths when using multipath extension
// TODO(@divma): improve docs, reconsider access to inner
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default, Hash)]
pub struct PathId(pub(crate) u32);

impl coding::Codec for PathId {
    fn decode<B: bytes::Buf>(r: &mut B) -> coding::Result<Self> {
        let v = VarInt::decode(r)?;
        let v = u32::try_from(v.0).map_err(|_| coding::UnexpectedEnd)?;
        Ok(Self(v))
    }

    fn encode<B: bytes::BufMut>(&self, w: &mut B) {
        VarInt(self.0.into()).encode(w)
    }
}

impl PathId {
    /// The maximum path ID allowed.
    pub const MAX: Self = Self(u32::MAX);

    /// The 0 path id.
    pub const ZERO: Self = Self(0);

    pub(crate) fn size(&self) -> usize {
        VarInt(self.0 as u64).size()
    }

    /// Saturating integer addition. Computes self + rhs, saturating at the numeric bounds instead
    /// of overflowing.
    pub fn saturating_add(self, rhs: impl Into<Self>) -> Self {
        let rhs = rhs.into();
        let inner = self.0.saturating_add(rhs.0);
        Self(inner)
    }
}

impl std::fmt::Display for PathId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<T: Into<u32>> From<T> for PathId {
    fn from(source: T) -> Self {
        Self(source.into())
    }
}

/// Description of a particular network path
pub(super) struct PathData {
    pub(super) remote: SocketAddr,
    pub(super) rtt: RttEstimator,
    /// Whether we're enabling ECN on outgoing packets
    pub(super) sending_ecn: bool,
    /// Congestion controller state
    pub(super) congestion: Box<dyn congestion::Controller>,
    /// Pacing state
    pub(super) pacing: Pacer,
    pub(super) challenge: Option<u64>,
    pub(super) challenge_pending: bool,
    /// Pending responses to PATH_CHALLENGE frames
    pub(super) path_responses: PathResponses,
    /// Whether we're certain the peer can both send and receive on this address
    ///
    /// Initially equal to `use_stateless_retry` for servers, and becomes false again on every
    /// migration. Always true for clients.
    pub(super) validated: bool,
    /// Total size of all UDP datagrams sent on this path
    pub(super) total_sent: u64,
    /// Total size of all UDP datagrams received on this path
    pub(super) total_recvd: u64,
    /// The state of the MTU discovery process
    pub(super) mtud: MtuDiscovery,
    /// Packet number of the first packet sent after an RTT sample was collected on this path
    ///
    /// Used in persistent congestion determination.
    pub(super) first_packet_after_rtt_sample: Option<(SpaceId, u64)>,
    pub(super) in_flight: InFlight,
    /// Whether this path has had it's remote address reported back to the peer. This only happens
    /// if both peers agree to so based on their transport parameters.
    pub(super) observed_addr_sent: bool,
    /// Observed address frame with the largest sequence number received from the peer on this path.
    pub(super) last_observed_addr_report: Option<ObservedAddr>,
    /// The QUIC-MULTIPATH path status
    pub(super) status: PathStatus,
    /// The sequence number of the received PATH_AVAILABLE and PATH_BACKUP frames.
    pub(super) status_seq_no: Option<VarInt>,
    /// Number of the first packet sent on this path
    ///
    /// Used to determine whether a packet was sent on an earlier path. Insufficient to determine if
    /// a packet was sent on a later path.
    first_packet: Option<u64>,
    /// The number of times a PTO has been sent without receiving an ack.
    pub(super) pto_count: u32,
}

impl PathData {
    pub(super) fn new(
        remote: SocketAddr,
        allow_mtud: bool,
        peer_max_udp_payload_size: Option<u16>,
        now: Instant,
        config: &TransportConfig,
    ) -> Self {
        let congestion = config
            .congestion_controller_factory
            .clone()
            .build(now, config.get_initial_mtu());
        Self {
            remote,
            rtt: RttEstimator::new(config.initial_rtt),
            sending_ecn: true,
            pacing: Pacer::new(
                config.initial_rtt,
                congestion.initial_window(),
                config.get_initial_mtu(),
                now,
            ),
            congestion,
            challenge: None,
            challenge_pending: false,
            path_responses: PathResponses::default(),
            validated: false,
            total_sent: 0,
            total_recvd: 0,
            mtud: config
                .mtu_discovery_config
                .as_ref()
                .filter(|_| allow_mtud)
                .map_or(
                    MtuDiscovery::disabled(config.get_initial_mtu(), config.min_mtu),
                    |mtud_config| {
                        MtuDiscovery::new(
                            config.get_initial_mtu(),
                            config.min_mtu,
                            peer_max_udp_payload_size,
                            mtud_config.clone(),
                        )
                    },
                ),
            first_packet_after_rtt_sample: None,
            in_flight: InFlight::new(),
            observed_addr_sent: false,
            last_observed_addr_report: None,
            status: Default::default(),
            status_seq_no: None,
            first_packet: None,
            pto_count: 0,
        }
    }

    /// Create a new path from a previous one.
    ///
    /// This should only be called when migrating paths.
    pub(super) fn from_previous(remote: SocketAddr, prev: &Self, now: Instant) -> Self {
        let congestion = prev.congestion.clone_box();
        let smoothed_rtt = prev.rtt.get();
        Self {
            remote,
            rtt: prev.rtt,
            pacing: Pacer::new(smoothed_rtt, congestion.window(), prev.current_mtu(), now),
            sending_ecn: true,
            congestion,
            challenge: None,
            challenge_pending: false,
            path_responses: PathResponses::default(),
            validated: false,
            total_sent: 0,
            total_recvd: 0,
            mtud: prev.mtud.clone(),
            first_packet_after_rtt_sample: prev.first_packet_after_rtt_sample,
            in_flight: InFlight::new(),
            observed_addr_sent: false,
            last_observed_addr_report: None,
            status: prev.status,
            status_seq_no: prev.status_seq_no,
            first_packet: None,
            pto_count: 0,
        }
    }

    /// Resets RTT, congestion control and MTU states.
    ///
    /// This is useful when it is known the underlying path has changed.
    pub(super) fn reset(&mut self, now: Instant, config: &TransportConfig) {
        self.rtt = RttEstimator::new(config.initial_rtt);
        self.congestion = config
            .congestion_controller_factory
            .clone()
            .build(now, config.get_initial_mtu());
        self.mtud.reset(config.get_initial_mtu(), config.min_mtu);
    }

    /// Indicates whether we're a server that hasn't validated the peer's address and hasn't
    /// received enough data from the peer to permit sending `bytes_to_send` additional bytes
    pub(super) fn anti_amplification_blocked(&self, bytes_to_send: u64) -> bool {
        !self.validated && self.total_recvd * 3 < self.total_sent + bytes_to_send
    }

    /// Returns the path's current MTU
    pub(super) fn current_mtu(&self) -> u16 {
        self.mtud.current_mtu()
    }

    /// Account for transmission of `packet` with number `pn` in `space`
    pub(super) fn sent(
        &mut self,
        path: PathId,
        pn: u64,
        packet: SentPacket,
        space: &mut PacketSpace,
    ) {
        self.in_flight.insert(&packet);
        if self.first_packet.is_none() {
            self.first_packet = Some(pn);
        }
        // TODO(@divma): why is Path receiving a path_id??
        self.in_flight.bytes -= space.for_path(path).sent(pn, packet);
    }

    /// Remove `packet` with number `pn` from this path's congestion control counters, or return
    /// `false` if `pn` was sent before this path was established.
    pub(super) fn remove_in_flight(&mut self, pn: u64, packet: &SentPacket) -> bool {
        if self.first_packet.map_or(true, |first| first > pn) {
            return false;
        }
        self.in_flight.remove(packet);
        true
    }

    /// Increment the total size of sent UDP datagrams
    pub(super) fn inc_total_sent(&mut self, inc: u64) {
        self.total_sent = self.total_sent.saturating_add(inc);
    }

    /// Increment the total size of received UDP datagrams
    pub(super) fn inc_total_recvd(&mut self, inc: u64) {
        self.total_recvd = self.total_recvd.saturating_add(inc);
    }

    /// Return how long we need to wait before sending `bytes_to_send`
    ///
    /// See [`Pacer::delay`].
    pub(super) fn pacing_delay(&mut self, bytes_to_send: u64, now: Instant) -> Option<Instant> {
        let smoothed_rtt = self.rtt.get();
        self.pacing.delay(
            smoothed_rtt,
            bytes_to_send,
            self.current_mtu(),
            self.congestion.window(),
            now,
        )
    }

    /// Updates the last observed address report received on this path.
    ///
    /// If the address was updated, it's returned to be informed to the application.
    #[must_use = "updated observed address must be reported to the application"]
    pub(super) fn update_observed_addr_report(
        &mut self,
        observed: ObservedAddr,
    ) -> Option<SocketAddr> {
        match self.last_observed_addr_report.as_mut() {
            Some(prev) => {
                if prev.seq_no >= observed.seq_no {
                    // frames that do not increase the sequence number on this path are ignored
                    None
                } else if prev.ip == observed.ip && prev.port == observed.port {
                    // keep track of the last seq_no but do not report the address as updated
                    prev.seq_no = observed.seq_no;
                    None
                } else {
                    let addr = observed.socket_addr();
                    self.last_observed_addr_report = Some(observed);
                    Some(addr)
                }
            }
            None => {
                let addr = observed.socket_addr();
                self.last_observed_addr_report = Some(observed);
                Some(addr)
            }
        }
    }
}

/// RTT estimation for a particular network path
#[derive(Copy, Clone)]
pub struct RttEstimator {
    /// The most recent RTT measurement made when receiving an ack for a previously unacked packet
    latest: Duration,
    /// The smoothed RTT of the connection, computed as described in RFC6298
    smoothed: Option<Duration>,
    /// The RTT variance, computed as described in RFC6298
    var: Duration,
    /// The minimum RTT seen in the connection, ignoring ack delay.
    min: Duration,
}

impl RttEstimator {
    pub(super) fn new(initial_rtt: Duration) -> Self {
        Self {
            latest: initial_rtt,
            smoothed: None,
            var: initial_rtt / 2,
            min: initial_rtt,
        }
    }

    /// The current best RTT estimation.
    pub fn get(&self) -> Duration {
        self.smoothed.unwrap_or(self.latest)
    }

    /// Conservative estimate of RTT
    ///
    /// Takes the maximum of smoothed and latest RTT, as recommended
    /// in 6.1.2 of the recovery spec (draft 29).
    pub fn conservative(&self) -> Duration {
        self.get().max(self.latest)
    }

    /// Minimum RTT registered so far for this estimator.
    pub fn min(&self) -> Duration {
        self.min
    }

    // PTO computed as described in RFC9002#6.2.1
    pub(crate) fn pto_base(&self) -> Duration {
        self.get() + cmp::max(4 * self.var, TIMER_GRANULARITY)
    }

    pub(crate) fn update(&mut self, ack_delay: Duration, rtt: Duration) {
        self.latest = rtt;
        // min_rtt ignores ack delay.
        self.min = cmp::min(self.min, self.latest);
        // Based on RFC6298.
        if let Some(smoothed) = self.smoothed {
            let adjusted_rtt = if self.min + ack_delay <= self.latest {
                self.latest - ack_delay
            } else {
                self.latest
            };
            let var_sample = if smoothed > adjusted_rtt {
                smoothed - adjusted_rtt
            } else {
                adjusted_rtt - smoothed
            };
            self.var = (3 * self.var + var_sample) / 4;
            self.smoothed = Some((7 * smoothed + adjusted_rtt) / 8);
        } else {
            self.smoothed = Some(self.latest);
            self.var = self.latest / 2;
            self.min = self.latest;
        }
    }
}

#[derive(Default)]
pub(crate) struct PathResponses {
    pending: Vec<PathResponse>,
}

impl PathResponses {
    pub(crate) fn push(&mut self, packet: u64, token: u64, remote: SocketAddr) {
        /// Arbitrary permissive limit to prevent abuse
        const MAX_PATH_RESPONSES: usize = 16;
        let response = PathResponse {
            packet,
            token,
            remote,
        };
        let existing = self.pending.iter_mut().find(|x| x.remote == remote);
        if let Some(existing) = existing {
            // Update a queued response
            if existing.packet <= packet {
                *existing = response;
            }
            return;
        }
        if self.pending.len() < MAX_PATH_RESPONSES {
            self.pending.push(response);
        } else {
            // We don't expect to ever hit this with well-behaved peers, so we don't bother dropping
            // older challenges.
            trace!("ignoring excessive PATH_CHALLENGE");
        }
    }

    pub(crate) fn pop_off_path(&mut self, remote: SocketAddr) -> Option<(u64, SocketAddr)> {
        let response = *self.pending.last()?;
        if response.remote == remote {
            // We don't bother searching further because we expect that the on-path response will
            // get drained in the immediate future by a call to `pop_on_path`
            return None;
        }
        self.pending.pop();
        Some((response.token, response.remote))
    }

    pub(crate) fn pop_on_path(&mut self, remote: SocketAddr) -> Option<u64> {
        let response = *self.pending.last()?;
        if response.remote != remote {
            // We don't bother searching further because we expect that the off-path response will
            // get drained in the immediate future by a call to `pop_off_path`
            return None;
        }
        self.pending.pop();
        Some(response.token)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

#[derive(Copy, Clone)]
struct PathResponse {
    /// The packet number the corresponding PATH_CHALLENGE was received in
    packet: u64,
    /// The token of the PATH_CHALLENGE
    token: u64,
    /// The address the corresponding PATH_CHALLENGE was received from
    remote: SocketAddr,
}

/// Summary statistics of packets that have been sent on a particular path, but which have not yet
/// been acked or deemed lost
pub(super) struct InFlight {
    /// Sum of the sizes of all sent packets considered "in flight" by congestion control
    ///
    /// The size does not include IP or UDP overhead. Packets only containing ACK frames do not
    /// count towards this to ensure congestion control does not impede congestion feedback.
    pub(super) bytes: u64,
    /// Number of packets in flight containing frames other than ACK and PADDING
    ///
    /// This can be 0 even when bytes is not 0 because PADDING frames cause a packet to be
    /// considered "in flight" by congestion control. However, if this is nonzero, bytes will always
    /// also be nonzero.
    pub(super) ack_eliciting: u64,
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

    /// Update counters to account for a packet becoming acknowledged, lost, or abandoned
    fn remove(&mut self, packet: &SentPacket) {
        self.bytes -= u64::from(packet.size);
        self.ack_eliciting -= u64::from(packet.ack_eliciting);
    }
}

/// The QUIC-MULTIPATH path status
///
/// See section "3.3 Path Status Management":
/// <https://quicwg.org/multipath/draft-ietf-quic-multipath.html#name-path-status-management>
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub enum PathStatus {
    /// Paths marked with as available will be used when scheduling packets
    ///
    /// If multiple paths are available, packets will be scheduled on whichever has
    /// capacity.
    #[default]
    Available,
    /// Paths marked as backup will only be used if there are no available paths
    ///
    /// If the max_idle_timeout is specified the path will be kept alive so that it does not
    /// expire.
    Backup,
}

/// Application events about paths
#[derive(Debug, PartialEq, Eq)]
pub enum PathEvent {
    /// A new path has been opened
    Opened {
        /// Which path is now open
        id: PathId,
    },
    /// A path has been closed
    Closed {
        /// Which path has been closed
        id: PathId,
        /// Error code supplied by the peer
        /// See <https://www.ietf.org/archive/id/draft-ietf-quic-multipath-14.html#name-error-codes>
        /// for a list of known errors.
        error_code: VarInt,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_id_saturating_add() {
        // add within range behaves normally
        let large: PathId = u16::MAX.into();
        let next = u32::from(u16::MAX) + 1;
        assert_eq!(large.saturating_add(1u8), PathId::from(next));

        // outside range saturates
        assert_eq!(PathId::MAX.saturating_add(1u8), PathId::MAX)
    }
}
