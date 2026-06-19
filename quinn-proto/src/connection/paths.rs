use std::{
    cmp,
    net::{IpAddr, SocketAddr},
    ops::{Deref, DerefMut},
};

use rand::Rng;
use tracing::trace;

use super::{
    cid_state::CidState,
    mtud::MtuDiscovery,
    pacing::Pacer,
    spaces::{PacketNumberFilter, PacketSpace, SentPacket},
};
use crate::{
    Duration, Instant, TIMER_GRANULARITY, TransportConfig, TransportError, VarInt,
    cid_queue::CidQueue, congestion, packet::SpaceId,
};

#[cfg(feature = "qlog")]
use qlog::events::{ExData, quic::RecoveryMetricsUpdated};

const MAX_ADDITIONAL_PATHS: usize = 1024;

/// Protocol-level identifier for a multipath QUIC path.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct PathId(u32);

impl PathId {
    pub(crate) const ZERO: Self = Self(0);

    pub(crate) fn from_u32(value: u32) -> Self {
        Self(value)
    }

    pub(crate) fn into_inner(self) -> u32 {
        self.0
    }

    fn index(self) -> usize {
        self.0 as usize
    }
}

impl TryFrom<VarInt> for PathId {
    type Error = TransportError;

    fn try_from(value: VarInt) -> Result<Self, Self::Error> {
        let value = value.into_inner();
        if value > u32::MAX.into() {
            return Err(TransportError::PROTOCOL_VIOLATION(
                "path ID exceeds 32-bit limit",
            ));
        }
        Ok(Self(value as u32))
    }
}

impl From<PathId> for VarInt {
    fn from(value: PathId) -> Self {
        Self::from_u32(value.0)
    }
}

/// State for a single QUIC path.
pub(super) struct Path {
    id: PathId,
    data: PathData,
    remote_cids: CidQueue,
    local_cid_state: CidState,
    packet_number_filter: PacketNumberFilter,
    data_space: PacketSpace,
    peer_status: PathUsePreference,
    latest_peer_status_sequence: Option<u64>,
}

impl Path {
    pub(super) fn new(
        id: PathId,
        data: PathData,
        remote_cids: CidQueue,
        local_cid_state: CidState,
        packet_number_filter: PacketNumberFilter,
        data_space: PacketSpace,
    ) -> Self {
        Self {
            id,
            data,
            remote_cids,
            local_cid_state,
            packet_number_filter,
            data_space,
            peer_status: PathUsePreference::Available,
            latest_peer_status_sequence: None,
        }
    }

    pub(super) fn id(&self) -> PathId {
        self.id
    }

    pub(super) fn remote_cids(&self) -> &CidQueue {
        &self.remote_cids
    }

    pub(super) fn remote_cids_mut(&mut self) -> &mut CidQueue {
        &mut self.remote_cids
    }

    pub(super) fn local_cid_state(&self) -> &CidState {
        &self.local_cid_state
    }

    pub(super) fn local_cid_state_mut(&mut self) -> &mut CidState {
        &mut self.local_cid_state
    }

    pub(super) fn packet_number_filter(&self) -> &PacketNumberFilter {
        &self.packet_number_filter
    }

    pub(super) fn data_space(&self) -> &PacketSpace {
        &self.data_space
    }

    pub(super) fn data_space_mut(&mut self) -> &mut PacketSpace {
        &mut self.data_space
    }

    pub(super) fn data_and_space_mut(&mut self) -> (&mut PathData, &mut PacketSpace) {
        (&mut self.data, &mut self.data_space)
    }

    pub(super) fn replace_data(&mut self, data: PathData) -> PathData {
        std::mem::replace(&mut self.data, data)
    }

    pub(super) fn allocate_packet_number(&mut self, rng: &mut (impl Rng + ?Sized)) -> u64 {
        self.packet_number_filter
            .allocate(rng, &mut self.data_space)
    }

    pub(super) fn sent_data(&mut self, pn: u64, packet: SentPacket) {
        self.data.sent(pn, packet, &mut self.data_space);
    }

    pub(super) fn sent_on(&mut self, pn: u64, packet: SentPacket, space: &mut PacketSpace) {
        self.data.sent(pn, packet, space);
    }

    pub(super) fn peer_status(&self) -> PathUsePreference {
        self.peer_status
    }

    pub(super) fn update_peer_status(&mut self, status: PathUsePreference, sequence: u64) -> bool {
        if self
            .latest_peer_status_sequence
            .is_some_and(|latest| sequence <= latest)
        {
            return false;
        }
        self.latest_peer_status_sequence = Some(sequence);
        self.peer_status = status;
        true
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(super) enum PathUsePreference {
    Available,
    Backup,
}

impl Deref for Path {
    type Target = PathData;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl DerefMut for Path {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

/// Internal collection of paths for a connection.
pub(super) struct Paths {
    primary: Path,
    additional: Vec<Option<Path>>,
    abandoned: Vec<AbandonedPath>,
}

struct AbandonedPath {
    path: Path,
    retain_until: Instant,
}

impl Paths {
    pub(super) fn new(primary: Path) -> Self {
        Self {
            primary,
            additional: Vec::new(),
            abandoned: Vec::new(),
        }
    }

    pub(super) fn get(&self, id: PathId) -> Option<&Path> {
        match id {
            PathId::ZERO => Some(&self.primary),
            _ => self
                .additional
                .get(id.index().checked_sub(1)?)
                .and_then(Option::as_ref),
        }
    }

    pub(super) fn get_mut(&mut self, id: PathId) -> Option<&mut Path> {
        match id {
            PathId::ZERO => Some(&mut self.primary),
            _ => self
                .additional
                .get_mut(id.index().checked_sub(1)?)
                .and_then(Option::as_mut),
        }
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = &Path> {
        std::iter::once(&self.primary).chain(self.additional.iter().flatten())
    }

    pub(super) fn expired_validation_path_ids(&self, now: Instant) -> Vec<PathId> {
        self.additional
            .iter()
            .flatten()
            .filter(|path| {
                path.challenge.is_some()
                    && path
                        .validation_deadline
                        .is_some_and(|deadline| deadline <= now)
            })
            .map(Path::id)
            .collect()
    }

    pub(super) fn next_validation_deadline(&self) -> Option<Instant> {
        self.iter()
            .filter(|path| path.challenge.is_some())
            .filter_map(|path| path.validation_deadline)
            .min()
    }

    pub(super) fn abandon(&mut self, id: PathId, retain_until: Instant) -> bool {
        let Some(mut path) = (match id {
            PathId::ZERO => None,
            _ => self
                .additional
                .get_mut(
                    id.index()
                        .checked_sub(1)
                        .expect("nonzero path has additional index"),
                )
                .and_then(Option::take),
        }) else {
            return false;
        };
        if !path.data_space.pending_acks.ranges().is_empty() {
            path.data_space.pending_acks.set_immediate_ack_required();
        }
        self.abandoned.push(AbandonedPath { path, retain_until });
        true
    }

    pub(super) fn get_abandoned(&self, id: PathId, now: Instant) -> Option<&Path> {
        self.abandoned
            .iter()
            .find(|path| path.path.id() == id && now <= path.retain_until)
            .map(|path| &path.path)
    }

    pub(super) fn get_abandoned_mut(&mut self, id: PathId, now: Instant) -> Option<&mut Path> {
        self.abandoned
            .iter_mut()
            .find(|path| path.path.id() == id && now <= path.retain_until)
            .map(|path| &mut path.path)
    }

    pub(super) fn next_validation_path_id(&self) -> Option<PathId> {
        self.additional
            .iter()
            .flatten()
            .find(|path| path.challenge_pending)
            .map(Path::id)
    }

    pub(super) fn has_pending_validation(&self) -> bool {
        self.primary.challenge.is_some()
            || self
                .additional
                .iter()
                .flatten()
                .any(|path| path.challenge.is_some())
    }

    pub(super) fn next_abandoned_ack_path_id(&self, now: Instant) -> Option<PathId> {
        self.abandoned
            .iter()
            .find(|path| now <= path.retain_until && path.path.data_space.pending_acks.can_send())
            .map(|path| path.path.id())
    }

    pub(super) fn insert(&mut self, path: Path) -> Result<(), PathInsertError> {
        let id = path.id();
        if id == PathId::ZERO {
            return Err(PathInsertError::PathZero);
        }

        let index = id.index() - 1;
        if index >= MAX_ADDITIONAL_PATHS {
            return Err(PathInsertError::PathLimit);
        }
        if self.additional.len() <= index {
            self.additional.resize_with(index + 1, || None);
        }

        if self.additional[index].is_some() {
            return Err(PathInsertError::Occupied);
        }

        self.additional[index] = Some(path);
        Ok(())
    }

    pub(super) fn primary_mut(&mut self) -> &mut Path {
        &mut self.primary
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(super) enum PathInsertError {
    PathZero,
    PathLimit,
    Occupied,
}

impl Deref for Paths {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.primary
    }
}

impl DerefMut for Paths {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.primary
    }
}

/// Description of a particular network path
pub(super) struct PathData {
    pub(super) remote: SocketAddr,
    pub(super) local_ip: Option<IpAddr>,
    pub(super) rtt: RttEstimator,
    /// Whether we're enabling ECN on outgoing packets
    pub(super) sending_ecn: bool,
    /// Congestion controller state
    pub(super) congestion: Box<dyn congestion::Controller>,
    /// Pacing state
    pub(super) pacing: Pacer,
    pub(super) challenge: Option<u64>,
    pub(super) challenge_pending: bool,
    pub(super) validation_deadline: Option<Instant>,
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
    /// Number of the first packet sent on this path
    ///
    /// Used to determine whether a packet was sent on an earlier path. Insufficient to determine if
    /// a packet was sent on a later path.
    first_packet: Option<u64>,

    /// Snapshot of the qlog recovery metrics
    #[cfg(feature = "qlog")]
    recovery_metrics: RecoveryMetrics,

    /// Tag uniquely identifying a path in a connection
    generation: u64,
}

impl PathData {
    pub(super) fn new(
        remote: SocketAddr,
        local_ip: Option<IpAddr>,
        allow_mtud: bool,
        peer_max_udp_payload_size: Option<u16>,
        generation: u64,
        now: Instant,
        config: &TransportConfig,
    ) -> Self {
        let congestion = config
            .congestion_controller_factory
            .clone()
            .build(now, config.get_initial_mtu());
        Self {
            remote,
            local_ip,
            rtt: RttEstimator::new(config.initial_rtt),
            sending_ecn: true,
            pacing: Pacer::new(
                config.initial_rtt,
                congestion.initial_window(),
                config.get_initial_mtu(),
                config.max_outgoing_bytes_per_second,
                now,
            ),
            congestion,
            challenge: None,
            challenge_pending: false,
            validation_deadline: None,
            validated: false,
            total_sent: 0,
            total_recvd: 0,
            mtud: config
                .mtu_discovery_config
                .as_ref()
                .filter(|_| allow_mtud)
                .map_or_else(
                    || MtuDiscovery::disabled(config.get_initial_mtu(), config.min_mtu),
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
            first_packet: None,
            #[cfg(feature = "qlog")]
            recovery_metrics: RecoveryMetrics::default(),
            generation,
        }
    }

    pub(super) fn from_previous(
        remote: SocketAddr,
        prev: &Self,
        generation: u64,
        now: Instant,
    ) -> Self {
        let congestion = prev.congestion.clone_box();
        let smoothed_rtt = prev.rtt.get();
        Self {
            remote,
            local_ip: prev.local_ip,
            rtt: prev.rtt,
            pacing: Pacer::new(
                smoothed_rtt,
                congestion.window(),
                prev.current_mtu(),
                prev.pacing.max_bytes_per_second(),
                now,
            ),
            sending_ecn: true,
            congestion,
            challenge: None,
            challenge_pending: false,
            validation_deadline: None,
            validated: false,
            total_sent: 0,
            total_recvd: 0,
            mtud: prev.mtud.clone(),
            first_packet_after_rtt_sample: prev.first_packet_after_rtt_sample,
            in_flight: InFlight::new(),
            first_packet: None,
            #[cfg(feature = "qlog")]
            recovery_metrics: prev.recovery_metrics.clone(),
            generation,
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

    pub(super) fn observe_datagram(
        &mut self,
        remote: SocketAddr,
        local_ip: Option<IpAddr>,
        len: usize,
    ) {
        self.remote = remote;
        self.local_ip = local_ip;
        self.total_recvd = self.total_recvd.saturating_add(len as u64);
    }

    /// Account for transmission of `packet` with number `pn` in `space`
    pub(super) fn sent(&mut self, pn: u64, packet: SentPacket, space: &mut PacketSpace) {
        self.in_flight.insert(&packet);
        if self.first_packet.is_none() {
            self.first_packet = Some(pn);
        }
        if let Some(forgotten) = space.sent(pn, packet) {
            self.remove_in_flight(&forgotten);
        }
    }

    /// Remove `packet` with number `pn` from this path's congestion control counters, or return
    /// `false` if `pn` was sent before this path was established.
    pub(super) fn remove_in_flight(&mut self, packet: &SentPacket) -> bool {
        if packet.path_generation != self.generation {
            return false;
        }
        self.in_flight.remove(packet);
        true
    }

    #[cfg(feature = "qlog")]
    pub(super) fn qlog_recovery_metrics(
        &mut self,
        pto_count: u32,
    ) -> Option<RecoveryMetricsUpdated> {
        let controller_metrics = self.congestion.metrics();

        let metrics = RecoveryMetrics {
            min_rtt: Some(self.rtt.min),
            smoothed_rtt: Some(self.rtt.get()),
            latest_rtt: Some(self.rtt.latest),
            rtt_variance: Some(self.rtt.var),
            pto_count: Some(pto_count),
            bytes_in_flight: Some(self.in_flight.bytes),
            packets_in_flight: Some(self.in_flight.ack_eliciting),

            congestion_window: Some(controller_metrics.congestion_window),
            ssthresh: controller_metrics.ssthresh,
            pacing_rate: controller_metrics.pacing_rate,
        };

        let event = metrics.to_qlog_event(&self.recovery_metrics);
        self.recovery_metrics = metrics;
        event
    }

    pub(super) fn generation(&self) -> u64 {
        self.generation
    }
}

/// Congestion metrics as described in [`recovery_metrics_updated`].
///
/// [`recovery_metrics_updated`]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-quic-events.html#name-recovery_metrics_updated
#[cfg(feature = "qlog")]
#[derive(Default, Clone, PartialEq)]
#[non_exhaustive]
struct RecoveryMetrics {
    pub min_rtt: Option<Duration>,
    pub smoothed_rtt: Option<Duration>,
    pub latest_rtt: Option<Duration>,
    pub rtt_variance: Option<Duration>,
    pub pto_count: Option<u32>,
    pub bytes_in_flight: Option<u64>,
    pub packets_in_flight: Option<u64>,
    pub congestion_window: Option<u64>,
    pub ssthresh: Option<u64>,
    pub pacing_rate: Option<u64>,
}

#[cfg(feature = "qlog")]
impl RecoveryMetrics {
    /// Retain only values that have been updated since the last snapshot.
    fn retain_updated(&self, previous: &Self) -> Self {
        macro_rules! keep_if_changed {
            ($name:ident) => {
                if previous.$name == self.$name {
                    None
                } else {
                    self.$name
                }
            };
        }

        Self {
            min_rtt: keep_if_changed!(min_rtt),
            smoothed_rtt: keep_if_changed!(smoothed_rtt),
            latest_rtt: keep_if_changed!(latest_rtt),
            rtt_variance: keep_if_changed!(rtt_variance),
            pto_count: keep_if_changed!(pto_count),
            bytes_in_flight: keep_if_changed!(bytes_in_flight),
            packets_in_flight: keep_if_changed!(packets_in_flight),
            congestion_window: keep_if_changed!(congestion_window),
            ssthresh: keep_if_changed!(ssthresh),
            pacing_rate: keep_if_changed!(pacing_rate),
        }
    }

    /// Emit a `MetricsUpdated` event containing only updated values
    fn to_qlog_event(&self, previous: &Self) -> Option<RecoveryMetricsUpdated> {
        let updated = self.retain_updated(previous);

        if updated == Self::default() {
            return None;
        }

        Some(RecoveryMetricsUpdated {
            ex_data: ExData::default(),
            min_rtt: updated.min_rtt.map(|rtt| rtt.as_micros() as f32 / 1000.0),
            smoothed_rtt: updated
                .smoothed_rtt
                .map(|rtt| rtt.as_micros() as f32 / 1000.0),
            latest_rtt: updated
                .latest_rtt
                .map(|rtt| rtt.as_micros() as f32 / 1000.0),
            rtt_variance: updated
                .rtt_variance
                .map(|rtt| rtt.as_micros() as f32 / 1000.0),
            pto_count: updated
                .pto_count
                .map(|count| count.try_into().unwrap_or(u16::MAX)),
            bytes_in_flight: updated.bytes_in_flight,
            packets_in_flight: updated.packets_in_flight,
            congestion_window: updated.congestion_window,
            ssthresh: updated.ssthresh,
            pacing_rate: updated.pacing_rate,
        })
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
    pub(crate) fn new(initial_rtt: Duration) -> Self {
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
            let var_sample = smoothed.abs_diff(adjusted_rtt);
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
    pub(crate) fn push(&mut self, packet: u64, token: u64, path_id: PathId, remote: SocketAddr) {
        /// Arbitrary permissive limit to prevent abuse
        const MAX_PATH_RESPONSES: usize = 16;
        let response = PathResponse {
            packet,
            path_id,
            token,
            remote,
        };
        let existing = self
            .pending
            .iter_mut()
            .find(|x| x.path_id == path_id && x.remote == remote);
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

    pub(crate) fn pop_off_path(
        &mut self,
        path_id: PathId,
        remote: SocketAddr,
    ) -> Option<(u64, SocketAddr)> {
        let response = *self.pending.last()?;
        if response.path_id == path_id && response.remote == remote {
            // We don't bother searching further because we expect that the on-path response will
            // get drained in the immediate future by a call to `pop_on_path`
            return None;
        }
        self.pending.pop();
        Some((response.token, response.remote))
    }

    pub(crate) fn pop_on_path(&mut self, path_id: PathId, remote: SocketAddr) -> Option<u64> {
        let response = *self.pending.last()?;
        if response.path_id != path_id || response.remote != remote {
            // We don't bother searching further because we expect that the off-path response will
            // get drained in the immediate future by a call to `pop_off_path`
            return None;
        }
        self.pending.pop();
        Some(response.token)
    }

    pub(crate) fn next_path_id(&self) -> Option<PathId> {
        self.pending.last().map(|response| response.path_id)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

#[derive(Copy, Clone)]
struct PathResponse {
    /// The packet number the corresponding PATH_CHALLENGE was received in
    packet: u64,
    path_id: PathId,
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

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use crate::{
        Instant, TransportConfig,
        cid_queue::CidQueue,
        connection::{cid_state::CidState, spaces::PacketNumberFilter},
        shared::ConnectionId,
    };

    use super::*;

    fn path(id: u32) -> Path {
        let now = Instant::now();
        let remote = SocketAddr::from(([127, 0, 0, 1], 4433 + id as u16));
        Path::new(
            PathId(id),
            PathData::new(
                remote,
                None,
                true,
                None,
                id.into(),
                now,
                &TransportConfig::default(),
            ),
            CidQueue::new(ConnectionId::new(&[id as u8; 8])),
            CidState::new(8, None, now, 1),
            PacketNumberFilter::disabled(),
            PacketSpace::new(now),
        )
    }

    #[test]
    fn paths_insert_and_lookup_sparse_nonzero_path() {
        let mut paths = Paths::new(path(0));

        assert_eq!(paths.get(PathId::ZERO).unwrap().id(), PathId::ZERO);
        assert!(paths.get(PathId(3)).is_none());

        paths.insert(path(3)).unwrap();

        assert_eq!(paths.get(PathId(3)).unwrap().id(), PathId(3));
        assert!(paths.get(PathId(1)).is_none());
        assert!(paths.get(PathId(2)).is_none());
    }

    #[test]
    fn paths_rejects_path_zero_and_duplicates() {
        let mut paths = Paths::new(path(0));

        assert_eq!(paths.insert(path(0)), Err(PathInsertError::PathZero));
        paths.insert(path(1)).unwrap();
        assert_eq!(paths.insert(path(1)), Err(PathInsertError::Occupied));
    }

    #[test]
    fn paths_rejects_huge_sparse_path_id() {
        let mut paths = Paths::new(path(0));

        assert_eq!(
            paths.insert(path(MAX_ADDITIONAL_PATHS as u32 + 1)),
            Err(PathInsertError::PathLimit)
        );
    }

    #[test]
    fn paths_abandon_nonzero_path() {
        let mut paths = Paths::new(path(0));
        let now = Instant::now();
        paths.insert(path(2)).unwrap();

        assert!(paths.get(PathId(2)).is_some());
        assert!(!paths.abandon(PathId::ZERO, now));
        assert!(paths.abandon(PathId(2), now + Duration::from_secs(1)));
        assert!(paths.get(PathId(2)).is_none());
        assert_eq!(
            paths.get_abandoned(PathId(2), now).map(Path::id),
            Some(PathId(2))
        );
        assert!(
            paths
                .get_abandoned(PathId(2), now + Duration::from_secs(2))
                .is_none()
        );
        assert!(!paths.abandon(PathId(2), now + Duration::from_secs(3)));
    }

    #[test]
    fn paths_abandon_schedules_final_ack() {
        let mut paths = Paths::new(path(0));
        let now = Instant::now();
        let mut path = path(2);
        path.data_space_mut().pending_acks.insert_one(7, now);
        paths.insert(path).unwrap();

        assert!(paths.abandon(PathId(2), now + Duration::from_secs(1)));
        assert_eq!(paths.next_abandoned_ack_path_id(now), Some(PathId(2)));

        let path = paths.get_abandoned_mut(PathId(2), now).unwrap();
        path.data_space_mut().pending_acks.acks_sent();
        assert_eq!(paths.next_abandoned_ack_path_id(now), None);
        assert_eq!(
            paths.next_abandoned_ack_path_id(now + Duration::from_secs(2)),
            None
        );
    }

    #[test]
    fn paths_select_pending_validation_path() {
        let mut paths = Paths::new(path(0));
        let mut pending = path(2);
        pending.challenge = Some(7);
        pending.challenge_pending = true;
        paths.insert(pending).unwrap();
        paths.insert(path(1)).unwrap();

        assert!(paths.has_pending_validation());
        assert_eq!(paths.next_validation_path_id(), Some(PathId(2)));

        paths.get_mut(PathId(2)).unwrap().challenge_pending = false;
        assert!(paths.has_pending_validation());
        assert_eq!(paths.next_validation_path_id(), None);

        paths.get_mut(PathId(2)).unwrap().challenge = None;
        assert!(!paths.has_pending_validation());
    }

    #[test]
    fn paths_expire_only_due_validation_paths() {
        let now = Instant::now();
        let mut paths = Paths::new(path(0));
        let mut first = path(1);
        first.challenge = Some(1);
        first.validation_deadline = Some(now + Duration::from_millis(5));
        let mut second = path(2);
        second.challenge = Some(2);
        second.validation_deadline = Some(now + Duration::from_millis(10));
        paths.insert(first).unwrap();
        paths.insert(second).unwrap();

        assert_eq!(
            paths.next_validation_deadline(),
            Some(now + Duration::from_millis(5))
        );
        assert_eq!(paths.expired_validation_path_ids(now), Vec::<PathId>::new());
        assert_eq!(
            paths.expired_validation_path_ids(now + Duration::from_millis(6)),
            vec![PathId(1)]
        );
        assert_eq!(
            paths.expired_validation_path_ids(now + Duration::from_millis(11)),
            vec![PathId(1), PathId(2)]
        );
    }

    #[test]
    fn path_status_ignores_stale_sequence_numbers() {
        let mut path = path(1);

        assert_eq!(path.peer_status(), PathUsePreference::Available);
        assert!(path.update_peer_status(PathUsePreference::Backup, 2));
        assert_eq!(path.peer_status(), PathUsePreference::Backup);
        assert!(!path.update_peer_status(PathUsePreference::Available, 1));
        assert_eq!(path.peer_status(), PathUsePreference::Backup);
        assert!(!path.update_peer_status(PathUsePreference::Available, 2));
        assert_eq!(path.peer_status(), PathUsePreference::Backup);
        assert!(path.update_peer_status(PathUsePreference::Available, 3));
        assert_eq!(path.peer_status(), PathUsePreference::Available);
    }
}
