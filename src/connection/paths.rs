use std::{cmp, net::SocketAddr};

use tracing::trace;

use super::{
    mtud::MtuDiscovery,
    pacing::Pacer,
    spaces::{PacketSpace, SentPacket},
};
use crate::{Duration, Instant, TIMER_GRANULARITY, TransportConfig, congestion, packet::SpaceId};

#[cfg(feature = "__qlog")]
use qlog::events::quic::MetricsUpdated;

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
    #[cfg(feature = "__qlog")]
    congestion_metrics: CongestionMetrics,

    /// Address discovery information for this path
    pub(super) address_info: PathAddressInfo,
    /// Rate limiter for OBSERVED_ADDRESS frames on this path
    pub(super) observation_rate_limiter: PathObservationRateLimiter,
}

impl PathData {
    pub(super) fn new(
        remote: SocketAddr,
        allow_mtud: bool,
        peer_max_udp_payload_size: Option<u16>,
        now: Instant,
        config: &TransportConfig,
    ) -> Self {
        let congestion = config.congestion_controller_factory.new_controller(
            config.get_initial_mtu() as u64,
            16 * 1024 * 1024,
            now,
        );
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
            first_packet: None,
            #[cfg(feature = "__qlog")]
            congestion_metrics: CongestionMetrics::default(),
            address_info: PathAddressInfo::new(),
            observation_rate_limiter: PathObservationRateLimiter::new(10, now), // Default rate of 10
        }
    }

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
            validated: false,
            total_sent: 0,
            total_recvd: 0,
            mtud: prev.mtud.clone(),
            first_packet_after_rtt_sample: prev.first_packet_after_rtt_sample,
            in_flight: InFlight::new(),
            first_packet: None,
            #[cfg(feature = "__qlog")]
            congestion_metrics: prev.congestion_metrics.clone(),
            address_info: PathAddressInfo::new(), // Reset for new path
            observation_rate_limiter: PathObservationRateLimiter::new(
                prev.observation_rate_limiter.rate as u8,
                now,
            ), // Fresh limiter with same rate
        }
    }

    /// Resets RTT, congestion control and MTU states.
    ///
    /// This is useful when it is known the underlying path has changed.
    pub(super) fn reset(&mut self, now: Instant, config: &TransportConfig) {
        self.rtt = RttEstimator::new(config.initial_rtt);
        self.congestion = config.congestion_controller_factory.new_controller(
            config.get_initial_mtu() as u64,
            16 * 1024 * 1024,
            now,
        );
        self.mtud.reset(config.get_initial_mtu(), config.min_mtu);
        self.address_info = PathAddressInfo::new(); // Reset address info
        // Reset tokens but preserve rate
        let rate = self.observation_rate_limiter.rate as u8;
        self.observation_rate_limiter = PathObservationRateLimiter::new(rate, now);
    }

    /// Update the observed address for this path
    pub(super) fn update_observed_address(&mut self, address: SocketAddr, now: Instant) {
        self.address_info.update_observed_address(address, now);
    }

    /// Check if the observed address has changed from the expected remote address
    pub(super) fn has_address_changed(&self) -> bool {
        self.address_info.has_address_changed(&self.remote)
    }

    /// Mark that we've notified the application about the current address
    pub(super) fn mark_address_notified(&mut self) {
        self.address_info.mark_notified();
    }

    /// Check if we can send an observation on this path
    pub(super) fn can_send_observation(&mut self, now: Instant) -> bool {
        self.observation_rate_limiter.can_send(now)
    }

    /// Consume a token for sending an observation
    pub(super) fn consume_observation_token(&mut self, now: Instant) {
        self.observation_rate_limiter.consume_token(now)
    }

    /// Update observation tokens based on elapsed time
    pub(super) fn update_observation_tokens(&mut self, now: Instant) {
        self.observation_rate_limiter.update_tokens(now)
    }

    /// Set the observation rate for this path
    pub(super) fn set_observation_rate(&mut self, rate: u8) {
        self.observation_rate_limiter.set_rate(rate)
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
    pub(super) fn sent(&mut self, pn: u64, packet: SentPacket, space: &mut PacketSpace) {
        self.in_flight.insert(&packet);
        if self.first_packet.is_none() {
            self.first_packet = Some(pn);
        }
        self.in_flight.bytes -= space.sent(pn, packet);
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

    #[cfg(feature = "__qlog")]
    pub(super) fn qlog_congestion_metrics(&mut self, pto_count: u32) -> Option<MetricsUpdated> {
        let controller_metrics = self.congestion.metrics();

        let metrics = CongestionMetrics {
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

        let event = metrics.to_qlog_event(&self.congestion_metrics);
        self.congestion_metrics = metrics;
        event
    }
}

/// Congestion metrics as described in [`recovery_metrics_updated`].
///
/// [`recovery_metrics_updated`]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-quic-events.html#name-recovery_metrics_updated
#[cfg(feature = "__qlog")]
#[derive(Default, Clone, PartialEq)]
#[non_exhaustive]
struct CongestionMetrics {
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

#[cfg(feature = "__qlog")]
impl CongestionMetrics {
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
    fn to_qlog_event(&self, previous: &Self) -> Option<MetricsUpdated> {
        let updated = self.retain_updated(previous);

        if updated == Self::default() {
            return None;
        }

        Some(MetricsUpdated {
            min_rtt: updated.min_rtt.map(|rtt| rtt.as_secs_f32()),
            smoothed_rtt: updated.smoothed_rtt.map(|rtt| rtt.as_secs_f32()),
            latest_rtt: updated.latest_rtt.map(|rtt| rtt.as_secs_f32()),
            rtt_variance: updated.rtt_variance.map(|rtt| rtt.as_secs_f32()),
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
    fn new(initial_rtt: Duration) -> Self {
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
    token: u64,
    /// The address the corresponding PATH_CHALLENGE was received from
    remote: SocketAddr,
}

/// Tracks PATH_CHALLENGE tokens for NAT traversal candidate validation
#[derive(Default)]
pub(crate) struct NatTraversalChallenges {
    pending: Vec<NatTraversalChallenge>,
}

impl NatTraversalChallenges {
    pub(crate) fn push(&mut self, remote: SocketAddr, token: u64) {
        /// Arbitrary permissive limit to prevent abuse
        const MAX_NAT_CHALLENGES: usize = 10;

        // Check if we already have a challenge for this address
        if let Some(existing) = self.pending.iter_mut().find(|x| x.remote == remote) {
            existing.token = token;
            return;
        }

        if self.pending.len() < MAX_NAT_CHALLENGES {
            self.pending.push(NatTraversalChallenge { remote, token });
        } else {
            // Replace the oldest challenge
            self.pending[0] = NatTraversalChallenge { remote, token };
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

#[derive(Copy, Clone)]
struct NatTraversalChallenge {
    /// The address to send the PATH_CHALLENGE to
    remote: SocketAddr,
    /// The challenge token
    token: u64,
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

/// Information about addresses observed for a specific path
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PathAddressInfo {
    /// The most recently observed address for this path
    pub(super) observed_address: Option<SocketAddr>,
    /// When the address was last observed
    pub(super) last_observed: Option<Instant>,
    /// Number of times the address has been observed
    pub(super) observation_count: u64,
    /// Whether we've notified the application about this address
    pub(super) notified: bool,
}

/// Rate limiter for OBSERVED_ADDRESS frames per path
#[derive(Debug, Clone)]
pub(super) struct PathObservationRateLimiter {
    /// Tokens available for sending observations
    pub(super) tokens: f64,
    /// Maximum tokens (burst capacity)
    pub(super) max_tokens: f64,
    /// Rate of token replenishment (tokens per second)
    pub(super) rate: f64,
    /// Last time tokens were updated
    pub(super) last_update: Instant,
}

impl PathObservationRateLimiter {
    /// Create a new rate limiter with the given rate
    pub(super) fn new(rate: u8, now: Instant) -> Self {
        let rate_f64 = rate as f64;
        Self {
            tokens: rate_f64,
            max_tokens: rate_f64,
            rate: rate_f64,
            last_update: now,
        }
    }

    /// Update tokens based on elapsed time
    pub(super) fn update_tokens(&mut self, now: Instant) {
        let elapsed = now
            .saturating_duration_since(self.last_update)
            .as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.max_tokens);
        self.last_update = now;
    }

    /// Check if we can send an observation
    pub(super) fn can_send(&mut self, now: Instant) -> bool {
        self.update_tokens(now);
        self.tokens >= 1.0
    }

    /// Consume a token for sending an observation
    pub(super) fn consume_token(&mut self, now: Instant) {
        self.update_tokens(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
        }
    }

    /// Update the rate
    pub(super) fn set_rate(&mut self, rate: u8) {
        let rate_f64 = rate as f64;
        self.rate = rate_f64;
        self.max_tokens = rate_f64;
        // Don't change current tokens, just cap at new max
        self.tokens = self.tokens.min(self.max_tokens);
    }
}

impl PathAddressInfo {
    pub(super) fn new() -> Self {
        Self {
            observed_address: None,
            last_observed: None,
            observation_count: 0,
            notified: false,
        }
    }

    /// Update with a newly observed address
    pub(super) fn update_observed_address(&mut self, address: SocketAddr, now: Instant) {
        if self.observed_address == Some(address) {
            // Same address observed again - preserve notification status
            self.observation_count += 1;
        } else {
            // New address observed
            self.observed_address = Some(address);
            self.observation_count = 1;
            self.notified = false; // Reset notification flag for new address
        }
        self.last_observed = Some(now);
    }

    /// Check if the observed address has changed from the expected address
    pub(super) fn has_address_changed(&self, expected: &SocketAddr) -> bool {
        match self.observed_address {
            Some(observed) => observed != *expected,
            None => false,
        }
    }

    /// Mark that we've notified the application about this address
    pub(super) fn mark_notified(&mut self) {
        self.notified = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn path_address_info_new() {
        let info = PathAddressInfo::new();
        assert_eq!(info.observed_address, None);
        assert_eq!(info.last_observed, None);
        assert_eq!(info.observation_count, 0);
        assert!(!info.notified);
    }

    #[test]
    fn path_address_info_update_new_address() {
        let mut info = PathAddressInfo::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let now = Instant::now();

        info.update_observed_address(addr, now);

        assert_eq!(info.observed_address, Some(addr));
        assert_eq!(info.last_observed, Some(now));
        assert_eq!(info.observation_count, 1);
        assert!(!info.notified);
    }

    #[test]
    fn path_address_info_update_same_address() {
        let mut info = PathAddressInfo::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443);
        let now1 = Instant::now();

        info.update_observed_address(addr, now1);
        assert_eq!(info.observation_count, 1);

        let now2 = now1 + Duration::from_secs(1);
        info.update_observed_address(addr, now2);

        assert_eq!(info.observed_address, Some(addr));
        assert_eq!(info.last_observed, Some(now2));
        assert_eq!(info.observation_count, 2);
    }

    #[test]
    fn path_address_info_update_different_address() {
        let mut info = PathAddressInfo::new();
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443);
        let now1 = Instant::now();

        info.update_observed_address(addr1, now1);
        info.mark_notified();
        assert!(info.notified);

        let now2 = now1 + Duration::from_secs(1);
        info.update_observed_address(addr2, now2);

        assert_eq!(info.observed_address, Some(addr2));
        assert_eq!(info.last_observed, Some(now2));
        assert_eq!(info.observation_count, 1);
        assert!(!info.notified); // Reset when address changes
    }

    #[test]
    fn path_address_info_has_address_changed() {
        let mut info = PathAddressInfo::new();
        let expected = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let observed = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443);

        // No observed address yet
        assert!(!info.has_address_changed(&expected));

        // Same as expected
        info.update_observed_address(expected, Instant::now());
        assert!(!info.has_address_changed(&expected));

        // Different from expected
        info.update_observed_address(observed, Instant::now());
        assert!(info.has_address_changed(&expected));
    }

    #[test]
    fn path_address_info_ipv6() {
        let mut info = PathAddressInfo::new();
        let addr = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            8080,
        );
        let now = Instant::now();

        info.update_observed_address(addr, now);

        assert_eq!(info.observed_address, Some(addr));
        assert_eq!(info.observation_count, 1);
    }

    #[test]
    fn path_address_info_notification_tracking() {
        let mut info = PathAddressInfo::new();
        assert!(!info.notified);

        // First observe an address
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80);
        info.update_observed_address(addr, Instant::now());
        assert!(!info.notified);

        // Mark as notified
        info.mark_notified();
        assert!(info.notified);

        // Notification flag persists when observing same address
        info.update_observed_address(addr, Instant::now());
        assert!(info.notified); // Still true for same address

        // But resets on address change
        let new_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 80);
        info.update_observed_address(new_addr, Instant::now());
        assert!(!info.notified);
    }

    // Tests for PathData with address discovery integration
    #[test]
    fn path_data_with_address_info() {
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let config = TransportConfig::default();
        let now = Instant::now();

        let path = PathData::new(remote, false, None, now, &config);

        // Should have address_info field
        assert!(path.address_info.observed_address.is_none());
        assert!(path.address_info.last_observed.is_none());
        assert_eq!(path.address_info.observation_count, 0);
        assert!(!path.address_info.notified);
    }

    #[test]
    fn path_data_update_observed_address() {
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let config = TransportConfig::default();
        let now = Instant::now();

        let mut path = PathData::new(remote, false, None, now, &config);

        // Update observed address
        let observed = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443);
        path.update_observed_address(observed, now);

        assert_eq!(path.address_info.observed_address, Some(observed));
        assert_eq!(path.address_info.last_observed, Some(now));
        assert_eq!(path.address_info.observation_count, 1);
        assert!(!path.address_info.notified);
    }

    #[test]
    fn path_data_has_address_changed() {
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let config = TransportConfig::default();
        let now = Instant::now();

        let mut path = PathData::new(remote, false, None, now, &config);

        // No change when no observed address
        assert!(!path.has_address_changed());

        // Update with same as remote
        path.update_observed_address(remote, now);
        assert!(!path.has_address_changed());

        // Update with different address
        let different = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443);
        path.update_observed_address(different, now);
        assert!(path.has_address_changed());
    }

    #[test]
    fn path_data_mark_address_notified() {
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let config = TransportConfig::default();
        let now = Instant::now();

        let mut path = PathData::new(remote, false, None, now, &config);

        // Update and mark as notified
        let observed = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443);
        path.update_observed_address(observed, now);
        assert!(!path.address_info.notified);

        path.mark_address_notified();
        assert!(path.address_info.notified);
    }

    #[test]
    fn path_data_from_previous_preserves_address_info() {
        let remote1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let remote2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443);
        let config = TransportConfig::default();
        let now = Instant::now();

        let mut path1 = PathData::new(remote1, false, None, now, &config);

        // Set up address info
        let observed = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 5678);
        path1.update_observed_address(observed, now);
        path1.mark_address_notified();

        // Create new path from previous
        let path2 = PathData::from_previous(remote2, &path1, now);

        // Address info should be reset for new path
        assert!(path2.address_info.observed_address.is_none());
        assert!(path2.address_info.last_observed.is_none());
        assert_eq!(path2.address_info.observation_count, 0);
        assert!(!path2.address_info.notified);
    }

    #[test]
    fn path_data_reset_clears_address_info() {
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let config = TransportConfig::default();
        let now = Instant::now();

        let mut path = PathData::new(remote, false, None, now, &config);

        // Set up address info
        let observed = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443);
        path.update_observed_address(observed, now);
        path.mark_address_notified();

        // Reset should clear address info
        path.reset(now, &config);

        assert!(path.address_info.observed_address.is_none());
        assert!(path.address_info.last_observed.is_none());
        assert_eq!(path.address_info.observation_count, 0);
        assert!(!path.address_info.notified);
    }

    // Tests for per-path rate limiting
    #[test]
    fn path_data_with_rate_limiter() {
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let config = TransportConfig::default();
        let now = Instant::now();

        let path = PathData::new(remote, false, None, now, &config);

        // Should have a rate limiter
        assert!(path.observation_rate_limiter.tokens > 0.0);
        assert_eq!(path.observation_rate_limiter.rate, 10.0); // Default rate
        assert_eq!(path.observation_rate_limiter.max_tokens, 10.0);
        assert_eq!(path.observation_rate_limiter.last_update, now);
    }

    #[test]
    fn path_data_can_send_observation() {
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let config = TransportConfig::default();
        let now = Instant::now();

        let mut path = PathData::new(remote, false, None, now, &config);

        // Should be able to send initially (has tokens)
        assert!(path.can_send_observation(now));

        // Consume a token
        path.consume_observation_token(now);

        // Should still have tokens available
        assert!(path.can_send_observation(now));

        // Consume all tokens
        for _ in 0..9 {
            path.consume_observation_token(now);
        }

        // Should be out of tokens
        assert!(!path.can_send_observation(now));

        // Wait for token replenishment
        let later = now + Duration::from_millis(200); // 0.2 seconds = 2 tokens
        assert!(path.can_send_observation(later));
    }

    #[test]
    fn path_data_rate_limiter_replenishment() {
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let config = TransportConfig::default();
        let now = Instant::now();

        let mut path = PathData::new(remote, false, None, now, &config);

        // Consume all tokens
        for _ in 0..10 {
            path.consume_observation_token(now);
        }
        assert_eq!(path.observation_rate_limiter.tokens, 0.0);

        // Check replenishment after 1 second
        let later = now + Duration::from_secs(1);
        path.update_observation_tokens(later);

        // Should have replenished to max (rate = 10/sec)
        assert_eq!(path.observation_rate_limiter.tokens, 10.0);
    }

    #[test]
    fn path_data_rate_limiter_custom_rate() {
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let config = TransportConfig::default();
        let now = Instant::now();

        let mut path = PathData::new(remote, false, None, now, &config);

        // Update with custom rate
        path.set_observation_rate(5); // 5 per second
        assert_eq!(path.observation_rate_limiter.rate, 5.0);
        assert_eq!(path.observation_rate_limiter.max_tokens, 5.0);

        // Consume all tokens
        for _ in 0..5 {
            path.consume_observation_token(now);
        }
        assert!(!path.can_send_observation(now));

        // Check replenishment with new rate
        let later = now + Duration::from_millis(400); // 0.4 seconds = 2 tokens at rate 5
        path.update_observation_tokens(later);
        assert_eq!(path.observation_rate_limiter.tokens, 2.0);
    }

    #[test]
    fn path_data_rate_limiter_from_previous() {
        let remote1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let remote2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443);
        let config = TransportConfig::default();
        let now = Instant::now();

        let mut path1 = PathData::new(remote1, false, None, now, &config);

        // Set custom rate and consume some tokens
        path1.set_observation_rate(20);
        for _ in 0..5 {
            path1.consume_observation_token(now);
        }

        // Create new path from previous
        let path2 = PathData::from_previous(remote2, &path1, now);

        // New path should have fresh rate limiter with same rate
        assert_eq!(path2.observation_rate_limiter.rate, 20.0);
        assert_eq!(path2.observation_rate_limiter.max_tokens, 20.0);
        assert_eq!(path2.observation_rate_limiter.tokens, 20.0); // Full tokens
    }

    #[test]
    fn path_data_reset_preserves_rate() {
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let config = TransportConfig::default();
        let now = Instant::now();

        let mut path = PathData::new(remote, false, None, now, &config);

        // Set custom rate
        path.set_observation_rate(15);

        // Consume some tokens
        for _ in 0..3 {
            path.consume_observation_token(now);
        }

        // Reset the path
        path.reset(now, &config);

        // Rate should be preserved, tokens should be reset
        assert_eq!(path.observation_rate_limiter.rate, 15.0);
        assert_eq!(path.observation_rate_limiter.tokens, 15.0); // Full tokens after reset
    }
}
