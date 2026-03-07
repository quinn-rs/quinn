use std::any::Any;
use std::cmp;
use std::sync::Arc;

use super::{BASE_DATAGRAM_SIZE, Controller, ControllerFactory};
use crate::connection::RttEstimator;
use crate::Instant;

/// Prague congestion controller implementing L4S-compatible ECN-based congestion control.
///
/// Prague uses DCTCP-style ECN feedback to maintain a running estimate of the
/// congestion marking fraction (alpha). On ECN congestion events, the window is
/// reduced proportionally to alpha rather than halved, enabling low-latency
/// coexistence with classic traffic in L4S (Low Latency, Low Loss, Scalable
/// Throughput) deployments.
///
/// References:
/// - RFC 9331 (L4S architecture)
/// - RFC 9332 (DualQ Coupled AQM)
/// - draft-ietf-tsvwg-ecn-l4s-id (L4S ECN protocol)
/// - RFC 8257 (DCTCP)
#[derive(Debug, Clone)]
pub struct Prague {
    config: Arc<PragueConfig>,
    current_mtu: u64,
    /// Congestion window in bytes
    window: u64,
    /// Slow start threshold
    ssthresh: u64,
    /// EWMA of ECN marking fraction (0.0 to 1.0)
    alpha: f64,
    /// Bytes acked in the current RTT measurement window
    acked_in_round: u64,
    /// Number of ECN congestion events in the current RTT measurement window
    ecn_in_round: bool,
    /// Packet number that ends the current measurement round
    round_end: u64,
    /// Whether the current round has started (we have a valid round_end)
    round_started: bool,
    /// Last sent packet number (for tracking round boundaries)
    last_sent_packet: u64,
    /// Recovery start time to deduplicate congestion events
    recovery_start_time: Instant,
    /// Bytes acked for Appropriate Byte Counting in congestion avoidance
    bytes_acked: u64,
    /// Whether we are in slow start
    in_slow_start: bool,
}

impl Prague {
    /// Construct a new Prague controller
    pub fn new(config: Arc<PragueConfig>, now: Instant, current_mtu: u16) -> Self {
        Self {
            window: config.initial_window,
            ssthresh: u64::MAX,
            alpha: 0.0,
            acked_in_round: 0,
            ecn_in_round: false,
            round_end: 0,
            round_started: false,
            last_sent_packet: 0,
            recovery_start_time: now,
            current_mtu: current_mtu as u64,
            bytes_acked: 0,
            in_slow_start: true,
            config,
        }
    }

    fn minimum_window(&self) -> u64 {
        2 * self.current_mtu
    }

    /// Update alpha EWMA at the end of a measurement round.
    ///
    /// alpha = (1 - g) * alpha + g * F
    /// where F is 1.0 if any CE marks were seen this round, 0.0 otherwise.
    fn update_alpha(&mut self) {
        let f = if self.ecn_in_round { 1.0 } else { 0.0 };
        self.alpha = (1.0 - self.config.alpha_g) * self.alpha + self.config.alpha_g * f;
        self.acked_in_round = 0;
        self.ecn_in_round = false;
    }

    /// Start a new measurement round ending at the most recently sent packet.
    fn start_new_round(&mut self) {
        self.round_end = self.last_sent_packet;
        self.round_started = true;
    }
}

impl Controller for Prague {
    fn on_sent(&mut self, _now: Instant, _bytes: u64, last_packet_number: u64) {
        self.last_sent_packet = last_packet_number;
        if !self.round_started {
            self.start_new_round();
        }
    }

    fn on_ack(
        &mut self,
        _now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        _rtt: &RttEstimator,
    ) {
        if app_limited || sent <= self.recovery_start_time {
            return;
        }

        self.acked_in_round += bytes;

        if self.in_slow_start {
            // Slow start: grow by acked bytes (standard behavior)
            self.window += bytes;
            if self.window >= self.ssthresh {
                self.in_slow_start = false;
                self.bytes_acked = self.window - self.ssthresh;
            }
        } else {
            // Congestion avoidance: additive increase of 1 MSS per RTT.
            // Use Appropriate Byte Counting (RFC 3465).
            self.bytes_acked += bytes;
            if self.bytes_acked >= self.window {
                self.bytes_acked -= self.window;
                self.window += self.current_mtu;
            }
        }
    }

    fn on_end_acks(
        &mut self,
        _now: Instant,
        _in_flight: u64,
        _app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        // Check if this ACK batch completes a measurement round.
        if let Some(largest) = largest_packet_num_acked {
            if self.round_started && largest >= self.round_end {
                self.update_alpha();
                self.start_new_round();
            }
        }
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        is_ecn: bool,
        _lost_bytes: u64,
    ) {
        if is_ecn {
            // ECN congestion signal: record for alpha computation.
            self.ecn_in_round = true;

            if sent <= self.recovery_start_time {
                return;
            }
            self.recovery_start_time = now;

            if self.in_slow_start {
                // Exit slow start on first ECN mark.
                self.in_slow_start = false;
                self.ssthresh = self.window;
            }

            // Prague/DCTCP response: reduce by alpha/2.
            // cwnd = cwnd * (1 - alpha/2)
            let reduction = (self.window as f64 * self.alpha / 2.0) as u64;
            self.window = self.window.saturating_sub(reduction);
            self.window = self.window.max(self.minimum_window());
            self.ssthresh = self.window;
        } else {
            // Packet loss: use classic (Cubic-style) response.
            if sent <= self.recovery_start_time {
                return;
            }
            self.recovery_start_time = now;

            if self.in_slow_start {
                self.in_slow_start = false;
            }

            self.ssthresh = cmp::max(
                (self.window as f64 * self.config.loss_reduction_factor) as u64,
                self.minimum_window(),
            );
            self.window = self.ssthresh;

            if is_persistent_congestion {
                self.window = self.minimum_window();
            }
        }

        self.bytes_acked = 0;
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.current_mtu = new_mtu as u64;
        self.window = self.window.max(self.minimum_window());
    }

    fn window(&self) -> u64 {
        self.window
    }

    fn metrics(&self) -> super::ControllerMetrics {
        super::ControllerMetrics {
            congestion_window: self.window(),
            ssthresh: Some(self.ssthresh),
            pacing_rate: None,
        }
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.config.initial_window
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// Configuration for the [`Prague`] congestion controller
#[derive(Debug, Clone)]
pub struct PragueConfig {
    initial_window: u64,
    /// EWMA gain for alpha updates (default 1/16 per DCTCP/RFC 8257)
    alpha_g: f64,
    /// Multiplicative decrease factor for loss-based congestion events (default 0.5)
    loss_reduction_factor: f64,
}

impl PragueConfig {
    /// Default limit on the amount of outstanding data in bytes.
    ///
    /// Recommended value: `min(10 * max_datagram_size, max(2 * max_datagram_size, 14720))`
    pub fn initial_window(&mut self, value: u64) -> &mut Self {
        self.initial_window = value;
        self
    }

    /// EWMA gain for updating the ECN marking fraction estimate (alpha).
    ///
    /// Smaller values make alpha respond more slowly to changes in congestion.
    /// Default: 1/16 (0.0625) per RFC 8257 (DCTCP).
    pub fn alpha_g(&mut self, value: f64) -> &mut Self {
        self.alpha_g = value;
        self
    }

    /// Reduction factor applied to the congestion window on packet loss.
    ///
    /// ECN-based reductions use alpha/2 instead. This factor only applies
    /// when actual packet loss is detected. Default: 0.5.
    pub fn loss_reduction_factor(&mut self, value: f64) -> &mut Self {
        self.loss_reduction_factor = value;
        self
    }
}

impl Default for PragueConfig {
    fn default() -> Self {
        Self {
            initial_window: 14720.clamp(2 * BASE_DATAGRAM_SIZE, 10 * BASE_DATAGRAM_SIZE),
            alpha_g: 1.0 / 16.0,
            loss_reduction_factor: 0.5,
        }
    }
}

impl ControllerFactory for PragueConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Prague::new(self, now, current_mtu))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Duration;

    fn config() -> Arc<PragueConfig> {
        Arc::new(PragueConfig::default())
    }

    fn rtt() -> RttEstimator {
        RttEstimator::new(Duration::from_millis(100))
    }

    fn make(now: Instant) -> Prague {
        Prague::new(config(), now, 1200)
    }

    #[test]
    fn slow_start_growth() {
        let now = Instant::now();
        let mut cc = make(now);
        let initial = cc.window();

        let sent = now + Duration::from_millis(1);
        cc.on_sent(sent, 1200, 1);
        cc.on_ack(sent, sent, 1200, false, &rtt());

        assert_eq!(cc.window(), initial + 1200);
    }

    #[test]
    fn ecn_exits_slow_start() {
        let now = Instant::now();
        let mut cc = make(now);
        assert!(cc.in_slow_start);

        cc.on_sent(now, 1200, 1);
        let later = now + Duration::from_millis(10);
        cc.on_congestion_event(later, later, false, true, 0);

        assert!(!cc.in_slow_start);
    }

    #[test]
    fn alpha_increases_on_ecn() {
        let now = Instant::now();
        let mut cc = make(now);
        assert_eq!(cc.alpha, 0.0);

        // Send packets to set up round tracking
        cc.on_sent(now, 1200, 1);
        cc.on_sent(now, 1200, 2);

        // ECN event
        let t1 = now + Duration::from_millis(10);
        cc.on_congestion_event(t1, t1, false, true, 0);

        // Complete the round
        cc.on_end_acks(t1, 1200, false, Some(2));

        // Alpha should have increased from 0 toward g (1/16)
        assert!(cc.alpha > 0.0);
        assert!((cc.alpha - 1.0 / 16.0).abs() < 1e-10);
    }

    #[test]
    fn alpha_decays_without_ecn() {
        let now = Instant::now();
        let mut cc = make(now);

        // Force alpha to a known value
        cc.alpha = 0.5;

        // Send and complete a round with no ECN
        cc.on_sent(now, 1200, 1);
        cc.on_ack(now, now, 1200, false, &rtt());
        cc.on_end_acks(now, 0, false, Some(1));

        // Alpha should decay: 0.5 * (1 - 1/16) = 0.46875
        let expected = 0.5 * (1.0 - 1.0 / 16.0);
        assert!((cc.alpha - expected).abs() < 1e-10);
    }

    #[test]
    fn ecn_reduces_proportionally() {
        let now = Instant::now();
        let mut cc = make(now);
        cc.in_slow_start = false;
        cc.ssthresh = 10000;
        cc.window = 10000;
        cc.alpha = 0.5;

        cc.on_sent(now, 1200, 1);
        let t1 = now + Duration::from_millis(10);
        cc.on_congestion_event(t1, t1, false, true, 0);

        // Window should reduce by alpha/2 = 0.25 -> 10000 * 0.75 = 7500
        assert_eq!(cc.window(), 7500);
    }

    #[test]
    fn loss_reduces_by_half() {
        let now = Instant::now();
        let mut cc = make(now);
        cc.in_slow_start = false;
        cc.ssthresh = 10000;
        cc.window = 10000;

        cc.on_sent(now, 1200, 1);
        let t1 = now + Duration::from_millis(10);
        cc.on_congestion_event(t1, t1, false, false, 1200);

        // Window should reduce by loss_reduction_factor (0.5) -> 5000
        assert_eq!(cc.window(), 5000);
    }

    #[test]
    fn ecn_with_zero_alpha_no_reduction() {
        let now = Instant::now();
        let mut cc = make(now);
        cc.in_slow_start = false;
        cc.ssthresh = 10000;
        cc.window = 10000;
        cc.alpha = 0.0;

        cc.on_sent(now, 1200, 1);
        let t1 = now + Duration::from_millis(10);
        cc.on_congestion_event(t1, t1, false, true, 0);

        // alpha=0 means reduction = 0, window stays at minimum_window check
        assert_eq!(cc.window(), 10000);
    }

    #[test]
    fn persistent_congestion_resets_window() {
        let now = Instant::now();
        let mut cc = make(now);
        cc.in_slow_start = false;
        cc.window = 10000;

        cc.on_sent(now, 1200, 1);
        let t1 = now + Duration::from_millis(10);
        cc.on_congestion_event(t1, t1, true, false, 1200);

        assert_eq!(cc.window(), cc.minimum_window());
    }

    #[test]
    fn congestion_avoidance_linear_growth() {
        let now = Instant::now();
        let mut cc = make(now);
        cc.in_slow_start = false;
        cc.window = 12000;
        cc.ssthresh = 12000;
        cc.bytes_acked = 0;

        // ACK enough bytes to fill one window -> should increase by 1 MTU
        cc.on_sent(now, 1200, 1);
        let t1 = now + Duration::from_millis(10);
        cc.on_ack(t1, t1, 12000, false, &rtt());

        assert_eq!(cc.window(), 12000 + 1200);
    }

    #[test]
    fn minimum_window_enforced() {
        let now = Instant::now();
        let mut cc = make(now);
        cc.in_slow_start = false;
        cc.window = 2400; // minimum window = 2 * 1200 = 2400
        cc.alpha = 1.0; // max reduction

        cc.on_sent(now, 1200, 1);
        let t1 = now + Duration::from_millis(10);
        cc.on_congestion_event(t1, t1, false, true, 0);

        // Should not go below minimum window
        assert_eq!(cc.window(), 2400);
    }

    #[test]
    fn duplicate_congestion_events_ignored() {
        let now = Instant::now();
        let mut cc = make(now);
        cc.in_slow_start = false;
        cc.window = 10000;
        cc.alpha = 0.5;

        cc.on_sent(now, 1200, 1);
        let t1 = now + Duration::from_millis(10);
        cc.on_congestion_event(t1, t1, false, true, 0);
        let w_after_first = cc.window();

        // Second event with same sent time should be ignored
        cc.on_congestion_event(t1, t1, false, true, 0);
        assert_eq!(cc.window(), w_after_first);
    }

    #[test]
    fn mtu_update() {
        let now = Instant::now();
        let mut cc = make(now);
        cc.window = 2400; // exactly minimum at mtu=1200

        cc.on_mtu_update(1500);
        assert_eq!(cc.current_mtu, 1500);
        // minimum_window is now 3000, window should be clamped up
        assert_eq!(cc.window(), 3000);
    }
}
