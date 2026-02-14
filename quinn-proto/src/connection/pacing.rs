//! Pacing of packet transmissions.

use crate::congestion::ControllerMetrics;
use crate::{Duration, Instant};

use tracing::warn;

/// A simple token-bucket pacer
///
/// The pacer's capacity is derived on a fraction of the congestion window
/// which can be sent in regular intervals
/// Once the bucket is empty, further transmission is blocked.
/// The bucket refills at a rate slightly faster
/// than one congestion window per RTT, as recommended in
/// <https://tools.ietf.org/html/draft-ietf-quic-recovery-34#section-7.7>
pub(super) struct Pacer {
    capacity: u64,
    /// Inputs [`Self::capacity`] was derived from, or `None` if it was derived from a pacing rate
    last_window_inputs: Option<WindowInputs>,
    tokens: u64,
    max_bytes_per_second: Option<u64>,
    prev: Instant,
}

/// Inputs a window-derived [`Pacer::capacity`] was calculated from
#[derive(Copy, Clone, Eq, PartialEq)]
struct WindowInputs {
    /// Congestion window in bytes, after [`rate_limited_window`] has clamped it
    window: u64,
    /// MTU of the path in bytes
    mtu: u16,
}

impl Pacer {
    /// Obtains a new [`Pacer`].
    pub(super) fn new(
        smoothed_rtt: Duration,
        window: u64,
        mtu: u16,
        max_bytes_per_second: Option<u64>,
        now: Instant,
    ) -> Self {
        let window = rate_limited_window(smoothed_rtt, window, max_bytes_per_second);
        let capacity = optimal_capacity(smoothed_rtt, window, mtu);
        Self {
            capacity,
            last_window_inputs: Some(WindowInputs { window, mtu }),
            tokens: capacity,
            max_bytes_per_second,
            prev: now,
        }
    }

    /// Obtains the `max_bytes_per_second` used when this [`Pacer`] was constructed.
    pub(crate) fn max_bytes_per_second(&self) -> Option<u64> {
        self.max_bytes_per_second
    }

    /// Record that a packet has been transmitted.
    pub(super) fn on_transmit(&mut self, packet_length: u16) {
        self.tokens = self.tokens.saturating_sub(packet_length.into())
    }

    /// Return how long we need to wait before sending `bytes_to_send`
    ///
    /// If we can send a packet right away, this returns `None`. Otherwise, returns `Some(d)`,
    /// where `d` is the time before this function should be called again.
    ///
    /// The 5/4 ratio used here comes from the suggestion that N = 1.25 in the draft IETF RFC for
    /// QUIC.
    /// `controller_metrics` provides [`ControllerMetrics`] from the congestion controller used to adjust
    /// pacing.
    ///
    /// Two of its fields are consumed here:
    /// - `congestion_window` (bytes) sets the refill rate when the controller does not compute
    ///   a rate of its own: one window per `smoothed_rtt`, times the 5/4 ratio above.
    /// - `pacing_rate` (bytes/sec) sets the upper limit of how fast we're sending data, and
    ///   takes precedence over `congestion_window` when present.
    ///   e.g: <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-04.html#name-pacing-rate-cpacing_rate>
    pub(super) fn delay(
        &mut self,
        smoothed_rtt: Duration,
        bytes_to_send: u64,
        mtu: u16,
        now: Instant,
        controller_metrics: &ControllerMetrics,
    ) -> Option<Instant> {
        let window = controller_metrics.congestion_window;
        debug_assert_ne!(
            window, 0,
            "zero-sized congestion control window is nonsense"
        );

        // A controller that computes its own sending rate drives the bucket directly; the
        // window- and RTT-derived refill below is used only when no rate is reported.
        if let Some(pacing_rate) = controller_metrics.pacing_rate {
            return self.delay_at_rate(pacing_rate, bytes_to_send, mtu, now);
        }

        let window = rate_limited_window(smoothed_rtt, window, self.max_bytes_per_second);
        let inputs = WindowInputs { window, mtu };
        if self.last_window_inputs != Some(inputs) {
            self.capacity = optimal_capacity(smoothed_rtt, window, mtu);

            // here we cap the number of bytes sent at once during a burst
            self.tokens = self.capacity.min(self.tokens);
            self.last_window_inputs = Some(inputs);
        }

        // if we can already send a packet, there is no need for delay
        if self.tokens >= bytes_to_send {
            return None;
        }

        // we disable pacing for extremely large windows
        if window > u64::from(u32::MAX) {
            return None;
        }

        let window = window as u32;

        let time_elapsed = now.checked_duration_since(self.prev).unwrap_or_else(|| {
            warn!("received a timestamp early than a previous recorded time, ignoring");
            Default::default()
        });

        if smoothed_rtt.as_nanos() == 0 {
            return None;
        }

        let elapsed_rtts = time_elapsed.as_secs_f64() / smoothed_rtt.as_secs_f64();
        let new_tokens = (window as f64 * 1.25 * elapsed_rtts).round() as u64;
        self.tokens = self.tokens.saturating_add(new_tokens).min(self.capacity);

        // In the unlikely event that we're getting polled faster than tokens are generated, ensure
        // that `elapsed_rtts` can grow until we make progress.
        if new_tokens > 0 {
            self.prev = now;
        }

        // if we can already send a packet, there is no need for delay
        if self.tokens >= bytes_to_send {
            return None;
        }

        let unscaled_delay = smoothed_rtt
            .checked_mul((bytes_to_send.max(self.capacity) - self.tokens) as _)
            .unwrap_or(Duration::MAX)
            / window;

        // divisions come before multiplications to prevent overflow
        // this is the time at which the pacing window becomes empty
        Some(now + (unscaled_delay / 5) * 4)
    }

    /// Return how long we need to wait before sending `bytes_to_send` when the congestion
    /// controller dictates an explicit `pacing_rate` in bytes/sec.
    ///
    /// Credit accumulates in `tokens` at `pacing_rate` for the time elapsed since the last
    /// refill, bounded by a burst budget derived from that same rate. If the credit on hand
    /// is short, the returned instant is when the shortfall will have been earned.
    fn delay_at_rate(
        &mut self,
        pacing_rate: u64,
        bytes_to_send: u64,
        mtu: u16,
        now: Instant,
    ) -> Option<Instant> {
        // An explicit rate is clamped directly. The 1.25 correction in
        // `rate_limited_window` exists only to cancel out the legacy refill speedup, which
        // this path does not apply. A rate of zero would divide by zero below.
        let rate = match self.max_bytes_per_second {
            Some(max_bytes_per_second) => Ord::min(pacing_rate, max_bytes_per_second),
            None => pacing_rate,
        }
        .max(1);

        let capacity = rate_capacity(rate, mtu);
        if capacity != self.capacity {
            self.capacity = capacity;
            // here we cap the number of bytes sent at once during a burst
            self.tokens = self.capacity.min(self.tokens);
        }
        // Invalidate the window path's cache: its inputs no longer describe `capacity`.
        self.last_window_inputs = None;

        let time_elapsed = now.checked_duration_since(self.prev).unwrap_or_else(|| {
            warn!("received a timestamp early than a previous recorded time, ignoring");
            Default::default()
        });
        let new_tokens = (rate as f64 * time_elapsed.as_secs_f64()) as u64;

        // Advance `prev` only once whole bytes have been earned, so elapsed time too short to
        // pay for a single byte is carried over rather than discarded. Without this, a slow
        // rate polled frequently would never accumulate anything.
        if new_tokens > 0 {
            self.tokens = self.tokens.saturating_add(new_tokens).min(self.capacity);
            self.prev = now;
        }

        // Capped at the burst budget so that a `bytes_to_send` exceeding the whole bucket is
        // still released eventually, rather than waiting for a level the bucket never reaches.
        let target = Ord::min(bytes_to_send, self.capacity);
        if self.tokens >= target {
            return None;
        }

        // Wait for the shortfall only. Deriving the delay from `bytes_to_send` would re-arm
        // the same interval on every poll and never retire, stalling the connection.
        let deficit = target - self.tokens;
        Some(now + Duration::from_secs_f64(deficit as f64 / rate as f64))
    }
}

/// Calculates a pacer capacity for a pacing rate
///
/// Burst intervals trade distributing datagrams over time against waking the connection up more
/// often than user-space timer accuracy can service; overshooting one by more than 25% loses the
/// tokens for the extra elapsed time.
fn rate_capacity(pacing_rate: u64, mtu: u16) -> u64 {
    let mtu = u64::from(mtu);
    let bytes_in =
        |interval: Duration| ((pacing_rate as u128 * interval.as_nanos()) / 1_000_000_000) as u64;

    let target_capacity = bytes_in(TARGET_BURST_INTERVAL);
    // Never restrict capacity below one MTU.
    let max_capacity = Ord::max(bytes_in(MAX_BURST_INTERVAL), mtu);

    // Batch the greater of `TARGET_BURST_INTERVAL` or `MIN_BURST_SIZE` worth of traffic at a
    // time, limited to at most `MAX_BURST_INTERVAL` worth to avoid inducing excessive latency.
    Ord::min(
        max_capacity,
        target_capacity.clamp(MIN_BURST_SIZE * mtu, MAX_BURST_SIZE * mtu),
    )
}

/// Calculates a pacer capacity for a certain window and RTT, which imply a rate
fn optimal_capacity(smoothed_rtt: Duration, window: u64, mtu: u16) -> u64 {
    let rtt = smoothed_rtt.as_nanos().max(1);
    let rate = u64::try_from(window as u128 * 1_000_000_000 / rtt).unwrap_or(u64::MAX);
    rate_capacity(rate, mtu)
}

/// Clamps the window to limit the sending rate to `max_bytes_per_second`.
///
/// If `max_bytes_per_second` is `None`, the original window is returned.
fn rate_limited_window(
    smoothed_rtt: Duration,
    window: u64,
    max_bytes_per_second: Option<u64>,
) -> u64 {
    let Some(max_bytes_per_second) = max_bytes_per_second else {
        return window;
    };

    let rate_window = max_bytes_per_second as f64 * smoothed_rtt.as_secs_f64();

    // the pacer refills tokens at x1.25 speed, so we shrink the window to cancel out the speedup
    // (otherwise the actual sending rate could be higher than `max_bytes_per_second`)
    let adjusted_rate_window = (rate_window / 1.25).round();

    Ord::min(window, Ord::max(adjusted_rate_window as u64, 1))
}

/// Period of traffic to batch together on a reasonably fast connection
const TARGET_BURST_INTERVAL: Duration = Duration::from_millis(2);

/// Maximum period of traffic to batch together on a slow connection
///
/// Takes precedence over [`MIN_BURST_SIZE`].
const MAX_BURST_INTERVAL: Duration = Duration::from_millis(10);

/// Minimum number of datagrams to batch together, so long as we won't have to wait for more than
/// [`MAX_BURST_INTERVAL`]
const MIN_BURST_SIZE: u64 = 10;

/// Creating 256 packets took 1ms in a benchmark, so larger bursts don't make sense.
const MAX_BURST_SIZE: u64 = 256;

#[cfg(test)]
mod tests {
    use super::*;

    /// 100 Mbit/s in bytes/sec, the rate used by the controller-paced tests.
    const TEST_PACING_RATE: u64 = 12_500_000;

    /// Metrics from a controller that does not compute a rate of its own, as Cubic and Reno
    /// report them.
    fn unpaced_metrics(congestion_window: u64) -> ControllerMetrics {
        ControllerMetrics {
            congestion_window,
            ..Default::default()
        }
    }

    /// Metrics as a delay-based controller such as BBR3 reports them: both a pacing rate
    /// and a send quantum are always present.
    fn paced_metrics(
        congestion_window: u64,
        pacing_rate: u64,
        send_quantum: u64,
    ) -> ControllerMetrics {
        ControllerMetrics {
            congestion_window,
            pacing_rate: Some(pacing_rate),
            send_quantum: Some(send_quantum),
            ..Default::default()
        }
    }

    /// Polls `pacer` repeatedly at the single instant `now`, transmitting one `mtu`-sized
    /// datagram each time it is allowed to, until it asks the caller to wait.
    ///
    /// Returns the instant the pacer wants to be polled again and the number of bytes
    /// emitted before it blocked, or `None` if it never blocked.
    fn burst_until_blocked(
        pacer: &mut Pacer,
        rtt: Duration,
        mtu: u16,
        now: Instant,
        metrics: &ControllerMetrics,
    ) -> Option<(Instant, u64)> {
        let mut sent = 0;
        for _ in 0..10_000 {
            match pacer.delay(rtt, u64::from(mtu), mtu, now, metrics) {
                Some(resume) => return Some((resume, sent)),
                None => {
                    pacer.on_transmit(mtu);
                    sent += u64::from(mtu);
                }
            }
        }
        None
    }

    /// Drives an always-backlogged sender through `pacer` for `duration` of simulated time the
    /// way `poll_transmit` does: send whenever the pacer allows it, otherwise jump to the instant
    /// it asked to be polled again. Returns the bytes emitted.
    fn bytes_sent_over(
        pacer: &mut Pacer,
        rtt: Duration,
        mtu: u16,
        start: Instant,
        duration: Duration,
        metrics: &ControllerMetrics,
    ) -> u64 {
        /// Guards against a pacer that never advances time; far above the ~8k polls a correct
        /// pacer needs for one second at [`TEST_PACING_RATE`].
        const MAX_POLLS: u64 = 1_000_000;

        let deadline = start + duration;
        let mut at = start;
        let mut sent = 0;
        let mut polls = 0;
        while at < deadline {
            polls += 1;
            assert!(
                polls < MAX_POLLS,
                "pacer made no progress: {sent} bytes emitted without reaching the deadline"
            );
            match pacer.delay(rtt, u64::from(mtu), mtu, at, metrics) {
                None => {
                    pacer.on_transmit(mtu);
                    sent += u64::from(mtu);
                }
                Some(resume) => at = resume,
            }
        }
        sent
    }

    #[test]
    fn blocks_greedy_sender_at_controller_pacing_rate() {
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let window = 2_000_000;
        let now = Instant::now();
        // `send_quantum` at BBR3's `2 * SMSS` floor, i.e. what it reports at low rates.
        let metrics = paced_metrics(window, TEST_PACING_RATE, 2 * u64::from(mtu));
        let mut pacer = Pacer::new(rtt, window, mtu, None, now);

        // Honouring a finite rate is only possible by delaying, so a sender polling at a
        // single instant must eventually be told to wait.
        assert!(
            burst_until_blocked(&mut pacer, rtt, mtu, now, &metrics).is_some(),
            "pacer never blocked while polled at a single instant, so the controller's \
             pacing rate is not being enforced"
        );
    }

    #[test]
    fn pacing_delay_unblocks_once_it_expires() {
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let window = 2_000_000;
        let now = Instant::now();
        let metrics = paced_metrics(window, TEST_PACING_RATE, 2 * u64::from(mtu));
        let mut pacer = Pacer::new(rtt, window, mtu, None, now);

        let (resume, _) = burst_until_blocked(&mut pacer, rtt, mtu, now, &metrics)
            .expect("pacer must block once the burst budget is spent");

        // `poll_transmit` re-runs when the pacing timer fires. If the pacer re-derives the
        // same delay from the new `now` it would re-arm forever and the connection stalls.
        assert_eq!(
            pacer.delay(rtt, u64::from(mtu), mtu, resume, &metrics),
            None,
            "the delay the pacer asked for must be long enough to unblock the send"
        );
    }

    #[test]
    fn aggregate_throughput_matches_controller_pacing_rate() {
        const SECONDS: u64 = 1;

        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let window = 2_000_000;
        let metrics = paced_metrics(window, TEST_PACING_RATE, 2 * u64::from(mtu));
        let start = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, None, start);

        let sent = bytes_sent_over(
            &mut pacer,
            rtt,
            mtu,
            start,
            Duration::from_secs(SECONDS),
            &metrics,
        );

        let expected = TEST_PACING_RATE * SECONDS;
        // Slack covers the bucket the pacer starts full plus the trailing partial burst.
        let slack = expected / 20;
        assert!(
            sent <= expected + slack,
            "emitted {sent} bytes in {SECONDS}s, but pacing_rate allows only {expected}"
        );
        assert!(
            sent + slack >= expected,
            "emitted {sent} bytes in {SECONDS}s, underrunning pacing_rate {expected}"
        );
    }

    #[test]
    fn does_not_panic_on_bad_instant() {
        let old_instant = Instant::now();
        let new_instant = old_instant + Duration::from_micros(15);
        let rtt = Duration::from_micros(400);

        assert!(
            Pacer::new(rtt, 30000, 1500, None, new_instant)
                .delay(
                    Duration::from_micros(0),
                    0,
                    1500,
                    old_instant,
                    &unpaced_metrics(1),
                )
                .is_none()
        );
        assert!(
            Pacer::new(rtt, 30000, 1500, None, new_instant)
                .delay(
                    Duration::from_micros(0),
                    1600,
                    1500,
                    old_instant,
                    &unpaced_metrics(1),
                )
                .is_none()
        );
        assert!(
            Pacer::new(rtt, 30000, 1500, None, new_instant)
                .delay(
                    Duration::from_micros(0),
                    1500,
                    1500,
                    old_instant,
                    &unpaced_metrics(3000),
                )
                .is_none()
        );
    }

    #[test]
    fn derives_initial_capacity() {
        let window = 2_000_000;
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();

        let pacer = Pacer::new(rtt, window, mtu, None, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 * TARGET_BURST_INTERVAL.as_nanos() / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, pacer.capacity);

        let pacer = Pacer::new(Duration::from_millis(0), window, mtu, None, now);
        assert_eq!(pacer.capacity, MAX_BURST_SIZE * mtu as u64);
        assert_eq!(pacer.tokens, pacer.capacity);

        let pacer = Pacer::new(rtt, 1, mtu, None, now);
        assert_eq!(pacer.capacity, mtu as u64);
        assert_eq!(pacer.tokens, pacer.capacity);
    }

    #[test]
    fn adjusts_capacity() {
        let window = 2_000_000;
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();

        let mut pacer = Pacer::new(rtt, window, mtu, None, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 * TARGET_BURST_INTERVAL.as_nanos() / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, pacer.capacity);
        let initial_tokens = pacer.tokens;

        pacer.delay(rtt, mtu as u64, mtu, now, &unpaced_metrics(window * 2));
        assert_eq!(
            pacer.capacity,
            (2 * window as u128 * TARGET_BURST_INTERVAL.as_nanos() / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, initial_tokens);

        pacer.delay(rtt, mtu as u64, mtu, now, &unpaced_metrics(window / 2));
        assert_eq!(
            pacer.capacity,
            (window as u128 / 2 * TARGET_BURST_INTERVAL.as_nanos() / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, initial_tokens / 2);

        pacer.delay(rtt, mtu as u64, mtu * 2, now, &unpaced_metrics(window));
        assert_eq!(
            pacer.capacity,
            (window as u128 * TARGET_BURST_INTERVAL.as_nanos() / rtt.as_nanos()) as u64
        );

        pacer.delay(rtt, mtu as u64, 20_000, now, &unpaced_metrics(window));
        assert_eq!(pacer.capacity, 20_000_u64 * MIN_BURST_SIZE);
    }

    #[test]
    fn computes_pause_correctly() {
        let window = 2_000_000u64;
        let mtu = 1000;
        let rtt = Duration::from_millis(50);
        let old_instant = Instant::now();

        let mut pacer = Pacer::new(rtt, window, mtu, None, old_instant);
        let packet_capacity = pacer.capacity / mtu as u64;

        for _ in 0..packet_capacity {
            assert_eq!(
                pacer.delay(rtt, mtu as u64, mtu, old_instant, &unpaced_metrics(window)),
                None,
                "When capacity is available packets should be sent immediately"
            );

            pacer.on_transmit(mtu);
        }

        let pace_duration = Duration::from_nanos((TARGET_BURST_INTERVAL.as_nanos() * 4 / 5) as u64);

        let actual_delay = pacer
            .delay(rtt, mtu as u64, mtu, old_instant, &unpaced_metrics(window))
            .expect("Send must be delayed")
            .duration_since(old_instant);

        let diff = actual_delay.abs_diff(pace_duration);

        // Allow up to 2ns difference due to rounding
        assert!(
            diff < Duration::from_nanos(2),
            "expected ≈ {pace_duration:?}, got {actual_delay:?} (diff {diff:?})"
        );
        // Refill half of the tokens
        assert_eq!(
            pacer.delay(
                rtt,
                mtu as u64,
                mtu,
                old_instant + pace_duration / 2,
                &unpaced_metrics(window),
            ),
            None
        );
        assert_eq!(pacer.tokens, pacer.capacity / 2);

        for _ in 0..packet_capacity / 2 {
            assert_eq!(
                pacer.delay(rtt, mtu as u64, mtu, old_instant, &unpaced_metrics(window)),
                None,
                "When capacity is available packets should be sent immediately"
            );

            pacer.on_transmit(mtu);
        }

        // Refill all capacity by waiting more than the expected duration
        assert_eq!(
            pacer.delay(
                rtt,
                mtu as u64,
                mtu,
                old_instant + pace_duration * 3 / 2,
                &unpaced_metrics(window),
            ),
            None
        );
        assert_eq!(pacer.tokens, pacer.capacity);
    }

    #[test]
    fn computes_pause_correctly_for_rate_limited() {
        let window = 2_000_000u64;
        let mtu = 1000;
        let rtt = Duration::from_millis(50);
        let old_instant = Instant::now();

        let mut pacer = Pacer::new(rtt, window, mtu, Some(2_000), old_instant);
        assert_eq!(
            pacer.delay(rtt, 1_000, mtu, old_instant, &unpaced_metrics(window)),
            None,
            "When capacity is available packets should be sent immediately"
        );
        pacer.on_transmit(mtu);

        let actual_delay = pacer
            .delay(rtt, 1_000, mtu, old_instant, &unpaced_metrics(window))
            .expect("Send must be delayed")
            .duration_since(old_instant);

        let expected_delay = Duration::from_millis(500);
        let diff = actual_delay.abs_diff(expected_delay);

        // Allow up to 2ns difference due to rounding
        assert!(
            diff < Duration::from_nanos(2),
            "expected ≈ {expected_delay:?}, got {actual_delay:?} (diff {diff:?})"
        );

        // Should be able to send after a while
        let now = old_instant + expected_delay / 2;
        assert_eq!(
            pacer.delay(rtt, 500, mtu, now, &unpaced_metrics(window)),
            None
        );
    }

    #[test]
    fn derives_burst_budget_from_controller_pacing_rate() {
        let window = 2_000_000;
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();
        // A window twice the one the pacer was built with must not disturb a budget the
        // controller's rate determines.
        let metrics = paced_metrics(window * 2, TEST_PACING_RATE, 2 * u64::from(mtu));
        let mut pacer = Pacer::new(rtt, window, mtu, None, now);

        pacer.delay(rtt, u64::from(mtu), mtu, now, &metrics);

        assert_eq!(pacer.capacity, rate_capacity(TEST_PACING_RATE, mtu));
        // 2ms of traffic at 100 Mbit/s, i.e. `TARGET_BURST_INTERVAL` worth.
        assert_eq!(pacer.capacity, 25_000);
    }

    #[test]
    fn pacing_delay_covers_exactly_the_token_shortfall() {
        // 200 MB/s in bytes/s
        const RATE: u64 = 200_000_000;

        let window = 2_000_000;
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();
        let metrics = paced_metrics(window, RATE, 2 * u64::from(mtu));
        let mut pacer = Pacer::new(rtt, window, mtu, None, now);

        let (resume, _) = burst_until_blocked(&mut pacer, rtt, mtu, now, &metrics)
            .expect("pacer must block once the burst budget is spent");

        // The wait pays for the credit still missing, not for the whole datagram: charging
        // for bytes already covered by tokens on hand would pace below `pacing_rate`.
        let deficit = u64::from(mtu) - pacer.tokens;
        assert_eq!(
            resume - now,
            Duration::from_secs_f64(deficit as f64 / RATE as f64)
        );
    }

    #[test]
    fn burst_is_bounded_by_the_target_interval() {
        let window = 2_000_000;
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();
        let metrics = paced_metrics(window, TEST_PACING_RATE, 2 * u64::from(mtu));
        let mut pacer = Pacer::new(rtt, window, mtu, None, now);

        let (_, burst) = burst_until_blocked(&mut pacer, rtt, mtu, now, &metrics)
            .expect("pacer must block once the burst budget is spent");

        // Bursting more than `TARGET_BURST_INTERVAL` worth of traffic is what fills bottleneck
        // queues; falling far short of it wakes the connection up more often than the timer can
        // service. One datagram of slack either way is inherent in releasing whole datagrams.
        let budget = rate_capacity(TEST_PACING_RATE, mtu);
        assert!(
            burst <= budget + u64::from(mtu),
            "burst of {burst} bytes overshoots the {budget} byte budget by over one datagram"
        );
        assert!(
            burst + u64::from(mtu) >= budget,
            "burst of {burst} bytes undershoots the {budget} byte budget by over one datagram"
        );
    }

    #[test]
    fn shrinks_burst_budget_when_pacing_rate_drops() {
        let window = 2_000_000;
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();
        let quantum = 2 * u64::from(mtu);
        let fast = paced_metrics(window, TEST_PACING_RATE, quantum);
        let slow = paced_metrics(window, TEST_PACING_RATE / 10, quantum);
        let mut pacer = Pacer::new(rtt, window, mtu, None, now);

        // Earn credit at the high rate, as during a ProbeBW_UP phase...
        assert_eq!(pacer.delay(rtt, u64::from(mtu), mtu, now, &fast), None);
        assert_eq!(pacer.capacity, rate_capacity(TEST_PACING_RATE, mtu));

        // ...then a gain change lowers it. Credit earned at the old rate must not survive as a
        // burst the new rate cannot pay for.
        pacer.delay(rtt, u64::from(mtu), mtu, now, &slow);

        let budget = rate_capacity(TEST_PACING_RATE / 10, mtu);
        assert_eq!(pacer.capacity, budget);
        assert!(
            pacer.tokens <= budget,
            "{} tokens outlive the {budget} byte budget of the lowered rate",
            pacer.tokens
        );
    }

    #[test]
    fn rate_path_does_not_leave_stale_window_capacity() {
        let window = 2_000_000;
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, None, now);

        // A controller free to report a rate on some calls and not on others is within what
        // `ControllerMetrics` allows. The rate path leaves its own budget behind...
        pacer.delay(
            rtt,
            u64::from(mtu),
            mtu,
            now,
            &paced_metrics(window, TEST_PACING_RATE, 2 * u64::from(mtu)),
        );
        assert_eq!(pacer.capacity, rate_capacity(TEST_PACING_RATE, mtu));

        // ...so the window path must not mistake it for a budget of its own, even though
        // neither the window nor the MTU it keys on has changed.
        pacer.delay(rtt, u64::from(mtu), mtu, now, &unpaced_metrics(window));

        assert_eq!(
            pacer.capacity,
            optimal_capacity(rtt, window, mtu),
            "the window path kept a burst budget the rate path derived"
        );
    }

    #[test]
    fn max_bytes_per_second_overrides_a_higher_controller_rate() {
        const SECONDS: u64 = 1;
        /// 1 Mbit/s in bytes/sec, two orders of magnitude under [`TEST_PACING_RATE`].
        const LIMIT: u64 = 125_000;

        let window = 2_000_000;
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let start = Instant::now();
        let metrics = paced_metrics(window, TEST_PACING_RATE, 2 * u64::from(mtu));
        let mut pacer = Pacer::new(rtt, window, mtu, Some(LIMIT), start);

        let sent = bytes_sent_over(
            &mut pacer,
            rtt,
            mtu,
            start,
            Duration::from_secs(SECONDS),
            &metrics,
        );

        // The configured ceiling binds even though the controller asks for far more.
        let expected = LIMIT * SECONDS;
        let slack = expected / 20;
        assert!(
            sent <= expected + slack,
            "emitted {sent} bytes in {SECONDS}s, over the {expected} byte ceiling"
        );
        assert!(
            sent + slack >= expected,
            "emitted {sent} bytes in {SECONDS}s, underrunning the {expected} byte ceiling"
        );
    }
}
