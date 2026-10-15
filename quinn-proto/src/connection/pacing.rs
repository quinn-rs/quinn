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
    /// Max bytes released in a single burst on the rate path (the controller's send quantum)
    quantum: u64,
    /// Bytes sent in the current burst
    burst_sent: u64,
    /// Start of the current burst, or `None` prior to the first burst
    burst_start: Option<Instant>,
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
            quantum: capacity,
            burst_sent: 0,
            burst_start: None,
        }
    }

    /// Obtains the `max_bytes_per_second` used when this [`Pacer`] was constructed.
    pub(crate) fn max_bytes_per_second(&self) -> Option<u64> {
        self.max_bytes_per_second
    }

    /// Record that a packet has been transmitted.
    pub(super) fn on_transmit(&mut self, packet_length: u16) {
        self.tokens = self.tokens.saturating_sub(packet_length.into());
        self.burst_sent = self.burst_sent.saturating_add(packet_length.into());
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

        if let Some(pacing_rate) = controller_metrics.pacing_rate {
            return self.delay_at_rate(
                pacing_rate,
                controller_metrics.send_quantum,
                bytes_to_send,
                mtu,
                now,
            );
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
        let time_elapsed = self.elapsed_since_prev(now);

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

    /// Computes the next transmit instant under an explicit `pacing_rate` (bytes/sec).
    ///
    /// Refills `tokens` at `pacing_rate` up to `capacity`, and caps each burst at `quantum`.
    /// When blocked by insufficient tokens or the burst limit, returns the instant when a
    /// full `quantum` of tokens will be available and the next burst is permitted to start.
    fn delay_at_rate(
        &mut self,
        pacing_rate: u64,
        send_quantum: Option<u64>,
        bytes_to_send: u64,
        mtu: u16,
        now: Instant,
    ) -> Option<Instant> {
        // Clamp to the configured ceiling and floor at 1 byte/s to prevent division by zero.
        let rate = pacing_rate
            .min(self.max_bytes_per_second.unwrap_or(u64::MAX))
            .max(1);

        // Size bucket capacity to absorb late timer wakeups without dropping refilled tokens
        self.capacity = rate_capacity(rate, mtu);
        self.tokens = self.tokens.min(self.capacity);
        self.quantum = send_quantum
            .unwrap_or(self.capacity)
            .clamp(u64::from(mtu), self.capacity);
        self.last_window_inputs = None;

        let elapsed = self.elapsed_since_prev(now);
        let new_tokens = (rate as f64 * elapsed.as_secs_f64()) as u64;
        if new_tokens > 0 {
            self.tokens = self.tokens.saturating_add(new_tokens).min(self.capacity);
            self.prev = now;
        }

        // Space burst starts by at least half a quantum duration so accumulated tokens
        // cannot drain faster than 2x `rate`.
        let min_burst_interval = Duration::from_secs_f64(self.quantum as f64 / rate as f64 / 2.0);
        let next_burst_at = self
            .burst_start
            .map_or(now, |start| start + min_burst_interval);
        if now >= next_burst_at {
            self.burst_sent = 0;
        }

        let bytes_needed = bytes_to_send.min(self.quantum);
        let fits_in_burst = self.burst_sent + bytes_needed <= self.quantum;
        if self.tokens >= bytes_needed && fits_in_burst {
            if self.burst_sent == 0 {
                self.burst_start = Some(now);
            }
            return None;
        }

        // Wait until `tokens` refills to a full `quantum`, and if the current burst is full,
        // until `next_burst_at`.
        let deficit = self.quantum.saturating_sub(self.tokens);
        let tokens_ready_at = now + Duration::from_secs_f64(deficit as f64 / rate as f64);
        if fits_in_burst {
            Some(tokens_ready_at)
        } else {
            Some(tokens_ready_at.max(next_burst_at))
        }
    }

    fn elapsed_since_prev(&self, now: Instant) -> Duration {
        now.checked_duration_since(self.prev).unwrap_or_else(|| {
            warn!("received a timestamp earlier than a previously recorded time, ignoring");
            Default::default()
        })
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

    /// 100 Mbit/s in bytes/sec.
    const TEST_PACING_RATE: u64 = 12_500_000;

    /// Summary statistics from driving a [`Pacer`] over a simulated duration.
    struct DriveStats {
        sent: u64,
        wakeups: u64,
        max_burst: u64,
    }

    /// Metrics from a window-only controller (e.g. Cubic or Reno).
    fn unpaced_metrics(congestion_window: u64) -> ControllerMetrics {
        ControllerMetrics {
            congestion_window,
            ..Default::default()
        }
    }

    /// Metrics from a rate-based controller (e.g. BBR3) with explicit pacing rate and quantum.
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

    /// Transmits `mtu`-sized packets at `now` until the pacer blocks, returning `(resume_at, bytes_sent)`.
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

    /// Drives a backlogged sender for `duration`, advancing directly to each requested wakeup instant.
    fn drive(
        pacer: &mut Pacer,
        rtt: Duration,
        mtu: u16,
        start: Instant,
        duration: Duration,
        metrics: &ControllerMetrics,
    ) -> DriveStats {
        drive_with_timer(pacer, rtt, mtu, start, duration, metrics, |requested| {
            requested
        })
    }

    /// Drives a backlogged sender for `duration`, resuming each wait at `timer(requested)`.
    fn drive_with_timer(
        pacer: &mut Pacer,
        rtt: Duration,
        mtu: u16,
        start: Instant,
        duration: Duration,
        metrics: &ControllerMetrics,
        mut timer: impl FnMut(Instant) -> Instant,
    ) -> DriveStats {
        const MAX_POLLS: u64 = 1_000_000;

        let deadline = start + duration;
        let mut at = start;
        let mut sent = 0;
        let mut wakeups = 0;
        let mut burst = 0;
        let mut max_burst = 0;
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
                    burst += u64::from(mtu);
                }
                Some(resume) => {
                    wakeups += 1;
                    max_burst = max_burst.max(burst);
                    burst = 0;
                    at = timer(resume);
                }
            }
        }
        DriveStats {
            sent,
            wakeups,
            max_burst: max_burst.max(burst),
        }
    }

    #[test]
    fn blocks_greedy_sender_at_controller_pacing_rate() {
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let window = 2_000_000;
        let now = Instant::now();
        let metrics = paced_metrics(window, TEST_PACING_RATE, 2 * u64::from(mtu));
        let mut pacer = Pacer::new(rtt, window, mtu, None, now);

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
            .expect("pacer must block once the burst limit is reached");

        assert_eq!(
            pacer.delay(rtt, u64::from(mtu), mtu, resume, &metrics),
            None,
            "the delay the pacer asked for must be long enough to unblock the send"
        );
    }

    #[test]
    fn rate_path_wakes_once_per_burst() {
        const SECONDS: u64 = 1;

        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let window = 2_000_000;
        // 1ms of traffic at `TEST_PACING_RATE`.
        let quantum = TEST_PACING_RATE / 1000;
        let metrics = paced_metrics(window, TEST_PACING_RATE, quantum);
        let start = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, None, start);

        let DriveStats { sent, wakeups, .. } = drive(
            &mut pacer,
            rtt,
            mtu,
            start,
            Duration::from_secs(SECONDS),
            &metrics,
        );

        // Waiting for a full `quantum` refill wakes once per burst (~1ms) rather than once
        // per packet (~120us).
        let datagrams = TEST_PACING_RATE * SECONDS / u64::from(mtu);
        assert!(
            wakeups <= datagrams / 4,
            "woke the connection {wakeups} times to send {sent} bytes in {SECONDS}s (~{datagrams} \
             datagrams), which is on the order of one wake per packet"
        );
        assert!(wakeups > 0, "pacer never asked to be polled again");

        let expected = TEST_PACING_RATE * SECONDS;
        let slack = expected / 20;
        assert!(
            sent + slack >= expected,
            "woke {wakeups} times but emitted only {sent} bytes in {SECONDS}s, underrunning \
             pacing_rate {expected}"
        );
    }

    #[test]
    fn rate_path_burst_is_bounded_by_the_send_quantum() {
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let window = 2_000_000;
        let now = Instant::now();
        let quantum = TEST_PACING_RATE / 1000;
        let metrics = paced_metrics(window, TEST_PACING_RATE, quantum);
        let mut pacer = Pacer::new(rtt, window, mtu, None, now);

        let (_, burst) = burst_until_blocked(&mut pacer, rtt, mtu, now, &metrics)
            .expect("pacer must block once the burst limit is reached");

        // Burst size must match `quantum` (1ms of traffic) within one MTU, even though
        // bucket `capacity` holds `TARGET_BURST_INTERVAL` (2ms).
        assert!(
            burst <= quantum + u64::from(mtu),
            "burst of {burst} bytes overshoots the {quantum} byte send quantum by over one datagram"
        );
        assert!(
            burst + u64::from(mtu) >= quantum,
            "burst of {burst} bytes undershoots the {quantum} byte send quantum by over one datagram"
        );
    }

    #[test]
    fn rate_path_keeps_pacing_rate_when_wakes_run_late() {
        const SECONDS: u64 = 1;

        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let window = 2_000_000;
        let quantum = TEST_PACING_RATE / 1000;
        let metrics = paced_metrics(window, TEST_PACING_RATE, quantum);

        // Because bursts can start half a quantum interval (500us) apart, the pacer can
        // catch up from constant timer lateness under 500us by retaining refilled tokens in `capacity`.
        for late in [100, 250, 400].map(Duration::from_micros) {
            let start = Instant::now();
            let mut pacer = Pacer::new(rtt, window, mtu, None, start);

            let DriveStats {
                sent, max_burst, ..
            } = drive_with_timer(
                &mut pacer,
                rtt,
                mtu,
                start,
                Duration::from_secs(SECONDS),
                &metrics,
                |requested| requested + late,
            );

            let expected = TEST_PACING_RATE * SECONDS;
            let slack = expected / 20;
            assert!(
                sent + slack >= expected,
                "{late:?} late wakes: emitted {sent} bytes in {SECONDS}s, underrunning \
                 pacing_rate {expected}"
            );
            assert!(
                max_burst <= quantum + u64::from(mtu),
                "{late:?} late wakes: burst of {max_burst} bytes overshoots the {quantum} byte \
                 send quantum by over one datagram"
            );
        }
    }

    #[test]
    fn rate_path_keeps_pacing_rate_on_a_millisecond_timer() {
        const SECONDS: u64 = 1;

        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let window = 2_000_000;
        let quantum = TEST_PACING_RATE / 1000;
        let metrics = paced_metrics(window, TEST_PACING_RATE, quantum);
        let start = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, None, start);

        // Simulate a 1ms timer wheel with deterministic jitter in [0, 200us).
        let mut wakes = 0u64;
        let tick = Duration::from_millis(1).as_nanos();
        let timer = |requested: Instant| {
            wakes += 1;
            let since = (requested - start).as_nanos();
            let ticked = Duration::from_nanos((since.div_ceil(tick) * tick) as u64);
            let jitter = Duration::from_micros(wakes * 7919 % 200);
            start + ticked + jitter
        };

        let DriveStats {
            sent, max_burst, ..
        } = drive_with_timer(
            &mut pacer,
            rtt,
            mtu,
            start,
            Duration::from_secs(SECONDS),
            &metrics,
            timer,
        );

        let expected = TEST_PACING_RATE * SECONDS;
        let slack = expected / 20;
        assert!(
            sent + slack >= expected,
            "emitted {sent} bytes in {SECONDS}s on a 1ms timer, underrunning pacing_rate \
             {expected}"
        );
        assert!(
            max_burst <= quantum + u64::from(mtu),
            "burst of {max_burst} bytes overshoots the {quantum} byte send quantum by over one \
             datagram"
        );
    }

    #[test]
    fn rate_path_burst_stays_within_send_quantum_after_a_stall() {
        const SECONDS: u64 = 1;

        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let window = 2_000_000;
        let quantum = TEST_PACING_RATE / 1000;
        let metrics = paced_metrics(window, TEST_PACING_RATE, quantum);
        let start = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, None, start);

        // Simulate a single 50ms runtime stall halfway through the run.
        let stall_at = start + Duration::from_millis(500);
        let mut stalled = false;
        let timer = |requested: Instant| {
            if !stalled && requested >= stall_at {
                stalled = true;
                return requested + Duration::from_millis(50);
            }
            requested
        };

        let DriveStats {
            sent, max_burst, ..
        } = drive_with_timer(
            &mut pacer,
            rtt,
            mtu,
            start,
            Duration::from_secs(SECONDS),
            &metrics,
            timer,
        );

        // Accumulated tokens after a stall must still be released in `quantum`-sized bursts.
        assert!(
            max_burst <= quantum + u64::from(mtu),
            "burst of {max_burst} bytes after a stall overshoots the {quantum} byte send \
             quantum by over one datagram"
        );
        let expected = TEST_PACING_RATE * SECONDS;
        let slack = expected / 20;
        assert!(
            sent <= expected + slack,
            "emitted {sent} bytes in {SECONDS}s, but pacing_rate allows only {expected}"
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

        let DriveStats { sent, .. } = drive(
            &mut pacer,
            rtt,
            mtu,
            start,
            Duration::from_secs(SECONDS),
            &metrics,
        );

        let expected = TEST_PACING_RATE * SECONDS;
        // Slack accounts for the initially full bucket and trailing partial burst.
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
    fn derives_burst_budget_from_controller_metrics() {
        let window = 2_000_000;
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();
        let metrics = paced_metrics(window * 2, TEST_PACING_RATE, 12_000);
        let mut pacer = Pacer::new(rtt, window, mtu, None, now);

        pacer.delay(rtt, u64::from(mtu), mtu, now, &metrics);

        // `quantum` limits single bursts, while `capacity` is sized to `TARGET_BURST_INTERVAL`
        // so late timer wakeups do not drop refilled tokens.
        assert_eq!(pacer.quantum, 12_000);
        assert_eq!(pacer.capacity, rate_capacity(TEST_PACING_RATE, mtu));

        // When `send_quantum` is `None`, `quantum` defaults to `capacity`.
        let mut pacer = Pacer::new(rtt, window, mtu, None, now);
        let no_quantum = ControllerMetrics {
            congestion_window: window,
            pacing_rate: Some(TEST_PACING_RATE),
            ..Default::default()
        };

        pacer.delay(rtt, u64::from(mtu), mtu, now, &no_quantum);

        assert_eq!(pacer.capacity, rate_capacity(TEST_PACING_RATE, mtu));
        assert_eq!(pacer.quantum, pacer.capacity);
        // 2ms of traffic at 100 Mbit/s (`TARGET_BURST_INTERVAL`).
        assert_eq!(pacer.capacity, 25_000);
    }

    #[test]
    fn pacing_delay_covers_exactly_the_token_deficit() {
        // 200 MB/s in bytes/s
        const RATE: u64 = 200_000_000;

        let window = 2_000_000;
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();
        let metrics = paced_metrics(window, RATE, 2 * u64::from(mtu));
        let mut pacer = Pacer::new(rtt, window, mtu, None, now);

        // Initialize `quantum` and drain `tokens` below one MTU.
        assert_eq!(pacer.delay(rtt, u64::from(mtu), mtu, now, &metrics), None);
        pacer.tokens = u64::from(mtu) / 2;

        let resume = pacer
            .delay(rtt, u64::from(mtu), mtu, now, &metrics)
            .expect("pacer must block with less than one MTU of tokens");

        // Delay must equal the time required to refill the token deficit up to `quantum`.
        let deficit = pacer.quantum - pacer.tokens;
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
        let metrics = unpaced_metrics(window);
        let mut pacer = Pacer::new(rtt, window, mtu, None, now);

        let (_, burst) = burst_until_blocked(&mut pacer, rtt, mtu, now, &metrics)
            .expect("pacer must block once bucket capacity is exhausted");

        // Unpaced bursts are bounded by `optimal_capacity` within one MTU.
        let budget = optimal_capacity(rtt, window, mtu);
        assert!(
            burst <= budget + u64::from(mtu),
            "burst of {burst} bytes overshoots the {budget} byte capacity by over one datagram"
        );
        assert!(
            burst + u64::from(mtu) >= budget,
            "burst of {burst} bytes undershoots the {budget} byte capacity by over one datagram"
        );
    }

    #[test]
    fn window_path_wakes_once_per_burst() {
        const SECONDS: u64 = 1;

        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let window = 2_000_000;
        let start = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, None, start);

        let DriveStats { sent, wakeups, .. } = drive(
            &mut pacer,
            rtt,
            mtu,
            start,
            Duration::from_secs(SECONDS),
            &unpaced_metrics(window),
        );

        // Window-paced buckets hold at least `MIN_BURST_SIZE` datagrams per refill.
        let datagrams = sent / u64::from(mtu);
        assert!(
            wakeups * MIN_BURST_SIZE <= datagrams,
            "woke the connection {wakeups} times to send {datagrams} datagrams, fewer than the \
             {MIN_BURST_SIZE} per burst that MIN_BURST_SIZE promises"
        );
        assert!(wakeups > 0, "pacer never asked to be polled again");
    }

    #[test]
    fn shrinks_burst_budget_when_pacing_rate_drops() {
        let window = 2_000_000;
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();
        let quantum = |pacing_rate: u64| Ord::max(pacing_rate / 1000, u64::from(mtu));
        let fast = paced_metrics(window, TEST_PACING_RATE, quantum(TEST_PACING_RATE));
        let slow = paced_metrics(
            window,
            TEST_PACING_RATE / 10,
            quantum(TEST_PACING_RATE / 10),
        );
        let mut pacer = Pacer::new(rtt, window, mtu, None, now);

        // Configure bucket at the high rate, then drop to the slow rate.
        assert_eq!(pacer.delay(rtt, u64::from(mtu), mtu, now, &fast), None);
        assert_eq!(pacer.quantum, quantum(TEST_PACING_RATE));

        // Lowering the rate must immediately clamp both `quantum` and `tokens` to the new limits.
        let (_, burst) = burst_until_blocked(&mut pacer, rtt, mtu, now, &slow)
            .expect("pacer must block once the lowered burst limit is reached");

        let budget = quantum(TEST_PACING_RATE / 10);
        assert_eq!(pacer.quantum, budget);
        assert!(
            burst <= budget,
            "burst of {burst} bytes exceeds the {budget} byte quantum of the lowered rate"
        );
        assert!(
            pacer.tokens <= rate_capacity(TEST_PACING_RATE / 10, mtu),
            "{} tokens exceed the bucket capacity of the lowered rate",
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

        // Switching to the rate path invalidates `last_window_inputs`...
        pacer.delay(
            rtt,
            u64::from(mtu),
            mtu,
            now,
            &paced_metrics(
                window,
                TEST_PACING_RATE,
                rate_capacity(TEST_PACING_RATE, mtu),
            ),
        );
        assert_eq!(pacer.capacity, rate_capacity(TEST_PACING_RATE, mtu));

        // ...so switching back to the window path recomputes `capacity` even if `(window, mtu)`
        // matches the initial window inputs.
        pacer.delay(rtt, u64::from(mtu), mtu, now, &unpaced_metrics(window));

        assert_eq!(
            pacer.capacity,
            optimal_capacity(rtt, window, mtu),
            "the window path kept a capacity derived by the rate path"
        );
    }

    #[test]
    fn max_bytes_per_second_overrides_a_higher_controller_rate() {
        const SECONDS: u64 = 1;
        /// 1 Mbit/s in bytes/sec.
        const LIMIT: u64 = 125_000;

        let window = 2_000_000;
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let start = Instant::now();
        let metrics = paced_metrics(window, TEST_PACING_RATE, 2 * u64::from(mtu));
        let mut pacer = Pacer::new(rtt, window, mtu, Some(LIMIT), start);

        let DriveStats { sent, .. } = drive(
            &mut pacer,
            rtt,
            mtu,
            start,
            Duration::from_secs(SECONDS),
            &metrics,
        );

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
